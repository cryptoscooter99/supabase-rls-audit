#!/usr/bin/env bash
# Test runner for rowwarden-rls-audit.sql.
# Uses the standard libpq env vars (PGHOST, PGPORT, PGUSER, PGPASSWORD) to reach a
# SCRATCH Postgres server where the user is a superuser (the fixture creates roles,
# a foreign-data wrapper and extension members). It creates two throwaway
# databases and drops them at the end.
set -euo pipefail
export PGOPTIONS="${PGOPTIONS:-} -c client_min_messages=warning"

here="$(cd "$(dirname "$0")" && pwd)"
audit="$here/../rowwarden-rls-audit.sql"
db_empty="rls_audit_test_empty"
db_fixture="rls_audit_test_fixture"
fail=0

psqlq() { psql -X -q -v ON_ERROR_STOP=1 "$@"; }
ok()    { echo "PASS  $*"; }
bad()   { echo "FAIL  $*"; fail=1; }

# Run the audit file as-is inside a READ ONLY transaction. Prints all five
# columns separated by '|'. A write attempt would make this call fail.
# $2 (optional) is SQL to run first inside the same transaction.
run_audit_full() {
  {
    echo "BEGIN READ ONLY;"
    if [ -n "${2:-}" ]; then printf '%s\n' "$2"; fi
    echo "\\pset format unaligned"
    echo "\\pset tuples_only on"
    echo "\\pset fieldsep '|'"
    cat "$audit"
    echo "ROLLBACK;"
  } | psqlq -d "$1"
}
# First three columns only: severity|check|object
run_audit() { run_audit_full "$@" | cut -d'|' -f1-3; }

# expect_text CHECK OBJECT MUST_MATCH [MUST_NOT_MATCH]
# The full row for CHECK + OBJECT must match the first regex and not the second.
expect_text() {
  local row
  row="$(printf '%s\n' "$full" | awk -F'|' -v c="$1" -v o="$2" '$2 == c && $3 == o')"
  if [ -z "$row" ]; then bad "wording: no $1 row for $2"; return; fi
  if ! printf '%s\n' "$row" | grep -Eq -- "$3"; then
    bad "wording: $1 $2 should match /$3/"; echo "      $row"; return
  fi
  if [ -n "${4:-}" ] && printf '%s\n' "$row" | grep -Eq -- "$4"; then
    bad "wording: $1 $2 should not match /$4/"; echo "      $row"; return
  fi
  ok "wording: $1 $2"
}

cleanup() {
  psql -X -q -d postgres -c "DROP DATABASE IF EXISTS $db_empty" \
                         -c "DROP DATABASE IF EXISTS $db_fixture" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Server: $(psql -X -At -d postgres -c 'SHOW server_version')"

for db in "$db_empty" "$db_fixture"; do
  psqlq -d postgres -c "DROP DATABASE IF EXISTS $db" -c "CREATE DATABASE $db"
done

# --- empty database, no storage schema -------------------------------------

out="$(run_audit "$db_empty" 2>&1)" && rc=0 || rc=$?
if [ "$rc" -ne 0 ]; then bad "empty database: audit errored"; echo "$out"
elif [ -n "$out" ]; then bad "empty database: expected zero rows, got:"; echo "$out"
else ok "empty database, no storage schema: zero rows, no error"; fi

# --- fixture ---------------------------------------------------------------
psqlq -d "$db_fixture" -f "$here/fixture.sql" >/dev/null

before="$(psql -X -At -d "$db_fixture" -c "SELECT count(*) FROM pg_class")"
full="$(run_audit_full "$db_fixture" 2>&1)" && rc=0 || rc=$?
after="$(psql -X -At -d "$db_fixture" -c "SELECT count(*) FROM pg_class")"

if [ "$rc" -ne 0 ]; then
  bad "fixture: audit errored inside BEGIN READ ONLY"; echo "$full"
else
  ok "audit ran inside BEGIN READ ONLY ... ROLLBACK"
  [ "$before" = "$after" ] && ok "pg_class unchanged by the audit ($before rows)" \
                           || bad "pg_class changed: $before -> $after"

  out="$(printf '%s\n' "$full" | cut -d'|' -f1-3)"

  # Exact ordered match: every bad object flagged with the expected check and
  # severity, and nothing else flagged.
  if diff <(printf '%s\n' "$out") "$here/expected.txt" >/dev/null; then
    ok "findings match expected.txt exactly ($(wc -l < "$here/expected.txt" | tr -d ' ') rows)"
  else
    bad "findings differ from expected.txt (< actual, > expected)"
    diff <(printf '%s\n' "$out") "$here/expected.txt" || true
  fi

  # Explicit: every bad_* name in the fixture shows up in the output (as an
  # object, or in a table list in the fix column), independent of expected.txt.
  missing=""
  for name in $(grep -oE '(^|[^a-z0-9_])bad_[a-z0-9_]+' "$here/fixture.sql" | sed -E 's/^[^b]//' | sort -u); do
    printf '%s\n' "$full" | grep -q -- "$name" || missing="$missing $name"
  done
  if [ -z "$missing" ]; then ok "every bad_* object in the fixture is reported"
  else bad "bad_* objects not reported:$missing"; fi

  # Explicit: no good twin anywhere in the output (including table lists in the
  # fix column), nothing from an excluded schema, and no partition of a parent
  # that has RLS off (the parent itself is reported).
  if printf '%s\n' "$full" | grep -q 'good_'; then
    bad "a good twin was flagged or listed:"
    printf '%s\n' "$full" | grep 'good_'
  else
    ok "no good twin flagged or listed"
  fi
  if printf '%s\n' "$out" | grep -Eq 'excluded|auth\.|vault\.|child_of_'; then
    bad "an excluded-schema object or a partition of an unprotected parent was flagged:"
    printf '%s\n' "$out" | grep -E 'excluded|auth\.|vault\.|child_of_'
  else
    ok "no excluded-schema object, and no partition of an unprotected parent, flagged"
  fi

  # Full five-column output is well formed: five populated fields, valid severity.
  if printf '%s\n' "$full" | awk -F'|' 'NF != 5 || $1 !~ /^(high|medium|low)$/ || $2=="" || $3=="" || $4=="" || $5=="" {exit 1}'; then
    ok "all five columns populated, severities valid"
  else
    bad "malformed rows in full output"
  fi

  # Item 1: with auth on the search_path Postgres prints uid() instead of
  # auth.uid(). The findings must not change.
  sp_full="$(run_audit_full "$db_fixture" "SET LOCAL search_path = auth, public;" 2>&1)" && rc=0 || rc=$?
  if [ "$rc" -eq 0 ] && [ "$sp_full" = "$full" ]; then
    ok "identical findings with auth on the search_path"
  else
    bad "findings change with auth on the search_path (< with auth, > default)"
    diff <(printf '%s\n' "$sp_full") <(printf '%s\n' "$full") || true
  fi

  # Wording that the review asked for.
  expect_text policy_using_true 'public.bad_check_true_update policy "bad_check_true_update_p"' \
    'save any values in the rows they can update' 'every row'
  expect_text policy_using_true 'public.bad_true_update policy "bad_true_update_p"' \
    'update every row with any values'
  expect_text policy_using_true 'public.bad_true_select policy "bad_true_select_p"' \
    'read every row' 'any values'
  expect_text policy_not_tied_to_caller 'public.bad_logged_in_only policy "bad_logged_in_only_p"' \
    'only condition is that the caller is signed in'
  expect_text policy_not_tied_to_caller 'public.bad_logged_in_check policy "bad_logged_in_check_p"' \
    'WITH CHECK condition only checks that the caller is signed in.*save any values'
  expect_text policy_not_tied_to_caller 'public.bad_public_update policy "bad_public_update_p"' \
    'applies to everyone.*anyone with your public API key can update'
  expect_text rls_disabled 'app.bad_app_rls_off' \
    'can read every row' 'change'
  expect_text storage_policy_using_true 'storage.objects policy "bad_storage_anon_upload"' \
    'upload files'
  expect_text materialized_view_exposed 'public.bad_matview' \
    'cannot have RLS'
  expect_text storage_bucket_no_limits 'storage bucket "bad_no_limits_bucket"' \
    'sets no file size limit .*project-wide upload limit' 'any size'
  expect_text rls_no_policies '2 tables in public' \
    'Confirm each is meant to be server-only: bad_rls_no_policy, bad_rls_no_policy_2\.'
  expect_text rls_no_policies '1 table in app' \
    'Confirm it is meant to be server-only: bad_app_no_policy\.'
  expect_text security_definer_rls_helper 'public.bad_secdef_helper()' \
    "^low\\|.*RLS helper callable through the API.*Confirm it only returns the caller's own data, or move it to a schema the API does not expose"
  # Round 2
  expect_text partition_rls_disabled 'public.bad_part_open_2025' \
    '^medium\|.*RLS is off on this partition\. Queries through the parent table are protected, but anything that reads the partition directly bypasses RLS\.\|Run: ALTER TABLE public\.bad_part_open_2025 ENABLE ROW LEVEL SECURITY; no policies are needed, access through the parent keeps working\.$'
  expect_text policy_not_tied_to_caller 'public.bad_role_authed policy "bad_role_authed_p"' \
    'only condition is that the caller is signed in'
  expect_text policy_not_tied_to_caller 'public.bad_role_public_update policy "bad_role_public_update_p"' \
    'only condition is that the caller is signed in.*can update'
  expect_text policy_not_tied_to_caller 'public.bad_anon_update policy "bad_anon_update_p"' \
    'anyone with your public API key can update'
  expect_text security_definer_executable 'public.bad_secdef_service_only()' \
    '^medium\|.*can bypass RLS' 'RLS helper'
  # Round 3
  expect_text partition_rls_disabled 'public.bad_srv_part_2025' \
    '^medium\|.*RLS is off on this partition and no table above it is protected, so anything that reads the partition directly gets every row\. The API cannot reach its parent table, but new partitions pick up your default grants\.\|Run: ALTER TABLE public\.bad_srv_part_2025 ENABLE ROW LEVEL SECURITY; no policies are needed if only your server should read it\.$'
  expect_text partition_rls_disabled 'public.bad_nest_leaf_2025' \
    'RLS is off on this partition and on its parent\. Queries through the table above them that has RLS on are protected' \
    'Queries through the parent table are protected'
fi

# --- storage schema present but not Supabase-shaped -> must not error --------
psqlq -d "$db_empty" -c "CREATE SCHEMA storage; CREATE TABLE storage.buckets (id text);"
out="$(run_audit "$db_empty" 2>&1)" && rc=0 || rc=$?
if [ "$rc" -eq 0 ] && [ -z "$out" ]; then ok "odd storage.buckets shape: guarded, zero rows, no error"
else bad "odd storage.buckets shape"; echo "$out"; fi

echo
[ "$fail" -eq 0 ] && echo "ALL TESTS PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
