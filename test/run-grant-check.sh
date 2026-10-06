#!/usr/bin/env bash
# Loads grant-fixture.sql into a throwaway database, runs ../rowwarden-grant-check.sql inside
# BEGIN READ ONLY, and compares the findings with grant-expected.txt.
# Uses libpq env vars (PGHOST, PGPORT, PGUSER=postgres) for a SCRATCH superuser connection.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
db="grant_check_test"
psqlq() { psql -X -q -v ON_ERROR_STOP=1 "$@"; }
dropdb --if-exists "$db"; createdb "$db"
psqlq -d "$db" -f "$here/grant-fixture.sql" >/dev/null
out="$({ echo "BEGIN READ ONLY;"; echo "\\pset format unaligned"; echo "\\pset tuples_only on";
         echo "\\pset fieldsep '|'"; cat "$here/../rowwarden-grant-check.sql"; echo "ROLLBACK;"; } | psqlq -d "$db")"
got="$(printf '%s\n' "$out" | cut -d'|' -f1-3)"
if diff -u "$here/grant-expected.txt" <(printf '%s\n' "$got"); then echo "PASS  findings match grant-expected.txt"; else echo "FAIL  findings differ"; fail=1; fi
printf '%s\n' "$out" | grep -q 'bad_new_id_seq' && echo "PASS  sequence grant included in bad_new fix" || { echo "FAIL  bad_new fix lacks sequence grant"; fail=1; }
printf '%s\n' "$out" | grep -q 'good_' && { echo "FAIL  a good_ object was flagged"; fail=1; } || echo "PASS  no good_ object flagged"
printf '%s\n' "$out" | awk -F'|' 'NF!=5 || $4=="" || $5=="" {bad=1} END {exit bad}' && echo "PASS  every row has 5 populated columns" || { echo "FAIL  empty column"; fail=1; }
empty="grant_check_empty"; dropdb --if-exists "$empty"; createdb "$empty"
n="$({ echo "BEGIN READ ONLY;"; cat "$here/../rowwarden-grant-check.sql"; echo "ROLLBACK;"; } | psqlq -At -d "$empty" | wc -l | tr -d ' ')"
# roles are cluster-wide, so the empty database still has the API roles: expect only the mode row
[ "$n" = 1 ] && echo "PASS  empty database returns only the mode row" || { echo "FAIL  empty db returned $n rows"; fail=1; }
psqlq -d "$empty" -c "alter default privileges for role postgres in schema public grant select, insert, update, delete on tables to anon, authenticated, service_role;"
m="$({ echo "BEGIN READ ONLY;"; cat "$here/../rowwarden-grant-check.sql"; echo "ROLLBACK;"; } | psqlq -At -d "$empty")"
printf '%s\n' "$m" | grep -q '^mode|auto_grant|new tables in public|Old behaviour' && echo "PASS  pre-switch project reports Old behaviour" || { echo "FAIL  pre-switch mode row wrong: $m"; fail=1; }
printf '%s\n' "$out" | grep '|public.bad_new_rls_off|' | grep -q -- '-- optional, only if signed-in users should reach it: alter table public.bad_new_rls_off enable row level security' && echo "PASS  RLS-off table: authenticated grant is optional and preceded by enable RLS" || { echo "FAIL  bad_new_rls_off fix unsafe"; fail=1; }
printf '%s\n' "$out" | grep '|public.bad_new|' | grep -q '^check|no_api_grant|public.bad_new|.*|grant select, insert, update, delete on public.bad_new to service_role; grant usage, select on sequence public.bad_new_id_seq to service_role; -- optional' && echo "PASS  service_role grant first, authenticated optional" || { echo "FAIL  bad_new fix shape"; fail=1; }
printf '%s\n' "$out" | grep '|public.bad_new_view|' | grep -q 'security_invoker' && echo "PASS  view row warns about security_invoker" || { echo "FAIL  view row lacks security_invoker warning"; fail=1; }
printf '%s\n' "$out" | grep '|public.bad_new_matview|' | grep -q 'cannot have RLS' && echo "PASS  matview row warns it cannot have RLS" || { echo "FAIL  matview warning missing"; fail=1; }
g="grant_check_global"; dropdb --if-exists "$g"; createdb "$g"
psqlq -d "$g" -c "alter default privileges for role postgres grant select, insert, update, delete on tables to anon, authenticated, service_role;"
m2="$({ echo "BEGIN READ ONLY;"; cat "$here/../rowwarden-grant-check.sql"; echo "ROLLBACK;"; } | psqlq -At -d "$g")"
printf '%s\n' "$m2" | grep -q '^mode|auto_grant|new tables in public|Old behaviour' && echo "PASS  global default privileges count as Old behaviour" || { echo "FAIL  global defaults: $m2"; fail=1; }
dropdb "$g"
dropdb "$db"; dropdb "$empty"
exit "${fail:-0}"
