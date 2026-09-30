# Tests

`run.sh` loads `fixture.sql` into a throwaway database, runs `../rowwarden-rls-audit.sql`, and checks the result.

The fixture mimics Supabase: roles `anon`, `authenticated`, `service_role`; Supabase's default grants (`USAGE` on `public`, and default privileges so every table, view and function created there is granted to the API roles); a stub `auth` schema with `auth.uid()`, `auth.jwt()` and `auth.email()`; a `storage` schema with Supabase's bucket columns and a `storage.objects` table with RLS on. It has `bad_*` objects that must be flagged and `good_*` twins that must not, plus objects in excluded schemas, in a schema the API roles cannot use, and partitions of a parent with RLS off, none of which may be flagged.

What is asserted:

- The audit runs inside `BEGIN READ ONLY; ... ROLLBACK;` without error, and `pg_class` is unchanged afterwards.
- The findings match `expected.txt` exactly (severity, check, object, in order).
- Every `bad_*` name in the fixture appears in the output and no `good_*` name does. Both are checked across all five columns, so the table list in `rls_no_policies` counts. Nothing from an excluded schema and no partition of a parent with RLS off is flagged.
- All five output columns are populated and severities are valid.
- Running again with `auth` on the `search_path` (where Postgres prints `uid()` instead of `auth.uid()`) gives identical output.
- Specific wording: which side of a policy is `true`, the signed-in-only messages (including `auth.role()`), the anon write message, the bucket no-limits message, the per-schema `rls_no_policies` row and its table list, the RLS helper message, and all three `partition_rls_disabled` messages (protected parent, protected table further up, unreachable parent).
- An empty database with no `storage` schema returns zero rows and no error. So does one with a `storage.buckets` table that lacks Supabase's columns.

Regression cases, marked `(item N)` in `fixture.sql`:

1. Calls to `auth.uid()`, `auth.jwt()` and `auth.email()` are found through `pg_depend`, not by matching text: the `search_path` re-run gives the same output, and a string that merely contains "auth.uid()" does not count.
2. Trigger and event-trigger functions and procedures are not reported as callable.
3. Only reachable objects are reported: nothing in a schema without `USAGE`, nothing whose grants were revoked, and a single-column grant is enough. A partitioned table with RLS off is reported once, through its parent.
4. Signed-in-only conditions (either side, plain or `(select ...)`) and write policies with no `TO` clause are caught; a public read and owner-tied policies are not.
5. Restrictive policies are ignored.
6. `WITH CHECK (true)` with an owner-tied `USING` is described as "any values", not "every row".
7. Materialized views and foreign tables the API can reach are reported; locked-down ones are not.
8. Policies on `storage.objects` are checked.
9. Extension-owned views and functions are skipped; the bucket no-limits message no longer claims uploads of any size are accepted.
10. A policy that calls a helper whose body uses `auth.uid()` counts as tied to the caller, for plain and `BEGIN ATOMIC` bodies; a helper that never looks at the caller does not.
11. `rls_no_policies` is one row per schema; a `SECURITY DEFINER` function used by a policy is reported as a low `security_definer_rls_helper`, and not at all when the API cannot use its schema.

Second-round cases, marked `(round 2, item N)`:

1. Partitions are checked: RLS off on a partition under a parent with RLS on is a medium `partition_rls_disabled`, and a partition's own `USING (true)` policy is reported. A partition with RLS on, or with no API grants, is not.
2. `auth.role() = 'authenticated'` counts as a signed-in-only test (plain, cast, `(select ...)`, either way round). `auth.role()` itself does not tie rows to the caller, and a policy only `service_role` can pass is not reported. A public-schema helper that reads `auth.uid()` still counts as tied to the caller.
3. Covered in the README: a helper whose body mentions the caller functions counts as tied, even if it only checks that someone is signed in. In the fixture, the string "request.jwt.claims" in a policy is not reading the claims, while `current_setting('request.jwt.claims')` is.
4. Write policies `TO anon` that never tie rows to anything are reported, like the same policy with no `TO` clause. An anon write tied to a token claim is not.
5. A `SECURITY DEFINER` function used only by a policy the API cannot reach (`service_role` only, or on an unreachable table) stays a medium `security_definer_executable`. One used by a reachable restrictive policy is a low `security_definer_rls_helper`.

Third-round cases, marked `(round 3, item N)`:

1. A partition with RLS off is reported as a medium `partition_rls_disabled` (same severity as the protected-parent case) when no table above it has RLS on and the API cannot reach its parent: a server-only parent with revoked grants, a parent in a schema the API cannot use, and a leaf two levels under unreachable tables. A reachable middle table is reported once and covers the leaf under it. Partitions with RLS on, or without API grants, are not reported.
2. Nested partitions are found in one run: under a protected top-level table, both a middle table with RLS off and a leaf under it are `partition_rls_disabled`, and the leaf's message says its parent is unprotected too. A leaf with RLS on is not reported.

## Run

Point the standard libpq variables at a SCRATCH Postgres server (15 or later) where the user is a superuser. The script creates `rls_audit_test_empty` and `rls_audit_test_fixture` and drops them when it finishes. Do not point it at a real project. For example, with a throwaway container:

```bash
docker run -d --name rls-audit-pg -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:5432:5432 postgres:17
export PGHOST=localhost PGPORT=5432 PGUSER=postgres PGPASSWORD=postgres
./run.sh
```

Needs only `bash` and `psql` besides the scratch server. Roles are cluster-wide, so the fixture creates `anon`, `authenticated` and `service_role` on the scratch server if they do not exist. Superuser is needed for the fixture's foreign-data wrapper and for marking two objects as extension members.
