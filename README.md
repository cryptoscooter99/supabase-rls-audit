# Supabase RLS self-audit (by RowWarden)

A single SQL file that checks your own Supabase project for common Row Level Security mistakes. It reads your database catalog and returns one table of findings. It does not change anything.

## 1. Run it

1. Open your project in Supabase, then **SQL Editor**.
2. Paste the whole contents of [`rowwarden-rls-audit.sql`](rowwarden-rls-audit.sql) and run it.

You get one result set with these columns: `severity` (high / medium / low), `check`, `object`, `why_it_matters`, `fix`. Zero rows means nothing was flagged. That is the floor, not proof your app is safe (see Limits).

The file is a single `SELECT` that only reads `pg_catalog` and, if it exists, `storage.buckets`. It creates nothing and writes nothing, and it runs fine inside `BEGIN READ ONLY; ... ROLLBACK;`. It needs Postgres 15 or later (Supabase runs 15 and 17). It looks at every schema except Supabase's own (`auth`, `storage`, `extensions`, `graphql`, `graphql_public`, `realtime`, `supabase_functions`, `vault`, `pgsodium`, `net`, `cron`, `_realtime`, `supabase_migrations`) and Postgres system schemas. `public` is the main one. One exception: the policies on `storage.objects` decide who can upload, download and delete files, so they are checked too.

It only reports what the API can reach (bucket settings aside). An object counts when `anon` or `authenticated` has `USAGE` on its schema and a privilege on the object: a grant on some of a table's columns is enough, and for a function it is `EXECUTE`. A table whose API grants you revoked, or anything in a schema the API roles cannot use, is not reported. A partitioned table is checked through its parent, and a partition with RLS off is normally covered by its parent's finding. A partition with RLS off is reported on its own (`partition_rls_disabled`) when a table above it (at any depth) has RLS on, or when no table above it has RLS on and the API cannot reach its parent. Its own policies are checked like any table's.

## 2. What each check means

| Severity | Check | What it means | How to fix |
|---|---|---|---|
| high | `rls_disabled` | Row Level Security is off and `anon` or `authenticated` has privileges on the table, so they can read (and, with write grants, change) every row through the API. The message says who can do what. Partitions are reported under `partition_rls_disabled` instead. | `ALTER TABLE schema.table ENABLE ROW LEVEL SECURITY;` then add policies for the access you want. |
| medium | `partition_rls_disabled` | A partition the API can reach has RLS off. Either a table above it (its parent, or one further up) has RLS on, so queries through that table are protected but anything that reads the partition directly bypasses RLS. Or no table above it is protected and the API cannot reach its parent, for example a server-only table whose grants you revoked: new partitions still pick up your default grants, so anything that reads the partition directly gets every row. Medium in both cases because it is not certain the API serves a partition by name. | `ALTER TABLE schema.partition ENABLE ROW LEVEL SECURITY;` No policies are needed: access through a protected parent keeps working, and a server-only table needs none. |
| low | `rls_no_policies` | RLS is on but there are no policies, so anon and signed-in users get nothing. That is correct for server-only tables and a bug for everything else. Reported as one row per schema (`3 tables in public`), with the table names in the fix column. | Confirm each listed table is meant to be server-only. If the app needs one, add a policy scoped to the owning user. |
| high / medium | `policy_using_true` | A permissive policy for `anon`, `authenticated` or `public` has `USING (true)` or `WITH CHECK (true)`. High when it covers INSERT, UPDATE, DELETE or ALL, medium for SELECT. The message says which side is `true`: `USING (true)` means every row is visible or affected; `WITH CHECK (true)` means any values can be written, for example handing a row to another user. Restrictive policies and policies for other roles such as `service_role` are not flagged. | Replace the `true` with a condition tied to the row owner, e.g. `(select auth.uid()) = user_id`, or limit the policy to a server-side role. |
| medium | `policy_not_tied_to_caller` | A permissive policy lets users reach rows that are not theirs. Three cases: its `USING` or `WITH CHECK` only checks that the caller is signed in (`auth.uid() IS NOT NULL` or `auth.role() = 'authenticated'`), so "logged in" means "allowed"; it is for `authenticated` and never uses `auth.uid()`, `auth.jwt()` or `auth.email()`; or it is for everyone (no `TO` clause) or for `anon`, covers INSERT, UPDATE, DELETE or ALL, and never ties rows to the caller. A policy that calls a helper function whose body mentions `auth.uid()`, `auth.jwt()`, `auth.email()` or JWT claims counts as tied to the caller, even if the helper only checks that someone is signed in. Review your helper functions by hand. A read policy for everyone or for `anon` is treated as a deliberate public read unless its only condition is the signed-in test. A policy no API user can pass, such as `auth.role() = 'service_role'`, is skipped. | Tie the condition to the caller, e.g. `(select auth.uid()) = user_id`. For a policy with no `TO` clause or `TO anon`, also switch to `TO authenticated` unless signed-out visitors really need it. |
| medium | `view_not_security_invoker` | A view the API can reach runs with its owner's rights by default, so it can expose rows that RLS on the underlying tables would hide. Views that belong to an extension are skipped. | `ALTER VIEW schema.view SET (security_invoker = true);` |
| medium | `materialized_view_exposed` | `anon` or `authenticated` can read a materialized view. Materialized views cannot have RLS, so every row is visible to them. | If that is not intended, `REVOKE SELECT ON schema.view FROM PUBLIC, anon, authenticated;` or move it to a schema the API does not expose. |
| medium | `foreign_table_exposed` | `anon` or `authenticated` has privileges on a foreign table. Foreign tables cannot have RLS, so they can read (or change) every row. | If that is not intended, `REVOKE ALL ON schema.table FROM PUBLIC, anon, authenticated;` or move it to a schema the API does not expose. |
| medium | `security_definer_executable` | A `SECURITY DEFINER` function can be called by `anon` or `authenticated` through the API. It runs with its owner's rights and can bypass RLS. Postgres grants execute to everyone by default. Trigger and event-trigger functions and procedures are skipped because the API cannot call them, and extension functions because you do not maintain them. | `REVOKE EXECUTE ON FUNCTION ... FROM PUBLIC, anon, authenticated;` or make it `SECURITY INVOKER`. |
| low | `security_definer_rls_helper` | Same as above, but a policy that `anon` or `authenticated` can reach uses the function, so it is an RLS helper that the API can also call directly. A policy the API never reaches, such as one for `service_role` only, does not count. | Confirm it only returns the caller's own data, or move it to a schema the API does not expose. |
| high / medium | `storage_policy_using_true` | `policy_using_true` for a policy on `storage.objects`. For example `TO anon WITH CHECK (true)` lets anyone upload to any bucket and path, and `USING (true)` on SELECT lets anyone download every file, private buckets included. | Replace the `true` with a condition on the bucket and the file owner, e.g. `bucket_id = 'avatars' AND owner_id = (select auth.uid()::text)`. |
| medium | `storage_policy_not_tied_to_caller` | `policy_not_tied_to_caller` for a policy on `storage.objects`: signed-in users (or everyone) can reach other users' files. | Tie the condition to the file owner, e.g. `owner_id = (select auth.uid()::text)`. |
| low | `storage_bucket_public` | The bucket is public: anyone with a file URL can download it without logging in. | Confirm it is intended. Otherwise make it private and use signed URLs. |
| low | `storage_bucket_no_limits` | The bucket sets no `file_size_limit` or no `allowed_mime_types` of its own. Without a size limit only your project-wide upload limit applies; without allowed types any file type is accepted. | Set them on the bucket to what your app needs. |

Not flagged on purpose: a table with RLS enabled but not `FORCE`d. The table owner bypassing RLS is normal on Supabase. Restrictive policies are not checked either: they can only narrow access.

Policies that are literally `true` are reported once, under `policy_using_true` (or `storage_policy_using_true`), not again under the `not_tied_to_caller` checks.

## 3. Limits

- It is catalog-only. It cannot see your API routes, edge functions, keys, webhooks, secrets, or anything outside this database.
- "The API can reach it" is judged from schema `USAGE` and grants. The script cannot read your API settings, so an object in a schema `anon` can use but that you have not exposed is still reported.
- It flags patterns, not intent. Some findings will be deliberate (a public marketing bucket, a read-only lookup table).
- A policy that calls a helper function whose body mentions `auth.uid()`, `auth.jwt()`, `auth.email()` or JWT claims counts as tied to the caller, even if the helper only checks that someone is signed in. Review your helper functions by hand.
- It looks at a policy as a whole: if either `USING` or `WITH CHECK` is tied to the caller, the policy counts as tied.
- The signed-in tests it recognises are `auth.uid() IS NOT NULL` (or the `auth.jwt()` / `auth.email()` versions) and `auth.role() = 'authenticated'`, written plainly, with a cast, or as `(select ...)`. Other ways of writing the same thing are not caught.
- It does not evaluate what your policy expressions actually allow beyond the checks above.
- **Zero rows is not a clean bill of health.** A policy can look fine and still be wrong.

## 4. Want a human-signed review?

The script only sees your database catalog. [RowWarden](https://rowwarden.com) reviews the whole app: RLS and grants, auth settings, API routes, exposed keys and Stripe webhooks. You get a written report ranked by impact plus a pull request with fixes, within 48 hours, for a fixed $249. The review is done by an AI agent (Rowan) and every finding is signed off by a human before you see it. Nothing is touched until you sign a one-page scope, and production stays read-only.

Questions: rowan@rowwarden.com

## Tests and license

Tests live in [`test/`](test/README.md). MIT license, copyright Fleur Collective, L.L.C. (see [`LICENSE`](LICENSE)).
