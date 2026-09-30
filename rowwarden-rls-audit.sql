-- RowWarden RLS self-audit for Supabase / Postgres
--
-- What it does
--   Inspects the catalog of the database you run it in and returns ONE result
--   set of findings: severity (high / medium / low), check, object,
--   why_it_matters, fix. Zero rows means nothing was flagged. That is the
--   floor, not proof of safety (see README.md).
--
--   Apart from storage bucket settings, it only reports objects the API roles
--   can reach: anon or authenticated must have USAGE on the schema and a
--   privilege on the object. Policies on storage.objects are checked too.
--
-- Read-only, safe to run
--   A single SELECT. It only reads pg_catalog and, if present, storage.buckets.
--   It creates nothing, changes nothing, and can run inside
--   BEGIN READ ONLY; ... ROLLBACK;
--   (The storage.buckets read goes through query_to_xml() so the script does
--   not fail on projects that have no storage schema. That is a built-in
--   function running a fixed SELECT, not something this script creates.)
--
-- How to use
--   Paste this whole file into your own project's SQL Editor and run it.
--   Nothing leaves your database.
--
-- Free from RowWarden: https://rowwarden.com

WITH
-- Every non-system schema. `public` is the main case.
schemas AS (
  SELECT n.oid AS nsp_oid, n.nspname AS nsp
  FROM pg_catalog.pg_namespace n
  WHERE left(n.nspname, 3) <> 'pg_'
    AND n.nspname NOT IN (
      'information_schema', 'auth', 'storage', 'extensions', 'graphql',
      'graphql_public', 'realtime', 'supabase_functions', 'vault',
      'pgsodium', 'net', 'cron', '_realtime', 'supabase_migrations'
    )
),

-- The roles the API runs requests as. If they do not exist, nothing is
-- reachable and nothing is reported.
api_roles AS (
  SELECT r.oid AS role_oid, r.rolname
  FROM pg_catalog.pg_roles r
  WHERE r.rolname IN ('anon', 'authenticated')
),

-- Relations to inspect: tables, partitioned tables, partitions, views,
-- materialized views and foreign tables in those schemas, plus storage.objects
-- (only its policies are checked). A partition with RLS off is reported when
-- a table above it has RLS on, or when the API cannot reach its parent;
-- otherwise its parent's finding covers it. Its own policies are checked too.
rels AS (
  SELECT c.oid AS rel_oid, c.relnamespace AS nsp_oid, n.nspname AS nsp,
         c.relname, c.relkind, c.relrowsecurity AS rls_on, c.reloptions,
         c.relispartition AS is_part,
         -- RLS on anywhere above this partition, at any depth.
         (c.relispartition
          AND EXISTS (SELECT 1 FROM pg_catalog.pg_partition_ancestors(c.oid) a
                      JOIN pg_catalog.pg_class pc ON pc.oid = a.relid
                      WHERE a.relid <> c.oid
                        AND pc.relrowsecurity)) AS ancestor_rls_on,
         -- RLS on the table directly above it (only picks the wording).
         -- EXISTS rather than a scalar subquery: a table with several
         -- (legacy inheritance) parents must not make the script fail.
         (c.relispartition
          AND EXISTS (SELECT 1 FROM pg_catalog.pg_inherits i
                      JOIN pg_catalog.pg_class pc ON pc.oid = i.inhparent
                      WHERE i.inhrelid = c.oid
                        AND pc.relrowsecurity)) AS parent_rls_on,
         (c.oid = pg_catalog.to_regclass('storage.objects')) IS TRUE AS is_storage,
         EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                 WHERE d.classid = 'pg_catalog.pg_class'::regclass
                   AND d.objid = c.oid
                   AND d.deptype = 'e') AS ext_owned
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE (c.relnamespace IN (SELECT nsp_oid FROM schemas)
         AND c.relkind IN ('r', 'p', 'v', 'm', 'f'))
     OR c.oid = pg_catalog.to_regclass('storage.objects')
),

-- What each API role can do with each relation: it needs USAGE on the schema
-- and a privilege on the relation (a grant on some of its columns counts).
rel_role AS (
  SELECT x.rel_oid, r.role_oid, r.rolname,
         u.ok AND pg_catalog.has_any_column_privilege(r.role_oid, x.rel_oid, 'SELECT') AS can_select,
         u.ok AND pg_catalog.has_any_column_privilege(r.role_oid, x.rel_oid, 'INSERT') AS can_insert,
         u.ok AND pg_catalog.has_any_column_privilege(r.role_oid, x.rel_oid, 'UPDATE') AS can_update,
         u.ok AND pg_catalog.has_table_privilege(r.role_oid, x.rel_oid, 'DELETE')      AS can_delete
  FROM rels x
  CROSS JOIN api_roles r
  CROSS JOIN LATERAL (
    SELECT pg_catalog.has_schema_privilege(r.role_oid, x.nsp_oid, 'USAGE') AS ok
  ) u
),

-- Relations that anon or authenticated can reach, and how.
reach AS (
  SELECT x.*, a.anon_read, a.anon_write, a.auth_read, a.auth_write,
         CASE WHEN a.anon_read OR a.anon_write
              THEN 'anyone with your public API key'
              ELSE 'any signed-in user' END AS who
  FROM rels x
  JOIN (
    SELECT rr.rel_oid,
           coalesce(bool_or(rr.can_select)
                    FILTER (WHERE rr.rolname = 'anon'), false)          AS anon_read,
           coalesce(bool_or(rr.can_insert OR rr.can_update OR rr.can_delete)
                    FILTER (WHERE rr.rolname = 'anon'), false)          AS anon_write,
           coalesce(bool_or(rr.can_select)
                    FILTER (WHERE rr.rolname = 'authenticated'), false) AS auth_read,
           coalesce(bool_or(rr.can_insert OR rr.can_update OR rr.can_delete)
                    FILTER (WHERE rr.rolname = 'authenticated'), false) AS auth_write
    FROM rel_role rr
    GROUP BY rr.rel_oid
  ) a ON a.rel_oid = x.rel_oid
  WHERE a.anon_read OR a.anon_write OR a.auth_read OR a.auth_write
),

-- Functions each policy calls. Read from pg_depend, so it does not matter how
-- the expression prints or what the search_path is.
pol_fn AS (
  SELECT d.objid AS pol_oid, d.refobjid AS fn_oid
  FROM pg_catalog.pg_depend d
  WHERE d.classid = 'pg_catalog.pg_policy'::regclass
    AND d.refclassid = 'pg_catalog.pg_proc'::regclass
),

-- Supabase's "who is calling" functions. Missing ones are skipped.
caller_fn AS (
  SELECT f.fn_oid
  FROM (VALUES (pg_catalog.to_regprocedure('auth.uid()')::oid),
               (pg_catalog.to_regprocedure('auth.jwt()')::oid),
               (pg_catalog.to_regprocedure('auth.email()')::oid)) AS f(fn_oid)
  WHERE f.fn_oid IS NOT NULL
),

-- Supabase's auth.role(). It is not a caller function: it only says anon,
-- authenticated or service_role. "auth.role() = 'authenticated'" is treated
-- as a signed-in test below.
role_fn AS (
  SELECT f.fn_oid
  FROM (VALUES (pg_catalog.to_regprocedure('auth.role()')::oid)) AS f(fn_oid)
  WHERE f.fn_oid IS NOT NULL
),

-- Functions called by a policy that tie rows to the caller: the caller
-- functions themselves, or a helper in one of your schemas whose own body
-- uses them or the request's JWT claims (one hop; SQL-standard BEGIN ATOMIC
-- bodies are read through pg_depend). Other functions in auth, such as
-- auth.role(), do not count.
caller_scoped_fn AS (
  SELECT f.oid AS fn_oid
  FROM pg_catalog.pg_proc f
  WHERE f.oid IN (SELECT fn_oid FROM pol_fn)
    AND (f.oid IN (SELECT fn_oid FROM caller_fn)
         OR (f.pronamespace IN (SELECT nsp_oid FROM schemas)
             AND (f.prosrc ~* '(auth[[:space:]]*\.[[:space:]]*(uid|jwt|email)[[:space:]]*\(|request\.jwt\.claim)'
                  OR EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                             WHERE d.classid = 'pg_catalog.pg_proc'::regclass
                               AND d.objid = f.oid
                               AND d.refclassid = 'pg_catalog.pg_proc'::regclass
                               AND d.refobjid IN (SELECT fn_oid FROM caller_fn)))))
),

-- For each policy: whether it applies to anon / authenticated (PUBLIC, the
-- role itself, or a role it inherits) and whether that role also holds the
-- privilege the policy's command needs. If not, the policy never comes into
-- play through the API.
pol_reach AS (
  SELECT p.oid AS pol_oid,
         coalesce(bool_or(x.named) FILTER (WHERE rr.rolname = 'authenticated'), false) AS to_authenticated,
         coalesce(bool_or(x.named) FILTER (WHERE rr.rolname = 'anon'), false)          AS to_anon,
         coalesce(bool_or(x.hit)   FILTER (WHERE rr.rolname = 'anon'), false)          AS anon_reach,
         coalesce(bool_or(x.hit)   FILTER (WHERE rr.rolname = 'authenticated'), false) AS auth_reach
  FROM pg_catalog.pg_policy p
  JOIN rel_role rr ON rr.rel_oid = p.polrelid
  CROSS JOIN LATERAL (
    SELECT n.named,
           (0 = ANY (p.polroles) OR n.named)
           AND CASE p.polcmd
                 WHEN 'r' THEN rr.can_select
                 WHEN 'a' THEN rr.can_insert
                 WHEN 'w' THEN rr.can_update
                 WHEN 'd' THEN rr.can_delete
                 ELSE rr.can_select OR rr.can_insert OR rr.can_update OR rr.can_delete
               END AS hit
    FROM (SELECT EXISTS (SELECT 1 FROM unnest(p.polroles) AS pr(role_oid)
                         WHERE pr.role_oid <> 0
                           AND pg_catalog.pg_has_role(rr.role_oid, pr.role_oid, 'USAGE')) AS named) n
  ) x
  GROUP BY p.oid
),

-- Permissive policies the API roles can reach. Restrictive policies only
-- narrow access, so they are not checked.
pol AS (
  SELECT p.oid AS pol_oid, t.nsp, t.relname, t.is_storage, p.polname, p.polcmd,
         coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), '')      AS using_expr,
         coalesce(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '') AS check_expr,
         (0 = ANY (p.polroles)) AS to_public,
         r.to_authenticated, r.to_anon, r.anon_reach, r.auth_reach,
         EXISTS (SELECT 1 FROM pol_fn pf
                 WHERE pf.pol_oid = p.oid
                   AND pf.fn_oid IN (SELECT fn_oid FROM caller_scoped_fn)) AS fn_scoped,
         EXISTS (SELECT 1 FROM pol_fn pf
                 WHERE pf.pol_oid = p.oid
                   AND pf.fn_oid IN (SELECT fn_oid FROM role_fn)) AS role_used
  FROM pg_catalog.pg_policy p
  JOIN rels t ON t.rel_oid = p.polrelid
  JOIN pol_reach r ON r.pol_oid = p.oid
  WHERE p.polpermissive
    AND (r.anon_reach OR r.auth_reach)
),

pol2 AS (
  SELECT p.*,
         (p.using_expr = 'true') AS using_true,
         -- An UPDATE or ALL policy without WITH CHECK reuses its USING.
         (p.check_expr = 'true'
          OR (p.polcmd IN ('w', '*') AND p.check_expr = '' AND p.using_expr = 'true')) AS check_true,
         -- Tied to the caller: through a caller function or helper, or by
         -- reading the JWT claims with current_setting() directly. That call is
         -- matched in the printed expression, because pg_depend does not record
         -- built-in functions; a string literal cannot print this way.
         (p.fn_scoped
          OR (p.using_expr || ' ' || p.check_expr) ~* 'current_setting\(''request\.jwt\.claim') AS caller_scoped,
         -- A side that only checks that the caller is signed in:
         -- auth.uid() (or auth.jwt(), auth.email()) IS NOT NULL, or
         -- auth.role() = 'authenticated', in any printed form.
         ((p.fn_scoped AND n.u ~ '^(select)?(auth\.)?(uid|jwt|email)(as[a-z0-9_]+)?isnotnull$')
          OR n.u_role = 'authenticated') IS TRUE AS using_signed_in,
         ((p.fn_scoped AND n.c ~ '^(select)?(auth\.)?(uid|jwt|email)(as[a-z0-9_]+)?isnotnull$')
          OR n.c_role = 'authenticated') IS TRUE AS check_signed_in,
         -- Every condition is auth.role() = '<a role other than anon or
         -- authenticated>', such as 'service_role': no API user passes it.
         ((p.using_expr <> '' OR p.check_expr <> '')
          AND (p.using_expr = '' OR n.u_role NOT IN ('anon', 'authenticated'))
          AND (p.check_expr = '' OR n.c_role NOT IN ('anon', 'authenticated'))) IS TRUE AS role_blocked,
         CASE WHEN p.is_storage THEN 'files' ELSE 'rows' END AS things,
         CASE WHEN p.is_storage THEN 'every file in every bucket' ELSE 'every row' END AS every_thing,
         CASE WHEN p.is_storage THEN 'file owner' ELSE 'row owner' END AS owner_word,
         CASE WHEN p.is_storage THEN 'owner_id = (select auth.uid()::text)'
              ELSE '(select auth.uid()) = user_id' END AS owner_example
  FROM pol p
  -- Each condition as printed, lower-cased, without casts, spaces, brackets
  -- or quotes, so that every printed form of the same test compares equal
  -- (with or without "auth.", inside (select ...), with a cast). u_role /
  -- c_role: the role name in "auth.role() = '<role>'", either way round.
  CROSS JOIN LATERAL (
    SELECT x.u, x.c,
           CASE WHEN p.role_used THEN coalesce(
             (regexp_match(x.u, '^(?:select)?(?:auth\.)?role(?:as[a-z0-9_]+)?=''([a-z0-9_]*)''$'))[1],
             (regexp_match(x.u, '^''([a-z0-9_]*)''=(?:select)?(?:auth\.)?role(?:as[a-z0-9_]+)?$'))[1])
           END AS u_role,
           CASE WHEN p.role_used THEN coalesce(
             (regexp_match(x.c, '^(?:select)?(?:auth\.)?role(?:as[a-z0-9_]+)?=''([a-z0-9_]*)''$'))[1],
             (regexp_match(x.c, '^''([a-z0-9_]*)''=(?:select)?(?:auth\.)?role(?:as[a-z0-9_]+)?$'))[1])
           END AS c_role
    FROM (SELECT regexp_replace(regexp_replace(lower(p.using_expr), '::[a-z_]+', '', 'g'),
                                '[[:space:]()"]', '', 'g') AS u,
                 regexp_replace(regexp_replace(lower(p.check_expr), '::[a-z_]+', '', 'g'),
                                '[[:space:]()"]', '', 'g') AS c) x
  ) n
),

-- 1. RLS disabled on a table the API can reach. Partitions are check 1b.
c1 AS (
  SELECT 'high'::text AS severity,
         'rls_disabled'::text AS "check",
         t.nsp || '.' || t.relname AS object,
         'RLS is off, so '
           || CASE
                WHEN t.anon_read OR t.anon_write THEN
                  'anyone with your public API key can '
                  || CASE WHEN t.anon_read AND t.anon_write THEN 'read and change'
                          WHEN t.anon_write THEN 'change'
                          ELSE 'read' END
                  || ' every row in this table'
                  || CASE WHEN NOT t.anon_write AND t.auth_write
                          THEN ', and any signed-in user can change them' ELSE '' END
                ELSE
                  'any signed-in user can '
                  || CASE WHEN t.auth_read AND t.auth_write THEN 'read and change'
                          WHEN t.auth_write THEN 'change'
                          ELSE 'read' END
                  || ' every row in this table'
              END
           || '.' AS why_it_matters,
         'Run: ALTER TABLE ' || quote_ident(t.nsp) || '.' || quote_ident(t.relname)
           || ' ENABLE ROW LEVEL SECURITY; then add policies for the access you want.' AS fix
  FROM reach t
  WHERE t.relkind IN ('r', 'p')
    AND NOT t.is_storage
    AND NOT t.is_part
    AND NOT t.rls_on
),

-- 1b. A partition with RLS off that the API can reach, reported when either
--     a) a table above it (its parent, or any table further up) has RLS on:
--        reads through that table use its policies, reading the partition
--        by name does not; every level is found in one run; or
--     b) no table above it has RLS on and the API cannot reach its parent,
--        e.g. a server-only parent with its grants revoked, whose new
--        partitions still get the default grants.
--     Otherwise the parent's own finding covers it. Medium in both cases:
--     it is not known whether the API serves partitions by name.
c1p AS (
  SELECT 'medium', 'partition_rls_disabled',
         t.nsp || '.' || t.relname,
         CASE WHEN t.parent_rls_on
                THEN 'RLS is off on this partition. Queries through the parent table are protected, but anything that reads the partition directly bypasses RLS.'
              WHEN t.ancestor_rls_on
                THEN 'RLS is off on this partition and on its parent. Queries through the table above them that has RLS on are protected, but anything that reads this partition directly bypasses RLS.'
              ELSE 'RLS is off on this partition and no table above it is protected, so anything that reads the partition directly gets every row. The API cannot reach its parent table, but new partitions pick up your default grants.'
         END,
         'Run: ALTER TABLE ' || quote_ident(t.nsp) || '.' || quote_ident(t.relname)
           || CASE WHEN t.ancestor_rls_on
                   THEN ' ENABLE ROW LEVEL SECURITY; no policies are needed, access through the parent keeps working.'
                   ELSE ' ENABLE ROW LEVEL SECURITY; no policies are needed if only your server should read it.' END
  FROM reach t
  WHERE t.relkind IN ('r', 'p')
    AND t.is_part
    AND NOT t.rls_on
    AND (t.ancestor_rls_on
         OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_inherits i
                        JOIN reach pr ON pr.rel_oid = i.inhparent
                        WHERE i.inhrelid = t.rel_oid))
),

-- 2. RLS enabled, zero policies: one summary row per schema
c2 AS (
  SELECT 'low', 'rls_no_policies',
         count(*) || CASE WHEN count(*) = 1 THEN ' table in ' ELSE ' tables in ' END || t.nsp,
         CASE WHEN count(*) = 1 THEN 'This table has' ELSE 'These tables have' END
           || ' RLS on and no policies, so anon and signed-in users get nothing from '
           || CASE WHEN count(*) = 1 THEN 'it' ELSE 'them' END
           || ' through the API and only server-side roles can use '
           || CASE WHEN count(*) = 1 THEN 'it' ELSE 'them' END
           || '. That is right for server-only tables and a bug for anything the app reads or writes directly.',
         CASE WHEN count(*) = 1 THEN 'Confirm it is meant to be server-only: '
              ELSE 'Confirm each is meant to be server-only: ' END
           || string_agg(t.relname, ', ' ORDER BY t.relname COLLATE "C")
           || CASE WHEN count(*) = 1 THEN '. If the app should read or write it'
                   ELSE '. If the app should read or write one of them' END
           || ', add a policy scoped to the owning user.'
  FROM reach t
  WHERE t.relkind IN ('r', 'p')
    AND NOT t.is_storage
    AND NOT t.is_part
    AND t.rls_on
    AND NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = t.rel_oid
    )
  GROUP BY t.nsp
),

-- 3. Permissive policy whose USING or WITH CHECK is literally true. The
--    message says which side is true: USING true = every row visible or
--    affected, WITH CHECK true = any values can be written.
c3 AS (
  SELECT CASE WHEN p.polcmd = 'r' THEN 'medium' ELSE 'high' END,
         CASE WHEN p.is_storage THEN 'storage_policy_using_true' ELSE 'policy_using_true' END,
         p.nsp || '.' || p.relname || ' policy "' || p.polname || '"',
         CASE WHEN p.anon_reach THEN 'Anyone with your public API key' ELSE 'Any signed-in user' END
           || ' can '
           || CASE
                WHEN p.polcmd = 'r' THEN
                  CASE WHEN p.is_storage
                       THEN 'download every file in every bucket, private buckets included'
                       ELSE 'read every row, so the table is effectively public' END
                WHEN p.polcmd = 'a' THEN
                  CASE WHEN p.is_storage
                       THEN 'upload files with any values, to any bucket and path'
                       ELSE 'insert rows with any values' END
                WHEN p.polcmd = 'd' THEN 'delete ' || p.every_thing
                WHEN p.polcmd = 'w' AND p.using_true AND p.check_true
                  THEN 'update ' || p.every_thing || ' with any values'
                WHEN p.polcmd = 'w' AND p.using_true
                  THEN 'update ' || p.every_thing
                WHEN p.polcmd = 'w'
                  THEN 'save any values in the ' || p.things || ' they can update, for example '
                       || CASE WHEN p.is_storage THEN 'moving a file into another user''s folder'
                               ELSE 'handing a row to another user' END
                WHEN p.using_true AND p.check_true
                  THEN 'read, update and delete ' || p.every_thing || ', and write any values'
                WHEN p.using_true
                  THEN 'read, update and delete ' || p.every_thing
                ELSE 'write any values when they add or update ' || p.things || ', for example '
                       || CASE WHEN p.is_storage THEN 'putting a file into another user''s folder'
                               ELSE 'handing a row to another user' END
              END
           || '.',
         'Replace the literal true in '
           || CASE WHEN p.using_expr = 'true' AND p.check_expr = 'true' THEN 'USING and WITH CHECK'
                   WHEN p.using_expr = 'true' THEN 'USING'
                   ELSE 'WITH CHECK' END
           || CASE WHEN p.is_storage
                   THEN ' with a condition on the bucket and the file owner, such as bucket_id = ''avatars'' AND owner_id = (select auth.uid()::text).'
                   ELSE ' with a condition tied to the row owner, such as (select auth.uid()) = user_id, or restrict the policy to a server-side role.' END
  FROM pol2 p
  WHERE p.using_true OR p.check_true
),

-- 4. Permissive policy that does not tie rows to the caller:
--    a) its USING or WITH CHECK only checks that the caller is signed in
--       (auth.uid() IS NOT NULL, auth.role() = 'authenticated'), so
--       "logged in" means "allowed";
--    b) it is for authenticated and never uses auth.uid() / auth.jwt() /
--       auth.email(), directly or through a helper function;
--    c) it is for everyone (no TO clause) or for anon, is not SELECT-only,
--       and never ties to the caller. A read policy for everyone or for anon
--       is a deliberate public read.
--    Literal-true policies are reported by check 3 instead. Policies that no
--    API user can pass (e.g. auth.role() = 'service_role') are skipped.
c4 AS (
  SELECT 'medium',
         CASE WHEN p.is_storage THEN 'storage_policy_not_tied_to_caller' ELSE 'policy_not_tied_to_caller' END,
         p.nsp || '.' || p.relname || ' policy "' || p.polname || '"',
         CASE
           WHEN (p.using_signed_in AND (p.check_signed_in OR p.check_expr = ''))
             OR (p.check_signed_in AND p.using_expr = '')
             THEN 'Its only condition is that the caller is signed in'
           WHEN p.using_signed_in
             THEN 'Its USING condition only checks that the caller is signed in'
           WHEN p.check_signed_in
             THEN 'Its WITH CHECK condition only checks that the caller is signed in'
           WHEN p.to_public
             THEN 'It applies to everyone (TO public, the default when there is no TO clause) and nothing in it ties '
                  || p.things || ' to the caller'
           WHEN p.to_anon AND NOT p.to_authenticated
             THEN 'It is for anon, which needs no sign-in, and nothing in it ties '
                  || p.things || ' to an owner'
           ELSE 'Nothing in it ties ' || p.things
                || ' to the caller (no auth.uid(), auth.jwt() or auth.email(), directly or through a helper function)'
         END
           || ', so '
           || CASE WHEN NOT (p.using_signed_in OR p.check_signed_in) AND p.anon_reach
                   THEN 'anyone with your public API key' ELSE 'any signed-in user' END
           || ' can '
           || CASE
                -- Only WITH CHECK is loose: callers keep to rows they can
                -- already reach, but can write any values into them.
                WHEN p.check_signed_in AND NOT p.using_signed_in AND p.using_expr <> ''
                  THEN 'save any values in the ' || p.things || ' they can update, for example '
                       || CASE WHEN p.is_storage THEN 'moving a file into another user''s folder'
                               ELSE 'handing a row to another user' END
                WHEN p.polcmd = 'r' THEN CASE WHEN p.is_storage THEN 'download other users'' files'
                                              ELSE 'read other users'' rows' END
                WHEN p.polcmd = 'a' THEN CASE WHEN p.is_storage THEN 'upload files into other users'' folders'
                                              ELSE 'insert rows for other users' END
                WHEN p.polcmd = 'w' THEN CASE WHEN p.is_storage THEN 'overwrite or move other users'' files'
                                              ELSE 'update other users'' rows' END
                WHEN p.polcmd = 'd' THEN 'delete other users'' ' || p.things
                ELSE CASE WHEN p.is_storage THEN 'download and change other users'' files'
                          ELSE 'read and change other users'' rows' END
              END
           || '.',
         CASE
           WHEN p.using_signed_in OR p.check_signed_in
             THEN 'Replace the signed-in test with a condition tied to the ' || p.owner_word
                  || ', such as ' || p.owner_example
                  || ', or confirm every signed-in user should have this access.'
           WHEN p.to_public
             THEN 'Add TO authenticated and tie the condition to the ' || p.owner_word
                  || ', such as ' || p.owner_example || '.'
           WHEN p.to_anon AND NOT p.to_authenticated
             THEN 'Use TO authenticated and tie the condition to the ' || p.owner_word
                  || ', such as ' || p.owner_example || ', unless signed-out visitors really need this.'
           ELSE 'Tie the condition to the ' || p.owner_word || ', such as ' || p.owner_example || '.'
         END
  FROM pol2 p
  WHERE NOT (p.using_true OR p.check_true)
    -- A policy with no expression at all grants nothing.
    AND (p.using_expr <> '' OR p.check_expr <> '')
    AND NOT p.role_blocked
    AND (   -- a) signed-in test: matters to signed-in users
            ((p.using_signed_in OR p.check_signed_in) AND p.auth_reach)
         OR (NOT (p.using_signed_in OR p.check_signed_in)
             AND NOT p.caller_scoped
             AND (   -- b) for authenticated, any command
                     (p.to_authenticated AND p.auth_reach)
                     -- c) for everyone or for anon, and it writes
                  OR ((p.to_public OR p.to_anon) AND p.polcmd <> 'r'))))
),

-- 5. View without security_invoker=true (extension-owned views are skipped)
c5 AS (
  SELECT 'medium',
         'view_not_security_invoker',
         t.nsp || '.' || t.relname,
         'A view runs with its owner''s rights by default, so ' || t.who
           || ' can use it to see rows that RLS on the underlying tables would hide.',
         'Run: ALTER VIEW ' || quote_ident(t.nsp) || '.' || quote_ident(t.relname)
           || ' SET (security_invoker = true);'
  FROM reach t
  WHERE t.relkind = 'v'
    AND NOT t.ext_owned
    AND NOT EXISTS (
      SELECT 1
      FROM unnest(coalesce(t.reloptions, ARRAY[]::text[])) o
      WHERE o ~* '^security_invoker=(t|tr|tru|true|y|ye|yes|on|1)$'
    )
),

-- 6. SECURITY DEFINER function that anon or authenticated can call through
--    the API. Trigger and event-trigger functions, procedures, and extension
--    members are skipped. A function used by a policy that anon or
--    authenticated can reach (permissive or restrictive) is an RLS helper:
--    low. A policy the API never reaches (e.g. service_role only) does not
--    make it one.
secdef AS (
  SELECT p.oid AS fn_oid, s.nsp, p.proname, p.pronamespace,
         EXISTS (SELECT 1 FROM pol_fn pf
                 JOIN pol_reach r ON r.pol_oid = pf.pol_oid
                 WHERE pf.fn_oid = p.oid
                   AND (r.anon_reach OR r.auth_reach)) AS rls_helper
  FROM pg_catalog.pg_proc p
  JOIN schemas s ON s.nsp_oid = p.pronamespace
  WHERE p.prosecdef
    AND p.prokind = 'f'
    AND p.prorettype NOT IN ('pg_catalog.trigger'::regtype, 'pg_catalog.event_trigger'::regtype)
    AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                    WHERE d.classid = 'pg_catalog.pg_proc'::regclass
                      AND d.objid = p.oid
                      AND d.deptype = 'e')
),
c6 AS (
  SELECT CASE WHEN f.rls_helper THEN 'low' ELSE 'medium' END,
         CASE WHEN f.rls_helper THEN 'security_definer_rls_helper' ELSE 'security_definer_executable' END,
         f.nsp || '.' || f.proname || '(' || pg_catalog.pg_get_function_identity_arguments(f.fn_oid) || ')',
         CASE WHEN f.rls_helper
              THEN 'RLS helper callable through the API: a policy uses this SECURITY DEFINER function, and '
                   || string_agg(r.rolname, ' and ' ORDER BY r.rolname) || ' can also call it directly.'
              ELSE 'This function runs with its owner''s rights and can be called by '
                   || string_agg(r.rolname, ' and ' ORDER BY r.rolname)
                   || ' through the API, so it can bypass RLS.'
         END,
         CASE WHEN f.rls_helper
              THEN 'Confirm it only returns the caller''s own data, or move it to a schema the API does not expose.'
              ELSE 'Revoke access with REVOKE EXECUTE ON FUNCTION ' || quote_ident(f.nsp) || '.'
                   || quote_ident(f.proname) || '(' || pg_catalog.pg_get_function_identity_arguments(f.fn_oid)
                   || ') FROM PUBLIC, anon, authenticated; or switch it to SECURITY INVOKER.'
         END
  FROM secdef f
  JOIN api_roles r
    ON pg_catalog.has_schema_privilege(r.role_oid, f.pronamespace, 'USAGE')
   AND pg_catalog.has_function_privilege(r.role_oid, f.fn_oid, 'EXECUTE')
  GROUP BY f.fn_oid, f.nsp, f.proname, f.rls_helper
),

-- 7. Storage buckets. The storage schema may not exist, so the query text is
--    only pointed at storage.buckets when all five columns are present.
bucket_src AS (
  SELECT x.id, x.name, x.is_public, x.no_size, x.no_mime
  FROM xmltable(
    '/table/row'
    PASSING pg_catalog.query_to_xml(
      CASE WHEN (
             SELECT count(*)
             FROM pg_catalog.pg_attribute a
             WHERE a.attrelid = pg_catalog.to_regclass('storage.buckets')
               AND a.attname IN ('id', 'name', 'public', 'file_size_limit', 'allowed_mime_types')
               AND NOT a.attisdropped
           ) = 5
        THEN 'SELECT id::text AS id, name::text AS name, '
          || 'coalesce(public, false) AS is_public, '
          || '(file_size_limit IS NULL) AS no_size, '
          || '(allowed_mime_types IS NULL OR cardinality(allowed_mime_types) = 0) AS no_mime '
          || 'FROM storage.buckets'
        ELSE 'SELECT NULL::text AS id WHERE false'
      END,
      false, false, ''
    )
    COLUMNS id        text    PATH 'id',
            name      text    PATH 'name',
            is_public boolean PATH 'is_public',
            no_size   boolean PATH 'no_size',
            no_mime   boolean PATH 'no_mime'
  ) x
),
c7a AS (
  SELECT 'low', 'storage_bucket_public',
         'storage bucket "' || b.name || '"',
         'Anyone with the file URL can download files in this bucket without logging in.',
         'Confirm this is intended; if not, make the bucket private and serve files with signed URLs.'
  FROM bucket_src b
  WHERE b.is_public
),
c7b AS (
  SELECT 'low', 'storage_bucket_no_limits',
         'storage bucket "' || b.name || '"',
         CASE WHEN b.no_size AND b.no_mime
                THEN 'This bucket sets no file size limit and no allowed file types of its own, so only your project-wide upload limit applies and any file type is accepted.'
              WHEN b.no_size
                THEN 'This bucket sets no file size limit of its own, so only your project-wide upload limit applies.'
              ELSE 'This bucket sets no allowed file types, so any file type is accepted.'
         END,
         'Set '
           || CASE WHEN b.no_size AND b.no_mime THEN 'file_size_limit and allowed_mime_types'
                   WHEN b.no_size THEN 'file_size_limit'
                   ELSE 'allowed_mime_types' END
           || ' on the bucket to what your app actually needs.'
  FROM bucket_src b
  WHERE b.no_size OR b.no_mime
),

-- 8. Materialized views and foreign tables the API can reach. Neither can
--    have RLS, so a privilege is all it takes. Extension members are skipped.
c8 AS (
  SELECT 'medium',
         CASE t.relkind WHEN 'm' THEN 'materialized_view_exposed' ELSE 'foreign_table_exposed' END,
         t.nsp || '.' || t.relname,
         CASE t.relkind
           WHEN 'm' THEN
             'Materialized views cannot have RLS, so '
             || CASE WHEN t.anon_read THEN 'anyone with your public API key' ELSE 'any signed-in user' END
             || ' can read every row of this one through the API.'
           ELSE
             'Foreign tables cannot have RLS, so ' || t.who || ' can '
             || CASE WHEN (t.anon_read OR t.auth_read) AND (t.anon_write OR t.auth_write) THEN 'read and change'
                     WHEN t.anon_write OR t.auth_write THEN 'change'
                     ELSE 'read' END
             || ' every row of this one through the API.'
         END,
         'If that is not intended, run: REVOKE '
           || CASE t.relkind WHEN 'm' THEN 'SELECT' ELSE 'ALL' END
           || ' ON ' || quote_ident(t.nsp) || '.' || quote_ident(t.relname)
           || ' FROM PUBLIC, anon, authenticated; or move it to a schema the API does not expose.'
  FROM reach t
  WHERE NOT t.ext_owned
    AND ((t.relkind = 'm' AND (t.anon_read OR t.auth_read))
         OR t.relkind = 'f')
)

SELECT f.severity, f."check", f.object, f.why_it_matters, f.fix
FROM (
  SELECT * FROM c1
  UNION ALL SELECT * FROM c1p
  UNION ALL SELECT * FROM c2
  UNION ALL SELECT * FROM c3
  UNION ALL SELECT * FROM c4
  UNION ALL SELECT * FROM c5
  UNION ALL SELECT * FROM c6
  UNION ALL SELECT * FROM c7a
  UNION ALL SELECT * FROM c7b
  UNION ALL SELECT * FROM c8
) AS f(severity, "check", object, why_it_matters, fix)
ORDER BY
  CASE f.severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
  f."check" COLLATE "C",
  f.object COLLATE "C";
