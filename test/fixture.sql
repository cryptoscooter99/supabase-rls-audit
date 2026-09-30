-- Throwaway fixture that mimics the parts of Supabase the audit looks at.
-- Every "bad_*" object should be flagged; every "good_*" twin should not.
-- "(item N)" and "(round 2, item N)" mark the regression cases for the two
-- review rounds (see README.md).
-- Load into an empty scratch database only, as a superuser: it creates roles,
-- a foreign-data wrapper, and marks two objects as extension members.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon')          THEN CREATE ROLE anon NOLOGIN NOINHERIT; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN NOINHERIT; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role')  THEN CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS; END IF;
END $$;

-- Supabase's default grants (item 3): the API roles can use `public`, and
-- every table, view, function and sequence created there is granted to them.
-- Set before anything is created so every object below gets them.
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES    TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO anon, authenticated, service_role;

-- Stub auth schema with the caller functions, plus objects in excluded
-- schemas. The API roles can reach those objects, so only the exclusion list
-- keeps them out of the findings.
CREATE SCHEMA auth;
GRANT USAGE ON SCHEMA auth TO anon, authenticated, service_role;
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
  AS $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
CREATE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE
  AS $$ SELECT coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
CREATE FUNCTION auth.email() RETURNS text LANGUAGE sql STABLE
  AS $$ SELECT nullif(current_setting('request.jwt.claim.email', true), '') $$;
-- Shaped like Supabase's: it reads the JWT's role claim (anon /
-- authenticated / service_role), so it says nothing about which user.
CREATE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE
  AS $$ SELECT coalesce(nullif(current_setting('request.jwt.claim.role', true), ''),
                        (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role'))::text $$;
CREATE TABLE auth.excluded_no_rls (id int);
CREATE VIEW auth.excluded_view AS SELECT * FROM auth.excluded_no_rls;
GRANT ALL ON auth.excluded_no_rls, auth.excluded_view TO anon, authenticated;
CREATE SCHEMA vault;
GRANT USAGE ON SCHEMA vault TO anon, authenticated;
CREATE TABLE vault.excluded_no_rls (id int);
GRANT ALL ON vault.excluded_no_rls TO anon, authenticated;
CREATE SCHEMA graphql_public;
GRANT USAGE ON SCHEMA graphql_public TO anon, authenticated, service_role;
CREATE FUNCTION graphql_public.excluded_secdef() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;

-- Stub storage schema: bucket columns as in Supabase, and storage.objects with
-- RLS on and Supabase's grants, so its policies are checked (item 8).
CREATE SCHEMA storage;
GRANT USAGE ON SCHEMA storage TO anon, authenticated, service_role;
CREATE TABLE storage.buckets (
  id text PRIMARY KEY,
  name text NOT NULL,
  public boolean DEFAULT false,
  file_size_limit bigint,
  allowed_mime_types text[]
);
CREATE TABLE storage.objects (id uuid, bucket_id text, name text, owner uuid, owner_id text);
ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;
GRANT ALL ON storage.buckets, storage.objects TO anon, authenticated, service_role;

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types) VALUES
  ('bad_public_bucket',    'bad_public_bucket',    true,  1048576, '{image/png}'),
  ('bad_no_limits_bucket', 'bad_no_limits_bucket', false, NULL,    NULL),       -- (item 9) message
  ('bad_no_mime_bucket',   'bad_no_mime_bucket',   false, 1048576, NULL),
  ('good_bucket',          'good_bucket',          false, 1048576, '{image/png,image/jpeg}');

-- (item 8) bad: anon can upload anything to any bucket and path
CREATE POLICY bad_storage_anon_upload ON storage.objects FOR INSERT TO anon WITH CHECK (true);
-- (item 8) bad: any signed-in user can overwrite any file in a shared bucket
CREATE POLICY bad_storage_authed_update ON storage.objects FOR UPDATE TO authenticated
  USING (bucket_id = 'shared');
-- (item 8) good twins: owner-scoped access, and a public read of one bucket
CREATE POLICY good_storage_own_files ON storage.objects FOR ALL TO authenticated
  USING (owner_id = (SELECT auth.uid()::text)) WITH CHECK (owner_id = (SELECT auth.uid()::text));
CREATE POLICY good_storage_public_read ON storage.objects FOR SELECT
  USING (bucket_id = 'bad_public_bucket');

-- A schema the API roles have no USAGE on (item 3). Grants on the objects are
-- given anyway, so only the missing USAGE keeps them unreachable.
CREATE SCHEMA private_zone;

-- ---------------------------------------------------------------- tables
-- Good twins
CREATE TABLE public.good_rls_on (id int, owner_id uuid);
ALTER TABLE public.good_rls_on ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_owner_all ON public.good_rls_on FOR ALL TO authenticated
  USING ((SELECT auth.uid()) = owner_id) WITH CHECK ((SELECT auth.uid()) = owner_id);

-- RLS on but not FORCEd is not a finding (check 8); forced is not either.
CREATE TABLE public.good_rls_forced (id int, owner_id uuid);
ALTER TABLE public.good_rls_forced ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.good_rls_forced FORCE ROW LEVEL SECURITY;
CREATE POLICY good_forced_select ON public.good_rls_forced FOR SELECT TO authenticated
  USING (auth.uid() = owner_id);

CREATE TABLE public.good_jwt (id int);
ALTER TABLE public.good_jwt ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_jwt_select ON public.good_jwt FOR SELECT TO authenticated
  USING ((auth.jwt() ->> 'role') = 'admin');

CREATE TABLE public.good_true_service (id int);
ALTER TABLE public.good_true_service ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_service_all ON public.good_true_service FOR ALL TO service_role
  USING (true) WITH CHECK (true);

CREATE TABLE public.good_true_restrictive (id int);
ALTER TABLE public.good_true_restrictive ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_restrictive ON public.good_true_restrictive AS RESTRICTIVE FOR SELECT TO anon
  USING (true);

CREATE TABLE public.good_anon_read (id int, published boolean);
ALTER TABLE public.good_anon_read ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_anon_published ON public.good_anon_read FOR SELECT TO anon
  USING (published);

-- Bad objects
CREATE TABLE public.bad_rls_off (id int);                         -- check 1

CREATE SCHEMA app;                                                -- check 1, non-public schema
GRANT USAGE ON SCHEMA app TO anon, authenticated;
CREATE TABLE app.bad_app_rls_off (id int);                        -- (item 3) read-only grant: message says "read"
GRANT SELECT ON app.bad_app_rls_off TO anon, authenticated;

CREATE TABLE public.bad_true_select (id int);                     -- check 3 medium
ALTER TABLE public.bad_true_select ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_true_select_p ON public.bad_true_select FOR SELECT TO anon USING (true);

CREATE TABLE public.bad_true_default_role (id int);               -- check 3 medium, no TO clause = PUBLIC
ALTER TABLE public.bad_true_default_role ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_true_default_role_p ON public.bad_true_default_role FOR SELECT USING (true);

CREATE TABLE public.bad_true_insert (id int);                     -- check 3 high
ALTER TABLE public.bad_true_insert ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_true_insert_p ON public.bad_true_insert FOR INSERT TO public WITH CHECK (true);

CREATE TABLE public.bad_true_update (id int);                     -- check 3 high
ALTER TABLE public.bad_true_update ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_true_update_p ON public.bad_true_update FOR UPDATE TO authenticated USING (true);

CREATE TABLE public.bad_true_delete (id int);                     -- check 3 high
ALTER TABLE public.bad_true_delete ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_true_delete_p ON public.bad_true_delete FOR DELETE TO anon USING (true);

CREATE TABLE public.bad_true_all (id int);                        -- check 3 high
ALTER TABLE public.bad_true_all ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_true_all_p ON public.bad_true_all FOR ALL TO authenticated USING (true) WITH CHECK (true);

CREATE TABLE public.bad_authed_no_uid (id int, owner_id uuid);    -- check 4
ALTER TABLE public.bad_authed_no_uid ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_authed_no_uid_p ON public.bad_authed_no_uid FOR SELECT TO authenticated
  USING (owner_id IS NOT NULL);

-- (item 1) auth.email() ties rows to the caller too
CREATE TABLE public.good_email (id int, owner_email text);
ALTER TABLE public.good_email ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_email_p ON public.good_email FOR SELECT TO authenticated
  USING (owner_email = (SELECT auth.email()));
-- (item 1) the text "auth.uid()" inside a string is not a call to it
CREATE TABLE public.bad_fake_auth_ref (id int, label text);
ALTER TABLE public.bad_fake_auth_ref ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_fake_auth_ref_p ON public.bad_fake_auth_ref FOR SELECT TO authenticated
  USING (label <> 'auth.uid()');
-- (item 1) run.sh also re-runs the audit with auth on the search_path, where
-- Postgres prints uid() instead of auth.uid(), and expects identical output.

-- (item 3) a table with every API grant revoked cannot be reached ...
CREATE TABLE public.good_revoked_rls_off (id int);
REVOKE ALL ON public.good_revoked_rls_off FROM anon, authenticated;
-- ... while a grant on a single column is enough to reach one
CREATE TABLE public.bad_column_grant_rls_off (id int, note text);
REVOKE ALL ON public.bad_column_grant_rls_off FROM anon, authenticated;
GRANT SELECT (id) ON public.bad_column_grant_rls_off TO anon;
-- (item 3) nothing in a schema without USAGE is reachable
CREATE TABLE private_zone.good_hidden_rls_off (id int);
CREATE TABLE private_zone.good_hidden_true_select (id int);
ALTER TABLE private_zone.good_hidden_true_select ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_hidden_true_select_p ON private_zone.good_hidden_true_select FOR SELECT TO anon
  USING (true);
CREATE VIEW private_zone.good_hidden_view AS SELECT * FROM private_zone.good_hidden_rls_off;
GRANT ALL ON private_zone.good_hidden_rls_off, private_zone.good_hidden_true_select,
             private_zone.good_hidden_view TO anon, authenticated;
CREATE FUNCTION private_zone.good_hidden_secdef() RETURNS int     -- EXECUTE for PUBLIC by default
  LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
-- (round 2, item 1) partitions under a parent with RLS on. Partitions get the
-- same default grants but not the parent's RLS, and a partition read by name
-- skips the parent's policies.
CREATE TABLE public.good_part_parent (id int, owner_id uuid, created date) PARTITION BY RANGE (created);
ALTER TABLE public.good_part_parent ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_part_owner ON public.good_part_parent FOR ALL TO authenticated
  USING ((SELECT auth.uid()) = owner_id) WITH CHECK ((SELECT auth.uid()) = owner_id);
-- bad: RLS off on the partition itself (medium partition_rls_disabled)
CREATE TABLE public.bad_part_open_2025 PARTITION OF public.good_part_parent
  FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
-- good twin: RLS on, no policies of its own; reads through the parent still work
CREATE TABLE public.good_part_locked_2026 PARTITION OF public.good_part_parent
  FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
ALTER TABLE public.good_part_locked_2026 ENABLE ROW LEVEL SECURITY;
-- bad: RLS on, but the partition's own policy is USING (true) for anon
CREATE TABLE public.bad_part_true_2027 PARTITION OF public.good_part_parent
  FOR VALUES FROM ('2027-01-01') TO ('2028-01-01');
ALTER TABLE public.bad_part_true_2027 ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_part_true_2027_p ON public.bad_part_true_2027 FOR SELECT TO anon USING (true);
-- good twin: RLS off, but no API grants, so it cannot be read by name
CREATE TABLE public.good_part_revoked_2028 PARTITION OF public.good_part_parent
  FOR VALUES FROM ('2028-01-01') TO ('2029-01-01');
REVOKE ALL ON public.good_part_revoked_2028 FROM anon, authenticated;
-- A parent with RLS off is flagged itself (high); its partitions are not listed.
CREATE TABLE public.bad_part_parent (id int, created date) PARTITION BY RANGE (created);
CREATE TABLE public.child_of_bad_part_2025 PARTITION OF public.bad_part_parent
  FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
CREATE TABLE public.child_of_bad_part_2026 PARTITION OF public.bad_part_parent
  FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

-- (round 3, item 1) a server-only partitioned table: RLS off and the parent's
-- API grants revoked. New partitions still get the default grants, so a
-- partition read by name returns rows, and nothing else would report it.
CREATE TABLE public.good_srv_parent (id int, created date) PARTITION BY RANGE (created);
REVOKE ALL ON public.good_srv_parent FROM anon, authenticated;
-- bad: RLS off, reachable by name (medium partition_rls_disabled)
CREATE TABLE public.bad_srv_part_2025 PARTITION OF public.good_srv_parent
  FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
-- good twin: RLS on, no policies needed
CREATE TABLE public.good_srv_part_2026 PARTITION OF public.good_srv_parent
  FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
ALTER TABLE public.good_srv_part_2026 ENABLE ROW LEVEL SECURITY;
-- (round 3, item 1) the same when the parent sits in a schema the API
-- cannot use and the partition in one it can
CREATE TABLE private_zone.good_hidden_part_parent (id int, created date) PARTITION BY RANGE (created);
CREATE TABLE public.bad_hidden_parent_part_2025 PARTITION OF private_zone.good_hidden_part_parent
  FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
-- good twin: API grants revoked on the partition too
CREATE TABLE public.good_hidden_parent_part_2026 PARTITION OF private_zone.good_hidden_part_parent
  FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
REVOKE ALL ON public.good_hidden_parent_part_2026 FROM anon, authenticated;
-- (round 3, item 1) two levels, both above the leaf unreachable: the leaf is
-- reported ...
CREATE TABLE public.good_srv_nest_top (id int, region int, created date) PARTITION BY LIST (region);
REVOKE ALL ON public.good_srv_nest_top FROM anon, authenticated;
CREATE TABLE public.good_srv_nest_mid PARTITION OF public.good_srv_nest_top
  FOR VALUES IN (1) PARTITION BY RANGE (created);
REVOKE ALL ON public.good_srv_nest_mid FROM anon, authenticated;
CREATE TABLE public.bad_srv_nest_leaf PARTITION OF public.good_srv_nest_mid
  FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
-- ... but when the middle table is reachable, it is reported once and the
-- leaf under it is covered by that finding
CREATE TABLE public.good_srv_nest2_top (id int, region int, created date) PARTITION BY LIST (region);
REVOKE ALL ON public.good_srv_nest2_top FROM anon, authenticated;
CREATE TABLE public.bad_srv_nest2_mid PARTITION OF public.good_srv_nest2_top
  FOR VALUES IN (1) PARTITION BY RANGE (created);
CREATE TABLE public.child_of_bad_srv_nest2_leaf PARTITION OF public.bad_srv_nest2_mid
  FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');

-- (round 3, item 2) two levels under a protected top-level table: the middle
-- table and the leaf under it (both RLS off) are found in the same run
CREATE TABLE public.good_nest_top (id int, owner_id uuid, region int, created date) PARTITION BY LIST (region);
ALTER TABLE public.good_nest_top ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_nest_top_owner ON public.good_nest_top FOR ALL TO authenticated
  USING ((SELECT auth.uid()) = owner_id) WITH CHECK ((SELECT auth.uid()) = owner_id);
CREATE TABLE public.bad_nest_mid PARTITION OF public.good_nest_top
  FOR VALUES IN (1) PARTITION BY RANGE (created);
CREATE TABLE public.bad_nest_leaf_2025 PARTITION OF public.bad_nest_mid
  FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
-- good twin: a leaf with RLS on
CREATE TABLE public.good_nest_leaf_2026 PARTITION OF public.bad_nest_mid
  FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
ALTER TABLE public.good_nest_leaf_2026 ENABLE ROW LEVEL SECURITY;

-- (item 4) "logged in = allowed": the only condition is auth.uid() IS NOT NULL
CREATE TABLE public.bad_logged_in_only (id int, owner_id uuid);
ALTER TABLE public.bad_logged_in_only ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_logged_in_only_p ON public.bad_logged_in_only FOR SELECT TO authenticated
  USING (auth.uid() IS NOT NULL);
-- (item 4) the same, wrapped in (select ...), on the USING side of an UPDATE
CREATE TABLE public.bad_logged_in_update (id int, owner_id uuid);
ALTER TABLE public.bad_logged_in_update ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_logged_in_update_p ON public.bad_logged_in_update FOR UPDATE TO authenticated
  USING ((SELECT auth.uid()) IS NOT NULL) WITH CHECK ((SELECT auth.uid()) = owner_id);
-- (item 4) owner-scoped USING, but WITH CHECK only checks "signed in"
CREATE TABLE public.bad_logged_in_check (id int, owner_id uuid);
ALTER TABLE public.bad_logged_in_check ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_logged_in_check_p ON public.bad_logged_in_check FOR UPDATE TO authenticated
  USING ((SELECT auth.uid()) = owner_id) WITH CHECK (auth.uid() IS NOT NULL);
-- (item 4) the same with no TO clause: PUBLIC, but only signed-in users pass
CREATE TABLE public.bad_public_select_logged_in (id int);
ALTER TABLE public.bad_public_select_logged_in ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_public_select_logged_in_p ON public.bad_public_select_logged_in FOR SELECT
  USING (auth.uid() IS NOT NULL);
-- (item 4) no TO clause (PUBLIC), a write command, never tied to the caller
CREATE TABLE public.bad_public_update (id int, status text);
ALTER TABLE public.bad_public_update ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_public_update_p ON public.bad_public_update FOR UPDATE
  USING (status = 'open');
-- (item 4) good twins: a PUBLIC read is a deliberate public read; a PUBLIC
-- write tied to the owner; "signed in AND owner"
CREATE TABLE public.good_public_read (id int, published boolean);
ALTER TABLE public.good_public_read ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_public_read_p ON public.good_public_read FOR SELECT USING (published);
CREATE TABLE public.good_public_update_owner (id int, owner_id uuid);
ALTER TABLE public.good_public_update_owner ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_public_update_owner_p ON public.good_public_update_owner FOR UPDATE
  USING ((SELECT auth.uid()) = owner_id);
CREATE TABLE public.good_logged_in_and_owner (id int, owner_id uuid);
ALTER TABLE public.good_logged_in_and_owner ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_logged_in_and_owner_p ON public.good_logged_in_and_owner FOR SELECT TO authenticated
  USING (auth.uid() IS NOT NULL AND auth.uid() = owner_id);
-- A policy with no USING or WITH CHECK at all grants nothing
CREATE TABLE public.good_no_expr (id int);
ALTER TABLE public.good_no_expr ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_no_expr_p ON public.good_no_expr FOR SELECT TO authenticated;

-- (item 5) a RESTRICTIVE policy only narrows access and is not checked ...
CREATE TABLE public.good_soft_delete (id int, owner_id uuid, deleted_at timestamptz);
ALTER TABLE public.good_soft_delete ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_soft_delete_owner ON public.good_soft_delete FOR SELECT TO authenticated
  USING ((SELECT auth.uid()) = owner_id);
CREATE POLICY good_soft_delete_hide ON public.good_soft_delete AS RESTRICTIVE FOR SELECT TO authenticated
  USING (deleted_at IS NULL);
-- ... the same condition as the only (permissive) policy is flagged
CREATE TABLE public.bad_soft_delete (id int, owner_id uuid, deleted_at timestamptz);
ALTER TABLE public.bad_soft_delete ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_soft_delete_p ON public.bad_soft_delete FOR SELECT TO authenticated
  USING (deleted_at IS NULL);

-- (item 6) owner-scoped USING with WITH CHECK (true): any values can be
-- written, but not "every row" (good twin: good_rls_on)
CREATE TABLE public.bad_check_true_update (id int, owner_id uuid);
ALTER TABLE public.bad_check_true_update ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_check_true_update_p ON public.bad_check_true_update FOR UPDATE TO authenticated
  USING ((SELECT auth.uid()) = owner_id) WITH CHECK (true);

-- (item 10) policies that call a helper whose body ties rows to the caller
CREATE TABLE public.good_memberships (group_id int, member_ref text);
ALTER TABLE public.good_memberships ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_memberships_own ON public.good_memberships FOR SELECT TO authenticated
  USING (member_ref = (SELECT auth.uid())::text);
CREATE FUNCTION public.my_group_ids() RETURNS SETOF int LANGUAGE sql STABLE
  AS $$ SELECT group_id FROM public.good_memberships WHERE member_ref = (auth.uid())::text $$;
CREATE FUNCTION public.my_group_ids_atomic() RETURNS SETOF int LANGUAGE sql STABLE
  BEGIN ATOMIC
    SELECT group_id FROM public.good_memberships WHERE member_ref = (auth.uid())::text;
  END;
CREATE TABLE public.good_group_docs (id int, group_id int);
ALTER TABLE public.good_group_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_group_docs_p ON public.good_group_docs FOR SELECT TO authenticated
  USING (group_id IN (SELECT public.my_group_ids()));
CREATE TABLE public.good_group_notes (id int, group_id int);
ALTER TABLE public.good_group_notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_group_notes_p ON public.good_group_notes FOR ALL TO authenticated
  USING (group_id IN (SELECT public.my_group_ids_atomic()))
  WITH CHECK (group_id IN (SELECT public.my_group_ids_atomic()));
-- (item 10) bad twin: the helper never looks at the caller
CREATE FUNCTION public.any_group_ids() RETURNS SETOF int LANGUAGE sql STABLE
  AS $$ SELECT group_id FROM public.good_memberships $$;
CREATE TABLE public.bad_group_files (id int, group_id int);
ALTER TABLE public.bad_group_files ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_group_files_p ON public.bad_group_files FOR SELECT TO authenticated
  USING (group_id IN (SELECT public.any_group_ids()));

-- (item 11) RLS on with zero policies: one summary row per schema
CREATE TABLE public.bad_rls_no_policy (id int);
ALTER TABLE public.bad_rls_no_policy ENABLE ROW LEVEL SECURITY;
CREATE TABLE public.bad_rls_no_policy_2 (id int);
ALTER TABLE public.bad_rls_no_policy_2 ENABLE ROW LEVEL SECURITY;
CREATE TABLE app.bad_app_no_policy (id int);
ALTER TABLE app.bad_app_no_policy ENABLE ROW LEVEL SECURITY;
GRANT ALL ON app.bad_app_no_policy TO anon, authenticated;
-- good twin: no API grants either, so it is not listed
CREATE TABLE public.good_no_policy_no_grants (id int);
ALTER TABLE public.good_no_policy_no_grants ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.good_no_policy_no_grants FROM anon, authenticated;

-- (item 11) a SECURITY DEFINER helper that a policy uses is an RLS helper: low
CREATE FUNCTION public.bad_secdef_helper() RETURNS SETOF int
  LANGUAGE sql STABLE SECURITY DEFINER
  AS $$ SELECT group_id FROM public.good_memberships WHERE member_ref = (auth.uid())::text $$;
CREATE TABLE public.good_helper_docs (id int, group_id int);
ALTER TABLE public.good_helper_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_helper_docs_p ON public.good_helper_docs FOR SELECT TO authenticated
  USING (group_id IN (SELECT public.bad_secdef_helper()));
-- (item 11) good twin: the same helper in a schema the API cannot use
CREATE FUNCTION private_zone.good_hidden_helper() RETURNS SETOF int
  LANGUAGE sql STABLE SECURITY DEFINER
  AS $$ SELECT group_id FROM public.good_memberships WHERE member_ref = (auth.uid())::text $$;
CREATE TABLE public.good_hidden_helper_docs (id int, group_id int);
ALTER TABLE public.good_hidden_helper_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_hidden_helper_docs_p ON public.good_hidden_helper_docs FOR SELECT TO authenticated
  USING (group_id IN (SELECT private_zone.good_hidden_helper()));

-- (round 2, item 2) auth.role() = 'authenticated' only checks that the
-- caller is signed in, in every printed form (plain, cast, (select ...),
-- either way round). auth.role() itself does not tie rows to the caller.
CREATE TABLE public.bad_role_authed (id int);
ALTER TABLE public.bad_role_authed ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_role_authed_p ON public.bad_role_authed FOR SELECT TO authenticated
  USING (auth.role() = 'authenticated');
CREATE TABLE public.bad_role_public_read (id int);
ALTER TABLE public.bad_role_public_read ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_role_public_read_p ON public.bad_role_public_read FOR SELECT
  USING (auth.role()::text = 'authenticated');
CREATE TABLE public.bad_role_public_update (id int);
ALTER TABLE public.bad_role_public_update ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_role_public_update_p ON public.bad_role_public_update FOR UPDATE
  USING ('authenticated' = (SELECT auth.role()));
-- good twin: only service_role passes, and service_role skips RLS anyway,
-- so no API user gets anything from this policy
CREATE TABLE public.good_role_service (id int);
ALTER TABLE public.good_role_service ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_role_service_p ON public.good_role_service FOR ALL
  USING (auth.role() = 'service_role');
-- (good twin: good_group_docs above, whose public-schema helper reads auth.uid())

-- (round 2) "request.jwt.claims" as a plain string is not reading the claims ...
CREATE TABLE public.bad_claim_literal (id int, label text);
ALTER TABLE public.bad_claim_literal ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_claim_literal_p ON public.bad_claim_literal FOR SELECT TO authenticated
  USING (label <> 'request.jwt.claims');
-- ... while current_setting('request.jwt.claims') is
CREATE TABLE public.good_claims_direct (id int, owner_ref text);
ALTER TABLE public.good_claims_direct ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_claims_direct_p ON public.good_claims_direct FOR SELECT TO authenticated
  USING (owner_ref = current_setting('request.jwt.claims', true)::json ->> 'sub');

-- (round 2, item 4) write policies for anon that never tie rows to anything
CREATE TABLE public.bad_anon_update (id int, status text);
ALTER TABLE public.bad_anon_update ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_anon_update_p ON public.bad_anon_update FOR UPDATE TO anon
  USING (status = 'open');
CREATE TABLE public.bad_anon_delete (id int);
ALTER TABLE public.bad_anon_delete ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_anon_delete_p ON public.bad_anon_delete FOR DELETE TO anon
  USING (id > 0);
-- good twin: an anon write tied to a claim in the caller's token
CREATE TABLE public.good_anon_insert_jwt (id int, session_ref text);
ALTER TABLE public.good_anon_insert_jwt ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_anon_insert_jwt_p ON public.good_anon_insert_jwt FOR INSERT TO anon
  WITH CHECK (session_ref = (SELECT auth.jwt() ->> 'session_id'));
-- (good twin for reads: good_anon_read above)

-- (round 2, item 5) only policies the API reaches make a SECURITY DEFINER
-- function an RLS helper. Used only by a service_role policy: still medium.
CREATE FUNCTION public.bad_secdef_service_only() RETURNS SETOF int
  LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT 1 $$;
CREATE TABLE public.good_service_only_docs (id int);
ALTER TABLE public.good_service_only_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_service_only_docs_p ON public.good_service_only_docs TO service_role
  USING (id IN (SELECT public.bad_secdef_service_only()));
-- Used only by a policy on a table the API cannot reach: still medium.
CREATE FUNCTION public.bad_secdef_unreached() RETURNS SETOF int
  LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT 1 $$;
CREATE TABLE private_zone.good_hidden_docs (id int);
ALTER TABLE private_zone.good_hidden_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_hidden_docs_p ON private_zone.good_hidden_docs FOR SELECT TO authenticated
  USING (id IN (SELECT public.bad_secdef_unreached()));
-- Used by a reachable RESTRICTIVE policy: an RLS helper, low.
CREATE FUNCTION public.bad_secdef_restrictive_helper() RETURNS SETOF int
  LANGUAGE sql STABLE SECURITY DEFINER
  AS $$ SELECT group_id FROM public.good_memberships WHERE member_ref = (auth.uid())::text $$;
CREATE TABLE public.good_restrictive_helper_docs (id int, owner_id uuid, group_id int);
ALTER TABLE public.good_restrictive_helper_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY good_restrictive_helper_docs_own ON public.good_restrictive_helper_docs FOR SELECT TO authenticated
  USING ((SELECT auth.uid()) = owner_id);
CREATE POLICY good_restrictive_helper_docs_grp ON public.good_restrictive_helper_docs AS RESTRICTIVE
  FOR SELECT TO authenticated
  USING (group_id IN (SELECT public.bad_secdef_restrictive_helper()));

-- ----------------------------------------------------------------- views
CREATE VIEW public.bad_view AS SELECT * FROM public.good_rls_on;                              -- check 5
CREATE VIEW public.good_view WITH (security_invoker = true) AS SELECT * FROM public.good_rls_on;
CREATE VIEW public.good_view_on WITH (security_invoker = on) AS SELECT * FROM public.good_rls_on;

-- (item 7) materialized views and foreign tables cannot have RLS
CREATE MATERIALIZED VIEW public.bad_matview AS SELECT id, owner_id FROM public.good_rls_on;
CREATE MATERIALIZED VIEW public.good_matview_locked AS SELECT id FROM public.good_rls_on;
REVOKE ALL ON public.good_matview_locked FROM anon, authenticated;
CREATE FOREIGN DATA WRAPPER rw_test_fdw;            -- no handler: a catalog entry only, never queried
CREATE SERVER rw_test_server FOREIGN DATA WRAPPER rw_test_fdw;
CREATE FOREIGN TABLE public.bad_foreign (id int) SERVER rw_test_server;
CREATE FOREIGN TABLE public.good_foreign_locked (id int) SERVER rw_test_server;
REVOKE ALL ON public.good_foreign_locked FROM anon, authenticated;

-- ------------------------------------------------------------- functions
CREATE FUNCTION public.bad_secdef(a int, b text) RETURNS int         -- check 6 (PUBLIC has EXECUTE by default)
  LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;

CREATE FUNCTION public.good_secdef_locked() RETURNS int
  LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
REVOKE EXECUTE ON FUNCTION public.good_secdef_locked() FROM PUBLIC, anon, authenticated;

CREATE FUNCTION public.good_secdef_service() RETURNS int
  LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
REVOKE EXECUTE ON FUNCTION public.good_secdef_service() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.good_secdef_service() TO service_role;

CREATE FUNCTION public.good_invoker() RETURNS int
  LANGUAGE sql SECURITY INVOKER AS $$ SELECT 1 $$;

-- (item 2) trigger and event-trigger functions and procedures cannot be
-- called through the API (bad twin: bad_secdef)
CREATE FUNCTION public.good_secdef_trigger_fn() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN NEW; END $$;
CREATE FUNCTION public.good_secdef_event_fn() RETURNS event_trigger
  LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN END $$;
CREATE PROCEDURE public.good_secdef_proc()
  LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;

-- (item 9) extension members are skipped. plpgsql is installed in every
-- database, so it stands in for any extension here.
CREATE VIEW public.good_ext_view AS SELECT * FROM public.good_rls_on;
CREATE FUNCTION public.good_ext_secdef() RETURNS int
  LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
ALTER EXTENSION plpgsql ADD VIEW public.good_ext_view;
ALTER EXTENSION plpgsql ADD FUNCTION public.good_ext_secdef();
