-- Fixture for rowwarden-grant-check.sql: a Supabase-like public schema before and after the
-- October 30 switch. Run as a superuser named postgres in a throwaway database.
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
end $$;
grant usage on schema public to anon, authenticated, service_role;

-- old behaviour: default privileges grant every new table and sequence to the API roles
alter default privileges for role postgres in schema public
  grant select, insert, update, delete on tables to anon, authenticated, service_role;
alter default privileges for role postgres in schema public
  grant usage, select on sequences to anon, authenticated, service_role;

create table good_old (id serial primary key, owner uuid);
alter table good_old enable row level security;
create table bad_rls_off (id bigint generated always as identity primary key);   -- reachable, RLS off
create table info_server_only (id int primary key);
alter table info_server_only enable row level security;
revoke all on info_server_only from anon, authenticated;                           -- deliberate server-only

-- the switch: new tables stop getting grants
alter default privileges for role postgres in schema public
  revoke select, insert, update, delete on tables from anon, authenticated, service_role;
alter default privileges for role postgres in schema public
  revoke usage, select on sequences from anon, authenticated, service_role;

create table bad_new (id serial primary key);                                     -- no grants at all
alter table bad_new enable row level security;
create view bad_new_view as select 1 as x;                                         -- no grants, view
create table bad_seq (id serial primary key);                                      -- insert ok, sequence not
alter table bad_seq enable row level security;
grant select, insert on bad_seq to authenticated, service_role;
create table good_identity (id bigint generated always as identity primary key);   -- identity needs no seq grant
alter table good_identity enable row level security;
grant select, insert on good_identity to authenticated, service_role;

-- review round 1 cases
create table bad_new_rls_off (id serial primary key);                             -- no grants, RLS off
create table good_col_grant (id int primary key, a text, secret text);            -- column grants only
alter table good_col_grant enable row level security;
grant select (id, a) on good_col_grant to authenticated, service_role;
create sequence shared_seq;
create table bad_shared (id int default nextval('shared_seq') primary key);       -- non-owned sequence
alter table bad_shared enable row level security;
grant select, insert on bad_shared to authenticated, service_role;
create table bad_parted (id int, k int) partition by range (k);
alter table bad_parted enable row level security;
create table bad_parted_p1 partition of bad_parted for values from (0) to (10);   -- partition, RLS off
grant select on bad_parted_p1 to anon;

-- review round 2 cases
create materialized view bad_new_matview as select 1 as x;                         -- no grants, cannot have RLS
create table good_col_insert (id serial primary key, a text);                      -- insert only on column a
alter table good_col_insert enable row level security;
grant select, insert (a) on good_col_insert to authenticated, service_role;
