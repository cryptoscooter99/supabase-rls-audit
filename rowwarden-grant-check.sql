-- RowWarden grant check for Supabase's October 30, 2026 Data API change.
-- https://github.com/cryptoscooter99/supabase-rls-audit  (MIT, Fleur Collective, L.L.C.)
--
-- One read-only SELECT. It reads pg_catalog only and changes nothing.
-- Paste it into your project's SQL Editor and run it.
--
-- From October 30, 2026, new tables in `public` on existing projects no longer get automatic
-- grants for anon, authenticated and service_role. Existing tables keep the grants they have.
-- This query shows which mode your project is in, which tables the API roles cannot reach
-- (and the grant to fix it, if they should), and which reachable tables still have RLS off.
--
-- Columns: status (fix_first / check / info / mode), check, object, detail, fix.
-- Optional statements in the fix column are commented out with -- on purpose: run them only if
-- that role should reach the table.
with api_roles(role) as (
  select v.r from (values ('anon'), ('authenticated'), ('service_role')) v(r)
  where exists (select 1 from pg_roles where rolname = v.r)
),
-- old behaviour = default privileges (global or for schema public) give new tables created by
-- postgres all four of select/insert/update/delete for the role (directly or via PUBLIC)
auto_grant as (
  select ar.role,
         (select count(distinct a.privilege_type)
          from pg_default_acl d
          cross join lateral aclexplode(d.defaclacl) a
          where d.defaclnamespace in (0, coalesce((select oid from pg_namespace where nspname = 'public'), 0))
            and d.defaclobjtype = 'r'
            and pg_get_userbyid(d.defaclrole) = 'postgres'
            and a.grantee in (0, (select oid from pg_roles where rolname = ar.role))
            and a.privilege_type in ('SELECT', 'INSERT', 'UPDATE', 'DELETE')) = 4 as on_
  from api_roles ar
),
tbl as (
  select c.oid, format('%I.%I', n.nspname, c.relname) as obj, c.relkind, c.relrowsecurity, c.relispartition
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public'
    and c.relkind in ('r', 'p', 'v', 'm', 'f')
    and not exists (select 1 from pg_depend dp
                    where dp.classid = 'pg_class'::regclass and dp.objid = c.oid and dp.deptype = 'e')
),
-- column-level grants count as reachable (has_any_column_privilege is also true for table grants)
priv as (
  select t.oid, t.obj, t.relkind, t.relrowsecurity, t.relispartition, ar.role,
         has_any_column_privilege(ar.role, t.oid, 'SELECT') as s,
         has_any_column_privilege(ar.role, t.oid, 'INSERT') as i,
         has_any_column_privilege(ar.role, t.oid, 'UPDATE') as u,
         has_table_privilege(ar.role, t.oid, 'DELETE') as d
  from tbl t cross join api_roles ar
),
-- sequences used by a column default (serial or default nextval('...')); identity columns need none
col_seq as (
  select distinct ad.adrelid as table_oid, ad.adnum, s.oid as seq_oid, format('%I.%I', n.nspname, s.relname) as seq
  from pg_attrdef ad
  join pg_depend dp on dp.classid = 'pg_attrdef'::regclass and dp.objid = ad.oid
                   and dp.refclassid = 'pg_class'::regclass
  join pg_class s on s.oid = dp.refobjid and s.relkind = 'S'
  join pg_namespace n on n.oid = s.relnamespace
),
per_table as (
  select oid, obj, relkind, relrowsecurity, relispartition,
         case when relkind in ('v', 'm') then 'select' else 'select, insert, update, delete' end as privs,
         string_agg(role || ': ' || coalesce(nullif(
             concat(case when s then 'S' end, case when i then 'I' end,
                    case when u then 'U' end, case when d then 'D' end), ''), 'none'),
           ', ' order by role) as grants,
         array_agg(role order by role) filter (where role <> 'anon' and not (s or i or u or d)) as missing,
         bool_or(role in ('anon', 'authenticated') and (s or i or u or d)) as public_reachable
  from priv
  group by oid, obj, relkind, relrowsecurity, relispartition
),
rows_ as (
  -- mode: is the old auto-grant still on for new tables created by postgres?
  select 4 as ord, 'mode' as status, 'auto_grant' as check_, 'new tables in public' as object,
         case when bool_and(on_) then 'Old behaviour: new tables created by postgres are still granted to '
                                     || string_agg(role, ', ' order by role) || ' automatically.'
              when bool_or(on_) then 'Mixed: new tables created by postgres are granted automatically to '
                                     || string_agg(role, ', ' order by role) filter (where on_) || ' only.'
              else 'New behaviour: new tables created by postgres get no API grants until you add them. (Migrations that run as another role follow that role''s default privileges.)' end as detail,
         case when bool_or(on_) then 'Before October 30, add explicit grants (and a sequence grant for serial columns) to every migration that creates a table, so nothing breaks when the switch happens.'
              else 'Every table you create needs explicit grants, e.g. grant select, insert, update, delete on public.<table> to authenticated; plus grant usage, select on sequence <its sequence> for serial columns.' end as fix
  from auto_grant
  having count(*) > 0

  union all
  -- reachable with the public key, RLS off: the October 30 change does not touch these
  select 1, 'fix_first', 'rls_off_reachable', obj,
         'Reachable through the API (' || grants || ') with row level security off'
           || case when relispartition then ' (a partition: RLS on its parent does not cover direct queries to it)' else '' end
           || '. The October 30 change leaves existing tables as they are.',
         format('alter table %s enable row level security;  -- then add policies tied to the signed-in user', obj)
  from per_table
  where relkind in ('r', 'p') and not relrowsecurity and public_reachable

  union all
  -- the API roles cannot reach this object at all (partitions are reached through their parent)
  select case when 'service_role' = any(missing) then 2 else 3 end,
         case when 'service_role' = any(missing) then 'check' else 'info' end,
         'no_api_grant', obj,
         'No grant for ' || array_to_string(missing, ' or ') || ' (' || grants || '). '
           || case when 'service_role' = any(missing)
                   then 'Server code using the service role key through supabase-js or the REST API gets "permission denied" on it.'
                   else 'Fine for a server-only table; if signed-in users should reach it through the API, it needs a grant.' end
           || case when relkind in ('r', 'p') and not relrowsecurity
                   then ' Row level security is OFF on it, so turn it on before granting it to signed-in users.'
                   when relkind = 'v'
                   then ' It is a view: unless it uses security_invoker, it runs as its owner and bypasses RLS on its source tables.'
                   when relkind in ('m', 'f')
                   then ' It is a ' || case relkind when 'm' then 'materialized view' else 'foreign table' end
                        || ', which cannot have RLS: a role you grant it to sees every row.'
                   else '' end,
         concat_ws(' ',
           case when 'service_role' = any(missing) then
             format('grant %s on %s to service_role;', privs, obj)
             || coalesce((select string_agg(distinct format(' grant usage, select on sequence %s to service_role;', cs.seq), '')
                          from col_seq cs where cs.table_oid = per_table.oid), '') end,
           case when 'authenticated' = any(missing) then
             '-- optional, only if signed-in users should reach it:'
             || case when relkind in ('r', 'p') and not relrowsecurity
                     then format(' alter table %s enable row level security; (add policies first)', obj)
                     when relkind = 'v'
                     then format(' alter view %s set (security_invoker = true);', obj)
                     when relkind in ('m', 'f')
                     then ' (no RLS possible: every row is visible to roles you grant)'
                     else '' end
             || format(' grant %s on %s to authenticated;', privs, obj)
             || coalesce((select string_agg(distinct format(' grant usage, select on sequence %s to authenticated;', cs.seq), '')
                          from col_seq cs where cs.table_oid = per_table.oid), '') end)
  from per_table
  where missing is not null and not relispartition

  union all
  -- can insert into the table but not use the sequence behind a column default
  select 2, 'check', 'sequence_no_usage', cs.seq,
         p.role || ' can insert into ' || p.obj || ' but cannot use this sequence, so inserts fail with "permission denied for sequence".',
         format('grant usage, select on sequence %s to %s;', cs.seq, p.role)
  from col_seq cs
  join priv p on p.oid = cs.table_oid and p.role <> 'anon' and not p.relispartition
  where has_column_privilege(p.role, cs.table_oid, cs.adnum, 'INSERT')
    and not has_sequence_privilege(p.role, cs.seq_oid, 'USAGE')
)
select status, check_ as "check", object, detail, fix
from rows_
order by ord, object, check_, detail;
