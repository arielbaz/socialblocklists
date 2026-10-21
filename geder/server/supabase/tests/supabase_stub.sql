-- Imitation minimale de l'environnement Supabase, pour tester les migrations sur un
-- PostgreSQL nu : rôles, schéma auth, auth.uid(), droits par défaut du schéma public.
create role anon nologin;
create role authenticated nologin;
create role service_role nologin bypassrls;

create schema auth;
create table auth.users (id uuid primary key);
-- Supabase lit le « sub » du JWT ; ici, le test le fixe avec set request.jwt.claim.sub.
create function auth.uid() returns uuid language sql stable as $$
    select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;
grant usage on schema auth to anon, authenticated, service_role;

-- Comme Supabase : tout est accordé par défaut, c'est la RLS qui restreint.
grant usage on schema public to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
