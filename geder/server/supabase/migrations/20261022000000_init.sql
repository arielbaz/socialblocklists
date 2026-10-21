-- GEDER — schéma initial (Supabase / PostgreSQL 15+).
--
-- Principes :
-- * Aucun historique de navigation n'est stocké : seulement les demandes d'ouverture
--   que l'utilisateur envoie lui-même.
-- * RLS partout. Les appareils et le site public n'écrivent jamais directement :
--   ils passent par des fonctions serveur (clé service_role), qui valident tout.
-- * Les décisions de l'équipe filtrage passent par une fonction contrôlée
--   (decide_access_request), jamais par un UPDATE libre.

-- ---------------------------------------------------------------------------
-- Inscriptions bêta (page d'attente)
-- ---------------------------------------------------------------------------

create table public.beta_signups (
    id          uuid primary key default gen_random_uuid(),
    email       text not null check (email = lower(email) and email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' and length(email) <= 254),
    name        text check (length(name) <= 120),
    country     text not null check (country in ('FR', 'IL', 'BE', 'CH', 'CA', 'US', 'GB', 'other')),
    audience    text not null check (audience in ('family', 'personal', 'institution')),
    devices     smallint check (devices between 1 and 5000),
    community   text check (length(community) <= 200),
    message     text check (length(message) <= 1000),
    locale      text not null default 'fr' check (locale in ('fr', 'he', 'en')),
    consent_at  timestamptz not null,
    created_at  timestamptz not null default now()
);
create unique index beta_signups_email_key on public.beta_signups (email);

-- RLS sans politique : seul service_role (route serveur du site) lit et écrit.
alter table public.beta_signups enable row level security;

-- ---------------------------------------------------------------------------
-- Foyers, institutions, membres, équipe GEDER
-- ---------------------------------------------------------------------------

create table public.households (
    id          uuid primary key default gen_random_uuid(),
    name        text not null check (length(name) between 1 and 120),
    kind        text not null check (kind in ('family', 'personal', 'institution')),
    created_at  timestamptz not null default now()
);

create table public.household_members (
    household_id uuid not null references public.households (id) on delete cascade,
    user_id      uuid not null references auth.users (id) on delete cascade,
    -- admin : parent, conjoint, Rav ou tiers de confiance qui détient le PIN.
    role         text not null check (role in ('admin', 'member')),
    created_at   timestamptz not null default now(),
    primary key (household_id, user_id)
);
create index household_members_user_idx on public.household_members (user_id);

-- Équipe GEDER : responsable filtrage (« mashgiach numérique »), Rav superviseur, support.
create table public.staff (
    user_id     uuid primary key references auth.users (id) on delete cascade,
    role        text not null check (role in ('mashgiach', 'rav', 'support')),
    created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Appareils
-- ---------------------------------------------------------------------------

create table public.devices (
    id            uuid primary key default gen_random_uuid(),
    household_id  uuid not null references public.households (id) on delete cascade,
    label         text not null check (length(label) between 1 and 80),
    platform      text not null check (platform in ('android', 'windows', 'ios', 'macos', 'browser')),
    -- SHA-256 du jeton de l'appareil ; le jeton lui-même n'est jamais stocké.
    token_hash    bytea not null unique check (length(token_hash) = 32),
    created_at    timestamptz not null default now(),
    last_seen_at  timestamptz
);
create index devices_household_idx on public.devices (household_id);

-- ---------------------------------------------------------------------------
-- Demandes d'ouverture et règles par foyer
-- ---------------------------------------------------------------------------

create domain public.domain_name as text
    check (length(value) <= 253
       and value = lower(value)
       and value ~ '^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$');

create table public.access_requests (
    id             uuid primary key default gen_random_uuid(),
    household_id   uuid not null references public.households (id) on delete cascade,
    device_id      uuid references public.devices (id) on delete set null,
    domain         public.domain_name not null,
    reason         text check (length(reason) <= 500),
    status         text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
    -- household : ouvert pour ce foyer seulement ; global : ajouté à la liste commune.
    scope          text check (scope in ('household', 'global')),
    decided_by     uuid references auth.users (id),
    decided_at     timestamptz,
    decision_note  text check (length(decision_note) <= 500),
    created_at     timestamptz not null default now(),
    check ((status = 'pending') = (decided_at is null)),
    check ((status = 'approved') = (scope is not null))
);
create index access_requests_pending_idx on public.access_requests (created_at) where status = 'pending';
create index access_requests_household_idx on public.access_requests (household_id, created_at desc);
-- Une seule demande en attente par foyer et par domaine.
create unique index access_requests_one_pending on public.access_requests (household_id, domain) where status = 'pending';

-- Règles propres à un foyer, publiées en liste signée « foyer-<id> ».
create table public.household_rules (
    household_id       uuid not null references public.households (id) on delete cascade,
    rule               text not null check (length(rule) <= 255 and rule = lower(rule) and rule ~ '^(\*\.)?[a-z0-9_.-]+$'),
    source_request_id  uuid references public.access_requests (id) on delete set null,
    created_at         timestamptz not null default now(),
    primary key (household_id, rule)
);

-- Règles ajoutées à la liste commune, en attente de la prochaine publication.
create table public.global_rules (
    rule               text primary key check (length(rule) <= 255 and rule = lower(rule) and rule ~ '^(\*\.)?[a-z0-9_.-]+$'),
    source_request_id  uuid references public.access_requests (id) on delete set null,
    added_by           uuid references auth.users (id),
    created_at         timestamptz not null default now()
);

-- Historique des listes signées publiées (le fichier lui-même est sur le stockage objet).
create table public.list_publications (
    id            uuid primary key default gen_random_uuid(),
    name          text not null check (name ~ '^[a-z0-9-]{1,64}$'),
    version       bigint not null check (version > 0),
    sha256        text not null check (sha256 ~ '^[0-9a-f]{64}$'),
    storage_path  text not null,
    published_at  timestamptz not null default now(),
    unique (name, version)
);

-- ---------------------------------------------------------------------------
-- Fonctions d'autorisation (security definer : évite la récursion des politiques RLS)
-- ---------------------------------------------------------------------------

create function public.is_staff() returns boolean
language sql stable security definer set search_path = '' as $$
    select exists (select 1 from public.staff where user_id = auth.uid());
$$;

create function public.is_household_member(hid uuid) returns boolean
language sql stable security definer set search_path = '' as $$
    select exists (select 1 from public.household_members where household_id = hid and user_id = auth.uid());
$$;

create function public.is_household_admin(hid uuid) returns boolean
language sql stable security definer set search_path = '' as $$
    select exists (
        select 1 from public.household_members
        where household_id = hid and user_id = auth.uid() and role = 'admin'
    );
$$;

-- ---------------------------------------------------------------------------
-- Politiques RLS
-- ---------------------------------------------------------------------------

alter table public.households        enable row level security;
alter table public.household_members enable row level security;
alter table public.staff             enable row level security;
alter table public.devices           enable row level security;
alter table public.access_requests   enable row level security;
alter table public.household_rules   enable row level security;
alter table public.global_rules      enable row level security;
alter table public.list_publications enable row level security;

create policy households_read on public.households
    for select to authenticated using (public.is_household_member(id) or public.is_staff());

create policy members_read on public.household_members
    for select to authenticated using (public.is_household_member(household_id) or public.is_staff());

create policy staff_read_self on public.staff
    for select to authenticated using (user_id = auth.uid());

create policy devices_read on public.devices
    for select to authenticated using (public.is_household_member(household_id) or public.is_staff());
-- Les admins du foyer renomment ou retirent un appareil ; l'enrôlement passe par le serveur.
create policy devices_admin_update on public.devices
    for update to authenticated
    using (public.is_household_admin(household_id))
    with check (public.is_household_admin(household_id));
create policy devices_admin_delete on public.devices
    for delete to authenticated using (public.is_household_admin(household_id));

create policy requests_read on public.access_requests
    for select to authenticated using (public.is_household_member(household_id) or public.is_staff());
-- Un admin du foyer peut demander une ouverture depuis la console (les appareils passent par le serveur).
create policy requests_admin_insert on public.access_requests
    for insert to authenticated
    with check (public.is_household_admin(household_id) and status = 'pending' and decided_at is null);

create policy household_rules_read on public.household_rules
    for select to authenticated using (public.is_household_member(household_id) or public.is_staff());

create policy global_rules_read on public.global_rules
    for select to authenticated using (public.is_staff());

create policy publications_read on public.list_publications
    for select to authenticated using (true);

-- Le reste (écritures) n'a pas de politique : refusé à anon et authenticated.
revoke update, delete on public.access_requests from anon, authenticated;
revoke insert, update, delete on public.household_rules, public.global_rules, public.list_publications, public.staff
    from anon, authenticated;

-- ---------------------------------------------------------------------------
-- Décision de l'équipe filtrage
-- ---------------------------------------------------------------------------

-- Accepte ou refuse une demande en attente. Acceptée : la règle exacte du domaine est
-- ajoutée au foyer (scope « household ») ou à la liste commune (scope « global »).
create function public.decide_access_request(
    request_id uuid,
    approve boolean,
    decision_scope text default 'household',
    note text default null
) returns public.access_requests
language plpgsql security definer set search_path = '' as $$
declare
    req public.access_requests;
begin
    if not public.is_staff() then
        raise exception 'réservé à l''équipe GEDER' using errcode = '42501';
    end if;
    if approve and decision_scope not in ('household', 'global') then
        raise exception 'portée invalide : %', decision_scope using errcode = '22023';
    end if;

    update public.access_requests
       set status        = case when approve then 'approved' else 'rejected' end,
           scope         = case when approve then decision_scope end,
           decided_by    = auth.uid(),
           decided_at    = now(),
           decision_note = note
     where id = request_id and status = 'pending'
    returning * into req;

    if not found then
        raise exception 'demande introuvable ou déjà traitée' using errcode = 'P0002';
    end if;

    if approve and decision_scope = 'household' then
        insert into public.household_rules (household_id, rule, source_request_id)
        values (req.household_id, req.domain, req.id)
        on conflict do nothing;
    elsif approve then
        insert into public.global_rules (rule, source_request_id, added_by)
        values (req.domain, req.id, auth.uid())
        on conflict do nothing;
    end if;
    return req;
end;
$$;

revoke execute on function public.decide_access_request(uuid, boolean, text, text) from public, anon;
grant execute on function public.decide_access_request(uuid, boolean, text, text) to authenticated;

-- File d'attente de l'équipe filtrage, la plus ancienne d'abord (objectif : < 2 h en journée).
create view public.pending_requests_queue with (security_invoker = true) as
select r.id, r.domain, r.reason, r.created_at, now() - r.created_at as waiting,
       h.name as household_name, h.kind as household_kind,
       (select count(*) from public.access_requests o where o.domain = r.domain and o.status = 'pending') as same_domain_pending
  from public.access_requests r
  join public.households h on h.id = r.household_id
 where r.status = 'pending'
 order by r.created_at;
