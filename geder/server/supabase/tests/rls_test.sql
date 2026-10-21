-- Tests des droits (RLS) et du circuit des demandes d'ouverture.
-- Chaque contrôle lève une exception en cas d'échec (psql ON_ERROR_STOP).

create schema t;
grant usage on schema t to anon, authenticated, service_role;

create function t.check(ok boolean, label text) returns void language plpgsql as $$
begin
    if ok is not true then
        raise exception 'ÉCHEC : %', label;
    end if;
    raise notice 'ok  %', label;
end $$;

-- Vrai si l'instruction échoue (exécutée avec les droits de l'appelant).
create function t.fails(stmt text) returns boolean language plpgsql as $$
begin
    execute stmt;
    return false;
exception when others then
    return true;
end $$;

grant execute on all functions in schema t to anon, authenticated, service_role;

-- Utilisateurs : A admin du foyer 1, B membre du foyer 1, C admin du foyer 2, S mashgiach.
insert into auth.users (id) values
    ('00000000-0000-0000-0000-00000000000a'),
    ('00000000-0000-0000-0000-00000000000b'),
    ('00000000-0000-0000-0000-00000000000c'),
    ('00000000-0000-0000-0000-00000000000f');
insert into public.households (id, name, kind) values
    ('10000000-0000-0000-0000-000000000001', 'Famille Cohen', 'family'),
    ('10000000-0000-0000-0000-000000000002', 'Yeshiva Test', 'institution');
insert into public.household_members (household_id, user_id, role) values
    ('10000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', 'admin'),
    ('10000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000b', 'member'),
    ('10000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000c', 'admin');
insert into public.staff (user_id, role) values ('00000000-0000-0000-0000-00000000000f', 'mashgiach');
insert into public.devices (id, household_id, label, platform, token_hash) values
    ('20000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000001', 'Téléphone de David', 'android', sha256('jeton-1')),
    ('20000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000002', 'PC salle 1', 'windows', sha256('jeton-2'));
-- Demande envoyée par un appareil (via le serveur, en service_role).
insert into public.access_requests (id, household_id, device_id, domain, reason) values
    ('30000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000001',
     '20000000-0000-0000-0000-000000000001', 'www.bank-example.fr', 'virement'),
    ('30000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000002',
     '20000000-0000-0000-0000-000000000002', 'cours.torah-example.org', null);

-- Validation des données -------------------------------------------------------

select t.check(t.fails($$insert into public.access_requests (household_id, domain) values ('10000000-0000-0000-0000-000000000001', 'Pas Un Domaine')$$),
               'domaine invalide refusé');
select t.check(t.fails($$insert into public.access_requests (household_id, domain) values ('10000000-0000-0000-0000-000000000001', 'www.bank-example.fr')$$),
               'une seule demande en attente par foyer et domaine');
select t.check(t.fails($$insert into public.beta_signups (email, country, audience, consent_at) values ('Majuscule@Exemple.fr', 'FR', 'family', now())$$),
               'e-mail non normalisé refusé');
select t.check(t.fails($$update public.access_requests set status = 'approved' where id = '30000000-0000-0000-0000-000000000001'$$),
               'statut accepté sans portée ni date refusé (contrainte)');

-- Visiteur anonyme (site public) ----------------------------------------------

set role anon;
select t.check((select count(*) from public.beta_signups) = 0, 'anon : inscriptions bêta illisibles');
select t.check(t.fails($$insert into public.beta_signups (email, country, audience, consent_at) values ('a@b.fr', 'FR', 'family', now())$$),
               'anon : inscription directe refusée (passe par la route serveur)');
select t.check((select count(*) from public.households) = 0, 'anon : aucun foyer visible');
select t.check((select count(*) from public.access_requests) = 0, 'anon : aucune demande visible');
reset role;

-- B : simple membre du foyer 1 --------------------------------------------------

set role authenticated;
set request.jwt.claim.sub = '00000000-0000-0000-0000-00000000000b';
select t.check((select count(*) from public.households) = 1, 'membre : voit son seul foyer');
select t.check((select count(*) from public.access_requests) = 1, 'membre : voit les demandes de son foyer seulement');
select t.check((select count(*) from public.devices) = 1, 'membre : voit les appareils de son foyer seulement');
select t.check(t.fails($$insert into public.access_requests (household_id, domain) values ('10000000-0000-0000-0000-000000000001', 'autre-site.fr')$$),
               'membre : ne peut pas créer de demande');
select t.check(t.fails($$select public.decide_access_request('30000000-0000-0000-0000-000000000001', true)$$),
               'membre : ne peut pas décider');
select t.check(t.fails($$update public.access_requests set reason = 'pirate' where id = '30000000-0000-0000-0000-000000000001'$$),
               'membre : modification de demande refusée');
delete from public.devices where id = '20000000-0000-0000-0000-000000000001';
reset role;
select t.check(exists (select 1 from public.devices where id = '20000000-0000-0000-0000-000000000001'),
               'membre : suppression d''appareil sans effet');

-- A : admin du foyer 1 -----------------------------------------------------------

set role authenticated;
set request.jwt.claim.sub = '00000000-0000-0000-0000-00000000000a';
insert into public.access_requests (household_id, domain, reason)
    values ('10000000-0000-0000-0000-000000000001', 'www.horaires-example.fr', 'horaires de train');
select t.check((select count(*) from public.access_requests) = 2, 'admin : crée une demande pour son foyer');
select t.check(t.fails($$insert into public.access_requests (household_id, domain) values ('10000000-0000-0000-0000-000000000002', 'x-example.fr')$$),
               'admin : pas de demande pour un autre foyer');
select t.check(t.fails($$insert into public.access_requests (household_id, domain, status, scope, decided_at) values ('10000000-0000-0000-0000-000000000001', 'y-example.fr', 'approved', 'household', now())$$),
               'admin : ne peut pas créer une demande déjà acceptée');
update public.devices set label = 'Téléphone de Sarah' where id = '20000000-0000-0000-0000-000000000001';
update public.devices set label = 'piraté' where id = '20000000-0000-0000-0000-000000000002';
select t.check(t.fails($$insert into public.household_rules (household_id, rule) values ('10000000-0000-0000-0000-000000000001', 'casino-example.com')$$),
               'admin : ne peut pas s''ajouter une règle lui-même');
reset role;
select t.check((select label from public.devices where id = '20000000-0000-0000-0000-000000000001') = 'Téléphone de Sarah',
               'admin : renomme un appareil de son foyer');
select t.check((select label from public.devices where id = '20000000-0000-0000-0000-000000000002') = 'PC salle 1',
               'admin : ne touche pas aux appareils d''un autre foyer');

-- C : admin du foyer 2 -----------------------------------------------------------

set role authenticated;
set request.jwt.claim.sub = '00000000-0000-0000-0000-00000000000c';
select t.check((select count(*) from public.access_requests) = 1, 'autre foyer : ne voit pas les demandes du foyer 1');
select t.check((select count(*) from public.pending_requests_queue) = 1, 'autre foyer : file d''attente limitée à son foyer');
reset role;

-- S : mashgiach --------------------------------------------------------------------

set role authenticated;
set request.jwt.claim.sub = '00000000-0000-0000-0000-00000000000f';
select t.check((select count(*) from public.pending_requests_queue) = 3, 'équipe : voit toute la file d''attente');
select t.check((select domain from public.pending_requests_queue limit 1) = 'www.bank-example.fr', 'équipe : plus ancienne demande en tête');

select public.decide_access_request('30000000-0000-0000-0000-000000000001', true, 'household', 'banque vérifiée');
select t.check((select status from public.access_requests where id = '30000000-0000-0000-0000-000000000001') = 'approved', 'décision : acceptée');
select t.check((select decided_by from public.access_requests where id = '30000000-0000-0000-0000-000000000001') = '00000000-0000-0000-0000-00000000000f',
               'décision : auteur enregistré');
select t.check(exists (select 1 from public.household_rules where household_id = '10000000-0000-0000-0000-000000000001' and rule = 'www.bank-example.fr'),
               'décision : règle ajoutée au foyer');
select t.check(t.fails($$select public.decide_access_request('30000000-0000-0000-0000-000000000001', false)$$),
               'décision : une demande traitée ne se re-décide pas');
select t.check(t.fails($$select public.decide_access_request('30000000-0000-0000-0000-000000000002', true, 'partout')$$),
               'décision : portée invalide refusée');

select public.decide_access_request('30000000-0000-0000-0000-000000000002', true, 'global');
select t.check(exists (select 1 from public.global_rules where rule = 'cours.torah-example.org'), 'décision : règle ajoutée à la liste commune');
select t.check(not exists (select 1 from public.household_rules where rule = 'cours.torah-example.org'), 'décision globale : pas de règle de foyer');

select public.decide_access_request(id, false, note => 'site non conforme')
  from public.access_requests where domain = 'www.horaires-example.fr';
select t.check((select status from public.access_requests where domain = 'www.horaires-example.fr') = 'rejected', 'décision : refusée');
select t.check((select count(*) from public.pending_requests_queue) = 0, 'file d''attente vide');
select t.check(t.fails($$insert into public.list_publications (name, version, sha256, storage_path) values ('base-fr', 1, repeat('a', 64), 'x')$$),
               'équipe : publication de liste réservée au serveur');
reset role;

-- Le foyer voit sa nouvelle règle, l'autre foyer non.
set role authenticated;
set request.jwt.claim.sub = '00000000-0000-0000-0000-00000000000b';
select t.check((select count(*) from public.household_rules) = 1, 'membre : voit la règle ouverte pour son foyer');
select t.check((select count(*) from public.global_rules) = 0, 'membre : ne voit pas les règles communes en attente');
set request.jwt.claim.sub = '00000000-0000-0000-0000-00000000000c';
select t.check((select count(*) from public.household_rules) = 0, 'autre foyer : ne voit pas la règle du foyer 1');
reset role;

-- service_role (routes serveur) ------------------------------------------------------

set role service_role;
insert into public.beta_signups (email, name, country, audience, devices, locale, consent_at)
    values ('famille@example.fr', 'Famille Levy', 'FR', 'family', 3, 'fr', now());
select t.check(t.fails($$insert into public.beta_signups (email, country, audience, consent_at) values ('famille@example.fr', 'FR', 'family', now())$$),
               'service : e-mail en double refusé');
select t.check((select count(*) from public.beta_signups) = 1, 'service : inscription bêta enregistrée');
reset role;
