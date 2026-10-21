# Serveur GEDER (Supabase)

Le serveur ne voit jamais le trafic web : il stocke les comptes, les appareils, les
demandes d'ouverture et l'historique des listes publiées.

## Schéma (`supabase/migrations`)

| Table | Rôle |
|---|---|
| `beta_signups` | Inscriptions de la page d'attente (écriture par la route serveur du site uniquement) |
| `households`, `household_members` | Foyers, personnes et institutions ; membres `admin` (détient le PIN) ou `member` |
| `staff` | Équipe GEDER : `mashgiach`, `rav`, `support` |
| `devices` | Appareils enrôlés ; seul le SHA-256 du jeton d'appareil est stocké |
| `access_requests` | Demandes d'ouverture : `pending` → `approved` (foyer ou global) / `rejected` |
| `household_rules`, `global_rules` | Règles ouvertes par l'équipe, à publier en listes signées |
| `list_publications` | Historique des listes signées publiées |

Les décisions passent uniquement par `decide_access_request(id, approve, scope, note)`.
Cette fonction est réservée à l'équipe : elle horodate la décision, enregistre son
auteur et crée la règle. La vue `pending_requests_queue` donne la file d'attente, la
plus ancienne demande en tête (objectif : moins de 2 h en journée).

Aucun historique de navigation n'est stocké : seules les demandes que l'utilisateur
envoie lui-même arrivent ici.

## Tester

```bash
./supabase/tests/run.sh     # PostgreSQL 15+ local requis (initdb, pg_ctl, psql)
```

Le script démarre un PostgreSQL jetable et imite l'environnement Supabase (rôles `anon`,
`authenticated`, `service_role`, `auth.uid()`). Il applique ensuite les migrations et
vérifie 40 règles d'accès : chaque foyer ne voit que ses données, un membre ne peut ni
créer ni modifier de demande, seule l'équipe décide, etc.

## Mettre en production

1. Créer un projet Supabase (région UE pour le RGPD, ou proche d'Israël selon le marché).
2. `supabase link --project-ref <ref>` puis `supabase db push`.
3. Déclarer les membres de l'équipe dans `staff` (SQL, en tant que propriétaire).
4. Mettre `SUPABASE_URL` et `SUPABASE_SERVICE_ROLE_KEY` dans les variables
   d'environnement du site (`web/`). Cette clé ne doit jamais être exposée au navigateur.

## Prochaines étapes

- Fonction serveur pour enrôler un appareil (jeton) et recevoir ses demandes d'ouverture.
- Publication automatique : règles → liste signée (`geder-list sign`) → stockage
  objet → `list_publications`.
- Console : file d'attente de l'équipe et vue des parents.
