# Site GEDER (Next.js)

Page d'attente bilingue (français `/fr`, hébreu `/he` de droite à gauche) avec
inscription à la bêta. L'objectif fixé par le dossier de projet est de 200 inscrits.

```bash
npm install
npm run dev          # http://localhost:3000 → /fr
npm test             # validation + route /api/beta
npm run build
```

L'inscription passe par la route serveur `/api/beta`. Elle valide les champs, limite
à 5 envois par adresse IP toutes les 10 minutes, et ignore discrètement les robots
(champ piège). Elle écrit ensuite dans `beta_signups` avec la clé `service_role`. Un
e-mail déjà inscrit reçoit la même réponse qu'un nouveau : on ne peut pas savoir qui est
inscrit. Sans variables Supabase, le formulaire affiche « les inscriptions ouvrent très
bientôt ».

Variables d'environnement : voir `.env.example`.

À faire avant la mise en ligne :
- Relecture du texte hébreu par un locuteur natif.
- Validation des textes (promesses produit, gratuité de la bêta) et de la mention RGPD
  par l'avocat vie privée.
- Nom de domaine définitif.
