# GEDER — filtre Internet en liste blanche (Aribaz)

Ce dossier est le monorepo technique de GEDER, construit à partir du dossier de projet
« GEDER — Dossier de projet Aribaz ». Il contient le cœur du produit : le moteur de
filtrage partagé, le tunnel complet qui fait passer tout le trafic par ce moteur, et le
prototype Android prévu en semaine 2 de la feuille de route.

## Principes

1. **Refus par défaut.** Seul ce qui figure sur une liste blanche passe.
2. **Liaison DNS → IP.** Le moteur résout lui-même chaque nom. Une connexion n'est
   ouverte que vers une IP que notre résolveur vient de renvoyer pour un domaine
   autorisé. Le DoH, les IP codées en dur et les VPN tiers échouent donc sans qu'on
   ait besoin de les connaître.
3. **Listes signées.** Chaque liste est signée en Ed25519 sur le serveur et vérifiée
   sur l'appareil. Une liste non signée, falsifiée ou plus ancienne est refusée.
4. **Aucun déchiffrement.** On ne lit que le DNS et le SNI TLS, qui circulent en clair.
   Aucun certificat racine n'est installé sur les téléphones.
5. **Rien ne quitte l'appareil.** L'historique de navigation reste local.

## Contenu

```
geder/
├── core/                 Moteur Rust partagé (geder-core)
│   ├── src/domain.rs     Noms de domaine + trie de suffixes (labels inversés)
│   ├── src/dns.rs        Lecture/écriture DNS bornée (compression, anti-boucle)
│   ├── src/packet.rs     En-têtes IPv4/IPv6/TCP/UDP, réponses UDP avec sommes de contrôle
│   ├── src/tls.rs        SNI du ClientHello, détection de l'ECH
│   ├── src/binding.rs    Table de liaison DNS → IP (TTL bornés, capacité limitée)
│   ├── src/list.rs       Format de liste, signature et vérification Ed25519
│   ├── src/engine.rs     Le moteur : décisions DNS, connexions, paquets TUN
│   ├── src/pin.rs        PIN administrateur : Argon2id + blocage progressif
│   └── jni-test/         Test de la liaison JNI sur une JVM de bureau
├── tunnel/               Tunnel complet (geder-tunnel) : pile TCP/IP en espace
│   │                     utilisateur (ipstack) devant le moteur
│   └── tests/tun_e2e.rs  Test de bout en bout sur une vraie interface TUN Linux
├── android-ffi/          libgeder.so pour Android : moteur + tunnel, liaison JNI
├── tools/geder-list/     Outil serveur : clés, signature, vérification, test de domaine
├── lists/                Listes sources (non signées) : intégrée, France, Israël
├── android/              Prototype Android (Kotlin) : VpnService + Device Owner
└── docs/                 Exemple de QR code de provisionnement
```

## Ce que fait le moteur

| Situation | Décision |
|---|---|
| Requête DNS pour un domaine hors liste | `NXDOMAIN`, et le domaine est signalé (futur bouton « demander l'ouverture ») |
| Requête DNS A / AAAA pour un domaine autorisé | Transmise au résolveur amont, puis les IP sont liées au domaine |
| Requête HTTPS / SVCB (porteuse des clés ECH) | Réponse vide |
| Connexion vers une IP non liée (DoH, IP codée en dur, VPN tiers) | Refusée |
| UDP 443 (QUIC / HTTP3) | Refusé, pour forcer TCP |
| Port 853 (DNS sur TLS), DNS vers un autre résolveur | Refusés |
| ICMP et autres protocoles | Refusés |
| IP de CDN partagée, mais SNI d'un site interdit | Refusé |
| ClientHello avec ECH (SNI chiffré) | Refusé |
| Aucune liste chargée | Seules les règles intégrées passent (*fail-closed*) |

Les règles intégrées (`lists/integre.txt`) sont compilées dans le binaire : service GEDER,
urgences (Pikud HaOref, Magen David Adom), vérifications de connectivité et heure réseau.

## Format des listes

```text
!geder-list 1
!name base-fr
!version 2026102101
# commentaire
impots.gouv.fr          ← ce nom exact
*.impots.gouv.fr        ← tous ses sous-domaines (pas le nom lui-même)
!signature ed25519:…    ← ajoutée par `geder-list sign`
```

La version doit augmenter à chaque publication, faute de quoi l'appareil refuse la liste.

## Construire et tester

Prérequis : Rust stable (1.80 ou plus) et Java 17 pour le test JNI.

```bash
cd geder
cargo test --workspace                      # tests du moteur
cargo run -p geder-list -- check lists/*.txt
./core/jni-test/run.sh                      # liaison JNI, sur JVM de bureau
./core/jni-test/run.sh --tun                # idem + démarrage du tunnel (sudo)
sudo -E cargo test -p geder-tunnel --test tun_e2e -- --ignored   # tunnel de bout en bout
```

Le test de bout en bout crée une interface TUN Linux et y fait passer de vraies
connexions : IP non résolue refusée, domaine bloqué (`NXDOMAIN`), domaine autorisé
résolu puis joignable, SNI interdit coupé, QUIC refusé, UDP relayé, DNS sur TCP.

Outil de listes :

```bash
geder-list keygen cle.sec cle.pub           # cle.sec va dans le coffre, jamais dans Git
geder-list sign cle.sec lists/base-fr.txt base-fr.signed.txt
geder-list verify cle.pub base-fr.signed.txt
geder-list match lists/base-fr.txt www.impots.gouv.fr www.youtube.com
```

La CI (`.github/workflows/geder.yml`) lance le formatage, Clippy, les tests, la
validation des listes, le test de bout en bout du tunnel et le test JNI à chaque
modification de `geder/`. Sur ce dépôt (un fork), il faut d'abord activer les
workflows dans l'onglet Actions.

## Prototype Android

Le service VPN fonctionne en **tunnel complet** (étape 2, mode par défaut). Tout le
trafic IPv4 et IPv6 entre dans la TUN, dont le descripteur est confié au tunnel Rust :

```
appli ──► TUN ──► pile TCP/IP (ipstack) ──► moteur : autorisé ? ──► socket protégée ──► Internet
                        │                         │
                        └── DNS 10.111.0.53 ──────┘  (liste blanche, puis Cloudflare Families)
```

- Une connexion vers une IP que notre DNS n'a pas renvoyée n'est jamais ouverte. Cela
  couvre le DoH, les IP codées en dur, les VPN et proxys intégrés (Opera, Tor…).
- Sur le port 443, le SNI du ClientHello est contrôlé avant la connexion : un site
  interdit hébergé sur le même CDN qu'un site autorisé reste bloqué.
- QUIC, DNS sur TLS, DNS vers un autre résolveur, ICMP : refusés.
- Les sockets sortantes du tunnel sont sorties du VPN par `VpnService.protect`,
  appelé depuis Rust par un rappel JNI.

Le **mode DNS** (étape 1) reste disponible en secours (`FULL_TUNNEL = false` dans
`GederVpnService`). Il ne route que le résolveur et reste contournable par une IP codée
en dur.

Le mode Device Owner verrouille l'appareil : pas de réinitialisation, pas de mode sans
échec, pas d'ADB, pas de VPN tiers, pas de nouvel utilisateur, désinstallation bloquée,
VPN toujours actif et verrouillé (sans GEDER, pas de réseau du tout).

> ⚠️ Le code Kotlin n'a pas encore été compilé : le SDK Android n'était pas disponible
> dans l'environnement où il a été écrit. Tout le code natif est testé sous Linux : le
> moteur, le tunnel sur une vraie interface TUN, et la liaison JNI, rappels `protect` et
> `onBlocked` compris. Première tâche sur un poste équipé : `./gradlew assembleDebug`.

Construire :

```bash
# Une fois : Android Studio (SDK 35 + NDK), puis
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk

./android/scripts/dev-sign-lists.sh         # clé de dev + listes signées dans les assets
cd android && gradle wrapper && ./gradlew assembleDebug   # compile aussi libgeder (Rust)
```

Tester sur un téléphone de test réinitialisé, sans compte Google :

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
adb shell dpm set-device-owner dev.geder.app/.GederAdminReceiver
adb logcat -s GederVpn GederCore GederLists GederPolicy
```

En production, le provisionnement se fait par QR code au premier démarrage, après une
réinitialisation d'usine. Un exemple de contenu est dans `docs/provisioning-qr.example.json`.

À vérifier en priorité sur téléphone :
1. Les sites des listes de départ s'ouvrent : il manque sans doute des domaines tiers (CDN).
2. Les applis bloquées échouent vite plutôt que de rester bloquées en attente.
3. Le Wi-Fi et la 4G passent de l'un à l'autre sans couper le filtre.
4. Consommation de batterie et débit, par exemple une vidéo autorisée en HD.

## Feuille de route technique

| Étape | État |
|---|---|
| Moteur : liste blanche, liaison DNS → IP, anti-contournement (QUIC, DoT, ECH, SNI) | ✅ fait, testé |
| Listes signées Ed25519, anti-retour en arrière, outil serveur | ✅ fait, testé |
| PIN Argon2id avec blocage progressif | ✅ fait, testé (pas encore branché dans l'UI) |
| Liaison JNI | ✅ fait, testé sur JVM |
| Tunnel complet : pile TCP/IP, relais TCP/UDP, SNI, DNS UDP et TCP | ✅ fait, testé sur une vraie interface TUN |
| Android : VpnService (tunnel complet + mode DNS de secours), Device Owner, provisionnement QR | ✏️ écrit, à compiler et tester sur téléphone |
| Équipe rouge : tentatives de contournement sur le prototype | ⏳ semaine 3 |
| Serveur (Supabase) : comptes, appareils, demandes d'ouverture, publication des listes | ⏳ |
| Console parent + landing bêta (Next.js) | ⏳ semaine 4 |
| Windows (service SYSTEM + WFP), extension navigateur | ⏳ MVP |
| iOS / macOS (Network Extension, MDM) | ⏳ phase 2 |

## Règles de sécurité

- Aucune clé secrète dans Git (`*.sec` est ignoré). La clé de signature des listes vit
  dans le coffre du serveur de publication.
- La clé de dev (`android/dev-keys/`) ne doit jamais signer une liste diffusée.
- Tout le code qui lit des paquets ou des messages réseau est en Rust, borné et testé
  contre les entrées tronquées ou aléatoires.
- Le code de verrouillage, de PIN et de signature doit passer une revue humaine avant
  toute diffusion, puis un audit externe avant le lancement.
