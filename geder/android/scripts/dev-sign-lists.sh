#!/usr/bin/env bash
# Signe les listes de départ avec une clé de DÉVELOPPEMENT et les place dans les
# assets de l'APK. En production, la signature se fait sur le serveur de publication,
# avec la clé du coffre ; cette clé de dev ne doit jamais signer une liste diffusée.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
keys="$root/android/dev-keys"
assets="$root/android/app/src/main/assets"

cargo build -q --manifest-path "$root/Cargo.toml" -p geder-list
tool="$root/target/debug/geder-list"

mkdir -p "$keys" "$assets/lists" "$assets/keys"
if [[ ! -f "$keys/dev.sec" ]]; then
    "$tool" keygen "$keys/dev.sec" "$keys/dev.pub"
fi
cp "$keys/dev.pub" "$assets/keys/list-signing.pub"

for list in "$root"/lists/base-*.txt; do
    "$tool" sign "$keys/dev.sec" "$list" "$assets/lists/$(basename "$list")"
done
