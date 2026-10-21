#!/usr/bin/env bash
# Test de la liaison JNI (libgeder) sur une JVM de bureau, sans SDK Android.
# Usage : run.sh [--tun]
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="$here/out"
rm -rf "$out" && mkdir -p "$out/classes"

cargo build -q --manifest-path "$root/Cargo.toml" -p geder-android --features jni-test
cargo build -q --manifest-path "$root/Cargo.toml" -p geder-list
tool="$root/target/debug/geder-list"

"$tool" keygen "$out/test.sec" "$out/test.pub" >/dev/null
"$tool" sign "$out/test.sec" "$root/lists/base-fr.txt" "$out/base-fr.signed" >/dev/null

javac -d "$out/classes" "$here"/src/dev/geder/core/*.java
# Le test du tunnel crée une interface TUN : il faut root. `--tun` le lance via sudo.
runner=()
if [[ "$(id -u)" == 0 ]]; then
    export GEDER_JNI_TUN=1
elif [[ "${1:-}" == "--tun" ]]; then
    export GEDER_JNI_TUN=1
    runner=(sudo -E)
fi
"${runner[@]}" "$(command -v java)" -Dstdout.encoding=UTF-8 -Djava.library.path="$root/target/debug" -cp "$out/classes" dev.geder.core.JniSmokeTest \
    "$out/test.pub" "$out/base-fr.signed" "$root/lists/base-fr.txt"
