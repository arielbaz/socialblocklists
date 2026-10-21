#!/usr/bin/env bash
# Test de la liaison JNI de geder-core sur une JVM de bureau (pas besoin du SDK Android).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="$here/out"
rm -rf "$out" && mkdir -p "$out/classes"

cargo build -q --manifest-path "$root/Cargo.toml" -p geder-core --features android
cargo build -q --manifest-path "$root/Cargo.toml" -p geder-list
tool="$root/target/debug/geder-list"

"$tool" keygen "$out/test.sec" "$out/test.pub" >/dev/null
"$tool" sign "$out/test.sec" "$root/lists/base-fr.txt" "$out/base-fr.signed" >/dev/null

javac -d "$out/classes" "$here"/src/dev/geder/core/*.java
java -Dstdout.encoding=UTF-8 -Djava.library.path="$root/target/debug" -cp "$out/classes" dev.geder.core.JniSmokeTest \
    "$out/test.pub" "$out/base-fr.signed" "$root/lists/base-fr.txt"
