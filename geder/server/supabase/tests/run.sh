#!/usr/bin/env bash
# Applique les migrations sur un PostgreSQL jetable et lance les tests RLS.
# Prérequis : binaires PostgreSQL 15+ (initdb, pg_ctl, psql).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
migrations="$here/../migrations"
pgbin="${PG_BIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}"
export PATH="$pgbin:$PATH"

work="$(mktemp -d)"
# PostgreSQL refuse de tourner en root : on utilise alors un compte sans privilège.
as_db=()
if [[ "$(id -u)" == 0 ]]; then
    chown nobody "$work"
    as_db=(runuser -u nobody --)
fi
cleanup() {
    "${as_db[@]}" pg_ctl -D "$work/data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

"${as_db[@]}" initdb -D "$work/data" -U postgres --auth=trust >/dev/null
"${as_db[@]}" pg_ctl -D "$work/data" -o "-k $work -c listen_addresses=''" -l "$work/log" -w start >/dev/null

psql_run() { "${as_db[@]}" psql -h "$work" -U postgres -v ON_ERROR_STOP=1 -q "$@"; }
psql_run -d postgres -c "create database geder"
psql_run -d geder -f "$here/supabase_stub.sql"
for m in "$migrations"/*.sql; do
    psql_run -d geder -f "$m"
done
psql_run -d geder -At -f "$here/rls_test.sql" 2>&1 | sed -n -e 's/^.*NOTICE:  //p' -e '/ERROR/p'
test "${PIPESTATUS[0]}" -eq 0
echo "Supabase : migrations et tests RLS ok"
