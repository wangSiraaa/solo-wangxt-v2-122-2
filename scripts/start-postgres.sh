#!/usr/bin/env bash
# Start a user-local PostgreSQL for development/testing.
#
# If $PG_HOME points at a standard installation containing
#   lib/postgresql/15/bin/{initdb,pg_ctl,postgres}
# it uses that; otherwise set PG_BINDIR explicitly.
set -euo pipefail

PG_BINDIR="${PG_BINDIR:-$PG_HOME/usr/lib/postgresql/15/bin}"
DATA_DIR="${PGDATA:-$HOME/pgdata}"
RUN_DIR="$HOME/pgrun"
PORT="${PGPORT:-55432}"
DB="${PGDATABASE:-dnszone}"
DBUSER="${PGUSER:-dnsadmin}"

[ -x "$PG_BINDIR/initdb" ] || { echo "set PG_BINDIR to a postgresql-15 bin dir"; exit 2; }
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-$PG_HOME/usr/lib/aarch64-linux-gnu}"
mkdir -p "$RUN_DIR"

if [ ! -d "$DATA_DIR/base" ]; then
  "$PG_BINDIR/initdb" -D "$DATA_DIR" -U "$DBUSER" --auth=trust --encoding=UTF8 -A trust
  cat >> "$DATA_DIR/postgresql.conf" <<EOF
listen_addresses = '127.0.0.1'
port = $PORT
unix_socket_directories = '$RUN_DIR'
fsync = off
synchronous_commit = off
full_page_writes = off
EOF
fi

"$PG_BINDIR/pg_ctl" -D "$DATA_DIR" -l "$DATA_DIR/server.log" -w start
"$PG_BINDIR/psql" -h 127.0.0.1 -p "$PORT" -U "$DBUSER" -d postgres -tc \
  "SELECT 1 FROM pg_database WHERE datname='$DB'" | grep -q 1 || \
  "$PG_BINDIR/createdb" -h 127.0.0.1 -p "$PORT" -U "$DBUSER" "$DB"
echo "PostgreSQL ready on 127.0.0.1:$PORT db=$DB"
