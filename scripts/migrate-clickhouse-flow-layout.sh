#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
MIGRATION_MAX_THREADS="${MIGRATION_MAX_THREADS:-2}"
MIGRATION_MAX_MEMORY_BYTES="${MIGRATION_MAX_MEMORY_BYTES:-2147483648}"

for value in "$RETENTION_DAYS" "$MIGRATION_MAX_THREADS" "$MIGRATION_MAX_MEMORY_BYTES"; do
  if [[ ! "$value" =~ ^[0-9]+$ ]] || [[ "$value" == "0" ]]; then
    echo "numeric migration settings must be positive integers" >&2
    exit 2
  fi
done

if [[ "${CONFIRM_CLICKHOUSE_FLOW_MIGRATION:-}" != "yes" ]]; then
  cat >&2 <<'EOF'
Refusing to modify ClickHouse without explicit confirmation.
Review disk headroom, then run:
  CONFIRM_CLICKHOUSE_FLOW_MIGRATION=yes scripts/migrate-clickhouse-flow-layout.sh

The script stops the Controller while copying flow_records, atomically renames the tables,
and keeps the previous table as flow_records_legacy_<UTC timestamp> for rollback.
EOF
  exit 2
fi

compose=(docker compose --env-file "$ENV_FILE")
stamp="$(date -u +%Y%m%d%H%M%S)"
staging_table="flow_records_v2_${stamp}"
legacy_table="flow_records_legacy_${stamp}"
controller_was_running=false

if "${compose[@]}" ps --status running --services | grep -qx controller; then
  controller_was_running=true
  "${compose[@]}" stop controller
fi

restart_controller() {
  if [[ "$controller_was_running" == true ]]; then
    "${compose[@]}" start controller >/dev/null
  fi
}
trap restart_controller EXIT

ch() {
  local query="$1"
  printf '%s\n' "$query" | "${compose[@]}" exec -T clickhouse sh -lc '
    exec clickhouse-client \
      --user "$CLICKHOUSE_USER" \
      --password "$CLICKHOUSE_PASSWORD" \
      --database "$CLICKHOUSE_DB"
  '
}

current_engine="$(ch "SELECT engine FROM system.tables WHERE database=currentDatabase() AND name='flow_records' FORMAT TSVRaw")"
if [[ -z "$current_engine" ]]; then
  echo "flow_records does not exist; no migration is required" >&2
  exit 1
fi

available_bytes="$(ch "SELECT available_space FROM system.disks WHERE name='default' FORMAT TSVRaw")"
source_bytes="$(ch "SELECT coalesce(total_bytes, 0) FROM system.tables WHERE database=currentDatabase() AND name='flow_records' FORMAT TSVRaw")"
required_bytes=$((source_bytes + source_bytes / 5))
if (( available_bytes < required_bytes )); then
  echo "insufficient ClickHouse disk headroom: available=${available_bytes}, required~=${required_bytes}" >&2
  exit 1
fi

ch "
CREATE TABLE ${staging_table}
(
  sensor_id String,
  batch_id String,
  record_index UInt32,
  timestamp DateTime64(6, 'UTC'),
  data String,
  ingested_at DateTime64(6, 'UTC')
)
ENGINE=ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (sensor_id,timestamp,batch_id,record_index)
TTL toDateTime(timestamp) + INTERVAL ${RETENTION_DAYS} DAY DELETE
"

cutoff="$(ch "SELECT formatDateTime(now() - INTERVAL ${RETENTION_DAYS} DAY, '%Y-%m-%d %H:%i:%S', 'UTC') FORMAT TSVRaw")"

ch "
INSERT INTO ${staging_table}
SELECT sensor_id,batch_id,record_index,timestamp,data,ingested_at
FROM flow_records
WHERE timestamp >= parseDateTime64BestEffort('${cutoff}')
SETTINGS max_threads=${MIGRATION_MAX_THREADS}, max_memory_usage=${MIGRATION_MAX_MEMORY_BYTES}
"

source_rows="$(ch "SELECT count() FROM flow_records WHERE timestamp >= parseDateTime64BestEffort('${cutoff}') FORMAT TSVRaw")"
staging_rows="$(ch "SELECT count() FROM ${staging_table} FORMAT TSVRaw")"
if [[ "$source_rows" != "$staging_rows" ]]; then
  echo "row-count verification failed: source=${source_rows}, staging=${staging_rows}" >&2
  exit 1
fi

ch "RENAME TABLE flow_records TO ${legacy_table}, ${staging_table} TO flow_records"

cat <<EOF
ClickHouse flow layout migration completed.
New table: flow_records
Rollback table: ${legacy_table}
Rows copied: ${source_rows}

After at least one successful live and historical analysis, remove the rollback table manually:
  docker compose --env-file ${ENV_FILE} exec -T clickhouse clickhouse-client \
    --user '\$CLICKHOUSE_USER' --password '\$CLICKHOUSE_PASSWORD' \
    --database '\$CLICKHOUSE_DB' --query 'DROP TABLE ${legacy_table}'
EOF
