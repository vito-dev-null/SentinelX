#!/usr/bin/env sh
set -eu

APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CONFIG=${SENTINELX_CLUSTER_CONFIG:-$APP_DIR/config/server.properties}
. "$APP_DIR/scripts/cluster-autodetect.sh"
require_tailscale

health_status() {
    url=$1
    if /usr/bin/curl --fail --silent --show-error --max-time "${SENTINELX_PROBE_TIMEOUT:-2}" "$url/health" >/dev/null 2>&1; then
        printf 'UP'
    else
        printf 'DOWN'
    fi
}

worker_status() {
    url=$1
    value=$(/usr/bin/curl --fail --silent --show-error --max-time "${SENTINELX_PROBE_TIMEOUT:-2}" \
        "$url/api/worker/status" 2>/dev/null || true)
    case "$value" in
        *BUSY*) printf 'BUSY' ;;
        *AVAILABLE*) printf 'AVAILABLE' ;;
        *) printf 'UNKNOWN' ;;
    esac
}

command=${1:-status}
[ "$command" = status ] || { printf '%s\n' 'usage: cluster-control.sh status' >&2; exit 2; }

node1=$(health_status "${SENTINELX_LOCAL_URL:-http://127.0.0.1:8080}")
node2_url=${SENTINELX_NODE2_URL:-$(awk -F= '$1 == "worker.nodo2.url" {print $2; exit}' "$CONFIG" 2>/dev/null || true)}
node3_url=${SENTINELX_NODE3_URL:-$(awk -F= '$1 == "worker.nodo3.url" {print $2; exit}' "$CONFIG" 2>/dev/null || true)}
node2_url=${node2_url:-http://node2.example.invalid:8080}
node3_url=${node3_url:-http://node3.example.invalid:8080}
node2=$(health_status "$node2_url")
node3=$(health_status "$node3_url")
load='NONE'
if [ "$node2" = UP ]; then load="nodo2:$(worker_status "$node2_url")"; fi
if [ "$node3" = UP ]; then
    [ "$load" = NONE ] || load="$load "
    [ "$load" = NONE ] && load=''
    load="${load}nodo3:$(worker_status "$node3_url")"
fi

printf 'NODE1 controller=READY local-api=%s\n' "$node1"
printf 'TAILSCALE=CONNECTED\n'
printf 'NODE2_TARGET=%s\n' "$node2_url"
printf 'NODE3_TARGET=%s\n' "$node3_url"
printf 'NODE2 worker-api=%s\n' "$node2"
printf 'NODE3 worker-api=%s\n' "$node3"
printf 'HEAVY_WORKLOAD_OWNER=%s\n' "$load"
if [ "$node2" = UP ] || [ "$node3" = UP ]; then
    printf '%s\n' 'MODE=REMOTE'
else
    printf '%s\n' 'MODE=STANDALONE'
fi