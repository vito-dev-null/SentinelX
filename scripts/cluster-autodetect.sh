#!/usr/bin/env sh
set -eu

tailscale_ready() {
    command -v tailscale >/dev/null 2>&1 || return 1
    tailscale status --json 2>/dev/null | awk '/"BackendState": "Running"/{running=1} /"Online": true/{online=1} END{exit !(running && online)}'
}

require_tailscale() {
    if ! tailscale_ready; then
        printf '%s\n' 'TAILSCALE_UNAVAILABLE: run scripts/tailscale-connect.sh and retry' >&2
        exit 78
    fi
}

# Prints configured worker API URLs, one per line.
cluster_worker_urls() {
    if [ -n "${SENTINELX_WORKER_URLS:-}" ]; then
        printf '%s\n' "$SENTINELX_WORKER_URLS" | tr ',' '\n'
    elif [ -n "${SENTINELX_CLUSTER_CONFIG:-}" ] && [ -r "$SENTINELX_CLUSTER_CONFIG" ]; then
        awk -F= '/^worker\.nodo(2|3)\.url=/ && $2 ~ /^https?:\/\// && $2 !~ /example\.invalid/ {print $2}' "$SENTINELX_CLUSTER_CONFIG"
    fi
}

probe_worker() {
    url=$1
    /usr/bin/curl --fail --silent --show-error --max-time "${SENTINELX_PROBE_TIMEOUT:-2}" \
        "$url/health" >/dev/null 2>&1
}

first_available_worker() {
    for url in $(cluster_worker_urls); do
        [ -n "$url" ] || continue
        if probe_worker "$url"; then
            printf '%s\n' "$url"
            return 0
        fi
    done
    return 1
}

stop_local_backend() {
    for status in /proc/[0-9]*/status; do
        pid=${status#/proc/}; pid=${pid%/status}
        [ "$pid" != "$$" ] || continue
        [ -r "/proc/$pid/cmdline" ] || continue
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline")
        case "$cmdline" in
            *"enterprise-siem-1.0.0-shaded.jar server"*)
                cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null || true)
                [ "$cwd" = "${APP_DIR:-}" ] || continue
                kill "$pid" 2>/dev/null || true
                ;;
        esac
    done
}

cluster_mode() {
    require_tailscale
    SENTINELX_CLUSTER_CONFIG=${1:-${SENTINELX_CLUSTER_CONFIG:-}} \
        export SENTINELX_CLUSTER_CONFIG
    if url=$(first_available_worker); then
        printf 'REMOTE %s\n' "$url"
    else
        printf '%s\n' 'STANDALONE'
    fi
}
