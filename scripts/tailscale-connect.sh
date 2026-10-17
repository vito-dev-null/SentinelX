#!/usr/bin/env sh
set -eu

if ! command -v tailscale >/dev/null 2>&1; then
    printf '%s\n' 'tailscale CLI non trovato: installa Tailscale prima di continuare.' >&2
    exit 127
fi

if tailscale status --json 2>/dev/null | awk '/"BackendState": "Running"/{running=1} /"Online": true/{online=1} END{exit !(running && online)}'; then
    printf '%s\n' 'Tailscale gia connesso.'
    exit 0
fi

printf '%s\n' 'Tailscale non e connesso. Avvio tailscale up; completa l autenticazione nel browser.'
exec sudo tailscale up