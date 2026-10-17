#!/usr/bin/env sh
set -eu
APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PID_FILE="$APP_DIR/logs/sentinelx-server.pid"
if [ ! -r "$PID_FILE" ]; then exit 0; fi
pid=$(cat "$PID_FILE")
case "$pid" in (*[!0-9]*|'') rm -f "$PID_FILE"; exit 0;; esac
if [ -r "/proc/$pid/cmdline" ]; then
	cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline")
	case "$cmdline" in (*"$APP_DIR/target/enterprise-siem-1.0.0-shaded.jar server"*) kill "$pid";; esac
fi
end=$(($(date +%s) + 10))
while [ "$(date +%s)" -lt "$end" ] && kill -0 "$pid" 2>/dev/null; do sleep 1; done
if kill -0 "$pid" 2>/dev/null; then exit 1; fi
rm -f "$PID_FILE"
