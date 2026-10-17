#!/usr/bin/env sh
set -eu
APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$APP_DIR"
CONFIG="${1:-$APP_DIR/config/agent.properties}"
export SENTINELX_CLUSTER_CONFIG="${SENTINELX_CLUSTER_CONFIG:-$APP_DIR/config/server.properties}"
\. "$APP_DIR/scripts/cluster-autodetect.sh"
require_tailscale
mode=$(cluster_mode "$SENTINELX_CLUSTER_CONFIG")
JAVA_BIN=${JAVA_BIN:-$(command -v java || true)}
if [ -z "$JAVA_BIN" ] && [ -x "$HOME/.local/jvm/java-25-openjdk-amd64/bin/java" ]; then
	JAVA_BIN="$HOME/.local/jvm/java-25-openjdk-amd64/bin/java"
fi
[ -n "$JAVA_BIN" ] && [ -x "$JAVA_BIN" ] || { printf '%s\n' 'Java 25 non trovato' >&2; exit 1; }
case "$mode" in
	REMOTE\ *)
		worker_url=${mode#REMOTE }
		worker_host=$(printf '%s\n' "$worker_url" | sed -E 's#^[a-zA-Z]+://([^:/]+).*#\1#')
		export SENTINELX_SIEM_HOST="$worker_host"
		;;
	STANDALONE)
		export SENTINELX_FORCE_STANDALONE=true
		if ! /usr/bin/curl --fail --silent --max-time 2 http://127.0.0.1:8080/health >/dev/null 2>&1; then
			setsid nohup "$JAVA_BIN" --enable-native-access=ALL-UNNAMED -jar "$APP_DIR/target/enterprise-siem-1.0.0-shaded.jar" server --config "$APP_DIR/config/server.properties" \
				>> "$APP_DIR/logs/standalone-agent-backend.log" 2>&1 </dev/null &
		fi
		;;
esac
exec "$JAVA_BIN" --enable-native-access=ALL-UNNAMED -jar "$APP_DIR/target/enterprise-siem-1.0.0-shaded.jar" agent --config "$CONFIG"
