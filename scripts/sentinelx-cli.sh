#!/usr/bin/env sh
set -eu
APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEFAULT_JAVA="$HOME/.jdk/sentinelx-jdk25/jdk-25.0.2/bin/java"
JAVA_BIN=${JAVA_BIN:-$([ -x "$DEFAULT_JAVA" ] && printf '%s' "$DEFAULT_JAVA" || command -v java || true)}
JAVA_BIN=$(readlink -f "$JAVA_BIN")
JAVA_HOME=${JAVA_HOME:-$(CDPATH= cd -- "$(dirname -- "$JAVA_BIN")/.." && pwd)}
LD_LIBRARY_PATH="$JAVA_HOME/lib:$JAVA_HOME/lib/server${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export JAVA_HOME LD_LIBRARY_PATH
export SystemRoot=${SystemRoot:-/}
JAR="$APP_DIR/target/enterprise-siem-1.0.0-shaded.jar"
CONFIG="$APP_DIR/config/server.properties"
export SENTINELX_CLUSTER_CONFIG="$CONFIG"
\. "$APP_DIR/scripts/cluster-autodetect.sh"
CONFIGURED_SOC_URL=$(awk -F= '$1 == "soc.remoteUrl" {print $2; exit}' "$CONFIG" 2>/dev/null || true)
SOC_URL=${SENTINELX_SOC_URL:-${CONFIGURED_SOC_URL:-http://127.0.0.1:8080}}
[ -x /usr/bin/curl ] || { printf '%s\n' 'SENTINELX BACKEND: FAILED' 'REASON: curl is required for health polling' >&2; exit 1; }
[ -n "$JAVA_BIN" ] && [ -x "$JAVA_BIN" ] || { printf '%s\n' 'Java non trovato' >&2; exit 1; }
[ -r "$JAR" ] || { printf '%s\n' "JAR non trovato: $JAR" >&2; exit 1; }
[ -r "$CONFIG" ] || { printf '%s\n' "Configurazione non trovata: $CONFIG" >&2; exit 1; }
cd "$APP_DIR"

health() { /usr/bin/curl --fail --silent --show-error --max-time 2 "$SOC_URL/health" >/dev/null 2>&1; }

command=${1:-cli}
mode=$(cluster_mode "$CONFIG")
case "$mode" in
	REMOTE\ *)
		SOC_URL=${mode#REMOTE }
		export SENTINELX_SOC_URL="$SOC_URL"
		case "$SOC_URL" in http://127.0.0.1:*|http://localhost:*) ;; *) stop_local_backend ;; esac
		;;
	STANDALONE)
		SOC_URL=http://127.0.0.1:8080
		export SENTINELX_SOC_URL="$SOC_URL"
		if [ "$command" != "dispatch" ] && ! health; then
			SENTINELX_FORCE_STANDALONE=true setsid nohup "$JAVA_BIN" --enable-native-access=ALL-UNNAMED -jar "$JAR" server --config "$CONFIG" \
				>> "$APP_DIR/logs/cli-backend.log" 2>&1 </dev/null &
			backend_pid=$!
			end=$(($(date +%s) + 30))
			while [ "$(date +%s)" -lt "$end" ] && ! health; do sleep 1; done
			if ! health; then
				printf '%s\n' 'SENTINELX BACKEND: FAILED' "REASON: standalone backend unavailable (PID $backend_pid)" >&2
				exit 1
			fi
		fi
		;;
esac
if [ "$command" != "dispatch" ] && ! health; then
	printf '%s\n' 'SENTINELX BACKEND: UNAVAILABLE' "REASON: API unavailable at $SOC_URL" >&2
	exit 1
fi
if [ "$command" != "dispatch" ]; then
	printf '%s\n' 'SENTINELX BACKEND: UP' 'ACTION: using existing backend'
fi

"$JAVA_BIN" --enable-native-access=ALL-UNNAMED -jar "$JAR" cli "$@"
exit $?