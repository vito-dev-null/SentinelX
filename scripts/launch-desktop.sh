#!/usr/bin/env sh
set -eu

APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ -n "${JAVA_BIN:-}" ]; then
    JAVA_BIN=$(readlink -f "$JAVA_BIN")
    JAVA_HOME=${JAVA_HOME:-$(CDPATH= cd -- "$(dirname -- "$JAVA_BIN")/.." && pwd)}
    LD_LIBRARY_PATH="$JAVA_HOME/lib:$JAVA_HOME/lib/server${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export LD_LIBRARY_PATH
else
    DEFAULT_JAVA="$HOME/.jdk/sentinelx-jdk25/jdk-25.0.2/bin/java"
    JAVA_BIN=$([ -x "$DEFAULT_JAVA" ] && printf '%s' "$DEFAULT_JAVA" || command -v java || true)
    JAVA_BIN=$(readlink -f "$JAVA_BIN")
    JAVA_HOME=$(CDPATH= cd -- "$(dirname -- "$JAVA_BIN")/.." && pwd)
    LD_LIBRARY_PATH="$JAVA_HOME/lib:$JAVA_HOME/lib/server${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export JAVA_HOME LD_LIBRARY_PATH
fi
export JAVA_HOME
export SystemRoot=${SystemRoot:-/}
JAR="$APP_DIR/target/enterprise-siem-1.0.0-shaded.jar"
CONFIG=${1:-$APP_DIR/config/server.properties}
export SENTINELX_CLUSTER_CONFIG="$CONFIG"
\. "$APP_DIR/scripts/cluster-autodetect.sh"
CONFIGURED_SOC_URL=$(awk -F= '$1 == "soc.remoteUrl" {print $2; exit}' "$CONFIG" 2>/dev/null || true)
SOC_URL=${SENTINELX_SOC_URL:-${CONFIGURED_SOC_URL:-http://127.0.0.1:8080}}
LOG_DIR="$APP_DIR/logs"
LOG_FILE="$LOG_DIR/desktop-launcher.log"
PID_FILE=${SENTINELX_PID_FILE:-$LOG_DIR/sentinelx-server.pid}
CURL_BIN=/usr/bin/curl
URL=$SOC_URL

mkdir -p "$LOG_DIR"
log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE"; }
fail() {
    log "ERROR: $*"
    if [ -x /usr/bin/notify-send ]; then
        /usr/bin/notify-send --urgency=critical "SentinelX Node 3" "$*" || true
    fi
    exit 1
}
ready() {
    "$CURL_BIN" --fail --silent --show-error --max-time 2 "$URL/health" >/dev/null 2>&1 &&
    "$CURL_BIN" --fail --silent --show-error --max-time 2 "$URL/dashboard" >/dev/null 2>&1
}
gui_ready() {
    if command -v xdotool >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then
        xdotool search --name 'SentinelX 3' >/dev/null 2>&1
    else
        return 0
    fi
}

[ -n "$JAVA_BIN" ] && [ -x "$JAVA_BIN" ] || fail "Java non trovato"
[ -r "$JAR" ] || fail "JAR non trovato: $JAR"
[ -r "$CONFIG" ] || fail "Configurazione non trovata: $CONFIG"
[ -x "$CURL_BIN" ] || fail "curl non trovato: $CURL_BIN"

role=$(awk -F= '$1 == "node.role" {print $2; exit}' "$CONFIG" 2>/dev/null || true)
if [ "$role" = WORKER ]; then
    mode=STANDALONE
else
    if mode=$(cluster_mode "$CONFIG" 2>&1); then
        :
    else
        fail "Tailscale non disponibile: $mode"
    fi
fi
case "$mode" in
    REMOTE\ *)
        SOC_URL=${mode#REMOTE }
        URL=$SOC_URL
        export SENTINELX_SOC_URL="$SOC_URL"
        case "$SOC_URL" in http://127.0.0.1:*|http://localhost:*) ;; *) stop_local_backend ;; esac
        ready || fail "Worker rilevato ma API non disponibile: $SOC_URL"
        log "Modalita REMOTE-FIRST; worker API $SOC_URL"
        ;;
    STANDALONE)
        export SENTINELX_SOC_URL="http://127.0.0.1:8080"
        URL=$SENTINELX_SOC_URL
        if ! ready; then
            log "Tailscale connesso; nessun worker disponibile. Avvio controller locale"
            cd "$APP_DIR"
            SENTINELX_FORCE_STANDALONE=true setsid nohup "$JAVA_BIN" --enable-native-access=ALL-UNNAMED -jar "$JAR" server --config "$CONFIG" \
                >> "$LOG_FILE" 2>&1 </dev/null &
            printf '%s\n' "$!" > "$PID_FILE"
            end=$(($(date +%s) + 30))
            while [ "$(date +%s)" -lt "$end" ] && ! ready; do sleep 1; done
        fi
        ready || fail "Backend standalone non pronto entro 30 secondi"
        log "Modalita STANDALONE; backend locale disponibile"
        ;;
    *)
        fail "Modalita cluster non riconosciuta: $mode"
        ;;
esac
log "Dashboard embedded pronta"
if [ "${SENTINELX_PRINT_URL:-0}" = "1" ]; then
    printf '%s\n' "$URL"
fi
