#!/usr/bin/env sh
set -eu
APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CONFIG=${SENTINELX_NODE3_CONFIG:-$APP_DIR/config/server.properties}
JAVA_BIN=${JAVA_BIN:-$(command -v java || true)}
JAR="$APP_DIR/target/enterprise-siem-1.0.0-shaded.jar"
[ -n "$JAVA_BIN" ] && [ -x "$JAVA_BIN" ] || { printf '%s\n' 'Java non trovato' >&2; exit 1; }
[ -r "$JAR" ] || { printf '%s\n' "JAR non trovato: $JAR" >&2; exit 1; }
[ -r "$CONFIG" ] || { printf '%s\n' "Configurazione Node 3 non trovata: $CONFIG" >&2; exit 1; }
cd "$APP_DIR"
SENTINELX_SOC_URL=$(
	SENTINELX_PID_FILE="$APP_DIR/logs/sentinelx-node3.pid" \
		SENTINELX_PRINT_URL=1 \
		"$APP_DIR/scripts/launch-desktop.sh" "$CONFIG"
)
export SENTINELX_SOC_URL
exec "$JAVA_BIN" -Dprism.order=sw --enable-native-access=ALL-UNNAMED -jar "$JAR" desktop --config "$CONFIG" \
	>> "$APP_DIR/logs/desktop-launcher.log" 2>&1