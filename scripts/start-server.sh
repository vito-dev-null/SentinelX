#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
. "$(dirname "$0")/cluster-autodetect.sh"
require_tailscale
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
	JAVA_BIN="$JAVA_HOME/bin/java"
else
	JAVA_BIN="$(command -v java || true)"
fi
if [ -z "$JAVA_BIN" ] && [ -x "$HOME/.local/jvm/java-25-openjdk-amd64/bin/java" ]; then
	JAVA_BIN="$HOME/.local/jvm/java-25-openjdk-amd64/bin/java"
fi
if [ -z "$JAVA_BIN" ]; then
	printf '%s\n' 'Java 25 non trovato. Imposta JAVA_HOME o installa un JDK 25.' >&2
	exit 1
fi
exec "$JAVA_BIN" --enable-native-access=ALL-UNNAMED \
	-jar target/enterprise-siem-1.0.0-shaded.jar server
