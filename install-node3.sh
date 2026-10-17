#!/usr/bin/env sh
set -eu

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HOSTNAME_SHORT=${SENTINELX_NODE_NAME:-$(hostname -s)}
case "$HOSTNAME_SHORT" in
  nodo1)
    DEFAULT_INSTALL_DIR="$HOME/.local/share/sentinelx-node1"
    DESKTOP_NAME='SentinelX Node 1'
    DESKTOP_FILE_NAME='SentinelX-Node1.desktop'
    CONFIG_SOURCE="$SOURCE_DIR/config/server.properties"
    AGENT_CONFIG_SOURCE="$SOURCE_DIR/config/agent.properties"
    LAUNCH_COMMAND='launch-desktop.sh server.properties'
    NODE_NAME='Node 1'
    ;;
  nodo3)
    DEFAULT_INSTALL_DIR="$HOME/.local/share/sentinelx-node3"
    DESKTOP_NAME='SentinelX Node 3'
    DESKTOP_FILE_NAME='SentinelX-Node3.desktop'
    CONFIG_SOURCE="$SOURCE_DIR/config/examples/node3.properties"
    AGENT_CONFIG_SOURCE="$SOURCE_DIR/config/examples/node3-agent.properties"
    LAUNCH_COMMAND='launch-node3-desktop.sh'
    NODE_NAME='Node 3'
    ;;
  nodo2)
    DEFAULT_INSTALL_DIR="$HOME/.local/share/sentinelx-node2"
    DESKTOP_NAME='SentinelX Node 2'
    DESKTOP_FILE_NAME='SentinelX-Node2.desktop'
    CONFIG_SOURCE="$SOURCE_DIR/config/examples/node2-server.properties"
    AGENT_CONFIG_SOURCE="$SOURCE_DIR/config/examples/node2.properties"
    LAUNCH_COMMAND='launch-desktop.sh server.properties'
    NODE_NAME='Node 2'
    ;;
  *)
    printf '%s\n' "Unsupported host $HOSTNAME_SHORT; expected nodo1, nodo2 or nodo3." >&2
    exit 1
    ;;
esac
INSTALL_DIR=${1:-$DEFAULT_INSTALL_DIR}
DESKTOP_DIR=${XDG_APPLICATIONS_DIR:-"$HOME/.local/share/applications"}
DESKTOP_FILE="$DESKTOP_DIR/$DESKTOP_FILE_NAME"
JAR="$SOURCE_DIR/target/enterprise-siem-1.0.0-shaded.jar"

[ -r "$JAR" ] || { printf '%s\n' "Build artifact not found: $JAR" >&2; exit 1; }
[ -r "$CONFIG_SOURCE" ] || { printf '%s\n' "Server configuration not found: $CONFIG_SOURCE" >&2; exit 1; }
[ -r "$AGENT_CONFIG_SOURCE" ] || { printf '%s\n' "Agent configuration not found: $AGENT_CONFIG_SOURCE" >&2; exit 1; }

install -d "$INSTALL_DIR/target" "$INSTALL_DIR/config" "$INSTALL_DIR/assets" "$INSTALL_DIR/logs" "$INSTALL_DIR/scripts" "$DESKTOP_DIR"
install -m 0644 "$JAR" "$INSTALL_DIR/target/enterprise-siem-1.0.0-shaded.jar"
install -m 0644 "$SOURCE_DIR/assets/sentinelx-icon.svg" "$INSTALL_DIR/assets/sentinelx-icon.svg"
install -m 0644 "$CONFIG_SOURCE" "$INSTALL_DIR/config/server.properties"
install -m 0644 "$AGENT_CONFIG_SOURCE" "$INSTALL_DIR/config/agent.properties"
install -m 0644 "$SOURCE_DIR/config/rules.yaml" "$INSTALL_DIR/config/rules.yaml"
install -m 0755 "$SOURCE_DIR/scripts/launch-desktop.sh" "$INSTALL_DIR/scripts/launch-desktop.sh"
install -m 0755 "$SOURCE_DIR/scripts/cluster-autodetect.sh" "$INSTALL_DIR/scripts/cluster-autodetect.sh"
install -m 0755 "$SOURCE_DIR/scripts/cluster-control.sh" "$INSTALL_DIR/scripts/cluster-control.sh"
install -m 0755 "$SOURCE_DIR/scripts/stop.sh" "$INSTALL_DIR/scripts/stop.sh"
install -m 0755 "$SOURCE_DIR/scripts/sentinelx-cli.sh" "$INSTALL_DIR/scripts/sentinelx-cli.sh"
install -m 0755 "$SOURCE_DIR/scripts/start-server.sh" "$INSTALL_DIR/scripts/start-server.sh"
install -m 0755 "$SOURCE_DIR/scripts/start-agent.sh" "$INSTALL_DIR/scripts/start-agent.sh"
install -m 0755 "$SOURCE_DIR/scripts/tailscale-connect.sh" "$INSTALL_DIR/scripts/tailscale-connect.sh"
install -m 0755 "$SOURCE_DIR/scripts/launch-node3-desktop.sh" "$INSTALL_DIR/scripts/launch-node3-desktop.sh"

write_desktop() {
  desktop_file=$1
  name=$2
  exec_command=$3
  terminal=$4
  printf '%s\n' \
    '[Desktop Entry]' \
    'Type=Application' \
    "Name=$name" \
    "Comment=SentinelX $NODE_NAME" \
    "Exec=$INSTALL_DIR/scripts/$exec_command" \
    "Path=$INSTALL_DIR" \
    "Icon=$INSTALL_DIR/assets/sentinelx-icon.svg" \
    "Terminal=$terminal" \
    'StartupNotify=true' \
    'StartupWMClass=sentinelx-soc' \
    'Categories=Network;Security;' > "$DESKTOP_DIR/$desktop_file"
  if [ -d "$HOME/Desktop" ]; then install -m 0755 "$DESKTOP_DIR/$desktop_file" "$HOME/Desktop/$desktop_file"; fi
}

write_desktop "SentinelX-$HOSTNAME_SHORT.desktop" "SentinelX 3" "$LAUNCH_COMMAND" false
write_desktop "SentinelLog-$HOSTNAME_SHORT.desktop" "Sentinel Log" 'start-agent.sh' true

install -d "$INSTALL_DIR/deployment"
sed -e "s#@INSTALL_DIR@#$INSTALL_DIR#g" -e "s#@USER@#$(id -un)#g" \
  "$SOURCE_DIR/deployment/sentinelx-server.service.example" > "$INSTALL_DIR/deployment/sentinelx-server.service"
sed -e "s#@INSTALL_DIR@#$INSTALL_DIR#g" -e "s#@USER@#$(id -un)#g" \
  "$SOURCE_DIR/deployment/sentinelx-agent.service.example" > "$INSTALL_DIR/deployment/sentinelx-agent.service"

printf 'Installed %s in %s\n' "$DESKTOP_NAME" "$INSTALL_DIR"
printf 'Desktop entries: %s/SentinelX-%s.desktop and %s/SentinelLog-%s.desktop\n' "$DESKTOP_DIR" "$HOSTNAME_SHORT" "$DESKTOP_DIR" "$HOSTNAME_SHORT"
printf 'Services staged in %s/deployment; enable with: sudo install -m 0644 %s/deployment/*.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now sentinelx-server.service sentinelx-agent.service\n' "$INSTALL_DIR" "$INSTALL_DIR"
