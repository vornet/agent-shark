#!/bin/sh
set -eu
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEST="${XDG_DATA_HOME:-$HOME/.local/share}/agent-shark"
if [ "$(id -u)" = 0 ]; then echo 'Run the portable installer as your desktop user, without sudo.' >&2; exit 1; fi
mkdir -p "$DEST/server" "$DEST/setup"
cp -R "$SOURCE/server/." "$DEST/server/"
cp -R "$SOURCE/setup/." "$DEST/setup/"
for name in README.md LICENSE THIRD-PARTY-NOTICES.md THIRD-PARTY-LICENSES.txt uninstall.sh; do cp "$SOURCE/$name" "$DEST/$name"; done
chmod 755 "$DEST/server/AgentShark.Server" "$DEST/setup/AgentShark.Setup" "$DEST/uninstall.sh"
"$DEST/setup/AgentShark.Setup" integrate --clients detected
printf '\nAgentShark installed in %s. Restart connected AI clients.\n' "$DEST"
