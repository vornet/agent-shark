#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$HERE" = /usr/local/lib/agent-shark ]; then
  if [ "$(id -u)" != 0 ]; then echo 'System package removal requires sudo.' >&2; exit 1; fi
  if [ -f "$HERE/install-uid" ]; then
    uid=$(cat "$HERE/install-uid")
    user=$(id -nu "$uid")
    sudo -H -u "$user" "$HERE/setup/AgentShark.Setup" remove --clients all || true
  fi
  rm -rf -- /usr/local/lib/agent-shark
  pkgutil --forget com.vornet.agentshark >/dev/null 2>&1 || true
else
  expected="${XDG_DATA_HOME:-$HOME/.local/share}/agent-shark"
  if [ "$HERE" != "$expected" ] || [ "$(id -u)" = 0 ]; then echo 'Refusing removal outside the expected per-user installation.' >&2; exit 1; fi
  "$HERE/setup/AgentShark.Setup" remove --clients all || true
  rm -rf -- "$HERE"
fi
echo 'AgentShark removed. Evidence, configuration backups and user-modified client entries were retained.'
