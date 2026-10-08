#!/bin/bash
# Installs the root helper, the sudoers line that lets the MCP server read the
# rules, and the rules for programs whose path changes on every start.
#
#   sudo -A bash install.sh
set -e

if [ "$(id -u)" != 0 ]; then
  echo "run this as root: sudo -A bash install.sh" >&2
  exit 1
fi

USER_NAME=${SUDO_USER:-$(logname)}
USER_HOME=$(getent passwd "$USER_NAME" | cut -d: -f6)
SRC=$(cd "$(dirname "$0")" && pwd)
RULES=/etc/opensnitchd/rules

install -o root -g root -m 0755 "$SRC/opensnitch-rulectl" /usr/local/bin/opensnitch-rulectl

TMP=$(mktemp)
{
  echo '# Lets the opensnitch_mcp server read the firewall rules without a password.'
  echo '# Installing a rule is not covered here: it goes through sudo -A instead, so'
  echo '# the user confirms every change to the firewall.'
  echo "$USER_NAME ALL=(root) NOPASSWD: /usr/local/bin/opensnitch-rulectl dump"
} > "$TMP"
visudo -c -q -f "$TMP"
install -o root -g root -m 0440 "$TMP" /etc/sudoers.d/opensnitch-rulectl
rm -f "$TMP"

write_rule() {
  python3 - "$RULES/$1.json" "$1" "$2" "$3" <<'PY'
import json, os, sys
from datetime import datetime, timezone

target, name, data, note = sys.argv[1:5]
now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
rule = {
    "created": now, "updated": now, "name": name, "description": note,
    "action": "allow", "duration": "always", "enabled": True,
    "precedence": False, "nolog": False,
    "operator": {"operand": "process.path", "data": data, "type": "regexp",
                 "list": [], "sensitive": False},
}
with open(target, "w") as out:
    json.dump(rule, out, indent=2)
os.chmod(target, 0o600)
os.chown(target, 0, 0)
print(target)
PY
}

# Programs installed with am: one directory per app under /opt, each with an
# AM-updater script. am itself has none, so it drops out on its own.
am_apps() {
  for dir in /opt/*/; do
    [ -f "$dir/AM-updater" ] || continue
    basename "$dir"
  done
}

AM_NAMES=$(am_apps | sort | paste -sd'|')
if [ -n "$AM_NAMES" ]; then
  # An AppImage mounts itself on /tmp/.mount_ plus the first six characters of
  # its file name plus a random suffix.
  AM_PREFIXES=$(am_apps | cut -c1-6 | sort -u | paste -sd'|')

  write_rule allow-always-regexp-am-appimages \
    "^/tmp/\\.mount_($AM_PREFIXES)[a-z0-9]+/.+\$" \
    'AppImages installed with am: the mount point changes on every start'

  write_rule allow-always-regexp-am-opt \
    "^/opt/($AM_NAMES)/.+\$" \
    'Programs installed with am that run straight from /opt'
fi

write_rule allow-always-regexp-claude-versions \
  "^$(printf '%s' "$USER_HOME" | sed 's/\./\\\\./g')/\\.local/share/claude/versions/[0-9a-z.]+\$" \
  'Claude Code: the path carries the version, which changes on every update'

write_rule allow-always-regexp-ge-proton \
  "^$(printf '%s' "$USER_HOME" | sed 's/\./\\\\./g')/\\.local/share/Steam/compatibilitytools\\.d/GE-Proton[0-9]+-[0-9]+/files/bin/(wine-preloader|wine64-preloader|wineserver)\$" \
  'GE-Proton for Steam: the path carries the version, which changes on every update'

echo
ls -l /usr/local/bin/opensnitch-rulectl /etc/sudoers.d/opensnitch-rulectl
