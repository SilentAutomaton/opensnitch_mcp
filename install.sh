#!/bin/bash
# Installs the root helper, the sudoers line that lets the MCP server read the
# rules, and two rules for programs whose path changes on every start.
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

write_rule allow-always-regexp-telegram-appimage \
  '^/tmp/\.mount_telegr[a-z0-9]+/telegram$' \
  'Telegram AppImage from am: the mount point changes on every start'

write_rule allow-always-regexp-claude-versions \
  "^$(printf '%s' "$USER_HOME" | sed 's/\./\\\\./g')/\\.local/share/claude/versions/[0-9a-z.]+\$" \
  'Claude Code: the path carries the version, which changes on every update'

echo
ls -l /usr/local/bin/opensnitch-rulectl /etc/sudoers.d/opensnitch-rulectl
