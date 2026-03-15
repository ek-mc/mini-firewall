#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$BASE_DIR/ddos-guard.sh"
IPSET_NAME="ddos_block"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

( crontab -l 2>/dev/null | grep -v "ddos-guard.sh" ) | crontab - || true
iptables -D INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
ipset destroy "$IPSET_NAME" 2>/dev/null || true

echo "Uninstalled cron + firewall set/rule (if present)."
