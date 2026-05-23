#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

# Remove cron entry
( crontab -l 2>/dev/null | grep -v "ddos-guard.sh" ) | crontab - || true
echo "Removed cron entry (if present)."

# Remove nftables table (drops all sets and rules atomically)
if nft list table inet ddos_guard >/dev/null 2>&1; then
  nft delete table inet ddos_guard
  echo "Deleted nftables table 'inet ddos_guard'."
else
  echo "nftables table 'inet ddos_guard' not found — nothing to remove."
fi

echo "Uninstall complete."
