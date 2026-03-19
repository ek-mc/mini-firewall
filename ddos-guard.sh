#!/usr/bin/env bash
set -euo pipefail

# Minimal cron-based connection flood guard
# - Scans active TCP connections to protected ports
# - If IP exceeds threshold, blocks via ipset+iptables
# - Uses native ipset timeout (no manual bans file)

# ===== Config =====
PROTECTED_PORTS="80,443"
THRESHOLD_PER_IP=120
BAN_SECONDS=900
STATE_DIR="/var/lib/ddos-guard"
CONFIG_DIR="/etc/ddos-guard"
WHITELIST_FILE="$CONFIG_DIR/whitelist.txt"
LOG_FILE="/var/log/ddos-guard.log"
LOCK_FILE="/var/run/ddos-guard.lock"
IPSET_NAME="ddos_block"
DRY_RUN=0
# ================

usage() {
  cat <<USAGE
Usage: ddos-guard.sh [--dry-run] [--status] [--help]

Options:
  --dry-run   Detect and log what would be banned, without changing firewall/ipset
  --status    Show current set/rule status and recent log tail
  --help      Show this help
USAGE
}

log(){
  printf '%s %s\n' "$(date -Is)" "$*" >> "$LOG_FILE"
}

need_root(){
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
  fi
}

ensure_dirs(){
  mkdir -p "$STATE_DIR" "$CONFIG_DIR"
  touch "$LOG_FILE"
  touch "$WHITELIST_FILE"
}

ensure_lock(){
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    log "SKIP lock_busy file=$LOCK_FILE"
    exit 0
  fi
}

ensure_firewall(){
  command -v ipset >/dev/null 2>&1 || { echo "Missing ipset"; exit 1; }
  command -v iptables >/dev/null 2>&1 || { echo "Missing iptables"; exit 1; }

  ipset list "$IPSET_NAME" >/dev/null 2>&1 || ipset create "$IPSET_NAME" hash:ip timeout "$BAN_SECONDS" -exist

  if ! iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    if (( DRY_RUN == 1 )); then
      log "DRYRUN would_insert_iptables_rule ipset=$IPSET_NAME"
    else
      iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
      log "Inserted INPUT drop rule for ipset:$IPSET_NAME"
    fi
  fi
}

is_public_ipv4(){
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  [[ "$ip" =~ ^10\. ]] && return 1
  [[ "$ip" =~ ^127\. ]] && return 1
  [[ "$ip" =~ ^192\.168\. ]] && return 1
  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 1
  [[ "$ip" =~ ^169\.254\. ]] && return 1
  return 0
}

is_whitelisted(){
  local ip="$1"
  [[ -f "$WHITELIST_FILE" ]] || return 1
  grep -q -E "^${ip}(\s|$)" "$WHITELIST_FILE"
}

ban_ip(){
  local ip="$1" count="$2"

  if is_whitelisted "$ip"; then
    log "SKIP whitelist ip=$ip count=$count"
    return
  fi

  if (( DRY_RUN == 1 )); then
    log "DRYRUN BAN ip=$ip count=$count ttl=${BAN_SECONDS}s"
    return
  fi

  ipset add "$IPSET_NAME" "$ip" timeout "$BAN_SECONDS" -exist
  log "BAN ip=$ip count=$count ttl=${BAN_SECONDS}s"
}

scan_and_ban(){
  local ports_regex
  ports_regex=$(echo "$PROTECTED_PORTS" | sed 's/,/|/g')

  # Count current established/syn-recv remote IPs hitting protected local ports
  ss -Hnt state established,syn-recv '( sport = :'"$ports_regex"' )' 2>/dev/null \
    | awk '{print $5}' \
    | sed 's/\[//g;s/\]//g' \
    | awk -F':' '{print $1}' \
    | sort | uniq -c \
    | while read -r cnt ip; do
        [[ -z "${ip:-}" ]] && continue
        is_public_ipv4 "$ip" || continue
        if (( cnt >= THRESHOLD_PER_IP )); then
          ban_ip "$ip" "$cnt"
        fi
      done
}

show_status(){
  local members=0
  if ipset list "$IPSET_NAME" >/dev/null 2>&1; then
    members=$(ipset list "$IPSET_NAME" | awk '/^Number of entries:/ {print $4}')
  fi

  echo "mini-firewall status"
  echo "- set: $IPSET_NAME"
  echo "- members: ${members:-0}"
  echo "- ban_seconds: $BAN_SECONDS"
  echo "- threshold_per_ip: $THRESHOLD_PER_IP"
  echo "- protected_ports: $PROTECTED_PORTS"
  echo "- whitelist_file: $WHITELIST_FILE"

  if iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    echo "- iptables_rule: present"
  else
    echo "- iptables_rule: missing"
  fi

  if [[ -f "$LOG_FILE" ]]; then
    echo
    echo "last log lines:"
    tail -n 10 "$LOG_FILE" || true
  fi
}

parse_args(){
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --status)
        ensure_dirs
        ensure_firewall
        show_status
        exit 0
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        echo "Unknown option: $1" >&2
        usage
        exit 1
        ;;
    esac
  done
}

main(){
  need_root
  parse_args "$@"
  ensure_dirs
  ensure_lock
  ensure_firewall
  scan_and_ban
}

main "$@"
