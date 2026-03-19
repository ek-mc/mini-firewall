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
METRICS_FILE="$STATE_DIR/metrics.prom"
STATS_FILE="$STATE_DIR/stats.env"
ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"
DRY_RUN=0
# ================

RUN_COUNT=0
BAN_COUNT=0
LAST_RUN_TS=0

usage() {
  cat <<USAGE
Usage: ddos-guard.sh [--dry-run] [--status] [--metrics] [--help]

Options:
  --dry-run   Detect and log what would be banned, without changing firewall/ipset
  --status    Show current set/rule status and recent log tail
  --metrics   Print + write Prometheus-style metrics snapshot
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

load_stats(){
  if [[ -f "$STATS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$STATS_FILE" || true
  fi
  RUN_COUNT="${RUN_COUNT:-0}"
  BAN_COUNT="${BAN_COUNT:-0}"
  LAST_RUN_TS="${LAST_RUN_TS:-0}"
}

save_stats(){
  cat > "$STATS_FILE" <<STATS
RUN_COUNT=$RUN_COUNT
BAN_COUNT=$BAN_COUNT
LAST_RUN_TS=$LAST_RUN_TS
STATS
}

send_alert(){
  local msg="$1"
  [[ -n "$ALERT_WEBHOOK_URL" ]] || return 0
  command -v curl >/dev/null 2>&1 || return 0
  curl -sS -m 5 -H 'Content-Type: application/json' \
    -d "{\"text\":\"$msg\"}" \
    "$ALERT_WEBHOOK_URL" >/dev/null 2>&1 || true
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
  BAN_COUNT=$((BAN_COUNT + 1))
  log "BAN ip=$ip count=$count ttl=${BAN_SECONDS}s"
  send_alert "mini-firewall BAN ip=$ip count=$count ttl=${BAN_SECONDS}s host=$(hostname)"
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

write_metrics(){
  local members=0
  if ipset list "$IPSET_NAME" >/dev/null 2>&1; then
    members=$(ipset list "$IPSET_NAME" | awk '/^Number of entries:/ {print $4}')
  fi

  cat > "$METRICS_FILE" <<METRICS
# HELP ddos_guard_run_count Number of guard runs
# TYPE ddos_guard_run_count counter
ddos_guard_run_count $RUN_COUNT
# HELP ddos_guard_ban_count Number of total bans issued
# TYPE ddos_guard_ban_count counter
ddos_guard_ban_count $BAN_COUNT
# HELP ddos_guard_last_run_unix Last run timestamp (unix)
# TYPE ddos_guard_last_run_unix gauge
ddos_guard_last_run_unix $LAST_RUN_TS
# HELP ddos_guard_blocklist_size Current number of IPs in blocklist
# TYPE ddos_guard_blocklist_size gauge
ddos_guard_blocklist_size ${members:-0}
METRICS
}

show_metrics(){
  write_metrics
  cat "$METRICS_FILE"
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
  echo "- metrics_file: $METRICS_FILE"

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
        load_stats
        show_status
        exit 0
        ;;
      --metrics)
        ensure_dirs
        ensure_firewall
        load_stats
        show_metrics
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
  load_stats
  RUN_COUNT=$((RUN_COUNT + 1))
  LAST_RUN_TS=$(date +%s)
  scan_and_ban
  save_stats
  write_metrics
}

main "$@"
