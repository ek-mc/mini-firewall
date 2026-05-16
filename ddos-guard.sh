#!/usr/bin/env bash
set -euo pipefail

# Minimal cron-based connection flood guard
# - Scans active TCP connections to protected ports
# - If IP exceeds threshold, blocks via ipset+iptables (IPv4) and ip6tables+ipset (IPv6)
# - Uses native ipset timeout (no manual bans file)
# - Tracks repeat offenders and escalates to persistent blocklist after BAN_ESCALATE_THRESHOLD bans

# ===== Config =====
PROTECTED_PORTS="80,443"
THRESHOLD_PER_IP=120
BAN_SECONDS=900
BAN_ESCALATE_THRESHOLD=3       # bans in ESCALATE_WINDOW_SECONDS before persistent block
ESCALATE_WINDOW_SECONDS=86400  # 24 h window for repeat-offender counting
STATE_DIR="/var/lib/ddos-guard"
CONFIG_DIR="/etc/ddos-guard"
WHITELIST_FILE="$CONFIG_DIR/whitelist.txt"
LOG_FILE="/var/log/ddos-guard.log"
LOCK_FILE="/var/run/ddos-guard.lock"
IPSET_NAME="ddos_block"
IPSET6_NAME="ddos_block6"
PERSISTENT_SET="ddos_persistent"
PERSISTENT_SET6="ddos_persistent6"
OFFENDER_DIR="$STATE_DIR/offenders"
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
  mkdir -p "$STATE_DIR" "$CONFIG_DIR" "$OFFENDER_DIR"
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

  # IPv4 temporary ban set
  ipset list "$IPSET_NAME" >/dev/null 2>&1 || ipset create "$IPSET_NAME" hash:ip timeout "$BAN_SECONDS" -exist

  # IPv4 persistent ban set (no timeout — manual removal only)
  ipset list "$PERSISTENT_SET" >/dev/null 2>&1 || ipset create "$PERSISTENT_SET" hash:ip -exist

  if ! iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    if (( DRY_RUN == 1 )); then
      log "DRYRUN would_insert_iptables_rule ipset=$IPSET_NAME"
    else
      iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
      log "Inserted INPUT drop rule for ipset:$IPSET_NAME"
    fi
  fi

  if ! iptables -C INPUT -m set --match-set "$PERSISTENT_SET" src -j DROP 2>/dev/null; then
    if (( DRY_RUN == 1 )); then
      log "DRYRUN would_insert_iptables_rule ipset=$PERSISTENT_SET"
    else
      iptables -I INPUT -m set --match-set "$PERSISTENT_SET" src -j DROP
      log "Inserted INPUT drop rule for ipset:$PERSISTENT_SET"
    fi
  fi

  # IPv6 support (optional — skip gracefully if ip6tables unavailable)
  if command -v ip6tables >/dev/null 2>&1; then
    ipset list "$IPSET6_NAME" >/dev/null 2>&1 || \
      ipset create "$IPSET6_NAME" hash:ip family inet6 timeout "$BAN_SECONDS" -exist
    ipset list "$PERSISTENT_SET6" >/dev/null 2>&1 || \
      ipset create "$PERSISTENT_SET6" hash:ip family inet6 -exist

    if ! ip6tables -C INPUT -m set --match-set "$IPSET6_NAME" src -j DROP 2>/dev/null; then
      if (( DRY_RUN == 1 )); then
        log "DRYRUN would_insert_ip6tables_rule ipset=$IPSET6_NAME"
      else
        ip6tables -I INPUT -m set --match-set "$IPSET6_NAME" src -j DROP
        log "Inserted INPUT drop rule for ipset6:$IPSET6_NAME"
      fi
    fi

    if ! ip6tables -C INPUT -m set --match-set "$PERSISTENT_SET6" src -j DROP 2>/dev/null; then
      if (( DRY_RUN == 1 )); then
        log "DRYRUN would_insert_ip6tables_rule ipset=$PERSISTENT_SET6"
      else
        ip6tables -I INPUT -m set --match-set "$PERSISTENT_SET6" src -j DROP
        log "Inserted INPUT drop rule for ipset6:$PERSISTENT_SET6"
      fi
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

is_public_ipv6(){
  local ip="$1"
  # Must contain at least one colon to be IPv6
  [[ "$ip" == *:* ]] || return 1
  # Strip brackets if present (ss output can include them)
  ip="${ip#[}"
  ip="${ip%]}"
  # Loopback
  [[ "$ip" == "::1" ]] && return 1
  # Link-local fe80::/10
  [[ "${ip,,}" =~ ^fe8 ]] && return 1
  # Unique-local fc00::/7
  [[ "${ip,,}" =~ ^f[cd] ]] && return 1
  return 0
}

is_whitelisted(){
  local ip="$1"
  [[ -f "$WHITELIST_FILE" ]] || return 1
  grep -q -E "^${ip}(\s|$)" "$WHITELIST_FILE"
}

# ─── Repeat-offender escalation ───────────────────────────────────────────────
# Each banned IP gets a file under $OFFENDER_DIR/<ip_escaped> containing
# newline-separated Unix timestamps of recent bans.
# If the count within ESCALATE_WINDOW_SECONDS reaches BAN_ESCALATE_THRESHOLD,
# the IP is added to the persistent set and an escalation alert is sent.

_ip_to_filename(){
  # Replace characters unsafe for filenames (colons in IPv6) with underscores
  echo "${1//[:\/ ]/_}"
}

record_and_check_escalation(){
  local ip="$1"
  local fname
  fname="$OFFENDER_DIR/$(_ip_to_filename "$ip")"
  local now
  now=$(date +%s)
  local cutoff=$(( now - ESCALATE_WINDOW_SECONDS ))

  # Append current timestamp
  echo "$now" >> "$fname"

  # Count bans within the window
  local recent_count
  recent_count=$(awk -v cutoff="$cutoff" '$1 >= cutoff' "$fname" | wc -l)

  if (( recent_count >= BAN_ESCALATE_THRESHOLD )); then
    return 0  # escalate
  fi
  return 1  # normal ban only
}

escalate_ip(){
  local ip="$1" count="$2"
  local is_v6=0
  [[ "$ip" == *:* ]] && is_v6=1

  if (( DRY_RUN == 1 )); then
    log "DRYRUN ESCALATE ip=$ip count=$count (persistent)"
    return
  fi

  if (( is_v6 == 1 )) && command -v ip6tables >/dev/null 2>&1; then
    ipset add "$PERSISTENT_SET6" "$ip" -exist
    log "ESCALATE ip=$ip count=$count added to persistent set6:$PERSISTENT_SET6"
  else
    ipset add "$PERSISTENT_SET" "$ip" -exist
    log "ESCALATE ip=$ip count=$count added to persistent set:$PERSISTENT_SET"
  fi
  send_alert "mini-firewall ESCALATE (persistent ban) ip=$ip count=$count host=$(hostname)"
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

  local is_v6=0
  [[ "$ip" == *:* ]] && is_v6=1

  if (( is_v6 == 1 )) && command -v ip6tables >/dev/null 2>&1; then
    ipset add "$IPSET6_NAME" "$ip" timeout "$BAN_SECONDS" -exist
  else
    ipset add "$IPSET_NAME" "$ip" timeout "$BAN_SECONDS" -exist
  fi

  BAN_COUNT=$((BAN_COUNT + 1))
  log "BAN ip=$ip count=$count ttl=${BAN_SECONDS}s"
  send_alert "mini-firewall BAN ip=$ip count=$count ttl=${BAN_SECONDS}s host=$(hostname)"

  # Check for escalation to persistent block
  if record_and_check_escalation "$ip"; then
    escalate_ip "$ip" "$count"
  fi
}

scan_and_ban(){
  local ports_regex
  ports_regex=$(echo "$PROTECTED_PORTS" | sed 's/,/|/g')

  # Count current established/syn-recv remote IPs hitting protected local ports
  # ss output for IPv4: "ESTAB 0 0 0.0.0.0:443 1.2.3.4:54321"  -> field 5 is remote addr
  # ss output for IPv6: "ESTAB 0 0 [::]:443   [2001:db8::1]:54321" -> field 5 is remote addr
  ss -Hnt state established,syn-recv '( sport = :'"$ports_regex"' )' 2>/dev/null \
    | awk '{print $5}' \
    | sed 's/\[//g;s/\]//g' \
    | awk -F':' '
        # IPv6 addresses contain multiple colons; NF>2 means IPv6
        NF > 2 { addr=""; for(i=1;i<NF;i++) addr=addr (i>1?":":"") $i; print addr; next }
        # IPv4: last field is port, second-to-last is IP
        { print $(NF-1) }
      ' \
    | sort | uniq -c \
    | while read -r cnt ip; do
        [[ -z "${ip:-}" ]] && continue
        if is_public_ipv4 "$ip" || is_public_ipv6 "$ip"; then
          if (( cnt >= THRESHOLD_PER_IP )); then
            ban_ip "$ip" "$cnt"
          fi
        fi
      done
}

write_metrics(){
  local members=0 members6=0 persistent=0 persistent6=0
  if ipset list "$IPSET_NAME" >/dev/null 2>&1; then
    members=$(ipset list "$IPSET_NAME" | awk '/^Number of entries:/ {print $4}')
  fi
  if ipset list "$IPSET6_NAME" >/dev/null 2>&1; then
    members6=$(ipset list "$IPSET6_NAME" | awk '/^Number of entries:/ {print $4}')
  fi
  if ipset list "$PERSISTENT_SET" >/dev/null 2>&1; then
    persistent=$(ipset list "$PERSISTENT_SET" | awk '/^Number of entries:/ {print $4}')
  fi
  if ipset list "$PERSISTENT_SET6" >/dev/null 2>&1; then
    persistent6=$(ipset list "$PERSISTENT_SET6" | awk '/^Number of entries:/ {print $4}')
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
# HELP ddos_guard_blocklist_size Current number of IPs in temporary IPv4 blocklist
# TYPE ddos_guard_blocklist_size gauge
ddos_guard_blocklist_size ${members:-0}
# HELP ddos_guard_blocklist6_size Current number of IPs in temporary IPv6 blocklist
# TYPE ddos_guard_blocklist6_size gauge
ddos_guard_blocklist6_size ${members6:-0}
# HELP ddos_guard_persistent_size Current number of IPs in persistent IPv4 blocklist
# TYPE ddos_guard_persistent_size gauge
ddos_guard_persistent_size ${persistent:-0}
# HELP ddos_guard_persistent6_size Current number of IPs in persistent IPv6 blocklist
# TYPE ddos_guard_persistent6_size gauge
ddos_guard_persistent6_size ${persistent6:-0}
METRICS
}

show_metrics(){
  write_metrics
  cat "$METRICS_FILE"
}

show_status(){
  local members=0 members6=0 persistent=0 persistent6=0
  if ipset list "$IPSET_NAME" >/dev/null 2>&1; then
    members=$(ipset list "$IPSET_NAME" | awk '/^Number of entries:/ {print $4}')
  fi
  if ipset list "$IPSET6_NAME" >/dev/null 2>&1; then
    members6=$(ipset list "$IPSET6_NAME" | awk '/^Number of entries:/ {print $4}')
  fi
  if ipset list "$PERSISTENT_SET" >/dev/null 2>&1; then
    persistent=$(ipset list "$PERSISTENT_SET" | awk '/^Number of entries:/ {print $4}')
  fi
  if ipset list "$PERSISTENT_SET6" >/dev/null 2>&1; then
    persistent6=$(ipset list "$PERSISTENT_SET6" | awk '/^Number of entries:/ {print $4}')
  fi

  echo "mini-firewall status"
  echo "- set (ipv4 temp):       $IPSET_NAME  [${members:-0} entries]"
  echo "- set (ipv6 temp):       $IPSET6_NAME  [${members6:-0} entries]"
  echo "- set (ipv4 persistent): $PERSISTENT_SET  [${persistent:-0} entries]"
  echo "- set (ipv6 persistent): $PERSISTENT_SET6  [${persistent6:-0} entries]"
  echo "- ban_seconds: $BAN_SECONDS"
  echo "- threshold_per_ip: $THRESHOLD_PER_IP"
  echo "- escalate_after: $BAN_ESCALATE_THRESHOLD bans in ${ESCALATE_WINDOW_SECONDS}s"
  echo "- protected_ports: $PROTECTED_PORTS"
  echo "- whitelist_file: $WHITELIST_FILE"
  echo "- metrics_file: $METRICS_FILE"

  if iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    echo "- iptables_rule (ipv4 temp): present"
  else
    echo "- iptables_rule (ipv4 temp): missing"
  fi

  if command -v ip6tables >/dev/null 2>&1; then
    if ip6tables -C INPUT -m set --match-set "$IPSET6_NAME" src -j DROP 2>/dev/null; then
      echo "- ip6tables_rule (ipv6 temp): present"
    else
      echo "- ip6tables_rule (ipv6 temp): missing"
    fi
  else
    echo "- ip6tables: not available (IPv6 blocking disabled)"
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
