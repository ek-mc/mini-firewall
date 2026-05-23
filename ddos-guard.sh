#!/usr/bin/env bash
set -euo pipefail

# Minimal cron-based connection flood guard
# - Scans active TCP connections to protected ports via ss(8)
# - If IP exceeds threshold, blocks via nftables native sets (IPv4 + IPv6)
# - Uses nftables set element timeout (no manual bans file)
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
# nftables table / chain / set names
NFT_TABLE="inet ddos_guard"
NFT_CHAIN="input"
NFT_SET_TMP4="ddos_block4"
NFT_SET_TMP6="ddos_block6"
NFT_SET_PERSIST4="ddos_persist4"
NFT_SET_PERSIST6="ddos_persist6"
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
  --dry-run   Detect and log what would be banned, without changing firewall
  --status    Show current nftables set sizes and recent log tail
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

# ─── nftables helpers ─────────────────────────────────────────────────────────

# Check whether the ddos_guard table already exists
_nft_table_exists(){
  nft list table inet ddos_guard >/dev/null 2>&1
}

# Return the current element count of a named set
_nft_set_size(){
  local set_name="$1"
  nft list set inet ddos_guard "$set_name" 2>/dev/null \
    | grep -c 'elements = {' || echo 0
  # More reliable: count comma-separated entries
  nft list set inet ddos_guard "$set_name" 2>/dev/null \
    | awk '/elements = \{/{found=1} found{print}' \
    | grep -oE '[0-9a-fA-F:.]+' \
    | wc -l || echo 0
}

ensure_firewall(){
  command -v nft >/dev/null 2>&1 || { echo "Missing nft (nftables)"; exit 1; }

  if _nft_table_exists; then
    return 0
  fi

  if (( DRY_RUN == 1 )); then
    log "DRYRUN would_create_nftables_table table='inet ddos_guard'"
    return
  fi

  # Create the full table, sets, chain and drop rules in one atomic nft transaction
  nft -f - <<NFT
table inet ddos_guard {
  # Temporary ban sets — entries expire automatically after BAN_SECONDS
  set ${NFT_SET_TMP4} {
    type ipv4_addr
    flags dynamic, timeout
    timeout ${BAN_SECONDS}s
  }
  set ${NFT_SET_TMP6} {
    type ipv6_addr
    flags dynamic, timeout
    timeout ${BAN_SECONDS}s
  }
  # Persistent ban sets — no timeout, manual removal only
  set ${NFT_SET_PERSIST4} {
    type ipv4_addr
    flags interval
  }
  set ${NFT_SET_PERSIST6} {
    type ipv6_addr
    flags interval
  }
  chain ${NFT_CHAIN} {
    type filter hook input priority 0; policy accept;
    ip  saddr @${NFT_SET_TMP4}     drop
    ip6 saddr @${NFT_SET_TMP6}     drop
    ip  saddr @${NFT_SET_PERSIST4} drop
    ip6 saddr @${NFT_SET_PERSIST6} drop
  }
}
NFT

  log "Created nftables table 'inet ddos_guard' with sets and drop rules"
}

# ─── Stats ────────────────────────────────────────────────────────────────────

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

# ─── Webhook ──────────────────────────────────────────────────────────────────

send_alert(){
  local msg="$1"
  [[ -n "$ALERT_WEBHOOK_URL" ]] || return 0
  command -v curl >/dev/null 2>&1 || return 0
  curl -sS -m 5 -H 'Content-Type: application/json' \
    -d "{\"text\":\"$msg\"}" \
    "$ALERT_WEBHOOK_URL" >/dev/null 2>&1 || true
}

# ─── IP classification ────────────────────────────────────────────────────────

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
  [[ "$ip" == *:* ]] || return 1
  ip="${ip#[}"; ip="${ip%]}"
  [[ "$ip" == "::1" ]] && return 1
  [[ "${ip,,}" =~ ^fe8 ]] && return 1
  [[ "${ip,,}" =~ ^f[cd] ]] && return 1
  return 0
}

is_whitelisted(){
  local ip="$1"
  [[ -f "$WHITELIST_FILE" ]] || return 1
  grep -q -E "^${ip}(\s|$)" "$WHITELIST_FILE"
}

# ─── Repeat-offender escalation ───────────────────────────────────────────────

_ip_to_filename(){
  echo "${1//[:\/ ]/_}"
}

record_and_check_escalation(){
  local ip="$1"
  local fname
  fname="$OFFENDER_DIR/$(_ip_to_filename "$ip")"
  local now
  now=$(date +%s)
  local cutoff=$(( now - ESCALATE_WINDOW_SECONDS ))
  echo "$now" >> "$fname"
  local recent_count
  recent_count=$(awk -v cutoff="$cutoff" '$1 >= cutoff' "$fname" | wc -l)
  (( recent_count >= BAN_ESCALATE_THRESHOLD ))
}

escalate_ip(){
  local ip="$1" count="$2"

  if (( DRY_RUN == 1 )); then
    log "DRYRUN ESCALATE ip=$ip count=$count (persistent)"
    return
  fi

  if [[ "$ip" == *:* ]]; then
    nft add element inet ddos_guard "${NFT_SET_PERSIST6}" "{ ${ip} }"
    log "ESCALATE ip=$ip count=$count added to nft set ${NFT_SET_PERSIST6}"
  else
    nft add element inet ddos_guard "${NFT_SET_PERSIST4}" "{ ${ip} }"
    log "ESCALATE ip=$ip count=$count added to nft set ${NFT_SET_PERSIST4}"
  fi
  send_alert "mini-firewall ESCALATE (persistent ban) ip=$ip count=$count host=$(hostname)"
}

# ─── Ban ──────────────────────────────────────────────────────────────────────

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

  # nftables set elements accept per-element timeout override
  if [[ "$ip" == *:* ]]; then
    nft add element inet ddos_guard "${NFT_SET_TMP6}" \
      "{ ${ip} timeout ${BAN_SECONDS}s }"
  else
    nft add element inet ddos_guard "${NFT_SET_TMP4}" \
      "{ ${ip} timeout ${BAN_SECONDS}s }"
  fi

  BAN_COUNT=$((BAN_COUNT + 1))
  log "BAN ip=$ip count=$count ttl=${BAN_SECONDS}s"
  send_alert "mini-firewall BAN ip=$ip count=$count ttl=${BAN_SECONDS}s host=$(hostname)"

  if record_and_check_escalation "$ip"; then
    escalate_ip "$ip" "$count"
  fi
}

# ─── Scan ─────────────────────────────────────────────────────────────────────

scan_and_ban(){
  local ports_regex
  ports_regex=$(echo "$PROTECTED_PORTS" | sed 's/,/|/g')

  # ss -Hnt: no header, TCP only, numeric ports
  # state established,syn-recv: only active connections
  # field 5 is the remote address:port
  ss -Hnt state established,syn-recv '( sport = :'"$ports_regex"' )' 2>/dev/null \
    | awk '{print $5}' \
    | sed 's/\[//g;s/\]//g' \
    | awk -F':' '
        NF > 2 { addr=""; for(i=1;i<NF;i++) addr=addr (i>1?":":"") $i; print addr; next }
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

# ─── Metrics ──────────────────────────────────────────────────────────────────

_nft_count_elements(){
  # Count IPs in a named nftables set
  local set_name="$1"
  nft list set inet ddos_guard "$set_name" 2>/dev/null \
    | awk '/elements = \{/{p=1} p' \
    | grep -oE '[0-9a-fA-F:]+\.[0-9a-fA-F:]+|[0-9a-fA-F:]{2,}' \
    | wc -l || echo 0
}

write_metrics(){
  local tmp4=0 tmp6=0 persist4=0 persist6=0
  if _nft_table_exists; then
    tmp4=$(_nft_count_elements "$NFT_SET_TMP4")
    tmp6=$(_nft_count_elements "$NFT_SET_TMP6")
    persist4=$(_nft_count_elements "$NFT_SET_PERSIST4")
    persist6=$(_nft_count_elements "$NFT_SET_PERSIST6")
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
ddos_guard_blocklist_size ${tmp4}
# HELP ddos_guard_blocklist6_size Current number of IPs in temporary IPv6 blocklist
# TYPE ddos_guard_blocklist6_size gauge
ddos_guard_blocklist6_size ${tmp6}
# HELP ddos_guard_persistent_size Current number of IPs in persistent IPv4 blocklist
# TYPE ddos_guard_persistent_size gauge
ddos_guard_persistent_size ${persist4}
# HELP ddos_guard_persistent6_size Current number of IPs in persistent IPv6 blocklist
# TYPE ddos_guard_persistent6_size gauge
ddos_guard_persistent6_size ${persist6}
METRICS
}

show_metrics(){
  write_metrics
  cat "$METRICS_FILE"
}

# ─── Status ───────────────────────────────────────────────────────────────────

show_status(){
  local tmp4=0 tmp6=0 persist4=0 persist6=0
  if _nft_table_exists; then
    tmp4=$(_nft_count_elements "$NFT_SET_TMP4")
    tmp6=$(_nft_count_elements "$NFT_SET_TMP6")
    persist4=$(_nft_count_elements "$NFT_SET_PERSIST4")
    persist6=$(_nft_count_elements "$NFT_SET_PERSIST6")
  fi

  echo "mini-firewall status (nftables backend)"
  echo "- table:                 inet ddos_guard"
  echo "- set (ipv4 temp):       ${NFT_SET_TMP4}  [${tmp4} entries]"
  echo "- set (ipv6 temp):       ${NFT_SET_TMP6}  [${tmp6} entries]"
  echo "- set (ipv4 persistent): ${NFT_SET_PERSIST4}  [${persist4} entries]"
  echo "- set (ipv6 persistent): ${NFT_SET_PERSIST6}  [${persist6} entries]"
  echo "- ban_seconds:           $BAN_SECONDS"
  echo "- threshold_per_ip:      $THRESHOLD_PER_IP"
  echo "- escalate_after:        $BAN_ESCALATE_THRESHOLD bans in ${ESCALATE_WINDOW_SECONDS}s"
  echo "- protected_ports:       $PROTECTED_PORTS"
  echo "- whitelist_file:        $WHITELIST_FILE"
  echo "- metrics_file:          $METRICS_FILE"

  if _nft_table_exists; then
    echo "- nftables_table:        present"
  else
    echo "- nftables_table:        missing (run without --status to initialise)"
  fi

  if [[ -f "$LOG_FILE" ]]; then
    echo
    echo "last log lines:"
    tail -n 10 "$LOG_FILE" || true
  fi
}

# ─── Args ─────────────────────────────────────────────────────────────────────

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

# ─── Entry point ──────────────────────────────────────────────────────────────

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
