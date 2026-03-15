#!/usr/bin/env bash
set -euo pipefail

# Minimal cron-based connection flood guard
# - Scans active TCP connections to protected ports
# - If IP exceeds threshold, blocks via ipset+iptables
# - Auto-unblocks after BAN_SECONDS

# ===== Config =====
PROTECTED_PORTS="80,443"
THRESHOLD_PER_IP=120
BAN_SECONDS=900
STATE_DIR="/var/lib/ddos-guard"
LOG_FILE="/var/log/ddos-guard.log"
IPSET_NAME="ddos_block"
# ================

mkdir -p "$STATE_DIR"
touch "$STATE_DIR/bans.tsv"

log(){
  printf '%s %s\n' "$(date -Is)" "$*" >> "$LOG_FILE"
}

need_root(){
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
  fi
}

ensure_firewall(){
  command -v ipset >/dev/null 2>&1 || { echo "Missing ipset"; exit 1; }
  command -v iptables >/dev/null 2>&1 || { echo "Missing iptables"; exit 1; }

  ipset list "$IPSET_NAME" >/dev/null 2>&1 || ipset create "$IPSET_NAME" hash:ip -exist

  if ! iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
    log "Inserted INPUT drop rule for ipset:$IPSET_NAME"
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

ban_ip(){
  local ip="$1" count="$2" now expires
  now=$(date +%s)
  expires=$((now + BAN_SECONDS))

  ipset add "$IPSET_NAME" "$ip" -exist

  if grep -q "^${ip}\t" "$STATE_DIR/bans.tsv"; then
    awk -v ip="$ip" -v ex="$expires" 'BEGIN{OFS="\t"} {if($1==ip){$2=ex} print}' "$STATE_DIR/bans.tsv" > "$STATE_DIR/bans.tmp"
    mv "$STATE_DIR/bans.tmp" "$STATE_DIR/bans.tsv"
  else
    printf '%s\t%s\n' "$ip" "$expires" >> "$STATE_DIR/bans.tsv"
  fi

  log "BAN ip=$ip count=$count ttl=${BAN_SECONDS}s"
}

unban_expired(){
  local now
  now=$(date +%s)
  awk -v now="$now" 'BEGIN{OFS="\t"} {if($2>now){print}}' "$STATE_DIR/bans.tsv" > "$STATE_DIR/bans.keep" || true

  # Remove expired from ipset
  awk -v now="$now" '{if($2<=now) print $1}' "$STATE_DIR/bans.tsv" | while read -r ip; do
    [[ -z "$ip" ]] && continue
    ipset del "$IPSET_NAME" "$ip" 2>/dev/null || true
    log "UNBAN ip=$ip"
  done

  mv "$STATE_DIR/bans.keep" "$STATE_DIR/bans.tsv"
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

main(){
  need_root
  ensure_firewall
  unban_expired
  scan_and_ban
}

main "$@"
