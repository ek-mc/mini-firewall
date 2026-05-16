# mini-firewall

Minimal cron-based anti-flood firewall guard for Linux servers using **ipset + iptables** (IPv4 and IPv6).

> Designed to block obvious abusive connection bursts with short temporary bans and automatic escalation to persistent blocks for repeat offenders.

## Status
- Version: **v0.4.0**
- License: MIT
- Latest release: https://github.com/ek-mc/mini-firewall/releases/latest

## Features
- Runs every minute via cron.
- Scans active TCP connections to protected ports (default: `80,443`).
- Bans high-connection public IPs via `ipset` + `iptables` (IPv4) and `ip6tables` (IPv6).
- Uses **native ipset timeout** for auto-unban (default: 15 minutes).
- **Repeat-offender escalation**: IPs banned `BAN_ESCALATE_THRESHOLD` (default: 3) times within `ESCALATE_WINDOW_SECONDS` (default: 24 h) are moved to a persistent blocklist with no expiry.
- Supports **whitelist** file to skip trusted IPs.
- Supports `--dry-run` mode.
- Supports `--status` mode.
- Supports `--metrics` mode and writes Prometheus-style snapshot to `/var/lib/ddos-guard/metrics.prom`.
- Optional webhook alerts on ban events via `ALERT_WEBHOOK_URL` env var.
- Logs actions to `/var/log/ddos-guard.log`.

## Files
- `ddos-guard.sh` — main detection/ban script.
- `install-cron.sh` — install helper script.
- `uninstall.sh` — uninstall helper script.
- `CHANGELOG.md` — release notes.
- `VERSION` — current version.

## Default behavior
- Protected ports: `80,443`
- Threshold per IP: `120`
- Ban time: `900s`
- Escalation threshold: `3` bans within `86400s` (24 h) → persistent block

You can change these at the top of `ddos-guard.sh`:
- `PROTECTED_PORTS`
- `THRESHOLD_PER_IP`
- `BAN_SECONDS`
- `BAN_ESCALATE_THRESHOLD` — number of bans in the window before persistent block (default: `3`)
- `ESCALATE_WINDOW_SECONDS` — rolling window for repeat-offender counting (default: `86400` = 24 h)

## IPv6 support
IPv6 blocking is enabled automatically when `ip6tables` is available. Two additional ipsets are created:
- `ddos_block6` — temporary IPv6 bans (same TTL as IPv4)
- `ddos_persistent6` — persistent IPv6 bans for repeat offenders

If `ip6tables` is not installed, IPv6 blocking is silently skipped.

## Whitelist
File: `/etc/ddos-guard/whitelist.txt`

Add one trusted public IP per line (IPv4 or IPv6), for example:
```txt
1.2.3.4
2001:db8::1
```

## Optional webhook alerts
Set an environment variable before running script (or in cron wrapper):
```bash
export ALERT_WEBHOOK_URL="https://example.com/webhook"
```

## Install Guide

### 1) Clone repository
```bash
git clone https://github.com/ek-mc/mini-firewall.git
cd mini-firewall
```

### 2) Install dependencies
- Requires Linux with:
  - `ipset`
  - `iptables`
  - `ip6tables` (optional, for IPv6 blocking)
  - `ss` (from `iproute2`)
  - `flock` (from `util-linux`)

On Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y ipset iptables ip6tables iproute2 util-linux
```

### 3) Configure thresholds (optional)
Edit `ddos-guard.sh`:
- `PROTECTED_PORTS`
- `THRESHOLD_PER_IP`
- `BAN_SECONDS`
- `BAN_ESCALATE_THRESHOLD`
- `ESCALATE_WINDOW_SECONDS`

### 4) Install cron job
```bash
sudo bash install-cron.sh
```

### 5) Verify
```bash
sudo crontab -l | grep ddos-guard.sh
sudo tail -n 50 /var/log/ddos-guard.log
sudo bash ddos-guard.sh --status
```

### 6) Dry run test
```bash
sudo bash ddos-guard.sh --dry-run
```

### 7) Metrics snapshot
```bash
sudo bash ddos-guard.sh --metrics
cat /var/lib/ddos-guard/metrics.prom
```

### 8) Uninstall (if needed)
```bash
sudo bash uninstall.sh
```

## Logs and state
- Log file: `/var/log/ddos-guard.log`
- Lock file: `/var/run/ddos-guard.lock`
- Whitelist: `/etc/ddos-guard/whitelist.txt`
- Stats file: `/var/lib/ddos-guard/stats.env`
- Metrics file: `/var/lib/ddos-guard/metrics.prom`
- Offender records: `/var/lib/ddos-guard/offenders/`

## Notes (important)
- This is a minimal defensive script, **not** a full DDoS platform.
- For production WordPress/high traffic setups, pair with:
  - Nginx `limit_req/limit_conn`
  - fail2ban
  - CDN/WAF controls
- Test carefully to avoid blocking legitimate traffic.

## Changelog
See [CHANGELOG.md](CHANGELOG.md).

## License
MIT — see [LICENSE](LICENSE).
