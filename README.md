# mini-firewall

Minimal cron-based anti-flood firewall guard for Linux servers using **ipset + iptables**.

> Designed to block obvious abusive connection bursts with short temporary bans.

## Status
- Version: **v0.1.0**
- License: MIT
- Latest release: https://github.com/ek-mc/mini-firewall/releases/latest

## Features
- Runs every minute via cron.
- Scans active TCP connections to protected ports (default: `80,443`).
- Bans high-connection public IPs via `ipset` + `iptables`.
- Auto-unbans after TTL (default: 15 minutes).
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

You can change these at the top of `ddos-guard.sh`:
- `PROTECTED_PORTS`
- `THRESHOLD_PER_IP`
- `BAN_SECONDS`


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
  - `ss` (from `iproute2`)

On Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y ipset iptables iproute2
```

### 3) Configure thresholds (optional)
Edit `ddos-guard.sh`:
- `PROTECTED_PORTS`
- `THRESHOLD_PER_IP`
- `BAN_SECONDS`

### 4) Install cron job
```bash
sudo bash install-cron.sh
```

### 5) Verify
```bash
sudo crontab -l | grep ddos-guard.sh
sudo tail -n 50 /var/log/ddos-guard.log
```

### 6) Uninstall (if needed)
```bash
sudo bash uninstall.sh
```

## Logs and state
- Log file: `/var/log/ddos-guard.log`
- State dir: `/var/lib/ddos-guard`

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
