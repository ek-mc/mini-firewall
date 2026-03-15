# Changelog

## [0.1.0] - 2026-03-15
### Added
- Initial minimal cron-based firewall guard (`ddos-guard.sh`).
- Auto-ban logic using `ipset` + `iptables` for high-connection IPs.
- Auto-unban after TTL expiry.
- Install helper (`install-cron.sh`) for cron scheduling.
- Uninstall helper (`uninstall.sh`) to remove cron/rules.
- Documentation (`README.md`) and `.gitignore` for local/runtime artifacts.
