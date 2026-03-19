# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-03-20

### Added
- Whitelist support via `/etc/ddos-guard/whitelist.txt`.
- `--dry-run` mode to preview bans without modifying firewall/ipset.
- `--status` mode for quick operational checks.
- Run lock (`flock`) to prevent overlapping cron executions.

### Changed
- Reworked ban handling to use **native ipset timeouts** (`timeout` on set entries).
- Install script now creates whitelist/config directories.

## [0.1.0] - 2026-03-15

### Added
- Initial release.
- Cron-based connection burst detection.
- Auto-ban using ipset + iptables.
