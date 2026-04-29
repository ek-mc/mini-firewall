# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-03-20

### Added
- `--metrics` mode with Prometheus-style metrics output.
- Persistent counters (`run_count`, `ban_count`, `last_run`) in `/var/lib/ddos-guard/stats.env`.
- Optional webhook alert on bans via `ALERT_WEBHOOK_URL`.

### Changed
- Extended operational observability (`status` + metrics snapshot file).

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

## 2026-04-29

- Added basic GitHub Actions CI workflow (`.github/workflows/basic-ci.yml`).
- Maintenance: closed stale dependency PR queue for cleaner triage (where applicable).
