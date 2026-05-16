# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-05-16

### Added
- **IPv6 support** via `ip6tables` + `ipset` with `family inet6`. Two new sets: `ddos_block6` (temporary) and `ddos_persistent6` (persistent). IPv6 blocking is gracefully skipped if `ip6tables` is unavailable.
- **Repeat-offender escalation**: IPs that exceed `BAN_ESCALATE_THRESHOLD` (default: 3) bans within `ESCALATE_WINDOW_SECONDS` (default: 24 h) are automatically added to a persistent blocklist (`ddos_persistent` / `ddos_persistent6`) with no automatic expiry.
- New config variables: `BAN_ESCALATE_THRESHOLD`, `ESCALATE_WINDOW_SECONDS`, `IPSET6_NAME`, `PERSISTENT_SET`, `PERSISTENT_SET6`, `OFFENDER_DIR`.
- `--status` now reports all four ipset sizes and escalation config.
- `--metrics` now exports four additional Prometheus gauges: `ddos_guard_blocklist6_size`, `ddos_guard_persistent_size`, `ddos_guard_persistent6_size`.

### Changed
- `scan_and_ban` now parses both IPv4 and IPv6 remote addresses from `ss` output.
- `ban_ip` dispatches to the correct ipset family based on address type.

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
