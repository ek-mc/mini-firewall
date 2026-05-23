# Changelog

All notable changes to this project will be documented in this file.

## [0.5.0] - 2026-05-23

### Changed
- **Firewall backend: `iptables`/`ipset` → `nftables` native sets** (`ddos-guard.sh`).
  - A single `inet ddos_guard` table is created atomically via `nft -f -` on first
    run. The table contains four sets and four drop rules — replacing the previous
    four separate `ipset create` + `iptables -I` calls.
  - Temporary ban sets (`ddos_block4`, `ddos_block6`) use `flags dynamic, timeout`
    so entries expire automatically without a separate cleanup job.
  - Persistent ban sets (`ddos_persist4`, `ddos_persist6`) use `flags interval`
    for efficient CIDR-range support in future.
  - `ban_ip` and `escalate_ip` now call `nft add element` with a per-element
    `timeout` override instead of `ipset add … timeout`.
  - `ensure_firewall` is idempotent: if the table already exists the function
    returns immediately (no duplicate-rule risk).
  - `uninstall.sh` now calls `nft delete table inet ddos_guard` which atomically
    removes all sets and rules in one command.
  - `--status` output updated to show nftables table and set names.
  - Dependency on `ipset`, `iptables`, and `ip6tables` binaries removed;
    only `nft` (package `nftables`) is required.

### Notes
- Requires Linux kernel ≥ 3.13 and the `nftables` package (`apt install nftables`
  / `dnf install nftables`). All major distributions since 2019 ship it by default.
- Existing `ipset`/`iptables` rules from v0.4.0 are **not** automatically removed
  on upgrade. Run the old `uninstall.sh` before upgrading, or remove them manually:
  ```
  iptables -D INPUT -m set --match-set ddos_block src -j DROP
  ipset destroy ddos_block ddos_block6 ddos_persistent ddos_persistent6
  ```

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
