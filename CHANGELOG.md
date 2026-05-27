# Changelog

Skannr uses a simple semantic versioning scheme while the project is still
pre-1.0:

- `0.1.x`: bug fixes and documentation updates
- `0.2.0`: meaningful feature additions or data format changes
- `1.0.0`: stable operator-facing behavior and config/log compatibility

## 0.1.7 - 2026-05-27

- Replaced legacy `skannr.host` / `skannr.port` binding with required quoted
  `skannr.listeners` endpoint strings, such as `"127.0.0.1:5004"` and
  `"[::]:5006"`.
- Removed default port `5000` from active config and listener documentation.
- Added support for one or more configured listeners, including simultaneous
  IPv4 and IPv6 endpoints.
- Reworked listener startup so all configured endpoints bind before serving,
  and startup fails clearly on malformed or misplaced listener config.
- Made the browser connection badge show the actual connected endpoint, port,
  and address family.
- Improved Bluetooth display semantics with Identity and Services / UUIDs,
  including offline member UUID decoding.
- Reduced browser-side live table churn and stale BLE row retention.
- Fixed View-window changes so Reports, Insights, and Device History refresh for
  the selected window.
- Added report-score recency adjustment so stale historical profiles no longer
  keep the same rank indefinitely.

## 0.1.3 - 2026-05-22

- Clarified the roles of Insights, Reports, and Device History.
- Made Insights a recent tactical event feed.
- Improved Reports evidence readability by folding related details into fewer
  rows.

## 0.1.2 - 2026-05-22

- Improved Reports into a ranked, device-centric summary view.
- Consolidated Bluetooth and Wi-Fi report rows to reduce repetitive entries.
- Improved timestamp handling, source filtering, and report evidence rendering.

## 0.1.1 - 2026-05-21

- Renamed the project to Skannr and added release/version structure.
- Improved project documentation and operator setup guidance.
- Added GitHub/release helper structure and service-install documentation.

## 0.1.0 - 2026-05-19

Initial working local release.

- Flask dashboard with local static assets and Server-Sent Events.
- Wi-Fi Scan collector for managed-mode AP scans.
- Wi-Fi Monitor collector for on-demand monitor-mode sniffing and channel
  hopping.
- Bluetooth collectors for BLE Scan, BLE Identify, and Bluetooth Classic.
- RTL-SDR collector using `rtl_power`.
- Filesystem JSONL persistence with retention.
- Materialized Findings History, Device History, Insights, and Reports.
- Offline Wi-Fi OUI and Bluetooth company identifier lookup support.
- Version-aware installer for Python 3.6, 3.7, and newer runtimes.
- Operator README, design document, Apache-2.0 license, and GitHub-oriented
  project structure.
