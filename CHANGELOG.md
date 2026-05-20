# Changelog

Skannr uses a simple semantic versioning scheme while the project is still
pre-1.0:

- `0.1.x`: bug fixes and documentation updates
- `0.2.0`: meaningful feature additions or data format changes
- `1.0.0`: stable operator-facing behavior and config/log compatibility

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
