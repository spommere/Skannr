# Changelog

Skannr uses a simple semantic versioning scheme while the project is still
pre-1.0:

- `0.1.x`: bug fixes and documentation updates
- `0.2.x`: meaningful feature additions or data format changes
- `1.0.0`: stable operator-facing behavior and config/log compatibility

## 0.2.3 - 2026-06-05

- Added optional Ambient Weather PWS collection with live feed, Subject History,
  Insights, Reports, and Alerts. PWS rows keep station weather, wind, rain
  rates/totals, pressure, solar/UV, indoor readings, location/elevation, and
  battery context while keeping Ambient API keys and street addresses out of
  persisted/displayed data.
- Added NWS hourly forecast summaries to the NOAA collector. Forecast rows are
  treated as state-like poll subjects: repeated polls update one latest row per
  configured point, and forecast detail links work before the next materialized
  Subject History/Reports refresh.
- Added OpenStreetMap links for rendered latitude/longitude text and APRS range
  filters, plus first/latest APRS movement coordinates where retained.
- Added population-first Reports ordering. Cross-subject pattern rows now appear
  before per-subject rows for APRS-IS, NOAA, USGS, SWPC, LAN, and existing
  Wi-Fi/BLE/privacy aggregate reports.
- Added optional SWPC space-weather collection with live feed, Subject History,
  Reports, and Alerts for X-class flares, R/S/G scale conditions, Kp storms,
  and relevant SWPC alert/watch/warning products.
- Added explicit collector acquisition metadata (`scan`, `poll`, `listen`) and
  documented the subject-identity contract used by Subject History, live
  feed de-duplication, Reports, and Alerts.
- Tightened NOAA/USGS/SWPC poll-feed behavior so repeated polls update one
  event/subject row, while different NOAA areas, NHC product families/advisory
  numbers, USGS event IDs, and SWPC event IDs stay distinct.
- Made SWPC polling tolerant of partial product failures, matching NOAA's
  sub-feed behavior: successful SWPC product rows still update while failed
  products appear as collector warning status.
- Fixed PWS rain-transition report evidence so a stopped rain episode keeps the
  episode start/stop context in one place rather than leaving ambiguous
  start/stop rows.
- Added `ui.poll_feed_live_ttl_sec` and a collector contract validation script
  for future collector changes.

## 0.2.2 - 2026-06-04

- Added collector-neutral Subject History as the main derived layer. Wi-Fi,
  Bluetooth, APRS-IS, Rayhunter, RTL-SDR, NOAA, USGS, and LAN now roll up into
  subjects such as SSID, BSSID, MAC, callsign, endpoint, frequency, alert, quake
  identity, and LAN device/gateway before feeding Insights and Reports.
- Added APRS-IS live collection and intelligence support, including multiple
  feeds, CWOP/weather handling, local range enforcement, decoded station/object
  activity, weather/motion Insights, callsign-based Reports, subject drilldowns,
  and clearer per-feed System Status text.
- Added the live AlertEngine with a global alert strip, Alerts tab, ACK
  workflow, search, details links, retained alert events, and default high-signal
  rules for drone/Remote ID Wi-Fi, APRS severe weather, Rayhunter warnings,
  Wi-Fi disruption/open-sensitive SSIDs, BLE tracker-like devices, NOAA hazards,
  USGS earthquakes, and LAN gateway changes.
- Added optional NOAA, USGS, and LAN collectors with live tabs, Subject History,
  Reports, and Alerts. NOAA covers NWS/NHC hazard context, USGS covers nearby
  earthquake GeoJSON, and LAN passively records local neighbor/default-gateway
  state without probing the network.
- Improved browser status and table usability for new feeds: collector status
  dots, event-time columns, hyperlink details, alert search/ACK-all, wider
  narrow columns, NOAA headline de-duplication, and suppression of non-actionable
  NHC "no tropical cyclones" outlook alerts.
- Cleaned up System Status wording for APRS-IS and LAN so command/debug details
  stay in logs while the dashboard shows concise operator-facing source and
  availability text.

## 0.2.1 - 2026-06-02

- Migrated Skannr to a separated source/config/runtime layout. Python code and
  bundled assets now live under `src/skannr/`, generic templates under
  `config.example/`, local operator config under `config/`, requirements under
  `requirements/`, and generated runtime state under `runtime/`. Source-control
  and release staging now exclude local config, virtualenv, logs, pcaps, and
  archives, and the migration script rewrites legacy `log_dir: logs` settings
  to `runtime/logs`.
- Added Privacy reporting inside Reports and kept report score, confidence, and
  reason provenance distinct for clearer counter-surveillance review.
- Added an optional Rayhunter collector and derived intelligence integration.
  Skannr now reads Rayhunter JSON/status endpoints with gzip support, records
  normalized status/warning events, and renders parsed system/recording fields
  in Reports and Insights without dumping raw HTML.
- Simplified the Reports table by removing the visible Severity column,
  widening Confidence and Reasons, and removing redundant Rayhunter endpoint
  details from Subject, Summary, and Evidence.
- Improved connection and system-status behavior. Successful HTTP responses now
  mark the browser as connected even while live updates reconnect, and disabled
  configured collectors remain visible as `DISABLED` System rows.
- Removed the experimental environment-baseline / known-device workflow before
  making it part of the operator surface.
- Fixed the initial browser version badge so reloads wait for server metadata
  instead of briefly showing an old hardcoded version.

## 0.1.9 - 2026-05-31

- Kept Reports as the single intelligence report and removed the separate
  Presence report surface. Presence, security, signal, identity, scanner, and
  collector findings now share the same ranked Reports workflow.
- Improved Reports evidence quality with Confidence and Reasons columns,
  scanner-quality rows, tighter SSID/BSSID grouping, Wi-Fi managed-scan
  presence findings, and BLE randomized/private-address grouping.
- Reworked derived refresh coordination so browser reloads, wake/focus events,
  manual refreshes, and automatic refreshes join one backend refresh instead of
  creating competing work or stale UI states.
- Added clearer derived-refresh diagnostics, including numbered phases,
  backend worker timings, browser fetch/render diagnostics, and optional
  `--debug` / `-debug` startup logging.
- Fixed stale Reports and Device History timestamps after restart or refresh by
  making cached loads detect unmaterialized raw logs, joining active catch-up
  refreshes, and overlaying newest live Wi-Fi/Bluetooth observations before
  publishing derived views.
- Reduced derived-view refresh and browser load cost by compacting/gzipping
  HTTP payloads, capping browser-bound Device History rows, suppressing
  low-value stale anonymous BLE churn from Reports/Insights, compacting
  materialized cache writes, and avoiding unnecessary large-cache rewrites.
- Hardened materialized derived summaries with atomic writes, mixed-type
  serialization/sorting fixes, coherent dependent-summary repair, and bounded
  live-observation cache pruning.

## 0.1.8 - 2026-05-28

- Added collector status dots to the main collector tabs so Wi-Fi Scan,
  Wi-Fi Monitor, Bluetooth, and RTL-SDR show online/offline state at a glance.
- Added clickable drilldown views for Bluetooth MACs, Wi-Fi SSIDs, and Wi-Fi
  BSSIDs from Reports, Device History, and live scan tables.
- Made Wi-Fi Reports more SSID-centric by summarizing multi-BSSID networks in
  one profile row and moving full BSSID/radio details into drilldown.

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
