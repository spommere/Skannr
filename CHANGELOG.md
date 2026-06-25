# Changelog

Skannr uses a simple semantic versioning scheme while the project is still
pre-1.0:

- `0.1.x`: bug fixes and documentation updates
- `0.2.x`: meaningful feature additions or data format changes
- `1.0.0`: stable operator-facing behavior and config/log compatibility

## 0.3.3 - 2026-06-25

- **Temporal-density Bluetooth grouping.** The all-time MAC-count threshold for
  privacy-rotation groups is replaced with a recency-window check: only MACs seen
  within the last 4 hours count toward the group threshold (T=5). Stale MACs from
  power-cycled devices days ago no longer push genuinely separate devices into
  spurious groups. Session-overlap detection prevents grouping MACs that were
  seen simultaneously. Grouping logic is consolidated into a single seven-gate
  pass in `compact_bluetooth_devices_for_storage`; `add_bluetooth_subjects` no
  longer performs independent re-grouping or reconciliation.
- **Incremental grouping stability.** Incremental raw-log builds no longer
  resurrect individual MAC rows that were already folded into a privacy group,
  fixing a regression where groups were silently dissolved on every second
  Subject History refresh.
- **NOAA tsunami TEST filtering.** Events with `status == "Test"` or headlines
  starting with "TEST" never raise Skannr alerts, preventing NTWC communication
  test warnings from appearing as live alerts. Tsunami alert Details links now
  point to `https://www.tsunami.gov/` instead of the `api.weather.gov` JSON
  endpoint.
- **HTTP fetch consolidation.** `BaseCollector` now provides `run_blocking`,
  `fetch_text` (with gzip support), and `fetch_json`, removing duplicate
  implementations from NOAA, USGS, SWPC, PWS, ADS-B, and Rayhunter.
- **Relaxed default scan intervals.** Wi-Fi scan default: 2 s → 30 s. BLE scan
  default: 2 s → 15 s. Config example and code fallback values now match.
- **Defensive `group_member_summary` fix.** The `names` field is now explicitly
  converted to a list before subscripting, preventing a `TypeError` when the
  field arrives as a `set` from raw event folding.

## 0.3.2 - 2026-06-23

- **Wi-Fi Monitor MAC-based adapter selection.** Added `mac` config key to
  `wifi_monitor` so a single adapter can be pinned by MAC address regardless of
  kernel interface naming. `hardware.py` now exposes the interface MAC from sysfs;
  `wifi_monitor.py` filters candidates through `_mac_allows_interface()`.
- **JSONL null-byte sanitization.** Added `sanitize_json_line()` in `log_utils.py`
  to strip JSON-invalid control characters before every `json.loads` call, fixing
  corrupted-line crashes across the raw-log reading paths.
- **Recency bucket rework.** Subject History and Reports now use four recency
  buckets: Active (< 1h), Recent (1–24h), Stale (1–7d), Dormant (> 7d), replacing
  the old three-bucket scheme.
- **RTL-433 report verbosity compaction.** Frontend renderers now show signal
  ranges instead of per-event dumps, TPMS sample counts instead of individual
  samples, and filter out raw signal/modulation/hex-blob keys from latest fields.
- **Regression test hardening.** Reduced event limits, added per-source line caps,
  fixed recency/TPMS/annotation checks, improved progress output, and verified
  multi-node discovery through `node_logs_root`.
- **Code quality fixes.** YAML-null footgun in MAC filtering, deduplicated
  `_JSON_INVALID_CTRL_RE` regex across scripts, `sanitize_json_line` fast-path,
  and `black` formatting on changed files.
- **Bluetooth privacy-rotation grouping fix.** Multi-MAC devices advertising
  the same name (Bose speakers, LE-FBI trackers) now correctly fold into one
  grouped row when > 5 MACs share the name, instead of appearing as dozens of
  individual rows. Fixed `stable_bluetooth_mac_record()` time-span requirement
  and a double-display bug where ungrouped devices appeared in both the group
  and individual lists.

## 0.3.1 - 2026-06-22

- **Wi-Fi Monitor safety rework.** Skannr no longer rewrites `NetworkManager.conf`,
  migrates default routes, or guesses across arbitrary interfaces for monitor mode.
  `prepare_monitor_mode: true` prefers creating a separate `monX` interface;
  in-place conversion is behind explicit `allow_in_place_monitor_mode: true`.
  Managed Wi-Fi scan auto-selection prefers the current default-route interface to
  reduce conflict with the monitor adapter.
- **BLE stale-cache detection.** The BLE collector now tracks RSSI across scan
  cycles and suppresses devices whose RSSI stays identical for N consecutive
  cycles (configurable via `cache_stale_rssi_threshold`, default 10), filtering
  out BlueZ cached entries that stopped advertising.

## 0.3.0 - 2026-06-21

- **Subject History is now the single source of truth for Wi-Fi/BLE.** The
  `DeviceHistoryBuilder` layer was removed; its logic became an internal
  `WiFiBLEPostprocessor` inside `SubjectHistoryBuilder`. `device_history.json`
  is no longer written to disk. Subject History reads raw JSONL for all 15
  collectors directly.
- **BLE parsing, identity, and UUID cleanup.** Fixed the `bluetoothctl` parser
  so property lines (RSSI, UUIDs, TxPower) no longer become device names.
  Added centralized Bluetooth manufacturer normalization so raw company IDs
  such as `0x004c` surface as `Apple` instead of raw codes. Added
  `service_class.txt` support for UUID name lookup, resolving `0x110A` as
  `Audio Source`.
- **RTL-433 report evidence and browser deduper fix.** RTL-433 subject
  summaries now use concise presence-style wording. The browser Evidence
  deduper no longer removes `Pattern`, `Observed`, and `Activity` sections.
- **Configuration documentation overhaul.** Added `REFERENCE.md` as a
  comprehensive parameter appendix. Updated every collector YAML with clear
  inline comments for BLE scan methods, Wi-Fi retry cadence, Wi-Fi Monitor
  channel behavior, NOAA subfeeds, LAN source controls, and RTL-433 protocol
  guidance.
- **Reports and Subject History recency grouping.** Tables now group rows into
  `Seen within the last hour`, `within 24 hours`, and `24+ hours ago` with
  distinct yellow divider styling.
- **System Status grouping.** Collectors are grouped by ONLINE, OFFLINE/STOPPED,
  and DISABLED state.
- **Multi-node regression support.** `node_logs_root` discovers dated collector
  JSONL across multiple node directories with a default 250-event per-node cap.
- **1920px layout compliance.** Expanded budget across every visible tab
  including Reports, Subject History, Insights, LAN, Alerts, and System Status.
- **Apple Find My accessory detection.** BLE advertisements with Apple
  manufacturer data `0x004C` and payload type `0x12` are flagged, tracked
  through Subject History/Reports, and trigger the BLE tracker alert rule.
- **APRS-IS mobile trip evidence and grouped drilldowns.** Retained history
  includes route samples, position spans, pass-through labels, and detail
  panes for BLE/Wi-Fi/LAN grouped members without re-expanding main tables.
- **Wi-Fi Monitor live-feed search box.** Events can be filtered by type,
  channel, client MAC, AP/BSSID, SSID, signal, or timestamp.
- **BLE empty-scan diagnostics and BlueZ warmup.** Repeated empty Bleak scan
  windows now publish diagnostic status and can optionally run a short
  `bluetoothctl` warmup pass to wake BlueZ discovery.
- **Alerts table constrained layout.** Fixed-width columns with wrapping
  Summary/Details prevent long content from stretching the page.
- **Bluetooth table layout tightening.** Combined BLE Seen/Updates into one
  count column, removed low-value columns from the main table, and widened
  First/Last Seen for readable timestamps.
- **Optional Pushover alert delivery.** Newly emitted or escalated alerts can
  be sent through Pushover via a configurable background worker with
  internet-connectivity gating.
- **LAN annotation and decoder recovery fixes.** Custom LAN labels survive
  refresh and appear consistently in tables and Reports. Managed decoders
  (RTL-433, ADS-B) recover cleanly after transient RTL-SDR dongle loss.

## 0.2.8 - 2026-06-15

- Fixed managed `readsb` startup on RTL-SDR devices and kept shared dongle
  handoff working between managed ADS-B and RTL-433 so one collector can yield
  cleanly to the other.
- Hardened derived Subject History refreshes and report rendering when compact
  evidence mixes scalar and list fields or mixed epoch representations.
- Restored the live FindingsEngine helper behavior needed for presence
  expiration, Wi-Fi monitor emission policy, collector warnings, and direct
  collector event fan-out after restart.
- Rebalanced Insights for a 1920px viewport and tightened the browser layout
  budget for Reports, LAN live tables, LAN Identify, and System Status.
- Removed the standalone RTL-SDR power-scan collector and kept shared RTL-SDR
  probing for ADS-B and RTL-433 only.
- Fixed LAN annotation save, clear, and refresh behavior so custom labels stay
  visible in the LAN table, Subject History, and Reports.
- Tightened shared managed-decoder recovery so transient RTL-SDR loss does not
  strand the decoder background tasks.
- Added regression coverage for the new decoder fallback, compact-history,
  layout, annotation, and mixed-epoch edge cases.

## 0.2.7 - 2026-06-13

- Reworked derived-data refresh and retained state so Subject History,
  Insights, and Reports use compact collector state instead of repeatedly
  replaying old raw logs. Disabled collectors keep their last materialized
  rows, advance checkpoints safely, and no longer force expensive refresh work
  until re-enabled.
- Compacted noisy Wi-Fi and Bluetooth randomized-device history before it
  reaches Subject History. Low-identity randomized MAC churn now folds into
  aggregate rows, while stable, annotated, or report-linked devices remain
  individual subjects.
- Added durable Subject History annotations for Wi-Fi, Bluetooth, and LAN
  subjects. Annotations survive refresh/log pruning, appear in Reports and
  detail views, and never overwrite the underlying subject key.
- Tightened RTL-433 and ADS-B refresh behavior, frequency/status wording,
  Subject History rollup, and Reports evidence formatting. Small direct
  collector batches now reach Subject History even when collectors are switched
  or stopped before refresh.
- Improved Reports and Subject History table layout so high-volume columns have
  more usable width, sparse columns waste less space, timestamps stay readable,
  and long evidence no longer stretches tables far beyond a normal laptop
  viewport.
- Added install-time collector precheck and post-install postcheck behavior.
  Fresh installs seed collector `enabled` flags from required software, selected
  hardware probes, and Python dependency availability. SDR-backed collectors
  require visible RTL-SDR hardware before being enabled, while optional LAN
  enrichment tools are reported without disabling the LAN collector.
- Added rolling period retention caps for derived summaries: weekly summaries
  keep the most recent 4 periods, monthly summaries keep the most recent 12
  periods, and yearly summaries remain unbounded.

## 0.2.6 - 2026-06-13

- Added initial RTL-433 decoder support through `rtl_433`. RTL-433 now has a
  live tab, frequency-plan overrides, Subject History, Insights, Reports,
  detail links, RTL-SDR handoff with ADS-B/RTL-SDR power scanning, and
  disabled-by-default configurable RTL-433 alerts.
- Added initial ADS-B support through `dump1090`/`readsb`, including managed
  decoder startup, live aircraft rows, Subject History, Insights, Reports,
  detail links, low/nearby aircraft alerts, and richer altitude/motion fields.
- Tightened derived-data consistency so Insights, Subject History, and Reports
  all flow from materialized Subject History instead of rereading retained
  finding logs as a separate source.
- Reduced Wi-Fi Monitor noise and improved monitor-mode controls, including
  band/fixed-channel/hopping options, deauth/disassociation alert gating, and
  better report layout for monitor subjects.
- Added install-time collector precheck and post-install postcheck scripts.
  Fresh installs seed collector `enabled` flags from required local tool,
  selected hardware, and Python dependency availability; SDR-backed collectors
  require visible RTL-SDR hardware before being enabled on fresh config.
  Optional LAN enrichment tools such as
  `arp-scan` and `avahi-browse` are reported without disabling the LAN
  collector. System
  Status now distinguishes required, recommended, and optional LAN tool
  availability.
- Tightened collector/UI consistency checks and added a compact Rayhunter live
  tab so standalone collectors have matching browser tab and panel coverage.

## 0.2.5 - 2026-06-09

- Added longitudinal Reports rollups for PWS, APRS-IS weather stations, USGS,
  SWPC, and NOAA. PWS and APRS-IS weather stations now produce weekly,
  monthly, and yearly station patterns; USGS and SWPC produce weekly, monthly,
  and yearly population patterns; NOAA produces monthly/yearly hazard-context
  patterns. Reports expose period coverage, weather/rain/wind/pressure ranges,
  seismic magnitude and distance/depth ranges, SWPC R/S/G/Kp/X-class levels,
  and NOAA tropical/NWS/tsunami/forecast counts without duplicating repeated
  poll samples.
- Tightened Reports as the main intelligence product. Browser sorting now
  preserves the population-first Reports contract, APRS-IS weather-period rows
  are per-callsign subject reports, period-pattern rows get clearer
  reason/confidence metadata, and the browser renders period evidence with
  compact source-aware fields instead of sparse generic JSON labels.
- Added BLE Apple Find My accessory detection. BLE advertisements with Apple
  manufacturer data `0x004C` and payload type `0x12` are labeled as Apple Find
  My accessories, carried through Subject History and Reports, and can trigger
  the existing BLE tracker alert rule.
- Added optional Pushover delivery for Alerts. `alerts.pushover` can send
  newly emitted or escalated alerts through Pushover when configured, using a
  background worker and generic internet-connectivity checks so notification
  failures do not block collectors or the browser.

## 0.2.4 - 2026-06-07

- Added official tsunami.gov NTWC/PTWC support under the NOAA collector. Tsunami
  incident ID, message number, magnitude, depth, event time, coordinates, and
  source/map URLs flow into the NOAA live feed, Subject History, Insights, and
  Reports. Tsunami Warning/Watch/Advisory/Threat products open Alerts; Tsunami
  Information/final threat-passed products remain context rows only. Browser
  refreshes now recover recent tsunami feed rows, and PTWC bulletin timestamps
  are normalized into the standard date/time display.
- Added a global-major USGS earthquake subfeed. The normal USGS live tab now
  includes local-radius earthquakes and low-volume worldwide M6.5+ earthquakes,
  with Alerts for global major events and critical Alerts for M7.5+.
- Added optional Ambient Weather PWS collection with live feed, Subject History,
  Insights, Reports, and Alerts. PWS rows retain station weather, rain
  rates/totals, wind, pressure, solar/UV, indoor readings, coarse location,
  elevation, and battery context while excluding Ambient API keys and street
  address text.
- Added NWS hourly forecast summaries to the NOAA collector. Forecast rows are
  state-like poll subjects: repeated polls update one latest row per configured
  point, and live forecast details work before the next materialized
  Subject History/Reports refresh.
- Added optional SWPC space-weather collection with live feed, Subject History,
  Reports, and Alerts for X-class flares, R/S/G scale conditions, Kp storms,
  and relevant SWPC alert/watch/warning products. SWPC now tolerates partial
  product failures and reports failed subproducts in collector status.
- Tightened poll-feed identity and de-duplication. NOAA/NWS keys use Source +
  Area + Event, NHC storm products roll up by basin + storm/system + advisory
  number, USGS/SWPC rows upsert by event ID, and poll-feed live rows age out by
  `ui.poll_feed_live_ttl_sec` without deleting logs or materialized history.
- Added explicit collector acquisition metadata (`scan`, `poll`, `listen`) and
  documented the subject-identity contract used by Subject History, live feeds,
  Reports, and Alerts.
- Added population-first Reports ordering. Cross-subject pattern rows now appear
  before per-subject rows for APRS-IS, NOAA, USGS, SWPC, LAN, and existing
  Wi-Fi/BLE/privacy aggregate reports.
- Added OpenStreetMap links for rendered latitude/longitude text and APRS range
  filters, plus first/latest APRS movement coordinates where retained.
- Expanded LAN collection with optional passive mDNS/SSDP, DHCP/raw ARP,
  DHCP lease import, active ARP inventory via `arp-scan`, Avahi service import,
  vendor enrichment, and more stable LAN subject retention across intermittent
  missed ARP replies.
- Added an on-demand LAN Identify action for one selected IP address. It runs
  bounded `nmap` and short `curl` probes, shows open ports and HTTP/service
  hints, emits a compact Insight, and enriches the matching LAN subject/report.
- Reduced BLE Insights noise from randomized/private-address churn while
  retaining full BLE Subject History and Reports. Anonymous/recent BLE activity
  is summarized as population context, while per-device Insights focus on recent
  named or otherwise identifiable subjects.
- Removed `has_subject_history` from shipped collector YAML templates. Subject
  History participation is now internal collector metadata, and the collector
  contract validation script covers acquisition groups, poll identity, alert-key
  alignment, NOAA ACK de-duplication, SWPC partial failures, and PWS
  normalization examples.

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
