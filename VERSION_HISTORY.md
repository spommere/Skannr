# Version History

This is a local operator/development history. Keep it out of release artifacts
if you want the public repo to rely only on `CHANGELOG.md`.

`CHANGELOG.md` is the public-facing summary. This file keeps the more detailed
operator/development notes, including reconstructed detail when exact release
history is not available.

## post-0.2.2

- Added an optional NOAA SWPC collector for internet-fed space-weather context.
  It polls official SWPC alert products, NOAA R/S/G scale state, GOES primary
  X-ray flux, and planetary K/Kp data, then emits compact `swpc_event` records
  rather than retaining raw time-series samples.
- Added SWPC live UI, Subject History, Reports, and Alerts. Default SWPC Alerts
  trigger for X-class flares, R3+ radio blackouts, S3+ solar radiation storms,
  G3+ geomagnetic storms, and Kp 7+; lower configured R/S/G/Kp conditions remain
  visible as feed/context rows without opening Alerts.
- Added `config.example/collectors/swpc.yaml` plus global
  `findings.swpc_*`, `alerts.swpc_space_weather`, and `reports.swpc_*`
  thresholds, and documented the SWPC YAML parameters in `README.md` and
  `DESIGN.md`.

## 0.2.2 - 2026-06-04

- Added collector-neutral Subject History as the base derived summary. Raw
  Wi-Fi/BLE/APRS-IS/Rayhunter/RTL-SDR logs now roll up into subjects such as
  SSID, BSSID, MAC, callsign, endpoint, and frequency, and Reports/Insights use
  that materialized layer instead of each workflow owning separate raw-log
  scans.
- Added an APRS-IS collector for internet-fed local situational awareness. It
  supports collector-managed APRS-IS feeds, configured range filters, optional
  callsign includes, per-feed status/counters, and default-off server-message
  emission so unfilterable server comments do not clutter the live feed.
- Added APRS-IS live UI support with a dedicated top-level tab, source/status
  metadata, decoded callsign/target/path/message/position/motion columns, and
  cleaner route display that avoids repeating feed labels already shown in
  status/type context.
- Added APRS packet normalization for local station/object/weather activity,
  including Mic-E/position handling, weather-station fields, CWOP-style weather
  packets, geofence enforcement for feeds whose server-side filtering is loose,
  and station rollups by callsign/object.
- Added APRS-IS Insights for live local-area activity and weather changes,
  including mobile station movement, weather temperature changes, rain
  started/stopped, high hourly rain, and high wind/gust conditions.
- Added APRS-IS Reports grouped by callsign/object instead of one generic APRS
  summary. Reports now include concise subject, summary, evidence, confidence,
  position/weather/motion context, and source provenance for APRS-IS rows while
  keeping APRS-IS distinct as internet-fed context rather than local antenna
  evidence.
- Added a live AlertEngine with a global alert strip, Alerts tab, ACK workflow,
  and default rules for high-signal operator events: DJI/Remote ID drone Wi-Fi,
  APRS severe weather, Rayhunter warnings, Wi-Fi disruption bursts, sensitive
  open SSIDs, and tracker-like BLE devices. Generic collector setup/status
  alerts are disabled by default.
- Added APRS-IS subject links and drilldowns from the live APRS tab, Reports,
  and Subject History. APRS subject detail now retains backend server identity,
  preferred-server settings, sample servers, feed role, configured host/filter,
  and igate/path provenance.
- Added optional preferred-backend handling for pooled CWOP APRS-IS hosts,
  including backend identity parsing, collector-wide preferred-server timeout
  and retry limit, fallback logging, and one-feed-per-line APRS System Status
  text that omits browser-facing debug counters and redundant APRS-IS wording.
- Added optional NOAA, USGS, and LAN collectors. NOAA polls NWS active alerts
  and optional NHC feeds, USGS polls nearby earthquake GeoJSON, and LAN records
  passive local neighbor/default-gateway state. All three are disabled by
  default in `config.example`, use Subject History, have live top-level tabs,
  feed Findings/Reports, and expose high-signal Alerts for hazards,
  earthquakes, and LAN gateway changes.
- Fixed System Status table sizing so state values such as `DISABLED` no longer
  wrap in the State column.
- Hardened APRS-IS operator diagnostics with clearer connect/disconnect,
  timeout, retry, and packet/drop logging; tightened APRS report Evidence
  provenance; added Rayhunter subject drilldowns; exposed compact alert details
  in the Alerts tab; and documented the raw-log to Subject History to
  Insights/Reports data flow.

## 0.2.1 - 2026-06-02

- Migrated the project to a separated source/config/runtime layout. Python code,
  shipped UI, and bundled lookup data now live under `src/skannr/`; generic
  templates live under `config.example/`; editable operator config lives under
  `config/`; dependency manifests live under `requirements/`; and generated
  logs/materialized state live under `runtime/logs/`. `install.sh` seeds
  `config/` from `config.example/` when local config is missing. Skannr now runs
  as `PYTHONPATH=src python -m skannr.main`.
- Added source-control ignore rules for local config, virtualenv, runtime logs,
  pcaps, archives, and bytecode, and hardened `scripts/release.sh` so `--all`
  does not descend into local runtime/log directories during staging.
- Updated the standard-layout migration script to rewrite a legacy
  `log_dir: logs` setting in `config/skannr.yaml` to `runtime/logs`.
- Removed the experimental awareness/environment-baseline registry before
  keeping it as part of the operator workflow. This removes `skannr_baseline.yaml`
  loading, learning/reset/accept controls, `/baseline/*` routes, baseline
  report-deviation rows, and baseline metadata in Reports.
- Added a Privacy report summary inside Reports and attached confidence and
  reason-tag provenance to report rows.
- Added an optional disabled-by-default Rayhunter collector that fetches a
  configured endpoint with gzip decoding and emits normalized Rayhunter status
  and warning events.
- Made the browser connection badge use successful ordinary HTTP responses as
  proof that Skannr is reachable. If the live `/events` stream is reconnecting
  while status/metadata calls succeed, the badge now shows connected with a
  reconnecting live-updates note instead of staying disconnected until a long
  derived refresh finishes.
- Made Rayhunter visible in derived intelligence: zero-warning endpoint status
  now produces an informational Insight, and Reports includes a compact
  Rayhunter status row from the latest endpoint event in the selected view.
- Parsed Rayhunter HTML status pages into structured status fields for Reports
  and Insights, including version, storage, memory, current recording, last
  message, artifacts, OS, and GPS mode. Reports no longer dumps Rayhunter HTML
  into Evidence.
- Simplified the Reports table by removing the visible Severity column and
  reserving more width for Confidence and Reasons while keeping severity in the
  underlying report data and status counters.
- Kept configured collectors visible in System Status even when disabled.
  Disabled collectors now appear as informational `DISABLED` rows with their
  static hardware/config metadata, rather than disappearing from the System
  table.
- Removed redundant Rayhunter endpoint/internal identity display from Reports
  Subject, Summary, and Evidence while keeping endpoint as structured Evidence
  and internal identity matching on the report object.
- Removed the Rayhunter raw-page summary fallback. Rayhunter events and reports
  now carry only parsed, tag-free fields or a short parse-limited status message.
- Switched Rayhunter polling to the JSON endpoints used by Rayhunter's own UI
  (`/api/system-stats`, `/api/qmdl-manifest`, and the current
  `/api/analysis-report/...`) so Skannr records the same status fields without
  scraping the Svelte app shell. The HTML fallback now strips script/style
  bundles and rejects code-like field values, and derived Reports/Insights scrub
  older Rayhunter records before display.
- Expanded the 0.2.x plan around counter-surveillance / local RF situational
  awareness: Score versus Confidence separation, Privacy reporting inside
  Reports, deterministic watch rules, Rayhunter gzip-aware fetching, and
  consistent report evidence/provenance.
- Removed the stale hardcoded browser version badge value from the static HTML
  so reloads wait for the server-provided version instead of briefly showing an
  old release number.

## 0.1.9 - 2026-05-31

- Kept Reports as the single intelligence report. Presence is represented as a
  Reports type/category instead of a separate tab or separate report payload, so
  presence, security, signal, identity, and collector findings share one ranked
  review surface.
- Removed the Reports Type filter because the broad type buckets were too lossy
  to use as a reliable filter. Reports still shows Type as a visible column and
  summarizes the visible report-family mix above the table.
- Made the Reports summary use the same report-family classification as the
  visible Type column, so the summary cannot report Presence counts while the
  displayed rows say Analysis.
- Added Reports `Confidence` and `Reasons` columns so rows expose evidence
  quality and compact reason tags such as recurring, long, strong, security,
  multi-BSSID, randomized, and scanner.
- Suppressed low-confidence stale one-off anonymous/randomized BLE rows from
  Reports while preserving them in the materialized Device History.
- Added scanner-quality report rows for stale or empty Wi-Fi/Bluetooth history,
  making collection gaps visible in the same intelligence report.
- Tightened Wi-Fi SSID/BSSID grouping. For multi-BSSID SSIDs, the SSID profile
  owns routine AP presence, signal, and radio context; individual BSSID rows are
  kept only for warning-level security differences.
- Improved managed Wi-Fi Scan reporting without requiring monitor mode. Reports
  now surface recurring AP/SSID presence, long AP presence, intermittent AP
  windows, and large RSSI swings from materialized AP sessions.
- Improved BLE presence clustering for randomized/private addresses. No-name
  BLE churn is now grouped by a coarse manufacturer/name/service-UUID
  fingerprint instead of manufacturer alone, preserving raw per-MAC Device
  History while making Reports more useful for physical-device inference.
- Follow-up fixes for the drilldown UI: SSID detail links now use the existing
  Wi-Fi AP sorter, and Bluetooth Device History column widths keep narrow
  headers readable while allowing Services / UUIDs to wrap.
- Follow-up fixes for derived refresh hangs: browser refresh requests now have a
  configurable timeout, failed/hung requests release the UI in-flight state and
  reschedule the next automatic refresh, and the backend serializes forced
  refreshes while logging per-stage timings for Device History, analysis,
  Reports, and Findings History. The browser also polls `/derived_views/status`
  during refreshes so the status strip shows the active backend stage and
  elapsed time.
- Added `--debug` / `-debug` startup mode. It raises log verbosity to DEBUG and
  opens a live `logs/skannr.log` tail window when a graphical terminal is
  available; headless/systemd runs continue to use the same log file.
- Prevented continuous stale-refresh loops when a derived refresh takes longer
  than the stale threshold. After any refresh completes, the browser now waits
  for the normal automatic interval before allowing another stale catch-up
  refresh.
- Hardened derived refresh status polling. If `/derived_views/status` reports
  that the backend refresh is no longer in progress while the original browser
  refresh request is still marked running, the UI now clears the stale running
  state, reloads the derived bundle, and ignores any later timeout from the
  abandoned request.
- Optimized cached derived-view loads. Device History display filtering no
  longer deep-copies the full materialized summary before applying the selected
  window, and the browser now de-duplicates overlapping cached `/derived_views`
  requests for the same window during reload/focus handling.
- Made overlapping forced derived-refresh requests join the active backend
  refresh instead of failing with `derived refresh already running`. This keeps
  a second tab, wake event, or delayed automatic refresh from showing a false
  failure while the first refresh is still completing normally.
- Added a browser preflight status check before forced derived refreshes. After
  a page reload, the browser now detects an already-running backend refresh and
  waits for it instead of blindly sending another refresh request.
- Added numbered derived-refresh phases to backend logs, `/derived_views/status`,
  and the browser status text so long refreshes can be debugged as Phase 1/4
  Device History, Phase 2/4 Insights analysis, Phase 3/4 Reports, and Phase 4/4
  Findings History.
- Documented derived-refresh debugging steps in `README.md` and `DESIGN.md`.
- Made empty-cache catch-up refreshes honor the same cooldown as automatic
  refreshes and skip while a cached derived bundle load is already in progress.
  This prevents repeated catch-up rounds immediately after startup/reload.
- Clear stale browser-side refresh/wait state whenever a derived bundle is
  successfully loaded. This prevents a reconnecting old page context from
  leaving Reports or Device History stuck on "waiting" after the backend has
  already returned current cached data.
- Made derived bundle rendering section-isolated. A render error in one derived
  section no longer prevents the other derived tabs from updating their data and
  status strips, and render failures are surfaced in the shared status text.
- Prevented cached `/derived_views` loads from overwriting the backend phase
  state for a forced refresh. Cached reads can still be logged, but only the
  forced refresh updates `/derived_views/status`.
- Made normal derived-bundle loads check `/derived_views/status` first. If a
  forced backend refresh is in progress, the browser now joins that refresh and
  waits for completion instead of rendering an older cached bundle with a stale
  refreshed timestamp.
- Added low-volume `ui_debug` browser diagnostics for derived-view loading and
  rendering. The browser now logs derived load requests, received bundle counts,
  render completion, and the three derived status-strip texts to
  `logs/skannr.log` for troubleshooting cases where the backend returned data
  but the UI still shows "Waiting for ...".
- Fixed joined-refresh polling. A browser page that discovers an already-active
  backend refresh through `/derived_views/status` now starts its own status
  polling timer, so it notices backend completion and loads the finished derived
  bundle instead of staying on the first observed phase.
- Relaxed the derived-load stale-response guard. The browser no longer drops a
  valid `/derived_views` response just because the View selector string changed
  while `/view_metadata` was loading, for example from `default` to the same
  resolved retention window. Request ids still prevent genuinely superseded
  responses from rendering.
- Added explicit derived fetch diagnostics for `/derived_views` start,
  successful browser-side resolution, and failure. Also disabled reusing an
  existing derived-load Promise during restart/reconnect so a stale in-flight
  load cannot suppress the current page's data load.
- Compacted browser-bound derived-view payloads. `/derived_views` and the
  individual derived endpoints now keep full materialized JSON files on the
  backend, but omit durable checkpoints and bulky per-device session bodies
  from HTTP responses. Device History still carries session counts and active
  presence state for tables/detail panels, while Reports and Insights keep the
  fields the UI renders. This directly addresses the case where the backend
  returned `200` quickly but Firefox spent minutes receiving/parsing a large
  derived bundle.
- Fixed same-window derived-load starvation. Reload/focus/metadata events can
  all ask for `/derived_views` while the previous request is still receiving or
  parsing. The browser now joins an existing in-flight load for the same View
  window instead of invalidating it and starting over, so Reports and Device
  History can render the response that is already underway.
- Added a browser-side derived-load coordinator. Startup, metadata, wake/focus,
  and refresh-completion events now queue/coalesce through one scheduler instead
  of directly starting competing `/derived_views` loads. Completed renders also
  acknowledge `/derived_views/ack`, giving the backend log a clear marker that
  a browser actually rendered a generated bundle.
- Made forced backend derived refresh dependency-aware. Device History and
  Findings History refresh in parallel first; once Device History is ready,
  Insights analysis and Reports refresh in parallel from that same summary.
  The status endpoint now exposes these as two refresh phases and the backend
  waits for all workers before publishing the final compact bundle.
- Capped browser-bound Device History payload rows. The backend keeps the full
  materialized state, but `/derived_views` now sends a recent, report-linked
  Device History slice plus total AP/client/Bluetooth counts. This avoids
  sending thousands of Bluetooth rows that the table would not render anyway,
  while preserving drilldown records referenced by Reports.
- Grouped noisy BLE randomized/private-address history for the browser view.
  No-name manufacturer-only BLE rows are folded into manufacturer/day groups,
  and stale one-off BLE MACs (`seen_count == 1` and last seen over an hour ago)
  are kept out of individual Device History rows. The backend still preserves
  the full per-MAC materialized state for analysis.
- Added `/derived_views` response-size and timing diagnostics plus gzip JSON
  responses when the browser supports compression. Browser debug logs now split
  derived fetch time into response headers, body receipt, and JSON parse time so
  slow Reports/Device History loads can be attributed to backend work, network
  transfer, or browser parsing.
- Added a backend live-observation overlay for Wi-Fi AP and Bluetooth rows.
  Derived refreshes now reconcile materialized Device History with the newest
  live scan events before publishing Reports/Device History, preventing a just
  completed refresh from showing stale `last_seen` values while the live scan
  tabs are current. The backend logs how many live Wi-Fi/Bluetooth rows were
  applied and the maximum lag corrected.
- Fixed derived-view status freshness accounting. Reports, Insights, and Device
  History now show and schedule from each section's actual materialized
  `generated_at` time instead of the wrapper time from a cached `/derived_views`
  load, so loading old cached data after restart no longer looks like a fresh
  Reports refresh.
- Prevented cached derived loads from repainting stale Reports/Device History
  while a manual, automatic, or catch-up backend refresh is already in flight.
  The browser now waits for the active refresh result instead of loading the old
  cached bundle during the refresh window.
- Replaced the accumulated browser-side derived refresh/load flags with one
  coordinator state. Cached loads, own refresh POSTs, and joined backend
  refreshes now have separate completion paths: a browser-owned refresh renders
  the POST response, while a joined refresh polls backend status and then loads
  the finished bundle once. This avoids the prior race where status polling
  could start a cached GET just as the refresh POST was about to return.
- Cleaned up the backend derived-refresh coordinator. Forced refresh ownership,
  phase/status metadata, and last-finished state now live in one
  `DerivedRefreshCoordinator` instead of being scattered through shared
  `runtime` keys. The `/derived_views/status` response shape is unchanged, and
  concurrent forced refreshes still join the active backend refresh.
- Added a cached derived-view consistency repair for dependent summaries. When
  cached `/derived_views` loads find Reports or history analysis older than the
  materialized Device History snapshot, the backend rebuilds those dependent
  summaries from cached Device History before returning the bundle, avoiding
  mixed timestamps such as fresh Insights with stale Reports.
- Hardened the derived backend workflow after refresh review. Dependent-summary
  repair now participates in the same coordinator as forced refreshes, direct
  section endpoints read through the coherent derived bundle path, successful
  and failed derived operations are tracked separately, and runtime derived
  section updates are protected by a small cache lock.
- Made materialized derived-summary writes atomic. Device History, history
  analysis, Reports, and helper JSON writes now write a complete temporary file
  and replace the old file in one step, preventing browser reads from seeing a
  partially written JSON file.
- Bounded the backend live-observation overlay cache with runtime TTL/count
  pruning so randomized BLE/Wi-Fi churn cannot grow unbounded for the lifetime
  of the Skannr process.
- Fixed Device History serialization for old/mixed materialized values. Sets
  containing both strings and numbers are now serialized deterministically
  instead of failing refresh with Python 3 comparison errors.
- Fixed Wi-Fi report generation for old/mixed channel values. SSID grouping now
  normalizes channels before sorting, so cached dependent-summary repair cannot
  fail when historical summaries contain both numeric and string channel labels.
- Made repaired Reports and Insights report the Device History source snapshot
  time as their freshness time. Rebuilding dependent summaries from cached
  Device History no longer makes old source data look newly collected.
- Added a startup/page-load catch-up guard for Device History. Cached
  `/derived_views` loads now compare Device History's saved JSONL checkpoints
  with current collector log sizes and run a real refresh when raw scan logs
  contain unmaterialized bytes.
- Made the startup/page-load catch-up refresh run in the background instead of
  holding the `/derived_views` response open. Follow-up loads now join the
  active backend refresh, and cached loads defer another checkpoint-triggered
  refresh until the normal refresh interval after a successful full refresh.
- Reduced Device History refresh I/O after applying the live-observation
  overlay. Refresh now builds one full materialized summary, applies the live
  Wi-Fi/Bluetooth freshness overlay in-place, and writes the large
  `device_history.json` file once instead of rereading/copying/rewriting it
  after the builder already persisted it.
- Suppressed stale one-off anonymous BLE rows from short-horizon Insights, in
  line with the existing Reports/browser grouping of low-value randomized BLE
  churn. The raw per-MAC materialized history is still preserved, but old
  no-name single-sighting BLE rows no longer consume analysis time or produce
  low-value Insight rows.
- Switched materialized derived-summary JSON writes to compact atomic JSON
  instead of pretty-printed/sorted JSON. These files are cache artifacts rather
  than operator-authored config, so compact writes reduce CPU, disk I/O, and
  file size during refreshes on Pi storage.
- Added low-volume derived refresh substep timings for Device History,
  Findings History, history analysis, and Reports so future slow refreshes show
  whether time is spent building, saving, or display-filtering each section.
- Limited persisted Findings History and history-analysis inputs to the
  configured recent Insights window. Insights is a tactical recent-event feed,
  so refresh no longer saves tens of thousands of old finding rows or analyzes
  retained old Bluetooth privacy-address churn that would be filtered out
  before display.
- Kept bulky per-device session history out of the Insights analysis input.
  Reports remains responsible for recurring/longer-window presence patterns,
  while Insights evaluates recent signal/state rules without scanning retained
  session lists for every recently seen Bluetooth device.
- Stopped forcing an `fsync()` for derived-summary cache writes. The files are
  still written through a temporary file and atomically replaced, but refresh no
  longer waits for storage-level durability of rebuildable materialized caches
  on every cycle.
- Pruned stale anonymous single-sighting BLE addresses from the materialized
  Device History cache. Raw JSONL logs remain the audit trail, but the fast
  cache no longer carries thousands of old no-name private addresses that do
  not support identity, Reports, or Insights.

## 0.1.8 - 2026-05-28

- Added collector status dots to the main collector tabs. Wi-Fi Scan,
  Wi-Fi Monitor, and RTL-SDR each show one dot; Bluetooth shows separate BLE
  Scan and Bluetooth Classic dots. Filled means `ONLINE`; hollow means not
  online, with tooltip/ARIA labels for the exact state.
- Added browser-side drilldown views for Bluetooth MACs, Wi-Fi SSIDs, and
  Wi-Fi BSSIDs. Reports, Device History, and live Wi-Fi/Bluetooth scan rows now
  link into the same detail panel, using the currently loaded Device History and
  Reports data.
- Made Wi-Fi Reports more SSID-centric. Multi-BSSID SSID profiles now carry
  aggregate radio/security/vendor/signal evidence and leave full BSSID/radio
  lists to drilldown. Routine BSSID profile rows are suppressed when the SSID
  profile already covers them, while radio-specific security/channel findings
  and very strong radios remain visible as BSSID reports.

## 0.1.7 - 2026-05-27

Listener configuration:

- Replaced the legacy `skannr.host` / `skannr.port` web binding mode with
  required `skannr.listeners`.
- Removed the default active use of port 5000. The generated config now uses
  `"127.0.0.1:5004"`.
- Made `skannr.listeners` a YAML list of quoted endpoint strings only, for
  example `"127.0.0.1:5004"`, `"0.0.0.0:5004"`, and `"[::]:5006"`.
- Removed support for two-line listener entries with separate `host` and
  `port` keys.
- Documented that YAML `-` is standard list syntax and that endpoint strings
  should be quoted because unquoted bracketed IPv6 is not valid YAML in PyYAML.
- Added startup validation for empty listener lists, malformed endpoint strings,
  misplaced top-level `listeners`, unsupported legacy `host` / `port`, and
  invalid TCP ports.
- Reworked multi-listener serving so every configured endpoint is bound before
  any listener starts serving requests. This avoids hiding bind/startup failures
  in a background thread.
- Replaced repeated `socketio.run()` startup with explicit Werkzeug server
  objects. The browser uses Server-Sent Events and ordinary HTTP routes, so the
  serving path no longer depends on starting multiple Flask-SocketIO lifecycle
  wrappers in one process.
- Updated the browser connection badge to report the actual endpoint from
  `window.location`, including connected port and address family.

Bluetooth identity and UUID decoding:

- Added optional offline Bluetooth UUID assigned-number lookup files:
  `collectors/member_uuids.txt`, `collectors/service_uuids.txt`, and
  `collectors/characteristic_uuids.txt`.
- Loaded Bluetooth UUID mappings through dashboard metadata so the browser can
  decode advertised UUIDs without internet access.
- Propagated BLE `service_uuids` from Device History into Insights and Reports
  evidence so derived views retain the same UUID context seen during BLE Scan.
- Added Bluetooth UUID display logic shared by BLE Scan, Bluetooth Device
  History, Insights, and Reports.
- Renamed compact Bluetooth display from Name/Services to Identity and
  Services / UUIDs.
- Kept BLE advertisement fields semantically separate: advertised name,
  manufacturer-data company ID, and advertised service/member UUIDs stay as
  distinct raw fields in persisted data.
- Combined advertised name and manufacturer-data company information only in the
  operator-facing Identity display, for example
  `N62N1 | Mfr: AR Timing (0x0201)`.
- Decoded member/vendor UUIDs in Services / UUIDs with explicit labels, for
  example `Member UUID FEAF: Nest Labs Inc`, instead of folding them into Name
  or Subject fields.
- Removed the separate Manufacturer column from compact BLE Scan and Bluetooth
  Device History tables because the same information is now labeled in Identity.
- Documented the distinction between BLE manufacturer company identifiers and
  Bluetooth UUID assigned-number files in `README.md` and `DESIGN.md`.

Browser and derived-view performance:

- Reduced browser-side load from live radio events by coalescing Wi-Fi,
  Bluetooth, and Wi-Fi Monitor table rerenders instead of rebuilding those DOM
  tables once per received event.
- Pruned stale live-only BLE rows from the browser map so randomized BLE
  addresses do not accumulate indefinitely in the client session. Device
  History remains the durable historical store.
- Made Device History table filtering compute row cells once and stop after the
  configured visible-row limit, reducing work when many retained devices exist.
- Made View selector changes run a derived refresh for the newly selected
  window. Reports and Insights are materialized per window, so a cached-only
  load could show empty data until the user pressed Manual Refresh.
- Added report-score recency adjustment so old high-interest devices no longer
  keep the same rank indefinitely. Profiles now get `+15` if last seen within
  24 hours, `+5` within 1-3 days, `-15` within 3-7 days, and `-30` when older
  than 7 days.

## 0.1.3 - 2026-05-22

- Reframed Insights as a recent tactical/debuggable event feed.
- Added `history_analysis.insights_recent_hours` to limit Insights to recent
  activity by default.
- Filtered history-analysis Insights by activity time (`last_seen_epoch`) so
  stale device behavior does not reappear as recent after refresh.
- Changed the Insights view selector default to `All recent`.
- Improved Reports Evidence readability by folding related evidence lines:
  observed/session state, strong-signal findings/signal value, and Wi-Fi
  radio/security details.
- Documented the intended roles of Insights, Reports, and Device History in
  `README.md` and `DESIGN.md`.

## 0.1.2 - 2026-05-22

Best-effort reconstruction from local working-tree state and recent development
notes. Exact Git history was not available in `/scratch/spommere/Skannr`.

- Made Reports the primary ranked intelligence product.
- Added server-side score/ranking semantics for Reports, including operator
  attention scoring rather than malicious-probability scoring.
- Added/consolidated Bluetooth report profiles:
  - stable BLE MACs become one device-profile row
  - unnamed/private/randomized BLE addresses are grouped by manufacturer
  - repeated presence, long presence, current activity, signal strength, and
    days seen contribute to ranking
- Added/consolidated Wi-Fi report profiles:
  - AP-level findings are merged into one profile per BSSID
  - SSID-level behavior, such as multiple BSSIDs, is emitted as a separate
    SSID profile
  - strong AP, new AP, channel variation, security variation, and multi-BSSID
    context contribute to ranking
- Added the visible Reports `Score` column.
- Improved Reports filtering with source chips and type/search filtering.
- Changed Reports evidence rendering from pipe-delimited strings to structured
  label/value rows.
- Reduced redundant identity text in Reports by moving identity into `Subject`
  and behavior/context into `Evidence`.
- Fixed local/server timestamp handling so browser timezone no longer changes
  displayed report/device-history times.
- Kept derived views materialized so Reports, Insights, and Device History can
  refresh from summaries instead of repeatedly re-reading all raw logs.

## 0.1.1 - 2026-05-21

Best-effort reconstruction from local working-tree state and recent development
notes. Exact Git history was not available in `/scratch/spommere/Skannr`.

- Renamed the project from Spectra to Skannr across user-visible files.
- Added the `VERSION` file and displayed the application version in the page
  header.
- Added/expanded `CHANGELOG.md` with the initial versioning policy.
- Added/expanded `DESIGN.md` as the design document and kept `README.md` as the
  operator manual.
- Added Apache-2.0 licensing structure.
- Added systemd/service installation documentation for running Skannr as a
  service.
- Added GitHub/release workflow support, including the release helper script.
- Updated README guidance for Wi-Fi/Bluetooth manufacturer lookup data files
  and offline operation.
- Cleaned up project naming and release packaging expectations after the rename.
