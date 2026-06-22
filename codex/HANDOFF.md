# Skannr Handoff - 2026-06-21

## Update - 2026-06-21

### Version Bump to 0.3.0

Bumped version from 0.2.8 to 0.3.0. The jump reflects meaningful architecture
change (Subject History became the single source of truth for Wi-Fi/BLE) and
moves past the 0.2.x cycle.

**Changes made:**
- `VERSION`: 0.2.8 → 0.3.0
- `CHANGELOG.md`: added condensed 0.3.0 section summarizing all post-0.2.8 work
- `VERSION_HISTORY.md`: moved `post-0.2.9 work` and `post-0.2.8 / v0.2.9 work`
  into a new `0.3.0 detailed work` section; added empty `post-0.3.0 work` section
- `README.md`: added `0.3.x` to versioning policy
- `DESIGN.md`: version header 0.2.8 → 0.3.0
- `codex/HANDOFF.md`: this entry

### Subject History Architecture Cleanup

Renamed `DeviceHistoryBuilder` → `WiFiBLEPostprocessor` and moved it inside
`SubjectHistoryBuilder` as an internal helper, removing the prerequisite
`build_or_reuse_device_history_for_refresh()` step from the refresh pipeline.
`subject_history.json` is now the single source of truth; `device_history.json`
is no longer written to disk.

**Specific changes:**

- `device_history.py` → `wifi_ble_postprocessor.py`, class renamed to
  `WiFiBLEPostprocessor`
- `SubjectHistoryBuilder.build_summary()` now reads raw JSONL for all 15
  collectors and calls `WiFiBLEPostprocessor` internally for Wi-Fi/BLE
- `display_summary()` reads Wi-Fi/BLE data from `subject_history.json` directly
  instead of from `device_history.json`
- Background worker (`update_compact_device_history()`) still runs and saves
  checkpoint state for performance
- `build_or_reuse_device_history_for_refresh()`, `apply_live_overlay_and_prune_device_history()`,
  `recent_device_history_summary()`, and `apply_live_observations_to_history()`
  are now dead code (kept for now, can be removed in a future cleanup)
- Unused import `low_identity_bluetooth_record` removed from `main.py`
- Typo fix: `1902px` → `1920px` in regression test and docs

**Files touched:**
- `src/skannr/wifi_ble_postprocessor.py` (renamed from device_history.py)
- `src/skannr/subject_history.py`
- `src/skannr/main.py`
- `scripts/skannr_regression_test.py`
- `scripts/skannr_admin.py`
- `scripts/validate_collector_contract.py`
- `README.md`
- `DESIGN.md`
- `VERSION_HISTORY.md`
- `CHANGELOG.md`
- `codex/HANDOFF.md`

**Known deferred items (from read-only review):**
1. Value-normalization helper deduplication — deferred (semantics differ)
2. ✅ Bluetooth adapter centralization — done prior to this session
3. device_history/subject_history architecture — addressed in this session
4. Small helper-clone cleanup — deferred

**Test status:**
- Regression test runs but 14/71 tests fail due to missing source capture data
  on this machine (not a code issue)
- All layout budgets pass at 1920px

### Version Bump to 0.3.0 (follow-up)

Further version-bump work after the earlier 0.3.0 entry:

- Read the full codex files (`codex.txt`, `HANDOFF.md`) to understand project rules
- Updated `CHANGELOG.md` with a condensed 0.3.0 section summarizing all
  post-0.2.8 work (BLE cleanup, RTL-433 reports, config docs overhaul, recency
  grouping, layout compliance, Pushover, etc.)
- Restructured `VERSION_HISTORY.md` — moved `post-0.2.9 work` and
  `post-0.2.8 / v0.2.9 work` under a new `## 0.3.0 detailed work` section;
  created empty `## post-0.3.0 work` placeholder at top
- Added `0.3.x` to the versioning policy in `README.md`
- Updated `DESIGN.md` version header from 0.2.8 to 0.3.0

No code changes were made.

# Skannr Handoff - 2026-06-18

## Update - 2026-06-18

### Read-Only Code Review Follow-Up

A read-only Skannr code review was done before any documentation updates or
version bump work. The emphasis was streamlined structure, redundant code,
possible remnants no longer in use, and documentation quality in code.

Current outcome:

- no code changes were made yet
- no documentation files were updated yet
- the next release target remains `0.2.9`, but only after agreed findings are
  addressed and then the docs are brought back in sync

Review findings discussed with the user:

1. Value-normalization helper duplication exists across several modules, but
   this should be left alone for now.
   - Reason: some helpers look similar but do not yet have identical semantics,
     so broad deduplication before `0.2.9` risks forcing the wrong shared
     behavior.
2. Bluetooth adapter selection/probe handling is the best cleanup target to do
   before `0.2.9`.
   - This should follow the same general shape as other shared hardware
     selection logic:
     - shared handling owns adapter discovery, existence/probe checks,
       configured-vs-discovered ranking, and `bluetoothctl` controller
       visibility checks
     - `ble.py` keeps BLE-specific runtime behavior such as Bleak versus
       `bluetoothctl`, fallback, warmup, and BLE parsing/enrichment
     - `bt_classic.py` keeps classic inquiry execution and parsing
   - The user explicitly wants us to keep support for more than one Bluetooth
     adapter in mind, similar in principle to the split between
     `wifi` / `wifi_monitor`, while still keeping collector-specific workflow
     local where appropriate.
3. The `device_history.json` versus `subject_history.json` architecture issue
   should be deferred.
   - Current problem statement:
     - `subject_history.json` is intended to be the collector-neutral source of
       truth
     - Wi-Fi/Bluetooth still flow through `DeviceHistoryBuilder` first
     - `SubjectHistoryBuilder` then consumes that output
     - so the compatibility layer is still an active internal dependency rather
       than only a downstream export
   - If we revisit this later, the desired direction is:
     - make `subject_history.json` the true source of truth
     - move Wi-Fi/Bluetooth subject folding directly into Subject History
     - keep `device_history.json` only as a derived compatibility output for
       older UI/API consumers
     - move checkpoint ownership for Wi-Fi/Bluetooth to the Subject History
       side
   - This is a structural cleanup and should not be rushed into `0.2.9`.
4. Small generic utility/helper clones should also be deferred except for
   opportunistic cleanup when already touching the same area.
   - Meaning: only consolidate helpers whose semantics are already identical;
     do not force domain-specific behavior into generic shared helpers.

Agreed release-oriented plan:

- Fix now:
  - tighten and centralize Bluetooth adapter discovery/probe/ranking logic only
    (`#2`)
- Defer:
  - the `device_history.json` / `subject_history.json` structural cleanup
    (`#3`)
  - broad helper-clone cleanup (`#4`)
  - broad normalization-helper deduplication (`#1`)
- Sequence after code fixes:
  - review findings are addressed
  - update `README.md`, `DESIGN.md`, and `REFERENCE.md`
  - then bump the version to `0.2.9`

### Files Touched Today

- `codex/HANDOFF.md`

### Notes

- This update records review conclusions and planning only.
- No code refactor has started yet.
- No regression harness or runtime scripts were run in Codex for this pass.

# Skannr Handoff - 2026-06-17

## Update - 2026-06-17

### BLE Feed / Grouping Work

BLE identity corruption was traced to the new `bluetoothctl` path plus
insufficient downstream sanitization:

- `bluetoothctl` property lines such as `RSSI: ...`, `UUIDs: ...`,
  `TxPower: ...`, and manufacturer/property text were being accepted as device
  names.
- Those pseudo-names then flowed into `device_history`, identity grouping,
  Subject History, and Reports.

Fixes applied:

- `src/skannr/collectors/ble.py`
  - fixed the `bluetoothctl` parser so RSSI/property lines cannot become names
  - parses RSSI, UUIDs, and manufacturer keys into structured fields
  - strips ANSI color codes before parsing `bluetoothctl` output
  - uses `bluetoothctl info <MAC>` only for identity enrichment
    (name / alias / UUID / manufacturer), not RSSI
  - caches useful `info` results for the life of the process
  - preserves last-known visible BLE fields across sparse `bluetoothctl`
    windows so later name-only windows do not blank RSSI/manufacturer/services
- `src/skannr/device_history.py`
- `src/skannr/identity_policy.py`
- `src/skannr/history_analysis.py`
- `src/skannr/static/app.js`
  - all now reject property-text pseudo-names as identity

Debug helper added:

- `scripts/ble_feed_debug.py`
  - standalone `bluetoothctl` scan/info normalizer for debugging
  - supports bounded scans, optional MAC filter, JSON output, and `--skip-info`

Validation/evidence:

- Pre-`bluetoothctl` sample from 2026-06-14 was clean.
- Post-`bluetoothctl` samples from 2026-06-16 on Kali and Pi4 showed
  `name: "RSSI: ..."` with missing structured fields, confirming the fallback
  path as the source of that corruption.
- `/tmp/b.txt` later proved raw Kali `bluetoothctl` output included RSSI but
  ANSI escape codes were breaking parsing; stripping ANSI fixed that issue.

Scan-method recommendation:

- Do not switch categorically to `bluetoothctl`.
- Keep Bleak/BlueZ as the primary path where it works, and keep
  `bluetoothctl` as fallback or host-specific override.
- Reason: Bleak/BlueZ still provides richer structured advertisement data;
  `bluetoothctl` remains a text-oriented fallback even after the fixes.

### Offline Admin Tool

Added `scripts/skannr_admin.py` with `purge-collector` support for scoped
collector cleanup under `runtime/logs`.

Important user direction:

- Do not run `purge-collector` from Codex unless the user explicitly asks again.
- If needed, give the user the exact command and let them run it.

Notes:

- dry-run does not rebuild derived state and does not read raw collector log
  payloads, but it does read mixed `findings/*.jsonl` and `alerts/*.jsonl`
  to estimate scrub counts
- `--apply` prints live progress
- the rebuild path is the same derived-state rebuild Skannr already uses; it is
  not a separate rebuild mechanism

### RTL-433 Reports

The user wanted RTL-433 device-profile reports to read more like Wi-Fi/Bluetooth
presence summaries, especially under `Evidence -> Pattern`.

Server-side report generation changes in `src/skannr/reports.py`:

- RTL-433 subject summary text now uses concise presence-style wording such as:
  - `seen Wed`
  - `usually active 10am`
  - `daytime only`
- repeat-gap text stays in operational detail rather than in the presence
  pattern summary
- duplicate `last_seen` overwrite bug in the RTL-433 device-profile evidence
  payload was removed

Browser-side RTL-433 Evidence changes in `src/skannr/static/app.js`:

- `rtl433_device_profile` `Pattern` now uses Wi-Fi-style presence wording
  derived from:
  - `weekday_histogram`
  - `hour_histogram`
  - `day_night_counts`
- `Observed` keeps the observed range plus recent sightings
- `tpms_interpretation` is no longer mixed into `Pattern`; it remains separate
  semantic content

Critical finding from `/tmp/c.txt`:

- `/tmp/c.txt` contained the actual `runtime/logs/device_history/reports.json`
  payload, not just rendered browser text.
- For affected RTL-433 device-profile rows such as:
  - `Schrader-EG53MA4 C20135` / protocol 95
  - `Toyota f2f4d113` / protocol 88
  the server payload already had correct pattern inputs:
  - `weekday_histogram`
  - `hour_histogram`
  - `day_night_counts`
  - `first_seen`
  - `last_seen`
  - `observed`

That proved the remaining missing `Pattern` / `Observed` problem was not in
raw data or report generation.

Root cause:

- the generic browser Evidence deduper in `src/skannr/static/app.js` was
  removing `Pattern` and `Observed` when their text already appeared in the
  `Subject` summary line

Fix applied:

- the deduper now preserves semantic Evidence sections:
  - `Pattern`
  - `Observed`
  - `Activity`

Implication:

- do not purge `rtl433`
- do not delete `runtime/logs/findings` or `runtime/logs/device_history`
  for this issue
- if RTL-433 report rows still look wrong, the next check should be which exact
  `app.js` file the browser is receiving, not a data rebuild

### Additional BLE Subject Fix - 2026-06-17

After the earlier BLE parser/grouping work, another BLE report-label issue was
found:

- Reports could still show multiple Bluetooth Subjects based on raw manufacturer
  company IDs such as `0x004c`, `0x0065`, or `0x0701`.
- The same weak BLE identity could also present inconsistently: some rows looked
  like randomized-address groups, while others drilled into a single MAC.

Root cause:

- BLE manufacturer display text was not normalized centrally. Different code
  paths used `manufacturer_name`, raw `manufacturer`, or `vendor_name`, so the
  visible subject could vary between a descriptive label and a raw code.
- Individual BLE report subjects and grouped randomized BLE cluster subjects had
  different fallbacks, which let raw code-only manufacturer labels surface in
  the Reports Subject column.

Fix applied:

- `src/skannr/identity_policy.py`
  - added centralized Bluetooth manufacturer normalization helpers
  - strips trailing company-id suffixes from labels like `Apple, Inc. (0x004c)`
  - recognizes known code `0x004c` as `Apple` even when only the code is present
  - raw code-only labels such as `0x0065` / `0x0701` are no longer treated as
    human-facing visible identity
- `src/skannr/reports.py`
  - grouped randomized BLE cluster subjects now prefer a visible manufacturer
    name and otherwise fall back to a generic label rather than a raw code
  - individual BLE report subjects now use:
    - name if present
    - visible manufacturer if present
    - otherwise MAC only

Implication:

- `0x004c` should now surface as `Apple` rather than the raw code
- unknown code-only manufacturer buckets should no longer surface as raw
  company IDs in the Reports Subject column
- this fix improves label consistency, but it does not yet change the BLE
  private-group threshold logic itself; some weak BLE rows may still remain
  individual MAC-based rows while others become randomized-address clusters

### BLE UUID Name Lookup - 2026-06-17

Another BLE display issue was found after the earlier parser/grouping work:

- The BLE UI could show `Unknown UUID (110A)` for common Bluetooth service
  class IDs such as `0x110A` even when the user had provided a local lookup
  file.

Root cause:

- The browser label came from `bluetooth_uuid_names()` in
  `src/skannr/main.py`, not from `src/skannr/collectors/ble.py`.
- That loader only searched `member_uuids`, `service_uuids`, and
  `characteristic_uuids`, and its text fallback parser only understood the
  YAML-like `uuid:` / `name:` format.
- The user-supplied `src/skannr/data/collectors/service_class.txt` file uses a
  flat `0xNNNN<TAB>Name` layout, so values like `0x110A` were never loaded.

Fix applied:

- `src/skannr/main.py`
  - added `service_class` to the Bluetooth UUID source list
  - expanded the fallback text parser to accept flat text rows such as
    `0x110A    Audio Source`

Validation:

- `load_bluetooth_uuid_file(service_class.txt)` now resolves:
  - `110a -> Audio Source`
  - `110b -> Audio Sink`
- the file produced 68 UUID-name mappings during the local loader check

Implication:

- after restarting Skannr, BLE rows that previously rendered as
  `Unknown UUID (110A)` should display `Audio Source (110A)` instead.

### Files Touched Today

- `src/skannr/collectors/ble.py`
- `src/skannr/device_history.py`
- `src/skannr/identity_policy.py`
- `src/skannr/history_analysis.py`
- `src/skannr/reports.py`
- `src/skannr/static/app.js`
- `scripts/ble_feed_debug.py`
- `scripts/skannr_admin.py`
- `src/skannr/main.py`
- `codex/HANDOFF.md`
- `VERSION_HISTORY.md`

# Skannr Handoff - 2026-06-16

## Current State

This checkout is `/scratch/spommere/Skannr`. The local notes in
`codex/codex.txt` say this development machine is intentionally not the GitHub
upload host. There is an empty `.git` directory, so `git status` and `git diff`
do not work here. Use direct file inspection unless the user moves the work to a
real checkout.

Do not read runtime logs unless the user explicitly changes that instruction. Do
not read or grep `data/collectors/`; it contains large vendor lookup data. Do
not run `scripts/skannr_regression_test.py`; the user runs it outside Codex and
reports the results.

## Latest Completed Work

Reports and Subject History recency divider styling was adjusted so the
"Seen within ..." group rows are easier to distinguish from normal table rows:

- Increased recency divider font size above body-row text.
- Switched recency divider rows from pale gray to a light yellow treatment.
- Added stronger divider padding and heavier top/bottom borders.
- The discussed recency expand/collapse behavior was not implemented; it
  remains a possible later UI follow-up.
- User visual check: Reports and Subject History looked good after the divider
  styling change. A possible later polish item is to make the section headings
  "Cross-Subject Patterns" and "Subject Reports" stand out more now that the
  recency dividers are stronger.

Configuration documentation was refreshed across the full example tree:

- Updated every YAML file under `config.example/collectors/` with clearer inline
  comments for active parameters and grouped related knobs together.
- Updated `config.example/skannr.yaml` with section-level comments and a pointer
  to the new reference appendix.
- Added `REFERENCE.md` as the configuration parameter appendix. It covers the
  shared collector contract, `skannr.yaml`, every collector/action YAML, and
  interaction notes for BLE scan methods, Wi-Fi scan/retry cadence, Wi-Fi
  Monitor channel behavior, NOAA subfeeds, LAN source controls, and RTL-433
  protocol selection.
- Added a `README.md` Project Files pointer for `REFERENCE.md`.
- Added a detailed `VERSION_HISTORY.md` post-0.2.8 bullet and an `Unreleased`
  `CHANGELOG.md` note for the documentation/config reference work.

Specific user-requested documentation points now covered:

- BLE: BlueZ/Bleak primary scanning versus `bluetoothctl` primary/fallback,
  including `force_bluetoothctl_scan`, `bluetoothctl_fallback_after_timeout`,
  and `force_discover_scan`.
- Wi-Fi: `managed_scan_interval_sec` is normal scan cadence; `retry_interval_sec`
  applies after failure; `retry_timeout_sec` is setup/retry diagnostics.
- Wi-Fi Monitor: monitor setup controls, channel mode, learned/typical channels,
  `dwell_sec`, and retry behavior.
- NOAA: comments before NWS, forecast, NHC, and tsunami subfeeds;
  `tsunami.fetch_bulletin_text: false` avoids extra bulletin text requests and
  uses CAP/feed metadata only.
- LAN: passive OS/service sources, avahi, passive packet listeners, active ARP
  scan, and DHCP lease import controls.
- RTL-433: frequency plan syntax, common ISM frequencies, and cautious `-R`
  protocol guidance. Protocol IDs are version-owned by rtl_433, so the docs say
  to run `rtl_433 -R help` on the target host before hardcoding exact numbers.

## Files Touched In Latest Work

- `REFERENCE.md`
- `README.md`
- `CHANGELOG.md`
- `VERSION_HISTORY.md`
- `config.example/skannr.yaml`
- `config.example/collectors/adsb.yaml`
- `config.example/collectors/aprsis.yaml`
- `config.example/collectors/ble.yaml`
- `config.example/collectors/ble_identify.yaml`
- `config.example/collectors/bt_classic.yaml`
- `config.example/collectors/lan.yaml`
- `config.example/collectors/lan_identify.yaml`
- `config.example/collectors/noaa.yaml`
- `config.example/collectors/pws.yaml`
- `config.example/collectors/rayhunter.yaml`
- `config.example/collectors/rtl433.yaml`
- `config.example/collectors/swpc.yaml`
- `config.example/collectors/usgs.yaml`
- `config.example/collectors/wifi.yaml`
- `config.example/collectors/wifi_monitor.yaml`
- `src/skannr/static/style.css`
- `codex/HANDOFF.md`

## Validation

Validation run after the config documentation refresh and today's UI styling update:

- Parsed all 16 YAML files under `config.example/` with PyYAML.
- Checked updated docs/config files for CRLF and missing final newline.
- Scanned updated docs/config files for the typo variants from the user note;
  none found.
- Verified the recency divider CSS block directly after editing `src/skannr/static/style.css`.
- User-reported browser check: Reports and Subject History looked good after the
  divider styling change; other tabs were not reviewed in that pass.
- User-ran `scripts/skannr_regression_test.py` outside Codex with 169 total
  checks, 169 succeeded, 0 failed. Report artifact: `/scratch/spommere/Skannr_test/skannr-regression-20260616-182417/skannr-regression-20260616-182417.json`.

No regression harness run was performed. No browser validation was run inside Codex. No runtime logs were read.

## Recent Functional Work Already Completed

Before the documentation pass, the post-0.2.8 work included:

- System Status collector grouping by ONLINE, OFFLINE / STOPPED, and DISABLED.
- Reports and Subject History grouping by last-seen recency buckets: within the
  last hour, within the last 24 hours, and 24+ hours ago.
- Regression harness summary counts for total/succeeded/failed checks.
- Multi-node regression input via `node_logs_root` with dated collector JSONL
  discovery and a default 250-event per-node cap.
- Regression report Raw Sample Input now reports mode and source-file counts
  instead of listing every JSONL path.
- Annotation fixture stabilization for multi-node regression replay.
- 1902px layout compliance budget expansion across visible tabs.
- Post-0.2.7 retained-analysis work: APRS trip evidence, grouped BLE/Wi-Fi/LAN
  drilldowns, richer RTL-433 evidence, ADS-B analysis, TPMS interpretation, and
  NOAA forecast deltas, with regression coverage reported by the user as passing
  at 140/140 and later 163/163 checks.

## Known Caveats

- Use ASCII for edits unless an existing file requires otherwise.
- Keep changes scoped; do not broaden into runtime log inspection or regression
  execution without explicit user direction.
