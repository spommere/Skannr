# Code-Review Findings — pre-0.3.8 (2026-08-15)

Scope: full uncommitted working-tree diff (`git diff HEAD`), reviewed with
10 finder angles + per-candidate verification + gap sweep. Every item below
was verified against the actual code (CONFIRMED) unless marked PLAUSIBLE.
REFUTED candidates are listed at the end.

## A. Correctness bugs in new 0.3.8 code

- [x] **A1 — `snapshot_retention_hours: 0` wipes the whole snapshot ring.**
  `main.py:5332`/`:5286` pass `snapshot_retention_hours()` (0 = "never purge"
  per docstring/config comment) into `save_snapshots()`, where
  `snapshots.py:298` computes `cutoff = now - (0*3600)` and deletes every
  snapshot with mtime < now — i.e. all prior snapshots on each hourly save.
  Fix: skip purge when `retention_hours <= 0` inside `save_snapshots()`.
- [x] **A2 — SKIR delta timeline never renders with default 24h retention.**
  `llm.py:773` `delta_hours = [h for h in all_hours if last_epoch <= h < cutoff]`
  with `cutoff = all_hours[-1] - 24*3600`: with ~24h of retained snapshots (or
  a previous SKIR < 24h old, e.g. daily cron), `delta_hours` is always empty →
  "Delta Since Last Report" section silently dead. Feature only works with
  `snapshot_retention_hours` > 24 and SKIRs > 24h apart — undocumented.
- [x] **A3 — Delta/current window boundary mismatch (mixed axes).**
  Current window = last 24 snapshot FILES (`llm.py:746`), delta cutoff = last
  hour minus 24 WALL-CLOCK hours. With gappy snapshots the same hours can
  appear in both sections (false "new arrivals" in the LLM comparison), and
  the hour at `cutoff` appears in neither (off-by-one).
- [x] **A4 — llm.py hardcoded log dirs ignore `persistence.filesystem.log_dir`.**
  `load_latest_skir`/`list_skirs`/`load_skir_by_id` (`llm.py:1344,1360,1391`)
  and both timeline loaders (`llm.py:739,759`) default to
  `PROJECT_ROOT/runtime/logs`, while writers honor the configured dir
  (`_resolve_log_dir()` `llm.py:309`, `configured_log_dir()` `main.py`).
  With a custom `log_dir`, SKIR delta + timelines silently vanish.
  (Note: `paths.LOG_DIR` never existed; `paths.RUNTIME_LOG_DIR` does.)
- [x] **A5 — Renamed ui config keys have no migration.**
  `derived_scheduler_interval_sec` / `derived_auto_refresh_min` /
  `snapshot_backfill_hours` → new merged keys, but nothing migrates or warns:
  an operator who set the old key to 0 (disable scheduler) silently gets the
  15-min default back. Fix: migrate old keys in `_migrate_config_if_needed()`.
- [x] **A6 — Bundle correlation self-pairs when both wifi sources enabled.**
  `_extract_bundle_windows` reads `history["wifi"]` for both `"wifi"` and
  `"wifi_monitor"` (`history_analysis.py:1406-1407`) and stamps
  `"collector": source` → same device appears twice under different
  collectors; `_count_cooccurrences` treats them as cross-collector → a
  phantom "2 devices across 2 collectors" bundle for one physical AP.
- [x] **A7 — `sources: ["bluetooth", …]` silently drops all BLE subjects.**
  Extractor maps source `"bluetooth"` → stamped collector `"ble"`
  (`history_analysis.py:1399`), but the per-source cap filters
  `s["collector"] == source` (`:1322-1323`) → matches nothing → BLE devices
  removed from `windows_by_key`; feature emits zero bundles with no warning.
- [x] **A8 — Asymmetric co-occurrence counts.**
  `_count_cooccurrences` breaks after the first synchronized B-window per
  A-window (`:1518`), so the count is |A-windows with ≥1 synced B-window| —
  order-dependent (1 long session vs 3 short = count 1 or 3). Flips
  `min_cooccurrences` inclusion and edge weight for the same physical pair.
- [x] **A9 — Wi-Fi clients can never participate in bundles.**
  Client records have no `sessions` field (only APs and BLE devices get
  sessions, `wifi_ble_postprocessor.py`), and `_subject_windows` returns []
  for sessionless subjects when `min_sessions > 1` (default 2) → the client
  loop (`:1429-1448`) is dead code; only BLE↔AP bundles possible, contrary to
  the documented BLE+Wi-Fi correlation. The documented first_seen–last_seen
  span fallback is unreachable for sessionless subjects.
- [x] **A10 — Randomized BLE group records pass the identity gate.**
  Group records carry `mac: "randomized:…"`, `grouped_randomized: true`
  (`wifi_ble_postprocessor.py:1064`); `locally_administered_mac` returns
  False for that non-12-hex string → the randomized churn aggregate can
  anchor a bundle. Reuse `identity_policy.stable_bluetooth_mac_record` /
  skip `grouped_randomized`.
- [x] **A11 — Stale bundles stamped "recent".**
  `_bundle_observation` sets evidence `last_seen = timestamp` (generation
  time, `:1658`), so bundles built from co-occurrences older than the
  Insights window render as `activity_state: "recent"` and sort to the top
  of the tactical feed. Should use the max session end of the bundle.
- [x] **A12 — Bundle input filtered by the 60-min Insights window.**
  `recent_history_for_insights` drops subjects with `last_seen` older than
  `insights_recent_minutes` (default 60) → bundles built from multi-hour
  co-movement flicker with refresh timing instead of actual behavior.
- [x] **A13 — `recent_records(include_sessions=True)` shares mutable records.**
  `main.py:2046` appends the original record dict; analyzer input aliases the
  cached Subject History dicts. Latent (analysis is read-only today); any
  future in-place mutation corrupts cached history. Fix: `dict(record)` copy.
- [x] **A14 — Full session arrays now fed to ALL analyzers, not just bundle.**
  `include_sessions` defaults to `bundle_correlation_enabled` (True), so
  non-bundle rules (e.g. `ble_presence_pattern`) iterate full session arrays
  that were deliberately stripped before (`HEAD` main.py compact path). Cost
  regression per 15-min refresh + silently resurrects the previously-dead
  `ble_recurring_presence_pattern` rule. Fix: strip sessions for the
  non-bundle analyzers.
- [ ] **A15 — Flock dedupe key conflates probe/beacon paths.** — accepted
  `"flock-camera:{mac}"` shared by probe (client_mac) and beacon (bssid)
  paths (`alerts.py:605`): one camera with different BSSID vs probing client
  MAC creates two independent active alerts; when MACs coincide each
  observation wholesale-replaces the other's evidence/frame_type.
- [ ] **A16 — Flock probe alerts attribute the prober, not the camera.** — accepted (product decision)
  `probe_request` events carry `client_mac` = the prober and `ssid_probed` =
  the sought SSID; an SSID match alone (any phone re-probing a remembered
  `Flock-*`/`FS_*` SSID) raises "Flock Safety camera seen" attributed to the
  phone's MAC. Default-on (`enabled: true`).
- [ ] **A17 — Blank-SSID + generic-chipset OUI → "High" confidence.** — accepted (product decision)
  `flock_confidence` (`alerts.py:696`) marks blank-SSID probes from any of
  the 31 community OUIs (Espressif, Silicon Labs, Murata, Liteon — the
  code's own comment) as High. Deliberate per VERSION_HISTORY, but routine
  IoT blank probes surface as high-confidence camera warnings; no probe-count
  or stronger signal guard beyond `min_rssi: -85`. Decision needed: keep,
  reword, or gate.
- [x] **A18 — Presence classification vs SKIR prompt mismatch.**
  `int(24*0.90) = 21` → a subject present 21/24h (87.5%) is labeled [C]
  continuous, while the prompt tells the LLM "[C] Continuous (≥90% of
  hours)". Fix: integer-ceiling the 90% threshold (22/24).
- [x] **A19 — Proportional thresholds collapse for small delta windows.**
  For a 2h delta `_continuous_min = 1` → every subject classifies [C]; for a
  3h delta 67% presence is "continuous". SKIRs generated a few hours apart
  report everything as resident.
- [x] **A20 — Delta timeline unbounded (token inflation).**
  No cap on the delta window length: a SKIR > 24h old with 168h retention
  yields ~143-hour mask strings per subject against the documented
  ~158K-token context budget.
- [x] **A21 — Delta section header duplicates "(first → last)".**
  `llm.py:783-787` embeds labels in the title and `_format_presence_timeline`
  appends its own → "## Delta Since Last Report (A → B) (A → B)". Cosmetic.
- [x] **A22 — Snapshot files loaded twice per SKIR build.**
  `build_skir_context` → `_build_presence_timeline()` + `_build_delta_timeline()`
  each call `load_snapshots()` — ~168 file parses ×2 with 168h retention.
  Fix: load once and pass to both formatters.
- [x] **A23 — Default-config incoherence in bundle thresholds.**
  `min_sessions_per_device: 2` vs `min_cooccurrences: 3`: two devices with
  exactly 2 synchronized sessions can never reach 3 (count capped by window
  counts) — the 2-session eligibility advertised by min_sessions is
  impossible under defaults.
- [x] **A24 — `_devices` evidence renders as "[object Object]" in UI.**
  `genericEvidenceItems` (app.js) doesn't exclude `_`-prefixed keys, so the
  `_devices` array shows raw in the evidence text despite the string
  workarounds (`device_list`, `cooccurrence_pairs`).

## B. Efficiency / cleanup (verified, non-blocking)

- [x] **B1 — Flock per-event recomputation.** `matches_flock_camera`,
  `flock_confidence`, `flock_detection_reason` each rebuild the normalized
  OUI set per call; a matching beacon pays ~5 rebuilds + double
  `matches_flock_camera` (pre-check in `wifi_ap_alerts` + inside
  `wifi_flock_alerts`). Fix: precompute in `__init__`, compute one
  `(oui_known, vendor_match, ssid_match)` tuple per event.
- [x] **B2 — Bundle extraction parses all sessions before the cap.**
  `_extract_bundle_windows` parses every session epoch of every subject, then
  the 100-per-source cap discards most. `session_count` already exists on
  records for pre-selection.
- [x] **B3 — `_build_clique_bundles` O(P·S·C) with per-test tuple allocation**
  (up to ~10k cross-source qualifying pairs). Precompute adjacency sets;
  also `key_to_subject` rebuilds a dict the caller already has.
- [x] **B4 — `_count_cooccurrences` unbounded W² window scan** (no per-device
  window cap; sessions span up to 7 days). Sort windows and cap to most
  recent N (or bisect on start).
- [ ] **B5 — Flock OUI list duplicated across 3 places** — accepted
  (`FLOCK_COMMUNITY_OUIS` frozenset, `DEFAULT_ALERT_CONFIG`, config.example;
  b4:1e:52 only in config). Frozenset can't be disabled via config.
- [x] **B6 — llm.py path prologue duplicated 5×**; `paths.RUNTIME_LOG_DIR`
  exists and should be used instead of hand-rolled `os.path.join(PROJECT_ROOT,
  "runtime", "logs", …)` literals (also the A4 configured-dir issue).
- [ ] **B7 — `DEFAULT_ANALYSIS_CONFIG` duplicates `config.py` — accepted
  `DEFAULT_CONFIG["history_analysis"]`** — drift risk between app and
  standalone-HistoryAnalyzer callers.
- [ ] **B8 — main.py has four parallel `ui` accessors** re-declaring defaults — accepted
  already in `DEFAULT_CONFIG`, with three divergent interpretations of
  `derived_refresh_interval_min` (cooldown falls back to
  `derived_stale_after_min` when 0; scheduler treats 0 as disabled; 60s
  clamp). Same for the third copy of the default in app.js `uiConfig`.
- [x] **B9 — Subject-building copy-paste ×3** in `_extract_bundle_windows`
  (BLE device / Wi-Fi AP / Wi-Fi client blocks); cap filter re-scans
  `all_subjects` and rebuilds `windows_by_key` after the fact.

## C. Inherited / pre-existing (diff extends exposure)

- [ ] **C1 — DST fall-back filename collision** (`snapshots.py` `_hour_label`): — accepted (pre-existing)
  two hour epochs map to the same filename and overwrite. Pre-existing, but
  the 168h backfill window now re-exposes the colliding hour for 7 days.
- [ ] **C2 — Backfill 168h startup cost**: first startup can synchronously — accepted
  build up to 168 snapshots, each O(subjects), with no progress — delays
  startup and the first derived refresh. Bounded by design, worth a progress
  log or chunking.
- [x] **C3 — HANDOFF.md "24h hourly snapshots" section stale** (says fixed
  24h retention / "168h only in backfill tool" — now config-driven via
  `ui.snapshot_retention_hours`).
- [x] **C4 — `insights_recent_hours` vs `insights_recent_minutes`**: both
  valid (minutes wins when present); live configs use `_hours`, example/docs
  use `_minutes`. Document the fallback or consolidate.

## D. Verified non-defects (refuted)

- "Unknown-key collapse" (empty MACs merging into one `wifi_client:unknown`
  subject): upstream `setdefault(mac, …)` already merges MAC-less events
  into one record — at most one record per key exists.
- Flock probe dispatch does not shadow pre-existing probe alerting
  (alerts.py had none); config.example ↔ DEFAULT_ALERT_CONFIG flock OUI
  lists are identical (32 entries incl. b4:1e:52).
- `_edge_hours` / `first_idx` / `last_idx` sentinels behave correctly for
  n = 2–3; `edge_weights` has an `if edge_weights else 0` guard.
- No residual old key names in `src/` or `static/`; `derived_refresh_interval_sec`
  clamp semantics consistent with the old seconds-based clamp.
