# Version Plan

This is a local planning list for upcoming Skannr releases. Move completed
items into `VERSION_HISTORY.md` and `CHANGELOG.md` when the version is released.

## post-0.2.2

- Improve Wi-Fi Monitor channel-hopping controls. Support 2.4 GHz only, 5 GHz
  only, both bands, dwell time, fixed-channel mode, scan-discovered channels
  first, and common-channel fallback.
- Add on-demand Wi-Fi Monitor PCAP capture/export with duration limits and an
  explicit output path. Keep it off by default so Skannr does not become a
  high-volume packet recorder unless the operator asks for it.
- Close the remaining high-value Reports gaps without adding a rule engine:
  vendor/security/channel drift that is not already clear in Reports, new or
  strong nearby devices that are currently only visible in Insights, and stale
  collector coverage that affects report confidence.
- Keep Insights as the tactical interpretation layer for live/recent scans.
  New monitoring capabilities should produce quick, explainable Insights for
  what just happened, while persistent or higher-confidence patterns roll up
  into Reports as the final intelligence overview.
- Tighten Reports evidence only where it improves operator reading: consistent
  subject identity, first/last seen, session or seen count, signal range, and
  compact reason tags for the rows that still look sparse or inconsistent.
  Avoid broad evidence-schema work unless a visible report row needs it.
- Add RTL-SDR protocol decoder integration where useful, starting with tools
  such as `rtl_433` or APRS workflows. The goal is recognizable RF events, not
  only generic spectrum energy.

## 0.3.x

- Add small JSON export/API endpoints for current Reports, Device History,
  collector status, and raw-event search.
- Redesign materialized derived views around a database-style state store,
  likely SQLite, while keeping raw JSONL logs as the append-only audit trail.
  Device History should become durable indexed state rather than one large JSON
  document that must be parsed, copied, filtered, and rewritten.
- Make derived refresh incremental by default: read only new raw-log bytes from
  checkpoints, update affected device/network records, mark dirty identities,
  and regenerate Insights/Reports only for those changed identities.
- Make `/derived_views` a read/query path over already-materialized state.
  `POST /derived_views/refresh` should update materialized state; ordinary GETs
  should only query the selected time window.
- Add indexed materialized tables for Wi-Fi APs, SSID profiles, Wi-Fi clients,
  Bluetooth stable devices, randomized BLE clusters, observations, reports, and
  refresh/checkpoint metadata. Index common filters such as source, MAC, BSSID,
  SSID, last_seen_epoch, score, and severity.
- Preserve raw-log rebuild capability so SQLite/materialized state can be
  recreated from retained JSONL logs after corruption, schema changes, or manual
  reset.
- Add optional local LLaMA/GGUF-assisted report interpretation. Keep it
  operator-triggered, offline, and optional so Skannr still works without ML
  dependencies or a model installed.
