# Skannr Design Document

Version: 0.1.3, 2026-05-22

## 1. Overview

Skannr is a local wireless and RF monitoring dashboard. It runs on a Linux
host, starts one or more collectors, records normalized events, and presents
live and derived views in a browser.

The current implementation focuses on:

- lightweight Wi-Fi access-point scanning
- on-demand Wi-Fi monitor-mode packet capture and channel hopping
- BLE advertisement scanning
- on-demand BLE Device Information Service reads
- on-demand Bluetooth Classic inquiry
- RTL-SDR spectrum scanning with `rtl_power`
- deterministic Findings, Insights, Device History, and Reports generated from
  retained local logs

Skannr is intentionally small. It uses Flask, a local browser UI, JSONL files,
and materialized JSON summaries. It does not require a database, message
broker, external web assets, or internet access at runtime.

## 2. Goals And Non-Goals

### Goals

- Provide one local dashboard for nearby Wi-Fi, Bluetooth, and RTL-SDR activity.
- Degrade visibly when configured or required hardware is missing, rather than
  silently pretending the collector is healthy.
- Keep collectors independent so Wi-Fi scan, Wi-Fi monitor, Bluetooth, and
  RTL-SDR can fail or stop without taking down the whole dashboard.
- Persist raw events as simple JSONL files that can be inspected or analyzed
  outside Skannr.
- Maintain materialized summaries so normal startup and refresh do not need to
  reread large raw logs repeatedly.
- Generate deterministic Findings, Insights, and Reports without an LLM.
- Support Raspberry Pi and older Linux/Python environments where possible.

### Non-Goals

- Skannr is not an attack, injection, or exploitation framework.
- Skannr is not a multi-user production web service.
- Skannr is not a full IDS replacement.
- Skannr is not a high-rate SDR waterfall or signal visualization package.
- Skannr does not manage monitor-mode setup automatically.
- Skannr does not download vendor/manufacturer registries by itself.

## 3. Runtime Architecture

Skannr is a single Python process with these major components:

- `main.py`: Flask routes, browser event stream, collector lifecycle, derived
  view refresh orchestration, and process startup/shutdown.
- `bus.py`: in-process asynchronous event bus.
- `collectors/`: one Python module and one YAML file per collector.
- `persistence/`: persistence backend interface and filesystem JSONL backend.
- `findings.py`: live deterministic findings engine over collector events.
- `device_history.py`: materialized Wi-Fi and Bluetooth device state.
- `history_analysis.py`: deterministic Insights from Device History.
- `reports.py`: slower longitudinal summaries from Device History.
- `static/`: single-page browser dashboard.
- `skannr.yaml`: global runtime, persistence, UI, and analysis configuration.

Collectors run on an asyncio loop in a background thread. Flask serves the UI
and handles browser requests in the main web server context. Collector events
flow through the event bus to persistence, live browser updates, and the
Findings engine.

### Event Flow

The normal event path is:

1. A collector observes something or changes state.
2. The collector calls `BaseCollector.emit()`.
3. The event is published to `EventBus`.
4. `main.consume_events()` receives the event.
5. The event is written to `logs/<collector>/YYYY-MM-DD.jsonl`, except for
   selected high-rate state events.
6. The event is broadcast to connected browsers.
7. `FindingsEngine.process()` may emit one or more finding events.
8. Finding events are persisted under `logs/findings` and broadcast to browsers.
9. Collector health and system status snapshots are broadcast.

Browser updates use Server-Sent Events from `/events`. Socket.IO remains present
for compatibility, but the dashboard does not depend on a CDN-hosted Socket.IO
client.

### Event Envelope

Collector events use a normalized envelope:

```json
{
  "collector": "wifi",
  "type": "ap_beacon",
  "severity": "info",
  "timestamp_epoch": 1779235200,
  "timestamp": "2026-05-19 17:00:00",
  "data": {
    "ssid": "example",
    "bssid": "00:11:22:33:44:55"
  }
}
```

The collector and type identify the source and semantic event. Data is
collector-specific but should remain JSON-serializable. Epoch seconds are the
canonical internal time source for calculations. Local display timestamps in
`YYYY-MM-DD HH:MM:SS` are derived from epoch values on the Skannr host for the
UI and logs. Browser code uses epoch values for age/delta math but does not
parse or reformat Skannr timestamps in the browser machine's timezone.

## 4. Configuration Model

Global settings live in `skannr.yaml`. Collector-specific settings live in
`collectors/<collector>.yaml`.

The global file owns:

- Flask listen address and port
- persistence backend, log directory, and retention
- runtime queue/status timing knobs
- live Findings thresholds
- history-analysis thresholds
- Reports thresholds
- UI row limits, stale-data threshold, and automatic derived refresh interval

Collector YAML files own:

- collector key, label, order, description, and grouping
- enabled/auto-start behavior
- collector-owned validation commands
- collector-specific interface/adapter candidate lists, scan intervals, and
  thresholds

`config.load_config()` loads defaults from `config.py`, overlays `skannr.yaml`,
loads collector YAML files, normalizes retention, resolves relative `log_dir`
against the config directory, and asks each configured collector for its
hardware/software probes for System Status.

The first run writes `skannr.yaml` only if it does not exist. Existing YAML is
not rewritten on startup, so comments and user formatting are preserved.

## 5. Collector Model

All collectors derive from `BaseCollector`. The base class provides:

- stable collector states
- status snapshots for System Status
- Start/Stop lifecycle hooks
- event emission
- retry sleep helper
- shared shell validation execution for collectors that need it

Collector states are:

- `DETECTING`
- `ONLINE`
- `RETRYING`
- `OFFLINE`
- `STOPPED`

For hardware-oriented status lines, the browser translates collector-owned
probes and detected Linux devices into availability wording such as
`hci0: available`, `hci1: unavailable`, and `active: hci0`. Validation exit
codes and shell-output details are not shown in the normal dashboard status
line.

Device selection is externalized through YAML:

```yaml
interfaces: []
adapters: []
validation_timeout_sec: 10
```

Command validation is also YAML-driven for collectors that need a concrete
probe, for example RTL-SDR:

```yaml
validation: command -v rtl_power >/dev/null 2>&1 && command -v rtl_test >/dev/null 2>&1 && rtl_test -t
```

The validation string is formatted with collector config keys, run as a shell
command, and treated as passing only on exit code 0.

## 6. Built-In Collectors

### Wi-Fi Scan (`wifi`)

Purpose: lightweight managed-mode access-point scanning.

Implementation:

- Uses one scan source per collector run to avoid mixing parser detail.
- Prefers `iw dev <iface> scan`.
- Uses `iwlist <iface> scan` only when `iw` is absent or configured with
  `scan_tool: iwlist`.
- Does not put adapters into monitor mode.
- Does not capture probe requests, deauth frames, or associations.

Important events:

- `interface_mode`
- `scan_started`
- `scan_empty`
- `ap_beacon`
- `collector_retrying`
- `collector_offline`

Device History contribution:

- Wi-Fi AP records keyed by BSSID
- SSID history
- channel/frequency-band history
- encryption history
- signal min/max/latest
- vendor names when OUI files are present

### Wi-Fi Monitor (`wifi_monitor`)

Purpose: on-demand monitor-mode packet capture and channel hopping.

Implementation:

- Requires an interface that is already in monitor mode.
- Uses Scapy sniffing in a thread.
- Uses an asyncio channel hopper to retune with `iw dev <iface> set channel`.
- Supports 2.4 GHz and 5 GHz when the adapter reports those frequencies.
- Starts with configured typical channels.
- Can optionally append channels previously seen in Wi-Fi AP logs.

Important events:

- `monitor_started`
- `monitor_channel_changed`
- `probe_request`
- `ap_beacon`
- `association_seen`
- `disassoc_seen`
- `deauth_seen`
- `collector_retrying`
- `collector_offline`

High-rate `monitor_channel_changed` events are shown live but are not persisted,
because they are channel-hop state rather than device history.

Device History contribution:

- AP beacons fold into the same Wi-Fi AP model as Wi-Fi Scan.
- Probe, association, deauth, and disassociation events fold into Wi-Fi client
  history keyed by client MAC.

### BLE Scan (`ble`)

Purpose: passive Bluetooth Low Energy advertisement scanning.

Implementation:

- Uses `bleak` and BlueZ.
- Uses the ordered `adapters` list when configured; otherwise ranks available
  BlueZ adapters and normally chooses external USB adapters before built-in
  radios.
- Uses a shared adapter operation lock so BLE Scan and BLE Identify do not
  collide on the same adapter.
- Tracks seen, updated, and lost devices.
- The browser renders only recently seen BLE rows as live/identifiable
  candidates. The cutoff is `ui.bluetooth_live_recent_sec`, default `600`.
- Can reset/retry after repeated BlueZ `InProgress` errors.

Important events:

- `scanner_started`
- `device_seen`
- `device_updated`
- `device_lost`
- `collector_retrying`
- `collector_offline`

Device History contribution:

- Bluetooth device records keyed by MAC
- names, manufacturer IDs, service UUIDs, RSSI range
- first/last seen
- seen/update/lost counts
- presence sessions, including active sessions persisted across refreshes

The live Bluetooth table decodes common Bluetooth SIG service UUIDs for display.
The raw UUID values remain in Device History so vendor-specific services are
not lost.

### BLE Identify (`ble_identify`)

Purpose: on-demand active GATT query for selected BLE devices.

Implementation:

- Uses the same adapter validation model as BLE Scan.
- Does not auto-start.
- Does not appear as its own System Status row. The UI treats it as an
  on-demand Bluetooth action and shows adapter availability once through BLE
  Scan/Bluetooth Classic.
- The browser calls `/ble_identify` from Identify buttons on recent BLE Scan
  rows.
- Attempts to read selected Device Information Service fields.

Fields read:

- Manufacturer Name (`2A29`)
- Model Number (`2A24`)
- Serial Number (`2A25`)
- Firmware Revision (`2A26`)
- Hardware Revision (`2A27`)
- Software Revision (`2A28`)
- PnP ID (`2A50`)

Serial Number can be uniquely identifying. It is read only during explicit
on-demand Identify actions and should be treated as sensitive exported data.

Important events:

- `identify_started`
- `identify_result`
- `identify_failed`
- `collector_offline`

Device History contribution:

- Identify results enrich the Bluetooth record for the MAC.
- Identify activity is displayed as an unfiltered activity log under BLE Scan;
  Device History and Reports retain the longer-term Bluetooth history.

### Bluetooth Classic (`bt_classic`)

Purpose: on-demand classic Bluetooth inquiry for discoverable devices that may
not appear in BLE advertisements.

Implementation:

- Uses classic inquiry, preferably `hcitool scan --info`.
- Does not auto-start.
- Runs scan passes at configured intervals while active.

Important events:

- `scanner_started`
- `classic_scan_started`
- `classic_scan_completed`
- `classic_device_seen`
- `classic_device_updated`
- `classic_device_lost`
- `collector_retrying`

Device History contribution:

- Classic results are folded into the same Bluetooth device model.
- Transport is marked as `classic`.
- Vendor/name/class/clock offset fields are retained when available.

### RTL-SDR (`rtlsdr`)

Purpose: passive spectrum scanning over a configured frequency range.

Implementation:

- Validates `rtl_power`, `rtl_test`, and connected device presence.
- Runs `rtl_power` as an asyncio subprocess.
- Builds a baseline noise floor for `baseline_period_sec`.
- Emits signal detections when bins exceed the baseline by `threshold_db`.

Important events:

- `scanner_started`
- `baseline_ready`
- `signal_detected`
- `signal_lost`
- `scanner_stopped`
- `collector_offline`

Device History contribution:

- None yet. RTL-SDR appears in Insights/Reports source filters for consistency,
  but no materialized RTL-SDR device-history summary is implemented.

## 7. Persistence

The current durable backend is filesystem JSONL.

Raw events are written to:

```text
logs/<collector>/YYYY-MM-DD.jsonl
```

Application logs are written to:

```text
logs/skannr.log
```

The filesystem backend rotates JSONL files on startup according to:

```yaml
persistence:
  filesystem:
    retention_days: 30
```

`retention_days` must be zero or greater:

- `0` deletes retained JSONL logs during startup rotation.
- positive values keep that many days.
- a very large value effectively disables cleanup.

Raw logs are deliberately kept as the base audit trail. Derived summaries use
checkpoints to avoid rereading old raw logs during normal refresh.

## 8. Derived Data

Skannr has four derived data products:

- Findings
- Device History
- Insights
- Reports

The three dashboard-facing derived views have distinct responsibilities:

- Insights: recent event log, tactical/debuggable.
- Reports: ranked intelligence summary, strategic/operator-facing.
- Device History: state database view.

All four products use the same selected dashboard view window as their maximum
raw-log scope. Insights then apply an additional recent-event lookback,
`history_analysis.insights_recent_hours`, because the tab is meant to answer
"what changed recently?" rather than reproduce the full longitudinal report.
Set the value to `0` to disable the additional Insights cutoff.

The browser automatically refreshes the derived bundle while the page is open.
The interval is controlled by `ui.derived_auto_refresh_min` and defaults to 15
minutes; `0` disables the automatic refresh. Status strips show the last
refresh time and the next automatic refresh countdown. If the browser notices
that the derived bundle is already stale, it starts an immediate catch-up
refresh instead of waiting for the next scheduled interval. Refresh failures
remain visible until a later refresh succeeds. Browser wake/focus events reload
the derived views from the backend so a sleeping client can catch up to Pis
that continued collecting.
When live Wi-Fi/Bluetooth rows arrive, or collector status shows scan events
have already happened while Device History is still empty, the browser treats
that as evidence that raw scan data exists and starts a throttled catch-up
refresh. This covers the fresh-log case where the first page load sees empty
cached derived summaries before scans have been materialized.
Successful derived refreshes also rehydrate the live Wi-Fi Scan and BLE Scan
tables from Device History so missed browser events do not leave the scan tabs
showing stale rows when newer materialized data exists. The BLE Scan table is
also periodically repainted so its recent-device filter can age rows out even
when no new BLE event arrives after a sleeping browser wakes. Device History
records carry numeric epoch fields next to display timestamps, and the browser
uses those epochs for live/recent filtering when available. Display timestamps
remain the Skannr-host strings from the event or derived summary.

Manual or automatic refresh of any derived tab refreshes the whole bundle in
dependency order:

1. Findings History
2. Device History
3. History-based Insights
4. Reports

### Findings

Findings are live deterministic observations produced by `FindingsEngine` from
incoming events. The engine keeps small in-memory maps for recent Wi-Fi APs,
Wi-Fi clients, Bluetooth devices, RTL-SDR signals, and collector health. It
emits normalized finding records for explicit conditions such as:

- new or returned Wi-Fi AP/client
- blank Wi-Fi probe
- randomized/local Wi-Fi MAC
- strong nearby Wi-Fi client or AP
- probe burst
- BLE device seen/returned/lost
- strong BLE signal
- BLE identify success/failure
- RTL-SDR signal detection
- collector offline/retrying/stopped

Findings are written back as events under `logs/findings`.

`findings_history.json` is the materialized view used by the dashboard. It is
updated incrementally from new finding log bytes.

### Device History

Device History is the materialized per-device state used by the History tab,
Insights, and Reports.

System events are intentionally excluded from Device History because they are
runtime state, not per-device history. They remain eligible for Insights and
Reports when they are actionable.

Current Wi-Fi AP history tracks:

- SSID and SSID history
- BSSID
- vendor OUI, prefix, and name
- first seen / last seen
- channel / frequency history
- encryption history
- latest/min/max signal
- observation count
- finding count
- source collectors

Current Wi-Fi client history tracks:

- client MAC
- vendor OUI, prefix, and name
- probed SSIDs
- first seen / last seen
- latest/min/max signal
- probe count
- blank probe count
- association count
- deauth count
- disassociation count
- finding count
- source collectors

Current Bluetooth history tracks:

- MAC
- transports (`ble`, `classic`)
- names
- manufacturer/company fields
- model/firmware/hardware/software fields from BLE Identify
- service UUIDs
- first seen / last seen
- latest/min/max RSSI
- BLE seen/update/lost counts
- classic seen/update/lost counts
- presence sessions, including active sessions
- finding count

The first full build reads retained logs once and writes:

```text
logs/device_history/device_history.json
```

After that, refresh uses JSONL byte-offset checkpoints and reads only newly
appended log bytes. Older raw logs remain available for manual inspection, but
are not the normal runtime query path.

### Insights

Insights are the recent event feed. They combine live Findings with
short-horizon Device History observations so an operator can debug recent
changes and see the lower-level events that may later roll up into Reports.
They are intentionally event-oriented: one row describes one finding or
observation, sorted by event/activity time descending. Device-centric
consolidation and long-term pattern interpretation belong in Reports.

History observations are generated by `HistoryAnalyzer` and written to:

```text
logs/device_history/history_analysis.json
```

The persisted analysis file can cover the selected View window, but the
browser-facing Insights payload is filtered by
`history_analysis.insights_recent_hours`. For Findings, the event timestamp is
the cutoff field. For history observations, `last_seen_epoch` is preferred over
the row timestamp because observations are regenerated on refresh; this prevents
old device behavior from becoming "recent" merely because analysis was rebuilt.

Current rule families include:

- weak or open Wi-Fi encryption
- BSSID encryption changes
- BSSID advertised multiple SSIDs
- BSSID seen on multiple channels
- new strong Wi-Fi AP
- short-lived strong Wi-Fi AP
- same SSID seen on multiple BSSIDs
- many probed SSIDs
- watched/sensitive SSID probes
- repeated blank probes
- repeated deauth activity
- strong Bluetooth device
- lingering Bluetooth device
- repeated Bluetooth lost/return behavior
- recurring Bluetooth presence
- locally administered/randomized MAC population

The analysis does not call an LLM.

### Reports

Reports are slower longitudinal summaries over the selected view window. They
are generated by `ReportsBuilder` and written to:

```text
logs/device_history/reports.json
```

Current report families include:

- recurring Bluetooth presence by day/hour
- long Bluetooth presence
- strong Bluetooth signal in the report window
- recently new named/static Bluetooth device
- grouped unnamed BLE randomized/private addresses by manufacturer
- recently new Wi-Fi AP
- strong Wi-Fi AP in the report window
- Wi-Fi AP encryption variation
- Wi-Fi AP channel variation
- SSID with multiple BSSIDs
- Wi-Fi client probe activity
- Wi-Fi deauth/disassociation activity
- new Wi-Fi Monitor client activity

Bluetooth sessions are clipped to the selected report window so a last-24-hours
report does not count hours before the window boundary.

The Reports UI provides a Type filter over broad report families: security,
presence, signal, new-device, behavior, identity, collector, and analysis. The
small summary line above the table is derived from the currently visible rows,
so it changes with source filtering, type filtering, and search text.
Report evidence remains structured in JSON, but the browser renders it as
source-aware operator text. Related details are folded together to keep rows
readable: session state is part of `Observed`, Wi-Fi security is part of
`Radio`, and strong-signal findings include their signal value on the
`Findings` line. Bluetooth reports show pattern, observed, and signal context;
Wi-Fi AP reports show network, radio/security, and observed context; Wi-Fi
Monitor client reports show client, probe, and activity context. This keeps the
table readable without discarding the raw evidence fields. In the table, the
Evidence cell is rendered as compact stacked label/value lines rather than a
pipe-delimited log string.
Bluetooth report generation is device-centric on the server side. Stable BLE
MACs produce one device-profile row with a Subject, merged findings, summary,
and behavioral evidence. Unnamed/private BLE address churn remains grouped as a
manufacturer-level private-address cluster. The UI should render those server
decisions rather than re-derive intelligence from raw evidence fields.
Wi-Fi report generation uses the same server-side consolidation. AP-level
findings such as new AP, strong signal, channel variation, and security
variation are merged into one access-point profile per BSSID. SSID-level
behavior, such as multiple BSSIDs or locally administered/randomized BSSID
groups, is emitted as an SSID profile. The Subject column owns identity; Evidence
describes radio/security, observation pattern/session state, signal, vendors,
and BSSID lists as applicable.

#### Report Scoring

Reports use a server-side `score` from 0 to 100. The score is an operator
attention rank, not a probability of malicious activity. Rows are sorted by
severity, then score, then last-seen time. A high score means the profile is more
important to review because several signals line up: long presence, repeated
presence, current activity, strong nearby signal, new appearance, weak security,
or unusually broad address/BSSID behavior.

Bluetooth stable-device scoring:

- Longest session: `+25` for at least 1 hour, `+40` for at least 4 hours, `+50`
  for at least 8 hours.
- Days seen: `+15` for the configured recurring threshold, `+25` for 3-4 days,
  `+35` for 5 or more days.
- Predictable timing: `+10` for recurring start-hour pattern and `+10` for
  recurring active-hour pattern.
- Current activity: `+15` when the device is still active.
- Proximity: `+10` for RSSI at least `-70`, `+20` for at least `-55`, `+30` for
  at least `-45`.
- New named/static device: `+30`.

Bluetooth private-address cluster scoring:

- Address count: `+15` for at least 10 addresses, `+25` for at least 50,
  `+35` for at least 100.
- Current activity: `+10` if any private address in the cluster is still active.
- Proximity: `+20` for RSSI at least `-55`, `+30` for at least `-45`.
- Cluster score is capped at 95 because identity is weaker than a stable named
  device.

Wi-Fi AP/BSSID scoring:

- New AP: `+25`.
- Proximity: `+10` for RSSI at least `-70`, `+20` for at least `-55`, `+35` for
  at least `-40`, `+45` for at least `-25`.
- Security: `+50` for open/WEP/WPA, `+35` for meaningful encryption variation,
  `+20` for lower-value security-detail variation.
- Radio drift: `+15` when one BSSID appears on multiple channels.
- Current activity: `+10` when still active.
- Persistence: `+15` for at least 4 hours, `+25` for at least 8 hours.

Wi-Fi SSID scoring:

- BSSID count: `+10` for 2 BSSIDs, `+20` for 3-5, `+30` for 6 or more.
- Vendor diversity: `+25` when one SSID spans multiple vendors.
- Locally administered/randomized BSSIDs: `+15`.
- Security diversity: `+35` for mixed weak/open and secured security, `+20` for
  other mixed security values.
- Channel/band spread: `+10` for multiple channels, `+15` for both 2.4 GHz and
  5 GHz.
- Strong member: `+15` for any member at least `-55`, `+25` for any member at
  least `-40`.

Scores at or above 75 become warning-level profile rows unless a more specific
security rule already set severity. This is intentionally a high-attention
threshold, not a claim that the device or network is hostile.

## 9. Browser UI

The UI is a single static page served from `static/index.html`. Most dashboard
behavior lives in `static/app.js`; reusable table schemas/rendering live in
`static/tables.js`.

Top-level tabs:

- Insights
- Reports
- Device History
- Wi-Fi Scan
- Wi-Fi Monitor
- Bluetooth
- RTL-SDR
- System Status

Insights, Reports, and Device History have Source filter chips built from
collector metadata. They are filters over one dataset, not navigation tabs.
Bluetooth collectors are grouped under a single Bluetooth source group. Wi-Fi
Scan and Wi-Fi Monitor remain separate sources because one is managed scanning
and the other is monitor-mode capture.
Live Wi-Fi Scan and BLE Scan tables use one row-search box each instead of
separate per-column selector controls.
Device History omits System from its Source filter; System is not a device
source.

The header contains:

- application title
- connection badge
- view-window selector

The connection badge reflects the browser event stream. The view-window selector
is populated from `skannr.yaml`, `retention_days`, and optional
`view_window.default_days`. System Status uses concise availability wording for
hardware and keeps software checks in a separate column.

The dashboard uses local assets only. No CDN is required.

## 10. Manufacturer And Vendor Data

Skannr can resolve manufacturer names without internet access when local
registry files are present.

Wi-Fi vendor lookup:

- `collectors/oui.txt`: `https://standards-oui.ieee.org/oui/oui.txt`
- `collectors/mam.txt`: `https://standards-oui.ieee.org/oui28/mam.txt`
- `collectors/oui36.txt`: `https://standards-oui.ieee.org/oui36/oui36.txt`
- `collectors/iab.txt`: `https://standards-oui.ieee.org/iab/iab.txt`

The lookup uses longest-prefix matching. Locally administered MACs are shown as
locally administered/randomized when applicable.

Bluetooth company lookup:

- `collectors/company_identifiers.txt`: `https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers/`

When lookup files are missing or do not contain a prefix/identifier, Skannr
shows the raw OUI or company ID.

Skannr does not update these files automatically.

## 11. Deployment

The normal local run path is:

```bash
SKANNR_DIR=/path/to/skannr
cd "$SKANNR_DIR"
./install.sh
sudo "$SKANNR_DIR/.venv/bin/python" main.py
```

`install.sh` chooses a requirements file based on Python version:

- Python 3.6: `requirements-py36.txt`
- Python 3.7: `requirements-py37.txt`
- Python 3.8 and newer: `requirements-py38plus.txt`

System packages such as `rtl-sdr`, `aircrack-ng`, `bluetooth`, and `bluez` must
be installed separately.

For automatic startup, Skannr can run under systemd. Running as root is the
simplest setup because Wi-Fi monitor mode, packet capture, Bluetooth adapters,
and RTL-SDR devices often need elevated privileges or device permissions.

Remote access is controlled by `skannr.host`:

- `127.0.0.1`: local-only IPv4
- `0.0.0.0`: all IPv4 interfaces
- `::`: all IPv6 interfaces
- a specific IPv4 or IPv6 address: bind only there

IPv6 literal browser URLs require brackets:

```text
http://[200:...:abcd]:5000/
```

Skannr serves plain HTTP. HTTPS, authentication, and reverse proxy integration
are outside the current implementation.

## 12. Security And Privacy Model

Skannr is designed for local operator use. It assumes the operator controls
the host and is monitoring their own environment.

Security properties:

- no remote authentication layer
- no TLS in the built-in Flask server
- local files only
- no cloud dependency
- no automatic vendor registry downloads
- no active Wi-Fi operations
- BLE Identify is explicit and on demand
- Bluetooth Classic inquiry is explicit and on demand

If Skannr is exposed beyond localhost, the operator should use a trusted
network, VPN, SSH tunnel, or reverse proxy with appropriate access control.

## 13. Adding A Collector

Adding a collector currently requires:

1. Add `collectors/<key>.yaml` with key, label, order, validation commands, and
   collector-specific settings.
2. Add `collectors/<key>.py` implementing a `BaseCollector` subclass.
3. Implement `hardware_status()` on the subclass if System Status needs static
   hardware or software probes.
4. Add the class to `COLLECTOR_CLASS_BY_KEY` in `collectors/__init__.py`.
5. If the collector contributes to Device History, extend
   `DeviceHistoryBuilder.COLLECTORS` and add parsing logic.
6. If the collector should appear in Insights or Reports, add rules in
   `history_analysis.py` or `reports.py`.
7. If the collector needs custom live UI, add markup in `static/index.html`,
   table schema in `static/tables.js`, and behavior in `static/app.js`.

Collector metadata and derived-view source filters are already driven by YAML,
but collector class registration and domain-specific UI/history logic are still
explicit code changes. This is intentional for now: collector capture behavior
and history semantics differ enough that a fully dynamic plugin UI would add
complexity before the collector set stabilizes.

## 14. Known Limitations

- Device History currently has rich Wi-Fi and Bluetooth support; RTL-SDR has a
  placeholder history source only, and System is omitted because it is not a
  device source.
- Reports are deterministic summaries, not forensic conclusions.
- Wi-Fi Monitor only hears frames on the channel currently selected by the
  channel hopper.
- Managed Wi-Fi Scan cannot see probe requests or deauth frames.
- BLE visibility depends heavily on BlueZ behavior, adapter state, device
  privacy behavior, and whether devices advertise names.
- BLE Identify requires an active connection and many devices reject or time out
  such reads.
- Classic Bluetooth only sees discoverable classic devices.
- The built-in web server is for local/lightweight use, not hardened production
  hosting.

## 15. Current File Layout

```text
<skannr-dir>
  main.py
  config.py
  bus.py
  findings.py
  device_history.py
  history_analysis.py
  reports.py
  log_utils.py
  oui_lookup.py
  skannr.yaml
  install.sh
  requirements*.txt
  collectors/
    base.py
    hardware.py
    metadata.py
    wifi.py
    wifi.yaml
    wifi_monitor.py
    wifi_monitor.yaml
    ble.py
    ble.yaml
    ble_identify.py
    ble_identify.yaml
    bt_classic.py
    bt_classic.yaml
    rtlsdr.py
    rtlsdr.yaml
    company_identifiers.txt
    oui.txt
    mam.txt
    oui36.txt
    iab.txt
  persistence/
    base.py
    filesystem.py
    none.py
  static/
    index.html
    tables.js
    app.js
    style.css
  logs/
    <collector>/YYYY-MM-DD.jsonl
    device_history/device_history.json
    device_history/findings_history.json
    device_history/history_analysis.json
    device_history/reports.json
    skannr.log
```

## 16. Design Decisions

- Use filesystem JSONL instead of SQLite to keep deployment simple and make raw
  logs easy to inspect.
- Materialize Device History, Findings History, Insights, and Reports so refresh
  does not repeatedly scan all raw logs.
- Keep Wi-Fi Scan and Wi-Fi Monitor separate because monitor-mode channel
  hopping has different hardware, CPU, and connectivity implications.
- Group BLE Scan, BLE Identify, and Bluetooth Classic under one Bluetooth UI
  because they describe the same nearby-device domain.
- Keep BLE Identify active and explicit because it connects to devices.
- Treat collector validation as YAML-configurable shell probes so deployments
  can adapt to different interface names and hardware layouts.
- Avoid external web/CDN dependencies so Skannr remains usable on isolated Pi
  and field machines.
- Keep analysis deterministic and explainable instead of using an LLM inside
  Skannr.
