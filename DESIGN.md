# Skannr Design Document

Version: 0.1.0, 2026-05-19

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
- Degrade visibly when preferred hardware is missing, rather than silently
  falling back.
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
  "timestamp": "2026-05-19 17:00:00",
  "data": {
    "ssid": "example",
    "bssid": "00:11:22:33:44:55"
  }
}
```

The collector and type identify the source and semantic event. Data is
collector-specific but should remain JSON-serializable. Timestamps are local
display time in `YYYY-MM-DD HH:MM:SS`; older UTC `...Z` timestamps remain
readable.

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
- UI row limits, stale-data threshold, and signal bands

Collector YAML files own:

- collector key, label, order, description, and grouping
- enabled/auto-start behavior
- primary/fallback validation commands
- collector-specific interfaces, adapters, scan intervals, and thresholds

`config.load_config()` loads defaults from `config.py`, overlays `skannr.yaml`,
loads collector YAML files, normalizes retention, resolves relative `log_dir`
against the config directory, and runs hardware/software probes for System
Status.

The first run writes `skannr.yaml` only if it does not exist. Existing YAML is
not rewritten on startup, so comments and user formatting are preserved.

## 5. Collector Model

All collectors derive from `BaseCollector`. The base class provides:

- stable collector states
- status snapshots for System Status
- Start/Stop lifecycle hooks
- event emission
- retry sleep helper
- primary/fallback validation command execution

Collector states are:

- `DETECTING`
- `RUNNING_TIER1`
- `RUNNING_TIER2`
- `RETRYING`
- `OFFLINE`
- `STOPPED`

The UI renders `RUNNING_TIER1` as primary and `RUNNING_TIER2` as fallback.

Validation is externalized through YAML:

```yaml
primary_validation: test -d /sys/class/net/{preferred_interface}
fallback_validation: test -d /sys/class/net/{fallback_interface}
validation_timeout_sec: 10
```

The validation string is formatted with collector config keys, run as a shell
command, and treated as passing only on exit code 0. `none` disables that tier.

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
- Prefers `hci1`, falls back to `hci0` by default.
- Uses a shared adapter operation lock so BLE Scan and BLE Identify do not
  collide on the same adapter.
- Tracks seen, updated, and lost devices.
- Can reset/retry after repeated BlueZ `InProgress` errors.

Important events:

- `scanner_started`
- `hardware_fallback`
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

### BLE Identify (`ble_identify`)

Purpose: on-demand active GATT query for selected BLE devices.

Implementation:

- Uses the same adapter validation model as BLE Scan.
- Does not auto-start.
- The browser calls `/ble_identify` with a MAC address.
- Attempts to read selected Device Information Service fields.

Fields read:

- Manufacturer Name (`2A29`)
- Model Number (`2A24`)
- Firmware Revision (`2A26`)
- Hardware Revision (`2A27`)
- Software Revision (`2A28`)

Serial Number (`2A25`) is not read by default.

Important events:

- `identify_started`
- `identify_result`
- `identify_failed`
- `collector_offline`

Device History contribution:

- Identify results enrich the Bluetooth record for the MAC.

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
- Has no fallback by default.
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

- None yet. RTL-SDR appears in Insights/Reports subtabs for consistency, but
  no materialized RTL-SDR device-history summary is implemented.

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

All four use the same selected dashboard view window. Refreshing any derived
tab refreshes the whole bundle in dependency order:

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
- Wi-Fi fallback mode
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

Insights are deterministic analysis over the selected Device History view. They
are generated by `HistoryAnalyzer` and written to:

```text
logs/device_history/history_analysis.json
```

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

The analysis is ranked by severity, score, and timestamp. It does not call an
LLM.

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

## 9. Browser UI

The UI is a single static page served from `static/index.html` with behavior in
`static/app.js`.

Top-level tabs:

- Insights
- Reports
- Device History
- Wi-Fi Scan
- Wi-Fi Monitor
- Bluetooth
- RTL-SDR
- System Status

Insights, Reports, and Device History have collector subtabs built from
collector metadata. Bluetooth collectors are grouped under a single Bluetooth
source group. Wi-Fi Scan and Wi-Fi Monitor remain separate sources because one
is managed scanning and the other is monitor-mode capture.

The header contains:

- application title
- connection badge
- view-window selector

The connection badge reflects the browser event stream. The view-window selector
is populated from `skannr.yaml`, `retention_days`, and optional
`view_window.default_days`.

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
3. Add the class to `COLLECTOR_CLASS_BY_KEY` in `collectors/__init__.py`.
4. If the collector contributes to Device History, extend
   `DeviceHistoryBuilder.COLLECTORS` and add parsing logic.
5. If the collector should appear in Insights or Reports, add rules in
   `history_analysis.py` or `reports.py`.
6. If the collector needs custom live UI, add table/rendering logic in
   `static/index.html` and `static/app.js`.

Collector metadata and subtabs are already driven by YAML, but collector class
registration and domain-specific UI/history logic are still explicit code
changes. This is intentional for now: collector capture behavior and history
semantics differ enough that a fully dynamic plugin UI would add complexity
before the collector set stabilizes.

## 14. Known Limitations

- Device History currently has rich Wi-Fi and Bluetooth support; RTL-SDR and
  System have placeholder history subtabs only.
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
