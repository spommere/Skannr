# Skannr Design Document

Version: 0.3.4, 2026-06-27

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
- optional RTL-433 decoded ISM-band context through `rtl_433`
- optional ADS-B aircraft context through `dump1090`/`readsb`
- optional APRS-IS internet-fed local-area situational context
- optional NOAA/NWS/NHC/tsunami.gov internet-fed hazard context
- optional USGS internet-fed earthquake context
- optional NOAA SWPC internet-fed space-weather context
- optional Ambient Weather personal weather station context
- optional passive LAN neighbor/default-gateway context
- deterministic Findings, Insights, Subject History, Alerts, and Reports
  generated from retained local logs

Skannr is intentionally small. It uses Flask, a local browser UI, JSONL files,
and materialized JSON summaries. It does not require a database, message
broker, or external web assets. Internet access is only needed for collectors
that explicitly depend on it, such as APRS-IS, NOAA, USGS, SWPC, and PWS.

## 2. Goals And Non-Goals

### Goals

- Provide one local dashboard for nearby Wi-Fi, Bluetooth, RTL-433 decoded
  devices, ADS-B aircraft context, optional internet-fed situational context,
  and local LAN state.
- Degrade visibly when configured or required hardware is missing, rather than
  silently pretending the collector is healthy.
- Keep collectors independent so Wi-Fi scan, Wi-Fi monitor, Bluetooth,
  RTL-433, ADS-B, and internet-fed collectors can fail or stop without
  taking down the whole dashboard.
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
- Skannr does not silently choose and convert a managed Wi-Fi adapter into monitor mode; monitor-mode preparation requires explicit collector configuration.
- Skannr does not download vendor/manufacturer registries by itself.

## 3. Runtime Architecture

Skannr is a single Python process with these major components:

- `src/skannr/main.py`: Flask routes, browser event stream, collector lifecycle, derived
  view refresh orchestration, and process startup/shutdown.
- `src/skannr/bus.py`: in-process asynchronous event bus.
- `src/skannr/collectors/`: collector Python modules and hardware probes.
- `scripts/skannr_precheck.py` and `scripts/skannr_postcheck.py`: install-time
  and post-install collector support checks that seed fresh collector enabled
  flags and report missing required/recommended/optional local tools and
  selected hardware probes.
- `src/skannr/persistence/`: persistence backend interface and filesystem JSONL backend.
- `src/skannr/findings.py`: live deterministic findings engine over collector events.
- `src/skannr/alerts.py`: live alert engine for operator-attention events.
- `src/skannr/notifications.py`: optional external alert delivery such as
  Pushover.
- `src/skannr/connectivity.py`: shared generic internet connectivity checks.
- `src/skannr/device_history.py`: internal Wi-Fi/Bluetooth compatibility view
  used by older browser drilldown and live-table code.
- `src/skannr/subject_history.py`: collector-neutral subject rollups for
  Wi-Fi, Bluetooth, APRS-IS, Rayhunter, RTL-433, ADS-B, NOAA, USGS,
  SWPC, PWS, and LAN.
- `src/skannr/history_analysis.py`: deterministic Insights from the subject
  device view.
- `src/skannr/reports.py`: slower longitudinal summaries from Subject History.
- `src/skannr/static/`: single-page browser dashboard.
- `config.example/`: generic source-controlled configuration template.
- `~/.config/skannr/skannr.yaml`: local runtime, persistence, UI, and analysis configuration.
- `~/.config/skannr/collectors/*.yaml`: local collector-specific operator configuration.
- `runtime/logs/`: raw JSONL logs and materialized derived-view state.

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
5. The event is written to `runtime/logs/<collector>/YYYY-MM-DD.jsonl`, except for
   selected high-rate state events.
6. The event is broadcast to connected browsers.
7. `AlertEngine.process()` may emit alert events. Alert events are persisted
   under `runtime/logs/alerts` and broadcast to browsers. Active alerts are kept
   in memory and appear globally until ACKed or expired.
8. If Pushover is enabled, newly emitted or escalated alert events are submitted
   to a background notification worker. Duplicate/update alert traffic is not
   pushed. Delivery is best-effort and guarded by the generic internet
   connectivity check, so unavailable internet or Pushover API failures are
   logged without blocking collector fan-out.
9. `FindingsEngine.process()` may emit one or more finding events.
10. Finding events are broadcast to browsers and may be retained under
    `runtime/logs/findings` as live/debug evidence. Retained finding logs are
    not a derived-data dependency.
11. Collector health and system status snapshots are broadcast.

Browser updates use Server-Sent Events from `/events`. Socket.IO remains present
for compatibility, but the dashboard does not depend on a CDN-hosted Socket.IO
client.

### Derived Data Flow

Skannr keeps one raw event stream per collector and derives everything else from
that retained material. The important dependency graph is:

```text
collector event
  -> runtime/logs/<collector>/YYYY-MM-DD.jsonl
  -> runtime/logs/alerts/YYYY-MM-DD.jsonl       live AlertEngine output
  -> runtime/logs/findings/YYYY-MM-DD.jsonl     live/debug FindingsEngine output

raw collector JSONL
  -> runtime/logs/device_history/subject_history.json
     collector-neutral Subject History:
       Wi-Fi SSID/BSSID, Bluetooth MAC/name, APRS callsign/object,
       Rayhunter endpoint, RTL-433 decoded device, NOAA alert/advisory,
       USGS earthquake, SWPC space-weather event, PWS station, LAN device/gateway

Subject History
  -> Insights                                   short-lived tactical findings
  -> Reports                                    ranked intelligence summary
```

The `device_history` directory name is historical. `subject_history.json` is the
single materialized history model. Per-collector direct state files and
analysis artifacts also live in this directory.

Subject History is the main materialized layer. Reports and longer-window
analysis should read Subject History instead of rescanning raw collector logs.
The Wi-Fi/Bluetooth compatibility view exists only so older Wi-Fi/Bluetooth UI
code can keep using its existing table model while APRS-IS, Rayhunter,
RTL-433, ADS-B, NOAA, USGS, SWPC, PWS, and LAN share the same
subject-oriented contract.

Direct collectors expose their durable Subject History event types on the
collector class through `subject_history_event_types` and, for event families,
`subject_history_event_prefixes`. Subject History consumes that collector-owned
contract instead of carrying a second per-collector allowlist, so adding a new
feed event and adding it to history stay in the same ownership boundary.

Live BLE Findings are intentionally identity-gated. Anonymous or
manufacturer-only randomized BLE addresses remain visible in the BLE feed and
Subject History, but they do not create per-MAC `new`, `returned`,
`disappeared`, RSSI-change, or strong-device Insights by default. History
analysis summarizes that churn as a population row instead, so Insights remain
operator-readable while the raw subject detail is still retained.

Alerts are different from Reports. They are live operator-attention state:
drone/Remote ID sightings, APRS/PWS severe weather, Rayhunter warnings, Wi-Fi
disruption bursts, sensitive open SSIDs, tracker-like BLE devices, NOAA/USGS
hazards, SWPC high-impact space-weather events, and LAN gateway changes.
Alerts are emitted and persisted as events, but the active ACK/open state is
held in memory and reconstructed from current runtime events, not used as a
Reports dependency.

Cleanup follows those dependencies:

- Removing raw collector logs limits future rebuilds from scratch but does not
  automatically delete already-materialized Subject History, Insights, or
  Reports.
- Removing Subject History forces the Wi-Fi/Bluetooth compatibility view,
  Insights, and Reports to rebuild from retained raw collector logs on the next
  forced refresh.
- Removing raw logs or materialized Subject History does not remove user subject
  annotations. Those live in `runtime/logs/device_history/subject_annotations.json`
  and must be deleted explicitly when an operator wants a completely clean start.
- Removing Reports has no upstream effect; Reports rebuild from Subject History.
- Removing retained `runtime/logs/findings` JSONL has no upstream effect on
  current derived Insights or Reports because those derive from Subject History.

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

Generic defaults live in `config.example/`. Local runtime settings live in
`~/.config/skannr/skannr.yaml`, and local collector-specific settings live in
`~/.config/skannr/collectors/<collector>.yaml`.

The global file owns:

- Flask listen address and port
- persistence backend, log directory, and retention
- runtime queue/status timing knobs
- live Findings thresholds
- live AlertEngine rules and thresholds
- optional alert notification delivery, currently Pushover
- history-analysis thresholds
- Reports thresholds
- UI row limits, poll-feed live TTL, stale-data threshold, and automatic
  derived refresh interval
- optional dashboard View-window default

Collector YAML files own:

- collector key, label, order, description, and grouping
- collector acquisition mode: `scan`, `poll`, or `listen`
- whether a collector contributes to Subject History
- enabled/auto-start behavior
- collector-owned validation commands
- collector-specific interface/adapter candidate lists, scan intervals, and
  thresholds
- internet-feed endpoints, local coordinates/radii, product toggles,
  feed thresholds, retry timing, passive LAN source settings, and optional
  active LAN inventory settings where applicable

`config.load_config()` loads defaults from `src/skannr/config.py`, overlays
`~/.config/skannr/skannr.yaml`, loads collector YAML files, normalizes retention, resolves
relative `log_dir` against the project root, and asks each configured collector
for its hardware/software probes for System Status.

Collector availability has three levels. `scripts/skannr_precheck.py` is a
standalone standard-library script that can run before install, writes
`~/.config/skannr/precheck.yaml`, and can apply enabled flags plus Wi-Fi interface
suggestions to a freshly copied `~/.config/skannr/collectors/` tree. `install.sh` uses
that file when it creates a new local config: collectors with required local
tools are enabled, collectors with missing required tools stay disabled, and
config-required internet/API collectors stay disabled until the operator edits
their YAML. For Wi-Fi, the fresh-config seed writes the first non-monitor
wireless interface to `wifi.interfaces` and the first already-monitor-mode
interface to `wifi_monitor.interfaces` when those probes are available.
SDR-backed collectors also require visible RTL-SDR hardware during this
fresh-config seeding step, so installing `rtl_433` alone does not auto-enable
RTL-433 on a Pi with no dongle. Optional or recommended tools, such as LAN `arp`,
`arp-scan`, and `avahi-browse`, are reported without disabling the base
collector.

After Python dependencies are installed, `install.sh` runs
`scripts/skannr_postcheck.py` from the virtual environment. The postcheck reuses
the precheck inventory, writes `~/.config/skannr/postcheck.yaml`, and also verifies Python
modules such as `bleak` and `scapy`. On a fresh config, `install.sh` applies the
postcheck result as the final enabled/disabled decision, so the final seed
reflects required software, selected hardware probes, and Python dependencies.
Existing configs are not rewritten by these checks. Runtime availability remains
collector-owned: each collector exposes `hardware_status()` for System Status
and `detect()` for actual startup. This keeps install output helpful without
turning disabled optional collectors into installation failures.

`install.sh` copies `config.example/` to `config/` when `~/.config/skannr/skannr.yaml` is
missing. Existing YAML is not rewritten on startup, so comments and user
formatting are preserved.

The operator-facing YAML key reference lives in `README.md`. DESIGN keeps the
architecture contract: `config.example/` is the source-controlled template,
`config/` is machine-local, and changing YAML requires a Skannr restart.

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

### Acquisition Modes

Collector metadata includes one broad acquisition mode. The mode is not a
transport implementation; it is a UI/history contract for how repeated
observations should behave.

- `scan`: Skannr asks local hardware or the local OS for current observations.
  Wi-Fi Scan, BLE Scan, Bluetooth Classic, PWS, and LAN are scan
  collectors. Live rows should represent current/recent subjects, not every
  individual scan sample.
- `poll`: Skannr periodically fetches current or recent records from an
  endpoint. Rayhunter, NOAA, USGS, and SWPC are poll collectors. Poll feeds
  must de-duplicate by source event/subject identity because the same old
  advisory, earthquake, or space-weather product can appear in every poll.
- `listen`: Skannr opens a stream, sniffer, or local decoder feed and waits for
  events. APRS-IS, Wi-Fi Monitor, RTL-433, and ADS-B are listen collectors.
  Individual packets/frames/decoded device rows/aircraft state changes remain
  raw evidence, while Subject History rolls them up by station/device/network,
  decoded device subject, or aircraft ICAO.

The browser uses this metadata for future-facing behavior, but the durable
contract is subject-focused. Subject History participation is code-owned
metadata, not an operator YAML knob: normal collectors contribute subjects by
default, while status-only sources such as System are explicit code exceptions.
Subject-producing collectors should roll raw observations into stable subjects,
and later Insights/Reports should read those subjects instead of reinterpreting
raw logs independently.

### Subject Identity Contract

Durable collectors should define these fields consistently:

- `subject_id`: stable identity for the observed object or feed item in
  Subject History.
- `event_id`: upstream event/message/product identity where the source provides
  one.
- `fingerprint`: hash or compact value for material content changes. It should
  include event time when the event identity alone is not enough to distinguish
  two real events.
- `event_time`: when the source says the event happened.
- `updated`: when the source says the event/message changed.
- `first_seen` / `last_seen`: when Skannr observed the subject.

For scan and listen collectors, the subject is normally a physical or logical
nearby object: SSID/BSSID, MAC, callsign, frequency bin, or LAN host/gateway.
PWS is also scan-style: Ambient Weather returns current station state, and
Skannr rolls samples up by station ID/name/MAC.
For poll collectors, the subject is the source event/message/product. Poll
collectors must be careful not to treat every poll response as a new subject.
Live feed rows should upsert by the same key used by Subject History, and
Alerts should use the same key unless a rule intentionally narrows the alert
identity further. ACK state should not span different subjects/events.

For hardware-oriented status lines, the browser translates collector-owned
probes and detected Linux devices into availability wording such as
`hci0: available`, `hci1: unavailable`, and `active: hci0`. Validation exit
codes and shell-output details are not shown in the normal dashboard status
line. For non-device collectors, Hardware should describe the source class, for
example internet feed, Rayhunter endpoint, or local OS neighbor/default-route
state; command names such as `ip neigh` belong in Software/status details or
logs.

Device selection is externalized through YAML. Empty lists mean runtime chooses
from the devices Linux exposes; fresh-config precheck/postcheck can replace the
Wi-Fi lists with detected managed and monitor-mode interfaces:

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
- Excludes interfaces already in monitor mode from automatic fallback selection.
- An optional `mac` config key can pin managed scanning to one specific adapter
  by MAC address, regardless of which `wlanX` name the kernel assigns after
  reboot. When `mac` is set, only that adapter is eligible; all other adapters
  are ignored. On hosts with multiple Wi-Fi adapters (e.g. a Pi 4 with three
  WLAN dongles), this is the recommended way to keep the scan collector on the
  intended radio.
- Does not capture probe requests, deauth frames, or associations.

Important events:

- `interface_mode`
- `scan_started`
- `scan_empty`
- `ap_beacon`
- `collector_retrying`
- `collector_offline`

Subject History contribution:

- Wi-Fi AP records keyed by BSSID
- SSID history
- channel/frequency-band history
- encryption history
- signal min/max/latest
- vendor names when OUI files are present

### Wi-Fi Monitor (`wifi_monitor`)

Purpose: on-demand monitor-mode packet capture and channel hopping.

Implementation:

- Requires an interface that is already in monitor mode, or an explicitly
  configured interface with `prepare_monitor_mode: true`.
- Uses Scapy sniffing in a thread.
- Uses an asyncio channel hopper to retune with `iw dev <iface> set channel`.
- Supports 2.4 GHz and 5 GHz when the adapter reports those frequencies.
- Supports `channel_mode: hop` and `channel_mode: fixed`. Fixed mode tunes the
  monitor interface to one configured `fixed_channel` and leaves it there.
- Hop mode builds a channel plan from enabled bands, configured common
  channels, and optionally channels previously seen in Wi-Fi AP logs.
  `seen_channels_first` can prioritize site-observed channels; `common_channel_fallback`
  keeps common channels in the plan when discovered channels are sparse or
  absent. `dwell_sec` controls time spent on each channel.

Operational model:

- Skannr detects monitor-mode interfaces with `iw dev` and reports missing
  monitor mode in System Status. Fresh-config precheck/postcheck can seed
  `wifi_monitor.interfaces` with the first detected monitor-mode interface. By
  default Skannr does not change adapter mode.
- An optional `mac` config key can pin monitor-mode selection to one specific
  adapter by MAC address, regardless of which `wlanX` name the kernel assigns
  after reboot. When `mac` is set, only that adapter is eligible for monitor
  mode; all other adapters are ignored. This is the preferred way to keep a
  dedicated monitor dongle separate from the managed Wi-Fi interface.
- When `prepare_monitor_mode: true` is enabled, Skannr first tries to create a
  separate monitor interface on the selected phy with `iw phy <phy> interface
  add monX type monitor`, then brings only that monitor interface up.
- `interface: auto` is allowed for preparation, but only for a safe subset:
  USB/external adapters that advertise monitor-mode support and are not the
  current default-route interface. This keeps `wlan0`/`wlan1` renaming from
  mattering after reboot.
- If no safe auto candidate exists, Wi-Fi Monitor stays offline rather than
  guessing.
- In-place conversion of a source interface is disabled by default and requires
  explicit `allow_in_place_monitor_mode: true` because it brings that source
  interface down temporarily.
- Monitor-mode preparation requires the Skannr service process to have network
  administration privilege, usually root or equivalent `CAP_NET_ADMIN`. Manual
  success with `sudo ip` or `sudo iw` only proves the commands work for the
  interactive shell, not for a non-root service.
- Skannr does not rewrite `NetworkManager.conf` or migrate default routes. Host
  connectivity policy stays an OS-level responsibility outside the collector.
- Monitor-mode setup can be automated outside Skannr with a systemd oneshot
  or host-level network setup. This is still preferred when a site wants full
  control over NetworkManager and boot ordering.
- Monitor preparation remains opt-in and conservative so Skannr does not
  accidentally disrupt the normal managed Wi-Fi lifeline.

Important events:

- `monitor_started`
- `monitor_channel_changed`
- `probe_request`
- `association_seen`
- `disassoc_seen`
- `deauth_seen`
- `collector_retrying`
- `collector_offline`

High-rate `monitor_channel_changed` events are shown live but are not persisted,
because they are channel-hop state rather than device history.

Subject History contribution:

- AP beacons fold into the same Wi-Fi AP model as Wi-Fi Scan.
- Probe, association, deauth, and disassociation events fold into Wi-Fi client
  history keyed by client MAC.

802.11 frame filtering:

The monitor collector captures raw 802.11 frames via Scapy with a kernel BPF
filter (``type mgt``) so only management frames reach userspace.  Within the
management frame handler, only the subtypes useful for client discovery and
disruption detection are processed; the rest are discarded.

**Processed management subtypes:**

| Subtype | Name | Emitted as | Purpose |
|---------|------|------------|---------|
| 0 | Association Request | ``association_seen`` | Client connecting to an AP |
| 2 | Reassociation Request | ``association_seen`` | Client roaming between APs |
| 4 | Probe Request | ``probe_request`` | Client searching for networks — makes Wi-Fi clients visible in history |
| 10 | Disassociation | ``disassoc_seen`` | Graceful connection teardown |
| 12 | Deauthentication | ``deauth_seen`` | Forced disconnect — security-relevant |

**Filtered management subtypes:**

| Subtype | Name | Reason for exclusion |
|---------|------|---------------------|
| 8 | Beacon | Already captured by managed Wi-Fi Scan (``iw scan``) across all supported channels. Monitor-mode beacons are single-channel snapshots that would produce incomplete, channel-biased duplicates. |

**Dropped by kernel BPF (``filter="type mgt"``):**

| Type | Name | Reason for exclusion |
|------|------|---------------------|
| 1 | Control (ACK, RTS, CTS, etc.) | No device-history or security value. |
| 2 | Data | Encrypted payload — resource-intensive to process, no history value. |

Other management subtypes (1, 3, 5, 6, 7, 9, 11, 13, 14 — Authentication,
Deauthentication-Auth, etc.) are not handled because they do not contribute
to the collector's purpose: detecting client presence, AP association activity,
and disruption frames.

### BLE Scan (`ble`)

Purpose: passive Bluetooth Low Energy advertisement scanning.

Implementation:

- Uses `bleak` and BlueZ.
- Uses the ordered `adapters` list when configured; otherwise ranks available
  BlueZ adapters and normally chooses external USB adapters before built-in
  radios.
- An optional `mac` config key can pin BLE scanning to one specific adapter by
  MAC address, regardless of which `hciN` name the kernel assigns after reboot.
  When `mac` is set, only that adapter is eligible; all other adapters are
  ignored. On hosts with multiple Bluetooth adapters (e.g. a Pi 4 with two
  dongles), this is the recommended way to keep the BLE collector on the
  intended radio. On single-adapter hosts (Kali, Hampi4) where only `hci0`
  exists, leaving `mac` empty is sufficient — the built-in adapter is the only
  candidate.
- Uses a shared adapter operation lock so BLE Scan and BLE Identify do not
  collide on the same adapter.
- Tracks seen, updated, and lost devices.
- Wraps each Bleak discovery window in a hard timeout so BlueZ hangs become
  visible retry diagnostics, then runs timeout recovery against BlueZ and the
  adapter.
- Falls back to a `bluetoothctl` scan parser after Bleak discovery timeouts,
  and can start there with `force_bluetoothctl_scan` on hosts where Bleak hangs
  but `bluetoothctl scan on` works.
- Runs a bounded, rate-limited `bluetoothctl --timeout N scan on` warmup after
  repeated empty scan windows to recover BlueZ hosts that need discovery kicked
  externally, such as some Kali setups.
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

Subject History contribution:

- Bluetooth device records keyed by MAC
- names, manufacturer IDs, service UUIDs, RSSI range
- Apple Find My marker, payload type, status byte, and owner-lookup hint bytes
  when Apple manufacturer data uses payload type `0x12`
- first/last seen
- seen/update/lost counts
- presence sessions, including active sessions persisted across refreshes

The live Bluetooth table keeps BLE advertisement fields semantically separate
while presenting a compact operator view. The Identity display combines the
advertised name with labeled manufacturer-data company information, for example
`N62N1 | Mfr: AR Timing (0x0201)`. The raw advertised name, manufacturer-data
company ID, and advertised UUID list remain distinct in persisted records for
later drilldown.

Skannr decodes common Bluetooth SIG UUIDs for display. It has a small built-in
table for common service UUIDs such as `0x180A` Device Information, and can
also load optional offline UUID assigned-number files from
`src/skannr/data/collectors/member_uuids.txt`,
`src/skannr/data/collectors/service_uuids.txt`, and
`src/skannr/data/collectors/characteristic_uuids.txt`. This is separate from
`company_identifiers.txt`, which resolves manufacturer-data company IDs.
Standard service UUID labels and member/vendor UUID labels are displayed in
Services / UUIDs fields. Member UUIDs are labeled explicitly, for example
`Member UUID FEAF: Nest Labs Inc`. Unknown UUIDs remain visible as raw values.

Apple Find My accessories are detected from BLE manufacturer data, not from
names or GATT reads. Bleak exposes Apple company ID `0x004C` separately from
the payload bytes, so Skannr matches payload byte `0x12` and records compact
fields only: `findmy_accessory`, `findmy_label`, `findmy_payload_type`,
`findmy_status`, and `findmy_hint`. This intentionally does not claim an
AirTag-specific identity because AirTags, AirPods cases, and third-party Find
My accessories can share the same advertisement family, and the BLE address
rotates.

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

Subject History contribution:

- Identify results enrich the Bluetooth record for the MAC.
- Identify activity is displayed as an unfiltered activity log under BLE Scan;
  Subject History and Reports retain the longer-term Bluetooth history.

### Bluetooth Classic (`bt_classic`)

Purpose: on-demand classic Bluetooth inquiry for discoverable devices that may
not appear in BLE advertisements.

Implementation:

- Uses classic inquiry, preferably `hcitool scan --info`.
- Does not auto-start.
- Runs scan passes at configured intervals while active.
- Uses the same `mac` config key as BLE Scan to pin adapter selection to one
  specific Bluetooth adapter by MAC address, surviving `hciN` name swaps.

Important events:

- `scanner_started`
- `classic_scan_started`
- `classic_scan_completed`
- `classic_device_seen`
- `classic_device_updated`
- `classic_device_lost`
- `collector_retrying`

Subject History contribution:

- Classic results are folded into the same Bluetooth device model.
- Transport is marked as `classic`.
- Vendor/name/class/clock offset fields are retained when available.

### RTL-433 (`rtl433`)

Purpose: consume decoded ISM-band device messages from `rtl_433`.

RTL-433 is decoder-backed. Skannr does not demodulate TPMS, garage/security,
weather-sensor, utility-meter, or remote-control protocols directly. It starts
`rtl_433`, requests JSON output, preserves the decoded payload fields, and
normalizes a small subject identity around model, ID, channel, and protocol
when those fields are present. Sparse payloads fall back to a bounded hash of
the decoded JSON.

An individual RTL-SDR dongle is exclusive. ADS-B and RTL-433 normally cannot
run on the same dongle at the same time, but a host can run them concurrently
when it has multiple dongles. `main.py` treats `rtl433` and managed `adsb` as
RTL-SDR owners keyed by configured `device_index`: starting one from the browser
stops only another running member with the same device index and marks that
previous collector offline with a handoff reason. ADS-B with `manage_decoder: false` or a configured `url` is only
reading an external decoder feed and does not claim a Skannr-managed dongle.

Implementation:

- Validates the `rtl_433` executable and parses the configured frequency plan.
- Supports fixed frequencies and ranges using Skannr syntax such as
  `433.92:0`, `315.22:12`, `915-916:50:10`, or a comma-separated combination.
  Range entries are `start-end:step_khz:dwell_sec`.
- Converts the plan into `rtl_433 -f ... -H ...` arguments and runs `rtl_433`
  as an asyncio subprocess with `-F json`, `-M protocol`, and signal-level
  metadata.
- Publishes the current configured frequency hop to the browser and uses that
  frequency as a fallback when a decoded JSON row omits its own frequency.
- Reads one JSON object per stdout line, preserves bounded raw decoded fields,
  and emits `rtl433_event`.
- Classifies broad categories such as `tpms`, `security`, `weather`, and
  `utility` using conservative string matching over decoded fields.
- For TPMS-like decodes, normalizes pressure, temperature, battery/status, and
  wheel/position fields when `rtl_433` exposes them, while preserving the raw
  decoded payload for audit.

Important events:

- `scanner_started`
- `collector_retrying`
- `collector_offline`
- `rtl433_event`

Subject History contribution:

- Subjects are keyed by decoded model, ID, channel, and protocol when possible.
- Subjects retain first seen, last seen, event count, burst count, sample
  times, sample fields, frequencies, latest signal level, and latest raw
  decoded fields.
- Compact pattern evidence is retained per subject: hour and weekday histograms,
  day/night buckets, per-frequency counts, recent observation samples, and
  short repeat-gap timing. Reports and detail panes use this to explain recurring
  devices without rereading raw logs.
- TPMS subjects additionally retain pressure and temperature ranges, latest
  battery/status/position fields, compact TPMS samples, and a conservative
  interpretation label such as repeated sensor or possible vehicle/pass-through
  cluster.

Insights and Reports:

- Findings emit compact decoded-subject rows. TPMS/security-like categories are
  warning severity in the live feed, but the dedicated alert rule is disabled
  by default.
- Reports add a population row plus per-subject rows for repeated or
  TPMS/security-like decoded subjects. TPMS report evidence includes pressure,
  temperature, battery/status, repeated sensor IDs, and short-window multi-sensor
  clusters as possible vehicle/pass-through activity. Report language is
  intentionally conservative: it can describe activity clusters and possible
  garage/security/remote/contact activity, but it does not infer open/close
  state unless the decoded payload explicitly contains state.
- Alerts use `alerts.rtl433_signal`, which is configurable but disabled by
  default because local ISM environments are noisy and real samples are needed
  before deciding what should page the operator.

### ADS-B (`adsb`)

Purpose: consume decoded ADS-B aircraft state from `dump1090` or `readsb`.

ADS-B is decoder-backed. The RTL-SDR is owned by `dump1090` or `readsb`, which
demodulates 1090 MHz ADS-B and exposes aircraft state through an
`aircraft.json` file or HTTP endpoint. By default Skannr starts the configured
decoder on `device_index`, writes decoder JSON files under
`runtime/logs/adsb_decoder/`, reads `aircraft.json`, and stops the decoder when
the collector stops. Operators can set `manage_decoder: false` or configure
`url` when an external service already owns the decoder. Skannr does not try to
auto-pick a dongle; the local YAML assigns which dongle each managed collector
uses.

Implementation:

- Starts the configured decoder when `manage_decoder` is enabled and no `url`
  is configured.
- Finds the managed or first readable configured `aircraft.json` path, or reads
  a configured HTTP `url`.
- Polls the decoded snapshot at `poll_interval_sec`, default one second.
- Normalizes aircraft rows into compact fields: ICAO, callsign, squawk,
  emergency state, latitude/longitude, altitude, speed, track, vertical rate,
  decoder message count, RSSI, source, and optional distance from configured
  observer latitude/longitude.
- Keeps a per-ICAO fingerprint so unchanged snapshot rows do not create
  duplicate live rows or subject updates.
- Emits `adsb_aircraft` rows only when material aircraft state changes.

Important events:

- `collector_online`
- `collector_offline`
- `collector_retrying`
- `adsb_aircraft`

Subject History contribution:

- Subjects are keyed by ICAO hex. Callsign is display enrichment, not stable
  identity, because callsigns can be absent or reused.
- Aircraft subjects retain first seen, last seen, update count, position count,
  sample callsigns/squawks, latest position, altitude range, closest distance,
  maximum speed, path span, local pass/session spans, bounded route samples,
  nearby approach/departure context, and emergency state.
- ADS-B collector health summaries retain decoder state, source path/URL, managed
  device index, poll interval, and one-dongle RTL-SDR scheduling guidance.

Insights and Reports:

- Findings emit optional new-aircraft rows, emergency-squawk warnings, and
  low-nearby aircraft warnings.
- Reports add an ADS-B population row, decoder-health guidance when the collector
  is offline or retrying, plus per-aircraft profile rows for emergency aircraft,
  low nearby aircraft, repeated local passes, approach/departure-like tracks, or
  aircraft seen enough times to pass `reports.adsb_report_min_seen`.
- Alerts use `alerts.adsb_aircraft`: emergency state is critical by default;
  aircraft below `low_altitude_ft` and within `nearby_radius_km` are warning by
  default.

### Rayhunter (`rayhunter`)

Purpose: poll an optional Rayhunter cellular-monitor HTTP endpoint and convert
its health, recording metadata, and analysis warning count into Skannr subjects,
reports, and alerts.

Rayhunter is a cellular-monitor integration, not a generic Skannr RF scan. The
signal and protocol interpretation is Rayhunter's responsibility. Skannr treats
the configured endpoint as provenance and records only compact status and
warning metadata.

Implementation:

- Requires `endpoint` before the collector can start.
- Polls the endpoint every `poll_interval_sec`, default 30 seconds.
- Uses `request_timeout_sec` for HTTP requests.
- Prefers Rayhunter JSON APIs:
  `/api/system-stats`, `/api/qmdl-manifest`, `/api/config`, and
  `/api/analysis-report/<recording>`.
- Falls back to parsing the visible status page when the JSON APIs are missing.
- Accepts gzip responses.
- Sanitizes status text and older persisted data so HTML, JavaScript bundles,
  and minified Svelte fragments are not retained as operator evidence.
- Does not fetch or retain `.qmdl`, `.pcap`, ZIP, or other large Rayhunter
  artifacts.

Important events:

- `collector_online`
- `rayhunter_status`
- `collector_retrying`
- `collector_offline`

Subject History contribution:

- Subject History keeps one endpoint subject keyed by the configured endpoint.
- The subject stores the latest reachable/retrying/offline state, warning count,
  Rayhunter version, device OS, storage, memory, battery, GPS mode, current
  recording ID/size/start time, and recording last-message time when available.
- Reports show one row per endpoint using subject `Rayhunter <endpoint>`.
  The summary carries the warning count and selected-window status-event count.

Alert behavior:

- `rayhunter_warning` emits an alert when Rayhunter reports a non-zero warning
  count.
- Generic collector-health alerts are controlled separately by
  `alerts.collector_issue`.

### APRS-IS (`aprsis`)

Purpose: internet-fed APRS situational context for a configured local-area
filter.

Implementation:

- Opens one or more filtered APRS-IS TCP feed connections, normally on port
  `14580`.
- Supports separate normal APRS and CWOP/weather feeds under one collector.
- Uses feed connection/login success as the internet availability check.
- Reports per-feed `ONLINE`/`OFFLINE` status, with optional preferred backend
  matching for pooled hosts such as CWOP.
- Enforces a local radius after decoding when `enforce_radius` is enabled,
  which protects Reports from loose server-side filtering.
- Emits compact packet metadata for station position, object, message, status,
  weather, telemetry, and generic packet events.
- Marks every normalized APRS event with `internet_fed: true`.

Important events:

- `collector_online`
- `collector_offline`
- `aprs_position`
- `aprs_object`
- `aprs_message`
- `aprs_status`
- `aprs_weather`
- `aprs_telemetry`
- `aprs_packet`

Subject History contribution:

- APRS-IS is not local RF evidence. Subject History rolls APRS packets up by
  callsign/object/weather station for Insights and Reports.
- APRS-IS weather stations also get daily aggregates that roll into weekly,
  monthly, and yearly period summaries. Reports use those period rows for
  longitudinal weather patterns such as temperature range/change, rain-rate
  maxima, rain episodes, wind/gust maxima, pressure range/change, and
  sample/day coverage.
- APRS-IS mobile stations retain bounded trip evidence in compact Subject
  History: first/latest positions, recent route samples, recent packet samples,
  movement/span/speed fields, and a pass-through/repeated-presence rollup label.
  Browser detail panes expose those samples for normal drilldown while raw JSONL
  remains the deeper audit source.

### NOAA (`noaa`)

Purpose: internet-fed weather, tsunami, tropical hazard, and point-forecast
context for a configured point/state, optional NHC basins, and official
tsunami.gov warning centers.

Implementation:

- Polls NWS active alerts through `api.weather.gov`.
- Resolves the configured latitude/longitude through the NWS points API and
  polls the hourly forecast URL for a compact point-forecast summary.
- Polls configured NHC RSS feeds for tropical advisories.
- Polls tsunami.gov NTWC/PTWC Atom feeds and linked CAP products for tsunami
  bulletins. CAP fields provide source, message number, incident ID, magnitude,
  depth, event time, coordinates, severity, instructions, and resource/map URLs
  when the center publishes structured CAP content.
- Optionally fetches the small linked plain-text bulletin when Atom/CAP is
  sparse, primarily for PTWC products, to recover magnitude, location, origin
  time, depth, and coordinates without retaining bulk event JSON.
- Emits only new or materially changed alerts/advisories during one collector
  run. Forecast summaries emit only when the derived near-term forecast state
  materially changes.
- Uses feed-specific stable subject identities. NWS alerts use Source + Area +
  Event. NHC storm products roll up into one advisory package per basin +
  storm/system name + advisory number. Forecast summaries use one subject per
  configured point. Tsunami.gov products use one subject per warning center +
  tsunami incident ID, so later message numbers update the same incident row.
  This keeps repeated polls in one live row while separating distinct areas,
  advisory numbers, forecast points, and tsunami incidents.
- Keeps forecast data subject-focused: one `noaa_forecast_summary` row per
  configured point with generated/update time, current forecast, temperature
  range, precipitation probability, next likely precipitation period, and max
  wind. It does not persist every hourly period as a separate subject.
- Retained forecast summaries compare the latest point forecast with the previous
  retained forecast for the same point. Delta evidence includes temperature,
  precipitation probability, wind, coastal/surf or other hazard text additions
  and clears, plus a conservative deterioration/improvement/mixed-change label.
- Treats generic NHC Tropical Weather Outlook messages such as "there are no
  tropical cyclones at this time" as state-like outlook subjects that do not
  alert and do not become new rows merely because the feed link/timestamp
  changed.
- Treats tsunami Information Statements as informational context. Tsunami
  Warning, Watch, Advisory, or Threat products open Alerts; information-only
  statements remain in the feed/history/report layers without paging the
  operator.
- Uses poll cadence from `~/.config/skannr/collectors/noaa.yaml`, default `300` seconds.

Important events:

- `collector_online`
- `collector_retrying`
- `collector_offline`
- `noaa_weather_alert`
- `noaa_tropical_advisory`
- `noaa_forecast_summary`
- `noaa_tsunami_alert`

Subject History contribution:

- Subject History rolls NOAA alerts/advisories and point forecasts up by the
  same feed-specific identities used by the live tab, Reports, and Alerts.
- NOAA also builds monthly and yearly period summaries over distinct material
  NOAA subjects. These rows track tropical systems, basins, NWS hazard subjects,
  hazard areas/severities, tsunami incidents/messages, forecast-context rows,
  forecast-change evidence, sources, and retained previous-period subject-count
  deltas. They deliberately avoid advisory-package product count by storm/system
  and max-severity rollups as primary outputs.

### USGS (`usgs`)

Purpose: internet-fed earthquake context for a configured local/regional radius.

Implementation:

- Polls the USGS GeoJSON earthquake API.
- Queries by configured latitude, longitude, radius, and minimum magnitude.
- Optionally polls a worldwide `global_major` subfeed for M6.5+ earthquakes
  and merges those rows into the same USGS live feed by USGS event ID.
- Calculates distance from the configured point when event coordinates are
  present.
- Uses the USGS event ID as the stable subject identity across local and
  global-major subfeeds.
- Includes event time plus magnitude, place, status, felt/CDI/MMI, alert color,
  and tsunami flag in the material fingerprint.
- Uses poll cadence from `~/.config/skannr/collectors/usgs.yaml`, default `300` seconds.

Important events:

- `collector_online`
- `collector_retrying`
- `collector_offline`
- `usgs_earthquake`

Subject History contribution:

- Subject History rolls earthquakes up by USGS event identity for live detail,
  Reports, and Alerts.
- USGS also builds weekly, monthly, and yearly period summaries over unique
  event IDs. Reports use those rows for longitudinal seismic context: local
  versus global-major counts, notable and tsunami-flagged counts, magnitude
  range, nearest configured-point distance, shallowest depth, alert colors,
  scopes, feeds, and latest-event context.

### SWPC (`swpc`)

Purpose: internet-fed NOAA Space Weather Prediction Center context for solar
flare, radio blackout, solar radiation storm, geomagnetic storm, Kp, and CME
watch/update conditions.

Implementation:

- Polls configured SWPC public JSON products.
- Reads official SWPC alert/watch/warning products from `alerts.json`.
- Reads NOAA R/S/G scale state from `noaa-scales.json`.
- Reads GOES primary X-ray flux only to derive X-class flare events. It groups
  contiguous samples above `xray_min_class` and emits one compact flare event
  with start, peak, end, peak class, and source URL.
- Reads planetary K/Kp and emits compact geomagnetic-storm events at or above
  `feed_min_kp`.
- Does not retain raw X-ray or Kp time-series samples; only normalized
  `swpc_event` records are persisted.
- Uses SWPC event identity as the stable subject identity. Official
  alert/watch/warning products and compact X-ray/Kp events include source event
  time in identity or fingerprint. NOAA R/S/G scale rows are state-like and
  update only when the current scale materially changes.
- Tolerates partial product failures. If at least one enabled SWPC product
  succeeds, successful rows are emitted and failed product names are surfaced in
  collector status. The collector only enters retrying when all enabled SWPC
  products fail.
- Uses poll cadence from `~/.config/skannr/collectors/swpc.yaml`, default `300` seconds.

Important events:

- `collector_online`
- `collector_retrying`
- `collector_offline`
- `swpc_event`

Subject History contribution:

- Subject History rolls SWPC space-weather events up by event identity for live
  detail, Reports, and Alerts.
- SWPC also builds weekly, monthly, and yearly period summaries over unique
  space-weather subjects. Reports use those rows to show alert-threshold and
  critical counts, event-kind counts, highest X-ray flare class, max Kp, and
  strongest R/S/G scale labels directly in the report row.

Alert behavior:

- X-class flares are Alerts by default at `X1.0` or higher.
- Radio blackout Alerts default to `R3` or higher.
- Solar radiation storm Alerts default to `S3` or higher.
- Geomagnetic storm Alerts default to `G3` or higher, including Kp `7` or
  higher from the planetary K index.
- Lower R/S/G/Kp conditions can still appear in the SWPC live feed and derived
  context without becoming Alerts.

### PWS (`pws`)

Purpose: current local personal weather station context from Ambient Weather.

Implementation:

- Polls Ambient Weather's `/v1/devices` API with local
  `application_key`/`api_key` credentials from `~/.config/skannr/collectors/pws.yaml`.
- Uses a scan-style cadence, default `60` seconds, because the endpoint returns
  current station state rather than a historical event feed.
- Emits one `pws_weather` event per station when material weather fields change.
- Never emits API credentials in browser status, raw event payloads, Reports, or
  Subject History. Source URLs are redacted to the public endpoint.
- Uses station ID, station name, or MAC address as stable subject identity.
- Normalizes outdoor and indoor temperature/humidity/dewpoint/feels-like
  readings, wind/gust and 10-minute wind averages, one-hour rain rate, expanded
  rain totals, pressure, solar/UV, coarse location, coordinates, elevation,
  sample time, timezone, last-rain time, battery/status fields, and source
  metadata.
- Intentionally ignores the street address returned by Ambient; Skannr keeps
  only coarse location metadata and coordinates.
- Tracks simple rain episodes in Subject History. When the latest transition is
  `stopped`, report evidence keeps the episode start and stop together so
  Reports do not show ambiguous standalone rain start/stop rows.
- Builds daily PWS station aggregates and rolls them into weekly, monthly, and
  yearly summaries for Reports. Period rows carry temperature range/change,
  average humidity, observed rain total, maximum one-hour rain rate, rain
  episode count, approximate rain-active span, maximum wind/gust, pressure
  range/change, solar/UV maxima, and sample/day coverage. These are derived
  from retained PWS samples, so longer-period comparisons are sparse until
  enough data has accumulated.

Important events:

- `collector_online`
- `collector_retrying`
- `collector_offline`
- `pws_weather`

Subject History contribution:

- Subject History rolls PWS samples up by station and by period for live detail,
  Insights, Reports, and Alerts.

Alert behavior:

- High one-hour rain rate and high wind gusts can open `pws_weather` Alerts.
- Thresholds are independent from APRS weather thresholds so local station
  alerts can be tuned separately.

### LAN (`lan`)

Purpose: local-network context from the host OS and low-impact LAN listeners.

Implementation:

- Reads `ip neigh` JSON output when available, with text fallback.
- Reads `arp -an` as a secondary source.
- Reads default IPv4/IPv6 route state.
- Listens for passive mDNS and SSDP advertisements by default when LAN is
  enabled, then folds services, locations, and server strings into LAN subject
  identity.
- Optionally imports resolved Bonjour/mDNS records with
  `avahi-browse -a -r -p -t`. This source is disabled by default and requires
  `avahi-utils` / a working Avahi daemon. Missing Avahi only creates a warning;
  the normal LAN collector stays online.
- Avahi records are enrichment, not authoritative inventory. Resolved `=` rows
  are joined to LAN subjects by trusted TXT MAC fields (`mac`, `waMA`) first,
  then by current IP address. Other MAC-like TXT fields are retained as clues
  because fields such as AirPlay `deviceid` or HomeKit `id` may not be the
  Ethernet/Wi-Fi MAC.
- Optionally reads dnsmasq-style DHCP lease files or command output on a slower
  import cadence. Router-specific exports should be wrapped in a local command
  that prints dnsmasq-style rows.
- Optional passive DHCP and raw ARP listeners are available but off by default
  because they can require elevated privileges or collide with local services.
- Optional active ARP inventory uses `arp-scan` on its own cadence and is off by
  default.
- Active ARP subjects are retained across intermittent missed replies. The
  default retention is three active-scan intervals, with a 180 second minimum,
  and can be overridden with `active_arp_scan_retention_sec`.
- `active_arp_scan_interfaces: []` delegates interface choice to `arp-scan`.
  On multi-homed Pis this may choose the wrong network, so production configs
  should list intended interfaces explicitly, for example `eth0` for the
  property LAN and `wlan0` only when the Wi-Fi interface's subnet should also be
  inventoried.
- Active ARP scan is IPv4 Ethernet/L2 discovery. It is not a Yggdrasil/tun0
  inventory mechanism; Yggdrasil is a routed IPv6 overlay and should be treated
  as remote-access infrastructure.
- The third `arp-scan` output column is retained as `vendor_name` and shown as
  an explicit LAN feed column. Skannr runs `arp-scan` from a known vendor-data
  directory when possible so `ieee-oui.txt` / `mac-vendor.txt` lookup does not
  depend on systemd's working directory.
- Uses poll cadence from `~/.config/skannr/collectors/lan.yaml`, default `60` seconds.
- An optional `mac` config key can pin all LAN collection (ARP scan, passive
  listeners) to one specific adapter by MAC address, regardless of which
  `wlanN` name the kernel assigns after reboot. When `mac` is set, only the
  interface whose MAC matches is eligible. On hosts with a single network
  interface, leaving `mac` empty auto-discovers the available interface.

Important events:

- `collector_online`
- `collector_offline`
- `collector_retrying`
- `lan_device_seen`
- `lan_device_changed`
- `lan_gateway_seen`
- `lan_gateway_changed`

Subject History contribution:

- Subject History rolls LAN observations up by MAC/IP identity and default
  gateway identity for live detail, Reports, and Alerts.

### LAN Identify (`lan_identify`)

Purpose: operator-requested active enrichment for one LAN IP address.

Implementation notes:

- This is an action collector, modeled after BLE Identify. It does not run a
  background loop and does not scan the subnet.
- The browser calls `/lan_identify` from Identify buttons on live LAN rows that
  have an IPv4 or IPv6 address.
- The action runs bounded `nmap` service detection and short `curl` HTTP/HTTPS
  root probes using fixed code-owned commands plus YAML timeout/port knobs.
- Results are compacted to open ports, service banners, HTTP titles, selected
  headers, script names, brand-like snippets, and errors. Raw HTML and large
  nmap fingerprints are not kept in the browser model.
- Successful results emit a `lan_identify` Finding and are folded into the
  matching LAN Subject History record by subject key, MAC, or IP.

Important events:

- `identify_started`
- `identify_result`
- `identify_failed`
- `collector_offline`

Subject History contribution:

- Subject History stores LAN Identify enrichment on the LAN subject so Reports
  can show clues such as `Wi-Fi Setup`, `myq.js`, Chamberlain/MyQ hints, or open
  HTTP ports alongside passive vendor and service observations.

## 7. Persistence

The current durable backend is filesystem JSONL.

Raw events are written to:

```text
runtime/logs/<collector>/YYYY-MM-DD.jsonl
```

Application logs are written to:

```text
runtime/logs/skannr.log
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

Skannr has four operator-facing derived data products plus one internal
compatibility view:

- Findings
- Subject History
- Insights
- Reports
- Wi-Fi/Bluetooth subjects (via `WiFiBLEPostprocessor` internally)

The dashboard-facing derived views have distinct responsibilities:

- Insights: recent event log, tactical/debuggable.
- Reports: ranked intelligence summary, strategic/operator-facing.
- Subject History: collector-neutral subject rollup for every collector family
  and the visible History tab.
- Wi-Fi/Bluetooth compatibility view: derived from Subject History for older
  browser drilldown and live-table code.

All four products use the same selected dashboard view window as their maximum
raw-log scope. Insights then apply an additional recent-event lookback,
`history_analysis.insights_recent_minutes`, because the tab is meant to answer
"what changed recently?" rather than reproduce the full longitudinal report.
Set the value to `0` to disable the additional Insights cutoff.

The server rebuilds derived views autonomously on a background scheduler
(`derived_scheduler_interval_sec`, default 15 min). The browser polls for
new data at the interval set by `derived_auto_refresh_min` (default 15 min)
and only re-renders when `data_version_epoch` has changed. Manual Refresh
(POST) still triggers an immediate server-side rebuild.

The backend accepts only one forced derived refresh at a time. A second refresh
request joins the active refresh and waits through `/derived_views/status`
instead of starting a competing rebuild.
Normal derived-bundle loads also check `/derived_views/status` before reading
cached summaries. If a forced refresh is active, the browser joins the active
refresh and waits for completion instead of rendering older cached data.
Each backend stage logs start/finish timings with an operator-facing phase
number:

- Phase 1/2, Subject History: fold raw collector logs into the
  collector-neutral subject cache.
- Phase 2/2, Insights analysis and Reports: derive tactical observations and
  the ranked operator-facing intelligence summary from Subject History.

The `/derived_views/status` endpoint exposes the active refresh window, phase
number, phase label, stage elapsed time, total elapsed time, and last completed
refresh time. The browser polls that endpoint while a refresh is in flight so
the status strip can distinguish a frontend stuck-state from a backend phase
that is still running.
Starting Skannr with `--debug` raises process logging to DEBUG and attempts to
open a graphical terminal tailing `runtime/logs/skannr.log`. On headless or systemd
deployments the same debug output remains available in the log file.
When live Wi-Fi/Bluetooth rows arrive, or collector status shows scan events
have already happened while Subject History is still empty, the browser treats
that as evidence that raw scan data exists and starts a throttled catch-up
refresh. This covers the fresh-log case where the first page load sees empty
cached derived summaries before scans have been materialized. Catch-up
refreshes share the same post-refresh cooldown used by automatic refreshes, so
slow Pis do not immediately start another catch-up cycle after a refresh has
completed.
Successful derived refreshes also rehydrate the live Wi-Fi Scan and BLE Scan
tables from the Wi-Fi/Bluetooth compatibility view so missed browser events do
not leave the scan tabs showing stale rows when newer materialized data exists.
The BLE Scan table is also periodically repainted so its recent-device filter
can age rows out even when no new BLE event arrives after a sleeping browser
wakes. Subject History and the compatibility view carry numeric epoch fields
next to display timestamps, and the browser uses those epochs for live/recent
filtering when available. Display timestamps remain the Skannr-host strings from
the event or derived summary.
Poll-feed live tables for NOAA, USGS, and SWPC upsert by source event/subject
identity and hide rows older than `ui.poll_feed_live_ttl_sec`, default 24
hours. This TTL only limits browser live-feed clutter. It does not delete raw
collector JSONL, Subject History, Reports, or Alerts.

Manual or automatic refresh of any derived tab refreshes the whole bundle in
dependency order:

1. Subject History from raw collector JSONL
2. Wi-Fi/Bluetooth compatibility view
3. History-based Insights and Reports

### Findings

Findings are live deterministic observations produced by `FindingsEngine` from
incoming events. The engine keeps small in-memory maps for recent Wi-Fi APs, Wi-Fi clients, Bluetooth devices, ADS-B aircraft, and
collector health. It
emits normalized finding records for explicit conditions such as:

- new or returned Wi-Fi AP/client
- blank Wi-Fi probe
- randomized/local Wi-Fi MAC
- strong nearby Wi-Fi client or AP
- probe burst
- configured sensitive SSID probe
- BLE device seen/returned/lost
- strong BLE signal
- BLE identify success/failure
- NOAA weather/tropical hazards and material alert upgrades
- USGS earthquake observations, global-major earthquake observations, and
  magnitude updates
- SWPC space-weather events
- LAN device/gateway observations and changes
- collector offline/retrying/stopped

For `wifi_monitor`, generic per-client probe churn, blank probes, randomized
MAC notices, client lost/returned events, generic probe bursts, generic AP
presence, and generic strong-client/AP observations are disabled as live
Findings by default. Monitor-mode still retains the raw data and rolls it into
Subject History/Reports, while live Insights focus on disruption frames and
explicitly configured sensitive SSID probes.

Findings may be written back as events under `runtime/logs/findings` for
operator audit/debugging and live replay while the process is running. They are
not reloaded as a derived upstream. Dashboard Insights are rebuilt from Subject
History through `history_analysis.json`, which keeps disabled collectors and old
finding logs from resurfacing after cleanup or configuration changes.

### Subject History

Subject History is the collector-neutral base summary used by Insights and
Reports. Raw collector JSONL remains the audit trail, but refresh rolls those
events up by stable subject so later layers do not each scan raw logs in their
own way.

Current subject identities are:

- Wi-Fi SSID, BSSID, and client MAC
- Bluetooth/BLE device MAC and coarse identity metadata
- APRS-IS callsign/object/weather station
- Rayhunter endpoint
- NOAA/NWS Source + Area + Event; NHC basin + storm advisory package;
  tsunami.gov center + incident ID
- USGS earthquake event ID
- SWPC space-weather event/product ID
- PWS station ID/name/MAC
- LAN device MAC/IP and default gateway identity

For NOAA/NHC, feed semantics define the subject. NHC storm products roll up by
basin + storm/system name + advisory number: Amanda Public Advisory 11, Forecast
Advisory 11, Forecast Discussion 11, and Wind Speed Probabilities 11 are one
advisory-package subject, while Amanda 12 is a new subject. For NWS alerts,
area is deliberately part of the subject, so a Beach Hazards Statement for San
Francisco differs from one for Santa Cruz. Generic NHC "no active cyclones"
outlook messages collapse by basin/event and update only on material text/state
changes.

For poll collectors, Subject History and the live feed share the same identity
rule. The browser may hide old poll-feed rows after `ui.poll_feed_live_ttl_sec`
for readability, but raw logs and Subject History retention are governed by the
normal runtime retention and materialized-history rules.

The materialized file is:

```text
runtime/logs/device_history/subject_history.json
```

User-provided subject annotations are stored separately in:

```text
runtime/logs/device_history/subject_annotations.json
```

Annotations are keyed by stable subject identity and applied as an overlay while
Subject History is loaded or rebuilt. They never overwrite `subject`,
`subject_id`, `subject_type`, or collector identity; UI, detail panes, Insights,
and Reports may display the annotation beside the original subject. The first
supported annotation families are Wi-Fi BSSIDs/clients, Bluetooth devices, and
LAN devices/gateways.

Randomized or locally administered identities are handled as low-confidence
subjects unless another stable signal exists. Raw per-MAC evidence stays in
append-only JSONL logs, but the `WiFiBLEPostprocessor` groups low-identity
Wi-Fi/BLE churn before folding records into Subject History. Named,
vendor/model-rich, service-rich, finding-linked, or otherwise identifiable
devices stay individual; low-identity randomized MACs collapse into aggregate
Device History and Subject History rows such as `4934 randomized devices found`.
This applies to Wi-Fi monitor client/probe MACs, Bluetooth private/randomized
addresses, and weak LAN private-MAC rows with no hostname or service evidence.
Bluetooth aggregate rows use the strongest shared identity bucket, so Apple
manufacturer-only rows, Apple Find My accessory rows, Microsoft rows, Unknown
rows, and any other manufacturer buckets remain separate in Subject History and
Reports cross-subject patterns.

The summary also carries report-compatible sections such as `wifi`,
`bluetooth`, `aprsis`, `rayhunter`, `rtl433`, `adsb`, `noaa`, `usgs`, `swpc`,
`pws`, and `lan`. The visible History tab renders Subject History rows so
APRS-IS callsigns, Rayhunter endpoints, RTL-433 decoded subjects, ADS-B
aircraft, NOAA alerts, USGS earthquakes, SWPC space-weather
events, PWS stations, and LAN subjects can be
inspected directly.
The Wi-Fi/Bluetooth compatibility view remains derived from this
summary. Compact privacy groups for BLE, Wi-Fi randomized clients, and LAN
private MACs retain bounded `group_members` evidence so detail panes can show
representative per-MAC first/last seen, activity counts, signal range, and
identity/source context without re-expanding the main tables.

For collectors outside the Wi-Fi/Bluetooth compatibility fold,
Subject History keeps compact per-collector direct state for APRS-IS,
Rayhunter, RTL-433, ADS-B, NOAA, USGS, SWPC, PWS, and LAN. Each
`subject_history_direct_<collector>.json` file stores compact history rows plus
the collector checkpoint; it does not retain every normalized raw observation.
Refresh reads only JSONL bytes beyond the saved checkpoint, folds those new
bytes into compact subject summaries, and writes the compact state for the next
refresh. The browser API exposes the normalized `subjects` list and report
sections, not the direct-state internals.

### Subject History And Wi-Fi/Bluetooth Compatibility

Subject History is the collector-neutral materialized view used by the visible
History tab. The historical `device_history` code/file is now the materialized
per-device Wi-Fi/Bluetooth compatibility view used by existing drilldowns and
live-table hydration. It is derived from Subject History so the dashboard API
remains stable while the backend has one collector-neutral base layer.

System events are intentionally excluded from Subject History because they are
runtime state, not durable subjects. They remain eligible for Insights and
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
runtime/logs/device_history/device_history.json
```

After that, refresh uses JSONL byte-offset checkpoints and reads only newly
appended log bytes. Older raw logs remain available for manual inspection, but
are not the normal runtime query path.

### Insights

Insights are the recent event feed. They combine live Findings with
short-horizon Subject History observations so an operator can debug recent
changes and see the lower-level events that may later roll up into Reports.
They are intentionally event-oriented: one row describes one finding or
observation, sorted by event/activity time descending. Device-centric
consolidation and long-term pattern interpretation belong in Reports.
For BLE, the generated history-analysis layer is intentionally stricter than
Subject History: anonymous/randomized BLE subjects are summarized as a
population row, and individual strong/linger/loss rows are emitted only for
recent named or otherwise identifiable subjects. This keeps phone-style BLE
address churn from overwhelming the tactical Insights tab.

History observations are generated by `HistoryAnalyzer` and written to:

```text
runtime/logs/device_history/history_analysis.json
```

The persisted analysis file can cover the selected View window, but the
browser-facing Insights payload is filtered by
`history_analysis.insights_recent_minutes`. For Findings, the event timestamp is
the cutoff field. For history observations, `last_seen_epoch` is preferred over
the row timestamp because observations are regenerated on refresh; this prevents
old device behavior from becoming "recent" merely because analysis was rebuilt.

Current rule families include Wi-Fi encryption/channel/probe/BSSID patterns,
Bluetooth signal/linger/presence patterns, and randomized-MAC population
observations.  Each collector defines its own insight rules — see that
collector's section under §6 Built-In Collectors.

The analysis does not call an LLM.

### Reports

Reports are slower longitudinal summaries over the selected view window. They
are generated by `ReportsBuilder` and written to:

```text
runtime/logs/device_history/reports.json
```

Report families cover per-collector subject profiles (Wi-Fi AP/SSID/client,
Bluetooth device/cluster, APRS-IS station/weather, NOAA hazard/tropical/tsunami,
USGS seismic, SWPC space-weather, PWS weather station, LAN device/gateway,
RTL-433 decoded subjects, ADS-B aircraft), population/cross-subject rows,
collector-health rows, and materialized period summaries.  Each collector
defines its own report families — see that collector's section under
§6 Built-In Collectors.

Bluetooth sessions are clipped to the selected report window so a last-24-hours
report does not count hours before the window boundary.

Reports carry an internal `report_scope`:

- `population`: cross-subject intelligence for a collector or local
  environment slice. These rows are sorted before per-subject rows. They link
  only when the row carries a concrete grouped identity such as an SSID;
  otherwise they avoid fake single-subject detail links.
- `collector` / `quality`: collector health or coverage confidence rows.
- `subject`: one concrete subject such as a BSSID, MAC, callsign, event ID,
  Rayhunter endpoint, or LAN device/gateway.

The UI lists population rows first, then collector/quality rows, then
per-subject rows. This keeps the Reports tab useful as an intelligence product:
first show the local pattern, then let the operator drill into the subject rows
that explain it.

The Reports UI provides a Type column over broad report families: pattern,
security, presence, signal, new-device, behavior, identity, collector, and
analysis. The small Reports summary line above the table is derived from the
currently visible rows, so it changes with source filtering and search text.
Confidence and
Reasons columns expose evidence quality and compact reason tags before the
operator reads the longer Evidence cell.
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
Materialized period reports use explicit evidence renderers for the same
reason. PWS and APRS-IS weather station period rows are per-subject
longitudinal rows, while NOAA, USGS, and SWPC period rows are population
patterns. Their evidence is grouped as period, weather/seismic/space-weather
level, latest event, and source coverage instead of falling back to raw JSON
key names. This keeps Reports readable while preserving the underlying
structured evidence for search and drilldown.
Bluetooth report generation is device-centric on the server side. Stable BLE
MACs produce one device-profile row with a Subject, merged findings, summary,
and behavioral evidence. Unnamed/private BLE address churn is grouped by a
coarse fingerprint made from manufacturer, useful advertised name, and advertised
service/member UUIDs. The UI should render those server decisions rather than
re-derive intelligence from raw evidence fields.
Wi-Fi report generation uses the same server-side consolidation. AP-level
findings such as signal variation, recurring/long presence, channel variation,
and security variation are first evaluated per BSSID. When an SSID profile
already covers a multi-BSSID network, routine AP presence, signal, and radio
context is folded into that SSID profile instead of producing one row per radio.
Individual BSSID rows are retained mainly for warning-level security
differences. SSID-level behavior, such as multiple BSSIDs, recurring SSID
presence, or locally administered/randomized BSSID groups, is emitted as an SSID
profile. The Subject column owns identity; Evidence describes radio/security,
observation pattern/session state, signal, vendors, and BSSID counts. Full
BSSID/radio lists belong in drilldown instead of the report row.

#### Report Scoring

Reports use a server-side `score` from 0 to 100. The score is an operator
attention rank, not a probability of malicious activity. Rows are sorted by
scope, then severity, then score, then last-seen time. A high score means the
profile is more important to review because several signals line up: long
presence, repeated presence, current activity, strong nearby signal, new
appearance, weak security, or unusually broad address/BSSID behavior.

Scoring rules are defined per subject family: Bluetooth stable-device,
Bluetooth private-address cluster, Wi-Fi AP/BSSID, and Wi-Fi SSID profiles.
Each rule family lives with its collector — see the Wi-Fi Scan and BLE Scan
sections under §6 Built-In Collectors for the current point values.

Scores at or above 75 become warning-level profile rows unless a more specific
security rule already set severity. This is intentionally a high-attention
threshold, not a claim that the device or network is hostile.

## 9. Browser UI

The UI is a single static page served from `src/skannr/static/index.html`. Most
dashboard behavior lives in `src/skannr/static/app.js`; reusable table
schemas/rendering live in `src/skannr/static/tables.js`.

Top-level tabs:

- Insights
- Reports
- Subject History
- Wi-Fi Scan
- Wi-Fi Monitor
- Bluetooth
- RTL-SDR
- APRS-IS
- NOAA
- USGS
- SWPC
- PWS
- LAN
- System Status
- Alerts

Insights, Reports, and Subject History have Source filter chips built from
collector metadata. They are filters over one dataset, not navigation tabs.
Bluetooth collectors are grouped under a single Bluetooth source group. Wi-Fi
Scan and Wi-Fi Monitor remain separate sources because one is managed scanning
and the other is monitor-mode capture.
Live Wi-Fi Scan and BLE Scan tables use one row-search box each instead of
separate per-column selector controls.
Subject History omits System from its Source filter; System is runtime state,
not a durable subject source.

Reports, Subject History, and live scan/feed tables expose clickable identity
fields for operator drilldown:

- Bluetooth MAC opens the Bluetooth device detail view.
- Wi-Fi SSID opens a grouped network detail view across all BSSIDs for that
  SSID.
- Wi-Fi BSSID opens one radio/AP detail view.
- Latitude/longitude text and APRS range filters open OpenStreetMap in a new
  browser tab. The browser linkifier recognizes canonical `lat, lon` text and
  APRS `r/lat/lon/radius` filters, so collectors should prefer those display
  forms instead of embedding provider-specific map URLs.

The detail view is browser-side and uses the currently loaded Subject History,
the Wi-Fi/Bluetooth compatibility payload, and Reports. It shows identity,
first/last seen, collector-specific context, signal or event counts when
available, related reports, and for SSIDs a BSSID radio table. This keeps the
main Reports rows compact while still preserving the evidence needed to inspect
a device, network, station, endpoint, event, or LAN subject.

The header contains:

- application title
- connection badge
- view-window selector

The connection badge reflects the browser event stream. The view-window selector
is populated from `~/.config/skannr/skannr.yaml`, `retention_days`, and optional
`view_window.default_days`. System Status uses concise availability wording for
hardware and keeps software checks in a separate column.

Collector tabs include compact status dots derived from the live collector
status snapshot. Single-collector tabs show one dot each. Bluetooth shows one
dot per Bluetooth-family collector. A filled dot means `ONLINE`; a hollow dot
means stopped, offline, retrying, disabled, or otherwise not online. Color is
only a secondary cue, with tooltips and ARIA labels carrying the exact collector
state. System Status shows an online/total collector summary instead of a dot;
Alerts shows total row count plus a separate unacknowledged-alert badge.

The dashboard uses local assets only. No CDN is required.

## 10. Manufacturer And Vendor Data

Skannr can resolve manufacturer names without internet access when local
registry files are present.

Wi-Fi vendor lookup:

- `src/skannr/data/collectors/oui.txt`: `https://standards-oui.ieee.org/oui/oui.txt`
- `src/skannr/data/collectors/mam.txt`: `https://standards-oui.ieee.org/oui28/mam.txt`
- `src/skannr/data/collectors/oui36.txt`: `https://standards-oui.ieee.org/oui36/oui36.txt`
- `src/skannr/data/collectors/iab.txt`: `https://standards-oui.ieee.org/iab/iab.txt`

The lookup uses longest-prefix matching. Locally administered MACs are shown as
locally administered/randomized when applicable.

Bluetooth company lookup:

- `src/skannr/data/collectors/company_identifiers.txt`: `https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers/`

Bluetooth UUID lookup:

- `src/skannr/data/collectors/member_uuids.txt`: Bluetooth SIG member/vendor UUID assignments,
  such as `0xFEAF` for Nest Labs Inc.
- `src/skannr/data/collectors/service_uuids.txt`: standard GATT service UUID assignments, such
  as `0x180A` for Device Information.
- `src/skannr/data/collectors/characteristic_uuids.txt`: standard GATT characteristic UUID
  assignments, such as `0x2A25` for Serial Number String.

Skannr reads these optional files in the copied Bluetooth SIG YAML-like format,
for example:

```yaml
uuids:
 - uuid: 0xFEAF
   name: Nest Labs Inc
```

When lookup files are missing or do not contain a prefix/identifier/UUID, Skannr
shows the raw OUI, company ID, or Bluetooth UUID.

Skannr does not update these files automatically.

## 11. Deployment

The normal local install/run path is:

```bash
SKANNR_DIR=/path/to/skannr
cd "$SKANNR_DIR"
python3 scripts/skannr_precheck.py
./install.sh
sudo env PYTHONPATH="$SKANNR_DIR/src" "$SKANNR_DIR/.venv/bin/python" -m skannr.main
```

The standalone precheck is recommended on a new host because it explains which
collectors have required software and selected hardware before config seeding.
`install.sh` also runs the precheck automatically when creating fresh config.

`install.sh` chooses a requirements file based on Python version:

- Python 3.6: `requirements/requirements-py36.txt`
- Python 3.7: `requirements/requirements-py37.txt`
- Python 3.8 and newer: `requirements/requirements-py38plus.txt`

System packages such as `rtl-sdr`, `aircrack-ng`, `bluetooth`, and `bluez` must
be installed separately.

For automatic startup, Skannr can run under systemd. Running as root is the
simplest setup because Wi-Fi monitor mode, packet capture, Bluetooth adapters,
and RTL-SDR devices often need elevated privileges or device permissions.

Remote access is controlled by `skannr.listeners`, a YAML list of quoted
endpoint strings:

- `"127.0.0.1:5004"`: local-only IPv4
- `"0.0.0.0:5004"`: all IPv4 interfaces
- `"[::]:5006"`: all IPv6 interfaces
- `"[specific IPv6 address]:5006"`: bind only that IPv6 address

One entry is valid; two entries are useful for simultaneous IPv4 and IPv6
access. Each enabled endpoint is bound before serving starts. The recommended
dual-stack configuration uses separate ports so behavior does not depend on
whether the OS allows IPv4-mapped IPv6 sockets. Endpoint strings should be
quoted, and IPv6 literals must use brackets:

```yaml
skannr:
  listeners:
    - "0.0.0.0:5004"
    - "[::]:5006"
```

IPv6 literal browser URLs require brackets:

```text
http://[200:...:abcd]:5006/
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

1. Add `~/.config/skannr/collectors/<key>.yaml` with key, label, order,
   `acquisition_mode`, validation commands, and collector-specific settings.
   Choose `scan`, `poll`, or `listen` based on how the collector obtains data.
2. Add `src/skannr/collectors/<key>.py` implementing a `BaseCollector` subclass.
3. Define the subject contract before adding Reports: stable `subject_id`,
   upstream `event_id` when present, material `fingerprint`, `event_time`,
   `updated`, `first_seen`, and `last_seen` semantics.
4. Decide whether the collector needs population Reports in addition to
   per-subject Reports. Population rows should answer "what pattern happened in
   the area/window?" while subject rows answer "which specific thing did it?"
5. Implement `hardware_status()` on the subclass if System Status needs static
   hardware or software probes.
6. Add the class to `COLLECTOR_CLASS_BY_KEY` in
   `src/skannr/collectors/__init__.py`.
7. If the collector contributes durable subjects, extend
   `SubjectHistoryBuilder.COLLECTORS` and add subject rollup logic. Wi-Fi and
   Bluetooth use the internal `WiFiBLEPostprocessor` for their rich device
   sessions, privacy grouping, and vendor enrichment.
8. If the collector is a poll feed, make its live tab upsert by the same
   source event/subject identity and apply the configured live-feed TTL when
   appropriate.
9. If the collector can emit Alerts, make the alert key line up with the
   subject/event key unless the rule intentionally needs a narrower key.
10. If the collector should appear in Insights or Reports, add rules in
   `history_analysis.py` or `reports.py`.
11. If the collector needs custom live UI, add markup in
   `src/skannr/static/index.html`, table schema in `src/skannr/static/tables.js`,
   and behavior in `src/skannr/static/app.js`.
12. Extend `scripts/validate_collector_contract.py` with examples that prove
    acquisition mode, subject identity, poll de-duplication, and alert keying
    for the new collector.

Collector metadata and derived-view source filters are already driven by YAML,
but collector class registration and domain-specific UI/history logic are still
explicit code changes. This is intentional for now: collector capture behavior
and history semantics differ enough that a fully dynamic plugin UI would add
complexity before the collector set stabilizes.

## 14. Known Limitations

- Subject History covers all registered collectors. System is omitted because it
  is runtime state rather than an observed subject source.
- Reports are deterministic summaries, not forensic conclusions.
- Per-collector limitations (channel coverage, protocol visibility, adapter
  behavior) are documented in each collector's section under §6.
- The built-in web server is for local/lightweight use, not hardened production
  hosting.

## 15. Current File Layout

```text
<skannr-dir>
  src/skannr/
    main.py
    config.py
    bus.py
    findings.py
    device_history.py
    subject_history.py
    history_analysis.py
    reports.py
    log_utils.py
    oui_lookup.py
    paths.py
    collectors/
      base.py
      hardware.py
      metadata.py
      wifi.py
      wifi_monitor.py
      ble.py
      ble_identify.py
      bt_classic.py
      rtl433.py
      adsb.py
      rayhunter.py
      aprsis.py
      noaa.py
      usgs.py
      swpc.py
      pws.py
      lan.py
      lan_identify.py
    persistence/
      base.py
      filesystem.py
      none.py
    static/
      index.html
      tables.js
      app.js
      style.css
    data/collectors/
      company_identifiers.txt
      member_uuids.txt
      oui.txt
      mam.txt
      oui36.txt
      iab.txt
  config/
    skannr.yaml                    # local, not source upload
    collectors/                    # local, not source upload
      wifi.yaml
      wifi_monitor.yaml
      ble.yaml
      ble_identify.yaml
      bt_classic.yaml
      rayhunter.yaml
      aprsis.yaml
  config.example/
    skannr.yaml                    # generic template
    collectors/
      wifi.yaml
      wifi_monitor.yaml
      ble.yaml
      ble_identify.yaml
      bt_classic.yaml
      rayhunter.yaml
      aprsis.yaml
  runtime/
    logs/
      <collector>/YYYY-MM-DD.jsonl
      device_history/subject_history.json
      device_history/device_history.json
      device_history/history_analysis.json
      device_history/reports.json
      skannr.log
  requirements/
    requirements*.txt
  install.sh
```

## 16. Design Decisions

- Use filesystem JSONL instead of SQLite to keep deployment simple and make raw
  logs easy to inspect.
- Materialize Subject History, Insights, Reports, and the Wi-Fi/Bluetooth
  compatibility view so refresh does not repeatedly scan all raw logs.
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
