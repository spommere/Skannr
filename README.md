# Skannr

Skannr is a local wireless monitoring dashboard for Wi-Fi, Bluetooth, and
RTL-SDR signals. It runs on Linux hosts such as Raspberry Pi OS or Kali, records
local JSONL event logs, and provides live views plus deterministic Insights,
Device History, and Reports through a browser UI.

Skannr is designed for local monitoring of your own environment. It does not
perform wireless attacks, packet injection, or cloud-based analysis.

For architecture, event flow, collector internals, and extension notes, see
[`DESIGN.md`](DESIGN.md).

## Project Files

- `README.md`: operator manual and day-to-day setup/use instructions
- `DESIGN.md`: architecture, data flow, collector model, and extension details
- `LICENSE`: project license
- `VERSION`: current application version
- `CHANGELOG.md`: release notes and versioning policy
- `skannr.yaml`: local runtime configuration, created on first run
- `collectors/*.yaml`: collector-specific configuration
- `collectors/*.py`: collector implementations and their hardware probes

Current version: see `VERSION`.

Versioning policy:

- `0.1.x`: bug fixes and documentation updates
- `0.2.0`: meaningful feature additions or data format changes
- `1.0.0`: stable operator-facing behavior and config/log compatibility

The rest of this README is the operator manual.

## Quick Start

```bash
SKANNR_DIR=/path/to/skannr
cd "$SKANNR_DIR"
./install.sh
sudo "$SKANNR_DIR/.venv/bin/python" main.py
```

Open:

```text
http://127.0.0.1:5000/
```

The first run creates `skannr.yaml` if it does not already exist. Existing
YAML is not rewritten on startup.

## Install System Packages

Python requirements do not install OS tools such as `rtl_power`, `iw`,
`airmon-ng`, Bluetooth utilities, or BlueZ.

On Debian, Kali, or Raspberry Pi OS:

```bash
sudo apt update
sudo apt install rtl-sdr librtlsdr-dev aircrack-ng bluetooth bluez wireless-tools iw
```

The installer creates `.venv` and chooses the Python requirements file by Python
version:

- Python 3.6: `requirements-py36.txt`
- Python 3.7: `requirements-py37.txt`
- Python 3.8 and newer: `requirements-py38plus.txt`

The Python dependencies include Flask, Flask-SocketIO, `simple-websocket`,
`bleak`, and `scapy` as appropriate for the local Python version.

To refresh an existing virtual environment after requirement changes:

```bash
SKANNR_DIR=/path/to/skannr
cd "$SKANNR_DIR"
./install.sh
. .venv/bin/activate
python3 -m pip show bleak scapy flask simple-websocket
```

## Run Skannr

Foreground run:

```bash
SKANNR_DIR=/path/to/skannr
cd "$SKANNR_DIR"
sudo "$SKANNR_DIR/.venv/bin/python" main.py
```

Use `sudo` for the simplest setup. Wi-Fi monitor mode, Bluetooth adapters,
RTL-SDR devices, and packet capture usually need root or equivalent Linux
capabilities/device permissions.

To use a non-default config path:

```bash
SKANNR_DIR=/path/to/skannr
sudo "$SKANNR_DIR/.venv/bin/python" "$SKANNR_DIR/main.py" --config "$SKANNR_DIR/skannr.yaml"
```

## Browser Access

By default Skannr listens only on local IPv4:

```yaml
skannr:
  host: 127.0.0.1
  port: 5000
```

For LAN IPv4 access:

```yaml
skannr:
  host: 0.0.0.0
  port: 5000
```

For IPv6, including overlay networks such as Yggdrasil:

```yaml
skannr:
  host: "::"
  port: 5000
```

Restart Skannr after changing `skannr.host`.

IPv6 literal browser URLs require brackets:

```text
http://[200:...:abcd]:5000/
```

Skannr serves plain HTTP. If using Brave/Safari, make sure the browser has not
changed the URL to `https://`. If you use a Yggdrasil address, the browser
device also needs Yggdrasil connectivity or another route to that address.

To verify the listener on the Skannr machine:

```bash
ss -ltnp | grep 5000
```

To verify access from another machine:

```bash
curl -g 'http://[IPv6_ADDRESS]:5000/collector_metadata'
```

## Run As A systemd Service

Create `/etc/systemd/system/skannr.service`:

```ini
[Unit]
Description=Skannr wireless monitoring dashboard
After=network-online.target bluetooth.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/path/to/skannr
ExecStart=/path/to/skannr/.venv/bin/python /path/to/skannr/main.py --config /path/to/skannr/skannr.yaml
Restart=on-failure
RestartSec=5
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

Install and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable skannr
sudo systemctl start skannr
```

Check status and logs:

```bash
sudo systemctl status skannr
sudo journalctl -u skannr -f
```

Stop or restart:

```bash
sudo systemctl stop skannr
sudo systemctl restart skannr
```

## Configuration Files

Global settings live in:

```text
skannr.yaml
```

Collector-specific settings live in:

```text
collectors/<collector>.yaml
```

Important global sections:

- `skannr`: listen host, port, log level
- `persistence`: log directory and retention
- `runtime`: queue/status timing knobs
- `findings`: live deterministic finding thresholds
- `history_analysis`: Insight thresholds and recent-event lookback
- `reports`: longitudinal Report thresholds
- `ui`: table limits, Bluetooth live-row age, stale-data warning age, and
  automatic derived refresh

The Reports section includes Bluetooth privacy-address grouping:

```yaml
reports:
  ble_private_address_group_min_count: 3
  new_device_window_sec: 3600
```

Unnamed/private BLE addresses at or above this count are summarized by
manufacturer instead of being reported as separate new physical devices.
`new_device_window_sec` controls how recent a first sighting must be before
Reports call a Wi-Fi AP, Wi-Fi client, or named/static Bluetooth device "new".

Changing YAML settings requires restarting Skannr so the browser receives the
new metadata and collector configuration.

## Logs, Retention, And Derived Data

Runtime files are written under `<skannr-dir>/logs` by default:

```text
logs/<collector>/YYYY-MM-DD.jsonl
logs/skannr.log
logs/device_history/device_history.json
logs/device_history/findings_history.json
logs/device_history/history_analysis.json
logs/device_history/reports.json
```

Raw collector events are JSONL. Skannr uses epoch seconds internally for time
comparisons and durations. UI-facing local timestamps are derived from those
epoch values on the Skannr host where the data is collected and shown in:

```text
YYYY-MM-DD HH:MM:SS
```

New event and summary records include both forms, for example
`timestamp_epoch` plus `timestamp`, or `last_seen_epoch` plus `last_seen`.
The browser uses epoch values for age/delta calculations only; it does not parse
or reformat Skannr timestamp strings in the browser machine's timezone.

Retention is controlled by:

```yaml
persistence:
  filesystem:
    retention_days: 30
```

`retention_days` must be `0` or greater:

- `0`: delete retained JSONL logs during startup rotation
- `30`: keep roughly 30 days
- `999999`: effectively disable cleanup

Insights, Reports, and Device History use the selected dashboard View window.
Skannr refreshes those derived views automatically while the browser page is
open. The default interval is 15 minutes:

```yaml
ui:
  derived_auto_refresh_min: 15
```

The three derived views have different jobs:

- Insights: recent event log, tactical/debuggable.
- Reports: ranked intelligence summary, strategic/operator-facing.
- Device History: state database view.

Insights are intentionally shorter-lived than Reports or Device History. They
use the selected dashboard View window as an upper bound, then apply the
configured recent-event lookback:

```yaml
history_analysis:
  insights_recent_hours: 6
```

Set `insights_recent_hours: 0` to show every Insight in the selected View
window. Reports and Device History are not shortened by this setting.

Set `derived_auto_refresh_min: 0` to disable automatic derived refresh. The
status line shows the last refresh time and the next automatic refresh countdown.
If the browser wakes up with stale derived data, it starts an immediate catch-up
refresh instead of waiting for the next interval. Refresh failures stay visible
in the status line until a later refresh succeeds. The Manual Refresh button is
still available when you want an immediate rebuild. Browser wake/focus events
also reload the derived view from the backend, which helps after a laptop sleeps
while the Pis keep collecting.

After a fresh log cleanup, the browser may initially load empty cached derived
summaries before the first scan events have been folded into Device History. If
live Wi-Fi/Bluetooth rows arrive, or collector status shows scan events have
already happened while Device History is still empty, the browser starts a
throttled catch-up refresh instead of waiting for the normal automatic refresh
interval.

A successful derived refresh also backfills the live Wi-Fi Scan and BLE Scan
tables from Device History. This keeps those scan rows current when the browser
missed live events while the collectors and raw logs kept running.

The BLE Scan table is a live/recent view. The browser periodically repaints it
so devices age out after `ui.bluetooth_live_recent_sec` even if no new BLE event
arrives after the client wakes from sleep. Device History includes numeric epoch
fields next to display timestamps, so recent filtering and duration math do not
depend on the browser interpreting Pi-local timestamp strings. Displayed
timestamps remain the strings generated by the Skannr host.

Manual or automatic refresh of any derived tab refreshes the whole derived bundle
in dependency order:

1. Findings History
2. Device History
3. history-based Insights
4. Reports

Device History and Findings History are materialized summaries with JSONL
checkpoints. After the first build, refresh normally reads only new raw-log
bytes, not all old logs again.

Reports has a Type filter for broad report families such as security, presence,
signal, new-device, behavior, identity, collector, and analysis. The summary
line above the table shows the most common report families in the current
source-filter/type-filter/search view.
Bluetooth Reports are device-centric: stable BLE MACs are consolidated into one
profile row per device, while unnamed/private BLE address rotation is summarized
as manufacturer clusters.
Wi-Fi Reports follow the same model: AP-level findings are consolidated into
one profile row per BSSID, while SSID-level behavior such as multiple BSSIDs is
reported as a separate SSID profile.
The Reports Evidence column is formatted as operator-readable context, for
example `Pattern`, `Observed`, and `Radio`, instead of exposing raw internal
field names such as `common_hours` or `presence_spans`. In the browser those
evidence items are rendered as stacked labeled lines for readability. Related
context is folded together where it improves readability: session state is part
of `Observed`, Wi-Fi security is part of `Radio`, and strong-signal findings
carry their signal value on the `Findings` line.

Device History does not include System in its Source filter because System
events are not device histories. System events can still appear in Insights and
Reports when they are actionable.

The header View selector defaults to `retention_days`. You can override only the
dashboard default without changing log retention:

```yaml
view_window:
  default_days: 7
```

## Collector Validation

Collector YAML files own their own hardware and software checks. For adapters
and interfaces, use ordered candidate lists. When the list is empty, Skannr
uses the devices Linux currently exposes:

```yaml
interfaces: []
adapters: []
validation_timeout_sec: 10
```

Some collectors also have a command-based validation. The command is formatted
with collector YAML keys, run with a timeout, and considered available only
when it exits with status 0:

```yaml
validation: command -v rtl_power >/dev/null 2>&1 && command -v rtl_test >/dev/null 2>&1 && rtl_test -t
```

System Status translates validation into operator-facing availability wording.
For example, hardware rows say `hci0: available`, `hci1: unavailable`, and
`active: hci0` instead of showing shell exit codes. Detailed validation
failures remain in logs/events for troubleshooting.

## Wi-Fi Scan

`Wi-Fi Scan` is the lightweight managed-mode collector.

It:

- uses one scan source per collector run
- prefers `iw dev <iface> scan`
- uses `iwlist <iface> scan` only when `iw` is absent or `scan_tool: iwlist`
  is configured
- lists visible access points
- records SSID, BSSID, vendor, channel/frequency, encryption, RSSI, and time
- can run on a normal managed Wi-Fi interface

The live table has one Search box that matches across SSID, BSSID, vendor,
channel/frequency, encryption, signal, and last-seen time.

It does not see probe requests, associations, deauth frames, or monitor-mode
traffic. Those belong to `Wi-Fi Monitor`.

Default config:

```text
collectors/wifi.yaml
```

## Wi-Fi Monitor

`Wi-Fi Monitor` is on demand and requires a Wi-Fi interface that is already in
monitor mode.

It:

- uses Scapy packet capture
- channel-hops across configured/supported 2.4 GHz and 5 GHz channels
- records probe requests, AP beacons, associations, disassociations, and deauth
  frames
- folds AP and client observations into Wi-Fi Device History

Skannr does not automatically put an adapter into monitor mode. Prepare a
separate adapter first, then click Start in System Status or the Wi-Fi Monitor
tab.

If no monitor-mode client/probe frames have been summarized for the selected
view, Device History shows an explicit no-data message under Wi-Fi Monitor.
That does not mean AP scanning is broken; AP observations are shown under
Wi-Fi Access Points.

Default config:

```text
collectors/wifi_monitor.yaml
```

Useful settings:

```yaml
interface: auto
bands:
- '2.4'
- '5'
typical_channels_24:
- 1
- 6
- 11
typical_channels_5:
- 36
- 40
- 44
- 48
- 149
- 153
- 157
- 161
- 165
include_seen_channels: false
dwell_sec: 1
```

## Bluetooth

The Bluetooth tab combines BLE Scan, Bluetooth Classic Scan, and BLE Identify
activity. BLE Identify is an internal on-demand Bluetooth action, not a System
Status collector row. Adapter availability is shown once through BLE Scan and
Bluetooth Classic.

### BLE Scan

`BLE Scan` passively reads BLE advertisements with `bleak` and BlueZ.
The live table shows only devices seen within `ui.bluetooth_live_recent_sec`
seconds, default `600`. Older BLE rows remain in Device History and Reports
but are hidden from the live table.
The Services column decodes common Bluetooth SIG service UUIDs, such as
`180A` to `Device Information`; vendor-specific UUIDs are left visible.
The live table has one Search box that matches across MAC, name, manufacturer,
RSSI, decoded services, and last-seen time.

Default config:

```text
collectors/ble.yaml
```

Use `adapters: []` to let Skannr rank the BlueZ adapters Linux exposes. External
USB adapters are normally chosen before built-in radios. List specific adapters
in order when you want to force a local choice. BLE visibility depends on adapter
behavior, BlueZ state, and whether nearby devices are advertising.

### Bluetooth Classic

`Bluetooth Classic` is on demand. It runs inquiry scans for discoverable classic
Bluetooth devices such as some laptops, phones, headsets, and watches.

Default config:

```text
collectors/bt_classic.yaml
```

Start it manually from the Bluetooth tab or System Status.

### BLE Identify

`BLE Identify` is on demand and actively connects to one selected BLE MAC.
Identify buttons are shown directly on recent BLE Scan rows. The Identify
activity log stays below the BLE Scan table and is not limited by the recent
device window.

Default config:

```text
collectors/ble_identify.yaml
```

It attempts to read selected Device Information Service fields:

- Manufacturer Name (`2A29`)
- Model Number (`2A24`)
- Serial Number (`2A25`)
- Firmware Revision (`2A26`)
- Hardware Revision (`2A27`)
- Software Revision (`2A28`)
- PnP ID (`2A50`)

Many devices reject active connections, require pairing, omit individual fields,
or stop advertising before the read finishes. Serial Number can be uniquely
identifying, so treat exported Identify data accordingly.

## RTL-SDR

`RTL-SDR` uses `rtl_power` for passive spectrum scanning.

Default config:

```text
collectors/rtlsdr.yaml
```

Default validation requires:

```yaml
validation: command -v rtl_power >/dev/null 2>&1 && command -v rtl_test >/dev/null 2>&1 && rtl_test -t
```

If `rtl_test -t` reports no supported device, the collector stays offline.

Common settings:

```yaml
scan_start_mhz: 400
scan_end_mhz: 470
step_khz: 50
gain: 40
threshold_db: 10
baseline_period_sec: 30
```

## Wi-Fi Manufacturer Names

Skannr can map Wi-Fi BSSIDs and client MACs to offline IEEE manufacturer data.
Place any of these files under `collectors/`:

- `collectors/oui.txt`: `https://standards-oui.ieee.org/oui/oui.txt`
- `collectors/mam.txt`: `https://standards-oui.ieee.org/oui28/mam.txt`
- `collectors/oui36.txt`: `https://standards-oui.ieee.org/oui36/oui36.txt`
- `collectors/iab.txt`: `https://standards-oui.ieee.org/iab/iab.txt`

Skannr parses classic OUI `(hex)` rows and MA-M/MA-S/IAB `(base 16)` ranges,
then uses longest-prefix matching. When a MAC has the locally administered bit
set, Skannr identifies it as locally administered/randomized.

Skannr does not download or update these files. Replace them manually and
restart Skannr to rebuild the in-memory lookup cache.

The Wi-Fi manufacturer files currently bundled in this scratch tree were
sourced on 2026-05-18.

## BLE Manufacturer Names

BLE advertisements may include Bluetooth SIG company identifiers such as
`0x004C`. Skannr can resolve these IDs offline if this file exists:

- `collectors/company_identifiers.txt`: copied content from `https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers/`

Expected content format:

```yaml
- value: 0x10C4
  name: 'OPICA GmbH'

- value: 0x004C
  name: 'Apple, Inc.'
```

When the file is missing or an ID is not listed, Skannr keeps showing the raw
ID, for example `0x004C`.

Skannr does not download or update this file. Replace it manually and restart
Skannr to rebuild the in-memory lookup cache.

The BLE company identifier file currently bundled in this scratch tree was
sourced on 2026-05-18.

## Package For Another Machine

Create a portable archive from the parent of the checkout directory without the
virtual environment, runtime logs, bytecode caches, or machine-generated config:

```bash
cd /path/to/parent
tar \
  --exclude='skannr/.venv' \
  --exclude='skannr/__pycache__' \
  --exclude='skannr/*/__pycache__' \
  --exclude='skannr/logs' \
  --exclude='skannr/skannr.yaml' \
  -czf skannr.tar.gz skannr
```

Copy `skannr.tar.gz` to the target machine, then install:

```bash
tar -xzf skannr.tar.gz
cd skannr
./install.sh
sudo ./.venv/bin/python main.py
```

Install system packages on the target as needed.

## Troubleshooting

### Browser Cannot Connect

Check the configured bind address:

```bash
SKANNR_DIR=/path/to/skannr
grep -n "host\\|port" "$SKANNR_DIR/skannr.yaml"
ss -ltnp | grep 5000
```

Use `host: 0.0.0.0` for IPv4 LAN access or `host: "::"` for IPv6 access.
Restart Skannr after changing the config.

### Brave Or Safari Changes HTTP To HTTPS

Skannr serves plain HTTP. Use:

```text
http://<host>:5000/
```

or:

```text
http://[IPv6_ADDRESS]:5000/
```

Disable HTTPS upgrade features for the site if the browser keeps forcing
`https://`.

### Collector Is Offline

Open System Status and read the collector Warning column. Common causes:

- Python package missing from `.venv`
- OS command missing from `PATH`
- configured interface or adapter absent
- RTL-SDR installed but no dongle connected
- Wi-Fi Monitor started without a monitor-mode interface
- BlueZ adapter wedged or busy

### Root-Owned Bytecode Or Logs

If Skannr was run with `sudo`, Python may create root-owned `__pycache__`
directories or logs. It is safe to delete `__pycache__` directories. Runtime
logs can also be deleted if you do not need the history.

To list root-owned files outside the virtual environment:

```bash
SKANNR_DIR=/path/to/skannr
find "$SKANNR_DIR" -path "$SKANNR_DIR/.venv" -prune -o -user root -print
```
