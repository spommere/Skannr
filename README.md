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
- `history_analysis`: Insight thresholds
- `reports`: longitudinal Report thresholds
- `ui`: table limits, stale-data warning age, automatic derived refresh, Wi-Fi
  signal filter bands

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

Raw collector events are JSONL. Event timestamps are local time in:

```text
YYYY-MM-DD HH:MM:SS
```

Older UTC `YYYY-MM-DDTHH:MM:SSZ` logs remain readable.

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

Set `derived_auto_refresh_min: 0` to disable automatic derived refresh. The
status line shows the last refresh time and the next automatic refresh countdown.
The Manual Refresh button is still available when you want an immediate rebuild.

Manual or automatic refresh of any derived tab refreshes the whole derived bundle
in dependency order:

1. Findings History
2. Device History
3. history-based Insights
4. Reports

Device History and Findings History are materialized summaries with JSONL
checkpoints. After the first build, refresh normally reads only new raw-log
bytes, not all old logs again.

The header View selector defaults to `retention_days`. You can override only the
dashboard default without changing log retention:

```yaml
view_window:
  default_days: 7
```

## Collector Validation

Each collector YAML can define primary and fallback validation commands:

```yaml
primary_validation: test -d /sys/class/net/{preferred_interface}
fallback_validation: test -d /sys/class/net/{fallback_interface}
validation_timeout_sec: 10
```

Placeholders such as `{preferred_interface}`, `{fallback_adapter}`, `{host}`, or
`{port}` are filled from the collector YAML.

Use `none` to disable a tier:

```yaml
fallback_validation: none
```

Validation status appears in System Status. A collector can be offline because
software is missing, hardware is absent, or the validation command failed.

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

The Bluetooth tab combines three related collectors.

### BLE Scan

`BLE Scan` passively reads BLE advertisements with `bleak` and BlueZ.

Default config:

```text
collectors/ble.yaml
```

Defaults prefer `hci1` and fall back to `hci0`. BLE visibility depends on
adapter behavior, BlueZ state, and whether nearby devices are advertising.

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

Default config:

```text
collectors/ble_identify.yaml
```

It attempts to read selected Device Information Service fields:

- Manufacturer Name (`2A29`)
- Model Number (`2A24`)
- Firmware Revision (`2A26`)
- Hardware Revision (`2A27`)
- Software Revision (`2A28`)

Skannr does not read or store Serial Number (`2A25`) by default. Many devices
reject active connections, require pairing, or stop advertising before the read
finishes.

## RTL-SDR

`RTL-SDR` uses `rtl_power` for passive spectrum scanning.

Default config:

```text
collectors/rtlsdr.yaml
```

Default validation requires:

```yaml
primary_validation: command -v rtl_power >/dev/null 2>&1 && command -v rtl_test >/dev/null 2>&1 && rtl_test -t
fallback_validation: none
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
- preferred interface or adapter absent
- fallback validation disabled
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
