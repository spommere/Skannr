# Skannr

Skannr is a local monitoring dashboard for Wi-Fi, Bluetooth, RTL-SDR signals,
optional APRS-IS/NOAA/USGS/SWPC/PWS situational context, and passive LAN
observations. It runs on Linux hosts such as Raspberry Pi OS or Kali, records
local JSONL event logs, and provides live views plus deterministic Insights,
Subject History, Alerts, and Reports through a browser UI.

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
- `src/skannr/`: Python package, collector code, shipped UI, and bundled lookup data
- `config.example/`: generic config template for source upload and fresh installs
- `config/`: local runtime configuration, created from `config.example/` by `install.sh`
- `runtime/`: generated logs, materialized views, and runtime state
- `requirements/*.txt`: Python dependency manifests

Current version: see `VERSION`.

Versioning policy:

- `0.1.x`: bug fixes and documentation updates
- `0.2.x`: meaningful feature additions or data format changes
- `1.0.0`: stable operator-facing behavior and config/log compatibility

The rest of this README is the operator manual.

## Quick Start

```bash
SKANNR_DIR=/path/to/skannr
cd "$SKANNR_DIR"
./install.sh
sudo env PYTHONPATH="$SKANNR_DIR/src" "$SKANNR_DIR/.venv/bin/python" -m skannr.main
```

Open:

```text
http://127.0.0.1:5004/
```

`install.sh` creates local `config/` from `config.example/` if
`config/skannr.yaml` does not already exist. Existing YAML is not overwritten.

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

- Python 3.6: `requirements/requirements-py36.txt`
- Python 3.7: `requirements/requirements-py37.txt`
- Python 3.8 and newer: `requirements/requirements-py38plus.txt`

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
sudo env PYTHONPATH="$SKANNR_DIR/src" "$SKANNR_DIR/.venv/bin/python" -m skannr.main
```

Use `sudo` for the simplest setup. Wi-Fi monitor mode, Bluetooth adapters,
RTL-SDR devices, and packet capture usually need root or equivalent Linux
capabilities/device permissions.

To use a non-default config path:

```bash
SKANNR_DIR=/path/to/skannr
sudo env PYTHONPATH="$SKANNR_DIR/src" "$SKANNR_DIR/.venv/bin/python" -m skannr.main --config "$SKANNR_DIR/config/skannr.yaml"
```

For live troubleshooting, start with `--debug`:

```bash
SKANNR_DIR=/path/to/skannr
sudo env PYTHONPATH="$SKANNR_DIR/src" "$SKANNR_DIR/.venv/bin/python" -m skannr.main --debug
```

Debug mode raises log verbosity to `DEBUG` and writes to `runtime/logs/skannr.log`. If
Skannr is started from a graphical desktop with a supported terminal available,
it also opens a small live `tail -F` log window. Headless and systemd runs keep
logging to `runtime/logs/skannr.log`; use `tail -f runtime/logs/skannr.log` from
another shell.

## Browser Access

Skannr listens on the endpoints listed under `skannr.listeners`. YAML uses `-`
for list items, so this is standard YAML sequence syntax. Put each endpoint in
quotes; IPv4 often parses without quotes, but bracketed IPv6 does not:

```yaml
skannr:
  listeners:
    - "127.0.0.1:5004"
```

For LAN IPv4 access:

```yaml
skannr:
  listeners:
    - "0.0.0.0:5004"
```

For IPv6, including overlay networks such as Yggdrasil:

```yaml
skannr:
  listeners:
    - "[::]:5006"
```

Restart Skannr after changing `skannr.listeners`.

To listen on one or more explicit endpoints, use `skannr.listeners`. One entry
is valid; two entries are useful when you want IPv4 and IPv6 at the same time.
Separate ports are the most reliable dual-stack configuration because same-port
IPv4/IPv6 binding depends on OS socket defaults. Quote every endpoint string,
and use brackets for IPv6 literals:

```yaml
skannr:
  listeners:
    - "0.0.0.0:5004"
    - "[::]:5006"
```

Browser URLs for this example:

```text
http://<IPv4_ADDRESS>:5004/
http://[IPv6_ADDRESS]:5006/
```

IPv6 literal browser URLs require brackets:

```text
http://[200:...:abcd]:5006/
```

Skannr serves plain HTTP. If using Brave/Safari, make sure the browser has not
changed the URL to `https://`. If you use a Yggdrasil address, the browser
device also needs Yggdrasil connectivity or another route to that address.

To verify the listener on the Skannr machine:

```bash
ss -ltnp | grep -E '5004|5006'
```

To verify access from another machine:

```bash
curl -g 'http://[IPv6_ADDRESS]:5006/collector_metadata'
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
Environment=PYTHONPATH=/path/to/skannr/src
ExecStart=/path/to/skannr/.venv/bin/python -m skannr.main --config /path/to/skannr/config/skannr.yaml
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

Global settings live in the local runtime config:

```text
config/skannr.yaml
```

Collector-specific settings live in:

```text
config/collectors/<collector>.yaml
```

Generic defaults for source upload and fresh installs live under
`config.example/`. On a new machine, run `./install.sh` or copy them manually:

```bash
cp -a config.example/. config/
```

Changing YAML settings requires restarting Skannr so the browser receives the
new metadata and collector configuration.

### Post-Install Local YAML Checklist

After `./install.sh`, review these local files on each Skannr host. The files
under `config/` are machine-specific; do not edit `config.example/` for a live
Pi unless you are intentionally changing the shipped template.

- `config/skannr.yaml`
  - Set `skannr.listeners` to the HTTP endpoints Skannr should bind, such as
    `127.0.0.1:5004`, `0.0.0.0:5004`, or `[::]:5006`.
  - Review `persistence.filesystem.retention_days` and
    `persistence.filesystem.log_dir` if the host has limited storage or a
    custom runtime path.
- `config/collectors/aprsis.yaml`
  - Set `enabled: true` only when this host should use APRS-IS.
  - Set `callsign` and `passcode`; use `-1` only for read-only/NOCALL-style
    testing.
  - Set each feed `host`, `port`, and `filter`. For a local-area stream, use
    port `14580` and a range filter such as `r/<lat>/<lon>/<km>`.
  - For CWOP/weather, keep a separate weather feed when needed and use
    `enforce_radius: true` if the server returns out-of-range packets.
  - Use `preferred_server` only when you deliberately want to reconnect until a
    pooled backend such as `CWOP-4` is selected.
- `config/collectors/noaa.yaml`
  - Set `enabled: true` only when internet-fed NOAA/NWS/NHC context is wanted.
  - Set `latitude` and `longitude` for the monitored point.
  - Optionally set `state` for broader NWS state context.
  - NWS point forecast summaries default on when `nws.enabled` is true and
    `latitude` / `longitude` are configured. Use `forecast.enabled: false` only
    if you want NWS alerts/NHC advisories without local forecast context.
  - Review `nws.enabled`, `nhc.enabled`, and `nhc.basins` for the local area.
- `config/collectors/usgs.yaml`
  - Set `enabled: true` only when USGS earthquake context is wanted.
  - Set `latitude`, `longitude`, `radius_km`, and `min_magnitude` for the area
    and noise level you care about.
- Optional collector files
  - `config/collectors/rayhunter.yaml`: set `endpoint` for the Rayhunter device.
  - `config/collectors/swpc.yaml`: enable if SWPC space-weather context is
    wanted; defaults focus on X flares and R3/S3/G3/Kp7+ conditions.
  - `config/collectors/pws.yaml`: enable if this host should poll an Ambient
    Weather personal weather station. Set `application_key`, `api_key`, and an
    optional stable `station_id` such as `GW0154` in local `config/` only.
  - `config/collectors/lan.yaml`: enable if passive LAN neighbor/default-gateway
    context is wanted.
  - `config/collectors/wifi*.yaml`, `ble.yaml`, `bt_classic.yaml`, and
    `rtlsdr.yaml`: review adapter/interface/device settings for the hardware
    attached to this host.

Restart Skannr after changing any YAML:

```bash
sudo systemctl restart skannr
```

## YAML Parameter Reference

The only shipped YAML files are:

- `config/skannr.yaml`: global runtime, persistence, analysis, report, alert,
  and UI settings
- `config/collectors/*.yaml`: one collector or action per file

`config.example/` carries generic templates for source upload and fresh
installs. `config/` is machine-specific local state.

### Global `skannr.yaml`

`skannr`:

- `listeners`: quoted `host:port` or `[IPv6]:port` HTTP listener strings.
- `log_level`: Python logging level such as `INFO` or `DEBUG`.

`persistence`:

- `backend`: persistence implementation. The current implementation is
  `filesystem`.
- `filesystem.log_dir`: runtime log/materialized-state directory. Relative
  paths are resolved under the Skannr project root.
- `filesystem.retention_days`: raw JSONL retention. `0` removes retained JSONL
  at startup rotation; large values effectively disable cleanup.

`runtime`:

- `event_log_maxlen`: in-memory recent-event count retained for browser
  snapshots.
- `sse_queue_size`: per-browser Server-Sent Events queue size before old events
  are dropped for that client.
- `sse_heartbeat_sec`: heartbeat interval for keeping `/events` connections
  alive.
- `system_status_interval_sec`: collector/system status broadcast cadence.
- `shutdown_timeout_sec`: graceful stop timeout for collector tasks.

`findings` controls live, low-memory event findings:

- `enabled`: turn live findings on/off.
- `max_items`: recent finding count kept in memory for browser snapshots.
- `bootstrap_events`: persisted event count replayed on startup to rebuild
  live-finding state.
- `strong_wifi_rssi`, `strong_wifi_ap_rssi`, `strong_ble_rssi`: dBm thresholds
  for strong Wi-Fi client/AP and BLE findings.
- `rssi_change_db`: minimum RSSI delta before reporting a signal change.
- `return_after_sec`, `lost_after_sec`: disappearance/reappearance windows.
- `burst_window_sec`, `burst_count`: burst detector window and count.
- `cooldown_sec`: per-finding de-duplication interval.
- `persistent_signal_sec`: minimum duration for a persistent signal finding.
- `aprs_move_km`: APRS station movement distance for a motion finding.
- `aprs_temp_change_f`: APRS weather temperature-change threshold.
- `aprs_rain_1h_high_in`: APRS weather high one-hour rain threshold.
- `aprs_wind_high_mph`, `aprs_gust_high_mph`: APRS wind/gust thresholds.
- `pws_temp_change_f`, `pws_rain_1h_high_in`, `pws_wind_high_mph`,
  `pws_gust_high_mph`: PWS weather change/rain-rate/wind thresholds.
- `noaa_upgrade_severities`: NWS severity names that become upgrade findings.
- `usgs_warning_magnitude`, `usgs_warning_distance_km`: USGS live warning
  threshold and local-distance threshold.
- `swpc_warning_xray_class`: minimum GOES X-ray flare class that becomes a
  warning Insight. The default is `X1.0`; M/C flares are not warning Insights
  by default.
- `swpc_warning_radio_blackout`, `swpc_warning_solar_radiation_storm`,
  `swpc_warning_geomagnetic_storm`, `swpc_warning_kp`: SWPC R/S/G/Kp warning
  Insight thresholds. Defaults are `R3`, `S3`, `G3`, and Kp `7`.
- `lan_return_after_sec`: LAN return-after-missing threshold.

`alerts` controls high-attention live alerts:

- `enabled`: turn AlertEngine on/off.
- `max_items`: maximum active/remembered alert rows kept in memory.
- `active_ttl_sec`: unacknowledged alert lifetime if the condition stops
  recurring.
- `dedupe_sec`: repeat window for coalescing the same unacknowledged alert.
  ACKed active alerts stay ACKed unless their level escalates.
- `ack_memory_ttl_sec`, `ack_memory_alert_types`: optional memory for
  long-running alert families. By default, ACKed NOAA/NHC hazard advisories are
  remembered for seven days so routine advisory-number updates do not require
  repeated ACKs.
- Every rule has `enabled` and `level`; some also have `critical_level`.
- `drone_wifi.min_rssi`, `ssid_patterns`, `vendor_patterns`, `oui_prefixes`:
  DJI/Remote ID style Wi-Fi alert matching.
- `aprs_weather.rain_1h_in`, `critical_rain_1h_in`, `wind_gust_mph`,
  `critical_wind_gust_mph`: APRS weather alert thresholds.
- `pws_weather.rain_1h_in`, `critical_rain_1h_in`, `wind_gust_mph`,
  `critical_wind_gust_mph`: PWS weather alert thresholds.
- `rayhunter_warning`: alerts when Rayhunter reports non-zero warnings.
- `wifi_disruption.window_sec`, `count`: deauth/disruption burst alert window.
- `wifi_open_sensitive.ssid_patterns`: open SSIDs that should alert.
- `ble_tracker.min_rssi`, `name_patterns`, `manufacturer_patterns`,
  `service_uuid_patterns`: tracker-like BLE alert matching.
- `collector_issue.ignored_reason_patterns`: reason patterns suppressed when
  generic collector issue alerts are enabled. The rule is disabled by default
  because System Status already shows collector setup problems.
- `noaa_hazard.critical_events`, `critical_severities`: NWS/NHC hazard terms
  and severities that escalate to the critical level.
- `usgs_earthquake.warning_magnitude_nearby`,
  `critical_magnitude_nearby`, `nearby_radius_km`,
  `critical_alert_colors`: earthquake alert thresholds.
- `swpc_space_weather.alert_min_xray_class`, `alert_min_radio_blackout`,
  `alert_min_solar_radiation_storm`, `alert_min_geomagnetic_storm`,
  `alert_min_kp`: SWPC alert thresholds. Defaults are `X1.0`, `R3`, `S3`,
  `G3`, and Kp `7`.
- `swpc_space_weather.critical_min_xray_class`,
  `critical_min_radio_blackout`, `critical_min_solar_radiation_storm`,
  `critical_min_geomagnetic_storm`, `critical_min_kp`: SWPC critical alert
  thresholds. Defaults are `X5.0`, `R4`, `S4`, `G4`, and Kp `8`.
- `lan_gateway_change`: alerts on default-gateway changes.
- `lan_new_device`: alerts on new LAN devices. It is off by default because
  normal LANs can be noisy.

`history_analysis` controls tactical Insights from Subject History:

- `new_device_window_sec`: how recent first-seen must be to call something new.
- `strong_wifi_rssi`, `strong_ble_rssi`: strong-signal Insight thresholds.
- `many_bssid_count`: BSSID count that makes an SSID look multi-BSSID.
- `wifi_same_ap_bssid_prefix_bytes`, `wifi_same_ap_max_last_byte_span`: BSSID
  similarity heuristic for one AP family.
- `many_probe_ssid_count`, `blank_probe_count`, `deauth_count`: Wi-Fi Monitor
  activity thresholds.
- `randomized_mac_count`: randomized/private MAC churn threshold.
- `ble_linger_sec`, `ble_lost_count`, `ble_recurring_min_sessions`,
  `ble_recurring_window_min`: BLE presence/loss/recurrence thresholds.
- `recent_activity_window_sec`: recent activity window for tactical Insights.
- `insights_recent_hours`: upper age bound for Insights within the selected
  dashboard View. `0` shows the whole selected View.
- `wifi_short_lived_sec`: short-lived Wi-Fi AP/session threshold.
- `sensitive_ssids`: SSID names/patterns treated as sensitive.

`reports` controls longer-window intelligence Reports:

- `ble_long_presence_sec`, `ble_recurring_min_days`,
  `ble_private_address_group_min_count`, `ble_strong_rssi`: BLE report
  thresholds.
- `new_device_window_sec`: new-subject report window.
- `wifi_strong_rssi`, `wifi_signal_swing_db`, `wifi_many_bssid_count`,
  `wifi_recurring_min_days`, `wifi_long_presence_sec`,
  `wifi_intermit_min_sessions`, `wifi_monitor_event_count`: Wi-Fi report
  thresholds.
- `aprs_mobile_min_distance_km`, `aprs_weather_temp_change_f`,
  `aprs_weather_high_rain_1h_in`, `aprs_weather_high_wind_mph`,
  `aprs_weather_high_gust_mph`: APRS Report thresholds.
- `pws_weather_temp_change_f`, `pws_weather_high_rain_1h_in`,
  `pws_weather_high_wind_mph`, `pws_weather_high_gust_mph`: PWS Report
  thresholds.
- `noaa_high_severities`: NOAA severities called out in Reports.
- `usgs_nearby_radius_km`, `usgs_warning_magnitude`: USGS report thresholds.
- `swpc_report_xray_class`, `swpc_report_radio_blackout`,
  `swpc_report_solar_radiation_storm`, `swpc_report_geomagnetic_storm`,
  `swpc_report_kp`: SWPC report thresholds. Defaults are `X1.0`, `R3`,
  `S3`, `G3`, and Kp `7`.
- `lan_report_new_devices`, `lan_report_gateway_changes`: include or suppress
  LAN report families.

`ui`:

- `max_live_rows`: maximum rows in live collector tables.
- `max_history_rows`: maximum rows in history/report-style tables.
- `max_history_payload_rows`: backend cap for large history payload sections.
- `max_event_log_items`: event log rows shown in the browser.
- `max_rendered_findings`: browser cap for Findings rows.
- `max_history_ssids`: SSIDs shown in compact history summaries.
- `bluetooth_live_recent_sec`: BLE live-table age cutoff.
- `poll_feed_live_ttl_sec`: NOAA/USGS/SWPC live-feed row age cutoff in
  seconds. The default is 24 hours. It affects only the live feed display, not
  raw logs, Subject History, Reports, or Alerts.
- `derived_stale_after_min`: age before derived data is considered stale.
- `derived_auto_refresh_min`: automatic derived-refresh cadence. `0` disables
  automatic refresh.
- `derived_refresh_timeout_sec`: browser/backend refresh timeout.
- `insights_recent_after_min`: browser-side recent Insight marker threshold.

Optional `view_window.default_days` sets the default dashboard View window
without changing raw-log retention.

### Collector YAML Metadata

Every file under `config/collectors/` can use these shared keys:

- `key`: stable collector/action key. It normally matches the filename.
- `kind`: optional `action` for on-demand actions such as BLE Identify.
- `order`: System Status/tab ordering.
- `label`: UI label.
- `description`: short operator-facing description.
- `source_group`, `source_group_label`: group related collectors in the UI.
- `acquisition_mode`: how the collector obtains data: `scan`, `poll`, or
  `listen`.
- `enabled`: whether the collector or action is available.
- `auto_start`: whether an enabled collector starts at Skannr startup.

Subject History participation is code-owned metadata, not an operator YAML
knob. Normal collectors contribute subjects by default; exceptions such as
System/status-only sources should be explicit in code.

Acquisition modes define shared behavior:

- `scan`: Skannr asks the local host for current observations. This includes
  Wi-Fi Scan, BLE Scan, Bluetooth Classic, RTL-SDR, PWS, and LAN.
- `poll`: Skannr periodically polls an endpoint or feed that returns current
  or recent events. This includes Rayhunter, NOAA, USGS, and SWPC.
- `listen`: Skannr opens a stream or sniffer and waits for events. This
  includes APRS-IS and Wi-Fi Monitor.

All durable collectors are subject-focused. They should provide a stable
subject identity, keep material update details in a fingerprint, and expose
event/update times when the source has them. Poll collectors need this most:
the same USGS earthquake, SWPC product, or NOAA/NHC message may appear on every
poll and should update one live row/subject instead of creating a new row each
time. The current poll identities are:

- NOAA/NWS/NHC: Source + Area/Basin + Event title. A Beach Hazards Statement
  for San Francisco and one for Santa Cruz are separate subjects; Amanda
  Forecast Advisory 11 and Amanda Wind Speed Probabilities 11 are also separate
  subjects. NWS point forecast summaries are one subject per configured point.
  Generic NHC "no active cyclones" outlook messages collapse by basin/event
  unless the material text changes.
- USGS: USGS event ID.
- SWPC: SWPC event/product ID. X-ray/Kp events include their event time in the
  identity or fingerprint; NOAA R/S/G scale rows are state-like and update only
  on material scale changes.
- PWS: station ID/name/MAC. Ambient Weather samples update one station row
  when current weather values change.

Collector-specific keys:

- `wifi.yaml`: `validation_timeout_sec`, `interfaces`,
  `managed_scan_interval_sec`, `scan_tool`, `retry_interval_sec`,
  `retry_timeout_sec`.
- `wifi_monitor.yaml`: `validation_timeout_sec`, `interface`, `interfaces`,
  `interface_regex`, `bands`, `typical_channels_24`,
  `typical_channels_5`, `include_seen_channels`, `dwell_sec`,
  `retry_interval_sec`, `retry_timeout_sec`.
- `ble.yaml`: `validation_timeout_sec`, `adapters`, `scan_interval_sec`,
  `device_timeout_sec`, `active_scan`, `callback_scan`,
  `bluez_duplicate_data`, `name_lookup_interval_sec`,
  `classic_name_lookup`, `classic_name_timeout_sec`, `retry_interval_sec`,
  `retry_timeout_sec`, `reset_after_in_progress`,
  `wedged_warning_after_in_progress`.
- `ble_identify.yaml`: `adapters`, `identify_timeout_sec`,
  `identify_attempts`, `identify_retry_delay_sec`, `retry_interval_sec`,
  `retry_timeout_sec`.
- `bt_classic.yaml`: `adapters`, `scan_interval_sec`, `scan_timeout_sec`,
  `device_timeout_sec`, `retry_interval_sec`.
- `rtlsdr.yaml`: `validation`, `validation_timeout_sec`, `device_index`,
  `scan_start_mhz`, `scan_end_mhz`, `step_khz`, `gain`, `threshold_db`,
  `baseline_period_sec`, `retry_interval_sec`, `retry_timeout_sec`.
- `rayhunter.yaml`: `endpoint`, `poll_interval_sec`, `request_timeout_sec`,
  `retry_interval_sec`, `retry_timeout_sec`.
- `aprsis.yaml`: `callsign`, `passcode`, `feeds`, `connect_timeout_sec`,
  `preferred_server_timeout_sec`, `preferred_server_max_attempts`,
  `read_timeout_sec`, `status_interval_sec`, `retry_interval_sec`,
  `offline_event_interval_sec`, `max_events_per_minute`, `store_raw`,
  `log_dropped_packets`, `emit_server_messages`.
- `noaa.yaml`: `poll_interval_sec`, `request_timeout_sec`, `user_agent`,
  `latitude`, `longitude`, `state`, `nws.enabled`, `nws.url`,
  `forecast.enabled`, `forecast.window_hours`, `forecast.soon_hours`,
  `forecast.precip_probability_threshold`, `forecast.url`, `nhc.enabled`,
  `nhc.basins`.
- `usgs.yaml`: `poll_interval_sec`, `request_timeout_sec`, `user_agent`,
  `latitude`, `longitude`, `radius_km`, `min_magnitude`, `orderby`,
  `warning_magnitude_nearby`, `warning_magnitude_regional`,
  `warning_nearby_radius_km`, `url`.
- `swpc.yaml`: `poll_interval_sec`, `request_timeout_sec`, `user_agent`,
  `products.alerts`, `products.noaa_scales`, `products.xray_flux`,
  `products.planetary_k`, `urls.alerts`, `urls.noaa_scales`,
  `urls.xray_flux`, `urls.planetary_k`, `xray_min_class`,
  `feed_min_radio_blackout`, `feed_min_solar_radiation_storm`,
  `feed_min_geomagnetic_storm`, `feed_min_kp`, `alert_min_xray_class`,
  `alert_min_radio_blackout`, `alert_min_solar_radiation_storm`,
  `alert_min_geomagnetic_storm`, `alert_min_kp`, and
  `product_keyword_patterns`.
- `pws.yaml`: `poll_interval_sec`, `request_timeout_sec`, `user_agent`,
  `station_id`, optional `mac_address` or `device_name`, `application_key`,
  and `api_key`. Keep real keys only in local `config/collectors/pws.yaml`.
- `lan.yaml`: `poll_interval_sec`, `command_timeout_sec`,
  `collect_ip_neigh`, `collect_arp`, `dhcp_lease_paths`.

APRS-IS `feeds` entries use:

- `name`: local feed name such as `local` or `weather`.
- `role`: semantic role used in status and event typing.
- `host`, `port`: APRS-IS TCP endpoint.
- `filter`: APRS-IS server filter, normally a range filter on port `14580`.
- `enforce_radius`: apply Skannr-side distance filtering after decoding.
- `include_callsigns`: optional explicit callsigns to request.
- `preferred_server`: optional backend name, for pooled hosts such as CWOP.

When adding or changing a collector identity rule, run:

```bash
python3 scripts/validate_collector_contract.py
```

That check locks down the acquisition-mode groups, representative
NOAA/USGS/SWPC subject/fingerprint behavior, NOAA ACK restart de-duplication,
SWPC partial-product failure handling, and PWS Ambient Weather normalization.

The Reports section includes Bluetooth privacy-address grouping:

```yaml
reports:
  ble_private_address_group_min_count: 3
  new_device_window_sec: 3600
  wifi_recurring_min_days: 2
  wifi_long_presence_sec: 14400
  wifi_intermit_min_sessions: 3
  wifi_signal_swing_db: 15
```

Unnamed/private BLE addresses at or above this count are summarized by a coarse
Bluetooth fingerprint: manufacturer, advertised name when useful, and advertised
service/member UUIDs. This avoids treating every rotating BLE address as a
separate physical device while still preserving the raw per-MAC Device History.
`new_device_window_sec` controls how recent a first sighting must be before
Reports call a Wi-Fi AP, Wi-Fi client, or named/static Bluetooth device "new".
The Wi-Fi thresholds add managed-scan presence signals to Reports: recurring
AP/SSID days, long AP presence, intermittent AP windows, and large RSSI swings.

## Logs, Retention, And Derived Data

Runtime files are written under `<skannr-dir>/runtime/logs` by default:

```text
runtime/logs/<collector>/YYYY-MM-DD.jsonl
runtime/logs/skannr.log
runtime/logs/device_history/subject_history.json
runtime/logs/device_history/device_history.json
runtime/logs/device_history/findings_history.json
runtime/logs/device_history/history_analysis.json
runtime/logs/device_history/reports.json
```

`subject_history.json` is the collector-neutral materialized layer for
long-lived intelligence. Wi-Fi and Bluetooth subjects come through Device
History, while APRS-IS, Rayhunter, RTL-SDR, NOAA, USGS, SWPC, PWS, and LAN keep
compact normalized observations in Subject History so refreshes read only new
JSONL bytes past the saved checkpoint. The browser receives the smaller
subject/report views, not the retained direct-observation state.

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

Insights, Reports, and Subject History use the selected dashboard View window.
Skannr refreshes those derived views automatically while the browser page is
open. The default interval is 15 minutes:

```yaml
ui:
  derived_auto_refresh_min: 15
  derived_refresh_timeout_sec: 600
```

The derived views have different jobs:

- Insights: recent event log, tactical/debuggable.
- Reports: ranked intelligence summary, strategic/operator-facing.
- Subject History: collector-neutral subject rollup for reports, analysis, and
  the History tab. It includes Wi-Fi/Bluetooth plus APRS-IS, Rayhunter,
  RTL-SDR, NOAA, USGS, SWPC, PWS, and LAN subjects.
- Device History: Wi-Fi/Bluetooth compatibility view derived from subjects.

Insights are intentionally shorter-lived than Reports or Subject History. They
use the selected dashboard View window as an upper bound, then apply the
configured recent-event lookback:

```yaml
history_analysis:
  insights_recent_hours: 6
```

Set `insights_recent_hours: 0` to show every Insight in the selected View
window. Reports and Subject History are not shortened by this setting.

Set `derived_auto_refresh_min: 0` to disable automatic derived refresh. The
status line shows the last refresh time and the next automatic refresh countdown.
If the browser wakes up with stale derived data, it starts an immediate catch-up
refresh instead of waiting for the next interval. Refresh failures stay visible
in the status line until a later refresh succeeds. A refresh request times out
after `derived_refresh_timeout_sec` so a stuck backend request cannot leave the
browser showing "refresh running" forever. The Manual Refresh button is still
available when you want an immediate rebuild. Browser wake/focus events also
reload the derived view from the backend, which helps after a laptop sleeps
while the Pis keep collecting.
If a refresh itself takes longer than the stale threshold, Skannr waits for the
normal automatic interval after completion instead of immediately starting
another catch-up refresh. This avoids a continuous refresh loop on slower
systems or large materialized histories.

After a fresh log cleanup, the browser may initially load empty cached derived
summaries before the first scan events have been folded into Subject History. If
live Wi-Fi/Bluetooth rows arrive, or collector status shows scan events have
already happened while Subject History is still empty, the browser starts a
throttled catch-up refresh instead of waiting for the normal automatic refresh
interval. Catch-up refreshes use the same post-refresh cooldown as automatic
refreshes, so an empty cached load cannot start repeated catch-up refreshes
immediately after a backend refresh finished.

A successful derived refresh also backfills the live Wi-Fi Scan and BLE Scan
tables from Device History. This keeps those scan rows current when the browser
missed live events while the collectors and raw logs kept running.

While a derived refresh is running, the browser polls `/derived_views/status`
and shows the numbered backend phase in the status strip. Use the same phase
numbers in `runtime/logs/skannr.log` when debugging a long refresh:

- Phase 1/2, Subject and Findings History: fold raw collector logs into the
  collector-neutral subject cache and load/window persisted finding records.
- Phase 2/2, Insights analysis and Reports: derive tactical observations and
  the ranked operator-facing intelligence summary from Subject History.

If refresh appears stuck, check which phase is still running and compare its
elapsed time with the previous completed phase lines in `runtime/logs/skannr.log`.
Normal derived-bundle loads also check `/derived_views/status` first. If the
backend is already in one of these phases, the browser waits for that refresh
to finish before loading `/derived_views`, so it does not render an older cached
bundle with a stale refreshed timestamp.

The BLE Scan table is a live/recent view. The browser periodically repaints it
so devices age out after `ui.bluetooth_live_recent_sec` even if no new BLE event
arrives after the client wakes from sleep. Device History includes numeric epoch
fields next to display timestamps, so recent filtering and duration math do not
depend on the browser interpreting Pi-local timestamp strings. Displayed
timestamps remain the strings generated by the Skannr host.

Manual or automatic refresh of any derived tab refreshes the whole derived bundle
in dependency order:

1. Subject History and Findings History
2. Device History compatibility view from Subject History
3. history-based Insights and Reports

Subject History, Device History, and Findings History are materialized
summaries with JSONL checkpoints. After the first build, refresh normally reads
only new raw-log bytes, not all old logs again.

Reports keeps a visible Type column for broad report families such as pattern,
security, presence, signal, new-device, behavior, identity, collector, and
analysis. The Reports summary line above the table shows the most common report
families in the current source-filter/search view. Reports also include
Confidence and Reasons columns so rows show evidence quality and compact reason
tags without requiring the Evidence column to be parsed first.
Reports are ordered by scope before score: cross-subject population patterns
first, collector/quality rows next, and per-subject rows after that. Population
rows summarize what changed in the local environment as a whole. They link only
when the row carries a concrete grouped identity such as a Wi-Fi SSID; otherwise
they avoid fake single-subject drilldowns. Per-subject rows still link to the
matching Subject History detail when a concrete MAC, BSSID, SSID, callsign,
endpoint, event ID, or LAN subject is available.
Bluetooth Reports are device-centric: stable BLE MACs are consolidated into one
profile row per device, while unnamed/private BLE address rotation is summarized
as coarse manufacturer/name/service-UUID clusters.
Wi-Fi Reports are SSID-centric when a network has several BSSIDs. SSID profiles
summarize BSSID count, channels, bands, vendors, security, and strongest signal.
Individual BSSID reports stay visible mainly when that radio has a warning-level
security difference; routine presence, signal, and radio context belongs on the
SSID profile to avoid one multi-BSSID network becoming many duplicate rows.
Managed Wi-Fi Scan also contributes presence signals based on AP sessions,
recurring days, long or intermittent AP presence, and RSSI swing.
The Reports Evidence column is formatted as operator-readable context, for
example `Pattern`, `Observed`, and `Radio`, instead of exposing raw internal
field names such as `common_hours` or `presence_spans`. In the browser those
evidence items are rendered as stacked labeled lines for readability. Related
context is folded together where it improves readability: session state is part
of `Observed`, Wi-Fi security is part of `Radio`, and strong-signal findings
carry their signal value on the `Findings` line.
Current population rows include multi-BSSID Wi-Fi SSID profiles, BLE
private/randomized address clusters, local RF privacy exposure, APRS-IS weather
station and mobile-station area patterns, NOAA tropical/hazard product sets,
USGS seismic activity, SWPC space-weather product sets, and LAN subject
population.

MAC, SSID, and BSSID values in Reports, Device History, and live scan tables are
clickable detail links. Bluetooth MAC links open one device view. Wi-Fi SSID
links open a grouped network view across all BSSIDs for that SSID. Wi-Fi BSSID
links open the one-radio/AP view. The detail panel uses the currently loaded
Device History and Reports data, so run Manual Refresh if the panel looks older
than the live scan table.
Latitude/longitude pairs rendered in tables, detail panels, report evidence,
alerts, or status banners are linked to OpenStreetMap in a new browser tab.
APRS range filters such as `r/19.6875/-155.9583/100` are linked to the filter
center with a zoom level chosen from the radius.

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
config/collectors/wifi.yaml
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
config/collectors/wifi_monitor.yaml
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
The Identity column combines the advertised BLE name with labeled manufacturer
data, for example `N62N1 | Mfr: AR Timing (0x0201)`. The raw name,
manufacturer-data company ID, and advertised UUIDs remain separate in the
stored data for later drilldown.

The Services / UUIDs column decodes common Bluetooth SIG UUIDs, such as `180A`
to `Device Information`. Optional local UUID mapping files can also decode
member/vendor UUIDs and label them explicitly, for example
`Member UUID FEAF: Nest Labs Inc`.

The live table has one Search box that matches across MAC, identity, RSSI,
decoded services/UUIDs, and last-seen time.

Default config:

```text
config/collectors/ble.yaml
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
config/collectors/bt_classic.yaml
```

Start it manually from the Bluetooth tab or System Status.

### BLE Identify

`BLE Identify` is on demand and actively connects to one selected BLE MAC.
Identify buttons are shown directly on recent BLE Scan rows. The Identify
activity log stays below the BLE Scan table and is not limited by the recent
device window.

Default config:

```text
config/collectors/ble_identify.yaml
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
config/collectors/rtlsdr.yaml
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

## APRS-IS

`APRS-IS` is an optional internet-fed situational-awareness collector. It does
not prove that Skannr's local antenna heard a packet; it reads a filtered
APRS-IS TCP feed for the configured area.

Default config:

```text
config/collectors/aprsis.yaml
```

Use port `14580` with a server-side filter. Do not run an unfiltered full
APRS-IS feed on a small host.

```yaml
enabled: true
callsign: NOCALL
passcode: -1
feeds:
  - name: local
    role: local
    host: noam.aprs2.net
    port: 14580
    filter: "r/37.7749/-122.4194/50"
  - name: weather
    role: weather
    host: cwop.aprs.net
    port: 14580
    filter: "r/37.7749/-122.4194/50"
    enforce_radius: true
```

If Skannr cannot connect to the configured APRS-IS endpoint, System Status and
Insights show the collector as `OFFLINE`. When connected, it reports `ONLINE`
or a per-feed `OFFLINE` status and emits compact station/object/message/status
packet metadata. The APRS-IS top tab shows live feed events, while Subject
History and Reports group APRS activity by callsign, object, or weather
station.

## NOAA

`NOAA` is an optional internet-fed hazard and forecast collector. It polls NWS
active alerts for a configured point/state, NWS hourly forecast summaries for a
configured point, and optional NHC tropical cyclone RSS feeds.

Default config:

```text
config/collectors/noaa.yaml
```

The default template is disabled. Enable it and set your local point or state:

```yaml
enabled: true
poll_interval_sec: 300
latitude: 19.6875
longitude: -155.9583
nws:
  enabled: true
forecast:
  enabled: true
  window_hours: 12
  soon_hours: 6
  precip_probability_threshold: 50
nhc:
  enabled: true
  basins:
  - central_pacific
```

NOAA data feeds the NOAA live tab, Subject History, Reports, and Alerts. NWS
forecast summaries are context rows and Insights/Reports input; they do not
open Alerts by themselves. Alerts default to warning/critical for high-severity
weather, tsunami, tornado, hurricane, and flash-flood conditions.
NOAA/NWS/NHC subjects are keyed by Source + Area/Basin + Event. This prevents
the same polled advisory from creating one row per poll while still keeping
different areas, product families, advisory numbers, and forecast points
separate.

## USGS

`USGS` is an optional internet-fed earthquake collector. It polls the USGS
GeoJSON earthquake API for a configured point, radius, and minimum magnitude.

Default config:

```text
config/collectors/usgs.yaml
```

Example:

```yaml
enabled: true
poll_interval_sec: 300
latitude: 19.6875
longitude: -155.9583
radius_km: 300
min_magnitude: 5.0
```

USGS data feeds the USGS live tab, Subject History, Reports, and Alerts.
The shipped default only ingests magnitude 5+ earthquakes so common small
regional quakes do not flood the dashboard. Lower `min_magnitude` only if you
want local microseismic activity in the live feed and derived views. Alert
defaults focus on nearby or larger earthquakes. USGS subjects are keyed by the
USGS event ID, and material fingerprints include the event time plus magnitude,
place, status, felt/CDI/MMI, alert color, and tsunami flag.

## SWPC

`SWPC` is an optional internet-fed NOAA Space Weather Prediction Center
collector. It polls public SWPC products and emits compact space-weather
events instead of retaining raw time-series samples.

Default config:

```text
config/collectors/swpc.yaml
```

Example:

```yaml
enabled: true
poll_interval_sec: 300
products:
  alerts: true
  noaa_scales: true
  xray_flux: true
  planetary_k: true
xray_min_class: X1.0
feed_min_radio_blackout: R1
feed_min_solar_radiation_storm: S1
feed_min_geomagnetic_storm: G1
feed_min_kp: 5
```

SWPC data feeds the SWPC live tab, Subject History, Reports, and Alerts. The
default live feed shows X-class flares, R/S/G scale activity at level 1 or
higher, and Kp 5 or higher. The default AlertEngine rule alerts only on X-class
flares, R3+ radio blackouts, S3+ solar radiation storms, G3+ geomagnetic
storms, or Kp 7+. Lower space-weather conditions remain visible as feed rows
and derived context without becoming Alerts.
SWPC subjects are keyed by SWPC event identity. Official alert/watch/warning
products and compact X-ray/Kp events include event time in their identity or
fingerprint, while the NOAA R/S/G scale feed behaves like state and only emits
when the current scale materially changes.
If one SWPC public product is temporarily unavailable, Skannr keeps successful
product rows flowing and shows the failed product name in collector status. The
collector only goes retrying when every enabled SWPC product fails.

## PWS

`PWS` is an optional Ambient Weather personal weather station collector. It
polls the current Ambient device state once per minute by default and treats
each station as a scan-style subject: one current/recent weather row, not one
row per poll.

Default config:

```text
config/collectors/pws.yaml
```

Example local config:

```yaml
enabled: true
poll_interval_sec: 60
station_id: GW0154
application_key: "<local Ambient application key>"
api_key: "<local Ambient API key>"
```

PWS data feeds the PWS live tab, Subject History, Insights, Reports, and
Alerts. The collector records current outdoor and indoor
temperature/humidity/dewpoint/feels-like readings, wind/gust and 10-minute wind
averages, one-hour rain rate, event/day/week/month/year rain totals, pressure,
solar/UV, coarse station location, coordinates, elevation, sample time,
timezone, last-rain time, battery/status fields, and source metadata. It does
not retain the street address returned by Ambient. Alert defaults mirror
severe-weather style thresholds: high one-hour rain rate and high wind gusts
become Alerts.
Subject History also tracks simple rain episodes. If the latest transition is
`stopped`, Reports keep the episode start and stop time together so the row does
not show a disconnected "rain stopped" timestamp without its start context.

Keep Ambient keys in local `config/collectors/pws.yaml` only. The
`config.example` template intentionally leaves them blank.

## LAN

`LAN` is an optional passive local-network collector. It reads local OS network
state such as neighbor tables, ARP output, default routes, and optional DHCP
lease files. It does not probe or scan the network.

Default config:

```text
config/collectors/lan.yaml
```

Example:

```yaml
enabled: true
poll_interval_sec: 60
collect_ip_neigh: true
collect_arp: true
dhcp_lease_paths: []
```

LAN data feeds the LAN live tab, Subject History, Reports, and Alerts. Gateway
change alerts are enabled by default; new LAN device alerts are disabled by
default because normal networks can be noisy.

## Wi-Fi Manufacturer Names

Skannr can map Wi-Fi BSSIDs and client MACs to offline IEEE manufacturer data.
Bundled IEEE registry files live under `src/skannr/data/collectors/`:

- `src/skannr/data/collectors/oui.txt`: `https://standards-oui.ieee.org/oui/oui.txt`
- `src/skannr/data/collectors/mam.txt`: `https://standards-oui.ieee.org/oui28/mam.txt`
- `src/skannr/data/collectors/oui36.txt`: `https://standards-oui.ieee.org/oui36/oui36.txt`
- `src/skannr/data/collectors/iab.txt`: `https://standards-oui.ieee.org/iab/iab.txt`

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

- `src/skannr/data/collectors/company_identifiers.txt`: copied content from `https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers/`

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

## Bluetooth UUID Names

Bluetooth company identifiers and Bluetooth UUIDs are different assigned-number
spaces. `company_identifiers.txt` resolves manufacturer-data IDs. Advertised
BLE service/member UUIDs are decoded separately.

Skannr has a small built-in table for common service UUIDs such as:

- `0x180A`: Device Information
- `0x180F`: Battery
- `0x1812`: Human Interface Device

For broader offline decoding, place any of these optional Bluetooth SIG UUID
files under `src/skannr/data/collectors/`:

- `src/skannr/data/collectors/member_uuids.txt`
- `src/skannr/data/collectors/service_uuids.txt`
- `src/skannr/data/collectors/characteristic_uuids.txt`

The files may use the copied Bluetooth SIG YAML-like format:

```yaml
uuids:
 - uuid: 0xFEAF
   name: Nest Labs Inc
```

When present, these mappings are sent to the browser. Standard service UUIDs
are decoded in Services / UUIDs fields. Member/vendor UUIDs, such as `FEAF`,
are also decoded there, but labeled as member UUIDs, for example
`Member UUID FEAF: Nest Labs Inc`. Manufacturer data stays in the Bluetooth
Identity display as a labeled `Mfr:` part and is not conflated with advertised
service/member UUIDs.
Reload the browser after adding or replacing one of these files.

## Package Code For Another Machine

Create a code-only archive from the parent of the checkout directory without the
virtual environment, operator config, runtime state, or bytecode caches:

```bash
cd /path/to/parent
tar \
  --exclude='skannr/.venv' \
  --exclude='skannr/.git' \
  --exclude='skannr/config' \
  --exclude='skannr/runtime' \
  --exclude='skannr/pcaps' \
  --exclude='skannr/**/__pycache__' \
  --exclude='*.pyc' \
  -czf skannr.tar.gz skannr
```

Copy `skannr.tar.gz` to a target that already has its own `config/` and
`runtime/` directories, then install/update dependencies. On a fresh target,
`install.sh` creates `config/` from `config.example/`.

```bash
tar -xzf skannr.tar.gz
cd skannr
./install.sh
sudo env PYTHONPATH="$PWD/src" ./.venv/bin/python -m skannr.main
```

Install system packages on the target as needed.

## Troubleshooting

### Browser Cannot Connect

Check the configured bind address:

```bash
SKANNR_DIR=/path/to/skannr
grep -n "host\\|port\\|listeners" "$SKANNR_DIR/config/skannr.yaml"
ss -ltnp | grep -E '5004|5006'
```

Use `"0.0.0.0:5004"` for IPv4 LAN access and `"[::]:5006"` for IPv6 access.
Restart Skannr after changing the config.

### Brave Or Safari Changes HTTP To HTTPS

Skannr serves plain HTTP. Use:

```text
http://<host>:5004/
```

or:

```text
http://[IPv6_ADDRESS]:5006/
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
