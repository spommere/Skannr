# Skannr

Skannr is a local monitoring dashboard for Wi-Fi, Bluetooth, optional
RTL-433/ADS-B/APRS-IS/NOAA/USGS/SWPC/PWS situational context, and passive LAN
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
- `REFERENCE.md`: configuration parameter appendix for `config.example/` and local `config/` files
- `docs/ui-sample-data.md`: sanitized fake UI sample rows based on observed
  collector event shapes
- `LICENSE`: project license
- `VERSION`: current application version
- `CHANGELOG.md`: release notes and versioning policy
- `src/skannr/`: Python package, collector code, shipped UI, and bundled lookup data
- `config.example/`: generic config template for source upload and fresh installs
- `config/`: local runtime configuration; precheck may create it with only `precheck.yaml`, and `install.sh` fills it from `config.example/` on fresh installs
- `runtime/`: generated logs, materialized views, and runtime state
- `requirements/*.txt`: Python dependency manifests
- `scripts/`: install checks, validation helpers, and internal regression tools

Current version: see `VERSION`.

Versioning policy:

- `0.1.x`: bug fixes and documentation updates
- `0.2.x`: meaningful feature additions or data format changes
- `0.3.x`: architecture and collector data-flow changes
- `1.0.0`: stable operator-facing behavior and config/log compatibility

The rest of this README is the operator manual.

## Install Model

Skannr installation is intentionally split into OS tools, Python dependencies,
and local collector enablement:

1. Install OS packages for the collectors this host may use.
2. Run `python3 scripts/skannr_precheck.py` on a new host if you want to see
   which collectors have the required software/hardware before install. This
   creates `config/precheck.yaml`; it may create `config/` with only that file.
3. Run `./install.sh`. On a fresh config, it copies `config.example/` into
   `config/`, applies `precheck.yaml`, installs Python dependencies, runs
   `scripts/skannr_postcheck.py`, writes `config/postcheck.yaml`, and applies
   the final postcheck result. Existing configs are not rewritten.
4. Review `config/collectors/*.yaml` for any collector you want to enable or
   disable manually, especially config-required internet/API collectors.
5. Start Skannr and use System Status for the authoritative runtime view of
   collector state, missing required tools, and missing optional tools.

Hardware-bound SDR collectors (`rtl433` and managed ADS-B) are auto-enabled
on fresh config only when required software and visible RTL-SDR hardware are
both present. Optional LAN enrichment tools such as `arp-scan` and
`avahi-browse` are reported but do not disable the base LAN collector.

## Quick Start

```bash
SKANNR_DIR=/path/to/skannr
cd "$SKANNR_DIR"
python3 scripts/skannr_precheck.py
./install.sh
sudo env PYTHONPATH="$SKANNR_DIR/src" "$SKANNR_DIR/.venv/bin/python" -m skannr.main
```

Open:

```text
http://127.0.0.1:5004/
```

`install.sh` creates local `config/` from `config.example/` if
`config/skannr.yaml` does not already exist. Existing YAML is not overwritten.
The precheck step is recommended for a new host; it is safe to skip because
`install.sh` runs it automatically when creating fresh config.

## Install System Packages

Python requirements do not install OS tools such as `iw`, `airmon-ng`,
Bluetooth utilities, BlueZ, `rtl_433`, or ADS-B decoder packages.

On Debian, Kali, or Raspberry Pi OS:

```bash
sudo apt update
sudo apt install rtl-sdr librtlsdr-dev aircrack-ng bluetooth bluez wireless-tools iw
```

Optional SDR decoder tools:

```bash
sudo apt install rtl-433 dump1090-mutability
```

- `rtl-433`: required only for the optional `rtl433` collector. It decodes
  supported ISM-band devices such as TPMS, weather sensors, some garage/security
  remotes, contact sensors, utility meters, and similar low-power transmitters.
- `dump1090-mutability` or another `dump1090`/`readsb` variant: required only
  for the optional ADS-B collector.

Optional LAN tools:

```bash
sudo apt install arp-scan avahi-daemon avahi-utils net-tools nmap curl
```

- `ip` from `iproute2`: used for neighbor table and default-route state. This
  is normally already installed on Raspberry Pi OS/Kali.
- `arp` from `net-tools`: optional fallback source for ARP cache data.
- `arp-scan`: required only if `collect_active_arp_scan: true`. If active ARP
  scan is enabled and `arp-scan` is missing, Skannr keeps the LAN collector
  online for the other LAN sources and shows a warning in System Status.
- `avahi-browse` from `avahi-utils`, usually with `avahi-daemon`: required
  only if `collect_avahi_browse: true`. It imports resolved Bonjour/mDNS
  service rows for better LAN identity enrichment.
- `nmap` and `curl`: used only by the on-demand LAN Identify action. Passive
  LAN observation does not run them.

Before first install you can run the standalone collector precheck:

```bash
python3 scripts/skannr_precheck.py
```

The precheck writes `config/precheck.yaml`. When `install.sh` creates a fresh
`config/` from `config.example/`, it applies those precheck results to
`config/collectors/*.yaml`: collectors with required local tools present are
enabled, missing local-tool collectors are disabled, and internet/API collectors
that need local configuration stay disabled until configured manually. For Wi-Fi,
fresh config also seeds `wifi.interfaces` with the first non-monitor wireless
interface and `wifi_monitor.interfaces` with the first already-monitor-mode
interface when those probes are available. For SDR-backed collectors, `rtl433`
and managed ADS-B are enabled only when required software is present and an
RTL-SDR dongle is visible through
`rtl_test -t`. The four fresh-install cases are therefore explicit: software and
hardware present enables the collector; software-only, hardware-only, or neither
keeps it disabled. Optional LAN enrichment tools such as `arp-scan` and
`avahi-browse` do not disable the LAN collector when the required base LAN tool
is available.

The installer creates `.venv` and chooses the Python requirements file by Python
version:

- Python 3.6: `requirements/requirements-py36.txt`
- Python 3.7: `requirements/requirements-py37.txt`
- Python 3.8 and newer: `requirements/requirements-py38plus.txt`

The Python dependencies include Flask, Flask-SocketIO, `simple-websocket`,
`bleak`, and `scapy` as appropriate for the local Python version.

At the end of installation, `install.sh` runs `scripts/skannr_postcheck.py`
inside the virtual environment and writes `config/postcheck.yaml`. The postcheck
repeats the collector tool/hardware inventory and also verifies Python modules
installed by the selected requirements file. For a fresh config only,
`install.sh` applies this final postcheck result after Python dependencies are
installed. Existing configs are not rewritten; runtime startup and System
Status still decide whether an enabled collector can actually run on the
current host.

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
RTL-SDR/ADS-B devices, and packet capture usually need root or equivalent Linux
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
  - Set `enabled: true` only when internet-fed NOAA/NWS/NHC/tsunami.gov
    context is wanted.
  - Set `latitude` and `longitude` for the monitored point.
  - Optionally set `state` for broader NWS state context.
  - NWS point forecast summaries default on when `nws.enabled` is true and
    `latitude` / `longitude` are configured. Use `forecast.enabled: false` only
    if you want NWS alerts/NHC advisories without local forecast context.
  - Review `nws.enabled`, `nhc.enabled`, `nhc.basins`, `tsunami.enabled`, and
    `tsunami.centers` for the local area and desired global context.
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
  - `config/collectors/adsb.yaml`: enable if this host runs `dump1090` or
    `readsb`. Set `device_index` when Skannr starts the decoder, or set `url`
    or verify one of the configured `aircraft_json_paths` matches an external
    decoder's `aircraft.json`; set `latitude` and `longitude` for nearby/low-
    aircraft distance scoring.
  - `config/collectors/rtl433.yaml`: enable only when this host should run
    `rtl_433` against an attached RTL-SDR dongle. Set `device_index` and
    `frequency_plan` for the local dongle and bands you want to decode. ADS-B
    and RTL-433 can run together only when they use different dongle indexes.
  - `config/collectors/lan.yaml`: enable if passive LAN neighbor/default-gateway
    and mDNS/SSDP service context is wanted. Active ARP scan is optional and
    disabled by default.
  - `config/collectors/wifi*.yaml`, `ble.yaml`, and `bt_classic.yaml`: review
    adapter/interface settings for the hardware attached to this host.

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
- `ble_live_identity_required`: require a useful BLE identity, normally a
  non-MAC name, before emitting per-device live BLE Findings. This keeps
  randomized/manufacturer-only address churn out of Insights while preserving
  it in live BLE data and Subject History.
- `ble_live_service_identity`: also treat service-UUID-only BLE subjects as
  individually finding-worthy. Default is `false` because common randomized
  beacons can still carry generic service hints.
- `wifi_monitor_emit_client_new`, `wifi_monitor_emit_client_returned`,
  `wifi_monitor_emit_client_lost`, `wifi_monitor_emit_blank_probe`,
  `wifi_monitor_emit_randomized_mac`, `wifi_monitor_emit_probe_burst`,
  `wifi_monitor_emit_strong_client`, `wifi_monitor_emit_ap_presence`,
  `wifi_monitor_emit_strong_ap`: optional Wi-Fi Monitor live-finding noise
  knobs. They default to `false` because monitor mode can see heavy randomized
  probe and beacon churn that is better handled by Wi-Fi Scan, Subject History,
  and Reports.
- `wifi_monitor_probe_burst_once`: when generic Wi-Fi Monitor probe-burst
  findings are enabled, emit once per burst instead of every cooldown interval.
- `sensitive_ssids`: SSID names or shell-style patterns that should produce a
  live Wi-Fi Monitor Insight when probed.
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
- `ack_memory_ttl_sec`, `ack_memory_alert_types`: memory for exact poll-feed
  alert events. NOAA/NHC, USGS, and SWPC alert fingerprints are remembered by
  default for seven days so retained upstream feed entries do not require
  repeated ACKs after restart or after the active row expires.
- `pushover.enabled`, `pushover.userkey`, `pushover.appkey`: optional Pushover
  phone notification delivery for newly emitted or escalated alerts. It is off
  by default. When enabled, Skannr checks generic internet connectivity
  before sending and logs delivery failures without interrupting collectors.
  `userkey` is the Pushover user key and `appkey` is the Pushover application
  API token:

  ```yaml
  alerts:
    pushover:
      enabled: true
      userkey: "your-pushover-user-key"
      appkey: "your-pushover-application-token"
  ```

  Pushover delivery is best-effort. Browser Alerts remain the source of truth;
  phone delivery runs in a background worker and is skipped when internet
  connectivity is unavailable.
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
- `noaa_hazard.critical_events`, `critical_severities`: NWS/NHC/tsunami.gov
  hazard terms and severities that escalate to the critical level.
- `usgs_earthquake.warning_magnitude_nearby`,
  `critical_magnitude_nearby`, `warning_magnitude_global`,
  `critical_magnitude_global`, `nearby_radius_km`, `critical_alert_colors`:
  earthquake alert thresholds.
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
- `ble_ignore_stale_single_seen_sec`: suppress old one-off anonymous BLE
  subjects from tactical Insights.
- `ble_population_min_count`, `ble_population_min_strong_count`: thresholds
  for the aggregate nearby-BLE population Insight that replaces many anonymous
  per-address rows.
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
- `device_history_update_interval_sec`: background cadence for compact Device
  History coalescing. This lets Wi-Fi/BLE/LAN identity state advance without
  blocking page load or collector startup. `0` disables the worker.
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
  Wi-Fi Scan, BLE Scan, Bluetooth Classic, PWS, and LAN.
- `poll`: Skannr periodically polls an endpoint or feed that returns current
  or recent events. This includes Rayhunter, NOAA, USGS, and SWPC.
- `listen`: Skannr opens a stream, sniffer, or local decoder feed and waits for
  events. This includes APRS-IS, Wi-Fi Monitor, and ADS-B.

All durable collectors are subject-focused. They should provide a stable
subject identity, keep material update details in a fingerprint, and expose
event/update times when the source has them. Poll collectors need this most:
the same USGS earthquake, SWPC product, or NOAA/NHC message may appear on every
poll and should update one live row/subject instead of creating a new row each
time. The current poll identities are:

- NOAA/NWS/NHC/tsunami.gov: NWS rows use Source + Area + Event, so a Beach
  Hazards Statement for San Francisco and one for Santa Cruz are separate
  subjects. NHC storm rows roll up by basin + storm/system name + advisory
  number, so Amanda Public Advisory 11, Forecast Advisory 11, Forecast
  Discussion 11, and Wind Speed Probabilities 11 update one advisory-package
  subject, while Amanda 12 is a new subject. NWS point forecast summaries are
  one subject per configured point. Tsunami.gov rows use warning center +
  incident ID, so later message numbers update the same incident. Generic NHC
  "no active cyclones" outlook messages collapse by basin/event unless the
  material text changes.
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
  `discover_timeout_sec`, `device_timeout_sec`, `active_scan`, `callback_scan`,
  `force_discover_scan`, `bluetoothctl_fallback_after_timeout`,
  `force_bluetoothctl_scan`, `bluez_duplicate_data`,
  `reset_after_discovery_timeout`, `bluez_warmup_after_empty_scans`,
  `bluez_warmup_scan_sec`, `bluez_warmup_min_interval_sec`,
  `name_lookup_interval_sec`, `classic_name_lookup`,
  `classic_name_timeout_sec`, `retry_interval_sec`,
  `retry_timeout_sec`, `reset_after_in_progress`,
  `wedged_warning_after_in_progress`.
- `ble_identify.yaml`: `adapters`, `identify_timeout_sec`,
  `identify_attempts`, `identify_retry_delay_sec`, `retry_interval_sec`,
  `retry_timeout_sec`.
- `bt_classic.yaml`: `adapters`, `scan_interval_sec`, `scan_timeout_sec`,
  `device_timeout_sec`, `retry_interval_sec`.
- `adsb.yaml`: `poll_interval_sec`, `request_timeout_sec`, `manage_decoder`,
  `device_index`, `decoder_command`, `decoder_args`, optional `url`,
  `aircraft_json_path`, `aircraft_json_paths`, `latitude`, `longitude`,
  `nearby_radius_km`, and `low_altitude_ft`.
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
  `nhc.basins`, `tsunami.enabled`, `tsunami.centers`,
  `tsunami.fetch_bulletin_text`, `tsunami.feeds`.
- `usgs.yaml`: `poll_interval_sec`, `request_timeout_sec`, `user_agent`,
  `latitude`, `longitude`, `radius_km`, `min_magnitude`, `orderby`,
  `global_major.enabled`, `global_major.min_magnitude`,
  `global_major.orderby`, optional `global_major.lookback_days`,
  `warning_magnitude_nearby`, `warning_magnitude_regional`,
  `warning_magnitude_global`, `warning_nearby_radius_km`, `url`.
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
  `collect_ip_neigh`, `collect_arp`, `collect_mdns`, `collect_ssdp`,
  `collect_avahi_browse`, `avahi_browse_interval_sec`,
  `avahi_browse_timeout_sec`, `avahi_browse_command`,
  `collect_passive_dhcp`, `passive_dhcp_ports`, `collect_passive_arp`,
  `passive_arp_interfaces`, `collect_active_arp_scan`,
  `active_arp_scan_interval_sec`, `active_arp_scan_timeout_sec`,
  `active_arp_scan_retention_sec`, `active_arp_scan_interfaces`,
  `active_arp_scan_command`, `active_arp_scan_working_dir`,
  `dhcp_lease_import_interval_sec`, `dhcp_lease_import_timeout_sec`,
  `dhcp_lease_paths`, `dhcp_lease_command`.
- `lan_identify.yaml`: `identify_timeout_sec`, `nmap_timeout_sec`,
  `curl_timeout_sec`, `curl_output_max_bytes`, `nmap_ports`,
  `http_probe_ports`, `http_hint_patterns`. This is an on-demand action; it
  does not run as part of normal LAN polling.

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

That check locks down the acquisition-mode groups, representative BLE Find My
payload detection, NOAA/USGS/SWPC subject/fingerprint behavior, NOAA ACK
restart de-duplication, SWPC partial-product failure handling, PWS Ambient
Weather normalization, and representative period-rollup report rows.

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
separate physical device while still preserving the raw per-MAC subject detail.
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
runtime/logs/device_history/subject_annotations.json
runtime/logs/device_history/history_analysis.json
runtime/logs/device_history/reports.json
```

The `device_history` directory name is historical. `subject_history.json` is the
primary materialized history model; the directory also stores per-collector
direct state and analysis artifacts. `subject_annotations.json` is a durable user
overlay for custom subject annotations. It is not rebuilt from raw logs and is
not removed by log pruning. Delete it explicitly only when intentionally
removing operator-provided names as part of a clean start.

Randomized or locally administered identities are kept as raw evidence in JSONL
logs but are grouped in normal materialized history when they have no stronger
stable identity. For example, Wi-Fi monitor probe MACs and Bluetooth private
addresses appear as aggregate randomized-device rows instead of thousands of
one-off subjects. The `WiFiBLEPostprocessor` (internal to Subject History)
performs this grouping, so normal refreshes do not keep rewriting per-MAC churn.
Older installs may still contain `findings_history.json`; current Skannr treats
that file as a legacy compatibility artifact and does not use it as an Insights
or Reports upstream.

`subject_history.json` is the collector-neutral materialized layer for
long-lived intelligence. Wi-Fi and Bluetooth observations are processed by an
internal `WiFiBLEPostprocessor` (session tracking, vendor enrichment, privacy
grouping), but the resulting AP, client, and Bluetooth rows are exposed as
Subject History alongside APRS-IS, Rayhunter,
RTL-SDR, RTL-433, ADS-B, NOAA, USGS, SWPC, PWS, and LAN subjects. The browser receives the
smaller subject/report views, not the retained direct-observation state.

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
  RTL-SDR, RTL-433, ADS-B, NOAA, USGS, SWPC, PWS, and LAN subjects.
- Compact privacy groups: BLE, Wi-Fi randomized-client, and LAN private-MAC
  groups stay as one main-table row, while detail panes expose bounded
  per-member evidence such as MAC, first/last seen, counts, signal, and
  identity/source context.
- Wi-Fi/Bluetooth compatibility view: internal view derived from Subject History
  for older browser drilldown and live-table code.

Insights are intentionally shorter-lived than Reports or Subject History. They
use the selected dashboard View window as an upper bound, then apply the
configured recent-event lookback:

```yaml
history_analysis:
  insights_recent_minutes: 60
```

Set `insights_recent_minutes: 0` to show every Insight in the selected View
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
tables from the Wi-Fi/Bluetooth compatibility view. This keeps those scan rows
current when the browser missed live events while the collectors and raw logs
kept running.

While a derived refresh is running, the browser polls `/derived_views/status`
and shows the numbered backend phase in the status strip. Use the same phase
numbers in `runtime/logs/skannr.log` when debugging a long refresh:

- Phase 1/2, Subject History: fold new collector JSONL bytes into compact
  per-collector subject state and the collector-neutral subject cache.
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
arrives after the client wakes from sleep. Subject History and the
Wi-Fi/Bluetooth compatibility view include numeric epoch fields next to display
timestamps, so recent filtering and duration math do not depend on the browser
interpreting Pi-local timestamp strings. Displayed timestamps remain the strings
generated by the Skannr host.

Manual or automatic refresh of any derived tab refreshes the whole derived bundle
in dependency order:

1. Subject History from compact Device History plus new direct collector JSONL
   bytes
2. Wi-Fi/Bluetooth compatibility view from Subject History
3. history-based Insights and Reports

Subject History and the Wi-Fi/Bluetooth compatibility view are materialized
summaries with JSONL checkpoints. Direct collectors keep compact per-collector
state files under `runtime/logs/device_history/subject_history_direct_*.json`;
those files store compact history rows, not every retained raw observation.
After the first build, refresh normally reads only new collector raw-log bytes,
not all old logs again. Live Findings may
still be written under `runtime/logs/findings` for audit/debugging, but retained
Findings JSONL is not a durable upstream for derived Insights or Reports.

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
Reports also include materialized period rows for longitudinal patterns such as
PWS and APRS-IS weather station trends, USGS seismic periods, SWPC
space-weather periods, and NOAA monthly/yearly hazard context.

MAC, SSID, and BSSID values in Reports, Subject History, and live scan tables are
clickable detail links. Bluetooth MAC links open one device view. Wi-Fi SSID
links open a grouped network view across all BSSIDs for that SSID. Wi-Fi BSSID
links open the one-radio/AP view. The detail panel uses the currently loaded
Subject History plus the Wi-Fi/Bluetooth compatibility payload and Reports data,
so run Manual Refresh if the panel looks older than the live scan table.
Latitude/longitude pairs rendered in tables, detail panels, report evidence,
alerts, or status banners are linked to OpenStreetMap in a new browser tab.
APRS range filters such as `r/19.6875/-155.9583/100` are linked to the filter
center with a zoom level chosen from the radius.

Subject History does not include System in its Source filter because System
events are runtime state, not durable subjects. System events can still appear
in Insights and Reports when they are actionable.

The header View selector defaults to `retention_days`. You can override only the
dashboard default without changing log retention:

```yaml
view_window:
  default_days: 7
```

## Collector Validation

Collector checks happen in three layers:

- Install-time precheck: `scripts/skannr_precheck.py` runs before the virtual
  environment is needed. It uses only the Python standard library, reports
  required/recommended/optional local tools and selected hardware probes, writes
  `config/precheck.yaml`, and can apply enabled flags plus Wi-Fi interface
  suggestions to a freshly copied `config/collectors/` tree. SDR-backed
  collectors are not auto-enabled unless required software and RTL-SDR hardware
  are both present.
- Post-install check: `install.sh` runs `scripts/skannr_postcheck.py` from the
  installed virtual environment. It reuses the same inventory, checks Python
  modules such as `bleak` and `scapy`, writes `config/postcheck.yaml`, and is
  applied to fresh config after dependencies are installed.
- Runtime startup/status checks: each collector owns `hardware_status()` and
  `detect()` checks for its actual configuration. System Status and collector
  banners use this layer to show whether an enabled collector is online,
  stopped, offline, missing required tools/hardware, or missing optional
  enrichment tools.

Collector YAML files own their own hardware and software settings. For adapters
and interfaces, use ordered candidate lists. When the list is empty, Skannr uses
the devices Linux currently exposes. On fresh installs, precheck/postcheck may
seed Wi-Fi lists so managed scan uses a non-monitor interface such as `wlan0`
and Wi-Fi Monitor uses an already-monitor-mode interface such as `wlan1`:

```yaml
interfaces: []
adapters: []
validation_timeout_sec: 10
```

Some collectors also have command-based runtime validation. The command is
formatted with collector YAML keys, run with a timeout, and considered
available only when it exits with status 0.

Optional collector tools are installed outside the Python virtual environment:

- Wi-Fi Monitor: `iw`, plus an adapter that can be put into monitor mode.
- RTL-433 decoded ISM feed: `rtl_433`.
- ADS-B: `dump1090`, `dump1090-fa`, `dump1090-mutability`, or `readsb`.
  By default the ADS-B collector starts the configured decoder and reads its
  generated `aircraft.json`. Set `manage_decoder: false` or configure `url` if
  an external service already manages the decoder.
- LAN base collection: `ip` is required. `arp` is recommended as another cache
  source. `arp-scan` and `avahi-browse` are optional enrichment tools; if they
  are missing, the LAN collector still runs from the available base sources and
  System Status reports the missing optional tool. `nmap` and `curl` are needed
  only for the on-demand LAN Identify action.

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
- ignores interfaces already in monitor mode when no explicit `interfaces` list
  is configured

The live table has one Search box that matches across SSID, BSSID, vendor,
channel/frequency, encryption, signal, and last-seen time.

It does not see probe requests, associations, deauth frames, or monitor-mode
traffic. Those belong to `Wi-Fi Monitor`.

Default config:

```text
config/collectors/wifi.yaml
```

## Wi-Fi Monitor

`Wi-Fi Monitor` is on demand and captures on a monitor-mode Wi-Fi interface.

It:

- uses Scapy packet capture
- channel-hops across configured/supported 2.4 GHz and 5 GHz channels
- records probe requests, AP beacons, associations, disassociations, and deauth
  frames
- folds AP and client observations into Wi-Fi subjects

By default, prepare a separate adapter first, then click Start in System Status
or the Wi-Fi Monitor tab. On Raspberry Pi systems with a dedicated ALFA or
similar USB adapter, keep that adapter out of NetworkManager and switch it to
monitor mode before starting the collector. On fresh installs, precheck/postcheck
seeds `interfaces` with the first interface already reported as monitor mode,
so a dedicated `wlan1` monitor adapter is not accidentally used by Wi-Fi Scan.

Skannr can also prepare a specifically configured interface before capture. Use
this only for a dedicated monitor adapter, not for the normal network interface.
The interface must be concrete; `prepare_monitor_mode: true` with
`interface: auto` and an empty `interfaces` list is treated as unsafe and Skannr
will not guess which managed adapter to convert:

```yaml
interface: wlan1
interfaces:
- wlan1
prepare_monitor_mode: true
set_networkmanager_unmanaged: true
```

With that setting, Skannr runs `nmcli dev set wlan1 managed no` when available,
then `ip link set wlan1 down`, `iw dev wlan1 set type monitor`, and
`ip link set wlan1 up` before sniffing. If `interface` is `auto`, Skannr only
discovers existing monitor-mode interfaces and does not guess which managed
adapter should be changed.

When this runs from the Skannr service, the service user must have enough
privilege to change Wi-Fi interface mode, usually root or equivalent
`CAP_NET_ADMIN`. Manual `sudo iw ...` success does not prove a non-root Skannr
service can do the same thing. After changing `config/collectors/wifi_monitor.yaml`,
restart Skannr and give NetworkManager/device state a short moment to settle
before checking `iw dev wlan1 info`.

For setup debugging, check `runtime/logs/skannr.log` or `journalctl -u skannr`.
Useful lines look like:

```text
Wi-Fi Monitor start config prepare_monitor_mode=True interface=wlan1 interfaces=['wlan1'] iw=/usr/sbin/iw ip=/usr/sbin/ip nmcli=/usr/bin/nmcli monitors=[] wireless=['wlan0', 'wlan1']
Wi-Fi Monitor monitor-mode setup candidates=['wlan1']
Wi-Fi Monitor setup command passed command=/usr/bin/nmcli dev set wlan1 managed no output=...
Wi-Fi Monitor setup command passed command=/usr/sbin/iw dev wlan1 set type monitor output=...
```

If the log says `interface=auto interfaces=[]` or `candidates=[]`, Skannr loaded
the config but has no concrete interface to prepare. Set `interface: wlan1` or
`interfaces: [wlan1]`.

For quick testing, this is usually enough until the next reboot or
NetworkManager reset:

```bash
sudo nmcli dev set wlan1 managed no
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
iw dev wlan1 info
```

For a permanent setup, prefer a NetworkManager keyfile entry so the monitor
adapter is not claimed as a normal managed Wi-Fi interface:

```ini
[keyfile]
unmanaged-devices=interface-name:wlan1
```

Then restart NetworkManager:

```bash
sudo systemctl restart NetworkManager
```

You can also make monitor-mode preparation automatic with a small systemd
oneshot service. This does not edit NetworkManager config; it assumes the
adapter is already unmanaged or otherwise safe to reconfigure:

```ini
[Unit]
Description=Set wlan1 to monitor mode
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set wlan1 down
ExecStart=/usr/sbin/iw dev wlan1 set type monitor
ExecStart=/usr/sbin/ip link set wlan1 up
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Save that as a local systemd unit such as
`/etc/systemd/system/wlan1-monitor-mode.service`, then enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wlan1-monitor-mode.service
iw dev wlan1 info
```

If `iw dev wlan1 info` does not show `type monitor`, Wi-Fi Monitor will remain
offline and System Status will report that no monitor-mode interface was found
or that monitor setup failed.

If no monitor-mode client/probe frames have been summarized for the selected
view, Subject History shows an explicit no-data message under Wi-Fi Monitor.
That does not mean AP scanning is broken; AP observations are shown under
Wi-Fi Access Points.

Default config:

```text
config/collectors/wifi_monitor.yaml
```

Useful settings:

```yaml
interface: auto
interfaces: []
interface_regex: wlan|^mon
prepare_monitor_mode: false
set_networkmanager_unmanaged: true
monitor_setup_timeout_sec: 10
bands:
- '2.4'
- '5'
channel_mode: hop
fixed_channel:
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
seen_channels_first: false
common_channel_fallback: true
dwell_sec: 1
```

`bands` can be limited to only `['2.4']` or only `['5']` when you want the
hopper to stay on one band. `channel_mode: fixed` makes Wi-Fi Monitor stay on
`fixed_channel` instead of hopping. In normal `hop` mode, `include_seen_channels`
adds channels observed in retained Wi-Fi logs; `seen_channels_first` puts those
site-specific channels before the common list; `common_channel_fallback` keeps
the common channels in the plan when discovered channels are sparse or absent.
`dwell_sec` controls how long the monitor remains on each channel.

## Bluetooth

The Bluetooth tab combines BLE Scan, Bluetooth Classic Scan, and BLE Identify
activity. BLE Identify is an internal on-demand Bluetooth action, not a System
Status collector row. Adapter availability is shown once through BLE Scan and
Bluetooth Classic.

### BLE Scan

`BLE Scan` passively reads BLE advertisements with `bleak` and BlueZ.
The live table shows only devices seen within `ui.bluetooth_live_recent_sec`
seconds, default `600`. Older BLE rows remain in Subject History and Reports but
are hidden from the live table.
The Identity column combines the advertised BLE name with labeled manufacturer
data, for example `N62N1 | Mfr: AR Timing (0x0201)`. The raw name,
manufacturer-data company ID, and advertised UUIDs remain separate in the
stored data for later drilldown.

Apple Find My accessories are flagged from Apple manufacturer data when the
payload type byte is `0x12` after company ID `0x004C`. The BLE row and device
detail show `Apple Find My accessory` plus compact status/hint bytes when
present. This identifies Find My protocol advertisements, not a specific
physical tag: AirTags, AirPods cases, and third-party Find My accessories can
share this pattern, and their BLE MAC addresses rotate.

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
behavior, BlueZ state, and whether nearby devices are advertising. Each Bleak
scan window has a hard `discover_timeout_sec` guard so a hung BlueZ discovery
call becomes a visible retry diagnostic instead of leaving the feed idle. On
hosts where the callback scanner hangs, Skannr can fall back to the
`bluetoothctl` scan path after a Bleak timeout; set `force_bluetoothctl_scan:
true` to start there immediately. If Bleak returns repeated empty scan windows,
Skannr can run a short, rate-limited
`bluetoothctl --timeout N scan on` warmup to wake BlueZ discovery; set
`bluez_warmup_after_empty_scans: 0` to disable that workaround.

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

## RTL-433

`RTL-433` is a decoder-backed listen collector. Skannr starts `rtl_433`, reads
its JSON output, keeps the decoded raw fields, and rolls each decoded source into
the live RTL-433 tab, Subject History, Insights, Reports, and optional alerts.

Default config:

```text
config/collectors/rtl433.yaml
```

Common setup:

```yaml
enabled: true
auto_start: false
device_index: 0
command: rtl_433
gain: auto
sample_rate: 250k
frequency_plan: "433.92:30,315:30,390:30,915:30"
```

Frequency plan syntax:

```text
<freq_mhz>:<dwell_sec>
<start_mhz>-<end_mhz>:<step_khz>:<dwell_sec>
```

Bare frequencies are MHz. For example, `144.39:0` means 144.39 MHz fixed.
Explicit suffixes are also accepted for uncommon cases: `Hz`, `kHz`, `MHz`,
`M`, `GHz`, and `G`.

Examples:

```text
433.92:0
315.22:12
915-916:50:10
315.22:12,915-916:50:10,433.92:10
```

For example, `915-916:50:10` scans 915.000 MHz through 916.000 MHz in
50 kHz steps and dwells for 10 seconds at each hop. The RTL-433 tab's current
frequency strip shows the active hop while it is running.

`0` or negative dwell means fixed/unlimited only when the plan has one
frequency. In a multi-frequency plan, Skannr normalizes non-positive dwell to a
small default so `rtl_433` can hop. Hopping can miss short bursts such as
keyfobs, garage remotes, and TPMS messages; use a fixed frequency when
investigating one target.

Useful starting points are:

- `315 MHz`: North America keyfobs, TPMS, garage/security devices
- `345 MHz`: North America security systems
- `390 MHz`: older North America garage/security remotes
- `433.92 MHz`: common ISM sensors/remotes, weather, security, some TPMS
- `868 MHz`: EU SRD/weather/utility sensors
- `915 MHz`: North America ISM sensors and utility/water/power meters

The RTL-433 live tab shows the latest row per decoded subject and keeps the raw
decoded fields compact in the Details column. The status strip above the table
shows the current configured frequency hop, for example `Scanning 433.92 MHz`.
Decoded payloads do not always include their own frequency or signal fields, so
Skannr fills the live row frequency from the current hop when needed and parses
numeric RSSI/SNR/noise values from rtl_433 strings when present. Subject History
keys a decoded source by model, ID, channel, and protocol when available, with a
hash fallback for sparse payloads. Subject History also retains compact pattern
evidence such as hour and weekday histograms, day/night buckets, per-frequency
counts, recent observation samples, and repeat-gap timing. For TPMS-like
decodes, Skannr also retains normalized pressure, temperature, battery/status,
position, compact TPMS samples, and per-sensor ranges when `rtl_433` exposes
those fields. Reports add a population row, per-subject rows for
TPMS/security-like devices and repeated decoded subjects, and conservative
short-window TPMS cluster rows that may indicate vehicle/pass-through activity.
The language is conservative: Skannr can report TPMS/security/remote/contact
activity clusters, but it does not claim that a garage opened or closed unless a
decoder payload explicitly contains that state.

Alerts for RTL-433 are configurable but disabled by default:

```yaml
alerts:
  rtl433_signal:
    enabled: false
    level: warning
    categories:
    - tpms
    - security
    model_patterns: []
    protocols: []
```

One RTL-SDR dongle normally cannot run RTL-433 and ADS-B decoding at the
same time. Skannr coordinates the configured `device_index` values: starting
an RTL-backed collector stops only other Skannr-managed RTL-backed collectors
that are running on the same index. If
ADS-B uses `device_index: 0` and RTL-433 uses `device_index: 1`, both can run
together. If both are left at `0`, Skannr keeps the existing single-dongle
handoff behavior. Linux device indexes can change across hardware changes or
boot order, so verify the host's RTL-SDR order before assigning collectors.

## ADS-B

`ADS-B` is a decoder-backed listen collector. Skannr does not demodulate
1090 MHz ADS-B directly; it starts the first available `dump1090`/`readsb` decoder by default, points it
at a runtime JSON output directory, reads the decoder's `aircraft.json`,
suppresses unchanged aircraft snapshots, and turns changed aircraft state into
live rows, Subject History, Insights, Reports, and optional alerts.

Default config:

```text
config/collectors/adsb.yaml
```

Common setup:

```yaml
enabled: true
poll_interval_sec: 1
manage_decoder: true
device_index: 0
decoder_command: ""
decoder_args:
- --net
- --device-index
- "{device_index}"
- --write-json
- "{json_dir}"
decoder_output_dir: ""
aircraft_json_paths:
- /run/dump1090-fa/aircraft.json
- /run/dump1090-mutability/aircraft.json
- /run/readsb/aircraft.json
- latitude: 19.6875
longitude: -155.9583
nearby_radius_km: 10
low_altitude_ft: 1500
```

If the decoder exposes aircraft JSON over HTTP instead of a local file, set:

```yaml
manage_decoder: false
url: http://127.0.0.1:8080/data/aircraft.json
```

When `manage_decoder: true` and `decoder_output_dir` is blank, Skannr writes
dump1090/readsb JSON files under `runtime/logs/adsb_decoder/`. Skannr's own raw
event audit remains separate under `runtime/logs/adsb/YYYY-MM-DD.jsonl`. The
default decoder arguments are selected from the executable: `dump1090*` uses
`--device-index {device_index}`, while `readsb` uses
`--device-type rtlsdr --device {device_index}`. If the local decoder
variant uses different RTL-SDR selection flags, override `decoder_args` in local config and keep
`device_index` set so Skannr still knows which dongle the managed decoder owns.

What it records:

- ICAO hex identity and callsign when present
- squawk and emergency state
- latitude/longitude when available
- altitude, ground speed, track, vertical rate, message count, RSSI
- distance from the configured observer latitude/longitude
- decoder/source path or URL

Subject History keys aircraft by ICAO hex and keeps first/last seen, update
count, position count, altitude range, closest distance, maximum speed, path
span, squawks, callsigns, latest position/motion, compact local pass spans,
bounded route samples, and nearby approach/departure context. ADS-B collector
health keeps decoder state and one-dongle RTL-SDR scheduling guidance. Reports
add an ADS-B population row, decoder-health guidance when the collector is not
online, plus per-aircraft rows for emergency aircraft, low nearby aircraft,
approach/departure-like tracks, repeated local passes, or aircraft seen at
least `reports.adsb_report_min_seen` times.

Alerts use `alerts.adsb_aircraft`:

```yaml
alerts:
  adsb_aircraft:
    enabled: true
    level: warning
    critical_level: critical
    nearby_radius_km: 10
    low_altitude_ft: 1500
```

Emergency squawk/state opens a critical alert. Aircraft at or below
`low_altitude_ft` and within `nearby_radius_km` open a warning alert. ADS-B can run beside RTL-433 when each collector is configured for a different
`device_index`; otherwise Skannr stops the same-index collector before starting
the new one.

## Rayhunter

`Rayhunter` is an optional poll collector for a Rayhunter cellular-monitor HTTP
endpoint. It is not a general RF scanner. Skannr only records Rayhunter's own
health, recording metadata, and analysis warning count from the configured
endpoint.

Default config:

```text
config/collectors/rayhunter.yaml
```

Typical local configuration:

```yaml
enabled: true
endpoint: http://127.0.0.1:8080/
poll_interval_sec: 30
request_timeout_sec: 10
retry_interval_sec: 10
```

Rayhunter support prefers the structured JSON APIs exposed by the Rayhunter UI:

- `/api/system-stats`
- `/api/qmdl-manifest`
- `/api/config`
- `/api/analysis-report/<recording>`

If those APIs are unavailable, Skannr falls back to parsing the endpoint's
visible status text. It accepts gzip responses and sanitizes HTML/Svelte page
content so bundled web-application code is not treated as evidence.

What it records:

- endpoint reachability
- warning count from Rayhunter's live analysis report
- Rayhunter version and device OS when available
- storage, memory, battery, and GPS mode
- current recording ID, size, start time, and last message time
- collector offline/retrying state when the endpoint cannot be reached

The Rayhunter live tab shows the latest compact status per endpoint, including
warning count, recording metadata, device health fields, and summary text.
Skannr does not download Rayhunter `.qmdl`, `.pcap`, ZIP, or other large
artifacts. Reports show one row per endpoint using the subject
`Rayhunter <endpoint>`, including the selected-window status-event count.
Subject History keeps the latest endpoint status. Alerts can be generated by
the `rayhunter_warning` rule when Rayhunter reports a non-zero warning count.

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

For APRS mobile stations, Subject History retains bounded trip evidence such as
first/latest positions, route samples, packet samples, movement/span/speed, and
a pass-through or repeated-presence rollup label. The APRS detail pane exposes
those samples for ordinary drilldown without expanding the main tables.

For APRS weather stations, Subject History also builds daily aggregates and
rolls them into weekly, monthly, and yearly Report rows. Those rows summarize
temperature range/change, average humidity, rain-rate maxima, rain episode
count, approximate rain-active span, wind/gust maxima, pressure range/change,
sample coverage, and feed/server provenance.

## NOAA

`NOAA` is an optional internet-fed hazard and forecast collector. It polls NWS
active alerts for a configured point/state, NWS hourly forecast summaries for a
configured point, optional NHC tropical cyclone RSS feeds, and official
tsunami.gov NTWC/PTWC feeds.

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
tsunami:
  enabled: true
  fetch_bulletin_text: true
  centers:
  - ntwc
  - ptwc
```

NOAA data feeds the NOAA live tab, Subject History, Reports, and Alerts. NWS
forecast summaries are context rows and Insights/Reports input; they do not
open Alerts by themselves. Retained point forecasts compare the latest summary
with the previous retained forecast for the same point, exposing temperature,
precipitation, wind, hazard-text, and deterioration/improvement deltas in
Reports and detail panes. Alerts default to warning/critical for high-severity
weather, tsunami warning/watch/advisory/threat products, tornado, hurricane,
and flash-flood conditions. Tsunami Information Statements remain visible in the
NOAA feed, Subject History, and Reports, but do not open Alerts by themselves.
NOAA/NWS/NHC/tsunami.gov subjects are keyed by the feed semantics. NWS alerts
use Source + Area + Event. NHC storm advisories use one advisory-package
subject per basin + storm/system name + advisory number, with individual
products such as Public Advisory, Forecast Advisory, Forecast Discussion, and
Wind Speed Probabilities retained as package details. Tsunami.gov rows use one
subject per warning center + tsunami incident ID, so later message numbers
update the same incident subject. This prevents the same polled item from
creating one row per poll while still keeping different areas, advisory
numbers, forecast points, and tsunami incidents separate.

Reports also include monthly and yearly NOAA hazard-context rollups. These
period rows count distinct NOAA subjects, tropical systems, NWS hazard subjects,
tsunami incidents/messages, forecast-context rows, forecast-change evidence,
sources, basins, and retained period-over-period subject-count changes. They
intentionally avoid treating NHC
package product count or maximum severity as the main longitudinal signal.

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
global_major:
  enabled: true
  min_magnitude: 6.5
```

USGS data feeds the USGS live tab, Subject History, Reports, and Alerts.
The local-radius feed ingests magnitude 5+ earthquakes by default so common
small regional quakes do not flood the dashboard. Lower `min_magnitude` only if
you want local microseismic activity in the live feed and derived views. The
optional `global_major` subfeed adds worldwide M6.5+ earthquakes into the same
USGS tab and deduplicates by USGS event ID when an event appears in both feeds.
Global M6.5+ earthquakes alert by default; global M7.5+ earthquakes are
critical by default. USGS subjects are keyed by the USGS event ID, and material
fingerprints include the event time plus magnitude, place, status, felt/CDI/MMI,
alert color, and tsunami flag.

Reports also include weekly, monthly, and yearly USGS period rows. These rows
summarize unique earthquake count, local versus global-major count, notable and
tsunami-flagged counts, magnitude range, nearest configured-point distance,
shallowest depth, alert colors, scopes, feeds, and the latest event folded into
the period.

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

Reports also include weekly, monthly, and yearly SWPC period rows. These rows
summarize unique event count, alert-threshold and critical counts, event-kind
counts, highest X-ray flare class, max Kp, and strongest R/S/G scale labels so
the report row itself shows conditions such as `R3`, `S3`, or `G3`.

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
For longer-window Reports, Subject History also rolls PWS samples into daily
aggregates and then weekly, monthly, and yearly station summaries. Those period
rows show temperature range/change, average humidity, observed rain total,
maximum one-hour rain rate, rain episode count, approximate rain-active span,
maximum wind/gust, pressure range/change, solar/UV maxima, and sample/day
coverage. A new station will only have current-day/current-week information at
first; week/month/year patterns become meaningful after enough samples have
been retained.

Keep Ambient keys in local `config/collectors/pws.yaml` only. The
`config.example` template intentionally leaves them blank.

## LAN

`LAN` is an optional local-network collector. By default it reads local OS
network state such as neighbor tables, ARP output, default routes, passive
mDNS/SSDP service advertisements, and optional DHCP lease files. It can also run
an active ARP inventory scan when explicitly enabled.

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
collect_mdns: true
collect_ssdp: true
collect_avahi_browse: false
avahi_browse_interval_sec: 300
collect_active_arp_scan: false
active_arp_scan_interval_sec: 300
active_arp_scan_retention_sec: ""
active_arp_scan_interfaces: []
active_arp_scan_working_dir: ""
dhcp_lease_import_interval_sec: 300
dhcp_lease_paths: []
dhcp_lease_command: ""
```

LAN data feeds the LAN live tab, Subject History, Reports, and Alerts. Gateway
change alerts are enabled by default; new LAN device alerts are disabled by
default because normal networks can be noisy.

Passive mDNS and SSDP listeners enrich LAN subjects with advertised services,
device locations, and server/product strings. Optional Avahi import runs
`avahi-browse -a -r -p -t` on its own cadence and parses only resolved `=`
rows, which add hostnames, service names, ports, and selected TXT clues. If
`avahi-browse` is missing or fails, LAN stays online for the other sources and
shows a warning.

DHCP lease import runs on its own cadence and can read local dnsmasq-style lease
files or an optional command that prints dnsmasq-style lease rows. Use a local
wrapper script for router-specific SSH/curl/API exports. Passive DHCP and raw
ARP listeners are configurable but off by default because they can require
elevated privileges or conflict with local services. Active ARP scan requires
`arp-scan`, may need root or `cap_net_raw`, and defaults to a 300 second cadence
when enabled.
ARP replies are best-effort, so active-scan subjects are retained across
intermittent missed replies. Leave `active_arp_scan_retention_sec` blank to
retain them for `max(180 seconds, active_arp_scan_interval_sec * 3)`.

For active ARP scan, `active_arp_scan_interfaces: []` leaves interface
selection to `arp-scan --localnet`. That can be surprising on a Pi with more
than one active network, for example `eth0` on the property LAN and `wlan0` on
a hotspot used by Rayhunter. Prefer listing the networks you want Skannr to
inventory:

```yaml
collect_active_arp_scan: true
active_arp_scan_interfaces:
- eth0
- wlan0
```

Skannr runs one `arp-scan` pass per listed interface. A wired `eth0` scan can
still discover Wi-Fi clients when the router bridges wired and Wi-Fi clients
into the same IPv4 LAN. Add `wlan0` only when you also want to inventory that
interface's own LAN, such as a separate hotspot subnet. Do not add `tun0` for
Yggdrasil: ARP scan works on IPv4 Ethernet/L2 networks, while Yggdrasil is a
routed IPv6 overlay. Use Yggdrasil for remote access to Skannr, not LAN device
inventory.

Skannr consumes the third `arp-scan` output column as `vendor_name` and shows it
as the LAN feed's `Vendor` column. Some `arp-scan` builds look for
`ieee-oui.txt` and `mac-vendor.txt` relative to their working directory; under
systemd that directory may not be `/usr/share/arp-scan`. By default Skannr uses
common arp-scan data directories when present. If your local install differs,
set:

```yaml
active_arp_scan_working_dir: /usr/share/arp-scan
```

Avahi enrichment is useful when mDNS/Bonjour advertises richer identity than
the OS neighbor table. For example, `arp-scan` may only show `Tuya Smart Inc.`
or `Apple, Inc.`, while Avahi can add `Living-Room.local`, AirPlay/HomeKit
services, model strings, ports, and router TXT fields. Skannr joins resolved
Avahi records to LAN subjects by trusted TXT MAC fields first, then by current
IP address. Other MAC-like TXT fields are retained as clues, not used as the
primary LAN identity.

LAN source requirements:

| Source | Config | Requirement | Missing behavior |
| --- | --- | --- | --- |
| OS neighbor table/default routes | `collect_ip_neigh` | `ip` / `iproute2` | skipped if unavailable |
| ARP cache fallback | `collect_arp` | `arp` / `net-tools` | skipped if unavailable |
| mDNS advertisements | `collect_mdns` | Python UDP multicast socket | warning if socket bind/join fails |
| SSDP advertisements | `collect_ssdp` | Python UDP multicast socket | warning if socket bind/join fails |
| Avahi resolved mDNS import | `collect_avahi_browse` | `avahi-browse` / `avahi-utils`, usually `avahi-daemon` | warning if command is missing, invalid, times out, or fails |
| DHCP lease files | `dhcp_lease_paths` | readable dnsmasq-style lease files | unreadable paths are skipped |
| Router lease import | `dhcp_lease_command` | local command/wrapper that prints dnsmasq-style lease rows | warning if command is invalid, missing, or fails |
| Passive DHCP listener | `collect_passive_dhcp` | Python UDP socket on ports 67/68; usually root/capability | warning if bind fails |
| Passive raw ARP listener | `collect_passive_arp` | Linux `AF_PACKET`; usually root/capability | warning if raw socket bind fails |
| Active ARP scan | `collect_active_arp_scan` | `arp-scan`; usually root/capability | warning if `arp-scan` is missing or fails |
| LAN Identify | `lan_identify` action | `nmap` and/or `curl` | unavailable if both are missing; partial result if one is missing |

LAN Identify is deliberately active and on demand. The LAN tab's Identify
button runs a bounded service scan plus short HTTP/HTTPS root probes against
one observed IPv4/IPv6 address. It records compact clues such as open ports,
service banners, HTTP titles, script names, selected headers, and brand-like
snippets. It does not scan the subnet and it does not run arbitrary commands
from the browser.

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
