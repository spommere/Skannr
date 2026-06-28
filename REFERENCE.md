# Skannr Reference

This file documents the example configuration tree. The YAML files in `config.example/` are the editable templates; copy them into `config/` for host-local settings. Keep secrets, API keys, exact local paths, and machine-specific interface names out of the example files.

## Configuration Model

Skannr loads the main application file from `~/.config/skannr/skannr.yaml` and collector files from `~/.config/skannr/collectors/*.yaml`. The `config.example/` tree is the source-controlled reference template.

Collector files share these top-level fields:

| Parameter | Meaning |
| --- | --- |
| `key` | Stable collector key. It must match the expected collector/action name. |
| `kind` | Optional type marker. `action` means on-demand UI action rather than normal background collector. |
| `order` | UI/status ordering among collectors. |
| `label` | Human-readable collector name. |
| `description` | Short UI/status description. |
| `source_group` | Optional UI grouping key, for example `bluetooth` or `lan`. |
| `source_group_label` | Human-readable source-group label. |
| `acquisition_mode` | How the source gathers data: `scan`, `listen`, or `poll`. |
| `enabled` | Enables loading the collector/action. Some enabled action collectors still require manual start. |
| `auto_start` | Starts the collector automatically when Skannr starts. Commonly false for disruptive or on-demand collectors. |
| `validation_timeout_sec` | Timeout used while validating collector setup/hardware availability. |
| `retry_interval_sec` | Delay before retrying after collector failure. This is not the normal successful scan/poll cadence. |
| `retry_timeout_sec` | Retry/setup timeout window used by collectors and status diagnostics. |

## Main `skannr.yaml`

### `skannr`

| Parameter | Meaning |
| --- | --- |
| `listeners` | Web listener endpoints. Use `127.0.0.1:5004` for local-only, `0.0.0.0:5004` for all IPv4, or `[::]:5006` for IPv6. |
| `log_level` | Python logging level for Skannr, such as `INFO` or `DEBUG`. |

### `persistence`

| Parameter | Meaning |
| --- | --- |
| `backend` | Persistence backend. The example uses `filesystem`. |
| `filesystem.log_dir` | Base directory for runtime JSONL logs and supporting collector artifacts. |
| `filesystem.retention_days` | Age-based retention for local filesystem event logs. |

### `runtime`

| Parameter | Meaning |
| --- | --- |
| `event_log_maxlen` | In-memory event log length retained for runtime display. |
| `sse_queue_size` | Per-client server-sent-events queue size. |
| `sse_heartbeat_sec` | SSE heartbeat interval. |
| `system_status_interval_sec` | System Status refresh cadence. |
| `shutdown_timeout_sec` | Graceful shutdown timeout. |

### `findings`

Findings promote raw observations into live Insights. Suppressing a live finding does not remove raw logs, Subject History, or Reports.

| Parameter | Meaning |
| --- | --- |
| `enabled` | Master switch for live findings. |
| `max_items` | Maximum live finding rows retained. |
| `bootstrap_events` | Number of recent raw events used to seed findings at startup/refresh. |
| `strong_wifi_rssi`, `strong_wifi_ap_rssi`, `strong_ble_rssi` | Signal thresholds used to flag strong nearby Wi-Fi/BLE observations. |
| `rssi_change_db` | RSSI swing threshold for signal-change findings. |
| `return_after_sec`, `lost_after_sec` | Time windows for returned/lost subject findings. |
| `ble_live_identity_required` | Requires useful BLE identity before creating per-device live findings. |
| `ble_live_service_identity` | Allows BLE service UUIDs to count as identity for live BLE findings. |
| `wifi_monitor_emit_*` | Per-signal switches for noisy Wi-Fi Monitor live findings. Raw monitor data still appears elsewhere. |
| `wifi_monitor_probe_burst_once` | Emits one probe-burst finding per burst window instead of repeated rows. |
| `sensitive_ssids` | SSID patterns considered sensitive in Wi-Fi findings. |
| `burst_window_sec`, `burst_count`, `cooldown_sec` | Burst/cooldown controls for repeated-event findings. |
| `persistent_signal_sec` | Duration threshold for persistent signal findings. |
| `aprs_*`, `pws_*` | APRS/PWS movement and weather thresholds. |
| `adsb_low_altitude_ft`, `adsb_nearby_radius_km`, `adsb_emit_new_aircraft` | ADS-B finding thresholds and new-aircraft emission switch. |
| `noaa_upgrade_severities` | NOAA severities that should be treated as upgraded/high significance. |
| `usgs_warning_*`, `swpc_warning_*` | Earthquake and space-weather finding thresholds. |
| `lan_return_after_sec` | LAN subject return window. |

### `alerts`

Alerts are the ACK/expiry-oriented layer. Each nested rule usually has `enabled` plus `level` and sometimes `critical_level`.

| Parameter | Meaning |
| --- | --- |
| `enabled` | Master alert switch. |
| `max_items` | Maximum retained alert rows. |
| `active_ttl_sec` | Time an unrefreshed alert stays active. |
| `dedupe_sec` | Coalescing window for repeated active alerts. |
| `ack_memory_ttl_sec` | How long ACK memory survives after poll-feed alert rows expire. |
| `ack_memory_alert_types` | Alert types that use long-lived ACK memory. |
| `pushover.*` | Optional Pushover notification integration and credentials. |
| `drone_wifi.*` | Wi-Fi drone/remote-ID SSID/vendor/OUI alert patterns. |
| `aprs_weather.*`, `pws_weather.*` | Weather alert thresholds for APRS/PWS data. |
| `rayhunter_warning.*` | Rayhunter alert rule. |
| `wifi_disruption.*` | Deauth/disassociation disruption alert window and counts. |
| `wifi_open_sensitive.*` | Open sensitive SSID alert patterns. |
| `ble_tracker.*` | BLE tracker name/manufacturer/service UUID patterns. |
| `collector_issue.*` | Optional collector availability alerting. Off by default because System Status already shows it. |
| `noaa_hazard.*` | NOAA severity/event-name alert rules. |
| `usgs_earthquake.*` | Earthquake magnitude, distance, and alert-color thresholds. |
| `swpc_space_weather.*` | Space-weather alert and critical thresholds. |
| `lan_gateway_change.*`, `lan_new_device.*` | LAN alert rules. New-device alerting is off by default because normal LANs are noisy. |
| `adsb_aircraft.*` | ADS-B nearby/low-altitude alert rule. |
| `rtl433_signal.*` | RTL-433 TPMS/security/remote/contact alert rule. Off by default until the local RF environment is understood. |

### `history_analysis`

History analysis drives derived Device History and Subject History patterns.

| Parameter | Meaning |
| --- | --- |
| `new_device_window_sec` | Window for treating an observation as new. |
| `strong_wifi_rssi`, `strong_ble_rssi` | Strong-signal thresholds for history patterns. |
| `many_bssid_count`, `wifi_same_ap_bssid_prefix_bytes`, `wifi_same_ap_max_last_byte_span` | Wi-Fi AP grouping and multi-BSSID heuristics. |
| `many_probe_ssid_count`, `blank_probe_count`, `deauth_count`, `randomized_mac_count` | Wi-Fi Monitor pattern thresholds. |
| `ble_linger_sec`, `ble_lost_count`, `ble_recurring_*`, `ble_ignore_stale_single_seen_sec`, `ble_population_*` | BLE linger, lost, recurring, stale, and population thresholds. |
| `recent_activity_window_sec`, `insights_recent_minutes` | Recentness windows used by history/insight summaries. |
| `wifi_short_lived_sec` | Wi-Fi short-lived subject threshold. |
| `rtl433_recent_min_events` | Minimum recent RTL-433 events for history patterns. |
| `sensitive_ssids` | SSID patterns considered sensitive during history analysis. |

### `reports`

Reports are longer-window derived summaries. These thresholds can intentionally be less immediate than Findings/Alerts.

| Parameter | Meaning |
| --- | --- |
| `ble_*` | BLE long-presence, recurring, private-address grouping, and strong-signal report thresholds. |
| `wifi_*` | Wi-Fi signal, recurrence, long-presence, intermittent, and monitor event thresholds. |
| `aprs_*`, `pws_*` | APRS/PWS movement and weather report thresholds. |
| `noaa_high_severities` | NOAA severities highlighted in reports. |
| `usgs_*`, `swpc_*` | Earthquake and space-weather report thresholds. |
| `adsb_*` | ADS-B nearby/low-altitude/min-seen report thresholds. |
| `rtl433_report_min_events` | Minimum RTL-433 events before reporting a subject/pattern. |
| `lan_report_new_devices`, `lan_report_gateway_changes` | LAN report switches. |

### `ui`

| Parameter | Meaning |
| --- | --- |
| `max_live_rows` | Maximum rows rendered in live collector tables. |
| `max_history_rows` | Maximum rows shown in history tables. |
| `max_history_payload_rows` | Payload-row cap for larger history views. |
| `max_event_log_items` | Browser event-log row cap. |
| `max_rendered_findings` | Browser rendered-finding cap. |
| `max_history_ssids` | SSID list cap in history summaries. |
| `bluetooth_live_recent_sec` | Recentness window for live Bluetooth rows. |
| `poll_feed_live_ttl_sec` | Hides old live NOAA/USGS/SWPC rows without deleting raw logs/history/reports. |
| `device_history_update_interval_sec` | Background cadence for compact Device History coalescing; 0 disables. |
| `derived_stale_after_min` | Age after which derived views are considered stale. |
| `derived_auto_refresh_min` | Automatic derived refresh cadence. |
| `derived_refresh_timeout_sec` | Timeout for derived refresh work. |
| `manual_refresh_small_delta_reuse_bytes` | Optional threshold allowing small raw deltas to reuse cached derived views. |
| `insights_recent_after_min` | Recentness window for insight freshness display. |

## Collector Appendix

### BLE Scan: `collectors/ble.yaml`

BLE supports two scan methods. BlueZ/Bleak is the normal primary method. `bluetoothctl` can be the fallback after BlueZ/Bleak timeouts, or the primary method when forced.

| Parameter | Meaning |
| --- | --- |
| `adapters` | Ordered BlueZ adapter preference list. Empty means auto-rank adapters. |
| `mac` | Optional MAC address of the single adapter allowed for BLE scanning. When set, only the adapter whose MAC matches is eligible — `hciN` name swaps across reboots are harmless. Leave empty to auto-select from all adapters. |
| `scan_interval_sec` | Delay between successful BLE scan passes. |
| `discover_timeout_sec` | Hard timeout for one Bleak discovery/callback scan pass. `0` uses scanner defaults. |
| `device_timeout_sec` | Live-row age-out after a BLE subject stops being observed. |
| `cache_stale_rssi_threshold` | Consecutive identical RSSI values before a device is treated as a stale BlueZ cache ghost (0 disables). |
| `active_scan` | Requests scan-response data when supported. |
| `callback_scan` | Uses Bleak advertisement callback scanning. |
| `force_discover_scan` | Forces Bleak discover mode instead of callback mode. |
| `bluetoothctl_fallback_after_timeout` | Uses bluetoothctl after BlueZ/Bleak discovery timeouts. |
| `force_bluetoothctl_scan` | Makes bluetoothctl the primary scan method. |
| `bluez_duplicate_data` | Keeps duplicate advertisement delivery enabled in BlueZ. |
| `reset_after_discovery_timeout` | Resets adapter after repeated discovery timeouts. |
| `bluez_warmup_after_empty_scans` | Number of empty scans before a warmup scan is attempted. |
| `bluez_warmup_scan_sec` | Length of the warmup scan. |
| `bluez_warmup_min_interval_sec` | Minimum time between warmup scans. |
| `name_lookup_interval_sec` | Minimum time between optional name lookups. |
| `classic_name_lookup` | Enables Classic Bluetooth name lookups for BLE addresses. |
| `classic_name_timeout_sec` | Timeout for one Classic name lookup. |
| `reset_after_in_progress` | Resets after repeated BlueZ "in progress" conditions. |
| `wedged_warning_after_in_progress` | Emits wedged-adapter warning threshold. |
| `retry_interval_sec` | Seconds between offline-to-retry and retry-to-offline attempts. |
| `retry_timeout_sec` | Seconds of consecutive failures before transitioning to offline. |

### BLE Identify: `collectors/ble_identify.yaml`

| Parameter | Meaning |
| --- | --- |
| `adapters` | Ordered BlueZ adapter preference list. |
| `mac` | Optional MAC address of the single adapter allowed for BLE Identify. When set, only the adapter whose MAC matches is eligible — `hciN` name swaps across reboots are harmless. Leave empty to auto-select. |
| `identify_timeout_sec` | Timeout for one active Device Information Service attempt. |
| `identify_attempts` | Number of identify attempts. |
| `identify_retry_delay_sec` | Delay between identify attempts. |
| `retry_interval_sec` | Seconds between offline-to-retry and retry-to-offline attempts. |
| `retry_timeout_sec` | Seconds of consecutive failures before transitioning to offline. |

### Bluetooth Classic: `collectors/bt_classic.yaml`

| Parameter | Meaning |
| --- | --- |
| `adapters` | Ordered BlueZ adapter preference list. |
| `mac` | Optional MAC address of the single adapter allowed for Classic inquiry. When set, only the adapter whose MAC matches is eligible — `hciN` name swaps across reboots are harmless. Leave empty to auto-select from all adapters. |
| `scan_interval_sec` | Delay between completed Classic inquiry scans. |
| `scan_timeout_sec` | Length of each Classic inquiry scan. |
| `device_timeout_sec` | Live-row age-out after a Classic device disappears. |
| `retry_interval_sec` | Seconds between offline-to-retry and retry-to-offline attempts. |

### Wi-Fi Scan: `collectors/wifi.yaml`

| Parameter | Meaning |
| --- | --- |
| `interfaces` | Ordered managed Wi-Fi interface preference list. Empty means auto-rank. |
| `mac` | Optional MAC address of the single adapter allowed for managed Wi-Fi scanning. When set, only the interface whose MAC matches is eligible — `wlanN` name swaps across reboots are harmless. Leave empty to auto-select from all managed interfaces. |
| `managed_scan_interval_sec` | Delay between successful managed AP scans. |
| `scan_tool` | Scanner backend. `auto` tries `iw` first and falls back when needed. |
| `retry_interval_sec` | Delay after scan command/setup failure. |
| `retry_timeout_sec` | Retry/setup timeout window shown in diagnostics. |

`managed_scan_interval_sec` and `retry_interval_sec` do not compete. The first is the normal successful scan cadence; the second is only used after failure.

### Wi-Fi Monitor: `collectors/wifi_monitor.yaml`

| Parameter | Meaning |
| --- | --- |
| `auto_start` | Starts monitor capture automatically. Usually false until the adapter is known-good. |
| `interface` | Single monitor interface or `auto`. |
| `interfaces` | Ordered interface preference/allow list. |
| `interface_regex` | Regex filter for auto-discovered monitor interfaces. |
| `mac` | Optional MAC address of the single adapter allowed for monitor mode. When set, only the interface whose MAC matches is eligible — interface-name swaps across reboots are harmless. Empty means auto-select from all monitor-capable adapters. |
| `prepare_monitor_mode` | Lets Skannr discover or prepare a safe monitor interface before capture. |
| `allow_in_place_monitor_mode` | Allows the older in-place fallback that brings the source interface down temporarily. Default is false. |
| `set_networkmanager_unmanaged` | Deprecated compatibility knob. Skannr no longer edits NetworkManager state at runtime. |
| `monitor_setup_timeout_sec` | Timeout for each monitor setup command. |
| `bands` | Channel bands to consider, usually `2.4` and/or `5`. |
| `channel_mode` | `hop` for channel hopping or `fixed` for one configured channel. |
| `fixed_channel` | Channel used when `channel_mode` is fixed. |
| `typical_channels_24`, `typical_channels_5` | Common channel lists used after adapter support filtering. |
| `include_seen_channels` | Adds channels observed in previous monitor logs. |
| `seen_channels_first` | Places learned channels before typical channels. |
| `common_channel_fallback` | Keeps common channels when no learned channels are usable. |
| `dwell_sec` | Seconds to stay on each channel while hopping. |
| `retry_interval_sec` | Seconds between retry attempts after setup/capture failure. |
| `retry_timeout_sec` | Seconds of consecutive failures before transitioning to offline. |

`dwell_sec` is the normal hop cadence. Retry settings only apply after setup/capture failure.

### RTL-433: `collectors/rtl433.yaml`

| Parameter | Meaning |
| --- | --- |
| `auto_start` | Starts rtl_433 automatically. Usually false until dongle/frequency choices are known. |
| `device_index` | RTL-SDR device index. Use a different index from ADS-B when both run on one host. |
| `command` | rtl_433 executable path/name. |
| `gain` | rtl_433 gain argument, commonly `auto` or a numeric value. |
| `sample_rate` | rtl_433 sample rate, for example `250k`. |
| `ppm` | RTL-SDR frequency correction passed to rtl_433. |
| `units` | rtl_433 unit output mode. |
| `frequency_plan` | Comma-separated fixed/hopping frequency plan. |
| `protocols` | Optional rtl_433 `-R` protocol IDs to enable. Empty means rtl_433 defaults. |
| `disabled_protocols` | Protocol IDs passed as negative `-R` values to suppress decoders. |
| `extra_args` | Extra raw rtl_433 CLI arguments for local experiments. |
| `retry_interval_sec` | Seconds between retry attempts after process failure. |
| `retry_timeout_sec` | Seconds of consecutive failures before transitioning to offline. |

Protocol numbers are owned by rtl_433 and can vary by version. Use `rtl_433 -R help` on the target host before hardcoding IDs. Example shape: `protocols: [40, 60]` becomes `-R 40 -R 60`; `disabled_protocols: [40]` becomes `-R -40`.

### ADS-B: `collectors/adsb.yaml`

| Parameter | Meaning |
| --- | --- |
| `poll_interval_sec` | Aircraft JSON refresh cadence. |
| `request_timeout_sec` | HTTP/local read timeout. |
| `manage_decoder` | Starts/manages dump1090/readsb when true. |
| `device_index` | RTL-SDR device index. Use a different index from RTL-433 when both run. |
| `decoder_command` | Explicit decoder command; blank uses fallback search. |
| `decoder_args` | Arguments for managed decoder startup. `{device_index}` and `{json_dir}` are substituted. |
| `decoder_output_dir` | Managed decoder JSON output directory; blank uses runtime default. |
| `decoder_start_timeout_sec` | Timeout for managed decoder startup. |
| `url` | External aircraft JSON endpoint. When set, Skannr does not start a decoder. |
| `aircraft_json_paths` | Local fallback aircraft JSON paths. |
| `latitude`, `longitude` | Optional observer location for distance calculations. |
| `nearby_radius_km`, `low_altitude_ft` | ADS-B warning/report thresholds. |

### APRS-IS: `collectors/aprsis.yaml`

| Parameter | Meaning |
| --- | --- |
| `callsign`, `passcode` | APRS-IS login identity. Use a real callsign/passcode in local config. |
| `feeds` | List of APRS-IS connections such as local and CWOP weather feeds. |
| `feeds[].name`, `feeds[].role` | Feed label and semantic role. |
| `feeds[].host`, `feeds[].port`, `feeds[].filter` | APRS-IS server and filter string. |
| `feeds[].enforce_radius` | Drops decoded packets outside the configured range after receipt. |
| `feeds[].include_callsigns` | Optional station callsigns to request explicitly. |
| `feeds[].preferred_server` | Optional pool backend banner to wait for before accepting a connection. |
| `connect_timeout_sec` | TCP connect/login timeout. |
| `preferred_server_timeout_sec`, `preferred_server_max_attempts` | Preferred-backend retry behavior for pooled servers. |
| `read_timeout_sec` | Quiet-read timeout before reconnecting. |
| `status_interval_sec` | Status snapshot cadence while connected. |
| `offline_event_interval_sec` | Minimum interval between offline status events. |
| `max_events_per_minute` | Per-feed rate cap. |
| `store_raw` | Stores raw APRS lines when true. |
| `log_dropped_packets` | Logs malformed/out-of-radius/rate-limited packet counts. |
| `emit_server_messages` | Emits APRS server login/filter messages into live table events. |
| `retry_interval_sec` | Seconds between offline-to-retry and retry-to-offline attempts. |

### NOAA: `collectors/noaa.yaml`

| Parameter | Meaning |
| --- | --- |
| `poll_interval_sec` | NOAA/NWS/NHC/tsunami refresh cadence. |
| `request_timeout_sec` | Per-request HTTP timeout. |
| `user_agent` | HTTP User-Agent header. |
| `latitude`, `longitude`, `state` | Location selectors for generated NWS feeds. |
| `nws.enabled`, `nws.url` | NWS active-alert feed switch and optional URL override. |
| `forecast.enabled` | Enables point forecast summaries. |
| `forecast.window_hours` | Future forecast window summarized. |
| `forecast.soon_hours` | Near-term forecast bucket. |
| `forecast.precip_probability_threshold` | Probability threshold highlighted in summaries. |
| `forecast.url` | Optional forecast URL override. |
| `nhc.enabled`, `nhc.basins` | National Hurricane Center subfeed switch and basin selectors. |
| `tsunami.enabled` | tsunami.gov CAP subfeed switch. |
| `tsunami.fetch_bulletin_text` | Fetches linked bulletin text. False avoids extra requests and uses feed metadata only. |
| `tsunami.centers`, `tsunami.feeds` | tsunami.gov center selectors and optional URL overrides. |

### USGS: `collectors/usgs.yaml`

| Parameter | Meaning |
| --- | --- |
| `poll_interval_sec`, `request_timeout_sec`, `user_agent` | HTTP polling controls. |
| `latitude`, `longitude`, `radius_km`, `min_magnitude`, `orderby` | Local-radius earthquake query controls. |
| `global_major.*` | Optional worldwide major-earthquake subfeed controls. |
| `warning_magnitude_*`, `warning_nearby_radius_km` | Feed/report/alert severity helper thresholds. |
| `url` | Optional full USGS query URL override. |

### SWPC: `collectors/swpc.yaml`

| Parameter | Meaning |
| --- | --- |
| `poll_interval_sec`, `request_timeout_sec`, `user_agent` | HTTP polling controls. |
| `products.*` | Switches for SWPC product families. |
| `urls.*` | Product URL overrides. |
| `xray_min_class`, `feed_min_*` | Feed event thresholds. |
| `alert_min_*` | Collector-level alert helper thresholds; main alert rules also live in `skannr.yaml`. |
| `product_keyword_patterns` | Official alert-product text filters retained by Skannr. |

### PWS: `collectors/pws.yaml`

| Parameter | Meaning |
| --- | --- |
| `poll_interval_sec`, `request_timeout_sec`, `user_agent` | Ambient Weather API polling controls. |
| `station_id` | Stable station label shown in Skannr. |
| `mac_address`, `device_name` | Optional filters when the account returns multiple devices. |
| `application_key`, `api_key` | Ambient Weather credentials. Keep real values in local config only. |

### Rayhunter: `collectors/rayhunter.yaml`

| Parameter | Meaning |
| --- | --- |
| `endpoint` | Rayhunter HTTP endpoint. |
| `poll_interval_sec`, `request_timeout_sec` | Normal HTTP polling cadence and timeout. |
| `retry_interval_sec`, `retry_timeout_sec` | Failure retry behavior. |

### LAN: `collectors/lan.yaml`

| Parameter | Meaning |
| --- | --- |
| `poll_interval_sec` | Main LAN collection cadence. |
| `mac` | Optional MAC address of the single adapter allowed for LAN collection (ARP scan, passive listeners). When set, only the interface whose MAC matches is eligible — `wlanN` name swaps across reboots are harmless. Leave empty to use all configured or auto-discovered interfaces. |
| `command_timeout_sec` | Default timeout for local helper commands. |
| `collect_ip_neigh`, `collect_arp`, `collect_mdns`, `collect_ssdp` | Passive OS/service-neighbor sources. |
| `collect_avahi_browse` | Enables `avahi-browse` service discovery. |
| `avahi_browse_interval_sec`, `avahi_browse_timeout_sec`, `avahi_browse_command` | avahi-browse cadence, timeout, and command. |
| `collect_passive_dhcp`, `passive_dhcp_ports` | Optional passive DHCP listener and ports. |
| `collect_passive_arp`, `passive_arp_interfaces` | Optional passive ARP listener and interface list. |
| `collect_active_arp_scan` | Enables active local ARP sweep. Generates local network traffic. |
| `active_arp_scan_interval_sec`, `active_arp_scan_timeout_sec` | Active scan cadence and timeout. |
| `active_arp_scan_retention_sec` | Retention for active scan results. Blank derives from scan interval. |
| `active_arp_scan_interfaces` | Interfaces for active scans. Empty lets the command choose default. |
| `active_arp_scan_command` | Active scan command; may include `{interface}`. |
| `active_arp_scan_working_dir` | Working directory for commands needing vendor databases. |
| `dhcp_lease_import_interval_sec`, `dhcp_lease_import_timeout_sec` | DHCP lease import cadence and timeout. |
| `dhcp_lease_paths` | Local DHCP lease files to parse. |
| `dhcp_lease_command` | Optional helper command that emits lease data. |
| `retry_interval_sec` | Seconds between retry attempts after failure. |
| `retry_timeout_sec` | Seconds of consecutive failures before transitioning to offline. |

### LAN Identify: `collectors/lan_identify.yaml`

| Parameter | Meaning |
| --- | --- |
| `identify_timeout_sec` | Overall action timeout. |
| `nmap_timeout_sec`, `nmap_ports` | nmap probe timeout and ports. |
| `curl_timeout_sec`, `curl_output_max_bytes` | HTTP probe timeout and captured output cap. |
| `http_probe_ports` | Ports probed with HTTP/HTTPS requests. |
| `http_hint_patterns` | Text patterns used to summarize likely service/device families. |
