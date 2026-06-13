"""Configuration loading for global and collector-specific settings.

Global settings live in config/skannr.yaml. Collector-specific settings live in
config/collectors/*.yaml, then get merged into config["collectors"] so the rest
of the runtime can treat all settings as one dictionary.
"""

import copy
import os

import yaml

from .collectors import detect_collector_hardware
from .log_utils import normalize_retention_days
from .paths import CONFIG_COLLECTORS_DIR, PROJECT_ROOT


# These defaults make a fresh Skannr checkout runnable without a config
# file. load_config() writes them only when config/skannr.yaml does not exist,
# then overlays any user edits in memory on later runs.
DEFAULT_CONFIG = {
    "skannr": {
        "listeners": ["127.0.0.1:5004"],
        "log_level": "INFO",
    },
    "persistence": {
        "backend": "filesystem",
        "filesystem": {
            "log_dir": "runtime/logs",
            "retention_days": 30,
        },
    },
    "runtime": {
        "event_log_maxlen": 100,
        "sse_queue_size": 200,
        "sse_heartbeat_sec": 15,
        "system_status_interval_sec": 5,
        "shutdown_timeout_sec": 10,
    },
    "findings": {
        "enabled": True,
        "max_items": 200,
        "bootstrap_events": 1000,
        "strong_wifi_rssi": -50,
        "strong_wifi_ap_rssi": -45,
        "strong_ble_rssi": -55,
        "rssi_change_db": 12,
        "return_after_sec": 300,
        "lost_after_sec": 300,
        "ble_live_identity_required": True,
        "ble_live_service_identity": False,
        "wifi_monitor_emit_client_new": False,
        "wifi_monitor_emit_client_returned": False,
        "wifi_monitor_emit_client_lost": False,
        "wifi_monitor_emit_blank_probe": False,
        "wifi_monitor_emit_randomized_mac": False,
        "wifi_monitor_emit_probe_burst": False,
        "wifi_monitor_emit_strong_client": False,
        "wifi_monitor_emit_ap_presence": False,
        "wifi_monitor_emit_strong_ap": False,
        "wifi_monitor_probe_burst_once": True,
        "sensitive_ssids": [],
        "burst_window_sec": 30,
        "burst_count": 5,
        "cooldown_sec": 120,
        "persistent_signal_sec": 60,
        "aprs_move_km": 0.3,
        "aprs_temp_change_f": 5,
        "aprs_rain_1h_high_in": 0.25,
        "aprs_wind_high_mph": 25,
        "aprs_gust_high_mph": 35,
        "pws_temp_change_f": 5,
        "pws_rain_1h_high_in": 0.25,
        "pws_wind_high_mph": 25,
        "pws_gust_high_mph": 35,
        "adsb_low_altitude_ft": 1500,
        "adsb_nearby_radius_km": 10,
        "adsb_emit_new_aircraft": True,
        "noaa_upgrade_severities": ["Severe", "Extreme"],
        "usgs_warning_magnitude": 4.0,
        "usgs_warning_distance_km": 100,
        "swpc_warning_xray_class": "X1.0",
        "swpc_warning_radio_blackout": "R3",
        "swpc_warning_solar_radiation_storm": "S3",
        "swpc_warning_geomagnetic_storm": "G3",
        "swpc_warning_kp": 7,
        "lan_return_after_sec": 3600,
    },
    "alerts": {
        "enabled": True,
        "max_items": 50,
        "active_ttl_sec": 3600,
        "dedupe_sec": 900,
        "ack_memory_ttl_sec": 604800,
        "ack_memory_alert_types": [
            "noaa_hazard",
            "usgs_earthquake",
            "swpc_space_weather",
        ],
        "pushover": {
            "enabled": False,
            "userkey": "",
            "appkey": "",
        },
        "drone_wifi": {
            "enabled": True,
            "level": "critical",
            "min_rssi": -80,
            "ssid_patterns": [
                "RID-*",
                "DJI*",
                "Mavic*",
                "Phantom*",
                "Inspire*",
                "Spark*",
                "Mini*",
                "Autel*",
                "Parrot*",
            ],
            "vendor_patterns": ["DJI", "SZ DJI", "Autel", "Parrot", "Yuneec"],
            "oui_prefixes": ["60:60:1f"],
        },
        "aprs_weather": {
            "enabled": True,
            "level": "warning",
            "critical_level": "critical",
            "rain_1h_in": 1.0,
            "critical_rain_1h_in": 2.0,
            "wind_gust_mph": 40,
            "critical_wind_gust_mph": 60,
        },
        "pws_weather": {
            "enabled": True,
            "level": "warning",
            "critical_level": "critical",
            "rain_1h_in": 1.0,
            "critical_rain_1h_in": 2.0,
            "wind_gust_mph": 40,
            "critical_wind_gust_mph": 60,
        },
        "rayhunter_warning": {
            "enabled": True,
            "level": "critical",
        },
        "wifi_disruption": {
            "enabled": True,
            "level": "critical",
            "window_sec": 60,
            "count": 5,
        },
        "wifi_open_sensitive": {
            "enabled": True,
            "level": "critical",
            "ssid_patterns": [],
        },
        "ble_tracker": {
            "enabled": True,
            "level": "critical",
            "min_rssi": -85,
            "name_patterns": [
                "*airtag*",
                "*find my*",
                "*tile*",
                "*chipolo*",
                "*smarttag*",
                "*tracker*",
                "*pebblebee*",
                "*orbit*",
            ],
            "manufacturer_patterns": [],
            "service_uuid_patterns": ["fd44"],
        },
        "collector_issue": {
            "enabled": False,
            "level": "warning",
            "ignored_reason_patterns": [
                "*No monitor-mode Wi-Fi interface found*",
            ],
        },
        "noaa_hazard": {
            "enabled": True,
            "level": "warning",
            "critical_level": "critical",
            "critical_events": [
                "*tsunami warning*",
                "*tornado warning*",
                "*hurricane warning*",
                "*flash flood warning*",
            ],
            "critical_severities": ["Extreme"],
        },
        "usgs_earthquake": {
            "enabled": True,
            "level": "warning",
            "critical_level": "critical",
            "warning_magnitude_nearby": 4.0,
            "critical_magnitude_nearby": 5.0,
            "warning_magnitude_global": 6.5,
            "critical_magnitude_global": 7.5,
            "nearby_radius_km": 100,
            "critical_alert_colors": ["orange", "red"],
        },
        "swpc_space_weather": {
            "enabled": True,
            "level": "warning",
            "critical_level": "critical",
            "alert_min_xray_class": "X1.0",
            "critical_min_xray_class": "X5.0",
            "alert_min_radio_blackout": "R3",
            "critical_min_radio_blackout": "R4",
            "alert_min_solar_radiation_storm": "S3",
            "critical_min_solar_radiation_storm": "S4",
            "alert_min_geomagnetic_storm": "G3",
            "critical_min_geomagnetic_storm": "G4",
            "alert_min_kp": 7,
            "critical_min_kp": 8,
        },
        "lan_gateway_change": {
            "enabled": True,
            "level": "warning",
        },
        "lan_new_device": {
            "enabled": False,
            "level": "warning",
        },
        "adsb_aircraft": {
            "enabled": True,
            "level": "warning",
            "critical_level": "critical",
            "nearby_radius_km": 10,
            "low_altitude_ft": 1500,
        },
        "rtl433_signal": {
            "enabled": False,
            "level": "warning",
            "categories": ["tpms", "security"],
            "model_patterns": [],
            "protocols": [],
        },
    },
    "history_analysis": {
        "new_device_window_sec": 3600,
        "strong_wifi_rssi": -50,
        "strong_ble_rssi": -55,
        "many_bssid_count": 2,
        "wifi_same_ap_bssid_prefix_bytes": 5,
        "wifi_same_ap_max_last_byte_span": 16,
        "many_probe_ssid_count": 5,
        "blank_probe_count": 10,
        "deauth_count": 5,
        "randomized_mac_count": 10,
        "ble_linger_sec": 3600,
        "ble_lost_count": 3,
        "ble_recurring_min_sessions": 3,
        "ble_recurring_window_min": 30,
        "recent_activity_window_sec": 1800,
        "insights_recent_minutes": 60,
        "wifi_short_lived_sec": 900,
        "rtl433_recent_min_events": 1,
        "sensitive_ssids": [],
    },
    "reports": {
        "ble_long_presence_sec": 3600,
        "ble_recurring_min_days": 2,
        "ble_private_address_group_min_count": 3,
        "new_device_window_sec": 3600,
        "ble_strong_rssi": -55,
        "wifi_strong_rssi": -50,
        "wifi_signal_swing_db": 15,
        "wifi_many_bssid_count": 2,
        "wifi_recurring_min_days": 2,
        "wifi_long_presence_sec": 14400,
        "wifi_intermit_min_sessions": 3,
        "wifi_monitor_event_count": 5,
        "aprs_mobile_min_distance_km": 0.3,
        "aprs_weather_temp_change_f": 5,
        "aprs_weather_high_rain_1h_in": 0.25,
        "aprs_weather_high_wind_mph": 25,
        "aprs_weather_high_gust_mph": 35,
        "pws_weather_temp_change_f": 5,
        "pws_weather_high_rain_1h_in": 0.25,
        "pws_weather_high_wind_mph": 25,
        "pws_weather_high_gust_mph": 35,
        "noaa_high_severities": ["Severe", "Extreme"],
        "usgs_nearby_radius_km": 100,
        "usgs_warning_magnitude": 4.0,
        "swpc_report_xray_class": "X1.0",
        "swpc_report_radio_blackout": "R3",
        "swpc_report_solar_radiation_storm": "S3",
        "swpc_report_geomagnetic_storm": "G3",
        "swpc_report_kp": 7,
        "adsb_low_altitude_ft": 1500,
        "adsb_nearby_radius_km": 10,
        "adsb_report_min_seen": 3,
        "rtl433_report_min_events": 2,
        "lan_report_new_devices": True,
        "lan_report_gateway_changes": True,
    },
    "ui": {
        "max_live_rows": 200,
        "max_history_rows": 500,
        "max_history_payload_rows": 1500,
        "max_event_log_items": 100,
        "max_rendered_findings": 1000,
        "max_history_ssids": 8,
        "bluetooth_live_recent_sec": 600,
        "poll_feed_live_ttl_sec": 86400,
        "device_history_update_interval_sec": 60,
        "derived_stale_after_min": 15,
        "derived_auto_refresh_min": 15,
        "derived_refresh_timeout_sec": 600,
        "insights_recent_after_min": 30,
    },
    "collectors": {},
}


def deep_update(base, override):
    """Merge a user config into defaults without losing nested defaults."""
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_update(base[key], value)
        else:
            base[key] = value
    return base


def project_dir_for_config(path):
    """Return the standard project root for a config file path."""
    directory = os.path.dirname(os.path.abspath(path))
    if os.path.basename(directory) == "config":
        return os.path.dirname(directory)
    return directory or PROJECT_ROOT


def collector_config_dir(config_path):
    """Return the directory containing per-collector YAML files."""
    configured = os.path.join(
        project_dir_for_config(config_path), "config", "collectors"
    )
    return configured if os.path.isdir(configured) else CONFIG_COLLECTORS_DIR


def load_collector_configs(config_path):
    """Load config/collectors/*.yaml into the runtime collector map.

    Collector YAML files keep collector-specific settings and display metadata
    out of the global skannr.yaml. The returned shape remains
    config["collectors"][key] so existing collector classes do not need to know
    where their settings came from.
    """
    directory = collector_config_dir(config_path)
    collectors = {}
    if not os.path.isdir(directory):
        return collectors
    for filename in sorted(os.listdir(directory)):
        if not filename.endswith((".yaml", ".yml")):
            continue
        path = os.path.join(directory, filename)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError):
            # A bad collector config should not prevent Skannr from starting;
            # that collector simply will not be present in this run.
            continue
        key = str(data.get("key") or os.path.splitext(filename)[0]).strip()
        if not key:
            continue
        item = dict(data)
        item["key"] = key
        item.setdefault("config_file", path)
        collectors[key] = item
    return collectors


def detect_hardware(config):
    """Populate config['hardware'] with collector-owned probe results."""
    config["hardware"] = detect_collector_hardware(config)
    return config["hardware"]


def load_config(path):
    """Load config/skannr.yaml, apply defaults, and refresh runtime probes."""
    config_path = os.path.abspath(path)
    config = copy.deepcopy(DEFAULT_CONFIG)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        if "listeners" in loaded:
            raise ValueError(
                "listeners must be nested under skannr.listeners, "
                "not at the top level"
            )
        skannr = loaded.get("skannr") or {}
        if "host" in skannr or "port" in skannr:
            raise ValueError(
                "skannr.host/skannr.port are no longer supported; "
                'use skannr.listeners such as ["127.0.0.1:5004"]'
            )
        # Collector settings are intentionally read only from
        # config/collectors/*.yaml. Ignore stale pre-layout collector blocks so
        # they cannot override per-collector config files.
        loaded.pop("collectors", None)
        deep_update(config, loaded)
    else:
        # Only create config/skannr.yaml on a fresh checkout. Existing files are
        # never rewritten on startup, which preserves user comments and
        # formatting.
        config["collectors"] = load_collector_configs(path)
        detect_hardware(config)
        save_config(path, config)
    config["collectors"] = load_collector_configs(path)
    config["persistence"]["filesystem"]["retention_days"] = normalize_retention_days(
        config["persistence"]["filesystem"].get("retention_days"),
        DEFAULT_CONFIG["persistence"]["filesystem"]["retention_days"],
    )
    # Keep the project/config location in memory only. Relative paths such as
    # runtime/logs should follow the project root, not whatever directory
    # started Python.
    config["_config_path"] = config_path
    config["_project_dir"] = project_dir_for_config(config_path)
    log_dir = config["persistence"]["filesystem"].get("log_dir", "runtime/logs")
    if not os.path.isabs(log_dir):
        config["persistence"]["filesystem"]["log_dir"] = os.path.abspath(
            os.path.join(config["_project_dir"], log_dir)
        )
    detect_hardware(config)
    return config


def save_config(path, config):
    """Persist global config without generated probes or collector YAML data."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    saved = copy.deepcopy(config)
    saved.pop("hardware", None)
    saved.pop("collectors", None)
    saved.pop("_config_path", None)
    saved.pop("_project_dir", None)
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(saved, fh, sort_keys=False, width=1000)
