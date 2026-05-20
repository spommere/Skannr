"""Configuration loading and lightweight hardware/software detection.

Global settings live in skannr.yaml. Collector-specific settings live in
collectors/*.yaml, then get merged into config["collectors"] so the rest of the
runtime can treat all settings as one dictionary.
"""

import copy
import importlib.util
import os
import shutil
import subprocess

import yaml

from log_utils import normalize_retention_days


# These defaults make a fresh Skannr checkout runnable without a config
# file. load_config() writes them only when skannr.yaml does not exist, then
# overlays any user edits in memory on later runs.
DEFAULT_CONFIG = {
    "skannr": {
        "host": "127.0.0.1",
        "port": 5000,
        "log_level": "INFO",
    },
    "persistence": {
        "backend": "filesystem",
        "filesystem": {
            "log_dir": "./logs",
            "retention_days": 30,
        },
    },
    "runtime": {
        "event_log_maxlen": 100,
        "sse_queue_size": 200,
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
        "burst_window_sec": 30,
        "burst_count": 5,
        "cooldown_sec": 120,
        "persistent_signal_sec": 60,
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
        "wifi_short_lived_sec": 900,
        "sensitive_ssids": [],
    },
    "reports": {
        "ble_long_presence_sec": 3600,
        "ble_recurring_min_days": 2,
        "ble_private_address_group_min_count": 3,
        "new_device_window_sec": 3600,
        "ble_strong_rssi": -55,
        "wifi_strong_rssi": -50,
        "wifi_many_bssid_count": 2,
        "wifi_monitor_event_count": 5,
    },
    "ui": {
        "max_live_rows": 200,
        "max_history_rows": 500,
        "max_event_log_items": 100,
        "max_rendered_findings": 1000,
        "max_history_ssids": 8,
        "derived_stale_after_min": 15,
        "insights_recent_after_min": 30,
        "wifi_signal_bands": [
            {"value": "strong", "label": "Strong (>= -60)", "min": -60},
            {
                "value": "okay",
                "label": "Okay (-60 to -70)",
                "min": -70,
                "max": -60,
            },
            {
                "value": "poor",
                "label": "Poor (-70 to -80)",
                "min": -80,
                "max": -70,
            },
            {
                "value": "very_poor",
                "label": "Very Poor (-80 or worse)",
                "max": -80,
            },
        ],
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
    """Return the directory that owns skannr.yaml."""
    directory = os.path.dirname(os.path.abspath(path))
    return directory or os.getcwd()


def collector_config_dir(config_path):
    """Return the directory containing per-collector YAML files."""
    configured = os.path.join(project_dir_for_config(config_path), "collectors")
    if os.path.isdir(configured):
        return configured
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "collectors"
    )


def load_collector_configs(config_path):
    """Load collectors/*.yaml into the runtime collector map.

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


def command_succeeds(command):
    """Return True when a probe command exits successfully."""
    try:
        subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=5,
        )
        return True
    except Exception:
        return False


def bluetoothctl_has_controller():
    """Detect Bluetooth when /sys or hciconfig do not expose the adapter."""
    try:
        result = subprocess.run(
            ["bluetoothctl", "list"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
            universal_newlines=True,
        )
        return "Controller " in result.stdout
    except Exception:
        return False


def adapter_exists(adapter):
    """Check for a Bluetooth adapter using several Pi/Linux mechanisms."""
    if os.path.exists(os.path.join("/sys/class/bluetooth", adapter)):
        return True
    if command_succeeds(["hciconfig", adapter]):
        return True
    if adapter == "hci0" and bluetoothctl_has_controller():
        return True
    return False


def interface_exists(interface):
    """Check whether a Linux network interface exists."""
    return os.path.exists(os.path.join("/sys/class/net", interface))


def package_available(name):
    """Check whether an optional Python package is importable in this venv."""
    return importlib.util.find_spec(name) is not None


def detect_hardware(config):
    """Populate config['hardware'] with static probe results for the UI.

    These are not active scans. They answer questions like "is rtl_power in
    PATH?", "does wlan1 exist?", and "is scapy installed for monitor capture?"
    so System Status can separate missing software from missing radio hardware.
    """
    collectors = config.get("collectors") or {}
    hardware = {}
    # The UI wants one row of probe results per collector. Keep the details
    # here in sync with the collector YAML defaults, but leave active validation
    # to each collector's detect() method.
    if "rtlsdr" in collectors:
        hardware["rtlsdr"] = {
            "rtl_power": bool(shutil.which("rtl_power")),
            "rtl_test": bool(shutil.which("rtl_test")),
        }
    if "ble" in collectors:
        ble = collectors["ble"]
        hardware["ble"] = {
            "preferred_detected": adapter_exists(
                ble.get("preferred_adapter", "hci1")
            ),
            "fallback_detected": adapter_exists(
                ble.get("fallback_adapter", "hci0")
            ),
            "preferred_adapter": ble.get("preferred_adapter", "hci1"),
            "fallback_adapter": ble.get("fallback_adapter", "hci0"),
            "bleak": package_available("bleak"),
        }
    if "ble_identify" in collectors:
        ble_identify = collectors["ble_identify"]
        hardware["ble_identify"] = {
            "preferred_detected": adapter_exists(
                ble_identify.get("preferred_adapter", "hci1")
            ),
            "fallback_detected": adapter_exists(
                ble_identify.get("fallback_adapter", "hci0")
            ),
            "preferred_adapter": ble_identify.get("preferred_adapter", "hci1"),
            "fallback_adapter": ble_identify.get("fallback_adapter", "hci0"),
            "bleak": package_available("bleak"),
            "auto_start": ble_identify.get("auto_start", False),
        }
    if "bt_classic" in collectors:
        bt_classic = collectors["bt_classic"]
        hardware["bt_classic"] = {
            "preferred_detected": adapter_exists(
                bt_classic.get("preferred_adapter", "hci1")
            ),
            "fallback_detected": adapter_exists(
                bt_classic.get("fallback_adapter", "hci0")
            ),
            "preferred_adapter": bt_classic.get("preferred_adapter", "hci1"),
            "fallback_adapter": bt_classic.get("fallback_adapter", "hci0"),
            "hcitool": bool(shutil.which("hcitool")),
            "bluetoothctl": bool(shutil.which("bluetoothctl")),
            "auto_start": bt_classic.get("auto_start", False),
        }
    if "wifi" in collectors:
        wifi = collectors["wifi"]
        hardware["wifi"] = {
            "preferred_detected": interface_exists(
                wifi.get("preferred_interface", "wlan1")
            ),
            "fallback_detected": interface_exists(
                wifi.get("fallback_interface", "wlan0")
            ),
            "preferred_interface": wifi.get("preferred_interface", "wlan1"),
            "fallback_interface": wifi.get("fallback_interface", "wlan0"),
            "iw": bool(shutil.which("iw")),
            "iwlist": bool(shutil.which("iwlist")),
        }
    if "wifi_monitor" in collectors:
        wifi_monitor = collectors["wifi_monitor"]
        hardware["wifi_monitor"] = {
            "iw": bool(shutil.which("iw")),
            "airmon_ng": bool(shutil.which("airmon-ng")),
            "scapy": package_available("scapy"),
            "auto_start": wifi_monitor.get("auto_start", False),
            "interface": wifi_monitor.get("interface", "auto"),
        }
    config["hardware"] = hardware
    return hardware


def load_config(path):
    """Load skannr.yaml, apply defaults in memory, and refresh runtime probes."""
    config_path = os.path.abspath(path)
    config = copy.deepcopy(DEFAULT_CONFIG)
    legacy_collectors = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        # Accept the old project key so existing local configs survive the
        # Spectra -> Skannr rename.
        if "spectra" in loaded and "skannr" not in loaded:
            loaded["skannr"] = loaded.pop("spectra")
        legacy_collectors = loaded.pop("collectors", {}) or {}
        deep_update(config, loaded)
    else:
        # Only create skannr.yaml on a fresh checkout. Existing files are never
        # rewritten on startup, which preserves user comments and formatting.
        config["collectors"] = load_collector_configs(path)
        detect_hardware(config)
        save_config(path, config)
    config["collectors"] = load_collector_configs(path)
    deep_update(config["collectors"], legacy_collectors)
    config["persistence"]["filesystem"][
        "retention_days"
    ] = normalize_retention_days(
        config["persistence"]["filesystem"].get("retention_days"),
        DEFAULT_CONFIG["persistence"]["filesystem"]["retention_days"],
    )
    # Keep the project/config location in memory only. Relative paths such as
    # ./logs should follow skannr.yaml, not whatever directory started Python.
    config["_config_path"] = config_path
    config["_project_dir"] = project_dir_for_config(config_path)
    log_dir = config["persistence"]["filesystem"].get("log_dir", "./logs")
    if not os.path.isabs(log_dir):
        config["persistence"]["filesystem"]["log_dir"] = os.path.abspath(
            os.path.join(config["_project_dir"], log_dir)
        )
    detect_hardware(config)
    return config


def save_config(path, config):
    """Persist global config without generated probes or collector YAML data."""
    saved = copy.deepcopy(config)
    saved.pop("hardware", None)
    saved.pop("collectors", None)
    saved.pop("_config_path", None)
    saved.pop("_project_dir", None)
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(saved, fh, sort_keys=False, width=1000)
