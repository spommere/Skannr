"""Collector factory for the configured Skannr collector set.

Each collector owns its hardware/tool behavior. This module only maps
collector keys from YAML metadata to concrete Python classes.
"""

from .aprsis import APRSISCollector
from .lan import LANCollector
from .noaa import NOAACollector
from .rtlsdr import RTLSDRCollector
from .rayhunter import RayhunterCollector
from .swpc import SWPCCollector
from .usgs import USGSCollector
from .ble import BLECollector
from .ble_identify import BLEIdentifyCollector
from .bt_classic import BluetoothClassicCollector
from .wifi import WiFiCollector
from .wifi_monitor import WiFiMonitorCollector
from .base import STATE_DISABLED
from .metadata import collector_keys


# Startup order controls the row order in System Status. The class map stays
# explicit, while collectors.metadata owns the shared display order and labels.
COLLECTOR_CLASS_BY_KEY = {
    "wifi": WiFiCollector,
    "wifi_monitor": WiFiMonitorCollector,
    "ble": BLECollector,
    "bt_classic": BluetoothClassicCollector,
    "rtlsdr": RTLSDRCollector,
    "rayhunter": RayhunterCollector,
    "aprsis": APRSISCollector,
    "noaa": NOAACollector,
    "usgs": USGSCollector,
    "swpc": SWPCCollector,
    "lan": LANCollector,
}

ACTION_CLASS_BY_KEY = {
    "ble_identify": BLEIdentifyCollector,
}


def load_collectors(config, bus):
    """Instantiate collectors enabled in their per-collector YAML files."""
    collectors = []
    for key in collector_keys(config, include_system=False):
        cls = COLLECTOR_CLASS_BY_KEY.get(key)
        if not cls:
            # Unknown keys can appear in config while a collector is being
            # developed. Ignore them instead of breaking the rest of the app.
            continue
        if cls.config_key not in (config.get("collectors") or {}):
            continue
        section = dict(config["collectors"].get(cls.config_key, {}))
        # Some collectors need global paths such as persistence.log_dir, but
        # passing the collector subsection keeps their normal config small.
        section["_global_config"] = config
        if section.get("enabled", True):
            collectors.append(cls(section, bus))
    return collectors


def disabled_collector_statuses(config):
    """Return System-table rows for configured but disabled collectors."""
    statuses = []
    collector_config = (config or {}).get("collectors") or {}
    for key in collector_keys(config, include_system=False):
        cls = COLLECTOR_CLASS_BY_KEY.get(key)
        section = collector_config.get(key)
        if not cls:
            continue
        if section is not None and section.get("enabled", True):
            continue
        statuses.append(
            {
                "key": key,
                "name": cls.name,
                "tab_label": cls.tab_label,
                "state": STATE_DISABLED,
                "hardware": cls.required_hardware,
                "events_this_session": 0,
                "last_event": None,
                "last_event_epoch": None,
                "warning": "" if section is not None else "No local collector config file.",
                "enabled": False,
            }
        )
    return statuses


def detect_collector_hardware(config):
    """Return static hardware/software probe results for configured collectors."""
    hardware = {}
    collector_config = config.get("collectors") or {}
    for key in collector_keys(config, include_system=False):
        cls = COLLECTOR_CLASS_BY_KEY.get(key)
        section = collector_config.get(key) or {}
        if not cls:
            continue
        hardware[key] = cls.hardware_status(section)
    return hardware


def load_actions(config, bus):
    """Instantiate enabled on-demand actions that are not dashboard collectors."""
    actions = {}
    collector_config = config.get("collectors") or {}
    for key, cls in ACTION_CLASS_BY_KEY.items():
        section = dict(collector_config.get(key) or {})
        section["_global_config"] = config
        if section.get("enabled", True):
            # Actions validate hardware when invoked. Running validation during
            # startup can block the dashboard on optional tools such as BlueZ.
            actions[key] = cls(section, bus)
    return actions
