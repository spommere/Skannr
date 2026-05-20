"""Collector factory for the configured Skannr collector set.

Each collector owns its hardware/tool behavior. This module only maps
collector keys from YAML metadata to concrete Python classes.
"""

from collectors.rtlsdr import RTLSDRCollector
from collectors.ble import BLECollector
from collectors.ble_identify import BLEIdentifyCollector
from collectors.bt_classic import BluetoothClassicCollector
from collectors.wifi import WiFiCollector
from collectors.wifi_monitor import WiFiMonitorCollector
from collectors.metadata import collector_keys


# Startup order controls the row order in System Status. The class map stays
# explicit, while collectors.metadata owns the shared display order and labels.
COLLECTOR_CLASS_BY_KEY = {
    "wifi": WiFiCollector,
    "wifi_monitor": WiFiMonitorCollector,
    "ble": BLECollector,
    "ble_identify": BLEIdentifyCollector,
    "bt_classic": BluetoothClassicCollector,
    "rtlsdr": RTLSDRCollector,
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
        section = dict(config["collectors"].get(cls.config_key, {}))
        # Some collectors need global paths such as persistence.log_dir, but
        # passing the collector subsection keeps their normal config small.
        section["_global_config"] = config
        if section.get("enabled", True):
            collectors.append(cls(section, bus))
    return collectors
