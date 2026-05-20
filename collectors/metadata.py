"""Shared collector identity metadata.

This file is intentionally small: it keeps collector names, ordering, and broad
capability flags in one place without trying to hide collector-specific capture
logic. Hardware probes and event parsing still live with the modules that know
those domains.
"""


FALLBACK_COLLECTOR_DEFINITIONS = [
    {
        "key": "wifi",
        "label": "Wi-Fi Scan",
        "description": "Lightweight Wi-Fi access-point scanning",
        "has_device_history": True,
    },
    {
        "key": "wifi_monitor",
        "label": "Wi-Fi Monitor",
        "description": "On-demand monitor-mode Wi-Fi packet capture and channel hopping",
        "has_device_history": True,
    },
    {
        "key": "ble",
        "label": "BLE Scan",
        "description": "Bluetooth Low Energy advertisement scanning",
        "source_group": "bluetooth",
        "source_group_label": "Bluetooth",
        "has_device_history": True,
    },
    {
        "key": "ble_identify",
        "label": "BLE Identify",
        "description": "On-demand active BLE Device Information Service reader",
        "source_group": "bluetooth",
        "source_group_label": "Bluetooth",
        "has_device_history": True,
    },
    {
        "key": "bt_classic",
        "label": "Bluetooth Classic",
        "description": "Classic Bluetooth inquiry scanning",
        "source_group": "bluetooth",
        "source_group_label": "Bluetooth",
        "has_device_history": True,
    },
    {
        "key": "rtlsdr",
        "label": "RTL-SDR",
        "description": "rtl_power spectrum scanning",
        "has_device_history": False,
    },
]


def collector_definitions(config=None, include_system=True):
    """Return collector metadata from loaded YAML, with a static fallback."""
    loaded = []
    for key, item in ((config or {}).get("collectors") or {}).items():
        loaded.append({
            "key": key,
            "label": item.get("label") or key,
            "description": item.get("description") or "",
            "source_group": item.get("source_group") or item.get("key") or key,
            "source_group_label": item.get("source_group_label") or item.get("label") or key,
            "has_device_history": bool(item.get("has_device_history", False)),
            "order": item.get("order", 999),
        })
    if loaded:
        definitions = sorted(loaded, key=lambda item: (item.get("order", 999), item["key"]))
    else:
        definitions = list(FALLBACK_COLLECTOR_DEFINITIONS)
    if include_system:
        definitions = definitions + [{
            "key": "system",
            "label": "System",
            "description": "Skannr collector health and dependency checks",
            "has_device_history": False,
            "order": 9999,
        }]
    return definitions


def collector_keys(config=None, include_system=True):
    """Return collector keys in the dashboard order."""
    return [
        item["key"] for item in collector_definitions(config, include_system=include_system)
    ]


def browser_subtabs(config=None):
    """Return the super-tab source list used by the browser."""
    tabs = [{"value": "all", "label": "All"}]
    seen = set()
    for item in collector_definitions(config, include_system=True):
        value = item.get("source_group") or item["key"]
        if value in seen:
            continue
        seen.add(value)
        tabs.append({
            "value": value,
            "label": item.get("source_group_label") or item["label"],
        })
    return tabs


def browser_source_groups(config=None):
    """Return grouped collector sources for browser filtering."""
    groups = {}
    for item in collector_definitions(config, include_system=True):
        value = item.get("source_group") or item["key"]
        groups.setdefault(value, {
            "label": item.get("source_group_label") or item["label"],
            "members": [],
        })
        groups[value]["members"].append(item["key"])
    return groups
