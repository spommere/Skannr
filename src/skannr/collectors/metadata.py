"""Shared collector identity metadata.

This file is intentionally small: it keeps collector names, ordering, and broad
capability flags in one place without trying to hide collector-specific capture
logic. Hardware probes and event parsing still live with the modules that know
those domains.
"""

ACQUISITION_SCAN = "scan"
ACQUISITION_POLL = "poll"
ACQUISITION_LISTEN = "listen"

COLLECTOR_ACQUISITION_MODES = (ACQUISITION_SCAN, ACQUISITION_POLL, ACQUISITION_LISTEN)


FALLBACK_COLLECTOR_DEFINITIONS = [
    {
        "key": "wifi",
        "order": 10,
        "label": "Wi-Fi Scan",
        "description": "Lightweight Wi-Fi access-point scanning",
        "acquisition_mode": ACQUISITION_SCAN,
        "has_subject_history": True,
    },
    {
        "key": "wifi_monitor",
        "order": 20,
        "label": "Wi-Fi Monitor",
        "description": "On-demand monitor-mode Wi-Fi packet capture and channel hopping",
        "acquisition_mode": ACQUISITION_LISTEN,
        "has_subject_history": True,
    },
    {
        "key": "ble",
        "order": 30,
        "label": "BLE Scan",
        "description": "Bluetooth Low Energy advertisement scanning",
        "source_group": "bluetooth",
        "source_group_label": "Bluetooth",
        "acquisition_mode": ACQUISITION_SCAN,
        "has_subject_history": True,
    },
    {
        "key": "ble_identify",
        "kind": "action",
        "order": 40,
        "label": "BLE Identify",
        "description": "On-demand active BLE Device Information Service reader",
        "source_group": "bluetooth",
        "source_group_label": "Bluetooth",
        "acquisition_mode": ACQUISITION_SCAN,
        "has_subject_history": True,
    },
    {
        "key": "bt_classic",
        "order": 45,
        "label": "Bluetooth Classic",
        "description": "Classic Bluetooth inquiry scanning",
        "source_group": "bluetooth",
        "source_group_label": "Bluetooth",
        "acquisition_mode": ACQUISITION_SCAN,
        "has_subject_history": True,
    },
    {
        "key": "rtl433",
        "order": 53,
        "label": "RTL-433",
        "description": "Optional rtl_433 decoded ISM-band device feed",
        "acquisition_mode": ACQUISITION_LISTEN,
        "has_subject_history": True,
    },
    {
        "key": "adsb",
        "order": 55,
        "label": "ADS-B",
        "description": "Optional dump1090/readsb decoded aircraft feed",
        "acquisition_mode": ACQUISITION_LISTEN,
        "has_subject_history": True,
    },
    {
        "key": "rayhunter",
        "order": 60,
        "label": "Rayhunter",
        "description": "Optional Rayhunter cellular-monitor status endpoint",
        "acquisition_mode": ACQUISITION_POLL,
        "has_subject_history": True,
    },
    {
        "key": "aprsis",
        "order": 70,
        "label": "APRS-IS",
        "description": "Optional internet-fed APRS-IS local-area situational feed",
        "acquisition_mode": ACQUISITION_LISTEN,
        "has_subject_history": True,
    },
    {
        "key": "noaa",
        "order": 80,
        "label": "NOAA",
        "description": "Optional internet-fed NOAA/NWS/NHC/tsunami.gov hazard feed",
        "acquisition_mode": ACQUISITION_POLL,
        "has_subject_history": True,
    },
    {
        "key": "usgs",
        "order": 90,
        "label": "USGS",
        "description": "Optional internet-fed USGS earthquake feed",
        "acquisition_mode": ACQUISITION_POLL,
        "has_subject_history": True,
    },
    {
        "key": "swpc",
        "order": 95,
        "label": "SWPC",
        "description": "Optional internet-fed NOAA SWPC space-weather event feed",
        "acquisition_mode": ACQUISITION_POLL,
        "has_subject_history": True,
    },
    {
        "key": "lan",
        "order": 110,
        "label": "LAN",
        "description": "Optional passive local-network neighbor observation",
        "acquisition_mode": ACQUISITION_SCAN,
        "has_subject_history": True,
    },
    {
        "key": "lan_identify",
        "kind": "action",
        "order": 115,
        "label": "LAN Identify",
        "description": "On-demand active LAN service and HTTP clue collector",
        "source_group": "lan",
        "source_group_label": "LAN",
        "acquisition_mode": ACQUISITION_SCAN,
        "has_subject_history": True,
    },
    {
        "key": "llm",
        "kind": "action",
        "order": 120,
        "label": "LLM",
        "description": "Local LLM-powered subject analysis",
        "acquisition_mode": ACQUISITION_POLL,
        "has_subject_history": False,
    },
    {
        "key": "pws",
        "order": 100,
        "label": "PWS",
        "description": "Optional personal weather station feed",
        "acquisition_mode": ACQUISITION_SCAN,
        "has_subject_history": True,
    },
]


def acquisition_mode(value, default=ACQUISITION_SCAN):
    """Return a supported acquisition mode for collector metadata."""
    mode = str(value or default or "").strip().lower()
    return mode if mode in COLLECTOR_ACQUISITION_MODES else default


def collector_definitions(config=None, include_system=True):
    """Return collector metadata from static definitions plus loaded YAML."""
    definitions = {
        item["key"]: dict(item)
        for item in FALLBACK_COLLECTOR_DEFINITIONS
        if item.get("kind") != "action"
    }
    for key, item in ((config or {}).get("collectors") or {}).items():
        if item.get("kind") == "action":
            continue
        base = definitions.get(key, {})
        definitions[key] = {
            **base,
            "key": key,
            "label": item.get("label") or base.get("label") or key,
            "description": item.get("description") or base.get("description") or "",
            "acquisition_mode": acquisition_mode(
                item.get("acquisition_mode"),
                base.get("acquisition_mode", ACQUISITION_SCAN),
            ),
            "source_group": item.get("source_group")
            or base.get("source_group")
            or item.get("key")
            or key,
            "source_group_label": item.get("source_group_label")
            or base.get("source_group_label")
            or item.get("label")
            or base.get("label")
            or key,
            "has_subject_history": bool(base.get("has_subject_history", True)),
            "order": item.get("order", base.get("order", 999)),
        }
    output = sorted(
        definitions.values(), key=lambda item: (item.get("order", 999), item["key"])
    )
    if include_system:
        output = output + [
            {
                "key": "system",
                "label": "System",
                "description": "Skannr collector health and dependency checks",
                "acquisition_mode": ACQUISITION_POLL,
                "has_subject_history": False,
                "order": 9999,
            }
        ]
    return output


def source_definition_from_config(key, item, base=None):
    """Return source metadata for one collector/action."""
    base = base or {}
    return {
        "key": key,
        "label": item.get("label") or base.get("label") or key,
        "acquisition_mode": acquisition_mode(
            item.get("acquisition_mode"), base.get("acquisition_mode", ACQUISITION_SCAN)
        ),
        "source_group": item.get("source_group")
        or base.get("source_group")
        or item.get("key")
        or key,
        "source_group_label": item.get("source_group_label")
        or base.get("source_group_label")
        or item.get("label")
        or base.get("label")
        or key,
        "order": item.get("order", base.get("order", 999)),
    }


def all_source_definitions(config=None, include_system=True):
    """Return collector/action source metadata for UI source grouping."""
    definitions = {item["key"]: dict(item) for item in FALLBACK_COLLECTOR_DEFINITIONS}
    for key, item in ((config or {}).get("collectors") or {}).items():
        definitions[key] = source_definition_from_config(
            key, item, definitions.get(key)
        )
    output = sorted(
        definitions.values(), key=lambda item: (item.get("order", 999), item["key"])
    )
    if include_system:
        output = output + [
            {
                "key": "system",
                "label": "System",
                "acquisition_mode": ACQUISITION_POLL,
                "source_group": "system",
                "source_group_label": "System",
                "order": 9999,
            }
        ]
    return output


def collector_keys(config=None, include_system=True):
    """Return collector keys in the dashboard order."""
    return [
        item["key"]
        for item in collector_definitions(config, include_system=include_system)
    ]


def browser_subtabs(config=None):
    """Return the super-tab source list used by the browser."""
    tabs = [{"value": "all", "label": "All"}]
    seen = set()
    for item in collector_definitions(config, include_system=True):
        # Multiple collectors can share one browser group. BLE Scan, BLE
        # Identify, and Bluetooth Classic all appear under "Bluetooth".
        value = item.get("source_group") or item["key"]
        if value in seen:
            continue
        seen.add(value)
        tabs.append(
            {
                "value": value,
                "label": item.get("source_group_label") or item["label"],
            }
        )
    return tabs


def browser_source_groups(config=None):
    """Return grouped collector sources for browser filtering."""
    groups = {}
    for item in all_source_definitions(config, include_system=True):
        value = item.get("source_group") or item["key"]
        groups.setdefault(
            value,
            {
                "label": item.get("source_group_label") or item["label"],
                "members": [],
            },
        )
        groups[value]["members"].append(item["key"])
    return groups
