"""Shared stable-subject policy for low-identity randomized devices."""

import re


def list_values(value):
    """Return a compact list for scalar/list evidence fields."""
    if value in (None, "", []):
        return []
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if item not in (None, "", [])]
    return [value]


def normalized_mac(value):
    """Return a lower-case colon MAC address or an empty string."""
    compact = "".join(ch for ch in str(value or "") if ch.lower() in "0123456789abcdef")
    if len(compact) != 12:
        return ""
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).lower()


def bluetooth_property_like_name(value):
    """Return True for BlueZ property text that should never be identity."""
    text = " ".join(str(value or "").strip().split())
    if not text:
        return False
    lowered = text.lower()
    prefixes = (
        "rssi:",
        "uuids:",
        "uuid:",
        "txpower:",
        "tx power:",
        "manufacturerdata",
        "manufacturer data:",
        "servicedata",
        "service data:",
        "appearance:",
        "class:",
        "icon:",
        "alias:",
        "name:",
        "legacypairing:",
        "paired:",
        "bonded:",
        "trusted:",
        "blocked:",
        "connected:",
    )
    if lowered.startswith(prefixes):
        return True
    return lowered.startswith("manufacturer ") and ":" in lowered


def locally_administered_mac(value):
    """Return True when a MAC has the local-admin bit set."""
    mac = normalized_mac(value)
    if not mac:
        return False
    try:
        return bool(int(mac.split(":", 1)[0], 16) & 0x02)
    except ValueError:
        return False


def generated_bluetooth_group_label(value):
    """Return True for labels Skannr generated for aggregate Bluetooth rows."""
    text = " ".join(str(value or "").strip().lower().split())
    if not text:
        return False
    generated_suffixes = (
        "randomized bluetooth device",
        "randomized bluetooth devices",
        "randomized bluetooth device found",
        "randomized bluetooth devices found",
        "randomized device",
        "randomized devices",
        "randomized device found",
        "randomized devices found",
    )
    return any(text == suffix or text.endswith(" " + suffix) for suffix in generated_suffixes)


def meaningful_bluetooth_names(record):
    """Return advertised Bluetooth names that are not just the MAC address."""
    mac = normalized_mac((record or {}).get("mac")).replace("-", ":")
    names = []
    if (record or {}).get("name"):
        names.append((record or {}).get("name"))
    names.extend(list_values((record or {}).get("names")))
    useful = []
    for name in names:
        text = str(name or "").strip()
        if not text:
            continue
        if text.lower().replace("-", ":") == mac:
            continue
        if bluetooth_property_like_name(text):
            continue
        if generated_bluetooth_group_label(text):
            continue
        useful.append(text)
    return sorted(set(useful))


KNOWN_BLUETOOTH_MANUFACTURER_CODES = {
    "0x004c": "Apple",
}


_BLUETOOTH_MANUFACTURER_CODE_RE = re.compile(r"0x[0-9a-f]{4,}", re.IGNORECASE)


def bluetooth_manufacturer_code(value):
    """Extract a normalized Bluetooth manufacturer code like 0x004c."""
    if isinstance(value, dict):
        candidates = [
            value.get("manufacturer_name"),
            value.get("manufacturer"),
            value.get("vendor_name"),
        ]
    else:
        candidates = [value]
    for candidate in candidates:
        match = _BLUETOOTH_MANUFACTURER_CODE_RE.search(str(candidate or ""))
        if match:
            return match.group(0).lower()
    return ""


def bluetooth_manufacturer_code_only(value):
    """Return True when a manufacturer label is only a numeric company id."""
    text = str(value or "").strip()
    return bool(text) and bool(_BLUETOOTH_MANUFACTURER_CODE_RE.fullmatch(text))


def cleaned_bluetooth_manufacturer_text(value):
    """Return manufacturer text with trailing company-id codes removed."""
    text = " ".join(str(value or "").strip().split())
    if not text:
        return ""
    text = re.sub(r"\s*\(0x[0-9a-f]{4,}\)\s*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*\[0x[0-9a-f]{4,}\]\s*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+0x[0-9a-f]{4,}\s*$", "", text, flags=re.IGNORECASE)
    return text.strip(' ,;-')


def bluetooth_visible_manufacturer_label(value):
    """Return a human-facing Bluetooth manufacturer label or empty string."""
    if isinstance(value, dict):
        candidates = [
            value.get("manufacturer_name"),
            value.get("vendor_name"),
            value.get("manufacturer"),
        ]
    else:
        candidates = [value]
    for candidate in candidates:
        text = cleaned_bluetooth_manufacturer_text(candidate)
        if text and not bluetooth_manufacturer_code_only(text):
            return text
    code = bluetooth_manufacturer_code(value)
    if code:
        return KNOWN_BLUETOOTH_MANUFACTURER_CODES.get(code, "")
    return ""


def bluetooth_manufacturer_label(record):
    """Return the best available Bluetooth manufacturer label."""
    visible = bluetooth_visible_manufacturer_label(record)
    if visible:
        return visible
    return str(
        (record or {}).get("manufacturer_name")
        or (record or {}).get("manufacturer")
        or (record or {}).get("vendor_name")
        or ""
    ).strip()


def low_identity_bluetooth_record(record):
    """Return True for Bluetooth rows that should be aggregated as privacy churn."""
    if (record or {}).get("annotation") or (record or {}).get("custom_name"):
        return False
    # Do not require the collector to prove that a BLE MAC is randomized here.
    # Some rotating BLE addresses in practice arrive without randomized_mac and
    # without the local-admin bit. The compaction layer decides whether to
    # actually group by requiring multiple MACs in the same identity bucket.
    for field in (
        "model_number",
        "serial_number",
        "firmware_revision",
        "hardware_revision",
        "software_revision",
        "pnp_id",
    ):
        if (record or {}).get(field):
            return False
    transports = set(str(item).lower() for item in list_values((record or {}).get("transports")))
    if "bt_classic" in transports or "classic" in transports:
        return False
    return True


def stable_bluetooth_mac_record(record):
    """Return True for a low-detail BLE row that behaves like a stable device."""
    if (record or {}).get("grouped_randomized"):
        return False
    if (record or {}).get("randomized_mac") or locally_administered_mac((record or {}).get("mac")):
        return False
    if (record or {}).get("active_session"):
        return True
    try:
        if int((record or {}).get("update_count") or 0) >= 10:
            return True
    except (TypeError, ValueError):
        pass
    first_seen = numeric_epoch((record or {}).get("first_seen_epoch"))
    last_seen = numeric_epoch((record or {}).get("last_seen_epoch"))
    return first_seen is not None and last_seen is not None and last_seen - first_seen >= 3600


def bluetooth_grouping_candidate(record):
    """Return True when a Bluetooth row is weak enough to fold into a group."""
    if not low_identity_bluetooth_record(record):
        return False
    bucket = bluetooth_identity_bucket(record)
    if bucket[0] == "name" and stable_bluetooth_mac_record(record):
        return False
    return True


def numeric_epoch(value):
    """Return numeric epoch-like values without importing log timestamp helpers."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def bluetooth_identity_bucket(record):
    """Return a stable aggregate identity for low-identity Bluetooth rows."""
    if (record or {}).get("grouped_randomized"):
        kind = str((record or {}).get("identity_bucket") or "").strip()
        label = str((record or {}).get("identity_label") or "").strip()
        if kind and label and not generated_bluetooth_group_label(label):
            return (kind, label)
    if (record or {}).get("findmy_accessory"):
        return ("findmy", "Apple Find My accessory")
    names = meaningful_bluetooth_names(record)
    if names:
        return ("name", names[0])
    manufacturer = bluetooth_manufacturer_label(record) or "Unknown"
    return ("manufacturer", manufacturer)


def bluetooth_group_label(record):
    """Return the Subject History label for a Bluetooth aggregate row."""
    kind, label = bluetooth_identity_bucket(record)
    if kind == "findmy":
        return "Apple Find My accessory randomized devices"
    if kind == "name":
        return "{} randomized Bluetooth devices".format(label)
    display = bluetooth_visible_manufacturer_label(record) or bluetooth_visible_manufacturer_label(label)
    if display:
        return "{} randomized Bluetooth devices".format(display)
    return "Randomized Bluetooth devices"


def low_identity_wifi_client(record):
    """Return True for randomized Wi-Fi client/probe MACs."""
    return bool((record or {}).get("randomized_mac") or locally_administered_mac((record or {}).get("mac")))


def wifi_client_group_label(_record=None):
    """Return the Subject History label for randomized Wi-Fi client rows."""
    return "Randomized Wi-Fi client MACs"


def low_identity_lan_record(record):
    """Return True for LAN rows that have only a private MAC and weak identity."""
    if not locally_administered_mac((record or {}).get("mac")):
        return False
    if (record or {}).get("hostname") or list_values((record or {}).get("hostnames")):
        return False
    for field in (
        "services",
        "open_ports",
        "http_titles",
        "http_urls",
        "locations",
        "servers",
        "service_banners",
    ):
        if list_values((record or {}).get(field)):
            return False
    return True


def lan_group_label(_record=None):
    """Return the Subject History label for low-identity LAN private MAC rows."""
    return "Randomized LAN/private MAC devices"
