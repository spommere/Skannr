"""Offline vendor lookup for Wi-Fi and Bluetooth MAC addresses.

Skannr never reaches out to the Internet during scans. If users place IEEE
registry files in collectors/, these helpers resolve BSSIDs/MACs locally;
otherwise callers still get useful fallback text such as locally administered /
randomized.
"""

import os
import re


_VENDORS = None


def collectors_dir():
    """Return the local collector data directory."""
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "collectors"
    )


def normalize_oui(mac_or_oui):
    """Return AA:BB:CC from a MAC/OUI string, or None when not parseable."""
    text = str(mac_or_oui or "").strip().upper().replace("-", ":")
    parts = text.split(":")
    if len(parts) >= 3 and all(
        re.match(r"^[0-9A-F]{2}$", part) for part in parts[:3]
    ):
        return ":".join(parts[:3])
    compact = re.sub(r"[^0-9A-F]", "", text)
    if len(compact) >= 6:
        return "{}:{}:{}".format(compact[0:2], compact[2:4], compact[4:6])
    return None


def compact_mac(mac_or_oui):
    """Return uppercase hex digits from a MAC/OUI string."""
    return re.sub(r"[^0-9A-F]", "", str(mac_or_oui or "").upper())


def format_prefix(prefix):
    """Format a compact IEEE prefix as colon-separated display text."""
    if not prefix:
        return ""
    pairs = [
        prefix[index : index + 2] for index in range(0, len(prefix) - 1, 2)
    ]
    if len(prefix) % 2:
        pairs.append(prefix[-1])
    return ":".join(pairs)


def vendor_name(mac_or_oui):
    """Return a vendor name from local IEEE registry files, or None."""
    if is_locally_administered(mac_or_oui):
        return "locally administered / randomized"
    match = vendor_match(mac_or_oui)
    return match["name"] if match else None


def vendor_prefix(mac_or_oui):
    """Return the matched IEEE prefix, formatted for display."""
    if is_locally_administered(mac_or_oui):
        return normalize_oui(mac_or_oui)
    match = vendor_match(mac_or_oui)
    return format_prefix(match["prefix"]) if match else None


def vendor_match(mac_or_oui):
    """Return the longest matching vendor record for a MAC/OUI string."""
    if is_locally_administered(mac_or_oui):
        # Locally administered addresses are intentionally not IEEE-assigned.
        # Calling them randomized is more accurate than matching the remaining
        # bytes against a registry prefix by accident.
        return None
    compact = compact_mac(mac_or_oui)
    if len(compact) < 6:
        return None
    data = vendors()
    # Prefer the most specific registry first: MA-S/IAB (36-bit), then MA-M
    # (28-bit), then the traditional MA-L/OUI 24-bit assignment.
    for length in (9, 7, 6):
        prefix = compact[:length]
        if prefix in data:
            return {"prefix": prefix, "name": data[prefix]}
    return None


def is_locally_administered(mac_or_oui):
    """Return True when the local/randomized MAC bit is set."""
    compact = compact_mac(mac_or_oui)
    if len(compact) < 2:
        return False
    try:
        return bool(int(compact[:2], 16) & 0x02)
    except ValueError:
        return False


def vendors(path=None):
    """Load and cache local IEEE MA-L/MA-M/MA-S/IAB mappings."""
    global _VENDORS
    if _VENDORS is not None and path is None:
        return _VENDORS
    if path is not None:
        # Explicit paths are used by tests/manual checks and should not replace
        # the process-wide cache for the normal collector lookup files.
        loaded = load_oui_file(path)
    else:
        loaded = load_all_registry_files()
    if path is None:
        _VENDORS = loaded
    return loaded


def load_all_registry_files():
    """Parse all supported local IEEE registry files into one prefix map."""
    directory = collectors_dir()
    loaded = {}
    loaded.update(load_oui_file(os.path.join(directory, "oui.txt")))
    loaded.update(
        load_range_registry_file(os.path.join(directory, "mam.txt"), 7)
    )
    loaded.update(
        load_range_registry_file(os.path.join(directory, "oui36.txt"), 9)
    )
    loaded.update(
        load_range_registry_file(os.path.join(directory, "iab.txt"), 9)
    )
    return loaded


def load_oui_file(path):
    """Parse IEEE oui.txt '(hex)' rows into {'AABBCC': 'Vendor'}."""
    if not os.path.exists(path):
        return {}
    loaded = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                match = re.match(
                    r"\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$",
                    line,
                )
                if not match:
                    continue
                prefix = "{}{}{}".format(
                    match.group(1), match.group(2), match.group(3)
                ).upper()
                loaded[prefix] = match.group(4).strip()
    except OSError:
        return {}
    return loaded


def load_range_registry_file(path, prefix_length):
    """Parse MA-M, MA-S, and IAB range files into compact prefix records.

    These files carry a 24-bit base OUI line followed by one or more base-16
    ranges. The first hex digits of the range extend the OUI to the registry's
    assignment length: 7 hex digits for MA-M and 9 for MA-S/IAB.
    """
    if not os.path.exists(path):
        return {}
    loaded = {}
    current_oui = None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                oui_match = re.match(
                    r"\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$",
                    line,
                )
                if oui_match:
                    current_oui = "{}{}{}".format(
                        oui_match.group(1),
                        oui_match.group(2),
                        oui_match.group(3),
                    ).upper()
                    continue
                range_match = re.match(
                    r"\s*([0-9A-Fa-f]+)-[0-9A-Fa-f]+\s+\(base 16\)\s+(.+?)\s*$",
                    line,
                )
                if not range_match or not current_oui:
                    continue
                extension = range_match.group(1).upper()
                prefix = (current_oui + extension)[:prefix_length]
                if len(prefix) == prefix_length:
                    loaded[prefix] = range_match.group(2).strip()
    except OSError:
        return {}
    return loaded
