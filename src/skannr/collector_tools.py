"""Collector tool inventory used by install-time prechecks.

Runtime health remains owned by each collector's ``hardware_status()`` and
``detect()`` methods. This module is intentionally advisory: it gives operators
one readable install-time inventory without deciding whether a disabled
collector should fail startup.
"""

import importlib.util
import shutil

COLLECTOR_TOOL_REQUIREMENTS = [
    {
        "collector": "Wi-Fi Scan",
        "any_commands": ["iw", "iwlist"],
        "note": "needed when managed Wi-Fi scan is enabled",
    },
    {
        "collector": "Wi-Fi Monitor",
        "commands": ["iw"],
        "python_modules": ["scapy"],
        "note": "needed when monitor-mode capture is enabled",
    },
    {
        "collector": "Bluetooth BLE",
        "python_modules": ["bleak"],
        "note": "needed when BLE scanning is enabled",
    },
    {
        "collector": "Bluetooth Classic",
        "any_commands": ["hcitool", "bluetoothctl"],
        "note": "needed when classic Bluetooth inquiry is enabled",
    },
    {
        "collector": "RTL-433 decoder",
        "commands": ["rtl_433"],
        "note": "needed when the rtl433 collector is enabled",
    },
    {
        "collector": "ADS-B decoder",
        "any_commands": ["dump1090", "dump1090-fa", "dump1090-mutability", "readsb"],
        "note": "needed when ADS-B manages its decoder locally",
    },
    {
        "collector": "LAN",
        "commands": ["ip"],
        "optional_commands": ["arp", "arp-scan", "avahi-browse"],
        "note": "optional tools enrich passive/active LAN collection",
    },
    {
        "collector": "LAN Identify",
        "commands": ["nmap", "curl"],
        "note": "needed only for on-demand LAN Identify",
    },
]


def command_found(name):
    """Return whether an executable exists in PATH."""
    return bool(shutil.which(name))


def python_module_found(name):
    """Return whether a Python module is importable."""
    return importlib.util.find_spec(name) is not None


def status_word(found):
    """Return a compact status label."""
    return "found" if found else "missing"


def probe_requirement(requirement):
    """Return one operator-facing collector tool row."""
    parts = []
    for command in requirement.get("commands") or []:
        parts.append("{}: {}".format(command, status_word(command_found(command))))
    any_commands = requirement.get("any_commands") or []
    if any_commands:
        found = any(command_found(command) for command in any_commands)
        parts.append("{}: {}".format("/".join(any_commands), status_word(found)))
    for module in requirement.get("python_modules") or []:
        parts.append(
            "python:{}: {}".format(module, status_word(python_module_found(module)))
        )
    for command in requirement.get("optional_commands") or []:
        parts.append(
            "optional {}: {}".format(command, status_word(command_found(command)))
        )
    return {
        "collector": requirement["collector"],
        "status": ", ".join(parts) if parts else "no external tool required",
        "note": requirement.get("note") or "",
    }


def precheck_rows():
    """Return all install-time collector tool rows."""
    return [probe_requirement(item) for item in COLLECTOR_TOOL_REQUIREMENTS]


def main():
    """Print the install-time collector tool inventory."""
    print("Collector tool precheck:")
    for row in precheck_rows():
        suffix = " ({})".format(row["note"]) if row["note"] else ""
        print("  {collector}: {status}{suffix}".format(suffix=suffix, **row))
    print("Missing tools only matter when the matching collector/action is enabled.")


if __name__ == "__main__":
    main()
