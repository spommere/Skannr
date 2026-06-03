"""Shared low-level hardware and software probes for collectors.

Collector classes decide which probes matter for their own status row. This
module only provides generic Linux checks so config loading does not need to
know about individual collector hardware.
"""

import importlib.util
import os
import subprocess


def command_succeeds(command):
    """Return True when a short probe command exits successfully."""
    try:
        subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=True,
        )
        return True
    except Exception:
        return False


def bluetoothctl_has_controller():
    """Return True when bluetoothctl can see at least one BlueZ controller."""
    try:
        result = subprocess.run(
            ["bluetoothctl", "list"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=3,
            universal_newlines=True,
        )
        return "Controller " in result.stdout
    except Exception:
        return False


def bluetooth_adapter_exists(adapter):
    """Probe for a Bluetooth adapter without depending on one tool."""
    if os.path.exists(os.path.join("/sys/class/bluetooth", adapter)):
        return True
    if command_succeeds(["hciconfig", adapter]):
        return True
    return adapter == "hci0" and bluetoothctl_has_controller()


def bluetooth_adapters():
    """Return Bluetooth adapter names currently visible to Linux."""
    directory = "/sys/class/bluetooth"
    try:
        return sorted(
            name for name in os.listdir(directory) if name.startswith("hci")
        )
    except OSError:
        return ["hci0"] if bluetoothctl_has_controller() else []


def bluetooth_adapter_details(adapter):
    """Return lightweight metadata useful for choosing Bluetooth adapters."""
    device_path = os.path.realpath(
        os.path.join("/sys/class/bluetooth", adapter, "device")
    )
    details = {
        "name": adapter,
        "manufacturer": "",
        "product": "",
        "usb": False,
    }
    current = device_path
    for _ in range(8):
        manufacturer = sysfs_read(os.path.join(current, "manufacturer"))
        product = sysfs_read(os.path.join(current, "product"))
        id_vendor = sysfs_read(os.path.join(current, "idVendor"))
        if manufacturer and not details["manufacturer"]:
            details["manufacturer"] = manufacturer
        if product and not details["product"]:
            details["product"] = product
        if id_vendor:
            details["usb"] = True
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return details


def bluetooth_adapter_score(adapter, config=None):
    """Rank external USB Bluetooth adapters ahead of built-in radios."""
    details = bluetooth_adapter_details(adapter)
    score = 0
    if details["usb"]:
        score += 50
    text = " ".join([details["manufacturer"], details["product"]]).lower()
    preferred_terms = (config or {}).get("preferred_terms") or [
        "asus",
        "plugable",
        "tp-link",
        "ub500",
        "bluetooth 5",
    ]
    if any(term.lower() in text for term in preferred_terms):
        score += 10
    return score


def sort_bluetooth_adapters(adapters, config=None):
    """Sort Bluetooth candidates by likely capability, then adapter name."""
    return sorted(
        adapters,
        key=lambda item: (-bluetooth_adapter_score(item, config), item),
    )


def network_interface_exists(interface):
    """Check whether a Linux network interface exists."""
    return os.path.exists(os.path.join("/sys/class/net", interface))


def wireless_interfaces():
    """Return network interfaces that look like Wi-Fi adapters."""
    directory = "/sys/class/net"
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    interfaces = []
    for name in names:
        path = os.path.join(directory, name)
        if os.path.isdir(os.path.join(path, "wireless")):
            interfaces.append(name)
        elif name.startswith(("wlan", "wlp", "wlx")):
            interfaces.append(name)
    return sorted(set(interfaces))


def configured_candidates(config, list_key, extra_keys=()):
    """Return ordered device candidates from one list and optional keys.

    Collector YAML now treats interfaces and adapters as ordinary ordered
    candidate lists. Some collectors also have a single convenience key such as
    ``interface``; ``extra_keys`` folds those into the same ordered result
    without making the collector code care where the candidate came from.
    """
    values = []
    configured = config.get(list_key)
    if isinstance(configured, str):
        values.extend(
            item.strip() for item in configured.split(",") if item.strip()
        )
    elif isinstance(configured, list):
        values.extend(
            str(item).strip() for item in configured if str(item).strip()
        )
    for key in extra_keys:
        value = str(config.get(key) or "").strip()
        if value:
            values.append(value)
    output = []
    for value in values:
        if value not in output:
            output.append(value)
    return output


def sysfs_read(path):
    """Read a short sysfs file, returning an empty string when absent."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def wireless_interface_details(interface):
    """Return lightweight metadata useful for choosing Wi-Fi adapters."""
    device_path = os.path.realpath(
        os.path.join("/sys/class/net", interface, "device")
    )
    driver_path = os.path.join(device_path, "driver")
    driver = (
        os.path.basename(os.path.realpath(driver_path))
        if os.path.exists(driver_path)
        else ""
    )
    details = {
        "name": interface,
        "driver": driver,
        "vendor_id": sysfs_read(os.path.join(device_path, "vendor")),
        "device_id": sysfs_read(os.path.join(device_path, "device")),
        "manufacturer": "",
        "product": "",
        "usb": False,
        "alfa_like": False,
    }
    current = device_path
    for _ in range(8):
        manufacturer = sysfs_read(os.path.join(current, "manufacturer"))
        product = sysfs_read(os.path.join(current, "product"))
        id_vendor = sysfs_read(os.path.join(current, "idVendor"))
        if manufacturer and not details["manufacturer"]:
            details["manufacturer"] = manufacturer
        if product and not details["product"]:
            details["product"] = product
        if id_vendor:
            details["usb"] = True
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    text = " ".join(
        [
            details["driver"],
            details["manufacturer"],
            details["product"],
        ]
    ).lower()
    details["alfa_like"] = "alfa" in text
    return details


def wifi_interface_score(interface, config=None):
    """Rank likely better Wi-Fi adapters ahead of built-in radios."""
    details = wireless_interface_details(interface)
    score = 0
    if details["alfa_like"]:
        score += 100
    if details["usb"]:
        score += 50
    driver = details["driver"]
    preferred_drivers = (config or {}).get("preferred_drivers") or [
        "ath9k_htc",
        "mt76",
        "rtl88",
        "rtl8xxxu",
        "8812au",
        "88x2bu",
    ]
    if any(driver.startswith(item) for item in preferred_drivers):
        score += 25
    if driver.startswith("brcm"):
        score -= 20
    return score


def sort_wifi_interfaces(interfaces, config=None):
    """Sort Wi-Fi candidates by adapter capability, then by interface name."""
    return sorted(
        interfaces,
        key=lambda item: (-wifi_interface_score(item, config), item),
    )


def monitor_mode_interfaces():
    """Return Wi-Fi interfaces currently configured for monitor mode."""
    try:
        output = subprocess.check_output(
            ["iw", "dev"],
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            timeout=5,
        )
    except Exception:
        return []

    interfaces = []
    current = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("Interface "):
            current = line.split(None, 1)[1].strip()
        elif line == "type monitor" and current:
            interfaces.append(current)
    return sorted(set(interfaces))


def availability_records(configured, discovered, exists_func):
    """Build ordered availability rows for configured and discovered devices."""
    names = []
    for name in configured + discovered:
        if name and name not in names:
            names.append(name)
    return [
        {
            "name": name,
            "available": bool(name in discovered or exists_func(name)),
        }
        for name in names
    ]


def package_available(name):
    """Check whether an optional Python package is importable in this venv."""
    return importlib.util.find_spec(name) is not None
