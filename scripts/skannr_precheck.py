#!/usr/bin/env python3
"""Install-time Skannr collector precheck.

This script is intentionally standalone and uses only the Python standard
library so it can run before install.sh creates or updates the virtualenv.
It reports required/recommended/optional local tools plus selected hardware
probes, writes config/precheck.yaml by default, and can apply generated
enabled flags to a freshly copied config/collectors tree. SDR-backed
collectors are enabled only when required software and RTL-SDR hardware are
both present; config-required internet/API collectors stay disabled until the
operator edits local YAML.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "skannr"
DEFAULT_OUTPUT = DEFAULT_CONFIG_DIR / "precheck.yaml"
DEFAULT_COLLECTOR_DIR = DEFAULT_CONFIG_DIR / "collectors"

COLLECTORS = [
    {
        "key": "wifi",
        "label": "Wi-Fi Scan",
        "required_any": ["iw", "iwlist"],
        "hint": "sudo apt install iw wireless-tools",
        "enable_when_pass": True,
    },
    {
        "key": "wifi_monitor",
        "label": "Wi-Fi Monitor",
        "required": ["iw"],
        "python_expected": ["scapy"],
        "hint": "sudo apt install iw  # scapy is installed by install.sh",
        "enable_when_pass": True,
    },
    {
        "key": "ble",
        "label": "Bluetooth BLE",
        "required_any": ["bluetoothctl", "hciconfig"],
        "python_expected": ["bleak"],
        "hint": "sudo apt install bluetooth bluez  # bleak is installed by install.sh on supported Python versions",
        "enable_when_pass": True,
    },
    {
        "key": "ble_identify",
        "label": "BLE Identify",
        "same_as": "ble",
        "hint": "same requirements as Bluetooth BLE",
        "enable_when_pass": True,
    },
    {
        "key": "bt_classic",
        "label": "Bluetooth Classic",
        "required_any": ["hcitool", "bluetoothctl"],
        "hint": "sudo apt install bluetooth bluez",
        "enable_when_pass": True,
    },
    {
        "key": "rtl433",
        "label": "RTL-433 decoder",
        "required": ["rtl_433"],
        "recommended": ["rtl_test"],
        "hardware": "rtlsdr",
        "hint": "sudo apt install rtl-433 rtl-sdr",
        "enable_when_pass": True,
    },
    {
        "key": "adsb",
        "label": "ADS-B decoder",
        "required_any": ["dump1090", "dump1090-fa", "dump1090-mutability", "readsb"],
        "hardware": "rtlsdr",
        "hint": "sudo apt install dump1090-mutability  # or install readsb or dump1090-fa",
        "enable_when_pass": True,
    },
    {
        "key": "lan",
        "label": "LAN",
        "required": ["ip"],
        "recommended": ["arp"],
        "optional": ["arp-scan", "avahi-browse"],
        "hint": "sudo apt install iproute2 net-tools arp-scan avahi-daemon avahi-utils",
        "enable_when_pass": True,
    },
    {
        "key": "lan_identify",
        "label": "LAN Identify",
        "required": ["nmap", "curl"],
        "hint": "sudo apt install nmap curl",
        "enable_when_pass": True,
    },
    {
        "key": "aprsis",
        "label": "APRS-IS",
        "config_required": True,
        "hint": "edit config/collectors/aprsis.yaml with callsign/passcode/filter, then set enabled: true",
        "enable_when_pass": False,
    },
    {
        "key": "noaa",
        "label": "NOAA",
        "config_required": True,
        "hint": "edit config/collectors/noaa.yaml for local latitude/longitude/state, then set enabled: true",
        "enable_when_pass": False,
    },
    {
        "key": "usgs",
        "label": "USGS",
        "config_required": True,
        "hint": "edit config/collectors/usgs.yaml for local latitude/longitude/radius, then set enabled: true",
        "enable_when_pass": False,
    },
    {
        "key": "swpc",
        "label": "SWPC",
        "config_required": True,
        "hint": "internet-fed collector; set enabled: true if this host should poll SWPC",
        "enable_when_pass": False,
    },
    {
        "key": "pws",
        "label": "PWS",
        "config_required": True,
        "hint": "edit config/collectors/pws.yaml with Ambient Weather keys, then set enabled: true",
        "enable_when_pass": False,
    },
    {
        "key": "rayhunter",
        "label": "Rayhunter",
        "config_required": True,
        "hint": "edit config/collectors/rayhunter.yaml with the local endpoint, then set enabled: true",
        "enable_when_pass": False,
    },
]


def command_found(name):
    return shutil.which(name) is not None


def python_module_found(name):
    try:
        __import__(name)
        return True
    except Exception:
        return False


def rtl_sdr_hardware_found():
    rtl_test = shutil.which("rtl_test")
    if not rtl_test:
        return False, "rtl_test missing; cannot probe RTL-SDR hardware"
    try:
        completed = subprocess.run(
            [rtl_test, "-t"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=8,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        return "Found" in output and "No supported devices found" not in output, "rtl_test timed out"
    except OSError as exc:
        return False, "rtl_test failed: {}".format(exc)
    output = completed.stdout or ""
    found = "Found" in output and "No supported devices found" not in output
    if found:
        return True, "rtl_test found RTL-SDR hardware"
    return False, "rtl_test did not find RTL-SDR hardware"


def hardware_probe(name):
    if name == "rtlsdr":
        return rtl_sdr_hardware_found()
    return False, "unknown hardware probe: {}".format(name)


def wireless_interfaces():
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
    return sorted(set(interfaces), key=interface_sort_key)


def interface_sort_key(name):
    match = re.match(r"^([a-zA-Z]+)([0-9]+)$", str(name or ""))
    if match:
        return (match.group(1), int(match.group(2)), name)
    return (str(name or ""), -1, str(name or ""))


def monitor_mode_interfaces():
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
    return sorted(set(interfaces), key=interface_sort_key)


def wifi_interface_suggestions(key):
    wireless = wireless_interfaces()
    monitors = monitor_mode_interfaces()
    if key == "wifi":
        managed = [name for name in wireless if name not in monitors]
        return managed[:1]
    if key == "wifi_monitor":
        return monitors[:1]
    return []


def probe_entry(entry, by_key, check_python=False):
    if entry.get("same_as"):
        base = by_key[entry["same_as"]]
        result = dict(base)
        result.update({
            "key": entry["key"],
            "label": entry["label"],
            "hint": entry.get("hint") or base.get("hint", ""),
        })
        return result

    found = []
    missing = []
    groups = []
    for command in entry.get("required", []):
        (found if command_found(command) else missing).append(command)
    for commands in [entry.get("required_any", [])]:
        if commands:
            present = [command for command in commands if command_found(command)]
            groups.append({"any_of": commands, "found": present})
            if present:
                found.extend(present)
            else:
                missing.append("/".join(commands))
    recommended = [command for command in entry.get("recommended", []) if not command_found(command)]
    optional = [command for command in entry.get("optional", []) if not command_found(command)]
    python_expected = entry.get("python_expected", [])
    python_missing = [name for name in python_expected if check_python and not python_module_found(name)]
    hardware_name = entry.get("hardware", "")
    hardware_found = None
    hardware_detail = ""
    if hardware_name:
        hardware_found, hardware_detail = hardware_probe(hardware_name)

    if entry.get("config_required"):
        status = "config_required"
        enabled = False
    elif missing or python_missing:
        status = "missing"
        enabled = False
    elif hardware_name and not hardware_found:
        status = "hardware_missing"
        enabled = False
    elif recommended or optional:
        status = "pass_optional_missing"
        enabled = bool(entry.get("enable_when_pass"))
    else:
        status = "pass"
        enabled = bool(entry.get("enable_when_pass"))

    suggested_interfaces = wifi_interface_suggestions(entry["key"])

    return {
        "key": entry["key"],
        "label": entry["label"],
        "status": status,
        "enabled": enabled,
        "suggested_interfaces": suggested_interfaces,
        "found": sorted(set(found)),
        "missing": missing,
        "recommended_missing": recommended,
        "optional_missing": optional,
        "python_expected": python_expected,
        "python_missing": python_missing,
        "hardware": hardware_name,
        "hardware_found": hardware_found,
        "hardware_detail": hardware_detail,
        "hint": entry.get("hint", ""),
        "groups": groups,
    }


def run_precheck(check_python=False):
    results = []
    by_key = {}
    for entry in COLLECTORS:
        result = probe_entry(entry, by_key, check_python=check_python)
        results.append(result)
        by_key[result["key"]] = result
    return results


def yaml_scalar(value):
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return '"{}"'.format(text)


def yaml_list(values):
    return "[{}]".format(", ".join(yaml_scalar(value) for value in values))


def write_precheck(path, results):
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Generated by scripts/skannr_precheck.py; safe to regenerate.",
        "collectors:",
    ]
    for result in results:
        lines.extend([
            "  {}:".format(result["key"]),
            "    label: {}".format(yaml_scalar(result["label"])),
            "    status: {}".format(result["status"]),
            "    enabled: {}".format("true" if result["enabled"] else "false"),
            "    suggested_interfaces: {}".format(yaml_list(result.get("suggested_interfaces", []))),
            "    found: {}".format(yaml_list(result.get("found", []))),
            "    missing: {}".format(yaml_list(result.get("missing", []))),
            "    recommended_missing: {}".format(yaml_list(result.get("recommended_missing", []))),
            "    optional_missing: {}".format(yaml_list(result.get("optional_missing", []))),
            "    python_expected: {}".format(yaml_list(result.get("python_expected", []))),
            "    python_missing: {}".format(yaml_list(result.get("python_missing", []))),
            "    hardware: {}".format(yaml_scalar(result.get("hardware", ""))),
            "    hardware_found: {}".format("true" if result.get("hardware_found") is True else "false" if result.get("hardware_found") is False else "null"),
            "    hardware_detail: {}".format(yaml_scalar(result.get("hardware_detail", ""))),
            "    hint: {}".format(yaml_scalar(result.get("hint", ""))),
        ])
    path.write_text("\n".join(lines) + "\n")


def parse_yaml_list(value):
    text = value.strip()
    if not text.startswith("[") or not text.endswith("]"):
        return []
    body = text[1:-1].strip()
    if not body:
        return []
    values = []
    current = []
    in_quote = False
    escape = False
    for char in body:
        if escape:
            current.append(char)
            escape = False
        elif char == "\\":
            escape = True
        elif char == '"':
            in_quote = not in_quote
        elif char == "," and not in_quote:
            values.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    values.append("".join(current).strip())
    return [item for item in values if item]


def parse_precheck(path):
    parsed = {}
    current = None
    for raw in path.read_text().splitlines():
        line = raw.rstrip()
        if line.startswith("  ") and line.endswith(":") and not line.startswith("    "):
            current = line.strip()[:-1]
            parsed.setdefault(current, {})
            continue
        if not current or not line.startswith("    ") or ":" not in line:
            continue
        key, value = line.strip().split(":", 1)
        value = value.strip()
        if key == "enabled":
            parsed[current][key] = value.lower() in {"true", "yes", "1"}
        elif key == "suggested_interfaces":
            parsed[current][key] = parse_yaml_list(value)
    return parsed


def parse_precheck_enabled(path):
    return {
        key: value.get("enabled", False)
        for key, value in parse_precheck(path).items()
        if "enabled" in value
    }


def set_enabled_in_file(path, enabled):
    text = path.read_text()
    lines = text.splitlines()
    changed = False
    output = []
    for line in lines:
        if not changed and line.startswith("enabled:"):
            output.append("enabled: {}".format("true" if enabled else "false"))
            changed = True
        else:
            output.append(line)
    if not changed:
        output.append("enabled: {}".format("true" if enabled else "false"))
    path.write_text("\n".join(output) + "\n")


def set_list_in_file(path, key, values):
    text = path.read_text()
    lines = text.splitlines()
    changed = False
    output = []
    replacement = "{}: {}".format(key, yaml_list(values))
    for line in lines:
        if not changed and line.startswith("{}:".format(key)):
            output.append(replacement)
            changed = True
        else:
            output.append(line)
    if not changed:
        output.append(replacement)
    path.write_text("\n".join(output) + "\n")


def apply_interface_suggestions(path, key, result):
    if key not in {"wifi", "wifi_monitor"}:
        return False
    if "suggested_interfaces" not in result:
        return False
    set_list_in_file(path, "interfaces", result.get("suggested_interfaces") or [])
    return True


def apply_precheck(precheck_path, collector_dir):
    parsed = parse_precheck(precheck_path)
    applied = []
    missing = []
    for key, result in sorted(parsed.items()):
        path = collector_dir / "{}.yaml".format(key)
        if not path.exists():
            missing.append(key)
            continue
        if "enabled" in result:
            set_enabled_in_file(path, result["enabled"])
        interfaces_applied = apply_interface_suggestions(path, key, result)
        applied.append((key, result.get("enabled"), interfaces_applied))
    return applied, missing


def print_report(results, title="Skannr collector precheck:"):
    print(title)
    for result in results:
        bits = []
        if result.get("found"):
            bits.append("installed/found: {}".format(", ".join(result["found"])))
        if result.get("missing"):
            bits.append("missing: {}".format(", ".join(result["missing"])))
        if result.get("recommended_missing"):
            bits.append("recommended missing: {}".format(", ".join(result["recommended_missing"])))
        if result.get("optional_missing"):
            bits.append("optional missing: {}".format(", ".join(result["optional_missing"])))
        if result.get("python_missing"):
            bits.append("python missing: {}".format(", ".join(result["python_missing"])))
        elif result.get("python_expected"):
            bits.append("python deps installed by install.sh: {}".format(", ".join(result["python_expected"])))
        if result.get("hardware"):
            bits.append("hardware {}: {}".format(
                result["hardware"],
                "found" if result.get("hardware_found") else "not found",
            ))
        if result.get("suggested_interfaces"):
            bits.append("suggested interfaces: {}".format(
                ", ".join(result.get("suggested_interfaces") or [])
            ))
        if not bits:
            bits.append("no external software probe")
        print("  {key}: {details}. collector {status}; enabled={enabled}".format(
            key=result["key"],
            details="; ".join(bits),
            status=result["status"],
            enabled="true" if result["enabled"] else "false",
        ))
        if result.get("hint") and result["status"] in {"missing", "hardware_missing", "config_required"}:
            print("    install/config hint: {}".format(result["hint"]))
    print("\nSummary:")
    for result in results:
        print("  {key}: {status}; enabled={enabled}".format(
            key=result["key"],
            status=result["status"],
            enabled="true" if result["enabled"] else "false",
        ))


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="precheck YAML output path")
    parser.add_argument("--apply", action="store_true", help="apply precheck enabled flags to config/collectors/*.yaml")
    parser.add_argument("--precheck", default=str(DEFAULT_OUTPUT), help="precheck YAML path to apply")
    parser.add_argument("--collector-dir", default=str(DEFAULT_COLLECTOR_DIR), help="collector config directory to update")
    parser.add_argument("--no-write", action="store_true", help="print only; do not write precheck YAML")
    parser.add_argument("--check-python", action="store_true", help="check Python modules in the current interpreter too")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.apply:
        precheck_path = Path(args.precheck)
        if not precheck_path.exists():
            print("precheck file not found: {}".format(precheck_path), file=sys.stderr)
            return 1
        applied, missing = apply_precheck(precheck_path, Path(args.collector_dir))
        for key, enabled, interfaces_applied in applied:
            enabled_text = "unchanged" if enabled is None else "true" if enabled else "false"
            suffix = "; interfaces updated" if interfaces_applied else ""
            print("applied precheck: {} enabled={}{}".format(key, enabled_text, suffix))
        for key in missing:
            print("precheck entry has no collector config: {}".format(key), file=sys.stderr)
        return 0

    results = run_precheck(check_python=args.check_python)
    title = "Skannr collector postcheck:" if args.check_python else "Skannr collector precheck:"
    print_report(results, title=title)
    if not args.no_write:
        output = Path(args.output)
        write_precheck(output, results)
        print("\nWrote {}".format(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
