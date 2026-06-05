"""Optional passive LAN observation collector."""

import asyncio
import json
import re
import shutil
import subprocess

from ..oui_lookup import normalize_oui, vendor_name, vendor_prefix
from .base import BaseCollector, STATE_OFFLINE, STATE_ONLINE, STATE_RETRYING


LAN_FIELD_MAX = 180


def compact_lan_text(value, max_length=LAN_FIELD_MAX):
    """Return compact one-line LAN text."""
    if value in (None, ""):
        return ""
    text = " ".join(str(value).replace("\x00", " ").split())
    return text[:max_length] if text else ""


def clean_lan_data(data):
    """Scrub LAN event data loaded from retained JSONL."""
    if not isinstance(data, dict):
        return {}
    cleaned = {}
    numeric_keys = {"timestamp_epoch", "first_seen_epoch", "last_seen_epoch"}
    list_keys = {"ips", "hostnames", "interfaces", "states", "sources", "gateways"}
    bool_keys = {"gateway"}
    for key, value in data.items():
        if value in (None, "", []):
            continue
        if key in numeric_keys:
            cleaned[key] = value
        elif key in bool_keys:
            cleaned[key] = bool(value)
        elif key in list_keys and isinstance(value, list):
            items = []
            for item in value:
                text = compact_lan_text(item, 80)
                if text and text not in items:
                    items.append(text)
            if items:
                cleaned[key] = items[:32]
        else:
            text = compact_lan_text(value)
            if text:
                cleaned[key] = text
    return cleaned


class LANCollector(BaseCollector):
    """Passively observe local OS LAN neighbor state."""

    config_key = "lan"
    name = "LAN"
    tab_label = "LAN"
    required_hardware = "Local network stack"
    local_source_label = "Local OS neighbor/default-route state"

    @classmethod
    def hardware_status(cls, config):
        """Return local command availability for LAN observation."""
        return {
            "ip": bool(shutil.which("ip")),
            "arp": bool(shutil.which("arp")),
            "enabled": bool(config.get("enabled", False)),
        }

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self._fingerprints = {}
        self._gateway_fingerprints = {}

    def detect(self):
        """Need either iproute2 or arp for passive LAN state."""
        if not shutil.which("ip") and not shutil.which("arp"):
            self.state = STATE_OFFLINE
            self.warning = "Neither ip nor arp was found in PATH."
            return False
        self.active_hardware = self.local_source_label
        self.state = STATE_ONLINE
        self.warning = None
        return True

    def observation_method(self):
        """Return the preferred local command source for diagnostic details."""
        return "ip-neigh" if shutil.which("ip") else "arp"

    async def start(self):
        """Poll local LAN state until stopped."""
        self._running = True
        if not self.detect():
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return
        await self.emit(
            "collector_online",
            {
                "method": self.observation_method(),
                "source": self.active_hardware,
                "local_observation": True,
            },
        )
        interval = float(self.config.get("poll_interval_sec", 60))
        while self._running:
            try:
                events = await self.run_blocking(self.poll_once)
                self.state = STATE_ONLINE
                self.warning = None
                for event_type, data in events:
                    await self.emit(event_type, data, "warning" if event_type.endswith("_changed") else "info")
            except Exception as exc:
                self.state = STATE_RETRYING
                self.warning = "LAN poll failed: {}".format(exc)
                await self.emit(
                    "collector_retrying",
                    {
                        "reason": self.warning,
                        "method": self.observation_method(),
                        "source": self.active_hardware,
                    },
                    "warning",
                )
            await asyncio.sleep(interval)

    async def run_blocking(self, callback, *args):
        """Run blocking subprocess work without requiring Python 3.9 to_thread."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, callback, *args)

    def poll_once(self):
        """Return new/materially changed LAN subjects and gateway changes."""
        devices = self.scan_devices()
        gateways = self.default_gateways()
        self.attach_gateway_flags(devices, gateways)
        events = []
        for device in devices:
            key = device.get("subject_key")
            fingerprint = self.device_fingerprint(device)
            previous = self._fingerprints.get(key)
            if previous == fingerprint:
                continue
            event_type = "lan_device_seen" if previous is None else "lan_device_changed"
            data = dict(device)
            data["change_type"] = "new" if previous is None else "changed"
            self._fingerprints[key] = fingerprint
            events.append((event_type, clean_lan_data(data)))
        for gateway in gateways:
            key = "{}:{}".format(gateway.get("family") or "", gateway.get("interface") or "")
            fingerprint = self.gateway_fingerprint(gateway)
            previous = self._gateway_fingerprints.get(key)
            if previous == fingerprint:
                continue
            event_type = "lan_gateway_seen" if previous is None else "lan_gateway_changed"
            data = dict(gateway)
            data["change_type"] = "new" if previous is None else "changed"
            self._gateway_fingerprints[key] = fingerprint
            events.append((event_type, clean_lan_data(data)))
        return events

    def scan_devices(self):
        """Return passive LAN devices from neighbor/ARP/DHCP sources."""
        records = []
        if self.config.get("collect_ip_neigh", True):
            records.extend(self.ip_neigh_records())
        if self.config.get("collect_arp", True):
            records.extend(self.arp_records())
        records.extend(self.lease_records())
        merged = {}
        for record in records:
            key = self.subject_key(record)
            if not key:
                continue
            item = merged.setdefault(
                key,
                {
                    "subject_key": key,
                    "mac": record.get("mac") or "",
                    "ips": [],
                    "hostnames": [],
                    "interfaces": [],
                    "states": [],
                    "sources": [],
                    "gateway": False,
                },
            )
            self.lan_sample(item, "ips", record.get("ip"))
            self.lan_sample(item, "hostnames", record.get("hostname"))
            self.lan_sample(item, "interfaces", record.get("interface"))
            self.lan_sample(item, "states", record.get("state"))
            self.lan_sample(item, "sources", record.get("source"))
            if record.get("mac") and not item.get("mac"):
                item["mac"] = record.get("mac")
        output = []
        for item in merged.values():
            item["ip"] = item["ips"][0] if item.get("ips") else ""
            item["hostname"] = item["hostnames"][0] if item.get("hostnames") else ""
            item["interface"] = item["interfaces"][0] if item.get("interfaces") else ""
            item["state"] = item["states"][0] if item.get("states") else ""
            self.add_vendor(item)
            output.append(item)
        return sorted(output, key=lambda item: item.get("subject_key") or "")

    def ip_neigh_records(self):
        """Return records from `ip neigh show`."""
        if not shutil.which("ip"):
            return []
        records = self.ip_neigh_json_records()
        if records:
            return records
        try:
            output = subprocess.check_output(
                ["ip", "neigh", "show"],
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=float(self.config.get("command_timeout_sec", 10)),
            )
        except Exception:
            return []
        records = []
        for line in output.splitlines():
            parsed = self.parse_ip_neigh_line(line)
            if parsed:
                records.append(parsed)
        return records

    def ip_neigh_json_records(self):
        """Return records from JSON iproute2 output when available."""
        try:
            output = subprocess.check_output(
                ["ip", "-j", "neigh", "show"],
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=float(self.config.get("command_timeout_sec", 10)),
            )
            payload = json.loads(output)
        except Exception:
            return []
        records = []
        for item in payload if isinstance(payload, list) else []:
            mac = normalize_mac(item.get("lladdr"))
            ip = compact_lan_text(item.get("dst"), 80)
            if not ip and not mac:
                continue
            records.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "interface": compact_lan_text(item.get("dev"), 80),
                    "state": compact_lan_text(item.get("state"), 80),
                    "source": "ip-neigh",
                }
            )
        return records

    def parse_ip_neigh_line(self, line):
        """Parse one `ip neigh show` line."""
        text = str(line or "").strip()
        if not text:
            return None
        parts = text.split()
        ip = parts[0] if parts else ""
        interface = value_after(parts, "dev")
        mac = normalize_mac(value_after(parts, "lladdr"))
        state = parts[-1] if parts else ""
        if not ip and not mac:
            return None
        return {
            "ip": compact_lan_text(ip, 80),
            "mac": mac,
            "interface": compact_lan_text(interface, 80),
            "state": compact_lan_text(state, 80),
            "source": "ip-neigh",
        }

    def arp_records(self):
        """Return records from `arp -an`."""
        if not shutil.which("arp"):
            return []
        try:
            output = subprocess.check_output(
                ["arp", "-an"],
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=float(self.config.get("command_timeout_sec", 10)),
            )
        except Exception:
            return []
        records = []
        for line in output.splitlines():
            match = re.search(
                r"^(?P<host>\S+)\s+\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:.-]+)",
                line,
            )
            if not match:
                continue
            records.append(
                {
                    "ip": compact_lan_text(match.group("ip"), 80),
                    "mac": normalize_mac(match.group("mac")),
                    "hostname": "" if match.group("host") == "?" else match.group("host"),
                    "interface": compact_lan_text(value_after(line.split(), "on"), 80),
                    "state": "",
                    "source": "arp",
                }
            )
        return records

    def lease_records(self):
        """Return records from configured dnsmasq-style lease files."""
        records = []
        for path in self.config.get("dhcp_lease_paths") or []:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            for line in lines:
                parsed = self.parse_dnsmasq_lease(line)
                if parsed:
                    records.append(parsed)
        return records

    def parse_dnsmasq_lease(self, line):
        """Parse one dnsmasq lease row."""
        parts = str(line or "").split()
        if len(parts) < 4:
            return None
        mac = normalize_mac(parts[1])
        ip = compact_lan_text(parts[2], 80)
        hostname = "" if parts[3] == "*" else compact_lan_text(parts[3], 80)
        if not mac and not ip:
            return None
        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "source": "dhcp-lease",
        }

    def default_gateways(self):
        """Return default gateway rows from the local routing table."""
        gateways = []
        if not shutil.which("ip"):
            return gateways
        gateways.extend(self.default_gateway_family(["ip", "route", "show", "default"], "IPv4"))
        gateways.extend(self.default_gateway_family(["ip", "-6", "route", "show", "default"], "IPv6"))
        return gateways

    def default_gateway_family(self, command, family):
        """Return default gateways for one address family."""
        try:
            output = subprocess.check_output(
                command,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=float(self.config.get("command_timeout_sec", 10)),
            )
        except Exception:
            return []
        gateways = []
        for line in output.splitlines():
            parts = line.split()
            gateway = value_after(parts, "via")
            interface = value_after(parts, "dev")
            if gateway or interface:
                gateways.append(
                    {
                        "gateway": True,
                        "gateway_ip": compact_lan_text(gateway, 80),
                        "interface": compact_lan_text(interface, 80),
                        "family": family,
                        "source": "default-route",
                    }
                )
        return gateways

    def attach_gateway_flags(self, devices, gateways):
        """Mark devices matching default gateway IPs."""
        by_ip = {}
        for device in devices:
            for ip in device.get("ips") or []:
                by_ip[ip] = device
        for gateway in gateways:
            device = by_ip.get(gateway.get("gateway_ip"))
            if not device:
                continue
            gateway["mac"] = device.get("mac") or ""
            gateway["vendor_name"] = device.get("vendor_name") or ""
            gateway["vendor_prefix"] = device.get("vendor_prefix") or ""
            device["gateway"] = True
            self.lan_sample(device, "gateways", gateway.get("gateway_ip"))

    def subject_key(self, record):
        """Return stable LAN identity by MAC when available, otherwise IP."""
        mac = normalize_mac(record.get("mac"))
        if mac:
            return mac
        ip = compact_lan_text(record.get("ip"), 80)
        return "ip:{}".format(ip) if ip else ""

    def device_fingerprint(self, device):
        """Return material LAN device fingerprint."""
        fields = [
            device.get("mac") or "",
            ",".join(device.get("ips") or []),
            ",".join(device.get("hostnames") or []),
            ",".join(device.get("interfaces") or []),
            ",".join(device.get("states") or []),
            str(bool(device.get("gateway"))),
        ]
        return "|".join(fields)

    def gateway_fingerprint(self, gateway):
        """Return material default-gateway fingerprint."""
        fields = [
            gateway.get("family") or "",
            gateway.get("gateway_ip") or "",
            gateway.get("interface") or "",
            gateway.get("mac") or "",
        ]
        return "|".join(fields)

    def lan_sample(self, item, key, value, limit=12):
        """Append one distinct LAN summary value."""
        text = compact_lan_text(value, 100)
        if not text:
            return
        item.setdefault(key, [])
        if text not in item[key] and len(item[key]) < limit:
            item[key].append(text)

    def add_vendor(self, item):
        """Fill offline vendor fields for a LAN MAC."""
        mac = item.get("mac") or item.get("subject_key") or ""
        item["vendor_oui"] = normalize_oui(mac) or ""
        item["vendor_prefix"] = vendor_prefix(mac) or item["vendor_oui"]
        item["vendor_name"] = vendor_name(mac) or ""


def normalize_mac(value):
    """Return lower-case colon MAC, or empty string."""
    compact = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if len(compact) != 12:
        return ""
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).lower()


def value_after(parts, key):
    """Return the token after key in a token list."""
    try:
        index = parts.index(key)
    except ValueError:
        return ""
    return parts[index + 1] if index + 1 < len(parts) else ""
