"""Optional passive and low-impact LAN observation collector."""

import asyncio
import json
import logging
import os
import re
import shlex
import shutil
import socket
import struct
import subprocess
import threading
import time

from ..oui_lookup import normalize_oui, vendor_info, vendor_name, vendor_prefix
from .base import BaseCollector, STATE_OFFLINE, STATE_ONLINE, STATE_RETRYING


LAN_FIELD_MAX = 180
ETH_P_ARP = 0x0806
COMMON_ARP_SCAN_PATHS = (
    "/usr/sbin/arp-scan",
    "/usr/local/sbin/arp-scan",
    "/usr/bin/arp-scan",
)
COMMON_ARP_SCAN_DATA_DIRS = (
    "/usr/share/arp-scan",
    "/usr/local/share/arp-scan",
)
ARP_SCAN_VENDOR_FILES = ("ieee-oui.txt", "mac-vendor.txt")


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
    numeric_keys = {
        "timestamp_epoch",
        "first_seen_epoch",
        "last_seen_epoch",
        "last_identified_epoch",
        "identify_count",
        "duration_sec",
    }
    list_keys = {
        "ips",
        "hostnames",
        "interfaces",
        "states",
        "sources",
        "mac_aliases",
        "gateways",
        "gateway_ips",
        "families",
        "services",
        "locations",
        "servers",
        "messages",
        "open_ports",
        "service_banners",
        "http_urls",
        "http_titles",
        "http_headers",
        "http_scripts",
        "http_hints",
        "identify_errors",
    }
    bool_keys = {"gateway", "identified", "nmap_available", "curl_available"}
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
                text = compact_lan_text(item, 120)
                if text and text not in items:
                    items.append(text)
            if items:
                cleaned[key] = items[:32]
        else:
            text = compact_lan_text(value)
            if text:
                cleaned[key] = text
    return cleaned


def resolve_known_executable(command):
    """Resolve common sbin tools when systemd PATH omits them."""
    command = list(command or [])
    if not command:
        return command
    executable = command[0]
    resolved = shutil.which(executable)
    if not resolved and os.path.basename(executable) == "arp-scan":
        for path in COMMON_ARP_SCAN_PATHS:
            if os.path.exists(path) and os.access(path, os.X_OK):
                resolved = path
                break
    if resolved:
        command[0] = resolved
    return command


def command_executable_available(command):
    """Return true when argv[0] can be executed."""
    command = list(command or [])
    if not command:
        return False
    executable = command[0]
    if shutil.which(executable):
        return True
    return os.path.isabs(executable) and os.path.exists(executable) and os.access(executable, os.X_OK)


def arp_scan_vendor_data_present(path):
    """Return true when a directory contains arp-scan vendor databases."""
    if not path or not os.path.isdir(path):
        return False
    return any(
        os.path.exists(os.path.join(path, filename))
        for filename in ARP_SCAN_VENDOR_FILES
    )


def decode_avahi_text(value):
    """Decode avahi-browse printable escapes such as `\\032` for spaces."""
    text = str(value or "")

    def replace_decimal(match):
        try:
            return chr(int(match.group(1), 10))
        except Exception:
            return match.group(0)

    text = re.sub(r"\\([0-9]{3})", replace_decimal, text)
    return re.sub(r"\\(.)", r"\1", text)


def parse_avahi_txt_field(value):
    """Return decoded TXT tokens from avahi-browse `-p` output."""
    text = str(value or "").strip()
    if not text:
        return []
    try:
        parts = shlex.split(text)
    except ValueError:
        parts = re.findall(r'"([^"]*)"', text)
    return [decode_avahi_text(part) for part in parts if decode_avahi_text(part)]


def txt_dict(tokens):
    """Return lowercase TXT key/value mapping."""
    output = {}
    for token in tokens or []:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        key = compact_lan_text(key, 80).lower()
        value = compact_lan_text(value, 160)
        if key and value and key not in output:
            output[key] = value
    return output


def usable_lan_join_ip(value):
    """Return true when an address is useful for joining LAN subject records."""
    ip = compact_lan_text(value, 120)
    if not ip:
        return False
    if ip == "127.0.0.1" or ip == "::1":
        return False
    return True


def avahi_trusted_mac(fields):
    """Return an Avahi TXT MAC safe enough to use as primary LAN identity."""
    for key in ("mac", "wama"):
        mac = normalize_mac((fields or {}).get(key))
        if mac:
            return mac
    return ""


def avahi_mac_aliases(fields):
    """Return MAC-like TXT clues without treating all as primary identity."""
    aliases = []
    for key in ("mac", "wama", "rama", "ram2", "deviceid", "btaddr", "id", "rpba"):
        mac = normalize_mac((fields or {}).get(key))
        if mac and mac not in aliases:
            aliases.append(mac)
    return aliases


def avahi_txt_messages(fields):
    """Return compact, high-value TXT clues for LAN identity enrichment."""
    keys = (
        "nm",
        "model",
        "md",
        "am",
        "ssid",
        "ranm",
        "rach",
        "rch2",
        "sysv",
        "osvers",
        "srcvers",
        "deviceid",
        "btaddr",
        "id",
    )
    messages = []
    for key in keys:
        value = (fields or {}).get(key)
        if value:
            messages.append("{}={}".format(key, value))
    return messages[:12]


class LANCollector(BaseCollector):
    """Observe local LAN subjects through passive state and optional probes."""

    config_key = "lan"
    name = "LAN"
    tab_label = "LAN"
    required_hardware = "Local network stack"
    subject_history_event_types = (
        "lan_device_seen",
        "lan_device_changed",
        "lan_gateway_seen",
        "lan_gateway_changed",
        "collector_offline",
        "collector_retrying",
    )
    local_source_label = "Local OS neighbor/default-route state"

    @classmethod
    def hardware_status(cls, config):
        """Return local command availability for LAN observation."""
        return {
            "ip": bool(shutil.which("ip")),
            "arp": bool(shutil.which("arp")),
            "arp_scan": cls.arp_scan_command_available(config),
            "avahi_browse": cls.avahi_browse_command_available(config),
            "enabled": bool(config.get("enabled", False)),
        }

    @classmethod
    def arp_scan_command_available(cls, config):
        """Return true when the configured arp-scan command is executable."""
        command_text = compact_lan_text(
            (config or {}).get("active_arp_scan_command")
            or "arp-scan --localnet",
            500,
        )
        try:
            command = shlex.split(command_text)
        except ValueError:
            return False
        return command_executable_available(resolve_known_executable(command))

    @classmethod
    def avahi_browse_command_available(cls, config):
        """Return true when the configured avahi-browse command is executable."""
        command_text = compact_lan_text(
            (config or {}).get("avahi_browse_command")
            or "avahi-browse -a -r -p -t",
            500,
        )
        try:
            command = shlex.split(command_text)
        except ValueError:
            return False
        return command_executable_available(command)

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self._fingerprints = {}
        self._gateway_fingerprints = {}
        self._passive_records = {}
        self._passive_records_lock = threading.Lock()
        self._listener_tasks = []
        self._listener_sockets = []
        self._listener_warnings = []
        self._last_arp_scan_at = 0
        self._arp_scan_records = []
        self._arp_scan_subjects = {}
        self._active_arp_scan_refreshed = False
        self._last_active_arp_scan_raw_count = 0
        self._last_lease_import_at = 0
        self._lease_records = []
        self._last_avahi_browse_at = 0
        self._avahi_browse_records = []

    def detect(self):
        """Need at least one low-impact LAN source."""
        if (
            not shutil.which("ip")
            and not shutil.which("arp")
            and not self.config.get("collect_mdns", True)
            and not self.config.get("collect_ssdp", True)
            and not self.config.get("collect_passive_dhcp", False)
            and not self.config.get("collect_passive_arp", False)
            and not self.config.get("collect_active_arp_scan", False)
            and not self.config.get("collect_avahi_browse", False)
        ):
            self.state = STATE_OFFLINE
            self.warning = "No LAN observation source is enabled or available."
            return False
        self.active_hardware = self.local_source_label
        self.state = STATE_ONLINE
        self.warning = None
        for warning in self.configured_source_warnings():
            self.note_listener_warning(warning)
        return True

    def configured_source_warnings(self):
        """Return immediate warnings for configured optional sources."""
        warnings = []
        if (
            self.config.get("collect_active_arp_scan", False)
            and not self.arp_scan_command_available(self.config)
        ):
            warnings.append(
                "Active ARP scan enabled but active_arp_scan_command is not executable."
            )
        if (
            self.config.get("collect_avahi_browse", False)
            and not self.avahi_browse_command_available(self.config)
        ):
            warnings.append(
                "Avahi browse import enabled but avahi_browse_command is not executable."
            )
        command = compact_lan_text(self.config.get("dhcp_lease_command"), 500)
        if command:
            try:
                argv = shlex.split(command)
            except ValueError as exc:
                warnings.append("Invalid DHCP lease command: {}".format(exc))
            else:
                if argv and not shutil.which(argv[0]):
                    warnings.append("DHCP lease command enabled but {} is not in PATH.".format(argv[0]))
        return warnings

    def observation_method(self):
        """Return the preferred local command source for diagnostic details."""
        methods = []
        if shutil.which("ip") and self.config.get("collect_ip_neigh", True):
            methods.append("ip-neigh")
        if shutil.which("arp") and self.config.get("collect_arp", True):
            methods.append("arp")
        if self.config.get("collect_mdns", True):
            methods.append("mDNS")
        if self.config.get("collect_ssdp", True):
            methods.append("SSDP")
        if self.config.get("collect_active_arp_scan", False):
            methods.append("arp-scan")
        if self.config.get("collect_avahi_browse", False):
            methods.append("avahi-browse")
        return ", ".join(methods) or "LAN observation"

    async def start(self):
        """Poll local LAN state until stopped."""
        self._running = True
        if not self.detect():
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return
        await self.start_listener_tasks()
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
                self.warning = self.listener_warning_text()
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

    async def stop(self):
        """Stop poll loop and any optional passive sockets."""
        self._running = False
        for sock in list(self._listener_sockets):
            try:
                sock.close()
            except OSError:
                pass
        for task in list(self._listener_tasks):
            task.cancel()
        self._listener_tasks = []
        self._listener_sockets = []
        await super().stop()

    async def run_blocking(self, callback, *args):
        """Run blocking subprocess or socket work without Python 3.9 to_thread."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, callback, *args)

    async def start_listener_tasks(self):
        """Start optional passive UDP/raw listeners."""
        specs = []
        if self.config.get("collect_mdns", True):
            sock = self.open_multicast_socket("224.0.0.251", 5353)
            if sock:
                specs.append(("mDNS", sock, self.parse_mdns_packet))
        if self.config.get("collect_ssdp", True):
            sock = self.open_multicast_socket("239.255.255.250", 1900)
            if sock:
                specs.append(("SSDP", sock, self.parse_ssdp_packet))
        if self.config.get("collect_passive_dhcp", False):
            for port in self.config.get("passive_dhcp_ports") or [67, 68]:
                sock = self.open_udp_socket("", int(port), "DHCP")
                if sock:
                    specs.append(("DHCP", sock, self.parse_dhcp_packet))
        if self.config.get("collect_passive_arp", False):
            for interface in self.passive_arp_interfaces():
                sock = self.open_arp_socket(interface)
                if sock:
                    specs.append(("ARP", sock, self.parse_arp_packet))
        for name, sock, parser in specs:
            self._listener_sockets.append(sock)
            task = asyncio.ensure_future(self.passive_listener_loop(name, sock, parser))
            self._listener_tasks.append(task)

    async def passive_listener_loop(self, name, sock, parser):
        """Receive passive packets and merge them into the LAN subject cache."""
        while self._running:
            try:
                payload, addr = await self.run_blocking(self.recv_from_socket, sock)
                if not payload:
                    continue
                records = parser(payload, addr)
                if isinstance(records, dict):
                    records = [records]
                for record in records or []:
                    self.remember_passive_record(record)
            except asyncio.CancelledError:
                break
            except OSError as exc:
                if self._running:
                    self.note_listener_warning("{} listener stopped: {}".format(name, exc))
                break
            except Exception as exc:
                self.note_listener_warning("{} listener error: {}".format(name, exc))
                await asyncio.sleep(1)

    def recv_from_socket(self, sock):
        """Blocking receive helper for executor-based socket reads."""
        try:
            return sock.recvfrom(65535)
        except socket.timeout:
            return None, None

    def open_udp_socket(self, host, port, label):
        """Open a UDP socket for passive listener use."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.set_reuse_socket(sock)
            sock.bind((host, int(port)))
            sock.settimeout(1.0)
            return sock
        except OSError as exc:
            self.note_listener_warning("{} listener unavailable on port {}: {}".format(label, port, exc))
            try:
                sock.close()
            except Exception:
                pass
            return None

    def open_multicast_socket(self, group, port):
        """Open an IPv4 multicast listener for mDNS or SSDP."""
        sock = self.open_udp_socket("", port, group)
        if not sock:
            return None
        try:
            mreq = struct.pack("=4sl", socket.inet_aton(group), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError as exc:
            self.note_listener_warning("{} multicast join failed: {}".format(group, exc))
            try:
                sock.close()
            except OSError:
                pass
            return None
        return sock

    def open_arp_socket(self, interface):
        """Open a raw ARP listener for one interface when permitted."""
        if not hasattr(socket, "AF_PACKET"):
            self.note_listener_warning("Passive ARP requires Linux AF_PACKET sockets.")
            return None
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
            sock.bind((interface, 0))
            sock.settimeout(1.0)
            return sock
        except OSError as exc:
            self.note_listener_warning("Passive ARP unavailable on {}: {}".format(interface, exc))
            try:
                sock.close()
            except Exception:
                pass
            return None

    def set_reuse_socket(self, sock):
        """Enable common reuse options before binding passive UDP sockets."""
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
        reuse_port = getattr(socket, "SO_REUSEPORT", None)
        if reuse_port is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, reuse_port, 1)
            except OSError:
                pass

    def note_listener_warning(self, message):
        """Store a bounded optional-listener warning for System Status."""
        text = compact_lan_text(message, 160)
        if not text:
            return
        if text not in self._listener_warnings:
            self._listener_warnings.append(text)
            self._listener_warnings = self._listener_warnings[-4:]
        self.warning = self.listener_warning_text()

    def listener_warning_text(self):
        """Return compact optional-listener warnings."""
        return "; ".join(self._listener_warnings[-3:])

    def poll_once(self):
        """Return new/materially changed LAN subjects and gateway changes."""
        devices = self.scan_devices()
        gateways = self.default_gateways()
        self.attach_gateway_flags(devices, gateways)
        gateways = self.collapse_gateways(gateways)
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
            key = gateway.get("subject_key") or self.gateway_subject_key(gateway)
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
        """Return LAN devices from local state, passive cache, and optional scan."""
        records = []
        if self.config.get("collect_ip_neigh", True):
            records.extend(self.ip_neigh_records())
        if self.config.get("collect_arp", True):
            records.extend(self.arp_records())
        records.extend(self.cached_lease_records())
        records.extend(self.passive_records())
        if self.config.get("collect_avahi_browse", False):
            records.extend(self.cached_avahi_browse_records())
        if self.config.get("collect_active_arp_scan", False):
            records.extend(self.cached_active_arp_scan_records())
        ip_subjects = self.ip_subject_map(records)
        merged = {}
        for record in records:
            key = self.subject_key(record, ip_subjects)
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
                    "mac_aliases": [],
                    "services": [],
                    "locations": [],
                    "servers": [],
                    "messages": [],
                    "gateway": False,
                    "vendor_name": record.get("vendor_name") or "",
                    "vendor_prefix": record.get("vendor_prefix") or "",
                },
            )
            self.lan_sample(item, "ips", record.get("ip"))
            self.lan_sample(item, "hostnames", record.get("hostname"))
            self.lan_sample(item, "interfaces", record.get("interface"))
            self.lan_sample(item, "states", record.get("state"))
            self.lan_sample(item, "sources", record.get("source"))
            for list_key in ("mac_aliases", "services", "locations", "servers", "messages"):
                for value in list_values(record.get(list_key)):
                    self.lan_sample(item, list_key, value)
            if record.get("mac") and not item.get("mac"):
                item["mac"] = record.get("mac")
            for key_name in ("vendor_name", "vendor_prefix"):
                if record.get(key_name) and not item.get(key_name):
                    item[key_name] = record.get(key_name)
        output = []
        for item in merged.values():
            item["ip"] = item["ips"][0] if item.get("ips") else ""
            item["hostname"] = item["hostnames"][0] if item.get("hostnames") else ""
            item["interface"] = item["interfaces"][0] if item.get("interfaces") else ""
            item["state"] = item["states"][0] if item.get("states") else ""
            self.add_vendor(item)
            output.append(item)
        if self._active_arp_scan_refreshed:
            logging.info(
                "LAN poll merged_subjects=%s raw_records=%s active_arp_raw_rows=%s "
                "active_arp_retained_subjects=%s",
                len(output),
                len(records),
                self._last_active_arp_scan_raw_count,
                len(self._arp_scan_records),
            )
            self._active_arp_scan_refreshed = False
        return sorted(output, key=lambda item: item.get("subject_key") or "")

    def passive_records(self):
        """Return cached passive listener records."""
        with self._passive_records_lock:
            return [dict(record) for record in self._passive_records.values()]

    def remember_passive_record(self, record):
        """Merge one passive LAN observation into the subject cache."""
        if not isinstance(record, dict):
            return
        key = self.subject_key(record)
        if not key:
            return
        with self._passive_records_lock:
            item = self._passive_records.setdefault(
                key,
                {
                    "subject_key": key,
                    "mac": record.get("mac") or "",
                    "ip": record.get("ip") or "",
                    "hostname": record.get("hostname") or "",
                    "interface": record.get("interface") or "",
                    "ips": [],
                    "hostnames": [],
                    "interfaces": [],
                    "states": [],
                    "sources": [],
                    "mac_aliases": [],
                    "services": [],
                    "locations": [],
                    "servers": [],
                    "messages": [],
                },
            )
            if record.get("mac") and not item.get("mac"):
                item["mac"] = record.get("mac")
            for scalar_key in ("ip", "hostname", "interface", "vendor_name", "vendor_prefix"):
                if record.get(scalar_key) and not item.get(scalar_key):
                    item[scalar_key] = record.get(scalar_key)
            self.lan_sample(item, "ips", record.get("ip"))
            self.lan_sample(item, "hostnames", record.get("hostname"))
            self.lan_sample(item, "interfaces", record.get("interface"))
            self.lan_sample(item, "states", record.get("state"))
            self.lan_sample(item, "sources", record.get("source"))
            for list_key in ("mac_aliases", "services", "locations", "servers", "messages"):
                for value in list_values(record.get(list_key)):
                    self.lan_sample(item, list_key, value)

    def ip_subject_map(self, records):
        """Return current IP-to-MAC-subject joins from MAC-bearing records."""
        joins = {}
        for record in records or []:
            mac = normalize_mac((record or {}).get("mac"))
            if not mac:
                continue
            key = self.subject_key({"mac": mac})
            for ip in list_values((record or {}).get("ip")) + list_values((record or {}).get("ips")):
                ip = compact_lan_text(ip, 120)
                if usable_lan_join_ip(ip):
                    joins[ip] = key
        return joins

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

    def cached_lease_records(self):
        """Return DHCP lease records, throttled independently from poll cadence."""
        interval = float(
            self.config.get(
                "dhcp_lease_import_interval_sec",
                self.config.get("active_arp_scan_interval_sec", 300),
            )
        )
        if not self.interval_due(self._last_lease_import_at, interval):
            return list(self._lease_records)
        self._last_lease_import_at = time.time()
        self._lease_records = self.lease_records()
        return list(self._lease_records)

    def lease_records(self):
        """Return records from configured dnsmasq-style lease files/commands."""
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
        records.extend(self.dhcp_lease_command_records())
        return records

    def dhcp_lease_command_records(self):
        """Return lease records from an optional command or router wrapper."""
        command = compact_lan_text(self.config.get("dhcp_lease_command"), 500)
        if not command:
            return []
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            self.note_listener_warning("Invalid DHCP lease command: {}".format(exc))
            return []
        try:
            output = subprocess.check_output(
                argv,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=float(self.config.get("dhcp_lease_import_timeout_sec", self.config.get("command_timeout_sec", 10))),
            )
        except Exception as exc:
            self.note_listener_warning("DHCP lease command failed: {}".format(exc))
            return []
        records = []
        for line in output.splitlines():
            parsed = self.parse_dnsmasq_lease(line)
            if parsed:
                parsed["source"] = "dhcp-lease-command"
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

    def cached_avahi_browse_records(self):
        """Return optional resolved Avahi records on their own cadence."""
        interval = float(self.config.get("avahi_browse_interval_sec", 300))
        if not self.interval_due(self._last_avahi_browse_at, interval):
            return list(self._avahi_browse_records)
        self._last_avahi_browse_at = time.time()
        self._avahi_browse_records = self.avahi_browse_records()
        return list(self._avahi_browse_records)

    def avahi_browse_records(self):
        """Return resolved mDNS/Bonjour records from optional avahi-browse."""
        command = compact_lan_text(
            self.config.get("avahi_browse_command") or "avahi-browse -a -r -p -t",
            500,
        )
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            self.note_listener_warning("Invalid avahi_browse_command: {}".format(exc))
            return []
        if not command_executable_available(argv):
            self.note_listener_warning("avahi-browse command is not executable.")
            return []
        timeout = float(self.config.get("avahi_browse_timeout_sec", 15))
        try:
            output = subprocess.check_output(
                argv,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=timeout,
            )
        except Exception as exc:
            self.note_listener_warning("avahi-browse failed: {}".format(exc))
            return []
        records = self.parse_avahi_browse_output(output)
        logging.info("LAN avahi-browse parsed_rows=%s command=%s", len(records), command)
        return records

    def parse_avahi_browse_output(self, output):
        """Parse resolved `avahi-browse -a -r -p -t` rows."""
        records = []
        for line in str(output or "").splitlines():
            parsed = self.parse_avahi_browse_line(line)
            if parsed:
                records.append(parsed)
        return records

    def parse_avahi_browse_line(self, line):
        """Parse one resolved Avahi `=` row."""
        text = re.sub(r"^\s*\d+\s+", "", str(line or "").strip())
        if not text.startswith("="):
            return None
        parts = text.split(";", 9)
        if len(parts) < 9:
            return None
        interface = decode_avahi_text(parts[1])
        protocol = decode_avahi_text(parts[2])
        service_name = decode_avahi_text(parts[3])
        service_type = decode_avahi_text(parts[4])
        hostname = decode_avahi_text(parts[6]) if len(parts) > 6 else ""
        address = decode_avahi_text(parts[7]) if len(parts) > 7 else ""
        port = decode_avahi_text(parts[8]) if len(parts) > 8 else ""
        txt_tokens = parse_avahi_txt_field(parts[9] if len(parts) > 9 else "")
        fields = txt_dict(txt_tokens)
        mac = avahi_trusted_mac(fields)
        aliases = avahi_mac_aliases(fields)
        messages = []
        if service_name or service_type:
            messages.append("{} {}".format(service_name, service_type).strip())
        if port:
            messages.append("port {}".format(port))
        messages.extend(avahi_txt_messages(fields))
        record = {
            "ip": compact_lan_text(address, 120) if usable_lan_join_ip(address) else "",
            "mac": mac,
            "hostname": compact_lan_text(hostname, 120),
            "interface": compact_lan_text(interface, 80),
            "source": "avahi-browse",
            "services": [
                item for item in (
                    compact_lan_text(service_type, 120),
                    compact_lan_text(service_name, 120),
                )
                if item
            ],
            "servers": [compact_lan_text("{} {}".format(protocol, port).strip(), 120)],
            "messages": messages,
            "mac_aliases": aliases,
        }
        return record if record.get("ip") or record.get("mac") else None

    def cached_active_arp_scan_records(self):
        """Return optional arp-scan records on their own cadence."""
        interval = float(self.config.get("active_arp_scan_interval_sec", 300))
        if not self.interval_due(self._last_arp_scan_at, interval):
            return self.current_arp_scan_records()
        self._last_arp_scan_at = time.time()
        fresh_records = self.active_arp_scan_records()
        self._last_active_arp_scan_raw_count = len(fresh_records)
        self.update_arp_scan_cache(fresh_records)
        self._arp_scan_records = self.current_arp_scan_records()
        self._active_arp_scan_refreshed = True
        logging.info(
            "LAN active arp-scan cache fresh_rows=%s retained_subjects=%s retention_sec=%.0f",
            len(fresh_records),
            len(self._arp_scan_records),
            self.active_arp_scan_retention_sec(),
        )
        return list(self._arp_scan_records)

    def update_arp_scan_cache(self, records):
        """Merge a best-effort active ARP scan into recent subject state."""
        now = time.time()
        for record in records or []:
            key = self.subject_key(record)
            if not key:
                continue
            self._arp_scan_subjects[key] = {
                "last_seen_at": now,
                "record": dict(record),
            }
        self.prune_arp_scan_cache(now)

    def current_arp_scan_records(self):
        """Return active-scan subjects retained across intermittent misses."""
        self.prune_arp_scan_cache(time.time())
        return [
            dict(entry.get("record") or {})
            for _key, entry in sorted(self._arp_scan_subjects.items())
        ]

    def prune_arp_scan_cache(self, now):
        """Drop active-scan subjects not seen for the configured retention."""
        ttl = self.active_arp_scan_retention_sec()
        for key, entry in list(self._arp_scan_subjects.items()):
            last_seen = float((entry or {}).get("last_seen_at") or 0)
            if last_seen and now - last_seen <= ttl:
                continue
            self._arp_scan_subjects.pop(key, None)

    def active_arp_scan_retention_sec(self):
        """Return how long to retain active ARP subjects after one missed scan."""
        configured = self.config.get("active_arp_scan_retention_sec")
        if configured not in (None, ""):
            try:
                return max(0.0, float(configured))
            except Exception:
                pass
        try:
            interval = float(self.config.get("active_arp_scan_interval_sec", 300))
        except Exception:
            interval = 300.0
        return max(180.0, interval * 3.0)

    def active_arp_scan_records(self):
        """Run optional active ARP scan and parse discovered subjects."""
        timeout = float(self.config.get("active_arp_scan_timeout_sec", 20))
        configured = self.config.get("active_arp_scan_interfaces") or []
        configured = [iface for iface in configured if iface and iface.strip()]
        if configured:
            interfaces = [iface for iface in configured if self._mac_allows_interface(iface)]
            if not interfaces:
                interfaces = self._discover_interfaces()
        else:
            interfaces = self._discover_interfaces()
        records = []
        for interface in interfaces:
            command = self.active_arp_scan_command(interface)
            if not command:
                continue
            cwd = self.active_arp_scan_working_dir()
            try:
                output = subprocess.check_output(
                    command,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    timeout=timeout,
                    cwd=cwd,
                )
            except Exception as exc:
                logging.warning(
                    "LAN active arp-scan failed interface=%s command=%s cwd=%s error=%s",
                    interface or "(default)",
                    " ".join(command),
                    cwd or "",
                    exc,
                )
                self.note_listener_warning("Active ARP scan failed: {}".format(exc))
                continue
            self.note_arp_scan_output_warnings(output)
            parsed = self.parse_arp_scan_output(output, interface)
            logging.info(
                "LAN active arp-scan interface=%s command=%s cwd=%s parsed_rows=%s",
                interface or "(default)",
                " ".join(command),
                cwd or "",
                len(parsed),
            )
            records.extend(parsed)
        return records

    def active_arp_scan_command(self, interface):
        """Return argv for one configured arp-scan invocation."""
        original = str(self.config.get("active_arp_scan_command") or "arp-scan --localnet").strip()
        if not original:
            return []
        try:
            text = original.format(interface=interface)
        except Exception:
            text = original
        try:
            command = shlex.split(text)
        except ValueError as exc:
            self.note_listener_warning("Invalid active ARP scan command: {}".format(exc))
            return []
        command = resolve_known_executable(command)
        if not command_executable_available(command):
            self.note_listener_warning(
                "Active ARP scan command is not executable: {}".format(
                    command[0] if command else original
                )
            )
            return []
        if (
            interface
            and "{interface}" not in original
            and "--interface" not in command
            and not any(part.startswith("--interface=") for part in command)
        ):
            command.extend(["--interface", interface])
        return command

    def active_arp_scan_working_dir(self):
        """Return a cwd where arp-scan can read its vendor data files."""
        configured = compact_lan_text(
            self.config.get("active_arp_scan_working_dir"), 500
        )
        if configured:
            return configured if os.path.isdir(configured) else None
        for path in COMMON_ARP_SCAN_DATA_DIRS:
            if arp_scan_vendor_data_present(path):
                return path
        return None

    def note_arp_scan_output_warnings(self, output):
        """Surface arp-scan vendor database access problems in status."""
        text = str(output or "")
        lowered = text.lower()
        if "permission denied" in lowered and (
            "ieee-oui.txt" in lowered or "mac-vendor.txt" in lowered
        ):
            self.note_listener_warning(
                "arp-scan could not read vendor files; set active_arp_scan_working_dir."
            )

    def parse_arp_scan_output(self, output, interface=""):
        """Parse common `arp-scan` tabular output."""
        records = []
        for line in str(output or "").splitlines():
            match = re.match(
                r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mac>[0-9a-fA-F:.-]{12,17})(?:\s+(?P<vendor>.*))?$",
                line,
            )
            if not match:
                continue
            records.append(
                {
                    "ip": compact_lan_text(match.group("ip"), 80),
                    "mac": normalize_mac(match.group("mac")),
                    "vendor_name": compact_lan_text(match.group("vendor"), 100),
                    "interface": compact_lan_text(interface, 80),
                    "source": "arp-scan",
                }
            )
        return records

    def interval_due(self, last_at, interval):
        """Return true when a throttled source should refresh."""
        try:
            interval = float(interval)
        except Exception:
            interval = 0
        if interval <= 0:
            return True
        return not last_at or time.time() - float(last_at) >= interval

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

    def collapse_gateways(self, gateways):
        """Collapse per-family/per-interface routes into one gateway subject."""
        collapsed = {}
        for gateway in gateways or []:
            key = self.gateway_subject_key(gateway)
            item = collapsed.setdefault(
                key,
                {
                    "subject_key": key,
                    "gateway": True,
                    "gateway_ip": gateway.get("gateway_ip") or "",
                    "gateway_ips": [],
                    "interface": gateway.get("interface") or "",
                    "interfaces": [],
                    "family": gateway.get("family") or "",
                    "families": [],
                    "source": "default-route",
                    "sources": [],
                    "mac": gateway.get("mac") or "",
                    "vendor_name": gateway.get("vendor_name") or "",
                    "vendor_prefix": gateway.get("vendor_prefix") or "",
                },
            )
            self.lan_sample(item, "gateway_ips", gateway.get("gateway_ip"))
            self.lan_sample(item, "interfaces", gateway.get("interface"))
            self.lan_sample(item, "families", gateway.get("family"))
            self.lan_sample(item, "sources", gateway.get("source"))
            for key_name in ("mac", "vendor_name", "vendor_prefix"):
                if gateway.get(key_name) and not item.get(key_name):
                    item[key_name] = gateway.get(key_name)
            if gateway.get("gateway_ip") and not item.get("gateway_ip"):
                item["gateway_ip"] = gateway.get("gateway_ip")
            if gateway.get("interface") and not item.get("interface"):
                item["interface"] = gateway.get("interface")
            if gateway.get("family") and not item.get("family"):
                item["family"] = gateway.get("family")
        return sorted(collapsed.values(), key=lambda item: item.get("subject_key") or "")

    def gateway_subject_key(self, gateway):
        """Return stable default-gateway identity, preferring MAC when known."""
        mac = normalize_mac((gateway or {}).get("mac"))
        if mac:
            return "mac:{}".format(mac)
        gateway_ip = compact_lan_text((gateway or {}).get("gateway_ip"), 80)
        if gateway_ip:
            return "ip:{}".format(gateway_ip)
        return "{}:{}".format((gateway or {}).get("family") or "", (gateway or {}).get("interface") or "")

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

    def _mac_allows_interface(self, iface):
        """Return True when *iface* matches the optional ``mac`` config key.

        When ``mac`` is unset every interface is allowed.  When set, only the
        adapter whose MAC matches the configured value is eligible — interface
        name swaps across reboots are harmless.
        """
        raw = self.config.get("mac")
        if not raw:
            return True
        configured_mac = str(raw).strip().lower()
        actual = self._interface_mac(iface)
        return actual == configured_mac if actual else False

    def _interface_mac(self, iface):
        """Return the lowercased MAC address for an interface, or empty string."""
        try:
            path = os.path.join("/sys/class/net", iface, "address")
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read().strip().lower()
        except OSError:
            return ""

    def _discover_interfaces(self):
        """Return all available network interfaces, filtered by optional MAC."""
        ifaces = []
        try:
            for name in os.listdir("/sys/class/net"):
                if name in (".", "..", "lo"):
                    continue
                if self._mac_allows_interface(name):
                    ifaces.append(name)
        except OSError:
            pass
        return ifaces or []

    def passive_arp_interfaces(self):
        """Return interfaces to bind raw passive ARP sockets on."""
        configured = self.config.get("passive_arp_interfaces") or []
        if configured:
            ifaces = [
                item for item in (
                    compact_lan_text(item, 80) for item in configured
                    if compact_lan_text(item, 80)
                )
                if self._mac_allows_interface(item)
            ]
            if ifaces:
                return ifaces
        return self._discover_interfaces()

    def subject_key(self, record, ip_subjects=None):
        """Return stable LAN identity by MAC when available, otherwise IP."""
        mac = normalize_mac((record or {}).get("mac"))
        if mac:
            return mac
        ip = compact_lan_text((record or {}).get("ip"), 80)
        if ip and ip_subjects and ip in ip_subjects:
            return ip_subjects[ip]
        return "ip:{}".format(ip) if ip else ""

    def device_fingerprint(self, device):
        """Return material LAN device fingerprint."""
        fields = [
            device.get("mac") or "",
            ",".join(device.get("ips") or []),
            ",".join(device.get("hostnames") or []),
            ",".join(device.get("interfaces") or []),
            ",".join(device.get("services") or []),
            ",".join(device.get("locations") or []),
            ",".join(device.get("servers") or []),
            ",".join(device.get("mac_aliases") or []),
            device.get("vendor_name") or "",
            device.get("vendor_prefix") or "",
            str(bool(device.get("gateway"))),
        ]
        return "|".join(fields)

    def gateway_fingerprint(self, gateway):
        """Return material default-gateway fingerprint."""
        fields = [
            ",".join(gateway.get("families") or [gateway.get("family") or ""]),
            ",".join(gateway.get("gateway_ips") or [gateway.get("gateway_ip") or ""]),
            ",".join(gateway.get("interfaces") or [gateway.get("interface") or ""]),
            gateway.get("mac") or "",
        ]
        return "|".join(fields)

    def parse_ssdp_packet(self, payload, addr):
        """Return LAN records from one SSDP packet."""
        text = payload.decode("utf-8", errors="replace")
        lines = [line.strip() for line in text.replace("\r\n", "\n").split("\n") if line.strip()]
        if not lines:
            return None
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        ip = addr[0] if addr else ""
        service = headers.get("st") or headers.get("nt") or lines[0]
        return {
            "ip": compact_lan_text(ip, 80),
            "source": "ssdp",
            "services": [service],
            "locations": [headers.get("location") or ""],
            "servers": [headers.get("server") or ""],
            "messages": [lines[0]],
        }

    def parse_mdns_packet(self, payload, addr):
        """Return LAN records from one mDNS packet using lightweight DNS parsing."""
        names = self.dns_names_from_packet(payload)
        if not names:
            return None
        hostnames = [
            name for name in names
            if name.lower().endswith(".local") and "._tcp" not in name and "._udp" not in name
        ][:8]
        services = [
            name for name in names
            if "._tcp" in name.lower() or "._udp" in name.lower()
        ][:12]
        if not hostnames and not services:
            return None
        ip = addr[0] if addr else ""
        return {
            "ip": compact_lan_text(ip, 80),
            "source": "mdns",
            "hostnames": hostnames,
            "services": services,
            "messages": names[:8],
        }

    def parse_dhcp_packet(self, payload, addr):
        """Return LAN records from one BOOTP/DHCP packet."""
        if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
            return None
        hlen = payload[2]
        mac = normalize_mac(payload[28 : 28 + min(int(hlen), 16)].hex())
        ciaddr = ipv4_from_bytes(payload[12:16])
        yiaddr = ipv4_from_bytes(payload[16:20])
        options = self.parse_dhcp_options(payload[240:])
        message_type = dhcp_message_type(options.get(53))
        requested_ip = ipv4_from_bytes(options.get(50) or b"")
        server_id = ipv4_from_bytes(options.get(54) or b"")
        hostname = decode_option(options.get(12))
        vendor = decode_option(options.get(60))
        ip = requested_ip or yiaddr or ciaddr or (addr[0] if addr else "")
        services = ["DHCP {}".format(message_type)] if message_type else ["DHCP"]
        messages = []
        if message_type:
            messages.append("DHCP {}".format(message_type))
        if requested_ip:
            messages.append("requested {}".format(requested_ip))
        return {
            "ip": compact_lan_text(ip, 80),
            "mac": mac,
            "hostname": compact_lan_text(hostname, 80),
            "source": "passive-dhcp",
            "services": services,
            "servers": [server_id],
            "messages": messages,
            "vendor_name": compact_lan_text(vendor, 100),
        }

    def parse_dhcp_options(self, payload):
        """Parse DHCP options into a code-to-bytes dictionary."""
        options = {}
        offset = 0
        while offset < len(payload):
            code = payload[offset]
            offset += 1
            if code == 255:
                break
            if code == 0:
                continue
            if offset >= len(payload):
                break
            length = payload[offset]
            offset += 1
            value = payload[offset : offset + length]
            offset += length
            options[code] = value
        return options

    def parse_arp_packet(self, payload, addr):
        """Return LAN records from one raw Ethernet ARP packet."""
        if len(payload) < 42:
            return None
        ethertype = struct.unpack("!H", payload[12:14])[0]
        if ethertype != ETH_P_ARP:
            return None
        arp = payload[14:]
        if len(arp) < 28:
            return None
        htype, ptype, hlen, plen, operation = struct.unpack("!HHBBH", arp[:8])
        if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
            return None
        sender_mac = normalize_mac(arp[8:14].hex())
        sender_ip = ipv4_from_bytes(arp[14:18])
        target_ip = ipv4_from_bytes(arp[24:28])
        if not sender_mac and not sender_ip:
            return None
        operation_text = "request" if operation == 1 else "reply" if operation == 2 else "op {}".format(operation)
        interface = addr[0] if isinstance(addr, tuple) and addr else ""
        return {
            "ip": sender_ip,
            "mac": sender_mac,
            "interface": compact_lan_text(interface, 80),
            "source": "passive-arp",
            "services": ["ARP"],
            "messages": ["ARP {} for {}".format(operation_text, target_ip)],
        }

    def dns_names_from_packet(self, payload):
        """Extract useful DNS names from one mDNS packet."""
        if len(payload) < 12:
            return []
        try:
            qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", payload[4:12])
        except struct.error:
            return []
        names = []
        offset = 12
        for _index in range(qdcount):
            name, offset = self.read_dns_name(payload, offset)
            if name:
                sample_name(names, name)
            if offset + 4 > len(payload):
                return names
            offset += 4
        for _index in range(ancount + nscount + arcount):
            name, offset = self.read_dns_name(payload, offset)
            if name:
                sample_name(names, name)
            if offset + 10 > len(payload):
                return names
            try:
                rr_type, _rr_class, _ttl, rdlength = struct.unpack("!HHIH", payload[offset : offset + 10])
            except struct.error:
                return names
            offset += 10
            rdata_offset = offset
            offset += rdlength
            if rr_type in (5, 12):
                rdata_name, _next_offset = self.read_dns_name(payload, rdata_offset)
                if rdata_name:
                    sample_name(names, rdata_name)
            elif rr_type == 33 and rdata_offset + 6 < len(payload):
                rdata_name, _next_offset = self.read_dns_name(payload, rdata_offset + 6)
                if rdata_name:
                    sample_name(names, rdata_name)
        return names

    def read_dns_name(self, payload, offset, depth=0):
        """Read a possibly compressed DNS name and return (name, next_offset)."""
        if depth > 8:
            return "", offset
        labels = []
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0 == 0xC0:
                if offset + 1 >= len(payload):
                    return "", offset + 1
                pointer = ((length & 0x3F) << 8) | payload[offset + 1]
                pointed, _unused = self.read_dns_name(payload, pointer, depth + 1)
                if pointed:
                    labels.append(pointed)
                offset += 2
                break
            offset += 1
            if offset + length > len(payload):
                return "", offset
            label = payload[offset : offset + length].decode("utf-8", errors="replace")
            labels.append(label)
            offset += length
        name = ".".join(part for part in labels if part).strip(".")
        return compact_lan_text(name, 160), offset

    def lan_sample(self, item, key, value, limit=12):
        """Append one distinct LAN summary value."""
        text = compact_lan_text(value, 120)
        if not text:
            return
        item.setdefault(key, [])
        if text not in item[key] and len(item[key]) < limit:
            item[key].append(text)

    def add_vendor(self, item):
        """Fill offline vendor fields for a LAN MAC."""
        mac = item.get("mac") or item.get("subject_key") or ""
        vi = vendor_info(mac)
        item["vendor_oui"] = vi["vendor_oui"] or ""
        item["vendor_prefix"] = vi["vendor_prefix"] or item.get("vendor_prefix") or vi["vendor_oui"]
        item["vendor_name"] = vi["vendor_name"] or item.get("vendor_name") or ""


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


def list_values(value):
    """Return a list for scalar-or-list values."""
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    return [value]


def ipv4_from_bytes(value):
    """Return dotted IPv4 text unless the value is empty or 0.0.0.0."""
    if not value or len(value) != 4:
        return ""
    try:
        text = socket.inet_ntoa(value)
    except OSError:
        return ""
    return "" if text == "0.0.0.0" else text


def decode_option(value):
    """Decode a DHCP option value."""
    if not value:
        return ""
    return compact_lan_text(value.decode("utf-8", errors="replace"), 100)


def dhcp_message_type(value):
    """Return common DHCP message type labels."""
    names = {
        1: "DISCOVER",
        2: "OFFER",
        3: "REQUEST",
        4: "DECLINE",
        5: "ACK",
        6: "NAK",
        7: "RELEASE",
        8: "INFORM",
    }
    if not value:
        return ""
    return names.get(value[0], str(value[0]))


def sample_name(names, name, limit=32):
    """Append one DNS name sample."""
    text = compact_lan_text(name, 160)
    if text and text not in names and len(names) < limit:
        names.append(text)
