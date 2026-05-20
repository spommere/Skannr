import asyncio
import os
import re
import subprocess

from bus import local_now
from collectors.base import BaseCollector, STATE_OFFLINE, STATE_RETRYING, STATE_RUNNING_TIER1, STATE_RUNNING_TIER2
from oui_lookup import normalize_oui, vendor_name, vendor_prefix


class WiFiCollector(BaseCollector):
    """Managed-mode Wi-Fi collector for visible access points.

    This collector intentionally does not put adapters into monitor mode and
    does not sniff packets. Probe requests, deauth frames, and channel hopping
    belong to the on-demand wifi_monitor collector.
    """

    config_key = "wifi"
    name = "Wi-Fi Scan"
    tab_label = "Wi-Fi Scan"
    required_hardware = "Wi-Fi interface for managed AP scans"

    def interface_exists(self, interface):
        """Check whether the configured Linux network interface exists."""
        return os.path.exists(os.path.join("/sys/class/net", interface))

    def detect(self):
        """Select preferred Wi-Fi interface first, then configured fallback."""
        preferred = self.config.get("preferred_interface", "wlan1")
        fallback = self.config.get("fallback_interface", "wlan0")
        primary_default = "test -d /sys/class/net/{} && (command -v iw >/dev/null 2>&1 || command -v iwlist >/dev/null 2>&1)".format(preferred)
        fallback_default = "test -d /sys/class/net/{} && (command -v iw >/dev/null 2>&1 || command -v iwlist >/dev/null 2>&1)".format(fallback)
        primary_ok, primary_detail = self.validate_tier("primary", primary_default)
        if primary_ok:
            self.active_hardware = preferred
            self.state = STATE_RUNNING_TIER1
            self.warning = None
            return True
        fallback_ok, fallback_detail = self.validate_tier("fallback", fallback_default)
        if fallback_ok:
            self.active_hardware = fallback
            self.state = STATE_RUNNING_TIER2
            self.warning = "Using fallback Wi-Fi scan interface {}. Primary validation failed: {}".format(fallback, primary_detail)
            return True
        self.active_hardware = None
        self.state = STATE_OFFLINE
        self.warning = "No usable Wi-Fi interface. Primary validation: {}; fallback validation: {}".format(primary_detail, fallback_detail)
        return False

    async def start(self):
        """Start managed AP scans on the selected interface."""
        self._running = True
        if not self.detect():
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return
        await self.emit("interface_mode", {
            "interface": self.active_hardware,
            "monitor": False,
            "warning": self.warning,
        }, "warning" if self.warning else "info")
        await self.managed_scan_loop(self.active_hardware)

    async def managed_scan_loop(self, iface):
        """Managed scanner for normal Wi-Fi interfaces."""
        interval = float(self.config.get("managed_scan_interval_sec", 2))
        await self.emit("scan_started", {
            "interface": iface,
            "method": "iw/iwlist",
            "note": "Managed scan lists visible AP SSIDs but does not capture probe requests.",
        })
        while self._running:
            try:
                # Reassert the interface state before every scan. On small Pi
                # setups the interface can be administratively down after errors.
                self.ensure_interface_up(iface)
                networks = self.scan_access_points(iface)
                if not networks:
                    await self.emit("scan_empty", {
                        "interface": iface,
                        "diagnostics": self.interface_diagnostics(iface),
                    }, "warning")
                for network in networks:
                    await self.emit("ap_beacon", network)
            except Exception as exc:
                # Keep retry diagnostics specific: interface state plus command
                # failure is much more useful than "Wi-Fi failed".
                self.state = STATE_RETRYING
                self.warning = "Managed Wi-Fi scan failed on {}: {}; {}".format(
                    iface,
                    exc,
                    self.interface_diagnostics(iface),
                )
                await self.emit("collector_retrying", {"reason": self.warning}, "warning")
            await asyncio.sleep(interval)

    def ensure_interface_up(self, iface):
        """Best-effort 'ip link set up' before capture or scan attempts."""
        if not iface:
            return
        try:
            subprocess.run(["ip", "link", "set", iface, "up"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def interface_diagnostics(self, iface):
        """Collect concise interface state for warnings shown in the UI."""
        if not iface:
            return "no interface selected"
        operstate = self.read_sys_value(iface, "operstate")
        flags = self.read_sys_value(iface, "flags")
        try:
            result = subprocess.run(
                ["ip", "-o", "link", "show", iface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                universal_newlines=True,
            )
            summary = result.stdout.strip() or result.stderr.strip()
        except Exception as exc:
            summary = "ip link unavailable: {}".format(exc)
        return "operstate={}, flags={}, link={}".format(operstate, flags, summary)

    def read_sys_value(self, iface, name):
        """Read one /sys/class/net value, returning 'unknown' on failure."""
        path = os.path.join("/sys/class/net", iface, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except Exception:
            return "unknown"

    def scan_access_points(self, iface):
        """Run whichever managed scan command is available and parse results."""
        output = self.run_scan_command(["iw", "dev", iface, "scan"])
        if output:
            return self.parse_iw_scan(output)
        output = self.run_scan_command(["iwlist", iface, "scan"])
        if output:
            return self.parse_iwlist_scan(output)
        return []

    def run_scan_command(self, command):
        """Run iw/iwlist with a timeout; empty output means try the next path."""
        try:
            return subprocess.check_output(command, universal_newlines=True, stderr=subprocess.STDOUT, timeout=20)
        except Exception:
            return ""

    def parse_iw_scan(self, output):
        """Parse 'iw dev <iface> scan' output into AP event dictionaries."""
        networks = []
        current = None
        for raw_line in output.splitlines():
            line = raw_line.strip()
            match = re.match(r"BSS\s+([0-9a-fA-F:]+)", line)
            if match:
                # A BSS line starts a new AP block. Flush the previous AP first.
                if current:
                    networks.append(current)
                current = {
                    "bssid": match.group(1).lower(),
                    "ssid": "",
                    "channel": None,
                    "encryption": "open",
                    "rssi": None,
                    "timestamp": local_now(),
                }
                current["vendor_oui"] = self.vendor_for(current["bssid"])
                current["vendor_prefix"] = self.vendor_prefix_for(current["bssid"])
                current["vendor_name"] = self.vendor_name_for(current["bssid"])
                continue
            if not current:
                continue
            if line.startswith("SSID:"):
                current["ssid"] = line.split("SSID:", 1)[1].strip()
            elif line.startswith("signal:"):
                current["rssi"] = self.parse_signal_dbm(line.split("signal:", 1)[1])
            elif line.startswith("freq:"):
                frequency = line.split("freq:", 1)[1].strip()
                current["frequency_mhz"] = self.parse_frequency_mhz(frequency)
                current["frequency_band"] = self.band_from_frequency(frequency)
                current["channel"] = self.channel_from_frequency(frequency)
            elif line.startswith("RSN:"):
                current["encryption"] = self.merge_encryption(current["encryption"], "WPA2/RSN")
            elif line.startswith("WPA:"):
                current["encryption"] = self.merge_encryption(current["encryption"], "WPA")
            elif line.startswith("* Authentication suites:") and "SAE" in line:
                current["encryption"] = self.merge_encryption(current["encryption"], "WPA3")
            elif line.startswith("capability:") and "Privacy" in line:
                current["encryption"] = self.merge_encryption(current["encryption"], "WEP/unknown")
        if current:
            networks.append(current)
        return networks

    def parse_iwlist_scan(self, output):
        """Parse older iwlist scan output into AP event dictionaries."""
        networks = []
        current = None
        for raw_line in output.splitlines():
            line = raw_line.strip()
            match = re.match(r"Cell\s+\d+\s+-\s+Address:\s+([0-9a-fA-F:]+)", line)
            if match:
                # Each Cell block corresponds to one visible access point.
                if current:
                    networks.append(current)
                current = {
                    "bssid": match.group(1).lower(),
                    "ssid": "",
                    "channel": None,
                    "encryption": "open",
                    "rssi": None,
                    "timestamp": local_now(),
                }
                current["vendor_oui"] = self.vendor_for(current["bssid"])
                current["vendor_prefix"] = self.vendor_prefix_for(current["bssid"])
                current["vendor_name"] = self.vendor_name_for(current["bssid"])
                continue
            if not current:
                continue
            if line.startswith("ESSID:"):
                current["ssid"] = line.split("ESSID:", 1)[1].strip().strip('"')
            elif "Channel" in line:
                channel = re.search(r"Channel\s+(\d+)", line)
                if channel:
                    current["channel"] = int(channel.group(1))
                    current["frequency_band"] = self.channel_band(current["channel"])
            elif "Signal level=" in line:
                current["rssi"] = self.parse_signal_dbm(line.split("Signal level=", 1)[1])
            elif line.startswith("Encryption key:"):
                current["encryption"] = "WEP/unknown" if line.endswith("on") else "open"
            elif line.startswith("IE: IEEE 802.11i/WPA2"):
                current["encryption"] = self.merge_encryption(current["encryption"], "WPA2")
            elif line.startswith("IE: WPA"):
                current["encryption"] = self.merge_encryption(current["encryption"], "WPA")
            elif "Authentication Suites" in line and "SAE" in line:
                current["encryption"] = self.merge_encryption(current["encryption"], "WPA3")
        if current:
            networks.append(current)
        return networks

    def channel_from_frequency(self, frequency):
        """Convert common 2.4 GHz / 5 GHz Wi-Fi frequencies to channels."""
        mhz = self.parse_frequency_mhz(frequency)
        if mhz is None:
            return None
        if 2412 <= mhz <= 2472:
            return int((mhz - 2407) / 5)
        if mhz == 2484:
            return 14
        if 5000 <= mhz <= 5900:
            return int((mhz - 5000) / 5)
        return None

    def parse_frequency_mhz(self, frequency):
        """Return numeric MHz from iw output such as '2412'."""
        try:
            value = float(frequency)
        except (TypeError, ValueError):
            return None
        return int(value) if value.is_integer() else value

    def band_from_frequency(self, frequency):
        """Return display band from a frequency in MHz."""
        mhz = self.parse_frequency_mhz(frequency)
        if mhz is None:
            return None
        if 2400 <= mhz < 2500:
            return "2.4"
        if 5000 <= mhz < 5900:
            return "5"
        if 5900 <= mhz < 7200:
            return "6"
        return None

    def channel_band(self, channel):
        """Return display band from common Wi-Fi channel numbers."""
        try:
            channel = int(channel)
        except (TypeError, ValueError):
            return None
        if 1 <= channel <= 14:
            return "2.4"
        if 30 <= channel <= 196:
            return "5"
        return None

    def parse_signal_dbm(self, text):
        """Extract a numeric dBm RSSI, ignoring quality-only values like 61/100."""
        match = re.search(r"(-?\d+(?:\.\d+)?)\s*dBm", str(text), re.IGNORECASE)
        if not match:
            return None
        value = float(match.group(1))
        return int(value) if value.is_integer() else value

    def get_ssid(self, packet, dot11_elt):
        """Extract SSID from Dot11 information elements."""
        elt = packet.getlayer(dot11_elt)
        while elt:
            if elt.ID == 0:
                info = elt.info or b""
                if isinstance(info, bytes):
                    return info.decode("utf-8", errors="replace")
                return str(info)
            elt = elt.payload.getlayer(dot11_elt)
        return ""

    def get_channel(self, packet, dot11_elt):
        """Extract channel from Dot11 DS Parameter Set element."""
        elt = packet.getlayer(dot11_elt)
        while elt:
            if elt.ID == 3 and elt.info:
                return elt.info[0]
            elt = elt.payload.getlayer(dot11_elt)
        return None

    def get_encryption(self, packet):
        """Return the best encryption label available from beacon elements."""
        labels = []
        rsn_label = self.rsn_encryption_label(packet)
        if rsn_label:
            labels.append(rsn_label)
        if self.has_vendor_wpa(packet):
            labels.append("WPA")
        if labels:
            return "/".join(labels)
        capabilities = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        if "privacy" in capabilities.lower():
            # Privacy without RSN/WPA information usually means WEP, but some
            # malformed or partial captures can look the same. Keep it explicit.
            return "WEP/unknown"
        return "open"

    def rsn_encryption_label(self, packet):
        """Return WPA2/WPA3 detail from an RSN information element."""
        elt = packet.getlayer("Dot11Elt")
        while elt:
            if elt.ID == 48:
                akms = self.rsn_akm_types(elt.info)
                if 8 in akms and (2 in akms or 1 in akms):
                    return "WPA2/WPA3"
                if 8 in akms:
                    return "WPA3"
                return "WPA2/RSN"
            elt = elt.payload.getlayer("Dot11Elt")
        return None

    def rsn_akm_types(self, info):
        """Extract RSN AKM suite type numbers; SAE type 8 indicates WPA3."""
        if not info:
            return []
        if isinstance(info, str):
            info = info.encode("latin1", errors="ignore")
        try:
            offset = 2
            offset += 4
            pairwise_count = info[offset] + (info[offset + 1] << 8)
            offset += 2 + (4 * pairwise_count)
            akm_count = info[offset] + (info[offset + 1] << 8)
            offset += 2
        except Exception:
            return []
        akms = []
        for _index in range(akm_count):
            suite = info[offset:offset + 4]
            if len(suite) < 4:
                break
            if suite[:3] == b"\x00\x0f\xac":
                akms.append(suite[3])
            offset += 4
        return akms

    def has_vendor_wpa(self, packet):
        """Detect legacy WPA vendor elements in beacon payloads."""
        elt = packet.getlayer("Dot11Elt")
        while elt:
            if elt.ID == 221 and self.is_wpa_vendor_info(elt.info):
                return True
            elt = elt.payload.getlayer("Dot11Elt")
        return False

    def is_wpa_vendor_info(self, info):
        """Check for Microsoft WPA OUI/type 00:50:f2:01."""
        if not info:
            return False
        if isinstance(info, str):
            info = info.encode("latin1", errors="ignore")
        return len(info) >= 4 and info[:4] == b"\x00\x50\xf2\x01"

    def merge_encryption(self, current, new_value):
        """Merge multiple scan hints into a readable encryption label."""
        if not current or current == "open":
            return new_value
        if current == "WEP/unknown" and new_value != "WEP/unknown":
            return new_value
        if new_value == "WEP/unknown" and current != "open":
            return current
        if current == new_value:
            return current
        values = []
        for value in (current, new_value):
            values.extend(part for part in value.split("/") if part)
        ordered = []
        for value in values:
            if value not in ordered and value != "unknown":
                ordered.append(value)
        if "WPA2" in ordered and "RSN" in ordered:
            ordered.remove("RSN")
        return "/".join(ordered) if ordered else new_value

    def vendor_for(self, mac):
        """Return the MAC OUI prefix used as a lightweight vendor hint."""
        return normalize_oui(mac)

    def vendor_name_for(self, mac):
        """Return an offline IEEE OUI vendor name when collectors/oui.txt exists."""
        return vendor_name(mac)

    def vendor_prefix_for(self, mac):
        """Return the longest matched IEEE prefix for display."""
        return vendor_prefix(mac) or self.vendor_for(mac)
