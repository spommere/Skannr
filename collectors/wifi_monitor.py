import asyncio
import os
import re
import subprocess
import threading
import time

from bus import local_now
from collectors.base import BaseCollector, STATE_OFFLINE, STATE_RETRYING, STATE_RUNNING_TIER1, STATE_STOPPED
from collectors.wifi import WiFiCollector
from log_utils import read_jsonl_events


class WiFiMonitorCollector(WiFiCollector):
    """On-demand monitor-mode Wi-Fi collector with channel hopping.

    The normal Wi-Fi collector stays lightweight and can run managed fallback
    scans. This collector assumes the user has already put a separate adapter
    into monitor mode, then samples supported 2.4/5 GHz channels for raw
    management frames such as probes, beacons, association attempts, and
    deauth/disassoc traffic.
    """

    config_key = "wifi_monitor"
    name = "Wi-Fi Monitor"
    tab_label = "Wi-Fi Monitor"
    required_hardware = "Wi-Fi adapter already in monitor mode"

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self._sniff_thread = None
        self._hopper_task = None
        self._current_channel = None
        self._channel_plan = []
        self._supported_channels = {}

    def detect(self):
        """Report availability without starting sniffing or channel hopping."""
        primary_ok, primary_detail = self.validate_tier("primary", "command -v iw >/dev/null 2>&1")
        if not primary_ok:
            self.active_hardware = None
            self.state = STATE_OFFLINE
            self.warning = "Wi-Fi monitor validation failed: {}".format(primary_detail)
            return False
        iface = self.select_monitor_interface()
        if not iface:
            self.active_hardware = None
            self.state = STATE_OFFLINE
            self.warning = "No monitor-mode Wi-Fi interface found. Put a separate Wi-Fi adapter into monitor mode, then click Start."
            return False
        self.active_hardware = iface
        self.state = STATE_STOPPED
        self.warning = None
        return True

    async def start(self):
        """Start monitor-mode sniffing only after the user clicks Start."""
        self._running = True
        iface = self.select_monitor_interface()
        if not iface:
            self.state = STATE_OFFLINE
            self.warning = "No monitor-mode Wi-Fi interface found. Put a separate Wi-Fi adapter into monitor mode, then click Start."
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            self._running = False
            return

        try:
            from scapy.all import Dot11, Dot11Elt, sniff
        except ImportError:
            self.state = STATE_OFFLINE
            self.warning = "Python package 'scapy' is not installed."
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            self._running = False
            return

        self.active_hardware = iface
        self.state = STATE_RUNNING_TIER1
        self.warning = None
        self.ensure_interface_up(iface)
        self._supported_channels = self.supported_channels_by_band()
        self._channel_plan = self.build_channel_plan()
        if not self._channel_plan:
            self.state = STATE_OFFLINE
            self.warning = "No supported 2.4 GHz or 5 GHz channels were discovered for {}.".format(iface)
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            self._running = False
            return

        loop = asyncio.get_event_loop()
        await self.emit("monitor_started", {
            "interface": iface,
            "channels": self._channel_plan,
            "supported_bands": sorted(self._supported_channels.keys()),
            "dwell_sec": self.dwell_seconds(),
        })

        def packet_handler(packet):
            """Convert raw 802.11 management frames into Skannr events."""
            if not self._running or not packet.haslayer(Dot11):
                return
            timestamp = local_now()
            dot11 = packet.getlayer(Dot11)
            rssi = getattr(packet, "dBm_AntSignal", None)
            channel = self.packet_channel(packet, Dot11Elt) or self._current_channel

            if dot11.type != 0:
                return
            if dot11.subtype == 4:
                payload = {
                    "client_mac": dot11.addr2,
                    "vendor_oui": self.vendor_for(dot11.addr2),
                    "vendor_prefix": self.vendor_prefix_for(dot11.addr2),
                    "vendor_name": self.vendor_name_for(dot11.addr2),
                    "ssid_probed": self.get_ssid(packet, Dot11Elt),
                    "rssi": rssi,
                    "channel": channel,
                    "timestamp": timestamp,
                    "monitor_interface": iface,
                }
                asyncio.run_coroutine_threadsafe(self.emit("probe_request", payload), loop)
            elif dot11.subtype == 8:
                payload = {
                    "bssid": dot11.addr2,
                    "vendor_oui": self.vendor_for(dot11.addr2),
                    "vendor_prefix": self.vendor_prefix_for(dot11.addr2),
                    "vendor_name": self.vendor_name_for(dot11.addr2),
                    "ssid": self.get_ssid(packet, Dot11Elt),
                    "channel": channel,
                    "encryption": self.get_encryption(packet),
                    "rssi": rssi,
                    "timestamp": timestamp,
                    "monitor_interface": iface,
                }
                asyncio.run_coroutine_threadsafe(self.emit("ap_beacon", payload), loop)
            elif dot11.subtype in (0, 2):
                payload = self.client_ap_payload(dot11, rssi, channel, timestamp, iface)
                asyncio.run_coroutine_threadsafe(self.emit("association_seen", payload), loop)
            elif dot11.subtype == 10:
                payload = self.client_ap_payload(dot11, rssi, channel, timestamp, iface)
                asyncio.run_coroutine_threadsafe(self.emit("disassoc_seen", payload), loop)
            elif dot11.subtype == 12:
                payload = self.client_ap_payload(dot11, rssi, channel, timestamp, iface)
                asyncio.run_coroutine_threadsafe(self.emit("deauth_seen", payload), loop)

        async def report_sniff_error(error):
            self.state = STATE_RETRYING
            self.warning = "Wi-Fi monitor sniff failed on {}: {}; {}".format(
                iface,
                error,
                self.interface_diagnostics(iface),
            )
            await self.emit("collector_retrying", {"reason": self.warning}, "warning")

        def sniff_loop():
            """Run Scapy in a thread while the asyncio task hops channels."""
            while self._running:
                try:
                    sniff(iface=iface, prn=packet_handler, store=False, stop_filter=lambda _pkt: not self._running, timeout=1)
                except Exception as exc:
                    asyncio.run_coroutine_threadsafe(report_sniff_error(exc), loop)
                    time.sleep(float(self.config.get("retry_interval_sec", 5)))

        self._hopper_task = loop.create_task(self.channel_hopper(iface))
        self._sniff_thread = threading.Thread(target=sniff_loop, daemon=True)
        self._sniff_thread.start()
        while self._running:
            await asyncio.sleep(1)

    async def stop(self):
        """Stop sniffing and channel hopping, but leave monitor mode intact."""
        await BaseCollector.stop(self)
        if self._hopper_task and not self._hopper_task.done():
            self._hopper_task.cancel()
            await asyncio.gather(self._hopper_task, return_exceptions=True)
        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=3)

    async def channel_hopper(self, iface):
        """Retune the monitor interface across the current channel plan."""
        dwell = self.dwell_seconds()
        while self._running:
            for channel in self._channel_plan:
                if not self._running:
                    return
                if self.set_channel(iface, channel):
                    self._current_channel = channel
                    await self.emit("monitor_channel_changed", {
                        "interface": iface,
                        "channel": channel,
                        "band": self.channel_band(channel),
                    })
                await asyncio.sleep(dwell)

    def dwell_seconds(self):
        """Return configured dwell time per channel."""
        try:
            dwell = float(self.config.get("dwell_sec", 1))
        except (TypeError, ValueError):
            dwell = 1
        return max(dwell, 0.1)

    def set_channel(self, iface, channel):
        """Best-effort retune of the monitor interface."""
        try:
            result = subprocess.run(
                ["iw", "dev", iface, "set", "channel", str(channel)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                return True
            self.warning = "Could not set {} to channel {}: {}".format(iface, channel, result.stdout.strip())
        except Exception as exc:
            self.warning = "Could not set {} to channel {}: {}".format(iface, channel, exc)
        return False

    def select_monitor_interface(self):
        """Return the first configured or discovered monitor-mode interface."""
        configured = self.config.get("interfaces") or []
        if isinstance(configured, str):
            configured = [configured]
        discovered = self.monitor_interfaces()
        for iface in configured:
            if iface in discovered:
                return iface
        preferred = self.config.get("interface")
        if preferred and preferred != "auto" and preferred in discovered:
            return preferred
        return discovered[0] if discovered else None

    def monitor_interfaces(self):
        """Parse 'iw dev' and return interfaces whose type is monitor."""
        try:
            output = subprocess.check_output(["iw", "dev"], stderr=subprocess.STDOUT, universal_newlines=True, timeout=5)
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
        return [iface for iface in interfaces if self.interface_allowed(iface)]

    def interface_allowed(self, iface):
        """Honor the optional interface_regex while defaulting to wlan-like names."""
        pattern = self.config.get("interface_regex")
        if pattern:
            try:
                return bool(re.search(pattern, iface))
            except re.error:
                return True
        return "wlan" in iface or iface.startswith("mon")

    def supported_channels_by_band(self):
        """Discover usable 2.4/5 GHz channels from the local adapter/driver."""
        output = self.iw_list_output()
        channels = {"2.4": set(), "5": set()}
        for line in output.splitlines():
            if "MHz" not in line or "[" not in line or "]" not in line:
                continue
            if "disabled" in line.lower():
                continue
            match = re.search(r"(\d+)\s+MHz\s+\[(\d+)\]", line)
            if not match:
                continue
            mhz = int(match.group(1))
            channel = int(match.group(2))
            if 2400 <= mhz < 2500:
                channels["2.4"].add(channel)
            elif 5000 <= mhz < 5900:
                channels["5"].add(channel)
        return {band: sorted(values) for band, values in channels.items() if values}

    def iw_list_output(self):
        """Return frequency capabilities for the selected PHY when possible."""
        phy = self.phy_for_interface(self.active_hardware)
        if phy:
            try:
                return subprocess.check_output(["iw", "phy", phy, "info"], stderr=subprocess.STDOUT, universal_newlines=True, timeout=10)
            except Exception:
                pass
        try:
            return subprocess.check_output(["iw", "list"], stderr=subprocess.STDOUT, universal_newlines=True, timeout=10)
        except Exception:
            return ""

    def phy_for_interface(self, iface):
        """Map an interface from 'iw dev' to its phy name such as phy0."""
        if not iface:
            return None
        try:
            output = subprocess.check_output(["iw", "dev"], stderr=subprocess.STDOUT, universal_newlines=True, timeout=5)
        except Exception:
            return None
        current_phy = None
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if line.startswith("phy#"):
                current_phy = "phy{}".format(line.split("#", 1)[1])
            elif line == "Interface {}".format(iface):
                return current_phy
        return None

    def build_channel_plan(self):
        """Build a low-overhead channel plan from common channels.

        Reading old logs during Start made the on-demand monitor collector do
        more work than expected. By default Skannr starts with common channels
        supported by the adapter. Users can opt in to appending previously seen
        AP channels later through include_seen_channels.
        """
        plan = []
        enabled_bands = self.enabled_bands()
        typical = {
            "2.4": self.config.get("typical_channels_24", [1, 6, 11]),
            "5": self.config.get("typical_channels_5", [36, 40, 44, 48, 149, 153, 157, 161, 165]),
        }
        seen = self.seen_channels_by_band() if self.config.get("include_seen_channels", False) else {}
        for band in enabled_bands:
            supported = set(self._supported_channels.get(band) or [])
            if not supported:
                continue
            for channel in list(typical.get(band) or []) + list(seen.get(band) or []):
                try:
                    channel = int(channel)
                except (TypeError, ValueError):
                    continue
                if channel in supported and channel not in plan:
                    plan.append(channel)
        return plan

    def enabled_bands(self):
        """Return configured bands that are also supported by the adapter."""
        bands = self.config.get("bands", ["2.4", "5"])
        if isinstance(bands, str):
            bands = [bands]
        normalized = []
        for band in bands:
            text = str(band).lower().replace("ghz", "").strip()
            if text in ("2", "2.4", "24"):
                normalized.append("2.4")
            elif text in ("5", "5.0"):
                normalized.append("5")
        return [band for band in normalized if band in self._supported_channels]

    def seen_channels_by_band(self):
        """Read retained Wi-Fi logs and collect AP channels already observed."""
        log_dir = self.configured_log_dir()
        channels = {"2.4": [], "5": []}
        for collector in ("wifi", "wifi_monitor"):
            for event in read_jsonl_events(log_dir, collector, None):
                if event.get("type") != "ap_beacon":
                    continue
                channel = (event.get("data") or {}).get("channel")
                try:
                    channel = int(channel)
                except (TypeError, ValueError):
                    continue
                band = self.channel_band(channel)
                if band and channel not in channels[band]:
                    channels[band].append(channel)
        return channels

    def configured_log_dir(self):
        """Return the configured persistence log directory."""
        global_config = self.config.get("_global_config") or {}
        filesystem = ((global_config.get("persistence") or {}).get("filesystem") or {})
        log_dir = filesystem.get("log_dir", "./logs")
        return log_dir if os.path.isabs(log_dir) else os.path.abspath(log_dir)

    def packet_channel(self, packet, dot11_elt):
        """Extract a packet channel, falling back to the hopper state."""
        channel = self.get_channel(packet, dot11_elt)
        if channel:
            return channel
        return self._current_channel

    def client_ap_payload(self, dot11, rssi, channel, timestamp, iface):
        """Build common client/AP event payload for management frames."""
        return {
            "client_mac": dot11.addr2,
            "ap_mac": dot11.addr1 or dot11.addr3,
            "rssi": rssi,
            "channel": channel,
            "timestamp": timestamp,
            "monitor_interface": iface,
        }

    def channel_band(self, channel):
        """Return 2.4 or 5 for common Wi-Fi channels."""
        try:
            channel = int(channel)
        except (TypeError, ValueError):
            return None
        if 1 <= channel <= 14:
            return "2.4"
        if 30 <= channel <= 196:
            return "5"
        return None
