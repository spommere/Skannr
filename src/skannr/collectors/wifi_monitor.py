"""Monitor-mode Wi-Fi packet collector and channel hopper."""

import asyncio
import logging
import os
import re
import shutil
import subprocess
import threading
import time

from ..bus import local_now
from ..log_utils import now_epoch, read_jsonl_events
from ..oui_lookup import vendor_info
from .base import (
    BaseCollector,
    STATE_OFFLINE,
    STATE_ONLINE,
    STATE_RETRYING,
    STATE_STOPPED,
)
from .hardware import (
    availability_records,
    configured_candidates,
    default_route_interface,
    interface_supports_monitor_mode,
    monitor_mode_interfaces,
    package_available,
    phy_for_interface,
    sort_wifi_interfaces,
    sysfs_read,
    wireless_interface_details,
    wireless_interfaces,
)
from .wifi import WiFiCollector

COMMAND_CANDIDATES = {
    "ip": ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"),
    "iw": ("/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw", "/bin/iw"),
    "nmcli": ("/usr/bin/nmcli", "/bin/nmcli", "/usr/sbin/nmcli", "/sbin/nmcli"),
    "airmon-ng": (
        "/usr/sbin/airmon-ng",
        "/sbin/airmon-ng",
        "/usr/bin/airmon-ng",
        "/bin/airmon-ng",
    ),
}


def command_path(name):
    """Return a command path even when systemd PATH omits sbin directories."""
    path = shutil.which(name)
    if path:
        return path
    for candidate in COMMAND_CANDIDATES.get(name, ()):
        if os.path.exists(candidate):
            return candidate
    return ""


class WiFiMonitorCollector(WiFiCollector):
    """On-demand monitor-mode Wi-Fi collector with channel hopping.

    The normal Wi-Fi collector stays lightweight and uses managed AP scans.
    This collector assumes the user has already put a separate adapter into
    monitor mode, then samples supported 2.4/5 GHz channels for raw management
    frames such as probes, beacons, association attempts, and deauth/disassoc
    traffic.
    """

    config_key = "wifi_monitor"
    name = "Wi-Fi Monitor"
    tab_label = "Wi-Fi Monitor"
    required_hardware = "Wi-Fi adapter already in monitor mode"

    @classmethod
    def hardware_status(cls, config):
        """Return monitor-mode interface and packet-capture dependency status."""
        wireless = wireless_interfaces()
        monitors = monitor_mode_interfaces()
        interface = config.get("interface", "auto")
        configured = configured_candidates(
            config, "interfaces", extra_keys=("interface",)
        )
        if interface == "auto":
            configured = [
                item for item in configured if item and item != "auto"
            ] or sort_wifi_interfaces(monitors, config)
        return {
            "iw": bool(command_path("iw")),
            "airmon_ng": bool(command_path("airmon-ng")),
            "scapy": package_available("scapy"),
            "auto_start": config.get("auto_start", False),
            "interface": interface,
            "prepare_monitor_mode": bool(config.get("prepare_monitor_mode", False)),
            "wireless_interfaces": wireless,
            "monitor_interfaces": monitors,
            "interfaces": availability_records(
                configured,
                monitors,
                lambda name: name in monitors,
            ),
        }

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self._sniff_thread = None
        self._hopper_task = None
        self._current_channel = None
        self._channel_plan = []
        self._supported_channels = {}
        self._monitor_setup_warning = ""
        self._prepared_monitor_source = None
        self._created_monitor_interface = None

    def detect(self):
        """Report availability without starting sniffing or channel hopping."""
        self.log_monitor_setup_context("detect")
        wireless = wireless_interfaces()
        if len(wireless) < 2:
            self.active_hardware = None
            self.state = STATE_OFFLINE
            self.warning = (
                "Only one Wi-Fi interface found ({}). Monitor-mode capture "
                "needs a second adapter to keep network connectivity."
            ).format(", ".join(wireless))
            return False
        if not command_path("iw"):
            self.active_hardware = None
            self.state = STATE_OFFLINE
            self.warning = "iw was not found in PATH."
            return False
        self.prepare_configured_monitor_interface()
        iface = self.select_monitor_interface()
        if not iface:
            self.active_hardware = None
            self.state = STATE_OFFLINE
            setup = self._monitor_setup_warning
            self.warning = (
                "No monitor-mode Wi-Fi interface found. Configure a dedicated "
                "interface and enable prepare_monitor_mode, or put the adapter "
                "into monitor mode before clicking Start."
            )
            if setup:
                self.warning = "{} Monitor setup: {}".format(self.warning, setup)
            return False
        self.active_hardware = iface
        self.state = STATE_STOPPED
        self.warning = None
        return True

    async def start(self):
        """Start monitor-mode sniffing only after the user clicks Start."""
        self._running = True
        self.log_monitor_setup_context("start")
        wireless = wireless_interfaces()
        if len(wireless) < 2:
            self.state = STATE_OFFLINE
            self.warning = (
                "Only one Wi-Fi interface found ({}). Monitor-mode capture "
                "needs a second adapter to keep network connectivity."
            ).format(", ".join(wireless))
            msg = self.warning
            logging.warning("Wi-Fi Monitor startup failed: %s", msg)
            await self.emit("collector_offline", {"reason": msg}, "warning")
            self._running = False
            return
        self.prepare_configured_monitor_interface()
        iface = self.select_monitor_interface()
        if not iface:
            self.state = STATE_OFFLINE
            setup = self._monitor_setup_warning
            self.warning = (
                "No monitor-mode Wi-Fi interface found. Configure a dedicated "
                "interface and enable prepare_monitor_mode, or put the adapter "
                "into monitor mode before clicking Start."
            )
            if setup:
                self.warning = "{} Monitor setup: {}".format(self.warning, setup)
            logging.warning("Wi-Fi Monitor startup failed: %s", self.warning)
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
        self.state = STATE_ONLINE
        self.warning = None
        self.ensure_interface_up(iface)
        self._supported_channels = self.supported_channels_by_band()
        self._channel_plan = self.build_channel_plan()
        if not self._channel_plan:
            self.state = STATE_OFFLINE
            if self.channel_mode() == "fixed":
                self.warning = (
                    "Fixed Wi-Fi Monitor channel {} is not configured, not in "
                    "an enabled band, or not supported by {}."
                ).format(
                    self.config.get("fixed_channel"),
                    iface,
                )
            else:
                self.warning = (
                    "No supported 2.4 GHz or 5 GHz channels were discovered " "for {}."
                ).format(
                    iface,
                )
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            self._running = False
            return

        loop = asyncio.get_event_loop()
        await self.emit(
            "monitor_started",
            {
                "interface": iface,
                "channels": self._channel_plan,
                "supported_bands": sorted(self._supported_channels.keys()),
                "dwell_sec": self.dwell_seconds(),
                "channel_mode": self.channel_mode(),
                "fixed_channel": self.fixed_channel(),
                "seen_channels_first": bool(
                    self.config.get("seen_channels_first", False)
                ),
                "common_channel_fallback": bool(
                    self.config.get("common_channel_fallback", True)
                ),
            },
        )

        def packet_handler(packet):
            """Convert raw 802.11 management frames into Skannr events.

            Only management frames (type 0) are processed.  Control (type 1)
            and Data (type 2) frames are dropped by the kernel BPF filter
            before reaching this handler.

            Processed subtypes:
              0, 2  Association / Reassociation → association_seen
              4     Probe Request → probe_request
              10    Disassociation → disassoc_seen
              12    Deauthentication → deauth_seen

            Subtype 8 (Beacon) is intentionally skipped.  Managed Wi-Fi Scan
            (wifi.py) already captures every AP beacon across all supported
            channels via ``iw scan`` on each scan cycle.  Monitor mode only
            sees beacons on the hopper's current channel, so including them
            would produce incomplete, channel-biased duplicates of the same
            AP data in Subject History — an AP visible on channel 6 but not
            channel 36 would appear and disappear depending on hopper
            position, not on actual AP presence.  The dev Pi 4 has a separate
            managed-scan adapter that covers all channels without the monitor
            hopper's single-channel-at-a-time limitation.
            """
            if not self._running:
                return
            dot11 = packet.getlayer(Dot11)
            if dot11 is None or dot11.type != 0:
                return

            # Deferred past the type gate — only management frames reach here.
            timestamp_epoch = now_epoch()
            timestamp = local_now(timestamp_epoch)
            rssi = getattr(packet, "dBm_AntSignal", None)
            channel = self.packet_channel(packet, Dot11Elt) or self._current_channel

            if dot11.subtype == 4:
                # Probe request: a client is asking for a network name. These
                # are the rows that make Wi-Fi clients visible in history.
                payload = {
                    "client_mac": dot11.addr2,
                    **vendor_info(dot11.addr2),
                    "ssid_probed": self.get_ssid(packet, Dot11Elt),
                    "rssi": rssi,
                    "channel": channel,
                    "timestamp": timestamp,
                    "timestamp_epoch": timestamp_epoch,
                    "monitor_interface": iface,
                }
                asyncio.run_coroutine_threadsafe(
                    self.emit("probe_request", payload), loop
                )
            # Subtype 8 (Beacon) is intentionally skipped —
            # see docstring above for rationale.
            elif dot11.subtype in (0, 2):
                # Association/reassociation requests show client/AP activity but
                # usually do not include a stable SSID.
                payload = self.client_ap_payload(
                    dot11, rssi, channel, timestamp, timestamp_epoch, iface
                )
                asyncio.run_coroutine_threadsafe(
                    self.emit("association_seen", payload), loop
                )
            elif dot11.subtype == 10:
                payload = self.client_ap_payload(
                    dot11, rssi, channel, timestamp, timestamp_epoch, iface
                )
                asyncio.run_coroutine_threadsafe(
                    self.emit("disassoc_seen", payload), loop
                )
            elif dot11.subtype == 12:
                payload = self.client_ap_payload(
                    dot11, rssi, channel, timestamp, timestamp_epoch, iface
                )
                asyncio.run_coroutine_threadsafe(
                    self.emit("deauth_seen", payload), loop
                )

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
                    sniff(
                        iface=iface,
                        prn=packet_handler,
                        store=False,
                        stop_filter=lambda _pkt: not self._running,
                        timeout=1,
                        filter="type mgt",
                    )
                except Exception as exc:
                    asyncio.run_coroutine_threadsafe(report_sniff_error(exc), loop)
                    time.sleep(float(self.config.get("retry_interval_sec", 5)))

        self._hopper_task = loop.create_task(self.channel_hopper(iface))
        self._sniff_thread = threading.Thread(target=sniff_loop, daemon=True)
        self._sniff_thread.start()
        monitor_check_counter = 0
        while self._running:
            monitor_check_counter += 1
            # Periodically verify the interface is still in monitor mode.
            # The managed WiFiCollector's iw scan (which runs before our
            # monitor-mode conversion) can reset the interface, and some
            # drivers (e.g. rtl88xxau) reset on every scan call.
            if (
                monitor_check_counter % 5 == 0
                and self.active_hardware
                and self.active_hardware not in self.monitor_interfaces()
            ):
                source_iface = self._prepared_monitor_source or self.active_hardware
                logging.warning(
                    "Wi-Fi Monitor interface %s was reset to managed mode, "
                    "re-asserting monitor mode",
                    self.active_hardware,
                )
                ok, detail = self.set_interface_monitor_mode(source_iface)
                if not ok:
                    logging.warning("Wi-Fi Monitor re-conversion failed: %s", detail)
                else:
                    self.active_hardware = detail
            await asyncio.sleep(1)

    async def stop(self):
        """Stop sniffing and channel hopping; delete temporary monitor iface."""
        await BaseCollector.stop(self)
        if self._hopper_task and not self._hopper_task.done():
            self._hopper_task.cancel()
            await asyncio.gather(self._hopper_task, return_exceptions=True)
        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=3)
        if self._created_monitor_interface:
            self.delete_monitor_interface(self._created_monitor_interface)
            self._created_monitor_interface = None
        self._prepared_monitor_source = None

    async def channel_hopper(self, iface):
        """Retune the monitor interface across the current channel plan."""
        dwell = self.dwell_seconds()
        if self.channel_mode() == "fixed":
            channel = self._channel_plan[0]
            if self.set_channel(iface, channel):
                self._current_channel = channel
                await self.emit(
                    "monitor_channel_changed",
                    {
                        "interface": iface,
                        "channel": channel,
                        "band": self.channel_band(channel),
                        "mode": "fixed",
                    },
                )
            while self._running:
                await asyncio.sleep(dwell)
            return

        while self._running:
            for channel in self._channel_plan:
                if not self._running:
                    return
                if self.set_channel(iface, channel):
                    self._current_channel = channel
                    await self.emit(
                        "monitor_channel_changed",
                        {
                            "interface": iface,
                            "channel": channel,
                            "band": self.channel_band(channel),
                            "mode": "hop",
                        },
                    )
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
                [
                    command_path("iw") or "iw",
                    "dev",
                    iface,
                    "set",
                    "channel",
                    str(channel),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                return True
            self.warning = "Could not set {} to channel {}: {}".format(
                iface, channel, result.stdout.strip()
            )
        except Exception as exc:
            self.warning = "Could not set {} to channel {}: {}".format(
                iface, channel, exc
            )
        return False

    def select_monitor_interface(self):
        """Return the best configured or discovered monitor-mode interface.

        Priority order:
        1. ``self.active_hardware`` — set by
           ``prepare_configured_monitor_interface()`` after a successful
           conversion, so we don't need to re-check ``iw dev`` (which can lag
           behind the kernel interface type change by a few hundred ms).
        2. Explicitly configured candidates found in monitor mode.
        3. Any discovered monitor-mode interface, sorted by capability.

        When ``mac`` is configured, all paths are constrained to the
        matching adapter.
        """
        if self.active_hardware:
            return self.active_hardware
        configured = self.configured_monitor_candidates()
        discovered = self.monitor_interfaces()
        for iface in configured:
            if iface in discovered:
                return iface
        ranked = sort_wifi_interfaces(discovered, self.config)
        for iface in ranked:
            if self._mac_allows_interface(iface):
                return iface
        return None

    def prepare_configured_monitor_interface(self):
        """Optionally prepare a safe monitor interface without host-policy edits."""
        if not bool(self.config.get("prepare_monitor_mode", False)):
            logging.info("Wi-Fi Monitor monitor-mode setup disabled")
            return
        self._monitor_setup_warning = ""
        self._prepared_monitor_source = None
        candidates = self.monitor_setup_candidates()
        logging.info("Wi-Fi Monitor monitor-mode setup candidates=%s", candidates)
        if not candidates:
            self._monitor_setup_warning = (
                "prepare_monitor_mode is true, but no safe monitor-capable "
                "non-uplink adapter was found"
            )
            logging.warning(
                "Wi-Fi Monitor setup skipped: %s", self._monitor_setup_warning
            )
            self.warning = self._monitor_setup_warning
            return
        for iface in candidates:
            ok, detail = self.set_interface_monitor_mode(iface)
            if ok:
                self.active_hardware = detail
                self._prepared_monitor_source = iface
                self.warning = None
                self._monitor_setup_warning = ""
                return
            self._monitor_setup_warning = detail
            self.warning = detail

    def log_monitor_setup_context(self, phase):
        """Log enough config/discovery context to debug monitor setup failures."""
        logging.info(
            "Wi-Fi Monitor %s config prepare_monitor_mode=%s interface=%s "
            "interfaces=%s iw=%s ip=%s nmcli=%s default_route=%s monitors=%s "
            "wireless=%s",
            phase,
            bool(self.config.get("prepare_monitor_mode", False)),
            self.config.get("interface", "auto"),
            self.config.get("interfaces") or [],
            command_path("iw") or "missing",
            command_path("ip") or "missing",
            command_path("nmcli") or "missing",
            default_route_interface() or "none",
            self.monitor_interfaces(),
            wireless_interfaces(),
        )

    def _mac_allows_interface(self, iface, mac=None):
        """Return True when *iface* matches the optional ``mac`` config key.

        When ``mac`` is unset (the default) every interface is allowed.
        When set, only the adapter whose MAC matches the configured value
        is eligible for monitor-mode setup — interface-name swaps across
        reboots are harmless.

        If *mac* is provided it is used directly, avoiding a sysfs read.
        """
        raw = self.config.get("mac")
        if not raw:
            return True
        configured_mac = str(raw).strip().lower()
        if mac is None:
            mac = sysfs_read(os.path.join("/sys/class/net", iface, "address")).lower()
        return mac == configured_mac

    def configured_monitor_candidates(self):
        """Return explicit interfaces eligible for Skannr monitor-mode setup."""
        candidates = configured_candidates(
            self.config, "interfaces", extra_keys=("interface",)
        )
        return [
            iface
            for iface in candidates
            if iface
            and iface != "auto"
            and self.interface_allowed(iface)
            and self._mac_allows_interface(iface)
        ]

    def auto_monitor_candidates(self):
        """Return safe auto-selected monitor-source candidates.

        Auto mode is limited to USB/external adapters that are monitor-capable
        and are not the current default-route interface. This keeps wlan0/wlan1
        naming swaps irrelevant while avoiding guesses against the live uplink.

        When ``mac`` is configured, only the matching adapter is considered.
        """
        route_iface = default_route_interface()
        candidates = []
        for iface in wireless_interfaces():
            if iface == route_iface or not self.interface_allowed(iface):
                continue
            details = wireless_interface_details(iface)
            if not self._mac_allows_interface(iface, details.get("mac", "")):
                continue
            if not details.get("usb"):
                continue
            if not self.interface_supports_monitor_mode(iface):
                continue
            candidates.append(iface)
        return sort_wifi_interfaces(candidates, self.config)

    def monitor_setup_candidates(self):
        """Return explicit or safe auto-selected source interfaces."""
        configured = self.configured_monitor_candidates()
        if configured:
            return configured
        if (self.config.get("interface") or "auto").strip().lower() != "auto":
            return []
        return self.auto_monitor_candidates()

    def interface_supports_monitor_mode(self, iface):
        """Return True when the adapter behind *iface* advertises monitor mode."""
        return interface_supports_monitor_mode(iface)

    def monitor_interface_on_same_phy(self, iface):
        """Return an existing monitor interface on the same phy, if any."""
        source_phy = self.phy_for_interface(iface)
        if not source_phy:
            return None
        for monitor_iface in self.monitor_interfaces():
            if self.phy_for_interface(monitor_iface) == source_phy:
                return monitor_iface
        return None

    def build_monitor_interface_name(self, phy):
        """Return a deterministic monitor interface name for one phy."""
        suffix = str(phy or "phy0").replace("phy", "")
        return "mon{}".format(suffix or "0")

    def delete_monitor_interface(self, iface):
        """Delete one temporary monitor interface, ignoring cleanup errors."""
        if not iface:
            return
        self.run_setup_command(["iw", "dev", iface, "del"])

    def create_monitor_interface(self, iface):
        """Create a separate monitor interface on the same phy as *iface*."""
        phy = self.phy_for_interface(iface)
        if not phy:
            return False, "could not resolve phy for {}".format(iface)
        existing = self.monitor_interface_on_same_phy(iface)
        if existing:
            return True, existing
        monitor_iface = self.build_monitor_interface_name(phy)
        if os.path.exists(os.path.join("/sys/class/net", monitor_iface)):
            if self.phy_for_interface(monitor_iface) == phy:
                if monitor_iface in self.monitor_interfaces():
                    return True, monitor_iface
                return False, (
                    "{} already exists on {} but is not in monitor mode"
                ).format(monitor_iface, phy)
            return False, (
                "{} already exists on another device; cannot create monitor iface"
            ).format(monitor_iface)
        steps = [
            [
                "iw",
                "phy",
                phy,
                "interface",
                "add",
                monitor_iface,
                "type",
                "monitor",
            ],
            ["ip", "link", "set", monitor_iface, "up"],
        ]
        for command in steps:
            ok, output = self.run_setup_command(command)
            if not ok:
                self.delete_monitor_interface(monitor_iface)
                return False, "{} failed: {}".format(" ".join(command), output)
        if monitor_iface not in self.monitor_interfaces():
            self.delete_monitor_interface(monitor_iface)
            return False, "{} was created but is not in monitor mode".format(
                monitor_iface
            )
        self._created_monitor_interface = monitor_iface
        return True, monitor_iface

    def set_interface_monitor_mode(self, iface):
        """Prepare or discover a monitor interface without touching the uplink."""
        if not os.path.exists(os.path.join("/sys/class/net", iface)):
            return False, "{} does not exist".format(iface)
        if iface in self.monitor_interfaces():
            return True, iface
        existing = self.monitor_interface_on_same_phy(iface)
        if existing:
            return True, existing
        if iface == default_route_interface():
            return False, (
                "refusing to touch {} because it currently carries the default "
                "IPv4 route"
            ).format(iface)
        if not self.interface_supports_monitor_mode(iface):
            return False, "{} does not advertise monitor-mode support".format(iface)
        ok, detail = self.create_monitor_interface(iface)
        if ok:
            return True, detail
        if not bool(self.config.get("allow_in_place_monitor_mode", False)):
            return False, (
                "{}; Skannr left {} unchanged because in-place monitor-mode "
                "conversion is disabled"
            ).format(detail, iface)
        steps = [
            ["ip", "link", "set", iface, "down"],
            ["iw", "dev", iface, "set", "type", "monitor"],
            ["ip", "link", "set", iface, "up"],
        ]
        for command in steps:
            success, output = self.run_setup_command(command)
            if not success:
                return False, "{} failed: {}".format(" ".join(command), output)
        if iface in self.monitor_interfaces():
            return True, iface
        return False, "{} is still not reported as monitor mode".format(iface)

    def run_setup_command(self, command):
        """Run one monitor setup command and return success plus compact output."""
        original = list(command)
        executable = command_path(command[0])
        if not executable:
            logging.warning(
                "Wi-Fi Monitor setup command unavailable: %s",
                " ".join(original),
            )
            return False, "{} not found".format(command[0])
        command = [executable] + list(command[1:])
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                universal_newlines=True,
                timeout=float(self.config.get("monitor_setup_timeout_sec", 10)),
            )
        except Exception as exc:
            logging.warning(
                "Wi-Fi Monitor setup command failed command=%s error=%s",
                " ".join(command),
                exc,
            )
            return False, str(exc)
        output = " ".join((result.stdout or "").split())[:300]
        if result.returncode == 0:
            logging.info(
                "Wi-Fi Monitor setup command passed command=%s output=%s",
                " ".join(command),
                output,
            )
        else:
            logging.warning(
                "Wi-Fi Monitor setup command failed command=%s exit=%s output=%s",
                " ".join(command),
                result.returncode,
                output,
            )
        return result.returncode == 0, output or "exit {}".format(result.returncode)

    def monitor_interfaces(self):
        """Parse 'iw dev' and return interfaces whose type is monitor."""
        try:
            output = subprocess.check_output(
                [command_path("iw") or "iw", "dev"],
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
            # match = re.search(r"(\d+)\s+MHz\s+\[(\d+)\]", line)
            match = re.search(r"(\d+)(?:\.\d+)?\s+MHz\s+\[(\d+)\]", line)
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
                return subprocess.check_output(
                    [command_path("iw") or "iw", "phy", phy, "info"],
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    timeout=10,
                )
            except Exception:
                pass
        try:
            return subprocess.check_output(
                [command_path("iw") or "iw", "list"],
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=10,
            )
        except Exception:
            return ""

    def phy_for_interface(self, iface):
        """Map an interface from 'iw dev' to its phy name such as phy0."""
        return phy_for_interface(iface)

    def build_channel_plan(self):
        """Build a low-overhead channel plan from configured controls.

        Reading old logs during Start made the on-demand monitor collector do
        more work than expected. By default Skannr starts with common channels
        supported by the adapter. Operators can choose a fixed channel, put
        previously seen AP channels first, or disable common-channel fallback.
        """
        if self.channel_mode() == "fixed":
            return self.fixed_channel_plan()

        plan = []
        enabled_bands = self.enabled_bands()
        typical = {
            "2.4": self.config.get("typical_channels_24", [1, 6, 11]),
            "5": self.config.get(
                "typical_channels_5", [36, 40, 44, 48, 149, 153, 157, 161, 165]
            ),
        }
        seen = (
            self.seen_channels_by_band()
            if self.config.get("include_seen_channels", False)
            else {}
        )
        seen_first = bool(self.config.get("seen_channels_first", False))
        fallback = bool(self.config.get("common_channel_fallback", True))
        for band in enabled_bands:
            supported = set(self._supported_channels.get(band) or [])
            if not supported:
                continue
            seen_channels = self.supported_channel_list(seen.get(band) or [], supported)
            typical_channels = self.supported_channel_list(
                typical.get(band) or [], supported
            )
            if seen_first:
                for channel in seen_channels:
                    self.append_channel(plan, channel)
                if fallback or not seen_channels:
                    for channel in typical_channels:
                        self.append_channel(plan, channel)
            else:
                if fallback or not seen_channels:
                    for channel in typical_channels:
                        self.append_channel(plan, channel)
                for channel in seen_channels:
                    self.append_channel(plan, channel)
        return plan

    def channel_mode(self):
        """Return normalized channel behavior: hop or fixed."""
        mode = str(self.config.get("channel_mode") or "hop").lower().strip()
        if mode in ("fixed", "single", "channel"):
            return "fixed"
        return "hop"

    def fixed_channel(self):
        """Return configured fixed channel as int, or None."""
        value = self.config.get("fixed_channel")
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def fixed_channel_plan(self):
        """Return a validated one-channel plan for fixed-channel mode."""
        channel = self.fixed_channel()
        if channel is None:
            return []
        band = self.channel_band(channel)
        if band not in self.enabled_bands():
            return []
        if channel not in set(self._supported_channels.get(band) or []):
            return []
        return [channel]

    def supported_channel_list(self, channels, supported):
        """Return configured/seen channels filtered by adapter support."""
        output = []
        for channel in channels or []:
            try:
                channel = int(channel)
            except (TypeError, ValueError):
                continue
            if channel in supported and channel not in output:
                output.append(channel)
        return output

    @staticmethod
    def append_channel(plan, channel):
        """Append a channel once while preserving order."""
        if channel not in plan:
            plan.append(channel)

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
        filesystem = (global_config.get("persistence") or {}).get("filesystem") or {}
        log_dir = filesystem.get("log_dir", "runtime/logs")
        return log_dir if os.path.isabs(log_dir) else os.path.abspath(log_dir)

    def packet_channel(self, packet, dot11_elt):
        """Extract a packet channel, falling back to the hopper state."""
        channel = self.get_channel(packet, dot11_elt)
        if channel:
            return channel
        return self._current_channel

    def client_ap_payload(
        self, dot11, rssi, channel, timestamp, timestamp_epoch, iface
    ):
        """Build common client/AP event payload for management frames."""
        receiver = dot11.addr1
        transmitter = dot11.addr2
        bssid = dot11.addr3
        return {
            # Keep the older client/ap names for existing history/report code,
            # but expose the real 802.11 address roles so deauth/disassoc
            # analysis does not overstate which side initiated the frame.
            "client_mac": transmitter,
            "ap_mac": receiver or bssid,
            "transmitter_mac": transmitter,
            "receiver_mac": receiver,
            "bssid": bssid,
            "receiver_is_broadcast": self.is_broadcast_mac(receiver),
            "rssi": rssi,
            "channel": channel,
            "timestamp": timestamp,
            "timestamp_epoch": timestamp_epoch,
            "monitor_interface": iface,
        }

    @staticmethod
    def is_broadcast_mac(mac):
        """Return True when a frame is addressed to the broadcast MAC."""
        return str(mac or "").lower() == "ff:ff:ff:ff:ff:ff"

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
