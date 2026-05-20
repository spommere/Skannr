"""Classic Bluetooth inquiry collector.

Classic inquiry is separate from BLE advertisement scanning. It can discover
different devices and names, but it is slower and often only useful when remote
devices are discoverable or actively using Bluetooth.
"""

import asyncio
import os
import re
import shutil
import subprocess

from collectors.base import (
    BaseCollector,
    STATE_OFFLINE,
    STATE_RETRYING,
    STATE_RUNNING_TIER1,
    STATE_RUNNING_TIER2,
)
from oui_lookup import vendor_name, vendor_prefix


class BluetoothClassicCollector(BaseCollector):
    """Classic Bluetooth inquiry scanner.

    BLE advertisements and classic Bluetooth inquiry are different radio paths.
    Phones, tablets, laptops, and watches that stay quiet in BLE scans can still
    appear in classic inquiry results, especially when their Bluetooth settings
    or pairing UI is open. This collector keeps that capture mode separate from
    BLE while the browser presents both under one Bluetooth tab.
    """

    config_key = "bt_classic"
    name = "Bluetooth Classic Scan"
    tab_label = "BT Classic"
    required_hardware = "Bluetooth adapter with classic inquiry support"
    MAC_RE = re.compile(
        r"^\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(.+?)\s*$"
    )

    def detect(self):
        """Pick the configured adapter tier and verify a scanner executable."""
        if not shutil.which("hcitool") and not shutil.which("bluetoothctl"):
            self.active_hardware = None
            self.state = STATE_OFFLINE
            self.warning = "Neither hcitool nor bluetoothctl was found in PATH."
            return False

        preferred = self.config.get("preferred_adapter", "hci1")
        fallback = self.config.get("fallback_adapter", "hci0")
        primary_default = "test -d /sys/class/bluetooth/{} || hciconfig {} >/dev/null 2>&1".format(
            preferred, preferred
        )
        fallback_default = "test -d /sys/class/bluetooth/{} || hciconfig {} >/dev/null 2>&1 || bluetoothctl list | grep -q 'Controller '".format(
            fallback, fallback
        )
        primary_ok, primary_detail = self.validate_tier(
            "primary", primary_default
        )
        if primary_ok:
            self.active_hardware = preferred
            self.state = STATE_RUNNING_TIER1
            self.warning = None
            return True

        fallback_ok, fallback_detail = self.validate_tier(
            "fallback", fallback_default
        )
        if fallback_ok:
            self.active_hardware = fallback
            self.state = STATE_RUNNING_TIER2
            self.warning = "Using fallback Bluetooth adapter {}; primary validation failed: {}".format(
                fallback, primary_detail
            )
            return True

        self.active_hardware = None
        self.state = STATE_OFFLINE
        self.warning = "No usable Bluetooth adapter. Primary validation: {}; fallback validation: {}".format(
            primary_detail, fallback_detail
        )
        return False

    async def start(self):
        """Run repeated classic Bluetooth inquiries until stopped."""
        self._running = True
        if not self.detect():
            await self.emit(
                "collector_offline", {"reason": self.warning}, "warning"
            )
            return

        await self.emit(
            "scanner_started",
            {
                "adapter": self.active_hardware,
                "tier": self.state,
                "mode": "classic",
            },
        )
        if self.state == STATE_RUNNING_TIER2:
            await self.emit(
                "hardware_fallback",
                {"adapter": self.active_hardware, "warning": self.warning},
                "warning",
            )

        seen = {}
        interval = float(self.config.get("scan_interval_sec", 30))
        timeout = float(self.config.get("device_timeout_sec", 180))
        while self._running:
            started = asyncio.get_event_loop().time()
            try:
                await self.emit(
                    "classic_scan_started", {"adapter": self.active_hardware}
                )
                devices = await self.run_inquiry()
            except Exception as exc:
                self.state = STATE_RETRYING
                self.warning = (
                    "Classic Bluetooth scan failed; retrying: {}".format(exc)
                )
                await self.emit(
                    "collector_retrying", {"reason": self.warning}, "warning"
                )
                await self.retry_sleep()
                continue

            now = asyncio.get_event_loop().time()
            await self.emit(
                "classic_scan_completed",
                {
                    "adapter": self.active_hardware,
                    "devices": len(devices),
                    "duration_sec": round(now - started, 1),
                },
            )
            for device in devices:
                mac = device.get("mac") or "unknown"
                previous = seen.get(mac)
                # Emit updated events too; names/class fields can appear only
                # after a later inquiry depending on the remote device.
                seen[mac] = {"last_seen": now, "name": device.get("name")}
                event_type = (
                    "classic_device_seen"
                    if previous is None
                    else "classic_device_updated"
                )
                await self.emit(event_type, device)

            lost = [
                mac
                for mac, item in seen.items()
                if now - item["last_seen"] > timeout
            ]
            for mac in lost:
                await self.emit(
                    "classic_device_lost", {"mac": mac, "transport": "classic"}
                )
                del seen[mac]

            elapsed = asyncio.get_event_loop().time() - started
            await asyncio.sleep(max(0.1, interval - elapsed))

    async def run_inquiry(self):
        """Run the best available classic Bluetooth inquiry command off-loop."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.scan_once)

    def scan_once(self):
        """Return parsed devices from one hcitool/bluetoothctl inquiry."""
        self.prepare_adapter()
        if shutil.which("hcitool"):
            command = ["hcitool"]
            if self.active_hardware:
                command.extend(["-i", self.active_hardware])
            command.extend(["scan", "--info"])
            return self.parse_hcitool_scan(
                self.command_output(
                    command,
                    timeout=float(self.config.get("scan_timeout_sec", 20)),
                )
            )
        return self.parse_bluetoothctl_devices(
            self.command_output(["bluetoothctl", "devices"], timeout=10)
        )

    def command_output(self, command, timeout=10):
        """Run a scanner command and return decoded combined output.

        Bluetooth names are controlled by remote devices and may contain bytes
        that are not valid UTF-8. Decode with replacement so one odd device
        name does not make the whole classic scan fail.
        """
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout,
        )
        output = self.decode_output(result.stdout)
        if result.returncode != 0:
            raise RuntimeError(
                output.strip()
                or "{} exited {}".format(" ".join(command), result.returncode)
            )
        return output

    def decode_output(self, data):
        """Decode scanner bytes while preserving readable diagnostic text."""
        if data is None:
            return ""
        if isinstance(data, str):
            return data
        return data.decode("utf-8", "replace")

    def parse_hcitool_scan(self, output):
        """Parse hcitool scan --info output into normalized device rows."""
        devices = []
        current = None
        for line in (output or "").splitlines():
            match = self.MAC_RE.match(line)
            if match:
                current = self.device_record(match.group(1), match.group(2))
                devices.append(current)
                continue
            if current is None:
                continue
            text = line.strip()
            if text.lower().startswith("clock offset:"):
                current["clock_offset"] = text.split(":", 1)[1].strip()
            elif text.lower().startswith("class:"):
                current["class"] = text.split(":", 1)[1].strip()
        return devices

    def parse_bluetoothctl_devices(self, output):
        """Parse bluetoothctl devices as a fallback when hcitool is absent."""
        devices = []
        for line in (output or "").splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) >= 3 and parts[0] == "Device":
                devices.append(self.device_record(parts[1], parts[2]))
        return devices

    def device_record(self, mac, name):
        """Build the common event payload for one classic Bluetooth device."""
        prefix = vendor_prefix(mac)
        return {
            "mac": mac.upper(),
            "name": self.clean_display_name(name),
            "transport": "classic",
            "vendor_prefix": prefix or "",
            "vendor_name": vendor_name(mac) or "",
            "class": "",
            "clock_offset": "",
        }

    def clean_display_name(self, name):
        """Reject command diagnostics so failures do not become device names."""
        text = str(name or "").strip()
        lowered = text.lower()
        bad_fragments = (
            "command '['",
            "timed out after",
            "operation already in progress",
            "failed to connect",
            "input/output error",
        )
        return (
            ""
            if any(fragment in lowered for fragment in bad_fragments)
            else text
        )

    def prepare_adapter(self):
        """Best-effort wake-up before inquiry."""
        adapter = self.active_hardware or self.config.get(
            "fallback_adapter", "hci0"
        )
        self.command_succeeds(["rfkill", "unblock", "bluetooth"])
        self.command_succeeds(["hciconfig", adapter, "up"])
        self.command_succeeds(["bluetoothctl", "power", "on"])

    def command_succeeds(self, command):
        """Return False rather than failing startup for optional setup tools."""
        try:
            subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=5,
            )
            return True
        except Exception:
            return False
