"""Passive Bluetooth Low Energy advertisement scanner.

The collector uses Bleak/BlueZ, merges advertisement and scan-response data, and
publishes device presence updates without making active GATT connections.
"""

import asyncio
import inspect
import os
import re
import shutil
import subprocess

import yaml

from ..identity_policy import bluetooth_property_like_name
from ..log_utils import now_epoch
from ..paths import CONFIG_COLLECTORS_DIR, DATA_COLLECTORS_DIR
from .base import (
    BaseCollector,
    STATE_OFFLINE,
    STATE_ONLINE,
    STATE_RETRYING,
)
from .hardware import (
    availability_records,
    bluetooth_adapter_exists,
    bluetooth_adapter_mac,
    bluetooth_adapters,
    configured_candidates,
    package_available,
    sort_bluetooth_adapters,
)

_ADAPTER_OPERATION_LOCKS = {}


class _SeenDevice:
    """Small compatibility object for merged Bleak callback results."""

    def __init__(self, address, name="", rssi=None):
        self.address = address
        self.name = name
        self.rssi = rssi


class _SeenAdvertisement:
    """Small compatibility object for the advertisement fields Skannr uses."""

    def __init__(self):
        self.local_name = ""
        self.rssi = None
        self.manufacturer_data = {}
        self.service_uuids = []


def adapter_operation_lock(adapter):
    """Return the shared asyncio lock for one Bluetooth adapter.

    BlueZ often rejects concurrent discovery/connect requests with
    "Operation already in progress". BLE Scan and BLE Identify are separate
    collectors, so they need one module-level lock to serialize radio use.
    """
    key = adapter or "default"
    lock = _ADAPTER_OPERATION_LOCKS.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _ADAPTER_OPERATION_LOCKS[key] = lock
    return lock


class BLECollector(BaseCollector):
    """Bluetooth Low Energy scanner based on bleak.

    If several adapters exist, Skannr uses the ordered ``adapters`` list from
    the collector YAML. Without an explicit list, it ranks discovered adapters
    and normally chooses external USB adapters before built-in radios.
    """

    config_key = "ble"
    name = "BLE Scan"
    tab_label = "BLE Scan"
    required_hardware = "USB Bluetooth 5.0 dongle or built-in Bluetooth adapter"
    _company_identifiers = None
    APPLE_COMPANY_ID = 0x004C
    APPLE_FINDMY_PAYLOAD_TYPE = 0x12
    MAC_NAME_RE = re.compile(
        r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$|^[0-9A-Fa-f]{12}$"
    )

    @classmethod
    def hardware_status(cls, config):
        """Return Bluetooth adapter availability and bleak dependency status."""
        discovered = bluetooth_adapters()
        configured = configured_candidates(
            config, "adapters"
        ) or sort_bluetooth_adapters(discovered, config)
        return {
            "adapters": availability_records(
                configured, discovered, bluetooth_adapter_exists
            ),
            "bleak": package_available("bleak"),
            "auto_start": config.get("auto_start", True),
        }

    def adapter_exists(self, adapter):
        """Probe for an adapter without assuming one Linux tool is present."""
        if os.path.exists(os.path.join("/sys/class/bluetooth", adapter)):
            return True
        if self.command_succeeds(["hciconfig", adapter]):
            return True
        if adapter == "hci0" and self.bluetoothctl_has_controller():
            return True
        return False

    def command_succeeds(self, command):
        """Run a setup/probe command and collapse all failures to False."""
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

    def command_output(self, command):
        """Return diagnostic command output for warnings shown in the UI."""
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=5,
            )
            return self.decode_output(result.stdout).strip()
        except Exception as exc:
            return str(exc)

    def decode_output(self, data):
        """Decode command output without failing on odd Bluetooth names."""
        if data is None:
            return ""
        if isinstance(data, str):
            return data
        return data.decode("utf-8", "replace")

    def strip_ansi(self, text):
        """Remove ANSI escape sequences from bluetoothctl output."""
        return re.sub(r"\[[0-?]*[ -/]*[@-~]", "", str(text or ""))

    def bluetoothctl_has_controller(self):
        """Fallback detection for systems where hci0 exists only in BlueZ."""
        try:
            result = subprocess.run(
                ["bluetoothctl", "list"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
                universal_newlines=True,
            )
            return "Controller " in result.stdout
        except Exception:
            return False

    def detect(self):
        """Select the first available Bluetooth adapter candidate."""
        candidates = configured_candidates(
            self.config, "adapters"
        ) or sort_bluetooth_adapters(bluetooth_adapters(), self.config)
        for adapter in candidates:
            if not self._mac_allows_adapter(adapter):
                continue
            if self.adapter_exists(adapter):
                self.active_hardware = adapter
                self.state = STATE_ONLINE
                self.warning = None
                return True
        self.active_hardware = None
        self.state = STATE_OFFLINE
        self.warning = "No usable Bluetooth adapter found."
        return False

    def _mac_allows_adapter(self, adapter):
        """Return True when *adapter* matches the optional ``mac`` config key.

        When ``mac`` is unset (the default) every adapter is allowed.
        When set, only the adapter whose MAC matches the configured value
        is eligible — ``hciN`` name swaps across reboots are harmless.
        """
        raw = self.config.get("mac")
        if not raw:
            return True
        configured_mac = str(raw).strip().lower()
        return bluetooth_adapter_mac(adapter) == configured_mac

    async def start(self):
        """Continuously scan BLE advertisements and publish device events."""
        self._running = True
        if not self.detect():
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return

        try:
            from bleak import BleakScanner
        except ImportError:
            # Keep missing optional dependencies visible as collector state
            # instead of crashing the whole Flask process.
            self.state = STATE_OFFLINE
            self.warning = "Python package 'bleak' is not installed."
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return

        self._runtime_force_discover_scan = bool(
            self.config.get("force_discover_scan", False)
        )
        self._runtime_bluetoothctl_scan = bool(
            self.config.get("force_bluetoothctl_scan", False)
        )
        self._stale_rssi_threshold = int(
            self.config.get("cache_stale_rssi_threshold", 10)
        )
        self._stale_rssi: dict[str, list[int]] = {}
        self.prepare_adapter()
        await self.emit(
            "scanner_started",
            self.startup_payload(),
        )
        # seen tracks device state between scans so the UI can distinguish new,
        # updated, and lost devices instead of appending duplicate rows forever.
        seen = {}
        timeout = float(self.config.get("device_timeout_sec", 60))
        interval = float(self.config.get("scan_interval_sec", 15))
        consecutive_in_progress = 0
        empty_scan_windows = 0
        last_bluez_warmup = 0

        while self._running:
            now = asyncio.get_running_loop().time()
            try:
                # Some adapters come back from errors powered off or blocked.
                # Re-running setup is cheap and makes unplug/replug recovery
                # more likely during field use.
                async with adapter_operation_lock(self.active_hardware):
                    self.prepare_adapter()
                    devices = await self.discover_devices_with_timeout(
                        BleakScanner, interval, use_adapter=True
                    )
            except TypeError:
                # Older bleak versions did not accept newer discover keywords.
                async with adapter_operation_lock(self.active_hardware):
                    self.prepare_adapter()
                    devices = await self.discover_devices_with_timeout(
                        BleakScanner, interval, use_adapter=False
                    )
            except Exception as exc:
                if self.is_operation_in_progress(exc):
                    # BlueZ can report InProgress when another scan/connect is
                    # still winding down. Serialize and attempt light recovery
                    # before declaring the collector offline.
                    consecutive_in_progress += 1
                    async with adapter_operation_lock(self.active_hardware):
                        self.recover_in_progress(consecutive_in_progress)
                else:
                    consecutive_in_progress = 0
                self.state = STATE_RETRYING
                self.warning = self.scan_retry_warning(exc, consecutive_in_progress)
                await self.emit(
                    "collector_retrying",
                    self.retry_payload(self.warning),
                    "warning",
                )
                await self.retry_sleep()
                if not self.detect():
                    self.state = STATE_OFFLINE
                    await self.emit(
                        "collector_offline", {"reason": self.warning}, "warning"
                    )
                continue

            consecutive_in_progress = 0
            if devices:
                empty_scan_windows = 0
            else:
                empty_scan_windows += 1
                last_bluez_warmup, warmup = self.maybe_warm_bluez_discovery(
                    empty_scan_windows, last_bluez_warmup
                )
                if self.should_emit_empty_scan(empty_scan_windows, warmup):
                    await self.emit(
                        "scan_empty",
                        self.empty_scan_payload(empty_scan_windows, warmup),
                        "warning",
                    )
            current = asyncio.get_running_loop().time()
            for device, advertisement in devices:
                # bleak exposes slightly different attributes across versions;
                # getattr keeps the collector compatible with Python 3.6-era
                # packages and modern Pi Python 3.11 packages.
                mac = getattr(device, "address", None) or "unknown"
                rssi = self.device_rssi(device, advertisement)
                name = self.device_name(device, advertisement)
                # Suppress devices that appear to be BlueZ cache ghosts
                # (identical RSSI across many scan cycles — physically impossible
                # for a real BLE signal; the device stopped advertising long ago).
                if self._is_stale_cache(mac, rssi):
                    continue
                payload = {
                    "mac": mac,
                    "name": name,
                    "rssi": rssi,
                    "manufacturer": self.manufacturer_summary(advertisement),
                    "service_uuids": self.service_uuids(advertisement),
                    "adv_data_hex": self.manufacturer_data_hex(advertisement),
                }
                payload.update(self.findmy_accessory_fields(advertisement))
                previous = seen.get(mac)
                payload = self.merge_display_payload(previous, payload)
                seen[mac] = dict(payload, last_seen=current)
                if previous is None:
                    # first_seen is filled by Device History using the event
                    # timestamp; the payload field is left for compatibility.
                    payload["first_seen"] = None
                    await self.emit("device_seen", payload)
                elif self.display_payload_changed(previous, payload):
                    # Names and service/manufacturer data can arrive in later
                    # advertisements or scan responses. Send the full displayed
                    # payload so the UI can fill blanks after the first sighting.
                    await self.emit("device_updated", payload)

            # Expire stale devices locally; bleak discovery returns only the
            # devices seen in the current scan window.
            lost = [
                mac
                for mac, data in seen.items()
                if current - data["last_seen"] > timeout
            ]
            for mac in lost:
                await self.emit("device_lost", {"mac": mac})
                del seen[mac]

            if not devices:
                await asyncio.sleep(
                    max(
                        0.1,
                        interval - (asyncio.get_running_loop().time() - now),
                    )
                )

    async def discover_devices_with_timeout(self, scanner, interval, use_adapter=True):
        """Run one Bleak discovery window with a hard timeout."""
        configured = float(self.config.get("discover_timeout_sec", 0) or 0)
        timeout = configured if configured > 0 else max(interval + 10, 15)
        try:
            return await asyncio.wait_for(
                self.discover_devices(scanner, interval, use_adapter=use_adapter),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            method = self.scan_method_label()
            self.recover_discovery_timeout()
            if bool(self.config.get("bluetoothctl_fallback_after_timeout", True)):
                self._runtime_bluetoothctl_scan = True
                self._runtime_force_discover_scan = False
                raise RuntimeError(
                    "BLE {} discovery timed out after {:.1f}s; falling back to bluetoothctl".format(
                        method, timeout
                    )
                )
            if method == "callback":
                self._runtime_force_discover_scan = True
                raise RuntimeError(
                    "BLE {} discovery timed out after {:.1f}s; falling back to discover()".format(
                        method, timeout
                    )
                )
            raise RuntimeError(
                "BLE {} discovery timed out after {:.1f}s".format(method, timeout)
            )

    def scan_method_label(self):
        """Return the current scan path used by this collector."""
        if getattr(self, "_runtime_bluetoothctl_scan", False):
            return "bluetoothctl"
        return (
            "discover"
            if getattr(self, "_runtime_force_discover_scan", False)
            else "callback"
        )

    async def discover_devices(self, scanner, interval, use_adapter=True):
        """Return [(device, advertisement_data)] across old/new bleak APIs.

        Recent bleak versions expose RSSI and service data in AdvertisementData,
        not always on the BLEDevice object. Older versions only return a list of
        BLEDevice objects. Normalizing here keeps the main scan loop simple and
        prevents the UI from losing RSSI on Python 3.11/Pi installs.
        """
        method = self.scan_method_label()
        if method == "bluetoothctl":
            return await self.discover_with_bluetoothctl(interval)
        if method == "discover":
            return await self.discover_once(scanner, interval, use_adapter)
        if self.config.get("callback_scan", True):
            try:
                return await self.discover_with_callback(
                    scanner, interval, use_adapter=use_adapter
                )
            except TypeError:
                # Fall through to the discover() compatibility ladder for older
                # bleak builds whose scanner constructor does not match the
                # callback API.
                pass

        return await self.discover_once(scanner, interval, use_adapter)

    async def discover_once(self, scanner, interval, use_adapter=True):
        """Run one Bleak discover() call with configured BlueZ options."""
        kwargs = {"timeout": interval}
        if use_adapter:
            kwargs["adapter"] = self.active_hardware
        if self.config.get("active_scan", True):
            # Active scanning asks peripheral devices for scan-response data,
            # where many devices put their local name. Apps like nRF Connect
            # commonly do this, so Skannr should request it explicitly when
            # the installed bleak backend supports the option.
            kwargs["scanning_mode"] = "active"
        if self.config.get("bluez_duplicate_data", True):
            # Keep duplicate advertisement/scan-response updates flowing on
            # BlueZ so later packets can fill in fields missing from the first
            # sighting, such as Local Name.
            kwargs["bluez"] = {"DuplicateData": True}
        try:
            result = await scanner.discover(return_adv=True, **kwargs)
            return self.normalize_discovery_result(result)
        except TypeError:
            return await self.discover_compat(scanner, kwargs)

    async def discover_compat(self, scanner, kwargs):
        """Retry discovery while dropping options older bleak does not know.

        Keep return_adv=True on every retry that supports it. Without that,
        Bleak may return only BLEDevice objects and Skannr loses
        AdvertisementData.local_name, where scan-response names usually live.
        """
        fallback = dict(kwargs)
        for key in ("bluez", "scanning_mode", "adapter"):
            fallback.pop(key, None)
            try:
                result = await scanner.discover(return_adv=True, **fallback)
                return self.normalize_discovery_result(result)
            except TypeError:
                continue
        result = await scanner.discover(timeout=kwargs.get("timeout", 5))
        return self.normalize_discovery_result(result)

    async def discover_with_bluetoothctl(self, interval):
        """Collect BLE rows using bluetoothctl when Bleak cannot scan."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.bluetoothctl_scan_once, interval)

    def bluetoothctl_scan_once(self, interval):
        """Run one bounded bluetoothctl scan and parse observed devices."""
        bluetoothctl = shutil.which("bluetoothctl")
        if not bluetoothctl:
            raise RuntimeError("bluetoothctl is not installed")
        duration = max(1, int(float(interval)))
        command = [bluetoothctl, "--timeout", str(duration), "scan", "on"]
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=duration + 3,
            )
        except Exception as exc:
            raise RuntimeError("bluetoothctl scan failed: {}".format(exc))
        output = self.strip_ansi(self.decode_output(result.stdout))
        if result.returncode != 0:
            raise RuntimeError(
                "bluetoothctl scan exited {}; {}".format(
                    result.returncode, output[:300]
                )
            )
        rows = self.parse_bluetoothctl_scan_output(output)
        if not rows:
            rows = self.parse_bluetoothctl_devices_output(
                self.command_output([bluetoothctl, "devices"])
            )
        rows = self.enrich_bluetoothctl_rows(rows)
        return self.bluez_rows_to_seen_devices(rows)

    def parse_bluetoothctl_scan_output(self, output):
        """Parse bluetoothctl scan output into normalized BLE rows."""
        rows = {}
        for raw_line in str(output or "").splitlines():
            line = raw_line.strip()
            match = re.search(
                r"\[CHG\]\s+Device\s+([0-9A-Fa-f:]{17})\s+RSSI:\s*(.+)$",
                line,
            )
            if match:
                mac = match.group(1).upper()
                entry = rows.setdefault(mac, self.empty_bluetoothctl_row())
                rssi = self.bluetoothctl_signal_value(match.group(2))
                if rssi is not None:
                    entry["rssi"] = rssi
                continue
            match = re.search(
                r"\[CHG\]\s+Device\s+([0-9A-Fa-f:]{17})\s+([^:]+):\s*(.*)",
                line,
            )
            if match:
                mac = match.group(1).upper()
                entry = rows.setdefault(mac, self.empty_bluetoothctl_row())
                self.apply_bluetoothctl_property(
                    entry,
                    match.group(2).strip(),
                    match.group(3).strip(),
                )
                continue
            match = re.search(
                r"(?:\[(?:NEW|DEL)\]\s+)?Device\s+([0-9A-Fa-f:]{17})(?:\s+(.+))?$",
                line,
            )
            if match:
                mac = match.group(1).upper()
                name = (match.group(2) or "").strip()
                entry = rows.setdefault(mac, self.empty_bluetoothctl_row())
                if (
                    name
                    and self.is_valid_display_name(name)
                    and not self.is_address_like_name(name)
                ):
                    entry["name"] = name
        return rows

    def parse_bluetoothctl_devices_output(self, output):
        """Parse bluetoothctl devices cache into normalized BLE rows."""
        rows = {}
        for raw_line in str(output or "").splitlines():
            parts = raw_line.strip().split(None, 2)
            if len(parts) >= 2 and parts[0] == "Device":
                mac = parts[1].upper()
                entry = rows.setdefault(mac, self.empty_bluetoothctl_row())
                if len(parts) >= 3:
                    name = parts[2].strip()
                    if (
                        name
                        and self.is_valid_display_name(name)
                        and not self.is_address_like_name(name)
                    ):
                        entry["name"] = name
        return rows

    def empty_bluetoothctl_row(self):
        """Return one mutable bluetoothctl-derived row accumulator."""
        return {
            "name": "",
            "rssi": None,
            "service_uuids": set(),
            "manufacturer_ids": set(),
        }

    def apply_bluetoothctl_property(self, entry, key, value):
        """Fold one bluetoothctl property line into a structured row."""
        lowered = str(key or "").strip().lower()
        normalized = re.sub(r"[^a-z0-9]+", " ", lowered).strip()
        value = str(value or "").strip()
        if not normalized:
            return
        if normalized in ("name", "alias"):
            if (
                value
                and self.is_valid_display_name(value)
                and not self.is_address_like_name(value)
            ):
                entry["name"] = value
            return
        if normalized in ("uuid", "uuids"):
            for uuid in self.bluetoothctl_uuid_values(value):
                entry["service_uuids"].add(uuid)
            return
        if normalized == "manufacturerdata key":
            code = self.bluetoothctl_manufacturer_code(value)
            if code is not None:
                entry["manufacturer_ids"].add(code)
            return

    def bluetoothctl_signal_value(self, value):
        """Return decimal RSSI/TxPower from bluetoothctl property text."""
        text = str(value or "").strip()
        match = re.search(r"\((-?\d+)\)", text)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
        match = re.search(r"(-?\d+)", text)
        if not match:
            return None
        try:
            return int(match.group(1))
        except ValueError:
            return None

    def bluetoothctl_uuid_values(self, value):
        """Extract UUID tokens from bluetoothctl property text."""
        text = str(value or "").strip()
        values = []
        for candidate in re.findall(r"\(([0-9A-Fa-f\-]{4,36})\)", text):
            cleaned = candidate.strip().lower()
            if cleaned:
                values.append(cleaned)
        if values:
            return values
        values = []
        for candidate in re.split(r"[,\s]+", text):
            cleaned = candidate.strip().lower()
            if re.match(r"^[0-9a-f]{4,8}$", cleaned) or re.match(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                cleaned,
            ):
                values.append(cleaned)
        return values

    def bluetoothctl_manufacturer_code(self, value):
        """Return an integer manufacturer id parsed from bluetoothctl text."""
        match = re.search(r"0x([0-9A-Fa-f]{1,4})", str(value or ""))
        if not match:
            return None
        try:
            return int(match.group(1), 16)
        except ValueError:
            return None

    def enrich_bluetoothctl_rows(self, rows):
        """Fill bluetoothctl scan rows from cached bluetoothctl info output."""
        if not rows or not bool(self.config.get("bluetoothctl_info_lookup", True)):
            return rows
        ttl = float(self.config.get("bluetoothctl_info_interval_sec", 300))
        limit = int(self.config.get("bluetoothctl_info_max_per_scan", 8))
        cache = getattr(self, "_bluetoothctl_info_cache", None)
        if cache is None:
            cache = {}
            self._bluetoothctl_info_cache = cache
        now = now_epoch()
        lookups = 0
        for mac, entry in rows.items():
            cached = cache.get(mac)
            cached_row = (cached or {}).get("row") or {}
            if self.bluetoothctl_row_has_identity(cached_row):
                self.merge_bluetoothctl_row(entry, cached_row)
                continue
            if cached and now - cached.get("checked_at", 0) < ttl:
                self.merge_bluetoothctl_row(entry, cached_row)
                continue
            if not self.bluetoothctl_row_needs_info(entry):
                continue
            if lookups >= limit:
                continue
            info_row = self.bluetoothctl_info_row(mac)
            cache[mac] = {"checked_at": now, "row": info_row}
            self.merge_bluetoothctl_row(entry, info_row)
            lookups += 1
        return rows

    def bluetoothctl_row_needs_info(self, entry):
        """Return True when bluetoothctl info may add missing identity fields."""
        return not (
            entry.get("name")
            and entry.get("manufacturer_ids")
            and entry.get("service_uuids")
        )

    def bluetoothctl_row_has_identity(self, entry):
        """Return True when cached bluetoothctl info already found useful data."""
        if not isinstance(entry, dict):
            return False
        return bool(
            entry.get("name")
            or entry.get("manufacturer_ids")
            or entry.get("service_uuids")
        )

    def bluetoothctl_info_row(self, mac):
        """Parse bluetoothctl info for one MAC into identity-only fields."""
        output = self.strip_ansi(self.command_output(["bluetoothctl", "info", mac]))
        entry = self.empty_bluetoothctl_row()
        for raw_line in str(output or "").splitlines():
            text = raw_line.strip()
            if ":" not in text:
                continue
            key, value = text.split(":", 1)
            normalized = re.sub(r"[^a-z0-9]+", " ", key.strip().lower()).strip()
            if normalized not in (
                "name",
                "alias",
                "uuid",
                "uuids",
                "manufacturerdata key",
            ):
                continue
            self.apply_bluetoothctl_property(entry, key.strip(), value.strip())
        return entry

    def merge_bluetoothctl_row(self, entry, extra):
        """Merge cached bluetoothctl info data into one scan row."""
        if not isinstance(extra, dict):
            return entry
        if (not entry.get("name")) and extra.get("name"):
            entry["name"] = extra.get("name")
        entry.setdefault("service_uuids", set()).update(
            extra.get("service_uuids") or set()
        )
        entry.setdefault("manufacturer_ids", set()).update(
            extra.get("manufacturer_ids") or set()
        )
        return entry

    def bluez_rows_to_seen_devices(self, rows):
        output = []
        for mac, data in sorted(rows.items()):
            device = _SeenDevice(
                mac,
                name=data.get("name") or "",
                rssi=data.get("rssi"),
            )
            advertisement = _SeenAdvertisement()
            advertisement.local_name = data.get("name") or ""
            advertisement.rssi = data.get("rssi")
            advertisement.service_uuids = sorted(data.get("service_uuids") or [])
            advertisement.manufacturer_data = {
                key: b"" for key in sorted(data.get("manufacturer_ids") or [])
            }
            output.append((device, advertisement))
        return output

    async def discover_with_callback(self, scanner, interval, use_adapter=True):
        """Collect a scan window by merging every Bleak callback update.

        Scan-response packets often arrive after the first advertisement and can
        carry the Local Name that tools like nRF Connect display. A callback
        scan lets Skannr merge those later fields before publishing the row.
        """
        seen = {}

        def remember(device, advertisement):
            # Callback mode may see several packets for one address in a scan
            # window. Merge them before publishing one row to the browser.
            address = getattr(device, "address", None)
            if not address:
                return
            entry = seen.get(address)
            if entry is None:
                entry = {
                    "device": _SeenDevice(address),
                    "advertisement": _SeenAdvertisement(),
                    "service_uuids": set(),
                }
                seen[address] = entry

            name = (
                getattr(advertisement, "local_name", None)
                if advertisement is not None
                else None
            )
            name = name or getattr(device, "name", None) or ""
            if name and not self.is_address_like_name(name):
                entry["device"].name = name
                entry["advertisement"].local_name = name

            rssi = self.device_rssi(device, advertisement)
            if rssi is not None:
                entry["device"].rssi = rssi
                entry["advertisement"].rssi = rssi

            manufacturer_data = (
                getattr(advertisement, "manufacturer_data", None)
                if advertisement is not None
                else None
            )
            if manufacturer_data:
                entry["advertisement"].manufacturer_data.update(manufacturer_data)

            for service in getattr(advertisement, "service_uuids", None) or []:
                entry["service_uuids"].add(service)
            entry["advertisement"].service_uuids = sorted(entry["service_uuids"])

        instance = self.build_callback_scanner(scanner, remember, use_adapter)
        await self.maybe_await(instance.start())
        try:
            await asyncio.sleep(interval)
        finally:
            await self.maybe_await(instance.stop())
        return [(entry["device"], entry["advertisement"]) for entry in seen.values()]

    def build_callback_scanner(self, scanner, callback, use_adapter):
        """Create a BleakScanner while tolerating old constructor signatures."""
        kwargs = {}
        if use_adapter:
            kwargs["adapter"] = self.active_hardware
        if self.config.get("active_scan", True):
            kwargs["scanning_mode"] = "active"
        if self.config.get("bluez_duplicate_data", True):
            kwargs["bluez"] = {"DuplicateData": True}

        candidates = [dict(kwargs)]
        for key in ("bluez", "scanning_mode", "adapter"):
            if key in kwargs:
                reduced = dict(candidates[-1])
                reduced.pop(key, None)
                candidates.append(reduced)

        last_error = None
        for candidate in candidates:
            try:
                return scanner(callback, **candidate)
            except TypeError as exc:
                last_error = exc
        raise last_error or TypeError("BleakScanner callback construction failed")

    async def maybe_await(self, value):
        """Await modern async Bleak methods while tolerating older sync ones."""
        if inspect.isawaitable(value):
            await value

    def normalize_discovery_result(self, result):
        """Normalize Bleak discover return shapes into device/adv pairs."""
        if isinstance(result, dict):
            return list(result.values())
        return [(device, None) for device in (result or [])]

    def device_rssi(self, device, advertisement):
        """Extract RSSI from AdvertisementData first, then older BLEDevice."""
        rssi = (
            getattr(advertisement, "rssi", None) if advertisement is not None else None
        )
        if rssi is None:
            rssi = getattr(device, "rssi", None)
        return rssi

    def _is_stale_cache(self, mac, rssi):
        """Return True when a device's RSSI has not changed across >= threshold
        consecutive scan cycles — strong evidence BlueZ is serving a cached
        device entry rather than a live BLE advertisement.

        A real BLE signal always fluctuates; identical integer RSSI across
        multiple scans is physically impossible for a live device.
        """
        if rssi is None:
            return False
        threshold = getattr(self, "_stale_rssi_threshold", 10)
        history = self._stale_rssi.get(mac, [])
        history.append(rssi)
        if len(history) > threshold + 2:
            history = history[-(threshold + 2) :]
        self._stale_rssi[mac] = history
        # RSSI changed — device is actually advertising again
        if len(history) >= 2 and len(set(history)) > 1:
            del self._stale_rssi[mac]
            return False
        return len(history) >= threshold

    def device_name(self, device, advertisement):
        """Extract the best available advertised/display name.

        Some tools show names from BlueZ's local cache even when the current
        advertisement does not include a Local Name field. Use that cache as a
        fallback for unnamed devices so Skannr can display the same resolved
        names when BlueZ knows them.
        """
        name = (
            getattr(advertisement, "local_name", None)
            if advertisement is not None
            else None
        )
        name = name or getattr(device, "name", None) or ""
        if (
            name
            and self.is_valid_display_name(name)
            and not self.is_address_like_name(name)
        ):
            return name
        mac = getattr(device, "address", None)
        return self.bluez_cached_name(mac)

    def is_address_like_name(self, name):
        """Return True when BlueZ reports the MAC address as the name."""
        value = str(name or "").strip()
        if self.MAC_NAME_RE.match(value):
            return True
        compact = re.sub(r"[^0-9A-Fa-f]", "", value)
        return (
            len(compact) == 12
            and compact.lower() == value.replace(" ", "").replace("_", "").lower()
        )

    def bluez_cached_name(self, mac):
        """Return a cached BlueZ name for a BLE address when available."""
        if not mac:
            return ""
        ttl = float(self.config.get("name_lookup_interval_sec", 60))
        cache = getattr(self, "_bluez_name_cache", None)
        if cache is None:
            cache = {}
            self._bluez_name_cache = cache
        now = now_epoch()
        cached = cache.get(mac)
        if cached and now - cached["checked_at"] < ttl:
            return cached["name"]
        # These lookups are best-effort conveniences. They are intentionally
        # cached because repeatedly shelling out for every advertisement is too
        # expensive on a Pi.
        name = (
            self.bluez_info_name(mac)
            or self.bluez_devices_name(mac)
            or self.classic_name(mac)
        )
        cache[mac] = {"checked_at": now, "name": name}
        return name

    def bluez_info_name(self, mac):
        """Parse Name/Alias from bluetoothctl info for one device."""
        output = self.strip_ansi(self.command_output(["bluetoothctl", "info", mac]))
        values = {}
        for line in output.splitlines():
            text = line.strip()
            if ":" not in text:
                continue
            key, value = text.split(":", 1)
            values[key.strip().lower()] = value.strip()
        name = values.get("name") or values.get("alias") or ""
        return (
            ""
            if not self.is_valid_display_name(name)
            or self.same_address(name, mac)
            or self.is_address_like_name(name)
            else name
        )

    def bluez_devices_name(self, mac):
        """Parse bluetoothctl devices as a broader local-cache fallback."""
        output = self.strip_ansi(self.command_output(["bluetoothctl", "devices"]))
        for line in output.splitlines():
            parts = line.strip().split(None, 2)
            if (
                len(parts) >= 3
                and parts[0] == "Device"
                and parts[1].lower() == mac.lower()
            ):
                name = parts[2].strip()
                return (
                    ""
                    if not self.is_valid_display_name(name)
                    or self.same_address(name, mac)
                    or self.is_address_like_name(name)
                    else name
                )
        return ""

    def classic_name(self, mac):
        """Try a classic Bluetooth name lookup for the same address.

        This only helps when the BLE address is also the public/classic address.
        Many laptops use randomized BLE addresses, in which case there is no
        safe address-only mapping from BLE advertisement to classic name.
        """
        if not self.config.get("classic_name_lookup", False):
            return ""
        try:
            result = subprocess.run(
                ["hcitool", "name", mac],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=float(self.config.get("classic_name_timeout_sec", 2)),
            )
        except Exception:
            return ""
        if result.returncode != 0:
            return ""
        name = self.decode_output(result.stdout).strip()
        return (
            ""
            if not self.is_valid_display_name(name)
            or self.same_address(name, mac)
            or self.is_address_like_name(name)
            else name
        )

    def is_valid_display_name(self, name):
        """Reject diagnostics so command failures never become device names."""
        text = str(name or "").strip()
        if not text:
            return False
        lowered = text.lower()
        bad_fragments = (
            "command '['",
            "timed out after",
            "operation already in progress",
            "failed to connect",
            "input/output error",
        )
        if any(fragment in lowered for fragment in bad_fragments):
            return False
        return not bluetooth_property_like_name(text)

    def same_address(self, left, right):
        """Compare Bluetooth addresses while ignoring separators/case."""
        normalize = lambda value: re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).lower()
        return bool(left and right and normalize(left) == normalize(right))

    def merge_display_payload(self, previous, current):
        """Preserve prior visible BLE fields when a new scan window is sparse."""
        previous = previous or {}
        merged = dict(current or {})
        if not merged.get("name") and previous.get("name"):
            merged["name"] = previous.get("name")
        if merged.get("rssi") is None and previous.get("rssi") is not None:
            merged["rssi"] = previous.get("rssi")
        if not merged.get("manufacturer") and previous.get("manufacturer"):
            merged["manufacturer"] = previous.get("manufacturer")
        if not merged.get("service_uuids") and previous.get("service_uuids"):
            merged["service_uuids"] = list(previous.get("service_uuids") or [])
        if not merged.get("adv_data_hex") and previous.get("adv_data_hex"):
            merged["adv_data_hex"] = previous.get("adv_data_hex")
        for field in (
            "findmy_accessory",
            "findmy_status",
            "findmy_hint",
            "findmy_label",
        ):
            if merged.get(field) in (None, "") and previous.get(field) not in (
                None,
                "",
            ):
                merged[field] = previous.get(field)
        return merged

    def display_payload_changed(self, previous, current):
        """Return True when any browser-visible BLE field changed."""
        fields = (
            "name",
            "rssi",
            "manufacturer",
            "service_uuids",
            "adv_data_hex",
            "findmy_accessory",
            "findmy_status",
            "findmy_hint",
        )
        for field in fields:
            if previous.get(field) != current.get(field):
                return True
        return False

    def service_uuids(self, advertisement):
        """Return service UUIDs from advertisement data when bleak provides it."""
        if advertisement is None:
            return []
        return list(getattr(advertisement, "service_uuids", None) or [])

    def manufacturer_summary(self, advertisement):
        """Summarize manufacturer IDs without storing bulky advertisement blobs."""
        if advertisement is None:
            return None
        data = getattr(advertisement, "manufacturer_data", None) or {}
        if not data:
            return None
        companies = self.company_identifiers()
        parts = []
        for key in sorted(data.keys()):
            code = "0x{:04X}".format(int(key))
            name = companies.get(code.upper())
            # If the optional SIG file is absent or incomplete, keep the raw
            # company ID so the user can look it up later.
            parts.append("{} ({})".format(name, code) if name else code)
        return ", ".join(parts)

    def manufacturer_data_hex(self, advertisement):
        """Return raw manufacturer-data payload bytes as hex keyed by company ID.

        This is the durable cross-reference key for correlating Skannr records
        with other BLE scanners (nRF Connect, Wireshark, etc.).  Each value is
        the hex-encoded payload that follows the company ID in the AD structure.
        """
        if advertisement is None:
            return None
        data = getattr(advertisement, "manufacturer_data", None) or {}
        if not data:
            return None
        return {
            "0x{:04X}".format(int(key)): value.hex()
            for key, value in data.items()
            if value
        }

    def findmy_accessory_fields(self, advertisement):
        """Return compact Apple Find My accessory markers from manufacturer data."""
        if advertisement is None:
            return {}
        data = getattr(advertisement, "manufacturer_data", None) or {}
        payload = data.get(self.APPLE_COMPANY_ID)
        if payload is None:
            payload = data.get("0x{:04X}".format(self.APPLE_COMPANY_ID))
        if payload is None:
            payload = data.get(str(self.APPLE_COMPANY_ID))
        payload = bytes(payload or b"")
        if not payload or payload[0] != self.APPLE_FINDMY_PAYLOAD_TYPE:
            return {}
        fields = {
            "findmy_accessory": True,
            "findmy_label": "Apple Find My accessory",
            "findmy_payload_type": "0x{:02X}".format(payload[0]),
        }
        if len(payload) >= 2:
            fields["findmy_status"] = "0x{:02X}".format(payload[1])
        if len(payload) >= 4:
            fields["findmy_hint"] = "0x{}".format(payload[2:4].hex().upper())
        return fields

    def company_identifiers(self):
        """Load optional offline Bluetooth SIG company-id mappings.

        Shipped text data lives under src/skannr/data/collectors. Optional
        YAML overrides can live under config/collectors. The expected public
        SIG shape is a list of entries like:
          - value: 0x10C4
            name: 'OPICA GmbH'
        """
        if self._company_identifiers is not None:
            return self._company_identifiers
        self._company_identifiers = {}
        candidates = [
            os.path.join(DATA_COLLECTORS_DIR, "company_identifiers.txt"),
            os.path.join(CONFIG_COLLECTORS_DIR, "company_identifiers.yaml"),
            os.path.join(CONFIG_COLLECTORS_DIR, "company_identifiers.yml"),
        ]
        for path in candidates:
            if os.path.exists(path):
                self._company_identifiers = self.load_company_identifiers(path)
                break
        return self._company_identifiers

    def load_company_identifiers(self, path):
        """Parse a local Bluetooth SIG company identifier YAML file."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or []
        except (OSError, yaml.YAMLError):
            return {}
        # Some exports wrap the list under a top-level key; support both.
        if isinstance(loaded, dict):
            loaded = loaded.get("company_identifiers") or loaded.get("values") or []
        companies = {}
        for item in loaded:
            if not isinstance(item, dict):
                continue
            value = item.get("value")
            name = item.get("name")
            if value is None or not name:
                continue
            try:
                code = "0x{:04X}".format(int(str(value), 0))
            except (TypeError, ValueError):
                continue
            companies[code.upper()] = str(name)
        return companies

    def prepare_adapter(self):
        """Best-effort adapter wake-up before every scan attempt."""
        adapter = self.selected_adapter()
        self.command_succeeds(["rfkill", "unblock", "bluetooth"])
        self.command_succeeds(["hciconfig", adapter, "up"])
        self.command_succeeds(["btmgmt", "power", "on"])
        self.command_succeeds(["bluetoothctl", "power", "on"])

    def recover_discovery_timeout(self):
        """Recover after Bleak hangs inside a discovery window."""
        adapter = self.selected_adapter()
        self.command_succeeds(["bluetoothctl", "scan", "off"])
        if bool(self.config.get("reset_after_discovery_timeout", True)):
            self.command_succeeds(["hciconfig", adapter, "reset"])
            self.command_succeeds(["hciconfig", adapter, "up"])
        self.prepare_adapter()

    def should_emit_empty_scan(self, empty_scan_windows, warmup):
        """Return true when an empty scan should be visible to operators."""
        threshold = int(self.config.get("bluez_warmup_after_empty_scans", 5))
        if warmup.get("attempted"):
            return True
        return threshold > 0 and empty_scan_windows == threshold

    def empty_scan_payload(self, empty_scan_windows, warmup):
        """Build a compact UI/log payload for BLE empty-scan diagnostics."""
        payload = {
            "adapter": self.selected_adapter(),
            "scan_method": self.scan_method_label(),
            "fallback_active": self.bluetoothctl_fallback_active(),
            "empty_scan_windows": empty_scan_windows,
            "bluez_warmup": warmup.get("state", "not attempted"),
        }
        if warmup.get("command"):
            payload["bluez_warmup_command"] = warmup["command"]
        if warmup.get("returncode") is not None:
            payload["bluez_warmup_returncode"] = warmup["returncode"]
        if warmup.get("error"):
            payload["bluez_warmup_error"] = warmup["error"]
        payload["bluez_cached_devices"] = self.bluez_cached_device_count()
        payload["diagnostics"] = self.adapter_diagnostics()
        return payload

    def maybe_warm_bluez_discovery(self, empty_scan_windows, last_warmup):
        """Kick BlueZ discovery after repeated empty Bleak scan windows.

        Some Kali/BlueZ combinations appear to leave the adapter powered but not
        actively discovering until an external `bluetoothctl scan on` wakes the
        controller. Keep this recovery bounded and rate-limited so quiet RF
        environments do not spawn a helper on every scan loop.
        """
        skipped = {"attempted": False, "state": "not attempted"}
        threshold = int(self.config.get("bluez_warmup_after_empty_scans", 5))
        if threshold <= 0:
            skipped["state"] = "disabled"
            return last_warmup, skipped
        if empty_scan_windows < threshold:
            return last_warmup, skipped
        now = now_epoch()
        min_interval = float(self.config.get("bluez_warmup_min_interval_sec", 60))
        if last_warmup and now - last_warmup < min_interval:
            skipped["state"] = "rate limited"
            return last_warmup, skipped
        warmup = self.bluez_discovery_warmup()
        if warmup.get("ok"):
            return now, warmup
        return last_warmup, warmup

    def bluez_cached_device_count(self):
        """Return the number of devices currently visible in BlueZ cache."""
        output = self.command_output(["bluetoothctl", "devices"])
        count = 0
        for line in output.splitlines():
            if line.strip().startswith("Device "):
                count += 1
        return count

    def bluez_discovery_warmup(self):
        """Run a short bluetoothctl discovery pass as a BlueZ wake-up."""
        bluetoothctl = shutil.which("bluetoothctl")
        if not bluetoothctl:
            return {
                "attempted": True,
                "ok": False,
                "state": "bluetoothctl missing",
            }
        duration = max(1, int(float(self.config.get("bluez_warmup_scan_sec", 4))))
        command = [bluetoothctl, "--timeout", str(duration), "scan", "on"]
        command_text = " ".join(command)
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=duration + 3,
            )
            ok = result.returncode == 0
            return {
                "attempted": True,
                "ok": ok,
                "state": "started" if ok else "failed",
                "command": command_text,
                "returncode": result.returncode,
            }
        except Exception as exc:
            return {
                "attempted": True,
                "ok": False,
                "state": "failed",
                "command": command_text,
                "error": str(exc),
            }

    def is_operation_in_progress(self, exc):
        """Detect stale/concurrent BlueZ discovery across bleak versions."""
        text = str(exc).lower()
        return "operation" in text and "progress" in text

    def recover_in_progress(self, count):
        """Clear stale BlueZ discovery state after InProgress failures.

        On Raspberry Pi Broadcom UART adapters, BlueZ can occasionally keep
        discovery marked active after many hours. First ask BlueZ to stop
        scanning. If the same error repeats several times, do a lightweight HCI
        reset so the collector can recover without restarting Skannr.
        """
        adapter = self.selected_adapter()
        self.command_succeeds(["bluetoothctl", "scan", "off"])
        reset_after = int(self.config.get("reset_after_in_progress", 3))
        if reset_after > 0 and count >= reset_after:
            self.command_succeeds(["hciconfig", adapter, "reset"])
            self.command_succeeds(["hciconfig", adapter, "up"])

    def startup_payload(self):
        """Build startup diagnostics for comparing hosts and regressions."""
        return {
            "adapter": self.active_hardware,
            "scan_method": self.scan_method_label(),
            "fallback_active": self.bluetoothctl_fallback_active(),
            "diagnostics": self.startup_diagnostics(),
        }

    def retry_payload(self, warning):
        """Build structured retry data so the UI can show method clearly."""
        return {
            "adapter": self.active_hardware or self.selected_adapter(),
            "reason": warning,
            "scan_method": self.scan_method_label(),
            "fallback_active": self.bluetoothctl_fallback_active(),
            "diagnostics": self.startup_diagnostics(),
        }

    def bluetoothctl_fallback_active(self):
        """Return true once the runtime path has switched to bluetoothctl."""
        return bool(getattr(self, "_runtime_bluetoothctl_scan", False))

    def startup_diagnostics(self):
        """Return stable version/config details useful for BLE regressions."""
        fields = [
            "method={}".format(self.scan_method_label()),
            "config_file={}".format(self.config.get("config_file", "unknown")),
            "bleak={}".format(self.python_package_version("bleak")),
            "bluetoothctl_version={}".format(
                self.command_output(["bluetoothctl", "--version"])[:80]
            ),
            "bluetoothd_version={}".format(
                self.command_output(["bluetoothd", "-v"])[:80]
            ),
            "callback_scan={}".format(bool(self.config.get("callback_scan", True))),
            "force_discover_scan={}".format(
                bool(self.config.get("force_discover_scan", False))
            ),
            "force_bluetoothctl_scan={}".format(
                bool(self.config.get("force_bluetoothctl_scan", False))
            ),
            "bluetoothctl_fallback_after_timeout={}".format(
                bool(self.config.get("bluetoothctl_fallback_after_timeout", True))
            ),
        ]
        return "; ".join(fields)

    def python_package_version(self, package):
        """Return an installed Python package version without hard dependency."""
        try:
            from importlib import metadata as importlib_metadata
        except ImportError:
            try:
                import importlib_metadata
            except ImportError:
                return "unknown"
        try:
            return importlib_metadata.version(package)
        except Exception:
            return "unknown"

    def scan_retry_warning(self, exc, in_progress_count):
        """Build a retry warning with a clearer wedged-controller hint."""
        detail = "BLE scan failed; retrying: {}; method={}; {}; {}".format(
            exc,
            self.scan_method_label(),
            self.startup_diagnostics(),
            self.adapter_diagnostics(),
        )
        threshold = int(self.config.get("wedged_warning_after_in_progress", 6))
        if (
            self.is_operation_in_progress(exc)
            and threshold > 0
            and in_progress_count >= threshold
        ):
            return (
                "{}; Bluetooth controller may be wedged. Light recovery failed after "
                "{} consecutive BlueZ InProgress errors. Restart the OS Bluetooth "
                "service/adapter using the host-specific procedure, or reboot if it "
                "does not recover."
            ).format(detail, in_progress_count)
        return detail

    def adapter_diagnostics(self):
        """Collect short adapter diagnostics for retry/offline warnings."""
        adapter = self.selected_adapter()
        details = [
            "adapter={}".format(adapter),
            "hciconfig={}".format(self.command_output(["hciconfig", adapter])[:300]),
            "bluetoothctl={}".format(
                self.command_output(["bluetoothctl", "show"])[:300]
            ),
            "rfkill={}".format(
                self.command_output(["rfkill", "list", "bluetooth"])[:300]
            ),
        ]
        return "; ".join(details)

    def selected_adapter(self):
        """Return the adapter currently in use, or a safe local default."""
        candidates = (
            configured_candidates(self.config, "adapters")
            or sort_bluetooth_adapters(bluetooth_adapters(), self.config)
            or ["hci0"]
        )
        return self.active_hardware or candidates[0]
