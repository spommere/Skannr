import asyncio
import inspect
import os
import re
import subprocess
import time

import yaml

from collectors.base import BaseCollector, STATE_OFFLINE, STATE_RETRYING, STATE_RUNNING_TIER1, STATE_RUNNING_TIER2


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

    The preferred adapter is usually an external USB BLE dongle. The fallback
    adapter is typically the Pi's built-in controller, which may work but often
    has shorter range or less reliable scanning.
    """

    config_key = "ble"
    name = "BLE Scan"
    tab_label = "BLE Scan"
    required_hardware = "USB Bluetooth 5.0 dongle or built-in Bluetooth adapter"
    _company_identifiers = None
    MAC_NAME_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$|^[0-9A-Fa-f]{12}$")

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
            subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=5)
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
        """Pick preferred adapter first, then fallback, then mark offline."""
        preferred = self.config.get("preferred_adapter", "hci1")
        fallback = self.config.get("fallback_adapter", "hci0")
        primary_default = "test -d /sys/class/bluetooth/{} || hciconfig {} >/dev/null 2>&1".format(preferred, preferred)
        fallback_default = "test -d /sys/class/bluetooth/{} || hciconfig {} >/dev/null 2>&1 || bluetoothctl list | grep -q 'Controller '".format(fallback, fallback)
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
            self.warning = "Using fallback Bluetooth adapter {}; range may be reduced. Primary validation failed: {}".format(fallback, primary_detail)
            return True
        self.active_hardware = None
        self.state = STATE_OFFLINE
        self.warning = "No usable Bluetooth adapter. Primary validation: {}; fallback validation: {}".format(primary_detail, fallback_detail)
        return False

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

        self.prepare_adapter()
        await self.emit("scanner_started", {"adapter": self.active_hardware, "tier": self.state})
        if self.state == STATE_RUNNING_TIER2:
            await self.emit("hardware_fallback", {"adapter": self.active_hardware, "warning": self.warning}, "warning")
        # seen tracks device state between scans so the UI can distinguish new,
        # updated, and lost devices instead of appending duplicate rows forever.
        seen = {}
        timeout = float(self.config.get("device_timeout_sec", 60))
        interval = float(self.config.get("scan_interval_sec", 5))
        consecutive_in_progress = 0

        while self._running:
            now = asyncio.get_running_loop().time()
            try:
                # Some adapters come back from errors powered off or blocked.
                # Re-running setup is cheap and makes unplug/replug recovery
                # more likely during field use.
                async with adapter_operation_lock(self.active_hardware):
                    self.prepare_adapter()
                    devices = await self.discover_devices(BleakScanner, interval, use_adapter=True)
            except TypeError:
                # Older bleak versions did not accept newer discover keywords.
                async with adapter_operation_lock(self.active_hardware):
                    self.prepare_adapter()
                    devices = await self.discover_devices(BleakScanner, interval, use_adapter=False)
            except Exception as exc:
                if self.is_operation_in_progress(exc):
                    consecutive_in_progress += 1
                    async with adapter_operation_lock(self.active_hardware):
                        self.recover_in_progress(consecutive_in_progress)
                else:
                    consecutive_in_progress = 0
                self.state = STATE_RETRYING
                self.warning = self.scan_retry_warning(exc, consecutive_in_progress)
                await self.emit("collector_retrying", {"reason": self.warning}, "warning")
                await self.retry_sleep()
                if not self.detect():
                    self.state = STATE_OFFLINE
                    await self.emit("collector_offline", {"reason": self.warning}, "warning")
                continue

            consecutive_in_progress = 0
            current = asyncio.get_running_loop().time()
            for device, advertisement in devices:
                # bleak exposes slightly different attributes across versions;
                # getattr keeps the collector compatible with Python 3.6-era
                # packages and modern Pi Python 3.11 packages.
                mac = getattr(device, "address", None) or "unknown"
                rssi = self.device_rssi(device, advertisement)
                name = self.device_name(device, advertisement)
                payload = {
                    "mac": mac,
                    "name": name,
                    "rssi": rssi,
                    "manufacturer": self.manufacturer_summary(advertisement),
                    "service_uuids": self.service_uuids(advertisement),
                    "adv_data_hex": None,
                }
                previous = seen.get(mac)
                seen[mac] = dict(payload, last_seen=current)
                if previous is None:
                    payload["first_seen"] = None
                    await self.emit("device_seen", payload)
                elif self.display_payload_changed(previous, payload):
                    # Names and service/manufacturer data can arrive in later
                    # advertisements or scan responses. Send the full displayed
                    # payload so the UI can fill blanks after the first sighting.
                    await self.emit("device_updated", payload)

            # Expire stale devices locally; bleak discovery returns only the
            # devices seen in the current scan window.
            lost = [mac for mac, data in seen.items() if current - data["last_seen"] > timeout]
            for mac in lost:
                await self.emit("device_lost", {"mac": mac})
                del seen[mac]

            if not devices:
                await asyncio.sleep(max(0.1, interval - (asyncio.get_running_loop().time() - now)))

    async def discover_devices(self, scanner, interval, use_adapter=True):
        """Return [(device, advertisement_data)] across old/new bleak APIs.

        Recent bleak versions expose RSSI and service data in AdvertisementData,
        not always on the BLEDevice object. Older versions only return a list of
        BLEDevice objects. Normalizing here keeps the main scan loop simple and
        prevents the UI from losing RSSI on Python 3.11/Pi installs.
        """
        if self.config.get("callback_scan", True):
            try:
                return await self.discover_with_callback(scanner, interval, use_adapter=use_adapter)
            except TypeError:
                # Fall through to the discover() compatibility ladder for older
                # bleak builds whose scanner constructor does not match the
                # callback API.
                pass

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

    async def discover_with_callback(self, scanner, interval, use_adapter=True):
        """Collect a scan window by merging every Bleak callback update.

        Scan-response packets often arrive after the first advertisement and can
        carry the Local Name that tools like nRF Connect display. A callback
        scan lets Skannr merge those later fields before publishing the row.
        """
        seen = {}

        def remember(device, advertisement):
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

            name = getattr(advertisement, "local_name", None) if advertisement is not None else None
            name = name or getattr(device, "name", None) or ""
            if name and not self.is_address_like_name(name):
                entry["device"].name = name
                entry["advertisement"].local_name = name

            rssi = self.device_rssi(device, advertisement)
            if rssi is not None:
                entry["device"].rssi = rssi
                entry["advertisement"].rssi = rssi

            manufacturer_data = getattr(advertisement, "manufacturer_data", None) if advertisement is not None else None
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
        rssi = getattr(advertisement, "rssi", None) if advertisement is not None else None
        if rssi is None:
            rssi = getattr(device, "rssi", None)
        return rssi

    def device_name(self, device, advertisement):
        """Extract the best available advertised/display name.

        Some tools show names from BlueZ's local cache even when the current
        advertisement does not include a Local Name field. Use that cache as a
        fallback for unnamed devices so Skannr can display the same resolved
        names when BlueZ knows them.
        """
        name = getattr(advertisement, "local_name", None) if advertisement is not None else None
        name = name or getattr(device, "name", None) or ""
        if name and not self.is_address_like_name(name):
            return name
        mac = getattr(device, "address", None)
        return self.bluez_cached_name(mac)

    def is_address_like_name(self, name):
        """Return True when BlueZ reports the MAC address as the name."""
        value = str(name or "").strip()
        if self.MAC_NAME_RE.match(value):
            return True
        compact = re.sub(r"[^0-9A-Fa-f]", "", value)
        return len(compact) == 12 and compact.lower() == value.replace(" ", "").replace("_", "").lower()

    def bluez_cached_name(self, mac):
        """Return a cached BlueZ name for a BLE address when available."""
        if not mac:
            return ""
        ttl = float(self.config.get("name_lookup_interval_sec", 60))
        cache = getattr(self, "_bluez_name_cache", None)
        if cache is None:
            cache = {}
            self._bluez_name_cache = cache
        now = time.time()
        cached = cache.get(mac)
        if cached and now - cached["checked_at"] < ttl:
            return cached["name"]
        name = self.bluez_info_name(mac) or self.bluez_devices_name(mac) or self.classic_name(mac)
        cache[mac] = {"checked_at": now, "name": name}
        return name

    def bluez_info_name(self, mac):
        """Parse Name/Alias from bluetoothctl info for one device."""
        output = self.command_output(["bluetoothctl", "info", mac])
        values = {}
        for line in output.splitlines():
            text = line.strip()
            if ":" not in text:
                continue
            key, value = text.split(":", 1)
            values[key.strip().lower()] = value.strip()
        name = values.get("name") or values.get("alias") or ""
        return "" if self.same_address(name, mac) or self.is_address_like_name(name) else name

    def bluez_devices_name(self, mac):
        """Parse bluetoothctl devices as a broader local-cache fallback."""
        output = self.command_output(["bluetoothctl", "devices"])
        for line in output.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) >= 3 and parts[0] == "Device" and parts[1].lower() == mac.lower():
                name = parts[2].strip()
                return "" if self.same_address(name, mac) or self.is_address_like_name(name) else name
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
        return "" if self.same_address(name, mac) or self.is_address_like_name(name) else name

    def same_address(self, left, right):
        """Compare Bluetooth addresses while ignoring separators/case."""
        normalize = lambda value: re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).lower()
        return bool(left and right and normalize(left) == normalize(right))

    def display_payload_changed(self, previous, current):
        """Return True when any browser-visible BLE field changed."""
        fields = ("name", "rssi", "manufacturer", "service_uuids")
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
            parts.append("{} ({})".format(name, code) if name else code)
        return ", ".join(parts)

    def company_identifiers(self):
        """Load optional offline Bluetooth SIG company-id mappings.

        Drop company_identifiers.txt or company_identifiers.yaml next to this
        collector. The expected public SIG shape is a list of entries like:
          - value: 0x10C4
            name: 'OPICA GmbH'
        """
        if self._company_identifiers is not None:
            return self._company_identifiers
        self._company_identifiers = {}
        for filename in ("company_identifiers.txt", "company_identifiers.yaml", "company_identifiers.yml"):
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
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
        adapter = self.active_hardware or self.config.get("fallback_adapter", "hci0")
        self.command_succeeds(["rfkill", "unblock", "bluetooth"])
        self.command_succeeds(["hciconfig", adapter, "up"])
        self.command_succeeds(["btmgmt", "power", "on"])
        self.command_succeeds(["bluetoothctl", "power", "on"])

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
        adapter = self.active_hardware or self.config.get("fallback_adapter", "hci0")
        self.command_succeeds(["bluetoothctl", "scan", "off"])
        reset_after = int(self.config.get("reset_after_in_progress", 3))
        if reset_after > 0 and count >= reset_after:
            self.command_succeeds(["hciconfig", adapter, "reset"])
            self.command_succeeds(["hciconfig", adapter, "up"])

    def scan_retry_warning(self, exc, in_progress_count):
        """Build a retry warning with a clearer wedged-controller hint."""
        detail = "BLE scan failed; retrying: {}; {}".format(exc, self.adapter_diagnostics())
        threshold = int(self.config.get("wedged_warning_after_in_progress", 6))
        if self.is_operation_in_progress(exc) and threshold > 0 and in_progress_count >= threshold:
            return (
                "{}; Bluetooth controller may be wedged. Light recovery failed after "
                "{} consecutive BlueZ InProgress errors. Restart the OS Bluetooth "
                "service/adapter using the host-specific procedure, or reboot if it "
                "does not recover."
            ).format(detail, in_progress_count)
        return detail

    def adapter_diagnostics(self):
        """Collect short adapter diagnostics for retry/offline warnings."""
        adapter = self.active_hardware or self.config.get("fallback_adapter", "hci0")
        details = [
            "adapter={}".format(adapter),
            "hciconfig={}".format(self.command_output(["hciconfig", adapter])[:300]),
            "bluetoothctl={}".format(self.command_output(["bluetoothctl", "show"])[:300]),
            "rfkill={}".format(self.command_output(["rfkill", "list", "bluetooth"])[:300]),
        ]
        return "; ".join(details)
