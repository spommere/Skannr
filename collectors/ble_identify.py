import asyncio

from collectors.ble import BLECollector, adapter_operation_lock
from collectors.base import STATE_OFFLINE, STATE_STOPPED


DIS_CHARACTERISTICS = {
    "manufacturer_name": "00002a29-0000-1000-8000-00805f9b34fb",
    "model_number": "00002a24-0000-1000-8000-00805f9b34fb",
    "firmware_revision": "00002a26-0000-1000-8000-00805f9b34fb",
    "hardware_revision": "00002a27-0000-1000-8000-00805f9b34fb",
    "software_revision": "00002a28-0000-1000-8000-00805f9b34fb",
}


class BLEIdentifyCollector(BLECollector):
    """On-demand active BLE Device Information Service reader.

    This collector is deliberately separate from passive BLE Scan. It makes an
    active GATT connection only when the user requests identification for one
    MAC address, then reads non-sensitive Device Information Service fields.
    """

    config_key = "ble_identify"
    name = "BLE Identify"
    tab_label = "BLE Identify"
    required_hardware = "Bluetooth adapter for active GATT identification"

    async def start(self):
        """Do not run a background loop; identification is target-based."""
        self._running = False
        if not self.detect():
            self.state = STATE_OFFLINE
        else:
            self.state = STATE_STOPPED

    async def identify(self, mac, timeout=None):
        """Connect to one BLE device and read Device Information fields."""
        mac = str(mac or "").strip()
        if not mac:
            await self.emit("identify_failed", {"reason": "No BLE MAC address provided"}, "warning")
            return
        if not self.detect():
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return
        try:
            from bleak import BleakClient
        except ImportError:
            self.state = STATE_OFFLINE
            self.warning = "Python package 'bleak' is not installed."
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return

        timeout = float(timeout or self.config.get("identify_timeout_sec", 10))
        await self.emit("identify_started", {
            "mac": mac,
            "adapter": self.active_hardware,
            "timeout_sec": timeout,
        })
        try:
            fields = await self.identify_with_retries(BleakClient, mac, timeout)
        except Exception as exc:
            await self.emit("identify_failed", {
                "mac": mac,
                "reason": self.identify_error_message(exc),
                "adapter": self.active_hardware,
            }, "warning")
            return

        if not any(fields.values()):
            await self.emit("identify_failed", {
                "mac": mac,
                "reason": "Device Information Service fields were not readable",
                "adapter": self.active_hardware,
            }, "warning")
            return
        await self.emit("identify_result", {
            "mac": mac,
            "adapter": self.active_hardware,
            **fields,
        })

    async def identify_with_retries(self, BleakClient, mac, timeout):
        """Serialize active GATT work and retry transient BlueZ busy errors."""
        attempts = int(self.config.get("identify_attempts", 3))
        attempts = max(1, attempts)
        delay = float(self.config.get("identify_retry_delay_sec", 1.5))
        last_error = None
        for attempt in range(attempts):
            try:
                async with adapter_operation_lock(self.active_hardware):
                    self.prepare_adapter_for_identify()
                    client = self.bleak_client(BleakClient, mac, timeout)
                    async with client:
                        return await self.read_device_information(client)
            except Exception as exc:
                last_error = exc
                if not self.is_operation_in_progress(exc) or attempt == attempts - 1:
                    raise
                await asyncio.sleep(delay)
        raise last_error

    def prepare_adapter_for_identify(self):
        """Wake the adapter and stop passive discovery before connecting."""
        self.prepare_adapter()
        self.command_succeeds(["bluetoothctl", "scan", "off"])

    def is_operation_in_progress(self, exc):
        """Detect BlueZ's transient busy response across bleak versions."""
        text = str(exc).lower()
        return "operation" in text and "progress" in text

    def identify_error_message(self, exc):
        """Return a user-facing identify error with the likely cause."""
        if self.is_operation_in_progress(exc):
            return "Bluetooth adapter is busy with another BlueZ operation. Try again after BLE Scan finishes its current pass, or stop BLE Scan before identifying."
        return str(exc)

    def bleak_client(self, client_cls, mac, timeout):
        """Create a BleakClient across older/newer bleak signatures."""
        try:
            return client_cls(mac, timeout=timeout, adapter=self.active_hardware)
        except TypeError:
            return client_cls(mac, timeout=timeout)

    async def read_device_information(self, client):
        """Read non-sensitive DIS strings; do not read serial number."""
        fields = {}
        for name, uuid in DIS_CHARACTERISTICS.items():
            fields[name] = await self.read_string_characteristic(client, uuid)
        return fields

    async def read_string_characteristic(self, client, uuid):
        """Best-effort UTF-8 decode for one optional GATT characteristic."""
        try:
            value = await asyncio.wait_for(client.read_gatt_char(uuid), timeout=5)
        except Exception:
            return ""
        try:
            return bytes(value).decode("utf-8", errors="replace").strip("\x00 \t\r\n")
        except Exception:
            return ""
