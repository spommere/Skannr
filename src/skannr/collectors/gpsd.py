"""Optional live observer location feed from a local GPSD service.

GPSD handles the USB/serial receiver. Skannr consumes GPSD's JSON reports and
keeps the latest valid fix in volatile process memory for location-aware
features. This collector's own status events omit coordinates; downstream
history consumers only persist observer samples when explicitly enabled.
"""

import asyncio
import json
import math
from datetime import datetime, timezone

from ..location import clear_observer_location, set_observer_location
from ..log_utils import now_epoch
from .base import BaseCollector, STATE_OFFLINE, STATE_ONLINE, STATE_RETRYING


class GPSDCollector(BaseCollector):
    """Read GPSD's JSON stream and publish coordinate-free fix status."""

    config_key = "gpsd"
    name = "GPSD Location"
    tab_label = "GPSD Location"
    required_hardware = "Optional USB GNSS receiver managed by GPSD"

    @classmethod
    def hardware_status(cls, config):
        """Report the configured GPSD endpoint without a startup network probe."""
        host = str(config.get("host") or "127.0.0.1")
        try:
            port = int(config.get("port", 2947))
        except (TypeError, ValueError):
            port = 2947
        return {
            "endpoint": "{}:{}".format(host, port),
            "auto_start": config.get("auto_start", True),
        }

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self.last_fix = None
        self.last_fix_received_epoch = None
        self._last_status_signature = None
        self._writer = None

    def endpoint(self):
        """Return validated GPSD host and port settings."""
        host = str(self.config.get("host") or "127.0.0.1").strip()
        if not host:
            host = "127.0.0.1"
        port = int(self.config.get("port", 2947))
        if not 1 <= port <= 65535:
            raise ValueError("GPSD port must be between 1 and 65535")
        return host, port

    def detect(self):
        """Check configuration; actual GPSD reachability is checked on connect."""
        try:
            host, port = self.endpoint()
        except (TypeError, ValueError) as exc:
            self.state = STATE_OFFLINE
            self.warning = str(exc)
            return False
        self.active_hardware = "GPSD {}:{}".format(host, port)
        self.state = STATE_DETECTING
        self.warning = None
        return True

    async def start(self):
        """Reconnect to GPSD, watching its JSON stream until stopped."""
        self._running = True
        if not self.detect():
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return
        self.clear_fix()
        connect_timeout = max(
            0.5, float(self.config.get("connect_timeout_sec", 5))
        )
        read_timeout = max(
            2.0, float(self.config.get("read_timeout_sec", 15))
        )
        retry_interval = max(
            1.0, float(self.config.get("retry_interval_sec", 5))
        )
        status_interval = max(
            1.0, float(self.config.get("status_interval_sec", 5))
        )

        while self._running:
            writer = None
            try:
                host, port = self.endpoint()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=connect_timeout
                )
                self._writer = writer
                writer.write(b'?WATCH={"enable":true,"json":true}\n')
                await writer.drain()
                self.state = STATE_ONLINE
                self.warning = "Waiting for a valid GPS fix."
                self._last_status_signature = None
                await self.emit(
                    "collector_online",
                    {"endpoint": "{}:{}".format(host, port)},
                )
                last_status_emit = 0.0

                while self._running:
                    line = await asyncio.wait_for(reader.readline(), timeout=read_timeout)
                    if not line:
                        raise ConnectionError("GPSD closed the JSON stream")
                    message = self.parse_line(line)
                    if not message:
                        continue
                    if message.get("class") == "TPV":
                        self.consume_tpv(message)
                    now = asyncio.get_running_loop().time()
                    if now - last_status_emit >= status_interval:
                        await self.emit_status()
                        last_status_emit = now
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.state = STATE_RETRYING
                self.warning = "GPSD connection retrying: {}".format(exc)
                self.clear_fix()
                await self.emit(
                    "collector_retrying", {"reason": self.warning}, "warning"
                )
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                self._writer = None
            if self._running:
                await asyncio.sleep(retry_interval)

    async def stop(self):
        """Clear volatile observer position when GPSD collection stops."""
        self.clear_fix()
        if self._writer is not None:
            self._writer.close()
        await super().stop()

    def status(self):
        """Add coordinate-free GNSS fix health to the System Status row."""
        result = super().status()
        age = None
        if self.last_fix_received_epoch is not None:
            age = max(0.0, now_epoch() - self.last_fix_received_epoch)
        stale_after = max(1.0, float(self.config.get("stale_after_sec", 10)))
        fix_valid = bool(self.last_fix) and age is not None and age <= stale_after
        result.update(
            {
                "fix_valid": fix_valid,
                "fix_age_sec": age,
                "fix_accuracy_m": (
                    self.last_fix.get("accuracy_m") if fix_valid else None
                ),
                "fix_mode": self.last_fix.get("fix_mode") if fix_valid else 0,
            }
        )
        return result

    def parse_line(self, line):
        """Decode one bounded GPSD JSON record, ignoring protocol chatter."""
        if not line or len(line) > 16384:
            return None
        try:
            value = json.loads(line.decode("utf-8", errors="replace"))
        except (TypeError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def consume_tpv(self, message):
        """Store a valid TPV fix in memory; reject no-fix and invalid reports."""
        try:
            mode = int(message.get("mode") or 0)
            latitude = float(message.get("lat"))
            longitude = float(message.get("lon"))
        except (TypeError, ValueError):
            mode = 0
            latitude = longitude = None
        if (
            mode < 2
            or latitude is None
            or longitude is None
            or not -90 <= latitude <= 90
            or not -180 <= longitude <= 180
        ):
            self.clear_fix()
            self.warning = "GPSD is connected but has no valid position fix."
            return False

        fix = {
            "latitude": latitude,
            "longitude": longitude,
            "received_epoch": now_epoch(),
            "fix_mode": mode,
            "stale_after_sec": max(
                1.0, float(self.config.get("stale_after_sec", 10))
            ),
        }
        gps_time = gpsd_time_epoch(message.get("time"))
        if gps_time is not None:
            fix["gps_time_epoch"] = gps_time
        accuracy = horizontal_accuracy(message)
        if accuracy is not None:
            fix["accuracy_m"] = accuracy
        for source_key, target_key in (
            ("alt", "altitude_m"),
            ("speed", "speed_mps"),
            ("track", "course_deg"),
        ):
            try:
                fix[target_key] = float(message[source_key])
            except (KeyError, TypeError, ValueError):
                pass
        if not set_observer_location("gpsd", fix):
            self.clear_fix()
            self.warning = "GPSD returned an invalid position fix."
            return False
        self.last_fix = {key: value for key, value in fix.items() if key not in (
            "latitude", "longitude"
        )}
        self.last_fix_received_epoch = fix["received_epoch"]
        self.state = STATE_ONLINE
        self.warning = None
        return True

    def clear_fix(self):
        """Remove this provider's latest in-memory location fix."""
        clear_observer_location("gpsd")
        self.last_fix = None
        self.last_fix_received_epoch = None

    async def emit_status(self):
        """Publish low-rate fix health without publishing coordinates or track."""
        age = (
            now_epoch() - self.last_fix_received_epoch
            if self.last_fix_received_epoch is not None
            else None
        )
        stale_after = max(1.0, float(self.config.get("stale_after_sec", 10)))
        fix_valid = bool(self.last_fix) and age is not None and age <= stale_after
        accuracy = (
            self.last_fix.get("accuracy_m") if fix_valid and self.last_fix else None
        )
        age_bucket = int(age) if age is not None and fix_valid else None
        signature = (
            fix_valid,
            round(accuracy, 1) if accuracy is not None else None,
            age_bucket,
        )
        if signature == self._last_status_signature:
            return
        self._last_status_signature = signature
        await self.emit(
            "gps_status",
            {
                "fix_valid": fix_valid,
                "fix_mode": self.last_fix.get("fix_mode", 0) if self.last_fix else 0,
                "accuracy_m": accuracy,
                "warning": self.warning or "",
            },
            "info" if fix_valid else "warning",
        )


def horizontal_accuracy(message):
    """Return a conservative horizontal error estimate from GPSD TPV fields."""
    errors = []
    for key in ("epx", "epy"):
        try:
            value = float(message[key])
        except (KeyError, TypeError, ValueError):
            continue
        if math.isfinite(value) and value >= 0:
            errors.append(value)
    if len(errors) == 2:
        return math.hypot(errors[0], errors[1])
    if errors:
        return errors[0]
    try:
        value = float(message.get("eph"))
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def gpsd_time_epoch(value):
    """Parse a GPSD ISO timestamp, returning None for absent/bad timestamps."""
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()
