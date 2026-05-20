"""RTL-SDR spectrum scan collector.

This collector wraps rtl_power, learns a baseline noise floor, then emits signal
events when frequency bins rise above that baseline.
"""

import asyncio
import logging

from collectors.base import (
    BaseCollector,
    STATE_OFFLINE,
    STATE_RUNNING_TIER1,
    STATE_RUNNING_TIER2,
)


class RTLSDRCollector(BaseCollector):
    """RTL-SDR spectrum collector driven by the rtl_power command-line tool."""

    config_key = "rtlsdr"
    name = "RTL-SDR"
    tab_label = "RTL-SDR"
    required_hardware = "RTL-SDR USB dongle"

    def __init__(self, config, bus):
        super().__init__(config, bus)
        # rtl_power is a long-running subprocess. _noise_floor stores the
        # baseline average per frequency bin; _active tracks bins currently
        # above the alert threshold.
        self._process = None
        self._stderr_task = None
        self._noise_floor = {}
        self._active = {}

    def detect(self):
        """Validate that rtl_power exists and an RTL-SDR device is present."""
        default_validation = "command -v rtl_power >/dev/null 2>&1 && command -v rtl_test >/dev/null 2>&1 && rtl_test -t"
        ok, detail = self.validate_tier("primary", default_validation)
        if ok:
            self.active_hardware = "RTL-SDR index {}".format(
                self.config.get("device_index", 0)
            )
            self.state = STATE_RUNNING_TIER1
            self.warning = None
            return True
        fallback_ok, fallback_detail = self.validate_tier("fallback", None)
        if fallback_ok:
            self.active_hardware = "RTL-SDR fallback"
            self.state = STATE_RUNNING_TIER2
            self.warning = "Using fallback RTL-SDR validation. Primary validation failed: {}".format(
                detail
            )
            return True
        self.active_hardware = None
        self.state = STATE_OFFLINE
        self.warning = (
            "RTL-SDR validation failed: {}; fallback validation: {}".format(
                detail, fallback_detail
            )
        )
        return False

    async def start(self):
        """Run rtl_power, build a baseline, then publish signal changes."""
        self._running = True
        if not self.detect():
            await self.emit(
                "collector_offline", {"reason": self.warning}, "warning"
            )
            return

        start_mhz = float(self.config.get("scan_start_mhz", 400))
        end_mhz = float(self.config.get("scan_end_mhz", 470))
        step_khz = float(self.config.get("step_khz", 50))
        gain = self.config.get("gain", 40)
        threshold = float(self.config.get("threshold_db", 10))
        baseline_sec = float(self.config.get("baseline_period_sec", 30))
        frequency_arg = "{}M:{}M:{}k".format(start_mhz, end_mhz, step_khz)
        gain_arg = "auto" if str(gain).lower() == "auto" else str(gain)

        # The browser uses this event to show scan parameters while the baseline
        # is still being collected.
        await self.emit(
            "scanner_started",
            {
                "range": frequency_arg,
                "gain": gain_arg,
                "threshold_db": threshold,
                "baseline_period_sec": baseline_sec,
            },
        )

        try:
            # rtl_power emits CSV lines to stdout. Using asyncio subprocess
            # keeps the collector non-blocking while other collectors run.
            self._process = await asyncio.create_subprocess_exec(
                "rtl_power",
                "-d",
                str(self.config.get("device_index", 0)),
                "-f",
                frequency_arg,
                "-g",
                gain_arg,
                "-i",
                "1",
                "-",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._stderr_task = asyncio.get_event_loop().create_task(
                self.drain_stderr()
            )
        except Exception as exc:
            self.state = STATE_OFFLINE
            await self.emit(
                "collector_offline", {"reason": str(exc)}, "warning"
            )
            return

        loop = asyncio.get_event_loop()
        baseline_deadline = loop.time() + baseline_sec
        baseline_samples = 0
        baseline_ready = False

        while self._running:
            line = await self._process.stdout.readline()
            if not line:
                break
            bins = self.parse_power_line(line.decode("utf-8", errors="replace"))
            if not bins:
                continue
            if loop.time() < baseline_deadline:
                # During the baseline window we learn normal power per bin and
                # intentionally do not report detections.
                baseline_samples += 1
                self.update_baseline(bins, baseline_samples)
                continue
            if not baseline_ready:
                baseline_ready = True
                await self.emit(
                    "baseline_ready", {"bins": len(self._noise_floor)}
                )
            await self.detect_signals(bins, threshold)

        await self.emit("scanner_stopped", {"reason": "process exited"})

    async def stop(self):
        """Terminate rtl_power before marking the collector stopped."""
        if self._process and self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=3)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
        if self._stderr_task and not self._stderr_task.done():
            self._stderr_task.cancel()
        await super().stop()

    async def drain_stderr(self):
        """Prevent rtl_power stderr from filling its pipe and blocking the scan."""
        if not self._process or not self._process.stderr:
            return
        while True:
            line = await self._process.stderr.readline()
            if not line:
                return
            logging.debug(
                "rtl_power stderr: %s",
                line.decode("utf-8", errors="replace").rstrip(),
            )

    def parse_power_line(self, line):
        """Parse one rtl_power CSV line into (MHz, dBm) bins."""
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 7:
            return []
        try:
            start_hz = float(parts[2])
            end_hz = float(parts[3])
            step_hz = float(parts[4])
            powers = [float(value) for value in parts[6:] if value]
        except ValueError:
            return []
        bins = []
        for index, power in enumerate(powers):
            # Clamp at end_hz because rtl_power may include the final edge bin.
            frequency_hz = min(start_hz + (index * step_hz), end_hz)
            bins.append((round(frequency_hz / 1000000.0, 6), power))
        return bins

    def update_baseline(self, bins, sample_count):
        """Maintain a running average noise floor per frequency bin."""
        for frequency_mhz, power in bins:
            old = self._noise_floor.get(frequency_mhz, power)
            self._noise_floor[frequency_mhz] = old + (
                (power - old) / float(sample_count)
            )

    async def detect_signals(self, bins, threshold):
        """Emit signal_detected/signal_lost based on baseline deltas."""
        seen_now = set()
        for frequency_mhz, power in bins:
            floor = self._noise_floor.get(frequency_mhz, power)
            above_floor = power - floor
            if above_floor >= threshold:
                seen_now.add(frequency_mhz)
                if frequency_mhz not in self._active:
                    # Only emit a detection once per active interval. The UI
                    # keeps the row visible until a later signal_lost event.
                    self._active[frequency_mhz] = {
                        "first_seen": None,
                        "last_seen": None,
                    }
                    await self.emit(
                        "signal_detected",
                        {
                            "frequency_mhz": frequency_mhz,
                            "power_dbm": power,
                            "above_floor_db": round(above_floor, 2),
                            "first_seen": None,
                            "last_seen": None,
                        },
                        "warning",
                    )
        lost = [
            frequency_mhz
            for frequency_mhz in self._active
            if frequency_mhz not in seen_now
        ]
        for frequency_mhz in lost:
            await self.emit("signal_lost", {"frequency_mhz": frequency_mhz})
            del self._active[frequency_mhz]
