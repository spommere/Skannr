"""Base lifecycle helpers shared by all collectors.

Collectors differ in how they talk to hardware, but their status reporting,
validation commands, retry intervals, and event emission should look the same
to the dashboard.
"""

import asyncio
import subprocess

from bus import local_now
from log_utils import now_epoch, timestamp_epoch


# Collector states are intentionally stable strings because the browser uses
# them for badges and button visibility.
STATE_DETECTING = "DETECTING"
STATE_ONLINE = "ONLINE"
STATE_RETRYING = "RETRYING"
STATE_OFFLINE = "OFFLINE"
STATE_STOPPED = "STOPPED"


class BaseCollector:
    """Common lifecycle and status behavior for every collector."""

    config_key = ""
    name = ""
    tab_label = ""
    required_hardware = ""

    @classmethod
    def hardware_status(cls, config):
        """Return static hardware/software probes for this collector."""
        return {}

    def __init__(self, config, bus):
        # Each concrete collector receives only its config subsection, plus the
        # shared event bus used to publish observations and state changes.
        self.config = config
        self.bus = bus
        self.state = STATE_DETECTING
        self.active_hardware = None
        self.events_this_session = 0
        self.last_event = None
        self.last_event_epoch = None
        self.warning = None
        self._running = False

    def detect(self):
        """Select hardware and set state/warning before start() begins work."""
        raise NotImplementedError

    async def start(self):
        """Run until stopped, publishing events through self.emit()."""
        raise NotImplementedError

    async def stop(self):
        """Common stop path used by UI controls and process shutdown."""
        self._running = False
        self.state = STATE_STOPPED
        await self.emit("collector_stopped", {"collector": self.name})

    def status(self):
        """Return the compact snapshot sent to the System Status table."""
        return {
            "key": self.config_key,
            "name": self.name,
            "tab_label": self.tab_label,
            "state": self.state,
            "hardware": self.active_hardware or self.required_hardware,
            "events_this_session": self.events_this_session,
            "last_event": self.last_event,
            "last_event_epoch": self.last_event_epoch,
            "warning": self.warning,
        }

    async def emit(self, event_type, data=None, severity="info"):
        """Publish one collector event and update local event counters."""
        self.events_this_session += 1
        data = data or {}
        self.last_event_epoch = timestamp_epoch(data.get("timestamp_epoch"))
        if self.last_event_epoch is None:
            self.last_event_epoch = now_epoch()
        self.last_event = local_now(self.last_event_epoch)
        await self.bus.publish(
            {
                "collector": self.config_key,
                "type": event_type,
                "severity": severity,
                "timestamp_epoch": self.last_event_epoch,
                "data": data,
            }
        )

    async def retry_sleep(self):
        """Sleep for the collector-specific retry interval."""
        await asyncio.sleep(float(self.config.get("retry_interval_sec", 5)))

    def validate_configured(self, key, default_command=None):
        """Run one named validation command from collector config."""
        command = self.config.get(key, default_command)
        if command is None:
            return False, "{} is disabled".format(key)
        text = str(command).strip()
        if not text or text.lower() == "none":
            return False, "{} is disabled".format(key)
        try:
            text = text.format(**self.config)
        except Exception:
            pass
        return self.run_validation(key, text)

    def run_validation(self, label, command):
        """Run a configured shell validation command and return (ok, detail)."""
        timeout = float(self.config.get("validation_timeout_sec", 10))
        try:
            # Validation commands are deliberately shell strings so users can
            # express local checks in YAML without changing Python code.
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=timeout,
                universal_newlines=True,
            )
        except subprocess.TimeoutExpired:
            return False, "{} timed out after {}s: {}".format(
                label, int(timeout), command
            )
        except Exception as exc:
            return False, "{} could not run: {}".format(label, exc)
        output = " ".join((result.stdout or "").split())[:500]
        if result.returncode == 0:
            return True, output or "{} passed".format(label)
        return False, output or "{} failed with exit {}".format(
            label, result.returncode
        )
