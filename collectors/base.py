"""Base lifecycle helpers shared by all collectors.

Collectors differ in how they talk to hardware, but their status reporting,
validation commands, retry intervals, and event emission should look the same
to the dashboard.
"""

import asyncio
import subprocess
from bus import utc_now


# Collector states are intentionally stable strings because the browser uses
# them for badges, button visibility, and primary/fallback wording.
STATE_DETECTING = "DETECTING"
STATE_RUNNING_TIER1 = "RUNNING_TIER1"
STATE_RUNNING_TIER2 = "RUNNING_TIER2"
STATE_RETRYING = "RETRYING"
STATE_OFFLINE = "OFFLINE"
STATE_STOPPED = "STOPPED"


class BaseCollector:
    """Common lifecycle and status behavior for every collector."""

    config_key = ""
    name = ""
    tab_label = ""
    required_hardware = ""

    def __init__(self, config, bus):
        # Each concrete collector receives only its config subsection, plus the
        # shared event bus used to publish observations and state changes.
        self.config = config
        self.bus = bus
        self.state = STATE_DETECTING
        self.active_hardware = None
        self.events_this_session = 0
        self.last_event = None
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
            "warning": self.warning,
        }

    async def emit(self, event_type, data=None, severity="info"):
        """Publish one collector event and update local event counters."""
        self.events_this_session += 1
        self.last_event = utc_now()
        await self.bus.publish(
            {
                "collector": self.config_key,
                "type": event_type,
                "severity": severity,
                "data": data or {},
            }
        )

    async def retry_sleep(self):
        """Sleep for the collector-specific retry interval."""
        await asyncio.sleep(float(self.config.get("retry_interval_sec", 5)))

    def validation_command(self, tier, default_command=None):
        """Return the configured shell validation for a collector tier.

        The command lives in skannr.yaml as primary_validation or
        fallback_validation. A value of "none" disables that tier.
        """
        value = self.config.get("{}_validation".format(tier), default_command)
        if value is None:
            return None
        text = str(value).strip()
        if not text or text.lower() == "none":
            return None
        try:
            text = text.format(**self.config)
        except Exception:
            pass
        return text

    def validate_tier(self, tier, default_command=None):
        """Run one configured validation command and return (ok, detail)."""
        command = self.validation_command(tier, default_command)
        if not command:
            return False, "{} validation is disabled".format(tier)
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
            return False, "{} validation timed out after {}s: {}".format(
                tier, int(timeout), command
            )
        except Exception as exc:
            return False, "{} validation could not run: {}".format(tier, exc)
        output = " ".join((result.stdout or "").split())[:500]
        if result.returncode == 0:
            return True, output or "{} validation passed".format(tier)
        return False, output or "{} validation failed with exit {}".format(
            tier, result.returncode
        )
