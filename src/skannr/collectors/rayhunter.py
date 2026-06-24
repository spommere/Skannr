"""Optional Rayhunter status collector.

Rayhunter exposes a local web endpoint. Some builds serve gzip-compressed page
content, so this collector explicitly requests and decodes gzip before parsing
the warning state.
"""

import asyncio
import gzip
import html
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from .base import BaseCollector, STATE_OFFLINE, STATE_ONLINE, STATE_RETRYING
from ..log_utils import sanitize_json_line


RAYHUNTER_CODE_MARKERS = (
    "=>",
    "function ",
    "globalthis.",
    "sessionstorage",
    "__sveltekit",
    "var ",
    "const ",
    "let ",
    "document.",
    "window.",
)

RAYHUNTER_FIELD_MAX = 180


def rayhunter_text_lines(text):
    """Return visible Rayhunter text lines without bundled app code."""
    cleaned = re.sub(
        r"(?is)<(script|style|template|noscript)\b[^>]*>.*?</\1>",
        "\n",
        text or "",
    )
    cleaned = re.sub(r"(?i)<br\s*/?>", "\n", cleaned)
    cleaned = re.sub(
        r"(?i)</(p|div|section|article|header|footer|h[1-6]|li|tr|td|th|a|button)>",
        "\n",
        cleaned,
    )
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    cleaned = html.unescape(cleaned)
    return [
        line.strip()
        for line in cleaned.splitlines()
        if safe_rayhunter_field(line.strip())
    ]


def safe_rayhunter_field(value, max_length=RAYHUNTER_FIELD_MAX):
    """Reject raw HTML/JS fragments before they reach Insights or Reports."""
    if value in (None, ""):
        return ""
    text = " ".join(str(value).split())
    if not text or len(text) > max_length:
        return ""
    lowered = text.lower()
    if any(marker in lowered for marker in RAYHUNTER_CODE_MARKERS):
        return ""
    if "<" in text or ">" in text:
        return ""
    # Balanced braces are common in minified JavaScript, not in status fields.
    if ("{" in text or "}" in text) and ":" not in text:
        return ""
    return text


def clean_rayhunter_field(value, max_length=RAYHUNTER_FIELD_MAX):
    """Return compact plain text suitable for operator-facing Rayhunter fields."""
    if value in (None, ""):
        return ""
    lines = rayhunter_text_lines(str(value))
    if not lines:
        return ""
    return safe_rayhunter_field(" ".join(lines), max_length=max_length)


def clean_rayhunter_data(data):
    """Scrub Rayhunter event data loaded from older persisted logs."""
    if not isinstance(data, dict):
        return {}
    cleaned = {}
    for key, value in data.items():
        if value in (None, "", []):
            continue
        if key in ("warning_count", "events_in_window", "warning_events_in_window"):
            cleaned[key] = value
        elif key == "recording_artifacts" and isinstance(value, list):
            artifacts = []
            for item in value:
                item = safe_rayhunter_field(item, max_length=12)
                if item in ("pcap", "qmdl", "zip") and item not in artifacts:
                    artifacts.append(item)
            if artifacts:
                cleaned[key] = artifacts
        else:
            max_length = 500 if key in ("summary", "reason", "warning") else RAYHUNTER_FIELD_MAX
            value = clean_rayhunter_field(value, max_length=max_length)
            if value:
                cleaned[key] = value
    return cleaned


class RayhunterCollector(BaseCollector):
    """Poll a Rayhunter web endpoint and normalize its warning status."""

    config_key = "rayhunter"
    name = "Rayhunter"
    tab_label = "Rayhunter"
    required_hardware = "Rayhunter HTTP endpoint"
    subject_history_event_types = ("rayhunter_status", "collector_offline", "collector_retrying")

    @classmethod
    def hardware_status(cls, config):
        """Return configured endpoint metadata."""
        return {
            "endpoint": config.get("endpoint") or "",
            "enabled": bool(config.get("enabled", False)),
        }

    def detect(self):
        """Require an endpoint before the collector can start."""
        endpoint = str(self.config.get("endpoint") or "").strip()
        if not endpoint:
            self.state = STATE_OFFLINE
            self.warning = "No Rayhunter endpoint configured."
            return False
        self.active_hardware = endpoint
        self.state = STATE_ONLINE
        self.warning = None
        return True

    async def start(self):
        """Poll Rayhunter until stopped."""
        self._running = True
        if not self.detect():
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return
        interval = float(self.config.get("poll_interval_sec", 30))
        await self.emit("collector_online", {"endpoint": self.active_hardware})
        while self._running:
            try:
                status = await asyncio.to_thread(
                    self.fetch_status, self.active_hardware
                )
                self.state = STATE_ONLINE
                self.warning = status.get("warning") or None
                await self.emit(
                    "rayhunter_status",
                    status,
                    "warning" if status.get("warning_count") else "info",
                )
            except Exception as exc:
                self.state = STATE_RETRYING
                self.warning = "Rayhunter fetch failed: {}".format(exc)
                await self.emit(
                    "collector_retrying",
                    {"endpoint": self.active_hardware, "reason": self.warning},
                    "warning",
                )
            await asyncio.sleep(interval)

    def fetch_status(self, endpoint):
        """Fetch and parse one Rayhunter response."""
        parsed = self.fetch_api_status(endpoint)
        if parsed is None:
            text, content_type = self.fetch_text(endpoint)
            parsed = self.parse_response(text, content_type)
        parsed.setdefault("endpoint", endpoint)
        parsed.setdefault("reachable", True)
        return parsed

    def fetch_text(self, endpoint, accept=None):
        """Return decoded endpoint text, including gzip-encoded responses."""
        headers = {"Accept-Encoding": "gzip", "User-Agent": "Skannr"}
        if accept:
            headers["Accept"] = accept
        request = urllib.request.Request(
            endpoint,
            headers=headers,
        )
        with urllib.request.urlopen(
            request, timeout=float(self.config.get("request_timeout_sec", 10))
        ) as response:
            body = response.read()
            encoding = str(response.headers.get("Content-Encoding") or "").lower()
            content_type = response.headers.get("Content-Type") or ""
        if encoding == "gzip" or body.startswith(b"\x1f\x8b"):
            body = gzip.decompress(body)
        return body.decode("utf-8", errors="replace"), content_type

    def fetch_json(self, endpoint, path):
        """Fetch one Rayhunter JSON API endpoint."""
        url = urllib.parse.urljoin(endpoint.rstrip("/") + "/", path.lstrip("/"))
        text, content_type = self.fetch_text(url, accept="application/json")
        data = self.parse_json(text, content_type)
        return data if isinstance(data, dict) else None

    def fetch_api_status(self, endpoint):
        """Read Rayhunter's own JSON APIs instead of scraping the Svelte shell."""
        stats = {}
        manifest = {}
        try:
            stats = self.fetch_json(endpoint, "/api/system-stats")
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            stats = {}
        try:
            manifest = self.fetch_json(endpoint, "/api/qmdl-manifest")
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            manifest = {}
        if not stats and not manifest:
            return None
        config = {}
        try:
            config = self.fetch_json(endpoint, "/api/config") or {}
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            config = {}
        status = self.parse_api_status(stats or {}, manifest or {}, config)
        current = (manifest or {}).get("current_entry") or {}
        if current.get("name"):
            try:
                report_text, _ = self.fetch_text(
                    urllib.parse.urljoin(
                        endpoint.rstrip("/") + "/",
                        "/api/analysis-report/{}".format(current["name"]),
                    ),
                    accept="application/x-ndjson",
                )
                status.update(self.parse_analysis_report(report_text))
            except (urllib.error.URLError, TimeoutError, ValueError, OSError):
                pass
        status["summary"] = self.status_summary(status)
        return {key: value for key, value in status.items() if value not in ("", [], None)}

    def parse_api_status(self, stats, manifest, config):
        """Normalize the JSON objects used by Rayhunter's own dashboard."""
        disk = (stats or {}).get("disk_stats") or {}
        memory = (stats or {}).get("memory_stats") or {}
        runtime_metadata = (stats or {}).get("runtime_metadata") or {}
        battery = (stats or {}).get("battery_status") or {}
        current = (manifest or {}).get("current_entry") or {}
        gps_mode = current.get("gps_mode")
        if gps_mode is None:
            gps_mode = (config or {}).get("gps_mode")
        status = {
            "warning_count": 0,
            "latest_event": self.clean_field(current.get("last_message_time") or ""),
            "warning": "",
            "rayhunter_version": self.clean_field(
                runtime_metadata.get("rayhunter_version") or ""
            ),
            "storage": self.storage_summary(disk),
            "memory": self.memory_summary(memory),
            "battery": self.battery_summary(battery),
            "recording_id": self.clean_field(current.get("name") or ""),
            "recording_size": self.readable_bytes(current.get("qmdl_size_bytes")),
            "recording_start": self.clean_field(current.get("start_time") or ""),
            "recording_last_message": self.clean_field(
                current.get("last_message_time") or ""
            ),
            "recording_artifacts": ["pcap", "qmdl", "zip"] if current else [],
            "device_os": self.clean_field(runtime_metadata.get("system_os") or ""),
            "gps_mode": self.gps_mode_label(gps_mode),
        }
        return status

    def parse_analysis_report(self, text):
        """Count warnings and metadata from Rayhunter NDJSON analysis output."""
        warnings = 0
        metadata = {}
        metadata_seen = False
        for line in (text or "").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(sanitize_json_line(line))
            except (TypeError, ValueError):
                continue
            if not metadata_seen:
                metadata = record or {}
                metadata_seen = True
                continue
            for event in record.get("events") or []:
                if not event:
                    continue
                if event.get("event_type") != "Informational":
                    warnings += 1
        rayhunter = (metadata or {}).get("rayhunter") or {}
        parsed = {
            "warning_count": warnings,
            "warning": "{} Rayhunter warning(s)".format(warnings) if warnings else "",
            "rayhunter_version": self.clean_field(
                rayhunter.get("rayhunter_version") or ""
            ),
            "device_os": self.clean_field(rayhunter.get("system_os") or ""),
        }
        return {key: value for key, value in parsed.items() if value not in ("", [], None)}

    def parse_response(self, text, content_type=""):
        """Extract Rayhunter status fields from JSON or the HTML status page."""
        data = self.parse_json(text, content_type)
        if isinstance(data, dict):
            return self.parse_json_status(data)
        return self.parse_page_status(text)

    def parse_page_status(self, text):
        """Parse the current Rayhunter HTML/text page into reportable fields."""
        lines = self.text_lines(text)
        joined = "\n".join(lines)
        lowered = joined.lower()
        warning_count = self.warning_count_from_text(lowered)
        status = {
            "warning_count": warning_count,
            "latest_event": self.field_value(joined, "Last Message")
            or self.latest_time_from_text(joined),
            "warning": "{} Rayhunter warning(s)".format(warning_count)
            if warning_count
            else "",
            "summary": "",
            "rayhunter_version": self.rayhunter_version(joined),
            "storage": self.line_after_label(lines, "Storage"),
            "memory": self.line_after_label(lines, "Memory (RAM)"),
            "battery": self.line_after_label(lines, "Battery"),
            "recording_id": self.field_value(joined, "ID"),
            "recording_size": self.recording_size(lines),
            "recording_start": self.field_value(joined, "Start"),
            "recording_last_message": self.field_value(joined, "Last Message"),
            "recording_artifacts": self.recording_artifacts(lines),
            "device_os": self.field_value(joined, "Device system OS"),
            "gps_mode": self.field_value(joined, "GPS Mode"),
        }
        status["summary"] = self.status_summary(status)
        if not status["summary"]:
            status["summary"] = "Rayhunter status page parsed with limited fields."
        return {
            key: value
            for key, value in status.items()
            if value not in ("", [], None)
        }

    def parse_json(self, text, content_type):
        """Parse JSON responses when Rayhunter exposes structured content."""
        if "json" not in str(content_type).lower() and not text.lstrip().startswith(("{", "[")):
            return None
        try:
            return json.loads(text)
        except (TypeError, ValueError):
            return None

    def parse_json_status(self, data):
        """Normalize common JSON fields without depending on one schema."""
        warnings = data.get("warnings")
        if isinstance(warnings, list):
            warning_count = len(warnings)
        else:
            warning_count = self.to_int(
                data.get("warning_count")
                or data.get("warnings_count")
                or data.get("num_warnings")
            )
        latest = (
            data.get("latest_event")
            or data.get("latest_event_time")
            or data.get("last_seen")
            or ""
        )
        return {
            "warning_count": warning_count,
            "latest_event": self.clean_field(latest),
            "warning": "{} Rayhunter warning(s)".format(warning_count)
            if warning_count
            else "",
            "summary": self.clean_field(
                data.get("summary") or data.get("status") or ""
            ),
            "rayhunter_version": self.clean_field(
                data.get("rayhunter_version") or data.get("version") or ""
            ),
            "storage": self.clean_field(data.get("storage") or ""),
            "memory": self.clean_field(data.get("memory") or data.get("ram") or ""),
            "recording_id": self.clean_field(
                data.get("recording_id") or data.get("id") or ""
            ),
            "recording_size": self.clean_field(
                data.get("recording_size") or data.get("size") or ""
            ),
            "recording_start": self.clean_field(
                data.get("recording_start") or data.get("start") or ""
            ),
            "recording_last_message": self.clean_field(
                data.get("recording_last_message") or latest or ""
            ),
            "device_os": self.clean_field(data.get("device_os") or ""),
            "gps_mode": self.clean_field(data.get("gps_mode") or ""),
        }

    def warning_count_from_text(self, lowered):
        """Return warning count from Rayhunter HTML/text."""
        if "no warnings" in lowered or "0 warnings" in lowered:
            return 0
        match = re.search(r"(\d+)\s+warnings?", lowered)
        if match:
            return self.to_int(match.group(1))
        return 1 if "warning" in lowered else 0

    def latest_time_from_text(self, text):
        """Best-effort latest event timestamp extraction from HTML/text."""
        match = re.search(r"Last Message:\s*([^\n]+)", text or "", re.IGNORECASE)
        if match:
            return match.group(1).strip()
        match = re.search(
            r"(20\d\d[-/]\d\d[-/]\d\d[ T]\d\d:\d\d(?::\d\d)?)", text or ""
        )
        return match.group(1) if match else ""

    def text_lines(self, text):
        """Return visible page text lines from Rayhunter HTML or plain text."""
        return rayhunter_text_lines(text)

    def clean_field(self, value):
        """Return a compact text field without HTML markup."""
        return clean_rayhunter_field(value)

    def field_value(self, text, label):
        """Return a value after 'Label:' in normalized page text."""
        match = re.search(
            r"(?im)^{}\s*:\s*([^\n]+)$".format(re.escape(label)),
            text or "",
        )
        return self.clean_field(match.group(1)) if match else ""

    def line_after_label(self, lines, label):
        """Return the text following a heading-style label on one line."""
        prefix = str(label or "").lower()
        for line in lines or []:
            if line.lower().startswith(prefix):
                return self.clean_field(line[len(label):].strip(" :-"))
        return ""

    def rayhunter_version(self, text):
        """Return the Rayhunter version from status or metadata sections."""
        match = re.search(
            r"(?im)^Rayhunter\s+Version\s+([^\s<]+)$",
            text or "",
        )
        if match:
            return self.clean_field(match.group(1))
        return self.field_value(text, "Rayhunter version")

    def recording_size(self, lines):
        """Return the current recording size near the recording ID."""
        for index, line in enumerate(lines or []):
            if re.match(r"^ID:\s*\S+", line, re.IGNORECASE):
                for candidate in (lines or [])[index + 1 : index + 4]:
                    if re.match(
                        r"^\d+(?:\.\d+)?\s*[KMGT]?B$",
                        candidate,
                        re.IGNORECASE,
                    ):
                        return candidate
        return ""

    def recording_artifacts(self, lines):
        """Return available recording artifact links such as pcap/qmdl/zip."""
        artifacts = []
        for line in lines or []:
            value = line.strip().lower()
            if value in ("pcap", "qmdl", "zip"):
                artifacts.append(value)
        return artifacts

    def status_summary(self, status):
        """Return a compact operator-readable Rayhunter status summary."""
        parts = []
        if status.get("rayhunter_version"):
            parts.append("Rayhunter {}".format(status["rayhunter_version"]))
        parts.append("{} warning(s)".format(status.get("warning_count") or 0))
        if status.get("storage"):
            parts.append("storage {}".format(status["storage"]))
        if status.get("memory"):
            parts.append("RAM {}".format(status["memory"]))
        if status.get("recording_id"):
            recording = "recording {}".format(status["recording_id"])
            if status.get("recording_size"):
                recording += " {}".format(status["recording_size"])
            parts.append(recording)
        if status.get("recording_last_message"):
            parts.append("last message {}".format(status["recording_last_message"]))
        if status.get("gps_mode"):
            parts.append("GPS {}".format(status["gps_mode"]))
        return "; ".join(parts)[:500]

    def storage_summary(self, disk):
        """Return Rayhunter's displayed storage summary from API stats."""
        if not isinstance(disk, dict):
            return ""
        used_percent = self.clean_field(disk.get("used_percent") or "")
        used_size = self.clean_field(disk.get("used_size") or "")
        available_size = self.clean_field(disk.get("available_size") or "")
        if used_percent and used_size and available_size:
            return "{} used ({} used / {} available)".format(
                used_percent, used_size, available_size
            )
        return used_percent or used_size or available_size

    def memory_summary(self, memory):
        """Return Rayhunter's displayed RAM summary from API stats."""
        if not isinstance(memory, dict):
            return ""
        free = self.clean_field(memory.get("free") or "")
        used = self.clean_field(memory.get("used") or "")
        if free and used:
            return "Free: {}, Used: {}".format(free, used)
        return free or used

    def battery_summary(self, battery):
        """Return a text equivalent of Rayhunter's battery icon state."""
        if not isinstance(battery, dict) or not battery:
            return ""
        level = self.to_int(battery.get("level"))
        if level <= 0 and str(battery.get("level") or "") not in ("0", "0.0"):
            return ""
        if battery.get("is_plugged_in"):
            return "{}%, plugged in".format(level)
        return "{}%".format(level)

    def gps_mode_label(self, mode):
        """Match Rayhunter's GPS mode labels."""
        try:
            mode = int(mode)
        except (TypeError, ValueError):
            return ""
        if mode == 1:
            return "Fixed coordinates"
        if mode == 2:
            return "API endpoint"
        return "Disabled"

    def readable_bytes(self, value):
        """Return Rayhunter-style human-readable byte counts."""
        try:
            size = float(value)
        except (TypeError, ValueError):
            return ""
        if size <= 0:
            return "0 Bytes"
        units = ["Bytes", "KB", "MB", "GB", "TB"]
        index = 0
        while size >= 1024 and index < len(units) - 1:
            size /= 1024.0
            index += 1
        if index == 0:
            return "{} {}".format(int(size), units[index])
        amount = "{:.2f}".format(size).rstrip("0").rstrip(".")
        return "{} {}".format(amount, units[index])

    def to_int(self, value):
        """Parse an integer-like value safely."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0
