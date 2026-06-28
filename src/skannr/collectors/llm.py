"""LLM-powered subject analysis ("Analyze" button on detail panels).

Gated behind ``~/.config/skannr/collectors/llm.yaml`` — file absent or
``enabled: false`` and the feature is hidden.  Uses the Anthropic SDK
over an Anthropic-compatible endpoint (e.g. DeepSeek).  Each request is
logged to ``runtime/logs/llm/YYYY-MM-DD.jsonl`` with token usage and cost.
"""

import json
import logging
import os
import time

from .base import BaseCollector, STATE_OFFLINE, STATE_ONLINE
from ..paths import CONFIG_DIR


# ── Pricing per 1M tokens (USD) ──────────────────────────────────
# Check for updates at https://api-docs.deepseek.com/quick_start/pricing/
_PRICES = {
    "deepseek-v4-flash": {
        "input_cache_hit": 0.0028,
        "input_cache_miss": 0.14,
        "output": 0.28,
    },
    "deepseek-v4-pro": {
        "input_cache_hit": 0.003625,
        "input_cache_miss": 0.435,
        "output": 0.87,
    },
}


# ── Analytical framing per subject type ──────────────────────────
# The system prompt already describes each collector.  These hints tell
# the LLM what to focus on for this specific observation.
_COLLECTOR_FRAMING = {
    "wifi_bssid": (
        "This is an access point BSSID. Focus on vendor identity from "
        "the OUI, channel/encryption choices, and whether the MAC is "
        "locally administered (randomized)."
    ),
    "wifi_ssid": (
        "This is an SSID profile that may span multiple BSSIDs. Focus on "
        "multi-BSSID implications, vendor diversity, and security spread."
    ),
    "wifi_client": (
        "This is a Wi-Fi client seen via monitor-mode. It sends probes, "
        "associates, or appears in deauth/disassoc frames — it does not "
        "beacon. Focus on what its probe behavior and channel use reveal."
    ),
    "wifi_client_group": (
        "This is a group of randomized Wi-Fi clients. Treat as one "
        "privacy-rotating device."
    ),
    "bluetooth_device": (
        "This is a BLE device from advertisement data only — not a GATT "
        "connection. Focus on the manufacturer ID and advertised name."
    ),
    "bluetooth_device_group": (
        "This is a group of BLE devices sharing a name or manufacturer. "
        "Treat as one privacy-rotating device."
    ),
    "rtl433_device": (
        "This is a decoded ISM-band device — could be TPMS, weather "
        "sensor, security contact, utility meter, or remote. Focus on "
        "what the model and ID suggest about the device type."
    ),
    "adsb_aircraft": (
        "This is an aircraft. Focus on operator identity from callsign, "
        "flight patterns from route, and unusual altitude/speed/emergency."
    ),
    "aprsis_weather": "This is an internet-fed weather station, not local RF.",
    "aprsis_mobile": "This is an internet-fed mobile APRS station.",
    "aprsis_station": "This is an internet-fed APRS station or object.",
    "rayhunter_status": (
        "This is a cellular-monitor endpoint. Non-zero warnings deserve "
        "attention."
    ),
    "noaa_weather_alert": (
        "This is a weather alert. Focus on severity, area, and whether "
        "it has upgraded or expired."
    ),
    "noaa_tropical_advisory": (
        "This is a tropical advisory. Focus on the storm track and "
        "advisory-number progression."
    ),
    "noaa_forecast_summary": (
        "This is a point forecast. Focus on deltas from the previous "
        "forecast and near-term precipitation."
    ),
    "noaa_tsunami_alert": (
        "This is a tsunami bulletin. Focus on magnitude, depth, and "
        "whether it is a Warning/Watch/Advisory or Information Statement."
    ),
    "usgs_earthquake": (
        "This is an earthquake event. Focus on magnitude, depth, "
        "distance from the configured point, and tsunami flag."
    ),
    "swpc_event": (
        "This is a space-weather event. Focus on the scale (R/S/G/Kp) "
        "and whether it crosses the alert threshold."
    ),
    "pws_station": (
        "This is a personal weather station. Focus on rain-rate changes, "
        "wind gusts, pressure trends, and temperature deltas."
    ),
    "lan_device": (
        "This is a LAN device seen via passive observation. Focus on "
        "vendor from MAC OUI, hostname, and mDNS/SSDP service clues."
    ),
    "lan_gateway": (
        "This is a LAN default gateway. Focus on whether it changed — "
        "a new MAC or IP for the gateway role is notable."
    ),
}


class LLMCollector(BaseCollector):
    """On-demand LLM analysis of Skannr subject detail records."""

    config_key = "llm"
    name = "LLM"
    tab_label = "LLM"

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self._client = None
        self._system_prompt = None
        self._log_dir = None
        self._log_dir_resolved = None

    # ── Lifecycle ─────────────────────────────────────────────

    def detect(self):
        model = str(self.config.get("model") or "").strip()
        api_key = str(self.config.get("api_key") or "").strip()
        if not model or not api_key:
            self.state = STATE_OFFLINE
            self.warning = "LLM model or api_key not configured."
            return False

        try:
            import anthropic
        except ImportError:
            self.state = STATE_OFFLINE
            self.warning = "Python package 'anthropic' is not installed."
            return False

        kwargs = dict(api_key=api_key)
        base_url = str(self.config.get("base_url") or "").strip()
        if base_url:
            kwargs["base_url"] = base_url

        try:
            self._client = anthropic.AsyncAnthropic(**kwargs)
        except Exception as exc:
            self.state = STATE_OFFLINE
            self.warning = "Failed to create client: {}".format(exc)
            return False

        self._load_system_prompt()
        self.state = STATE_ONLINE
        self.warning = None
        return True

    def _load_system_prompt(self):
        from ..paths import DATA_DIR
        path = os.path.join(DATA_DIR, "llm_system_prompt.md")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                self._system_prompt = fh.read().strip()

    # ── Analyze ───────────────────────────────────────────────

    async def analyze(self, subject_key, subject_type):
        """Build per-subject context, call the LLM, log usage.

        Returns ``{"answer": str, "usage": dict}`` or ``{"error": str}``.
        """
        if not self._client:
            self.detect()
        if not self._client:
            return {"error": self.warning or "LLM is not available."}

        context = self._build_subject_context(subject_key, subject_type)
        frame = _COLLECTOR_FRAMING.get(subject_type, "")
        if frame:
            context = "Observation: {}\n\n{}".format(frame, context)

        question = (
            "Analyze this subject. Synthesize across the fields above. "
            "Use your training knowledge about wireless vendors, device "
            "naming conventions, chipsets, protocols, sensor types, "
            "aircraft operators, seismic patterns, or anything else "
            "relevant. Do not restate fields the operator can already "
            "read — tell them what this observation MEANS."
        )

        max_tok = int(self.config.get("analyze_max_tokens", 2048))
        answer, status, usage = await self._call_llm(context, question, max_tok)

        inquiry = "analyze {}:{}".format(subject_type, subject_key)
        self._log_usage(inquiry, status, usage)

        return {"answer": answer, "usage": _public_usage(usage)}

    # ── LLM call ──────────────────────────────────────────────

    # Refusal keywords for guard-rail detection.
    _REFUSAL_KEYWORDS = (
        "cannot answer", "can't answer", "cannot fulfill",
        "cannot help", "can't help", "not able to",
        "won't be able", "refuse to", "not appropriate",
        "out of scope", "beyond the scope",
        "i'm unable to", "i am unable to",
    )

    async def _call_llm(self, context, question, max_tokens):
        """Call the LLM.  Returns ``(answer_text, status, usage_dict)``.

        *status* is one of ``"ok"``, ``"refused"``, ``"no_text"``, or
        ``"error"``.
        """
        user_message = "Context:\n{}\n\nQuestion: {}".format(context, question)
        start = time.time()

        kwargs = dict(
            model=str(self.config.get("model", "")).strip(),
            max_tokens=max_tokens,
            system=self._system_prompt or "",
            messages=[{"role": "user", "content": user_message}],
        )
        if max_tokens > 512:
            kwargs["thinking"] = {
                "type": "enabled",
                "budget_tokens": max_tokens // 2,
            }

        try:
            response = await self._client.messages.create(**kwargs)
        except Exception:
            try:
                del kwargs["thinking"]
                response = await self._client.messages.create(**kwargs)
            except Exception as exc:
                return ("LLM call failed: {}".format(exc), "error", {})

        elapsed = time.time() - start
        text = "".join(
            b.text for b in response.content
            if getattr(b, "type", "") == "text"
        )
        usage = getattr(response, "usage", None)

        if not text:
            blocks = [getattr(b, "type", "?") for b in response.content]
            text = "(no text — blocks: {})".format(", ".join(blocks))
            status = "no_text"
        elif any(kw in text.lower() for kw in self._REFUSAL_KEYWORDS):
            status = "refused"
        else:
            status = "ok"

        return text, status, {
            "input_tokens": getattr(usage, "input_tokens", 0),
            "output_tokens": getattr(usage, "output_tokens", 0),
            "cache_read_input_tokens": getattr(
                usage, "cache_read_input_tokens", 0),
            "cache_creation_input_tokens": getattr(
                usage, "cache_creation_input_tokens", 0),
            "elapsed_sec": round(elapsed, 1),
        }

    # ── Usage logging ─────────────────────────────────────────

    def _resolve_log_dir(self):
        if self._log_dir_resolved is None:
            global_config = self.config.get("_global_config") or {}
            fs = (global_config.get("persistence") or {}).get(
                "filesystem") or {}
            base = fs.get("log_dir", "runtime/logs")
            if not os.path.isabs(base):
                # Relative to the project root, not CONFIG_DIR.
                from ..paths import PROJECT_ROOT
                base = os.path.join(PROJECT_ROOT, base)
            self._log_dir_resolved = os.path.join(base, "llm")
        return self._log_dir_resolved

    def _log_usage(self, inquiry, status, usage):
        path = self._resolve_log_dir()
        os.makedirs(path, exist_ok=True)

        today = time.strftime("%Y-%m-%d")
        filepath = os.path.join(path, "{}.jsonl".format(today))

        model = str(self.config.get("model", "")).strip()
        prices = _PRICES.get(model, {})
        cache_read = usage.get("cache_read_input_tokens", 0)
        cache_write = usage.get("cache_creation_input_tokens", 0)
        regular = max(
            0, usage.get("input_tokens", 0) - cache_read - cache_write)
        cost = (
            cache_read * prices.get("input_cache_hit", 0)
            + (regular + cache_write) * prices.get("input_cache_miss", 0)
            + usage.get("output_tokens", 0) * prices.get("output", 0)
        ) / 1_000_000

        record = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "model": model,
            "status": status,
            "inquiry": inquiry,
            "in": usage.get("input_tokens", 0),
            "out": usage.get("output_tokens", 0),
            "cache_read": cache_read,
            "cache_write": cache_write,
            "elapsed": usage.get("elapsed_sec", 0),
            "cost": round(cost, 6),
        }

        try:
            with open(filepath, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
        except OSError as exc:
            logging.warning("LLM usage log write failed: %s", exc)

    # ── Context assembly ──────────────────────────────────────

    def _build_subject_context(self, subject_key, subject_type):
        sh = self._load_subject_history()
        sections = []

        subject = self._find_subject(sh, subject_key)

        if subject:
            identity = {}
            for key, value in subject.items():
                if not key.startswith("_") and value not in (
                    None, "", [], 0, {},
                ):
                    identity[key] = value
            sections.append("## Subject record")
            sections.append(json.dumps(identity, indent=2, default=str))

            src = subject.get("collector") or ""
            ann = self._load_annotation(src, subject_type, subject_key)
            if ann:
                sections.append("## Operator annotation")
                sections.append(json.dumps(ann, indent=2, default=str))

        # Raw events for subjects with a matching collector
        collector, match_field = self._subject_event_source(
            subject_type)
        if collector and subject:
            tail = int(self.config.get("context_tail_bytes", 131072))
            if match_field:
                match_value = str(
                    subject.get(match_field) or subject_key)
                raw = self._load_raw_events(
                    collector, limit=3,
                    match_field=match_field, match_value=match_value,
                    tail_bytes=tail)
            else:
                raw = self._load_raw_events(
                    collector, limit=3, tail_bytes=tail)
            if raw:
                sections.append(
                    "## Recent raw events ({})".format(collector))
                for i, event in enumerate(raw):
                    sections.append("Event {}: {}".format(
                        i + 1,
                        json.dumps(self._compact_event(event),
                                   default=str)))

        if not sections:
            sections.append(
                "(No data for {} {})".format(subject_type, subject_key))

        return "\n\n".join(sections)

    # ── Data access ───────────────────────────────────────────

    def _load_subject_history(self):
        path = os.path.join(
            self._resolve_log_dir(), "..", "device_history",
            "subject_history.json")
        path = os.path.normpath(path)
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _find_subject(sh, subject_key):
        subjects = sh.get("subjects", [])
        if not isinstance(subjects, list):
            return None
        # Exact match first.
        for s in subjects:
            if isinstance(s, dict) and (
                s.get("subject_id") or s.get("id") or ""
            ) == subject_key:
                return s
        # Try common prefixed forms (e.g. "ssid:xfinitywifi" from "xfinitywifi").
        for prefix in ("ssid:", "bluetooth:", "ip:", "gateway:"):
            for s in subjects:
                sid = s.get("subject_id") or s.get("id") or ""
                if isinstance(s, dict) and sid == prefix + subject_key:
                    return s
        # Try matching on the display subject/label field.
        for s in subjects:
            if isinstance(s, dict) and (
                s.get("subject") or s.get("label") or ""
            ) == subject_key:
                return s
        return None

    def _load_annotation(self, source, subject_type, subject_key):
        path = os.path.join(
            self._resolve_log_dir(), "..", "device_history",
            "subject_annotations.json")
        path = os.path.normpath(path)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None
        anns = data.get("annotations", {})
        if not isinstance(anns, dict):
            return None
        key = "{}|{}|{}".format(source, subject_type, subject_key)
        return anns.get(key)

    @staticmethod
    def _subject_event_source(subject_type):
        """Return (collector, match_field) for raw event lookup."""
        mapping = {
            "wifi_client": ("wifi_monitor", "client_mac"),
            "wifi_access_point": ("wifi", "bssid"),
            "wifi_bssid": ("wifi", "bssid"),
            "bluetooth_device": ("ble", "mac"),
            "bluetooth_device_group": ("ble", "mac"),
            "lan_device": ("lan", "mac"),
            "rtl433_device": ("rtl433", None),
            "adsb_aircraft": ("adsb", None),
            "aprsis_weather": ("aprsis", None),
            "aprsis_mobile": ("aprsis", None),
            "aprsis_station": ("aprsis", None),
            "noaa_weather_alert": ("noaa", None),
            "noaa_tropical_advisory": ("noaa", None),
            "noaa_forecast_summary": ("noaa", None),
            "noaa_tsunami_alert": ("noaa", None),
            "usgs_earthquake": ("usgs", None),
            "swpc_event": ("swpc", None),
            "pws_station": ("pws", None),
            "rayhunter_status": ("rayhunter", None),
            "lan_gateway": ("lan", "gateway_ip"),
        }
        return mapping.get(subject_type, (None, None))

    def _load_raw_events(self, collector, limit=5, match_field=None,
                         match_value=None, tail_bytes=131072):
        import glob
        coll_dir = os.path.join(
            os.path.dirname(self._resolve_log_dir()), collector)
        if not os.path.isdir(coll_dir):
            return []
        files = sorted(
            glob.glob(os.path.join(coll_dir, "*.jsonl")), reverse=True)
        events = []
        for path in files:
            if len(events) >= limit:
                break
            try:
                size = os.path.getsize(path)
                with open(path, "r", encoding="utf-8",
                          errors="replace") as fh:
                    if tail_bytes and size > tail_bytes:
                        fh.seek(max(0, size - tail_bytes))
                        fh.readline()
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if match_field is not None:
                            data = (event.get("data")
                                    if isinstance(event, dict) else {})
                            val = (data.get(match_field)
                                   if isinstance(data, dict) else None)
                            if str(val) != str(match_value):
                                continue
                        events.append(event)
                        if len(events) >= limit:
                            break
            except OSError:
                continue
        return events

    @staticmethod
    def _compact_event(event):
        data = event.get("data") if isinstance(event, dict) else {}
        return {
            "type": event.get("type"),
            "collector": event.get("collector"),
            "timestamp": event.get("timestamp"),
            "fields": {
                k: v for k, v in (
                    data.items() if isinstance(data, dict) else [])
                if k not in ("timestamp", "timestamp_epoch",
                             "monitor_interface")
                and not isinstance(v, (list, dict))
            } if isinstance(data, dict) else {},
        }


def _public_usage(usage):
    return {
        "input_tokens": usage.get("input_tokens", 0),
        "output_tokens": usage.get("output_tokens", 0),
        "cache_read": usage.get("cache_read_input_tokens", 0),
        "cache_write": usage.get("cache_creation_input_tokens", 0),
        "elapsed_sec": usage.get("elapsed_sec", 0),
    }
