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
from ..paths import CONFIG_DIR, ensure_owner
from ..snapshots import load_snapshots

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
        "This is a cellular-monitor endpoint. Non-zero warnings deserve " "attention."
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


def _timeline_label(subj_id, info, collector):
    """Build a short human-readable label for a snapshot subject."""
    name = (
        info.get("name")
        or info.get("ssid")
        or info.get("callsign")
        or info.get("hostname")
        or info.get("station_name")
        or info.get("identity_label")
        or info.get("model")
        or info.get("vendor_name")
        or ""
    )
    if name and name != subj_id:
        return str(name)[:55]
    return str(subj_id)[:55]


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

        kwargs = dict(api_key=api_key, timeout=600.0)
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
        self._log_usage(inquiry, status, usage, model=str(self.config.get("model", "")))

        return {
            "answer": answer,
            "usage": _public_usage(usage, model=str(self.config.get("model", ""))),
        }

    # ── LLM call ──────────────────────────────────────────────

    # Refusal keywords for guard-rail detection.
    _REFUSAL_KEYWORDS = (
        "cannot answer",
        "can't answer",
        "cannot fulfill",
        "cannot help",
        "can't help",
        "not able to",
        "won't be able",
        "refuse to",
        "not appropriate",
        "out of scope",
        "beyond the scope",
        "i'm unable to",
        "i am unable to",
    )

    async def _call_llm(self, context, question, max_tokens, system=None, model=None):
        """Call the LLM.  Returns ``(answer_text, status, usage_dict)``.

        *status* is one of ``"ok"``, ``"refused"``, ``"no_text"``, or
        ``"error"``.
        """
        user_message = "Context:\n{}\n\nQuestion: {}".format(context, question)
        start = time.time()

        kwargs = dict(
            model=model or str(self.config.get("model", "")).strip(),
            max_tokens=max_tokens,
            system=system or self._system_prompt or "",
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
            b.text for b in response.content if getattr(b, "type", "") == "text"
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

        return (
            text,
            status,
            {
                "input_tokens": getattr(usage, "input_tokens", 0),
                "output_tokens": getattr(usage, "output_tokens", 0),
                "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", 0),
                "cache_creation_input_tokens": getattr(
                    usage, "cache_creation_input_tokens", 0
                ),
                "elapsed_sec": round(elapsed, 1),
            },
        )

    # ── Usage logging ─────────────────────────────────────────

    def _resolve_log_dir(self):
        if self._log_dir_resolved is None:
            global_config = self.config.get("_global_config") or {}
            fs = (global_config.get("persistence") or {}).get("filesystem") or {}
            base = fs.get("log_dir", "runtime/logs")
            if not os.path.isabs(base):
                # Relative to the project root, not CONFIG_DIR.
                from ..paths import PROJECT_ROOT

                base = os.path.join(PROJECT_ROOT, base)
            self._log_dir_resolved = os.path.join(base, "llm")
        return self._log_dir_resolved

    def _log_usage(self, inquiry, status, usage, model=None):
        path = self._resolve_log_dir()
        os.makedirs(path, exist_ok=True)
        ensure_owner(path)

        today = time.strftime("%Y-%m-%d")
        filepath = os.path.join(path, "{}.jsonl".format(today))

        model = model or str(self.config.get("model", "")).strip()
        prices = _PRICES.get(model, {})
        cache_read = usage.get("cache_read_input_tokens", 0)
        cache_write = usage.get("cache_creation_input_tokens", 0)
        regular = max(0, usage.get("input_tokens", 0) - cache_read - cache_write)
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
            existed = os.path.exists(filepath)
            with open(filepath, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
            if not existed:
                ensure_owner(filepath)
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
                    None,
                    "",
                    [],
                    0,
                    {},
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
        collector, match_field = self._subject_event_source(subject_type)
        if collector and subject:
            tail = int(self.config.get("context_tail_bytes", 131072))
            if match_field:
                match_value = str(subject.get(match_field) or subject_key)
                raw = self._load_raw_events(
                    collector,
                    limit=3,
                    match_field=match_field,
                    match_value=match_value,
                    tail_bytes=tail,
                )
            else:
                raw = self._load_raw_events(collector, limit=3, tail_bytes=tail)
            if raw:
                sections.append("## Recent raw events ({})".format(collector))
                for i, event in enumerate(raw):
                    sections.append(
                        "Event {}: {}".format(
                            i + 1, json.dumps(self._compact_event(event), default=str)
                        )
                    )

        if not sections:
            sections.append("(No data for {} {})".format(subject_type, subject_key))

        return "\n\n".join(sections)

    # ── Data access ───────────────────────────────────────────

    def _load_subject_history(self):
        path = os.path.join(
            self._resolve_log_dir(), "..", "device_history", "subject_history.json"
        )
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
            if (
                isinstance(s, dict)
                and (s.get("subject_id") or s.get("id") or "") == subject_key
            ):
                return s
        # Try common prefixed forms (e.g. "ssid:xfinitywifi" from "xfinitywifi").
        for prefix in ("ssid:", "bluetooth:", "ip:", "gateway:"):
            for s in subjects:
                sid = s.get("subject_id") or s.get("id") or ""
                if isinstance(s, dict) and sid == prefix + subject_key:
                    return s
        # Try matching on the display subject/label field.
        for s in subjects:
            if (
                isinstance(s, dict)
                and (s.get("subject") or s.get("label") or "") == subject_key
            ):
                return s
        return None

    def _load_annotation(self, source, subject_type, subject_key):
        path = os.path.join(
            self._resolve_log_dir(), "..", "device_history", "subject_annotations.json"
        )
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

    def _load_raw_events(
        self, collector, limit=5, match_field=None, match_value=None, tail_bytes=131072
    ):
        import glob

        coll_dir = os.path.join(os.path.dirname(self._resolve_log_dir()), collector)
        if not os.path.isdir(coll_dir):
            return []
        files = sorted(glob.glob(os.path.join(coll_dir, "*.jsonl")), reverse=True)
        events = []
        for path in files:
            if len(events) >= limit:
                break
            try:
                size = os.path.getsize(path)
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
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
                            data = event.get("data") if isinstance(event, dict) else {}
                            val = (
                                data.get(match_field)
                                if isinstance(data, dict)
                                else None
                            )
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
            "fields": (
                {
                    k: v
                    for k, v in (data.items() if isinstance(data, dict) else [])
                    if k not in ("timestamp", "timestamp_epoch", "monitor_interface")
                    and not isinstance(v, (list, dict))
                }
                if isinstance(data, dict)
                else {}
            ),
        }

    # ── 24h presence timeline ──────────────────────────────────

    # Maximum hours in a "Delta Since Last Report" timeline block.  A SKIR
    # generated more than a day after the previous one would otherwise emit
    # unbounded-length presence masks and inflate the LLM context budget.
    MAX_DELTA_HOURS = 96

    @staticmethod
    def _format_presence_timeline(snap_list, title):
        """Build and format a presence timeline from *snap_list*.

        *snap_list* must be a chronologically-ordered list of snapshot dicts.
        Returns a formatted text block with per-subject presence masks and
        classification labels.
        """
        if len(snap_list) < 2:
            return ""
        n_hours = len(snap_list)
        first_label = snap_list[0].get("hour_start", "?")
        last_label = snap_list[-1].get("hour_start", "?")

        from collections import OrderedDict

        timeline = OrderedDict()

        for idx, snap in enumerate(snap_list):
            for coll, coll_data in snap.items():
                if coll.startswith("_") or coll in ("hour_start", "hour_start_epoch"):
                    continue
                if not isinstance(coll_data, dict):
                    continue
                subs = coll_data.get("subjects") or {}
                if not isinstance(subs, dict):
                    continue
                if coll not in timeline:
                    timeline[coll] = OrderedDict()
                for subj_id, info in subs.items():
                    if not isinstance(info, dict):
                        continue
                    if subj_id not in timeline[coll]:
                        timeline[coll][subj_id] = {
                            "mask": ["·"] * n_hours,
                            "count": 0,
                            "first_idx": n_hours,
                            "last_idx": -1,
                            "info": info,
                        }
                    entry = timeline[coll][subj_id]
                    if entry["last_idx"] < idx:
                        entry["info"] = info
                    entry["mask"][idx] = "■"
                    entry["count"] += 1
                    if idx < entry["first_idx"]:
                        entry["first_idx"] = idx
                    if idx > entry["last_idx"]:
                        entry["last_idx"] = idx

        lines = [
            "## {title} ({first} → {last})".format(
                title=title, first=first_label, last=last_label
            ),
            "Legend: ■ present  · absent  [C]=continuous [I]=intermittent "
            "[T]=transient [A]=appeared [D]=departed",
            "",
        ]

        for coll in sorted(timeline):
            entries = timeline[coll]
            cats = {"C": [], "I": [], "T": [], "A": [], "D": []}
            # Thresholds: proportional to window size.  The continuous bound
            # is integer-ceiled so it never understates the 90% claim made
            # in the SKIR prompt (int(24*0.90)=21 would label 87.5% as
            # continuous); the transient bound floors at ≤20% of hours.
            _continuous_min = max(1, (n_hours * 90 + 99) // 100)
            _transient_max = max(1, int(n_hours * 0.20))
            _edge_hours = max(1, n_hours // 4)
            for subj_id, e in entries.items():
                mask_str = "".join(e["mask"])
                info = e["info"]
                label = _timeline_label(subj_id, info, coll)
                line = "  {label} | {mask} | {n}/{total}h".format(
                    label=label[:55], mask=mask_str, n=e["count"], total=n_hours
                )

                # Classification
                first_edge = sum(1 for ch in e["mask"][:_edge_hours] if ch == "■")
                last_edge = sum(1 for ch in e["mask"][-_edge_hours:] if ch == "■")
                if e["count"] >= _continuous_min:
                    cats["C"].append((label, e["count"], ""))
                elif e["count"] <= _transient_max:
                    if first_edge == 0 and last_edge > 0:
                        cats["A"].append(line + " | appeared")
                    elif first_edge > 0 and last_edge == 0:
                        cats["D"].append(
                            line
                            + " | departed h{first}-h{last}".format(
                                first=e["first_idx"], last=e["last_idx"]
                            )
                        )
                    else:
                        span = ""
                        if e["count"] > 0:
                            span = " | h{first}-h{last}".format(
                                first=e["first_idx"], last=e["last_idx"]
                            )
                        cats["T"].append(line + span)
                else:
                    if first_edge == 0 and last_edge > 0:
                        cats["A"].append(
                            line + " | appeared h{first}".format(first=e["first_idx"])
                        )
                    elif first_edge > 0 and last_edge == 0:
                        cats["D"].append(
                            line + " | departed h{last}".format(last=e["last_idx"])
                        )
                    else:
                        cats["I"].append(
                            line
                            + " | h{first}-h{last}".format(
                                first=e["first_idx"], last=e["last_idx"]
                            )
                        )

            total_active = sum(len(v) for v in cats.values())
            parts = ["{coll}: {n} active".format(coll=coll, n=total_active)]
            for cat, label in [
                ("C", "continuous"),
                ("I", "intermittent"),
                ("T", "transient"),
                ("A", "appeared"),
                ("D", "departed"),
            ]:
                if cats[cat]:
                    parts.append("{n} {label}".format(n=len(cats[cat]), label=label))
            lines.append("### " + ", ".join(parts))

            # Continuous: just count, no per-subject lines
            if cats["C"]:
                names = [c[0] for c in cats["C"][:8]]
                lines.append(
                    "  [C] {n} continuous: {names}{more}".format(
                        n=len(cats["C"]),
                        names=", ".join(names),
                        more="..." if len(cats["C"]) > 8 else "",
                    )
                )

            # Intermittent: show all (usually few)
            for line in cats["I"][:15]:
                lines.append("  [I]" + line)
            if len(cats["I"]) > 15:
                lines.append(
                    "  ... and {n} more intermittent".format(n=len(cats["I"]) - 15)
                )

            # Transient: show all (usually few)
            for line in cats["T"][:10]:
                lines.append("  [T]" + line)
            if len(cats["T"]) > 10:
                lines.append(
                    "  ... and {n} more transient".format(n=len(cats["T"]) - 10)
                )

            # Appeared / Departed: always show all
            for line in cats["A"]:
                lines.append("  [A]" + line)
            for line in cats["D"]:
                lines.append("  [D]" + line)

            lines.append("")

        return "\n".join(lines)

    def _sh_snapshots_dir(self):
        """Return the sh_snapshots directory under the configured log dir.

        Writers (`main.py` snapshot hooks) resolve the configured runtime log
        dir the same way; the reader must match or the timelines go silently
        empty when ``persistence.filesystem.log_dir`` is customized.
        """
        base = os.path.dirname(self._resolve_log_dir())
        return os.path.join(base, "sh_snapshots")

    def _build_presence_timeline(self, snapshots=None, snapshot_dir=None):
        """Return a 24h presence timeline for the current window.

        *snapshots* is a pre-loaded snapshot dict shared with the delta
        builder so one SKIR build parses the directory once.  When omitted,
        snapshots are loaded from *snapshot_dir* (defaults to the configured
        runtime log dir's ``sh_snapshots``).
        """
        if snapshots is None:
            if snapshot_dir is None:
                snapshot_dir = self._sh_snapshots_dir()
            snapshots = load_snapshots(snapshot_dir)
        if not snapshots:
            return ""
        hours = sorted(snapshots.keys())[-24:]
        if len(hours) < 2:
            return ""
        return self._format_presence_timeline(
            [snapshots[h] for h in hours], "24h Presence Timeline"
        )

    def _build_delta_timeline(self, snapshots=None, snapshot_dir=None):
        """Return a presence timeline for the gap between the previous
        SKIR and the current 24h window, or None if no prior SKIR exists.

        The current window is the last 24 snapshot FILES; the delta is the
        stretch before it.  Aligning both on the same axis avoids overlap
        and off-by-one gaps when snapshot coverage is gappy.  Note the delta
        is empty unless snapshot retention exceeds the 24h current window —
        ``snapshot_retention_hours`` must be > 24 for this section to exist.
        """
        if snapshots is None:
            if snapshot_dir is None:
                snapshot_dir = self._sh_snapshots_dir()
            snapshots = load_snapshots(snapshot_dir)
        if not snapshots:
            return None
        last_skir = self.load_latest_skir(
            log_dir=os.path.dirname(self._skir_dir())
        )
        if not last_skir:
            return None
        last_epoch = last_skir.get("generated_at_epoch")
        if not last_epoch:
            return None
        all_hours = sorted(snapshots.keys())
        if len(all_hours) < 2:
            return None
        current_hours = all_hours[-24:]
        cutoff = current_hours[0]
        delta_hours = [h for h in all_hours if last_epoch <= h < cutoff]
        if len(delta_hours) < 2:
            return None
        # Cap the delta length: a SKIR > 24h old could otherwise produce
        # 100+ hour mask strings per subject and blow the SKIR token budget.
        delta_hours = delta_hours[-MAX_DELTA_HOURS:]
        return self._format_presence_timeline(
            [snapshots[h] for h in delta_hours],
            "Delta Since Last Report",
        )

    # ── SKIR: Skannr Intelligence Report ─────────────────────────

    def build_skir_context(self, report_bundle, subjects=None):
        """Build LLM context from reports + full subject data.

        Includes ALL subjects per collector so the LLM can do forensic
        cross-subject analysis (e.g. which 4 TPMS sensors form one car),
        not just summarize what ReportsBuilder already found.
        """
        reports = report_bundle.get("reports") or []
        window = report_bundle.get("window") or {}
        counts = report_bundle.get("counts") or {}
        sections = []

        # ── Header ──
        label = window.get("label", "unknown")
        days = window.get("days", "?")
        gen = report_bundle.get("generated_at", "unknown")
        sections.append(
            "## Period: {label} ({days}d) — {gen}\n"
            "Reports: {total} total ({w} warning, {i} info)".format(
                label=label,
                days=days,
                gen=gen,
                total=counts.get("total", len(reports)),
                w=counts.get("warning", 0),
                i=counts.get("info", 0),
            )
        )

        # ── Subject data by collector (FULL, per-collector) ──
        if subjects:
            by_coll = {}
            for s in subjects:
                coll = str(s.get("collector") or "unknown")
                by_coll.setdefault(coll, []).append(s)

            active = sorted(by_coll)
            skipped = [c for c in active if len(by_coll[c]) == 0]
            sections.append(
                "## Collectors with data: {active}\n"
                "## Collectors with NO data (skip in report): {skip}".format(
                    active=", ".join(active) if active else "none",
                    skip=", ".join(skipped) if skipped else "none",
                )
            )

            for coll in active:
                items = by_coll[coll]
                if not items:
                    continue
                # Separate collector health subjects — always include them
                # so the LLM has evidence for outage/recovery reporting.
                health_items = []
                data_items = []
                for s in items:
                    st = str(s.get("subject_type") or "")
                    if st.endswith("_collector"):
                        health_items.append(s)
                    else:
                        data_items.append(s)
                # Limit data subjects: most active first
                data_items = sorted(
                    data_items,
                    key=lambda s: (
                        s.get("event_count")
                        or s.get("seen_count")
                        or s.get("observation_count")
                        or 0
                    ),
                    reverse=True,
                )[:60]
                items = health_items + data_items
                sections.append(
                    "## Subjects: {coll} ({n} items)".format(coll=coll, n=len(items))
                )
                # Keep only essential fields per subject
                _KEEP_FIELDS = {
                    "subject_id",
                    "subject",
                    "collector",
                    "subject_type",
                    "custom_name",
                    "operator_owned",
                    "first_seen",
                    "last_seen",
                    "event_count",
                    "vendor_name",
                    "vendor_prefix",
                    "manufacturer",
                    "identity_label",
                    "names",
                    "name",
                    "ssid",
                    "ssids",
                    "encryption",
                    "channels",
                    "bands",
                    "signal_max",
                    "signal_min",
                    "bssid",
                    "mac",
                    "hostname",
                    "ips",
                    "ip",
                    "sessions",
                    "days_seen",
                    "active_session",
                    "presence_hours",
                    "lost_count",
                    "session_count",
                    "seen_count",
                    "update_count",
                    "findmy_accessory",
                    "findmy_status",
                    "findmy_label",
                    "service_uuids",
                    "adv_data_hex",
                    "protocol",
                    "pressure_PSI",
                    "temperature_F",
                    "temperature_C",
                    "frequency_mhz",
                    "rssi",
                    "snr",
                    "day_night",
                    "usual_hour",
                    "repeat_gap_avg_sec",
                    "status",
                    "tpms_samples",
                    "magnitude",
                    "depth_km",
                    "place",
                    "distance_km",
                    "tsunami",
                    "callsign",
                    "speed_kmh",
                    "distance_km",
                    "course_deg",
                    "altitude_ft",
                    "ground_speed_kt",
                    "track_deg",
                    "icao",
                    "airline_icao",
                    "squawk",
                    "emergency",
                    "temperature_f",
                    "pressure_hpa",
                    "rain_1h_in",
                    "wind_mph",
                    "gust_mph",
                    "humidity_pct",
                    "observation_count",
                    "identify_count",
                    "change_count",
                    "sources",
                    "interfaces",
                    "data",
                    "reason",
                    "error",
                }
                for s in items:
                    compact = {}
                    for k, v in s.items():
                        if k.startswith("_"):
                            continue
                        if k not in _KEEP_FIELDS:
                            continue
                        if v in (None, "", [], {}):
                            continue
                        if v == 0 and k not in ("warning_count", "error_count"):
                            continue
                        if isinstance(v, list):
                            v = [str(x) for x in v[:3]]
                        if isinstance(v, str) and len(v) > 120:
                            v = v[:117] + "..."
                        if isinstance(v, (int, float, str, list, bool)):
                            compact[k] = v
                        elif isinstance(v, dict):
                            for dk, dv in v.items():
                                # 0 is meaningful for counters like warning_count,
                                # error_count — "0 warnings" is important information.
                                if dv in (None, "", [], {}):
                                    continue
                                if dv == 0 and dk not in (
                                    "warning_count",
                                    "error_count",
                                ):
                                    continue
                                if isinstance(dv, list):
                                    dv = [str(x) for x in dv[:3]]
                                if isinstance(dv, str) and len(dv) > 120:
                                    dv = dv[:117] + "..."
                                if isinstance(dv, (int, float, str, list, bool)):
                                    compact[dk] = dv
                    if len(compact) >= 2:
                        sections.append(
                            json.dumps(compact, default=str, sort_keys=True)
                        )
            sections.append("")  # blank line after subject data

        # ── 24h presence timeline ──
        snapshots = load_snapshots(self._sh_snapshots_dir())
        timeline = self._build_presence_timeline(snapshots=snapshots)
        if timeline:
            sections.append(timeline)

        # ── Delta since last report ──
        delta = self._build_delta_timeline(snapshots=snapshots)
        if delta:
            sections.append(delta)

        # ── Priority reports with evidence ──
        priority = [
            r
            for r in reports
            if r.get("severity") == "warning"
            and r.get("confidence") == "High"
            and r.get("score", 0) >= 75
        ]
        if priority:
            lines = ["## Priority Reports ({} items)".format(len(priority))]
            for r in priority[:20]:
                ev = r.get("evidence") or {}
                alert = (
                    " [UNACKED ALERT]"
                    if (ev.get("active_alert") and not ev.get("alert_acked"))
                    else ""
                )
                lines.append(
                    "- [{src}] {title}: {summary} "
                    "(score={sc}, conf={cf}{al})".format(
                        src=r.get("source", "?"),
                        title=r.get("title", ""),
                        summary=r.get("summary", "")[:200],
                        sc=r.get("score", 0),
                        cf=r.get("confidence", "?"),
                        al=alert,
                    )
                )
            sections.append("\n".join(lines))

        return "\n\n".join(sections)

    async def generate_skir(self, window_days=7):
        """Generate a Skannr Intelligence Report from the current report bundle.

        Returns a SKIR dict with sections keyed for frontend rendering,
        or ``{"error": str}`` on failure.
        """
        if not self._client:
            self.detect()
        if not self._client:
            return {"error": self.warning or "LLM is not available."}

        bundle = self._load_report_bundle(window_days)
        if not bundle or not bundle.get("reports"):
            return {"error": "No report data available for SKIR generation."}

        sh = self._load_subject_history()
        subjects = sh.get("subjects") if isinstance(sh, dict) else None

        context = self.build_skir_context(bundle, subjects=subjects)
        skir_prompt = self._build_skir_system_prompt(bundle)
        max_tok = int(self.config.get("skir_max_tokens", 65536))

        skir_model = str(self.config.get("skir_model") or "").strip() or None
        effective = skir_model or str(self.config.get("model", ""))
        logging.info(
            "SKIR model=%s max_tokens=%s context_chars=%s",
            effective,
            max_tok,
            len(context),
        )
        answer, status, usage = await self._call_llm(
            context, skir_prompt, max_tok, system=self._system_prompt, model=skir_model
        )

        inquiry = "skir:{}d".format(window_days)
        self._log_usage(
            inquiry,
            status,
            usage,
            model=skir_model or str(self.config.get("model", "")),
        )

        if status == "error":
            return {"error": answer}

        # Try to parse JSON from the response
        skir = self._parse_skir_response(answer, bundle, usage)
        if skir is None:
            # Fallback: return raw text as the only section
            skir = self._skir_fallback(answer, bundle, usage)

        self._save_skir(skir)
        return skir

    def _build_skir_system_prompt(self, bundle):
        """Return the SKIR-generation system prompt."""
        window = bundle.get("window") or {}
        label = window.get("label", "unknown")
        return (
            "You are Skannr's RF intelligence analyst. You receive:\n"
            "1. Per-collector SUBJECT DATA — every device/signal/event "
            "Skannr observed, with full fields (identity, timing, signal, "
            "protocol-specific data).\n"
            "2. Priority REPORTS — what the deterministic engine flagged.\n\n"
            "Your job: analyze the SUBJECT DATA to find patterns the "
            "deterministic engine MISSED. The reports are hints; the subjects "
            "are the truth.\n\n"
            "PER-COLLECTOR ANALYSIS REQUIRED:\n"
            "- **rtl433**: Group sensors by protocol. Within each protocol "
            "group, find sets of 4 with correlated timing and similar "
            "temperature/pressure — these are one vehicle. Identify vehicle "
            "type from protocol+pressure. Report resident vs pass-through "
            "(multi-day vs single-window), day/night pattern. For non-TPMS "
            "devices (security sensors, weather stations, remotes): identify "
            "device type from protocol, note any alert patterns.\n"
            "- **ble**: Group by manufacturer/name. Separate privacy-rotating "
            "devices (multiple MACs, same identity, correlated timing) from "
            "genuinely separate devices. Classify: static (always present), "
            "mobile (intermittent, variable RSSI), transient (seen once). "
            "Identify Find My / tracker devices. Map the operator's device "
            "ecosystem (smart home, wearables, vehicles).\n"
            "- **wifi**: Group BSSIDs by SSID into networks. Per network: "
            "channel spread, band coverage (2.4/5/6 GHz), encryption type, "
            "vendor mix. Identify open/weak networks. Which network is the "
            "operator's? (strongest signal, most BSSIDs, most persistent). "
            "Which are neighbors? Detect hidden SSIDs, intermittent hotspots.\n"
            "- **wifi_monitor**: Analyze client probes, deauth/disassociation "
            "frames, association patterns. Which clients probe for which "
            "SSIDs? Any disruption bursts (possible attacks)? Randomized vs "
            "static client MACs. Cross-reference with wifi APs: which clients "
            "associate with which BSSIDs?\n"
            "- **lan**: Map network topology. Gateway(s), infrastructure "
            "(APs, switches), clients. Identify roles from hostnames, mDNS "
            "/SSDP services, OUI vendor. Track changes: new/removed devices, "
            "gateway changes, IP churn. Apple ecosystem vs IoT vs "
            "workstations.\n"
            "- **adsb**: Identify operators from callsigns. Emergency squawks "
            "(7700/7600/7500). Low-altitude aircraft near the node. Repeated "
            "routes/callsigns = regular traffic. Altitude/speed anomalies.\n"
            "- **aprsis**: Mobile vs fixed stations. Mobile: speed, distance, "
            "route patterns. Weather stations: temperature, wind, rain. "
            "Objects/events. Corroborate with PWS and NOAA.\n"
            "- **noaa**: Most severe weather alerts in window. Tropical "
            "systems: storm track, advisory progression. Tsunami bulletins: "
            "magnitude, depth, warning level. Forecast deltas.\n"
            "- **usgs**: Earthquakes by magnitude and distance. Aftershock "
            "patterns. Correlate with NOAA tsunami bulletins.\n"
            "- **swpc**: Space weather events by scale (R/S/G). X-ray flux, "
            "Kp index, storm levels. Impact on radio/GPS.\n"
            "- **pws**: Personal weather station data. Temperature range, "
            "rain totals, wind/gust max, pressure trends. Corroborate with "
            "APRS weather and NOAA forecasts.\n"
            "- **rayhunter**: Cellular monitoring status. "
            "**warning_count** is the Rayhunter device's own count of "
            "cell-site simulator / IMSI catcher alerts (the security signal). "
            "**warning_events_in_window** is a Skannr collector metric that "
            "includes harmless connectivity retries — ignore it for security "
            "analysis. Only flag Rayhunter when warning_count > 0.\n\n"
            "PRESENCE TIMELINE:\n"
            "Two presence timeline sections may appear:\n"
            "1. '24h Presence Timeline' — the last 24 hours (current state).\n"
            "2. 'Delta Since Last Report' — hours between the previous SKIR\n"
            "   generation and 24h ago (what happened since you last looked).\n"
            "Compare them to identify what CHANGED since the last report:\n"
            "- Subjects in Current but NOT in Delta = new arrivals.\n"
            "- Subjects in Delta but NOT in Current = recently departed.\n"
            "- Subjects whose count/pattern changed significantly.\n"
            "Use this to produce a 'What changed' section instead of only\n"
            "describing the current state. Mention specific subjects and\n"
            "time windows. Example: 'BLE tracker Tile-4A2F appeared at\n"
            "hour 20 and stayed (absent in delta), while the garage door\n"
            "sensor (present in delta, h12-h18) has not been seen in the\n"
            "current 24h window.'\n"
            "Classifications (proportional to window size):\n"
            "  [C] Continuous (≥90% of hours) = resident.\n"
            "  [I] Intermittent (20-90%) = comes and goes.\n"
            "  [T] Transient (≤20%) = brief visitor.\n"
            "  [A] Appeared = absent early, present late.\n"
            "  [D] Departed = present early, absent late.\n\n"
            "CROSS-COLLECTOR ANALYSIS:\n"
            "Find connections the deterministic pipeline cannot:\n"
            "- Wi-Fi client MAC == LAN MAC? Same device on two layers.\n"
            "- BLE device vendor == Wi-Fi AP vendor? Same ecosystem.\n"
            "- TPMS vehicle timing == ADS-B low aircraft? Proximity to airport.\n"
            "- APRS weather + PWS weather + NOAA forecast? Corroborating "
            "surface conditions.\n"
            "- USGS earthquake + NOAA tsunami? Related geophysical events.\n"
            "- LAN gateway change + new Wi-Fi AP? Network reconfiguration.\n"
            "- BLE tracker + Wi-Fi hotspot in same time window? Possible "
            "mobile visitor.\n\n"
            "OUTPUT — JSON object with these sections:\n"
            "1. **bluf** (array of strings): 5-8 SPECIFIC bullets. Every "
            "bullet names actual devices, frequencies, magnitudes. Not 'WiFi "
            "landscape is stable' but 'eero mesh (6 BSSIDs, ch 1/6/36, open "
            "guest on 30:3a:4a:70:31:e7 at -44 dBm) dominates 2.4/5 GHz'.\n"
            "2. **collector_analysis** (object): One key per collector with "
            "data. Each value: {{summary, findings: [{{finding, evidence, "
            "confidence, reasoning}}]}}. Deep per-collector analysis goes "
            "here.\n"
            "3. **cross_collector** (array): Patterns spanning multiple "
            "collectors that the deterministic pipeline cannot detect. Each: "
            "{{finding, collectors (array), evidence, confidence, reasoning}}. "
            "Examples: same MAC seen by wifi_monitor + lan; BLE vendor matches "
            "Wi-Fi AP vendor (same ecosystem); TPMS timing correlates with "
            "ADS-B low aircraft; USGS quake + NOAA tsunami bulletin.\n"
            "4. **anomalies_alerts** (array): Actionable items. Each: "
            "{{level, summary, source, action}}. Unacked alerts + anomalous "
            "patterns. Skip acked alerts.\n"
            "5. **confidence** (array of objects): 3-5 key findings. "
            "Each: {{finding (string), confidence (high/medium/low), "
            "reasoning (string)}}. Explain WHY you are confident or uncertain "
            "using RF-specific evidence (signal strength consistency, MAC "
            "vendor match, temporal correlation, protocol fingerprinting).\n"
            "6. **implications**: What this means for the operator.\n"
            "7. **overview**: One-paragraph summary.\n\n"
            "RULES:\n"
            "- Skip collectors with NO data. Do not mention them anywhere.\n"
            "- Analyze the SUBJECT DATA, not just the reports. Find what the "
            "deterministic engine didn't.\n"
            "- Be specific. Name devices, protocols, frequencies, MACs.\n"
            "- Synthesize across subjects. Multiple sensors = one vehicle. "
            "Multiple BSSIDs = one network. Multiple MACs = one device.\n"
            "- Do NOT report collector feed status. Focus on collected data.\n"
            "- No hedged language. Direct, declarative.\n"
            "- **operator_owned**: a boolean flag on some subjects. When true, "
            "the operator has confirmed this device is theirs. Attribute it to "
            "the operator with confidence. When absent or false, NEVER guess "
            'or imply ownership — say "a" not "the operator\'s." Only '
            "operator_owned=true means ownership is confirmed.\n"
            "ownership.\n"
            "- Return ONLY the JSON object, no markdown fences, no intro text.\n"
            "Window: {label}".format(label=label)
        )

    def _parse_skir_response(self, text, bundle, usage):
        """Parse LLM response text into the SKIR JSON schema."""
        clean = text.strip()
        # Strip markdown code fences: ```json ... ``` or ``` ... ```
        import re

        # Remove opening fence: ```json or ``` optionally preceded by text
        clean = re.sub(r"^.*?```(?:json)?\s*\n?", "", clean, flags=re.DOTALL)
        # Remove closing fence
        clean = re.sub(r"\n?```\s*$", "", clean)
        clean = clean.strip()
        # If the JSON was truncated (no closing brace), try to recover
        if not clean.endswith("}") and clean.startswith("{"):
            # Find the last complete key:value or array element
            # and close the structure
            clean = clean.rstrip(",\n\r\t ") + "\n}}"
        try:
            parsed = json.loads(clean)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed, dict):
            return None
        window = bundle.get("window") or {}
        return {
            "report_id": "SKIR-{}".format(time.strftime("%Y%m%d-%H%M")),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "generated_at_epoch": int(time.time()),
            "period": {
                "start": window.get("since", ""),
                "end": time.strftime("%Y-%m-%d %H:%M:%S"),
                "days": window.get("days"),
            },
            "model": str(self.config.get("skir_model") or self.config.get("model", "")),
            "usage": _public_usage(
                usage,
                model=str(
                    self.config.get("skir_model") or self.config.get("model", "")
                ),
            ),
            "bluf": parsed.get("bluf") or [],
            "collector_analysis": parsed.get("collector_analysis") or {},
            "cross_collector": parsed.get("cross_collector") or [],
            "anomalies_alerts": parsed.get("anomalies_alerts") or [],
            "confidence_assessment": parsed.get("confidence") or [],
            "implications": parsed.get("implications") or "",
            "overview": parsed.get("overview") or "",
            "appendix": {
                "total_reports": len(bundle.get("reports") or []),
                "total_warnings": (bundle.get("counts") or {}).get("warning", 0),
                "active_alerts": sum(
                    1
                    for r in (bundle.get("reports") or [])
                    if (r.get("evidence") or {}).get("active_alert")
                ),
            },
        }

    def _skir_fallback(self, text, bundle, usage):
        """Return a minimal SKIR when JSON parsing fails."""
        window = bundle.get("window") or {}
        return {
            "report_id": "SKIR-{}".format(time.strftime("%Y%m%d-%H%M")),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "generated_at_epoch": int(time.time()),
            "period": {
                "start": window.get("since", ""),
                "end": time.strftime("%Y-%m-%d %H:%M:%S"),
                "days": window.get("days"),
            },
            "model": str(self.config.get("model", "")),
            "usage": _public_usage(
                usage,
                model=str(
                    self.config.get("skir_model") or self.config.get("model", "")
                ),
            ),
            "bluf": ["(LLM returned unstructured text — see raw response)"],
            "source_summary": [],
            "significant_detections": [],
            "anomalies_alerts": [],
            "confidence_assessment": [],
            "implications": "",
            "overview": text[:2000],
            "appendix": {
                "total_reports": len(bundle.get("reports") or []),
                "parse_error": True,
            },
        }

    # ── SKIR persistence ────────────────────────────────────────

    def _skir_dir(self):
        base = os.path.dirname(self._resolve_log_dir())
        return os.path.join(base, "skir")

    def _save_skir(self, skir):
        """Persist SKIR to disk and write latest.json."""
        d = self._skir_dir()
        os.makedirs(d, exist_ok=True)
        ensure_owner(d)
        ts = time.strftime("%Y-%m-%dT%H-%M")
        path = os.path.join(d, "{}.json".format(ts))
        latest = os.path.join(d, "latest.json")
        body = json.dumps(skir, indent=2, default=str, sort_keys=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        ensure_owner(path)
        with open(latest, "w", encoding="utf-8") as fh:
            fh.write(body)
        ensure_owner(latest)

    @staticmethod
    def load_latest_skir(log_dir=None):
        """Return the most recent SKIR dict, or None."""
        if log_dir is None:
            from ..paths import RUNTIME_LOG_DIR

            log_dir = RUNTIME_LOG_DIR
        path = os.path.join(log_dir, "skir", "latest.json")
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None

    @staticmethod
    def list_skirs(log_dir=None):
        """Return a list of available SKIR metadata dicts, newest first."""
        if log_dir is None:
            from ..paths import RUNTIME_LOG_DIR

            log_dir = RUNTIME_LOG_DIR
        skir_dir = os.path.join(log_dir, "skir")
        if not os.path.isdir(skir_dir):
            return []
        items = []
        for fname in sorted(os.listdir(skir_dir), reverse=True):
            if fname == "latest.json" or not fname.endswith(".json"):
                continue
            fpath = os.path.join(skir_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    skir = json.load(fh)
                items.append(
                    {
                        "report_id": skir.get("report_id", fname),
                        "generated_at": skir.get("generated_at", ""),
                        "generated_at_epoch": skir.get("generated_at_epoch", 0),
                        "bluf": (skir.get("bluf") or [])[:3],
                        "period": skir.get("period", {}),
                    }
                )
            except (OSError, json.JSONDecodeError, KeyError):
                continue
        return items

    @staticmethod
    def load_skir_by_id(log_dir, report_id):
        """Return a specific SKIR dict by report_id, or None."""
        if log_dir is None:
            from ..paths import RUNTIME_LOG_DIR

            log_dir = RUNTIME_LOG_DIR
        skir_dir = os.path.join(log_dir, "skir")
        if not os.path.isdir(skir_dir):
            return None
        # Try direct filename match first: SKIR-20260628-1756 → 2026-06-28T17-56
        ts_part = report_id.replace("SKIR-", "")
        if len(ts_part) == 13:  # YYYYMMDD-HHMM
            fname = "{}-{}-{}T{}-{}.json".format(
                ts_part[:4], ts_part[4:6], ts_part[6:8], ts_part[9:11], ts_part[11:13]
            )
            fpath = os.path.join(skir_dir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8") as fh:
                        return json.load(fh)
                except (OSError, json.JSONDecodeError):
                    pass
        # Fallback: scan all files
        for fname in sorted(os.listdir(skir_dir), reverse=True):
            if fname == "latest.json" or not fname.endswith(".json"):
                continue
            fpath = os.path.join(skir_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    skir = json.load(fh)
                if skir.get("report_id") == report_id:
                    return skir
            except (OSError, json.JSONDecodeError):
                continue
        return None

    def _load_report_bundle(self, window_days=7):
        """Load the current reports.json bundle from disk."""
        reports_path = os.path.join(
            os.path.dirname(self._resolve_log_dir()), "device_history", "reports.json"
        )
        reports_path = os.path.normpath(reports_path)
        if not os.path.exists(reports_path):
            return None
        try:
            with open(reports_path, "r", encoding="utf-8") as fh:
                bundle = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None
        # If the window doesn't match, still use what's on disk
        return bundle


def _public_usage(usage, model=None):
    result = {
        "input_tokens": usage.get("input_tokens", 0),
        "output_tokens": usage.get("output_tokens", 0),
        "cache_read": usage.get("cache_read_input_tokens", 0),
        "cache_write": usage.get("cache_creation_input_tokens", 0),
        "elapsed_sec": usage.get("elapsed_sec", 0),
    }
    if model:
        prices = _PRICES.get(model, {})
        cache_read_tok = result["cache_read"]
        cache_write_tok = result["cache_write"]
        regular_tok = max(0, result["input_tokens"] - cache_read_tok - cache_write_tok)
        cost = (
            cache_read_tok * prices.get("input_cache_hit", 0)
            + (regular_tok + cache_write_tok) * prices.get("input_cache_miss", 0)
            + result["output_tokens"] * prices.get("output", 0)
        ) / 1_000_000
        result["cost"] = round(cost, 6)
    return result
