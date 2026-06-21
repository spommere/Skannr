"""Optional rtl_433 decoded ISM-band device collector."""

import asyncio
import hashlib
import json
import logging
import os
import re
import shlex
import shutil

from .base import BaseCollector, STATE_OFFLINE, STATE_ONLINE


RTL433_FIELD_MAX = 240
RTL433_MAX_RAW_KEYS = 80
RTL433_DEFAULT_DWELL_SEC = 30


def compact_rtl433_text(value, max_length=RTL433_FIELD_MAX):
    """Return compact one-line rtl_433 text."""
    if value in (None, ""):
        return ""
    text = " ".join(str(value).replace("\x00", " ").split())
    return text[:max_length] if text else ""


def rtl433_float(value):
    """Parse a numeric rtl_433 value."""
    try:
        return float(value)
    except (TypeError, ValueError):
        match = re.search(r"[-+]?[0-9]+(?:\.[0-9]+)?", str(value or ""))
        if not match:
            return None
        try:
            return float(match.group(0))
        except ValueError:
            return None


def rtl433_int(value):
    """Parse an integer-like rtl_433 value."""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def clean_rtl433_data(data):
    """Scrub rtl_433 payloads before persistence and derived summaries."""
    if not isinstance(data, dict):
        return {}
    cleaned = {}
    numeric_keys = {
        "timestamp_epoch",
        "event_time_epoch",
        "frequency_mhz",
        "tuned_frequency_mhz",
        "rssi_db",
        "snr_db",
        "noise_db",
        "protocol",
        "seen_count",
        "first_seen_epoch",
        "last_seen_epoch",
        "event_count",
        "burst_count",
        "burst_gap_min_sec",
        "burst_gap_max_sec",
        "burst_gap_avg_sec",
        "recent_observation_count",
        "pressure_kpa",
        "pressure_psi",
        "pressure_bar",
        "pressure_kpa_min",
        "pressure_kpa_max",
        "pressure_psi_min",
        "pressure_psi_max",
        "temperature_c",
        "temperature_f",
        "temperature_c_min",
        "temperature_c_max",
        "temperature_f_min",
        "temperature_f_max",
    }
    for key, value in data.items():
        if value in (None, "", []):
            continue
        if key in numeric_keys:
            cleaned[key] = value
        elif isinstance(value, dict):
            nested = clean_rtl433_raw(value)
            if nested:
                cleaned[key] = nested
        elif isinstance(value, list):
            items = []
            for item in value[:20]:
                if isinstance(item, dict):
                    nested = clean_rtl433_raw(item)
                    if nested:
                        items.append(nested)
                else:
                    text = compact_rtl433_text(item, 80)
                    if text:
                        items.append(text)
            if items:
                cleaned[key] = items
        else:
            text = compact_rtl433_text(value)
            if text:
                cleaned[key] = text
    return cleaned


def clean_rtl433_raw(data):
    """Return a bounded representation of arbitrary rtl_433 JSON fields."""
    if not isinstance(data, dict):
        return {}
    output = {}
    for index, key in enumerate(sorted(data)):
        if index >= RTL433_MAX_RAW_KEYS:
            output["_truncated"] = True
            break
        value = data.get(key)
        if value in (None, "", []):
            continue
        if isinstance(value, (int, float, bool)):
            output[str(key)[:80]] = value
        elif isinstance(value, dict):
            nested = clean_rtl433_raw(value)
            if nested:
                output[str(key)[:80]] = nested
        elif isinstance(value, list):
            output[str(key)[:80]] = [
                compact_rtl433_text(item, 80) for item in value[:20]
            ]
        else:
            output[str(key)[:80]] = compact_rtl433_text(value, 160)
    return output


class RTL433Collector(BaseCollector):
    """Run rtl_433 and publish decoded ISM-band device events."""

    config_key = "rtl433"
    name = "RTL-433"
    tab_label = "RTL-433"
    required_hardware = "RTL-SDR USB dongle and rtl_433"
    subject_history_event_types = (
        "rtl433_event",
        "scanner_started",
        "collector_offline",
        "collector_retrying",
    )

    @classmethod
    def hardware_status(cls, config):
        """Return rtl_433 executable availability and configured plan."""
        return {
            "rtl_433": bool(shutil.which("rtl_433")),
            "frequency_plan": config.get("frequency_plan") or "",
            "device_index": config.get("device_index", 0),
        }

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self._process = None
        self._stderr_task = None
        self._plan = []
        self._plan_summary = ""
        self._current_frequency_mhz = None

    def status(self):
        """Return collector status plus current rtl_433 tuning state."""
        status = super().status()
        process_started = bool(self._process and self._process.returncode is None)
        fixed_frequency = fixed_plan_frequency_mhz(self._plan)
        current_frequency = self._current_frequency_mhz
        if current_frequency is not None:
            status.update({
                "current_frequency_mhz": round(current_frequency, 6),
                "frequency_mhz": round(current_frequency, 6),
            })
        if fixed_frequency is not None:
            status.update({
                "planned_frequency_mhz": round(fixed_frequency, 6),
                "fixed_plan_running": process_started,
                "source": "configured plan",
            })
        elif current_frequency is not None:
            status.update({
                "source": "rtl_433 status",
            })
        status.update({
            "frequency_plan": self.config.get("frequency_plan") or "",
            "frequency_summary": self._plan_summary,
            "process_started": process_started,
            "device_index": self.config.get("device_index", 0),
        })
        return status

    def detect(self):
        """Validate rtl_433 and parse the configured frequency plan."""
        command = rtl433_command(self.config)
        if not command:
            self.active_hardware = None
            self.state = STATE_OFFLINE
            self.warning = "rtl_433 command not found"
            return False
        try:
            self._plan = parse_frequency_plan(
                self.config.get("frequency_plan") or "433.92:30"
            )
        except ValueError as exc:
            self.active_hardware = None
            self.state = STATE_OFFLINE
            self.warning = "Invalid rtl_433 frequency plan: {}".format(exc)
            return False
        self._plan_summary = summarize_frequency_plan(self._plan)
        self._current_frequency_mhz = fixed_plan_frequency_mhz(self._plan)
        self.active_hardware = "RTL-SDR index {}".format(
            self.config.get("device_index", 0)
        )
        self.state = STATE_ONLINE
        self.warning = None
        return True

    async def start(self):
        """Run rtl_433 until stopped, retrying after transient dongle failures."""
        self._running = True
        while self._running:
            if not self.detect():
                reason = self.warning or "rtl_433 detection failed"
                if reason.startswith("Invalid rtl_433 frequency plan"):
                    await self.emit("collector_offline", {"reason": reason}, "warning")
                    return
                await self.retrying(reason)
                continue

            command = rtl433_command(self.config)
            args = rtl433_args(self.config, self._plan)
            logging.info(
                "Starting rtl_433 command=%s args=%s device_index=%s frequency_plan=%s "
                "frequency_summary=%s",
                command,
                " ".join(shlex.quote(str(item)) for item in args),
                self.config.get("device_index", 0),
                self.config.get("frequency_plan") or "",
                self._plan_summary,
            )
            try:
                self._process = await asyncio.create_subprocess_exec(
                    command,
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                self._stderr_task = asyncio.get_event_loop().create_task(
                    self.drain_stderr()
                )
                self.state = STATE_ONLINE
                self.warning = None
                await self.emit(
                    "scanner_started",
                    {
                        "frequency_plan": self.config.get("frequency_plan") or "",
                        "frequency_summary": self._plan_summary,
                        "scan_frequencies_mhz": [
                            item.get("frequency_mhz") for item in self._plan
                        ],
                        "planned_frequency_mhz": self._current_frequency_mhz,
                        "source": "configured plan" if self._current_frequency_mhz is not None else None,
                        "process_started": True,
                        "gain": self.config.get("gain", "auto"),
                        "sample_rate": self.config.get("sample_rate", "250k"),
                        "decoder": "rtl_433",
                    },
                )
            except Exception as exc:
                await self.retrying("rtl_433 start failed: {}".format(exc))
                await self.stop_process()
                continue

            while self._running:
                line = await self._process.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    logging.debug("rtl_433 non-json stdout: %s", text[:500])
                    continue
                if rtl433_scanner_state_payload(payload):
                    frequency = rtl433_payload_frequency_mhz(payload, "center_frequency")
                    if frequency is not None:
                        self._current_frequency_mhz = frequency
                        await self.emit(
                            "scanner_frequency",
                            {
                                "frequency_mhz": frequency,
                                "frequency_summary": self._plan_summary,
                                "device_index": self.config.get("device_index", 0),
                                "source": "rtl_433 stdout",
                            },
                        )
                    continue
                data = rtl433_event_data(
                    payload, self._plan_summary, self._current_frequency_mhz
                )
                await self.emit("rtl433_event", data, severity_for_rtl433(data))

            if self._running:
                if self._process:
                    await self._process.wait()
                code = self._process.returncode if self._process else None
                reason = "rtl_433 exited with status {}".format(code)
                await self.retrying(reason, sleep=False)
                await self.stop_process()
                await self.retry_sleep()
            else:
                await self.stop_process()

    async def stop(self):
        """Terminate rtl_433 before marking the collector stopped."""
        await self.stop_process()
        await super().stop()

    async def stop_process(self):
        """Terminate the managed rtl_433 process."""
        if self._process and self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=3)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
        if self._stderr_task and not self._stderr_task.done():
            self._stderr_task.cancel()
        self._process = None
        self._stderr_task = None

    async def drain_stderr(self):
        """Prevent rtl_433 stderr from filling its pipe and blocking decodes."""
        if not self._process or not self._process.stderr:
            return
        while True:
            line = await self._process.stderr.readline()
            if not line:
                return
            text = line.decode("utf-8", errors="replace").rstrip()
            frequency = stderr_frequency_mhz(text)
            if frequency is not None:
                self._current_frequency_mhz = frequency
                await self.emit(
                    "scanner_frequency",
                    {
                        "frequency_mhz": frequency,
                        "frequency_summary": self._plan_summary,
                        "source": "rtl_433 stderr",
                    },
                )
            logging.debug("rtl_433 stderr: %s", text)

def rtl433_command(config):
    """Return the configured or default rtl_433 command path."""
    command = compact_rtl433_text(config.get("command"), 300)
    if command:
        resolved = shutil.which(command)
        if resolved:
            return resolved
        logging.warning(
            "Configured rtl_433 command %s was not found; trying rtl_433 fallback",
            command,
        )
    return shutil.which("rtl_433") or ""


def rtl433_args(config, plan):
    """Build rtl_433 command arguments for the configured plan."""
    args = [
        "-d",
        str(config.get("device_index", 0)),
        "-F",
        "json",
        "-M",
        "time:iso:utc",
        "-M",
        "protocol",
        "-M",
        "level",
        "-C",
        str(config.get("units", "native") or "native"),
    ]
    gain = str(config.get("gain", "auto")).strip()
    if gain and gain.lower() != "auto":
        args.extend(["-g", gain])
    sample_rate = compact_rtl433_text(config.get("sample_rate"), 40)
    if sample_rate:
        args.extend(["-s", sample_rate])
    ppm = config.get("ppm")
    if ppm not in (None, ""):
        args.extend(["-p", str(ppm)])
    for protocol in config.get("protocols") or []:
        args.extend(["-R", str(protocol)])
    for protocol in config.get("disabled_protocols") or []:
        text = str(protocol)
        args.extend(["-R", text if text.startswith("-") else "-{}".format(text)])
    for item in plan:
        args.extend(["-f", "{}M".format(trim_float(item["frequency_mhz"]))])
        if item.get("dwell_sec") > 0:
            args.extend(["-H", str(item["dwell_sec"])])
    for item in config.get("extra_args") or []:
        text = compact_rtl433_text(item, 500)
        if text:
            args.append(text)
    return args


def parse_frequency_plan(text):
    """Parse Skannr rtl433 frequency-plan syntax into per-frequency hops."""
    plan = []
    for raw_part in str(text or "").split(","):
        part = raw_part.strip()
        if not part:
            continue
        fields = [field.strip() for field in part.split(":")]
        if len(fields) not in (2, 3):
            raise ValueError("{} must be freq:dwell or start-end:step_khz:dwell".format(part))
        target = fields[0]
        if "-" in target:
            if len(fields) != 3:
                raise ValueError("{} range requires step_khz and dwell".format(part))
            start_text, end_text = [item.strip() for item in target.split("-", 1)]
            start = parse_frequency_mhz(start_text)
            end = parse_frequency_mhz(end_text)
            step_khz = rtl433_float(fields[1])
            dwell = parse_dwell(fields[2])
            if start is None or end is None or step_khz is None or step_khz <= 0:
                raise ValueError("{} has invalid range or step".format(part))
            if end < start:
                raise ValueError("{} range end is below start".format(part))
            step_mhz = step_khz / 1000.0
            current = start
            while current <= end + 0.000001:
                plan.append(
                    {
                        "frequency_mhz": round(current, 6),
                        "dwell_sec": dwell,
                        "range": "{}-{}".format(trim_float(start), trim_float(end)),
                        "step_khz": step_khz,
                    }
                )
                current += step_mhz
            continue
        dwell = parse_dwell(fields[1])
        frequency = parse_frequency_mhz(target)
        if frequency is None:
            raise ValueError("{} has invalid frequency".format(part))
        plan.append({"frequency_mhz": frequency, "dwell_sec": dwell})
    if not plan:
        raise ValueError("frequency plan is empty")
    if len(plan) > 1:
        for item in plan:
            if item.get("dwell_sec") <= 0:
                item["dwell_sec"] = RTL433_DEFAULT_DWELL_SEC
    return plan


def parse_frequency_mhz(value):
    """Parse frequency text into MHz; bare numbers are MHz by UI contract."""
    text = str(value or "").strip().lower()
    match = re.match(r"^([0-9]+(?:\.[0-9]+)?)(hz|khz|mhz|m|ghz|g)?$", text)
    if not match:
        return None
    number = rtl433_float(match.group(1))
    unit = match.group(2) or "mhz"
    if number is None:
        return None
    if unit == "hz":
        number /= 1000000.0
    elif unit == "khz":
        number /= 1000.0
    elif unit in ("ghz", "g"):
        number *= 1000.0
    return round(number, 6)


def parse_dwell(value):
    """Parse dwell seconds; zero/negative means fixed/unlimited for one frequency."""
    dwell = rtl433_float(value)
    if dwell is None:
        raise ValueError("invalid dwell {}".format(value))
    if dwell <= 0:
        return -1
    return int(dwell) if float(dwell).is_integer() else dwell


def fixed_plan_frequency_mhz(plan):
    """Return the fixed MHz value for a single unlimited-frequency plan."""
    if len(plan or []) != 1:
        return None
    item = (plan or [None])[0] or {}
    if item.get("range") or item.get("dwell_sec", 0) > 0:
        return None
    return item.get("frequency_mhz")


def summarize_frequency_plan(plan):
    """Return compact operator-facing frequency plan text."""
    ranges = []
    singles = []
    seen_ranges = set()
    for item in plan:
        if item.get("range"):
            key = (item.get("range"), item.get("step_khz"), item.get("dwell_sec"))
            if key not in seen_ranges:
                seen_ranges.add(key)
                ranges.append(
                    "{} MHz step {} kHz dwell {}s".format(
                        item.get("range"),
                        trim_float(item.get("step_khz")),
                        item.get("dwell_sec"),
                    )
                )
        else:
            dwell = item.get("dwell_sec")
            suffix = "fixed" if dwell <= 0 else "dwell {}s".format(dwell)
            singles.append("{} MHz {}".format(trim_float(item.get("frequency_mhz")), suffix))
    return ", ".join(singles + ranges)


def rtl433_event_data(payload, plan_summary, current_frequency_mhz=None):
    """Normalize one rtl_433 JSON payload while preserving raw fields."""
    raw = clean_rtl433_raw(payload)
    model = first_text(payload, "model", "type")
    channel = first_text(payload, "channel", "subtype")
    identifier = first_text(payload, "id", "device", "sensor_id", "code", "uid")
    protocol = rtl433_int(payload.get("protocol"))
    decoded_frequency = first_number(payload, "freq", "frequency", "frequency_MHz")
    frequency = decoded_frequency if decoded_frequency is not None else current_frequency_mhz
    if frequency is not None and frequency > 10000:
        frequency = frequency / 1000000.0
    elif frequency is not None and frequency > 1000:
        frequency = frequency / 1000.0
    tuned_frequency = current_frequency_mhz if current_frequency_mhz is not None else frequency
    subject_key = rtl433_subject_key(model, identifier, channel, protocol, raw)
    category = rtl433_category(model, raw)
    data = {
        "model": model,
        "id": identifier,
        "channel": channel,
        "protocol": protocol,
        "frequency_mhz": round(frequency, 6) if frequency is not None else None,
        "tuned_frequency_mhz": round(tuned_frequency, 6) if tuned_frequency is not None else None,
        "rssi_db": first_number(payload, "rssi", "rssi_db", "RSSI"),
        "snr_db": first_number(payload, "snr", "snr_db", "SNR"),
        "noise_db": first_number(payload, "noise", "noise_db", "Noise"),
        "event_time": first_text(payload, "time"),
        "subject_key": subject_key,
        "category": category,
        "frequency_plan": plan_summary,
        "raw": raw,
    }
    data.update(rtl433_tpms_fields(payload, category))
    return clean_rtl433_data(data)


def rtl433_tpms_fields(payload, category):
    """Return conservative TPMS-specific fields from a decoded rtl_433 payload."""
    if category != "tpms":
        return {}
    data = {}
    pressure_kpa = first_number(
        payload,
        "pressure_kPa",
        "pressure_kpa",
        "pressure_kpa_1",
        "pressure_kpa_2",
        "pressure_kPa_1",
        "pressure_kPa_2",
    )
    pressure_psi = first_number(
        payload,
        "pressure_PSI",
        "pressure_psi",
        "pressure_psi_1",
        "pressure_psi_2",
    )
    pressure_bar = first_number(payload, "pressure_bar", "pressure_Bar")
    if pressure_kpa is None and pressure_psi is not None:
        pressure_kpa = pressure_psi / 0.1450377377
    if pressure_psi is None and pressure_kpa is not None:
        pressure_psi = pressure_kpa * 0.1450377377
    if pressure_bar is None and pressure_kpa is not None:
        pressure_bar = pressure_kpa / 100.0
    if pressure_kpa is not None:
        data["pressure_kpa"] = round(pressure_kpa, 1)
    if pressure_psi is not None:
        data["pressure_psi"] = round(pressure_psi, 1)
    if pressure_bar is not None:
        data["pressure_bar"] = round(pressure_bar, 2)
    temperature_c = first_number(
        payload,
        "temperature_C",
        "temperature_c",
        "temperature_1_C",
        "temperature_2_C",
        "temperature_C_1",
        "temperature_C_2",
    )
    temperature_f = first_number(payload, "temperature_F", "temperature_f")
    if temperature_f is None and temperature_c is not None:
        temperature_f = temperature_c * 9.0 / 5.0 + 32.0
    if temperature_c is None and temperature_f is not None:
        temperature_c = (temperature_f - 32.0) * 5.0 / 9.0
    if temperature_c is not None:
        data["temperature_c"] = round(temperature_c, 1)
    if temperature_f is not None:
        data["temperature_f"] = round(temperature_f, 1)
    battery = first_text(
        payload,
        "battery",
        "battery_ok",
        "battery_low",
        "battery_mV",
        "battery_V",
    )
    if battery:
        data["battery_status"] = battery
    status = first_text(payload, "status", "state", "flags")
    if status:
        data["tpms_status"] = status
    position = first_text(payload, "tire", "tyre", "wheel", "position")
    if position:
        data["tpms_position"] = position
    return data


def rtl433_scanner_state_payload(payload):
    """Return True for rtl_433 frequency-hop status rows, not device decodes."""
    if not isinstance(payload, dict):
        return False
    if "center_frequency" not in payload:
        return False
    if "frequencies" not in payload and "hop_times" not in payload:
        return False
    decoded_keys = {
        "model",
        "type",
        "id",
        "device",
        "sensor_id",
        "code",
        "uid",
        "channel",
        "subtype",
        "protocol",
        "time",
        "rssi",
        "rssi_db",
        "snr",
        "snr_db",
        "noise",
        "noise_db",
    }
    return not any(key in payload for key in decoded_keys)


def rtl433_payload_frequency_mhz(payload, key):
    """Return one rtl_433 payload frequency in MHz."""
    frequency = rtl433_float((payload or {}).get(key))
    if frequency is None:
        return None
    if frequency > 10000:
        frequency /= 1000000.0
    elif frequency > 1000:
        frequency /= 1000.0
    return round(frequency, 6)


def rtl433_subject_key(model, identifier, channel, protocol, raw):
    """Return a stable subject key for a decoded rtl_433 device/event source."""
    parts = [
        compact_rtl433_text(model, 80).lower(),
        compact_rtl433_text(identifier, 80).lower(),
        compact_rtl433_text(channel, 40).lower(),
        str(protocol or ""),
    ]
    if any(parts):
        return "|".join(parts)
    digest = hashlib.sha1(
        json.dumps(raw or {}, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]
    return "unknown|{}".format(digest)


def rtl433_category(model, raw):
    """Classify broad rtl_433 device family for reports and optional alerts."""
    text = " ".join(
        [compact_rtl433_text(model, 100)]
        + [compact_rtl433_text(value, 80) for value in (raw or {}).values()]
    ).lower()
    if "tpms" in text or "tire" in text or "tyre" in text:
        return "tpms"
    if any(word in text for word in ("door", "contact", "garage", "keyfob", "remote", "security", "alarm")):
        return "security"
    if any(word in text for word in ("weather", "temperature", "humidity", "rain", "wind")):
        return "weather"
    if any(word in text for word in ("meter", "utility", "water", "power", "energy")):
        return "utility"
    return "device"


def severity_for_rtl433(data):
    """Return baseline event severity; alerts decide operator attention."""
    category = data.get("category")
    return "warning" if category in ("tpms", "security") else "info"


def first_text(payload, *keys):
    """Return the first non-empty compact string from payload."""
    for key in keys:
        value = compact_rtl433_text((payload or {}).get(key))
        if value:
            return value
    return ""


def first_number(payload, *keys):
    """Return the first parseable number from payload."""
    for key in keys:
        value = rtl433_float((payload or {}).get(key))
        if value is not None:
            return value
    return None


def stderr_frequency_mhz(text):
    """Parse an rtl_433 tuning frequency from a diagnostic line."""
    if not re.search(
        r"\b(freq(?:uency)?|tuned|tuning|center)\b",
        str(text or ""),
        re.IGNORECASE,
    ):
        return None
    match = re.search(
        r"([0-9]+(?:\.[0-9]+)?)\s*(mhz|khz|hz|m|k)?",
        str(text or ""),
        re.IGNORECASE,
    )
    if not match:
        return None
    value = rtl433_float(match.group(1))
    unit = (match.group(2) or "mhz").lower()
    if value is None:
        return None
    if unit == "hz":
        value /= 1000000.0
    elif unit in ("khz", "k"):
        value /= 1000.0
    return round(value, 6)


def trim_float(value):
    """Return a compact decimal string for YAML/status frequency values."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    text = "{:.6f}".format(number).rstrip("0").rstrip(".")
    return text or "0"
