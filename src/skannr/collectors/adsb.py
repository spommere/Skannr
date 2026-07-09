"""Optional ADS-B collector backed by dump1090/readsb aircraft JSON."""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import urllib.request

from .base import BaseCollector, STATE_OFFLINE, STATE_ONLINE

ADSB_FIELD_MAX = 160


def compact_adsb_text(value, max_length=ADSB_FIELD_MAX):
    """Return compact one-line ADS-B text."""
    if value in (None, ""):
        return ""
    text = " ".join(str(value).replace("\x00", " ").split())
    return text[:max_length] if text else ""


def adsb_float(value):
    """Parse a numeric ADS-B value."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def adsb_int(value):
    """Parse an integer-like ADS-B value."""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def clean_adsb_data(data):
    """Scrub ADS-B payloads before persistence and derived summaries."""
    if not isinstance(data, dict):
        return {}
    cleaned = {}
    numeric_keys = {
        "timestamp_epoch",
        "event_time_epoch",
        "lat",
        "lon",
        "altitude_ft",
        "altitude_baro_ft",
        "altitude_geom_ft",
        "ground_speed_kt",
        "track_deg",
        "vertical_rate_fpm",
        "seen_sec",
        "seen_pos_sec",
        "messages",
        "rssi_dbfs",
        "distance_km",
        "first_seen_epoch",
        "last_seen_epoch",
        "seen_count",
        "position_count",
        "min_altitude_ft",
        "max_altitude_ft",
        "min_distance_km",
        "max_ground_speed_kt",
        "path_span_km",
        "route_sample_count",
        "pass_count",
        "session_count",
        "approach_distance_km",
        "approach_altitude_ft",
        "approach_vertical_rate_fpm",
        "decoder_exit_status",
        "device_index",
        "poll_interval_sec",
    }
    bool_keys = {"emergency"}
    list_keys = {"sample_callsigns", "sample_squawks", "route_samples", "session_spans"}
    for key, value in data.items():
        if value in (None, "", []):
            continue
        if key in numeric_keys:
            cleaned[key] = value
        elif key in bool_keys:
            cleaned[key] = bool(value)
        elif key in list_keys and isinstance(value, list):
            items = []
            for item in value:
                text = compact_adsb_text(item, 48)
                if text and text not in items:
                    items.append(text)
            if items:
                cleaned[key] = items[:16]
        else:
            text = compact_adsb_text(value)
            if text:
                cleaned[key] = text
    return cleaned


def _normalize_filter_list(values):
    """Return a set of uppercase strings from a config list, ignoring empties."""
    if not values:
        return set()
    result = set()
    for v in values:
        text = str(v).strip().upper()
        if text:
            result.add(text)
    return result


class ADSBCollector(BaseCollector):
    """Read decoded aircraft state from dump1090/readsb JSON output."""

    config_key = "adsb"
    name = "ADS-B"
    tab_label = "ADS-B"
    required_hardware = "dump1090/readsb decoder and RTL-SDR"
    subject_history_event_types = (
        "adsb_aircraft",
        "collector_online",
        "collector_offline",
        "collector_retrying",
    )

    @classmethod
    def hardware_status(cls, config):
        """Return decoder and configured aircraft JSON availability."""
        paths = configured_paths(config)
        return {
            "dump1090": bool(
                shutil.which("dump1090")
                or shutil.which("dump1090-fa")
                or shutil.which("dump1090-mutability")
            ),
            "readsb": bool(shutil.which("readsb")),
            "manage_decoder": bool(config.get("manage_decoder", True)),
            "device_index": config.get("device_index", 0),
            "decoder_command": decoder_command(config) or "",
            "decoder_output_dir": decoder_output_dir(config),
            "aircraft_json_path": first_existing_path(paths) or "",
            "aircraft_json_paths": paths,
            "url": config.get("url") or "",
            "poll_interval_sec": config.get("poll_interval_sec", 1),
        }

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self._fingerprints = {}
        self._source = ""
        self._observer = observer_location(config)
        self._process = None
        self._stdout_task = None
        self._stderr_task = None
        self._decoder_command = ""

    def detect(self):
        """Verify that an aircraft JSON source is configured and readable."""
        source = self.aircraft_source()
        if not source:
            self.state = STATE_OFFLINE
            self.warning = "No dump1090/readsb aircraft.json source found."
            return False
        self._source = source
        self.active_hardware = source
        self.state = STATE_ONLINE
        self.warning = None
        return True

    def _aircraft_passes_filter(self, item):
        """Return True when *item* matches at least one configured filter rule.

        When no filter keys are set this returns True for every aircraft
        (no filtering).  Rules are OR'd — matching any single rule lets the
        aircraft through.
        """
        rules = self.config.get("filter") or {}
        if not isinstance(rules, dict):
            return True
        categories = _normalize_filter_list(rules.get("categories"))
        squawks = _normalize_filter_list(rules.get("squawks"))
        callsign_prefixes = _normalize_filter_list(rules.get("callsign_prefixes"))
        icao_prefixes = _normalize_filter_list(rules.get("icao_prefixes"))
        emergency_only = bool(rules.get("emergency_only"))
        if (
            not categories
            and not squawks
            and not callsign_prefixes
            and not icao_prefixes
            and not emergency_only
        ):
            return True
        if emergency_only:
            emergency = str(item.get("emergency") or "").strip().lower()
            if emergency and emergency != "none":
                return True
        if categories:
            cat = str(item.get("category") or "").strip().upper()
            if cat in categories:
                return True
        if squawks:
            sq = str(item.get("squawk") or "").strip()
            if sq in squawks:
                return True
        if callsign_prefixes:
            flight = str(item.get("flight") or "").strip().upper()
            prefix = ""
            for ch in flight:
                if not ch.isalpha():
                    break
                prefix += ch
            if len(prefix) == 3 and prefix in callsign_prefixes:
                return True
        if icao_prefixes:
            hex_addr = str(item.get("hex") or "").strip().upper()
            for prefix in icao_prefixes:
                if hex_addr.startswith(prefix):
                    return True
        return False

    async def start(self):
        """Poll decoded aircraft state until stopped, retrying managed decoder failures."""
        self._running = True
        interval = float(self.config.get("poll_interval_sec", 1))
        while self._running:
            if self.should_manage_decoder():
                try:
                    await self.start_decoder()
                except Exception as exc:
                    await self.retrying("ADS-B decoder start failed: {}".format(exc))
                    await self.stop_decoder()
                    continue
            if not self.detect():
                await self.retrying(self.warning)
                await self.stop_decoder()
                continue
            await self.emit(
                "collector_online",
                {
                    "source": self._source,
                    "poll_interval_sec": interval,
                    "decoder": self.decoder_name(),
                    "device_index": self.config.get("device_index", 0),
                },
            )
            while self._running:
                try:
                    if (
                        self.should_manage_decoder()
                        and self._process
                        and self._process.returncode is not None
                    ):
                        raise RuntimeError(
                            "{} exited with status {}".format(
                                self.decoder_name(), self._process.returncode
                            )
                        )
                    rows = await self.run_blocking(self.poll_once)
                    self.state = STATE_ONLINE
                    self.warning = None
                    for data in rows:
                        await self.emit("adsb_aircraft", data, self.severity_for(data))
                except Exception as exc:
                    await self.retrying(
                        "ADS-B poll failed: {}".format(exc),
                        {"source": self._source},
                        sleep=False,
                    )
                    if (
                        self.should_manage_decoder()
                        and self._process
                        and self._process.returncode is not None
                    ):
                        await self.stop_decoder()
                        await self.retry_sleep()
                        break
                await asyncio.sleep(interval)
            if self.should_manage_decoder():
                await self.stop_decoder()

    async def stop(self):
        """Stop the managed ADS-B decoder before marking collector stopped."""
        await self.stop_decoder()
        await super().stop()

    def poll_once(self):
        """Return changed aircraft rows from the current decoder snapshot."""
        payload = self.read_aircraft_json()
        now = adsb_float(payload.get("now"))
        aircraft = payload.get("aircraft") if isinstance(payload, dict) else []
        if not isinstance(aircraft, list):
            return []
        rows = []
        for item in aircraft:
            if not self._aircraft_passes_filter(item):
                continue
            data = self.aircraft_data(item, now)
            icao = data.get("icao")
            if not icao:
                continue
            fingerprint = stable_fingerprint(data)
            if self._fingerprints.get(icao) == fingerprint:
                continue
            self._fingerprints[icao] = fingerprint
            rows.append(data)
        return rows

    def read_aircraft_json(self):
        """Read dump1090/readsb aircraft JSON from URL or local path."""
        source = self._source or self.aircraft_source()
        if source.startswith("http://") or source.startswith("https://"):
            timeout = float(self.config.get("request_timeout_sec", 2))
            with urllib.request.urlopen(source, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        with open(source, "r", encoding="utf-8", errors="replace") as handle:
            return json.load(handle)

    def aircraft_source(self):
        """Return URL or first readable local aircraft.json path."""
        url = compact_adsb_text(self.config.get("url"))
        if url:
            return url
        if self.should_manage_decoder():
            path = self.managed_aircraft_json_path()
            if path:
                return path if os.path.exists(path) and os.access(path, os.R_OK) else ""
        return first_existing_path(configured_paths(self.config))

    def should_manage_decoder(self):
        """Return True when Skannr should start dump1090/readsb for ADS-B."""
        if not self.config.get("manage_decoder", True):
            return False
        return not bool(compact_adsb_text(self.config.get("url")))

    async def start_decoder(self):
        """Start dump1090/readsb and wait for aircraft.json to appear."""
        command = decoder_command(self.config)
        if not command:
            raise RuntimeError("dump1090/readsb command not found")
        self._decoder_command = command
        output_dir = decoder_output_dir(self.config)
        os.makedirs(output_dir, exist_ok=True)
        from ..paths import ensure_owner

        ensure_owner(output_dir)
        args = decoder_args(self.config, output_dir, command)
        self._source = os.path.join(output_dir, "aircraft.json")
        self._process = await asyncio.create_subprocess_exec(
            command,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        loop = asyncio.get_event_loop()
        self._stdout_task = loop.create_task(
            self.drain_decoder_pipe(self._process.stdout, "stdout")
        )
        self._stderr_task = loop.create_task(
            self.drain_decoder_pipe(self._process.stderr, "stderr")
        )
        timeout = float(self.config.get("decoder_start_timeout_sec", 10))
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if self._process.returncode is not None:
                raise RuntimeError(
                    "{} exited with status {}".format(command, self._process.returncode)
                )
            if os.path.exists(self._source) and os.access(self._source, os.R_OK):
                self.active_hardware = "{} -> {}".format(command, self._source)
                return
            await asyncio.sleep(0.25)
        raise RuntimeError(
            "{} did not create {} within {}s".format(
                command, self._source, int(timeout)
            )
        )

    async def stop_decoder(self):
        """Terminate a managed dump1090/readsb process."""
        if self._process and self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=3)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
        for task in (self._stdout_task, self._stderr_task):
            if task and not task.done():
                task.cancel()
        self._process = None
        self._stdout_task = None
        self._stderr_task = None
        self._decoder_command = ""

    async def drain_decoder_pipe(self, pipe, label):
        """Drain decoder output so stdout/stderr never block the process."""
        if not pipe:
            return
        while True:
            line = await pipe.readline()
            if not line:
                return
            logging.debug(
                "adsb decoder %s: %s",
                label,
                line.decode("utf-8", errors="replace").rstrip(),
            )

    def managed_aircraft_json_path(self):
        """Return the aircraft.json path owned by the managed decoder."""
        return os.path.join(decoder_output_dir(self.config), "aircraft.json")

    def aircraft_data(self, item, snapshot_now):
        """Normalize one dump1090/readsb aircraft row."""
        if not isinstance(item, dict):
            return {}
        icao = compact_adsb_text(item.get("hex"), 16).upper()
        callsign = compact_adsb_text(item.get("flight"), 16).strip()
        lat = adsb_float(item.get("lat"))
        lon = adsb_float(item.get("lon"))
        emergency = compact_adsb_text(item.get("emergency"), 24).lower()
        altitude = altitude_ft(
            first_present(item, "alt_baro", "altitude"),
            item.get("alt_geom"),
        )
        data = {
            "icao": icao,
            "callsign": callsign,
            "airline_icao": airline_icao_from_callsign(callsign),
            "category": compact_adsb_text(item.get("category"), 24),
            "position_source": compact_adsb_text(item.get("type"), 32),
            "air_ground": air_ground_state(item),
            "cpr_type": adsb_cpr_type(item),
            "squawk": compact_adsb_text(item.get("squawk"), 12),
            "emergency": bool(emergency and emergency != "none"),
            "lat": lat,
            "lon": lon,
            "altitude_ft": altitude,
            "altitude_baro_ft": altitude_ft(
                first_present(item, "alt_baro", "altitude"), None
            ),
            "altitude_geom_ft": altitude_ft(None, item.get("alt_geom")),
            "ground_speed_kt": adsb_float(first_present(item, "gs", "speed")),
            "track_deg": adsb_float(item.get("track")),
            "vertical_rate_fpm": adsb_float(
                first_present(item, "baro_rate", "geom_rate", "vert_rate")
            ),
            "seen_sec": adsb_float(item.get("seen")),
            "seen_pos_sec": adsb_float(item.get("seen_pos")),
            "messages": adsb_int(item.get("messages")),
            "rssi_dbfs": adsb_float(item.get("rssi")),
            "source": self._source,
            "decoder": self.decoder_name(),
        }
        if snapshot_now:
            seen = data.get("seen_sec") or 0
            data["event_time_epoch"] = snapshot_now - seen
        if lat is not None and lon is not None and self._observer:
            data["distance_km"] = distance_km(
                self._observer[0], self._observer[1], lat, lon
            )
        return clean_adsb_data(data)

    def decoder_name(self):
        """Return the selected decoder name for events and status rows."""
        configured = compact_adsb_text(self.config.get("decoder_command"), 300)
        return (
            decoder_label(self._decoder_command)
            or decoder_label(configured)
            or "external"
        )

    def severity_for(self, data):
        """Return event severity for the live aircraft row."""
        if data.get("emergency"):
            return "warning"
        altitude = adsb_float(data.get("altitude_ft"))
        distance = adsb_float(data.get("distance_km"))
        low_alt = adsb_float(self.config.get("low_altitude_ft", 1500))
        nearby = adsb_float(self.config.get("nearby_radius_km", 10))
        if (
            altitude is not None
            and distance is not None
            and altitude <= low_alt
            and distance <= nearby
        ):
            return "warning"
        return "info"


def configured_paths(config):
    """Return configured and common dump1090/readsb aircraft JSON paths."""
    paths = []
    for item in config.get("aircraft_json_paths") or []:
        text = compact_adsb_text(item, 300)
        if text:
            paths.append(text)
    for item in (
        config.get("aircraft_json_path"),
        "/run/dump1090-fa/aircraft.json",
        "/var/run/dump1090-fa/aircraft.json",
        "/run/dump1090-mutability/aircraft.json",
        "/var/run/dump1090-mutability/aircraft.json",
        "/run/readsb/aircraft.json",
        "/var/run/readsb/aircraft.json",
    ):
        text = compact_adsb_text(item, 300)
        if text and text not in paths:
            paths.append(text)
    return paths


ADSB_DECODER_COMMANDS = (
    "dump1090-mutability",
    "dump1090-fa",
    "dump1090",
    "readsb",
)

DUMP1090_DECODER_ARGS = (
    "--net",
    "--device-index",
    "{device_index}",
    "--write-json",
    "{json_dir}",
)

READSB_DECODER_ARGS = (
    "--net",
    "--device-type",
    "rtlsdr",
    "--device",
    "{device_index}",
    "--write-json",
    "{json_dir}",
)


def decoder_command(config):
    """Return the configured or first available ADS-B decoder command."""
    configured = compact_adsb_text(config.get("decoder_command"), 300)
    if configured:
        resolved = shutil.which(configured)
        if resolved:
            return resolved
        logging.warning(
            "Configured ADS-B decoder command %s was not found; trying installed fallbacks",
            configured,
        )
    for candidate in ADSB_DECODER_COMMANDS:
        path = shutil.which(candidate)
        if path:
            return path
    return ""


def decoder_label(command):
    """Return a compact decoder executable label."""
    text = compact_adsb_text(command, 300)
    return os.path.basename(text) if text else ""


def decoder_uses_readsb_args(command):
    """Return True for decoders that use readsb-style device arguments."""
    return decoder_label(command) == "readsb"


def decoder_default_args(command):
    """Return default managed-decoder args for the selected executable."""
    return (
        READSB_DECODER_ARGS
        if decoder_uses_readsb_args(command)
        else DUMP1090_DECODER_ARGS
    )


def decoder_args(config, output_dir, command=None):
    """Return decoder arguments, formatting {json_dir} when configured."""
    command = command or decoder_command(config)
    args = config.get("decoder_args")
    if decoder_args_are_default(args):
        args = decoder_default_args(command)
    if isinstance(args, str):
        args = args.split()
    formatted = []
    for arg in args or []:
        text = compact_adsb_text(arg, 500)
        if text:
            formatted.append(
                text.format(
                    json_dir=output_dir,
                    device_index=config.get("device_index", 0),
                )
            )
    return formatted


def decoder_args_are_default(args):
    """Return True when config uses the built-in/legacy default args."""
    if args in (None, ""):
        return True
    if isinstance(args, str):
        values = tuple(args.split())
    else:
        values = tuple(str(item) for item in (args or []))
    return values in (DUMP1090_DECODER_ARGS, READSB_DECODER_ARGS)


def decoder_output_dir(config):
    """Return where a managed decoder should write aircraft.json."""
    configured = compact_adsb_text(config.get("decoder_output_dir"), 500)
    if configured:
        return resolve_runtime_path(config, configured)
    return os.path.join(configured_log_dir(config), "adsb_decoder")


def configured_log_dir(config):
    """Return the configured filesystem log directory."""
    global_config = config.get("_global_config") or {}
    filesystem = (global_config.get("persistence") or {}).get("filesystem") or {}
    log_dir = compact_adsb_text(filesystem.get("log_dir"), 500) or "runtime/logs"
    return resolve_runtime_path(config, log_dir)


def resolve_runtime_path(config, path):
    """Resolve relative runtime paths against the project directory."""
    if os.path.isabs(path):
        return path
    global_config = config.get("_global_config") or {}
    project_dir = global_config.get("_project_dir") or os.getcwd()
    return os.path.abspath(os.path.join(project_dir, path))


def first_existing_path(paths):
    """Return the first readable path from a list."""
    for path in paths or []:
        if path and os.path.exists(path) and os.access(path, os.R_OK):
            return path
    return ""


def observer_location(config):
    """Return configured observer latitude/longitude if available."""
    lat = adsb_float(config.get("latitude"))
    lon = adsb_float(config.get("longitude"))
    if lat is None or lon is None:
        global_config = config.get("_global_config") or {}
        for key in ("usgs", "noaa"):
            section = (global_config.get("collectors") or {}).get(key) or {}
            lat = adsb_float(section.get("latitude"))
            lon = adsb_float(section.get("longitude"))
            if lat is not None and lon is not None:
                break
    return (lat, lon) if lat is not None and lon is not None else None


def altitude_ft(baro, geom):
    """Return altitude in feet, ignoring ground labels."""
    for value in (baro, geom):
        if isinstance(value, str) and value.lower() == "ground":
            return 0
        parsed = adsb_int(value)
        if parsed is not None:
            return parsed
    return None


def first_present(data, *keys):
    """Return the first present dump1090/readsb value from possible keys."""
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return None


def airline_icao_from_callsign(callsign):
    """Return ICAO airline/operator prefix when the callsign has one."""
    text = compact_adsb_text(callsign, 16).upper()
    prefix = ""
    for char in text:
        if not char.isalpha():
            break
        prefix += char
    return prefix if len(prefix) == 3 else ""


def air_ground_state(item):
    """Return aircraft air/ground state from decoder row fields."""
    if not isinstance(item, dict):
        return ""
    if str(item.get("airground") or "").strip():
        return compact_adsb_text(item.get("airground"), 24).lower()
    for key in ("alt_baro", "alt_geom", "altitude"):
        value = item.get(key)
        if isinstance(value, str) and value.lower() == "ground":
            return "ground"
    return "airborne"


def adsb_cpr_type(item):
    """Return decoder CPR type when aircraft.json exposes it."""
    if not isinstance(item, dict):
        return ""
    for key in ("cpr_type", "cpr", "cprtype"):
        value = compact_adsb_text(item.get(key), 32)
        if value:
            return value
    return ""


def stable_fingerprint(data):
    """Return a stable fingerprint for aircraft rows to suppress duplicates."""
    fields = [
        data.get("icao"),
        data.get("callsign"),
        data.get("airline_icao"),
        data.get("squawk"),
        data.get("air_ground"),
        data.get("cpr_type"),
        data.get("position_source"),
        data.get("lat"),
        data.get("lon"),
        data.get("altitude_ft"),
        data.get("altitude_baro_ft"),
        data.get("altitude_geom_ft"),
        data.get("ground_speed_kt"),
        data.get("track_deg"),
        data.get("vertical_rate_fpm"),
        data.get("emergency"),
        data.get("messages"),
    ]
    return hashlib.sha1(json.dumps(fields, sort_keys=True).encode("utf-8")).hexdigest()


def distance_km(lat1, lon1, lat2, lon2):
    """Return great-circle distance in kilometers."""
    import math

    values = [adsb_float(value) for value in (lat1, lon1, lat2, lon2)]
    if any(value is None for value in values):
        return None
    lat1, lon1, lat2, lon2 = [math.radians(value) for value in values]
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    )
    return round(6371.0 * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)), 2)
