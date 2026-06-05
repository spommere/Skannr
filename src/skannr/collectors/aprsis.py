"""Optional APRS-IS collector.

APRS-IS is an internet feed, not local RF evidence. The collector keeps that
distinction in every normalized packet so downstream Insights and Reports can
show it as situational context instead of local antenna reception.
"""

import asyncio
import fnmatch
import logging
import math
import re

from ..log_utils import now_epoch
from ..paths import VERSION_PATH
from .base import BaseCollector, STATE_OFFLINE, STATE_ONLINE


APRS_FIELD_MAX = 180
APRS_PAYLOAD_MAX = 240
APRSIS_DEFAULT_HOST = "rotate.aprs2.net"
APRSIS_DEFAULT_PORT = 14580
MIC_E_STANDARD_MESSAGES = {
    "111": "M0: Off Duty",
    "110": "M1: En Route",
    "101": "M2: In Service",
    "100": "M3: Returning",
    "011": "M4: Committed",
    "010": "M5: Special",
    "001": "M6: Priority",
    "000": "Emergency",
}


class PreferredServerMismatch(ConnectionError):
    """Raised when a pooled APRS-IS host connects to the wrong backend."""


MIC_E_CUSTOM_MESSAGES = {
    "111": "C0: Custom-0",
    "110": "C1: Custom-1",
    "101": "C2: Custom-2",
    "100": "C3: Custom-3",
    "011": "C4: Custom-4",
    "010": "C5: Custom-5",
    "001": "C6: Custom-6",
    "000": "Emergency",
}


def aprsis_port(value, default=APRSIS_DEFAULT_PORT):
    """Return a valid APRS-IS TCP port, or 0 for invalid configured values."""
    raw = default if value in (None, "") else value
    try:
        port = int(raw)
    except (TypeError, ValueError):
        return 0
    return port if 0 < port <= 65535 else 0


def compact_aprs_text(value, max_length=APRS_FIELD_MAX):
    """Return a compact one-line APRS text field for UI and logs."""
    if value in (None, ""):
        return ""
    text = " ".join(str(value).replace("\x00", " ").split())
    if not text:
        return ""
    return text[:max_length]


def aprsis_callsigns(value):
    """Return callsigns safe to append to an APRS-IS b/ filter."""
    if value in (None, ""):
        return []
    raw_items = value if isinstance(value, list) else str(value).split(",")
    callsigns = []
    for item in raw_items:
        text = compact_aprs_text(item, 32).upper()
        if not re.match(r"^[A-Z0-9][A-Z0-9-]{0,14}\*?$", text):
            continue
        if text not in callsigns:
            callsigns.append(text)
    return callsigns


def aprsis_text_list(value, max_length=64):
    """Return compact configured text values from a list or comma string."""
    if value in (None, ""):
        return []
    raw_items = value if isinstance(value, list) else str(value).split(",")
    items = []
    for item in raw_items:
        text = compact_aprs_text(item, max_length)
        if text and text not in items:
            items.append(text)
    return items


def aprsis_filter_with_callsigns(aprs_filter, callsigns):
    """Append explicit station includes to an APRS-IS server filter."""
    if not callsigns:
        return aprs_filter
    parts = [item for item in (aprs_filter, "b/{}".format("/".join(callsigns))) if item]
    return compact_aprs_text(" ".join(parts), 180)


def aprsis_server_identity(text):
    """Extract APRS-IS backend identity from banner/logresp comments."""
    message = str(text or "")
    server_name = ""
    server_address = ""
    address_match = re.search(
        r"\b((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})\b",
        message,
        flags=re.IGNORECASE,
    )
    if address_match:
        server_address = compact_aprs_text(address_match.group(1), 64)
    for pattern in (
        r"\b(CWOP-\d+)\b",
        r"\bserver\s+([A-Za-z0-9_.-]+)\b",
        r"\b([A-Za-z][A-Za-z0-9_.-]*-\d+)\s+(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b",
    ):
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            server_name = compact_aprs_text(match.group(1).upper(), 64)
            break
    return {
        "server_name": server_name,
        "server_address": server_address,
    }


def aprsis_server_matches(server_name, preferred_servers):
    """Return True when the current backend matches a preferred pattern."""
    current = str(server_name or "").strip().upper()
    if not current:
        return False
    for preferred in preferred_servers or []:
        pattern = str(preferred or "").strip().upper()
        if pattern and fnmatch.fnmatchcase(current, pattern):
            return True
    return False


def clean_aprs_data(data):
    """Scrub APRS event data loaded from retained logs."""
    if not isinstance(data, dict):
        return {}
    cleaned = {}
    for key, value in data.items():
        if value in (None, "", []):
            continue
        if key in (
            "packet_count",
            "station_count",
            "object_count",
            "message_count",
            "position_count",
            "status_count",
            "weather_count",
            "other_count",
            "events_in_window",
            "feed_count",
            "raw_lines",
            "server_comments",
            "packets_seen",
            "emitted",
            "connection_attempts",
            "disconnect_count",
            "dropped_parse",
            "dropped_geofence",
            "dropped_rate",
            "dropped_total",
            "connected_at_epoch",
            "last_connect_attempt_epoch",
            "last_disconnect_epoch",
            "last_packet_epoch",
            "last_emitted_epoch",
            "last_status_epoch",
            "last_dropped_epoch",
            "connection_age_sec",
            "idle_sec",
            "preferred_server_attempts",
            "preferred_server_max_attempts",
            "first_seen_epoch",
            "last_seen_epoch",
            "timestamp_epoch",
            "rain_started_epoch",
            "rain_stopped_epoch",
            "rain_last_transition_epoch",
            "rain_episode_started_epoch",
            "rain_episode_stopped_epoch",
            "distance_from_filter_km",
            "geofence_latitude",
            "geofence_longitude",
            "geofence_radius_km",
            "latitude",
            "longitude",
            "latest_latitude",
            "latest_longitude",
            "position_ambiguity",
            "speed_knots",
            "speed_kmh",
            "course_deg",
            "latest_speed_kmh",
            "latest_course_deg",
            "latest_temperature_f",
            "latest_humidity_percent",
            "latest_pressure_hpa",
            "first_latitude",
            "first_longitude",
            "last_latitude",
            "last_longitude",
            "min_latitude",
            "max_latitude",
            "min_longitude",
            "max_longitude",
            "position_span_km",
            "movement_km",
            "max_step_km",
            "max_speed_kmh",
            "temperature_min_f",
            "temperature_max_f",
            "temperature_change_f",
            "wind_speed_max_mph",
            "wind_gust_max_mph",
            "rain_1h_max_in",
            "latest_wind_speed_mph",
            "latest_wind_gust_mph",
            "latest_rain_1h_in",
            "wind_direction_deg",
            "wind_speed_mph",
            "wind_gust_mph",
            "temperature_f",
            "rain_1h_in",
            "rain_24h_in",
            "rain_since_midnight_in",
            "humidity_percent",
            "pressure_hpa",
            "luminosity_w_m2",
            "snow_in",
            "port",
        ):
            cleaned[key] = value
        elif key in (
            "internet_fed",
            "store_raw",
            "movement_detected",
            "weather_station",
            "rain_started",
            "rain_stopped",
            "rain_active",
            "geofence_enforced",
            "preferred_server_fallback",
        ):
            cleaned[key] = bool(value)
        elif isinstance(value, list):
            items = []
            for item in value:
                item = compact_aprs_text(item)
                if item and item not in items:
                    items.append(item)
            if items:
                cleaned[key] = items
        else:
            value = compact_aprs_text(value, max_length=APRS_PAYLOAD_MAX)
            if value:
                cleaned[key] = value
    return cleaned


def aprsis_bool(value, default=False):
    """Return a bool for YAML or string configuration values."""
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return default


def aprsis_float(value):
    """Return a float for APRS config/packet numeric fields, or None."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def aprsis_int(value):
    """Return an int for APRS config numeric fields, or None."""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def aprsis_radius_from_filter(value):
    """Extract r/lat/lon/km from an APRS-IS filter string when present."""
    match = re.search(
        r"(?:^|\s)r/([-+]?\d+(?:\.\d+)?)/([-+]?\d+(?:\.\d+)?)/"
        r"([-+]?\d+(?:\.\d+)?)",
        str(value or ""),
    )
    if not match:
        return None
    latitude, longitude, radius = [aprsis_float(item) for item in match.groups()]
    if latitude is None or longitude is None or radius is None or radius <= 0:
        return None
    return {
        "latitude": latitude,
        "longitude": longitude,
        "radius_km": radius,
    }


def aprsis_distance_km(lat1, lon1, lat2, lon2):
    """Return great-circle distance in kilometers for two APRS positions."""
    values = [aprsis_float(value) for value in (lat1, lon1, lat2, lon2)]
    if any(value is None for value in values):
        return None
    lat1, lon1, lat2, lon2 = [math.radians(value) for value in values]
    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1
    root = (
        math.sin(delta_lat / 2.0) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2.0) ** 2
    )
    return 6371.0 * 2.0 * math.asin(min(1.0, math.sqrt(root)))


def aprsis_feed_configs(config):
    """Return normalized APRS-IS feed definitions.

    A single legacy host/filter config becomes one feed. A new feeds: list can
    run normal APRS and CWOP/weather streams concurrently under one collector.
    """
    config = config or {}
    raw_feeds = config.get("feeds")
    if isinstance(raw_feeds, list) and raw_feeds:
        feed_items = [item for item in raw_feeds if isinstance(item, dict)]
    else:
        feed_items = [
            {
                "name": config.get("feed_name") or "primary",
                "role": config.get("feed_role") or "local",
                "host": config.get("host"),
                "port": config.get("port"),
                "filter": config.get("filter"),
            }
        ]

    feeds = []
    for index, item in enumerate(feed_items, start=1):
        if not aprsis_bool(item.get("enabled"), True):
            continue
        host = compact_aprs_text(
            item.get("host") or config.get("host") or APRSIS_DEFAULT_HOST,
            max_length=120,
        )
        port = aprsis_port(item.get("port", config.get("port")))
        aprs_filter = compact_aprs_text(
            item.get("filter") or config.get("filter") or "",
            max_length=180,
        )
        include_callsigns = aprsis_callsigns(
            item.get("include_callsigns")
            or item.get("included_callsigns")
            or item.get("watch_callsigns")
            or config.get("include_callsigns")
            or config.get("included_callsigns")
            or config.get("watch_callsigns")
        )
        preferred_servers = aprsis_text_list(
            item.get("preferred_servers")
            or item.get("preferred_server")
            or item.get("preferred_backend")
            or config.get("preferred_servers")
            or config.get("preferred_server")
            or config.get("preferred_backend")
        )
        preferred_server_timeout = aprsis_float(
            config.get("preferred_server_timeout_sec")
        )
        preferred_server_max_attempts = aprsis_int(
            config.get("preferred_server_max_attempts")
        )
        aprs_filter = aprsis_filter_with_callsigns(aprs_filter, include_callsigns)
        name = compact_aprs_text(item.get("name") or "feed{}".format(index), 48)
        role = compact_aprs_text(
            item.get("role") or aprsis_feed_role(host, aprs_filter), 48
        )
        geofence = aprsis_feed_geofence(item, aprs_filter)
        feeds.append(
            {
                "name": name,
                "role": role,
                "host": host,
                "port": port,
                "filter": aprs_filter,
                "include_callsigns": include_callsigns,
                "preferred_servers": preferred_servers,
                "preferred_server_timeout_sec": preferred_server_timeout,
                "preferred_server_max_attempts": preferred_server_max_attempts,
                "callsign": compact_aprs_text(
                    item.get("callsign") or config.get("callsign") or "NOCALL",
                    32,
                ),
                "passcode": compact_aprs_text(
                    item.get("passcode") or config.get("passcode") or "-1",
                    32,
                ),
                "store_raw": aprsis_bool(
                    item.get("store_raw"),
                    bool(config.get("store_raw", False)),
                ),
                "enforce_radius": aprsis_bool(item.get("enforce_radius"), False),
                "geofence": geofence,
            }
        )
    return feeds


def aprsis_public_feed(feed):
    """Return feed metadata safe to expose through System Status."""
    geofence = feed.get("geofence") or {}
    return {
        "name": feed.get("name") or "",
        "role": feed.get("role") or "",
        "host": feed.get("host") or "",
        "port": feed.get("port") or 0,
        "filter": feed.get("filter") or "",
        "preferred_servers": feed.get("preferred_servers") or [],
        "preferred_server_timeout_sec": feed.get("preferred_server_timeout_sec"),
        "preferred_server_max_attempts": feed.get("preferred_server_max_attempts"),
        "enforce_radius": bool(feed.get("enforce_radius")),
        "geofence": {
            key: geofence.get(key)
            for key in ("latitude", "longitude", "radius_km")
            if geofence.get(key) is not None
        },
    }


def aprsis_feed_role(host, aprs_filter):
    """Infer a display role for a feed when the config omits one."""
    text = "{} {}".format(host or "", aprs_filter or "").lower()
    if "cwop" in text or "t/w" in text:
        return "weather"
    return "local"


def aprsis_feed_geofence(item, aprs_filter):
    """Return explicit or filter-derived client-side geofence settings."""
    radius = aprsis_float(
        item.get("radius_km")
        or item.get("geofence_radius_km")
        or item.get("radius")
    )
    latitude = aprsis_float(
        item.get("latitude")
        or item.get("geofence_latitude")
        or item.get("lat")
    )
    longitude = aprsis_float(
        item.get("longitude")
        or item.get("geofence_longitude")
        or item.get("lon")
    )
    if latitude is not None and longitude is not None and radius and radius > 0:
        return {
            "latitude": latitude,
            "longitude": longitude,
            "radius_km": radius,
        }
    return aprsis_radius_from_filter(aprs_filter) or {}


class APRSISCollector(BaseCollector):
    """Read a filtered APRS-IS TCP feed and emit compact packet metadata."""

    config_key = "aprsis"
    name = "APRS-IS"
    tab_label = "APRS-IS"
    required_hardware = "Internet APRS-IS TCP feed"

    @classmethod
    def hardware_status(cls, config):
        """Return configured APRS-IS endpoint metadata."""
        feeds = aprsis_feed_configs(config)
        public_feeds = [aprsis_public_feed(feed) for feed in feeds]
        first = public_feeds[0] if public_feeds else {}
        return {
            "host": first.get("host") or config.get("host") or APRSIS_DEFAULT_HOST,
            "port": first.get("port") or aprsis_port(config.get("port")),
            "filter": first.get("filter") or config.get("filter") or "",
            "feeds": public_feeds,
            "feed_count": len(public_feeds),
            "callsign": config.get("callsign") or "",
            "enabled": aprsis_bool(config.get("enabled"), False),
            "internet_fed": True,
        }

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self.feeds = aprsis_feed_configs(config)
        self.active_feeds = []
        first = self.feeds[0] if self.feeds else {}
        self.host = first.get("host") or ""
        self.port = first.get("port") or 0
        self.callsign = first.get("callsign") or "NOCALL"
        self.passcode = first.get("passcode") or "-1"
        self.filter = first.get("filter") or ""
        self.store_raw = any(feed.get("store_raw") for feed in self.feeds)
        self._recent_emit_epochs = []
        self._last_offline_emit_epoch = {}
        self._last_status_emit_epoch = {}
        self._feed_states = {}
        self._feed_warnings = {}
        self._feed_stats = {}

    def status(self):
        """Return System Status plus per-feed APRS-IS runtime counters."""
        status = super().status()
        feeds = self.active_feeds or self.feeds
        status["feeds"] = [aprsis_public_feed(feed) for feed in feeds]
        status["feed_statuses"] = [self.health_payload(feed) for feed in feeds]
        return status

    def detect(self):
        """Require at least one configured endpoint and server-side filter."""
        valid = []
        invalid = []
        for feed in self.feeds:
            reason = self.invalid_feed_reason(feed)
            if reason:
                invalid.append("{}: {}".format(feed.get("name") or "feed", reason))
            else:
                valid.append(feed)
        if not valid:
            self.state = STATE_OFFLINE
            self.warning = (
                "No valid APRS-IS feed configured."
                if not invalid
                else "; ".join(invalid)
            )
            return False
        self.active_feeds = valid
        self.host = valid[0]["host"]
        self.port = valid[0]["port"]
        self.filter = valid[0]["filter"]
        self.active_hardware = "; ".join(
            self.feed_label(feed) for feed in self.active_feeds
        )
        self.state = STATE_OFFLINE
        self.warning = (
            "APRS-IS connection not established yet."
            if not invalid
            else "Invalid feed config: {}".format("; ".join(invalid))
        )
        return True

    def invalid_feed_reason(self, feed):
        """Return a config error for one feed, or an empty string."""
        if not feed.get("host") or int(feed.get("port") or 0) <= 0:
            return "missing host/port"
        if not feed.get("filter"):
            return "missing server-side filter"
        if feed.get("enforce_radius") and not feed.get("geofence"):
            return "enforce_radius requires r/lat/lon/km filter or geofence fields"
        return ""

    async def start(self):
        """Connect all configured APRS-IS feeds and reconnect on failure."""
        self._running = True
        if not self.detect():
            await self.emit("collector_offline", self.health_payload(), "warning")
            return
        tasks = [
            asyncio.ensure_future(self.run_feed(feed))
            for feed in self.active_feeds
        ]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            raise

    async def run_feed(self, feed):
        """Connect one APRS-IS feed until stopped."""
        while self._running:
            writer = None
            try:
                timeout = float(self.config.get("connect_timeout_sec", 10))
                self.set_feed_stat(feed, "preferred_server_fallback", False)
                attempt = self.increment_feed_stat(feed, "connection_attempts")
                self.set_feed_stat(feed, "last_connect_attempt_epoch", round(now_epoch(), 3))
                logging.info(
                    "APRS-IS feed connecting name=%s host=%s port=%s "
                    "filter=%s preferred=%s attempt=%s",
                    feed.get("name") or "",
                    feed.get("host") or "",
                    feed.get("port") or "",
                    feed.get("filter") or "",
                    ",".join(feed.get("preferred_servers") or []) or "none",
                    attempt,
                )
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(feed["host"], feed["port"]),
                    timeout=timeout,
                )
                logging.info(
                    "APRS-IS TCP connected name=%s host=%s port=%s",
                    feed.get("name") or "",
                    feed.get("host") or "",
                    feed.get("port") or "",
                )
                await self.read_server_banner(reader, feed)
                await self.login(writer, feed)
                await self.confirm_preferred_server(reader, feed)
                logging.info(
                    "APRS-IS feed connected name=%s host=%s port=%s filter=%s",
                    feed.get("name") or "",
                    feed.get("host") or "",
                    feed.get("port") or "",
                    feed.get("filter") or "",
                )
                self._feed_states[feed["name"]] = STATE_ONLINE
                self._feed_warnings.pop(feed["name"], None)
                self.set_feed_stat(feed, "connected_at_epoch", round(now_epoch(), 3))
                self.set_feed_stat(feed, "last_disconnect_reason", "")
                self.update_overall_state()
                await self.emit("collector_online", self.health_payload(feed))
                await self.read_packets(reader, feed)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.record_disconnect(feed, exc)
                logging.info(
                    "APRS-IS feed disconnected name=%s host=%s port=%s "
                    "reason=%s %s",
                    feed.get("name") or "",
                    feed.get("host") or "",
                    feed.get("port") or "",
                    exc,
                    self.feed_runtime_log_summary(feed),
                )
                self._feed_states[feed["name"]] = STATE_OFFLINE
                self._feed_warnings[feed["name"]] = str(exc)
                self.update_overall_state()
                await self.emit_offline(feed, exc)
            finally:
                if writer is not None:
                    writer.close()
                    wait_closed = getattr(writer, "wait_closed", None)
                    if wait_closed:
                        try:
                            await wait_closed()
                        except Exception:
                            pass
            if self._running:
                retry_interval = self.config.get("retry_interval_sec", 5)
                logging.info(
                    "APRS-IS feed reconnecting name=%s host=%s port=%s "
                    "retry_in=%ss",
                    feed.get("name") or "",
                    feed.get("host") or "",
                    feed.get("port") or "",
                    retry_interval,
                )
                await self.retry_sleep()

    async def confirm_preferred_server(self, reader, feed):
        """Wait briefly until a pooled host proves it is a preferred backend."""
        preferred = (feed or {}).get("preferred_servers") or []
        if not preferred:
            return
        if self.preferred_server_fallback_active(feed):
            return
        if self.preferred_server_reached(feed):
            self.log_preferred_server_reached(feed)
            return
        timeout = self.preferred_server_timeout(feed)
        logging.info(
            "APRS-IS preferred server pending name=%s host=%s preferred=%s "
            "timeout=%ss",
            feed.get("name") or "",
            feed.get("host") or "",
            ",".join(preferred),
            timeout,
        )
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            server_name = self.feed_stats(feed).get("server_name") or "unknown"
            logging.info(
                "APRS-IS preferred server timeout name=%s host=%s preferred=%s "
                "connected=%s",
                feed.get("name") or "",
                feed.get("host") or "",
                ",".join(preferred),
                server_name,
            )
            if self.handle_preferred_server_miss(feed, server_name, "timeout"):
                return
            raise PreferredServerMismatch(self.preferred_server_miss_text(feed, server_name))
        if not line:
            raise ConnectionError("feed closed before preferred server confirmation")
        text = line.decode("utf-8", errors="replace").strip()
        if text.startswith("#"):
            await self.handle_server_comment(feed, text)
            if self.preferred_server_reached(feed):
                self.log_preferred_server_reached(feed)
                return
            if self.preferred_server_fallback_active(feed):
                return
            server_name = self.feed_stats(feed).get("server_name") or "unknown"
            raise PreferredServerMismatch(self.preferred_server_miss_text(feed, server_name))
        # A packet before a server identity means the pooled backend did not
        # identify itself in time. Reconnect instead of staying on an unknown
        # server for a sparse CWOP interval.
        if self.handle_preferred_server_miss(feed, "unknown", "first-packet"):
            return
        raise PreferredServerMismatch(self.preferred_server_miss_text(feed, "unknown"))

    def preferred_server_timeout(self, feed):
        """Return the short preferred-backend confirmation timeout."""
        configured = feed.get("preferred_server_timeout_sec")
        if configured is None:
            configured = self.config.get("preferred_server_timeout_sec", 2)
        timeout = aprsis_float(configured)
        return timeout if timeout is not None and timeout > 0 else 2.0

    def server_banner_timeout(self, feed):
        """Return the banner wait, shortened for preferred pooled backends."""
        timeout = aprsis_float(self.config.get("banner_timeout_sec", 5))
        timeout = timeout if timeout is not None and timeout > 0 else 5.0
        if (feed or {}).get("preferred_servers"):
            timeout = min(timeout, self.preferred_server_timeout(feed))
        return timeout

    def preferred_server_reached(self, feed):
        """Return True if the current backend matches configured preference."""
        preferred = (feed or {}).get("preferred_servers") or []
        return bool(preferred) and aprsis_server_matches(
            self.feed_stats(feed).get("server_name") or "",
            preferred,
        )

    def preferred_server_fallback_active(self, feed):
        """Return True after the preferred-server retry limit has been reached."""
        return bool(self.feed_stats(feed).get("preferred_server_fallback"))

    def preferred_server_max_attempts(self, feed):
        """Return the collector-level preferred-backend retry limit."""
        configured = feed.get("preferred_server_max_attempts")
        if configured is None:
            configured = self.config.get("preferred_server_max_attempts")
        attempts = aprsis_int(configured)
        return attempts if attempts is not None and attempts > 0 else 0

    def preferred_server_miss_text(self, feed, server_name):
        """Return the standard preferred-server miss reason."""
        preferred = (feed or {}).get("preferred_servers") or []
        return "preferred server {} not reached; connected to {}".format(
            ", ".join(preferred),
            server_name or "unknown",
        )

    def handle_preferred_server_miss(self, feed, server_name, reason):
        """Record a non-preferred backend and return True when fallback is allowed."""
        stats = self.feed_stats(feed)
        attempts = int(stats.get("preferred_server_attempts") or 0) + 1
        stats["preferred_server_attempts"] = attempts
        stats["preferred_server_last_miss"] = server_name or "unknown"
        stats["preferred_server_last_miss_reason"] = reason or ""
        limit = self.preferred_server_max_attempts(feed)
        preferred = (feed or {}).get("preferred_servers") or []
        logging.info(
            "APRS-IS preferred server miss name=%s host=%s preferred=%s "
            "connected=%s reason=%s attempt=%s limit=%s",
            feed.get("name") or "",
            feed.get("host") or "",
            ",".join(preferred),
            server_name or "unknown",
            reason or "",
            attempts,
            limit or "unlimited",
        )
        if limit and attempts >= limit:
            stats["preferred_server_fallback"] = True
            logging.warning(
                "APRS-IS preferred server retry limit reached name=%s host=%s "
                "preferred=%s connected=%s attempts=%s; accepting current backend",
                feed.get("name") or "",
                feed.get("host") or "",
                ",".join(preferred),
                server_name or "unknown",
                attempts,
            )
            return True
        return False

    def log_preferred_server_reached(self, feed):
        """Log the accepted preferred backend for APRS-IS diagnosis."""
        stats = self.feed_stats(feed)
        stats["preferred_server_attempts"] = 0
        stats["preferred_server_fallback"] = False
        logging.info(
            "APRS-IS preferred server reached name=%s host=%s server=%s "
            "address=%s",
            feed.get("name") or "",
            feed.get("host") or "",
            stats.get("server_name") or "",
            stats.get("server_address") or "",
        )

    def update_overall_state(self):
        """Expose one combined System-row state for all APRS-IS feeds."""
        online = [
            feed["name"]
            for feed in self.active_feeds
            if self._feed_states.get(feed["name"]) == STATE_ONLINE
        ]
        offline = [
            feed["name"]
            for feed in self.active_feeds
            if self._feed_states.get(feed["name"]) != STATE_ONLINE
        ]
        self.state = STATE_ONLINE if online else STATE_OFFLINE
        if offline and online:
            self.warning = "APRS-IS feed(s) offline: {}".format(", ".join(offline))
        elif offline:
            details = [
                "{}: {}".format(name, self._feed_warnings.get(name))
                for name in offline
                if self._feed_warnings.get(name)
            ]
            self.warning = (
                "APRS-IS connection failed: {}".format("; ".join(details))
                if details
                else "APRS-IS connection not established yet."
            )
        else:
            self.warning = None

    async def read_server_banner(self, reader, feed=None):
        """Read the APRS-IS greeting before sending the login line.

        Most servers accept a login immediately after TCP connect, but reading
        the banner first matches the common APRS-IS client flow and records the
        actual backend node before filter/login negotiation.
        """
        feed = feed or (self.active_feeds[0] if self.active_feeds else {})
        timeout = self.server_banner_timeout(feed)
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            logging.info(
                "APRS-IS banner timeout feed=%s host=%s port=%s",
                feed.get("name") or "",
                feed.get("host") or "",
                feed.get("port") or "",
            )
            return
        if not line:
            return
        text = line.decode("utf-8", errors="replace").strip()
        if text:
            await self.handle_server_comment(feed, text)

    async def login(self, writer, feed=None):
        """Send the APRS-IS login line for a filtered client connection."""
        feed = feed or (self.active_feeds[0] if self.active_feeds else {})
        login = "user {} pass {} vers Skannr {} filter {}\n".format(
            feed.get("callsign") or self.callsign,
            feed.get("passcode") or self.passcode,
            self.version(),
            feed.get("filter") or self.filter,
        )
        writer.write(login.replace("\n", "\r\n").encode("ascii", errors="ignore"))
        await writer.drain()

    async def read_packets(self, reader, feed=None):
        """Read and normalize APRS-IS lines until the connection drops."""
        feed = feed or (self.active_feeds[0] if self.active_feeds else {})
        read_timeout = float(self.config.get("read_timeout_sec", 600))
        status_interval = float(self.config.get("status_interval_sec", 60))
        last_line_epoch = now_epoch()
        while self._running:
            timeout = read_timeout
            if status_interval > 0:
                remaining = max(1.0, read_timeout - (now_epoch() - last_line_epoch))
                timeout = min(status_interval, remaining)
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            except asyncio.TimeoutError:
                await self.emit_status(feed)
                if read_timeout > 0 and now_epoch() - last_line_epoch >= read_timeout:
                    logging.info(
                        "APRS-IS read timeout name=%s host=%s idle=%ss %s",
                        feed.get("name") or "",
                        feed.get("host") or "",
                        int(now_epoch() - last_line_epoch),
                        self.feed_runtime_log_summary(feed),
                    )
                    raise TimeoutError("no APRS-IS data for {}s".format(int(read_timeout)))
                continue
            if not line:
                logging.info(
                    "APRS-IS feed closed by server name=%s host=%s %s",
                    feed.get("name") or "",
                    feed.get("host") or "",
                    self.feed_runtime_log_summary(feed),
                )
                raise ConnectionError("feed closed")
            last_line_epoch = now_epoch()
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            self.increment_feed_stat(feed, "raw_lines")
            if text.startswith("#"):
                await self.handle_server_comment(feed, text)
                continue
            self.increment_feed_stat(feed, "packets_seen")
            self.set_feed_stat(feed, "last_packet_epoch", round(last_line_epoch, 3))
            self.set_feed_stat(feed, "last_packet_callsign", self.packet_callsign(text))
            self.set_feed_stat(feed, "last_packet", compact_aprs_text(text, 180))
            packet = self.parse_packet(text, feed)
            if not packet:
                await self.emit_status(feed)
                continue
            if not self.allow_packet_emit():
                self.record_packet_drop(feed, "rate", text, packet.get("data") or {})
                await self.emit_status(feed)
                continue
            self.increment_feed_stat(feed, "emitted")
            self.set_feed_stat(feed, "last_emitted_epoch", round(now_epoch(), 3))
            self.set_feed_stat(
                feed,
                "last_emitted_callsign",
                packet["data"].get("callsign") or "",
            )
            await self.emit(packet["event_type"], packet["data"], packet["severity"])

    async def emit_status(self, feed=None):
        """Publish non-persistent APRS-IS counters while a quiet feed is open."""
        feed = feed or (self.active_feeds[0] if self.active_feeds else {})
        feed_name = feed.get("name") or "primary"
        now = now_epoch()
        interval = float(self.config.get("status_interval_sec", 60))
        previous = self._last_status_emit_epoch.get(feed_name, 0)
        if previous and interval > 0 and now - previous < interval:
            return
        self._last_status_emit_epoch[feed_name] = now
        self.set_feed_stat(feed, "last_status_epoch", round(now, 3))
        await self.bus.publish(
            {
                "collector": self.config_key,
                "type": "collector_status",
                "severity": "info",
                "timestamp_epoch": now,
                "data": self.health_payload(feed),
            }
        )

    def packet_callsign(self, text):
        """Extract the packet source callsign before full APRS parsing."""
        match = re.match(r"^([^>:\s]+)>", text or "")
        return compact_aprs_text(match.group(1), 32) if match else ""

    def record_packet_drop(self, feed, reason, line="", data=None):
        """Record one packet Skannr received but did not emit downstream."""
        data = data or {}
        counter = {
            "parse": "dropped_parse",
            "geofence": "dropped_geofence",
            "rate": "dropped_rate",
        }.get(reason)
        if counter:
            self.increment_feed_stat(feed, counter)
        callsign = data.get("callsign") or self.packet_callsign(line)
        packet_type = data.get("packet_type") or ""
        self.set_feed_stat(feed, "last_dropped_epoch", round(now_epoch(), 3))
        self.set_feed_stat(feed, "last_dropped_reason", reason)
        self.set_feed_stat(feed, "last_dropped_callsign", callsign)
        self.set_feed_stat(feed, "last_dropped_packet_type", packet_type)
        self.set_feed_stat(feed, "last_dropped_packet", compact_aprs_text(line, 180))
        if aprsis_bool(self.config.get("log_dropped_packets"), True):
            logging.info(
                "APRS-IS packet dropped feed=%s reason=%s callsign=%s type=%s "
                "packet=%s",
                (feed or {}).get("name") or "",
                reason,
                callsign,
                packet_type,
                compact_aprs_text(line, 180),
            )

    async def handle_server_comment(self, feed, text):
        """Record APRS-IS server comments for filter/login diagnosis."""
        message = compact_aprs_text(text, 220)
        identity = aprsis_server_identity(message)
        self.increment_feed_stat(feed, "server_comments")
        self.set_feed_stat(feed, "last_server_message", message)
        if identity.get("server_name"):
            self.set_feed_stat(feed, "server_name", identity["server_name"])
        if identity.get("server_address"):
            self.set_feed_stat(feed, "server_address", identity["server_address"])
        logging.info(
            "APRS-IS server comment feed=%s message=%s",
            feed.get("name") or "",
            message,
        )
        self.enforce_preferred_server(feed)
        if aprsis_bool(self.config.get("emit_server_messages"), False):
            await self.emit("server_status", self.health_payload(feed), "info")

    def enforce_preferred_server(self, feed):
        """Disconnect pooled feeds that landed on a non-preferred backend."""
        preferred = (feed or {}).get("preferred_servers") or []
        if not preferred:
            return
        server_name = self.feed_stats(feed).get("server_name") or ""
        if not server_name:
            return
        if aprsis_server_matches(server_name, preferred):
            self.log_preferred_server_reached(feed)
            return
        if self.handle_preferred_server_miss(feed, server_name, "mismatch"):
            return
        raise PreferredServerMismatch(self.preferred_server_miss_text(feed, server_name))

    def feed_stats(self, feed):
        """Return mutable counters for one APRS-IS feed."""
        name = (feed or {}).get("name") or "primary"
        return self._feed_stats.setdefault(
            name,
            {
                "raw_lines": 0,
                "server_comments": 0,
                "packets_seen": 0,
                "emitted": 0,
                "dropped_parse": 0,
                "dropped_geofence": 0,
                "dropped_rate": 0,
                "connected_at_epoch": None,
                "last_connect_attempt_epoch": None,
                "last_disconnect_epoch": None,
                "last_disconnect_reason": "",
                "last_packet_epoch": None,
                "last_emitted_epoch": None,
                "last_status_epoch": None,
                "last_dropped_epoch": None,
                "last_server_message": "",
                "last_packet": "",
                "last_packet_callsign": "",
                "last_emitted_callsign": "",
                "last_dropped_reason": "",
                "last_dropped_callsign": "",
                "last_dropped_packet_type": "",
                "last_dropped_packet": "",
                "server_name": "",
                "server_address": "",
                "preferred_server_attempts": 0,
                "preferred_server_last_miss": "",
                "preferred_server_last_miss_reason": "",
                "preferred_server_fallback": False,
                "connection_attempts": 0,
                "disconnect_count": 0,
            },
        )

    def increment_feed_stat(self, feed, key):
        """Increment a per-feed diagnostic counter."""
        stats = self.feed_stats(feed)
        stats[key] = int(stats.get(key) or 0) + 1
        return stats[key]

    def set_feed_stat(self, feed, key, value):
        """Set a per-feed diagnostic value."""
        self.feed_stats(feed)[key] = value

    def record_disconnect(self, feed, exc):
        """Record one APRS-IS disconnect for status payloads and logs."""
        self.increment_feed_stat(feed, "disconnect_count")
        self.set_feed_stat(feed, "last_disconnect_epoch", round(now_epoch(), 3))
        self.set_feed_stat(feed, "last_disconnect_reason", compact_aprs_text(exc, 180))

    def feed_runtime_log_summary(self, feed):
        """Return compact per-feed counters for skannr.log diagnostics."""
        stats = self.feed_stats(feed)
        parts = [
            "server={}".format(stats.get("server_name") or "unknown"),
            "packets_seen={}".format(int(stats.get("packets_seen") or 0)),
            "emitted={}".format(int(stats.get("emitted") or 0)),
            "drops={}".format(
                int(stats.get("dropped_parse") or 0)
                + int(stats.get("dropped_geofence") or 0)
                + int(stats.get("dropped_rate") or 0)
            ),
        ]
        if stats.get("last_packet_callsign"):
            parts.append("last_packet={}".format(stats.get("last_packet_callsign")))
        if stats.get("last_packet_epoch") is not None:
            parts.append(
                "idle={}s".format(
                    int(max(0, now_epoch() - float(stats.get("last_packet_epoch"))))
                )
            )
        return " ".join(parts)

    async def emit_offline(self, feed=None, exc=None):
        """Emit OFFLINE state without writing the same failure every few seconds."""
        feed = feed or (self.active_feeds[0] if self.active_feeds else {})
        feed_name = feed.get("name") or "primary"
        interval = float(self.config.get("offline_event_interval_sec", 300))
        now = now_epoch()
        previous = self._last_offline_emit_epoch.get(feed_name, 0)
        if previous and now - previous < interval:
            return
        self._last_offline_emit_epoch[feed_name] = now
        logging.info(
            "APRS-IS feed offline name=%s host=%s port=%s reason=%s",
            feed.get("name") or "",
            feed.get("host") or "",
            feed.get("port") or "",
            exc or self.warning or "",
        )
        await self.emit(
            "collector_offline",
            self.health_payload(feed, exc),
            "warning",
        )

    def allow_packet_emit(self):
        """Rate-limit packet persistence so a busy APRS area cannot flood logs."""
        limit = int(self.config.get("max_events_per_minute", 120) or 0)
        if limit <= 0:
            return True
        now = now_epoch()
        self._recent_emit_epochs = [
            epoch for epoch in self._recent_emit_epochs if now - epoch < 60
        ]
        if len(self._recent_emit_epochs) >= limit:
            return False
        self._recent_emit_epochs.append(now)
        return True

    def parse_packet(self, line, feed=None):
        """Return normalized APRS packet data for one APRS-IS line."""
        feed = feed or (self.active_feeds[0] if self.active_feeds else None)
        feed = feed or (self.feeds[0] if self.feeds else {})
        match = re.match(r"^([^>:\s]+)>([^:]+):(.+)$", line)
        if not match:
            self.record_packet_drop(feed, "parse", line)
            return None
        source, path, payload = match.groups()
        destination, via_path, q_construct, igate = self.path_parts(path)
        packet_type = self.packet_type(payload)
        stats = self.feed_stats(feed)
        data = {
            "callsign": compact_aprs_text(source, 32),
            "destination": destination,
            "path": compact_aprs_text(path, 160),
            "via_path": via_path,
            "q_construct": q_construct,
            "igate": igate,
            "packet_type": packet_type,
            "payload": compact_aprs_text(payload, APRS_PAYLOAD_MAX),
            "host": feed.get("host") or self.host,
            "port": feed.get("port") or self.port,
            "filter": feed.get("filter") or self.filter,
            "feed_name": feed.get("name") or "",
            "feed_role": feed.get("role") or "",
            "server_name": stats.get("server_name") or "",
            "server_address": stats.get("server_address") or "",
            "preferred_servers": feed.get("preferred_servers") or [],
            "internet_fed": True,
        }
        try:
            parsed = self.parse_payload(payload, packet_type, destination)
        except Exception as exc:
            self.record_packet_drop(feed, "parse", line, data)
            logging.info(
                "APRS-IS parser failed feed=%s callsign=%s type=%s error=%s",
                feed.get("name") or "",
                data.get("callsign") or "",
                packet_type,
                exc,
            )
            return None
        data.update(
            {
                key: value
                for key, value in parsed.items()
                if value not in ("", None)
            }
        )
        packet_type = data.get("packet_type") or packet_type
        if not self.apply_feed_geofence(feed, data):
            self.record_packet_drop(feed, "geofence", line, data)
            return None
        if feed.get("store_raw") or self.store_raw:
            data["raw"] = compact_aprs_text(line, 500)
            data["store_raw"] = True
        title_type = packet_type if packet_type != "packet" else "activity"
        return {
            "event_type": "aprs_{}".format(packet_type),
            "severity": "info",
            "data": clean_aprs_data(data),
            "title_type": title_type,
        }

    def apply_feed_geofence(self, feed, data):
        """Drop packets outside a feed's client-side geofence."""
        if not feed.get("enforce_radius"):
            return True
        geofence = feed.get("geofence") or {}
        distance = aprsis_distance_km(
            geofence.get("latitude"),
            geofence.get("longitude"),
            data.get("latitude"),
            data.get("longitude"),
        )
        if distance is None:
            return False
        if distance > float(geofence.get("radius_km") or 0):
            return False
        data["distance_from_filter_km"] = round(distance, 2)
        data["geofence_enforced"] = True
        data["geofence_latitude"] = geofence.get("latitude")
        data["geofence_longitude"] = geofence.get("longitude")
        data["geofence_radius_km"] = geofence.get("radius_km")
        return True

    def feed_label(self, feed):
        """Return a readable label for System Status."""
        return "{}:{} {} ({})".format(
            feed.get("host") or "feed",
            feed.get("port") or "",
            feed.get("filter") or "",
            feed.get("name") or "primary",
        )

    def packet_type(self, payload):
        """Classify a small set of useful APRS packet families."""
        if not payload:
            return "packet"
        marker = payload[0]
        if marker in ("`", "'"):
            return "position"
        if marker == ";":
            return "object"
        if marker == ":":
            return "message"
        if marker == ">":
            return "status"
        if marker == "_":
            return "weather"
        if marker in ("!", "=", "/", "@"):
            return "position"
        if marker == "T":
            return "telemetry"
        return "packet"

    def path_parts(self, path):
        """Split destination, digipeater path, q construct, and igate fields."""
        parts = [compact_aprs_text(part.strip(), 40) for part in str(path).split(",")]
        parts = [part for part in parts if part]
        destination = parts[0] if parts else ""
        hops = parts[1:]
        q_index = None
        for index, hop in enumerate(hops):
            if hop.startswith("qA"):
                q_index = index
                break
        if q_index is None:
            return destination, ",".join(hops), "", ""
        via_path = ",".join(hops[:q_index])
        q_construct = hops[q_index]
        igate = hops[q_index + 1] if q_index + 1 < len(hops) else ""
        return destination, via_path, q_construct, igate

    def parse_payload(self, payload, packet_type, destination=""):
        """Parse common APRS position/object/message fields."""
        if payload and payload[0] in ("`", "'"):
            return self.parse_mic_e(destination, payload)
        if packet_type == "message":
            return self.parse_message(payload)
        if packet_type == "status":
            return {"comment": compact_aprs_text(payload[1:], APRS_PAYLOAD_MAX)}
        if packet_type == "object":
            return self.parse_object(payload)
        if packet_type == "position":
            return self.parse_position(payload)
        if packet_type == "weather":
            return self.parse_positionless_weather(payload)
        return {}

    def parse_mic_e(self, destination, payload):
        """Decode the useful Mic-E position, motion, and status fields."""
        dst = str(destination or "").split("-", 1)[0].upper()
        if len(dst) != 6 or len(payload or "") < 9:
            return {"comment": compact_aprs_text((payload or "")[1:], APRS_PAYLOAD_MAX)}
        if not re.match(r"^[0-9A-Z]{3}[0-9L-Z]{3}$", dst):
            return {"comment": compact_aprs_text(payload[1:], APRS_PAYLOAD_MAX)}
        body = payload[1:]
        latitude, ambiguity = self.mic_e_latitude(dst)
        longitude = self.mic_e_longitude(dst, body, ambiguity)
        speed_knots, course = self.mic_e_motion(body)
        result = {
            "aprs_format": "mic-e",
            "mic_e_message": self.mic_e_message(dst),
            "mic_e_marker": "old position" if payload[0] == "`" else "current position",
            "symbol": compact_aprs_text(body[6:8], 8),
            "symbol_code": compact_aprs_text(body[6:7], 4),
            "symbol_table": compact_aprs_text(body[7:8], 4),
            "comment": compact_aprs_text(body[8:], APRS_PAYLOAD_MAX),
        }
        if ambiguity:
            result["position_ambiguity"] = ambiguity
        if latitude is not None:
            result["latitude"] = latitude
        if longitude is not None:
            result["longitude"] = longitude
        if speed_knots is not None:
            result["speed_knots"] = speed_knots
            result["speed_kmh"] = round(speed_knots * 1.852, 1)
        if course is not None:
            result["course_deg"] = course
        return result

    def mic_e_latitude(self, destination):
        """Return Mic-E latitude and position ambiguity from destination text."""
        digits = []
        for char in destination:
            if char in "KLZ":
                digits.append(" ")
            elif char.isdigit():
                digits.append(char)
            elif "A" <= char <= "J":
                digits.append(str(ord(char) - ord("A")))
            elif "P" <= char <= "Y":
                digits.append(str(ord(char) - ord("P")))
            else:
                return None, 0
        text = "".join(digits)
        match = re.match(r"^\d+( *)$", text)
        if not match:
            return None, 0
        ambiguity = len(match.group(1))
        digits = list(text)
        if ambiguity >= 4:
            digits[2] = "3"
        elif ambiguity > 0:
            digits[6 - ambiguity] = "5"
        normalized = "".join(digits).replace(" ", "0")
        try:
            minutes = float("{}.{}".format(normalized[2:4], normalized[4:6]))
            latitude = int(normalized[:2]) + minutes / 60.0
        except ValueError:
            return None, ambiguity
        if ord(destination[3]) <= ord("L"):
            latitude = -latitude
        return round(latitude, 6), ambiguity

    def mic_e_longitude(self, destination, body, ambiguity):
        """Return Mic-E longitude from the payload and destination modifiers."""
        try:
            degrees = ord(body[0]) - 28
            if ord(destination[4]) >= ord("P"):
                degrees += 100
            if 180 <= degrees <= 189:
                degrees -= 80
            elif 190 <= degrees <= 199:
                degrees -= 190
            minutes = ord(body[1]) - 28.0
            if minutes >= 60:
                minutes -= 60
            minutes += (ord(body[2]) - 28.0) / 100.0
        except (TypeError, IndexError):
            return None
        minutes = self.ambiguous_minutes(minutes, ambiguity)
        longitude = degrees + minutes / 60.0
        if ord(destination[5]) >= ord("P"):
            longitude = -longitude
        return round(longitude, 6)

    def ambiguous_minutes(self, minutes, ambiguity):
        """Place ambiguous Mic-E minutes in the center of their uncertainty box."""
        if ambiguity >= 4:
            return 30.0
        if ambiguity == 3:
            return (int(minutes / 10) + 0.5) * 10.0
        if ambiguity == 2:
            return int(minutes) + 0.5
        if ambiguity == 1:
            return (int(minutes * 10) + 0.5) / 10.0
        return minutes

    def mic_e_motion(self, body):
        """Return Mic-E speed in knots and course in degrees."""
        try:
            speed = (ord(body[3]) - 28) * 10
            course_seed = ord(body[4]) - 28
            speed += int(course_seed / 10)
            course = (course_seed % 10) * 100 + ord(body[5]) - 28
        except (TypeError, IndexError):
            return None, None
        if speed >= 800:
            speed -= 800
        if course >= 400:
            course -= 400
        return speed, course

    def mic_e_message(self, destination):
        """Return the Mic-E status/message type encoded in destination bits."""
        bits = []
        custom = False
        for char in destination[:3]:
            if char.isdigit() or char == "L":
                bits.append("0")
            elif "P" <= char <= "Z":
                bits.append("1")
            elif "A" <= char <= "K":
                bits.append("1")
                custom = True
            else:
                return ""
        key = "".join(bits)
        table = MIC_E_CUSTOM_MESSAGES if custom else MIC_E_STANDARD_MESSAGES
        return table.get(key, "")

    def parse_message(self, payload):
        """Parse the APRS message addressee and text when present."""
        if len(payload) < 11 or not payload.startswith(":"):
            return {}
        addressee = compact_aprs_text(payload[1:10].strip(), 32)
        message = compact_aprs_text(payload[10:].lstrip(":"), APRS_PAYLOAD_MAX)
        return {"addressee": addressee, "message": message}

    def parse_object(self, payload):
        """Parse an APRS object name plus optional uncompressed position."""
        result = {"object_name": compact_aprs_text(payload[1:10].strip(), 64)}
        if len(payload) >= 37:
            result.update(
                self.position_fields(
                    payload[18:26],
                    payload[27:36],
                    payload[26:27] + payload[36:37],
                    payload[37:],
                )
            )
        return result

    def parse_position(self, payload):
        """Parse common uncompressed APRS position payloads."""
        if payload[0] in ("!", "=") and len(payload) >= 20:
            return self.position_fields(
                payload[1:9],
                payload[10:19],
                payload[9:10] + payload[19:20],
                payload[20:],
            )
        if payload[0] in ("/", "@") and len(payload) >= 27:
            return self.position_fields(
                payload[8:16],
                payload[17:26],
                payload[16:17] + payload[26:27],
                payload[27:],
            )
        return {"comment": compact_aprs_text(payload[1:], APRS_PAYLOAD_MAX)}

    def position_fields(self, lat_text, lon_text, symbol, comment):
        """Return decoded latitude/longitude when the APRS position is plain."""
        latitude = self.parse_latitude(lat_text)
        longitude = self.parse_longitude(lon_text)
        result = {
            "symbol": compact_aprs_text(symbol, 8),
            "comment": compact_aprs_text(comment, APRS_PAYLOAD_MAX),
        }
        if str(symbol or "").endswith("_"):
            result.update(self.parse_weather_data(comment))
            result["packet_type"] = "weather"
            result["aprs_format"] = "weather"
        if latitude is not None:
            result["latitude"] = latitude
        if longitude is not None:
            result["longitude"] = longitude
        return result

    def parse_positionless_weather(self, payload):
        """Parse APRS positionless weather packets that start with '_'."""
        body = str(payload or "")[1:]
        result = {"packet_type": "weather", "aprs_format": "weather"}
        if len(body) >= 8 and body[:8].isdigit():
            result["weather_timestamp"] = compact_aprs_text(body[:8], 16)
            body = body[8:]
        result.update(self.parse_weather_data(body))
        if "comment" not in result:
            result["comment"] = compact_aprs_text(body, APRS_PAYLOAD_MAX)
        return result

    def parse_weather_data(self, text):
        """Parse APRS weather fields from a position or positionless report."""
        body = str(text or "")
        result = {}
        match = re.match(r"^(\d{3})/(\d{3})", body)
        if match:
            result["wind_direction_deg"] = self.to_int(match.group(1))
            result["wind_speed_mph"] = self.to_int(match.group(2))
            body = body[7:]
        while body:
            field = body[0]
            value = None
            consumed = 0
            if field in ("c", "s", "S", "g", "r", "p", "P", "L", "l", "#"):
                if len(body) < 4 or not re.match(r"^[A-Za-z#][0-9. ]{3}", body):
                    break
                value = body[1:4]
                consumed = 4
                if (
                    field == "s"
                    and result.get("wind_direction_deg") is not None
                    and result.get("wind_speed_mph") is None
                ):
                    field = "S"
            elif field == "t":
                match = re.match(r"^t(-?\d{2,3})", body)
                if not match:
                    break
                value = match.group(1)
                consumed = 1 + len(value)
            elif field == "h":
                if len(body) < 3 or not re.match(r"^h[0-9. ]{2}", body):
                    break
                value = body[1:3]
                consumed = 3
            elif field == "b":
                if len(body) < 6 or not re.match(r"^b[0-9. ]{5}", body):
                    break
                value = body[1:6]
                consumed = 6
            else:
                break
            self.add_weather_field(result, field, value)
            body = body[consumed:]
        result["comment"] = compact_aprs_text(body, APRS_PAYLOAD_MAX)
        summary = self.weather_summary(result)
        if summary:
            result["weather_summary"] = summary
        return result

    def add_weather_field(self, result, field, raw_value):
        """Add one decoded APRS weather value to a result dictionary."""
        value = str(raw_value or "").replace(" ", "")
        if not value or "." in value:
            return
        if field == "c":
            result["wind_direction_deg"] = self.to_int(value)
        elif field == "S":
            result["wind_speed_mph"] = self.to_int(value)
        elif field == "g":
            result["wind_gust_mph"] = self.to_int(value)
        elif field == "t":
            result["temperature_f"] = self.to_int(value)
        elif field == "r":
            result["rain_1h_in"] = self.hundredths(value)
        elif field == "p":
            result["rain_24h_in"] = self.hundredths(value)
        elif field == "P":
            result["rain_since_midnight_in"] = self.hundredths(value)
        elif field == "h":
            humidity = self.to_int(value)
            if humidity == 0:
                humidity = 100
            result["humidity_percent"] = humidity
        elif field == "b":
            try:
                result["pressure_hpa"] = round(float(value) / 10.0, 1)
            except ValueError:
                pass
        elif field == "L":
            result["luminosity_w_m2"] = self.to_int(value)
        elif field == "l":
            luminosity = self.to_int(value)
            if luminosity is not None:
                result["luminosity_w_m2"] = luminosity + 1000
        elif field == "s":
            result["snow_in"] = self.hundredths(value)

    def weather_summary(self, data):
        """Return compact APRS weather text for live tables and Reports."""
        parts = []
        wind = []
        if data.get("wind_direction_deg") is not None:
            wind.append("{} deg".format(data["wind_direction_deg"]))
        if data.get("wind_speed_mph") is not None:
            wind.append("{} mph".format(data["wind_speed_mph"]))
        if data.get("wind_gust_mph") is not None:
            wind.append("gust {} mph".format(data["wind_gust_mph"]))
        if wind:
            parts.append("wind {}".format(" ".join(wind)))
        if data.get("temperature_f") is not None:
            parts.append("{} F".format(data["temperature_f"]))
        if data.get("humidity_percent") is not None:
            parts.append("humidity {}%".format(data["humidity_percent"]))
        if data.get("pressure_hpa") is not None:
            parts.append("{} hPa".format(data["pressure_hpa"]))
        if data.get("rain_1h_in") is not None:
            parts.append("1h rain rate {:.2f} in/hr".format(data["rain_1h_in"]))
        if data.get("rain_24h_in") is not None:
            parts.append("rain 24h {:.2f} in".format(data["rain_24h_in"]))
        if data.get("rain_since_midnight_in") is not None:
            parts.append("rain midnight {:.2f} in".format(data["rain_since_midnight_in"]))
        if data.get("luminosity_w_m2") is not None:
            parts.append("luminosity {} W/m2".format(data["luminosity_w_m2"]))
        if data.get("snow_in") is not None:
            parts.append("snow {:.2f} in".format(data["snow_in"]))
        return compact_aprs_text("; ".join(parts), APRS_PAYLOAD_MAX)

    def to_int(self, value):
        """Return an integer for APRS numeric fields, or None."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def hundredths(self, value):
        """Return an APRS hundredths-of-an-inch value as inches."""
        try:
            return round(int(value) / 100.0, 2)
        except (TypeError, ValueError):
            return None

    def parse_latitude(self, value):
        """Decode DDMM.mmN/S latitude."""
        text = str(value or "")
        if len(text) < 8:
            return None
        return self.coordinate(text[:2], text[2:7], text[7:8], ("N", "S"))

    def parse_longitude(self, value):
        """Decode DDDMM.mmE/W longitude."""
        text = str(value or "")
        if len(text) < 9:
            return None
        return self.coordinate(text[:3], text[3:8], text[8:9], ("E", "W"))

    def coordinate(self, degrees, minutes, hemisphere, expected):
        """Return decimal degrees for APRS uncompressed coordinates."""
        hemisphere = hemisphere.upper()
        if hemisphere not in expected:
            return None
        try:
            value = float(degrees) + float(minutes) / 60.0
        except ValueError:
            return None
        if hemisphere in ("S", "W"):
            value = -value
        return round(value, 6)

    def health_payload(self, feed=None, exc=None):
        """Return status fields shared by ONLINE/OFFLINE events."""
        feed = feed or (self.active_feeds[0] if self.active_feeds else {})
        geofence = feed.get("geofence") or {}
        feed_name = feed.get("name") or "primary"
        stats = self.feed_stats(feed)
        reason = (
            str(exc)
            if exc is not None
            else self._feed_warnings.get(feed_name)
            or stats.get("last_disconnect_reason")
            or self.warning
        )
        now = now_epoch()
        connected_epoch = stats.get("connected_at_epoch")
        last_packet_epoch = stats.get("last_packet_epoch")
        last_connect_attempt_epoch = stats.get("last_connect_attempt_epoch")
        last_disconnect_epoch = stats.get("last_disconnect_epoch")
        dropped_total = (
            int(stats.get("dropped_parse") or 0)
            + int(stats.get("dropped_geofence") or 0)
            + int(stats.get("dropped_rate") or 0)
        )
        return clean_aprs_data(
            {
                "feed_name": feed.get("name") or "",
                "feed_role": feed.get("role") or "",
                "feed_state": self._feed_states.get(feed.get("name") or "", self.state),
                "host": feed.get("host") or self.host,
                "port": feed.get("port") or self.port,
                "filter": feed.get("filter") or self.filter,
                "include_callsigns": feed.get("include_callsigns") or [],
                "preferred_servers": feed.get("preferred_servers") or [],
                "callsign": feed.get("callsign") or self.callsign,
                "feed_count": len(self.active_feeds or self.feeds),
                "reason": reason,
                "geofence_enforced": bool(feed.get("enforce_radius")),
                "geofence_latitude": geofence.get("latitude"),
                "geofence_longitude": geofence.get("longitude"),
                "geofence_radius_km": geofence.get("radius_km"),
                "raw_lines": stats.get("raw_lines"),
                "server_comments": stats.get("server_comments"),
                "packets_seen": stats.get("packets_seen"),
                "emitted": stats.get("emitted"),
                "dropped_parse": stats.get("dropped_parse"),
                "dropped_geofence": stats.get("dropped_geofence"),
                "dropped_rate": stats.get("dropped_rate"),
                "dropped_total": dropped_total,
                "connected_at_epoch": connected_epoch,
                "last_connect_attempt_epoch": last_connect_attempt_epoch,
                "last_disconnect_epoch": last_disconnect_epoch,
                "last_disconnect_reason": stats.get("last_disconnect_reason") or "",
                "connection_attempts": stats.get("connection_attempts"),
                "disconnect_count": stats.get("disconnect_count"),
                "last_packet_epoch": last_packet_epoch,
                "last_emitted_epoch": stats.get("last_emitted_epoch"),
                "last_status_epoch": stats.get("last_status_epoch"),
                "last_dropped_epoch": stats.get("last_dropped_epoch"),
                "connection_age_sec": (
                    round(now - float(connected_epoch), 1)
                    if connected_epoch is not None
                    else None
                ),
                "idle_sec": (
                    round(now - float(last_packet_epoch), 1)
                    if last_packet_epoch is not None
                    else None
                ),
                "last_server_message": stats.get("last_server_message") or "",
                "server_name": stats.get("server_name") or "",
                "server_address": stats.get("server_address") or "",
                "preferred_server_attempts": stats.get("preferred_server_attempts"),
                "preferred_server_max_attempts": self.preferred_server_max_attempts(feed),
                "preferred_server_last_miss": stats.get("preferred_server_last_miss") or "",
                "preferred_server_last_miss_reason": (
                    stats.get("preferred_server_last_miss_reason") or ""
                ),
                "preferred_server_fallback": bool(stats.get("preferred_server_fallback")),
                "last_packet_callsign": stats.get("last_packet_callsign") or "",
                "last_packet": stats.get("last_packet") or "",
                "last_emitted_callsign": stats.get("last_emitted_callsign") or "",
                "last_dropped_reason": stats.get("last_dropped_reason") or "",
                "last_dropped_callsign": stats.get("last_dropped_callsign") or "",
                "last_dropped_packet_type": stats.get("last_dropped_packet_type") or "",
                "last_dropped_packet": stats.get("last_dropped_packet") or "",
                "internet_fed": True,
            }
        )

    def version(self):
        """Return the Skannr VERSION string for the APRS-IS login banner."""
        try:
            with open(VERSION_PATH, "r", encoding="utf-8") as fh:
                return compact_aprs_text(fh.read().strip(), 32) or "unknown"
        except OSError:
            return "unknown"
