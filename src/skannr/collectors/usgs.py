"""Optional USGS earthquake polling collector."""

import asyncio
import hashlib
import json
import math
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

from ..log_utils import format_epoch
from .base import BaseCollector, STATE_OFFLINE, STATE_ONLINE, STATE_RETRYING


USGS_QUERY_ENDPOINT = "https://earthquake.usgs.gov/fdsnws/event/1/query"
USGS_FIELD_MAX = 240


def compact_usgs_text(value, max_length=USGS_FIELD_MAX):
    """Return compact one-line USGS text."""
    if value in (None, ""):
        return ""
    text = " ".join(str(value).replace("\x00", " ").split())
    return text[:max_length] if text else ""


def clean_usgs_data(data):
    """Scrub USGS event data loaded from retained JSONL."""
    if not isinstance(data, dict):
        return {}
    cleaned = {}
    numeric_keys = {
        "magnitude",
        "latitude",
        "longitude",
        "depth_km",
        "distance_km",
        "event_time_epoch",
        "updated_epoch",
        "felt",
        "cdi",
        "mmi",
        "tsunami",
    }
    bool_keys = {"internet_fed"}
    for key, value in data.items():
        if value in (None, "", []):
            continue
        if key in numeric_keys:
            cleaned[key] = value
        elif key in bool_keys:
            cleaned[key] = bool(value)
        else:
            text = compact_usgs_text(value)
            if text:
                cleaned[key] = text
    return cleaned


class USGSCollector(BaseCollector):
    """Poll USGS GeoJSON earthquake feeds for a configured local area."""

    config_key = "usgs"
    name = "USGS"
    tab_label = "USGS"
    required_hardware = "Internet access"

    @classmethod
    def hardware_status(cls, config):
        """Return configured USGS query metadata."""
        return {
            "internet_source": True,
            "enabled": bool(config.get("enabled", False)),
            "latitude": config.get("latitude"),
            "longitude": config.get("longitude"),
            "radius_km": config.get("radius_km"),
        }

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self._fingerprints = {}

    def detect(self):
        """USGS needs either a full query URL or a point/radius query."""
        if not self.config.get("url") and (
            self.config.get("latitude") in (None, "")
            or self.config.get("longitude") in (None, "")
        ):
            self.state = STATE_OFFLINE
            self.warning = "No USGS latitude/longitude or URL configured."
            return False
        self.active_hardware = "USGS earthquake feed"
        self.state = STATE_ONLINE
        self.warning = None
        return True

    async def start(self):
        """Poll USGS until stopped."""
        self._running = True
        if not self.detect():
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return
        await self.emit(
            "collector_online",
            {"source": "USGS", "url": self.query_url(), "internet_fed": True},
        )
        interval = float(self.config.get("poll_interval_sec", 300))
        while self._running:
            try:
                events = await self.run_blocking(self.poll_once)
                self.state = STATE_ONLINE
                self.warning = None
                for data in events:
                    await self.emit(
                        "usgs_earthquake",
                        data,
                        "warning" if self.usgs_event_is_warning(data) else "info",
                    )
            except Exception as exc:
                self.state = STATE_RETRYING
                self.warning = "USGS poll failed: {}".format(exc)
                await self.emit(
                    "collector_retrying",
                    {"reason": self.warning, "internet_fed": True},
                    "warning",
                )
            await asyncio.sleep(interval)

    async def run_blocking(self, callback, *args):
        """Run a blocking network call without requiring Python 3.9 to_thread."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, callback, *args)

    def poll_once(self):
        """Fetch and return new/changed earthquake events."""
        payload = self.fetch_json(self.query_url())
        events = []
        for feature in payload.get("features") or []:
            if not isinstance(feature, dict):
                continue
            data = self.earthquake_data(feature)
            if not data.get("event_id"):
                continue
            key = "usgs:{}".format(data["event_id"])
            if self.changed(key, data.get("fingerprint")):
                events.append(data)
        return events

    def query_url(self):
        """Return the configured USGS query URL."""
        if self.config.get("url"):
            return str(self.config["url"])
        params = {
            "format": "geojson",
            "orderby": self.config.get("orderby", "time"),
            "latitude": self.config.get("latitude"),
            "longitude": self.config.get("longitude"),
            "maxradiuskm": self.config.get("radius_km", 300),
            "minmagnitude": self.config.get("min_magnitude", 5.0),
        }
        if self.config.get("lookback_days"):
            try:
                days = float(self.config["lookback_days"])
                params["starttime"] = (
                    datetime.utcnow() - timedelta(days=days)
                ).strftime("%Y-%m-%d")
            except (TypeError, ValueError):
                pass
        query = urllib.parse.urlencode(
            {key: value for key, value in params.items() if value not in (None, "")}
        )
        return "{}?{}".format(USGS_QUERY_ENDPOINT, query)

    def earthquake_data(self, feature):
        """Normalize one USGS GeoJSON feature."""
        props = feature.get("properties") or {}
        geometry = feature.get("geometry") or {}
        coords = geometry.get("coordinates") or []
        longitude = coords[0] if len(coords) > 0 else None
        latitude = coords[1] if len(coords) > 1 else None
        depth = coords[2] if len(coords) > 2 else None
        event_time_epoch = millis_epoch(props.get("time"))
        updated_epoch = millis_epoch(props.get("updated"))
        data = {
            "event_id": compact_usgs_text(feature.get("id") or props.get("ids") or "", 120),
            "magnitude": number_or_none(props.get("mag")),
            "place": compact_usgs_text(props.get("place"), 240),
            "latitude": number_or_none(latitude),
            "longitude": number_or_none(longitude),
            "depth_km": number_or_none(depth),
            "distance_km": self.distance_from_config(latitude, longitude),
            "event_time": format_epoch(event_time_epoch) if event_time_epoch else "",
            "event_time_epoch": event_time_epoch,
            "updated": format_epoch(updated_epoch) if updated_epoch else "",
            "updated_epoch": updated_epoch,
            "status": compact_usgs_text(props.get("status"), 80),
            "felt": number_or_none(props.get("felt")),
            "cdi": number_or_none(props.get("cdi")),
            "mmi": number_or_none(props.get("mmi")),
            "alert_color": compact_usgs_text(props.get("alert"), 40),
            "tsunami": int(props.get("tsunami") or 0),
            "detail_url": compact_usgs_text(props.get("url") or props.get("detail"), 240),
            "source": "USGS",
            "internet_fed": True,
        }
        data["fingerprint"] = self.fingerprint(
            data,
            (
                "magnitude",
                "place",
                "updated_epoch",
                "status",
                "felt",
                "cdi",
                "mmi",
                "alert_color",
                "tsunami",
            ),
        )
        return clean_usgs_data(data)

    def fetch_json(self, url):
        """Fetch one USGS GeoJSON URL."""
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/geo+json, application/json",
                "User-Agent": self.config.get("user_agent") or "Skannr USGS collector",
            },
        )
        with urllib.request.urlopen(
            request, timeout=float(self.config.get("request_timeout_sec", 15))
        ) as response:
            body = response.read()
        data = json.loads(body.decode("utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}

    def changed(self, key, fingerprint):
        """Return True when an event is new or materially changed."""
        if not fingerprint:
            return False
        if self._fingerprints.get(key) == fingerprint:
            return False
        self._fingerprints[key] = fingerprint
        return True

    def fingerprint(self, data, fields):
        """Return a stable fingerprint for material event changes."""
        payload = "|".join(str((data or {}).get(field) or "") for field in fields)
        return hashlib.sha1(payload.encode("utf-8", errors="replace")).hexdigest()

    def distance_from_config(self, latitude, longitude):
        """Return distance from the configured observer point."""
        try:
            center_lat = float(self.config.get("latitude"))
            center_lon = float(self.config.get("longitude"))
            lat = float(latitude)
            lon = float(longitude)
        except (TypeError, ValueError):
            return None
        return round(distance_km(center_lat, center_lon, lat, lon), 2)

    def usgs_event_is_warning(self, data):
        """Return True for USGS events that deserve warning severity."""
        magnitude = number_or_none((data or {}).get("magnitude")) or 0
        distance = number_or_none((data or {}).get("distance_km"))
        nearby_mag = float(self.config.get("warning_magnitude_nearby", 4.0))
        regional_mag = float(self.config.get("warning_magnitude_regional", 5.0))
        nearby_radius = float(self.config.get("warning_nearby_radius_km", 100))
        alert_color = str((data or {}).get("alert_color") or "").lower()
        if int((data or {}).get("tsunami") or 0):
            return True
        if alert_color in ("yellow", "orange", "red"):
            return True
        if distance is not None and distance <= nearby_radius and magnitude >= nearby_mag:
            return True
        return magnitude >= regional_mag


def number_or_none(value):
    """Return a float for numeric-looking values."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def millis_epoch(value):
    """Return seconds from USGS millisecond timestamps."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return int(number / 1000) if number > 100000000000 else int(number)


def distance_km(lat1, lon1, lat2, lon2):
    """Return approximate great-circle distance in kilometers."""
    radius = 6371.0
    phi1 = math.radians(float(lat1))
    phi2 = math.radians(float(lat2))
    delta_phi = math.radians(float(lat2) - float(lat1))
    delta_lambda = math.radians(float(lon2) - float(lon1))
    a = (
        math.sin(delta_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    )
    return radius * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
