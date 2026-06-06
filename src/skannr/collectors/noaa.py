"""Optional NOAA/NWS/NHC polling collector.

NOAA feeds are internet-fed situational context. They are useful for operator
alerts and reports, but they are not evidence from a local RF antenna.
"""

import asyncio
import calendar
import hashlib
import html
import json
import logging
import re
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

from ..log_utils import now_epoch, timestamp_epoch
from .base import BaseCollector, STATE_OFFLINE, STATE_ONLINE, STATE_RETRYING


NOAA_FIELD_MAX = 240
NOAA_TEXT_MAX = 800
NWS_ALERTS_ENDPOINT = "https://api.weather.gov/alerts/active"
NWS_POINTS_ENDPOINT = "https://api.weather.gov/points/{},{}"
NHC_FEEDS = {
    "atlantic": "https://www.nhc.noaa.gov/index-at.xml",
    "eastern_pacific": "https://www.nhc.noaa.gov/index-ep.xml",
    "central_pacific": "https://www.nhc.noaa.gov/index-cp.xml",
}
NHC_OUTLOOK_PHRASES = (
    "tropical weather outlook",
    "there are no tropical cyclones at this time",
)
NHC_STORM_PHRASES = (
    "hurricane",
    "tropical storm",
    "tropical depression",
    "subtropical storm",
    "subtropical depression",
    "potential tropical cyclone",
    "post-tropical cyclone",
    "remnants of",
)
NHC_NUMBERED_SYSTEM_RE = re.compile(
    r"\b(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|"
    r"thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|"
    r"[0-9]{1,2})[- ][a-z]\b"
)
def compact_noaa_text(value, max_length=NOAA_FIELD_MAX):
    """Return a compact one-line NOAA text field."""
    if value in (None, ""):
        return ""
    text = re.sub(
        r"\s+",
        " ",
        html.unescape(re.sub(r"(?is)<[^>]+>", " ", str(value))).replace("\x00", " "),
    ).strip()
    return text[:max_length] if text else ""


def clean_noaa_data(data):
    """Scrub NOAA event data loaded from retained JSONL."""
    if not isinstance(data, dict):
        return {}
    cleaned = {}
    numeric_keys = {
        "timestamp_epoch",
        "effective_epoch",
        "onset_epoch",
        "expires_epoch",
        "ends_epoch",
        "updated_epoch",
        "forecast_generated_epoch",
        "first_period_start_epoch",
        "last_period_end_epoch",
        "next_precip_start_epoch",
        "next_precip_end_epoch",
        "latitude",
        "longitude",
        "forecast_hour_count",
        "forecast_window_hours",
        "forecast_soon_hours",
        "precip_probability_threshold",
        "current_temperature_f",
        "temperature_min_f",
        "temperature_max_f",
        "temperature_change_f",
        "current_precip_probability",
        "max_precip_probability",
        "next_precip_probability",
        "max_wind_mph",
    }
    bool_keys = {"internet_fed", "precip_likely_soon"}
    list_keys = {"zones", "geocode_ugc", "geocode_same"}
    long_text_keys = {"description", "instruction", "summary"}
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
                text = compact_noaa_text(item, 80)
                if text and text not in items:
                    items.append(text)
            if items:
                cleaned[key] = items[:24]
        else:
            max_length = NOAA_TEXT_MAX if key in long_text_keys else NOAA_FIELD_MAX
            text = compact_noaa_text(value, max_length)
            if text:
                cleaned[key] = text
    return cleaned


class NOAACollector(BaseCollector):
    """Poll NOAA/NWS/NHC feeds and emit changed hazard advisories."""

    config_key = "noaa"
    name = "NOAA"
    tab_label = "NOAA"
    required_hardware = "Internet access"

    @classmethod
    def hardware_status(cls, config):
        """Return configured feed metadata."""
        return {
            "internet_source": True,
            "enabled": bool(config.get("enabled", False)),
            "nws": bool((config.get("nws") or {}).get("enabled", True)),
            "forecast": bool(cls.forecast_enabled_for_config(config)),
            "nhc": bool((config.get("nhc") or {}).get("enabled", True)),
        }

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self._fingerprints = {}
        self._forecast_hourly_url = None
        self._forecast_point_key = None
        self._forecast_area_desc = None
        self._last_subfeed_errors = []

    def detect(self):
        """NOAA only needs at least one enabled feed source."""
        if not self.feed_sources():
            self.state = STATE_OFFLINE
            self.warning = "No NOAA/NWS/NHC source configured."
            return False
        self.active_hardware = "NOAA internet feeds"
        self.state = STATE_ONLINE
        self.warning = None
        return True

    async def start(self):
        """Poll configured NOAA feeds until stopped."""
        self._running = True
        if not self.detect():
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return
        await self.emit(
            "collector_online",
            {
                "source": "NOAA",
                "feeds": [source["name"] for source in self.feed_sources()],
                "internet_fed": True,
            },
        )
        interval = float(self.config.get("poll_interval_sec", 300))
        while self._running:
            try:
                events = await self.run_blocking(self.poll_once)
                self.state = STATE_ONLINE
                self.warning = "; ".join(self._last_subfeed_errors) or None
                if self.warning:
                    await self.emit(
                        "collector_online",
                        {
                            "source": "NOAA",
                            "feeds": [source["name"] for source in self.feed_sources()],
                            "warning": self.warning,
                            "internet_fed": True,
                        },
                        "warning",
                    )
                for item in events:
                    await self.emit(
                        item["type"],
                        item["data"],
                        "warning" if self.noaa_event_is_warning(item["data"]) else "info",
                    )
            except Exception as exc:
                self.state = STATE_RETRYING
                self.warning = "NOAA poll failed: {}".format(exc)
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

    def feed_sources(self):
        """Return enabled feed descriptors."""
        sources = []
        nws = self.config.get("nws") or {}
        if nws.get("enabled", True):
            sources.append({"name": "nws_alerts", "kind": "nws"})
        if self.forecast_enabled():
            sources.append({"name": "nws_forecast", "kind": "nws_forecast"})
        nhc = self.config.get("nhc") or {}
        if nhc.get("enabled", True):
            for basin in self.configured_nhc_basins(nhc):
                if basin in NHC_FEEDS:
                    sources.append(
                        {"name": "nhc_{}".format(basin), "kind": "nhc", "basin": basin}
                    )
        return sources

    @classmethod
    def forecast_enabled_for_config(cls, config):
        """Return True when NWS hourly forecast polling should be active."""
        config = config or {}
        nws = config.get("nws") or {}
        forecast = config.get("forecast") or nws.get("forecast") or {}
        default_enabled = bool(nws.get("enabled", True))
        enabled = forecast.get("enabled", default_enabled)
        latitude = config.get("latitude", nws.get("latitude"))
        longitude = config.get("longitude", nws.get("longitude"))
        return bool(enabled and latitude not in (None, "") and longitude not in (None, ""))

    def forecast_enabled(self):
        """Return True when this collector should poll NWS hourly forecast."""
        return self.forecast_enabled_for_config(self.config)

    def forecast_config(self):
        """Return optional forecast config from either top-level or NWS section."""
        nws = self.config.get("nws") or {}
        return self.config.get("forecast") or nws.get("forecast") or {}

    def configured_nhc_basins(self, nhc):
        """Return configured NHC basin names."""
        basins = nhc.get("basins")
        if basins in (None, ""):
            basins = ["atlantic", "eastern_pacific", "central_pacific"]
        if isinstance(basins, str):
            basins = [item.strip() for item in basins.split(",")]
        return [
            str(item or "").strip().lower().replace("-", "_").replace(" ", "_")
            for item in basins or []
            if str(item or "").strip()
        ]

    def poll_once(self):
        """Fetch all enabled NOAA sources and return new/changed events."""
        events = []
        errors = []
        seen = set()
        self._last_subfeed_errors = []
        for source in self.feed_sources():
            try:
                if source["kind"] == "nws":
                    source_events = self.poll_nws_alerts()
                elif source["kind"] == "nws_forecast":
                    source_events = self.poll_nws_forecast()
                elif source["kind"] == "nhc":
                    source_events = self.poll_nhc_feed(source["basin"])
                else:
                    source_events = []
            except Exception as exc:
                errors.append("{}: {}".format(source.get("name") or "NOAA", exc))
                continue
            for item in source_events:
                data = item.get("data") or {}
                dedupe_key = (
                    item.get("type") or "",
                    stable_noaa_event_key(data, item.get("type") or ""),
                    data.get("fingerprint") or data.get("source_url") or "",
                )
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                events.append(item)
        if errors and len(errors) == len(self.feed_sources()):
            self._last_subfeed_errors = errors
            raise RuntimeError("; ".join(errors))
        self._last_subfeed_errors = errors
        for error in errors:
            logging.warning("NOAA sub-feed poll failed: %s", error)
        return events

    def poll_nws_forecast(self):
        """Fetch and normalize the configured NWS hourly point forecast."""
        data = self.nws_forecast_data()
        if not data.get("event_id"):
            raise RuntimeError("NWS hourly forecast returned no usable summary")
        stable_key = stable_noaa_event_key(data, "noaa_forecast_summary")
        if self.changed("nws-forecast:{}".format(stable_key), data.get("fingerprint")):
            return [{"type": "noaa_forecast_summary", "data": data}]
        return []

    def poll_nws_alerts(self):
        """Fetch and normalize active NWS alerts."""
        payload = self.fetch_json(self.nws_url())
        events = []
        for feature in payload.get("features") or []:
            if not isinstance(feature, dict):
                continue
            data = self.nws_alert_data(feature)
            if not data.get("event_id"):
                continue
            if self.changed("nws:{}".format(data["event_id"]), data.get("fingerprint")):
                events.append({"type": "noaa_weather_alert", "data": data})
        return events

    def nws_url(self):
        """Return the configured NWS alerts URL."""
        nws = self.config.get("nws") or {}
        if nws.get("url"):
            return str(nws["url"])
        params = {}
        latitude = self.config.get("latitude", nws.get("latitude"))
        longitude = self.config.get("longitude", nws.get("longitude"))
        if latitude not in (None, "") and longitude not in (None, ""):
            params["point"] = "{},{}".format(latitude, longitude)
        elif nws.get("area") or self.config.get("state"):
            params["area"] = nws.get("area") or self.config.get("state")
        if nws.get("status"):
            params["status"] = nws.get("status")
        if nws.get("event"):
            params["event"] = nws.get("event")
        query = urllib.parse.urlencode(params)
        return "{}?{}".format(NWS_ALERTS_ENDPOINT, query) if query else NWS_ALERTS_ENDPOINT

    def nws_forecast_data(self):
        """Return one compact summary for the configured NWS hourly forecast."""
        forecast = self.forecast_config()
        forecast_url = self.nws_forecast_hourly_url()
        if not forecast_url:
            raise RuntimeError("NWS points metadata did not include forecastHourly")
        payload = self.fetch_json(forecast_url)
        props = payload.get("properties") or {}
        periods = [
            period
            for period in props.get("periods") or []
            if isinstance(period, dict) and period.get("startTime")
        ]
        if not periods:
            raise RuntimeError("NWS hourly forecast returned no periods")
        periods.sort(key=lambda item: iso_epoch(item.get("startTime")) or 0)
        now = now_epoch()
        window_hours = self.forecast_int(forecast, "window_hours", 12, 1, 72)
        soon_hours = self.forecast_int(forecast, "soon_hours", 6, 1, window_hours)
        precip_threshold = self.forecast_int(
            forecast, "precip_probability_threshold", 50, 1, 100
        )
        window_end = now + window_hours * 3600
        selected = [
            period
            for period in periods
            if (iso_epoch(period.get("startTime")) or 0) <= window_end
            and (iso_epoch(period.get("endTime")) or now) >= now
        ]
        selected = selected or periods[: min(len(periods), window_hours)]
        generated = compact_noaa_text(
            props.get("generatedAt") or props.get("updateTime") or "", 120
        )
        updated = compact_noaa_text(props.get("updateTime") or generated, 120)
        area_desc = self.forecast_area_desc()
        latitude, longitude = self.configured_point()
        current = selected[0]
        temperatures = [
            to_float(period.get("temperature"))
            for period in selected
            if to_float(period.get("temperature")) is not None
        ]
        precip_values = [
            self.period_precip_probability(period)
            for period in selected
            if self.period_precip_probability(period) is not None
        ]
        wind_values = [
            parse_wind_speed_mph(period.get("windSpeed"))
            for period in selected
            if parse_wind_speed_mph(period.get("windSpeed")) is not None
        ]
        soon_end = now + soon_hours * 3600
        next_precip = self.next_precip_period(selected, precip_threshold, soon_end)
        current_temp = to_float(current.get("temperature"))
        current_pop = self.period_precip_probability(current)
        temp_min = min(temperatures) if temperatures else None
        temp_max = max(temperatures) if temperatures else None
        temp_change = None
        last_temp = to_float(selected[-1].get("temperature")) if selected else None
        if current_temp is not None and last_temp is not None:
            temp_change = last_temp - current_temp
        first_start = compact_noaa_text(current.get("startTime"), 80)
        last_end = compact_noaa_text((selected[-1] or {}).get("endTime"), 80)
        headline = self.forecast_headline(
            selected,
            next_precip,
            precip_threshold,
            soon_hours,
            temp_min,
            temp_max,
            max(wind_values) if wind_values else None,
        )
        data = {
            "event_id": "nws-forecast:{}:{}".format(latitude, longitude),
            "event": "NWS hourly forecast",
            "headline": headline,
            "severity": "Minor",
            "status": "Forecast",
            "message_type": "Forecast",
            "category": "Met",
            "alert_kind": "forecast",
            "area_desc": area_desc,
            "effective": first_start,
            "expires": last_end,
            "updated": updated,
            "summary": headline,
            "description": self.forecast_description(selected),
            "source": "NWS",
            "source_url": compact_noaa_text(forecast_url, 240),
            "internet_fed": True,
            "latitude": latitude,
            "longitude": longitude,
            "forecast_hour_count": len(selected),
            "forecast_window_hours": window_hours,
            "forecast_soon_hours": soon_hours,
            "precip_probability_threshold": precip_threshold,
            "current_forecast": compact_noaa_text(current.get("shortForecast"), 120),
            "current_temperature_f": current_temp,
            "current_precip_probability": current_pop,
            "temperature_min_f": temp_min,
            "temperature_max_f": temp_max,
            "temperature_change_f": temp_change,
            "max_precip_probability": max(precip_values) if precip_values else None,
            "max_wind_mph": max(wind_values) if wind_values else None,
            "first_period_start": first_start,
            "last_period_end": last_end,
            "forecast_generated": generated,
            "precip_likely_soon": bool(next_precip),
        }
        for field in (
            "forecast_generated",
            "first_period_start",
            "last_period_end",
            "updated",
        ):
            epoch = iso_epoch(data.get(field))
            if epoch is not None:
                data["{}_epoch".format(field)] = epoch
        if next_precip:
            start = compact_noaa_text(next_precip.get("startTime"), 80)
            end = compact_noaa_text(next_precip.get("endTime"), 80)
            data.update(
                {
                    "next_precip_start": start,
                    "next_precip_end": end,
                    "next_precip_probability": self.period_precip_probability(
                        next_precip
                    ),
                    "next_precip_forecast": compact_noaa_text(
                        next_precip.get("shortForecast"), 120
                    ),
                }
            )
            for field in ("next_precip_start", "next_precip_end"):
                epoch = iso_epoch(data.get(field))
                if epoch is not None:
                    data["{}_epoch".format(field)] = epoch
        data["fingerprint"] = self.fingerprint(
            data,
            (
                "event",
                "area_desc",
                "forecast_generated",
                "updated",
                "headline",
                "current_forecast",
                "current_temperature_f",
                "current_precip_probability",
                "temperature_min_f",
                "temperature_max_f",
                "max_precip_probability",
                "next_precip_start",
                "next_precip_probability",
                "max_wind_mph",
            ),
        )
        return clean_noaa_data(data)

    def nws_forecast_hourly_url(self):
        """Return the hourly forecast URL for the configured point."""
        forecast = self.forecast_config()
        if forecast.get("url"):
            return str(forecast.get("url"))
        latitude, longitude = self.configured_point()
        if latitude in (None, "") or longitude in (None, ""):
            return ""
        point_key = "{},{}".format(latitude, longitude)
        if self._forecast_hourly_url and self._forecast_point_key == point_key:
            return self._forecast_hourly_url
        points_url = forecast.get("points_url") or NWS_POINTS_ENDPOINT.format(
            latitude, longitude
        )
        payload = self.fetch_json(points_url)
        props = payload.get("properties") or {}
        self._forecast_hourly_url = props.get("forecastHourly") or props.get("forecast") or ""
        self._forecast_point_key = point_key
        self._forecast_area_desc = self.points_area_desc(payload) or point_key
        return self._forecast_hourly_url

    def configured_point(self):
        """Return configured latitude/longitude as strings."""
        nws = self.config.get("nws") or {}
        return (
            self.config.get("latitude", nws.get("latitude")),
            self.config.get("longitude", nws.get("longitude")),
        )

    def forecast_area_desc(self):
        """Return a stable area label for the configured forecast point."""
        latitude, longitude = self.configured_point()
        return self._forecast_area_desc or "point {},{}".format(latitude, longitude)

    def points_area_desc(self, payload):
        """Return a compact human label from NWS points metadata."""
        props = (payload or {}).get("properties") or {}
        relative = props.get("relativeLocation") or {}
        rel_props = relative.get("properties") or {}
        city = compact_noaa_text(rel_props.get("city"), 80)
        state = compact_noaa_text(rel_props.get("state"), 20)
        if city and state:
            return "{}, {}".format(city, state)
        grid = compact_noaa_text(props.get("gridId"), 20)
        grid_x = props.get("gridX")
        grid_y = props.get("gridY")
        if grid and grid_x not in (None, "") and grid_y not in (None, ""):
            return "{} grid {},{}".format(grid, grid_x, grid_y)
        return ""

    def forecast_int(self, config, key, default, minimum, maximum):
        """Return a bounded integer forecast option."""
        try:
            value = int(config.get(key, default))
        except (TypeError, ValueError):
            value = default
        return max(minimum, min(maximum, value))

    def period_precip_probability(self, period):
        """Return NWS probabilityOfPrecipitation value as a number."""
        value = (period or {}).get("probabilityOfPrecipitation")
        if isinstance(value, dict):
            value = value.get("value")
        return to_float(value)

    def next_precip_period(self, periods, threshold, soon_end):
        """Return the first near-term period meeting the precipitation threshold."""
        for period in periods or []:
            start_epoch = iso_epoch(period.get("startTime")) or 0
            if start_epoch > soon_end:
                continue
            probability = self.period_precip_probability(period)
            if probability is not None and probability >= threshold:
                return period
        return None

    def forecast_headline(
        self, periods, next_precip, precip_threshold, soon_hours, temp_min, temp_max, wind_max
    ):
        """Return a compact point forecast summary."""
        parts = []
        if next_precip:
            probability = self.period_precip_probability(next_precip)
            start = compact_forecast_time(next_precip.get("startTime"))
            parts.append(
                "precip {}% around {}".format(
                    int(round(probability)) if probability is not None else "?",
                    start or "near term",
                )
            )
        else:
            parts.append("no precip >= {}% in next {}h".format(precip_threshold, soon_hours))
        if temp_min is not None and temp_max is not None:
            parts.append("temp {}-{}F".format(int(round(temp_min)), int(round(temp_max))))
        if wind_max is not None:
            parts.append("wind up to {} mph".format(int(round(wind_max))))
        current = compact_noaa_text((periods[0] or {}).get("shortForecast"), 80) if periods else ""
        if current:
            parts.append(current)
        return "; ".join(parts)

    def forecast_description(self, periods):
        """Return a compact sequence of near-term forecast periods."""
        parts = []
        for period in (periods or [])[:6]:
            start = compact_forecast_time(period.get("startTime"))
            temp = period.get("temperature")
            forecast = compact_noaa_text(period.get("shortForecast"), 80)
            pop = self.period_precip_probability(period)
            wind = compact_noaa_text(period.get("windSpeed"), 40)
            fields = [
                start,
                forecast,
                "{}F".format(temp) if temp not in (None, "") else "",
                "{}% precip".format(int(round(pop))) if pop is not None else "",
                wind and "wind {}".format(wind),
            ]
            text = " ".join(str(field) for field in fields if field)
            if text:
                parts.append(text)
        return "; ".join(parts)

    def nws_alert_data(self, feature):
        """Normalize one NWS alert feature."""
        props = feature.get("properties") or {}
        event_id = props.get("id") or feature.get("id") or props.get("@id") or ""
        event_name = compact_noaa_text(props.get("event"), 120)
        headline = compact_noaa_text(props.get("headline"), 300)
        description = compact_noaa_text(props.get("description"), NOAA_TEXT_MAX)
        instruction = compact_noaa_text(props.get("instruction"), NOAA_TEXT_MAX)
        data = {
            "event_id": compact_noaa_text(event_id, 180),
            "event": event_name,
            "headline": headline,
            "severity": compact_noaa_text(props.get("severity"), 40),
            "urgency": compact_noaa_text(props.get("urgency"), 40),
            "certainty": compact_noaa_text(props.get("certainty"), 40),
            "status": compact_noaa_text(props.get("status"), 40),
            "message_type": compact_noaa_text(props.get("messageType"), 40),
            "category": compact_noaa_text(props.get("category"), 80),
            "area_desc": compact_noaa_text(props.get("areaDesc"), 300),
            "effective": compact_noaa_text(props.get("effective"), 80),
            "onset": compact_noaa_text(props.get("onset"), 80),
            "expires": compact_noaa_text(props.get("expires"), 80),
            "ends": compact_noaa_text(props.get("ends"), 80),
            "sender": compact_noaa_text(props.get("senderName"), 160),
            "description": description,
            "instruction": instruction,
            "summary": headline or description or event_name,
            "source": "NWS",
            "source_url": compact_noaa_text(props.get("@id") or event_id, 240),
            "alert_kind": self.alert_kind(event_name, headline, description),
            "internet_fed": True,
        }
        geocode = props.get("geocode") or {}
        data["geocode_ugc"] = geocode.get("UGC") or []
        data["geocode_same"] = geocode.get("SAME") or []
        for field in ("effective", "onset", "expires", "ends"):
            epoch = iso_epoch(data.get(field))
            if epoch is not None:
                data["{}_epoch".format(field)] = epoch
        data["fingerprint"] = self.fingerprint(
            data,
            (
                "event",
                "headline",
                "severity",
                "urgency",
                "certainty",
                "status",
                "message_type",
                "effective",
                "onset",
                "expires",
                "ends",
                "instruction",
            ),
        )
        return clean_noaa_data(data)

    def poll_nhc_feed(self, basin):
        """Fetch and normalize one NHC RSS feed."""
        text = self.fetch_text(NHC_FEEDS[basin])
        events = []
        for item in self.rss_items(text):
            data = self.nhc_item_data(item, basin)
            if not data.get("event_id"):
                continue
            stable_key = stable_noaa_event_key(data, "noaa_tropical_advisory")
            if self.changed("nhc:{}".format(stable_key), data.get("fingerprint")):
                events.append({"type": "noaa_tropical_advisory", "data": data})
        return events

    def rss_items(self, text):
        """Return RSS/Atom item elements while tolerating namespace tags."""
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return []
        return [
            element
            for element in root.iter()
            if strip_namespace(element.tag) in ("item", "entry")
        ]

    def nhc_item_data(self, item, basin):
        """Normalize one NHC RSS item."""
        title = compact_noaa_text(child_text(item, "title"), 240)
        link = compact_noaa_text(child_text(item, "link"), 240)
        guid = compact_noaa_text(child_text(item, "guid") or link or title, 240)
        updated = compact_noaa_text(
            child_text(item, "pubDate") or child_text(item, "updated"), 120
        )
        summary = compact_noaa_text(
            child_text(item, "description") or child_text(item, "summary"), NOAA_TEXT_MAX
        )
        alert_kind = self.nhc_alert_kind(title, summary)
        data = {
            "event_id": guid,
            "event": title,
            "headline": title,
            "severity": "Minor" if alert_kind == "tropical_outlook" else self.nhc_severity(title, summary),
            "status": "",
            "message_type": "Outlook" if alert_kind == "tropical_outlook" else "Update",
            "area_desc": basin.replace("_", " ").title(),
            "updated": updated,
            "summary": summary or title,
            "description": summary,
            "source": "NHC",
            "source_url": link,
            "alert_kind": alert_kind,
            "basin": basin,
            "internet_fed": True,
        }
        epoch = timestamp_epoch(updated)
        if epoch is not None:
            data["updated_epoch"] = epoch
        if alert_kind == "tropical_outlook":
            # Outlook timestamps/links can churn even when the basin state is
            # still "no tropical cyclones"; treat only material text changes as
            # new feed events.
            fingerprint_fields = ("event", "headline", "severity", "summary", "basin")
        else:
            fingerprint_fields = (
                "event",
                "headline",
                "severity",
                "updated",
                "summary",
                "source_url",
                "basin",
            )
        data["fingerprint"] = self.fingerprint(data, fingerprint_fields)
        return clean_noaa_data(data)

    def fetch_json(self, url):
        """Fetch JSON from a NOAA endpoint."""
        text = self.fetch_text(url, accept="application/geo+json, application/json")
        data = json.loads(text)
        return data if isinstance(data, dict) else {}

    def fetch_text(self, url, accept=None):
        """Fetch one URL as UTF-8 text."""
        headers = {
            "User-Agent": self.config.get("user_agent") or "Skannr NOAA collector",
        }
        if accept:
            headers["Accept"] = accept
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(
            request, timeout=float(self.config.get("request_timeout_sec", 15))
        ) as response:
            body = response.read()
        return body.decode("utf-8", errors="replace")

    def changed(self, key, fingerprint):
        """Return True when a source item is new or materially changed."""
        if not fingerprint:
            return False
        if self._fingerprints.get(key) == fingerprint:
            return False
        self._fingerprints[key] = fingerprint
        return True

    def fingerprint(self, data, fields):
        """Return a stable fingerprint for material alert changes."""
        payload = "|".join(str((data or {}).get(field) or "") for field in fields)
        return hashlib.sha1(payload.encode("utf-8", errors="replace")).hexdigest()

    def alert_kind(self, *values):
        """Classify alert content into broad hazard families."""
        text = " ".join(str(value or "") for value in values).lower()
        if "tsunami" in text:
            return "tsunami"
        if any(word in text for word in ("hurricane", "tropical storm", "cyclone")):
            return "tropical"
        if any(word in text for word in ("tornado", "thunderstorm", "flash flood", "flood")):
            return "weather"
        return "weather"

    def nhc_alert_kind(self, title, summary):
        """Classify NHC RSS entries without alerting on routine outlooks."""
        title_text = str(title or "").lower()
        text = "{} {}".format(title or "", summary or "").lower()
        if any(phrase in text for phrase in NHC_OUTLOOK_PHRASES):
            return "tropical_outlook"
        if "tropical weather outlook" in title_text:
            return "tropical_outlook"
        if any(phrase in text for phrase in NHC_STORM_PHRASES):
            return "tropical"
        if NHC_NUMBERED_SYSTEM_RE.search(text):
            return "tropical"
        return "tropical_outlook"

    def nhc_severity(self, *values):
        """Return a compact severity for NHC titles/descriptions."""
        text = " ".join(str(value or "") for value in values).lower()
        if "warning" in text:
            return "Severe"
        if "watch" in text or "advisory" in text:
            return "Moderate"
        return "Minor"

    def noaa_event_is_warning(self, data):
        """Return True when NOAA content should be emitted as warning severity."""
        severity = str((data or {}).get("severity") or "").lower()
        kind = str((data or {}).get("alert_kind") or "").lower()
        if kind == "tropical_outlook":
            return False
        event = str((data or {}).get("event") or "").lower()
        return (
            severity in ("severe", "extreme")
            or kind in ("tsunami", "tropical")
            or any(word in event for word in ("warning", "watch", "tornado"))
        )


def child_text(element, local_name):
    """Return child text by local tag name."""
    for child in list(element):
        if strip_namespace(child.tag) == local_name:
            if local_name == "link" and child.get("href"):
                return child.get("href")
            return child.text or ""
    return ""


def strip_namespace(tag):
    """Return XML tag name without namespace."""
    return str(tag or "").split("}", 1)[-1]


def iso_epoch(value):
    """Parse common NOAA ISO timestamps into epoch seconds."""
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    normalized = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", normalized)
    for pattern in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.strptime(normalized, pattern)
            return int(calendar.timegm(parsed.utctimetuple()))
        except ValueError:
            pass
    for pattern in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return int(time.mktime(datetime.strptime(normalized, pattern).timetuple()))
        except ValueError:
            pass
    return timestamp_epoch(text)


def to_float(value):
    """Return a numeric value when NOAA encodes one as int/float/string."""
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_wind_speed_mph(value):
    """Return the largest mph value from NWS windSpeed text."""
    numbers = [
        float(match.group(1))
        for match in re.finditer(r"([0-9]+(?:\.[0-9]+)?)", str(value or ""))
    ]
    return max(numbers) if numbers else None


def compact_forecast_time(value):
    """Return a compact forecast timestamp for summaries."""
    text = compact_noaa_text(value, 80)
    if not text:
        return ""
    match = re.match(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})", text)
    if match:
        return "{} {}".format(match.group(1), match.group(2))
    return text


def stable_noaa_event_key(data, event_type=""):
    """Return a stable key for grouping NOAA events across routine updates."""
    data = data or {}
    if event_type == "noaa_tropical_advisory" or data.get("source") == "NHC":
        basin = noaa_key_fragment(data.get("basin") or data.get("area_desc") or "global")
        event = (
            data.get("event")
            or data.get("headline")
            or data.get("summary")
            or data.get("event_id")
            or "nhc"
        )
        return "nhc:{}:{}".format(basin, noaa_key_fragment(event))
    source = noaa_key_fragment(data.get("source") or "NOAA")
    area = noaa_key_fragment(data.get("area_desc") or "global")
    event = noaa_key_fragment(
        data.get("event") or data.get("headline") or data.get("event_id") or "noaa"
    )
    return "{}:{}:{}".format(source, area, event)


def noaa_key_fragment(value):
    """Return a compact lowercase key fragment for NOAA grouping."""
    return re.sub(r"[^a-z0-9_.:-]+", "-", str(value or "").strip().lower()).strip("-")
