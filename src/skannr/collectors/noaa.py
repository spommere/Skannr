"""Optional NOAA/NWS/NHC/tsunami.gov polling collector.

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
TSUNAMI_FEEDS = {
    "ntwc": {
        "label": "NTWC",
        "atom_url": "https://www.tsunami.gov/events/xml/PAAQAtom.xml",
        "cap_url": "https://www.tsunami.gov/events/xml/PAAQCAP.xml",
    },
    "ptwc": {
        "label": "PTWC",
        "atom_url": "https://www.tsunami.gov/events/xml/PHEBAtom.xml",
        "cap_url": "https://www.tsunami.gov/events/xml/PHEBCAP.xml",
    },
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
NHC_PRODUCT_RE = re.compile(
    r"^(?P<system>.+?)\s+"
    r"(?P<product>Public Advisory|Forecast Advisory|Forecast Discussion|"
    r"Wind Speed Probabilities|Intermediate Advisory|Advisory|Discussion|"
    r"Graphics)\s+"
    r"(?:Number\s+)?(?P<number>[0-9]{1,3}[A-Z]?)\b",
    re.IGNORECASE,
)
NHC_STORM_ID_RE = re.compile(r"\b(?:AL|EP|CP)[0-9]{2}[0-9]{4}\b", re.IGNORECASE)
NHC_SYSTEM_PREFIX_RE = re.compile(
    r"^(?:"
    r"Potential Tropical Cyclone|Post-Tropical Cyclone|Remnants Of|Remnants of|"
    r"Hurricane|Tropical Storm|Tropical Depression|Subtropical Storm|"
    r"Subtropical Depression"
    r")\s+",
    re.IGNORECASE,
)
NHC_PRODUCT_ORDER = {
    "public advisory": 0,
    "advisory": 1,
    "intermediate advisory": 2,
    "forecast advisory": 3,
    "forecast discussion": 4,
    "discussion": 5,
    "wind speed probabilities": 6,
    "graphics": 7,
}


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
        "event_time_epoch",
        "forecast_generated_epoch",
        "first_period_start_epoch",
        "last_period_end_epoch",
        "next_precip_start_epoch",
        "next_precip_end_epoch",
        "latitude",
        "longitude",
        "magnitude",
        "depth_km",
        "forecast_hour_count",
        "forecast_window_hours",
        "forecast_soon_hours",
        "precip_probability_threshold",
        "nhc_product_count",
        "current_temperature_f",
        "temperature_min_f",
        "temperature_max_f",
        "temperature_change_f",
        "current_precip_probability",
        "max_precip_probability",
        "next_precip_probability",
        "max_wind_mph",
        "period_start_epoch",
        "period_end_epoch",
        "event_count",
        "tropical_system_count",
        "nhc_product_count_total",
        "nws_hazard_count",
        "tsunami_incident_count",
        "tsunami_message_count",
        "forecast_count",
        "previous_event_count",
        "event_count_delta",
        "previous_forecast_generated_epoch",
        "previous_current_temperature_f",
        "previous_temperature_min_f",
        "previous_temperature_max_f",
        "previous_max_precip_probability",
        "previous_next_precip_probability",
        "previous_max_wind_mph",
        "current_temperature_delta_f",
        "temperature_min_delta_f",
        "temperature_max_delta_f",
        "max_precip_probability_delta",
        "next_precip_probability_delta",
        "max_wind_delta_mph",
    }
    bool_keys = {"internet_fed", "precip_likely_soon"}
    list_keys = {
        "zones",
        "geocode_ugc",
        "geocode_same",
        "nhc_product_types",
        "nhc_product_titles",
        "nhc_product_urls",
        "resource_urls",
        "map_urls",
        "basins",
        "tropical_systems",
        "hazard_events",
        "hazard_areas",
        "hazard_severities",
        "tsunami_incidents",
        "sources",
        "forecast_delta_findings",
    }
    dict_list_keys = {"nhc_products"}
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
            item_max_length = (
                240
                if key in ("nhc_product_urls", "resource_urls", "map_urls")
                else 80
            )
            for item in value:
                text = compact_noaa_text(item, item_max_length)
                if text and text not in items:
                    items.append(text)
            if items:
                cleaned[key] = items[:24]
        elif key in dict_list_keys and isinstance(value, list):
            items = []
            for item in value:
                if not isinstance(item, dict):
                    continue
                product = clean_noaa_data(item)
                if product:
                    items.append(product)
            if items:
                cleaned[key] = items[:24]
        else:
            max_length = NOAA_TEXT_MAX if key in long_text_keys else NOAA_FIELD_MAX
            text = compact_noaa_text(value, max_length)
            if text:
                cleaned[key] = text
    return cleaned


class NOAACollector(BaseCollector):
    """Poll NOAA/NWS/NHC/tsunami.gov feeds and emit changed hazard advisories."""

    config_key = "noaa"
    name = "NOAA"
    tab_label = "NOAA"
    required_hardware = "Internet access"
    subject_history_event_types = (
        "noaa_weather_alert",
        "noaa_tropical_advisory",
        "noaa_forecast_summary",
        "noaa_tsunami_alert",
        "collector_offline",
        "collector_retrying",
    )

    @classmethod
    def hardware_status(cls, config):
        """Return configured feed metadata."""
        return {
            "internet_source": True,
            "enabled": bool(config.get("enabled", False)),
            "nws": bool((config.get("nws") or {}).get("enabled", True)),
            "forecast": bool(cls.forecast_enabled_for_config(config)),
            "nhc": bool((config.get("nhc") or {}).get("enabled", True)),
            "tsunami": bool((config.get("tsunami") or {}).get("enabled", True)),
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
            self.warning = "No NOAA/NWS/NHC/tsunami source configured."
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
        tsunami = self.config.get("tsunami") or {}
        if tsunami.get("enabled", True):
            for center in self.configured_tsunami_centers(tsunami):
                if center in TSUNAMI_FEEDS:
                    sources.append(
                        {
                            "name": "tsunami_{}".format(center),
                            "kind": "tsunami",
                            "center": center,
                        }
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

    def configured_tsunami_centers(self, tsunami):
        """Return configured tsunami.gov center names."""
        centers = tsunami.get("centers")
        if centers in (None, ""):
            centers = ["ntwc", "ptwc"]
        if isinstance(centers, str):
            centers = [item.strip() for item in centers.split(",")]
        return [
            str(item or "").strip().lower().replace("-", "_").replace(" ", "_")
            for item in centers or []
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
                elif source["kind"] == "tsunami":
                    source_events = self.poll_tsunami_feed(source["center"])
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
        alert_kind = self.alert_kind(event_name, headline, description)
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
            "source_url": "https://www.tsunami.gov/" if alert_kind == "tsunami" else compact_noaa_text(props.get("@id") or event_id, 240),
            "alert_kind": alert_kind,
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
        packages = {}
        for item in self.rss_items(text):
            data = self.nhc_item_data(item, basin)
            if not data.get("event_id"):
                continue
            stable_key = stable_noaa_event_key(data, "noaa_tropical_advisory")
            packages[stable_key] = merge_nhc_package(packages.get(stable_key), data)
        events = []
        for stable_key, data in packages.items():
            if self.changed("nhc:{}".format(stable_key), data.get("fingerprint")):
                events.append({"type": "noaa_tropical_advisory", "data": data})
        return events

    def poll_tsunami_feed(self, center):
        """Fetch and normalize one tsunami.gov center feed."""
        feed = self.tsunami_feed_definition(center)
        data = {}
        atom_error = None
        cap_error = None
        try:
            text = self.fetch_text(
                feed.get("atom_url") or "",
                accept="application/atom+xml, application/xml, text/xml",
            )
            data = merge_noaa_fields(data, self.tsunami_atom_data(text, center, feed))
        except Exception as exc:
            atom_error = exc
        cap_url = data.get("cap_url") or feed.get("cap_url") or ""
        if cap_url:
            try:
                text = self.fetch_text(
                    cap_url,
                    accept="application/cap+xml, application/xml, text/xml",
                )
                cap_data = self.tsunami_cap_data(text, center, feed)
                if cap_data and not cap_data.get("cap_url"):
                    cap_data["cap_url"] = cap_url
                data = merge_noaa_fields(data, cap_data)
            except Exception as exc:
                cap_error = exc
        if self.tsunami_should_fetch_bulletin(data):
            bulletin_url = tsunami_bulletin_text_url(
                data.get("source_url"),
                *(data.get("resource_urls") or []),
            )
            if bulletin_url:
                try:
                    text = self.fetch_text(bulletin_url, accept="text/plain")
                    data = merge_noaa_fields(
                        data,
                        tsunami_bulletin_data(
                            text,
                            feed.get("label") or center.upper(),
                            bulletin_url,
                        ),
                    )
                except Exception as exc:
                    logging.warning(
                        "tsunami.gov %s bulletin fetch failed: %s", center, exc
                    )
        if not data:
            if atom_error and cap_error:
                raise RuntimeError(
                    "tsunami.gov {} Atom and CAP failed: {}; {}".format(
                        center, atom_error, cap_error
                    )
                )
            raise RuntimeError(
                "tsunami.gov {} returned no usable feed data: {}".format(
                    center, atom_error or cap_error or "empty feed"
                )
            )
        data = self.finalize_tsunami_data(data, center, feed)
        stable_key = stable_noaa_event_key(data, "noaa_tsunami_alert")
        if self.changed("tsunami:{}".format(stable_key), data.get("fingerprint")):
            return [{"type": "noaa_tsunami_alert", "data": data}]
        return []

    def tsunami_should_fetch_bulletin(self, data):
        """Return True when the compact text bulletin can add missing fields."""
        tsunami = self.config.get("tsunami") or {}
        if not tsunami.get("fetch_bulletin_text", True):
            return False
        data = data or {}
        return (
            data.get("magnitude") in (None, "")
            or not data.get("event_time")
            or not data.get("latitude")
            or (data.get("event") or "") == "Tsunami message"
        )

    def tsunami_feed_definition(self, center):
        """Return configured tsunami.gov URLs for a center."""
        base = dict(TSUNAMI_FEEDS.get(center) or {})
        tsunami = self.config.get("tsunami") or {}
        feeds = tsunami.get("feeds") or {}
        override = feeds.get(center) if isinstance(feeds, dict) else None
        if isinstance(override, dict):
            base.update(override)
        return base

    def tsunami_atom_data(self, text, center, feed):
        """Normalize one tsunami.gov Atom feed."""
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return {}
        entries = [
            element
            for element in root.iter()
            if strip_namespace(element.tag) == "entry"
        ]
        entry = entries[0] if entries else None
        source = feed.get("label") or center.upper()
        feed_title = compact_noaa_text(child_text(root, "title"), 160)
        feed_updated = compact_noaa_text(child_text(root, "updated"), 120)
        element = entry or root
        title = compact_noaa_text(child_text(element, "title"), 200)
        updated = compact_noaa_text(child_text(element, "updated") or feed_updated, 120)
        event_id = compact_noaa_text(child_text(element, "id") or feed_title, 200)
        summary = compact_noaa_text(
            child_text(element, "summary") or child_text(element, "content") or "",
            NOAA_TEXT_MAX,
        )
        links = xml_links(element) or xml_links(root)
        source_url = preferred_tsunami_url(links, "bulletin")
        cap_url = preferred_tsunami_url(links, "cap") or feed.get("cap_url") or ""
        map_urls = [
            link.get("href")
            for link in links
            if "map" in str(link.get("title") or link.get("href") or "").lower()
            and link.get("href")
            and tsunami_url_matches_center(link.get("href"), center)
        ]
        resource_urls = [
            link.get("href")
            for link in links
            if link.get("href") and tsunami_url_matches_center(link.get("href"), center)
        ]
        latitude, longitude = parse_lat_lon_pair(first_descendant_text(element, "point"))
        category = tsunami_summary_field(summary, "Category")
        magnitude, magnitude_type = parse_tsunami_magnitude(
            tsunami_summary_field(summary, "Preliminary Magnitude")
        )
        issue_time = tsunami_summary_field(summary, "Bulletin Issue Time")
        event_name = feed_title or "Tsunami message"
        data = {
            "event_id": event_id,
            "source_event_id": event_id,
            "event": event_name,
            "headline": event_name,
            "severity": tsunami_severity(category, event_name),
            "status": "Actual",
            "message_type": "Update",
            "category": "Geo",
            "alert_kind": "tsunami",
            "tsunami_category": category,
            "area_desc": title,
            "updated": updated or issue_time,
            "summary": summary or event_name,
            "description": summary,
            "source": source,
            "source_url": source_url or cap_url,
            "cap_url": cap_url,
            "internet_fed": True,
            "latitude": latitude,
            "longitude": longitude,
            "magnitude": magnitude,
            "magnitude_type": magnitude_type,
            "message_number": tsunami_message_number(feed_title or event_name),
            "resource_urls": resource_urls,
            "map_urls": map_urls,
        }
        return clean_noaa_data(data)

    def tsunami_cap_data(self, text, center, feed):
        """Normalize one tsunami.gov CAP feed."""
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return {}
        source = feed.get("label") or center.upper()
        identifier = compact_noaa_text(first_descendant_text(root, "identifier"), 200)
        sent = compact_noaa_text(first_descendant_text(root, "sent"), 120)
        status = compact_noaa_text(first_descendant_text(root, "status"), 40)
        msg_type = compact_noaa_text(first_descendant_text(root, "msgType"), 40)
        cap_source = compact_noaa_text(first_descendant_text(root, "source") or source, 80)
        incidents = compact_noaa_text(first_descendant_text(root, "incidents"), 120)
        info = first_descendant(root, "info")
        params = cap_parameters(info)
        resources = cap_resources(info)
        area = first_descendant(info, "area") if info is not None else None
        area_desc = compact_noaa_text(child_text(area, "areaDesc"), 240)
        circle = compact_noaa_text(child_text(area, "circle"), 80)
        latitude, longitude = parse_lat_lon_pair(
            params.get("EventLatLon") or circle.replace(",", " ")
        )
        magnitude, magnitude_type = parse_tsunami_magnitude(
            params.get("EventPreliminaryMagnitude"),
            params.get("EventPreliminaryMagnitudeType"),
        )
        depth_km = parse_tsunami_depth_km(params.get("EventDepth"))
        event_name = compact_noaa_text(child_text(info, "event"), 160)
        headline = compact_noaa_text(child_text(info, "headline"), 300)
        description = compact_noaa_text(child_text(info, "description"), NOAA_TEXT_MAX)
        instruction = compact_noaa_text(child_text(info, "instruction"), NOAA_TEXT_MAX)
        source_url = compact_noaa_text(
            child_text(info, "web") or preferred_resource_url(resources, "bulletin"),
            240,
        )
        resource_urls = [item.get("uri") for item in resources if item.get("uri")]
        map_urls = [
            item.get("uri")
            for item in resources
            if item.get("uri")
            and "map" in str(item.get("description") or item.get("uri") or "").lower()
        ]
        json_url = preferred_resource_url(resources, "json")
        data = {
            "event_id": identifier,
            "source_event_id": identifier,
            "tsunami_identifier": identifier,
            "incident_id": incidents,
            "event": event_name or headline or "Tsunami message",
            "headline": headline or event_name,
            "severity": compact_noaa_text(child_text(info, "severity"), 40),
            "urgency": compact_noaa_text(child_text(info, "urgency"), 40),
            "certainty": compact_noaa_text(child_text(info, "certainty"), 40),
            "status": status,
            "message_type": msg_type,
            "category": compact_noaa_text(child_text(info, "category"), 80),
            "alert_kind": "tsunami",
            "tsunami_category": tsunami_event_category(event_name, headline),
            "area_desc": params.get("EventLocationName") or area_desc,
            "effective": sent,
            "updated": sent,
            "expires": compact_noaa_text(child_text(info, "expires"), 120),
            "sender": compact_noaa_text(child_text(info, "senderName"), 160),
            "description": description,
            "instruction": instruction,
            "summary": headline or description or event_name,
            "source": cap_source or source,
            "source_url": source_url,
            "json_url": json_url,
            "internet_fed": True,
            "latitude": latitude,
            "longitude": longitude,
            "magnitude": magnitude,
            "magnitude_type": magnitude_type,
            "depth_km": depth_km,
            "event_time": compact_noaa_text(params.get("EventOriginTime"), 120),
            "product_code": params.get("ProductCode"),
            "message_number": tsunami_message_number(identifier),
            "resource_urls": resource_urls,
            "map_urls": map_urls,
        }
        return clean_noaa_data(data)

    def finalize_tsunami_data(self, data, center, feed):
        """Fill stable identity and derived fields for a tsunami.gov event."""
        data = clean_noaa_data(data)
        source = data.get("source") or feed.get("label") or center.upper()
        incident = (
            data.get("incident_id")
            or data.get("tsunami_identifier")
            or data.get("source_event_id")
            or data.get("event_id")
            or data.get("source_url")
            or data.get("headline")
            or source
        )
        data["source"] = source
        data["event_id"] = "tsunami:{}:{}".format(
            noaa_key_fragment(source),
            noaa_key_fragment(incident),
        )
        data["alert_kind"] = "tsunami"
        if not data.get("event"):
            data["event"] = data.get("headline") or "Tsunami message"
        if not data.get("headline"):
            data["headline"] = data.get("event") or "Tsunami message"
        if not data.get("severity"):
            data["severity"] = tsunami_severity(
                data.get("tsunami_category"),
                data.get("event"),
                data.get("headline"),
            )
        if not data.get("source_url"):
            data["source_url"] = data.get("cap_url") or feed.get("atom_url") or ""
        for field in ("effective", "updated", "expires", "event_time"):
            epoch = iso_epoch(data.get(field))
            if epoch is not None:
                data["{}_epoch".format(field)] = epoch
        data["fingerprint"] = self.fingerprint(
            data,
            (
                "event_id",
                "message_number",
                "event",
                "headline",
                "severity",
                "urgency",
                "certainty",
                "status",
                "message_type",
                "updated",
                "event_time",
                "magnitude",
                "area_desc",
                "summary",
                "instruction",
                "source_url",
            ),
        )
        return clean_noaa_data(data)

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
        package = parse_nhc_package(title, summary)
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
        data.update(package)
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
        status = str((data or {}).get("status") or "").lower()
        if status == "test":
            return False
        severity = str((data or {}).get("severity") or "").lower()
        kind = str((data or {}).get("alert_kind") or "").lower()
        if kind == "tropical_outlook":
            return False
        if kind == "tsunami":
            return tsunami_is_alertworthy(data)
        event = str((data or {}).get("event") or "").lower()
        return (
            severity in ("severe", "extreme")
            or kind == "tropical"
            or any(word in event for word in ("warning", "watch", "tornado"))
        )


def child_text(element, local_name):
    """Return child text by local tag name."""
    if element is None:
        return ""
    for child in list(element):
        if strip_namespace(child.tag) == local_name:
            if local_name == "link" and child.get("href"):
                return child.get("href")
            return child.text or ""
    return ""


def first_descendant(element, local_name):
    """Return the first descendant element with a local tag name."""
    if element is None:
        return None
    for child in element.iter():
        if strip_namespace(child.tag) == local_name:
            return child
    return None


def first_descendant_text(element, local_name):
    """Return the first descendant text value by local tag name."""
    child = first_descendant(element, local_name)
    return child.text if child is not None and child.text else ""


def strip_namespace(tag):
    """Return XML tag name without namespace."""
    return str(tag or "").split("}", 1)[-1]


def xml_links(element):
    """Return compact link descriptors from an XML element."""
    links = []
    if element is None:
        return links
    for child in element.iter():
        if strip_namespace(child.tag) != "link":
            continue
        href = child.get("href") or (child.text or "")
        if not href:
            continue
        links.append(
            {
                "href": compact_noaa_text(href, 240),
                "rel": compact_noaa_text(child.get("rel"), 80),
                "type": compact_noaa_text(child.get("type"), 80),
                "title": compact_noaa_text(child.get("title"), 120),
            }
        )
    return links


def preferred_tsunami_url(links, purpose):
    """Return the best tsunami.gov URL for a purpose."""
    purpose = str(purpose or "").lower()
    candidates = []
    for link in links or []:
        href = link.get("href") or ""
        text = " ".join(
            str(link.get(field) or "") for field in ("title", "type", "rel", "href")
        ).lower()
        if not href:
            continue
        if purpose == "cap" and ("cap" in text or href.lower().endswith("cap.xml")):
            candidates.append(href)
        elif purpose == "bulletin" and (
            "bulletin" in text
            or "/text/" in href.lower()
            or href.lower().endswith(".txt")
            or href.lower().endswith(".shtml")
        ):
            candidates.append(href)
    if candidates:
        return candidates[0]
    return ""


def cap_parameters(info):
    """Return CAP parameter valueName/value pairs."""
    params = {}
    if info is None:
        return params
    for parameter in info.iter():
        if strip_namespace(parameter.tag) != "parameter":
            continue
        name = compact_noaa_text(child_text(parameter, "valueName"), 120)
        value = compact_noaa_text(child_text(parameter, "value"), 240)
        if name and value:
            params[name] = value
    return params


def cap_resources(info):
    """Return compact CAP resource descriptors."""
    resources = []
    if info is None:
        return resources
    for resource in info.iter():
        if strip_namespace(resource.tag) != "resource":
            continue
        uri = compact_noaa_text(child_text(resource, "uri"), 240)
        description = compact_noaa_text(child_text(resource, "resourceDesc"), 120)
        if uri or description:
            resources.append({"uri": uri, "description": description})
    return resources


def preferred_resource_url(resources, purpose):
    """Return a CAP resource URL matching the requested purpose."""
    purpose = str(purpose or "").lower()
    for resource in resources or []:
        uri = resource.get("uri") or ""
        description = str(resource.get("description") or "").lower()
        text = "{} {}".format(description, uri.lower())
        if purpose in text and uri:
            return uri
    return ""


def parse_lat_lon_pair(value):
    """Return latitude/longitude from common tsunami.gov coordinate strings."""
    text = str(value or "").strip()
    if not text:
        return None, None
    numbers = [
        float(match.group(1))
        for match in re.finditer(r"(-?\d+(?:\.\d+)?)", text)
    ]
    if len(numbers) < 2:
        return None, None
    lat = numbers[0]
    lon = numbers[1]
    if abs(lat) > 90 and abs(lon) <= 90:
        lat, lon = lon, lat
    return lat, lon


def tsunami_summary_field(summary, label):
    """Extract a named field from the compact tsunami.gov Atom summary text."""
    text = str(summary or "")
    if not text or not label:
        return ""
    pattern = re.compile(
        r"{}\s*:\s*(.*?)(?=\s+[A-Z][A-Za-z0-9 /().-]{{2,40}}\s*:|$)".format(
            re.escape(label)
        )
    )
    match = pattern.search(text)
    return compact_noaa_text(match.group(1), 160) if match else ""


def parse_tsunami_magnitude(value, magnitude_type=None):
    """Return numeric tsunami event magnitude and optional type."""
    text = str(value or "").strip()
    if not text:
        return None, compact_noaa_text(magnitude_type, 40)
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)", text)
    magnitude = float(match.group(1)) if match else None
    type_match = re.search(r"\(([^)]+)\)", text)
    parsed_type = type_match.group(1) if type_match else magnitude_type
    return magnitude, compact_noaa_text(parsed_type, 40)


def parse_tsunami_depth_km(value):
    """Return tsunami event depth in kilometers when encoded in CAP parameters."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)", text)
    if not match:
        return None
    depth = float(match.group(1))
    if "mile" in text:
        depth *= 1.60934
    return depth


def tsunami_bulletin_text_url(*urls):
    """Return a tsunami.gov plain-text bulletin URL from linked resources."""
    for value in urls or []:
        text = str(value or "").strip()
        if not text or "tsunami.gov" not in text:
            continue
        lower = text.lower()
        if lower.endswith(".txt"):
            return text
        stripped = text.rstrip("/")
        leaf = stripped.rsplit("/", 1)[-1]
        if re.match(r"^[A-Z]{4}[0-9]{2}$", leaf, re.IGNORECASE):
            return "{}/{}.txt".format(stripped, leaf.upper())
    return ""


def tsunami_url_matches_center(url, center):
    """Return True when a tsunami.gov URL belongs to the configured center."""
    text = str(url or "").lower()
    if not text:
        return False
    expected = "pheb" if str(center or "").lower() == "ptwc" else "paaq"
    return expected in text


def tsunami_bulletin_data(text, source, url):
    """Extract compact fields from a tsunami.gov plain-text bulletin."""
    compact = compact_noaa_text(text, NOAA_TEXT_MAX)
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    if not lines:
        return {}
    headline = compact_noaa_text(lines[0], 180)
    event = ""
    for line in lines[1:6]:
        upper = line.upper()
        if "TSUNAMI" in upper and "MESSAGE" in upper:
            event = compact_noaa_text(line, 180)
            break
    event = event or headline
    magnitude = parse_bulletin_number(text, r"\bMAGNITUDE\s+([0-9]+(?:\.[0-9]+)?)")
    depth_km = parse_bulletin_number(text, r"\bDEPTH\s+([0-9]+(?:\.[0-9]+)?)\s*KM")
    latitude, longitude = parse_bulletin_coordinates(text)
    location = parse_bulletin_field(text, "LOCATION")
    origin_time = normalize_bulletin_time(parse_bulletin_field(text, "ORIGIN TIME"))
    incident = tsunami_incident_from_url(url)
    data = {
        "event": event,
        "headline": headline,
        "severity": tsunami_severity(event, headline, compact),
        "status": "Actual",
        "message_type": "Update",
        "category": "Geo",
        "alert_kind": "tsunami",
        "tsunami_category": tsunami_event_category(event, headline, compact),
        "area_desc": location,
        "summary": compact,
        "description": compact,
        "source": source,
        "source_url": url,
        "internet_fed": True,
        "latitude": latitude,
        "longitude": longitude,
        "magnitude": magnitude,
        "depth_km": depth_km,
        "event_time": origin_time,
        "incident_id": incident,
        "message_number": tsunami_message_number(headline, event, url),
    }
    return clean_noaa_data(data)


def parse_bulletin_number(text, pattern):
    """Return a float extracted from a tsunami text bulletin."""
    match = re.search(pattern, str(text or ""), re.IGNORECASE)
    return float(match.group(1)) if match else None


def parse_bulletin_field(text, label):
    """Return a one-line field from a tsunami text bulletin."""
    match = re.search(
        r"^\s*\*?\s*{}\s+(.+?)\s*$".format(re.escape(label)),
        str(text or ""),
        re.IGNORECASE | re.MULTILINE,
    )
    return compact_noaa_text(match.group(1), 160) if match else ""


def normalize_bulletin_time(value):
    """Return a parseable UTC timestamp for PTWC text bulletin times."""
    text = compact_noaa_text(value, 80)
    if not text:
        return ""
    match = re.match(
        r"^(\d{2})(\d{2})\s+UTC\s+([A-Z]{3,9})\s+(\d{1,2})\s+(\d{4})$",
        text,
        re.IGNORECASE,
    )
    if not match:
        return text
    month = {
        "JAN": 1,
        "JANUARY": 1,
        "FEB": 2,
        "FEBRUARY": 2,
        "MAR": 3,
        "MARCH": 3,
        "APR": 4,
        "APRIL": 4,
        "MAY": 5,
        "JUN": 6,
        "JUNE": 6,
        "JUL": 7,
        "JULY": 7,
        "AUG": 8,
        "AUGUST": 8,
        "SEP": 9,
        "SEPT": 9,
        "SEPTEMBER": 9,
        "OCT": 10,
        "OCTOBER": 10,
        "NOV": 11,
        "NOVEMBER": 11,
        "DEC": 12,
        "DECEMBER": 12,
    }.get(match.group(3).upper())
    if not month:
        return text
    return "{:04d}-{:02d}-{:02d}T{}:{}:00Z".format(
        int(match.group(5)),
        month,
        int(match.group(4)),
        match.group(1),
        match.group(2),
    )


def parse_bulletin_coordinates(text):
    """Return decimal coordinates from PTWC-style bulletin text."""
    match = re.search(
        r"\bCOORDINATES\s+([0-9]+(?:\.[0-9]+)?)\s+"
        r"(NORTH|SOUTH)\s+([0-9]+(?:\.[0-9]+)?)\s+(EAST|WEST)\b",
        str(text or ""),
        re.IGNORECASE,
    )
    if not match:
        return None, None
    lat = float(match.group(1))
    if match.group(2).lower() == "south":
        lat = -lat
    lon = float(match.group(3))
    if match.group(4).lower() == "west":
        lon = -lon
    return lat, lon


def tsunami_incident_from_url(url):
    """Return the tsunami.gov incident ID embedded in an event URL."""
    match = re.search(r"/events/P[A-Z]{3}/\d{4}/\d{2}/\d{2}/([^/]+)/", str(url or ""))
    return compact_noaa_text(match.group(1), 80) if match else ""


def tsunami_message_number(*values):
    """Return a tsunami message number from a title or CAP identifier."""
    text = " ".join(str(value or "") for value in values)
    match = re.search(r"\b(?:number|message)\s+([0-9]{1,3})\b", text, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"\bP[A-Z]{3}-([0-9]{1,3})-[A-Za-z0-9_-]+\b", text)
    return match.group(1) if match else ""


def tsunami_event_category(*values):
    """Return a compact tsunami product category from event/headline text."""
    text = " ".join(str(value or "") for value in values).lower()
    if "final tsunami threat message" in text or "threat has passed" in text:
        return "Information"
    for category in ("warning", "watch", "advisory", "threat", "information"):
        if category in text:
            return category.title()
    return ""


def tsunami_severity(*values):
    """Map tsunami.gov product category text to a NOAA-like severity."""
    category = tsunami_event_category(*values)
    if category == "Warning":
        return "Severe"
    if category in ("Watch", "Advisory", "Threat"):
        return "Moderate"
    return "Minor"


def tsunami_is_alertworthy(data):
    """Return True for tsunami products that should open Skannr Alerts."""
    status = str((data or {}).get("status") or "").lower()
    if status == "test":
        return False
    text = " ".join(
        str((data or {}).get(field) or "")
        for field in ("event", "headline", "tsunami_category", "summary", "description", "instruction")
    ).lower()
    headline = str((data or {}).get("headline") or "").lower()
    if headline.startswith("test"):
        return False
    if "this is a test" in text or "test purposes" in text:
        return False
    if "final tsunami threat message" in text or "threat has passed" in text:
        return False
    if re.search(r"\btsunami\s+(warning|watch|advisory)\b", text):
        return True
    if "tsunami threat" in text and "no tsunami threat" not in text:
        return True
    if "information" in text:
        return False
    severity = str((data or {}).get("severity") or "").lower()
    return severity in ("moderate", "severe", "extreme")


def merge_noaa_fields(base, extra):
    """Merge NOAA dictionaries without replacing useful fields with blanks."""
    merged = dict(base or {})
    for key, value in (extra or {}).items():
        if value in (None, "", []):
            continue
        if key in ("resource_urls", "map_urls") and isinstance(value, list):
            current = list(merged.get(key) or [])
            for item in value:
                if item and item not in current:
                    current.append(item)
            if current:
                merged[key] = current
        else:
            merged[key] = value
    return merged


def parse_nhc_package(title, summary):
    """Return NHC storm/advisory package metadata when a title is parseable."""
    match = NHC_PRODUCT_RE.search(str(title or "").strip())
    if not match:
        return {}
    system = compact_noaa_text(match.group("system"), 120)
    product_type = compact_noaa_text(match.group("product"), 80)
    advisory_number = compact_noaa_text(match.group("number"), 20).upper()
    if not system or not product_type or not advisory_number:
        return {}
    storm_id = nhc_storm_id(title, summary)
    system_key = noaa_key_fragment(nhc_system_key(system))
    package_key = "{}:advisory-{}".format(
        system_key,
        noaa_key_fragment(advisory_number),
    )
    return {
        "nhc_system": system,
        "nhc_system_key": system_key,
        "nhc_storm_id": storm_id,
        "nhc_advisory_number": advisory_number,
        "nhc_product_type": product_type,
        "nhc_package_key": package_key,
        "nhc_package_label": "{} Advisory {}".format(system, advisory_number),
    }


def nhc_storm_id(*values):
    """Return the NHC cyclone ID, for example EP012026, when present."""
    text = " ".join(str(value or "") for value in values)
    match = NHC_STORM_ID_RE.search(text)
    return match.group(0).upper() if match else ""


def nhc_system_key(system):
    """Return a stable storm-name key if the formal NHC cyclone ID is absent."""
    text = compact_noaa_text(system, 120)
    previous = None
    while text and text != previous:
        previous = text
        text = NHC_SYSTEM_PREFIX_RE.sub("", text).strip()
    return text or system


def merge_nhc_package(existing, data):
    """Merge NHC RSS sub-products into one advisory-package event."""
    data = clean_noaa_data(data)
    if not data.get("nhc_package_key"):
        return data
    products = []
    for product in (existing or {}).get("nhc_products") or []:
        if isinstance(product, dict):
            products.append(product)
    product = nhc_product_entry(data)
    if product:
        product_key = nhc_product_key(product)
        replaced = False
        for index, current in enumerate(products):
            if nhc_product_key(current) == product_key:
                products[index] = product
                replaced = True
                break
        if not replaced:
            products.append(product)
    products = sorted(products, key=nhc_product_sort_key)
    primary = nhc_primary_product(products) or product or {}
    latest = max(
        products,
        key=lambda item: float(item.get("updated_epoch") or 0),
        default=primary,
    )
    merged = dict(existing or {})
    merged.update(data)
    merged["event"] = data.get("nhc_package_label") or data.get("event") or ""
    merged["headline"] = merged["event"]
    merged["message_type"] = "Advisory Package"
    merged["nhc_products"] = products
    merged["nhc_product_count"] = len(products)
    merged["nhc_product_types"] = [
        item.get("product_type")
        for item in products
        if item.get("product_type")
    ]
    merged["nhc_product_titles"] = [
        item.get("title")
        for item in products
        if item.get("title")
    ]
    merged["nhc_product_urls"] = [
        item.get("source_url")
        for item in products
        if item.get("source_url")
    ]
    if primary:
        merged["event_id"] = primary.get("event_id") or merged.get("event_id") or ""
        merged["source_url"] = primary.get("source_url") or merged.get("source_url") or ""
        merged["summary"] = primary.get("summary") or merged.get("summary") or ""
        merged["description"] = merged["summary"]
    if latest:
        merged["updated"] = latest.get("updated") or merged.get("updated") or ""
        if latest.get("updated_epoch") is not None:
            merged["updated_epoch"] = latest.get("updated_epoch")
    merged["fingerprint"] = nhc_package_fingerprint(merged)
    return clean_noaa_data(merged)


def nhc_product_entry(data):
    """Return a compact product entry for an NHC advisory package."""
    product_type = data.get("nhc_product_type") or ""
    title = data.get("event") or data.get("headline") or ""
    if not product_type and not title:
        return {}
    return clean_noaa_data(
        {
            "product_type": product_type or "Product",
            "title": title,
            "event_id": data.get("event_id") or "",
            "source_url": data.get("source_url") or "",
            "updated": data.get("updated") or "",
            "updated_epoch": data.get("updated_epoch"),
            "severity": data.get("severity") or "",
            "summary": data.get("summary") or "",
            "fingerprint": data.get("fingerprint") or "",
        }
    )


def nhc_product_key(product):
    """Return a stable key for replacing the same package sub-product."""
    product_type = noaa_key_fragment((product or {}).get("product_type") or "")
    if product_type:
        return product_type
    return "{}:{}".format(
        "product",
        noaa_key_fragment((product or {}).get("source_url") or (product or {}).get("title") or ""),
    )


def nhc_product_sort_key(product):
    """Return display ordering for NHC package products."""
    product_type = str((product or {}).get("product_type") or "").lower()
    return (
        NHC_PRODUCT_ORDER.get(product_type, 50),
        str((product or {}).get("title") or ""),
    )


def nhc_primary_product(products):
    """Return the product whose link/summary should represent the package."""
    for product in products or []:
        if str(product.get("product_type") or "").lower() in (
            "public advisory",
            "advisory",
            "intermediate advisory",
        ):
            return product
    return (products or [None])[0]


def nhc_package_fingerprint(data):
    """Return a material fingerprint for an aggregated NHC advisory package."""
    product_bits = []
    for product in data.get("nhc_products") or []:
        product_bits.append(
            "|".join(
                str(product.get(field) or "")
                for field in ("product_type", "title", "updated", "source_url", "fingerprint")
            )
        )
    payload = "|".join(
        [
            str(data.get("nhc_package_key") or ""),
            str(data.get("event") or ""),
            str(data.get("basin") or ""),
            "||".join(product_bits),
        ]
    )
    return hashlib.sha1(payload.encode("utf-8", errors="replace")).hexdigest()


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
    if event_type == "noaa_tsunami_alert" or data.get("alert_kind") == "tsunami":
        source = noaa_key_fragment(data.get("source") or "tsunami")
        incident = noaa_key_fragment(
            data.get("incident_id")
            or data.get("event_id")
            or data.get("source_event_id")
            or data.get("tsunami_identifier")
            or data.get("source_url")
            or data.get("headline")
            or "tsunami"
        )
        return "tsunami:{}:{}".format(source, incident)
    if event_type == "noaa_tropical_advisory" or data.get("source") == "NHC":
        basin = noaa_key_fragment(data.get("basin") or data.get("area_desc") or "global")
        package = noaa_key_fragment(data.get("nhc_package_key") or "")
        if not package:
            parsed = parse_nhc_package(
                data.get("event") or data.get("headline") or "",
                data.get("summary") or data.get("description") or "",
            )
            package = noaa_key_fragment(parsed.get("nhc_package_key") or "")
        if package:
            return "nhc:{}:{}".format(basin, package)
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
