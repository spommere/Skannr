"""Optional Ambient Weather personal weather station collector."""

import asyncio
import calendar
import datetime
import hashlib
import json
import urllib.parse
import urllib.request

from ..log_utils import format_epoch
from .base import BaseCollector, STATE_OFFLINE, STATE_ONLINE, STATE_RETRYING


AMBIENT_DEVICES_ENDPOINT = "https://api.ambientweather.net/v1/devices"
PWS_FIELD_MAX = 240
PWS_TEXT_MAX = 500


def compact_pws_text(value, max_length=PWS_FIELD_MAX):
    """Return compact one-line PWS text."""
    if value in (None, ""):
        return ""
    text = " ".join(str(value).replace("\x00", " ").split())
    return text[:max_length] if text else ""


def clean_pws_data(data):
    """Scrub PWS event data loaded from retained JSONL."""
    if not isinstance(data, dict):
        return {}
    cleaned = {}
    numeric_keys = {
        "timestamp_epoch",
        "event_time_epoch",
        "latitude",
        "longitude",
        "temperature_f",
        "humidity_percent",
        "dewpoint_f",
        "feels_like_f",
        "indoor_temperature_f",
        "indoor_humidity_percent",
        "indoor_dewpoint_f",
        "indoor_feels_like_f",
        "wind_direction_deg",
        "wind_direction_avg_10m_deg",
        "wind_speed_mph",
        "wind_speed_avg_10m_mph",
        "wind_gust_mph",
        "max_daily_gust_mph",
        "rain_1h_in",
        "rain_event_in",
        "rain_day_in",
        "rain_week_in",
        "rain_month_in",
        "rain_year_in",
        "rain_total_in",
        "last_rain_epoch",
        "pressure_rel_inhg",
        "pressure_abs_inhg",
        "solar_w_m2",
        "uv_index",
        "elevation_m",
        "elevation_ft",
        "observation_count",
        "update_count",
        "first_seen_epoch",
        "last_seen_epoch",
        "temperature_min_f",
        "temperature_max_f",
        "temperature_change_f",
        "first_temperature_f",
        "latest_rain_1h_in",
        "rain_1h_max_in",
        "wind_speed_max_mph",
        "wind_gust_max_mph",
        "rain_started_epoch",
        "rain_stopped_epoch",
        "rain_last_transition_epoch",
        "rain_episode_started_epoch",
        "rain_episode_stopped_epoch",
    }
    bool_keys = {"rain_started", "rain_stopped", "rain_active"}
    list_keys = {"sample_battery"}
    long_text_keys = {"weather_summary"}
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
                text = compact_pws_text(item, 80)
                if text and text not in items:
                    items.append(text)
            if items:
                cleaned[key] = items[:24]
        else:
            max_length = PWS_TEXT_MAX if key in long_text_keys else PWS_FIELD_MAX
            text = compact_pws_text(value, max_length)
            if text:
                cleaned[key] = text
    return cleaned


class PWSCollector(BaseCollector):
    """Poll Ambient Weather for current personal weather station state."""

    config_key = "pws"
    name = "PWS"
    tab_label = "PWS"
    required_hardware = "Ambient Weather API"

    @classmethod
    def hardware_status(cls, config):
        """Return configured PWS source metadata without exposing secrets."""
        return {
            "internet_source": True,
            "enabled": bool(config.get("enabled", False)),
            "station_id": config.get("station_id"),
            "mac_address": redacted_present(config.get("mac_address")),
            "application_key": redacted_present(config.get("application_key")),
            "api_key": redacted_present(config.get("api_key")),
            "poll_interval_sec": config.get("poll_interval_sec", 60),
        }

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self._fingerprints = {}

    def detect(self):
        """Ambient Weather needs both API credentials."""
        if not self.config.get("application_key") or not self.config.get("api_key"):
            self.state = STATE_OFFLINE
            self.warning = "No Ambient Weather application_key/api_key configured."
            return False
        self.active_hardware = "Ambient Weather API"
        self.state = STATE_ONLINE
        self.warning = None
        return True

    async def start(self):
        """Poll Ambient Weather until stopped."""
        self._running = True
        if not self.detect():
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return
        await self.emit(
            "collector_online",
            {
                "source": "Ambient Weather",
                "url": self.query_url(redacted=True),
                "station_id": self.config.get("station_id") or "",
                "poll_interval_sec": self.config.get("poll_interval_sec", 60),
                "internet_fed": True,
            },
        )
        interval = float(self.config.get("poll_interval_sec", 60))
        while self._running:
            try:
                events = await self.run_blocking(self.poll_once)
                self.state = STATE_ONLINE
                self.warning = None
                for data in events:
                    await self.emit("pws_weather", data, "info")
            except Exception as exc:
                self.state = STATE_RETRYING
                self.warning = "PWS poll failed: {}".format(
                    self.redacted_error_text(exc)
                )
                await self.emit(
                    "collector_retrying",
                    {"reason": self.warning, "source": "Ambient Weather"},
                    "warning",
                )
            await asyncio.sleep(interval)

    async def run_blocking(self, callback, *args):
        """Run a blocking network call without requiring Python 3.9 to_thread."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, callback, *args)

    def poll_once(self):
        """Fetch and return new/changed PWS station rows."""
        payload = self.fetch_json(self.query_url())
        devices = payload if isinstance(payload, list) else []
        selected = self.selected_devices(devices)
        events = []
        selected_count = len(selected)
        for index, device in enumerate(selected):
            data = self.weather_data(device, index, selected_count)
            station_id = data.get("station_id")
            if not station_id:
                continue
            key = "pws:{}".format(station_id)
            if self.changed(key, data.get("fingerprint")):
                events.append(data)
        return events

    def query_url(self, redacted=False):
        """Return the Ambient Weather devices URL."""
        app_key = "REDACTED" if redacted else self.config.get("application_key")
        api_key = "REDACTED" if redacted else self.config.get("api_key")
        query = urllib.parse.urlencode(
            {
                "applicationKey": app_key or "",
                "apiKey": api_key or "",
            }
        )
        return "{}?{}".format(AMBIENT_DEVICES_ENDPOINT, query)

    def fetch_json(self, url):
        """Fetch the Ambient Weather devices endpoint."""
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": self.config.get("user_agent") or "Skannr PWS collector",
            },
        )
        with urllib.request.urlopen(
            request, timeout=float(self.config.get("request_timeout_sec", 15))
        ) as response:
            body = response.read()
        data = json.loads(body.decode("utf-8", errors="replace"))
        return data if isinstance(data, list) else []

    def redacted_error_text(self, exc):
        """Return exception text without leaking local Ambient credentials."""
        text = compact_pws_text(exc, PWS_TEXT_MAX)
        for key in ("application_key", "api_key"):
            value = self.config.get(key)
            if value:
                text = text.replace(str(value), "REDACTED")
        return text

    def selected_devices(self, devices):
        """Return Ambient devices matching optional local filters."""
        devices = [device for device in devices or [] if isinstance(device, dict)]
        mac_filter = normalize_mac(self.config.get("mac_address"))
        name_filter = compact_pws_text(self.config.get("device_name")).lower()
        if mac_filter:
            return [
                device
                for device in devices
                if normalize_mac(device.get("macAddress") or device.get("mac_address"))
                == mac_filter
            ]
        if name_filter:
            return [
                device
                for device in devices
                if name_filter in self.device_name(device).lower()
            ]
        return devices

    def weather_data(self, device, index=0, selected_count=1):
        """Normalize one Ambient Weather device record."""
        info = device.get("info") if isinstance(device.get("info"), dict) else {}
        last_data = (
            device.get("lastData") if isinstance(device.get("lastData"), dict) else {}
        )
        mac = normalize_mac(device.get("macAddress") or device.get("mac_address"))
        name = self.device_name(device)
        station_id = self.station_id(device, index, selected_count)
        event_time_epoch = (
            millis_epoch(last_data.get("dateutc"))
            or parse_time_value(last_data.get("date"))
            or parse_time_value(device.get("lastDataDate"))
        )
        coords = self.device_coords(info)
        coords_info = info.get("coords") if isinstance(info.get("coords"), dict) else {}
        latitude = first_number(
            info,
            ("latitude", "lat"),
            fallback=coords.get("lat"),
        )
        longitude = first_number(
            info,
            ("longitude", "lon", "lng"),
            fallback=coords.get("lon"),
        )
        data = {
            "station_id": station_id,
            "station_name": name,
            "mac_address": mac,
            "model": compact_pws_text(info.get("model") or device.get("model")),
            "latitude": number_or_none(latitude),
            "longitude": number_or_none(longitude),
            "location_name": compact_pws_text(coords_info.get("location")),
            "elevation_m": first_number(coords_info, ("elevation",)),
            "elevation_ft": meters_to_feet(first_number(coords_info, ("elevation",))),
            "event_time": format_epoch(event_time_epoch) if event_time_epoch else "",
            "event_time_epoch": event_time_epoch,
            "timestamp_epoch": event_time_epoch,
            "ambient_date": compact_pws_text(last_data.get("date")),
            "timezone": compact_pws_text(last_data.get("tz")),
            "temperature_f": first_number(last_data, ("tempf", "tempF")),
            "humidity_percent": first_number(last_data, ("humidity", "humidityout")),
            "dewpoint_f": first_number(last_data, ("dewPoint", "dewpoint", "dewpointf")),
            "feels_like_f": first_number(last_data, ("feelsLike", "feelslike")),
            "indoor_temperature_f": first_number(last_data, ("tempinf", "tempin", "tempinF")),
            "indoor_humidity_percent": first_number(last_data, ("humidityin",)),
            "indoor_dewpoint_f": first_number(last_data, ("dewPointin", "dewpointin")),
            "indoor_feels_like_f": first_number(last_data, ("feelsLikein", "feelslikein")),
            "wind_direction_deg": first_number(last_data, ("winddir",)),
            "wind_direction_avg_10m_deg": first_number(last_data, ("winddir_avg10m",)),
            "wind_speed_mph": first_number(last_data, ("windspeedmph",)),
            "wind_speed_avg_10m_mph": first_number(last_data, ("windspdmph_avg10m",)),
            "wind_gust_mph": first_number(last_data, ("windgustmph",)),
            "max_daily_gust_mph": first_number(last_data, ("maxdailygust",)),
            "rain_1h_in": first_number(last_data, ("hourlyrainin",)),
            "rain_event_in": first_number(last_data, ("eventrainin",)),
            "rain_day_in": first_number(last_data, ("dailyrainin",)),
            "rain_week_in": first_number(last_data, ("weeklyrainin",)),
            "rain_month_in": first_number(last_data, ("monthlyrainin",)),
            "rain_year_in": first_number(last_data, ("yearlyrainin",)),
            "rain_total_in": first_number(last_data, ("totalrainin",)),
            "last_rain_time": compact_pws_text(last_data.get("lastRain")),
            "last_rain_epoch": parse_time_value(last_data.get("lastRain")),
            "pressure_rel_inhg": first_number(last_data, ("baromrelin",)),
            "pressure_abs_inhg": first_number(last_data, ("baromabsin",)),
            "solar_w_m2": first_number(last_data, ("solarradiation",)),
            "uv_index": first_number(last_data, ("uv",)),
            "battery": self.battery_text(last_data),
            "source": "Ambient Weather",
            "source_url": AMBIENT_DEVICES_ENDPOINT,
        }
        data["weather_summary"] = self.weather_summary(data)
        data["fingerprint"] = self.fingerprint(
            data,
            (
                "event_time_epoch",
                "temperature_f",
                "humidity_percent",
                "dewpoint_f",
                "feels_like_f",
                "indoor_temperature_f",
                "indoor_humidity_percent",
                "indoor_dewpoint_f",
                "indoor_feels_like_f",
                "wind_direction_deg",
                "wind_direction_avg_10m_deg",
                "wind_speed_mph",
                "wind_speed_avg_10m_mph",
                "wind_gust_mph",
                "rain_1h_in",
                "rain_event_in",
                "rain_day_in",
                "rain_week_in",
                "rain_month_in",
                "rain_year_in",
                "pressure_rel_inhg",
                "solar_w_m2",
                "uv_index",
                "last_rain_time",
                "battery",
            ),
        )
        return clean_pws_data(data)

    def device_name(self, device):
        """Return an Ambient device display name."""
        info = device.get("info") if isinstance(device.get("info"), dict) else {}
        return compact_pws_text(
            info.get("name")
            or device.get("name")
            or info.get("location")
            or self.config.get("station_id")
            or ""
        )

    def station_id(self, device, index, selected_count=1):
        """Return the stable PWS subject identity."""
        configured = compact_pws_text(self.config.get("station_id"), 120)
        if configured and selected_count <= 1:
            return configured
        name = self.device_name(device)
        if name:
            return name
        mac = normalize_mac(device.get("macAddress") or device.get("mac_address"))
        if mac:
            return mac
        return "pws-{}".format(index + 1)

    def device_coords(self, info):
        """Return lat/lon from Ambient info.coords shapes."""
        coords = info.get("coords") if isinstance(info, dict) else {}
        if not isinstance(coords, dict):
            return {}
        nested = coords.get("coords")
        if isinstance(nested, dict):
            coords = nested
        return {
            "lat": coords.get("lat") or coords.get("latitude"),
            "lon": coords.get("lon") or coords.get("lng") or coords.get("longitude"),
        }

    def battery_text(self, data):
        """Return compact battery/status fields from Ambient lastData."""
        parts = []
        for key in sorted(str(k) for k in (data or {}).keys() if str(k).startswith("batt")):
            value = data.get(key)
            if value in (None, ""):
                continue
            parts.append("{}={}".format(key, value))
        return "; ".join(parts[:8])

    def weather_summary(self, data):
        """Return compact current PWS weather text."""
        parts = []
        if data.get("temperature_f") is not None:
            parts.append("temp {:.0f} F".format(float(data["temperature_f"])))
        if data.get("humidity_percent") is not None:
            parts.append("humidity {:.0f}%".format(float(data["humidity_percent"])))
        if data.get("indoor_temperature_f") is not None:
            parts.append("indoor {:.0f} F".format(float(data["indoor_temperature_f"])))
        wind = data.get("wind_speed_mph")
        gust = data.get("wind_gust_mph")
        if wind is not None or gust is not None:
            wind_parts = []
            if wind is not None:
                wind_parts.append("{:.0f} mph".format(float(wind)))
            if gust is not None:
                wind_parts.append("gust {:.0f}".format(float(gust)))
            parts.append("wind {}".format(" ".join(wind_parts)))
        rain = data.get("rain_1h_in")
        if rain is not None:
            parts.append("1h rain rate {:.2f} in/hr".format(float(rain)))
        pressure = data.get("pressure_rel_inhg")
        if pressure is not None:
            parts.append("pressure {:.2f} inHg".format(float(pressure)))
        return "; ".join(parts)

    def changed(self, key, fingerprint):
        """Return True when a station row is new or materially changed."""
        if not fingerprint:
            return False
        if self._fingerprints.get(key) == fingerprint:
            return False
        self._fingerprints[key] = fingerprint
        return True

    def fingerprint(self, data, fields):
        """Return a stable fingerprint for material PWS changes."""
        payload = "|".join(str((data or {}).get(field) or "") for field in fields)
        return hashlib.sha1(payload.encode("utf-8", errors="replace")).hexdigest()


def redacted_present(value):
    """Return a non-secret indicator for configured credentials."""
    return "configured" if compact_pws_text(value) else ""


def normalize_mac(value):
    """Return lowercase colon-separated MAC text when possible."""
    text = compact_pws_text(value, 80).lower().replace("-", ":")
    if not text:
        return ""
    raw = "".join(ch for ch in text if ch in "0123456789abcdef")
    if len(raw) == 12:
        return ":".join(raw[index : index + 2] for index in range(0, 12, 2))
    return text


def number_or_none(value):
    """Return a float for numeric-looking values."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def first_number(data, keys, fallback=None):
    """Return the first numeric value found in data for the named keys."""
    for key in keys:
        value = (data or {}).get(key)
        number = number_or_none(value)
        if number is not None:
            return number
    return number_or_none(fallback)


def millis_epoch(value):
    """Return seconds from millisecond or second timestamps."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return int(number / 1000) if number > 100000000000 else int(number)


def parse_epoch_value(value):
    """Return epoch seconds for simple numeric date strings."""
    return millis_epoch(value)


def parse_time_value(value):
    """Return epoch seconds for Ambient numeric or ISO timestamp fields."""
    epoch = millis_epoch(value)
    if epoch is not None:
        return epoch
    text = compact_pws_text(value, 80)
    if not text:
        return None
    utc_text = text[:-1] if text.endswith("Z") else text
    if utc_text.endswith("+00:00") or utc_text.endswith("-00:00"):
        utc_text = utc_text[:-6]
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt_value = datetime.datetime.strptime(utc_text, fmt)
            return int(calendar.timegm(dt_value.utctimetuple()))
        except ValueError:
            continue
    return None


def meters_to_feet(value):
    """Return feet for a meter value."""
    number = number_or_none(value)
    return round(number * 3.28084, 1) if number is not None else None
