"""Optional NOAA/NWS/NHC polling collector.

NOAA feeds are internet-fed situational context. They are useful for operator
alerts and reports, but they are not evidence from a local RF antenna.
"""

import asyncio
import calendar
import hashlib
import html
import json
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
NHC_PRODUCT_NUMBER_RE = re.compile(
    r"\b(public advisory|forecast/advisory|forecast advisory|intermediate advisory|"
    r"special advisory|advisory|discussion|update)\s+"
    r"(?:number\s+|no\.?\s+|#\s*)?[0-9]+[a-z-]*\b",
    re.IGNORECASE,
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
    }
    bool_keys = {"internet_fed"}
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
            "nhc": bool((config.get("nhc") or {}).get("enabled", True)),
        }

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self._fingerprints = {}

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
                self.warning = None
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
        nhc = self.config.get("nhc") or {}
        if nhc.get("enabled", True):
            for basin in self.configured_nhc_basins(nhc):
                if basin in NHC_FEEDS:
                    sources.append(
                        {"name": "nhc_{}".format(basin), "kind": "nhc", "basin": basin}
                    )
        return sources

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
        seen = set()
        for source in self.feed_sources():
            if source["kind"] == "nws":
                source_events = self.poll_nws_alerts()
            elif source["kind"] == "nhc":
                source_events = self.poll_nhc_feed(source["basin"])
            else:
                source_events = []
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
        return events

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
        data["fingerprint"] = self.fingerprint(
            data, ("event", "headline", "severity", "updated", "summary", "source_url")
        )
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


def stable_noaa_event_key(data, event_type=""):
    """Return a stable key for grouping NOAA events across routine updates."""
    data = data or {}
    if event_type == "noaa_tropical_advisory" or data.get("source") == "NHC":
        title = (
            data.get("event")
            or data.get("headline")
            or data.get("summary")
            or data.get("event_id")
            or "nhc"
        )
        title = stable_nhc_advisory_title(title) or title
        return "nhc:{}".format(noaa_key_fragment(title))
    return noaa_key_fragment(
        data.get("event_id") or data.get("headline") or data.get("event") or "noaa"
    )


def stable_nhc_advisory_title(value):
    """Remove advisory numbers from NHC titles for stable advisory identity."""
    text = compact_noaa_text(value, 240)
    if not text:
        return ""
    text = NHC_PRODUCT_NUMBER_RE.sub(lambda match: match.group(1), text)
    return re.sub(r"\s+", " ", text).strip(" -;:")


def noaa_key_fragment(value):
    """Return a compact lowercase key fragment for NOAA grouping."""
    return re.sub(r"[^a-z0-9_.:-]+", "-", str(value or "").strip().lower()).strip("-")
