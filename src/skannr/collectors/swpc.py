"""Optional NOAA SWPC space-weather polling collector.

SWPC is an internet-fed situational context source, similar to NOAA/NWS/NHC
and USGS. The collector fetches small public products, normalizes notable
space-weather conditions into compact events, and does not persist raw
time-series samples.
"""

import asyncio
import calendar
import hashlib
import json
import logging
import re
import time
import urllib.request
from datetime import datetime

from ..bus import local_now
from ..log_utils import now_epoch, timestamp_epoch
from .base import BaseCollector, STATE_OFFLINE, STATE_ONLINE, STATE_RETRYING


SWPC_FIELD_MAX = 240
SWPC_TEXT_MAX = 1000
SWPC_ALERTS_URL = "https://services.swpc.noaa.gov/products/alerts.json"
SWPC_SCALES_URL = "https://services.swpc.noaa.gov/products/noaa-scales.json"
SWPC_XRAY_URL = "https://services.swpc.noaa.gov/json/goes/primary/xrays-1-day.json"
SWPC_KP_URL = "https://services.swpc.noaa.gov/products/noaa-planetary-k-index.json"

SWPC_KIND_LABELS = {
    "xray_flare": "X-class solar flare",
    "radio_blackout": "Radio blackout",
    "solar_radiation_storm": "Solar radiation storm",
    "geomagnetic_storm": "Geomagnetic storm",
    "cme_watch": "CME watch/update",
    "swpc_product": "SWPC product",
}


def compact_swpc_text(value, max_length=SWPC_FIELD_MAX):
    """Return compact one-line SWPC text."""
    if value in (None, ""):
        return ""
    text = " ".join(str(value).replace("\x00", " ").split())
    return text[:max_length] if text else ""


def clean_swpc_data(data):
    """Scrub SWPC event data loaded from retained JSONL."""
    if not isinstance(data, dict):
        return {}
    cleaned = {}
    numeric_keys = {
        "timestamp_epoch",
        "event_time_epoch",
        "start_time_epoch",
        "end_time_epoch",
        "peak_time_epoch",
        "updated_epoch",
        "issue_epoch",
        "period_start_epoch",
        "period_end_epoch",
        "event_count",
        "alert_count",
        "critical_count",
        "xray_flare_count",
        "radio_blackout_count",
        "solar_radiation_storm_count",
        "geomagnetic_storm_count",
        "max_kp",
        "max_radio_blackout",
        "max_solar_radiation_storm",
        "max_geomagnetic_storm",
        "scale_value",
        "kp_index",
        "xray_flux_peak",
        "xray_flux_threshold",
        "update_count",
        "first_seen_epoch",
        "last_seen_epoch",
    }
    bool_keys = {"internet_fed", "alert_recommended"}
    list_keys = {"events", "kind_counts", "scale_labels"}
    long_text_keys = {"message", "summary"}
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
                text = compact_swpc_text(item, 80)
                if text and text not in items:
                    items.append(text)
            if items:
                cleaned[key] = items[:24]
        else:
            max_length = SWPC_TEXT_MAX if key in long_text_keys else SWPC_FIELD_MAX
            text = compact_swpc_text(value, max_length)
            if text:
                cleaned[key] = text
    if not cleaned.get("scale_label"):
        label = swpc_scale_label(
            cleaned.get("scale_family"), cleaned.get("scale_value")
        )
        if label:
            cleaned["scale_label"] = label
    return cleaned


class SWPCCollector(BaseCollector):
    """Poll NOAA SWPC feeds and emit compact space-weather events."""

    config_key = "swpc"
    name = "SWPC"
    tab_label = "SWPC"
    required_hardware = "Internet access"
    subject_history_event_types = ("swpc_event", "collector_offline", "collector_retrying")

    @classmethod
    def hardware_status(cls, config):
        """Return configured SWPC product metadata."""
        return {
            "internet_source": True,
            "enabled": bool(config.get("enabled", False)),
            "alerts": bool((config.get("products") or {}).get("alerts", True)),
            "noaa_scales": bool(
                (config.get("products") or {}).get("noaa_scales", True)
            ),
            "xray_flux": bool((config.get("products") or {}).get("xray_flux", True)),
            "planetary_k": bool(
                (config.get("products") or {}).get("planetary_k", True)
            ),
        }

    def __init__(self, config, bus):
        super().__init__(config, bus)
        self._fingerprints = {}
        self._last_subfeed_errors = []

    def detect(self):
        """SWPC only needs at least one enabled public product source."""
        if not self.feed_sources():
            self.state = STATE_OFFLINE
            self.warning = "No SWPC product source configured."
            return False
        self.active_hardware = "NOAA SWPC internet feeds"
        self.state = STATE_ONLINE
        self.warning = None
        return True

    async def start(self):
        """Poll configured SWPC feeds until stopped."""
        self._running = True
        if not self.detect():
            await self.emit("collector_offline", {"reason": self.warning}, "warning")
            return
        await self.emit(
            "collector_online",
            {
                "source": "SWPC",
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
                            "source": "SWPC",
                            "feeds": [source["name"] for source in self.feed_sources()],
                            "warning": self.warning,
                            "internet_fed": True,
                        },
                        "warning",
                    )
                for data in events:
                    await self.emit(
                        "swpc_event",
                        data,
                        "warning" if swpc_event_is_alert(data, self.config) else "info",
                    )
            except Exception as exc:
                self.state = STATE_RETRYING
                self.warning = "SWPC poll failed: {}".format(exc)
                await self.emit(
                    "collector_retrying",
                    {"reason": self.warning, "internet_fed": True},
                    "warning",
                )
            await asyncio.sleep(interval)

    def feed_sources(self):
        """Return enabled SWPC product descriptors."""
        products = self.config.get("products") or {}
        sources = []
        if products.get("alerts", True):
            sources.append({"name": "alerts", "kind": "alerts"})
        if products.get("noaa_scales", True):
            sources.append({"name": "noaa_scales", "kind": "noaa_scales"})
        if products.get("xray_flux", True):
            sources.append({"name": "goes_xray", "kind": "xray_flux"})
        if products.get("planetary_k", True):
            sources.append({"name": "planetary_k", "kind": "planetary_k"})
        return sources

    def poll_once(self):
        """Fetch all enabled SWPC products and return new/changed events."""
        events = []
        errors = []
        sources = self.feed_sources()
        self._last_subfeed_errors = []
        for source in sources:
            try:
                if source["kind"] == "alerts":
                    events.extend(self.poll_alert_products())
                elif source["kind"] == "noaa_scales":
                    events.extend(self.poll_noaa_scales())
                elif source["kind"] == "xray_flux":
                    events.extend(self.poll_xray_flux())
                elif source["kind"] == "planetary_k":
                    events.extend(self.poll_planetary_k())
            except Exception as exc:
                errors.append("{}: {}".format(source.get("name") or "SWPC", exc))
                continue
        if errors and len(errors) == len(sources):
            self._last_subfeed_errors = errors
            raise RuntimeError("; ".join(errors))
        self._last_subfeed_errors = errors
        for error in errors:
            logging.warning("SWPC sub-feed poll failed: %s", error)
        return events

    def product_url(self, key, default):
        """Return configured endpoint URL for a SWPC product key."""
        urls = self.config.get("urls") or {}
        return str(urls.get(key) or default)

    def poll_alert_products(self):
        """Fetch official SWPC alert/watch/warning products."""
        payload = self.fetch_json(self.product_url("alerts", SWPC_ALERTS_URL))
        events = []
        for record in records_from_payload(payload):
            data = self.alert_product_data(record)
            if not data:
                continue
            if self.changed("product:{}".format(data["event_id"]), data["fingerprint"]):
                events.append(data)
        return events

    def alert_product_data(self, record):
        """Normalize one alerts.json product record."""
        record = record if isinstance(record, dict) else {}
        message = self.record_message(record)
        if not message:
            return None
        if not self.product_matches_interest(message):
            return None
        product_id = compact_swpc_text(
            record.get("product_id")
            or record.get("message_code")
            or record.get("code")
            or record.get("id")
            or "swpc-product",
            120,
        )
        issue_time = compact_swpc_text(
            record.get("issue_datetime")
            or record.get("issue_time")
            or record.get("time_tag")
            or record.get("time")
            or record.get("date")
            or "",
            120,
        )
        issue_epoch = swpc_time_epoch(issue_time)
        kind, family, scale, xray_class = classify_swpc_text(message)
        summary = compact_swpc_text(first_message_line(message), 300)
        if not summary:
            summary = SWPC_KIND_LABELS.get(kind, "SWPC product")
        event_id = compact_swpc_text(
            "{}:{}:{}".format(
                product_id,
                issue_time or "unknown-time",
                record.get("serial_number") or stable_hash(message)[:12],
            ),
            220,
        )
        data = {
            "event_id": event_id,
            "event_kind": kind,
            "event": SWPC_KIND_LABELS.get(kind, "SWPC product"),
            "summary": summary,
            "message": message,
            "product_id": product_id,
            "issue_time": issue_time,
            "issue_epoch": issue_epoch,
            "event_time": issue_time,
            "event_time_epoch": issue_epoch,
            "source": "SWPC alerts",
            "source_url": self.product_url("alerts", SWPC_ALERTS_URL),
            "scale_family": family,
            "scale_value": scale,
            "scale_label": swpc_scale_label(family, scale),
            "xray_class": xray_class,
            "internet_fed": True,
        }
        data["alert_recommended"] = swpc_event_is_alert(data, self.config)
        data["fingerprint"] = self.fingerprint(
            data,
            (
                "event_kind",
                "event_time_epoch",
                "summary",
                "message",
                "scale_family",
                "scale_value",
                "xray_class",
            ),
        )
        return clean_swpc_data(data)

    def record_message(self, record):
        """Return the readable text from one SWPC product record."""
        if not isinstance(record, dict):
            return ""
        for key in ("message", "text", "body", "summary", "description"):
            if record.get(key):
                return compact_swpc_text(record.get(key), SWPC_TEXT_MAX)
        parts = []
        for key in sorted(record):
            if key in ("product_id", "issue_datetime", "issue_time", "time_tag"):
                continue
            if record.get(key) not in (None, ""):
                parts.append("{} {}".format(key, record.get(key)))
        return compact_swpc_text(" ".join(parts), SWPC_TEXT_MAX)

    def product_matches_interest(self, message):
        """Return True when an official SWPC product should be retained."""
        patterns = self.config.get("product_keyword_patterns")
        if patterns in (None, ""):
            patterns = [
                "*x-ray*",
                "*xray*",
                "*x-class*",
                "*radio blackout*",
                "*solar radiation storm*",
                "*geomagnetic storm*",
                "*CME*",
                "*coronal mass ejection*",
                "*Kp*",
            ]
        text = str(message or "").lower()
        return any(fnmatch_text(text, pattern) for pattern in patterns or [])

    def poll_noaa_scales(self):
        """Fetch current NOAA R/S/G scale states."""
        payload = self.fetch_json(self.product_url("noaa_scales", SWPC_SCALES_URL))
        scale_payload = current_scale_payload(payload)
        events = []
        for family, kind in (
            ("R", "radio_blackout"),
            ("S", "solar_radiation_storm"),
            ("G", "geomagnetic_storm"),
        ):
            value, text = scale_value_from_payload(scale_payload.get(family))
            if value is None or value < self.feed_min_scale(family):
                continue
            level = "{}{}".format(family, int(value))
            summary = "{} {}".format(SWPC_KIND_LABELS[kind], level)
            if text:
                summary = "{}; {}".format(summary, text)
            now = now_epoch()
            data = {
                "event_id": "scale:{}:{}".format(family, int(value)),
                "event_kind": kind,
                "event": SWPC_KIND_LABELS[kind],
                "summary": summary,
                "event_time": local_now(now),
                "event_time_epoch": now,
                "updated": local_now(now),
                "updated_epoch": now,
                "source": "SWPC NOAA scales",
                "source_url": self.product_url("noaa_scales", SWPC_SCALES_URL),
                "scale_family": family,
                "scale_value": int(value),
                "scale_label": level,
                "internet_fed": True,
            }
            data["alert_recommended"] = swpc_event_is_alert(data, self.config)
            data["fingerprint"] = self.fingerprint(
                data, ("event_kind", "scale_family", "scale_value", "summary")
            )
            if self.changed("scale:{}".format(family), data["fingerprint"]):
                events.append(clean_swpc_data(data))
        return events

    def poll_xray_flux(self):
        """Fetch GOES X-ray flux and emit X-threshold flare events only."""
        payload = self.fetch_json(self.product_url("xray_flux", SWPC_XRAY_URL))
        records = [
            sample
            for sample in records_from_payload(payload)
            if xray_sample_matches_energy(sample)
        ]
        threshold_class = str(self.config.get("xray_min_class") or "X1.0")
        threshold = xray_class_to_flux(threshold_class) or 1e-4
        groups = xray_threshold_groups(records, threshold)
        events = []
        for group in groups:
            data = self.xray_group_event(group, threshold_class, threshold)
            if data and self.changed("xray:{}".format(data["event_id"]), data["fingerprint"]):
                events.append(data)
        return events

    def xray_group_event(self, group, threshold_class, threshold):
        """Return one normalized X-class flare event from contiguous samples."""
        if not group:
            return None
        peak = max(group, key=lambda item: item["flux"])
        start = group[0]
        end = group[-1]
        peak_class = xray_flux_to_class(peak["flux"])
        event_id = "xray:{}:{}".format(start["time"], peak["time"])
        summary = "GOES X-ray flux crossed {}; peak {} at {}".format(
            threshold_class,
            peak_class,
            peak["time"],
        )
        data = {
            "event_id": event_id,
            "event_kind": "xray_flare",
            "event": "X-class solar flare",
            "summary": summary,
            "event_time": peak["time"],
            "event_time_epoch": peak["epoch"],
            "start_time": start["time"],
            "start_time_epoch": start["epoch"],
            "end_time": end["time"],
            "end_time_epoch": end["epoch"],
            "peak_time": peak["time"],
            "peak_time_epoch": peak["epoch"],
            "source": "GOES primary XRS",
            "source_url": self.product_url("xray_flux", SWPC_XRAY_URL),
            "scale_family": "X",
            "scale_label": peak_class,
            "xray_class": peak_class,
            "xray_flux_peak": peak["flux"],
            "xray_flux_threshold": threshold,
            "internet_fed": True,
        }
        data["alert_recommended"] = swpc_event_is_alert(data, self.config)
        data["fingerprint"] = self.fingerprint(
            data, ("event_kind", "start_time", "peak_time", "xray_class", "xray_flux_peak")
        )
        return clean_swpc_data(data)

    def poll_planetary_k(self):
        """Fetch planetary K/Kp and emit storm-threshold events."""
        payload = self.fetch_json(self.product_url("planetary_k", SWPC_KP_URL))
        records = records_from_payload(payload)
        latest = latest_kp_record(records)
        if not latest:
            return []
        kp = number_or_none(
            latest.get("kp_index")
            or latest.get("estimated_kp")
            or latest.get("kp")
            or latest.get("Kp")
        )
        if kp is None or kp < float(self.config.get("feed_min_kp", 5)):
            return []
        time_text = compact_swpc_text(
            latest.get("time_tag") or latest.get("time") or latest.get("timestamp") or "",
            120,
        )
        epoch = swpc_time_epoch(time_text) or now_epoch()
        scale_label = kp_to_g_scale(kp)
        summary = "Planetary Kp {:.1f}".format(kp)
        if scale_label:
            summary = "{} ({})".format(summary, scale_label)
        data = {
            "event_id": "kp:{}:{:.1f}".format(time_text or epoch, kp),
            "event_kind": "geomagnetic_storm",
            "event": "Geomagnetic storm",
            "summary": summary,
            "event_time": time_text or local_now(epoch),
            "event_time_epoch": epoch,
            "source": "SWPC planetary K index",
            "source_url": self.product_url("planetary_k", SWPC_KP_URL),
            "scale_family": "Kp",
            "scale_label": scale_label,
            "scale_value": g_scale_number(scale_label),
            "kp_index": kp,
            "internet_fed": True,
        }
        data["alert_recommended"] = swpc_event_is_alert(data, self.config)
        data["fingerprint"] = self.fingerprint(
            data, ("event_kind", "event_time", "kp_index", "scale_label")
        )
        if self.changed("kp", data["fingerprint"]):
            return [clean_swpc_data(data)]
        return []

    def feed_min_scale(self, family):
        """Return the minimum NOAA scale value shown in the live feed."""
        key = {
            "R": "feed_min_radio_blackout",
            "S": "feed_min_solar_radiation_storm",
            "G": "feed_min_geomagnetic_storm",
        }.get(family)
        if not key:
            return 1
        return int(scale_number(self.config.get(key), default=1) or 1)

    def fetch_json(self, url):
        """Fetch one SWPC JSON URL."""
        text = self.fetch_text(url, accept="application/json, text/json")
        return json.loads(text)

    def changed(self, key, fingerprint):
        """Return True when a source event is new or materially changed."""
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


def records_from_payload(payload):
    """Return dict records from common SWPC JSON shapes."""
    if isinstance(payload, dict):
        for key in ("products", "features", "data", "items"):
            if isinstance(payload.get(key), list):
                return records_from_payload(payload[key])
        return [payload]
    if not isinstance(payload, list):
        return []
    if payload and isinstance(payload[0], list):
        headers = [str(item or "").strip() for item in payload[0]]
        records = []
        for row in payload[1:]:
            if isinstance(row, list):
                records.append(
                    {
                        headers[index] if index < len(headers) else str(index): value
                        for index, value in enumerate(row)
                    }
                )
        return records
    return [item for item in payload if isinstance(item, dict)]


def current_scale_payload(payload):
    """Return the most likely current NOAA R/S/G scale object."""
    if not isinstance(payload, dict):
        return {}
    for key in ("0", "current", "Current", "now", "Now"):
        value = payload.get(key)
        if isinstance(value, dict) and any(item in value for item in ("R", "S", "G")):
            return value
    if any(item in payload for item in ("R", "S", "G")):
        return payload
    for value in payload.values():
        if isinstance(value, dict) and any(item in value for item in ("R", "S", "G")):
            return value
    return {}


def scale_value_from_payload(value):
    """Return (scale number, text) from one NOAA scale value."""
    if isinstance(value, dict):
        scale = (
            value.get("Scale")
            or value.get("scale")
            or value.get("Current")
            or value.get("current")
            or value.get("value")
        )
        text = compact_swpc_text(
            value.get("Text") or value.get("text") or value.get("message") or "",
            220,
        )
        return scale_number(scale), text
    return scale_number(value), ""


def classify_swpc_text(message):
    """Return (event_kind, scale_family, scale_value, xray_class)."""
    text = str(message or "")
    lowered = text.lower()
    xray_class = extract_xray_class(text)
    if xray_class:
        return "xray_flare", "X", None, xray_class
    if "radio blackout" in lowered:
        return "radio_blackout", "R", extract_scale_value(text, "R"), ""
    if "solar radiation storm" in lowered:
        return "solar_radiation_storm", "S", extract_scale_value(text, "S"), ""
    if "geomagnetic storm" in lowered:
        return "geomagnetic_storm", "G", extract_scale_value(text, "G"), ""
    if "coronal mass ejection" in lowered or re.search(r"\bCME\b", text):
        return "cme_watch", "", None, ""
    scale_match = re.search(r"\b([RSG])\s*([1-5])\b", text, re.IGNORECASE)
    if scale_match:
        family = scale_match.group(1).upper()
        kind = {
            "R": "radio_blackout",
            "S": "solar_radiation_storm",
            "G": "geomagnetic_storm",
        }.get(family, "swpc_product")
        return kind, family, int(scale_match.group(2)), ""
    return "swpc_product", "", None, ""


def extract_scale_value(text, family):
    """Return the first R/S/G scale value found in text."""
    match = re.search(r"\b{}\s*([1-5])\b".format(re.escape(family)), text, re.IGNORECASE)
    return int(match.group(1)) if match else None


def extract_xray_class(text):
    """Return the first X-class token found in SWPC text."""
    match = re.search(r"\bX\s*([0-9]+(?:\.[0-9]+)?)\b", str(text or ""), re.IGNORECASE)
    if not match:
        return ""
    return "X{}".format(match.group(1))


def xray_sample_matches_energy(sample):
    """Return True for the GOES 0.1-0.8nm X-ray channel."""
    energy = str((sample or {}).get("energy") or "").lower()
    return not energy or "0.1-0.8" in energy or "long" in energy


def xray_threshold_groups(records, threshold):
    """Return contiguous samples above the configured X-ray threshold."""
    samples = []
    for record in records or []:
        flux = number_or_none(
            record.get("observed_flux")
            or record.get("flux")
            or record.get("value")
            or record.get("xray_flux")
        )
        if flux is None or flux < threshold:
            continue
        time_text = compact_swpc_text(
            record.get("time_tag") or record.get("time") or record.get("timestamp") or "",
            120,
        )
        epoch = swpc_time_epoch(time_text)
        if epoch is None:
            continue
        samples.append({"time": time_text, "epoch": epoch, "flux": flux})
    samples.sort(key=lambda item: item["epoch"])
    groups = []
    current = []
    previous_epoch = None
    for sample in samples:
        if previous_epoch is not None and sample["epoch"] - previous_epoch > 1800:
            if current:
                groups.append(current)
            current = []
        current.append(sample)
        previous_epoch = sample["epoch"]
    if current:
        groups.append(current)
    return groups


def latest_kp_record(records):
    """Return the latest planetary K/Kp record by timestamp."""
    latest = None
    latest_epoch = None
    for record in records or []:
        time_text = record.get("time_tag") or record.get("time") or record.get("timestamp")
        epoch = swpc_time_epoch(time_text)
        if epoch is None:
            continue
        if latest_epoch is None or epoch >= latest_epoch:
            latest = record
            latest_epoch = epoch
    return latest


def xray_class_to_flux(value):
    """Convert a solar flare class such as X1.0 to W/m^2 flux."""
    match = re.match(
        r"^\s*([ABCMX])\s*([0-9]+(?:\.[0-9]+)?)?\s*$",
        str(value or ""),
        re.IGNORECASE,
    )
    if not match:
        return None
    base = {
        "A": 1e-8,
        "B": 1e-7,
        "C": 1e-6,
        "M": 1e-5,
        "X": 1e-4,
    }.get(match.group(1).upper())
    multiplier = float(match.group(2) or 1.0)
    return base * multiplier if base else None


def xray_flux_to_class(flux):
    """Convert W/m^2 X-ray flux to a compact flare class."""
    try:
        value = float(flux)
    except (TypeError, ValueError):
        return ""
    if value >= 1e-4:
        return "X{:.1f}".format(value / 1e-4)
    if value >= 1e-5:
        return "M{:.1f}".format(value / 1e-5)
    if value >= 1e-6:
        return "C{:.1f}".format(value / 1e-6)
    if value >= 1e-7:
        return "B{:.1f}".format(value / 1e-7)
    return "A{:.1f}".format(value / 1e-8) if value > 0 else ""


def kp_to_g_scale(kp):
    """Return the NOAA G-scale label implied by Kp."""
    try:
        value = float(kp)
    except (TypeError, ValueError):
        return ""
    if value >= 9:
        return "G5"
    if value >= 8:
        return "G4"
    if value >= 7:
        return "G3"
    if value >= 6:
        return "G2"
    if value >= 5:
        return "G1"
    return ""


def g_scale_number(label):
    """Return numeric value for a G-scale label."""
    return scale_number(label, default=None)


def scale_number(value, default=None):
    """Return numeric value from R3/S3/G3/Kp-style scale text."""
    if value in (None, ""):
        return default
    if isinstance(value, (int, float)):
        return int(float(value))
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)", str(value))
    if not match:
        return default
    try:
        return int(float(match.group(1)))
    except (TypeError, ValueError):
        return default


def swpc_scale_label(family, value):
    """Return a compact NOAA scale label such as G3, R3, or S3."""
    family_text = compact_swpc_text(family, 8).upper()
    if family_text not in {"G", "R", "S"}:
        return ""
    number = scale_number(value)
    if number is None:
        return ""
    return "{}{}".format(family_text, number)


def swpc_event_is_alert(data, config=None):
    """Return True when a normalized SWPC event crosses alert thresholds."""
    data = data or {}
    config = config or {}
    kind = data.get("event_kind") or ""
    family = data.get("scale_family") or ""
    if kind == "xray_flare":
        threshold = xray_class_to_flux(config.get("alert_min_xray_class") or "X1.0")
        return (xray_class_to_flux(data.get("xray_class")) or 0) >= (threshold or 1e-4)
    if family == "Kp":
        return (number_or_none(data.get("kp_index")) or 0) >= float(
            config.get("alert_min_kp", 7)
        )
    thresholds = {
        "R": config.get("alert_min_radio_blackout") or "R3",
        "S": config.get("alert_min_solar_radiation_storm") or "S3",
        "G": config.get("alert_min_geomagnetic_storm") or "G3",
    }
    if family in thresholds:
        value = scale_number(data.get("scale_value"))
        return value is not None and value >= scale_number(thresholds[family], default=3)
    return False


def swpc_event_is_critical(data, config=None):
    """Return True when a normalized SWPC alert should be critical."""
    data = data or {}
    config = config or {}
    kind = data.get("event_kind") or ""
    family = data.get("scale_family") or ""
    if kind == "xray_flare":
        threshold = xray_class_to_flux(config.get("critical_min_xray_class") or "X5.0")
        return (xray_class_to_flux(data.get("xray_class")) or 0) >= (threshold or 5e-4)
    if family == "Kp":
        return (number_or_none(data.get("kp_index")) or 0) >= float(
            config.get("critical_min_kp", 8)
        )
    thresholds = {
        "R": config.get("critical_min_radio_blackout") or "R4",
        "S": config.get("critical_min_solar_radiation_storm") or "S4",
        "G": config.get("critical_min_geomagnetic_storm") or "G4",
    }
    if family in thresholds:
        value = scale_number(data.get("scale_value"))
        return value is not None and value >= scale_number(thresholds[family], default=4)
    return False


def swpc_time_epoch(value):
    """Parse common SWPC UTC timestamps into epoch seconds."""
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    normalized = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", normalized)
    patterns = (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    )
    for pattern in patterns:
        try:
            parsed = datetime.strptime(normalized, pattern)
            if parsed.tzinfo is not None:
                return int(calendar.timegm(parsed.utctimetuple()))
            return int(calendar.timegm(parsed.timetuple()))
        except ValueError:
            pass
    return timestamp_epoch(text)


def number_or_none(value):
    """Return a float for numeric-ish values."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def first_message_line(message):
    """Return the first useful non-header line in a SWPC message."""
    for line in str(message or "").splitlines():
        text = line.strip()
        if not text:
            continue
        if text.lower().startswith("space weather message code"):
            continue
        if text.lower().startswith("serial number"):
            continue
        if text.lower().startswith("issue time"):
            continue
        return text
    return ""


def stable_hash(text):
    """Return a short stable hash for event IDs."""
    return hashlib.sha1(str(text or "").encode("utf-8", errors="replace")).hexdigest()


def fnmatch_text(text, pattern):
    """Return case-insensitive fnmatch-style text match."""
    import fnmatch

    return fnmatch.fnmatch(str(text or "").lower(), str(pattern or "").lower())
