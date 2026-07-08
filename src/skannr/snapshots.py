"""Hourly compact Subject History snapshots — save, load, purge.

These compact snapshots are saved once per hour as a side effect of the
production refresh cycle.  Each snapshot is a lightweight dict keyed by
collector with subject counts, event counts, and per-subject identity/
enrichment fields.

The delta_snapshot_test backfill tool also uses this module.
"""

import json
import os
import time
from datetime import datetime

from .paths import ensure_owner

DEFAULT_RETENTION_HOURS = 168  # 7 days


# Per-subject-type enrichment fields extracted from the ``data`` dict of
# each subject record in ``sh_dict["subjects"]``.  Only fields present and
# non-empty are included in the snapshot; all values are coerced to str.
_SUBJECT_ENRICHMENT = {
    "wifi_access_point": [
        "ssid",
        "encryption",
        "channel",
        "vendor_name",
        "signal_max",
    ],
    "wifi_client": [
        "vendor_name",
        "ssids",
        "rssi_min",
        "rssi_max",
    ],
    "wifi_client_group": [
        "vendor_name",
        "identity_label",
        "rssi_min",
        "rssi_max",
    ],
    "bluetooth_device": [
        "name",
        "identity_label",
        "manufacturer",
        "findmy_accessory",
        "severity",
        "service_uuids",
        "rssi_min",
        "rssi_max",
    ],
    "bluetooth_device_group": [
        "identity_label",
        "manufacturer",
        "findmy_accessory",
        "device_count",
    ],
    "aprsis_station": [
        "callsign",
        "packet_type",
        "movement_detected",
        "trip_rollup",
        "weather_station",
        "position_span_km",
    ],
    "aprsis_weather_station": [
        "callsign",
        "temperature_f",
        "wind_speed_mph",
        "wind_gust_mph",
        "rain_1h_in",
        "humidity_percent",
        "pressure_hpa",
        "rain_active",
    ],
    "rayhunter_endpoint": [
        "endpoint",
        "rayhunter_version",
        "warning_count",
        "events_in_window",
        "battery",
        "gps_mode",
        "storage",
    ],
    "rtl433_device": [
        "model",
        "id",
        "channel",
        "protocol",
        "category",
        "latest_rssi_db",
        "latest_frequency_mhz",
    ],
    "adsb_aircraft": [
        "icao",
        "callsign",
        "flight",
        "altitude_ft",
        "speed_kts",
        "distance_km",
        "emergency",
        "category",
    ],
    "noaa_weather_alert": [
        "event",
        "headline",
        "severity",
        "alert_kind",
        "area_desc",
        "summary",
    ],
    "noaa_forecast": [
        "temperature_min_f",
        "temperature_max_f",
        "max_precip_probability",
        "max_wind_mph",
        "forecast_change_direction",
    ],
    "noaa_tsunami_alert": [
        "headline",
        "magnitude",
        "tsunami_category",
        "area_desc",
    ],
    "noaa_tropical_advisory": [
        "event",
        "severity",
        "headline",
    ],
    "usgs_earthquake": [
        "magnitude",
        "place",
        "depth_km",
        "distance_km",
        "alert_color",
        "tsunami",
    ],
    "swpc_event": [
        "event",
        "event_kind",
        "scale_label",
        "xray_class",
        "kp_index",
    ],
    "pws_weather": [
        "station_name",
        "temperature_f",
        "humidity_percent",
        "wind_speed_mph",
        "wind_gust_mph",
        "rain_1h_in",
        "pressure_rel_inhg",
    ],
    "lan_device": [
        "mac",
        "ip",
        "hostname",
        "vendor_name",
        "state",
        "observation_count",
    ],
    "lan_gateway": [
        "gateway_ip",
        "vendor_name",
        "observation_count",
    ],
}


# ---------------------------------------------------------------------------
# Build compact snapshot from a Subject History display dict
# ---------------------------------------------------------------------------


def build_snapshot_from_sh(sh_dict, hour_epoch=None):
    """Extract one compact snapshot from a Subject History display dict.

    Uses the normalised ``sh_dict["subjects"]`` list as the single source,
    so every collector gets per-subject detail — not just Wi‑Fi / BLE.

    When *hour_epoch* is given, subjects whose ``last_seen_epoch`` is older
    than the hour are excluded, producing a true per-hour presence window
    instead of a cumulative snapshot.
    """
    snap = {
        "_generated_at": sh_dict.get("generated_at", ""),
        "_generated_at_epoch": sh_dict.get("generated_at_epoch", 0),
    }

    raw_records = sh_dict.get("raw_records_read") or {}
    if not isinstance(raw_records, dict):
        raw_records = {}

    subjects = sh_dict.get("subjects") or []
    if not isinstance(subjects, list):
        subjects = []

    # Group by collector, optionally filtering to the snapshot hour
    by_collector = {}  # collector -> list of subject dicts
    for s in subjects:
        if not isinstance(s, dict):
            continue
        if hour_epoch is not None:
            last_seen = s.get("last_seen_epoch")
            if last_seen is None:
                continue
            # *hour_epoch* is the END of the hour window.
            # Subject must have been active within [hour_epoch-3600, hour_epoch).
            if last_seen < hour_epoch - 3600 or last_seen >= hour_epoch:
                continue
        coll = s.get("collector", "unknown")
        by_collector.setdefault(coll, []).append(s)

    for coll, items in sorted(by_collector.items()):
        col_bin = {
            "subject_count": len(items),
            "event_count": 0,
            "subjects": {},
        }

        for entry in items:
            subj_id = str(entry.get("subject_id") or "").lower()[:120]
            if not subj_id:
                continue

            subj_type = entry.get("subject_type", "")
            data = entry.get("data")
            if not isinstance(data, dict):
                data = {}

            subj = {
                "first_seen_epoch": entry.get("first_seen_epoch"),
                "last_seen_epoch": entry.get("last_seen_epoch"),
                "event_count": _event_count(entry, data, coll),
            }

            # Enrichment from data
            enrich_keys = _SUBJECT_ENRICHMENT.get(subj_type, [])
            for f in enrich_keys:
                v = data.get(f)
                if v not in (None, ""):
                    subj[f] = str(v)[:180]

            # Catch-all: always include at least subject_type if nothing else
            if len(subj) <= 3:  # only the 3 base keys
                subj["subject_type"] = subj_type

            col_bin["subjects"][subj_id] = subj

        # Event count: prefer raw_records_read when available
        source_key = {
            "wifi": "wifi",
            "wifi_monitor": "wifi_monitor",
            "ble": "ble",
        }.get(coll, coll)
        col_bin["event_count"] = int(raw_records.get(source_key, 0) or 0)
        snap[coll] = col_bin

    return snap


def _event_count(entry, data, collector):
    """Return a plausible per-subject event count from the subject record."""
    # Top-level (set by subject_history for subject-based collectors)
    ec = entry.get("event_count")
    if ec:
        return ec
    # Inside data (varies by collector)
    for k in (
        "event_count",
        "packet_count",
        "observation_count",
        "seen_count",
        "update_count",
        "burst_count",
    ):
        v = data.get(k)
        if v:
            try:
                return int(v)
            except (TypeError, ValueError):
                pass
    return 0


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def save_snapshots(snapshots, out_dir, retention_hours=DEFAULT_RETENTION_HOURS):
    """Persist snapshots and purge files older than *retention_hours*."""
    os.makedirs(out_dir, exist_ok=True)
    ensure_owner(out_dir)
    now = int(time.time())
    cutoff = now - (retention_hours * 3600)

    # Purge old
    for fname in os.listdir(out_dir):
        if not fname.startswith("snapshot_"):
            continue
        fpath = os.path.join(out_dir, fname)
        try:
            if os.path.getmtime(fpath) < cutoff:
                os.remove(fpath)
        except OSError:
            pass

    # Write new
    for hour_epoch, snap in sorted(snapshots.items()):
        ts = _hour_label(hour_epoch)
        path = os.path.join(out_dir, f"snapshot_{ts.replace(' ', 'T')}.json")
        out = {"hour_start": ts, "hour_start_epoch": hour_epoch}
        for k, v in snap.items():
            out[k] = v
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, separators=(",", ":"), sort_keys=True)
        ensure_owner(path)
    return len(snapshots)


def load_snapshots(snap_dir):
    """Load all snapshots from disk, keyed by hour_start_epoch."""
    snapshots = {}
    if not os.path.isdir(snap_dir):
        return snapshots
    for fname in sorted(os.listdir(snap_dir)):
        if not fname.startswith("snapshot_") or not fname.endswith(".json"):
            continue
        fpath = os.path.join(snap_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            snapshots[data["hour_start_epoch"]] = data
        except (json.JSONDecodeError, KeyError, OSError):
            continue
    return snapshots


def _hour_label(epoch):
    """Return a local-time hour label like '2026-06-26 14:00'."""
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:00")
