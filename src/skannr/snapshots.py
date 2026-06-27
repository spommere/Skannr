"""Hourly compact Subject History snapshots — save, load, purge.

These compact snapshots are saved once per hour as a side effect of the
production refresh cycle.  Each snapshot is a lightweight dict keyed by
collector (wifi_ap, wifi_client, ble) with subject counts, event counts,
and per-subject identity/enrichment fields.

The delta_snapshot_test backfill tool also uses this module.
"""

import json
import os
import time
from datetime import datetime

# Subject-based collectors: have per-subject identity fields.
# Each tuple: (top_level_key, list_key, tuple_of_identity_keys)
SH_SECTIONS = {
    "wifi_ap":     ("wifi", "access_points", ("bssid", "ssid")),
    "wifi_client": ("wifi", "clients",        ("mac",)),
    "ble":         ("ble",  "devices",        ("identity_label", "mac")),
}

# Event-based collectors: lists keyed by collector name in the SH dict.
SH_EVENT_COLLECTORS = [
    "aprsis", "rayhunter", "rtl433", "adsb",
    "noaa", "usgs", "swpc", "pws", "lan",
]

ALL_COLLECTORS = list(SH_SECTIONS.keys()) + SH_EVENT_COLLECTORS

DEFAULT_RETENTION_HOURS = 168  # 7 days


# ---------------------------------------------------------------------------
# Build compact snapshot from a Subject History display dict
# ---------------------------------------------------------------------------

def build_snapshot_from_sh(sh_dict):
    """Extract one compact snapshot from a Subject History display dict."""
    snap = {
        "_generated_at": sh_dict.get("generated_at", ""),
        "_generated_at_epoch": sh_dict.get("generated_at_epoch", 0),
    }

    # Per-collector raw event counts from the summary (when available)
    raw_records = sh_dict.get("raw_records_read") or {}
    if not isinstance(raw_records, dict):
        raw_records = {}

    # Subject-based collectors — per-subject detail
    for col_key, (top, list_key, id_keys) in SH_SECTIONS.items():
        container = sh_dict.get(top, {})
        if not isinstance(container, dict):
            container = {}
        subjects = container.get(list_key, [])
        if not isinstance(subjects, list):
            subjects = []

        total_events = 0
        col_bin = {"subject_count": len(subjects), "event_count": 0,
                   "subjects": {}}

        for entry in subjects:
            if not isinstance(entry, dict):
                continue
            identity = None
            for k in id_keys:
                v = entry.get(k)
                if v:
                    identity = str(v).lower()[:120]
                    break
            if identity is None:
                continue

            ev_count = (
                entry.get("seen_count", 0) +
                entry.get("update_count", 0) +
                entry.get("lost_count", 0))
            subj = {
                "first_seen_epoch": entry.get("first_seen_epoch"),
                "last_seen_epoch": entry.get("last_seen_epoch"),
                "event_count": ev_count,
            }
            total_events += ev_count
            _enrich(subj, entry, col_key)
            col_bin["subjects"][identity] = subj

        # Use raw_records_read when available (source collector keys differ)
        source_key = {
            "wifi_ap": "wifi", "wifi_client": "wifi_monitor",
            "ble": "ble",
        }.get(col_key, col_key)
        col_bin["event_count"] = int(raw_records.get(source_key, total_events) or total_events)
        snap[col_key] = col_bin

    # Event-based collectors — counts only
    for col_key in SH_EVENT_COLLECTORS:
        events = sh_dict.get(col_key, [])
        if not isinstance(events, list):
            events = []
        ev_count = int(raw_records.get(col_key, len(events)) or len(events))
        snap[col_key] = {
            "subject_count": len(events),
            "event_count": ev_count,
            "subjects": {},
        }

    return snap


def _enrich(subj, entry, col_key):
    """Copy lightweight enrichment fields from a SH record."""
    if col_key == "wifi_ap":
        for f in ("ssid", "encryption", "channel", "vendor_name"):
            _set_if_present(subj, f, entry.get(f))
    elif col_key == "wifi_client":
        for f in ("vendor_name", "rssi_min", "rssi_max"):
            _set_if_present(subj, f, entry.get(f))
    elif col_key == "ble":
        for f in ("name", "identity_label", "manufacturer",
                  "grouped_randomized", "findmy_accessory",
                  "device_count", "rssi_min", "rssi_max", "severity"):
            _set_if_present(subj, f, entry.get(f))


def _set_if_present(d, k, v):
    if v not in (None, ""):
        d[k] = str(v)[:180]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_snapshots(snapshots, out_dir, retention_hours=DEFAULT_RETENTION_HOURS):
    """Persist snapshots and purge files older than *retention_hours*."""
    os.makedirs(out_dir, exist_ok=True)
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
