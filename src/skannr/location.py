"""Volatile observer location shared by location-aware collectors and alerts.

The current implementation keeps only the latest valid fix in memory. It does
not write observer positions to Skannr's event logs or materialized history.
"""

import threading
import time


_LOCK = threading.RLock()
_CURRENT_FIX = None


def set_observer_location(source, fix):
    """Replace the current in-memory observer fix with a validated copy."""
    global _CURRENT_FIX
    if not isinstance(fix, dict):
        return False
    try:
        latitude = float(fix.get("latitude"))
        longitude = float(fix.get("longitude"))
        received_epoch = float(fix.get("received_epoch") or time.time())
    except (TypeError, ValueError):
        return False
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        return False
    cleaned = {
        "source": str(source or "unknown"),
        "latitude": latitude,
        "longitude": longitude,
        "received_epoch": received_epoch,
    }
    try:
        cleaned["stale_after_sec"] = max(0.0, float(fix.get("stale_after_sec", 10)))
    except (TypeError, ValueError):
        cleaned["stale_after_sec"] = 10.0
    for key in ("gps_time_epoch", "accuracy_m", "altitude_m", "speed_mps", "course_deg"):
        try:
            value = float(fix.get(key))
        except (TypeError, ValueError):
            continue
        if value == value and abs(value) != float("inf"):
            cleaned[key] = value
    try:
        cleaned["fix_mode"] = int(fix.get("fix_mode") or 0)
    except (TypeError, ValueError):
        pass
    with _LOCK:
        _CURRENT_FIX = cleaned
    return True


def clear_observer_location(source=None):
    """Clear the current fix, optionally only when it came from *source*."""
    global _CURRENT_FIX
    with _LOCK:
        if _CURRENT_FIX is None:
            return
        if source and _CURRENT_FIX.get("source") != str(source):
            return
        _CURRENT_FIX = None


def current_observer_location(max_age_sec=None, now=None):
    """Return a copy of a fresh location fix, or ``None`` when absent/stale."""
    now = time.time() if now is None else float(now)
    with _LOCK:
        fix = dict(_CURRENT_FIX) if _CURRENT_FIX else None
    if not fix:
        return None
    age = max(0.0, now - float(fix.get("received_epoch") or now))
    if max_age_sec is None:
        max_age_sec = fix.get("stale_after_sec", 10)
    try:
        max_age = max(0.0, float(max_age_sec))
    except (TypeError, ValueError):
        max_age = 10.0
    if max_age and age > max_age:
        return None
    fix["age_sec"] = age
    return fix
