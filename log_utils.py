"""Helpers for JSONL log windows, timestamps, and incremental checkpoints.

This module is intentionally free of collector-specific logic. Device History,
Findings, Reports, and the Flask routes all use these helpers so they agree on
retention windows, timestamp parsing, and how much raw JSONL has already been
folded into materialized summaries.
"""

import calendar
import json
import os
import time
from datetime import datetime, timedelta


def utc_epoch(timestamp):
    """Parse Skannr timestamps into seconds since epoch.

    New logs use local display time, while older logs used UTC ISO strings with
    a trailing Z. Support both so existing history remains readable.
    """
    if isinstance(timestamp, (int, float)):
        return float(timestamp)
    if not timestamp:
        return None
    text = str(timestamp).strip()
    # Legacy Spectra/early Skannr logs used UTC ISO strings. Keep them readable
    # so users do not need to delete old logs after an upgrade.
    for pattern in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00"):
        try:
            return float(
                calendar.timegm(datetime.strptime(text, pattern).timetuple())
            )
        except ValueError:
            pass
    # Current logs are local display timestamps. time.mktime() intentionally
    # interprets them in the host timezone so browser rows match local time.
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S %Z"):
        try:
            return float(
                time.mktime(datetime.strptime(text, pattern).timetuple())
            )
        except ValueError:
            pass
    return None


def normalize_retention_days(value, default=30):
    """Return a non-negative retention day count.

    A value of 0 is valid and means "delete all JSONL logs during startup
    rotation". Negative values are rejected because they make retention
    behavior ambiguous.
    """
    try:
        days = int(value)
    except (TypeError, ValueError):
        days = int(default)
    if days < 0:
        raise ValueError("persistence.filesystem.retention_days must be >= 0")
    return days


def resolve_window_days(config, raw="default"):
    """Return a numeric view window, capped by retention when applicable.

    None means "all retained logs". When retention is a positive finite number,
    numeric windows do not claim to cover more days than can still exist on disk.
    """
    retention_config = ((config or {}).get("persistence") or {}).get(
        "filesystem"
    ) or {}
    retention_days = normalize_retention_days(
        retention_config.get("retention_days", 30)
    )
    default_days = (
        (config or {})
        .get("view_window", {})
        .get("default_days", retention_days or None)
    )
    if raw is None:
        return None
    value = "default" if raw == "" else str(raw).strip().lower()
    if value == "all":
        return None
    if value == "default":
        value = default_days
    try:
        days = float(value)
    except (TypeError, ValueError):
        days = float(default_days)
    if days <= 0:
        return None
    if retention_days > 0:
        days = min(days, float(retention_days))
    return int(days) if days.is_integer() else days


def view_window_options(config):
    """Build non-duplicated View selector options for the dashboard."""
    retention_config = ((config or {}).get("persistence") or {}).get(
        "filesystem"
    ) or {}
    retention_days = normalize_retention_days(
        retention_config.get("retention_days", 30)
    )
    default_days = resolve_window_days(config, "default")
    options = []
    seen = set()

    def add(value, label, days_key):
        # Avoid showing "Default (last 30 days)" and "Last 30 days" as two
        # separate choices when the configured default is already 30.
        if days_key in seen:
            return
        seen.add(days_key)
        options.append({"value": value, "label": label})

    if default_days is None:
        add("default", "Default (all retained logs)", "all")
    else:
        add(
            "default",
            "Default (last {} days)".format(int(default_days)),
            default_days,
        )

    for days in (1, 7, 30):
        if retention_days > 0 and days > retention_days:
            continue
        label = "Last 24 hours" if days == 1 else "Last {} days".format(days)
        add(str(days), label, days)

    options.append({"value": "all", "label": "All retained logs"})
    return options


def window_since_epoch(window_days):
    """Convert a day count into a local-time epoch cutoff."""
    if window_days is None:
        return None
    now = datetime.now().replace(microsecond=0)
    return time.mktime((now - timedelta(days=float(window_days))).timetuple())


def window_metadata(window_days):
    """Describe the selected retained-log range."""
    if window_days is None:
        return {"days": None, "label": "All retained logs", "since": None}
    since_epoch = window_since_epoch(window_days)
    since = (
        datetime.fromtimestamp(since_epoch)
        .replace(microsecond=0)
        .strftime("%Y-%m-%d %H:%M:%S")
    )
    label_days = (
        int(window_days) if float(window_days).is_integer() else window_days
    )
    return {
        "days": window_days,
        "label": "Last {} days".format(label_days),
        "since": since,
    }


def event_in_window(event, window_days):
    """Return True when a JSONL event belongs in the selected view window."""
    since_epoch = window_since_epoch(window_days)
    if since_epoch is None:
        return True
    data = event.get("data") or {}
    timestamp = event.get("timestamp") or data.get("timestamp")
    epoch = utc_epoch(timestamp)
    return epoch is not None and epoch >= since_epoch


def read_jsonl_events(log_dir, collector, window_days=None):
    """Yield parsed events from logs/<collector> filtered by a view window."""
    directory = os.path.join(log_dir, collector)
    if not os.path.isdir(directory):
        return
    for filename in sorted(os.listdir(directory)):
        if not filename.endswith(".jsonl"):
            continue
        path = os.path.join(directory, filename)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        event = json.loads(line)
                    except ValueError:
                        # A truncated line should not make the whole collector
                        # history unreadable after an interrupted write.
                        continue
                    if event_in_window(event, window_days):
                        yield event
        except OSError:
            continue


def count_jsonl_files(log_dir, collector):
    """Count retained JSONL files for a collector directory."""
    directory = os.path.join(log_dir, collector)
    if not os.path.isdir(directory):
        return 0
    return sum(1 for name in os.listdir(directory) if name.endswith(".jsonl"))


def local_timestamp():
    """Return Skannr's local display timestamp format."""
    return datetime.now().replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")


def has_jsonl_checkpoint(summary):
    """Return True when a materialized summary has JSONL file offsets."""
    checkpoint = (summary or {}).get("checkpoint") or {}
    return int(checkpoint.get("version") or 0) >= 1 and isinstance(
        checkpoint.get("collectors"), dict
    )


def empty_jsonl_checkpoint():
    """Create the generic offset-tracking structure for JSONL summaries."""
    timestamp = local_timestamp()
    return {
        "version": 1,
        "created_at": timestamp,
        "updated_at": timestamp,
        "collectors": {},
    }


def current_jsonl_checkpoint(log_dir, collectors):
    """Mark current JSONL file ends as already materialized."""
    checkpoint = empty_jsonl_checkpoint()
    for collector in collectors:
        directory = os.path.join(log_dir, collector)
        files = checkpoint["collectors"].setdefault(collector, {})
        if not os.path.isdir(directory):
            continue
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith(".jsonl"):
                continue
            path = os.path.join(directory, filename)
            try:
                size = os.path.getsize(path)
                files[filename] = {
                    "offset": size,
                    "size": size,
                    "mtime": os.path.getmtime(path),
                }
            except OSError:
                continue
    return checkpoint


def read_incremental_jsonl_events(log_dir, collector, checkpoint):
    """Yield JSONL events added after the stored byte offsets."""
    directory = os.path.join(log_dir, collector)
    collector_state = checkpoint.setdefault("collectors", {}).setdefault(
        collector, {}
    )
    if not os.path.isdir(directory):
        return
    for filename in sorted(os.listdir(directory)):
        if not filename.endswith(".jsonl"):
            continue
        path = os.path.join(directory, filename)
        old = collector_state.get(filename) or {}
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        offset = int(old.get("offset") or 0)
        if offset > size:
            # Log rotation or manual truncation can make a saved offset point
            # past EOF. Restart this file from byte 0 in that case.
            offset = 0
        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                for raw_line in fh:
                    try:
                        yield json.loads(raw_line.decode("utf-8"))
                    except (UnicodeDecodeError, ValueError):
                        # Keep moving if one raw line is corrupt or partially
                        # written. The next refresh will continue after EOF.
                        continue
                offset = fh.tell()
        except OSError:
            continue
        collector_state[filename] = {
            "offset": offset,
            "size": size,
            "mtime": os.path.getmtime(path),
        }
    checkpoint["updated_at"] = local_timestamp()
