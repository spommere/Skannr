"""Helpers for JSONL log windows, timestamps, and incremental checkpoints.

This module is intentionally free of collector-specific logic. Device History,
Findings, Reports, and the Flask routes all use these helpers so they agree on
retention windows, timestamp parsing, and how much raw JSONL has already been
folded into materialized summaries.
"""

import json
import os
import re
import tempfile
import time
from datetime import datetime

from .paths import ensure_owner

# Control characters that are never valid in JSON (even inside strings).
# JSON only permits \t (0x09), \n (0x0A), and \r (0x0D).
_JSON_INVALID_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def sanitize_json_line(line):
    """Strip control characters that are invalid in JSON from *line*.

    Null bytes and other binary garbage can appear in log files after an
    interrupted write or filesystem corruption.  Removing them lets
    ``json.loads`` succeed on the remaining valid JSON text.

    The fast-path avoids a string allocation on clean lines (the common case).
    """
    if _JSON_INVALID_CTRL_RE.search(line) is None:
        return line
    return _JSON_INVALID_CTRL_RE.sub("", line)


def now_epoch():
    """Return the current local host epoch seconds.

    Epoch seconds are Skannr's internal time source. Display strings are derived
    from this value only when writing UI-facing fields.
    """
    return int(time.time())


def cleanup_orphaned_temp_files(log_dir):
    """Remove stale ``.tmp`` files left by interrupted atomic writes.

    ``save_json_atomic`` writes to a temp file then renames it atomically.
    If the process is killed mid-write the temp file is orphaned — safe to
    delete because the data was never committed.
    """
    removed = 0
    for dirpath, _dirnames, filenames in os.walk(log_dir):
        for fname in filenames:
            if not fname.endswith(".tmp"):
                continue
            if not fname.startswith("."):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                os.remove(fpath)
                removed += 1
                logging.info("removed orphaned temp file %s", fpath)
            except OSError:
                pass
    if removed:
        logging.info("cleaned up %s orphaned temp files under %s", removed, log_dir)


def save_json_atomic(path, payload, pretty=False, fsync=False):
    """Write JSON by replacing the old file only after the new file is complete."""
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    ensure_owner(directory)
    json_options = (
        {"indent": 2, "sort_keys": True}
        if pretty
        else {"separators": (",", ":"), "sort_keys": False}
    )
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=directory,
            prefix=".{}.".format(os.path.basename(path)),
            suffix=".tmp",
            delete=False,
        ) as fh:
            temp_path = fh.name
            json.dump(payload, fh, **json_options)
            fh.flush()
            if fsync:
                os.fsync(fh.fileno())
        os.replace(temp_path, path)
        temp_path = None
        ensure_owner(path)
    finally:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass


def format_epoch(epoch):
    """Format epoch seconds using Skannr's local display timestamp format."""
    try:
        value = float(epoch)
    except (TypeError, ValueError):
        value = now_epoch()
    return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")


def timestamp_epoch(timestamp):
    """Return epoch seconds for numeric values or display timestamp strings."""
    if isinstance(timestamp, (int, float)):
        return int(float(timestamp))
    if not timestamp:
        return None
    text = str(timestamp).strip()
    # time.mktime() intentionally interprets display timestamps in the host
    # timezone so browser rows and derived summaries agree with local time.
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S %Z"):
        try:
            return int(time.mktime(datetime.strptime(text, pattern).timetuple()))
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
    retention_config = ((config or {}).get("persistence") or {}).get("filesystem") or {}
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
    retention_config = ((config or {}).get("persistence") or {}).get("filesystem") or {}
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
    return now_epoch() - int(float(window_days) * 86400)


def window_metadata(window_days):
    """Describe the selected retained-log range."""
    if window_days is None:
        return {"days": None, "label": "All retained logs", "since": None}
    since_epoch = window_since_epoch(window_days)
    since = format_epoch(since_epoch)
    label_days = int(window_days) if float(window_days).is_integer() else window_days
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
    epoch = event_time_epoch(event) or timestamp_epoch(data.get("timestamp"))
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
                        event = json.loads(sanitize_json_line(line))
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
    """Return the current local display timestamp."""
    return format_epoch(now_epoch())


def event_time_epoch(event):
    """Return an event's canonical epoch timestamp."""
    data = (event or {}).get("data") or {}
    for value in (
        (event or {}).get("timestamp_epoch"),
        data.get("timestamp_epoch"),
        (event or {}).get("epoch"),
        data.get("epoch"),
    ):
        epoch = timestamp_epoch(value)
        if epoch is not None:
            return epoch
    return timestamp_epoch((event or {}).get("timestamp"))


def record_time_epoch(record, field):
    """Return a record field's epoch companion or parse its display value."""
    if not isinstance(record, dict):
        return None
    epoch = timestamp_epoch(record.get("{}_epoch".format(field)))
    if epoch is not None:
        return epoch
    return timestamp_epoch(record.get(field))


def has_jsonl_checkpoint(summary):
    """Return True when a materialized summary has JSONL file offsets."""
    checkpoint = (summary or {}).get("checkpoint") or {}
    return int(checkpoint.get("version") or 0) >= 1 and isinstance(
        checkpoint.get("collectors"), dict
    )


def empty_jsonl_checkpoint():
    """Create the generic offset-tracking structure for JSONL summaries."""
    epoch = now_epoch()
    timestamp = format_epoch(epoch)
    return {
        "version": 1,
        "created_at": timestamp,
        "created_at_epoch": epoch,
        "updated_at": timestamp,
        "updated_at_epoch": epoch,
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


def read_incremental_jsonl_events(log_dir, collector, checkpoint, read_stats=None):
    """Yield JSONL events added after the stored byte offsets."""
    directory = os.path.join(log_dir, collector)
    collector_state = checkpoint.setdefault("collectors", {}).setdefault(collector, {})
    stats = None
    if read_stats is not None:
        stats = read_stats.setdefault(
            collector,
            {
                "pending_bytes": 0,
                "bytes_read": 0,
                "raw_lines": 0,
                "decoded_records": 0,
                "invalid_lines": 0,
                "files": 0,
                "max_line_bytes": 0,
                "event_types": {},
            },
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
        if stats is not None and size > offset:
            stats["pending_bytes"] += size - offset
            stats["files"] += 1
        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                for raw_line in fh:
                    raw_size = len(raw_line)
                    if stats is not None:
                        stats["bytes_read"] += raw_size
                        stats["raw_lines"] += 1
                        stats["max_line_bytes"] = max(
                            int(stats.get("max_line_bytes") or 0), raw_size
                        )
                    try:
                        event = json.loads(sanitize_json_line(raw_line.decode("utf-8")))
                    except (UnicodeDecodeError, ValueError):
                        if stats is not None:
                            stats["invalid_lines"] += 1
                        # Keep moving if one raw line is corrupt or partially
                        # written. The next refresh will continue after EOF.
                        continue
                    if stats is not None:
                        stats["decoded_records"] += 1
                        event_type = str(
                            event.get("type") or event.get("event_type") or "unknown"
                        )
                        event_types = stats.setdefault("event_types", {})
                        event_types[event_type] = (
                            int(event_types.get(event_type) or 0) + 1
                        )
                    yield event
                offset = fh.tell()
        except OSError:
            continue
        collector_state[filename] = {
            "offset": offset,
            "size": size,
            "mtime": os.path.getmtime(path),
        }
    epoch = now_epoch()
    checkpoint["updated_at"] = format_epoch(epoch)
    checkpoint["updated_at_epoch"] = epoch
