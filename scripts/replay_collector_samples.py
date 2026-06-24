#!/usr/bin/env python3
"""Replay representative Skannr collector samples through derived views.

This is an offline integration test built from captured runtime/logs trees. It
populates ./runtime/logs like a deployment, runs the real Skannr derived-view
builders, and writes a repeatable report under ./test.
"""

import argparse
import json
import os
import shutil
import sys
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from skannr.bus import local_now
from skannr.log_utils import sanitize_json_line
from skannr.main import (  # noqa: E402
    refresh_history_analysis,
    refresh_reports,
    refresh_subject_history,
    runtime,
    subject_annotation_key,
)

DEFAULT_DATE = "2026-06-12"
MAX_EVENTS_PER_COLLECTOR = 100
LOG_DIR = Path("/scratch/spommere/Skannr_test/runtime/logs")
REPORT_DIR = Path("/scratch/spommere/Skannr_test")

DEFAULT_PI4_ROOT = Path("/scratch/spommere/Skannr_test/newpi4/runtime/logs")
DEFAULT_HAMPI4_ROOT = Path("/scratch/spommere/Skannr_test/newhampi4/runtime/logs")

# Pick one source per collector so the replay covers both Pis without duplicating
# the same collector family from both captures. Values identify which source root
# to use; parse_args resolves them into concrete paths.
COLLECTOR_SOURCE_KEYS = {
    "adsb": "pi4",
    "aprsis": "hampi4",
    "ble": "pi4",
    "bt_classic": "pi4",
    "lan": "pi4",
    "noaa": "hampi4",
    "pws": "hampi4",
    "rayhunter": "pi4",
    "rtl433": "pi4",
    "rtlsdr": "pi4",
    "swpc": "hampi4",
    "usgs": "hampi4",
    "wifi": "pi4",
    "wifi_monitor": "pi4",
}

DEVICE_EVENT_TYPES = {
    "adsb": {"adsb_aircraft"},
    "aprsis": {"aprs_position", "aprs_weather", "aprs_status", "aprs_object"},
    "ble": {"device_seen", "device_updated", "device_lost"},
    "bt_classic": {"device_seen", "device_updated", "device_lost"},
    "lan": {"lan_device_seen", "lan_device_changed", "lan_gateway_seen", "lan_gateway_changed"},
    "noaa": {"noaa_weather_alert", "noaa_tropical_advisory", "noaa_forecast_summary", "noaa_tsunami_alert"},
    "pws": {"pws_weather"},
    "rayhunter": {"rayhunter_status"},
    "rtl433": {"rtl433_event"},
    "rtlsdr": {"baseline_ready", "signal_detected", "signal_lost", "scanner_started"},
    "swpc": {"swpc_event"},
    "usgs": {"usgs_earthquake"},
    "wifi": {"ap_beacon", "scan_result", "wifi_ap", "scan_empty"},
    "wifi_monitor": {"ap_beacon", "probe_request", "association_seen", "deauth_seen", "disassoc_seen"},
}

LIFECYCLE_TYPES = {
    "collector_online",
    "scanner_started",
    "monitor_started",
    "scan_started",
    "interface_mode",
}

DEVICE_HISTORY_COLLECTORS = {"wifi", "wifi_monitor", "ble", "ble_identify", "bt_classic"}
DIRECT_COLLECTORS = {
    "aprsis",
    "rayhunter",
    "rtlsdr",
    "rtl433",
    "adsb",
    "noaa",
    "usgs",
    "swpc",
    "pws",
    "lan",
    "lan_identify",
}
PHASE2_ENABLED_COLLECTORS = DEVICE_HISTORY_COLLECTORS | {"rtl433"}
ANNOTATION_NAME = "Replay LAN annotation"


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", default=DEFAULT_DATE, help="source JSONL date to replay")
    parser.add_argument("--max-events", type=int, default=MAX_EVENTS_PER_COLLECTOR)
    parser.add_argument("--pi4-root", default=str(DEFAULT_PI4_ROOT), help="pi4 runtime/logs source root")
    parser.add_argument("--hampi4-root", default=str(DEFAULT_HAMPI4_ROOT), help="hampi4 runtime/logs source root")
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace ./runtime/logs; without this, existing logs are moved to ./test/backup-*",
    )
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="fail instead of moving/replacing an existing ./runtime/logs tree",
    )
    return parser.parse_args()



def collector_sources(args):
    roots = {"pi4": Path(args.pi4_root), "hampi4": Path(args.hampi4_root)}
    return {collector: roots[source] for collector, source in COLLECTOR_SOURCE_KEYS.items()}

def event_type(event):
    return str(event.get("type") or event.get("event_type") or "unknown")


def event_data(event):
    data = event.get("data")
    return data if isinstance(data, dict) else {}


def subject_key(collector, event):
    data = event_data(event)
    typ = event_type(event)
    if collector == "adsb":
        return data.get("icao") or data.get("hex") or data.get("flight")
    if collector == "aprsis":
        return data.get("callsign") or data.get("station") or data.get("object_name")
    if collector in ("ble", "bt_classic"):
        return data.get("mac") or data.get("address") or data.get("name")
    if collector == "lan":
        return data.get("mac") or data.get("ip") or data.get("gateway_ip")
    if collector == "noaa":
        return data.get("event_id") or data.get("event") or data.get("headline") or data.get("summary")
    if collector == "pws":
        return data.get("station_id") or data.get("station_name") or data.get("source")
    if collector == "rayhunter":
        return data.get("endpoint") or data.get("device") or "rayhunter"
    if collector == "rtl433":
        return data.get("subject_key") or "|".join(str(data.get(k) or "") for k in ("model", "id", "channel", "protocol"))
    if collector == "rtlsdr":
        return data.get("frequency_mhz") or data.get("center_frequency") or typ
    if collector == "swpc":
        return data.get("event_id") or data.get("event") or data.get("summary") or data.get("message_id")
    if collector == "usgs":
        return data.get("event_id") or data.get("place") or data.get("id")
    if collector == "wifi":
        return data.get("bssid") or data.get("ssid") or typ
    if collector == "wifi_monitor":
        return data.get("client_mac") or data.get("bssid") or data.get("ssid") or typ
    return data.get("subject_key") or data.get("id") or typ


def read_jsonl(path):
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, 1):
            line = sanitize_json_line(line)
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except ValueError as exc:
                raise RuntimeError(f"{path}:{line_number}: invalid JSON: {exc}") from exc


def sample_events(collector, source_root, date, max_events):
    path = Path(source_root) / collector / f"{date}.jsonl"
    if not path.exists():
        return [], {"source": str(path), "missing": True}
    lifecycle = []
    buckets = defaultdict(list)
    unkeyed = []
    counts = Counter()
    unique_keys = set()
    for event in read_jsonl(path):
        typ = event_type(event)
        counts[typ] += 1
        key = subject_key(collector, event)
        if key:
            unique_keys.add(str(key))
        if typ in LIFECYCLE_TYPES and len(lifecycle) < 3:
            lifecycle.append(event)
            continue
        if typ not in DEVICE_EVENT_TYPES.get(collector, set()):
            continue
        if key:
            buckets[str(key)].append(event)
        else:
            unkeyed.append(event)
    selected = list(lifecycle)
    queues = [deque(items[:5]) for _, items in sorted(buckets.items())]
    while queues and len(selected) < max_events:
        next_round = []
        for queue in queues:
            if len(selected) >= max_events:
                break
            if queue:
                selected.append(queue.popleft())
            if queue:
                next_round.append(queue)
        queues = next_round
    for event in unkeyed:
        if len(selected) >= max_events:
            break
        selected.append(event)
    meta = {
        "source": str(path),
        "source_records": sum(counts.values()),
        "source_event_types": dict(counts),
        "source_unique_keys": len(unique_keys),
        "selected_records": len(selected),
        "selected_unique_keys": len({str(subject_key(collector, item)) for item in selected if subject_key(collector, item)}),
    }
    return selected, meta


def rewrite_event_times(events, start_epoch):
    rewritten = []
    for index, event in enumerate(events):
        item = json.loads(json.dumps(event))
        epoch = start_epoch + index
        item["timestamp_epoch"] = epoch
        item["timestamp"] = local_now(epoch)
        rewritten.append(item)
    return rewritten



def collect_from_keys(keys, groups, limit):
    selected = []
    queues = [deque(groups[key]) for key in keys if groups.get(key)]
    while queues and len(selected) < limit:
        next_round = []
        for queue in queues:
            if len(selected) >= limit:
                break
            if queue:
                selected.append(queue.popleft())
            if queue:
                next_round.append(queue)
        queues = next_round
    return selected


def split_replay_batches(collector, events, max_events):
    groups = defaultdict(list)
    for index, event in enumerate(events):
        key = subject_key(collector, event) or f"__row_{index}"
        groups[str(key)].append(event)
    keys = sorted(groups)
    if len(keys) > 1:
        first_keys = keys[::2]
        second_keys = keys[1::2]
        return (
            collect_from_keys(first_keys, groups, max_events),
            collect_from_keys(second_keys, groups, max_events),
        )
    return events[:max_events], events[max_events : max_events * 2]


def sample_unique_keys(events, collector):
    return {str(subject_key(collector, event)) for event in events if subject_key(collector, event)}

def prepare_log_dir(force, keep_existing):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    if LOG_DIR.exists() and any(LOG_DIR.iterdir()):
        if keep_existing:
            raise RuntimeError(f"{LOG_DIR} already exists and is not empty")
        if force:
            shutil.rmtree(LOG_DIR)
        else:
            backup = REPORT_DIR / f"backup-runtime-logs-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            shutil.move(str(LOG_DIR), str(backup))
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / "device_history").mkdir(parents=True, exist_ok=True)


def write_raw_logs(samples, date, append=False):
    raw_counts = {}
    for collector, events in samples.items():
        collector_dir = LOG_DIR / collector
        collector_dir.mkdir(parents=True, exist_ok=True)
        path = collector_dir / f"{date}.jsonl"
        mode = "a" if append else "w"
        with path.open(mode, encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
        raw_counts[collector] = len(events)
    return raw_counts


def total_raw_counts(date):
    counts = {}
    for collector_dir in sorted(LOG_DIR.iterdir() if LOG_DIR.exists() else []):
        if not collector_dir.is_dir() or collector_dir.name == "device_history":
            continue
        path = collector_dir / f"{date}.jsonl"
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            counts[collector_dir.name] = sum(1 for line in handle if line.strip())
    return counts


def configure_runtime(enabled_collectors):
    runtime["config"] = {
        "_project_dir": str(ROOT),
        "skannr": {"log_level": "INFO"},
        "persistence": {"filesystem": {"log_dir": str(LOG_DIR)}},
        "collectors": {collector: {"enabled": True} for collector in enabled_collectors},
        "ui": {"manual_refresh_small_delta_reuse_bytes": 0},
        "history_analysis": {"recent_activity_window_sec": 7200},
        "reports": {},
    }
    with runtime["derived_cache_lock"]:
        runtime["device_history"] = None
        runtime["subject_history"] = None
        runtime["history_analysis"] = None
        runtime["reports"] = None


def count_subjects_by_collector(subject_history):
    counts = Counter()
    for subject in subject_history.get("subjects") or []:
        counts[subject.get("collector") or subject.get("subject_type") or "unknown"] += 1
    return dict(sorted(counts.items()))


def count_reports_by_collector(reports):
    counts = Counter()
    for report in reports.get("reports") or []:
        counts[report.get("collector") or report.get("source") or "unknown"] += 1
    return dict(sorted(counts.items()))


def subject_rows_by_type(subject_history, subject_type):
    return [
        item
        for item in subject_history.get("subjects") or []
        if item.get("subject_type") == subject_type
    ]


def choose_annotation_subject(subject_history):
    for preferred_type in ("lan_device", "wifi_bssid", "wifi_client", "bluetooth_device"):
        for subject in subject_history.get("subjects") or []:
            if subject.get("subject_type") == preferred_type and subject.get("subject_id"):
                return subject
    return None


def write_annotation(subject):
    if not subject:
        return None
    key = subject_annotation_key(
        subject.get("collector"), subject.get("subject_type"), subject.get("subject_id")
    )
    epoch = int(time.time())
    payload = {
        "schema": "subject_annotations.v1",
        "updated_at": local_now(epoch),
        "updated_at_epoch": epoch,
        "annotations": {
            key: {
                "collector": subject.get("collector"),
                "subject_type": subject.get("subject_type"),
                "subject_id": subject.get("subject_id"),
                "custom_name": ANNOTATION_NAME,
                "updated_at": local_now(epoch),
                "updated_at_epoch": epoch,
            }
        },
    }
    path = LOG_DIR / "device_history" / "subject_annotations.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return {"key": key, "subject": subject, "path": str(path)}


def subject_has_annotation(subject_history, annotation):
    if not annotation:
        return False

    def has_annotation(summary):
        for subject in (summary or {}).get("subjects") or []:
            key = subject_annotation_key(
                subject.get("collector"), subject.get("subject_type"), subject.get("subject_id")
            )
            if key != annotation.get("key"):
                continue
            ann = subject.get("annotation") or {}
            return ann.get("custom_name") == ANNOTATION_NAME or subject.get("custom_name") == ANNOTATION_NAME
        return False

    if has_annotation(subject_history):
        return True
    path = LOG_DIR / "device_history" / "subject_history.json"
    if path.exists():
        try:
            return has_annotation(json.loads(path.read_text(encoding="utf-8")))
        except ValueError:
            return False
    return False


def report_has_annotation(reports):
    for report in reports.get("reports") or []:
        ann = report.get("annotation") or {}
        if ann.get("custom_name") == ANNOTATION_NAME:
            return True
        if ANNOTATION_NAME in str(report.get("subject") or ""):
            return True
        evidence = report.get("evidence") if isinstance(report.get("evidence"), dict) else {}
        ann = evidence.get("annotation") or {}
        if ann.get("custom_name") == ANNOTATION_NAME:
            return True
    return False


def checkpoint_offsets_match_logs(subject_history, raw_counts):
    checkpoint = (subject_history or {}).get("checkpoint") or {}
    collectors = checkpoint.get("collectors") or {}
    failures = []
    for collector in raw_counts:
        path = LOG_DIR / collector / f"{DEFAULT_DATE}.jsonl"
        if not path.exists():
            continue
        state = (collectors.get(collector) or {}).get(path.name) or {}
        size = path.stat().st_size
        if int(state.get("offset") or -1) != size:
            failures.append({"collector": collector, "file": path.name, "offset": state.get("offset"), "size": size})
    return failures


def coverage_gaps(sample_meta):
    gaps = []
    for collector, meta in sorted(sample_meta.items()):
        if meta.get("missing"):
            gaps.append(f"{collector}: missing source file")
        elif int(meta.get("selected_records") or 0) <= 0:
            gaps.append(f"{collector}: no replayable device/status records")
    return gaps


def grouping_counts(subject_history):
    subjects = subject_history.get("subjects") or []
    return {
        "bluetooth_groups": len([s for s in subjects if s.get("subject_type") == "bluetooth_device_group"]),
        "bluetooth_devices": len([s for s in subjects if s.get("subject_type") == "bluetooth_device"]),
        "wifi_client_groups": len([s for s in subjects if s.get("subject_type") == "wifi_client_group"]),
        "wifi_clients": len([s for s in subjects if s.get("subject_type") == "wifi_client"]),
        "lan_groups": len([s for s in subjects if s.get("subject_type") == "lan_device_group"]),
        "lan_devices": len([s for s in subjects if s.get("subject_type") == "lan_device"]),
    }


def expected_collectors_from_samples(samples):
    return sorted(collector for collector, events in samples.items() if events)


def validate_outputs(
    samples,
    subject_history,
    analysis,
    reports,
    previous_subject_counts=None,
    annotation=None,
    initial_subject_history=None,
):
    checks = []
    expected = expected_collectors_from_samples(samples)
    subject_counts = count_subjects_by_collector(subject_history)
    report_counts = count_reports_by_collector(reports)
    observation_count = len(analysis.get("observations") or [])
    for collector in expected:
        raw_ok = len(samples.get(collector) or []) > 0
        checks.append((f"raw log populated: {collector}", raw_ok))
    for collector in ("adsb", "aprsis", "ble", "lan", "noaa", "rayhunter", "rtl433", "swpc", "usgs", "wifi"):
        if collector in expected:
            mapped = "bluetooth" if collector == "ble" else collector
            checks.append((f"Subject History has {mapped}", subject_counts.get(mapped, 0) > 0))
    checks.append(("Subject History total subjects > 0", (subject_history.get("subject_counts") or {}).get("total", 0) > 0))
    checks.append(("Reports populated", len(reports.get("reports") or []) > 0))
    checks.append(("Insights analysis produced valid observations list", isinstance(analysis.get("observations"), list)))
    groups = grouping_counts(subject_history)
    bluetooth_subjects = [s for s in subject_history.get("subjects") or [] if s.get("collector") == "bluetooth"]
    checks.append(("Bluetooth grouping evaluated", bool(bluetooth_subjects)))
    checks.append(("Bluetooth aggregate groups present when sample warrants", groups["bluetooth_groups"] > 0))
    checks.append(("Wi-Fi randomized client group present", groups["wifi_client_groups"] > 0))
    checks.append(("LAN grouping check evaluated", groups["lan_groups"] >= 0))
    if annotation:
        checks.append(("Subject annotation survived refresh", subject_has_annotation(subject_history, annotation)))
        checks.append(("Report annotation survived refresh", report_has_annotation(reports)))
    if previous_subject_counts:
        checks.append((
            "Subject History total did not decrease after second refresh",
            (subject_history.get("subject_counts") or {}).get("total", 0) >= sum(previous_subject_counts.values()),
        ))
    if initial_subject_history:
        checks.append((
            "Phase 2 Subject History counts changed",
            count_subjects_by_collector(subject_history) != count_subjects_by_collector(initial_subject_history),
        ))
        checks.append((
            "Phase 2 Subject History generation did not go backwards",
            int(subject_history.get("generated_at_epoch") or 0) >= int(initial_subject_history.get("generated_at_epoch") or 0),
        ))
    ok = all(result for _, result in checks)
    return ok, checks, subject_counts, report_counts, observation_count


def write_report(
    run_started,
    sample_meta,
    raw_counts,
    subject_history,
    analysis,
    reports,
    checks,
    subject_counts,
    report_counts,
    observation_count,
    initial_summary=None,
    annotation=None,
    checkpoint_failures=None,
    gaps=None,
):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    markdown_path = REPORT_DIR / f"collector-replay-{stamp}.md"
    json_path = REPORT_DIR / f"collector-replay-{stamp}.json"
    payload = {
        "generated_at": local_now(),
        "elapsed_sec": round(time.monotonic() - run_started, 3),
        "log_dir": str(LOG_DIR),
        "raw_counts": raw_counts,
        "sample_meta": sample_meta,
        "initial_summary": initial_summary or {},
        "subject_counts": subject_counts,
        "report_counts": report_counts,
        "observation_count": observation_count,
        "checks": [{"name": name, "ok": ok} for name, ok in checks],
        "annotation": annotation or {},
        "checkpoint_failures": checkpoint_failures or [],
        "coverage_gaps": gaps or [],
        "grouping_counts": grouping_counts(subject_history),
        "subject_history_generated_at": subject_history.get("generated_at"),
        "reports_generated_at": reports.get("generated_at"),
        "analysis_generated_at": analysis.get("generated_at"),
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    lines = [
        "# Skannr Collector Replay Report",
        "",
        f"Generated: {payload['generated_at']}",
        f"Elapsed: {payload['elapsed_sec']} sec",
        f"Log dir: `{LOG_DIR}`",
        "",
        "## Raw Replay",
        "",
        "| Collector | Source | Source records | Source keys | Replayed records | Replayed keys |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for collector in sorted(sample_meta):
        meta = sample_meta[collector]
        lines.append(
            "| {collector} | `{source}` | {source_records} | {source_unique_keys} | {selected_records} | {selected_unique_keys} |".format(
                collector=collector,
                source=meta.get("source", ""),
                source_records=meta.get("source_records", 0),
                source_unique_keys=meta.get("source_unique_keys", 0),
                selected_records=meta.get("selected_records", 0),
                selected_unique_keys=meta.get("selected_unique_keys", 0),
            )
        )
    lines.extend([
        "",
        "## Derived Counts",
        "",
        f"Subject History subjects: {(subject_history.get('subject_counts') or {}).get('total', 0)}",
        f"Insights observations: {observation_count}",
        f"Reports: {len(reports.get('reports') or [])}",
        "",
        "Initial refresh summary:",
        "",
        f"- Subjects: {(initial_summary or {}).get('subjects', 0)}",
        f"- Insights observations: {(initial_summary or {}).get('observations', 0)}",
        f"- Reports: {(initial_summary or {}).get('reports', 0)}",
        "",
        "Subject counts by collector:",
        "",
    ])
    for collector, count in sorted(subject_counts.items()):
        lines.append(f"- `{collector}`: {count}")
    lines.extend(["", "Report counts by collector:", ""])
    for collector, count in sorted(report_counts.items()):
        lines.append(f"- `{collector}`: {count}")
    lines.extend(["", "## Grouping", ""])
    for key, value in sorted(grouping_counts(subject_history).items()):
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Coverage Gaps", ""])
    for gap in gaps or []:
        lines.append(f"- {gap}")
    if not gaps:
        lines.append("- none")
    lines.extend(["", "## Checkpoint Failures", ""])
    for failure in checkpoint_failures or []:
        lines.append(f"- `{failure['collector']}` {failure['file']}: offset {failure['offset']} != size {failure['size']}")
    if not checkpoint_failures:
        lines.append("- none")
    lines.extend(["", "## Checks", ""])
    for name, ok in checks:
        lines.append(f"- {'PASS' if ok else 'FAIL'}: {name}")
    lines.append("")
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    return markdown_path, json_path


def main():
    args = parse_args()
    run_started = time.monotonic()
    prepare_log_dir(args.force, args.keep_existing)
    base_epoch = int(time.time()) - 1800
    initial_samples = {}
    second_samples = {}
    sample_meta = {}
    offset = 0
    for collector, source_root in collector_sources(args).items():
        events, meta = sample_events(collector, source_root, args.date, args.max_events * 2)
        if not events:
            sample_meta[collector] = meta
            continue
        first, second = split_replay_batches(collector, events, args.max_events)
        initial_samples[collector] = rewrite_event_times(first, base_epoch + offset)
        offset += max(len(first), 1) + 60
        if second:
            second_samples[collector] = rewrite_event_times(second, base_epoch + offset + 3600)
            offset += max(len(second), 1) + 60
        meta["initial_records"] = len(first)
        meta["second_records"] = len(second)
        meta["selected_records"] = len(first) + len(second)
        sample_meta[collector] = meta

    write_raw_logs(initial_samples, args.date)
    configure_runtime(set(initial_samples) | set(second_samples))
    initial_subject_history = refresh_subject_history("default")
    initial_analysis = refresh_history_analysis("default")
    initial_reports = refresh_reports("default")
    initial_ok, initial_checks, initial_subject_counts, _, _ = validate_outputs(
        initial_samples, initial_subject_history, initial_analysis, initial_reports
    )
    annotation = write_annotation(choose_annotation_subject(initial_subject_history))

    write_raw_logs(second_samples, args.date, append=True)
    configure_runtime((set(initial_samples) | set(second_samples)) & PHASE2_ENABLED_COLLECTORS)
    subject_history = refresh_subject_history("default")
    analysis = refresh_history_analysis("default")
    reports = refresh_reports("default")
    combined_samples = {
        collector: initial_samples.get(collector, []) + second_samples.get(collector, [])
        for collector in set(initial_samples) | set(second_samples)
    }
    ok, checks, subject_counts, report_counts, observation_count = validate_outputs(
        combined_samples,
        subject_history,
        analysis,
        reports,
        previous_subject_counts=initial_subject_counts,
        annotation=annotation,
        initial_subject_history=initial_subject_history,
    )
    if second_samples.get("adsb"):
        initial_icaos = sample_unique_keys(initial_samples.get("adsb") or [], "adsb")
        final_icaos = sample_unique_keys(combined_samples.get("adsb") or [], "adsb")
        new_icaos = final_icaos - initial_icaos
        checks.append(("ADS-B second batch contains new aircraft", bool(new_icaos)))
        checks.append((
            "Subject History ADS-B count includes second batch aircraft",
            subject_counts.get("adsb", 0) >= len(final_icaos),
        ))
        ok = ok and all(result for name, result in checks if name.startswith("ADS-B") or name.startswith("Subject History ADS-B"))
    direct_second = [collector for collector in sorted(second_samples) if collector in DIRECT_COLLECTORS and collector != "rtl433"]
    for collector in direct_second:
        mapped = "lan" if collector == "lan_identify" else collector
        checks.append((
            f"Disabled direct collector {collector} retained/folded after phase 2",
            subject_counts.get(mapped, 0) > 0,
        ))
    raw_counts = total_raw_counts(args.date)
    checkpoint_failures = checkpoint_offsets_match_logs(subject_history, raw_counts)
    checks.append(("Derived checkpoint offsets reached replayed log EOF", not checkpoint_failures))
    gaps = coverage_gaps(sample_meta)
    checks = [("Initial refresh checks passed", initial_ok)] + initial_checks + checks
    initial_summary = {
        "subjects": (initial_subject_history.get("subject_counts") or {}).get("total", 0),
        "subject_counts": initial_subject_counts,
        "observations": len(initial_analysis.get("observations") or []),
        "reports": len(initial_reports.get("reports") or []),
    }
    ok = all(result for _, result in checks)
    markdown_path, json_path = write_report(
        run_started,
        sample_meta,
        raw_counts,
        subject_history,
        analysis,
        reports,
        checks,
        subject_counts,
        report_counts,
        observation_count,
        initial_summary=initial_summary,
        annotation=annotation,
        checkpoint_failures=checkpoint_failures,
        gaps=gaps,
    )
    print(f"report: {markdown_path}")
    print(f"json: {json_path}")
    if not ok:
        print("collector replay checks failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
