#!/usr/bin/env python3
"""Offline Skannr admin helpers.

This script is dry-run by default. Use ``--apply`` to make changes.
Current command set:
  - purge-collector: remove one collector's retained raw logs, scrub related
    findings/alert JSONL rows when the source is attributable, remove derived
    materialized summaries, and rebuild derived state from the remaining logs.
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from skannr.config import load_config
from skannr.wifi_ble_postprocessor import WiFiBLEPostprocessor
from skannr.history_analysis import HistoryAnalyzer, save_analysis
from skannr.log_utils import sanitize_json_line, save_json_atomic
from skannr.paths import CONFIG_PATH, RUNTIME_LOG_DIR
from skannr.reports import ReportsBuilder, save_reports
from skannr.subject_history import SubjectHistoryBuilder

COLLECTOR_ALIASES = {
    "rtl_433": "rtl433",
    "rtl433": "rtl433",
    "bluetooth": "ble",
    "ble": "ble",
    "ble_scan": "ble",
    "ble_identify": "ble_identify",
    "bt_classic": "bt_classic",
}

MIXED_SOURCE_ALIASES = {
    "ble": {"bluetooth", "ble"},
    "ble_identify": {"bluetooth", "ble_identify", "ble"},
    "bt_classic": {"bluetooth", "bt_classic"},
    "rtl433": {"rtl433", "rtl_433"},
}

DERIVED_STATE_GLOBS = (
    "device_history/device_history.json",
    "device_history/subject_history.json",
    "device_history/history_analysis.json",
    "device_history/reports.json",
    "device_history/findings_history.json",
    "device_history/subject_history_direct_state.json",
    "device_history/subject_history_direct_*.json",
)


def canonical_collector(name):
    value = str(name or "").strip().lower()
    return COLLECTOR_ALIASES.get(value, value)


def configured_log_dir(config):
    filesystem = ((config or {}).get("persistence") or {}).get("filesystem") or {}
    log_dir = filesystem.get("log_dir") or str(RUNTIME_LOG_DIR)
    return Path(log_dir).resolve()


def enabled_subject_history_collectors(config):
    collector_config = (config.get("collectors") or {}) if isinstance(config, dict) else {}
    enabled = set()
    for collector in SubjectHistoryBuilder.COLLECTORS:
        section = collector_config.get(collector)
        if section is not None and bool(section.get("enabled", True)):
            enabled.add(collector)
    return enabled


def event_matches_collector(event, collector):
    if not isinstance(event, dict):
        return False
    aliases = {collector} | set(MIXED_SOURCE_ALIASES.get(collector, set()))
    data = event.get("data") or {}
    candidates = {
        str(event.get("collector") or "").strip().lower(),
        str(event.get("source") or "").strip().lower(),
        str(event.get("type") or "").strip().lower(),
        str(data.get("collector") or "").strip().lower(),
        str(data.get("source") or "").strip().lower(),
    }
    if candidates & aliases:
        return True
    event_type = str(event.get("type") or "").strip().lower()
    if collector == "ble" and (event_type.startswith("ble_") or "bluetooth" in candidates):
        return True
    if collector == "rtl433" and event_type.startswith("rtl433"):
        return True
    return False


def rewrite_jsonl_without_collector(path, collector, apply):
    total = 0
    removed = 0
    kept_lines = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                total += 1
                try:
                    event = json.loads(sanitize_json_line(line))
                except ValueError:
                    kept_lines.append(line)
                    continue
                if event_matches_collector(event, collector):
                    removed += 1
                    continue
                kept_lines.append(line)
    except OSError:
        return {"path": str(path), "total": 0, "removed": 0, "changed": False}
    changed = removed > 0
    if apply and changed:
        directory = path.parent
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=directory,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as fh:
            temp_path = Path(fh.name)
            for line in kept_lines:
                fh.write(line)
        os.replace(temp_path, path)
    return {"path": str(path), "total": total, "removed": removed, "changed": changed}


def collect_derived_state_paths(log_dir):
    paths = []
    for pattern in DERIVED_STATE_GLOBS:
        paths.extend(sorted(log_dir.glob(pattern)))
    unique = []
    seen = set()
    for path in paths:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def remove_path(path, apply):
    exists = path.exists()
    if apply and exists:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    return {"path": str(path), "exists": exists}


def device_history_from_subject_history(subject_history):
    if not isinstance(subject_history, dict) or subject_history.get("empty"):
        return {
            "wifi": {"access_points": [], "clients": []},
            "ble": {"devices": []},
            "bluetooth": {"devices": []},
            "generated_at": "",
            "generated_at_epoch": 0,
        }
    output = {
        key: value
        for key, value in subject_history.items()
        if key not in (
            "schema",
            "aprsis",
            "rayhunter",
            "rtl433",
            "noaa",
            "usgs",
            "swpc",
            "lan",
            "subjects",
            "subject_counts",
        )
    }
    output["wifi"] = subject_history.get("wifi") or {"access_points": [], "clients": []}
    output["ble"] = subject_history.get("ble") or {"devices": []}
    output["bluetooth"] = subject_history.get("bluetooth") or output["ble"]
    return output


def reports_history_from_subject_history(subject_history):
    history = dict(subject_history or {})
    history["subject_history"] = subject_history
    history["device_history"] = device_history_from_subject_history(subject_history)
    return history


def status(message, enabled=True):
    if enabled:
        print(f"[skannr-admin] {message}")


def rebuild_derived(config, log_dir, progress=False):
    device_path = log_dir / "device_history" / "device_history.json"
    subject_path = log_dir / "device_history" / "subject_history.json"
    analysis_path = log_dir / "device_history" / "history_analysis.json"
    reports_path = log_dir / "device_history" / "reports.json"

    status(f"rebuilding device history from {log_dir}", progress)
    device_summary = WiFiBLEPostprocessor(str(log_dir), state_path=str(device_path)).build(
        persist=True,
        merge_previous=False,
    )
    status(f"wrote device history to {device_path}", progress)
    status("rebuilding subject history", progress)
    subject_builder = SubjectHistoryBuilder(
        str(log_dir),
        state_path=str(subject_path),
        device_history_state_path=str(device_path),
        enabled_collectors=enabled_subject_history_collectors(config),
    )
    subject_summary = subject_builder.build(device_history_summary=device_summary, persist=True)
    status(f"wrote subject history to {subject_path}", progress)

    status("rebuilding history analysis", progress)
    analyzer = HistoryAnalyzer((config or {}).get("history_analysis", {}))
    analysis = analyzer.analyze(device_history_from_subject_history(subject_summary))
    analysis["state_path"] = str(analysis_path)
    save_analysis(str(analysis_path), analysis)
    status(f"wrote history analysis to {analysis_path}", progress)

    status("rebuilding reports", progress)
    reports = ReportsBuilder((config or {}).get("reports", {})).build(
        reports_history_from_subject_history(subject_summary)
    )
    reports["state_path"] = str(reports_path)
    save_reports(str(reports_path), reports)
    status(f"wrote reports to {reports_path}", progress)
    return {
        "device_history": str(device_path),
        "subject_history": str(subject_path),
        "history_analysis": str(analysis_path),
        "reports": str(reports_path),
    }


def purge_collector(args):
    config = load_config(str(Path(args.config).resolve()))
    log_dir = configured_log_dir(config)
    collector = canonical_collector(args.collector)
    raw_dir = log_dir / collector
    findings_dir = log_dir / "findings"
    alerts_dir = log_dir / "alerts"

    progress = bool(args.apply)
    status(f"starting purge for collector {collector}", progress)
    status(f"checking raw collector directory {raw_dir}", progress)
    raw_action = remove_path(raw_dir, args.apply)
    if progress:
        status(
            f"{'removed' if raw_action['exists'] else 'skipped missing'} raw collector directory {raw_action['path']}",
            progress,
        )
    mixed_results = []
    for directory in (findings_dir, alerts_dir):
        if not directory.is_dir():
            status(f"skipping missing mixed log directory {directory}", progress)
            continue
        status(f"scanning mixed log directory {directory}", progress)
        for path in sorted(directory.glob("*.jsonl")):
            result = rewrite_jsonl_without_collector(path, collector, args.apply)
            if result["changed"]:
                mixed_results.append(result)
                status(
                    f"{'rewrote' if args.apply else 'would rewrite'} {result['path']} removing {result['removed']} of {result['total']} line(s)",
                    progress,
                )
    derived_paths = collect_derived_state_paths(log_dir)
    status(f"resetting {len(derived_paths)} derived state file(s)", progress)
    derived_actions = []
    for path in derived_paths:
        result = remove_path(path, args.apply)
        derived_actions.append(result)
        if progress:
            status(
                f"{'removed' if result['exists'] else 'skipped missing'} derived state {result['path']}",
                progress,
            )

    rebuilt = None
    if args.apply and not args.no_rebuild:
        rebuilt = rebuild_derived(config, log_dir, progress=True)
    elif args.apply and args.no_rebuild:
        status("derived rebuild skipped (--no-rebuild)", progress)

    print(f"Collector: {collector}")
    print(f"Log dir: {log_dir}")
    print(f"Mode: {'apply' if args.apply else 'dry-run'}")
    print()
    print("Raw collector log directory:")
    print(f"  {raw_action['path']} ({'present' if raw_action['exists'] else 'missing'})")
    print()
    print("Mixed JSONL scrubs:")
    if mixed_results:
        for item in mixed_results:
            print(f"  {item['path']}: remove {item['removed']} of {item['total']} line(s)")
    else:
        print("  no attributable findings/alerts rows matched")
    print()
    print("Derived state reset:")
    for item in derived_actions:
        print(f"  {item['path']} ({'present' if item['exists'] else 'missing'})")
    if rebuilt:
        print()
        print("Rebuilt:")
        for key, value in rebuilt.items():
            print(f"  {key}: {value}")
    elif args.apply and args.no_rebuild:
        print()
        print("Derived rebuild skipped (--no-rebuild).")
    elif not args.apply:
        print()
        print("No changes applied. Re-run with --apply to execute.")


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(CONFIG_PATH), help="Path to skannr.yaml")
    subparsers = parser.add_subparsers(dest="command")

    purge = subparsers.add_parser(
        "purge-collector",
        help="remove one collector's retained raw logs and rebuild derived state",
    )
    purge.add_argument("collector", help="collector key such as ble, rtl433, rtl_433, wifi, noaa")
    purge.add_argument("--apply", action="store_true", help="make changes; default is dry-run")
    purge.add_argument("--no-rebuild", action="store_true", help="remove/scrub files without rebuilding derived state")
    purge.set_defaults(func=purge_collector)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not getattr(args, "command", None):
        parser.print_help()
        raise SystemExit(2)
    args.func(args)


if __name__ == "__main__":
    main()
