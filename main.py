"""Skannr web runtime, collector lifecycle, and derived-data routes.

The collectors publish events into an asyncio bus. This file owns the Flask UI,
browser fan-out, persistence writes, live findings, and the on-demand refresh
flow for materialized history/analysis/report summaries.
"""

import argparse
import asyncio
import concurrent.futures
import json
import logging
import os
import queue
import signal
import threading
import time
from collections import deque

from flask import Flask, Response, make_response, request, send_from_directory
from flask_socketio import SocketIO

from bus import EventBus, utc_now
from collectors import load_collectors
from collectors.metadata import (
    browser_source_groups,
    browser_subtabs,
    collector_definitions,
    collector_keys,
)
from config import load_config
from device_history import DeviceHistoryBuilder
from findings import FindingsEngine
from history_analysis import HistoryAnalyzer, save_analysis
from log_utils import (
    count_jsonl_files,
    current_jsonl_checkpoint,
    event_in_window,
    has_jsonl_checkpoint,
    read_incremental_jsonl_events,
    read_jsonl_events,
    resolve_window_days as resolve_log_window_days,
    utc_epoch,
    view_window_options,
    window_metadata,
)
from persistence import load_persistence
from reports import ReportsBuilder, save_reports


def read_app_version():
    """Read the release version from the project VERSION file."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip() or "0.0.0"
    except OSError:
        return "0.0.0"


APP_VERSION = read_app_version()


# Flask serves the static dashboard. The browser uses a local Server-Sent Events
# stream for live updates; Socket.IO remains available for compatibility with
# older clients. Collectors run on an asyncio loop in a background thread so the
# Flask request thread is not blocked by scans.
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Shared process state. This is intentionally small and explicit because the UI
# needs snapshots of current collector state whenever a browser connects or an
# event arrives.
runtime = {
    "bus": None,
    "collectors": [],
    "tasks": [],
    "loop": None,
    "config": None,
    "persistence": None,
    "findings": FindingsEngine(),
    "tasks_by_key": {},
    "event_log": deque(maxlen=100),
    "sse_clients": [],
    "shutting_down": False,
    "device_history": None,
    "history_analysis": None,
    "findings_history": None,
    "reports": None,
}


@app.after_request
def disable_browser_cache(response):
    """Force browsers to pick up dashboard/static changes after a restart."""
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/")
def index():
    """Serve the single-page dashboard."""
    response = make_response(
        send_from_directory(app.static_folder, "index.html")
    )
    return response


@app.route("/events")
def events():
    """Stream live dashboard events without depending on an external JS client."""
    client = queue.Queue(maxsize=runtime_int("sse_queue_size", 200, minimum=1))
    runtime["sse_clients"].append(client)

    # A new browser needs the same initial snapshots that the old Socket.IO
    # connect handler sent. Queue them before the generator starts yielding.
    enqueue_sse(
        client,
        "collector_status",
        [collector.status() for collector in runtime["collectors"]],
    )
    enqueue_sse(client, "system_status", system_status())
    enqueue_sse(client, "findings_snapshot", runtime["findings"].snapshot())
    enqueue_sse(
        client,
        "skannr_event",
        {
            "collector": "system",
            "timestamp": utc_now(),
            "type": "browser_connected",
            "severity": "info",
            "data": {"message": "Browser connection established"},
        },
    )

    def stream():
        # The generator owns removal from runtime["sse_clients"] so browsers can
        # disconnect/reconnect without leaking queue objects.
        try:
            yield ": connected\n\n"
            while True:
                name, payload = client.get()
                yield format_sse(name, payload)
        finally:
            try:
                runtime["sse_clients"].remove(client)
            except ValueError:
                pass

    return Response(
        stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/collector_control", methods=["POST"])
def collector_control():
    """Receive Start/Stop clicks from the local browser UI."""
    on_collector_control(request.get_json(silent=True) or {})
    return {"ok": True}


@app.route("/ble_identify", methods=["POST"])
def ble_identify():
    """Queue one active BLE Device Information Service read."""
    payload = request.get_json(silent=True) or {}
    mac = payload.get("mac")
    timeout = payload.get("timeout_sec")
    loop = runtime.get("loop")
    collector = collector_by_key("ble_identify")
    if not loop or not collector:
        return {
            "ok": False,
            "error": "BLE Identify collector is not available",
        }, 503
    if not mac:
        return {"ok": False, "error": "Missing BLE MAC address"}, 400
    asyncio.run_coroutine_threadsafe(collector.identify(mac, timeout), loop)
    return {"ok": True}


@app.route("/collector_metadata", methods=["GET"])
def collector_metadata():
    """Return collector names/order shared by dashboard super-tabs."""
    config = runtime.get("config") or {}
    # Browser tabs and source filters are generated from the same collector
    # metadata so adding/removing a collector does not require editing JS lists.
    return {
        "collectors": collector_definitions(config, include_system=True),
        "subtabs": browser_subtabs(config),
        "source_groups": browser_source_groups(config),
    }


@app.route("/view_metadata", methods=["GET"])
def view_metadata():
    """Return dashboard defaults after applying skannr.yaml and retention."""
    config = runtime.get("config") or {}
    return {
        "version": APP_VERSION,
        "active": "default",
        "options": view_window_options(config),
        "ui": config.get("ui", {}),
        "collectors": {
            "rtlsdr": {
                "scan_start_mhz": config.get("collectors", {})
                .get("rtlsdr", {})
                .get("scan_start_mhz"),
                "scan_end_mhz": config.get("collectors", {})
                .get("rtlsdr", {})
                .get("scan_end_mhz"),
                "step_khz": config.get("collectors", {})
                .get("rtlsdr", {})
                .get("step_khz"),
                "gain": config.get("collectors", {})
                .get("rtlsdr", {})
                .get("gain"),
                "threshold_db": config.get("collectors", {})
                .get("rtlsdr", {})
                .get("threshold_db"),
            },
        },
    }


@app.route("/device_history", methods=["GET"])
def device_history():
    """Return the last on-demand device-history summary."""
    window_days = requested_window_days()
    return cached_derived_view(
        "device_history", load_cached_device_history, window_days
    )


@app.route("/derived_views", methods=["GET"])
def derived_views():
    """Return a consistent Findings/History/Observations bundle."""
    return build_derived_views(requested_window_days(), force=False)


@app.route("/derived_views/refresh", methods=["POST"])
def derived_views_refresh():
    """Refresh all derived tabs in dependency order for the current view."""
    return build_derived_views(requested_window_days(), force=True)


@app.route("/device_history/refresh", methods=["POST"])
def device_history_refresh():
    """Compatibility route: refresh the full derived-data bundle."""
    return build_derived_views(requested_window_days(), force=True)[
        "device_history"
    ]


@app.route("/findings_history", methods=["GET"])
def findings_history():
    """Return persisted findings for the selected view window."""
    window_days = requested_window_days()
    return cached_derived_view(
        "findings_history", load_cached_findings_history, window_days
    )


@app.route("/findings_history/refresh", methods=["POST"])
def findings_history_refresh():
    """Compatibility route: refresh the full derived-data bundle."""
    return build_derived_views(requested_window_days(), force=True)["findings"]


@app.route("/history_analysis", methods=["GET"])
def history_analysis():
    """Return the last on-demand history-analysis snapshot."""
    window_days = requested_window_days()
    return cached_derived_view(
        "history_analysis", load_cached_history_analysis, window_days
    )


@app.route("/history_analysis/refresh", methods=["POST"])
def history_analysis_refresh():
    """Compatibility route: refresh the full derived-data bundle."""
    return build_derived_views(requested_window_days(), force=True)[
        "history_analysis"
    ]


@app.route("/reports", methods=["GET"])
def reports():
    """Return the last generated report summary."""
    window_days = requested_window_days()
    return cached_derived_view("reports", load_cached_reports, window_days)


@app.route("/reports/refresh", methods=["POST"])
def reports_refresh():
    """Compatibility route: refresh the full derived-data bundle."""
    return build_derived_views(requested_window_days(), force=True)["reports"]


@socketio.on("connect")
def on_connect():
    """Send the current state immediately to a newly connected browser."""
    socketio.emit(
        "collector_status",
        [collector.status() for collector in runtime["collectors"]],
    )
    socketio.emit("system_status", system_status())
    socketio.emit("findings_snapshot", runtime["findings"].snapshot())
    socketio.emit(
        "skannr_event",
        {
            "collector": "system",
            "timestamp": utc_now(),
            "type": "browser_connected",
            "severity": "info",
            "data": {"message": "Browser connection established"},
        },
    )


@socketio.on("collector_control")
def on_collector_control(message):
    """Translate browser Start/Stop clicks into work on the asyncio loop."""
    key = (message or {}).get("key")
    action = (message or {}).get("action")
    loop = runtime.get("loop")
    if not key or action not in ("start", "stop") or not loop:
        return
    if action == "stop":
        asyncio.run_coroutine_threadsafe(stop_collector(key), loop)
    else:
        asyncio.run_coroutine_threadsafe(start_collector(key), loop)


def collector_by_key(key):
    """Return the active collector object for a config key."""
    for collector in runtime.get("collectors") or []:
        if collector.config_key == key:
            return collector
    return None


def format_sse(name, payload):
    """Format one named Server-Sent Event record."""
    return "event: {}\ndata: {}\n\n".format(
        name, json.dumps(payload, sort_keys=True)
    )


def enqueue_sse(client, name, payload):
    """Best-effort enqueue for one browser; drop oldest data if it falls behind."""
    try:
        client.put_nowait((name, payload))
    except queue.Full:
        try:
            client.get_nowait()
        except queue.Empty:
            pass
        try:
            client.put_nowait((name, payload))
        except queue.Full:
            pass


def broadcast(name, payload):
    """Send one dashboard message over both Socket.IO and local SSE."""
    socketio.emit(name, payload)
    for client in list(runtime["sse_clients"]):
        enqueue_sse(client, name, payload)


async def consume_events(bus):
    """Fan out collector events to persistence and all connected browsers."""
    while True:
        event = await bus.next()
        persistence = runtime.get("persistence")
        # Periodic status/channel-hop events are derived state. Persisting every
        # copy would bury the useful radio/BLE/Wi-Fi observations.
        high_rate_state_event = (
            event.get("collector") == "system"
            and event.get("type") == "system_status"
        ) or (
            event.get("collector") == "wifi_monitor"
            and event.get("type") == "monitor_channel_changed"
        )
        if persistence and not high_rate_state_event:
            try:
                persistence.write(event)
            except Exception as exc:
                logging.exception("failed to persist event: %s", exc)
        runtime["event_log"].appendleft(event)
        broadcast("skannr_event", event)
        # Findings are generated synchronously from each event so the browser and
        # JSONL logs see the finding immediately after the source event.
        for finding in runtime["findings"].process(event):
            finding_event = {
                "collector": "findings",
                "type": "finding",
                "severity": finding["severity"],
                "timestamp": finding["timestamp"],
                "data": finding,
            }
            if persistence:
                try:
                    persistence.write(finding_event)
                except Exception as exc:
                    logging.exception("failed to persist finding: %s", exc)
            broadcast("skannr_event", finding_event)
        broadcast(
            "collector_status",
            [collector.status() for collector in runtime["collectors"]],
        )
        broadcast("system_status", system_status())


async def start_collectors(config, bus):
    """Create enabled collectors and launch each auto-start collector."""
    loop = asyncio.get_event_loop()
    collectors = load_collectors(config, bus)
    runtime["collectors"] = collectors
    for collector in collectors:
        auto_start = bool(collector.config.get("auto_start", True))
        if not auto_start:
            # On-demand collectors should still appear in System Status. Run
            # their lightweight detection once, but do not start capture until
            # the user clicks Start.
            try:
                collector.detect()
                if str(collector.state).startswith("RUNNING"):
                    collector.state = "STOPPED"
            except Exception as exc:
                collector.state = "OFFLINE"
                collector.warning = "Detection failed: {}".format(exc)
        # Emit a load event before start() so the browser can show a row even if
        # the collector immediately finds missing hardware or packages.
        await bus.publish(
            {
                "collector": "system",
                "type": "collector_loaded",
                "severity": "info",
                "data": collector.status(),
            }
        )
        if not auto_start:
            continue
        # Python 3.6 lacks asyncio.create_task(), so use the loop method for Pi
        # installations that still run older system Python.
        task = loop.create_task(collector.start())
        runtime["tasks"].append(task)
        runtime["tasks_by_key"][collector.config_key] = task
    # One task consumes the bus and pushes to browsers; another sends periodic
    # system snapshots so static probe status stays fresh.
    runtime["tasks"].append(loop.create_task(consume_events(bus)))
    runtime["tasks"].append(loop.create_task(publish_system_status(bus)))
    await bus.publish(
        {
            "collector": "system",
            "type": "app_started",
            "severity": "info",
            "data": {
                "message": "Skannr event bus is online",
                "timestamp": utc_now(),
            },
        }
    )


async def start_collector(key):
    """Restart one collector after the user clicks Start in the dashboard."""
    loop = asyncio.get_event_loop()
    for collector in runtime["collectors"]:
        if collector.config_key != key:
            continue
        task = runtime["tasks_by_key"].get(key)
        # Avoid starting duplicate scanner loops for the same adapter/interface.
        if task and not task.done():
            await runtime["bus"].publish(
                {
                    "collector": "system",
                    "type": "collector_already_running",
                    "data": collector.status(),
                }
            )
            return
        task = loop.create_task(collector.start())
        runtime["tasks"].append(task)
        runtime["tasks_by_key"][key] = task
        await runtime["bus"].publish(
            {
                "collector": "system",
                "type": "collector_started",
                "data": collector.status(),
            }
        )
        return


async def stop_collector(key):
    """Stop one collector and cancel its task if it is still active."""
    for collector in runtime["collectors"]:
        if collector.config_key != key:
            continue
        await collector.stop()
        task = runtime["tasks_by_key"].get(key)
        if task and not task.done():
            task.cancel()
        await runtime["bus"].publish(
            {
                "collector": "system",
                "type": "collector_stopped",
                "data": collector.status(),
            }
        )
        return


async def publish_system_status(bus):
    """Publish static hardware/software probe results every few seconds."""
    interval = runtime_number("system_status_interval_sec", 5, minimum=1)
    while True:
        await bus.publish(
            {
                "collector": "system",
                "type": "system_status",
                "data": system_status(),
            }
        )
        await asyncio.sleep(interval)


def system_status():
    """Build the status object consumed by the System Status tab."""
    return {
        "hardware": (runtime.get("config") or {}).get("hardware", {}),
    }


def bootstrap_findings():
    """Replay recent JSONL events into the findings engine on startup."""
    persistence = runtime.get("persistence")
    findings = runtime.get("findings")
    config = runtime.get("config") or {}
    if not persistence or not findings:
        return
    try:
        limit = int(config.get("findings", {}).get("bootstrap_events", 1000))
        if limit <= 0:
            return
        collectors = collector_keys(config, include_system=True)
        events = []
        for collector in collectors:
            # Query only a bounded tail per collector. Durable first_seen state
            # is seeded from Device History below; this replay is for live
            # cooldown/presence continuity, not a full history rebuild.
            events.extend(persistence.query(collector=collector, limit=limit))
        summary = findings.bootstrap(events)
        if summary:
            persistence.write(
                {
                    "collector": "findings",
                    "type": "finding",
                    "severity": summary["severity"],
                    "timestamp": summary["timestamp"],
                    "data": summary,
                }
            )
    except Exception as exc:
        logging.exception("failed to bootstrap findings: %s", exc)


def requested_window_days():
    """Resolve the requested dashboard log window from query/body/config."""
    payload = (
        request.get_json(silent=True) if request.method == "POST" else None
    )
    raw = request.args.get("days")
    if raw is None and payload:
        raw = payload.get("days")
    if raw is None:
        raw = "default"
    return resolve_window_days(raw)


def resolve_window_days(raw="default"):
    """Return a numeric day window, or None when the UI asks for all logs."""
    return resolve_log_window_days(runtime.get("config") or {}, raw)


def summary_matches_window(summary, window_days):
    """Return True when a cached derived view uses the requested log range."""
    window = (summary or {}).get("window") or {}
    current = window.get("days")
    if current is None or window_days is None:
        return current is None and window_days is None
    return float(current) == float(window_days)


def cached_derived_view(key, loader, window_days):
    """Return a runtime cached view only when it matches the selected window."""
    if runtime.get(key) is None or not summary_matches_window(
        runtime.get(key), window_days
    ):
        runtime[key] = loader(window_days)
    return runtime[key]


def view_window_metadata(window_days):
    """Describe the selected log range in the same shape used by history."""
    return window_metadata(window_days)


def configured_log_dir():
    """Return the absolute filesystem persistence directory."""
    config = runtime.get("config") or {}
    persistence = config.get("persistence", {})
    filesystem = persistence.get("filesystem", {})
    log_dir = filesystem.get("log_dir", "./logs")
    if os.path.isabs(log_dir):
        return log_dir
    project_dir = config.get("_project_dir") or os.getcwd()
    return os.path.abspath(os.path.join(project_dir, log_dir))


def read_findings_history(window_days):
    """Read persisted findings JSONL records for the selected view window."""
    log_dir = configured_log_dir()
    findings = []
    files_read = count_jsonl_files(log_dir, "findings")
    records_read = 0
    for event in read_jsonl_events(log_dir, "findings", window_days):
        records_read += 1
        if event.get("type") == "finding" and event.get("data"):
            findings.append(normalize_finding_source(event["data"]))
    findings.sort(
        key=lambda item: utc_epoch(item.get("timestamp")) or 0, reverse=True
    )
    generated_at = utc_now()
    return {
        "generated_at": generated_at,
        "generated_at_epoch": time.time(),
        "window": view_window_metadata(window_days),
        "files_read": files_read,
        "records_read": records_read,
        "findings": findings,
        "counts": {
            "total": len(findings),
            "warning": sum(
                1 for item in findings if item.get("severity") == "warning"
            ),
            "info": sum(
                1 for item in findings if item.get("severity") == "info"
            ),
            "error": sum(
                1
                for item in findings
                if item.get("severity") in ("error", "alert")
            ),
        },
    }


def refresh_findings_history(window_days):
    """Incrementally materialize persisted Finding rows for Insights."""
    previous = read_json_file(findings_history_path())
    if previous and has_jsonl_checkpoint(previous):
        # Fast path: fold only new lines from logs/findings/*.jsonl.
        summary = update_findings_summary(previous)
    elif previous and previous.get("findings"):
        # Trust an older materialized file, then start from current EOF.
        summary = dict(previous)
        summary["checkpoint"] = current_jsonl_checkpoint(
            configured_log_dir(), ("findings",)
        )
        summary["generated_at"] = utc_now()
        summary["incremental_records_read"] = 0
    else:
        summary = build_findings_summary()
    save_json_file(findings_history_path(), summary)
    return display_findings_summary(summary, window_days)


def build_findings_summary():
    """Read current findings logs once and create the durable summary file."""
    log_dir = configured_log_dir()
    findings = []
    records_read = 0
    for event in read_jsonl_events(log_dir, "findings", None):
        records_read += 1
        if event.get("type") == "finding" and event.get("data"):
            findings.append(normalize_finding_source(event["data"]))
    findings.sort(
        key=lambda item: utc_epoch(item.get("timestamp")) or 0, reverse=True
    )
    return {
        "generated_at": utc_now(),
        "generated_at_epoch": time.time(),
        "window": view_window_metadata(None),
        "state_path": findings_history_path(),
        "files_read": count_jsonl_files(log_dir, "findings"),
        "records_read": records_read,
        "incremental_records_read": records_read,
        "checkpoint": current_jsonl_checkpoint(log_dir, ("findings",)),
        "findings": findings,
        "counts": count_findings(findings),
    }


def update_findings_summary(previous):
    """Fold only new findings JSONL bytes into the materialized summary."""
    summary = dict(previous)
    findings = list(summary.get("findings") or [])
    checkpoint = summary.get("checkpoint") or empty_jsonl_checkpoint()
    records_read = 0
    for event in read_incremental_jsonl_events(
        configured_log_dir(), "findings", checkpoint
    ):
        records_read += 1
        if event.get("type") == "finding" and event.get("data"):
            findings.append(normalize_finding_source(event["data"]))
    findings.sort(
        key=lambda item: utc_epoch(item.get("timestamp")) or 0, reverse=True
    )
    summary.update(
        {
            "generated_at": utc_now(),
            "generated_at_epoch": time.time(),
            "window": view_window_metadata(None),
            "state_path": findings_history_path(),
            "files_read": count_jsonl_files(configured_log_dir(), "findings"),
            "records_read": int(summary.get("records_read") or 0)
            + records_read,
            "incremental_records_read": records_read,
            "checkpoint": checkpoint,
            "findings": findings,
            "counts": count_findings(findings),
            "cached": False,
        }
    )
    return summary


def display_findings_summary(summary, window_days):
    """Filter materialized Finding rows by timestamp without reading JSONL."""
    output = dict(summary or {})
    findings = list(output.get("findings") or [])
    if window_days is not None:
        findings = [
            item
            for item in findings
            if event_in_window(
                {"timestamp": item.get("timestamp"), "data": item}, window_days
            )
        ]
    output["findings"] = findings
    output["window"] = view_window_metadata(window_days)
    output["materialized_window"] = (summary or {}).get(
        "window"
    ) or view_window_metadata(None)
    output["counts"] = count_findings(findings)
    return output


def count_findings(findings):
    """Return severity counters for materialized Finding rows."""
    return {
        "total": len(findings),
        "warning": sum(
            1 for item in findings if item.get("severity") == "warning"
        ),
        "info": sum(1 for item in findings if item.get("severity") == "info"),
        "error": sum(
            1 for item in findings if item.get("severity") in ("error", "alert")
        ),
    }


def build_derived_views(window_days="default", force=False):
    """Build or return one consistent derived-data bundle.

    A normal page load must be cheap: it reads persisted summaries or returns
    empty placeholders. The Refresh button is the explicit materialization path
    that folds in only JSONL bytes not already covered by saved checkpoints.
    """
    window_days = resolve_window_days(window_days)
    if force:
        # Device History is the dependency for both analysis and reports. Build
        # it once, then run every derived view from the same in-memory summary.
        refresh_device_history(window_days, update_analysis=False)
        refresh_history_analysis(window_days)
        refresh_reports(window_days)
        runtime["findings_history"] = refresh_findings_history(window_days)
    else:
        cached_derived_view(
            "findings_history", load_cached_findings_history, window_days
        )
        cached_derived_view(
            "device_history", load_cached_device_history, window_days
        )
        cached_derived_view(
            "history_analysis", load_cached_history_analysis, window_days
        )
        cached_derived_view("reports", load_cached_reports, window_days)
    generated_at = utc_now()
    generated_at_epoch = time.time()
    return {
        "generated_at": generated_at,
        "generated_at_epoch": generated_at_epoch,
        "window": view_window_metadata(window_days),
        "findings": add_refresh_metadata(
            runtime["findings_history"], generated_at, generated_at_epoch
        ),
        "device_history": add_refresh_metadata(
            runtime["device_history"], generated_at, generated_at_epoch
        ),
        "history_analysis": add_refresh_metadata(
            runtime["history_analysis"], generated_at, generated_at_epoch
        ),
        "reports": add_refresh_metadata(
            runtime["reports"], generated_at, generated_at_epoch
        ),
    }


def add_refresh_metadata(summary, refreshed_at, refreshed_at_epoch):
    """Attach request-level refresh time without mutating cached summaries."""
    if not isinstance(summary, dict):
        return summary
    copy = dict(summary)
    copy["refreshed_at"] = refreshed_at
    copy["refreshed_at_epoch"] = refreshed_at_epoch
    return copy


def normalize_finding_source(finding):
    """Map old system lifecycle findings back to their collector source.

    Older persisted findings recorded collector state changes as source=system
    even though their key already named the collector. Normalize on read so old
    rows appear under the same collector subtab as newly generated rows.
    """
    finding = dict(finding or {})
    if finding.get("source") != "system":
        return finding
    if finding.get("type") not in (
        "collector_offline",
        "collector_retrying",
        "collector_stopped",
    ):
        return finding
    known = set(
        collector_keys(runtime.get("config") or {}, include_system=False)
    )
    attributes = finding.get("attributes") or {}
    source = attributes.get("collector")
    if not source:
        key = str(finding.get("key") or "")
        source = key.rsplit(":", 1)[-1] if ":" in key else ""
    if source in known:
        finding["source"] = source
    return finding


def device_history_path():
    """Return the persisted Device History summary path."""
    return os.path.join(
        configured_log_dir(), "device_history", "device_history.json"
    )


def findings_history_path():
    """Return the materialized Findings summary path."""
    return os.path.join(
        configured_log_dir(), "device_history", "findings_history.json"
    )


def history_analysis_path():
    """Return the persisted history-analysis summary path."""
    return os.path.join(
        configured_log_dir(), "device_history", "history_analysis.json"
    )


def reports_path():
    """Return the persisted report summary path."""
    return os.path.join(configured_log_dir(), "device_history", "reports.json")


def read_json_file(path):
    """Best-effort JSON file read for cached derived summaries."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def save_json_file(path, payload):
    """Write one materialized derived summary."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)


def load_cached_findings_history(window_days):
    """Load materialized Findings without falling back to JSONL scanning."""
    summary = read_json_file(findings_history_path())
    if isinstance(summary, dict):
        summary["cached"] = True
        return display_findings_summary(summary, window_days)
    return empty_findings_history(window_days)


def empty_findings_history(window_days):
    """Return a browser-ready empty Findings summary when no cache exists."""
    return {
        "generated_at": utc_now(),
        "generated_at_epoch": time.time(),
        "cached": True,
        "empty": True,
        "window": view_window_metadata(window_days),
        "state_path": findings_history_path(),
        "files_read": 0,
        "records_read": 0,
        "findings": [],
        "counts": {"total": 0, "warning": 0, "info": 0, "error": 0},
    }


def load_cached_device_history(window_days):
    """Load persisted Device History without falling back to raw-log parsing."""
    summary = read_json_file(device_history_path())
    if isinstance(summary, dict):
        summary.setdefault("window", view_window_metadata(None))
        summary.setdefault("generated_at", utc_now())
        output = DeviceHistoryBuilder(
            configured_log_dir(),
            state_path=device_history_path(),
            window_days=window_days,
        ).display_summary(summary, window_days)
        output["cached"] = True
        return output
    return empty_device_history(window_days)


def empty_device_history(window_days):
    """Return a browser-ready Device History summary when no cache exists."""
    return {
        "generated_at": utc_now(),
        "cached": True,
        "empty": True,
        "log_dir": configured_log_dir(),
        "state_path": device_history_path(),
        "window": view_window_metadata(window_days),
        "files_read": 0,
        "records_read": 0,
        "wifi": {"access_points": [], "clients": []},
        "ble": {"devices": []},
        "bluetooth": {"devices": []},
    }


def load_cached_history_analysis(window_days):
    """Load persisted analysis without triggering a Device History refresh."""
    analysis = read_json_file(history_analysis_path())
    if isinstance(analysis, dict):
        analysis.setdefault("window", view_window_metadata(None))
        analysis.setdefault("generated_at", utc_now())
        analysis.setdefault("observations", [])
        analysis.setdefault(
            "counts", count_observations(analysis.get("observations") or [])
        )
        analysis["cached"] = True
        if not summary_matches_window(analysis, window_days):
            empty = empty_history_analysis(window_days)
            empty["cached_window"] = analysis.get("window")
            empty["empty_reason"] = "Refresh insights for this view window"
            return empty
        return analysis
    return empty_history_analysis(window_days)


def empty_history_analysis(window_days):
    """Return an empty analysis snapshot when no persisted analysis exists."""
    return {
        "generated_at": utc_now(),
        "cached": True,
        "empty": True,
        "window": view_window_metadata(window_days),
        "state_path": history_analysis_path(),
        "observations": [],
        "counts": {"total": 0, "warning": 0, "info": 0},
    }


def load_cached_reports(window_days):
    """Load persisted Reports without triggering any raw-log work."""
    reports = read_json_file(reports_path())
    if isinstance(reports, dict):
        reports.setdefault("window", view_window_metadata(None))
        reports.setdefault("generated_at", utc_now())
        reports.setdefault("reports", [])
        reports.setdefault(
            "counts", count_reports(reports.get("reports") or [])
        )
        reports["cached"] = True
        if not summary_matches_window(reports, window_days):
            empty = empty_reports(window_days)
            empty["cached_window"] = reports.get("window")
            empty["empty_reason"] = "Refresh reports for this view window"
            return empty
        return reports
    return empty_reports(window_days)


def empty_reports(window_days):
    """Return an empty report bundle when no generated report exists."""
    return {
        "generated_at": utc_now(),
        "cached": True,
        "empty": True,
        "window": view_window_metadata(window_days),
        "state_path": reports_path(),
        "reports": [],
        "counts": {"total": 0, "warning": 0, "info": 0},
    }


def count_reports(reports):
    """Compute report counters for older cached files without counts."""
    return {
        "total": len(reports),
        "warning": sum(
            1 for item in reports if item.get("severity") == "warning"
        ),
        "info": sum(1 for item in reports if item.get("severity") == "info"),
    }


def count_observations(observations):
    """Compute analysis counters for older cached files without counts."""
    return {
        "total": len(observations),
        "warning": sum(
            1 for item in observations if item.get("severity") == "warning"
        ),
        "info": sum(
            1 for item in observations if item.get("severity") == "info"
        ),
    }


def refresh_device_history(window_days="default", update_analysis=True):
    """Build and cache device history from retained raw JSONL logs."""
    window_days = resolve_window_days(window_days)
    log_dir = configured_log_dir()
    builder = DeviceHistoryBuilder(log_dir, window_days=window_days)
    # Builder.build() persists the all-retained materialized summary, then
    # returns a display-filtered copy for the selected View window.
    runtime["device_history"] = builder.build(persist=True)
    if update_analysis:
        refresh_history_analysis(window_days)
    return runtime["device_history"]


def refresh_history_analysis(window_days="default"):
    """Analyze the cached Device History summary and persist observations."""
    window_days = resolve_window_days(window_days)
    history = runtime.get("device_history")
    if history is None or not summary_matches_window(history, window_days):
        # Analysis depends on Device History. Rebuild only that dependency when
        # the current cached history belongs to another View window.
        history = refresh_device_history(window_days, update_analysis=False)
    if history is None:
        return {
            "generated_at": utc_now(),
            "observations": [],
            "counts": {"total": 0, "warning": 0, "info": 0},
        }
    config = runtime.get("config") or {}
    analyzer = HistoryAnalyzer(config.get("history_analysis", {}))
    analysis = analyzer.analyze(history)
    analysis["window"] = view_window_metadata(window_days)
    state_path = history.get("state_path") or os.path.join(
        "logs", "device_history", "device_history.json"
    )
    analysis_path = os.path.join(
        os.path.dirname(state_path), "history_analysis.json"
    )
    analysis["state_path"] = analysis_path
    try:
        save_analysis(analysis_path, analysis)
    except OSError as exc:
        logging.exception("failed to persist history analysis: %s", exc)
    runtime["history_analysis"] = analysis
    return analysis


def refresh_reports(window_days="default"):
    """Generate report-style summaries from the cached Device History."""
    window_days = resolve_window_days(window_days)
    history = runtime.get("device_history")
    if history is None or not summary_matches_window(history, window_days):
        history = refresh_device_history(window_days, update_analysis=False)
    config = runtime.get("config") or {}
    builder = ReportsBuilder(config.get("reports", {}), window_days=window_days)
    report = builder.build(history or {})
    report["state_path"] = reports_path()
    try:
        save_reports(reports_path(), report)
    except OSError as exc:
        logging.exception("failed to persist reports: %s", exc)
    runtime["reports"] = report
    return report


def run_loop(config):
    """Own the asyncio event loop used by all collectors."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    runtime["loop"] = loop
    bus = EventBus()
    runtime["bus"] = bus
    loop.run_until_complete(start_collectors(config, bus))
    loop.run_forever()


async def shutdown_runtime():
    """Stop collectors first, then cancel background tasks and stop the loop."""
    if runtime["shutting_down"]:
        return
    runtime["shutting_down"] = True
    try:
        current = asyncio.current_task()
    except AttributeError:
        current = asyncio.Task.current_task()
    for collector in runtime["collectors"]:
        try:
            await collector.stop()
        except Exception as exc:
            logging.exception(
                "failed to stop collector %s: %s", collector.config_key, exc
            )
    pending = [
        task
        for task in runtime["tasks"]
        if task is not current and not task.done()
    ]
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    loop = runtime.get("loop")
    if loop and loop.is_running():
        loop.call_soon(loop.stop)


def stop_runtime(*_args):
    """Signal handler that schedules orderly collector cleanup."""
    loop = runtime.get("loop")
    if loop and loop.is_running():
        future = asyncio.run_coroutine_threadsafe(shutdown_runtime(), loop)
        try:
            future.result(
                timeout=runtime_number("shutdown_timeout_sec", 10, minimum=1)
            )
        except concurrent.futures.TimeoutError:
            logging.error("timed out waiting for collector shutdown")
    raise KeyboardInterrupt


def runtime_settings():
    """Return internal runtime knobs from skannr.yaml with safe defaults."""
    return (runtime.get("config") or {}).get("runtime") or {}


def runtime_number(key, default, minimum=0):
    """Parse one numeric runtime setting and clamp it to a sane minimum."""
    try:
        value = float(runtime_settings().get(key, default))
    except (TypeError, ValueError):
        value = float(default)
    return max(value, minimum)


def runtime_int(key, default, minimum=0):
    """Parse one integer runtime setting."""
    return int(runtime_number(key, default, minimum))


def parse_args():
    """Parse CLI options; the default config stays local to the project tree."""
    parser = argparse.ArgumentParser(description="Skannr monitoring dashboard")
    project_dir = os.path.dirname(os.path.abspath(__file__))
    default_config = os.path.join(project_dir, "skannr.yaml")
    legacy_config = os.path.join(project_dir, "spectra.yaml")
    if not os.path.exists(default_config) and os.path.exists(legacy_config):
        default_config = legacy_config
    parser.add_argument(
        "--config", default=default_config, help="Path to skannr.yaml"
    )
    return parser.parse_args()


def main():
    """Configure logging/persistence, start collectors, and serve the UI."""
    args = parse_args()
    config = load_config(args.config)
    runtime["config"] = config
    runtime["event_log"] = deque(
        maxlen=runtime_int("event_log_maxlen", 100, minimum=1)
    )
    runtime["findings"] = FindingsEngine(config.get("findings", {}))
    log_dir = configured_log_dir()
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        level=getattr(
            logging, config["skannr"]["log_level"].upper(), logging.INFO
        ),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(log_dir, "skannr.log")),
            logging.StreamHandler(),
        ],
    )
    runtime["persistence"] = load_persistence(config)
    bootstrap_findings()
    # Seed known device identities from the materialized summary so a restart
    # does not classify every known AP/BLE device as new.
    runtime["findings"].seed_device_history(load_cached_device_history(None))

    signal.signal(signal.SIGINT, stop_runtime)
    signal.signal(signal.SIGTERM, stop_runtime)

    thread = threading.Thread(target=run_loop, args=(config,), daemon=True)
    thread.start()

    host = str(config["skannr"]["host"])
    port = int(config["skannr"]["port"])
    install_werkzeug_wildcard_ipv6_filter(host)
    logging.info("Skannr listening on %s", display_listen_url(host, port))
    socketio.run(app, host=host, port=port)


def display_listen_url(host, port):
    """Return a readable URL for IPv4, hostnames, and IPv6 literals."""
    if ":" in host and not host.startswith("["):
        return "http://[{}]:{}".format(host, port)
    return "http://{}:{}".format(host, port)


def install_werkzeug_wildcard_ipv6_filter(host):
    """Hide Werkzeug's misleading sample URL for wildcard IPv6 binds.

    Werkzeug 2.0 logs "Running on all addresses" for host="::", then prints a
    URL based on one chosen interface address. On machines with eth0 plus a
    Yggdrasil tun interface that second line can look like Skannr is bound only
    to eth0, even though the socket is actually listening on all IPv6 addresses.
    """
    if str(host) != "::":
        return

    class WildcardIPv6StartupFilter(logging.Filter):
        def filter(self, record):
            message = record.getMessage()
            return not message.startswith(" * Running on http://[")

    logging.getLogger("werkzeug").addFilter(WildcardIPv6StartupFilter())


if __name__ == "__main__":
    main()
