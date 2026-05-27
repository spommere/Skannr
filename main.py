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
import re
import signal
import threading
import time
from collections import deque

from flask import Flask, Response, make_response, request, send_from_directory
from flask_socketio import SocketIO
import yaml
from werkzeug.serving import make_server

from bus import EventBus, local_now
from collectors import load_actions, load_collectors
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
    now_epoch,
    record_time_epoch,
    read_incremental_jsonl_events,
    read_jsonl_events,
    resolve_window_days as resolve_log_window_days,
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
    "actions": {},
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
    "web_servers": [],
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
    response = make_response(send_from_directory(app.static_folder, "index.html"))
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
            "timestamp_epoch": now_epoch(),
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
    action = action_by_key("ble_identify")
    if not loop or not action:
        return {
            "ok": False,
            "error": "BLE Identify action is not available",
        }, 503
    if not mac:
        return {"ok": False, "error": "Missing BLE MAC address"}, 400
    asyncio.run_coroutine_threadsafe(action.identify(mac, timeout), loop)
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
                "gain": config.get("collectors", {}).get("rtlsdr", {}).get("gain"),
                "threshold_db": config.get("collectors", {})
                .get("rtlsdr", {})
                .get("threshold_db"),
            },
        },
        "bluetooth_uuid_names": bluetooth_uuid_names(),
    }


def bluetooth_uuid_names():
    """Load optional offline Bluetooth UUID names for browser decoding.

    Company identifiers are manufacturer-data IDs and are handled by the BLE
    collector. This lookup covers Bluetooth UUID assigned-number files such as
    member_uuids.txt, where values like 0xFEAF identify a vendor/member UUID
    advertised in the service UUID list.
    """
    names = {}
    directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collectors")
    for basename in (
        "member_uuids",
        "service_uuids",
        "characteristic_uuids",
    ):
        for extension in (".txt", ".yaml", ".yml"):
            path = os.path.join(directory, "{}{}".format(basename, extension))
            names.update(load_bluetooth_uuid_file(path))
    return names


def load_bluetooth_uuid_file(path):
    """Parse one optional Bluetooth SIG UUID mapping file."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return {}
    parsed = bluetooth_uuid_names_from_yaml(text)
    return parsed or bluetooth_uuid_names_from_text(text)


def bluetooth_uuid_names_from_yaml(text):
    """Return UUID-name pairs from YAML-shaped SIG assigned-number exports."""
    try:
        loaded = yaml.safe_load(text) or []
    except yaml.YAMLError:
        return {}
    if isinstance(loaded, dict):
        loaded = (
            loaded.get("uuids")
            or loaded.get("service_uuids")
            or loaded.get("member_uuids")
            or loaded.get("characteristic_uuids")
            or loaded.get("values")
            or []
        )
    if not isinstance(loaded, list):
        return {}
    names = {}
    for item in loaded:
        if not isinstance(item, dict):
            continue
        value = item.get("uuid", item.get("value"))
        name = item.get("name")
        short_id = normalize_bluetooth_uuid_key(value)
        if short_id and name:
            names[short_id] = str(name)
    return names


def bluetooth_uuid_names_from_text(text):
    """Fallback parser for copied SIG text that is only YAML-like."""
    names = {}
    current_uuid = None
    for line in (text or "").splitlines():
        uuid_match = re.search(
            r"\b(?:uuid|value):\s*['\"]?(0x[0-9a-fA-F]+|[0-9a-fA-F]{4})",
            line,
        )
        if uuid_match:
            current_uuid = normalize_bluetooth_uuid_key(uuid_match.group(1))
        name_match = re.search(r"\bname:\s*(.+)$", line)
        if current_uuid and name_match:
            name = name_match.group(1).strip().strip("'\"")
            if name:
                names[current_uuid] = name
                current_uuid = None
    return names


def normalize_bluetooth_uuid_key(value):
    """Normalize 16-bit Bluetooth UUID values to lower-case four hex digits."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return "{:04x}".format(int(text, 0))
    except ValueError:
        compact = re.sub(r"[^0-9a-fA-F]", "", text).lower()
        if len(compact) == 4:
            return compact
        match = re.match(r"^0000([0-9a-f]{4})", compact)
        return match.group(1) if match else ""


def derived_response(callback):
    """Run a derived-data route and keep failures JSON-shaped.

    Browsers always parse these endpoints as JSON. Without this wrapper, a
    Flask traceback page is returned as HTML and the frontend can only report a
    misleading JSON parse error instead of the real refresh failure.
    """
    try:
        return callback()
    except Exception as exc:
        logging.exception("derived-data request failed")
        return {"ok": False, "error": str(exc)}, 500


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
    return derived_response(
        lambda: build_derived_views(requested_window_days(), force=False)
    )


@app.route("/derived_views/refresh", methods=["POST"])
def derived_views_refresh():
    """Refresh all derived tabs in dependency order for the current view."""
    return derived_response(
        lambda: build_derived_views(requested_window_days(), force=True)
    )


@app.route("/device_history/refresh", methods=["POST"])
def device_history_refresh():
    """Compatibility route: refresh the full derived-data bundle."""
    return derived_response(
        lambda: build_derived_views(requested_window_days(), force=True)[
            "device_history"
        ]
    )


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
    return derived_response(
        lambda: build_derived_views(requested_window_days(), force=True)["findings"]
    )


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
    return derived_response(
        lambda: build_derived_views(requested_window_days(), force=True)[
            "history_analysis"
        ]
    )


@app.route("/reports", methods=["GET"])
def reports():
    """Return the last generated report summary."""
    window_days = requested_window_days()
    return cached_derived_view("reports", load_cached_reports, window_days)


@app.route("/reports/refresh", methods=["POST"])
def reports_refresh():
    """Compatibility route: refresh the full derived-data bundle."""
    return derived_response(
        lambda: build_derived_views(requested_window_days(), force=True)["reports"]
    )


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
            "timestamp_epoch": now_epoch(),
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


def action_by_key(key):
    """Return an on-demand action object for an action key."""
    return (runtime.get("actions") or {}).get(key)


def format_sse(name, payload):
    """Format one named Server-Sent Event record."""
    return "event: {}\ndata: {}\n\n".format(name, json.dumps(payload, sort_keys=True))


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
            event.get("collector") == "system" and event.get("type") == "system_status"
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
                "timestamp_epoch": finding.get("timestamp_epoch"),
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
    runtime["actions"] = load_actions(config, bus)
    for collector in collectors:
        auto_start = bool(collector.config.get("auto_start", True))
        if not auto_start:
            # On-demand collectors should still appear in System Status. Run
            # their lightweight detection once, but do not start capture until
            # the user clicks Start.
            try:
                collector.detect()
                if collector.state == "ONLINE":
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
                "timestamp_epoch": now_epoch(),
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
                    "timestamp_epoch": summary.get("timestamp_epoch"),
                    "data": summary,
                }
            )
    except Exception as exc:
        logging.exception("failed to bootstrap findings: %s", exc)


def requested_window_days():
    """Resolve the requested dashboard log window from query/body/config."""
    payload = request.get_json(silent=True) if request.method == "POST" else None
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
            findings.append(event["data"])
    findings.sort(
        key=lambda item: record_time_epoch(item, "timestamp") or 0,
        reverse=True,
    )
    generated_at_epoch = now_epoch()
    generated_at = local_now(generated_at_epoch)
    return {
        "generated_at": generated_at,
        "generated_at_epoch": generated_at_epoch,
        "window": view_window_metadata(window_days),
        "files_read": files_read,
        "records_read": records_read,
        "findings": findings,
        "counts": {
            "total": len(findings),
            "warning": sum(1 for item in findings if item.get("severity") == "warning"),
            "info": sum(1 for item in findings if item.get("severity") == "info"),
            "error": sum(
                1 for item in findings if item.get("severity") in ("error", "alert")
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
        generated_at_epoch = now_epoch()
        summary["generated_at"] = local_now(generated_at_epoch)
        summary["generated_at_epoch"] = generated_at_epoch
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
            findings.append(event["data"])
    findings.sort(
        key=lambda item: record_time_epoch(item, "timestamp") or 0,
        reverse=True,
    )
    generated_at_epoch = now_epoch()
    return {
        "generated_at": local_now(generated_at_epoch),
        "generated_at_epoch": generated_at_epoch,
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
            findings.append(event["data"])
    findings.sort(
        key=lambda item: record_time_epoch(item, "timestamp") or 0,
        reverse=True,
    )
    generated_at_epoch = now_epoch()
    summary.update(
        {
            "generated_at": local_now(generated_at_epoch),
            "generated_at_epoch": generated_at_epoch,
            "window": view_window_metadata(None),
            "state_path": findings_history_path(),
            "files_read": count_jsonl_files(configured_log_dir(), "findings"),
            "records_read": int(summary.get("records_read") or 0) + records_read,
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
                {
                    "timestamp": item.get("timestamp"),
                    "timestamp_epoch": item.get("timestamp_epoch"),
                    "data": item,
                },
                window_days,
            )
        ]
    findings = filter_insight_recent_records(findings, use_last_seen=False)
    output["findings"] = findings
    output["window"] = view_window_metadata(window_days)
    output["insights_window"] = insights_recent_window_metadata()
    output["materialized_window"] = (summary or {}).get(
        "window"
    ) or view_window_metadata(None)
    output["counts"] = count_findings(findings)
    return output


def display_history_analysis(analysis, window_days):
    """Return the browser-facing recent-event slice of history analysis.

    HistoryAnalyzer persists all observations for the selected View window so a
    later configuration change can expose more or less history without another
    raw-log scan. The Insights tab, however, is a tactical event feed. It shows
    only observations whose actual device activity is recent enough.
    """
    output = dict(analysis or {})
    observations = list(output.get("observations") or [])
    observations = filter_insight_recent_records(observations, use_last_seen=True)
    output["observations"] = observations
    output["window"] = view_window_metadata(window_days)
    output["insights_window"] = insights_recent_window_metadata()
    output["counts"] = count_observations(observations)
    return output


def filter_insight_recent_records(records, use_last_seen=True):
    """Keep records that belong in the Insights recent event feed.

    Findings are already point-in-time events, so their event timestamp is the
    right cutoff field. History observations are regenerated on refresh and use
    refresh time as their row timestamp; for those rows, last_seen_epoch is the
    real activity time and prevents old behavior from reappearing as "new" just
    because the analysis was rebuilt.
    """
    cutoff = insights_recent_cutoff_epoch()
    if cutoff is None:
        return list(records or [])
    return [
        item
        for item in records or []
        if record_is_recent_insight(item, use_last_seen, cutoff)
    ]


def record_is_recent_insight(record, use_last_seen, cutoff):
    """Return True when a finding/observation is inside the Insights window."""
    epoch = insight_activity_epoch(record, use_last_seen)
    return epoch is not None and epoch >= cutoff


def insight_activity_epoch(record, use_last_seen=True):
    """Return the epoch used to decide whether an Insight row is recent."""
    if use_last_seen:
        epoch = record_time_epoch(record, "last_seen")
        if epoch is not None:
            return epoch
    return record_time_epoch(record, "timestamp")


def insights_recent_cutoff_epoch():
    """Return the configured Insights cutoff epoch, or None for no cutoff."""
    config = runtime.get("config") or {}
    analysis_config = config.get("history_analysis") or {}
    hours = analysis_config.get("insights_recent_hours", 6)
    try:
        hours = float(hours)
    except (TypeError, ValueError):
        hours = 6
    if hours <= 0:
        return None
    return now_epoch() - int(hours * 3600)


def insights_recent_window_metadata():
    """Describe the short tactical window used by the Insights tab."""
    config = runtime.get("config") or {}
    analysis_config = config.get("history_analysis") or {}
    hours = analysis_config.get("insights_recent_hours", 6)
    try:
        hours = float(hours)
    except (TypeError, ValueError):
        hours = 6
    if hours <= 0:
        return {"hours": None, "label": "All insight events"}
    label = int(hours) if float(hours).is_integer() else hours
    return {"hours": hours, "label": "Recent {} hours".format(label)}


def count_findings(findings):
    """Return severity counters for materialized Finding rows."""
    return {
        "total": len(findings),
        "warning": sum(1 for item in findings if item.get("severity") == "warning"),
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
        cached_derived_view("device_history", load_cached_device_history, window_days)
        cached_derived_view(
            "history_analysis", load_cached_history_analysis, window_days
        )
        cached_derived_view("reports", load_cached_reports, window_days)
    generated_at_epoch = now_epoch()
    generated_at = local_now(generated_at_epoch)
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


def device_history_path():
    """Return the persisted Device History summary path."""
    return os.path.join(configured_log_dir(), "device_history", "device_history.json")


def findings_history_path():
    """Return the materialized Findings summary path."""
    return os.path.join(configured_log_dir(), "device_history", "findings_history.json")


def history_analysis_path():
    """Return the persisted history-analysis summary path."""
    return os.path.join(configured_log_dir(), "device_history", "history_analysis.json")


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
    generated_at_epoch = now_epoch()
    return {
        "generated_at": local_now(generated_at_epoch),
        "generated_at_epoch": generated_at_epoch,
        "cached": True,
        "empty": True,
        "window": view_window_metadata(window_days),
        "insights_window": insights_recent_window_metadata(),
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
        summary.setdefault("generated_at_epoch", now_epoch())
        summary.setdefault("generated_at", local_now(summary["generated_at_epoch"]))
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
    generated_at_epoch = now_epoch()
    return {
        "generated_at": local_now(generated_at_epoch),
        "generated_at_epoch": generated_at_epoch,
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
        analysis.setdefault("generated_at_epoch", now_epoch())
        analysis.setdefault("generated_at", local_now(analysis["generated_at_epoch"]))
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
        return display_history_analysis(analysis, window_days)
    return empty_history_analysis(window_days)


def empty_history_analysis(window_days):
    """Return an empty analysis snapshot when no persisted analysis exists."""
    generated_at_epoch = now_epoch()
    return {
        "generated_at": local_now(generated_at_epoch),
        "generated_at_epoch": generated_at_epoch,
        "cached": True,
        "empty": True,
        "window": view_window_metadata(window_days),
        "insights_window": insights_recent_window_metadata(),
        "state_path": history_analysis_path(),
        "observations": [],
        "counts": {"total": 0, "warning": 0, "info": 0},
    }


def load_cached_reports(window_days):
    """Load persisted Reports without triggering any raw-log work."""
    reports = read_json_file(reports_path())
    if isinstance(reports, dict):
        reports.setdefault("window", view_window_metadata(None))
        reports.setdefault("generated_at_epoch", now_epoch())
        reports.setdefault("generated_at", local_now(reports["generated_at_epoch"]))
        reports.setdefault("reports", [])
        reports.setdefault("counts", count_reports(reports.get("reports") or []))
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
    generated_at_epoch = now_epoch()
    return {
        "generated_at": local_now(generated_at_epoch),
        "generated_at_epoch": generated_at_epoch,
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
        "warning": sum(1 for item in reports if item.get("severity") == "warning"),
        "info": sum(1 for item in reports if item.get("severity") == "info"),
    }


def count_observations(observations):
    """Compute analysis counters for older cached files without counts."""
    return {
        "total": len(observations),
        "warning": sum(1 for item in observations if item.get("severity") == "warning"),
        "info": sum(1 for item in observations if item.get("severity") == "info"),
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
        generated_at_epoch = now_epoch()
        return {
            "generated_at": local_now(generated_at_epoch),
            "generated_at_epoch": generated_at_epoch,
            "observations": [],
            "counts": {"total": 0, "warning": 0, "info": 0},
        }
    config = runtime.get("config") or {}
    analyzer = HistoryAnalyzer(config.get("history_analysis", {}))
    analysis = analyzer.analyze(history)
    analysis["window"] = view_window_metadata(window_days)
    analysis["insights_window"] = insights_recent_window_metadata()
    state_path = history.get("state_path") or os.path.join(
        "logs", "device_history", "device_history.json"
    )
    analysis_path = os.path.join(os.path.dirname(state_path), "history_analysis.json")
    analysis["state_path"] = analysis_path
    try:
        save_analysis(analysis_path, analysis)
    except OSError as exc:
        logging.exception("failed to persist history analysis: %s", exc)
    runtime["history_analysis"] = display_history_analysis(analysis, window_days)
    return runtime["history_analysis"]


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
        task for task in runtime["tasks"] if task is not current and not task.done()
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
            future.result(timeout=runtime_number("shutdown_timeout_sec", 10, minimum=1))
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
    parser.add_argument("--config", default=default_config, help="Path to skannr.yaml")
    return parser.parse_args()


def main():
    """Configure logging/persistence, start collectors, and serve the UI."""
    args = parse_args()
    config = load_config(args.config)
    runtime["config"] = config
    runtime["event_log"] = deque(maxlen=runtime_int("event_log_maxlen", 100, minimum=1))
    runtime["findings"] = FindingsEngine(config.get("findings", {}))
    log_dir = configured_log_dir()
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, config["skannr"]["log_level"].upper(), logging.INFO),
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

    run_web_listeners(config)


def run_web_listeners(config):
    """Start one or more dashboard listeners from skannr.yaml.

    The only supported binding config is ``skannr.listeners``. The list may
    contain one endpoint or several endpoints; separate IPv4/IPv6 ports avoid
    depending on platform-specific IPv4-mapped IPv6 socket behavior.
    """
    listeners = configured_web_listeners(config)
    logging.info(
        "Resolved Skannr listener config: %s",
        ", ".join(display_listen_url(item["host"], item["port"]) for item in listeners),
    )
    servers = [create_web_server(listener) for listener in listeners]
    runtime["web_servers"] = servers

    for server, listener in zip(servers[:-1], listeners[:-1]):
        thread = threading.Thread(
            target=serve_web_listener,
            args=(server, listener),
            daemon=True,
        )
        thread.start()
    serve_web_listener(servers[-1], listeners[-1])


def configured_web_listeners(config):
    """Return normalized dashboard listener dictionaries."""
    skannr_config = (config or {}).get("skannr") or {}
    listeners = skannr_config.get("listeners") or []
    normalized = []
    for index, listener in enumerate(listeners, start=1):
        if not isinstance(listener, str):
            raise ValueError(
                "skannr.listeners[{}] must be a quoted endpoint string".format(index)
            )
        normalized.append(parse_listener_endpoint(listener, index))
    if normalized:
        return normalized
    raise ValueError("skannr.listeners must contain at least one enabled endpoint")


def parse_listener_endpoint(endpoint, index):
    """Parse one compact host:port listener entry from skannr.yaml."""
    text = str(endpoint).strip()
    if not text:
        raise ValueError("skannr.listeners[{}] endpoint is empty".format(index))
    if text.startswith("["):
        close = text.find("]")
        if close < 0 or close + 1 >= len(text) or text[close + 1] != ":":
            raise ValueError(
                "skannr.listeners[{}] IPv6 endpoints must use [addr]:port".format(index)
            )
        host = text[1:close]
        port_text = text[close + 2 :]
    elif text.count(":") == 1:
        host, port_text = text.rsplit(":", 1)
    else:
        raise ValueError(
            "skannr.listeners[{}] must be host:port; use [IPv6]:port for "
            "IPv6 literals".format(index)
        )
    if not host:
        raise ValueError("skannr.listeners[{}] host is empty".format(index))
    return {"host": host, "port": parse_listener_port(port_text, index)}


def parse_listener_port(port_value, index):
    """Validate one configured listener TCP port."""
    try:
        port = int(port_value)
    except (TypeError, ValueError):
        raise ValueError("skannr.listeners[{}].port must be an integer".format(index))
    if port < 1 or port > 65535:
        raise ValueError(
            "skannr.listeners[{}].port must be between 1 and 65535".format(index)
        )
    return port


def create_web_server(listener):
    """Bind one dashboard listener and return its Werkzeug server.

    Binding every configured listener before serving any of them makes startup
    deterministic: a bad address or busy port fails immediately instead of
    hiding inside a background thread. This also avoids calling
    Flask-SocketIO's lifecycle wrapper more than once in the same process.
    """
    host = str(listener["host"])
    port = int(listener["port"])
    install_werkzeug_wildcard_ipv6_filter(host)
    server = make_server(host, port, app, threaded=True)
    logging.info("Skannr listening on %s", display_listen_url(host, port))
    return server


def serve_web_listener(server, listener):
    """Run one blocking dashboard listener."""
    try:
        server.serve_forever()
    except Exception as exc:
        logging.exception(
            "Skannr listener failed on %s: %s",
            display_listen_url(listener["host"], listener["port"]),
            exc,
        )
        raise


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
