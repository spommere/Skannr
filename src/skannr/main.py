"""Skannr web runtime, collector lifecycle, and derived-data routes.

The collectors publish events into an asyncio bus. This file owns the Flask UI,
browser fan-out, persistence writes, live findings, and the on-demand refresh
flow for materialized history/analysis/report summaries.
"""

import argparse
import asyncio
import concurrent.futures
import copy
import gzip
import json
import logging
import os
import queue
import re
import shutil
import signal
import subprocess
import threading
import time
from collections import deque

from flask import Flask, Response, make_response, request, send_from_directory
from flask_socketio import SocketIO
import yaml
from werkzeug.serving import make_server

from .alerts import AlertEngine
from .bus import EventBus, local_now
from .collectors import disabled_collector_statuses, load_actions, load_collectors
from .collectors.metadata import (
    browser_source_groups,
    browser_subtabs,
    collector_definitions,
    collector_keys,
)
from .connectivity import internet_available
from .collectors.rayhunter import clean_rayhunter_data, clean_rayhunter_field
from .config import load_config
from .wifi_ble_postprocessor import WiFiBLEPostprocessor
from .findings import FindingsEngine
from .history_analysis import HistoryAnalyzer, save_analysis
from .identity_policy import (
    bluetooth_group_label as identity_bluetooth_group_label,
    bluetooth_identity_bucket as identity_bluetooth_identity_bucket,
    bluetooth_manufacturer_label as identity_bluetooth_manufacturer_label,
    bluetooth_grouping_candidate as identity_bluetooth_grouping_candidate,
    low_identity_wifi_client,
    meaningful_bluetooth_names as identity_meaningful_bluetooth_names,
)
from .log_utils import (
    cleanup_orphaned_temp_files,
    current_jsonl_checkpoint,
    has_jsonl_checkpoint,
    now_epoch,
    record_time_epoch,
    resolve_window_days as resolve_log_window_days,
    save_json_atomic,
    timestamp_epoch,
    view_window_options,
    window_metadata,
)
from .notifications import pushover_enabled, send_pushover_alert
from .paths import (
    CONFIG_COLLECTORS_DIR,
    CONFIG_DIR,
    CONFIG_PATH,
    DATA_COLLECTORS_DIR,
    OLD_CONFIG_DIR,
    STATIC_DIR,
    VERSION_PATH,
    ensure_owner,
)
from .persistence import load_persistence
from .reports import ReportsBuilder, save_reports
from .subject_history import SubjectHistoryBuilder
from .snapshots import build_snapshot_from_sh, load_snapshots, save_snapshots


def read_app_version():
    """Read the release version from the project VERSION file."""
    try:
        with open(VERSION_PATH, "r", encoding="utf-8") as fh:
            return fh.read().strip() or "0.0.0"
    except OSError:
        return "0.0.0"


APP_VERSION = read_app_version()

POLL_FEED_REPLAY_TYPES = {
    "noaa": {
        "noaa_weather_alert",
        "noaa_tropical_advisory",
        "noaa_forecast_summary",
        "noaa_tsunami_alert",
    },
    "usgs": {"usgs_earthquake"},
    "swpc": {"swpc_event"},
    "pws": {"pws_weather"},
}


def alert_engine_config(config):
    """Return AlertEngine config enriched with effective collector subfeed state."""
    alert_config = copy.deepcopy((config or {}).get("alerts") or {})
    disabled_noaa_sources = {
        str(item or "").strip().lower()
        for item in alert_config.get("_disabled_noaa_sources") or []
        if str(item or "").strip()
    }
    noaa = ((config or {}).get("collectors") or {}).get("noaa") or {}
    if noaa:
        if not bool(noaa.get("enabled", False)):
            disabled_noaa_sources.add("noaa")
        else:
            nws = noaa.get("nws") or {}
            if not bool(nws.get("enabled", True)):
                disabled_noaa_sources.add("nws")
            nhc = noaa.get("nhc") or {}
            if not bool(nhc.get("enabled", True)):
                disabled_noaa_sources.add("nhc")
    if disabled_noaa_sources:
        alert_config["_disabled_noaa_sources"] = sorted(disabled_noaa_sources)
    return alert_config


DERIVED_REFRESH_PHASES = {
    "refresh": {
        "refresh_base": (1, 2, "Subject History"),
        "refresh_derived": (2, 2, "Insights + Reports"),
    },
    "repair": {
        "repair_dependents": (1, 1, "Repair"),
    },
    "cached": {
        "cached_subject_history": (1, 4, "Subject History"),
        "cached_device_history": (2, 4, "Device History"),
        "cached_history_analysis": (3, 4, "Insights"),
        "cached_reports": (4, 4, "Reports"),
    },
}


class DerivedRefreshCoordinator:
    """Own backend derived-refresh state and progress reporting."""

    def __init__(self, phases):
        self.phases = phases
        self.refresh_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.started = None
        self.window = None
        self.mode = None
        self.stage = None
        self.stage_label = None
        self.stage_step = None
        self.stage_total = None
        self.stage_started = None
        self.finished_epoch = None
        self.finished_window = None
        self.failed_epoch = None
        self.failed_window = None
        self.last_error = ""

    def try_start(self, window_days, mode="refresh"):
        """Start one derived writer or return the active operation status."""
        if not self.refresh_lock.acquire(blocking=False):
            return False, self.status()
        started = time.monotonic()
        with self.state_lock:
            self.started = started
            self.window = window_days
            self.mode = mode
            self.stage = "starting"
            self.stage_label = "Starting"
            self.stage_step = 0
            self.stage_total = len(self.phases.get(mode) or {})
            self.stage_started = started
        return True, None

    def finish(self, window_days, success=True, error=""):
        """Publish completion and release the derived writer lock."""
        with self.state_lock:
            finished_epoch = now_epoch()
            mode = self.mode
            if success and mode == "refresh":
                self.finished_epoch = finished_epoch
                self.finished_window = window_days
                self.last_error = ""
            elif success:
                self.last_error = ""
            else:
                self.failed_epoch = finished_epoch
                self.failed_window = window_days
                self.last_error = str(error or "")
            self.started = None
            self.window = None
            self.mode = None
            self.stage = None
            self.stage_label = None
            self.stage_step = None
            self.stage_total = None
            self.stage_started = None
        self.refresh_lock.release()

    def status(self):
        """Return a compact snapshot for `/derived_views/status`."""
        with self.state_lock:
            started = self.started
            stage_started = self.stage_started
            status = {
                "in_progress": bool(started),
                "mode": self.mode or "",
                "window": self.window,
                "stage": self.stage or "",
                "stage_label": self.stage_label or "",
                "phase_step": self.stage_step,
                "phase_total": self.stage_total,
                "last_finished_epoch": self.finished_epoch,
                "last_finished_window": self.finished_window,
                "last_failed_epoch": self.failed_epoch,
                "last_failed_window": self.failed_window,
                "last_error": self.last_error,
            }
        now = time.monotonic()
        status["elapsed_sec"] = round(now - started, 1) if started else 0
        status["stage_elapsed_sec"] = (
            round(now - stage_started, 1) if stage_started else 0
        )
        return status

    def phase_info(self, mode, name):
        """Return numbered operator-facing phase metadata."""
        phases = self.phases.get(mode) or {}
        return phases.get(name, (0, len(phases), name.replace("_", " ").title()))

    def start_phase(self, mode, name):
        """Start a logged phase and update refresh status when appropriate."""
        started = time.monotonic()
        step, total, label = self.phase_info(mode, name)
        if self.is_active():
            with self.state_lock:
                self.stage = name
                self.stage_label = label
                self.stage_step = step
                self.stage_total = total
                self.stage_started = started
        return started, step, total, label

    def set_stage_label(self, text):
        """Update the operator-facing stage label for status polling."""
        if not self.is_active():
            return
        with self.state_lock:
            self.stage_label = str(text or "")

    def finish_phase(self, mode, name, label):
        """Mark a phase complete for status polling."""
        if not self.is_active():
            return
        with self.state_lock:
            self.stage = "{} finished".format(name)
            self.stage_label = "{} finished".format(label)
            self.stage_started = time.monotonic()

    def is_active(self):
        """Return True when a derived writer owns the coordinator."""
        with self.state_lock:
            return bool(self.started)


derived_refresh = DerivedRefreshCoordinator(DERIVED_REFRESH_PHASES)


# Flask serves the static dashboard. The browser uses a local Server-Sent Events
# stream for live updates; Socket.IO remains available for compatibility with
# older clients. Collectors run on an asyncio loop in a background thread so the
# Flask request thread is not blocked by scans.
app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")
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
    "alerts": AlertEngine(),
    "findings": FindingsEngine(),
    "tasks_by_key": {},
    "task_names": {},
    "event_log": deque(maxlen=100),
    "live_observations": {"wifi_aps": {}, "bluetooth": {}, "lan": {}},
    "live_observations_lock": threading.Lock(),
    "sse_clients": [],
    "shutting_down": False,
    "subject_history": None,
    "device_history": None,
    "device_history_update_lock": threading.Lock(),
    "device_history_worker_thread": None,
    "history_analysis": None,
    "findings_history": None,
    "reports": None,
    "derived_cache_lock": threading.RLock(),
    "web_servers": [],
    "push_executor": None,
    "internet_status": None,
}

RTL_SDR_EXCLUSIVE_COLLECTORS = {"rtl433", "adsb"}


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
    heartbeat_sec = runtime_int("sse_heartbeat_sec", 15, minimum=1)
    logging.info(
        "SSE client connected active_clients=%s heartbeat_sec=%s",
        len(runtime["sse_clients"]),
        heartbeat_sec,
    )

    # A new browser needs the same initial snapshots that the old Socket.IO
    # connect handler sent. Queue them before the generator starts yielding.
    enqueue_sse(
        client,
        "collector_status",
        collector_statuses(),
    )
    enqueue_sse(client, "system_status", system_status())
    enqueue_sse(client, "alerts_snapshot", runtime["alerts"].snapshot())
    enqueue_sse(client, "findings_snapshot", runtime["findings"].snapshot())
    enqueue_sse(client, "lan_snapshot", live_lan_snapshot())
    for event in recent_poll_feed_events():
        enqueue_sse(client, "skannr_event", event)
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
            yield "retry: 3000\n: connected\n\n"
            while True:
                try:
                    name, payload = client.get(timeout=heartbeat_sec)
                except queue.Empty:
                    yield ": heartbeat\n\n"
                    continue
                yield format_sse(name, payload)
        finally:
            try:
                runtime["sse_clients"].remove(client)
            except ValueError:
                pass
            logging.info(
                "SSE client disconnected active_clients=%s",
                len(runtime["sse_clients"]),
            )

    return Response(
        stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/collector_control", methods=["POST"])
def collector_control():
    """Receive Start/Stop clicks from the local browser UI."""
    on_collector_control(request.get_json(silent=True) or {})
    return {"ok": True}


@app.route("/alerts/ack", methods=["POST"])
def alerts_ack():
    """Acknowledge one active alert and refresh connected dashboards."""
    payload = request.get_json(silent=True) or {}
    alert_id = payload.get("id")
    if not alert_id:
        return {"ok": False, "error": "missing alert id"}, 400
    acked = runtime["alerts"].ack(alert_id)
    save_alert_state(force=True)
    alerts = runtime["alerts"].snapshot()
    broadcast("alerts_snapshot", alerts)
    return {"ok": True, "acked": bool(acked), "alert": acked, "alerts": alerts}


@app.route("/alerts/ack_all", methods=["POST"])
def alerts_ack_all():
    """Acknowledge every active alert and refresh connected dashboards."""
    count = runtime["alerts"].ack_all()
    save_alert_state(force=True)
    alerts = runtime["alerts"].snapshot()
    broadcast("alerts_snapshot", alerts)
    return {"ok": True, "acked": count, "alerts": alerts}


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


@app.route("/lan_identify", methods=["POST"])
def lan_identify():
    """Queue one active LAN service/HTTP identification probe."""
    payload = request.get_json(silent=True) or {}
    target = payload.get("target") or payload.get("ip")
    mac = payload.get("mac") or ""
    subject_key = payload.get("subject_key") or ""
    timeout = payload.get("timeout_sec")
    loop = runtime.get("loop")
    action = action_by_key("lan_identify")
    if not loop or not action:
        return {
            "ok": False,
            "error": "LAN Identify action is not available",
        }, 503
    if not target:
        return {"ok": False, "error": "Missing LAN IP address"}, 400
    asyncio.run_coroutine_threadsafe(
        action.identify(target, mac, subject_key, timeout), loop
    )
    return {"ok": True}


@app.route("/llm/analyze", methods=["POST"])
def llm_analyze():
    """Run LLM analysis on one subject detail record."""
    payload = request.get_json(silent=True) or {}
    subject_key = str(payload.get("subject_key") or "").strip()
    subject_type = str(payload.get("subject_type") or "").strip()
    loop = runtime.get("loop")
    action = action_by_key("llm")
    if not loop or not action:
        return {"ok": False, "error": "LLM is not available"}, 503
    if not subject_key:
        return {"ok": False, "error": "Missing subject_key"}, 400
    future = asyncio.run_coroutine_threadsafe(
        action.analyze(subject_key, subject_type), loop
    )
    try:
        result = future.result(timeout=120)
    except Exception as exc:
        return {"ok": False, "error": "LLM call failed: {}".format(exc)}, 500
    if not result or "error" in (result or {}):
        return {"ok": False, "error": (result or {}).get("error", "Unknown")}, 500
    return {"ok": True, "answer": result["answer"], "usage": result["usage"]}


@app.route("/llm/generate-skir", methods=["POST"])
def llm_generate_skir():
    """Generate a Skannr Intelligence Report from the current report bundle."""
    loop = runtime.get("loop")
    action = action_by_key("llm")
    if not loop or not action:
        return {"ok": False, "error": "LLM is not available"}, 503
    config = runtime.get("config") or {}
    llm_config = (config.get("collectors") or {}).get("llm") or {}
    if not llm_config.get("generate_skir"):
        return {"ok": False, "error": "SKIR generation is not enabled"}, 400
    future = asyncio.run_coroutine_threadsafe(action.generate_skir(), loop)
    try:
        result = future.result(timeout=300)
    except TimeoutError:
        return {"ok": False, "error": "SKIR generation timed out after 300s"}, 500
    except Exception as exc:
        logging.exception("SKIR generation failed")
        return {"ok": False, "error": "SKIR generation failed: {}".format(exc)}, 500
    if not result or "error" in (result or {}):
        return {"ok": False, "error": (result or {}).get("error", "Unknown")}, 500
    return {"ok": True, "skir": result}


@app.route("/llm/skir/latest", methods=["GET"])
def llm_skir_latest():
    """Return the most recently generated SKIR from disk."""
    from .collectors.llm import LLMCollector

    config = runtime.get("config") or {}
    llm_config = (config.get("collectors") or {}).get("llm") or {}
    if not llm_config.get("generate_skir"):
        return {"ok": False, "error": "SKIR is not enabled"}, 404
    log_dir = configured_log_dir()
    skir = LLMCollector.load_latest_skir(log_dir)
    if skir is None:
        return {"ok": False, "error": "No SKIR available"}, 404
    return {"ok": True, "skir": skir}


@app.route("/llm/skir/list", methods=["GET"])
def llm_skir_list():
    """Return a list of available SKIR reports with metadata."""
    from .collectors.llm import LLMCollector

    config = runtime.get("config") or {}
    llm_config = (config.get("collectors") or {}).get("llm") or {}
    if not llm_config.get("generate_skir"):
        return {"ok": False, "error": "SKIR is not enabled"}, 404
    log_dir = configured_log_dir()
    items = LLMCollector.list_skirs(log_dir)
    return {"ok": True, "skirs": items}


@app.route("/llm/skir/<report_id>", methods=["GET"])
def llm_skir_by_id(report_id):
    """Return a specific SKIR by its report_id."""
    from .collectors.llm import LLMCollector

    config = runtime.get("config") or {}
    llm_config = (config.get("collectors") or {}).get("llm") or {}
    if not llm_config.get("generate_skir"):
        return {"ok": False, "error": "SKIR is not enabled"}, 404
    log_dir = configured_log_dir()
    skir = LLMCollector.load_skir_by_id(log_dir, report_id)
    if skir is None:
        return {"ok": False, "error": "SKIR not found"}, 404
    return {"ok": True, "skir": skir}


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
    """Return dashboard defaults after applying config/skannr.yaml and retention."""
    config = runtime.get("config") or {}
    llm_cfg = (config.get("collectors") or {}).get("llm") or {}
    return {
        "version": APP_VERSION,
        "active": "default",
        "options": view_window_options(config),
        "ui": config.get("ui", {}),
        "collectors": {
            "rtl433": {
                "frequency_plan": config.get("collectors", {})
                .get("rtl433", {})
                .get("frequency_plan"),
            },
        },
        "bluetooth_uuid_names": bluetooth_uuid_names(),
        "skir_enabled": bool(llm_cfg.get("enabled") and llm_cfg.get("generate_skir")),
    }


@app.route("/ui_debug", methods=["POST"])
def ui_debug():
    """Record low-volume browser diagnostics in the Skannr log."""
    payload = request.get_json(silent=True) or {}
    logging.info(
        "ui_debug client=%s event=%s detail=%s",
        payload.get("client_id") or "unknown",
        payload.get("event") or "unknown",
        payload.get("detail") or {},
    )
    return {"ok": True}


_BLUETOOTH_UUID_NAMES_CACHE = None


def bluetooth_uuid_names():
    """Load optional offline Bluetooth UUID names for browser decoding.

    Company identifiers are manufacturer-data IDs and are handled by the BLE
    collector. This lookup covers Bluetooth UUID assigned-number files such as
    member_uuids.txt, where values like 0xFEAF identify a vendor/member UUID
    advertised in the service UUID list. It also accepts Bluetooth classic
    service class files so older/common 16-bit service UUIDs like 0x110A can
    be resolved in the BLE UI.

    Results are cached for the process lifetime.  The source files are
    small (~36 KB total) and do not change at runtime.
    """
    global _BLUETOOTH_UUID_NAMES_CACHE
    if _BLUETOOTH_UUID_NAMES_CACHE is not None:
        return _BLUETOOTH_UUID_NAMES_CACHE
    names = {}
    directories = (DATA_COLLECTORS_DIR, CONFIG_COLLECTORS_DIR)
    for basename in (
        "member_uuids",
        "service_uuids",
        "service_class",
        "characteristic_uuids",
    ):
        for directory in directories:
            for extension in (".txt", ".yaml", ".yml"):
                path = os.path.join(directory, "{}{}".format(basename, extension))
                file_names = load_bluetooth_uuid_file(path)
                for key, value in file_names.items():
                    if key in names and names[key] != value:
                        logging.warning(
                            "Bluetooth UUID collision: key=%s existing=%r "
                            "incoming=%r file=%s",
                            key,
                            names[key],
                            value,
                            path,
                        )
                    names[key] = value
    _BLUETOOTH_UUID_NAMES_CACHE = names
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
    """Fallback parser for copied SIG text in YAML-like or flat-text formats."""
    names = {}
    current_uuid = None
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        flat_match = re.match(
            r"^(0x[0-9a-fA-F]+|[0-9a-fA-F]{4})\s+(.+?)\s*$",
            stripped,
        )
        if flat_match:
            short_id = normalize_bluetooth_uuid_key(flat_match.group(1))
            name = flat_match.group(2).strip()
            if short_id and name:
                names[short_id] = name
            current_uuid = None
            continue
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
    started = time.monotonic()
    try:
        return json_response(callback(), route_started=started)
    except Exception as exc:
        logging.exception("derived-data request failed")
        return json_response(
            {"ok": False, "error": str(exc)}, status=500, route_started=started
        )


def json_response(payload, status=200, route_started=None):
    """Return JSON with response-size timing and optional gzip compression."""
    serialize_started = time.monotonic()
    body = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    serialize_elapsed = time.monotonic() - serialize_started
    raw_bytes = len(body)
    gzip_elapsed = 0
    encoding = "identity"
    wire_body = body
    accept_encoding = request.headers.get("Accept-Encoding", "").lower()
    if "gzip" in accept_encoding and raw_bytes >= 1024:
        gzip_started = time.monotonic()
        wire_body = gzip.compress(body)
        gzip_elapsed = time.monotonic() - gzip_started
        encoding = "gzip"
    response = Response(wire_body, status=status, mimetype="application/json")
    response.headers["Content-Length"] = str(len(wire_body))
    response.headers["X-Skannr-Json-Bytes"] = str(raw_bytes)
    if encoding == "gzip":
        response.headers["Content-Encoding"] = "gzip"
        response.headers["Vary"] = "Accept-Encoding"
    logging.info(
        "%s response status=%s json_bytes=%s wire_bytes=%s encoding=%s "
        "serialize=%.2fs gzip=%.2fs route_elapsed=%.2fs",
        request.path,
        status,
        raw_bytes,
        len(wire_body),
        encoding,
        serialize_elapsed,
        gzip_elapsed,
        time.monotonic() - route_started if route_started else 0,
    )
    return response


@app.route("/device_history", methods=["GET"])
def device_history():
    """Return the last on-demand device-history summary."""
    window_days = requested_window_days()
    return derived_bundle_section("device_history", window_days)


@app.route("/subject_history", methods=["GET"])
def subject_history():
    """Return normalized collector subjects for the selected view window."""
    window_days = requested_window_days()
    return derived_bundle_section("subject_history", window_days)


@app.route("/subject_annotations", methods=["POST"])
def subject_annotations_update():
    """Create, update, or delete one durable subject annotation."""
    payload = request.get_json(silent=True) or {}
    collector = str(payload.get("collector") or "").strip().lower()
    subject_type = str(payload.get("subject_type") or "").strip().lower()
    subject_id = str(payload.get("subject_id") or "").strip()
    custom_name = str(payload.get("custom_name") or "").strip()[:160]
    operator_owned = bool(payload.get("operator_owned"))
    if not subject_id or not subject_annotation_allowed(collector, subject_type):
        return json_response(
            {"ok": False, "error": "Subject type does not support annotations"},
            status=400,
        )
    annotations = load_subject_annotations()
    key = subject_annotation_key(collector, subject_type, subject_id)
    if custom_name or operator_owned:
        updated_epoch = now_epoch()
        annotations[key] = {
            "collector": collector,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "custom_name": custom_name,
            "operator_owned": operator_owned,
            "updated_at": local_now(updated_epoch),
            "updated_at_epoch": updated_epoch,
        }
    else:
        annotations.pop(key, None)
    try:
        save_subject_annotations(annotations)
        persist_subject_annotation_overlays(annotations)
    except OSError as exc:
        logging.exception("failed to persist subject annotation: %s", exc)
        return json_response({"ok": False, "error": str(exc)}, status=500)
    logging.info(
        "subject annotation updated key=%s state_path=%s",
        key,
        subject_annotations_path(),
    )
    with runtime["derived_cache_lock"]:
        if runtime["subject_history"] is not None:
            runtime["subject_history"] = apply_subject_annotations(
                runtime["subject_history"]
            )
        if runtime["device_history"] is not None:
            runtime["device_history"] = apply_subject_annotations(
                runtime["device_history"]
            )
        if runtime["reports"] is not None:
            runtime["reports"] = apply_report_annotations(runtime["reports"])
    return json_response(
        {
            "ok": True,
            "key": key,
            "annotation": annotations.get(key),
            "state_path": subject_annotations_path(),
        }
    )


@app.route("/subject_history/refresh", methods=["POST"])
def subject_history_refresh():
    """Compatibility route: refresh the full derived-data bundle."""
    return derived_response(
        lambda: build_derived_views(requested_window_days(), force=True)[
            "subject_history"
        ]
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


@app.route("/derived_views/status", methods=["GET"])
def derived_views_status():
    """Return current derived-refresh progress for UI/debug status strips."""
    return derived_refresh.status()


@app.route("/derived_views/ack", methods=["POST"])
def derived_views_ack():
    """Record that one browser finished rendering a derived bundle."""
    payload = request.get_json(silent=True) or {}
    logging.info(
        "derived ack client=%s window=%s generated_at=%s sections=%s",
        payload.get("client_id") or "unknown",
        payload.get("window") or "",
        payload.get("generated_at") or "",
        payload.get("sections") or {},
    )
    return {"ok": True}


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
    """Compatibility route for the retired persisted Findings History view."""
    window_days = requested_window_days()
    return empty_findings_history(window_days)


@app.route("/findings_history/refresh", methods=["POST"])
def findings_history_refresh():
    """Compatibility route: refresh the bundle but keep Findings History empty."""

    def refresh_and_return_empty():
        build_derived_views(requested_window_days(), force=True)
        return empty_findings_history(requested_window_days())

    return derived_response(refresh_and_return_empty)


@app.route("/history_analysis", methods=["GET"])
def history_analysis():
    """Return the last on-demand history-analysis snapshot."""
    window_days = requested_window_days()
    return derived_bundle_section("history_analysis", window_days)


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
    return derived_bundle_section("reports", window_days)


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
        collector_statuses(),
    )
    socketio.emit("system_status", system_status())
    socketio.emit("alerts_snapshot", runtime["alerts"].snapshot())
    socketio.emit("findings_snapshot", runtime["findings"].snapshot())
    socketio.emit("lan_snapshot", live_lan_snapshot())
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
        overrides = collector_start_overrides(key, (message or {}).get("overrides"))
        asyncio.run_coroutine_threadsafe(start_collector(key, overrides), loop)


def collector_start_overrides(key, raw):
    """Return whitelisted one-shot runtime config overrides for Start clicks."""
    if not isinstance(raw, dict):
        return {}
    if key == "rtl433":
        value = raw.get("frequency_plan")
        if value in (None, ""):
            return {}
        return {"frequency_plan": str(value).strip()}
    return {}


def collector_by_key(key):
    """Return the active collector object for a config key."""
    for collector in runtime.get("collectors") or []:
        if collector.config_key == key:
            return collector
    return None


def collector_statuses():
    """Return enabled collector status plus disabled configured rows."""
    config = runtime.get("config") or {}
    statuses = [collector.status() for collector in runtime.get("collectors") or []]
    seen = {status.get("key") for status in statuses}
    for status in disabled_collector_statuses(config):
        if status.get("key") not in seen:
            statuses.append(status)
    order = {
        key: index
        for index, key in enumerate(collector_keys(config, include_system=False))
    }
    return sorted(
        statuses,
        key=lambda item: (order.get(item.get("key"), 999), item.get("key") or ""),
    )


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
    try:
        socketio.emit(name, payload)
    except Exception as exc:
        logging.exception("Socket.IO broadcast failed event=%s: %s", name, exc)
    for client in list(runtime["sse_clients"]):
        try:
            enqueue_sse(client, name, payload)
        except Exception as exc:
            logging.exception("SSE enqueue failed event=%s: %s", name, exc)


def event_log_context(event):
    """Return compact event identity for exception logs."""
    data = event.get("data") if isinstance(event, dict) else None
    data_keys = sorted(data.keys())[:20] if isinstance(data, dict) else []
    return {
        "collector": event.get("collector") if isinstance(event, dict) else None,
        "type": event.get("type") if isinstance(event, dict) else None,
        "timestamp": event.get("timestamp") if isinstance(event, dict) else None,
        "data_keys": data_keys,
    }


def process_bus_event(event):
    """Persist, analyze, and publish one collector event."""
    persistence = runtime.get("persistence")
    # Periodic status/channel-hop events are derived state. Persisting every
    # copy would bury the useful radio/BLE/Wi-Fi observations.
    high_rate_state_event = (
        (event.get("collector") == "system" and event.get("type") == "system_status")
        or (
            event.get("collector") == "aprsis"
            and event.get("type") == "collector_status"
        )
        or (
            event.get("collector") == "wifi_monitor"
            and event.get("type") == "monitor_channel_changed"
        )
        or (
            event.get("collector") == "rtl433"
            and event.get("type") == "scanner_frequency"
        )
    )
    if persistence and not high_rate_state_event:
        try:
            persistence.write(event)
        except Exception as exc:
            logging.exception("failed to persist event: %s", exc)
    record_live_observation(event)
    runtime["event_log"].appendleft(event)
    broadcast("skannr_event", event)
    try:
        alert_events = runtime["alerts"].process(event)
    except Exception as exc:
        logging.exception("alert processing failed: %s", exc)
        alert_events = []
    for alert_event in alert_events:
        if persistence:
            try:
                persistence.write(alert_event)
            except Exception as exc:
                logging.exception("failed to persist alert: %s", exc)
        submit_alert_notification(alert_event)
        broadcast("skannr_event", alert_event)
        broadcast("alerts_snapshot", runtime["alerts"].snapshot())
    save_alert_state()
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
        collector_statuses(),
    )
    broadcast("system_status", system_status())


def submit_alert_notification(alert_event):
    """Submit optional external notification delivery for a new alert."""
    alert = (alert_event or {}).get("data") or {}
    if alert.get("emit_reason") not in ("new", "escalated"):
        return
    pushover_config = ((runtime.get("config") or {}).get("alerts") or {}).get(
        "pushover"
    ) or {}
    if not pushover_enabled(pushover_config):
        return
    executor = runtime.get("push_executor")
    if not executor:
        logging.warning("Pushover alert delivery skipped: worker is not running")
        return
    executor.submit(deliver_pushover_alert, dict(alert), dict(pushover_config))


def deliver_pushover_alert(alert, pushover_config):
    """Run Pushover delivery in a worker thread."""
    try:
        send_pushover_alert(alert, pushover_config)
    except Exception as exc:
        logging.warning("Pushover alert delivery failed: %s", exc)


async def consume_events(bus):
    """Fan out collector events to persistence and all connected browsers."""
    while True:
        event = await bus.next()
        try:
            process_bus_event(event)
        except Exception as exc:
            logging.exception(
                "event fan-out failed event=%s: %s",
                event_log_context(event),
                exc,
            )


def recent_poll_feed_events():
    """Return recent poll-feed events that should hydrate live feed tables."""
    events = []
    for event in reversed(list(runtime.get("event_log") or [])):
        collector = event.get("collector") if isinstance(event, dict) else None
        event_type = event.get("type") if isinstance(event, dict) else None
        if event_type in POLL_FEED_REPLAY_TYPES.get(collector, set()):
            events.append(event)
    return events


def runtime_task_done(task):
    """Log unexpected exits from collector and runtime background tasks."""
    name = runtime["task_names"].pop(task, "background task")
    collector_key = task_key_for_task(task)
    if runtime.get("shutting_down"):
        return
    if task.cancelled():
        logging.info("background task cancelled name=%s", name)
        return
    exc = task.exception()
    if exc:
        logging.error(
            "background task failed name=%s",
            name,
            exc_info=(type(exc), exc, exc.__traceback__),
        )
    else:
        collector = collector_by_key(collector_key) if collector_key else None
        if collector:
            logging.warning(
                "background task exited name=%s state=%s warning=%s",
                name,
                collector.state,
                collector.warning,
            )
        else:
            logging.warning("background task exited unexpectedly name=%s", name)


def track_runtime_task(task, name, key=None):
    """Register a background task so silent collector exits are visible."""
    runtime["task_names"][task] = name
    runtime["tasks"].append(task)
    if key:
        runtime["tasks_by_key"][key] = task
    task.add_done_callback(runtime_task_done)
    return task


def task_key_for_task(task):
    """Return the collector key registered for one runtime task."""
    for key, item in (runtime.get("tasks_by_key") or {}).items():
        if item is task:
            return key
    return None


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
        if collector.config_key in RTL_SDR_EXCLUSIVE_COLLECTORS:
            await handoff_rtl_sdr_collectors(collector)
        # Python 3.6 lacks asyncio.create_task(), so use the loop method for Pi
        # installations that still run older system Python.
        track_runtime_task(
            loop.create_task(collector.start()),
            "collector:{}".format(collector.config_key),
            collector.config_key,
        )
    # One task consumes the bus and pushes to browsers; another sends periodic
    # system snapshots so static probe status stays fresh.
    track_runtime_task(loop.create_task(consume_events(bus)), "event fan-out")
    track_runtime_task(
        loop.create_task(publish_system_status(bus)),
        "system status publisher",
    )
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


async def start_collector(key, overrides=None):
    """Restart one collector after the user clicks Start in the dashboard."""
    loop = asyncio.get_event_loop()
    for collector in runtime["collectors"]:
        if collector.config_key != key:
            continue
        task = runtime["tasks_by_key"].get(key)
        # Avoid starting duplicate scanner loops for the same adapter/interface.
        if task and not task.done():
            if not overrides:
                await runtime["bus"].publish(
                    {
                        "collector": "system",
                        "type": "collector_already_running",
                        "data": collector.status(),
                    }
                )
                return
            await collector.stop()
            if not task.done():
                task.cancel()
            await runtime["bus"].publish(
                {
                    "collector": "system",
                    "type": "collector_restarting",
                    "data": collector.status(),
                }
            )
        if overrides:
            collector.config.update(overrides)
            update_runtime_collector_config(key, overrides, collector)
        if key in RTL_SDR_EXCLUSIVE_COLLECTORS:
            await handoff_rtl_sdr_collectors(collector)
        track_runtime_task(
            loop.create_task(collector.start()),
            "collector:{}".format(key),
            key,
        )
        await runtime["bus"].publish(
            {
                "collector": "system",
                "type": "collector_started",
                "data": collector.status(),
            }
        )
        return


def update_runtime_collector_config(key, overrides, collector):
    """Keep status/metadata aligned with one-shot UI collector overrides."""
    if not overrides:
        return
    config = runtime.get("config") or {}
    collectors = config.setdefault("collectors", {})
    section = collectors.setdefault(key, {})
    section.update(overrides)
    hardware = config.setdefault("hardware", {})
    try:
        hardware[key] = collector.__class__.hardware_status(collector.config)
    except Exception:
        pass


async def handoff_rtl_sdr_collectors(target):
    """Stop active RTL-SDR-backed collectors that claim the same device."""
    target_key = target.config_key
    target_device = rtl_sdr_ownership_key(target_key, target.config)
    if not target_device:
        return
    for collector in runtime.get("collectors") or []:
        key = collector.config_key
        if key == target_key or key not in RTL_SDR_EXCLUSIVE_COLLECTORS:
            continue
        if rtl_sdr_ownership_key(key, collector.config) != target_device:
            continue
        task = runtime["tasks_by_key"].get(key)
        if not task or task.done():
            continue
        await collector.stop()
        if not task.done():
            task.cancel()
        collector.state = "OFFLINE"
        collector.warning = "RTL-SDR handed to {}".format(collector_label(target_key))
        await runtime["bus"].publish(
            {
                "collector": key,
                "type": "collector_offline",
                "severity": "warning",
                "data": {
                    "reason": collector.warning,
                    "handoff_to": target_key,
                    "rtl_sdr_device": target_device,
                },
            }
        )
        await runtime["bus"].publish(
            {
                "collector": "system",
                "type": "collector_stopped",
                "data": collector.status(),
            }
        )


ADSB_DECODER_COMMANDS = (
    "dump1090-mutability",
    "dump1090-fa",
    "dump1090",
    "readsb",
)


def rtl_sdr_ownership_key(key, config):
    """Return the local RTL-SDR device claimed by this collector, if any."""
    if key not in RTL_SDR_EXCLUSIVE_COLLECTORS:
        return None
    if key == "adsb":
        if not bool(config.get("manage_decoder", True)):
            return None
        if str(config.get("url") or "").strip():
            return None
        if not adsb_decoder_available(config):
            return None
    if key == "rtl433" and not rtl433_decoder_available(config):
        return None
    return "index {}".format(config.get("device_index", 0))


def adsb_decoder_available(config):
    """Return True when managed ADS-B can start a local decoder process."""
    configured = str(config.get("decoder_command") or "").strip()
    if configured and shutil.which(configured):
        return True
    return any(shutil.which(candidate) for candidate in ADSB_DECODER_COMMANDS)


def rtl433_decoder_available(config):
    """Return True when RTL-433 can start its local decoder process."""
    configured = str(config.get("command") or "").strip()
    if configured and shutil.which(configured):
        return True
    return bool(shutil.which("rtl_433"))


def collector_label(key):
    """Return operator-facing collector label from metadata/config."""
    for item in collector_definitions(
        runtime.get("config") or {}, include_system=False
    ):
        if item.get("key") == key:
            return item.get("label") or key
    return key


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
    config = runtime.get("config") or {}
    return {
        "hardware": config.get("hardware", {}),
        "internet": cached_internet_status(),
    }


def cached_internet_status():
    """Return a cached generic internet connectivity status."""
    now = now_epoch()
    cached = runtime.get("internet_status") or {}
    if now - float(cached.get("checked_at_epoch") or 0) < 60:
        return cached
    online = internet_available(timeout=1.5)
    status = {
        "online": online,
        "state": "ONLINE" if online else "OFFLINE",
        "checked_at": local_now(now),
        "checked_at_epoch": now,
    }
    runtime["internet_status"] = status
    return status


def record_live_observation(event):
    """Keep backend live scan state in step with the browser event stream.

    Device History is built from durable JSONL logs, but the live scan tabs are
    fed directly from this same event stream. Keeping a small latest-observation
    map here prevents Reports/Device History from publishing stale last_seen
    values when the materialized checkpoint falls behind the live stream.
    """
    if not isinstance(event, dict):
        return
    collector = event.get("collector")
    event_type = event.get("type")
    data = event.get("data") or {}
    timestamp_epoch_value = record_time_epoch(event, "timestamp")
    if timestamp_epoch_value is None:
        timestamp_epoch_value = timestamp_epoch(event.get("timestamp_epoch"))
    if timestamp_epoch_value is None:
        timestamp_epoch_value = now_epoch()
    timestamp = event.get("timestamp") or local_now(timestamp_epoch_value)
    if collector == "wifi" and event_type == "ap_beacon":
        bssid = normalized_identity(data.get("bssid"))
        if not bssid:
            return
        observation = {
            "bssid": bssid,
            "ssid": data.get("ssid") or "",
            "vendor_name": data.get("vendor_name") or "",
            "vendor_prefix": data.get("vendor_prefix") or "",
            "last_seen": timestamp,
            "last_seen_epoch": timestamp_epoch_value,
            "signal_latest": data.get("rssi"),
            "channel": data.get("channel"),
            "encryption": data.get("encryption"),
        }
        with runtime["live_observations_lock"]:
            runtime["live_observations"]["wifi_aps"][bssid] = observation
            prune_live_observation_map(
                runtime["live_observations"]["wifi_aps"],
                live_observation_ttl_sec(),
                live_observation_max_items(),
            )
    elif collector in ("ble", "bt_classic") and event_type in (
        "device_seen",
        "device_updated",
        "device_lost",
        "classic_device_seen",
        "classic_device_updated",
        "classic_device_lost",
    ):
        mac = normalized_identity(data.get("mac"))
        if not mac:
            return
        observation = {
            "mac": mac,
            "name": data.get("name") or "",
            "manufacturer": data.get("manufacturer") or data.get("vendor_name") or "",
            "vendor_name": data.get("vendor_name") or "",
            "vendor_prefix": data.get("vendor_prefix") or "",
            "last_seen": timestamp,
            "last_seen_epoch": timestamp_epoch_value,
            "signal_latest": data.get("rssi"),
            "service_uuids": data.get("service_uuids") or [],
            "findmy_accessory": bool(data.get("findmy_accessory")),
            "findmy_label": data.get("findmy_label") or "",
            "findmy_payload_type": data.get("findmy_payload_type") or "",
            "findmy_status": data.get("findmy_status") or "",
            "findmy_hint": data.get("findmy_hint") or "",
        }
        with runtime["live_observations_lock"]:
            runtime["live_observations"]["bluetooth"][mac] = observation
            prune_live_observation_map(
                runtime["live_observations"]["bluetooth"],
                live_observation_ttl_sec(),
                live_observation_max_items(),
            )
    elif collector == "ble_identify" and event_type == "identify_result":
        mac = normalized_identity(data.get("mac"))
        if not mac:
            return
        observation = {
            "mac": mac,
            "manufacturer_name": data.get("manufacturer_name") or "",
            "model_number": data.get("model_number") or "",
            "serial_number": data.get("serial_number") or "",
            "firmware_revision": data.get("firmware_revision") or "",
            "hardware_revision": data.get("hardware_revision") or "",
            "software_revision": data.get("software_revision") or "",
            "pnp_id": data.get("pnp_id") or "",
            "last_seen": timestamp,
            "last_seen_epoch": timestamp_epoch_value,
        }
        with runtime["live_observations_lock"]:
            current = runtime["live_observations"]["bluetooth"].get(mac) or {}
            current.update({key: value for key, value in observation.items() if value})
            runtime["live_observations"]["bluetooth"][mac] = current
            prune_live_observation_map(
                runtime["live_observations"]["bluetooth"],
                live_observation_ttl_sec(),
                live_observation_max_items(),
            )
    elif collector == "lan" and event_type in (
        "lan_device_seen",
        "lan_device_changed",
        "lan_gateway_seen",
        "lan_gateway_changed",
    ):
        key = (
            normalized_identity(data.get("subject_key"))
            or normalized_identity(data.get("mac"))
            or normalized_identity(data.get("ip"))
            or normalized_identity(data.get("gateway_ip"))
        )
        if not key:
            return
        observation = dict(data)
        observation["event_type"] = event_type
        observation["last_seen"] = timestamp
        observation["last_seen_epoch"] = timestamp_epoch_value
        with runtime["live_observations_lock"]:
            runtime["live_observations"].setdefault("lan", {})[key] = observation
            prune_live_observation_map(
                runtime["live_observations"]["lan"],
                live_observation_ttl_sec(),
                live_observation_max_items(),
            )


def live_lan_snapshot():
    """Return current LAN live subjects for newly connected browsers."""
    with runtime["live_observations_lock"]:
        items = [
            dict(item)
            for item in (runtime["live_observations"].get("lan") or {}).values()
        ]
    return sorted(
        items,
        key=lambda item: timestamp_epoch(item.get("last_seen_epoch")) or 0,
        reverse=True,
    )


def normalized_identity(value):
    """Normalize a MAC/BSSID key for map lookup."""
    return str(value or "").strip().lower()


def live_observation_ttl_sec():
    """Return how long live observations should be retained for overlay."""
    return runtime_int("live_observation_ttl_sec", 3600, minimum=60)


def live_observation_max_items():
    """Return the max live observations retained per collector family."""
    return runtime_int("live_observation_max_items", 2000, minimum=100)


def prune_live_observation_map(observations, ttl_sec, max_items):
    """Bound backend live-overlay state by age and count."""
    if not observations:
        return
    cutoff = now_epoch() - ttl_sec
    for key, observation in list(observations.items()):
        epoch = timestamp_epoch((observation or {}).get("last_seen_epoch"))
        if epoch is not None and epoch < cutoff:
            observations.pop(key, None)
    if len(observations) <= max_items:
        return
    ordered = sorted(
        observations.items(),
        key=lambda item: timestamp_epoch((item[1] or {}).get("last_seen_epoch")) or 0,
        reverse=True,
    )
    keep = {key for key, _value in ordered[:max_items]}
    for key in list(observations):
        if key not in keep:
            observations.pop(key, None)


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
    with runtime["derived_cache_lock"]:
        if runtime.get(key) is None or not summary_matches_window(
            runtime.get(key), window_days
        ):
            runtime[key] = loader(window_days)
        return runtime[key]


def _cached_load(key, loader, window_days):
    """Load one cached summary and log its elapsed time.

    Unlike ``timed_derived_stage`` this does not touch the
    ``DerivedRefreshCoordinator`` — cached loads are invisible to the
    browser and should not publish phase progress.
    """
    started = time.monotonic()
    cached_derived_view(key, loader, window_days)
    logging.info(
        "derived cached load %s finished elapsed=%.2fs",
        key,
        time.monotonic() - started,
    )


def view_window_metadata(window_days):
    """Describe the selected log range in the same shape used by history."""
    return window_metadata(window_days)


def configured_log_dir():
    """Return the absolute filesystem persistence directory."""
    config = runtime.get("config") or {}
    persistence = config.get("persistence", {})
    filesystem = persistence.get("filesystem", {})
    log_dir = filesystem.get("log_dir", "runtime/logs")
    if os.path.isabs(log_dir):
        return log_dir
    project_dir = config.get("_project_dir") or os.getcwd()
    return os.path.abspath(os.path.join(project_dir, log_dir))


def read_findings_history(window_days):
    """Compatibility shim: retained findings logs are not a derived upstream."""
    return empty_findings_history(window_days)


def refresh_findings_history(window_days):
    """Compatibility shim: derived Insights now come from Subject History."""
    display = empty_findings_history(window_days)
    with runtime["derived_cache_lock"]:
        runtime["findings_history"] = display
    return display


LOW_VALUE_BLE_FINDING_TYPES = {
    "ble_device_new",
    "ble_device_returned",
    "ble_device_lost",
    "ble_device_strong",
    "ble_rssi_change",
}

LOW_VALUE_FINDING_TYPES = {
    # APRS packets are already available in the APRS-IS live feed and Subject
    # History. Insights keeps movement/weather interpretation instead.
    "aprs_object",
    "aprs_packet",
    "aprs_position",
    "aprs_status",
    "aprs_weather",
    # LAN subject changes are retained in Subject History and Reports. Emitting
    # one Insight per mDNS/source/interface update makes Insights read like a
    # raw LAN event log.
    "lan_device_changed",
    # Managed Wi-Fi scans see weak neighboring APs appear and disappear often.
    # The subject history/report layers keep that behavior; Insights should not
    # show every AP flap as a separate row.
    "wifi_ap_lost",
    "wifi_ap_returned",
}

WIFI_MONITOR_FINDING_FLAGS = {
    "wifi_client_new": "wifi_monitor_emit_client_new",
    "wifi_client_returned": "wifi_monitor_emit_client_returned",
    "wifi_client_lost": "wifi_monitor_emit_client_lost",
    "wifi_probe_blank_ssid": "wifi_monitor_emit_blank_probe",
    "wifi_randomized_mac": "wifi_monitor_emit_randomized_mac",
    "wifi_probe_burst": "wifi_monitor_emit_probe_burst",
    "wifi_client_strong": "wifi_monitor_emit_strong_client",
    "wifi_ap_new": "wifi_monitor_emit_ap_presence",
    "wifi_ap_strong": "wifi_monitor_emit_strong_ap",
}

LATEST_BY_KEY_FINDING_TYPES = {
    # These are current-state samples/status rows. Keep the newest row for the
    # subject and let transition/threshold finding types carry event meaning.
    "noaa_forecast_summary",
    "aprsis_weather_high_rain",
    "aprsis_weather_high_wind",
    "pws_weather",
    "pws_weather_high_rain",
    "pws_weather_high_wind",
    "rayhunter_status",
    "swpc_event",
    "usgs_earthquake",
    "wifi_ap_strong",
}


def filter_low_value_findings(findings):
    """Drop or coalesce low-value finding rows for the tactical Insights feed."""
    output = []
    latest_seen = set()
    for item in findings or []:
        if disabled_collector_finding(item):
            continue
        if low_value_finding(item):
            continue
        if low_value_ble_finding(item):
            continue
        if low_value_wifi_monitor_finding(item):
            continue
        sanitized = sanitize_rayhunter_finding(item)
        latest_key = latest_state_finding_key(sanitized)
        if latest_key:
            if latest_key in latest_seen:
                continue
            latest_seen.add(latest_key)
        output.append(sanitized)
    return output


def disabled_collector_finding(item):
    """Return true when a finding comes from a currently disabled collector."""
    if not isinstance(item, dict):
        return False
    source = str(item.get("source") or "").strip()
    if not source or source in ("system", "findings", "privacy"):
        return False
    collectors = (runtime.get("config") or {}).get("collectors") or {}
    section = collectors.get(source)
    return section is not None and not bool(section.get("enabled", True))


def enabled_subject_history_collectors():
    """Return collectors enabled for Subject History materialization."""
    collector_config = (runtime.get("config") or {}).get("collectors") or {}
    enabled = set()
    for collector in SubjectHistoryBuilder.COLLECTORS:
        section = collector_config.get(collector)
        if section is not None and bool(section.get("enabled", True)):
            enabled.add(collector)
    return enabled


def low_value_finding(item):
    """Return true for finding rows that are too routine for Insights."""
    if not isinstance(item, dict):
        return False
    return item.get("type") in LOW_VALUE_FINDING_TYPES


def latest_state_finding_key(item):
    """Return a de-duplication key for current-state findings."""
    if not isinstance(item, dict):
        return ""
    finding_type = item.get("type")
    if finding_type not in LATEST_BY_KEY_FINDING_TYPES:
        return ""
    return "{}:{}:{}".format(
        item.get("source") or "",
        finding_type or "",
        item.get("key") or item.get("title") or "",
    )


def low_value_ble_finding(item):
    """Return true for anonymous/manufacturer-only BLE live finding rows."""
    if not isinstance(item, dict) or item.get("source") != "ble":
        return False
    if item.get("type") not in LOW_VALUE_BLE_FINDING_TYPES:
        return False
    attributes = item.get("attributes") or {}
    mac = str(attributes.get("mac") or "").strip().lower().replace("-", ":")
    name = str(attributes.get("name") or "").strip()
    if name and name.lower().replace("-", ":") != mac:
        return False
    return True


def low_value_wifi_monitor_finding(item):
    """Return true for monitor-mode rows disabled by Wi-Fi Monitor finding knobs."""
    if not isinstance(item, dict) or item.get("source") != "wifi_monitor":
        return False
    flag = WIFI_MONITOR_FINDING_FLAGS.get(item.get("type"))
    if not flag:
        return False
    findings_config = (runtime.get("config") or {}).get("findings") or {}
    return not bool(findings_config.get(flag, False))


def sanitize_rayhunter_finding(item):
    """Prevent older Rayhunter page dumps from leaking into Insights."""
    if not isinstance(item, dict) or item.get("source") != "rayhunter":
        return item
    sanitized = dict(item)
    attributes = clean_rayhunter_data(sanitized.get("attributes") or {})
    detail = clean_rayhunter_field(sanitized.get("detail"), max_length=500)
    if not detail:
        warning_count = attributes.get("warning_count")
        try:
            warning_count = int(float(warning_count or 0))
        except (TypeError, ValueError):
            warning_count = 0
        if warning_count:
            detail = "Rayhunter reported {} warning(s).".format(warning_count)
        else:
            endpoint = attributes.get("endpoint") or "default"
            detail = "Rayhunter endpoint {} is reachable; 0 warnings".format(endpoint)
    sanitized["detail"] = detail
    sanitized["attributes"] = attributes
    return sanitized


def recent_history_for_insights(history, include_sessions=False, cutoff_epoch=None):
    """Return a shallow Device History copy limited to recent activity.

    Insights is a tactical recent-event feed. Analyzing thousands of retained
    old BLE privacy addresses just to filter their observations out afterward
    made refreshes slow without changing what the browser displays.

    When *include_sessions* is True, per-device session arrays are preserved
    so that cross-collector bundle correlation can use them.  Records are
    copied (top level) so analysis never aliases the cached Subject History.

    *cutoff_epoch* overrides the tactical Insights cutoff — bundle correlation
    passes a 24h lookback because multi-hour co-movement needs more history
    than the 60-minute tactical window.
    """
    cutoff = insights_recent_cutoff_epoch() if cutoff_epoch is None else cutoff_epoch
    if cutoff is None or not isinstance(history, dict):
        return history

    def recent_records(records, include_sessions=False):
        selected = []
        for record in records or []:
            last_seen = record_time_epoch(record, "last_seen")
            if last_seen is None or last_seen < cutoff:
                continue
            if include_sessions:
                selected.append(dict(record))
            else:
                # Insights is not the recurring-presence report. Reports keeps
                # the full session history; the tactical feed only needs the
                # current record fields to evaluate recent signal/state rules.
                compact = dict(record)
                compact["sessions"] = []
                selected.append(compact)
        return selected

    output = dict(history)
    wifi = history.get("wifi") or {}
    bluetooth = history.get("bluetooth") or history.get("ble") or {}
    output["wifi"] = {
        "access_points": recent_records(
            wifi.get("access_points") or [],
            include_sessions=include_sessions),
        "clients": recent_records(
            wifi.get("clients") or [],
            include_sessions=include_sessions),
    }
    output["bluetooth"] = {
        "devices": recent_records(
            bluetooth.get("devices") or [],
            include_sessions=include_sessions),
    }
    output["ble"] = {"devices": output["bluetooth"]["devices"]}
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


def insights_recent_minutes():
    """Return the configured tactical Insights window in minutes."""
    config = runtime.get("config") or {}
    analysis_config = config.get("history_analysis") or {}
    if "insights_recent_minutes" in analysis_config:
        value = analysis_config.get("insights_recent_minutes")
        multiplier = 1
    else:
        value = analysis_config.get("insights_recent_hours", 6)
        multiplier = 60
    try:
        minutes = float(value) * multiplier
    except (TypeError, ValueError):
        minutes = 360
    return minutes


def insights_recent_cutoff_epoch():
    """Return the configured Insights cutoff epoch, or None for no cutoff."""
    minutes = insights_recent_minutes()
    if minutes <= 0:
        return None
    return now_epoch() - int(minutes * 60)


def insights_recent_window_metadata():
    """Describe the short tactical window used by the Insights tab."""
    minutes = insights_recent_minutes()
    if minutes <= 0:
        return {"minutes": None, "hours": None, "label": "All insight events"}
    hours = minutes / 60.0
    if minutes < 120:
        label_value = int(minutes) if float(minutes).is_integer() else minutes
        return {
            "minutes": minutes,
            "hours": hours,
            "label": "Recent {} minutes".format(label_value),
        }
    label_value = int(hours) if float(hours).is_integer() else round(hours, 2)
    return {
        "minutes": minutes,
        "hours": hours,
        "label": "Recent {} hours".format(label_value),
    }


def build_derived_views(window_days="default", force=False):
    """Build derived views with one refresh writer at a time."""
    window_days = resolve_window_days(window_days)
    if not force:
        return build_derived_views_unlocked(window_days, force=False)

    started, status = derived_refresh.try_start(window_days)
    if not started:
        logging.info(
            "derived refresh request joined active refresh; "
            "window=%s elapsed=%.1fs phase=%s/%s stage=%s",
            status.get("window"),
            status.get("elapsed_sec", 0),
            status.get("phase_step") or "?",
            status.get("phase_total") or "?",
            status.get("stage") or "unknown",
        )
        return {
            "ok": True,
            "refresh_in_progress": True,
            "status": status,
        }
    success = False
    error = ""
    try:
        result = build_derived_views_unlocked(window_days, force=True)
        success = True
        return result
    except Exception as exc:
        error = str(exc)
        raise
    finally:
        derived_refresh.finish(window_days, success=success, error=error)


def active_derived_operation_response():
    """Return the standard join response for an active backend derived writer."""
    return {
        "ok": True,
        "refresh_in_progress": True,
        "status": derived_refresh.status(),
    }


def derived_bundle_section(section, window_days):
    """Return one section from the coherent derived bundle or active status."""
    bundle = build_derived_views(window_days, force=False)
    if bundle.get("refresh_in_progress"):
        return bundle
    return bundle[section]


def build_derived_views_unlocked(window_days="default", force=False):
    """Build or return one consistent derived-data bundle.

    A normal page load must be cheap: it reads persisted summaries or returns
    empty placeholders. The Refresh button is the explicit materialization path
    that folds in only JSONL bytes not already covered by saved checkpoints.
    """
    window_days = resolve_window_days(window_days)
    started = time.monotonic()
    mode = "refresh" if force else "cached"
    logging.info("derived views %s started; window=%s", mode, window_days)
    if force:
        reuse_response = reuse_recent_refresh_for_small_delta(window_days)
        if reuse_response is not None:
            logging.info(
                "derived views refresh reused recent cached bundle; window=%s elapsed=%.2fs",
                window_days,
                time.monotonic() - started,
            )
            return reuse_response
        # Subject History is the durable dependency for both Insights analysis
        # and Reports. Live findings are runtime-only and are not reloaded from
        # retained findings JSONL during derived refresh.
        run_parallel_derived_stages(
            "refresh_base",
            [
                (
                    "subject_history",
                    lambda: refresh_subject_history(window_days),
                ),
            ],
        )
        run_parallel_derived_stages(
            "refresh_derived",
            [
                ("history_analysis", lambda: refresh_history_analysis(window_days)),
                ("reports", lambda: refresh_reports(window_days)),
            ],
        )
    else:
        _cached_load("subject_history", load_cached_subject_history, window_days)
        _cached_load("device_history", load_cached_device_history, window_days)
        _cached_load("history_analysis", load_cached_history_analysis, window_days)
        _cached_load("reports", load_cached_reports, window_days)
        refresh_pending_raw_logs(window_days)
        if not derived_refresh.is_active():
            repair_response = refresh_stale_cached_dependents(window_days)
            if repair_response:
                return repair_response
    bundle = build_cached_derived_bundle(window_days, mode=mode)
    logging.info(
        "derived views %s finished; window=%s elapsed=%.2fs",
        mode,
        window_days,
        time.monotonic() - started,
    )
    return bundle


def reuse_recent_refresh_for_small_delta(window_days):
    """Return cached derived bundle when manual refresh would only fold a small delta."""
    with runtime["derived_cache_lock"]:
        history = runtime.get("subject_history") or {}
    if not isinstance(history, dict) or history.get("empty"):
        return None
    if not summary_matches_window(history, window_days):
        return None
    if not recent_successful_derived_refresh():
        return None
    started = time.monotonic()
    pending_stats = subject_history_pending_jsonl_stats(history)
    pending_bytes = int(pending_stats.get("pending_bytes") or 0)
    threshold = small_delta_reuse_max_pending_bytes()
    logging.info(
        "derived manual refresh small-delta check finished elapsed=%.2fs "
        "effective_pending_raw=%s effective_pending_bytes=%s threshold_bytes=%s "
        "effective_pending_by_collector=%s subject_checkpoint_pending_bytes=%s "
        "subject_checkpoint_pending_by_collector=%s",
        time.monotonic() - started,
        pending_stats.get("pending", False),
        pending_bytes,
        threshold,
        compact_pending_jsonl_stats(pending_stats),
        pending_stats.get("subject_checkpoint_pending_bytes", 0),
        compact_pending_jsonl_stats(
            {
                "pending_by_collector": pending_stats.get(
                    "subject_checkpoint_pending_by_collector"
                )
                or {}
            }
        ),
    )
    if not pending_stats.get("pending", False):
        return build_cached_derived_bundle(window_days, mode="refresh_cached")
    if pending_stats_have_direct_collector_work(pending_stats):
        return None
    if threshold <= 0 or pending_bytes > threshold:
        return None
    return build_cached_derived_bundle(window_days, mode="refresh_cached")


def pending_stats_have_direct_collector_work(stats):
    """Return True when direct collector JSONL bytes require a real refresh."""
    pending_by_collector = (stats or {}).get("pending_by_collector") or {}
    return any(
        collector in SubjectHistoryBuilder.DIRECT_COLLECTORS
        and int((values or {}).get("bytes") or 0) > 0
        for collector, values in pending_by_collector.items()
    )


def small_delta_reuse_max_pending_bytes():
    """Return pending-byte limit for reusing a recent refresh on manual Refresh."""
    ui = (runtime.get("config") or {}).get("ui") or {}
    value = ui.get("manual_refresh_small_delta_reuse_bytes", 0)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def build_cached_derived_bundle(window_days, mode="cached"):
    """Build a response bundle from already-loaded derived runtime summaries."""
    if not derived_refresh.is_active():
        repair_response = refresh_stale_cached_dependents(window_days)
        if repair_response:
            return repair_response
    generated_at_epoch = now_epoch()
    generated_at = local_now(generated_at_epoch)
    with runtime["derived_cache_lock"]:
        subject_history = apply_subject_annotations(runtime["subject_history"])
        device_history = apply_subject_annotations(runtime["device_history"])
        reports = apply_report_annotations(runtime["reports"])
        bundle = {
            "generated_at": generated_at,
            "generated_at_epoch": generated_at_epoch,
            "window": view_window_metadata(window_days),
            "findings": add_refresh_metadata(
                empty_findings_history(window_days), generated_at, generated_at_epoch
            ),
            "subject_history": add_refresh_metadata(
                subject_history, generated_at, generated_at_epoch
            ),
            "device_history": add_refresh_metadata(
                device_history, generated_at, generated_at_epoch
            ),
            "history_analysis": add_refresh_metadata(
                runtime["history_analysis"], generated_at, generated_at_epoch
            ),
            "reports": add_refresh_metadata(reports, generated_at, generated_at_epoch),
        }
        # Compute a stable data-version from the underlying section
        # summaries.  This only changes when the scheduler (or manual
        # refresh) rebuilds data.  The browser uses it to skip redundant
        # DOM re-renders during polling.
        section_epochs = [
            summary_generated_epoch(runtime.get("subject_history")),
            summary_generated_epoch(runtime.get("device_history")),
            summary_generated_epoch(runtime.get("history_analysis")),
            summary_generated_epoch(runtime.get("reports")),
        ]
        section_epochs = [e for e in section_epochs if e is not None]
        bundle["data_version_epoch"] = (
            max(section_epochs) if section_epochs else generated_at_epoch
        )
    logging.info(
        "derived views %s reused cached summaries; window=%s generated_at=%s",
        mode,
        window_days,
        generated_at,
    )
    return compact_derived_bundle_for_browser(bundle)


def refresh_stale_cached_dependents(window_days):
    """Repair cached analysis/report summaries that lag Subject History.

    A cached `/derived_views` request should not read raw logs, but it can safely
    rebuild summaries derived from already-materialized Subject History. This
    keeps Reports/Insights from presenting older generation times than the
    subject snapshot they are supposed to describe.
    """
    with runtime["derived_cache_lock"]:
        history = runtime.get("subject_history") or {}
    if not isinstance(history, dict) or history.get("empty"):
        return
    history_epoch = summary_generated_epoch(history)
    if not history_epoch:
        return None
    with runtime["derived_cache_lock"]:
        analysis = runtime.get("history_analysis") or {}
        reports = runtime.get("reports") or {}
    if not (
        dependent_summary_is_stale(analysis, history_epoch, window_days)
        or dependent_summary_is_stale(reports, history_epoch, window_days)
    ):
        return None
    started, status = derived_refresh.try_start(window_days, mode="repair")
    if not started:
        logging.info(
            "derived cached repair joined active operation; "
            "window=%s elapsed=%.1fs phase=%s/%s stage=%s",
            status.get("window"),
            status.get("elapsed_sec", 0),
            status.get("phase_step") or "?",
            status.get("phase_total") or "?",
            status.get("stage") or "unknown",
        )
        return active_derived_operation_response()
    success = False
    error = ""
    try:
        timed_derived_stage(
            "repair_dependents",
            lambda: repair_stale_cached_dependents_unlocked(window_days, history_epoch),
            "repair",
        )
        success = True
        return None
    except Exception as exc:
        error = str(exc)
        raise
    finally:
        derived_refresh.finish(window_days, success=success, error=error)


def refresh_pending_raw_logs(window_days):
    """Run a real refresh when cached Subject History is behind raw JSONL logs."""
    with runtime["derived_cache_lock"]:
        history = runtime.get("subject_history") or {}
    if not subject_history_has_pending_jsonl(history):
        return None
    if recent_successful_derived_refresh():
        logging.info(
            "derived cached load found pending raw JSONL but recent refresh "
            "completed; deferring to normal refresh interval; window=%s "
            "subject_history_generated=%s",
            window_days,
            history.get("generated_at") or "",
        )
        return None
    started, status = derived_refresh.try_start(window_days, mode="refresh")
    if not started:
        logging.info(
            "derived cached load noticed active raw-log refresh; "
            "serving cached bundle; window=%s elapsed=%.1fs phase=%s/%s stage=%s",
            status.get("window"),
            status.get("elapsed_sec", 0),
            status.get("phase_step") or "?",
            status.get("phase_total") or "?",
            status.get("stage") or "unknown",
        )
        return None
    logging.info(
        "derived cached load found raw JSONL beyond Subject History checkpoint; "
        "starting background refresh; window=%s subject_history_generated=%s",
        window_days,
        history.get("generated_at") or "",
    )
    thread = threading.Thread(
        target=run_background_derived_refresh,
        args=(window_days,),
        daemon=True,
    )
    thread.start()
    return None


def run_background_derived_refresh(window_days):
    """Run a coordinator-owned catch-up refresh outside the request thread."""
    success = False
    error = ""
    try:
        build_derived_views_unlocked(window_days, force=True)
        success = True
    except Exception as exc:
        error = str(exc)
        logging.exception("background derived refresh failed")
    finally:
        derived_refresh.finish(window_days, success=success, error=error)


def recent_successful_derived_refresh():
    """Return True when a full refresh just completed in this process."""
    status = derived_refresh.status()
    finished_epoch = timestamp_epoch(status.get("last_finished_epoch"))
    if finished_epoch is None:
        return False
    cooldown = pending_raw_log_refresh_cooldown_sec()
    return now_epoch() - finished_epoch < cooldown


def pending_raw_log_refresh_cooldown_sec():
    """Return the minimum interval before cached loads auto-start another refresh."""
    ui = (runtime.get("config") or {}).get("ui") or {}
    try:
        minutes = float(ui.get("derived_refresh_interval_min", 15))
    except (TypeError, ValueError):
        minutes = 15
    if minutes <= 0:
        try:
            minutes = float(ui.get("derived_stale_after_min", 15))
        except (TypeError, ValueError):
            minutes = 15
    return max(int(minutes * 60), 60)


def device_history_update_interval_sec():
    """Return background compact Device History update cadence in seconds."""
    ui = (runtime.get("config") or {}).get("ui") or {}
    try:
        value = float(ui.get("device_history_update_interval_sec", 60))
    except (TypeError, ValueError):
        value = 60
    if value <= 0:
        return 0
    return max(int(value), 5)


def _migrate_ui_config_keys(config):
    """Migrate pre-0.3.8 ``ui`` config keys to their consolidated names.

    Mutates ``config["ui"]`` in place (config is the merged runtime config,
    not the on-disk file).  Logs a warning when keys are migrated so an
    operator whose old value was silently ignored can see what happened.
    """
    ui = config.get("ui") or {}
    if not isinstance(ui, dict):
        return
    migrated = []

    if "derived_refresh_interval_min" not in ui:
        old_auto = ui.get("derived_auto_refresh_min")
        old_sched = ui.get("derived_scheduler_interval_sec")
        try:
            if old_auto is not None:
                ui["derived_refresh_interval_min"] = float(old_auto)
                migrated.append(
                    "derived_auto_refresh_min={} -> derived_refresh_interval_min".format(
                        old_auto
                    )
                )
            elif old_sched is not None:
                minutes = max(1, int(float(old_sched) / 60))
                ui["derived_refresh_interval_min"] = minutes
                migrated.append(
                    "derived_scheduler_interval_sec={} -> derived_refresh_interval_min={}".format(
                        old_sched, minutes
                    )
                )
        except (TypeError, ValueError):
            pass

    if "snapshot_retention_hours" not in ui:
        old_backfill = ui.get("snapshot_backfill_hours")
        if old_backfill is not None:
            try:
                ui["snapshot_retention_hours"] = int(old_backfill)
                migrated.append(
                    "snapshot_backfill_hours={} -> snapshot_retention_hours".format(
                        old_backfill
                    )
                )
            except (TypeError, ValueError):
                pass

    if migrated:
        logging.warning("Config key migration: %s", "; ".join(migrated))


def derived_refresh_interval_sec():
    """Return server-side derived-data rebuild interval in seconds.

    Reads ``ui.derived_refresh_interval_min`` from config/skannr.yaml,
    converts to seconds.  Default 15 min (900s).  0 disables the
    scheduler.
    """
    ui = (runtime.get("config") or {}).get("ui") or {}
    try:
        minutes = float(ui.get("derived_refresh_interval_min", 15))
    except (TypeError, ValueError):
        minutes = 15
    if minutes <= 0:
        return 0
    return max(int(minutes * 60), 60)


def snapshot_retention_hours():
    """Return how many hours of snapshots to keep and backfill.

    Reads ``ui.snapshot_retention_hours`` from config/skannr.yaml.
    Default 24.  Controls both retention (purge older files) and
    backfill (scan for gaps this far back at startup).  0 = never
    purge and skip backfill.
    """
    ui = (runtime.get("config") or {}).get("ui") or {}
    try:
        value = int(ui.get("snapshot_retention_hours", 24))
    except (TypeError, ValueError):
        value = 24
    return max(value, 0)


def _startup_prune_device_history():
    """Run a one-time full prune of the compact device history at startup.

    The incremental worker only prunes newly-added records.  This pass
    re-evaluates every existing device against the current prune rules,
    catching records that became eligible while the app was stopped or
    before a rule was tightened.
    """
    path = device_history_path()
    summary = read_json_file(path)
    if not isinstance(summary, dict) or summary.get("empty"):
        return
    started = time.monotonic()
    builder = WiFiBLEPostprocessor(
        configured_log_dir(),
        state_path=path,
        window_days=None,
    )
    _summary, pruned_bt = builder.prune_low_value_bluetooth_devices(summary)
    _summary, pruned_ap = builder.prune_stale_ap_sessions(summary)
    if pruned_bt or pruned_ap:
        try:
            save_json_atomic(path, summary)
        except OSError as exc:
            logging.warning("startup device history prune save failed: %s", exc)
    logging.info(
        "startup device history prune finished elapsed=%.2fs "
        "pruned_bluetooth=%s pruned_ap_sessions=%s total_devices=%s",
        time.monotonic() - started,
        pruned_bt,
        pruned_ap,
        len((summary.get("bluetooth") or summary.get("ble") or {}).get("devices", [])),
    )


def start_device_history_worker():
    """Start the background compact Device History updater when configured."""
    interval = device_history_update_interval_sec()
    if interval <= 0:
        logging.info("device_history background updater disabled")
        return
    if runtime.get("device_history_worker_thread"):
        return
    thread = threading.Thread(
        target=device_history_worker_loop,
        args=(interval,),
        daemon=True,
        name="skannr-device-history",
    )
    runtime["device_history_worker_thread"] = thread
    thread.start()


def device_history_worker_loop(interval):
    """Periodically fold raw Wi-Fi/BLE/LAN events into compact Device History."""
    logging.info("device_history background updater started interval_sec=%s", interval)
    while not runtime.get("shutting_down"):
        if sleep_until_shutdown(interval):
            break
        update_compact_device_history(reason="periodic")
    logging.info("device_history background updater stopped")


def derived_refresh_scheduler_loop(interval_sec):
    """Background thread: periodically rebuild all derived views.

    Runs independently of any browser connection.  Uses the same
    ``DerivedRefreshCoordinator`` lock as manual browser refreshes so
    they never collide.
    """
    logging.info("derived refresh scheduler started interval_sec=%s", interval_sec)
    # Short grace period so collectors produce initial JSONL before the
    # first rebuild.
    first_wait = min(30, interval_sec // 2)
    if sleep_until_shutdown(first_wait):
        return
    while not runtime.get("shutting_down"):
        cycle_started = time.monotonic()
        try:
            if derived_refresh.is_active():
                logging.info("derived scheduler skipped; refresh already in progress")
            else:
                logging.info("derived scheduler triggering periodic rebuild")
                build_derived_views(force=True)
                logging.info(
                    "derived scheduler rebuild finished elapsed=%.2fs",
                    time.monotonic() - cycle_started,
                )
        except Exception as exc:
            logging.exception(
                "derived scheduler rebuild failed elapsed=%.2fs: %s",
                time.monotonic() - cycle_started,
                exc,
            )
        if sleep_until_shutdown(interval_sec):
            break
    logging.info("derived refresh scheduler stopped")


def start_derived_refresh_scheduler():
    """Launch the background derived-data rebuild scheduler thread."""
    interval = derived_refresh_interval_sec()
    if interval <= 0:
        logging.info("derived refresh scheduler disabled (interval <= 0)")
        return
    thread = threading.Thread(
        target=derived_refresh_scheduler_loop,
        args=(interval,),
        daemon=True,
        name="skannr-derived-scheduler",
    )
    thread.start()
    return thread


def sleep_until_shutdown(seconds):
    """Sleep in short chunks so shutdown does not wait on a long interval."""
    deadline = time.monotonic() + max(float(seconds), 0.0)
    while not runtime.get("shutting_down"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(1.0, remaining))
    return True


def update_compact_device_history(reason="periodic"):
    """Advance compact Device History without rebuilding Subject History."""
    if derived_refresh.is_active():
        logging.info(
            "device_history background update skipped reason=%s active_refresh=true",
            reason,
        )
        return None
    lock = runtime["device_history_update_lock"]
    if not lock.acquire(blocking=False):
        logging.info(
            "device_history background update skipped reason=%s active_update=true",
            reason,
        )
        return None
    try:
        log_dir = configured_log_dir()
        builder = WiFiBLEPostprocessor(
            log_dir,
            state_path=device_history_path(),
            window_days=None,
        )
        started = time.monotonic()
        summary = builder.build_summary()
        logging.info(
            "device_history background build finished reason=%s elapsed=%.2fs "
            "records=%s incremental_records=%s incremental_by_collector=%s "
            "raw_read_stats=%s",
            reason,
            time.monotonic() - started,
            summary.get("records_read", 0),
            summary.get("incremental_records_read", 0),
            summary.get("incremental_records_read_by_collector") or {},
            compact_incremental_read_stats(summary.get("incremental_jsonl_read_stats")),
        )
        prune_started = time.monotonic()
        summary, pruned_bluetooth = builder.prune_low_value_bluetooth_devices(summary)
        summary, pruned_ap_sessions = builder.prune_stale_ap_sessions(summary)
        logging.info(
            "device_history background prune finished reason=%s elapsed=%.2fs "
            "pruned_bluetooth=%s pruned_ap_sessions=%s",
            reason,
            time.monotonic() - prune_started,
            pruned_bluetooth,
            pruned_ap_sessions,
        )
        summary = apply_subject_annotations(summary)
        builder.save_summary(summary)
        return summary
    except Exception as exc:
        logging.exception(
            "device_history background update failed reason=%s: %s", reason, exc
        )
        return None
    finally:
        lock.release()


def subject_history_has_pending_jsonl(history):
    """Return True when collector JSONL files contain unmaterialized bytes."""
    return subject_history_pending_jsonl_stats(history).get("pending", False)


def subject_history_pending_jsonl_stats(history):
    """Return pending raw work for the current Subject History pipeline.

    Device History-backed collectors are materialized upstream and Subject
    History consumes the compact Device History state. For those collectors,
    compare current log EOF to device_history.json's checkpoint. Direct
    collectors still use Subject History's own checkpoint.
    """
    log_dir = configured_log_dir()
    enabled = enabled_subject_history_collectors()
    device_collectors = tuple(
        collector
        for collector in SubjectHistoryBuilder.DEVICE_COLLECTORS
        if collector in enabled
    )
    # Direct collectors can have raw events that were written before the
    # operator switched collectors. SubjectHistoryBuilder decides whether to
    # fold those pending rows or advance disabled checkpoints, so pending-work
    # detection must not hide disabled direct collectors.
    direct_collectors = SubjectHistoryBuilder.DIRECT_COLLECTORS
    subject_checkpoint = None
    if (
        isinstance(history, dict)
        and not history.get("empty")
        and has_jsonl_checkpoint(history)
    ):
        subject_checkpoint = history.get("checkpoint") or {}

    device_summary = read_json_file(device_history_path())
    device_checkpoint = None
    device_checkpoint_source = "none"
    if (
        isinstance(device_summary, dict)
        and not device_summary.get("empty")
        and has_jsonl_checkpoint(device_summary)
    ):
        device_checkpoint = device_summary.get("checkpoint") or {}
        device_checkpoint_source = "device_history"

    device_pending = checkpoint_pending_stats(
        device_checkpoint, current_jsonl_checkpoint(log_dir, device_collectors)
    )
    direct_pending = checkpoint_pending_stats(
        subject_checkpoint, current_jsonl_checkpoint(log_dir, direct_collectors)
    )
    effective = combine_pending_jsonl_stats(device_pending, direct_pending)
    effective["device_checkpoint_source"] = device_checkpoint_source
    effective["direct_checkpoint_source"] = (
        "subject_history" if subject_checkpoint is not None else "none"
    )

    subject_pending = checkpoint_pending_stats(
        subject_checkpoint, current_jsonl_checkpoint(log_dir, enabled)
    )
    effective["subject_checkpoint_pending_bytes"] = subject_pending.get(
        "pending_bytes", 0
    )
    effective["subject_checkpoint_pending_files"] = subject_pending.get(
        "pending_files", 0
    )
    effective["subject_checkpoint_pending_by_collector"] = (
        subject_pending.get("pending_by_collector") or {}
    )
    return effective


def raw_history_files_have_bytes():
    """Return True when any retained subject-history collector log has content."""
    checkpoint = current_jsonl_checkpoint(
        configured_log_dir(), enabled_subject_history_collectors()
    )
    return checkpoint_has_any_bytes(checkpoint)


def checkpoint_has_any_bytes(checkpoint):
    """Return True when a checkpoint snapshot contains any non-empty JSONL file."""
    collectors = (checkpoint or {}).get("collectors") or {}
    for files in collectors.values():
        for state in (files or {}).values():
            if int((state or {}).get("size") or 0) > 0:
                return True
    return False


def checkpoint_has_pending_bytes(previous, current):
    """Compare saved JSONL offsets with current file sizes."""
    return checkpoint_pending_stats(previous, current).get("pending", False)


def checkpoint_pending_stats(previous, current):
    """Return pending JSONL byte/file counts by collector."""
    previous_collectors = (previous or {}).get("collectors") or {}
    current_collectors = (current or {}).get("collectors") or {}
    pending_by_collector = {}
    pending_files = 0
    pending_bytes = 0
    for collector, files in current_collectors.items():
        previous_files = previous_collectors.get(collector) or {}
        collector_bytes = 0
        collector_files = 0
        for filename, state in (files or {}).items():
            size = int((state or {}).get("size") or 0)
            if size <= 0:
                continue
            old = previous_files.get(filename) or {}
            offset = int(old.get("offset") or 0)
            delta = size - offset
            if delta <= 0:
                continue
            collector_bytes += delta
            collector_files += 1
        if collector_bytes:
            pending_by_collector[collector] = {
                "bytes": collector_bytes,
                "files": collector_files,
            }
            pending_bytes += collector_bytes
            pending_files += collector_files
    return {
        "pending": pending_bytes > 0,
        "pending_bytes": pending_bytes,
        "pending_files": pending_files,
        "pending_by_collector": pending_by_collector,
    }


def combine_pending_jsonl_stats(*stats_items):
    """Merge pending JSONL stats produced for disjoint collector sets."""
    pending_by_collector = {}
    pending_files = 0
    pending_bytes = 0
    for stats in stats_items:
        if not isinstance(stats, dict):
            continue
        pending_files += int(stats.get("pending_files") or 0)
        pending_bytes += int(stats.get("pending_bytes") or 0)
        for collector, values in (stats.get("pending_by_collector") or {}).items():
            target = pending_by_collector.setdefault(
                collector, {"bytes": 0, "files": 0}
            )
            target["bytes"] += int((values or {}).get("bytes") or 0)
            target["files"] += int((values or {}).get("files") or 0)
    return {
        "pending": pending_bytes > 0,
        "pending_bytes": pending_bytes,
        "pending_files": pending_files,
        "pending_by_collector": pending_by_collector,
    }


def compact_pending_jsonl_stats(stats):
    """Return concise pending JSONL stats for refresh timing logs."""
    parts = []
    for collector, values in sorted(
        ((stats or {}).get("pending_by_collector") or {}).items()
    ):
        parts.append(
            "{}={}B/{}f".format(
                collector,
                int((values or {}).get("bytes") or 0),
                int((values or {}).get("files") or 0),
            )
        )
    return ",".join(parts) if parts else "none"


def compact_incremental_read_stats(stats):
    """Return concise raw JSONL reader stats for refresh timing logs."""
    parts = []
    for collector, values in sorted((stats or {}).items()):
        if not isinstance(values, dict):
            continue
        event_types = values.get("event_types") or {}
        top_types = ";".join(
            "{}:{}".format(event_type, count)
            for event_type, count in sorted(
                event_types.items(), key=lambda item: int(item[1] or 0), reverse=True
            )[:4]
        )
        parts.append(
            "{}={}B/{}lines/{}json/{}bad/max{}B/types[{}]".format(
                collector,
                int(values.get("bytes_read") or values.get("pending_bytes") or 0),
                int(values.get("raw_lines") or 0),
                int(values.get("decoded_records") or 0),
                int(values.get("invalid_lines") or 0),
                int(values.get("max_line_bytes") or 0),
                top_types or "none",
            )
        )
    return ",".join(parts) if parts else "none"


def repair_stale_cached_dependents_unlocked(window_days, history_epoch):
    """Rebuild stale derived summaries from cached Subject History."""
    with runtime["derived_cache_lock"]:
        history = runtime.get("subject_history") or {}
        analysis = runtime.get("history_analysis") or {}
    if dependent_summary_is_stale(analysis, history_epoch, window_days):
        logging.info(
            "derived cached repair refreshing history_analysis; "
            "subject_history_generated=%s analysis_generated=%s",
            history.get("generated_at") or "",
            (analysis or {}).get("generated_at") or "",
        )
        refresh_history_analysis(window_days)
    with runtime["derived_cache_lock"]:
        reports = runtime.get("reports") or {}
    if dependent_summary_is_stale(reports, history_epoch, window_days):
        logging.info(
            "derived cached repair refreshing reports; "
            "subject_history_generated=%s reports_generated=%s "
            "reports_history_generated=%s",
            history.get("generated_at") or "",
            (reports or {}).get("generated_at") or "",
            (reports or {}).get("history_generated_at") or "",
        )
        refresh_reports(window_days)


def dependent_summary_is_stale(summary, history_epoch, window_days):
    """Return True when a cached summary no longer matches Subject History."""
    if not isinstance(summary, dict):
        return True
    if summary.get("empty") or summary.get("empty_reason"):
        return True
    if not summary_matches_window(summary, window_days):
        return True
    summary_epoch = summary_generated_epoch(summary)
    if not summary_epoch or summary_epoch < history_epoch:
        return True
    return False


def summary_generated_epoch(summary):
    """Return a numeric generated_at_epoch from a derived summary."""
    try:
        value = float((summary or {}).get("generated_at_epoch"))
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def timed_derived_stage(name, callback, mode):
    """Run one derived-data stage and log elapsed time for hang diagnosis."""
    started, step, total, label = derived_refresh.start_phase(mode, name)
    logging.info(
        "derived phase %s/%s %s started; stage=%s",
        step,
        total,
        label,
        name,
    )
    try:
        return callback()
    finally:
        logging.info(
            "derived phase %s/%s %s finished; stage=%s elapsed=%.2fs",
            step,
            total,
            label,
            name,
            time.monotonic() - started,
        )
        derived_refresh.finish_phase(mode, name, label)


def run_parallel_derived_stages(group_name, tasks):
    """Run one dependency-safe refresh group and wait for every member.

    The coordinator exposes one operator-facing phase per dependency group,
    while each worker logs its own elapsed time. If one worker fails, the
    remaining workers are still joined before the first exception is re-raised,
    so the backend never publishes a partially refreshed bundle.
    """
    started, step, total, label = derived_refresh.start_phase("refresh", group_name)
    logging.info(
        "derived phase %s/%s %s started; stage=%s", step, total, label, group_name
    )
    errors = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        future_to_name = {
            executor.submit(run_derived_worker, name, callback): name
            for name, callback in tasks
        }
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                future.result()
            except Exception as exc:
                logging.exception("derived worker %s failed: %s", name, exc)
                errors.append((name, exc))
    elapsed = time.monotonic() - started
    if errors:
        raise errors[0][1]
    logging.info(
        "derived phase %s/%s %s finished; stage=%s elapsed=%.2fs",
        step,
        total,
        label,
        group_name,
        elapsed,
    )
    derived_refresh.finish_phase("refresh", group_name, label)


def run_derived_worker(name, callback):
    """Run one member of a parallel derived refresh group."""
    started = time.monotonic()
    logging.info("derived worker %s started", name)
    try:
        return callback()
    finally:
        logging.info(
            "derived worker %s finished elapsed=%.2fs",
            name,
            time.monotonic() - started,
        )


def add_refresh_metadata(summary, refreshed_at, refreshed_at_epoch):
    """Attach request-level refresh time without mutating cached summaries."""
    if not isinstance(summary, dict):
        return summary
    copy = dict(summary)
    copy["refreshed_at"] = refreshed_at
    copy["refreshed_at_epoch"] = refreshed_at_epoch
    return copy


SUMMARY_BROWSER_KEYS = {
    "cached",
    "empty",
    "empty_reason",
    "generated_at",
    "generated_at_epoch",
    "history_generated_at",
    "history_generated_at_epoch",
    "insights_window",
    "materialized_window",
    "raw_logs_incremental",
    "records_read",
    "refreshed_at",
    "refreshed_at_epoch",
    "state_path",
    "window",
}

WIFI_AP_BROWSER_KEYS = {
    "annotation",
    "bssid",
    "custom_name",
    "channels",
    "encryption",
    "finding_count",
    "first_seen",
    "first_seen_epoch",
    "last_seen",
    "last_seen_epoch",
    "observations",
    "randomized_mac",
    "signal_latest",
    "signal_max",
    "signal_min",
    "ssid",
    "ssids",
    "vendor_name",
    "vendor_oui",
    "vendor_prefix",
}

WIFI_CLIENT_BROWSER_KEYS = {
    "annotation",
    "association_count",
    "custom_name",
    "deauth_count",
    "disassoc_count",
    "finding_count",
    "first_seen",
    "first_seen_epoch",
    "last_seen",
    "last_seen_epoch",
    "grouped_randomized",
    "group_members",
    "mac",
    "probe_count",
    "randomized_group_count",
    "randomized_mac",
    "sample_macs",
    "signal_latest",
    "signal_max",
    "signal_min",
    "ssids",
    "vendor_name",
    "vendor_oui",
    "vendor_prefix",
}

BLUETOOTH_DEVICE_BROWSER_KEYS = {
    "adv_data_hex",
    "annotation",
    "classic_seen_count",
    "custom_name",
    "finding_count",
    "firmware_revision",
    "findmy_accessory",
    "findmy_hint",
    "findmy_label",
    "findmy_payload_type",
    "findmy_status",
    "first_seen",
    "first_seen_epoch",
    "group_key",
    "grouped_randomized",
    "group_members",
    "last_seen",
    "last_seen_epoch",
    "lost_count",
    "mac",
    "manufacturer",
    "manufacturer_id",
    "manufacturer_name",
    "model_number",
    "name",
    "names",
    "pnp_id",
    "randomized_group_count",
    "rssi",
    "sample_macs",
    "seen_count",
    "serial_number",
    "service_uuids",
    "signal_latest",
    "signal_max",
    "signal_min",
    "transports",
    "update_count",
    "vendor_name",
    "vendor_oui",
    "vendor_prefix",
}

FINDING_BROWSER_KEYS = {
    "activity_state",
    "attributes",
    "detail",
    "id",
    "key",
    "last_seen",
    "last_seen_epoch",
    "severity",
    "source",
    "timestamp",
    "timestamp_epoch",
    "title",
    "type",
}

OBSERVATION_BROWSER_KEYS = {
    "activity_state",
    "age_minutes",
    "detail",
    "evidence",
    "id",
    "last_seen",
    "last_seen_epoch",
    "score",
    "severity",
    "source",
    "timestamp",
    "timestamp_epoch",
    "title",
    "type",
}

SUBJECT_BROWSER_KEYS = {
    "annotation",
    "collector",
    "custom_name",
    "data",
    "first_seen",
    "first_seen_epoch",
    "last_seen",
    "last_seen_epoch",
    "subject",
    "subject_id",
    "subject_type",
}


def compact_derived_bundle_for_browser(bundle):
    """Return the derived bundle shape needed by the browser.

    The materialized summaries intentionally keep rich state for server-side
    Reports and Insights. The browser only needs table/detail fields. Sending
    checkpoint metadata and full per-device session arrays made the tab spend
    minutes downloading/parsing JSON once Device History grew into tens of MB.
    This response-only compaction preserves the server runtime and persisted
    files while keeping `/derived_views` small enough for regular polling.
    """
    if not isinstance(bundle, dict):
        return bundle
    compact = dict(bundle)
    compact["findings"] = compact_findings_for_browser(bundle.get("findings"))
    compact["subject_history"] = compact_subject_history_for_browser(
        bundle.get("subject_history")
    )
    compact["device_history"] = compact_device_history_for_browser(
        bundle.get("device_history"), bundle.get("reports")
    )
    compact["history_analysis"] = compact_history_analysis_for_browser(
        bundle.get("history_analysis")
    )
    compact["reports"] = compact_reports_for_browser(bundle.get("reports"))
    return compact


def compact_summary_top_level(summary):
    """Keep browser-relevant summary metadata and drop durable checkpoints."""
    if not isinstance(summary, dict):
        return summary
    output = {key: summary[key] for key in SUMMARY_BROWSER_KEYS if key in summary}
    if "counts" in summary:
        output["counts"] = summary["counts"]
    return output


def compact_findings_for_browser(summary):
    """Strip non-UI fields from the tactical Insights finding feed."""
    output = compact_summary_top_level(summary)
    if not isinstance(output, dict):
        return output
    output["findings"] = [
        compact_record_for_browser(item, FINDING_BROWSER_KEYS)
        for item in (summary or {}).get("findings") or []
        if isinstance(item, dict)
    ]
    return output


def compact_history_analysis_for_browser(summary):
    """Strip non-UI fields from generated history observations."""
    output = compact_summary_top_level(summary)
    if not isinstance(output, dict):
        return output
    output["observations"] = [
        compact_record_for_browser(item, OBSERVATION_BROWSER_KEYS)
        for item in (summary or {}).get("observations") or []
        if isinstance(item, dict)
    ]
    return output


def compact_reports_for_browser(summary):
    """Keep generated report rows while dropping non-UI summary metadata."""
    output = compact_summary_top_level(summary)
    if not isinstance(output, dict):
        return output
    output["reports"] = [
        compact_json_value_for_browser(item)
        for item in (summary or {}).get("reports") or []
        if isinstance(item, dict)
    ]
    return output


def compact_subject_history_for_browser(summary):
    """Keep normalized subject rows while dropping durable direct observations."""
    output = compact_summary_top_level(summary)
    if not isinstance(output, dict):
        return output
    row_limit = max_history_payload_rows()
    subjects = [
        item for item in (summary or {}).get("subjects") or [] if isinstance(item, dict)
    ]
    selected = select_subject_records_for_browser(subjects, row_limit)
    output["subjects"] = [
        compact_record_for_browser(item, SUBJECT_BROWSER_KEYS) for item in selected
    ]
    output["subject_counts"] = (summary or {}).get("subject_counts") or {
        "total": 0,
        "by_collector": {},
        "by_type": {},
    }
    output["total_subjects"] = len(subjects)
    return output


def select_subject_records_for_browser(subjects, row_limit):
    """Return globally recent subjects plus per-collector rows for each tab."""
    if row_limit <= 0:
        return []
    selected = []
    seen = set()

    def add(record):
        key = subject_record_browser_key(record)
        if key in seen:
            return
        seen.add(key)
        selected.append(record)

    for record in subjects[:row_limit]:
        add(record)

    by_collector = {}
    for record in subjects:
        by_collector.setdefault(str(record.get("collector") or ""), []).append(record)
    for collector in sorted(by_collector):
        for record in by_collector[collector][:row_limit]:
            add(record)
    return selected


def subject_record_browser_key(record):
    """Return a stable identity for de-duplicating compact subject rows."""
    return (
        str((record or {}).get("collector") or ""),
        str((record or {}).get("subject_type") or ""),
        str((record or {}).get("subject_id") or ""),
        str((record or {}).get("subject") or ""),
    )


def represented_device_count(records):
    """Return represented row count, expanding aggregate randomized rows."""
    total = 0
    for record in records or []:
        if not isinstance(record, dict):
            continue
        try:
            total += max(
                1,
                int(
                    record.get("randomized_group_count")
                    or record.get("device_count")
                    or 1
                ),
            )
        except (TypeError, ValueError):
            total += 1
    return total


def compact_device_history_for_browser(summary, reports_summary=None):
    """Return compact Device History records for browser tables/detail panes."""
    output = compact_summary_top_level(summary)
    if not isinstance(output, dict):
        return output
    wifi = (summary or {}).get("wifi") or {}
    bluetooth = (summary or {}).get("bluetooth") or (summary or {}).get("ble") or {}
    required = required_device_history_keys(reports_summary)
    row_limit = max_history_payload_rows()
    access_points = wifi.get("access_points") or []
    clients = wifi.get("clients") or []
    devices = bluetooth.get("devices") or []
    output["wifi"] = {
        "access_points": compact_device_records_for_browser(
            access_points,
            WIFI_AP_BROWSER_KEYS,
            row_limit,
            lambda record: wifi_ap_required_for_browser(record, required),
        ),
        "clients": compact_wifi_clients_for_browser(
            clients,
            row_limit,
            required["wifi_clients"],
        ),
        "total_access_points": len(access_points),
        "total_clients": represented_device_count(clients),
    }
    output["bluetooth"] = {
        "devices": compact_bluetooth_devices_for_browser(
            devices,
            row_limit,
            required["bluetooth"],
        ),
        "total_devices": represented_device_count(devices),
    }
    output["ble"] = {
        "devices": output["bluetooth"]["devices"],
        "total_devices": output["bluetooth"]["total_devices"],
    }
    return output


def compact_device_records_for_browser(records, keys, limit, required_callback):
    """Compact materialized device records without losing table counts."""
    selected = select_device_records_for_browser(records, limit, required_callback)
    return [
        compact_device_record_for_browser(record, keys)
        for record in selected
        if isinstance(record, dict)
    ]


def compact_records_with_randomized_group(
    records,
    browser_keys,
    limit,
    required_keys,
    identity_field,
    should_group,
    group_key,
    update_group,
):
    """Compact records while folding multi-MAC randomized identities into groups."""
    individual = []
    candidates = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        identity = normalized_record_key(record, identity_field)
        group_candidate = should_group(record)
        if not group_candidate:
            individual.append(record)
            continue
        bucket = group_key(record)
        candidates.setdefault(bucket, []).append(record)

    randomized_groups = []
    for bucket, candidate_records in candidates.items():
        represented = sum(
            browser_group_record_count(record) for record in candidate_records
        )
        if represented <= 1:
            individual.extend(candidate_records)
            continue
        # Name-based grouping requires > 5 MACs before folding into a group.
        # A handful of MACs sharing a name (e.g. 2-5 "rnet" Amazon devices)
        # are more likely genuinely separate devices than one privacy-rotating
        # device.  This mirrors the persisted-cache threshold in
        # WiFiBLEPostprocessor.compact_bluetooth_devices_for_storage().
        if str(bucket or "").startswith("name|") and represented <= 5:
            individual.extend(candidate_records)
            continue
        group = None
        for record in candidate_records:
            group = update_group(group, record)
        randomized_groups.append(group)

    selected = select_device_records_for_browser(
        individual,
        limit,
        lambda record: normalized_record_key(record, identity_field) in required_keys,
    )
    compact = [
        compact_device_record_for_browser(record, browser_keys)
        for record in selected
        if isinstance(record, dict)
    ]
    compact.extend(randomized_groups)
    compact.sort(key=browser_record_sort_key, reverse=True)
    return compact


def browser_group_record_count(record):
    """Return represented identity count for browser grouping decisions."""
    try:
        return max(
            1,
            int(
                record.get("randomized_group_count") or record.get("device_count") or 1
            ),
        )
    except (TypeError, ValueError):
        return 1


def compact_wifi_clients_for_browser(records, limit, required_macs):
    """Compact Wi-Fi client rows and group randomized probe MACs for display.

    Server-side grouping decisions pass through unchanged.  Only individual
    records are candidates for browser-side folding.
    """
    server_groups = []
    individuals = []
    for record in records:
        if not isinstance(record, dict):
            continue
        if record.get("grouped_randomized"):
            server_groups.append(record)
        else:
            individuals.append(record)
    result = compact_records_with_randomized_group(
        individuals,
        WIFI_CLIENT_BROWSER_KEYS,
        limit,
        required_macs,
        "mac",
        lambda record: low_identity_wifi_client(record),
        lambda record: "randomized-wifi-client-macs",
        update_randomized_wifi_client_group,
    )
    for group in server_groups:
        result.append(
            compact_device_record_for_browser(group, WIFI_CLIENT_BROWSER_KEYS)
        )
    result.sort(key=browser_record_sort_key, reverse=True)
    return result


def update_randomized_wifi_client_group(group, record):
    """Fold one randomized Wi-Fi client into the browser aggregate row."""
    if group is None:
        group = {
            "mac": "randomized-client-macs",
            "grouped_randomized": True,
            "randomized_mac": True,
            "randomized_group_count": 0,
            "sample_macs": [],
            "group_members": [],
            "ssids": [],
            "first_seen": record.get("first_seen"),
            "first_seen_epoch": record.get("first_seen_epoch"),
            "last_seen": record.get("last_seen"),
            "last_seen_epoch": record.get("last_seen_epoch"),
            "signal_latest": record.get("signal_latest"),
            "signal_min": record.get("signal_min"),
            "signal_max": record.get("signal_max"),
            "probe_count": 0,
            "association_count": 0,
            "deauth_count": 0,
            "disassoc_count": 0,
            "finding_count": 0,
        }
    group["randomized_group_count"] = int(
        group.get("randomized_group_count") or 0
    ) + int(record.get("randomized_group_count") or record.get("device_count") or 1)
    append_group_sample_mac(group, record, limit=8)
    append_browser_group_member(group, record, "wifi")
    group["ssids"] = merge_group_list(group, record, "ssids", 50)
    increment_group_counts(
        group,
        record,
        (
            "probe_count",
            "association_count",
            "deauth_count",
            "disassoc_count",
            "finding_count",
        ),
    )
    update_group_time_bounds(group, record)
    update_group_signal_bounds(group, record)
    return group


def append_browser_group_member(group, record, source, limit=24):
    """Keep compact per-member details in browser synthetic groups."""
    members = group.setdefault("group_members", [])
    source_members = record.get("group_members")
    candidates = (
        source_members
        if isinstance(source_members, list) and source_members
        else [browser_group_member_summary(record, source)]
    )
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        member = {
            key: value
            for key, value in candidate.items()
            if value not in (None, "", [], {})
        }
        mac = str(member.get("mac") or "").strip().lower()
        if not mac or any(
            str(item.get("mac") or "").lower() == mac for item in members
        ):
            continue
        if len(members) < limit:
            members.append(member)


def browser_group_member_summary(record, source):
    """Return one compact browser member summary from a source record."""
    member = {
        "mac": record.get("mac") or "",
        "first_seen": record.get("first_seen") or "",
        "last_seen": record.get("last_seen") or "",
        "signal_min": record.get("signal_min"),
        "signal_max": record.get("signal_max"),
    }
    if source == "wifi":
        member.update(
            {
                "identity": record.get("vendor_name")
                or record.get("vendor_prefix")
                or "",
                "ssids": (record.get("ssids") or [])[:8],
                "probe_count": record.get("probe_count") or 0,
                "association_count": record.get("association_count") or 0,
                "deauth_count": record.get("deauth_count") or 0,
                "disassoc_count": record.get("disassoc_count") or 0,
            }
        )
    elif source == "bluetooth":
        names = record.get("names") or (
            [record.get("name")] if record.get("name") else []
        )
        member.update(
            {
                "identity": (
                    names[0]
                    if names
                    else (
                        record.get("manufacturer")
                        or record.get("manufacturer_name")
                        or ""
                    )
                ),
                "names": names[:6],
                "service_uuids": (record.get("service_uuids") or [])[:8],
                "seen_count": record.get("seen_count") or 0,
                "update_count": record.get("update_count") or 0,
                "lost_count": record.get("lost_count") or 0,
                "classic_seen_count": record.get("classic_seen_count") or 0,
                "session_count": record.get("session_count") or 0,
                "active_session": bool(record.get("active_session")),
            }
        )
    return member


def increment_group_counts(group, record, fields):
    """Add numeric counters from one low-identity record into an aggregate row."""
    for field in fields:
        group[field] = int(group.get(field) or 0) + int(record.get(field) or 0)


def append_group_sample_mac(group, record, limit):
    """Keep a bounded sample of identities represented by an aggregate row."""
    mac = str(record.get("mac") or "").strip()
    samples = group.setdefault("sample_macs", [])
    if mac and len(samples) < limit:
        samples.append(mac)


def merge_group_list(group, record, field, limit):
    """Merge list-valued evidence into an aggregate row with a stable cap."""
    return sorted(set(group.get(field) or []) | set(record.get(field) or []))[:limit]


def update_group_time_bounds(group, record):
    """Expand an aggregate row's first/last seen bounds from one record."""
    first_epoch = record_time_epoch(record, "first_seen")
    last_epoch = record_time_epoch(record, "last_seen")
    group_first = record_time_epoch(group, "first_seen")
    group_last = record_time_epoch(group, "last_seen")
    if first_epoch and (not group_first or first_epoch < group_first):
        group["first_seen_epoch"] = first_epoch
        group["first_seen"] = record.get("first_seen")
    if last_epoch and (not group_last or last_epoch > group_last):
        group["last_seen_epoch"] = last_epoch
        group["last_seen"] = record.get("last_seen")
        group["signal_latest"] = record.get("signal_latest")


def update_group_signal_bounds(group, record):
    """Expand aggregate signal min/max values from one record."""
    for field, reducer in (("signal_min", min), ("signal_max", max)):
        values = [
            value
            for value in (group.get(field), record.get(field))
            if isinstance(value, (int, float))
        ]
        if values:
            group[field] = reducer(values)


def compact_bluetooth_devices_for_browser(records, limit, required_macs):
    """Compact Bluetooth history for browser display.

    Server-side grouping decisions (name, manufacturer, Find My) are final —
    already-grouped records pass through unchanged.  Only stale one-off MACs
    are folded here as a browser-only payload optimization.
    """
    server_groups = []
    individuals = []
    for record in records:
        if not isinstance(record, dict):
            continue
        if record.get("grouped_randomized"):
            server_groups.append(record)
        else:
            individuals.append(record)
    result = compact_records_with_randomized_group(
        individuals,
        BLUETOOTH_DEVICE_BROWSER_KEYS,
        limit,
        required_macs,
        "mac",
        lambda record: stale_single_seen_bluetooth_record(record),
        randomized_bluetooth_group_key,
        update_randomized_bluetooth_group,
    )
    for group in server_groups:
        result.append(
            compact_device_record_for_browser(group, BLUETOOTH_DEVICE_BROWSER_KEYS)
        )
    result.sort(key=browser_record_sort_key, reverse=True)
    return result


def select_device_records_for_browser(records, limit, required_callback):
    """Choose rows to send while preserving report-linked drilldown records."""
    usable = [record for record in records if isinstance(record, dict)]
    usable.sort(key=browser_record_sort_key, reverse=True)
    if limit <= 0:
        return usable
    required = []
    optional = []
    for record in usable:
        if required_callback(record):
            required.append(record)
        else:
            optional.append(record)
    selected = list(required)
    remaining = max(0, limit - len(selected))
    selected.extend(optional[:remaining])
    return selected


def likely_randomized_bluetooth_record(record):
    """Return True for low-identity randomized BLE rows to group for display."""
    return identity_bluetooth_grouping_candidate(record)


def stale_single_seen_bluetooth_record(record):
    """Return True for stale one-off BLE MACs that should not get a row."""
    if int(record.get("seen_count") or 0) != 1:
        return False
    last_seen = record_time_epoch(record, "last_seen")
    if not last_seen:
        return False
    return now_epoch() - last_seen > 3600


def meaningful_bluetooth_names(record):
    """Return de-duplicated advertised names that are not just the MAC address."""
    return identity_meaningful_bluetooth_names(record)


def bluetooth_manufacturer_label(record):
    """Return the best available Bluetooth manufacturer label."""
    return identity_bluetooth_manufacturer_label(record)


def randomized_bluetooth_group_key(record):
    """Group low-identity BLE rows by the strongest shared identity signal."""
    bucket = identity_bluetooth_identity_bucket(record)
    return "{}|{}".format(bucket[0], bucket[1].lower())


def randomized_bluetooth_group_label(record):
    """Return the display label for a low-identity Bluetooth aggregate row."""
    return "{} found".format(identity_bluetooth_group_label(record))


def update_randomized_bluetooth_group(group, record):
    """Accumulate one randomized/no-name BLE address into a synthetic row."""
    if group is None:
        group = {
            "grouped_randomized": True,
            "group_key": randomized_bluetooth_group_key(record),
            "mac": "",
            "name": randomized_bluetooth_group_label(record),
            "manufacturer": bluetooth_manufacturer_label(record),
            "transports": ["ble"],
            "first_seen": record.get("first_seen") or "",
            "first_seen_epoch": record.get("first_seen_epoch"),
            "last_seen": record.get("last_seen") or "",
            "last_seen_epoch": record.get("last_seen_epoch"),
            "signal_min": record.get("signal_min"),
            "signal_max": record.get("signal_max"),
            "seen_count": 0,
            "update_count": 0,
            "lost_count": 0,
            "classic_seen_count": 0,
            "session_count": 0,
            "finding_count": 0,
            "randomized_group_count": 0,
            "sample_macs": [],
            "group_members": [],
            "service_uuids": [],
        }

    group["randomized_group_count"] += int(
        record.get("randomized_group_count") or record.get("device_count") or 1
    )
    increment_group_counts(
        group, record, ("seen_count", "update_count", "lost_count", "finding_count")
    )
    group["session_count"] += int(
        record.get("session_count") or len(record.get("sessions") or [])
    )
    group["classic_seen_count"] += int(record.get("classic_seen_count") or 0)
    group["active_session"] = bool(group.get("active_session")) or bool(
        record.get("active_session")
    )
    update_group_time_bounds(group, record)
    update_group_signal_bounds(group, record)
    append_group_sample_mac(group, record, limit=6)
    append_browser_group_member(group, record, "bluetooth")
    group["service_uuids"] = merge_group_list(group, record, "service_uuids", 12)
    return group


def compact_device_record_for_browser(record, keys):
    """Drop bulky session bodies while keeping their count and active state."""
    item = compact_record_for_browser(record, keys)
    sessions = record.get("sessions")
    if isinstance(sessions, list):
        item["session_count"] = len(sessions)
    elif record.get("session_count") is not None:
        item["session_count"] = record.get("session_count")
    if "active_session" in record:
        item["active_session"] = bool(record.get("active_session"))
    return item


def compact_record_for_browser(record, keys):
    """Copy whitelisted fields, preserving only compact JSON values."""
    output = {}
    for key in keys:
        if key not in record:
            continue
        output[key] = compact_json_value_for_browser(record.get(key))
    return output


def max_history_payload_rows():
    """Return the server-side cap for browser Device History row payloads."""
    config = runtime.get("config") or {}
    ui = config.get("ui") or {}
    try:
        return max(0, int(ui.get("max_history_payload_rows", 1500)))
    except (TypeError, ValueError):
        return 1500


def browser_record_sort_key(record):
    """Sort Device History rows by most recent activity before payload capping."""
    return (
        record_time_epoch(record, "last_seen")
        or record_time_epoch(record, "timestamp")
        or 0
    )


def required_device_history_keys(reports_summary):
    """Collect report-linked identities that must survive payload capping."""
    required = {
        "bluetooth": set(),
        "wifi_bssids": set(),
        "wifi_ssids": set(),
        "wifi_clients": set(),
    }
    for report in (reports_summary or {}).get("reports") or []:
        if not isinstance(report, dict):
            continue
        evidence = report.get("evidence") or {}
        add_required_key(required["bluetooth"], evidence.get("mac"))
        for mac in evidence.get("sample_macs") or []:
            add_required_key(required["bluetooth"], mac)
        add_required_key(required["wifi_bssids"], evidence.get("bssid"))
        for bssid in evidence.get("bssids") or []:
            add_required_key(required["wifi_bssids"], bssid)
        add_required_key(required["wifi_ssids"], evidence.get("ssid"))
        add_required_key(required["wifi_clients"], evidence.get("client_mac"))
        add_required_key(required["wifi_clients"], evidence.get("mac"))
    return required


def add_required_key(target, value):
    """Add a normalized non-empty key to a required-record set."""
    text = str(value or "").strip()
    if text:
        target.add(text.lower())


def normalized_record_key(record, key):
    """Return a lower-case identity key from a materialized record."""
    return str((record or {}).get(key) or "").strip().lower()


def wifi_ap_required_for_browser(record, required):
    """Return True when a Wi-Fi AP is needed for a report/detail drilldown."""
    bssid = normalized_record_key(record, "bssid")
    ssid = normalized_record_key(record, "ssid") or "(blank)"
    return bssid in required["wifi_bssids"] or ssid in required["wifi_ssids"]


def compact_json_value_for_browser(value):
    """Keep nested evidence small without changing its displayed meaning."""
    if isinstance(value, dict):
        return {
            key: compact_json_value_for_browser(item)
            for key, item in value.items()
            if browser_value_is_useful(item)
        }
    if isinstance(value, list):
        return [
            compact_json_value_for_browser(item)
            for item in value
            if browser_value_is_useful(item)
        ]
    return value


def browser_value_is_useful(value):
    """Return False for empty values that only add JSON size."""
    return value not in (None, "", [], {})


def device_history_path():
    """Return the persisted Device History summary path."""
    return os.path.join(configured_log_dir(), "device_history", "device_history.json")


def subject_history_path():
    """Return the persisted Subject History summary path."""
    return os.path.join(configured_log_dir(), "device_history", "subject_history.json")


def subject_annotations_path():
    """Return the durable user annotation overlay path for Subject History."""
    return os.path.join(
        configured_log_dir(), "device_history", "subject_annotations.json"
    )


ANNOTATABLE_SUBJECT_TYPES = {
    ("wifi", "wifi_bssid"),
    ("wifi", "wifi_ssid"),
    ("wifi", "wifi_client"),
    ("bluetooth", "bluetooth_device"),
    ("lan", "lan_device"),
    ("lan", "lan_gateway"),
    ("rtl433", "rtl433_device"),
}


ANNOTATION_MAC_SUBJECT_TYPES = {
    ("bluetooth", "bluetooth_device"),
    ("wifi", "wifi_bssid"),
    ("wifi", "wifi_client"),
}


def normalize_annotation_subject_id(collector, subject_type, subject_id):
    """Return the canonical subject id used by durable annotation keys."""
    collector = str(collector or "").strip().lower()
    subject_type = str(subject_type or "").strip().lower()
    value = str(subject_id or "").strip()
    if (collector, subject_type) in ANNOTATION_MAC_SUBJECT_TYPES:
        compact = re.sub(r"[^0-9a-fA-F]", "", value)
        if len(compact) == 12:
            return ":".join(
                compact[index : index + 2] for index in range(0, 12, 2)
            ).upper()
    return value


def subject_annotation_key(collector, subject_type, subject_id):
    """Return the durable key for a subject annotation overlay."""
    collector = str(collector or "").strip().lower()
    subject_type = str(subject_type or "").strip().lower()
    return "{}|{}|{}".format(
        collector,
        subject_type,
        normalize_annotation_subject_id(collector, subject_type, subject_id),
    )


def normalize_annotation_key(key):
    """Canonicalize a stored annotation key while preserving unknown shapes."""
    parts = str(key or "").split("|", 2)
    if len(parts) != 3:
        return str(key or "")
    return subject_annotation_key(parts[0], parts[1], parts[2])


def subject_annotation_allowed(collector, subject_type):
    """Return True when this subject family supports user annotations."""
    return (
        str(collector or "").strip().lower(),
        str(subject_type or "").strip().lower(),
    ) in ANNOTATABLE_SUBJECT_TYPES


def load_subject_annotations():
    """Load durable Subject History annotations keyed by subject identity."""
    payload = read_json_file(subject_annotations_path())
    if not isinstance(payload, dict):
        return {}
    annotations = payload.get("annotations") or {}
    if not isinstance(annotations, dict):
        return {}
    clean = {}
    for key, value in annotations.items():
        if not isinstance(value, dict):
            continue
        custom_name = str(value.get("custom_name") or "").strip()
        operator_owned = bool(value.get("operator_owned"))
        if not custom_name and not operator_owned:
            continue
        entry = {
            "custom_name": custom_name[:160],
            "operator_owned": operator_owned,
            "updated_at": value.get("updated_at") or "",
            "updated_at_epoch": value.get("updated_at_epoch"),
        }
        clean[normalize_annotation_key(key)] = entry
    return clean


def save_subject_annotations(annotations):
    """Persist the user annotation overlay atomically."""
    updated_epoch = now_epoch()
    path = subject_annotations_path()
    payload = {
        "schema": "subject_annotations.v1",
        "updated_at": local_now(updated_epoch),
        "updated_at_epoch": updated_epoch,
        "annotations": annotations,
    }
    save_json_atomic(path, payload)
    try:
        os.chmod(path, 0o644)
    except OSError:
        logging.debug("could not chmod subject annotation file %s", path, exc_info=True)


def apply_subject_annotations(summary, annotations=None):
    """Apply user annotations as overlay fields without renaming subjects."""
    if not isinstance(summary, dict):
        return summary
    annotations = annotations if annotations is not None else load_subject_annotations()
    output = copy.deepcopy(summary)
    strip_subject_annotation_fields(output)
    if not annotations:
        return output
    annotate_subject_rows(output.get("subjects") or [], annotations)
    annotate_wifi_records((output.get("wifi") or {}), annotations)
    annotate_bluetooth_records(
        (output.get("bluetooth") or output.get("ble") or {}), annotations
    )
    annotate_lan_records(output.get("lan") or [], annotations)
    if output.get("ble") is not None and output.get("bluetooth") is not output.get(
        "ble"
    ):
        annotate_bluetooth_records((output.get("ble") or {}), annotations)
    return output


def strip_annotation_fields(record):
    """Remove derived annotation fields before applying the current overlay."""
    if isinstance(record, dict):
        record.pop("annotation", None)
        record.pop("custom_name", None)
        record.pop("operator_owned", None)
        for nested_key in ("data", "evidence"):
            nested = record.get(nested_key)
            if isinstance(nested, dict):
                nested.pop("annotation", None)
                nested.pop("custom_name", None)
                nested.pop("operator_owned", None)


def strip_subject_annotation_fields(summary):
    """Remove stale annotation overlays from subject/device summaries."""
    for subject in summary.get("subjects") or []:
        strip_annotation_fields(subject)
    wifi = summary.get("wifi") or {}
    for item in wifi.get("access_points") or []:
        strip_annotation_fields(item)
    for item in wifi.get("clients") or []:
        strip_annotation_fields(item)
    bluetooth_sections = []
    if isinstance(summary.get("bluetooth"), dict):
        bluetooth_sections.append(summary.get("bluetooth"))
    if isinstance(summary.get("ble"), dict) and summary.get("ble") is not summary.get(
        "bluetooth"
    ):
        bluetooth_sections.append(summary.get("ble"))
    for bluetooth in bluetooth_sections:
        for item in bluetooth.get("devices") or []:
            strip_annotation_fields(item)
    for item in summary.get("lan") or []:
        strip_annotation_fields(item)


def persist_subject_annotation_overlays(annotations):
    """Update persisted subject/device summaries after annotation changes."""
    for path in (subject_history_path(), device_history_path()):
        summary = read_json_file(path)
        if not isinstance(summary, dict):
            continue
        try:
            save_json_file(path, apply_subject_annotations(summary, annotations))
        except OSError:
            logging.exception("failed to update annotation overlay in %s", path)


def apply_report_annotations(reports, annotations=None):
    """Apply durable subject annotations to cached report rows."""
    if not isinstance(reports, dict):
        return reports
    annotations = annotations if annotations is not None else load_subject_annotations()
    output = copy.deepcopy(reports)
    strip_report_annotation_fields(output)
    if not annotations:
        return output
    for report in output.get("reports") or []:
        if not isinstance(report, dict):
            continue
        annotation, original = annotation_for_report(report, annotations)
        if not annotation:
            continue
        attach_annotation(report, annotation)
        evidence = report.get("evidence")
        if isinstance(evidence, dict):
            attach_annotation(evidence, annotation)
        custom_name = str(annotation.get("custom_name") or "").strip()
        if custom_name:
            report["subject"] = annotated_report_subject(
                custom_name,
                original or report.get("subject") or "",
            )
    return output


def strip_report_annotation_fields(reports):
    """Remove stale report annotation overlays before applying current ones."""
    for report in (reports or {}).get("reports") or []:
        if not isinstance(report, dict):
            continue
        custom_name = str(
            (
                (report.get("annotation") or {}).get("custom_name")
                if isinstance(report.get("annotation"), dict)
                else ""
            )
            or report.get("custom_name")
            or ""
        ).strip()
        subject = str(report.get("subject") or "")
        if custom_name:
            prefix = custom_name + " ("
            if subject.startswith(prefix) and subject.endswith(")"):
                report["subject"] = subject[len(prefix) : -1]
                subject = report["subject"]
        original = report_original_subject(report)
        if original and subject.endswith("({})".format(original)):
            report["subject"] = original
        elif (
            report_annotation_source(report)
            and " (" in subject
            and subject.endswith(")")
        ):
            report["subject"] = subject.rsplit(" (", 1)[1][:-1]
        strip_annotation_fields(report)


def report_annotation_source(report):
    """Return True for report sources that support user subject annotations."""
    return str((report or {}).get("source") or "").strip().lower() in (
        "bluetooth",
        "wifi",
        "wifi_monitor",
        "lan",
    )


def report_original_subject(report):
    """Reconstruct the unannotated report subject when evidence is available."""
    evidence = (
        report.get("evidence") if isinstance(report.get("evidence"), dict) else {}
    )
    source = str(report.get("source") or "").strip().lower()
    if source == "bluetooth":
        return bluetooth_report_original_subject(evidence)
    if source == "wifi":
        return wifi_report_original_subject(evidence)
    if source == "lan":
        report_type = str(report.get("type") or "").strip().lower()
        if "gateway" in report_type:
            return lan_gateway_report_original_subject(evidence)
        return lan_device_report_original_subject(evidence)
    return ""


def annotation_for_report(report, annotations):
    """Return the annotation and original subject for a report row."""
    evidence = (
        report.get("evidence") if isinstance(report.get("evidence"), dict) else {}
    )
    source = str(report.get("source") or "").strip().lower()
    report_type = str(report.get("type") or "").strip().lower()
    candidates = []
    original = ""
    if source == "bluetooth":
        mac = evidence.get("mac") or ""
        if mac:
            candidates.append(
                subject_annotation_key("bluetooth", "bluetooth_device", mac)
            )
            original = bluetooth_report_original_subject(evidence)
    elif source == "wifi":
        bssid = evidence.get("bssid") or ""
        ssid = evidence.get("ssid") or ""
        if bssid:
            candidates.append(subject_annotation_key("wifi", "wifi_bssid", bssid))
        if ssid:
            candidates.append(
                subject_annotation_key("wifi", "wifi_ssid", "ssid:{}".format(ssid))
            )
        original = wifi_report_original_subject(evidence)
    elif source == "wifi_monitor":
        mac = (
            evidence.get("mac")
            or evidence.get("client_mac")
            or evidence.get("transmitter_mac")
            or ""
        )
        if mac:
            candidates.append(subject_annotation_key("wifi", "wifi_client", mac))
            original = mac
    elif source == "lan":
        subject_id = (
            evidence.get("subject_key")
            or evidence.get("mac")
            or evidence.get("ip")
            or ""
        )
        if "gateway" in report_type:
            subject_id = (
                evidence.get("subject_key")
                or evidence.get("gateway_ip")
                or subject_id
                or "gateway"
            )
            candidates.append(subject_annotation_key("lan", "lan_gateway", subject_id))
            original = lan_gateway_report_original_subject(evidence)
        elif subject_id:
            candidates.append(subject_annotation_key("lan", "lan_device", subject_id))
            original = lan_device_report_original_subject(evidence)
    for key in candidates:
        annotation = annotations.get(key)
        if annotation:
            return annotation, original
    return None, ""


def annotated_report_subject(custom_name, original):
    """Return annotation plus original subject without double-wrapping."""
    custom = str(custom_name or "").strip()
    original = str(original or "").strip()
    if not custom:
        return original
    if original.startswith(custom + " (") and original.endswith(")"):
        return original
    return "{} ({})".format(custom, original) if original else custom


def bluetooth_report_original_subject(evidence):
    """Reconstruct a Bluetooth report subject from evidence."""
    parts = []
    names = [
        str(name).strip() for name in evidence.get("names") or [] if str(name).strip()
    ]
    if names:
        parts.append(names[0])
    if evidence.get("mac"):
        parts.append(str(evidence.get("mac")))
    if evidence.get("manufacturer"):
        parts.append(str(evidence.get("manufacturer")))
    return " - ".join(parts)


def wifi_report_original_subject(evidence):
    """Reconstruct a Wi-Fi report subject from evidence."""
    ssid = str(evidence.get("ssid") or "").strip()
    bssid = str(evidence.get("bssid") or "").strip()
    if ssid and bssid:
        return "{} - {}".format(ssid, bssid)
    return ssid or bssid


def lan_gateway_report_original_subject(evidence):
    """Reconstruct a LAN gateway report subject from evidence."""
    identity = (
        evidence.get("mac")
        or evidence.get("gateway_ip")
        or ", ".join(evidence.get("gateway_ips") or [])
        or evidence.get("subject_key")
        or ""
    )
    return "LAN gateway {}".format(identity).strip()


def lan_device_report_original_subject(evidence):
    """Reconstruct a LAN device report subject from evidence."""
    identity = (
        evidence.get("hostname")
        or evidence.get("mac")
        or evidence.get("ip")
        or evidence.get("subject_key")
        or "device"
    )
    return "LAN {}".format(identity)


def annotate_subject_rows(subjects, annotations):
    """Attach matching annotation payloads to normalized subject rows."""
    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        annotation = annotation_for_subject(subject, annotations)
        if annotation:
            attach_annotation(subject, annotation)


def annotation_for_subject(subject, annotations):
    """Return the annotation for one normalized subject row, if any."""
    collector = subject.get("collector")
    subject_type = subject.get("subject_type")
    if not subject_annotation_allowed(collector, subject_type):
        return None
    key = subject_annotation_key(collector, subject_type, subject.get("subject_id"))
    return annotations.get(key)


def attach_annotation(record, annotation):
    """Attach annotation fields while preserving the original subject identity."""
    custom_name = str((annotation or {}).get("custom_name") or "").strip()
    operator_owned = bool((annotation or {}).get("operator_owned"))
    if not custom_name and not operator_owned:
        return
    record["custom_name"] = custom_name
    record["operator_owned"] = operator_owned
    record["annotation"] = {
        "custom_name": custom_name,
        "operator_owned": operator_owned,
        "updated_at": (annotation or {}).get("updated_at") or "",
        "updated_at_epoch": (annotation or {}).get("updated_at_epoch"),
    }


def annotate_wifi_records(wifi, annotations):
    """Attach annotations to Wi-Fi AP/client records consumed by UI and Reports."""
    for ap in (wifi or {}).get("access_points") or []:
        if not isinstance(ap, dict):
            continue
        for subject_type, subject_id in (
            ("wifi_bssid", ap.get("bssid")),
            ("wifi_ssid", "ssid:{}".format(ap.get("ssid")) if ap.get("ssid") else ""),
        ):
            annotation = annotations.get(
                subject_annotation_key("wifi", subject_type, subject_id)
            )
            if annotation:
                attach_annotation(ap, annotation)
                break
    for client in (wifi or {}).get("clients") or []:
        if not isinstance(client, dict) or client.get("grouped_randomized"):
            continue
        annotation = annotations.get(
            subject_annotation_key("wifi", "wifi_client", client.get("mac"))
        )
        if annotation:
            attach_annotation(client, annotation)


def annotate_bluetooth_records(bluetooth, annotations):
    """Attach annotations to Bluetooth records consumed by UI and Reports."""
    for device in (bluetooth or {}).get("devices") or []:
        if not isinstance(device, dict) or device.get("grouped_randomized"):
            continue
        annotation = annotations.get(
            subject_annotation_key("bluetooth", "bluetooth_device", device.get("mac"))
        )
        if annotation:
            attach_annotation(device, annotation)


def annotate_lan_records(events, annotations):
    """Attach annotations to LAN summary event data consumed by UI and Reports."""
    for event in events or []:
        if not isinstance(event, dict):
            continue
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        event_type = event.get("type") or ""
        if event_type == "lan_gateway_summary":
            subject_type = "lan_gateway"
            subject_id = data.get("subject_key") or data.get("gateway_ip") or "gateway"
        elif event_type == "lan_device_summary":
            subject_type = "lan_device"
            subject_id = (
                data.get("subject_key")
                or data.get("mac")
                or data.get("ip")
                or "unknown"
            )
        else:
            continue
        annotation = annotations.get(
            subject_annotation_key("lan", subject_type, subject_id)
        )
        if annotation:
            attach_annotation(data, annotation)
            attach_annotation(event, annotation)


def findings_history_path():
    """Return the materialized Findings summary path."""
    return os.path.join(configured_log_dir(), "device_history", "findings_history.json")


def history_analysis_path():
    """Return the persisted history-analysis summary path."""
    return os.path.join(configured_log_dir(), "device_history", "history_analysis.json")


def reports_path():
    """Return the persisted report summary path."""
    return os.path.join(configured_log_dir(), "device_history", "reports.json")


def alert_state_path():
    """Return the persisted live alert state path."""
    return os.path.join(configured_log_dir(), "alerts_state.json")


def load_alert_state():
    """Restore active alert ACK/dedupe state from the previous process."""
    state = read_json_file(alert_state_path())
    if isinstance(state, dict):
        runtime["alerts"].load_state(state)
        logging.info(
            "loaded alert state path=%s active=%s",
            alert_state_path(),
            len(runtime["alerts"].active),
        )


def save_alert_state(force=False):
    """Persist live alert ACK/dedupe state when it changed."""
    alerts = runtime.get("alerts")
    if not alerts:
        return
    if not force and not alerts.dirty:
        return
    try:
        save_json_atomic(alert_state_path(), alerts.export_state())
        alerts.dirty = False
    except OSError as exc:
        logging.exception("failed to persist alert state: %s", exc)


def read_json_file(path):
    """Best-effort JSON file read for cached derived summaries."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def save_json_file(path, payload):
    """Write one materialized derived summary."""
    save_json_atomic(path, payload)


def load_cached_findings_history(window_days):
    """Compatibility shim: Findings History is no longer materialized."""
    return empty_findings_history(window_days)


def empty_findings_history(window_days):
    """Return a browser-ready empty Findings summary when no cache exists."""
    window_days = resolve_window_days(window_days)
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


def load_cached_subject_history(window_days):
    """Load display-ready Subject History without raw-log work."""
    summary = read_json_file(subject_history_path())
    if isinstance(summary, dict):
        summary.setdefault("window", view_window_metadata(None))
        summary.setdefault("generated_at_epoch", now_epoch())
        summary.setdefault("generated_at", local_now(summary["generated_at_epoch"]))
        summary["cached"] = True
        # Subject History is persisted as an all-retained materialized summary;
        # display_summary derives the selected view window without rereading logs.
        summary = apply_subject_annotations(summary)
        return SubjectHistoryBuilder(
            configured_log_dir(),
            state_path=subject_history_path(),
            device_history_state_path=device_history_path(),
            window_days=window_days,
            enabled_collectors=enabled_subject_history_collectors(),
        ).display_summary(summary, window_days)
    return empty_subject_history(window_days)


def empty_subject_history(window_days):
    """Return an empty Subject History summary when no cache exists."""
    generated_at_epoch = now_epoch()
    return {
        "schema": "subject_history.v1",
        "generated_at": local_now(generated_at_epoch),
        "generated_at_epoch": generated_at_epoch,
        "cached": True,
        "empty": True,
        "log_dir": configured_log_dir(),
        "state_path": subject_history_path(),
        "device_history_state_path": device_history_path(),
        "window": view_window_metadata(window_days),
        "files_read": 0,
        "records_read": 0,
        "wifi": {"access_points": [], "clients": []},
        "ble": {"devices": []},
        "bluetooth": {"devices": []},
        "aprsis": [],
        "rayhunter": [],
        "rtl433": [],
        "noaa": [],
        "usgs": [],
        "swpc": [],
        "lan": [],
        "subjects": [],
        "subject_counts": {
            "total": 0,
            "by_collector": {},
            "by_type": {},
        },
    }


def load_cached_device_history(window_days):
    """Load persisted Device History without falling back to raw-log parsing."""
    with runtime["derived_cache_lock"]:
        subject_history = runtime.get("subject_history")
    if (
        isinstance(subject_history, dict)
        and not subject_history.get("empty")
        and summary_matches_window(subject_history, window_days)
    ):
        return device_history_from_subject_history(subject_history, window_days)
    summary = read_json_file(device_history_path())
    if isinstance(summary, dict):
        summary.setdefault("window", view_window_metadata(None))
        summary.setdefault("generated_at_epoch", now_epoch())
        summary.setdefault("generated_at", local_now(summary["generated_at_epoch"]))
        output = WiFiBLEPostprocessor(
            configured_log_dir(),
            state_path=device_history_path(),
            window_days=window_days,
        ).display_summary(summary, window_days)
        output = apply_subject_annotations(output)
        output["cached"] = True
        return output
    return empty_device_history(window_days)


def device_history_from_subject_history(subject_history, window_days):
    """Return the compatibility Device History view from Subject History."""
    if not isinstance(subject_history, dict) or subject_history.get("empty"):
        return empty_device_history(window_days)
    output = {
        key: value
        for key, value in subject_history.items()
        if key
        not in (
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
    output["state_path"] = device_history_path()
    output["subject_history_state_path"] = subject_history.get("state_path")
    output["window"] = view_window_metadata(window_days)
    output["wifi"] = subject_history.get("wifi") or {
        "access_points": [],
        "clients": [],
    }
    output["ble"] = subject_history.get("ble") or {"devices": []}
    output["bluetooth"] = subject_history.get("bluetooth") or output["ble"]
    return output


def analysis_history_from_subject_history(subject_history, window_days):
    """Return the Device History compatibility input used by Insights."""
    return device_history_from_subject_history(subject_history, window_days)


def reports_history_from_subject_history(subject_history, window_days):
    """Return the subject-based history contract consumed by Reports."""
    if not isinstance(subject_history, dict) or subject_history.get("empty"):
        return {}
    history = dict(subject_history)
    history["subject_history"] = subject_history
    history["device_history"] = device_history_from_subject_history(
        subject_history, window_days
    )
    return history


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
    """Load persisted analysis without triggering a Subject History refresh."""
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
        reports["reports"] = [
            sanitize_rayhunter_report(item) for item in reports.get("reports") or []
        ]
        reports = apply_report_annotations(reports)
        reports["counts"] = count_reports(reports.get("reports") or [])
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


def sanitize_rayhunter_report(item):
    """Prevent older cached Reports rows from showing Rayhunter page bundles."""
    if not isinstance(item, dict):
        return item
    source = item.get("source") or ""
    report_type = item.get("type") or ""
    if source != "rayhunter" and not str(report_type).startswith("rayhunter"):
        return item
    sanitized = dict(item)
    evidence = clean_rayhunter_data(sanitized.get("evidence") or {})
    summary = clean_rayhunter_field(sanitized.get("summary"), max_length=500)
    if not summary:
        try:
            warning_count = int(float(evidence.get("warning_count") or 0))
        except (TypeError, ValueError):
            warning_count = 0
        if sanitized.get("severity") == "warning" and not warning_count:
            summary = "Rayhunter collector is not healthy."
        else:
            summary = "Rayhunter reported {} warning(s).".format(warning_count)
    sanitized["summary"] = summary
    sanitized["subject"] = "Rayhunter"
    sanitized["evidence"] = evidence
    return sanitized


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


def apply_live_observations_to_history(summary, copy_summary=True):
    """Overlay current backend live scan observations onto Device History.

    This is not a replacement for JSONL materialization. It is a consistency
    bridge between the live event stream and the just-generated derived bundle:
    if the live Wi-Fi/BLE tabs have newer rows than the materialized summary,
    Reports and Device History should not show stale last_seen values.
    """
    if not isinstance(summary, dict):
        return summary, {"wifi": 0, "bluetooth": 0, "max_lag_sec": 0}
    with runtime["live_observations_lock"]:
        prune_live_observation_map(
            runtime["live_observations"].get("wifi_aps") or {},
            live_observation_ttl_sec(),
            live_observation_max_items(),
        )
        prune_live_observation_map(
            runtime["live_observations"].get("bluetooth") or {},
            live_observation_ttl_sec(),
            live_observation_max_items(),
        )
        live_wifi = copy.deepcopy(runtime["live_observations"].get("wifi_aps") or {})
        live_bluetooth = copy.deepcopy(
            runtime["live_observations"].get("bluetooth") or {}
        )
    if not live_wifi and not live_bluetooth:
        return summary, {"wifi": 0, "bluetooth": 0, "max_lag_sec": 0}

    output = copy.deepcopy(summary) if copy_summary else summary
    wifi_records = output.setdefault("wifi", {}).setdefault("access_points", [])
    bluetooth_records = output.setdefault("bluetooth", {}).setdefault("devices", [])
    output.setdefault("ble", {})["devices"] = bluetooth_records
    stats = {"wifi": 0, "bluetooth": 0, "max_lag_sec": 0}
    stats["live_wifi"] = len(live_wifi)
    stats["live_bluetooth"] = len(live_bluetooth)
    stats["newest_live_wifi_epoch"] = max(
        (
            timestamp_epoch(item.get("last_seen_epoch"))
            for item in live_wifi.values()
            if isinstance(item, dict)
        ),
        default=None,
    )
    stats["newest_live_bluetooth_epoch"] = max(
        (
            timestamp_epoch(item.get("last_seen_epoch"))
            for item in live_bluetooth.values()
            if isinstance(item, dict)
        ),
        default=None,
    )
    stats["newest_history_wifi_epoch"] = max(
        (record_time_epoch(record, "last_seen") for record in wifi_records),
        default=None,
    )
    stats["newest_history_bluetooth_epoch"] = max(
        (record_time_epoch(record, "last_seen") for record in bluetooth_records),
        default=None,
    )
    stats["wifi"] = overlay_wifi_live_observations(wifi_records, live_wifi, stats)
    stats["bluetooth"] = overlay_bluetooth_live_observations(
        bluetooth_records, live_bluetooth, stats
    )
    wifi_records.sort(key=browser_record_sort_key, reverse=True)
    bluetooth_records.sort(key=browser_record_sort_key, reverse=True)
    output["ble"]["devices"] = bluetooth_records
    return output, stats


def overlay_wifi_live_observations(records, live_observations, stats):
    """Apply newer live Wi-Fi AP observations to materialized AP records."""
    by_bssid = {normalized_identity(record.get("bssid")): record for record in records}
    applied = 0
    for bssid, observation in (live_observations or {}).items():
        live_epoch = timestamp_epoch(observation.get("last_seen_epoch"))
        if live_epoch is None:
            continue
        record = by_bssid.get(bssid)
        if record is None:
            record = {
                "bssid": bssid,
                "ssid": observation.get("ssid") or "",
                "ssids": (
                    [observation.get("ssid") or ""] if observation.get("ssid") else []
                ),
                "first_seen": observation.get("last_seen") or local_now(live_epoch),
                "first_seen_epoch": live_epoch,
                "last_seen": observation.get("last_seen") or local_now(live_epoch),
                "last_seen_epoch": live_epoch,
                "channels": [],
                "encryption": [],
                "observations": 1,
                "sources": ["wifi"],
            }
            records.append(record)
            by_bssid[bssid] = record
            applied += 1
        else:
            current_epoch = record_time_epoch(record, "last_seen")
            if current_epoch is not None and live_epoch <= current_epoch:
                continue
            if current_epoch is not None:
                stats["max_lag_sec"] = max(
                    stats["max_lag_sec"], live_epoch - current_epoch
                )
            record["last_seen"] = observation.get("last_seen") or local_now(live_epoch)
            record["last_seen_epoch"] = live_epoch
            applied += 1
        for field in ("ssid", "vendor_name", "vendor_prefix"):
            if observation.get(field):
                record[field] = observation[field]
        append_unique(record, "ssids", observation.get("ssid"))
        append_unique(record, "channels", observation.get("channel"))
        append_unique(record, "encryption", observation.get("encryption"))
        update_signal_from_live(record, observation.get("signal_latest"))
    return applied


def overlay_bluetooth_live_observations(records, live_observations, stats):
    """Apply newer live Bluetooth observations to materialized device records."""
    by_mac = {normalized_identity(record.get("mac")): record for record in records}
    applied = 0
    for mac, observation in (live_observations or {}).items():
        live_epoch = timestamp_epoch(observation.get("last_seen_epoch"))
        if live_epoch is None:
            continue
        record = by_mac.get(mac)
        if record is None:
            record = {
                "mac": mac,
                "names": [],
                "first_seen": observation.get("last_seen") or local_now(live_epoch),
                "first_seen_epoch": live_epoch,
                "last_seen": observation.get("last_seen") or local_now(live_epoch),
                "last_seen_epoch": live_epoch,
                "seen_count": 1,
                "update_count": 0,
                "lost_count": 0,
                "service_uuids": [],
                "transports": ["ble"],
            }
            records.append(record)
            by_mac[mac] = record
            applied += 1
        else:
            current_epoch = record_time_epoch(record, "last_seen")
            if current_epoch is not None and live_epoch <= current_epoch:
                pass
            else:
                if current_epoch is not None:
                    stats["max_lag_sec"] = max(
                        stats["max_lag_sec"], live_epoch - current_epoch
                    )
                record["last_seen"] = observation.get("last_seen") or local_now(
                    live_epoch
                )
                record["last_seen_epoch"] = live_epoch
                applied += 1
        if observation.get("name"):
            record["name"] = observation["name"]
            append_unique(record, "names", observation["name"])
        for field in (
            "manufacturer",
            "manufacturer_name",
            "model_number",
            "serial_number",
            "firmware_revision",
            "hardware_revision",
            "software_revision",
            "pnp_id",
            "vendor_name",
            "vendor_prefix",
            "findmy_label",
            "findmy_payload_type",
            "findmy_status",
            "findmy_hint",
        ):
            if observation.get(field):
                record[field] = observation[field]
        if observation.get("findmy_accessory"):
            record["findmy_accessory"] = True
        for uuid in observation.get("service_uuids") or []:
            append_unique(record, "service_uuids", uuid)
        update_signal_from_live(record, observation.get("signal_latest"))
    return applied


def append_unique(record, field, value):
    """Append a non-empty scalar to a list field once."""
    if value in (None, ""):
        return
    values = list(record.get(field) or [])
    if value not in values:
        values.append(value)
    record[field] = values


def update_signal_from_live(record, value):
    """Update latest/min/max signal fields from a live observation."""
    try:
        signal = int(value)
    except (TypeError, ValueError):
        return
    current_min = int_or_none(record.get("signal_min"))
    current_max = int_or_none(record.get("signal_max"))
    record["signal_latest"] = signal
    record["signal_min"] = signal if current_min is None else min(current_min, signal)
    record["signal_max"] = signal if current_max is None else max(current_max, signal)


def int_or_none(value):
    """Return an integer for numeric fields that may be blank in old summaries."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def format_log_epoch(epoch):
    """Format optional epoch values for concise diagnostics."""
    value = timestamp_epoch(epoch)
    return local_now(value) if value is not None else "none"


def recent_device_history_summary(max_age_sec):
    """Return a recent persisted Device History summary, if one is usable."""
    summary = read_json_file(device_history_path())
    if not isinstance(summary, dict) or summary.get("empty"):
        return None, None
    generated_epoch = summary_generated_epoch(summary) or timestamp_epoch(
        summary.get("generated_at")
    )
    if generated_epoch is None:
        return None, None
    age_sec = max(0, now_epoch() - int(generated_epoch))
    if age_sec > max_age_sec:
        return None, age_sec
    return summary, age_sec


def apply_live_overlay_and_prune_device_history(
    device_builder, full_device_summary, persist=False
):
    """Apply live Wi-Fi/Bluetooth overlay and optional persisted pruning."""
    overlay_started = time.monotonic()
    full_device_summary, overlay_stats = apply_live_observations_to_history(
        full_device_summary,
        copy_summary=not persist,
    )
    logging.info(
        "derived device_history live overlay finished elapsed=%.2fs",
        time.monotonic() - overlay_started,
    )
    if overlay_stats["wifi"] or overlay_stats["bluetooth"]:
        logging.info(
            "derived live overlay applied; wifi=%s/%s bluetooth=%s/%s "
            "max_lag=%.1fs newest_live_wifi=%s newest_history_wifi=%s "
            "newest_live_bluetooth=%s newest_history_bluetooth=%s",
            overlay_stats["wifi"],
            overlay_stats.get("live_wifi", 0),
            overlay_stats["bluetooth"],
            overlay_stats.get("live_bluetooth", 0),
            overlay_stats["max_lag_sec"],
            format_log_epoch(overlay_stats.get("newest_live_wifi_epoch")),
            format_log_epoch(overlay_stats.get("newest_history_wifi_epoch")),
            format_log_epoch(overlay_stats.get("newest_live_bluetooth_epoch")),
            format_log_epoch(overlay_stats.get("newest_history_bluetooth_epoch")),
        )
    else:
        logging.info(
            "derived live overlay checked; live_wifi=%s live_bluetooth=%s "
            "newest_live_wifi=%s newest_history_wifi=%s "
            "newest_live_bluetooth=%s newest_history_bluetooth=%s",
            overlay_stats.get("live_wifi", 0),
            overlay_stats.get("live_bluetooth", 0),
            format_log_epoch(overlay_stats.get("newest_live_wifi_epoch")),
            format_log_epoch(overlay_stats.get("newest_history_wifi_epoch")),
            format_log_epoch(overlay_stats.get("newest_live_bluetooth_epoch")),
            format_log_epoch(overlay_stats.get("newest_history_bluetooth_epoch")),
        )
    prune_started = time.monotonic()
    full_device_summary, pruned_bluetooth = (
        device_builder.prune_low_value_bluetooth_devices(full_device_summary)
    )
    full_device_summary, pruned_ap_sessions = device_builder.prune_stale_ap_sessions(
        full_device_summary
    )
    logging.info(
        "derived device_history prune finished elapsed=%.2fs "
        "pruned_bluetooth=%s pruned_ap_sessions=%s",
        time.monotonic() - prune_started,
        pruned_bluetooth,
        pruned_ap_sessions,
    )
    return full_device_summary


def build_or_reuse_device_history_for_refresh(log_dir, window_days):
    """Return Device History for Subject History without duplicating background work."""
    device_builder = WiFiBLEPostprocessor(
        log_dir,
        state_path=device_history_path(),
        window_days=window_days,
    )
    lock = runtime["device_history_update_lock"]
    if not lock.acquire(blocking=False):
        max_age_sec = max(device_history_update_interval_sec() * 2, 30)
        cached_summary, age_sec = recent_device_history_summary(max_age_sec)
        if isinstance(cached_summary, dict):
            logging.info(
                "derived device_history reused cached summary while background "
                "update is active; age=%ss max_age=%ss records=%s generated=%s",
                age_sec,
                max_age_sec,
                cached_summary.get("records_read", 0),
                cached_summary.get("generated_at") or "",
            )
            return apply_live_overlay_and_prune_device_history(
                device_builder, cached_summary, persist=False
            )
        wait_started = time.monotonic()
        logging.info(
            "derived device_history waiting for active background update; "
            "cached_age=%s max_age=%s",
            age_sec if age_sec is not None else "none",
            max_age_sec,
        )
        lock.acquire()
        logging.info(
            "derived device_history wait for active background update finished elapsed=%.2fs",
            time.monotonic() - wait_started,
        )
    try:
        started = time.monotonic()
        full_device_summary = device_builder.build_summary()
        logging.info(
            "derived device_history build_summary finished elapsed=%.2fs records=%s "
            "incremental_records=%s incremental_by_collector=%s raw_read_stats=%s",
            time.monotonic() - started,
            full_device_summary.get("records_read", 0),
            full_device_summary.get("incremental_records_read", 0),
            full_device_summary.get("incremental_records_read_by_collector") or {},
            compact_incremental_read_stats(
                full_device_summary.get("incremental_jsonl_read_stats")
            ),
        )
        full_device_summary = apply_live_overlay_and_prune_device_history(
            device_builder, full_device_summary, persist=True
        )
        full_device_summary = apply_subject_annotations(full_device_summary)
        try:
            device_builder.save_summary(full_device_summary)
        except OSError as exc:
            logging.exception("failed to persist device history: %s", exc)
        return full_device_summary
    finally:
        lock.release()


def _push_known_bssids_to_alerts(subject_history):
    """Extract BSSID->SSID mapping from subject history and push to AlertEngine.

    Used by wifi_disruption_alerts to suppress false positives when deauth
    frames are between co-BSSIDs of the same known SSID (e.g., band steering).
    """
    if runtime.get("alerts") is None:
        return
    wifi = (subject_history or {}).get("wifi") or {}
    aps = wifi.get("access_points") or []
    bssid_to_ssid = {}
    for ap in aps:
        bssid = ap.get("bssid")
        ssid = ap.get("ssid")
        if bssid and ssid:
            bssid_to_ssid[normalized_identity(bssid)] = ssid
    runtime["alerts"].set_known_bssids(bssid_to_ssid)


def backfill_missing_snapshots():
    """Build hourly snapshots for missing hours within the lookback window.

    The lookback is controlled by ``ui.snapshot_retention_hours`` (default 24).
    Set to 168 for a 7-day window, or 0 to disable.

    Reads the persisted ``subject_history.json`` and builds a compact
    snapshot for each hour that has subject data but no existing snapshot
    file on disk.  This ensures the SKIR presence timeline is complete
    after a restart even before the scheduler's first cycle.

    Best-effort: hours predating the cached Subject History are skipped.
    The scheduler fills the current hour and future hours going forward.
    """
    backfill_hours = snapshot_retention_hours()
    if backfill_hours <= 0:
        logging.info("snapshot backfill disabled (backfill_hours=0)")
        return
    snapshot_dir = os.path.join(configured_log_dir(), "sh_snapshots")
    started = time.monotonic()
    try:
        existing = load_snapshots(snapshot_dir) if os.path.isdir(snapshot_dir) else {}
    except OSError:
        existing = {}

    now = int(time.time())
    now_hour = now - (now % 3600)
    hours_to_check = list(
        range(now_hour - backfill_hours * 3600, now_hour, 3600)
    )
    missing = [h for h in hours_to_check if h not in existing]

    if not missing:
        logging.info(
            "snapshot backfill: all %sh covered (%s snapshots on disk) "
            "elapsed=%.2fs",
            backfill_hours,
            len(existing),
            time.monotonic() - started,
        )
        return

    sh_path = subject_history_path()
    sh_dict = read_json_file(sh_path)
    if not isinstance(sh_dict, dict) or sh_dict.get("empty"):
        logging.info(
            "snapshot backfill skipped; no cached subject history at %s "
            "elapsed=%.2fs",
            sh_path,
            time.monotonic() - started,
        )
        return

    snapshots = {}
    for hour_epoch in missing:
        expected_file = time.strftime(
            "snapshot_%Y-%m-%dT%H:%M.json", time.localtime(hour_epoch)
        )
        expected_path = os.path.join(snapshot_dir, expected_file)
        if os.path.isfile(expected_path):
            continue

        snap = build_snapshot_from_sh(sh_dict, hour_epoch=hour_epoch)
        has_data = any(
            isinstance(v, dict) and v.get("subject_count", 0) > 0
            for k, v in snap.items()
            if not str(k).startswith("_")
        )
        if has_data:
            snapshots[hour_epoch] = snap

    if snapshots:
        try:
            written = save_snapshots(snapshots, snapshot_dir, retention_hours=snapshot_retention_hours())
            logging.info(
                "snapshot backfill built %s snapshots written=%s "
                "missing_checked=%s elapsed=%.2fs",
                len(snapshots),
                written,
                len(missing),
                time.monotonic() - started,
            )
        except OSError as exc:
            logging.warning(
                "snapshot backfill save failed: %s elapsed=%.2fs",
                exc,
                time.monotonic() - started,
            )
    else:
        logging.info(
            "snapshot backfill: no subject data for %s missing hours " "elapsed=%.2fs",
            len(missing),
            time.monotonic() - started,
        )


def _save_hourly_snapshot(subject_display):
    """Save one compact hourly snapshot for the 24h SKIR ring buffer.

    Only writes when the current hour doesn't already have a snapshot on
    disk.  Snapshot retention is 24 hours — older files are purged by
    ``save_snapshots``.
    """
    snapshot_dir = os.path.join(configured_log_dir(), "sh_snapshots")
    try:
        now = int(time.time())
        # Save for the most recently completed hour.  The snapshot label
        # is the END of the hour: "09:00" = data from 08:00–08:59.
        # The first refresh after 09:00 creates the 09:00 snapshot.
        hour_epoch = now - (now % 3600)
        # Skip if this hour already has a snapshot (check by filename:
        # "snapshot_2026-06-28T16:00.json" encodes the hour label).
        expected = time.strftime(
            "snapshot_%Y-%m-%dT%H:%M.json", time.localtime(hour_epoch)
        )
        expected_path = os.path.join(snapshot_dir, expected)
        if os.path.isfile(expected_path):
            return
        snap = build_snapshot_from_sh(subject_display, hour_epoch=hour_epoch)
        save_snapshots({hour_epoch: snap}, snapshot_dir, retention_hours=snapshot_retention_hours())
        logging.info(
            "hourly snapshot saved hour=%s subjects=%s",
            time.strftime("%Y-%m-%d %H:00", time.localtime(hour_epoch)),
            sum(
                s.get("subject_count", 0)
                for s in snap.values()
                if isinstance(s, dict) and not str(s).startswith("_")
            ),
        )
    except OSError as exc:
        logging.warning("hourly snapshot save failed: %s", exc)


def refresh_subject_history(window_days="default"):
    """Build Subject History and its Device History compatibility view."""
    window_days = resolve_window_days(window_days)
    log_dir = configured_log_dir()
    derived_refresh.set_stage_label("Subject History — checking pending data")
    pending_started = time.monotonic()
    cached_full_summary = read_json_file(subject_history_path())
    pending_stats = subject_history_pending_jsonl_stats(cached_full_summary)
    pending_raw = pending_stats.get("pending", False)
    logging.info(
        "derived subject_history pending check finished elapsed=%.2fs "
        "pending_raw=%s pending_bytes=%s pending_files=%s pending_by_collector=%s "
        "cached_generated=%s",
        time.monotonic() - pending_started,
        pending_raw,
        pending_stats.get("pending_bytes", 0),
        pending_stats.get("pending_files", 0),
        compact_pending_jsonl_stats(pending_stats),
        (cached_full_summary or {}).get("generated_at") or "",
    )
    if (
        isinstance(cached_full_summary, dict)
        and not cached_full_summary.get("empty")
        and not pending_raw
    ):
        derived_refresh.set_stage_label("Subject History — loading cached")
        reuse_started = time.monotonic()
        subject_display = load_cached_subject_history(window_days)
        device_display = device_history_from_subject_history(
            subject_display, window_days
        )
        with runtime["derived_cache_lock"]:
            runtime["subject_history"] = subject_display
            runtime["device_history"] = device_display
        _push_known_bssids_to_alerts(subject_display)
        _save_hourly_snapshot(subject_display)
        logging.info(
            "derived subject_history reused cached summary; window=%s elapsed=%.2fs subjects=%s generated=%s",
            window_days,
            time.monotonic() - reuse_started,
            ((subject_display.get("subject_counts") or {}).get("total", 0)),
            subject_display.get("generated_at") or "",
        )
        return subject_display
    subject_builder = SubjectHistoryBuilder(
        log_dir,
        state_path=subject_history_path(),
        device_history_state_path=device_history_path(),
        window_days=window_days,
        enabled_collectors=enabled_subject_history_collectors(),
        progress_callback=lambda text: derived_refresh.set_stage_label(
            "Subject History — {}".format(text)
        ),
    )
    subject_started = time.monotonic()
    full_subject_summary = subject_builder.build_summary()
    full_subject_summary = apply_subject_annotations(full_subject_summary)
    logging.info(
        "derived subject_history build_summary finished elapsed=%.2fs subjects=%s "
        "records=%s incremental_records=%s incremental_by_collector=%s raw_read_stats=%s",
        time.monotonic() - subject_started,
        (full_subject_summary.get("subject_counts") or {}).get("total", 0),
        full_subject_summary.get("records_read", 0),
        full_subject_summary.get("incremental_records_read", 0),
        full_subject_summary.get("incremental_records_read_by_collector") or {},
        compact_incremental_read_stats(
            full_subject_summary.get("incremental_jsonl_read_stats")
        ),
    )
    try:
        save_started = time.monotonic()
        save_json_file(subject_history_path(), full_subject_summary)
        logging.info(
            "derived subject_history save finished elapsed=%.2fs",
            time.monotonic() - save_started,
        )
    except OSError as exc:
        logging.exception("failed to persist subject history: %s", exc)

    display_started = time.monotonic()
    subject_display = subject_builder.display_summary(full_subject_summary, window_days)
    device_display = device_history_from_subject_history(subject_display, window_days)
    logging.info(
        "derived subject_history display_summary finished elapsed=%.2fs",
        time.monotonic() - display_started,
    )
    logging.info(
        "derived subject_history display cache disabled; display derived on demand"
    )
    with runtime["derived_cache_lock"]:
        runtime["subject_history"] = subject_display
        runtime["device_history"] = device_display
    _push_known_bssids_to_alerts(subject_display)
    _save_hourly_snapshot(subject_display)
    return subject_display


def refresh_device_history(window_days="default", update_analysis=True):
    """Compatibility wrapper: Device History is derived from Subject History."""
    window_days = resolve_window_days(window_days)
    subject_history = refresh_subject_history(window_days)
    display_summary = device_history_from_subject_history(subject_history, window_days)
    if update_analysis:
        refresh_history_analysis(window_days)
    return display_summary


def refresh_history_analysis(window_days="default"):
    """Analyze cached Subject History through the Device History compatibility view."""
    window_days = resolve_window_days(window_days)
    with runtime["derived_cache_lock"]:
        subject_history = runtime.get("subject_history")
    if subject_history is None or not summary_matches_window(
        subject_history, window_days
    ):
        # Analysis depends on Subject History. Rebuild only that dependency when
        # the current cached history belongs to another View window.
        subject_history = refresh_subject_history(window_days)
    history = analysis_history_from_subject_history(subject_history, window_days)
    if history is None:
        generated_at_epoch = now_epoch()
        return {
            "generated_at": local_now(generated_at_epoch),
            "generated_at_epoch": generated_at_epoch,
            "observations": [],
            "counts": {"total": 0, "warning": 0, "info": 0},
        }
    history_epoch = summary_generated_epoch(subject_history)
    with runtime["derived_cache_lock"]:
        cached_analysis = runtime.get("history_analysis")
    if cached_analysis is None:
        cached_analysis = load_cached_history_analysis(window_days)
    if history_epoch and not dependent_summary_is_stale(
        cached_analysis, history_epoch, window_days
    ):
        logging.info(
            "derived history_analysis reused cached summary; window=%s generated=%s subject_history_generated=%s observations=%s",
            window_days,
            (cached_analysis or {}).get("generated_at") or "",
            subject_history.get("generated_at") or "",
            len((cached_analysis or {}).get("observations") or []),
        )
        with runtime["derived_cache_lock"]:
            runtime["history_analysis"] = cached_analysis
        return cached_analysis
    config = runtime.get("config") or {}
    analyzer = HistoryAnalyzer(config.get("history_analysis", {}))
    analyze_started = time.monotonic()
    analysis_cfg = config.get("history_analysis") or {}
    include_sessions = bool(
        analysis_cfg.get("bundle_correlation_enabled", True))
    analysis_input = recent_history_for_insights(history)
    bundle_input = None
    if include_sessions:
        # Bundle correlation correlates multi-hour co-movement, so the tactical
        # 60-min cutoff would make bundles flicker with refresh timing. Use a
        # 24h lookback with session arrays for the bundle rule only — the other
        # rules keep the compact session-stripped input.
        bundle_input = recent_history_for_insights(
            history,
            include_sessions=True,
            cutoff_epoch=now_epoch() - 86400,
        )
    analysis = analyzer.analyze(analysis_input, bundle_history=bundle_input)
    logging.info(
        "derived history_analysis build finished elapsed=%.2fs observations=%s",
        time.monotonic() - analyze_started,
        len(analysis.get("observations") or []),
    )
    analysis["window"] = view_window_metadata(window_days)
    analysis["insights_window"] = insights_recent_window_metadata()
    state_path = history.get("state_path") or os.path.join(
        "logs", "device_history", "device_history.json"
    )
    analysis_path = os.path.join(os.path.dirname(state_path), "history_analysis.json")
    analysis["state_path"] = analysis_path
    try:
        save_started = time.monotonic()
        save_analysis(analysis_path, analysis)
        logging.info(
            "derived history_analysis save finished elapsed=%.2fs",
            time.monotonic() - save_started,
        )
    except OSError as exc:
        logging.exception("failed to persist history analysis: %s", exc)
    display = display_history_analysis(analysis, window_days)
    with runtime["derived_cache_lock"]:
        runtime["history_analysis"] = display
    return display


def refresh_reports(window_days="default"):
    """Generate report-style summaries from cached Subject History."""
    window_days = resolve_window_days(window_days)
    with runtime["derived_cache_lock"]:
        subject_history = runtime.get("subject_history")
    if subject_history is None or not summary_matches_window(
        subject_history, window_days
    ):
        subject_history = refresh_subject_history(window_days)
    history_epoch = summary_generated_epoch(subject_history)
    with runtime["derived_cache_lock"]:
        cached_reports = runtime.get("reports")
    if cached_reports is None:
        cached_reports = load_cached_reports(window_days)
    if history_epoch and not dependent_summary_is_stale(
        cached_reports, history_epoch, window_days
    ):
        logging.info(
            "derived reports reused cached summary; window=%s generated=%s subject_history_generated=%s reports=%s",
            window_days,
            (cached_reports or {}).get("generated_at") or "",
            subject_history.get("generated_at") or "",
            len((cached_reports or {}).get("reports") or []),
        )
        with runtime["derived_cache_lock"]:
            runtime["reports"] = cached_reports
        return cached_reports
    config = runtime.get("config") or {}
    history = reports_history_from_subject_history(subject_history, window_days)
    builder = ReportsBuilder(config.get("reports", {}), window_days=window_days)
    build_started = time.monotonic()
    alerts = runtime.get("alerts")
    active_alerts = alerts.snapshot() if alerts else []
    insight_data = runtime.get("history_analysis") or load_cached_history_analysis(
        window_days
    )
    collector_health = _build_collector_health_summary()
    report = builder.build(
        history or {},
        active_alerts=active_alerts,
        insight_data=insight_data,
        collector_health=collector_health,
    )
    logging.info(
        "derived reports build finished elapsed=%.2fs reports=%s",
        time.monotonic() - build_started,
        len(report.get("reports") or []),
    )
    report["state_path"] = reports_path()
    try:
        save_started = time.monotonic()
        save_reports(reports_path(), report)
        logging.info(
            "derived reports save finished elapsed=%.2fs",
            time.monotonic() - save_started,
        )
    except OSError as exc:
        logging.exception("failed to persist reports: %s", exc)
    with runtime["derived_cache_lock"]:
        runtime["reports"] = report
    return report


def _build_collector_health_summary():
    """Return per-collector health data for report enrichment."""
    collectors = runtime.get("collectors") or {}
    if not isinstance(collectors, dict):
        return {}
    health = {}
    for key, coll in collectors.items():
        entry = {
            "state": getattr(coll, "state", None),
            "events_this_session": getattr(coll, "events_this_session", 0),
            "last_event_epoch": getattr(coll, "last_event_epoch", None),
            "warning": getattr(coll, "warning", None),
            "active_hardware": getattr(coll, "active_hardware", None),
        }
        # Keep only non-None values
        health[key] = {k: v for k, v in entry.items() if v is not None}
    return health


def run_loop(config):
    """Own the asyncio event loop used by all collectors."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    runtime["loop"] = loop
    bus = EventBus()
    runtime["bus"] = bus
    logging.info("collector event loop starting")
    try:
        loop.run_until_complete(start_collectors(config, bus))

        msg = runtime.pop("_migration_msg", None)
        if msg:

            async def _emit_migration_alert():
                await asyncio.sleep(1)
                epoch = now_epoch()
                alert_events = runtime["alerts"].emit_alert(
                    alert_type="config_migration",
                    key="config_migration:{}".format(int(epoch)),
                    level="warning",
                    source="system",
                    title="Config moved",
                    subject="Config directory",
                    summary=msg,
                    timestamp=local_now(epoch),
                    now=epoch,
                    emit=True,
                )
                for alert_event in alert_events:
                    bus.publish(alert_event)
                broadcast("alerts_snapshot", runtime["alerts"].snapshot())

            loop.create_task(_emit_migration_alert())

        loop.run_forever()
    except Exception as exc:
        logging.exception("collector event loop failed: %s", exc)
        raise
    finally:
        logging.info("collector event loop stopped")


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
    save_alert_state(force=True)
    executor = runtime.get("push_executor")
    if executor:
        executor.shutdown(wait=False)
        runtime["push_executor"] = None
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
    """Return internal runtime knobs from config/skannr.yaml with safe defaults."""
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
    parser.add_argument(
        "--config", default=CONFIG_PATH, help="Path to config/skannr.yaml"
    )
    parser.add_argument(
        "-debug",
        "--debug",
        action="store_true",
        help="Enable DEBUG logging and open a live log window when possible",
    )
    return parser.parse_args()


def open_debug_log_window(log_path):
    """Open a live log tail in a desktop terminal when this host has one."""
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        logging.info("debug log window not opened: no graphical display detected")
        return
    terminals = [
        ("x-terminal-emulator", ["-e", "tail", "-n", "200", "-F", log_path]),
        ("lxterminal", ["-e", "tail -n 200 -F '{}'".format(log_path)]),
        (
            "xterm",
            ["-T", "Skannr Debug Log", "-e", "tail", "-n", "200", "-F", log_path],
        ),
    ]
    for executable, args in terminals:
        path = shutil.which(executable)
        if not path:
            continue
        try:
            subprocess.Popen([path] + args)
            logging.info("opened debug log window with %s", executable)
            return
        except OSError as exc:
            logging.warning(
                "failed to open debug log window with %s: %s", executable, exc
            )
    logging.info(
        "debug log window not opened: no supported terminal found; tail %s",
        log_path,
    )


def log_aprsis_config_summary(config):
    """Log APRS-IS config source without exposing passcodes."""
    aprsis = ((config or {}).get("collectors") or {}).get("aprsis") or {}
    if not aprsis:
        logging.info("Loaded APRS-IS config: not configured")
        return
    feeds = []
    for feed in aprsis.get("feeds") or []:
        if not isinstance(feed, dict):
            continue
        feeds.append(
            {
                "name": feed.get("name") or "",
                "role": feed.get("role") or "",
                "host": feed.get("host") or "",
                "port": feed.get("port") or "",
                "filter": feed.get("filter") or "",
                "enforce_radius": bool(feed.get("enforce_radius")),
            }
        )
    logging.info(
        "Loaded APRS-IS config: file=%s enabled=%s feed_count=%s feeds=%s "
        "top_level_host=%s top_level_filter_set=%s",
        aprsis.get("config_file") or "",
        aprsis.get("enabled"),
        len(feeds),
        feeds,
        aprsis.get("host") or "",
        bool(aprsis.get("filter")),
    )


def _migrate_config_if_needed(config_path):
    """Copy config from the pre-0.3.5 repo location to ~/.config/skannr/.

    Returns an alert-worthy message string when the operator should be
    notified, or None when there is nothing to say.  The caller emits a
    synthetic alert so the message appears in the global alert strip.

    This function is called BEFORE logging is configured, so it must not
    call logging.* or print().  The caller is responsible for logging.
    """
    import shutil

    if config_path != CONFIG_PATH:
        return None
    old_config = os.path.join(OLD_CONFIG_DIR, "skannr.yaml")

    if not os.path.exists(old_config):
        return None

    if not os.path.exists(CONFIG_PATH):
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            ensure_owner(CONFIG_DIR)
            for item in os.listdir(OLD_CONFIG_DIR):
                src = os.path.join(OLD_CONFIG_DIR, item)
                dst = os.path.join(CONFIG_DIR, item)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(src, dst)
                ensure_owner(dst)
        except OSError as exc:
            return "Config migration failed: {} — {}".format(OLD_CONFIG_DIR, exc)
        return "Config moved to {} — you may delete {}.".format(
            CONFIG_DIR,
            OLD_CONFIG_DIR,
        )

    return "Old config {} still exists — you may delete it.".format(
        OLD_CONFIG_DIR,
    )


def main():
    """Configure logging/persistence, start collectors, and serve the UI."""
    args = parse_args()
    runtime["_migration_msg"] = _migrate_config_if_needed(args.config)
    config = load_config(args.config)
    runtime["config"] = config
    runtime["event_log"] = deque(maxlen=runtime_int("event_log_maxlen", 100, minimum=1))
    runtime["alerts"] = AlertEngine(alert_engine_config(config))
    runtime["findings"] = FindingsEngine(config.get("findings", {}))
    runtime["push_executor"] = concurrent.futures.ThreadPoolExecutor(
        max_workers=1, thread_name_prefix="skannr-push"
    )
    log_dir = configured_log_dir()
    os.makedirs(log_dir, exist_ok=True)
    ensure_owner(log_dir)
    log_path = os.path.join(log_dir, "skannr.log")
    log_level_name = "DEBUG" if args.debug else config["skannr"]["log_level"].upper()
    logging.basicConfig(
        level=getattr(logging, log_level_name, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler(),
        ],
    )
    ensure_owner(log_path)
    cleanup_orphaned_temp_files(log_dir)
    if args.debug:
        logging.info("debug logging enabled; log_path=%s", log_path)
        open_debug_log_window(log_path)
    migration_msg = runtime.get("_migration_msg")
    if migration_msg:
        logging.warning("Config migration: %s", migration_msg)
    _migrate_ui_config_keys(config)
    load_alert_state()
    log_aprsis_config_summary(config)
    runtime["persistence"] = load_persistence(config)
    bootstrap_findings()
    # Seed recent device identities from the materialized summary so a restart
    # does not classify every visible AP/BLE device as newly observed.
    runtime["findings"].seed_device_history(load_cached_device_history(None))

    signal.signal(signal.SIGINT, stop_runtime)
    signal.signal(signal.SIGTERM, stop_runtime)

    thread = threading.Thread(target=run_loop, args=(config,), daemon=True)
    thread.start()
    start_device_history_worker()
    _startup_prune_device_history()
    backfill_missing_snapshots()
    start_derived_refresh_scheduler()

    run_web_listeners(config)


def run_web_listeners(config):
    """Start one or more dashboard listeners from config/skannr.yaml.

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
    """Parse one compact host:port listener entry from config/skannr.yaml."""
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
