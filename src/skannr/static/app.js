const socket = createLocalEventSocket();
const CLIENT_SESSION_ID = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
const rows = {
  ble: new Map(),
  btClassic: new Map(),
  bleIdentify: [],
  aprsis: [],
  noaa: [],
  usgs: [],
  swpc: [],
  pws: [],
  adsb: [],
  rtl433: [],
  bleDiagnostic: "",
  bleScanDetail: "",
  rayhunter: [],
  lan: [],
  lanIdentify: [],
  aps: new Map(),
  monitorEvents: [],
  insights: [],
  reports: [],
  alerts: []
};
let COLLECTOR_SUBTABS = [
  {value: "all", label: "All"},
  {value: "wifi", label: "Wi-Fi Scan"},
  {value: "wifi_monitor", label: "Wi-Fi Monitor"},
  {value: "bluetooth", label: "Bluetooth"},
  {value: "rtl433", label: "RTL-433"},
  {value: "adsb", label: "ADS-B"},
  {value: "rayhunter", label: "Rayhunter"},
  {value: "aprsis", label: "APRS-IS"},
  {value: "noaa", label: "NOAA"},
  {value: "usgs", label: "USGS"},
  {value: "swpc", label: "SWPC"},
  {value: "pws", label: "PWS"},
  {value: "lan", label: "LAN"},
  {value: "system", label: "System"}
];
let COLLECTOR_SOURCE_GROUPS = {
  bluetooth: {label: "Bluetooth", members: ["ble", "ble_identify", "bt_classic"]},
};
let COLLECTOR_METADATA = [];
let latestCollectorStatuses = [];
let latestSystemStatus = {};
let latestFindingsHistory = null;
let latestDeviceHistory = null;
let activeSubtabs = {
  insights: "all",
  reports: "all",
  history: "all",
};
let latestHistoryAnalysis = null;
let latestReports = null;
let activeReportColumnOptions = {showReasons: true};
let activeWindow = "default";
let findingsHistoryLoaded = false;
let rtl433ScannerState = {};
const DERIVED_OPERATION = {
  IDLE: "idle",
  LOADING: "loading",
  REFRESHING: "refreshing",
  WAITING: "waiting"
};
const derivedCoordinator = {
  operation: DERIVED_OPERATION.IDLE,
  loadPromise: null,
  loadRequestId: 0,
  loadWindow: "",
  loadScheduleTimer: null,
  pendingLoadReason: "",
  refreshRequestId: 0,
  refreshMode: "",
  statusPollTimer: null,
  pollRecoverOnComplete: false,
  statusText: ""
};
let autoDerivedRefreshTimer = null;
let derivedStatusTicker = null;
let nextAutoDerivedRefreshAtMs = null;
let lastDerivedRefreshError = "";
let lastDerivedRefreshCompletedAtMs = 0;
let lastWakeRefreshAtMs = 0;
let emptyDerivedRefreshRequestedAtMs = 0;
let emptyDerivedRefreshAttempts = 0;
let missingSubjectRefreshRequestedAtMs = 0;
const connectionState = {
  httpOkAtMs: 0,
  eventStreamOpen: false
};
const HTTP_CONNECTIVITY_GRACE_MS = 45000;
const transientCollectorBanners = new Map();
const liveRenderTimers = new Map();
const LIVE_RENDER_DELAY_MS = 500;
const DERIVED_LOAD_DEBOUNCE_MS = 400;
const BLUETOOTH_SERVICE_NAMES = {
  "1800": "Generic Access",
  "1801": "Generic Attribute",
  "1802": "Immediate Alert",
  "1803": "Link Loss",
  "1804": "Tx Power",
  "1805": "Current Time",
  "1806": "Reference Time Update",
  "1807": "Next DST Change",
  "1808": "Glucose",
  "1809": "Health Thermometer",
  "180a": "Device Information",
  "180d": "Heart Rate",
  "180e": "Phone Alert Status",
  "180f": "Battery",
  "1810": "Blood Pressure",
  "1811": "Alert Notification",
  "1812": "Human Interface Device",
  "1813": "Scan Parameters",
  "1814": "Running Speed and Cadence",
  "1815": "Automation IO",
  "1816": "Cycling Speed and Cadence",
  "1818": "Cycling Power",
  "1819": "Location and Navigation",
  "181a": "Environmental Sensing",
  "181b": "Body Composition",
  "181c": "User Data",
  "181d": "Weight Scale",
  "181e": "Bond Management",
  "181f": "Continuous Glucose Monitoring",
  "1820": "Internet Protocol Support",
  "1821": "Indoor Positioning",
  "1822": "Pulse Oximeter",
  "1823": "HTTP Proxy",
  "1824": "Transport Discovery",
  "1825": "Object Transfer",
  "1826": "Fitness Machine",
  "1827": "Mesh Provisioning",
  "1828": "Mesh Proxy",
  "1829": "Reconnection Configuration",
  "183a": "Insulin Delivery",
  "183b": "Binary Sensor",
  "183c": "Emergency Configuration",
  "fe59": "Nordic DFU",
  "fe95": "Xiaomi",
  "feaa": "Eddystone",
  "fec7": "Apple Nearby",
  "fef3": "Google",
};
let bluetoothUuidNames = {};
let uiConfig = {
  max_live_rows: 200,
  max_history_rows: 500,
  max_history_payload_rows: 1500,
  max_event_log_items: 100,
  max_rendered_findings: 1000,
  max_history_ssids: 8,
  bluetooth_live_recent_sec: 600,
  poll_feed_live_ttl_sec: 86400,
  derived_stale_after_min: 15,
  derived_auto_refresh_min: 15,
  derived_refresh_timeout_sec: 600,
  insights_recent_after_min: 30
};

function fetchJson(url, options) {
  const requestOptions = {
    cache: "no-store",
    ...(options || {})
  };
  return fetch(url, requestOptions)
    .then((response) => {
      noteHttpConnected();
      const contentType = response.headers.get("content-type") || "";
      const isJson = contentType.includes("application/json");
      if (isJson) {
        return response.json().then((payload) => {
          if (!response.ok || payload.ok === false) {
            throw new Error(payload.error || `HTTP ${response.status}`);
          }
          return payload;
        });
      }
      return response.text().then((text) => {
        const detail = String(text || "").replace(/\s+/g, " ").slice(0, 240);
        throw new Error(`HTTP ${response.status}: ${detail || response.statusText}`);
      });
    })
    .catch((error) => {
      if (error && error.name === "AbortError") {
        throw new Error(`timed out after ${Math.round((requestOptions._timeoutMs || 0) / 1000)} seconds`);
      }
      throw error;
    })
    .finally(() => {
      clearRequestTimeout(requestOptions);
    });
}

function fetchPlainJson(url, options) {
  return fetch(url, {cache: "no-store", ...(options || {})})
    .then((response) => {
      noteHttpConnected();
      return response.json();
    });
}

function fetchDerivedBundle(url, requestWindow) {
  const started = performance.now();
  return fetch(url, {cache: "no-store"})
    .then((response) => {
      noteHttpConnected();
      const headersAt = performance.now();
      const contentType = response.headers.get("content-type") || "";
      const contentLength = response.headers.get("content-length") || "";
      const encoding = response.headers.get("content-encoding") || "identity";
      const jsonBytes = response.headers.get("x-skannr-json-bytes") || "";
      return response.text().then((text) => {
        const bodyAt = performance.now();
        if (!contentType.includes("application/json")) {
          const detail = String(text || "").replace(/\s+/g, " ").slice(0, 240);
          throw new Error(`HTTP ${response.status}: ${detail || response.statusText}`);
        }
        let payload;
        const parseStarted = performance.now();
        try {
          payload = JSON.parse(text);
        } catch (error) {
          uiDebug("derived_fetch_parse_failed", {
            window: requestWindow,
            status: response.status,
            content_length: contentLength,
            json_bytes: jsonBytes,
            encoding,
            chars: text.length,
            error: errorMessage(error)
          });
          throw error;
        }
        const parsedAt = performance.now();
        uiDebug("derived_fetch_timing", {
          window: requestWindow,
          status: response.status,
          content_length: contentLength,
          json_bytes: jsonBytes,
          encoding,
          chars: text.length,
          headers_ms: Math.round(headersAt - started),
          body_ms: Math.round(bodyAt - headersAt),
          parse_ms: Math.round(parsedAt - parseStarted),
          total_ms: Math.round(parsedAt - started)
        });
        if (!response.ok || payload.ok === false) {
          throw new Error(payload.error || `HTTP ${response.status}`);
        }
        return payload;
      });
    });
}

function uiDebug(event, detail) {
  const payload = {
    client_id: CLIENT_SESSION_ID,
    event,
    detail: detail || {}
  };
  fetch("/ui_debug", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload),
    keepalive: true
  }).catch(() => {
    // Browser diagnostics must never affect dashboard behavior.
  });
}

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    showTab(button.dataset.tab);
  });
});

function showTab(name) {
  document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
  document.querySelectorAll(".panel").forEach((item) => item.classList.remove("active"));
  const button = document.querySelector(`.tab[data-tab="${name}"]`);
  const panel = document.querySelector(`#tab-${name}`);
  if (button) button.classList.add("active");
  if (panel) panel.classList.add("active");
}

const viewWindowFilter = document.getElementById("view-window-filter");
if (viewWindowFilter) {
  activeWindow = viewWindowFilter.value || "default";
  viewWindowFilter.addEventListener("change", () => {
    activeWindow = viewWindowFilter.value || "default";
    findingsHistoryLoaded = false;
    emptyDerivedRefreshRequestedAtMs = 0;
    emptyDerivedRefreshAttempts = 0;
    refreshDerivedViews("view");
  });
}
const insightsSeverityFilter = document.getElementById("insights-severity-filter");
if (insightsSeverityFilter) {
  insightsSeverityFilter.addEventListener("change", renderInsights);
}
const insightsActivityFilter = document.getElementById("insights-activity-filter");
if (insightsActivityFilter) {
  insightsActivityFilter.addEventListener("change", renderInsights);
}
const insightsSearch = document.getElementById("insights-search");
if (insightsSearch) {
  insightsSearch.addEventListener("input", renderInsights);
}
const insightsRefreshButton = document.getElementById("insights-refresh");
if (insightsRefreshButton) {
  insightsRefreshButton.addEventListener("click", () => refreshDerivedViews("manual"));
}
const reportsRefreshButton = document.getElementById("reports-refresh");
if (reportsRefreshButton) {
  reportsRefreshButton.addEventListener("click", () => refreshDerivedViews("manual"));
}
const reportsSearch = document.getElementById("reports-search");
if (reportsSearch) {
  reportsSearch.addEventListener("input", () => renderReports(latestReports || {}));
}
const wifiSearch = document.getElementById("wifi-search");
if (wifiSearch) {
  wifiSearch.addEventListener("input", renderWifiTables);
}
const wifiMonitorSearch = document.getElementById("wifi-monitor-search");
if (wifiMonitorSearch) {
  wifiMonitorSearch.addEventListener("input", renderWifiMonitorTable);
}
const bleSearch = document.getElementById("ble-search");
if (bleSearch) {
  bleSearch.addEventListener("input", renderBleTable);
}
const aprsisSearch = document.getElementById("aprsis-search");
if (aprsisSearch) {
  aprsisSearch.addEventListener("input", renderAprsisTable);
}
const noaaSearch = document.getElementById("noaa-search");
if (noaaSearch) {
  noaaSearch.addEventListener("input", renderNoaaTable);
}
const usgsSearch = document.getElementById("usgs-search");
if (usgsSearch) {
  usgsSearch.addEventListener("input", renderUsgsTable);
}
const swpcSearch = document.getElementById("swpc-search");
if (swpcSearch) {
  swpcSearch.addEventListener("input", renderSwpcTable);
}
const pwsSearch = document.getElementById("pws-search");
if (pwsSearch) {
  pwsSearch.addEventListener("input", renderPwsTable);
}
const adsbSearch = document.getElementById("adsb-search");
if (adsbSearch) {
  adsbSearch.addEventListener("input", renderAdsbTable);
}
const rtl433Search = document.getElementById("rtl433-search");
if (rtl433Search) {
  rtl433Search.addEventListener("input", renderRtl433Table);
}
const rayhunterSearch = document.getElementById("rayhunter-search");
if (rayhunterSearch) {
  rayhunterSearch.addEventListener("input", renderRayhunterTable);
}
const rtl433SubmitButton = document.getElementById("rtl433-submit");
if (rtl433SubmitButton) {
  rtl433SubmitButton.addEventListener("click", () => controlCollector("rtl433", "start"));
}
const lanSearch = document.getElementById("lan-search");
if (lanSearch) {
  lanSearch.addEventListener("input", renderLanTable);
}
const alertsSearch = document.getElementById("alerts-search");
if (alertsSearch) {
  alertsSearch.addEventListener("input", renderAlertsTable);
}
const alertsAckAllButton = document.getElementById("alerts-ack-all");
if (alertsAckAllButton) {
  alertsAckAllButton.addEventListener("click", ackAllAlerts);
}
document.addEventListener("click", (event) => {
  const button = event.target.closest("button");
  if (!button || button.disabled) return;
  button.classList.remove("button-clicked");
  void button.offsetWidth;
  button.classList.add("button-clicked");
  window.setTimeout(() => button.classList.remove("button-clicked"), 220);
});
const btClassicStartButton = document.getElementById("bt-classic-start");
if (btClassicStartButton) {
  btClassicStartButton.addEventListener("click", () => controlCollector("bt_classic", "start"));
}
const btClassicStopButton = document.getElementById("bt-classic-stop");
if (btClassicStopButton) {
  btClassicStopButton.addEventListener("click", () => controlCollector("bt_classic", "stop"));
}
document.querySelectorAll("[data-bluetooth-subtab]").forEach((button) => {
  button.addEventListener("click", () => showBluetoothSubtab(button.dataset.bluetoothSubtab));
});
const historyRefreshButton = document.getElementById("history-refresh");
if (historyRefreshButton) {
  historyRefreshButton.addEventListener("click", () => refreshDerivedViews("manual"));
}
const historySearch = document.getElementById("history-search");
if (historySearch) {
  historySearch.addEventListener("input", () => {
    if (latestDeviceHistory) renderDeviceHistory(latestDeviceHistory);
  });
}
socket.on("connect", () => setSocketState("Connected", "ok"));
socket.on("disconnect", () => setSocketState("Disconnected", "muted"));
socket.on("collector_status", renderCollectorHealth);
socket.on("system_status", renderSystemStatus);
socket.on("alerts_snapshot", renderAlertsSnapshot);
socket.on("findings_snapshot", renderFindingsSnapshot);
socket.on("lan_snapshot", renderLanSnapshot);
socket.on("skannr_event", handleEvent);
buildSubtabs();
loadCollectorMetadata();
loadViewMetadata();
setInterval(renderLiveTables, 30000);
["focus", "pageshow", "online"].forEach((eventName) => {
  window.addEventListener(eventName, refreshAfterBrowserWake);
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refreshAfterBrowserWake();
});
setupDetailPanel();

function createLocalEventSocket() {
  const handlers = new Map();
  const api = {
    on(name, callback) {
      if (!handlers.has(name)) handlers.set(name, []);
      handlers.get(name).push(callback);
    },
    emit(name, payload) {
      if (name !== "collector_control") return;
      fetch("/collector_control", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload || {})
      }).catch(() => {
        emitLocal("disconnect");
      });
    }
  };

  function emitLocal(name, payload) {
    (handlers.get(name) || []).forEach((callback) => callback(payload));
  }

  if (!window.EventSource) {
    setTimeout(() => emitLocal("disconnect"), 0);
    return api;
  }

  let source = null;
  let reconnectTimer = null;

  function scheduleEventStreamReconnect() {
    if (reconnectTimer) return;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      if (source && source.readyState === EventSource.OPEN) return;
      if (source) source.close();
      openEventStream();
    }, 10000);
  }

  function openEventStream() {
    source = new EventSource("/events");
    source.onopen = () => {
      connectionState.eventStreamOpen = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      noteHttpConnected();
      emitLocal("connect");
    };
    source.onerror = () => {
      connectionState.eventStreamOpen = false;
      emitLocal("disconnect");
      scheduleEventStreamReconnect();
    };
    [
      "collector_status",
      "system_status",
      "alerts_snapshot",
      "findings_snapshot",
      "lan_snapshot",
      "skannr_event"
    ].forEach((name) => {
      source.addEventListener(name, (message) => {
        try {
          emitLocal(name, JSON.parse(message.data));
        } catch (_error) {
          // Ignore malformed records; the next event will refresh the dashboard.
        }
      });
    });
  }

  setTimeout(openEventStream, 0);
  return api;
}

function noteHttpConnected() {
  connectionState.httpOkAtMs = Date.now();
  if (!connectionState.eventStreamOpen) {
    setSocketState("Connected", "warning", "live updates reconnecting");
  }
}

function recentHttpConnection() {
  return Date.now() - connectionState.httpOkAtMs <= HTTP_CONNECTIVITY_GRACE_MS;
}

function setSocketState(text, cls, detail) {
  const node = document.getElementById("socket-state");
  const target = displayConnectionHost();
  if (text === "Disconnected" && recentHttpConnection()) {
    node.textContent = `Connected to ${target} (live updates reconnecting)`;
    node.className = "badge warning";
    return;
  }
  const suffix = detail ? ` (${detail})` : "";
  node.textContent = text === "Connected" ? `Connected to ${target}${suffix}` : `Disconnected from ${target}`;
  node.className = `badge ${cls}`;
}

function displayConnectionHost() {
  const host = window.location.hostname || "this host";
  const port = window.location.port;
  const displayHost = host.includes(":") ? `[${host}]` : host;
  const endpoint = port ? `${displayHost}:${port}` : displayHost;
  const family = connectionAddressFamily(host);
  return family ? `${endpoint} (${family})` : endpoint;
}

function connectionAddressFamily(host) {
  if (host.includes(":")) return "IPv6";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return "IPv4";
  if (host === "localhost") return "local";
  return "";
}

function browserTitleHost() {
  return displayConnectionHost();
}

function updateBrowserTitle() {
  const host = browserTitleHost();
  const unacked = (rows.alerts || []).filter((item) => !item.acked).length;
  const parts = ["Skannr"];
  if (host) parts.push(host);
  document.title = `${parts.join(" ")}${unacked ? ` (${unacked})` : ""}`;
}

function handleEvent(event) {
  if (event.collector === "alerts") renderAlertEvent(event);
  if (event.collector === "findings") renderFindingEvent(event);
  if (event.collector === "ble") renderBleEvent(event);
  if (event.collector === "ble_identify") renderBleIdentifyEvent(event);
  if (event.collector === "bt_classic") renderBtClassicEvent(event);
  if (event.collector === "wifi") renderWifiEvent(event);
  if (event.collector === "wifi_monitor") renderWifiMonitorEvent(event);
  if (event.collector === "aprsis") renderAprsisEvent(event);
  if (event.collector === "noaa") renderNoaaEvent(event);
  if (event.collector === "usgs") renderUsgsEvent(event);
  if (event.collector === "swpc") renderSwpcEvent(event);
  if (event.collector === "pws") renderPwsEvent(event);
  if (event.collector === "adsb") renderAdsbEvent(event);
  if (event.collector === "rtl433") renderRtl433Event(event);
  if (event.collector === "rayhunter") renderRayhunterEvent(event);
  if (event.collector === "lan") renderLanEvent(event);
  if (event.collector === "lan_identify") renderLanIdentifyEvent(event);
  if (event.collector === "system" && event.type === "system_status") renderSystemStatus(event.data);
}

function renderAlertsSnapshot(alerts) {
  rows.alerts = sortAlerts((alerts || []).map(normalizeAlert));
  renderGlobalAlerts();
  renderAlertsTable();
}

function renderAlertEvent(event) {
  if (event.type !== "alert" || !event.data) return;
  upsertAlert(normalizeAlert(event.data));
  renderGlobalAlerts();
  renderAlertsTable();
}

function normalizeAlert(alert) {
  return {
    id: String(alert.id || `${alert.source || "alert"}:${alert.subject || ""}`),
    level: String(alert.level || "warning").toLowerCase(),
    source: alert.source || "",
    title: alert.title || "Alert",
    subject: alert.subject || "",
    summary: alert.summary || "",
    first_seen: alert.first_seen || "",
    first_seen_epoch: alert.first_seen_epoch,
    last_seen: alert.last_seen || "",
    last_seen_epoch: alert.last_seen_epoch,
    count: Number(alert.count || 1),
    acked: Boolean(alert.acked),
    acked_at: alert.acked_at || "",
    acked_at_epoch: alert.acked_at_epoch,
    evidence: alert.evidence || {}
  };
}

function upsertAlert(alert) {
  const index = rows.alerts.findIndex((item) => item.id === alert.id);
  if (index >= 0) rows.alerts[index] = alert;
  else rows.alerts.unshift(alert);
  rows.alerts = sortAlerts(rows.alerts).slice(0, 50);
}

function sortAlerts(alerts) {
  const priority = {critical: 2, warning: 1, info: 0};
  return (alerts || []).slice().sort((left, right) => {
    const acked = Number(Boolean(left.acked)) - Number(Boolean(right.acked));
    if (acked) return acked;
    const level = (priority[right.level] || 0) - (priority[left.level] || 0);
    if (level) return level;
    return Number(right.last_seen_epoch || 0) - Number(left.last_seen_epoch || 0);
  });
}

function renderGlobalAlerts() {
  const container = document.getElementById("global-alerts");
  const badge = document.getElementById("alerts-tab-count");
  const alerts = sortAlerts(rows.alerts || []);
  const unackedAlerts = alerts.filter((item) => !item.acked);
  updateTabCounts();
  updateBrowserTitle();
  if (badge) {
    const critical = unackedAlerts.filter((item) => item.level === "critical").length;
    badge.textContent = unackedAlerts.length ? `+${unackedAlerts.length}` : "";
    badge.className = `tab-alert-count ${critical ? "critical" : ""}`;
    badge.title = unackedAlerts.length ? `${unackedAlerts.length} unacknowledged alert(s)` : "";
  }
  if (!container) return;
  container.innerHTML = "";
  if (!unackedAlerts.length) {
    container.hidden = true;
    return;
  }
  container.hidden = false;
  const alert = unackedAlerts[0];
  const item = document.createElement("div");
  item.className = `global-alert global-alert-${alert.level}`;
  const label = document.createElement("span");
  label.className = "global-alert-level";
  label.textContent = alert.level === "critical" ? "CRITICAL" : "ALERT";
  const text = document.createElement("span");
  text.className = "global-alert-text";
  text.textContent = alert.summary || `${alert.title}: ${alert.subject}`;
  const meta = document.createElement("span");
  meta.className = "global-alert-meta";
  const metaParts = [];
  if (alert.last_seen) metaParts.push(`last ${alert.last_seen}`);
  if (unackedAlerts.length > 1) metaParts.push(`+${unackedAlerts.length - 1} more`);
  meta.textContent = metaParts.join(" ");
  const actions = document.createElement("span");
  actions.className = "global-alert-actions";
  const ack = document.createElement("button");
  ack.type = "button";
  ack.textContent = "ACK";
  ack.addEventListener("click", () => ackAlert(alert.id));
  const view = document.createElement("button");
  view.type = "button";
  view.textContent = "Alerts";
  view.addEventListener("click", () => showTab("alerts"));
  actions.appendChild(ack);
  actions.appendChild(view);
  item.appendChild(label);
  item.appendChild(text);
  if (meta.textContent.trim()) item.appendChild(meta);
  item.appendChild(actions);
  container.appendChild(item);
}

const ALERT_TABLE_COLUMN_CLASSES = [
  "alert-col-level",
  "alert-col-source",
  "alert-col-subject",
  "alert-col-summary",
  "alert-col-details",
  "alert-col-first-seen",
  "alert-col-last-seen",
  "alert-col-count",
  "alert-col-state"
];

function renderAlertsTable() {
  const tbody = document.getElementById("alerts-list");
  const status = document.getElementById("alerts-status");
  if (!tbody) return;
  const alerts = sortAlerts(rows.alerts || []);
  const visibleAlerts = alerts.filter(alertMatchesSearch);
  const unackedCount = alerts.filter((item) => !item.acked).length;
  if (status) {
    if (alerts.length) {
      const searchText = alertSearchText();
      const prefix = searchText ? `${visibleAlerts.length} matching alert(s); ` : "";
      status.textContent = `${prefix}${unackedCount} unacknowledged alert(s), ${alerts.length} active alert(s)`;
    } else {
      status.textContent = "No active alerts";
    }
    status.className = `status-strip ${unackedCount ? "alert" : "muted"}`;
  }
  tbody.innerHTML = "";
  visibleAlerts.forEach((alert) => {
    const tr = document.createElement("tr");
    [
      alert.level.toUpperCase(),
      sourceLabel(alert.source),
      alert.subject,
      alert.summary,
      alertDetailsNode(alert),
      alert.first_seen,
      alert.last_seen,
      alert.count,
      alert.acked ? `ACK ${alert.acked_at || ""}` : "Unacknowledged"
    ].forEach((value, index) => {
      const td = document.createElement("td");
      td.className = ALERT_TABLE_COLUMN_CLASSES[index] || "";
      appendTableCellValue(td, value);
      tr.appendChild(td);
    });
    const actionCell = document.createElement("td");
    actionCell.className = "alert-col-action";
    if (!alert.acked) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = "ACK";
      button.addEventListener("click", () => ackAlert(alert.id));
      actionCell.appendChild(button);
    }
    tr.appendChild(actionCell);
    tbody.appendChild(tr);
  });
}

function alertSearchText() {
  return String((alertsSearch && alertsSearch.value) || "").trim().toLowerCase();
}

function alertMatchesSearch(alert) {
  const needle = alertSearchText();
  if (!needle) return true;
  return [
    alert.level,
    sourceLabel(alert.source),
    alert.subject,
    alert.summary,
    alertDetailsText(alert),
    alert.first_seen,
    alert.last_seen,
    alert.count,
    alert.acked ? `ACK ${alert.acked_at || ""}` : "Unacknowledged"
  ].some((value) => String(value || "").toLowerCase().includes(needle));
}

function alertDetailsText(alert) {
  return alertDetailItems(alert)
    .map((item) => `${item.label} ${item.value}${item.unit || ""}`)
    .join("; ");
}

function alertDetailsNode(alert) {
  const items = alertDetailItems(alert);
  const text = alertDetailsText(alert);
  if (!items.length) return text;
  const span = document.createElement("span");
  span.className = "alert-detail-items";
  items.forEach((item, index) => {
    if (index) span.appendChild(document.createTextNode("; "));
    span.appendChild(document.createTextNode(`${item.label} `));
    const url = alertDetailUrl(item.key, item.value);
    if (url) {
      const link = document.createElement("a");
      link.href = url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = item.value;
      span.appendChild(link);
    } else {
      appendMapLinkedText(span, `${item.value}${item.unit || ""}`);
    }
  });
  return {node: span, text};
}

function alertDetailItems(alert) {
  const evidence = (alert || {}).evidence || {};
  const items = [];
  const swpcLevel = swpcLevelText(evidence);
  if (swpcLevel) {
    items.push({key: "swpc_level", label: "SWPC Level", value: swpcLevel, unit: ""});
  }
  [
    ["bssid", "BSSID", ""],
    ["mac", "MAC", ""],
    ["endpoint", "Endpoint", ""],
    ["source_url", "Source URL", ""],
    ["detail_url", "Detail URL", ""],
    ["cap_url", "CAP URL", ""],
    ["json_url", "JSON URL", ""],
    ["callsign", "Callsign", ""],
    ["event", "Event", ""],
    ["event_id", "Event", ""],
    ["incident_id", "Incident", ""],
    ["tsunami_identifier", "Tsunami ID", ""],
    ["tsunami_category", "Tsunami Category", ""],
    ["message_number", "Message", ""],
    ["nhc_system", "NHC System", ""],
    ["nhc_advisory_number", "Advisory", ""],
    ["nhc_storm_id", "Storm ID", ""],
    ["event_time", "Event Time", ""],
    ["updated", "Updated", ""],
    ["effective", "Effective", ""],
    ["onset", "Onset", ""],
    ["expires", "Expires", ""],
    ["severity", "Severity", ""],
    ["magnitude", "Magnitude", ""],
    ["magnitude_type", "Magnitude Type", ""],
    ["depth_km", "Depth", " km"],
    ["latitude", "Latitude", ""],
    ["longitude", "Longitude", ""],
    ["distance_km", "Distance", " km"],
    ["gateway_ip", "Gateway", ""],
    ["interface", "Interface", ""],
    ["warning_count", "Warnings", ""],
    ["rssi", "RSSI", " dBm"],
    ["channel", "Channel", ""],
    ["rain_1h_in", "1h Rain Rate", " in/hr"],
    ["wind_gust_mph", "Gust", " mph"],
    ["findmy_payload_type", "Find My Type", ""],
    ["findmy_status", "Find My Status", ""],
    ["findmy_hint", "Find My Hint", ""],
    ["confidence", "Confidence", ""]
  ].forEach(([key, label, unit]) => {
    if (evidence[key] !== undefined && evidence[key] !== null && evidence[key] !== "") {
      items.push({key, label, value: String(evidence[key]), unit});
    }
  });
  if (Array.isArray(evidence.service_uuids) && evidence.service_uuids.length) {
    items.push({key: "service_uuids", label: "Services", value: compactList(evidence.service_uuids, 3), unit: ""});
  }
  if (evidence.findmy_accessory) {
    items.push({key: "findmy_accessory", label: "Find My", value: evidence.findmy_label || "Apple Find My accessory", unit: ""});
  }
  if (Array.isArray(evidence.nhc_product_types) && evidence.nhc_product_types.length) {
    items.push({key: "nhc_product_types", label: "Products", value: compactList(evidence.nhc_product_types, 5), unit: ""});
  }
  if (evidence.vendor_name) {
    items.push({key: "vendor_name", label: "Vendor", value: String(evidence.vendor_name), unit: ""});
  }
  return items;
}

function alertDetailUrl(key, value) {
  if (!["endpoint", "source_url", "detail_url", "cap_url", "json_url"].includes(key)) return "";
  const text = String(value || "").trim();
  if (!/^https?:\/\//i.test(text)) return "";
  try {
    const url = new URL(text);
    return url.href;
  } catch (_error) {
    return "";
  }
}

function ackAlert(alertId) {
  fetchJson("/alerts/ack", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({id: alertId})
  }).then((payload) => {
    renderAlertsSnapshot(payload.alerts || []);
  }).catch((error) => {
    console.warn("alert ack failed", error);
  });
}

function ackAllAlerts() {
  fetchJson("/alerts/ack_all", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({})
  }).then((payload) => {
    renderAlertsSnapshot(payload.alerts || []);
  }).catch((error) => {
    console.warn("alert ack-all failed", error);
  });
}

function renderFindingsSnapshot(findings) {
  if (findingsHistoryLoaded) return;
  rows.insights = sortInsights((findings || []).map(normalizeFindingInsight)).slice(0, uiNumber("max_live_rows"));
  renderInsights();
}

function renderFindingEvent(event) {
  if (event.type !== "finding" || !event.data) return;
  rows.insights.unshift(normalizeFindingInsight(event.data));
  rows.insights = sortInsights(rows.insights);
  if (!findingsHistoryLoaded) rows.insights = rows.insights.slice(0, uiNumber("max_live_rows"));
  updateInsightsStatus();
  renderInsights();
}

function renderInsights() {
  updateTabCounts();
  const tbody = document.getElementById("insights-list");
  if (!tbody) return;
  const columns = insightColumns({});
  const table = document.getElementById("insights-table");
  if (table) table.classList.toggle("with-source", showInsightSourceColumn());
  renderInsightsHeader(columns);
  tbody.innerHTML = "";
  rows.insights.filter(insightMatchesFilters).filter(insightMatchesSearch).slice(0, uiNumber("max_rendered_findings")).forEach((insight) => {
    const tr = document.createElement("tr");
    insightColumns(insight).forEach((column) => {
      const td = document.createElement("td");
      td.className = `insight-col-${column.key}`;
      td.textContent = column.value;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function renderInsightsHeader(columns) {
  const head = document.getElementById("insights-head");
  if (!head) return;
  const tr = document.createElement("tr");
  (columns || insightColumns({})).forEach((column) => {
    const th = document.createElement("th");
    th.className = `insight-col-${column.key}`;
    th.textContent = column.label;
    tr.appendChild(th);
  });
  head.innerHTML = "";
  head.appendChild(tr);
}

function insightColumns(insight) {
  const columns = [
    {key: "time", label: "Time", value: insight.timestamp || ""},
    {key: "severity-category", label: "Severity / Category", value: insightSeverityCategory(insight)}
  ];
  if (showInsightSourceColumn()) columns.push({key: "source", label: "Source", value: sourceLabel(insight.source)});
  columns.push(
    {key: "activity", label: "Activity", value: activityLabel(insight)},
    {key: "insight", label: "Insight", value: insight.title || ""},
    {key: "details", label: "Details", value: insightDetails(insight)}
  );
  return columns;
}

function insightCells(insight) {
  return insightColumns(insight).map((column) => column.value);
}

function insightSeverityCategory(insight) {
  return [insight.severity || "", insight.category || ""].filter(Boolean).join(" / ");
}


function recencyBucketForItem(item) {
  const timestampMs = recordTimestampMs(item, "last_seen") || recordTimestampMs(item, "timestamp");
  if (!timestampMs) return {key: "older", label: "Seen 24+ hours ago"};
  const ageMs = Date.now() - timestampMs;
  if (ageMs <= 60 * 60000) return {key: "hour", label: "Seen within last hour"};
  if (ageMs <= 24 * 60 * 60000) return {key: "day", label: "Seen within last 24 hours"};
  return {key: "older", label: "Seen 24+ hours ago"};
}

function groupedByRecency(items) {
  const groups = [
    {key: "hour", label: "Seen within last hour", items: []},
    {key: "day", label: "Seen within last 24 hours", items: []},
    {key: "older", label: "Seen 24+ hours ago", items: []},
  ];
  const byKey = new Map(groups.map((group) => [group.key, group]));
  (items || []).forEach((item) => {
    const bucket = recencyBucketForItem(item);
    (byKey.get(bucket.key) || byKey.get("older")).items.push(item);
  });
  return groups;
}

function appendTableGroupRow(tbody, label, count, className) {
  if (!tbody) return;
  const columnCount = tbody.closest("table")?.querySelectorAll("thead th").length || 1;
  const tr = document.createElement("tr");
  tr.className = className || "table-group-row";
  const td = document.createElement("td");
  td.colSpan = columnCount;
  td.textContent = count === undefined ? label : `${label} (${count})`;
  tr.appendChild(td);
  tbody.appendChild(tr);
}

function collectorHealthGroup(item) {
  const state = String((item || {}).state || "").toUpperCase();
  if (state === "ONLINE") return "online";
  if (state === "DISABLED") return "disabled";
  return "offline";
}

function collectorHealthGroups(statuses) {
  const groups = [
    {key: "online", label: "ONLINE", items: []},
    {key: "offline", label: "OFFLINE / STOPPED", items: []},
    {key: "disabled", label: "DISABLED", items: []},
  ];
  const byKey = new Map(groups.map((group) => [group.key, group]));
  (statuses || []).forEach((item) => byKey.get(collectorHealthGroup(item)).items.push(item));
  return groups;
}


function renderReports(reportBundle) {
  // Search input events can call render paths directly in older loaded pages.
  // Only replace the cached bundle when the argument is an actual report bundle.
  if (reportBundle && Array.isArray(reportBundle.reports)) {
    latestReports = reportBundle;
  } else if (!latestReports) {
    latestReports = {};
  }
  rows.reports = sortReports(latestReports.reports || []);
  const maxRendered = uiNumber("max_rendered_findings");
  const needle = reportSearchNeedle();
  const visibleReports = [];
  rows.reports
    .filter(reportMatchesSubtab)
    .forEach((report) => {
      const tr = buildReportRow(report);
      if (!reportRowMatchesSearch(tr, needle)) return;
      visibleReports.push(report);
    });
  activeReportColumnOptions = {
    showReasons: !visibleReports.every((report) =>
      String((report || {}).source || "").toLowerCase() === "wifi_monitor"
    ) && visibleReports.some((report) =>
      compactList((report || {}).reason_tags || [], 6)
    )
  };
  renderReportsHeader();
  const patternReports = visibleReports.filter(reportIsCrossSubjectReport);
  const subjectReports = visibleReports.filter((report) => !reportIsCrossSubjectReport(report));
  const rendered = renderReportSection("pattern", patternReports, maxRendered, 0);
  renderReportSection("subject", subjectReports, maxRendered, rendered);
  updateReportsStatus(latestReports, visibleReports);
  updateReportsSummary(visibleReports);
  updateTabCounts();
}

function renderReportSection(kind, reports, maxRendered, alreadyRendered) {
  const tbody = document.getElementById(`reports-${kind}-list`);
  const section = document.getElementById(`reports-${kind}-section`);
  const empty = document.getElementById(`reports-${kind}-empty`);
  const table = tbody ? tbody.closest("table") : null;
  if (!tbody) return alreadyRendered || 0;
  tbody.innerHTML = "";
  const items = reports || [];
  const hasRows = items.length > 0;
  const canRender = hasRows && (alreadyRendered || 0) < maxRendered;
  if (section) section.hidden = false;
  if (empty) {
    empty.hidden = canRender;
    if (!hasRows) {
      empty.textContent = kind === "pattern"
        ? "No cross-subject patterns match the current view"
        : "No subject reports match the current view";
    } else if (!canRender) {
      empty.textContent = "Render limit reached before this section";
    } else {
      empty.textContent = "";
    }
  }
  if (table) table.hidden = !canRender;
  let rendered = alreadyRendered || 0;
  groupedByRecency(items).forEach((group) => {
    if (!group.items.length || rendered >= maxRendered) return;
    appendTableGroupRow(tbody, group.label, group.items.length, "table-group-row recency-group-row");
    group.items.forEach((report) => {
      if (rendered >= maxRendered) return;
      tbody.appendChild(buildReportRow(report));
      rendered += 1;
    });
  });
  return rendered;
}

function buildReportRow(report) {
  const tr = document.createElement("tr");
  reportColumns(report).forEach((column) => {
    const td = document.createElement("td");
    td.className = `report-col-${column.key}`;
    if (column.key === "evidence") {
      renderReportEvidenceCell(td, reportEvidenceItems(report));
    } else if (column.key === "report") {
      renderReportTitleCell(td, report);
    } else if (column.key === "subject") {
      renderReportSubjectSummaryCell(td, report);
    } else {
      td.textContent = column.value;
    }
    tr.appendChild(td);
  });
  return tr;
}

function reportRowMatchesSearch(row, needle) {
  if (!needle) return true;
  return String(row.textContent || "").toLowerCase().includes(needle);
}

function reportIsPresenceReport(report) {
  const type = String((report || {}).type || "").toLowerCase();
  const evidence = (report || {}).evidence || {};
  const findings = valueList(evidence.findings).join(" ").toLowerCase();
  const text = `${type} ${findings}`;
  return text.includes("presence") ||
    text.includes("recurring") ||
    text.includes("long") ||
    text.includes("cluster") ||
    text.includes("private_address") ||
    text.includes("private-address") ||
    text.includes("new access point") ||
    text.includes("new bluetooth") ||
    text.includes("new named/static");
}

function renderReportsHeader() {
  const heads = document.querySelectorAll(".reports-head");
  const targets = heads.length ? heads : [document.getElementById("reports-head")].filter(Boolean);
  targets.forEach((head) => {
    const tr = document.createElement("tr");
    reportColumns({}).forEach((column) => {
      const th = document.createElement("th");
      th.className = `report-col-${column.key}`;
      th.textContent = column.label;
      tr.appendChild(th);
    });
    head.innerHTML = "";
    head.appendChild(tr);
  });
}


function reportColumns(report) {
  const columns = [
    {key: "subject", label: "Subject", value: report.subject || ""},
    {key: "report", label: "Report", value: report.title || ""},
    {key: "score", label: "Score", value: report.score || 0},
    {key: "confidence", label: "Confidence", value: report.confidence || ""}
  ];
  const reasonValue = compactList(report.reason_tags || [], 6);
  if (activeReportColumnOptions.showReasons) {
    columns.push({key: "reasons", label: "Reasons", value: reasonValue});
  }
  columns.push(
    {key: "evidence", label: "Evidence", value: reportEvidenceText(report)},
    {key: "last-seen", label: "Last Seen", value: report.last_seen || ""}
  );
  return columns;
}

function renderReportTitleCell(cell, report) {
  const source = sourceLabel((report || {}).source);
  if (source) {
    const sourceLine = document.createElement("div");
    sourceLine.className = "report-source-line";
    sourceLine.textContent = source;
    cell.appendChild(sourceLine);
  }
  const titleLine = document.createElement("div");
  titleLine.className = "report-title-line";
  titleLine.textContent = (report || {}).title || "";
  cell.appendChild(titleLine);
}

function renderReportSubjectSummaryCell(cell, report) {
  const subjectLine = document.createElement("div");
  subjectLine.className = "report-subject-line";
  appendTableCellValue(subjectLine, reportSubjectCell(report, (report || {}).subject || ""));
  cell.appendChild(subjectLine);
  const summary = reportSummaryText(report);
  if (summary) {
    const summaryLine = document.createElement("div");
    summaryLine.className = "report-summary-line";
    appendMapLinkedText(summaryLine, summary);
    cell.appendChild(summaryLine);
  }
}

function reportSummaryText(report) {
  const summary = String((report || {}).summary || "");
  if (!summary) return "";
  const context = {
    text: normalizedEvidenceText([
      sourceLabel((report || {}).source),
      compactList((report || {}).reason_tags || [], 6),
      (report || {}).title || "",
      (report || {}).subject || ""
    ].filter(Boolean).join(" | "))
  };
  const suffix = summary.endsWith(".") ? "." : "";
  const body = suffix ? summary.slice(0, -1) : summary;
  const segments = body.split(";").map((part) => part.trim()).filter(Boolean);
  if (segments.length <= 1) {
    return evidenceSegmentAlreadyShown(body, context) ? "" : summary;
  }
  const kept = segments.filter((segment) => !evidenceSegmentAlreadyShown(segment, context));
  return kept.length ? `${kept.join("; ")}${suffix}` : "";
}

function reportSubjectCell(report, fallback) {
  const target = detailTargetForReport(report);
  const label = fallback || (target && target.key) || "";
  if (!target || !target.key) return label;
  return detailLink(label, target.type, target.key);
}

function detailTargetForReport(report) {
  const evidence = (report || {}).evidence || {};
  const source = String((report || {}).source || "").toLowerCase();
  const type = String((report || {}).type || "").toLowerCase();
  const populationScope = String((report || {}).report_scope || "").toLowerCase() === "population";
  if (source === "bluetooth" || type.startsWith("ble_")) {
    if (evidence.mac) return {type: "bluetooth-device", key: evidence.mac};
    return null;
  }
  if (type === "wifi_ssid_profile" && evidence.ssid) {
    return {type: "wifi-ssid", key: evidence.ssid};
  }
  if ((source === "wifi" || type.startsWith("wifi_ap")) && evidence.bssid) {
    return {type: "wifi-bssid", key: evidence.bssid};
  }
  if ((source === "wifi" || type.includes("ssid")) && evidence.ssid) {
    return {type: "wifi-ssid", key: evidence.ssid};
  }
  if (source === "wifi_monitor" && evidence.mac) {
    return {type: "wifi-client", key: evidence.mac};
  }
  if (source === "aprsis" || type.startsWith("aprsis")) {
    if (populationScope) return null;
    const key = evidence.callsign || String((report || {}).subject || "").replace(/^APRS\s+/i, "");
    return key ? {type: "aprsis-subject", key} : null;
  }
  if (source === "rayhunter" || type.startsWith("rayhunter")) {
    const key = evidence.endpoint || String((report || {}).subject || "").replace(/^Rayhunter\s*/i, "");
    return key ? {type: "rayhunter-subject", key} : null;
  }
  if (source === "noaa" || type.startsWith("noaa")) {
    if (populationScope) return null;
    const key = evidence.event_id || String((report || {}).subject || "").replace(/^NOAA\s+/i, "");
    return key ? {type: "noaa-subject", key} : null;
  }
  if (source === "usgs" || type.startsWith("usgs")) {
    if (populationScope) return null;
    const key = evidence.event_id || String((report || {}).subject || "").replace(/^USGS\s+/i, "");
    return key ? {type: "usgs-subject", key} : null;
  }
  if (source === "swpc" || type.startsWith("swpc")) {
    if (populationScope) return null;
    const key = evidence.event_id || String((report || {}).subject || "").replace(/^SWPC\s+/i, "");
    return key ? {type: "swpc-subject", key} : null;
  }
  if (source === "rtl433" || type.startsWith("rtl433")) {
    if (populationScope) return null;
    const key = evidence.subject_key || String((report || {}).subject || "").replace(/^RTL-433\s+/i, "");
    return key ? {type: "rtl433-subject", key} : null;
  }
  if (source === "pws" || type.startsWith("pws")) {
    if (populationScope) return null;
    const key = evidence.station_id || String((report || {}).subject || "").replace(/^PWS\s+/i, "");
    return key ? {type: "pws-subject", key} : null;
  }
  if (source === "lan" || type.startsWith("lan")) {
    if (populationScope) return null;
    const key = evidence.subject_key || evidence.mac || evidence.gateway_ip || String((report || {}).subject || "").replace(/^LAN\s+/i, "");
    return key ? {type: "lan-subject", key} : null;
  }
  return null;
}

function derivedRefreshActive() {
  return [
    DERIVED_OPERATION.REFRESHING,
    DERIVED_OPERATION.WAITING
  ].includes(derivedCoordinator.operation);
}

function derivedLoadActive() {
  return (
    derivedCoordinator.operation === DERIVED_OPERATION.LOADING &&
    derivedCoordinator.loadPromise
  );
}

function setDerivedCoordinatorIdle() {
  derivedCoordinator.operation = DERIVED_OPERATION.IDLE;
  derivedCoordinator.refreshMode = "";
  derivedCoordinator.statusText = "";
  derivedCoordinator.pollRecoverOnComplete = false;
}

function cancelScheduledDerivedLoad() {
  if (derivedCoordinator.loadScheduleTimer) {
    clearTimeout(derivedCoordinator.loadScheduleTimer);
    derivedCoordinator.loadScheduleTimer = null;
  }
  derivedCoordinator.pendingLoadReason = "";
}

function cancelActiveDerivedLoad(reason) {
  cancelScheduledDerivedLoad();
  if (!derivedCoordinator.loadPromise) return;
  uiDebug("derived_load_cancelled", {
    reason: reason || "",
    previous_window: derivedCoordinator.loadWindow || ""
  });
  derivedCoordinator.loadRequestId += 1;
  derivedCoordinator.loadPromise = null;
  derivedCoordinator.loadWindow = "";
  if (derivedCoordinator.operation === DERIVED_OPERATION.LOADING) {
    derivedCoordinator.operation = DERIVED_OPERATION.IDLE;
  }
}

function loadDerivedViews() {
  uiDebug("derived_load_requested", {
    window: activeWindow || "default",
    operation: derivedCoordinator.operation,
    mode: derivedCoordinator.refreshMode || ""
  });
  if (derivedRefreshActive()) {
    uiDebug("derived_load_skipped_refreshing", derivedStatusSnapshot());
    return Promise.resolve(null);
  }
  const requestWindow = activeWindow || "default";
  if (derivedLoadActive()) {
    if (derivedCoordinator.loadWindow === requestWindow) {
      uiDebug("derived_load_joined_inflight", {
        window: requestWindow
      });
      return derivedCoordinator.loadPromise;
    }
    uiDebug("derived_load_replacing_inflight", {
      previous_window: derivedCoordinator.loadWindow || "",
      request_window: requestWindow
    });
    derivedCoordinator.loadRequestId += 1;
    derivedCoordinator.loadPromise = null;
    derivedCoordinator.loadWindow = "";
  }
  derivedCoordinator.operation = DERIVED_OPERATION.LOADING;
  const requestId = ++derivedCoordinator.loadRequestId;
  derivedCoordinator.loadWindow = requestWindow;
  const loadPromise = fetchJson("/derived_views/status")
    .then((status) => {
      if (requestId !== derivedCoordinator.loadRequestId) {
        uiDebug("derived_load_ignored_status", {
          request_window: requestWindow,
          active_window: activeWindow || "default",
          request_id: requestId,
          latest_request_id: derivedCoordinator.loadRequestId
        });
        return null;
      }
      if (status && status.in_progress) {
        uiDebug("derived_load_fetching_during_refresh", status);
        continuePollingActiveDerivedRefresh("Backend refresh", status);
      }
      uiDebug("derived_fetch_start", {window: requestWindow});
      return fetchDerivedBundle(
        `/derived_views${windowQuery(requestWindow)}`,
        requestWindow
      );
    })
    .then((bundle) => {
      if (!bundle) return null;
      uiDebug("derived_fetch_resolved", {
        request_window: requestWindow,
        active_window: activeWindow || "default",
        request_id: requestId,
        latest_request_id: derivedCoordinator.loadRequestId
      });
      if (requestId !== derivedCoordinator.loadRequestId) {
        uiDebug("derived_load_ignored_bundle", {
          request_window: requestWindow,
          active_window: activeWindow || "default",
          request_id: requestId,
          latest_request_id: derivedCoordinator.loadRequestId
        });
        return null;
      }
      if (bundle.refresh_in_progress) {
        uiDebug("derived_load_bundle_in_progress", bundle.status || {});
        continuePollingActiveDerivedRefresh(
          "Backend refresh",
          bundle.status || {}
        );
        return null;
      }
      uiDebug("derived_load_received", safeDerivedBundleSummary(bundle));
      renderDerivedViews(bundle);
      return bundle;
    })
    .catch((error) => {
      uiDebug("derived_load_failed", {
        request_window: requestWindow,
        request_id: requestId,
        latest_request_id: derivedCoordinator.loadRequestId,
        error: errorMessage(error)
      });
      if (requestId === derivedCoordinator.loadRequestId) {
        setDerivedStatus(`Derived views unavailable: ${error}`, "alert");
      }
      return null;
    })
    .finally(() => {
      if (derivedCoordinator.loadPromise === loadPromise) {
        derivedCoordinator.loadPromise = null;
        derivedCoordinator.loadWindow = "";
        if (derivedCoordinator.operation === DERIVED_OPERATION.LOADING) {
          derivedCoordinator.operation = DERIVED_OPERATION.IDLE;
        }
      }
    });
  derivedCoordinator.loadPromise = loadPromise;
  return loadPromise;
}

function requestDerivedLoad(reason, options) {
  const requestWindow = activeWindow || "default";
  const immediate = Boolean((options || {}).immediate);
  uiDebug("derived_load_queued", {
    reason: reason || "",
    window: requestWindow,
    operation: derivedCoordinator.operation,
    load_window: derivedCoordinator.loadWindow || "",
    refresh_mode: derivedCoordinator.refreshMode || ""
  });
  if (derivedRefreshActive()) {
    uiDebug("derived_load_deferred_refreshing", derivedStatusSnapshot());
    return Promise.resolve(null);
  }
  if (derivedLoadActive() && derivedCoordinator.loadWindow === requestWindow) {
    uiDebug("derived_load_joined_inflight", {
      reason: reason || "",
      window: requestWindow
    });
    return derivedCoordinator.loadPromise;
  }
  if (derivedLoadActive() && derivedCoordinator.loadWindow !== requestWindow) {
    uiDebug("derived_load_superseded_inflight", {
      reason: reason || "",
      previous_window: derivedCoordinator.loadWindow || "",
      request_window: requestWindow
    });
    derivedCoordinator.loadRequestId += 1;
    derivedCoordinator.loadPromise = null;
    derivedCoordinator.loadWindow = "";
    if (derivedCoordinator.operation === DERIVED_OPERATION.LOADING) {
      derivedCoordinator.operation = DERIVED_OPERATION.IDLE;
    }
  }
  derivedCoordinator.pendingLoadReason = derivedCoordinator.pendingLoadReason
    ? `${derivedCoordinator.pendingLoadReason}, ${reason || "request"}`
    : (reason || "request");
  if (derivedCoordinator.loadScheduleTimer) {
    clearTimeout(derivedCoordinator.loadScheduleTimer);
  }
  const delay = immediate ? 0 : DERIVED_LOAD_DEBOUNCE_MS;
  derivedCoordinator.loadScheduleTimer = setTimeout(runScheduledDerivedLoad, delay);
  return Promise.resolve(null);
}

function runScheduledDerivedLoad() {
  const reason = derivedCoordinator.pendingLoadReason || "scheduled";
  derivedCoordinator.pendingLoadReason = "";
  derivedCoordinator.loadScheduleTimer = null;
  uiDebug("derived_load_coordinator_run", {
    reason,
    window: activeWindow || "default"
  });
  loadDerivedViews();
}

function windowQuery(windowValue) {
  return `?days=${encodeURIComponent(windowValue || activeWindow || "default")}`;
}

function windowRequestOptions() {
  return {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({days: activeWindow || "default"})
  };
}

function refreshDerivedViews(mode) {
  return runDerivedRefresh(mode || "manual", "Derived refresh failed");
}

function runDerivedRefresh(refreshMode, failurePrefix) {
  const label = derivedRefreshLabel(refreshMode);
  if (derivedRefreshActive()) {
    setDerivedStatus(`${label} skipped; refresh already running`, "warning");
    if (refreshMode === "automatic") scheduleAutoDerivedRefresh();
    return Promise.resolve(null);
  }
  cancelActiveDerivedLoad("refresh starting");
  derivedCoordinator.operation = DERIVED_OPERATION.REFRESHING;
  const requestId = ++derivedCoordinator.refreshRequestId;
  derivedCoordinator.refreshMode = refreshMode;
  nextAutoDerivedRefreshAtMs = null;
  setDerivedStatus(`${label} running`, "warning");
  derivedCoordinator.statusText = `${label} running`;
  let failed = false;
  return refreshWhenBackendIdle(label, refreshMode)
    .then((bundle) => {
      if (requestId !== derivedCoordinator.refreshRequestId) return;
      if (!bundle) return;
      if (bundle && bundle.refresh_in_progress) {
        continuePollingActiveDerivedRefresh(label, bundle.status || {});
        return;
      }
      validateDerivedBundleShape(bundle);
      lastDerivedRefreshError = "";
      renderDerivedViews(bundle);
    })
    .catch((error) => {
      if (requestId !== derivedCoordinator.refreshRequestId) return;
      failed = true;
      lastDerivedRefreshError = `${failurePrefix}: ${error}`;
      derivedCoordinator.statusText = "";
      setDerivedStatus(lastDerivedRefreshError, "alert");
    })
    .finally(() => {
      if (requestId !== derivedCoordinator.refreshRequestId) return;
      if (derivedCoordinator.operation === DERIVED_OPERATION.WAITING) return;
      setDerivedCoordinatorIdle();
      lastDerivedRefreshCompletedAtMs = Date.now();
      stopDerivedStatusPolling();
      scheduleAutoDerivedRefresh();
      if (!failed) updateDerivedStatusLines();
    });
}

function refreshWhenBackendIdle(label, refreshMode) {
  return fetchJson("/derived_views/status")
    .then((status) => {
      if (status && status.in_progress) {
        continuePollingActiveDerivedRefresh(label, status);
        return null;
      }
      if (backendRefreshRecentlyFinished(status, refreshMode)) {
        lastDerivedRefreshCompletedAtMs = Number(status.last_finished_epoch) * 1000;
        setDerivedCoordinatorIdle();
        scheduleAutoDerivedRefresh();
        requestDerivedLoad("recent backend refresh", {immediate: true});
        return null;
      }
      const refreshPromise = fetchJson(
        "/derived_views/refresh",
        withTimeout(windowRequestOptions(), derivedRefreshTimeoutMs())
      );
      setTimeout(() => {
        if (derivedCoordinator.operation === DERIVED_OPERATION.REFRESHING) {
          startDerivedStatusPolling(label, false);
        }
      }, 1000);
      return refreshPromise;
    });
}

function backendRefreshRecentlyFinished(status, refreshMode) {
  if (!status || !status.last_finished_epoch) return false;
  if (refreshMode !== "automatic" && refreshMode !== "catch-up") return false;
  const intervalMin = uiNonNegativeNumber("derived_auto_refresh_min");
  if (intervalMin <= 0) return false;
  const finishedMs = Number(status.last_finished_epoch) * 1000;
  if (!Number.isFinite(finishedMs) || finishedMs <= 0) return false;
  return Date.now() - finishedMs < intervalMin * 60000;
}

function continuePollingActiveDerivedRefresh(label, status) {
  cancelActiveDerivedLoad("backend refresh active");
  derivedCoordinator.operation = DERIVED_OPERATION.WAITING;
  derivedCoordinator.refreshMode = "waiting";
  lastDerivedRefreshError = "";
  const text = derivedRefreshStatusText(label, status || {});
  derivedCoordinator.statusText =
    text || `${label} waiting for active backend refresh`;
  setDerivedStatus(
    derivedCoordinator.statusText,
    "warning"
  );
  if (!derivedCoordinator.statusPollTimer || !derivedCoordinator.pollRecoverOnComplete) {
    startDerivedStatusPolling(label, true);
  }
}

function startDerivedStatusPolling(label, recoverOnComplete) {
  stopDerivedStatusPolling();
  derivedCoordinator.pollRecoverOnComplete = Boolean(recoverOnComplete);
  pollDerivedRefreshStatus(label);
  derivedCoordinator.statusPollTimer = setInterval(() => {
    pollDerivedRefreshStatus(label);
  }, 5000);
}

function stopDerivedStatusPolling() {
  if (derivedCoordinator.statusPollTimer) {
    clearInterval(derivedCoordinator.statusPollTimer);
    derivedCoordinator.statusPollTimer = null;
  }
}

function pollDerivedRefreshStatus(label) {
  fetchJson("/derived_views/status")
    .then((status) => {
      if (!derivedRefreshActive()) return;
      if (status && status.in_progress === false) {
        if (derivedCoordinator.pollRecoverOnComplete) {
          recoverCompletedDerivedRefresh(label);
        } else {
          stopDerivedStatusPolling();
          derivedCoordinator.statusText = `${label} finishing`;
          setDerivedStatus(derivedCoordinator.statusText, "warning");
        }
        return;
      }
      const text = derivedRefreshStatusText(label, status || {});
      if (text) {
        derivedCoordinator.statusText = text;
        setDerivedStatus(text, "warning");
      }
    })
    .catch(() => {
      // Keep the original running/timeout status if the debug endpoint is not
      // reachable; the main refresh request still owns success/failure state.
    });
}

function recoverCompletedDerivedRefresh(label) {
  derivedCoordinator.refreshRequestId += 1;
  setDerivedCoordinatorIdle();
  lastDerivedRefreshCompletedAtMs = Date.now();
  stopDerivedStatusPolling();
  setDerivedStatus(`${label} finished on backend; loading updated data`, "warning");
  requestDerivedLoad("backend refresh completed", {immediate: true});
  scheduleAutoDerivedRefresh();
}

function derivedRefreshStatusText(label, status) {
  if (!status.in_progress) return "";
  const parts = [`${label} running`];
  if (status.phase_step && status.phase_total) {
    parts.push(
      `phase ${status.phase_step}/${status.phase_total}: ` +
      `${status.stage_label || status.stage || "working"}`
    );
  } else if (status.stage) {
    const stageElapsed = Number(status.stage_elapsed_sec || 0);
    parts.push(
      `backend stage: ${status.stage}${stageElapsed ? ` ${Math.round(stageElapsed)}s` : ""}`
    );
  }
  if (status.phase_step && status.phase_total) {
    const stageElapsed = Number(status.stage_elapsed_sec || 0);
    if (stageElapsed) parts.push(`phase ${Math.round(stageElapsed)}s`);
  }
  const elapsed = Number(status.elapsed_sec || 0);
  if (elapsed) parts.push(`total ${Math.round(elapsed)}s`);
  return parts.join(" | ");
}

function withTimeout(options, timeoutMs) {
  if (!window.AbortController || !timeoutMs) return options;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return {
    ...options,
    signal: controller.signal,
    _timeoutTimer: timer,
    _timeoutMs: timeoutMs
  };
}

function clearRequestTimeout(options) {
  if (options && options._timeoutTimer) clearTimeout(options._timeoutTimer);
}

function derivedRefreshTimeoutMs() {
  const configuredSec = uiNonNegativeNumber("derived_refresh_timeout_sec");
  const timeoutSec = configuredSec > 0 ? configuredSec : 600;
  return timeoutSec * 1000;
}

function renderDerivedViews(bundle) {
  uiDebug("derived_render_start", safeDerivedBundleSummary(bundle));
  clearStaleDerivedRefreshState();
  const errors = [];
  const displayHistory = subjectHistoryDisplayBundle(bundle);
  safelyRenderDerivedSection("Insights compatibility", errors, () =>
    renderFindingsHistory({})
  );
  safelyRenderDerivedSection("Subject History", errors, () =>
    renderDeviceHistory(displayHistory)
  );
  safelyRenderDerivedSection("Live scan hydration", errors, () =>
    hydrateLiveScanTablesFromHistory(bundle.device_history || {})
  );
  safelyRenderDerivedSection("Poll feed hydration", errors, () =>
    hydratePollFeedTablesFromHistory(displayHistory)
  );
  safelyRenderDerivedSection("Insights analysis", errors, () =>
    renderHistoryAnalysis(bundle.history_analysis || {})
  );
  safelyRenderDerivedSection("Reports", errors, () =>
    renderReports(bundle.reports || {})
  );
  safelyRenderDerivedSection("Combined Insights", errors, renderCombinedInsights);
  if (derivedHistoryHasRows()) {
    emptyDerivedRefreshAttempts = 0;
  }
  updateDerivedStatusLines();
  if (errors.length) {
    setDerivedStatus(`Derived view render issue: ${errors.join("; ")}`, "alert");
  }
  uiDebug("derived_render_done", {
    errors,
    status: derivedStatusSnapshot()
  });
  acknowledgeDerivedRender(bundle);
  maybeRefreshEmptyDerivedViews("derived views loaded");
}

function subjectHistoryDisplayBundle(bundle) {
  const source = bundle || {};
  const subjectHistory = source.subject_history || {};
  const deviceHistory = source.device_history || {};
  const bluetooth = subjectHistory.bluetooth || subjectHistory.ble || deviceHistory.bluetooth || deviceHistory.ble || {};
  const wifi = subjectHistory.wifi || deviceHistory.wifi || {};
  return {
    ...subjectHistory,
    generated_at: subjectHistory.generated_at || deviceHistory.generated_at || "",
    generated_at_epoch: subjectHistory.generated_at_epoch || deviceHistory.generated_at_epoch,
    refreshed_at: subjectHistory.refreshed_at || deviceHistory.refreshed_at || "",
    refreshed_at_epoch: subjectHistory.refreshed_at_epoch || deviceHistory.refreshed_at_epoch,
    window: subjectHistory.window || deviceHistory.window || {},
    records_read: subjectHistory.records_read || deviceHistory.records_read || 0,
    wifi,
    ble: bluetooth,
    bluetooth,
    subjects: Array.isArray(subjectHistory.subjects) ? subjectHistory.subjects : [],
    subject_counts: subjectHistory.subject_counts || {},
    total_subjects: subjectHistory.total_subjects || ((subjectHistory.subject_counts || {}).total || 0)
  };
}

function acknowledgeDerivedRender(bundle) {
  const summary = derivedBundleSummary(bundle);
  fetch("/derived_views/ack", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      client_id: CLIENT_SESSION_ID,
      generated_at: summary.generated_at || "",
      window: ((bundle || {}).window || {}).label || activeWindow || "default",
      sections: {
        findings: summary.findings,
        observations: summary.observations,
        reports: summary.reports,
        wifi_aps: summary.history_aps,
        wifi_clients: summary.history_clients,
        bluetooth_devices: summary.history_bluetooth
      }
    }),
    keepalive: true
  }).catch(() => {
    // Render acknowledgements are diagnostic only.
  });
}

function derivedBundleSummary(bundle) {
  const history = (bundle || {}).device_history || {};
  const reports = (bundle || {}).reports || {};
  const analysis = (bundle || {}).history_analysis || {};
  const findings = (bundle || {}).findings || {};
  const wifi = history.wifi || {};
  const bluetooth = history.bluetooth || history.ble || {};
  return {
    generated_at: (bundle || {}).generated_at || "",
    history_generated_at: history.generated_at || "",
    reports_generated_at: reports.generated_at || "",
    history_aps: (wifi.access_points || []).length,
    history_clients: (wifi.clients || []).length,
    history_bluetooth: (bluetooth.devices || []).length,
    reports: (reports.reports || []).length,
    observations: (analysis.observations || []).length,
    findings: (findings.findings || []).length
  };
}

function safeDerivedBundleSummary(bundle) {
  try {
    return derivedBundleSummary(bundle);
  } catch (error) {
    return {summary_error: errorMessage(error)};
  }
}

function errorMessage(error) {
  return error && error.message ? error.message : String(error);
}

function derivedStatusSnapshot() {
  return {
    insights: statusText("insights-status"),
    reports: statusText("reports-status"),
    history: statusText("history-status"),
    operation: derivedCoordinator.operation,
    refresh_mode: derivedCoordinator.refreshMode || "",
    load_window: derivedCoordinator.loadWindow || ""
  };
}

function statusText(id) {
  const status = document.getElementById(id);
  return status ? status.textContent : "";
}

function safelyRenderDerivedSection(label, errors, renderer) {
  try {
    renderer();
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    errors.push(`${label}: ${message}`);
  }
}

function clearStaleDerivedRefreshState() {
  if (!derivedRefreshActive()) {
    derivedCoordinator.statusText = "";
    return;
  }
  if (derivedCoordinator.operation !== DERIVED_OPERATION.WAITING) return;
  setDerivedCoordinatorIdle();
  stopDerivedStatusPolling();
  scheduleAutoDerivedRefresh();
}

function renderLiveTables() {
  pruneLiveScanRows();
  prunePollFeedRows();
  renderBleTable();
  renderAprsisTable();
  renderNoaaTable();
  renderUsgsTable();
  renderSwpcTable();
  renderPwsTable();
  renderLanTable();
  updateTabCounts();
}

function scheduleLiveRender(key, renderer) {
  if (liveRenderTimers.has(key)) return;
  const timer = setTimeout(() => {
    liveRenderTimers.delete(key);
    renderer();
  }, LIVE_RENDER_DELAY_MS);
  liveRenderTimers.set(key, timer);
}

function pruneLiveScanRows() {
  pruneRecentMap(
    rows.ble,
    "last_seen",
    liveBluetoothRetentionMs(),
    uiNumber("max_live_rows") * 5
  );
}

function liveBluetoothRetentionMs() {
  const recentSec = Math.max(uiNumber("bluetooth_live_recent_sec"), 60);
  return recentSec * 1000;
}

function prunePollFeedRows() {
  const ttlMs = pollFeedRetentionMs();
  const maxItems = uiNumber("max_live_rows");
  rows.noaa = pruneRecentArray(
    rows.noaa,
    ["event_time", "forecast_generated", "updated", "onset", "effective", "first_period_start", "last_seen"],
    ttlMs,
    maxItems
  );
  rows.usgs = pruneRecentArray(
    rows.usgs,
    ["event_time", "updated", "last_seen"],
    ttlMs,
    maxItems
  );
  rows.swpc = pruneRecentArray(
    rows.swpc,
    ["event_time", "peak_time", "issue", "issue_time", "updated", "last_seen"],
    ttlMs,
    maxItems
  );
}

function pollFeedRetentionMs() {
  const ttlSec = Math.max(uiNumber("poll_feed_live_ttl_sec"), 60);
  return ttlSec * 1000;
}

function pruneRecentArray(items, timestampKeys, maxAgeMs, maxItems) {
  const now = Date.now();
  const retained = [];
  (items || []).forEach((item, index) => {
    const timestampMs = firstRecordTimestampMs(item, timestampKeys);
    if (timestampMs && now - timestampMs > maxAgeMs) return;
    retained.push({item, index, timestampMs: timestampMs || 0});
  });
  if (retained.length <= maxItems) return retained.map((entry) => entry.item);
  const keepIndexes = new Set(
    [...retained]
      .sort((left, right) => right.timestampMs - left.timestampMs)
      .slice(0, maxItems)
      .map((entry) => entry.index)
  );
  return retained
    .filter((entry) => keepIndexes.has(entry.index))
    .map((entry) => entry.item);
}

function firstRecordTimestampMs(item, keys) {
  for (const key of keys || []) {
    const timestampMs = recordTimestampMs(item, key);
    if (timestampMs) return timestampMs;
  }
  return null;
}

function pruneRecentMap(map, timestampKey, maxAgeMs, maxItems) {
  const now = Date.now();
  const entries = [];
  map.forEach((item, key) => {
    const timestampMs = recordTimestampMs(item, timestampKey);
    if (timestampMs && now - timestampMs > maxAgeMs) {
      map.delete(key);
      return;
    }
    entries.push([key, timestampMs || 0]);
  });
  if (entries.length <= maxItems) return;
  entries.sort((left, right) => right[1] - left[1]);
  const keep = new Set(entries.slice(0, maxItems).map(([key]) => key));
  entries.forEach(([key]) => {
    if (!keep.has(key)) map.delete(key);
  });
}

function maybeRefreshEmptyDerivedViews(reason) {
  if (
    derivedRefreshActive() ||
    derivedLoadActive() ||
    derivedHistoryHasRows() ||
    !liveScanRowsSeen()
  ) {
    return;
  }
  if (!catchUpRefreshAllowed()) return;
  if (emptyDerivedRefreshAttempts >= 3) return;
  const now = Date.now();
  if (now - emptyDerivedRefreshRequestedAtMs < 60000) return;
  emptyDerivedRefreshRequestedAtMs = now;
  emptyDerivedRefreshAttempts += 1;
  setDerivedStatus(`Refreshing derived views after new scan data (${reason})`, "warning");
  setTimeout(() => refreshDerivedViews("catch-up"), 1000);
}

function maybeRefreshMissingSubject(reason, lookup) {
  if (typeof lookup !== "function" || lookup()) return;
  if (derivedRefreshActive() || derivedLoadActive()) return;
  if (!catchUpRefreshAllowed()) return;
  const now = Date.now();
  if (now - missingSubjectRefreshRequestedAtMs < 60000) return;
  missingSubjectRefreshRequestedAtMs = now;
  setDerivedStatus(`Refreshing derived views after new subject (${reason})`, "warning");
  setTimeout(() => refreshDerivedViews("catch-up"), 1000);
}

function catchUpRefreshAllowed() {
  const intervalMin = uiNonNegativeNumber("derived_auto_refresh_min");
  if (intervalMin <= 0 || !lastDerivedRefreshCompletedAtMs) return true;
  return Date.now() - lastDerivedRefreshCompletedAtMs >= intervalMin * 60000;
}

function derivedHistoryHasRows() {
  const history = latestDeviceHistory || {};
  const wifi = history.wifi || {};
  const bluetooth = history.bluetooth || history.ble || {};
  const directSubjects = Array.isArray(history.subjects)
    ? history.subjects.filter((item) =>
      ["aprsis", "rayhunter", "rtl433", "adsb", "noaa", "usgs", "swpc", "pws", "lan"].includes(String(item.collector || ""))
    )
    : [];
  return Boolean(
    (wifi.access_points || []).length ||
    (wifi.clients || []).length ||
    (bluetooth.devices || []).length ||
    directSubjects.length
  );
}

function liveScanRowsSeen() {
  return Boolean(
    rows.aps.size ||
    rows.ble.size ||
    rows.btClassic.size ||
    rows.aprsis.length ||
    rows.noaa.length ||
    rows.usgs.length ||
    rows.swpc.length ||
    rows.pws.length ||
    rows.adsb.length ||
    rows.lan.length ||
    rows.lanIdentify.length ||
    collectorSubjectEventsSeen()
  );
}

function collectorSubjectEventsSeen() {
  const subjectCollectors = subjectCollectorKeys();
  return (latestCollectorStatuses || []).some((item) => {
    return subjectCollectors.has(item.key) && Number(item.events_this_session || 0) > 0;
  });
}

function subjectCollectorKeys() {
  const keys = (COLLECTOR_METADATA || [])
    .filter((item) => item && item.has_subject_history)
    .map((item) => String(item.key || "").trim())
    .filter(Boolean);
  if (keys.length) return new Set(keys);
  return new Set([
    "wifi",
    "wifi_monitor",
    "ble",
    "bt_classic",
    "adsb",
    "rayhunter",
    "aprsis",
    "noaa",
    "usgs",
    "swpc",
    "pws",
    "lan"
  ]);
}

function validateDerivedBundleShape(bundle) {
  if (!bundle || typeof bundle !== "object") {
    throw new Error("refresh returned no derived bundle");
  }
  if (!bundle.device_history || !bundle.history_analysis || !bundle.reports) {
    throw new Error("refresh returned incomplete derived data");
  }
}

function hydrateLiveScanTablesFromHistory(history) {
  const wifi = (history || {}).wifi || {};
  const bluetooth = (history || {}).bluetooth || (history || {}).ble || {};
  let wifiChanged = false;
  (wifi.access_points || []).forEach((item) => {
    if (!item.bssid) return;
    const current = rows.aps.get(item.bssid) || {};
    const channel = latestArrayValue(item.channels);
    rows.aps.set(item.bssid, {
      ...current,
      ssid: latestArrayValue(item.ssids) || current.ssid || "",
      bssid: item.bssid,
      vendor_name: item.vendor_name,
      vendor_prefix: item.vendor_prefix,
      vendor_oui: item.vendor_oui,
      channel,
      frequency_band: bandForChannel(channel),
      encryption: latestArrayValue(item.encryption) || current.encryption || "",
      rssi: item.signal_latest || item.signal_max || current.rssi,
      last_seen: item.last_seen || current.last_seen || "",
      last_seen_epoch: item.last_seen_epoch || current.last_seen_epoch
    });
    wifiChanged = true;
  });

  let bleChanged = false;
  (bluetooth.devices || []).filter(bleDeviceIsRecent).forEach((item) => {
    if (!item.mac) return;
    const current = rows.ble.get(item.mac) || {};
    rows.ble.set(item.mac, {
      ...current,
      ...item,
      manufacturer:
        item.manufacturer || item.manufacturer_name || current.manufacturer,
      rssi: item.signal_latest || item.signal_max || current.rssi,
      last_seen: item.last_seen || current.last_seen || "",
      last_seen_epoch: item.last_seen_epoch || current.last_seen_epoch
    });
    bleChanged = true;
  });

  if (wifiChanged) renderWifiTables();
  if (bleChanged) scheduleLiveRender("ble", renderBleTable);
}

function hydratePollFeedTablesFromHistory(history) {
  let noaaChanged = false;
  historySubjectsFor(history, "noaa").forEach((subject) => {
    const data = subjectData(subject);
    const row = {
      ...data,
      event_type: noaaEventTypeForSubject(subject),
      last_seen: subject.last_seen || data.last_seen || "",
      last_seen_epoch: subject.last_seen_epoch || data.last_seen_epoch
    };
    if (!noaaLiveEventKey(row) || newerPollRowExists(rows.noaa, noaaLiveEventKey, row)) return;
    upsertNoaaEventRow(row);
    noaaChanged = true;
  });

  let usgsChanged = false;
  historySubjectsFor(history, "usgs").forEach((subject) => {
    const data = subjectData(subject);
    const row = {
      ...data,
      event_type: "usgs_earthquake",
      last_seen: subject.last_seen || data.last_seen || "",
      last_seen_epoch: subject.last_seen_epoch || data.last_seen_epoch
    };
    if (!usgsLiveEventKey(row) || newerPollRowExists(rows.usgs, usgsLiveEventKey, row)) return;
    upsertUsgsEventRow(row);
    usgsChanged = true;
  });

  let swpcChanged = false;
  historySubjectsFor(history, "swpc").forEach((subject) => {
    const data = subjectData(subject);
    const row = {
      ...data,
      event_type: "swpc_event",
      last_seen: subject.last_seen || data.last_seen || "",
      last_seen_epoch: subject.last_seen_epoch || data.last_seen_epoch
    };
    if (!swpcLiveEventKey(row) || newerPollRowExists(rows.swpc, swpcLiveEventKey, row)) return;
    upsertSwpcEventRow(row);
    swpcChanged = true;
  });

  let pwsChanged = false;
  historySubjectsFor(history, "pws").forEach((subject) => {
    const data = subjectData(subject);
    const row = {
      ...data,
      event_type: "pws_weather",
      last_seen: subject.last_seen || data.last_seen || "",
      last_seen_epoch: subject.last_seen_epoch || data.last_seen_epoch
    };
    if (!pwsLiveEventKey(row) || newerPollRowExists(rows.pws, pwsLiveEventKey, row)) return;
    upsertPwsEventRow(row);
    pwsChanged = true;
  });

  if (noaaChanged || usgsChanged || swpcChanged) prunePollFeedRows();
  if (noaaChanged) renderNoaaTable();
  if (usgsChanged) renderUsgsTable();
  if (swpcChanged) renderSwpcTable();
  if (pwsChanged) renderPwsTable();
}

function noaaEventTypeForSubject(subject) {
  const data = subjectData(subject);
  const type = String((subject || {}).subject_type || data.event_type || "");
  if (type === "noaa_forecast" || data.alert_kind === "forecast") {
    return "noaa_forecast_summary";
  }
  if (type === "noaa_tsunami_alert" || data.alert_kind === "tsunami") {
    return "noaa_tsunami_alert";
  }
  if (type === "noaa_tropical_advisory" || String(data.alert_kind || "").startsWith("tropical")) {
    return "noaa_tropical_advisory";
  }
  return "noaa_weather_alert";
}

function newerPollRowExists(list, keyFn, row) {
  const key = keyFn(row);
  const rowEpoch = Number(row.last_seen_epoch || 0);
  return (list || []).some((item) =>
    keyFn(item) === key && Number(item.last_seen_epoch || 0) > rowEpoch
  );
}

function latestArrayValue(values) {
  if (!Array.isArray(values) || !values.length) return "";
  return values[values.length - 1];
}

function setDerivedStatus(text, state) {
  setInsightsStatus(text, state);
  setHistoryStatus(text, state);
  setReportsStatus(text, state);
}

function renderFindingsHistory(summary) {
  latestFindingsHistory = summary;
  findingsHistoryLoaded = true;
  renderCombinedInsights();
}

function setInsightsStatus(text, state) {
  const status = document.getElementById("insights-status");
  if (!status) return;
  status.textContent = text;
  status.className = `status-strip ${state || "muted"}`;
}

function setReportsStatus(text, state) {
  const status = document.getElementById("reports-status");
  if (!status) return;
  status.textContent = text;
  status.className = `status-strip ${state || "muted"}`;
}

function updateDerivedStatusLines() {
  if (derivedRefreshActive()) {
    setDerivedStatus(
      derivedCoordinator.statusText || autoRefreshText(),
      "warning"
    );
    return;
  }
  if (lastDerivedRefreshError) {
    const auto = autoRefreshText();
    setDerivedStatus(
      auto ? `${lastDerivedRefreshError} | ${auto}` : lastDerivedRefreshError,
      "alert"
    );
    return;
  }
  if (shouldRunStaleDerivedRefresh()) {
    refreshDerivedViewsAutomatically();
    return;
  }
  if (latestFindingsHistory || latestHistoryAnalysis) updateInsightsStatus();
  if (latestReports) {
    updateReportsStatus(latestReports);
  }
  if (latestDeviceHistory) updateDeviceHistoryStatus(latestDeviceHistory);
}

function derivedStatusPrefix(window, generatedAt, generatedAtEpoch) {
  const parts = [((window || {}).label || "Selected range")];
  if (generatedAt) parts.push(`refreshed ${generatedAt}`);
  const stale = derivedStaleText(generatedAt, generatedAtEpoch);
  if (stale) parts.push(stale);
  const auto = autoRefreshText();
  if (auto) parts.push(auto);
  return parts.join(" | ");
}

function derivedStatusState(generatedAt, generatedAtEpoch, normalState) {
  return derivedStaleText(generatedAt, generatedAtEpoch) && normalState !== "alert" ? "warning" : normalState;
}

function derivedStaleText(generatedAt, generatedAtEpoch) {
  const threshold = uiNonNegativeNumber("derived_stale_after_min");
  if ((!generatedAt && !generatedAtEpoch) || threshold <= 0) return "";
  const timestampMs = Number.isFinite(Number(generatedAtEpoch))
    ? Number(generatedAtEpoch) * 1000
    : null;
  if (!timestampMs) return "";
  const ageMin = Math.floor((Date.now() - timestampMs) / 60000);
  if (ageMin < threshold) return "";
  return `stale: refreshed ${ageMin} min ago`;
}

function latestSeenStatusText(records, keys) {
  const timestampMs = latestRecordTimestampMs(records, keys);
  if (!timestampMs) return records && records.length ? "latest seen: unknown" : "";
  return `latest seen ${formatAgeMinutes(timestampMs)} ago`;
}

function derivedDataStatusState(records, keys, normalState) {
  if (normalState === "alert") return normalState;
  const threshold = uiNonNegativeNumber("derived_stale_after_min");
  if (threshold <= 0) return normalState;
  const timestampMs = latestRecordTimestampMs(records, keys);
  if (!timestampMs) return normalState;
  return Date.now() - timestampMs >= threshold * 60000 ? "warning" : normalState;
}

function latestRecordTimestampMs(records, keys) {
  const values = (records || []).map((item) => {
    for (const key of keys) {
      const timestampMs = recordTimestampMs(item, key);
      if (timestampMs) return timestampMs;
    }
    return null;
  }).filter((value) => Number.isFinite(value) && value > 0);
  return values.length ? Math.max(...values) : null;
}

function formatAgeMinutes(timestampMs) {
  const ageMin = Math.max(0, Math.floor((Date.now() - timestampMs) / 60000));
  if (ageMin < 60) return `${ageMin} min`;
  const hours = Math.floor(ageMin / 60);
  const minutes = ageMin % 60;
  return minutes ? `${hours}h ${minutes}m` : `${hours}h`;
}

function derivedRefreshLabel(mode) {
  return {
    automatic: "Automatic refresh",
    "catch-up": "Catch-up refresh",
    view: "View refresh",
    manual: "Manual refresh"
  }[mode] || "Derived refresh";
}

function autoRefreshText() {
  if (derivedRefreshActive()) {
    return `${derivedRefreshLabel(derivedCoordinator.refreshMode).toLowerCase()} running`;
  }
  if (!nextAutoDerivedRefreshAtMs) return "";
  const remainingMs = nextAutoDerivedRefreshAtMs - Date.now();
  if (remainingMs <= 0) return "next automatic refresh now";
  const remainingMin = Math.max(1, Math.ceil(remainingMs / 60000));
  return `next automatic refresh in ${remainingMin} min`;
}

function configureAutoDerivedRefresh() {
  if (autoDerivedRefreshTimer) {
    clearTimeout(autoDerivedRefreshTimer);
    autoDerivedRefreshTimer = null;
  }
  nextAutoDerivedRefreshAtMs = null;
  startDerivedStatusTicker();
  scheduleAutoDerivedRefresh();
}

function startDerivedStatusTicker() {
  if (derivedStatusTicker) clearInterval(derivedStatusTicker);
  derivedStatusTicker = setInterval(updateDerivedStatusLines, 30000);
}

function scheduleAutoDerivedRefresh() {
  if (autoDerivedRefreshTimer) {
    clearTimeout(autoDerivedRefreshTimer);
    autoDerivedRefreshTimer = null;
  }
  const intervalMin = uiNonNegativeNumber("derived_auto_refresh_min");
  if (intervalMin <= 0) {
    nextAutoDerivedRefreshAtMs = null;
    return;
  }
  const intervalMs = intervalMin * 60000;
  nextAutoDerivedRefreshAtMs = Date.now() + intervalMs;
  autoDerivedRefreshTimer = setTimeout(refreshDerivedViewsAutomatically, intervalMs);
}

function refreshDerivedViewsAutomatically() {
  return runDerivedRefresh("automatic", "Automatic refresh failed");
}

function refreshAfterBrowserWake() {
  const now = Date.now();
  if (now - lastWakeRefreshAtMs < 10000 || derivedRefreshActive()) return;
  lastWakeRefreshAtMs = now;
  renderLiveTables();
  requestDerivedLoad("browser wake");
  updateDerivedStatusLines();
}

function shouldRunStaleDerivedRefresh() {
  const intervalMin = uiNonNegativeNumber("derived_auto_refresh_min");
  const staleMin = uiNonNegativeNumber("derived_stale_after_min");
  if (intervalMin <= 0 || staleMin <= 0 || derivedRefreshActive()) return false;
  const refreshCooldownMs = intervalMin * 60000;
  if (
    lastDerivedRefreshCompletedAtMs &&
    Date.now() - lastDerivedRefreshCompletedAtMs < refreshCooldownMs
  ) {
    return false;
  }
  const lastRefreshMs = latestDerivedRefreshMs();
  if (!lastRefreshMs) return false;
  const ageMs = Date.now() - lastRefreshMs;
  if (ageMs < staleMin * 60000) return false;
  if (autoDerivedRefreshTimer) {
    clearTimeout(autoDerivedRefreshTimer);
    autoDerivedRefreshTimer = null;
  }
  nextAutoDerivedRefreshAtMs = Date.now();
  return true;
}

function latestDerivedRefreshMs() {
  const timestamps = [
    summaryRefreshMs(latestFindingsHistory),
    summaryRefreshMs(latestHistoryAnalysis),
    summaryRefreshMs(latestDeviceHistory),
    summaryRefreshMs(latestReports)
  ].filter((value) => Number.isFinite(value) && value > 0);
  return timestamps.length ? Math.max(...timestamps) : null;
}

function summaryRefreshMs(summary) {
  if (!summary) return null;
  const epoch = Number(summary.generated_at_epoch || summary.refreshed_at_epoch);
  if (Number.isFinite(epoch) && epoch > 0) return epoch * 1000;
  return null;
}

function recordTimestampMs(item, key) {
  if (!item) return null;
  const epoch = Number(item[`${key}_epoch`]);
  if (Number.isFinite(epoch) && epoch > 0) return epoch * 1000;
  if (key === "issue_time") {
    const issueEpoch = Number(item.issue_epoch);
    if (Number.isFinite(issueEpoch) && issueEpoch > 0) return issueEpoch * 1000;
  }
  return parseTimestampStringMs(item[key]);
}

function parseTimestampStringMs(value) {
  const text = String(value || "").trim();
  if (!text) return null;
  const match = text.match(
    /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?(?:\s*(Z|GMT|UTC)|([+-]\d{2}):?(\d{2}))?$/i
  );
  if (match) {
    const year = Number(match[1]);
    const month = Number(match[2]) - 1;
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6] || 0);
    if (match[7]) {
      return Date.UTC(year, month, day, hour, minute, second);
    }
    if (match[8]) {
      const sign = match[8].startsWith("-") ? -1 : 1;
      const offsetHours = Math.abs(Number(match[8]));
      const offsetMinutes = Number(match[9] || 0);
      const offsetMs = sign * ((offsetHours * 60 + offsetMinutes) * 60 * 1000);
      return Date.UTC(year, month, day, hour, minute, second) - offsetMs;
    }
    return new Date(year, month, day, hour, minute, second).getTime();
  }
  const parsed = Date.parse(text);
  return Number.isFinite(parsed) ? parsed : null;
}

function displayTimestamp(item, key) {
  const timestampMs = recordTimestampMs(item, key);
  if (timestampMs) return formatTimestampMs(timestampMs);
  return String((item || {})[key] || "");
}

function displayFirstTimestamp(item, keys) {
  for (const key of keys || []) {
    const text = displayTimestamp(item, key);
    if (text) return text;
  }
  return "";
}

function formatTimestampMs(timestampMs) {
  const date = new Date(timestampMs);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (value) => String(value).padStart(2, "0");
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate())
  ].join("-") + " " + [
    pad(date.getHours()),
    pad(date.getMinutes()),
    pad(date.getSeconds())
  ].join(":");
}

function uiNonNegativeNumber(key) {
  const value = Number(uiConfig[key]);
  if (Number.isFinite(value) && value >= 0) return value;
  return 0;
}

function insightMatchesFilters(insight) {
  return insightMatchesSubtab(insight) &&
    insightMatchesActivityFilter(insight) &&
    insightMatchesSeverityFilter(insight);
}

function insightMatchesSearch(insight) {
  return rowMatchesSearch(insightCells(insight), insightsSearch);
}

function insightMatchesSubtab(insight) {
  const mode = activeSubtabs.insights || "all";
  if (mode === "all") return true;
  return sourceMatchesSubtab(insight.source, mode);
}

function sourceLabel(source) {
  const key = String(source || "").toLowerCase();
  if (key === "privacy") return "Privacy";
  if (key === "rayhunter") return "Rayhunter";
  if (key === "aprsis") return "APRS-IS";
  if (key === "noaa") return "NOAA";
  if (key === "usgs") return "USGS";
  if (key === "swpc") return "SWPC";
  if (key === "adsb") return "ADS-B";
  if (key === "rtl433") return "RTL-433";
  if (key === "lan") return "LAN";
  const match = collectorEntryForSource(key);
  return match ? match.label : (source || "");
}

function showInsightSourceColumn() {
  return (activeSubtabs.insights || "all") === "all";
}

function updateReportsStatus(bundle, visibleReports) {
  const source = bundle || {};
  const window = source.window || {};
  const refreshedAt = source.generated_at || source.refreshed_at;
  const refreshedEpoch = source.generated_at_epoch || source.refreshed_at_epoch;
  const total = rows.reports.length;
  const visible = visibleReports || rows.reports
    .filter(reportMatchesSubtab)
    .filter(reportMatchesSearch);
  const warnings = rows.reports.filter((item) => item.severity === "warning").length;
  const newestSeen = latestSeenStatusText(visible, ["last_seen", "timestamp"]);
  const normalState = derivedStatusState(
    refreshedAt,
    refreshedEpoch,
    visible.some((item) => item.severity === "warning" || item.severity === "error" || item.severity === "alert") ? "warning" : "ok"
  );
  setReportsStatus(
    [
      derivedStatusPrefix(window, refreshedAt, refreshedEpoch),
      newestSeen,
      `${visible.length} shown`,
      `${total} reports`,
      `${warnings} warnings`
    ].filter(Boolean).join(" | "),
    derivedDataStatusState(visible, ["last_seen", "timestamp"], normalState)
  );
}

function reportMatchesSubtab(report) {
  const mode = activeSubtabs.reports || "all";
  if (mode === "all") return true;
  return sourceMatchesSubtab(report.source, mode);
}

function reportMatchesSearch(report) {
  const needle = reportSearchNeedle();
  if (!needle) return true;
  return reportRowMatchesSearch(buildReportRow(report), needle);
}

function reportSearchNeedle() {
  if (!reportsSearch) return "";
  return String(reportsSearch.value || "").trim().toLowerCase();
}

function updateReportsSummary(visible) {
  const summary = document.getElementById("reports-summary");
  if (!summary) return;
  const reports = visible || [];
  if (!reports.length) {
    summary.textContent = "No reports match the current view";
    return;
  }
  const counts = reports.reduce((acc, report) => {
    const key = reportTypeCategory(report);
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const top = Object.entries(counts)
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, 4)
    .map(([key, count]) => `${reportFilterTypeLabel(key)}: ${count}`);
  const patternCount = reports.filter(reportIsCrossSubjectReport).length;
  const subjectCount = reports.length - patternCount;
  summary.textContent = `Report scope: Patterns: ${patternCount} | Subjects: ${subjectCount} | Mix: ${top.join(" | ")}`;
}

function reportTypeCategory(report) {
  const scope = String((report || {}).report_scope || "").toLowerCase();
  if (scope === "population") return "pattern";
  if (scope === "collector" || scope === "quality") return "collector";
  const text = String(report.type || "").toLowerCase();
  if (text.includes("new")) return "new";
  if (reportIsPresenceReport(report)) return "presence";
  return categoryForType(text || "report");
}

function reportIsCrossSubjectReport(report) {
  const scope = String((report || {}).report_scope || "").toLowerCase();
  if (["population", "collector", "quality"].includes(scope)) return true;
  return Boolean(((report || {}).evidence || {}).population_kind);
}

function reportFilterTypeLabel(type) {
  return {
    security: "Security",
    presence: "Presence",
    privacy: "Privacy",
    signal: "Signal",
    new: "New",
    behavior: "Behavior",
    identity: "Identity",
    collector: "Collector",
    pattern: "Pattern",
    analysis: "Analysis"
  }[type] || type;
}

function sortReports(items) {
  return (items || []).sort((left, right) => {
    const scope = reportScopeRank(right) - reportScopeRank(left);
    if (scope !== 0) return scope;
    const severity = severityRank(right.severity) - severityRank(left.severity);
    if (severity !== 0) return severity;
    const score = Number(right.score || 0) - Number(left.score || 0);
    if (score !== 0) return score;
    const leftMs = recordTimestampMs(left, "last_seen") || recordTimestampMs(left, "timestamp");
    const rightMs = recordTimestampMs(right, "last_seen") || recordTimestampMs(right, "timestamp");
    if (leftMs && rightMs && leftMs !== rightMs) return rightMs - leftMs;
    if (leftMs && !rightMs) return -1;
    if (!leftMs && rightMs) return 1;
    return String(right.last_seen || right.timestamp || "").localeCompare(String(left.last_seen || left.timestamp || ""));
  });
}

function reportScopeRank(report) {
  const scope = String((report || {}).report_scope || "").toLowerCase();
  if (scope === "population" || ((report || {}).evidence || {}).population_kind) return 3;
  if (scope === "collector" || scope === "quality") return 2;
  return 1;
}

function sourceMatchesSubtab(source, mode) {
  const key = String(source || "").toLowerCase();
  const group = COLLECTOR_SOURCE_GROUPS[mode];
  if (group && Array.isArray(group.members)) return key === mode || group.members.includes(key);
  return key === mode;
}

function collectorEntryForSource(source) {
  const key = String(source || "").toLowerCase();
  for (const groupKey of Object.keys(COLLECTOR_SOURCE_GROUPS || {})) {
    const group = COLLECTOR_SOURCE_GROUPS[groupKey] || {};
    if ((group.members || []).includes(key)) {
      return {value: groupKey, label: group.label || groupKey};
    }
  }
  return COLLECTOR_SUBTABS.find((entry) => entry.value === key);
}

function updateTabCounts() {
  setTabCount("insights", rows.insights.length);
  setTabCount("reports", rows.reports.length);
  setTabCount("history", subjectHistoryRowCount());
  setTabCount("wifi", rows.aps.size);
  setTabCount("wifi_monitor", rows.monitorEvents.length);
  setTabCount("bluetooth", bluetoothTabRowCount());
  setTabCount("rtl433", rows.rtl433.length);
  setTabCount("adsb", rows.adsb.length);
  setTabCount("rayhunter", rows.rayhunter.length);
  setTabCount("aprsis", rows.aprsis.length);
  setTabCount("noaa", rows.noaa.length);
  setTabCount("usgs", rows.usgs.length);
  setTabCount("swpc", rows.swpc.length);
  setTabCount("pws", rows.pws.length);
  setTabCount("lan", rows.lan.length + rows.lanIdentify.length);
  setTabCount("alerts", rows.alerts.length);
  updateSystemTabCount();
  updateSourceFilterCounts();
}

function setTabCount(tab, count, title) {
  const node = document.querySelector(`[data-tab-count="${tab}"]`);
  if (!node) return;
  node.textContent = String(count || 0);
  if (title) node.title = title;
  else node.removeAttribute("title");
}

function updateSystemTabCount() {
  const statuses = latestCollectorStatuses || [];
  const total = statuses.length;
  const online = statuses.filter((item) => String((item || {}).state || "").toUpperCase() === "ONLINE").length;
  const disabled = statuses.filter((item) => String((item || {}).state || "").toUpperCase() === "DISABLED").length;
  const offline = statuses.filter((item) => ["OFFLINE", "STOPPED"].includes(String((item || {}).state || "").toUpperCase())).length;
  const details = [`${online} online`, `${total} total`];
  if (offline) details.push(`${offline} offline/stopped`);
  if (disabled) details.push(`${disabled} disabled`);
  const label = total ? `${online}/${total}` : "0";
  setTabCount("system", label, details.join(", "));
}

function bluetoothTabRowCount() {
  const recentBle = [...rows.ble.values()].filter(bleDeviceIsRecent).length;
  return recentBle + rows.btClassic.size + rows.bleIdentify.length;
}

function subjectHistoryRowCount(source) {
  const history = latestDeviceHistory || {};
  const wifi = history.wifi || {};
  const bluetooth = history.bluetooth || history.ble || {};
  const sourceKey = String(source || "all").toLowerCase();
  const countForDirectSource = (collector) => historySubjectsFor(history, collector).length;
  const displayAps = (wifi.access_points || []).length;
  const displayClients = (wifi.clients || []).length;
  const displayBluetooth = (bluetooth.devices || []).length;
  if (sourceKey === "wifi") return displayAps;
  if (sourceKey === "wifi_monitor") return displayClients;
  if (sourceKey === "bluetooth") return displayBluetooth;
  if (sourceKey && sourceKey !== "all") return countForDirectSource(sourceKey);
  return displayAps + displayClients + displayBluetooth +
    ["aprsis", "rayhunter", "rtl433", "adsb", "noaa", "usgs", "swpc", "pws", "lan"]
      .reduce((total, collector) => total + countForDirectSource(collector), 0);
}

function updateSourceFilterCounts() {
  document.querySelectorAll(".source-filter[data-subtab-group] .source-filter-button").forEach((button) => {
    const group = button.closest(".source-filter")?.dataset.subtabGroup || "";
    const source = button.dataset.subtab || "all";
    const count = sourceFilterCount(group, source);
    let badge = button.querySelector(".source-filter-count");
    if (!badge) {
      badge = document.createElement("span");
      badge.className = "source-filter-count";
      button.appendChild(badge);
    }
    badge.textContent = String(count || 0);
  });
}

function sourceFilterCount(group, source) {
  const mode = source || "all";
  if (group === "insights") {
    return rows.insights.filter((item) => mode === "all" || sourceMatchesSubtab(item.source, mode)).length;
  }
  if (group === "reports") {
    return rows.reports.filter((item) => mode === "all" || sourceMatchesSubtab(item.source, mode)).length;
  }
  if (group === "history") {
    return subjectHistoryRowCount(mode);
  }
  return 0;
}

function insightMatchesActivityFilter(insight) {
  const mode = insightsActivityFilter ? insightsActivityFilter.value : "all";
  if (mode === "all") return true;
  const severity = String(insight.severity || "").toLowerCase();
  const isImportantSeverity = severity === "warning" || severity === "error" || severity === "alert";
  const state = activityState(insight);
  const score = Number(insight.score || 0);
  if (mode === "important") {
    return isImportantSeverity || state === "recurring" || score >= 70;
  }
  if (mode === "recent") {
    return state === "active" || state === "recent";
  }
  return true;
}

function activityState(insight) {
  if (insight.activity_state) return String(insight.activity_state).toLowerCase();
  if (String(insight.type || "").includes("recurring") || String(insight.category || "").includes("recurring")) return "recurring";
  const age = insightAgeMinutes(insight);
  if (age === null) return "unknown";
  return age <= uiNonNegativeNumber("insights_recent_after_min") ? "recent" : "stale";
}

function insightAgeMinutes(insight) {
  const timestampMs = recordTimestampMs(insight, "last_seen") || recordTimestampMs(insight, "timestamp");
  if (!timestampMs) return null;
  return Math.max(0, Math.floor((Date.now() - timestampMs) / 60000));
}

function activityLabel(insight) {
  const state = activityState(insight);
  const age = insight.age_minutes !== undefined && insight.age_minutes !== null ? Number(insight.age_minutes) : insightAgeMinutes(insight);
  if (state === "recurring") return "recurring";
  if (age === null || !Number.isFinite(age)) return state;
  if (age < 1) return `${state} now`;
  return `${state} ${age} min`;
}

function insightDetails(insight) {
  const parts = [];
  if (insight.detail) parts.push(insight.detail);
  if (insight.evidence_text) parts.push(insight.evidence_text);
  return parts.join(" | ");
}

function insightMatchesSeverityFilter(insight) {
  const mode = insightsSeverityFilter ? insightsSeverityFilter.value : "all";
  const severity = String(insight.severity || "").toLowerCase();
  const isError = severity === "error" || severity === "alert";
  if (mode === "all") return true;
  if (mode === "warning") return severity === "warning";
  if (mode === "warning_error") return severity === "warning" || isError;
  if (mode === "error") return isError;
  return true;
}

function appendSelectOption(select, value, label) {
  const option = document.createElement("option");
  option.value = value;
  option.textContent = label;
  select.appendChild(option);
}

function buildSubtabs() {
  document.querySelectorAll(".source-filter[data-subtab-group]").forEach((container) => {
    const group = container.dataset.subtabGroup;
    const entries = subtabEntriesForGroup(group);
    let selected = activeSubtabs[group] || "all";
    if (!entries.some((entry) => entry.value === selected)) {
      selected = "all";
      activeSubtabs[group] = selected;
    }
    container.innerHTML = "";
    entries.forEach((entry) => {
      const button = document.createElement("button");
      button.className = `source-filter-button ${entry.value === selected ? "active" : ""}`;
      button.dataset.subtab = entry.value;
      button.appendChild(document.createTextNode(entry.label));
      const count = document.createElement("span");
      count.className = "source-filter-count";
      count.textContent = "0";
      button.appendChild(count);
      button.addEventListener("click", () => {
        container.querySelectorAll(".source-filter-button").forEach((item) => item.classList.remove("active"));
        button.classList.add("active");
        activeSubtabs[group] = button.dataset.subtab;
        updateSubtabPanel(group);
        if (group === "insights") renderInsights();
        if (group === "reports") renderReports(latestReports || {});
      });
      container.appendChild(button);
    });
    updateSubtabPanel(group);
  });
  updateTabCounts();
}

function subtabEntriesForGroup(group) {
  if (group === "history") {
    const historySources = historySourceValues();
    return COLLECTOR_SUBTABS.filter((entry) => historySources.has(entry.value));
  }
  return COLLECTOR_SUBTABS;
}

function historySourceValues() {
  const values = new Set(["all"]);
  document.querySelectorAll(".history-source-panel").forEach((panel) => {
    if (panel.dataset.source) values.add(panel.dataset.source);
  });
  return values;
}

function loadCollectorMetadata() {
  fetchPlainJson("/collector_metadata")
    .then((metadata) => {
      COLLECTOR_METADATA = Array.isArray(metadata.collectors) ? metadata.collectors : [];
      if (metadata.source_groups) COLLECTOR_SOURCE_GROUPS = metadata.source_groups;
      if (!Array.isArray(metadata.subtabs) || !metadata.subtabs.length) return;
      COLLECTOR_SUBTABS = metadata.subtabs;
      buildSubtabs();
    })
    .catch(() => {
      // Keep the built-in fallback tabs when the metadata endpoint is not ready.
    });
}

function controlCollector(key, action) {
  const payload = collectorControlPayload(key, action);
  const detail = key === "rtl433" && action === "start"
    ? rtl433StartRequestedDetail(payload.overrides || {})
    : `${action} requested`;
  setCollectorBanner(key, action === "start" ? "STARTING" : "STOPPING", detail);
  if (key === "rtl433" && action === "start" && payload.overrides && payload.overrides.frequency_plan) {
    updateRtl433FrequencyState({
      clear_frequency_state: true,
      frequency_summary: payload.overrides.frequency_plan,
      planned_frequency_mhz: rtl433FixedPlanFrequency(payload.overrides.frequency_plan),
      submitted_plan: payload.overrides.frequency_plan,
      tune_pending: true
    });
  }
  socket.emit("collector_control", payload);
}

function rtl433StartRequestedDetail(overrides) {
  return overrides.frequency_plan
    ? `start requested | plan ${overrides.frequency_plan}`
    : "start requested";
}

function collectorControlPayload(key, action) {
  const payload = {key, action};
  if (key === "rtl433" && action === "start") {
    const overrides = rtl433OverridesFromInputs();
    if (Object.keys(overrides).length) payload.overrides = overrides;
  }
  return payload;
}

function rtl433OverridesFromInputs() {
  const input = document.getElementById("rtl433-plan");
  const value = input ? String(input.value || "").trim() : "";
  return value ? {frequency_plan: value} : {};
}

function rtl433FixedPlanFrequency(plan) {
  const text = String(plan || "").trim();
  if (!text || text.includes(",")) return undefined;
  const fields = text.split(":").map((field) => field.trim());
  if (fields.length !== 2 || fields[0].includes("-")) return undefined;
  const dwell = Number(fields[1]);
  if (!Number.isFinite(dwell) || dwell > 0) return undefined;
  return rtl433FrequencyTextToMhz(fields[0]);
}

function rtl433FrequencyTextToMhz(value) {
  const match = String(value || "").trim().toLowerCase().match(/^([0-9]+(?:\.[0-9]+)?)(hz|khz|mhz|m|ghz|g)?$/);
  if (!match) return undefined;
  let number = Number(match[1]);
  if (!Number.isFinite(number)) return undefined;
  const unit = match[2] || "mhz";
  if (unit === "hz") number /= 1000000;
  else if (unit === "khz") number /= 1000;
  else if (unit === "ghz" || unit === "g") number *= 1000;
  return Number(number.toFixed(6));
}

function showBluetoothSubtab(name) {
  document.querySelectorAll("[data-bluetooth-subtab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.bluetoothSubtab === name);
  });
  document.querySelectorAll(".bluetooth-source-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.bluetoothSource === name);
  });
}

function loadViewMetadata() {
  if (!viewWindowFilter) return;
  fetchPlainJson("/view_metadata")
    .then((metadata) => {
      applyDashboardMetadata(metadata || {});
      if (!Array.isArray(metadata.options) || !metadata.options.length) {
        requestDerivedLoad("metadata without view options");
        return;
      }
      const selected = activeWindow || metadata.active || "default";
      viewWindowFilter.innerHTML = "";
      metadata.options.forEach((entry) => appendSelectOption(viewWindowFilter, entry.value, entry.label));
      activeWindow = metadata.options.some((entry) => entry.value === selected) ? selected : (metadata.active || "default");
      viewWindowFilter.value = activeWindow;
      findingsHistoryLoaded = false;
      requestDerivedLoad("view metadata loaded");
    })
    .catch(() => {
      // Keep the small static fallback selector if metadata is not available.
      configureAutoDerivedRefresh();
      requestDerivedLoad("view metadata fallback");
    });
}

function applyDashboardMetadata(metadata) {
  applyAppVersion(metadata.version);
  if (metadata.ui) {
    uiConfig = {...uiConfig, ...metadata.ui};
  }
  bluetoothUuidNames = {
    ...BLUETOOTH_SERVICE_NAMES,
    ...(metadata.bluetooth_uuid_names || {})
  };
  configureAutoDerivedRefresh();
  applyRtl433Defaults((metadata.collectors || {}).rtl433 || {});
}

function applyAppVersion(version) {
  const node = document.getElementById("app-version");
  if (!node) return;
  node.textContent = version ? `v${version}` : "";
}

function applyRtl433Defaults(config) {
  setInputValue("rtl433-plan", config.frequency_plan);
  const fixedFrequency = rtl433FixedPlanFrequency(config.frequency_plan);
  if (fixedFrequency !== undefined) {
    updateRtl433FrequencyState({
      frequency_summary: config.frequency_plan,
      planned_frequency_mhz: fixedFrequency,
      source: "configured plan"
    });
  }
}

function setInputValue(id, value) {
  const input = document.getElementById(id);
  if (!input || value === undefined || value === null) return;
  input.value = value;
}

function uiNumber(key) {
  const value = Number(uiConfig[key]);
  if (Number.isFinite(value) && value > 0) return Math.floor(value);
  return 1;
}

function renderBleEvent(event) {
  document.getElementById("ble-status").textContent = event.type;
  if (event.type === "collector_offline" || event.type === "collector_retrying") {
    const method = event.data.scan_method ? `method=${event.data.scan_method}` : "";
    const fallback = event.data.fallback_active ? "bluetoothctl fallback active" : "";
    const reason = event.data.reason || event.data.warning || "";
    rows.bleScanDetail = [method, fallback].filter(Boolean).join(" | ");
    setCollectorBanner("ble", event.type, eventStatusDetail("ble", event.data.adapter, [rows.bleScanDetail, reason].filter(Boolean).join(" | ")));
  }
  if (event.type === "scanner_started") {
    const method = event.data.scan_method ? `method=${event.data.scan_method}` : "";
    const fallback = event.data.fallback_active ? "bluetoothctl fallback active" : "";
    const diagnostics = event.data.diagnostics || "";
    rows.bleScanDetail = [method, fallback, diagnostics].filter(Boolean).join(" | ");
    setCollectorBanner("ble", "ONLINE", eventStatusDetail("ble", event.data.adapter, rows.bleScanDetail));
  }
  if (event.type === "scan_empty") {
    rows.bleDiagnostic = bleEmptyScanDetail(event.data || {});
    rows.bleScanDetail = [
      event.data.scan_method ? `method=${event.data.scan_method}` : "",
      event.data.fallback_active ? "bluetoothctl fallback active" : ""
    ].filter(Boolean).join(" | ");
    setCollectorBanner("ble", "collector_retrying", rows.bleDiagnostic);
    scheduleLiveRender("ble", renderBleTable);
  }
  if (!["device_seen", "device_updated"].includes(event.type)) return;
  const data = event.data;
  const key = data.mac;
  const current = rows.ble.get(key) || {};
  const merged = {
    ...current,
    ...data,
    name: data.name || current.name || "",
    rssi: data.rssi !== undefined && data.rssi !== null ? data.rssi : current.rssi,
    manufacturer: data.manufacturer || current.manufacturer || null,
    service_uuids: Array.isArray(data.service_uuids) && data.service_uuids.length ? data.service_uuids : (current.service_uuids || []),
    findmy_accessory: data.findmy_accessory !== undefined ? data.findmy_accessory : current.findmy_accessory,
    findmy_status: data.findmy_status || current.findmy_status || "",
    findmy_hint: data.findmy_hint || current.findmy_hint || "",
    findmy_label: data.findmy_label || current.findmy_label || "",
    last_seen: event.timestamp,
    last_seen_epoch: event.timestamp_epoch
  };
  rows.ble.set(key, merged);
  pruneLiveScanRows();
  scheduleLiveRender("ble", renderBleTable);
  maybeRefreshEmptyDerivedViews("Bluetooth scan");
}

function bleEmptyScanDetail(data) {
  const parts = [
    data.adapter ? `adapter ${data.adapter}` : "adapter unknown",
    data.scan_method ? `method=${data.scan_method}` : "",
    data.fallback_active ? "bluetoothctl fallback active" : "",
    `${data.empty_scan_windows || 0} empty scan window(s)`,
    data.bluez_warmup ? `BlueZ warmup ${data.bluez_warmup}` : "BlueZ warmup unknown"
  ];
  if (data.bluez_warmup_returncode !== undefined) {
    parts.push(`rc ${data.bluez_warmup_returncode}`);
  }
  if (data.bluez_cached_devices !== undefined) {
    parts.push(`BlueZ cache ${data.bluez_cached_devices} device(s)`);
  }
  if (data.bluez_warmup_error) parts.push(data.bluez_warmup_error);
  if (data.diagnostics) parts.push(data.diagnostics);
  return parts.filter(Boolean).join("; ");
}

function renderBleTable() {
  updateTabCounts();
  const tbody = document.getElementById("ble-devices");
  if (!tbody) return;
  tbody.innerHTML = "";
  const devices = [...rows.ble.values()]
    .filter(bleDeviceIsRecent)
    .filter(bleDeviceMatchesSearch)
    .sort(compareBleIdentifyDevices)
    .slice(0, uiNumber("max_live_rows"));
  if (!devices.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 6;
    td.textContent = rows.bleDiagnostic
      ? `No recently seen BLE devices; ${rows.bleDiagnostic}`
      : "No recently seen BLE devices";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  devices.forEach((item) => {
    const tr = document.createElement("tr");
    [
      ["ble-col-mac", detailLink(item.mac || "", "bluetooth-device", item.mac || "")],
      ["ble-col-identity", bleDeviceIdentity(item)],
      ["ble-col-rssi", formatSignal(item.rssi)],
      ["ble-col-services", bluetoothServiceList(item.service_uuids)],
      ["ble-col-last-seen", item.last_seen || ""]
    ].forEach(([className, value]) => {
      const td = document.createElement("td");
      td.className = className;
      appendTableCellValue(td, value || "");
      tr.appendChild(td);
    });
    const actionCell = document.createElement("td");
    actionCell.className = "ble-col-action";
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Identify";
    button.addEventListener("click", () => identifyBleMac(item.mac || ""));
    actionCell.appendChild(button);
    tr.appendChild(actionCell);
    tbody.appendChild(tr);
  });
}

function bleDeviceIsRecent(item) {
  const maxAgeSec = uiNumber("bluetooth_live_recent_sec");
  const timestampMs = recordTimestampMs(item, "last_seen");
  if (!timestampMs) return false;
  return Date.now() - timestampMs <= maxAgeSec * 1000;
}

function bleDeviceMatchesSearch(item) {
  return rowMatchesSearch([
    item.mac,
    bleDeviceIdentity(item),
    formatSignal(item.rssi),
    bluetoothServiceList(item.service_uuids),
    item.last_seen
  ], bleSearch);
}

function valueList(value) {
  if (Array.isArray(value)) return value.filter((item) => item !== "" && item !== null && item !== undefined);
  if (value === "" || value === null || value === undefined) return [];
  return [value];
}

function bluetoothServiceList(uuids) {
  return valueList(uuids).map(bluetoothServiceLabel).join(", ");
}

function bluetoothServiceLabel(uuid) {
  const shortId = bluetoothAssignedNumber(uuid);
  if (!shortId) return customBluetoothUuidLabel(uuid);
  if (bluetoothMemberUuid(shortId)) {
    const label = `Member UUID ${shortId.toUpperCase()}`;
    const name = bluetoothUuidNames[shortId.toLowerCase()];
    return name ? `${label}: ${name}` : label;
  }
  const name = bluetoothUuidNames[shortId.toLowerCase()] ||
    BLUETOOTH_SERVICE_NAMES[shortId.toLowerCase()];
  if (name) return `${name} (${shortId.toUpperCase()})`;
  return shortId.length === 4 ? `Unknown UUID (${shortId.toUpperCase()})` : String(uuid || "");
}

function bluetoothAssignedNumber(uuid) {
  const text = String(uuid || "").trim().toLowerCase();
  if (!text) return "";
  const compact = text.replace(/[^0-9a-f]/g, "");
  if (/^[0-9a-f]{4}$/.test(compact)) {
    return compact;
  }
  if (/^0000[0-9a-f]{4}$/.test(compact)) {
    return compact.slice(4);
  }
  const compactBase = compact.match(
    /^0000([0-9a-f]{4})00001000800000805f9b34fb$/
  );
  if (compactBase) return compactBase[1];
  const match = text.match(/^0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb$/);
  return match ? match[1] : "";
}

function customBluetoothUuidLabel(uuid) {
  const text = String(uuid || "").trim();
  if (!text) return "";
  const compact = text.replace(/[^0-9a-fA-F]/g, "");
  if (compact.length > 8) return `Vendor UUID ${compact.slice(0, 8)}...`;
  return text;
}

function renderBtClassicEvent(event) {
  document.getElementById("bt_classic-status").textContent = event.type;
  const data = event.data || {};
  if (event.type === "scanner_started") {
    setCollectorBanner("bt_classic", "ONLINE", eventStatusDetail("bt_classic", data.adapter, ""));
  }
  if (event.type === "classic_scan_started") {
    setBtClassicScanState(`Scanning on ${data.adapter || "adapter"}...`, "warning");
  }
  if (event.type === "classic_scan_completed") {
    const count = Number(data.devices || 0);
    const label = count === 1 ? "1 device" : `${count} devices`;
    setBtClassicScanState(`Last scan completed at ${event.timestamp}: ${label} found in ${data.duration_sec || "?"}s`, count ? "ok" : "muted");
  }
  if (event.type === "collector_offline" || event.type === "collector_retrying") {
    setCollectorBanner("bt_classic", event.type, eventStatusDetail("bt_classic", data.adapter, data.reason || data.warning || ""));
  }
  if (event.type === "classic_device_seen" || event.type === "classic_device_updated") {
    const key = data.mac;
    const current = rows.btClassic.get(key) || {};
    rows.btClassic.set(key, {
      ...current,
      ...data,
      last_seen: event.timestamp,
      last_seen_epoch: event.timestamp_epoch
    });
    scheduleLiveRender("btClassic", renderBtClassicTable);
    maybeRefreshEmptyDerivedViews("Bluetooth classic scan");
  }
  if (event.type === "classic_device_lost") {
    const current = rows.btClassic.get(data.mac) || data;
    rows.btClassic.set(data.mac, {
      ...current,
      last_seen: event.timestamp,
      last_seen_epoch: event.timestamp_epoch,
      state: "lost"
    });
    scheduleLiveRender("btClassic", renderBtClassicTable);
    maybeRefreshEmptyDerivedViews("Bluetooth classic scan");
  }
}

function renderBtClassicTable() {
  renderSchemaTable("bt-classic-devices", [...rows.btClassic.values()], "btClassicDevices");
  updateTabCounts();
}

function setBtClassicScanState(text, state) {
  const node = document.getElementById("bt-classic-scan-state");
  if (!node) return;
  node.textContent = text;
  node.className = `status-strip ${state || "muted"}`;
}

function identifyBleMac(mac, timeout) {
  if (!mac) {
    setTransientCollectorBanner("ble_identify", "identify_failed", "Missing BLE MAC address");
    return;
  }
  const normalizedTimeout = Number(timeout);
  setTransientCollectorBanner("ble_identify", "IDENTIFYING", `Identifying ${mac}`, 5000);
  fetch("/ble_identify", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      mac,
      timeout_sec: Number.isFinite(normalizedTimeout) ? normalizedTimeout : undefined
    })
  }).then((response) => {
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  }).catch((error) => {
    setTransientCollectorBanner("ble_identify", "identify_failed", `Identify request failed: ${error}`);
  });
}

function renderBleIdentifyEvent(event) {
  const data = event.data || {};
  if (event.type === "identify_started") {
    setTransientCollectorBanner("ble_identify", "IDENTIFYING", `${data.mac} via ${data.adapter || "adapter"}`, 5000);
  } else if (event.type === "identify_result") {
    setTransientCollectorBanner("ble_identify", "IDLE", `${data.mac}: ${data.manufacturer_name || data.model_number || "identified"}`);
    rows.bleIdentify.unshift({
      ...data,
      event_type: event.type,
      timestamp: event.timestamp,
      timestamp_epoch: event.timestamp_epoch
    });
    rows.bleIdentify = rows.bleIdentify.slice(0, uiNumber("max_live_rows"));
    mergeBleIdentifyResult(data, event.timestamp, event.timestamp_epoch);
    renderBleIdentifyTable();
    scheduleLiveRender("ble", renderBleTable);
  } else if (event.type === "identify_failed" || event.type === "collector_offline") {
    setTransientCollectorBanner("ble_identify", event.type, data.reason || "Identify failed");
    rows.bleIdentify.unshift({
      ...data,
      event_type: event.type,
      timestamp: event.timestamp,
      timestamp_epoch: event.timestamp_epoch
    });
    rows.bleIdentify = rows.bleIdentify.slice(0, uiNumber("max_live_rows"));
    renderBleIdentifyTable();
  }
}

function renderBleIdentifyTable() {
  renderSchemaTable("ble-identify-results", rows.bleIdentify, "bleIdentifyResults", {preserveOrder: true});
  updateTabCounts();
}

function mergeBleIdentifyResult(data, timestamp, timestampEpoch) {
  if (!data || !data.mac) return;
  const current = rows.ble.get(data.mac) || {};
  rows.ble.set(data.mac, {
    ...current,
    ...data,
    last_seen: current.last_seen || timestamp,
    last_seen_epoch: current.last_seen_epoch || timestampEpoch
  });
}

function compareBleIdentifyDevices(left, right) {
  const leftMs = recordTimestampMs(left, "last_seen");
  const rightMs = recordTimestampMs(right, "last_seen");
  if (leftMs && rightMs && leftMs !== rightMs) return rightMs - leftMs;
  if (leftMs && !rightMs) return -1;
  if (!leftMs && rightMs) return 1;
  return (left.mac || "").localeCompare(right.mac || "");
}

function bluetoothMemberUuid(shortId) {
  return String(shortId || "").toLowerCase().startsWith("fe");
}

function bleDeviceIdentity(item) {
  const device = item || {};
  const direct = bluetoothDisplayName(device.name, device.mac);
  const parts = [];
  if (direct) parts.push(direct);
  bluetoothDisplayNames(device.names, device.mac)
    .filter((name) => name !== direct)
    .forEach((name) => parts.push(name));
  const manufacturer = bluetoothManufacturerIdentity(device);
  if (manufacturer) parts.push(`Mfr: ${manufacturer}`);
  if (device.findmy_accessory) parts.push(device.findmy_label || "Apple Find My accessory");
  return parts.join(" | ");
}

function bluetoothDisplayNames(names, mac) {
  if (!Array.isArray(names)) return [];
  const seen = new Set();
  return names
    .map((name) => bluetoothDisplayName(name, mac))
    .filter(Boolean)
    .filter((name) => {
      const key = name.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

function bluetoothManufacturerIdentity(item) {
  const value = (item || {}).manufacturer_name ||
    (item || {}).manufacturer ||
    (item || {}).vendor_name ||
    "";
  return String(value).trim();
}

function bluetoothDisplayName(name, mac) {
  const value = String(name || "").trim();
  if (
    !value ||
    bluetoothNameLooksLikeAddress(value, mac) ||
    bluetoothNameLooksLikeCommandError(value) ||
    bluetoothNameLooksLikeProperty(value)
  ) return "";
  return value;
}

function bluetoothNameLooksLikeAddress(name, mac) {
  const value = String(name || "").trim();
  if (!value) return false;
  if (/^[0-9a-f]{2}([:\-][0-9a-f]{2}){5}$/i.test(value)) return true;
  if (/^[0-9a-f]{12}$/i.test(value)) return true;
  const compactName = value.replace(/[^0-9a-f]/gi, "").toLowerCase();
  const compactMac = String(mac || "").replace(/[^0-9a-f]/gi, "").toLowerCase();
  return Boolean(compactMac && compactName === compactMac);
}

function bluetoothNameLooksLikeCommandError(name) {
  return /^command:?\s+/i.test(String(name || "").trim());
}

function bluetoothNameLooksLikeProperty(name) {
  const value = String(name || "").trim();
  if (!value) return false;
  return /^(rssi|uuids?|tx\s*power|txpower|manufacturer(?:\s+data)?|service(?:\s+data)?|appearance|class|icon|alias|name|legacy\s*pairing|paired|bonded|trusted|blocked|connected)\s*:/i.test(value);
}

function renderWifiEvent(event) {
  document.getElementById("wifi-status").textContent = event.type;
  if (event.type === "interface_mode") {
    const mode = "managed scan";
    const detail = eventStatusDetail("wifi", event.data.interface, event.data.warning || "");
    setCollectorBanner("wifi", "ONLINE", `${detail} | ${mode}`);
  }
  if (event.type === "collector_retrying" || event.type === "collector_offline") {
    setCollectorBanner("wifi", event.type, eventStatusDetail("wifi", event.data.interface, event.data.reason || ""));
  }
  if (event.type === "scan_started") {
    setCollectorBanner("wifi", "ONLINE", `${eventStatusDetail("wifi", event.data.interface, "")} | ${event.data.note}`);
  }
  if (event.type === "scan_empty") {
    setCollectorBanner("wifi", "collector_retrying", `${event.data.interface}: no SSIDs found; ${event.data.diagnostics || ""}`);
  }
  if (event.type === "ap_beacon") {
    rows.aps.set(event.data.bssid, {
      ...event.data,
      last_seen: event.timestamp,
      last_seen_epoch: event.timestamp_epoch
    });
    scheduleLiveRender("wifi", renderWifiTables);
    maybeRefreshEmptyDerivedViews("Wi-Fi scan");
  }
}

function renderWifiMonitorEvent(event) {
  document.getElementById("wifi_monitor-status").textContent = event.type;
  if (event.type === "monitor_started") {
    const data = event.data || {};
    const mode = data.channel_mode === "fixed"
      ? `fixed channel ${data.fixed_channel || formatChannelList(data.channels)}`
      : `hop ${formatChannelList(data.channels)}`;
    const seen = data.seen_channels_first ? "seen first" : "common first";
    const fallback = data.common_channel_fallback ? "fallback common" : "no common fallback";
    setCollectorBanner("wifi_monitor", "ONLINE", `${data.interface} available, active: ${data.interface} | ${mode} | dwell ${data.dwell_sec}s`);
    setWifiMonitorPlan(`Bands ${formatChannelList(data.supported_bands)} | ${mode} | ${seen} | ${fallback}`, "ok");
  }
  if (event.type === "monitor_channel_changed") {
    const data = event.data || {};
    const mode = data.mode === "fixed" ? "fixed" : "hopping";
    setWifiMonitorPlan(`${data.interface} ${mode} on channel ${data.channel} (${data.band} GHz)`, "ok");
  }
  if (event.type === "collector_retrying" || event.type === "collector_offline") {
    setCollectorBanner("wifi_monitor", event.type, (event.data || {}).reason || "");
    setWifiMonitorPlan((event.data || {}).reason || event.type, "alert");
  }
  if (event.type === "ap_beacon") {
    renderWifiEvent({...event, collector: "wifi"});
  }
  if (["probe_request", "ap_beacon", "association_seen", "deauth_seen", "disassoc_seen"].includes(event.type)) {
    rows.monitorEvents.unshift({
      ...event.data,
      event_type: event.type,
      last_seen: event.timestamp,
      last_seen_epoch: event.timestamp_epoch
    });
    rows.monitorEvents = rows.monitorEvents.slice(0, uiNumber("max_live_rows"));
    scheduleLiveRender("wifiMonitor", renderWifiMonitorTable);
  }
}

function renderWifiMonitorTable() {
  const events = rows.monitorEvents.filter(wifiMonitorEventMatchesSearch);
  renderSchemaTable("wifi-monitor-events", events, "wifiMonitorEvents");
  updateTabCounts();
}

function wifiMonitorEventMatchesSearch(item) {
  return rowMatchesSearch(schemaCells("wifiMonitorEvents", item), wifiMonitorSearch);
}

function renderAprsisEvent(event) {
  const status = document.getElementById("aprsis-status");
  if (status) status.textContent = event.type;
  const data = event.data || {};
  if (event.type === "collector_online") {
    setCollectorBanner("aprsis", "ONLINE", aprsisStatusDetail(data));
    return;
  }
  if (event.type === "collector_status") {
    setCollectorBanner("aprsis", data.feed_state || "ONLINE", aprsisStatusDetail(data));
    return;
  }
  if (event.type === "collector_offline" || event.type === "collector_retrying") {
    setCollectorBanner("aprsis", event.type, aprsisStatusDetail(data));
    return;
  }
  if (event.type === "server_status") {
    setCollectorBanner("aprsis", "ONLINE", aprsisStatusDetail(data));
    rows.aprsis.unshift({
      ...data,
      event_type: event.type,
      packet_type: "server",
      comment: data.last_server_message || data.reason || "",
      last_seen: event.timestamp,
      last_seen_epoch: event.timestamp_epoch
    });
    rows.aprsis = rows.aprsis.slice(0, uiNumber("max_live_rows"));
    scheduleLiveRender("aprsis", renderAprsisTable);
    return;
  }
  if (!String(event.type || "").startsWith("aprs_")) return;
  rows.aprsis.unshift({
    ...data,
    event_type: event.type,
    packet_type: data.packet_type || event.type.replace(/^aprs_/, ""),
    last_seen: event.timestamp,
    last_seen_epoch: event.timestamp_epoch
  });
  rows.aprsis = rows.aprsis.slice(0, uiNumber("max_live_rows"));
  scheduleLiveRender("aprsis", renderAprsisTable);
}

function renderAprsisTable() {
  const events = rows.aprsis.filter(aprsisEventMatchesSearch);
  renderSchemaTable("aprsis-events", events, "aprsisEvents", {preserveOrder: true});
  updateTabCounts();
}

function aprsisEventMatchesSearch(item) {
  return rowMatchesSearch([
    item.last_seen || "",
    item.packet_type || item.event_type || "",
    item.callsign || "",
    item.destination || "",
    item.object_name || "",
    item.addressee || "",
    item.via_path || "",
    item.q_construct || "",
    item.igate || "",
    item.feed_name || "",
    item.feed_role || "",
    item.mic_e_message || "",
    item.weather_summary || "",
    item.symbol || "",
    item.message || "",
    item.comment || "",
    item.payload || "",
    formatAprsisPosition(item),
    formatAprsisMotion(item)
  ], aprsisSearch);
}

function aprsisStatusDetail(data) {
  const includeState = arguments.length > 1 && arguments[1] && arguments[1].includeState;
  const parts = [];
  const feedName = String(data.feed_name || "").trim();
  const feedRole = aprsisDistinctFeedRole(feedName, data.feed_role);
  const state = displayState(data.feed_state || data.collector_state || "");
  if (includeState && state && feedName) {
    parts.push(`${state}: feed ${feedName}`);
  } else {
    if (includeState && state) parts.push(`${state}:`);
    if (feedName) parts.push(`feed ${feedName}`);
  }
  if (feedRole) parts.push(feedRole);
  if (data.host || data.port) {
    parts.push(`${data.host || "feed"}:${data.port || ""}`);
  }
  if (data.server_name) {
    parts.push(`server ${data.server_name}`);
  } else if (data.server_address) {
    parts.push(`server ${data.server_address}`);
  }
  if ((data.preferred_servers || []).length) {
    parts.push(`preferred ${compactList(data.preferred_servers, 3)}`);
  }
  if (data.preferred_server_fallback) {
    const miss = data.preferred_server_last_miss || data.server_name || "current server";
    parts.push(`preferred fallback ${miss}`);
  } else if (data.preferred_server_attempts) {
    const limit = data.preferred_server_max_attempts
      ? `/${data.preferred_server_max_attempts}`
      : "";
    parts.push(`preferred retry ${data.preferred_server_attempts}${limit}`);
  }
  if (data.filter) parts.push(`filter ${data.filter}`);
  if (Array.isArray(data.include_callsigns) && data.include_callsigns.length) {
    parts.push(`includes ${data.include_callsigns.join(", ")}`);
  }
  const reason = aprsisStatusReason(data);
  if (reason) parts.push(`reason ${reason}`);
  if (data.last_packet_callsign) {
    const age = data.idle_sec !== undefined ? formatSeconds(data.idle_sec) : "";
    parts.push(`last packet ${data.last_packet_callsign}${age ? ` ${age} ago` : ""}`);
  }
  return parts.filter(Boolean).join(" | ");
}

function aprsisStatusReason(data) {
  const state = String(data.feed_state || data.collector_state || "").toUpperCase();
  if (state === "ONLINE") return "";
  const reason = String(data.reason || data.last_disconnect_reason || "").trim();
  if (!reason) return "";
  const lowered = reason.toLowerCase();
  if (lowered.includes("aprs-is feed(s) offline")) return "";
  if (lowered.startsWith("#")) return "";
  return reason.length > 140 ? `${reason.slice(0, 137)}...` : reason;
}

function formatSeconds(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds < 0) return "";
  if (seconds < 90) return `${Math.round(seconds)}s`;
  const minutes = seconds / 60;
  if (minutes < 90) return `${Math.round(minutes)}m`;
  return `${Math.round(minutes / 60)}h`;
}

function formatAprsisPosition(item) {
  return formatLatLon(item.latitude, item.longitude);
}

function formatAprsisTarget(item) {
  return [
    item.object_name ? `object ${item.object_name}` : "",
    item.addressee ? `to ${item.addressee}` : "",
    item.destination ? `dst ${item.destination}` : ""
  ].filter(Boolean).join("; ");
}

function aprsisSubjectLink(item) {
  const callsign = String((item || {}).callsign || "").trim();
  if (!callsign) return "";
  return detailLink(callsign, "aprsis-subject", callsign);
}

function formatAprsisRoute(item) {
  return [
    item.via_path ? `via ${item.via_path}` : "",
    item.q_construct || "",
    item.igate ? `igate ${item.igate}` : ""
  ].filter(Boolean).join("; ");
}

function formatAprsisText(item) {
  return [
    item.mic_e_message || "",
    item.message || item.comment || "",
    item.aprs_format ? `format ${item.aprs_format}` : ""
  ].filter(Boolean).join("; ") || item.payload || "";
}

function normalizeAprsWeatherSummary(value) {
  return String(value || "").replace(
    /\brain 1h ([0-9]+(?:\.[0-9]+)?) in\b/g,
    "1h rain rate $1 in/hr"
  );
}

function formatAprsisMotion(item) {
  if (item.weather_summary) return normalizeAprsWeatherSummary(item.weather_summary);
  const speedKmh = Number(item.speed_kmh);
  const speedKnots = Number(item.speed_knots);
  const course = Number(item.course_deg);
  const parts = [];
  if (Number.isFinite(speedKmh)) {
    parts.push(`${speedKmh.toFixed(1)} km/h`);
  } else if (Number.isFinite(speedKnots)) {
    parts.push(`${speedKnots.toFixed(0)} kt`);
  }
  if (Number.isFinite(course)) parts.push(`${course.toFixed(0)} deg`);
  if (item.symbol) parts.push(`symbol ${item.symbol}`);
  return parts.join("; ");
}

function renderNoaaEvent(event) {
  const status = document.getElementById("noaa-status");
  if (status) status.textContent = event.type;
  const data = event.data || {};
  if (event.type === "collector_online") {
    setCollectorBanner("noaa", "ONLINE", noaaStatusDetail(data));
    return;
  }
  if (event.type === "collector_offline" || event.type === "collector_retrying") {
    setCollectorBanner("noaa", event.type, data.reason || "");
    return;
  }
  if (![
    "noaa_weather_alert",
    "noaa_tropical_advisory",
    "noaa_forecast_summary",
    "noaa_tsunami_alert"
  ].includes(event.type)) return;
  const row = {
    ...data,
    event_type: event.type,
    last_seen: event.timestamp,
    last_seen_epoch: event.timestamp_epoch
  };
  upsertNoaaEventRow(row);
  prunePollFeedRows();
  scheduleLiveRender("noaa", renderNoaaTable);
  maybeRefreshMissingSubject("NOAA feed", () => findNoaaHistorySubject(noaaLiveEventKey(row)));
  maybeRefreshEmptyDerivedViews("NOAA feed");
}

function upsertNoaaEventRow(row) {
  const key = noaaLiveEventKey(row);
  if (key) {
    for (let index = rows.noaa.length - 1; index >= 0; index -= 1) {
      if (noaaLiveEventKey(rows.noaa[index]) === key) rows.noaa.splice(index, 1);
    }
  }
  rows.noaa.unshift(row);
}

function noaaLiveEventKey(item) {
  if (!item) return "";
  return noaaSubjectKey(item);
}

function renderNoaaTable() {
  const events = rows.noaa
    .filter(noaaEventMatchesSearch)
    .sort(compareNoaaEvents);
  renderSchemaTable("noaa-events", events, "noaaEvents", {preserveOrder: true});
  updateTabCounts();
}

function compareNoaaEvents(left, right) {
  return noaaEventSortMs(right) - noaaEventSortMs(left);
}

function noaaEventSortMs(item) {
  return firstRecordTimestampMs(
    item,
    ["event_time", "forecast_generated", "updated", "onset", "effective", "first_period_start", "last_seen"]
  ) || 0;
}

function noaaEventMatchesSearch(item) {
  return rowMatchesSearch([
    item.last_seen,
    item.event_type,
    item.alert_kind,
    noaaEventTimeText(item),
    item.event || item.headline || item.event_id,
    item.severity,
    item.urgency,
    item.certainty,
    item.status,
    item.area_desc,
    item.nhc_system,
    item.nhc_storm_id,
    item.nhc_advisory_number,
    compactList(item.nhc_product_types || [], 8),
    compactList(item.nhc_product_titles || [], 8),
    item.incident_id,
    item.tsunami_identifier,
    item.tsunami_category,
    item.message_number,
    item.magnitude,
    item.depth_km,
    item.product_code,
    noaaForecastText(item),
    noaaTimingText(item),
    item.source
  ], noaaSearch);
}

function noaaStatusDetail(data) {
  const feeds = Array.isArray(data.feeds) ? data.feeds.join(", ") : "";
  return [
    data.source || "NOAA",
    feeds ? `feeds ${feeds}` : "",
    data.warning || "",
    data.internet_fed ? "internet-fed" : ""
  ].filter(Boolean).join(" | ");
}

function noaaSeverityText(item) {
  return [
    item.severity || "",
    item.urgency ? `urgency ${item.urgency}` : "",
    item.certainty ? `certainty ${item.certainty}` : ""
  ].filter(Boolean).join("; ");
}

function noaaSubjectLink(item) {
  const key = noaaSubjectKey(item);
  const label = (item || {}).event || (item || {}).headline || key;
  return key ? detailLink(label, "noaa-subject", key) : label;
}

function noaaSubjectKey(item) {
  const eventType = String((item || {}).event_type || "").trim();
  const source = String((item || {}).source || "").trim();
  const alertKind = String((item || {}).alert_kind || "").trim();
  if (eventType === "noaa_tsunami_alert" || alertKind === "tsunami" || ["NTWC", "PTWC"].includes(source.toUpperCase())) {
    const eventId = String((item || {}).event_id || "").trim();
    if (eventId.toLowerCase().startsWith("tsunami:")) return noaaKeyFragment(eventId);
    const feedSource = noaaKeyFragment(source || "tsunami");
    const incident = noaaKeyFragment(
      (item || {}).incident_id ||
      (item || {}).tsunami_identifier ||
      (item || {}).source_event_id ||
      eventId ||
      (item || {}).source_url ||
      (item || {}).headline ||
      "tsunami"
    );
    return `tsunami:${feedSource}:${incident}`;
  }
  if (eventType === "noaa_tropical_advisory" || source === "NHC") {
    const basin = noaaKeyFragment((item || {}).basin || (item || {}).area_desc || "global");
    const packageKey = noaaKeyFragment((item || {}).nhc_package_key || "");
    if (packageKey) return `nhc:${basin}:${packageKey}`;
    const event = noaaKeyFragment(
      (item || {}).event ||
      (item || {}).headline ||
      (item || {}).summary ||
      "nhc"
    );
    return `nhc:${basin}:${event}`;
  }
  const feedSource = noaaKeyFragment(source || "NOAA");
  const area = noaaKeyFragment((item || {}).area_desc || "global");
  const event = noaaKeyFragment(
    (item || {}).event ||
    (item || {}).headline ||
    (item || {}).event_id ||
    "noaa"
  );
  return `${feedSource}:${area}:${event}`;
}

function noaaKeyFragment(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.:-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function noaaProductsText(item) {
  const count = Number((item || {}).nhc_product_count || 0);
  const types = compactList((item || {}).nhc_product_types || [], 8);
  if (count && types) return `${count} product(s): ${types}`;
  return types;
}

function noaaProductLinksNode(item) {
  const products = Array.isArray((item || {}).nhc_products)
    ? (item || {}).nhc_products
    : [];
  const urls = Array.isArray((item || {}).nhc_product_urls)
    ? (item || {}).nhc_product_urls
    : [];
  const entries = products.length
    ? products.map((product) => ({
        label: product.product_type || product.title || product.source_url || "Product",
        url: product.source_url || ""
      }))
    : urls.map((url, index) => ({label: `Product ${index + 1}`, url}));
  const filtered = entries.filter((entry) => /^https?:\/\//i.test(String(entry.url || "")));
  if (!filtered.length) return "";
  const span = document.createElement("span");
  const labels = [];
  filtered.forEach((entry, index) => {
    if (index) span.appendChild(document.createTextNode("; "));
    const link = externalLink(entry.label, entry.url);
    if (link && link.node instanceof Node) span.appendChild(link.node);
    else span.appendChild(document.createTextNode(String(entry.label || entry.url || "")));
    labels.push(`${entry.label} ${entry.url}`.trim());
  });
  return {node: span, text: labels.join("; ")};
}

function noaaTimingText(item) {
  const isForecast = (item || {}).alert_kind === "forecast";
  return [
    (item || {}).alert_kind === "tsunami" ? noaaTsunamiText(item) : "",
    !isForecast && item.effective ? `effective ${displayTimestamp(item, "effective")}` : "",
    item.onset ? `onset ${displayTimestamp(item, "onset")}` : "",
    item.first_period_start ? `from ${displayTimestamp(item, "first_period_start")}` : "",
    item.next_precip_start ? `next precip ${displayTimestamp(item, "next_precip_start")}` : "",
    !isForecast && item.expires ? `expires ${displayTimestamp(item, "expires")}` : "",
    item.last_period_end ? `through ${displayTimestamp(item, "last_period_end")}` : "",
    item.updated ? `updated ${displayTimestamp(item, "updated")}` : ""
  ].filter(Boolean).join("; ");
}

function noaaForecastText(item) {
  const parts = [];
  if (item.current_forecast) parts.push(item.current_forecast);
  const tempMin = numericEvidence(item.temperature_min_f);
  const tempMax = numericEvidence(item.temperature_max_f);
  if (tempMin !== null && tempMax !== null) {
    parts.push(`temp ${tempMin.toFixed(0)}-${tempMax.toFixed(0)} F`);
  }
  const nextPop = numericEvidence(item.next_precip_probability);
  if (nextPop !== null) {
    parts.push(`next precip ${nextPop.toFixed(0)}%`);
  } else {
    const maxPop = numericEvidence(item.max_precip_probability);
    if (maxPop !== null) parts.push(`max precip ${maxPop.toFixed(0)}%`);
  }
  const wind = numericEvidence(item.max_wind_mph);
  if (wind !== null) parts.push(`wind ${wind.toFixed(0)} mph`);
  return parts.join("; ");
}

function noaaTsunamiText(item) {
  const parts = [];
  if (item.message_number) parts.push(`message ${item.message_number}`);
  const magnitude = numericEvidence(item.magnitude);
  if (magnitude !== null) {
    parts.push(`M${magnitude.toFixed(1)}${item.magnitude_type ? ` ${item.magnitude_type}` : ""}`);
  }
  const depth = numericEvidence(item.depth_km);
  if (depth !== null) parts.push(`depth ${depth.toFixed(1)} km`);
  if (item.tsunami_category) parts.push(item.tsunami_category);
  return parts.join("; ");
}

function noaaEventTimeText(item) {
  return displayFirstTimestamp(
    item,
    ["event_time", "forecast_generated", "updated", "onset", "effective", "first_period_start"]
  );
}

function renderUsgsEvent(event) {
  const status = document.getElementById("usgs-status");
  if (status) status.textContent = event.type;
  const data = event.data || {};
  if (event.type === "collector_online") {
    setCollectorBanner("usgs", "ONLINE", usgsStatusDetail(data));
    return;
  }
  if (event.type === "collector_offline" || event.type === "collector_retrying") {
    setCollectorBanner("usgs", event.type, data.reason || "");
    return;
  }
  if (event.type !== "usgs_earthquake") return;
  upsertUsgsEventRow({
    ...data,
    event_type: event.type,
    last_seen: event.timestamp,
    last_seen_epoch: event.timestamp_epoch
  });
  prunePollFeedRows();
  scheduleLiveRender("usgs", renderUsgsTable);
  maybeRefreshEmptyDerivedViews("USGS feed");
}

function upsertUsgsEventRow(row) {
  const key = usgsLiveEventKey(row);
  if (key) {
    for (let index = rows.usgs.length - 1; index >= 0; index -= 1) {
      if (usgsLiveEventKey(rows.usgs[index]) === key) rows.usgs.splice(index, 1);
    }
  }
  rows.usgs.unshift(row);
}

function usgsLiveEventKey(item) {
  return String((item || {}).event_id || "").trim();
}

function renderUsgsTable() {
  const events = rows.usgs
    .filter(usgsEventMatchesSearch)
    .sort(compareUsgsEvents);
  renderSchemaTable("usgs-events", events, "usgsEvents", {preserveOrder: true});
  updateTabCounts();
}

function compareUsgsEvents(left, right) {
  return usgsEventSortMs(right) - usgsEventSortMs(left);
}

function usgsEventSortMs(item) {
  return firstRecordTimestampMs(item, ["event_time", "updated", "last_seen"]) || 0;
}

function usgsEventMatchesSearch(item) {
  return rowMatchesSearch([
    item.event_id,
    item.magnitude,
    item.place,
    item.feed,
    item.scope,
    item.feed_label,
    item.distance_km,
    item.depth_km,
    item.alert_color,
    item.status,
    item.event_time,
    item.updated
  ], usgsSearch);
}

function usgsStatusDetail(data) {
  return [
    data.source || "USGS",
    data.feed_summary || data.url || "",
    data.internet_fed ? "internet-fed" : ""
  ].filter(Boolean).join(" | ");
}

function usgsSubjectLink(item) {
  const key = String((item || {}).event_id || "").trim();
  const label = usgsMagnitudeText(item) || key;
  return key ? detailLink(label, "usgs-subject", key) : label;
}

function usgsMagnitudeText(item) {
  const value = Number((item || {}).magnitude);
  return Number.isFinite(value) ? `M${value.toFixed(1)}` : "";
}

function usgsScopeText(item) {
  if ((item || {}).global_major) return "global major";
  const label = String((item || {}).feed_label || "").trim();
  if (label) return label;
  const scope = String((item || {}).scope || "").trim();
  if (scope) return scope;
  return String((item || {}).feed || "").trim();
}

function usgsDistanceText(item) {
  const value = Number((item || {}).distance_km);
  return Number.isFinite(value) ? `${value.toFixed(1)} km` : "";
}

function usgsAlertText(item) {
  return [
    item.alert_color ? `alert ${item.alert_color}` : "",
    Number(item.tsunami || 0) ? "tsunami" : ""
  ].filter(Boolean).join("; ");
}

function renderSwpcEvent(event) {
  const status = document.getElementById("swpc-status");
  if (status) status.textContent = event.type;
  const data = event.data || {};
  if (event.type === "collector_online") {
    setCollectorBanner("swpc", "ONLINE", swpcStatusDetail(data));
    return;
  }
  if (event.type === "collector_offline" || event.type === "collector_retrying") {
    setCollectorBanner("swpc", event.type, data.reason || "");
    return;
  }
  if (event.type !== "swpc_event") return;
  upsertSwpcEventRow({
    ...data,
    event_type: event.type,
    last_seen: event.timestamp,
    last_seen_epoch: event.timestamp_epoch
  });
  prunePollFeedRows();
  scheduleLiveRender("swpc", renderSwpcTable);
  maybeRefreshEmptyDerivedViews("SWPC feed");
}

function upsertSwpcEventRow(row) {
  const key = swpcLiveEventKey(row);
  if (key) {
    for (let index = rows.swpc.length - 1; index >= 0; index -= 1) {
      if (swpcLiveEventKey(rows.swpc[index]) === key) rows.swpc.splice(index, 1);
    }
  }
  rows.swpc.unshift(row);
}

function swpcLiveEventKey(item) {
  return String((item || {}).event_id || (item || {}).summary || "").trim();
}

function renderSwpcTable() {
  const events = rows.swpc
    .filter(swpcEventMatchesSearch)
    .sort(compareSwpcEvents);
  renderSchemaTable("swpc-events", events, "swpcEvents", {preserveOrder: true});
  updateTabCounts();
}

function compareSwpcEvents(left, right) {
  return swpcEventSortMs(right) - swpcEventSortMs(left);
}

function swpcEventSortMs(item) {
  return recordTimestampMs(item, "event_time") ||
    recordTimestampMs(item, "peak_time") ||
    recordTimestampMs(item, "issue_time") ||
    recordTimestampMs(item, "issue") ||
    recordTimestampMs(item, "last_seen") ||
    0;
}

function swpcEventMatchesSearch(item) {
  return rowMatchesSearch([
    item.last_seen,
    item.event_time,
    item.peak_time,
    item.issue_time,
    item.event_kind,
    item.event,
    item.summary,
    swpcLevelText(item),
    swpcTimingText(item),
    swpcDetailsText(item),
    item.source,
    item.source_url,
    item.product_id
  ], swpcSearch);
}

function swpcStatusDetail(data) {
  const feeds = Array.isArray(data.feeds) ? data.feeds.join(", ") : "";
  return [
    data.source || "SWPC",
    feeds ? `feeds ${feeds}` : ""
  ].filter(Boolean).join(" | ");
}

function swpcKindText(item) {
  return String((item || {}).event_kind || (item || {}).event || "event")
    .replace(/^swpc_/, "")
    .replace(/_/g, " ");
}

function swpcLevelText(item) {
  const parts = [];
  if ((item || {}).xray_class) parts.push(item.xray_class);
  if ((item || {}).scale_label) parts.push(item.scale_label);
  const scale = swpcScaleText(item);
  if (scale && !parts.includes(scale)) parts.push(scale);
  const kp = formatKpIndex((item || {}).kp_index);
  if (kp) parts.push(kp);
  return parts.join("; ");
}

function swpcScaleText(item) {
  const family = String((item || {}).scale_family || "").trim();
  const value = (item || {}).scale_value;
  if (!family || value === undefined || value === null || value === "") return "";
  if (family.toLowerCase() === "kp") return "";
  return `${family}${value}`;
}

function formatKpIndex(value) {
  const kp = Number(value);
  return Number.isFinite(kp) ? `Kp ${kp.toFixed(1)}` : "";
}

function swpcTimingText(item) {
  return [
    (item || {}).start_time ? `start ${displayTimestamp(item, "start_time")}` : "",
    (item || {}).peak_time ? `peak ${displayTimestamp(item, "peak_time")}` : "",
    (item || {}).end_time ? `end ${displayTimestamp(item, "end_time")}` : "",
    (item || {}).issue_time ? `issued ${displayTimestamp(item, "issue_time")}` : "",
    (item || {}).updated ? `updated ${displayTimestamp(item, "updated")}` : ""
  ].filter(Boolean).join("; ");
}

function swpcEventTimeText(item) {
  return displayFirstTimestamp(
    item,
    ["event_time", "peak_time", "issue_time", "issue", "updated"]
  );
}

function swpcDetailsText(item) {
  const summary = (item || {}).summary || "";
  const message = (item || {}).message || "";
  return [
    summary,
    message && message !== summary ? `message ${message}` : "",
    (item || {}).product_id ? `product ${(item || {}).product_id}` : "",
    (item || {}).xray_flux_peak !== undefined ? `peak flux ${(item || {}).xray_flux_peak}` : "",
    (item || {}).alert_recommended ? "alert threshold" : ""
  ].filter(Boolean).join("; ");
}

function swpcSourceNode(item) {
  const source = (item || {}).source || "";
  const url = (item || {}).source_url || "";
  if (!url) return source;
  return externalLink(source ? `${source}; ${url}` : url, url);
}

function swpcSubjectLink(item) {
  const key = String((item || {}).event_id || (item || {}).summary || "").trim();
  const label = [
    (item || {}).event || "SWPC event",
    swpcLevelText(item)
  ].filter(Boolean).join(" ");
  return key ? detailLink(label, "swpc-subject", key) : label;
}

function renderPwsEvent(event) {
  const status = document.getElementById("pws-status");
  if (status) status.textContent = event.type;
  const data = event.data || {};
  if (event.type === "collector_online") {
    setCollectorBanner("pws", "ONLINE", pwsStatusDetail(data));
    return;
  }
  if (event.type === "collector_offline" || event.type === "collector_retrying") {
    setCollectorBanner("pws", event.type, data.reason || "");
    return;
  }
  if (event.type !== "pws_weather") return;
  const row = {
    ...data,
    event_type: event.type,
    last_seen: event.timestamp,
    last_seen_epoch: event.timestamp_epoch
  };
  upsertPwsEventRow(row);
  scheduleLiveRender("pws", renderPwsTable);
  maybeRefreshMissingSubject("PWS feed", () => findPwsHistorySubject(pwsLiveEventKey(row)));
  maybeRefreshEmptyDerivedViews("PWS feed");
}

function upsertPwsEventRow(row) {
  const key = pwsLiveEventKey(row);
  if (key) {
    for (let index = rows.pws.length - 1; index >= 0; index -= 1) {
      if (pwsLiveEventKey(rows.pws[index]) === key) rows.pws.splice(index, 1);
    }
  }
  rows.pws.unshift(row);
  rows.pws = rows.pws.slice(0, uiNumber("max_live_rows"));
}

function pwsLiveEventKey(item) {
  return String((item || {}).station_id || (item || {}).station_name || (item || {}).mac_address || "").trim();
}

function renderPwsTable() {
  const events = rows.pws.filter(pwsEventMatchesSearch);
  renderSchemaTable("pws-events", events, "pwsEvents", {preserveOrder: true});
  updateTabCounts();
}

function pwsEventMatchesSearch(item) {
  return rowMatchesSearch([
    item.last_seen,
    item.station_id,
    item.station_name,
    item.mac_address,
    item.model,
    item.event_time,
    pwsWeatherText(item),
    pwsWindText(item),
    pwsRainText(item),
    pwsPressureText(item),
    pwsSolarText(item),
    item.weather_summary,
    item.source,
    item.location_name,
    item.timezone,
    item.ambient_date,
    item.last_rain_time,
    item.battery
  ], pwsSearch);
}

function pwsStatusDetail(data) {
  return [
    data.source || "Ambient Weather",
    data.station_id ? `station ${data.station_id}` : "",
    data.poll_interval_sec ? `scan ${data.poll_interval_sec}s` : "",
    data.url || ""
  ].filter(Boolean).join(" | ");
}

function pwsSubjectLink(item) {
  const key = pwsLiveEventKey(item);
  const label = (item || {}).station_id || (item || {}).station_name || key;
  return key ? detailLink(label, "pws-subject", key) : label;
}

function pwsWeatherText(item, options = {}) {
  const parts = [];
  const includeIndoor = options.includeIndoor !== false;
  const temp = numericEvidence((item || {}).temperature_f);
  const humidity = numericEvidence((item || {}).humidity_percent);
  const dew = numericEvidence((item || {}).dewpoint_f);
  const feels = numericEvidence((item || {}).feels_like_f);
  if (temp !== null) parts.push(`temp ${temp.toFixed(0)} F`);
  if (feels !== null) parts.push(`feels ${feels.toFixed(0)} F`);
  if (humidity !== null) parts.push(`humidity ${humidity.toFixed(0)}%`);
  if (dew !== null) parts.push(`dew ${dew.toFixed(0)} F`);
  const indoor = pwsIndoorText(item);
  if (includeIndoor && indoor) parts.push(`indoor ${indoor}`);
  return parts.join("; ");
}

function pwsIndoorText(item) {
  const parts = [];
  const temp = numericEvidence((item || {}).indoor_temperature_f);
  const humidity = numericEvidence((item || {}).indoor_humidity_percent);
  const feels = numericEvidence((item || {}).indoor_feels_like_f);
  const dew = numericEvidence((item || {}).indoor_dewpoint_f);
  if (temp !== null) parts.push(`${temp.toFixed(0)} F`);
  if (humidity !== null) parts.push(`${humidity.toFixed(0)}%`);
  if (feels !== null) parts.push(`feels ${feels.toFixed(0)} F`);
  if (dew !== null) parts.push(`dew ${dew.toFixed(0)} F`);
  return parts.join("; ");
}

function pwsWindText(item) {
  const parts = [];
  const direction = numericEvidence((item || {}).wind_direction_deg);
  const avgDirection = numericEvidence((item || {}).wind_direction_avg_10m_deg);
  const speed = numericEvidence((item || {}).wind_speed_mph);
  const avgSpeed = numericEvidence((item || {}).wind_speed_avg_10m_mph);
  const gust = numericEvidence((item || {}).wind_gust_mph);
  const maxGust = numericEvidence((item || {}).wind_gust_max_mph || (item || {}).max_daily_gust_mph);
  if (direction !== null) parts.push(`${direction.toFixed(0)} deg`);
  if (speed !== null) parts.push(`${speed.toFixed(0)} mph`);
  if (avgDirection !== null || avgSpeed !== null) {
    const avg = [];
    if (avgDirection !== null) avg.push(`${avgDirection.toFixed(0)} deg`);
    if (avgSpeed !== null) avg.push(`${avgSpeed.toFixed(1)} mph`);
    parts.push(`10m avg ${avg.join(" ")}`);
  }
  if (gust !== null) parts.push(`gust ${gust.toFixed(0)}`);
  if (maxGust !== null && (gust === null || maxGust !== gust)) parts.push(`max gust ${maxGust.toFixed(0)}`);
  return parts.join("; ");
}

function pwsRainText(item) {
  const parts = [];
  const rain = numericEvidence((item || {}).rain_1h_in);
  const maxRain = numericEvidence((item || {}).rain_1h_max_in);
  const event = numericEvidence((item || {}).rain_event_in);
  const day = numericEvidence((item || {}).rain_day_in);
  const week = numericEvidence((item || {}).rain_week_in);
  const month = numericEvidence((item || {}).rain_month_in);
  const year = numericEvidence((item || {}).rain_year_in);
  if (rain !== null) parts.push(`1h rate ${rain.toFixed(2)} in/hr`);
  if (maxRain !== null && (rain === null || maxRain !== rain)) parts.push(`max ${maxRain.toFixed(2)} in/hr`);
  if (event !== null) parts.push(`event ${event.toFixed(2)} in`);
  if (day !== null) parts.push(`day ${day.toFixed(2)} in`);
  if (week !== null) parts.push(`week ${week.toFixed(2)} in`);
  if (month !== null) parts.push(`month ${month.toFixed(2)} in`);
  if (year !== null) parts.push(`year ${year.toFixed(2)} in`);
  const lastRain = pwsLastRainText(item);
  if (lastRain) parts.push(`last rain ${lastRain}`);
  const transition = pwsRainTransitionText(item || {});
  if (transition) parts.push(transition);
  return parts.join("; ");
}

function pwsLastRainText(item) {
  return displayTimestamp(item, "last_rain") ||
    displayTimestamp(item, "last_rain_time") ||
    String((item || {}).last_rain_time || "");
}

function pwsRainTransitionText(item) {
  const transition = String((item || {}).rain_last_transition || "").trim();
  if (!transition) return "";
  if (transition.toLowerCase() === "stopped") {
    const stopped = (item || {}).rain_episode_stopped_at || (item || {}).rain_last_transition_at || "";
    const started = (item || {}).rain_episode_started_at || "";
    if (stopped && started) return `rain stopped ${stopped}; episode started ${started}`;
  }
  return `rain ${transition} ${(item || {}).rain_last_transition_at || ""}`.trim();
}

function pwsPressureText(item) {
  const parts = [];
  const rel = numericEvidence((item || {}).pressure_rel_inhg);
  const absValue = numericEvidence((item || {}).pressure_abs_inhg);
  if (rel !== null) parts.push(`rel ${rel.toFixed(2)} inHg`);
  if (absValue !== null) parts.push(`abs ${absValue.toFixed(2)} inHg`);
  return parts.join("; ");
}

function pwsSolarText(item) {
  const parts = [];
  const solar = numericEvidence((item || {}).solar_w_m2);
  const uv = numericEvidence((item || {}).uv_index);
  if (solar !== null) parts.push(`${solar.toFixed(0)} W/m2`);
  if (uv !== null) parts.push(`UV ${uv.toFixed(1)}`);
  return parts.join("; ");
}

function pwsElevationText(item) {
  const feet = numericEvidence((item || {}).elevation_ft);
  const meters = numericEvidence((item || {}).elevation_m);
  if (feet !== null) return `${feet.toFixed(0)} ft`;
  if (meters !== null) return `${meters.toFixed(0)} m`;
  return "";
}

function renderAdsbEvent(event) {
  const status = document.getElementById("adsb-status");
  if (status) status.textContent = event.type;
  const data = event.data || {};
  if (event.type === "collector_online") {
    setCollectorBanner("adsb", "ONLINE", adsbStatusDetail(data));
  }
  if (event.type === "collector_offline" || event.type === "collector_retrying") {
    setCollectorBanner("adsb", event.type, data.reason || "");
  }
  if (event.type !== "adsb_aircraft") return;
  const row = {
    ...data,
    last_seen: event.timestamp,
    last_seen_epoch: event.timestamp_epoch
  };
  upsertAdsbEventRow(row);
  scheduleLiveRender("adsb", renderAdsbTable);
  maybeRefreshMissingSubject("ADS-B feed", () => findAdsbHistorySubject(adsbLiveEventKey(row)));
}

function upsertAdsbEventRow(row) {
  const key = adsbLiveEventKey(row);
  if (!key) return;
  for (let index = rows.adsb.length - 1; index >= 0; index -= 1) {
    if (adsbLiveEventKey(rows.adsb[index]) === key) rows.adsb.splice(index, 1);
  }
  rows.adsb.unshift(row);
  rows.adsb = rows.adsb.slice(0, uiNumber("max_live_rows"));
}

function adsbLiveEventKey(item) {
  return String((item || {}).icao || "").toUpperCase();
}

function renderAdsbTable() {
  const events = rows.adsb
    .filter(adsbEventMatchesSearch)
    .sort((a, b) => (Number(b.last_seen_epoch || 0) - Number(a.last_seen_epoch || 0)));
  renderSchemaTable("adsb-events", events, "adsbEvents", {preserveOrder: true});
  updateTabCounts();
}

function adsbEventMatchesSearch(item) {
  return rowMatchesSearch([
    item.icao,
    item.callsign,
    item.airline_icao,
    item.squawk,
    adsbPositionText(item),
    adsbAltitudeText(item),
    adsbStateMotionText(item),
    adsbDistanceText(item)
  ], adsbSearch);
}

function adsbSubjectLink(item) {
  const key = adsbLiveEventKey(item);
  const airline = item.airline_icao ? `(${item.airline_icao})` : "";
  const label = [item.callsign, airline, item.icao].filter(Boolean).join(" ") || key;
  return key ? detailLink(label, "adsb-subject", key) : label;
}

function adsbPositionText(item) {
  if (item.lat === undefined || item.lon === undefined) return "";
  return `${item.lat}, ${item.lon}`;
}

function adsbAltitudeText(item) {
  const parts = [];
  if (item.altitude_ft !== undefined) parts.push(`${item.altitude_ft} ft`);
  if (item.altitude_baro_ft !== undefined && item.altitude_baro_ft !== item.altitude_ft) {
    parts.push(`baro ${item.altitude_baro_ft}`);
  }
  if (item.altitude_geom_ft !== undefined && item.altitude_geom_ft !== item.altitude_ft) {
    parts.push(`geom ${item.altitude_geom_ft}`);
  }
  return parts.join("; ");
}

function adsbAirGroundText(item) {
  return item.air_ground || "";
}

function adsbCprText(item) {
  return item.cpr_type || "";
}

function adsbSpeedTrackText(item) {
  const parts = [];
  if (item.ground_speed_kt !== undefined) parts.push(`${item.ground_speed_kt} kt`);
  if (item.track_deg !== undefined) parts.push(`heading ${item.track_deg} deg`);
  if (item.vertical_rate_fpm !== undefined) parts.push(`vr ${item.vertical_rate_fpm} fpm`);
  return parts.join("; ");
}

function adsbStateMotionText(item) {
  const parts = [];
  if (item.air_ground) parts.push(item.air_ground);
  if (item.cpr_type) parts.push(`CPR ${item.cpr_type}`);
  if (item.position_source) parts.push(item.position_source);
  const motion = adsbSpeedTrackText(item);
  if (motion) parts.push(motion);
  return parts.join("; ");
}

function adsbDistanceText(item) {
  const value = item.min_distance_km !== undefined ? item.min_distance_km : item.distance_km;
  return value !== undefined ? `${value} km` : "";
}

function adsbStatusDetail(data) {
  return ["1090 MHz", data.decoder || "", data.poll_interval_sec ? `poll ${data.poll_interval_sec}s` : ""]
    .filter(Boolean)
    .join(" | ");
}

function renderRtl433Event(event) {
  const status = document.getElementById("rtl433-status");
  if (status) status.textContent = event.type;
  const data = event.data || {};
  if (event.type === "scanner_started") {
    setCollectorBanner("rtl433", "ONLINE", rtl433StatusDetail(data));
    updateRtl433FrequencyState(data);
    return;
  }
  if (event.type === "scanner_frequency") {
    updateRtl433FrequencyState(data);
    return;
  }
  if (event.type === "collector_online") {
    setCollectorBanner("rtl433", "ONLINE", rtl433StatusDetail(data));
    return;
  }
  if (event.type === "collector_offline" || event.type === "collector_retrying") {
    setCollectorBanner("rtl433", event.type, data.reason || "");
    return;
  }
  if (event.type !== "rtl433_event") return;
  const row = {
    ...data,
    last_seen: event.timestamp,
    last_seen_epoch: event.timestamp_epoch
  };
  upsertRtl433EventRow(row);
  scheduleLiveRender("rtl433", renderRtl433Table);
  maybeRefreshMissingSubject("RTL-433 feed", () => findRtl433HistorySubject(rtl433LiveEventKey(row)));
}

function upsertRtl433EventRow(row) {
  const key = rtl433LiveEventKey(row);
  if (!key) return;
  let eventCount = Number(row.event_count || row.seen_count || 1);
  let burstCount = Number(row.burst_count || 0);
  for (let index = rows.rtl433.length - 1; index >= 0; index -= 1) {
    if (rtl433LiveEventKey(rows.rtl433[index]) !== key) continue;
    const previous = rows.rtl433[index];
    eventCount = Math.max(eventCount, Number(previous.event_count || previous.seen_count || 1) + 1);
    const previousEpoch = Number(previous.last_seen_epoch || 0);
    const currentEpoch = Number(row.last_seen_epoch || 0);
    if (previousEpoch && currentEpoch && currentEpoch - previousEpoch <= 120) {
      burstCount = Number(previous.burst_count || 0) + 1;
    }
    rows.rtl433.splice(index, 1);
  }
  row.event_count = eventCount;
  if (burstCount) row.burst_count = burstCount;
  rows.rtl433.unshift(row);
  rows.rtl433 = rows.rtl433.slice(0, uiNumber("max_live_rows"));
}

function rtl433LiveEventKey(item) {
  return String((item || {}).subject_key || [
    (item || {}).model,
    (item || {}).id,
    (item || {}).channel,
    (item || {}).protocol
  ].filter(Boolean).join("|")).toLowerCase();
}

function renderRtl433Table() {
  const events = rows.rtl433
    .filter(rtl433EventMatchesSearch)
    .sort((a, b) => Number(b.last_seen_epoch || 0) - Number(a.last_seen_epoch || 0));
  renderSchemaTable("rtl433-events", events, "rtl433Events", {preserveOrder: true});
  updateTabCounts();
}

function rtl433EventMatchesSearch(item) {
  return rowMatchesSearch([
    item.model,
    item.id,
    item.channel,
    item.protocol,
    item.category,
    rtl433DetailsText(item),
    rtl433SignalText(item)
  ], rtl433Search);
}

function rtl433SubjectLink(item) {
  const key = rtl433LiveEventKey(item);
  const label = rtl433SubjectLabel(item);
  return key ? detailLink(label, "rtl433-subject", key) : label;
}

function rtl433SubjectLabel(item) {
  const parts = [item.model, item.id ? `id ${item.id}` : "", item.channel ? `ch ${item.channel}` : ""];
  return parts.filter(Boolean).join(" ") || item.subject || item.subject_key || "RTL-433 subject";
}

function rtl433CategoryText(item) {
  return String((item || {}).category || "").replace(/_/g, " ");
}

function rtl433LiveActivityText(item) {
  const parts = [];
  const events = Number((item || {}).event_count || (item || {}).seen_count || 0);
  const bursts = Number((item || {}).burst_count || 0);
  if (events) parts.push(`${events} event${events === 1 ? "" : "s"}`);
  if (bursts) parts.push(`${bursts} burst${bursts === 1 ? "" : "s"}`);
  return parts.join("; ");
}

function rtl433SignalText(item) {
  item = item || {};
  const parts = [];
  const frequency = firstPresentValue(
    item.tuned_frequency_mhz,
    item.current_frequency_mhz,
    item.latest_tuned_frequency_mhz,
    item.frequency_mhz,
    item.latest_frequency_mhz
  );
  const rssi = firstPresentValue(item.rssi_db, item.latest_rssi_db, item.rssi);
  const snr = firstPresentValue(item.snr_db, item.latest_snr_db, item.snr);
  const noise = firstPresentValue(item.noise_db, item.latest_noise_db, item.noise);
  if (frequency !== undefined) parts.push(`${frequency} MHz`);
  if (rssi !== undefined) parts.push(`RSSI ${rssi} dB`);
  if (snr !== undefined) parts.push(`SNR ${snr} dB`);
  if (noise !== undefined) parts.push(`noise ${noise} dB`);
  return parts.join("; ");
}

function updateRtl433FrequencyStateFromStatus(item) {
  if (!item || item.key !== "rtl433") return;
  const state = String(item.state || "");
  if (!["ONLINE", "DETECTING", "RETRYING"].includes(state)) return;
  updateRtl433FrequencyState({
    frequency_summary: item.frequency_summary || item.frequency_plan || "",
    planned_frequency_mhz: item.planned_frequency_mhz,
    current_frequency_mhz: item.current_frequency_mhz,
    frequency_mhz: item.frequency_mhz,
    fixed_plan_running: item.fixed_plan_running,
    process_started: item.process_started || state === "ONLINE",
    device_index: item.device_index,
    source: item.source || "collector status"
  });
}

function updateRtl433FrequencyState(data) {
  const incoming = {...(data || {})};
  if (incoming.clear_frequency_state) {
    rtl433ScannerState = {};
    delete incoming.clear_frequency_state;
  }
  if (incoming.source === "configured plan") {
    incoming.planned_frequency_mhz = firstPresentValue(
      incoming.planned_frequency_mhz,
      incoming.frequency_mhz,
      incoming.current_frequency_mhz
    );
    if (incoming.process_started && incoming.planned_frequency_mhz !== undefined) {
      incoming.current_frequency_mhz = incoming.planned_frequency_mhz;
      incoming.fixed_plan_running = true;
      incoming.tune_pending = false;
    } else {
      delete incoming.frequency_mhz;
      delete incoming.current_frequency_mhz;
    }
  }
  if (String(incoming.source || "").startsWith("rtl_433")) {
    incoming.tune_pending = false;
  }
  rtl433ScannerState = {...rtl433ScannerState, ...incoming};
  const node = document.getElementById("rtl433-frequency-state");
  if (!node) return;
  const rawReportedFrequency = firstPresentValue(
    rtl433ScannerState.frequency_mhz,
    rtl433ScannerState.current_frequency_mhz
  );
  const plannedFrequency = rtl433ScannerState.planned_frequency_mhz;
  const processStarted = Boolean(rtl433ScannerState.process_started);
  const fixedPlanRunning = Boolean(rtl433ScannerState.fixed_plan_running) && plannedFrequency !== undefined;
  const reportedFrequency = fixedPlanRunning ? undefined : rawReportedFrequency;
  const parts = [
    rtl433ScannerState.tune_pending ? "waiting for rtl_433 frequency confirmation" : "",
    fixedPlanRunning ? `rtl_433 running fixed ${plannedFrequency} MHz` : "",
    reportedFrequency !== undefined ? `rtl_433 reports ${reportedFrequency} MHz` : "",
    reportedFrequency === undefined && !fixedPlanRunning && processStarted ? "rtl_433 process started" : "",
    plannedFrequency !== undefined && !fixedPlanRunning ? `planned ${plannedFrequency} MHz` : "",
    reportedFrequency === undefined && !fixedPlanRunning && plannedFrequency !== undefined ? "not frequency-confirmed" : "",
    rtl433ScannerState.device_index !== undefined ? `RTL-SDR ${rtl433ScannerState.device_index}` : "",
    rtl433ScannerState.hop_index && rtl433ScannerState.hop_count ? `hop ${rtl433ScannerState.hop_index}/${rtl433ScannerState.hop_count}` : "",
    rtl433ScannerState.dwell_sec ? `dwell ${rtl433ScannerState.dwell_sec}s` : "",
    rtl433ScannerState.source ? `source ${rtl433ScannerState.source}` : "",
    rtl433ScannerState.frequency_summary && reportedFrequency === undefined && plannedFrequency === undefined ? rtl433ScannerState.frequency_summary : ""
  ].filter(Boolean);
  node.textContent = parts.length ? parts.join(" | ") : "Waiting for current RTL-433 frequency";
  node.className = `status-strip ${(reportedFrequency !== undefined || fixedPlanRunning) ? "ok" : (plannedFrequency !== undefined || processStarted ? "warning" : "muted")}`;
}

function firstPresentValue(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return undefined;
}

function rtl433DetailsText(item) {
  const raw = (item || {}).raw || (item || {}).latest_raw || (item || {}).sample_fields || {};
  const ignore = new Set(["time", "model", "type", "id", "channel", "protocol", "freq", "frequency", "frequency_mhz", "rssi", "rssi_db", "snr", "noise"]);
  const details = [];
  Object.keys(raw || {}).sort().forEach((key) => {
    if (ignore.has(String(key).toLowerCase())) return;
    const value = raw[key];
    if (value === undefined || value === null || value === "") return;
    details.push(`${key}: ${rtl433ValueText(value)}`);
  });
  return compactList(details, 8);
}

function rtl433ValueText(value) {
  if (Array.isArray(value)) return compactList(value, 4);
  if (value && typeof value === "object") {
    return compactList(Object.keys(value).sort().map((key) => `${key}=${value[key]}`), 4);
  }
  return String(value);
}

function rtl433StatusDetail(data) {
  return [
    data.frequency_summary || data.frequency_plan || "",
    data.decoder || "rtl_433",
    data.gain ? `gain ${data.gain}` : "",
    data.sample_rate ? `sample ${data.sample_rate}` : ""
  ].filter(Boolean).join(" | ");
}

function renderRayhunterEvent(event) {
  const status = document.getElementById("rayhunter-status");
  if (status) status.textContent = event.type;
  const data = event.data || {};
  if (event.type === "collector_online") {
    setCollectorBanner("rayhunter", "ONLINE", data.endpoint || "");
    return;
  }
  if (event.type === "collector_offline" || event.type === "collector_retrying") {
    setCollectorBanner("rayhunter", event.type, data.reason || "");
    return;
  }
  if (event.type !== "rayhunter_status") return;
  const row = {
    ...data,
    last_seen: event.timestamp,
    last_seen_epoch: event.timestamp_epoch
  };
  upsertRayhunterEventRow(row);
  setCollectorBanner("rayhunter", "ONLINE", rayhunterSummaryText(row) || rayhunterWarningText(row) || row.endpoint || "");
  scheduleLiveRender("rayhunter", renderRayhunterTable);
  maybeRefreshMissingSubject("Rayhunter feed", () => findRayhunterHistorySubject(row.endpoint));
}

function upsertRayhunterEventRow(row) {
  const key = rayhunterLiveEventKey(row);
  if (!key) return;
  for (let index = rows.rayhunter.length - 1; index >= 0; index -= 1) {
    if (rayhunterLiveEventKey(rows.rayhunter[index]) === key) rows.rayhunter.splice(index, 1);
  }
  rows.rayhunter.unshift(row);
  rows.rayhunter = rows.rayhunter.slice(0, uiNumber("max_live_rows"));
}

function rayhunterLiveEventKey(item) {
  return String((item || {}).endpoint || "").toLowerCase();
}

function renderRayhunterTable() {
  const events = rows.rayhunter
    .filter(rayhunterEventMatchesSearch)
    .sort((a, b) => Number(b.last_seen_epoch || 0) - Number(a.last_seen_epoch || 0));
  renderSchemaTable("rayhunter-events", events, "rayhunterEvents", {preserveOrder: true});
  updateTabCounts();
}

function rayhunterEventMatchesSearch(item) {
  return rowMatchesSearch([
    item.endpoint,
    rayhunterWarningText(item),
    rayhunterRecordingText(item),
    rayhunterDeviceText(item),
    rayhunterSummaryText(item)
  ], rayhunterSearch);
}

function rayhunterSubjectLink(item) {
  const endpoint = (item || {}).endpoint || "";
  return endpoint ? detailLink(endpoint, "rayhunter-subject", endpoint) : "";
}

function rayhunterWarningText(item) {
  const count = Number((item || {}).warning_count || 0);
  const parts = [];
  parts.push(count ? `${count} warning(s)` : "none");
  if (item.warning) parts.push(item.warning);
  if (item.reason) parts.push(item.reason);
  return parts.filter(Boolean).join("; ");
}

function rayhunterRecordingText(item) {
  const artifacts = compactList((item || {}).recording_artifacts || [], 4);
  return [
    item.recording_id || "",
    item.recording_size || "",
    artifacts
  ].filter(Boolean).join("; ");
}

function rayhunterDeviceText(item) {
  return [
    item.rayhunter_version ? `version ${item.rayhunter_version}` : "",
    item.device_os || "",
    item.gps_mode ? `GPS ${item.gps_mode}` : "",
    item.storage || "",
    item.memory || "",
    item.battery || ""
  ].filter(Boolean).join("; ");
}

function rayhunterSummaryText(item) {
  return [
    item.summary || "",
    item.latest_event || "",
    item.warning_events_in_window ? `${item.warning_events_in_window} warning event(s)` : "",
    item.events_in_window ? `${item.events_in_window} event(s)` : ""
  ].filter(Boolean).join("; ");
}

function renderLanEvent(event) {
  const status = document.getElementById("lan-status");
  if (status) status.textContent = event.type;
  const data = event.data || {};
  if (event.type === "collector_online") {
    setCollectorBanner("lan", "ONLINE", data.method || "passive LAN observation");
    return;
  }
  if (event.type === "collector_offline" || event.type === "collector_retrying") {
    setCollectorBanner("lan", event.type, data.reason || "");
    return;
  }
  if (!["lan_device_seen", "lan_device_changed", "lan_gateway_seen", "lan_gateway_changed"].includes(event.type)) return;
  upsertLanRow({
    ...data,
    event_type: event.type,
    last_seen: event.timestamp,
    last_seen_epoch: event.timestamp_epoch
  });
  scheduleLiveRender("lan", renderLanTable);
  maybeRefreshEmptyDerivedViews("LAN observation");
}

function renderLanSnapshot(items) {
  rows.lan = Array.isArray(items) ? items.slice(0, uiNumber("max_live_rows")) : [];
  scheduleLiveRender("lan", renderLanTable);
}

function lanLiveRowKey(item) {
  const value =
    (item || {}).subject_key ||
    (item || {}).mac ||
    (item || {}).ip ||
    (item || {}).gateway_ip ||
    "";
  return String(value).trim().toLowerCase();
}

function upsertLanRow(row) {
  const key = lanLiveRowKey(row);
  if (key) {
    rows.lan = rows.lan.filter((item) => lanLiveRowKey(item) !== key);
  }
  rows.lan.unshift(row);
  rows.lan = rows.lan.slice(0, uiNumber("max_live_rows"));
}

function renderLanTable() {
  const events = rows.lan.filter(lanEventMatchesSearch);
  renderSchemaTable("lan-events", events, "lanEvents", {
    preserveOrder: true,
    columnClassPrefix: "lan-event-col",
    columnKeys: ["time", "type", "subject", "vendor", "identity", "interface", "source", "gateway", "change", "action"]
  });
  renderLanIdentifyTable();
  updateTabCounts();
}

function lanEventMatchesSearch(item) {
  return rowMatchesSearch([
    item.last_seen,
    item.event_type,
    item.subject_key,
    item.mac,
    item.ip,
    valueList(item.ips).join(" "),
    item.hostname,
    valueList(item.hostnames).join(" "),
    item.vendor_name,
    item.vendor_prefix,
    item.interface,
    valueList(item.interfaces).join(" "),
    item.state,
    valueList(item.states).join(" "),
    valueList(item.sources).join(" "),
    valueList(item.mac_aliases).join(" "),
    valueList(item.services).join(" "),
    valueList(item.locations).join(" "),
    valueList(item.servers).join(" "),
    valueList(item.messages).join(" "),
    item.gateway_ip,
    valueList(item.gateway_ips).join(" "),
    item.family,
    valueList(item.families).join(" "),
    item.change_type
  ], lanSearch);
}

function lanSubjectLink(item) {
  const key = String((item || {}).subject_key || (item || {}).mac || (item || {}).ip || "").trim();
  const label = [
    (item || {}).mac || "",
    compactList((item || {}).ips || ((item || {}).ip ? [(item || {}).ip] : []), 2)
  ].filter(Boolean).join(" / ") || key;
  return key ? detailLink(label, "lan-subject", key) : label;
}

function lanIdentifyTarget(item) {
  const ips = (item && Array.isArray(item.ips)) ? item.ips : [];
  return String((ips[0] || (item || {}).ip || (item || {}).gateway_ip || "")).trim();
}

function lanIdentifyTargetText(item) {
  const direct = String((item || {}).target || (item || {}).ip || "").trim();
  if (direct) return direct;
  const subjectKey = String((item || {}).subject_key || "").trim();
  const ipMatch = subjectKey.match(/^ip:(.+)$/);
  return ipMatch ? ipMatch[1] : subjectKey;
}

function lanIdentifyButton(item) {
  const target = lanIdentifyTarget(item);
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Identify";
  button.disabled = !target;
  button.title = target ? `Run LAN Identify for ${target}` : "LAN Identify needs an IP address";
  button.addEventListener("click", () => identifyLanTarget(item));
  return button;
}

function identifyLanTarget(item) {
  const target = lanIdentifyTarget(item);
  if (!target) {
    setTransientCollectorBanner("lan_identify", "identify_failed", "Missing LAN IP address");
    return;
  }
  setTransientCollectorBanner("lan_identify", "IDENTIFYING", `Identifying ${target}`, 5000);
  fetch("/lan_identify", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      target,
      mac: (item || {}).mac || "",
      subject_key: (item || {}).subject_key || ""
    })
  }).then((response) => {
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  }).catch((error) => {
    setTransientCollectorBanner("lan_identify", "identify_failed", `Identify request failed: ${error}`);
  });
}

function renderLanIdentifyEvent(event) {
  const data = event.data || {};
  if (event.type === "identify_started") {
    setTransientCollectorBanner("lan_identify", "IDENTIFYING", `${data.target || data.ip} via ${data.tools || "tools"}`, 5000);
    return;
  }
  if (event.type === "collector_offline") {
    setTransientCollectorBanner("lan_identify", event.type, data.reason || "LAN Identify unavailable");
    return;
  }
  if (event.type !== "identify_result" && event.type !== "identify_failed") return;
  const label = event.type === "identify_result" ? "identified" : (data.reason || "failed");
  setTransientCollectorBanner("lan_identify", event.type, `${data.target || data.ip || "target"}: ${label}`);
  rows.lanIdentify.unshift({
    ...data,
    event_type: event.type,
    timestamp: event.timestamp,
    timestamp_epoch: event.timestamp_epoch
  });
  rows.lanIdentify = rows.lanIdentify.slice(0, uiNumber("max_live_rows"));
  renderLanIdentifyTable();
  updateTabCounts();
  if (event.type === "identify_result") {
    maybeRefreshEmptyDerivedViews("LAN identify");
  }
}

function renderLanIdentifyTable() {
  const events = rows.lanIdentify.filter(lanIdentifyMatchesSearch);
  renderSchemaTable("lan-identify-results", events, "lanIdentifyResults", {
    preserveOrder: true,
    columnClassPrefix: "lan-identify-col",
    columnKeys: ["time", "target", "result", "ports", "http", "hints", "errors"]
  });
}

function lanIdentifyMatchesSearch(item) {
  return rowMatchesSearch([
    item.timestamp,
    item.target,
    item.ip,
    item.mac,
    valueList(item.open_ports).join(" "),
    valueList(item.service_banners).join(" "),
    valueList(item.http_urls).join(" "),
    valueList(item.http_titles).join(" "),
    valueList(item.http_headers).join(" "),
    valueList(item.http_scripts).join(" "),
    valueList(item.http_hints).join(" "),
    valueList(item.identify_errors).join(" ")
  ], lanSearch);
}

function lanIdentityText(item) {
  return [
    item.hostname || compactList(item.hostnames || [], 2),
    compactList(item.services || [], 2)
  ].filter(Boolean).join("; ");
}

function lanVendorText(item) {
  return (item || {}).vendor_name || (item || {}).vendor_prefix || "";
}

function lanInterfaceStateText(item) {
  return [
    item.interface || compactList(item.interfaces || [], 3),
    item.family || compactList(item.families || [], 2),
    item.state || compactList(item.states || [], 2)
  ].filter(Boolean).join("; ");
}

function lanGatewayText(item) {
  if (item.gateway_ip || (item.gateway_ips || []).length) {
    return [
      item.family || compactList(item.families || [], 2),
      item.gateway_ip || compactList(item.gateway_ips || [], 3),
      item.interface || compactList(item.interfaces || [], 3),
      item.mac || ""
    ].filter(Boolean).join("; ");
  }
  return item.gateway ? "gateway" : "";
}

function setWifiMonitorPlan(text, state) {
  const node = document.getElementById("wifi-monitor-plan");
  if (!node) return;
  node.textContent = text;
  node.className = `status-strip ${state || "muted"}`;
}

function formatChannelList(values) {
  const items = valueList(values);
  if (!items.length) return "none";
  return items.join(", ");
}

function renderWifiTables() {
  const aps = [...rows.aps.values()]
    .filter(wifiApMatchesSearch)
    .sort(compareWifiAccessPoints);
  renderSchemaTable("wifi-aps", aps, "wifiAccessPoints", {
    preserveOrder: true
  });
  updateTabCounts();
}

function annotationText(item) {
  const data = (item && item.data && typeof item.data === "object") ? item.data : {};
  return String(
    ((item || {}).annotation || {}).custom_name ||
    (item || {}).custom_name ||
    ((data || {}).annotation || {}).custom_name ||
    (data || {}).custom_name ||
    ""
  ).trim();
}

function annotatedLabel(item, subject) {
  const original = String(subject || "");
  const custom = annotationText(item);
  return custom ? `${custom} (${original})` : original;
}

function annotatedDetailLink(item, subject, type, key) {
  return detailLink(annotatedLabel(item, subject), type, key);
}

function annotatedWifiClientHistoryLabel(item) {
  if (item && item.grouped_randomized) return wifiClientHistoryLabel(item);
  const key = (item || {}).mac || "";
  return detailLink(annotatedLabel(item, key), "wifi-client", key);
}

function subjectAnnotationButton(subject) {
  if (!subject || !subject.collector || !subject.subject_type || !subject.subject_id) return "";
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = annotationText(subject) ? "Edit" : "Name";
  button.title = "Edit subject annotation";
  button.addEventListener("click", () => editSubjectAnnotation(subject));
  return {node: button, text: button.textContent};
}

function editSubjectAnnotation(subject) {
  const original = String(subject.subject || subject.subject_id || "subject");
  const current = annotationText(subject);
  const value = window.prompt(`Annotation for ${original}`, current);
  if (value === null) return;
  saveSubjectAnnotation(subject, value.trim());
}

function saveSubjectAnnotation(subject, customName) {
  setHistoryStatus("Saving subject annotation", "warning");
  return fetchJson("/subject_annotations", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      collector: subject.collector,
      subject_type: subject.subject_type,
      subject_id: subject.subject_id,
      custom_name: customName || ""
    })
  })
    .then((payload) => {
      applySavedSubjectAnnotation(subject, payload.annotation || null);
      applySavedReportAnnotation(subject, payload.annotation || null);
      setHistoryStatus(customName ? "Subject annotation saved" : "Subject annotation cleared", "ok");
      return payload;
    })
    .catch((error) => setHistoryStatus(`Subject annotation failed: ${error}`, "alert"));
}

function applySavedSubjectAnnotation(subject, annotation) {
  if (!latestDeviceHistory || !Array.isArray(latestDeviceHistory.subjects)) return;
  let changed = false;
  latestDeviceHistory.subjects.forEach((item) => {
    if (!subjectAnnotationTargetMatches(item, subject)) return;
    if (annotation && annotation.custom_name) {
      item.annotation = annotation;
      item.custom_name = annotation.custom_name;
    } else {
      delete item.annotation;
      delete item.custom_name;
      if (item.data && typeof item.data === "object") {
        delete item.data.annotation;
        delete item.data.custom_name;
      }
    }
    changed = true;
  });
  if (changed) renderDeviceHistory(latestDeviceHistory);
}

function subjectAnnotationTargetMatches(item, subject) {
  if (!item || !subject) return false;
  return String(item.collector || "").toLowerCase() === String(subject.collector || "").toLowerCase()
    && String(item.subject_type || "").toLowerCase() === String(subject.subject_type || "").toLowerCase()
    && String(item.subject_id || "") === String(subject.subject_id || "");
}

function applySavedReportAnnotation(subject, annotation) {
  if (!latestReports || !Array.isArray(latestReports.reports)) return;
  let changed = false;
  latestReports.reports.forEach((report) => {
    if (!reportMatchesAnnotationTarget(report, subject)) return;
    const evidence = (report.evidence && typeof report.evidence === "object") ? report.evidence : null;
    if (annotation && annotation.custom_name) {
      const original = originalReportSubject(report, subject);
      report.annotation = annotation;
      report.custom_name = annotation.custom_name;
      report.subject = annotatedReportSubject(annotation.custom_name, original);
      if (evidence) {
        evidence.annotation = annotation;
        evidence.custom_name = annotation.custom_name;
      }
    } else {
      report.subject = originalReportSubject(report, subject);
      delete report.annotation;
      delete report.custom_name;
      if (evidence) {
        delete evidence.annotation;
        delete evidence.custom_name;
      }
    }
    changed = true;
  });
  if (changed) renderReports(latestReports);
}

function reportMatchesAnnotationTarget(report, subject) {
  if (!report || !subject) return false;
  const source = String(report.source || "").toLowerCase();
  const collector = String(subject.collector || "").toLowerCase();
  if (source !== collector) return false;
  const evidence = (report.evidence && typeof report.evidence === "object") ? report.evidence : {};
  if (collector === "lan") {
    return String(evidence.subject_key || evidence.mac || evidence.ip || "") === String(subject.subject_id || "");
  }
  if (collector === "bluetooth") {
    return normalizedMacText(evidence.mac || "") === normalizedMacText(subject.subject_id || "");
  }
  if (collector === "wifi") {
    return String(evidence.bssid || evidence.ssid || "") === String(subject.subject_id || "");
  }
  return false;
}

function originalReportSubject(report, subject) {
  const current = String((report || {}).subject || "").trim();
  const custom = annotationText(report);
  if (custom && current.startsWith(`${custom} (`) && current.endsWith(")")) {
    return current.slice(custom.length + 2, -1);
  }
  return current || String((subject || {}).subject || (subject || {}).subject_id || "").trim();
}

function annotatedReportSubject(customName, original) {
  const custom = String(customName || "").trim();
  const base = String(original || "").trim();
  if (!custom) return base;
  if (base.startsWith(`${custom} (`) && base.endsWith(")")) return base;
  return base ? `${custom} (${base})` : custom;
}

function normalizedMacText(value) {
  const compact = String(value || "").replace(/[^0-9a-fA-F]/g, "");
  if (compact.length !== 12) return String(value || "").trim().toUpperCase();
  return compact.match(/../g).join(":").toUpperCase();
}

function wifiClientHistoryLabel(item) {
  if (item && item.grouped_randomized) {
    const count = Number(item.randomized_group_count || 0);
    return `${count} randomized client MAC${count === 1 ? "" : "s"}`;
  }
  return detailLink((item || {}).mac || "", "wifi-client", (item || {}).mac || "");
}

function wifiMonitorHistorySummaryText(wifi, clients) {
  const totalClients = Number((wifi || {}).total_clients || (clients || []).length);
  if (!(clients || []).length) {
    return "No Wi-Fi client/probe history in this view. Wi-Fi Monitor must be running in monitor mode to collect clients, probes, deauth, and association frames.";
  }
  const randomized = (clients || []).reduce((total, item) => {
    if (!item || !item.randomized_mac) return total;
    return total + Number(item.randomized_group_count || 1);
  }, 0);
  const known = Math.max(0, totalClients - randomized);
  const parts = [];
  if ((clients || []).length < totalClients) {
    parts.push(`${(clients || []).length} of ${totalClients} Wi-Fi client/probe histories loaded for display`);
  } else {
    parts.push(`${totalClients} Wi-Fi client/probe histories in this view`);
  }
  if (randomized || known) {
    parts.push(`${known} stable/vendor MACs`);
    parts.push(`${randomized} randomized MACs`);
  }
  return parts.join(" | ");
}

function compareWifiAccessPoints(left, right) {
  const leftMs = recordTimestampMs(left, "last_seen");
  const rightMs = recordTimestampMs(right, "last_seen");
  if (leftMs && rightMs && leftMs !== rightMs) return rightMs - leftMs;
  if (leftMs && !rightMs) return -1;
  if (!leftMs && rightMs) return 1;
  const leftSsid = left.ssid || "";
  const rightSsid = right.ssid || "";
  if (leftSsid !== rightSsid) return leftSsid.localeCompare(rightSsid);
  return (left.bssid || "").localeCompare(right.bssid || "");
}

function renderDeviceHistory(history) {
  latestDeviceHistory = history;
  updateDeviceHistoryStatus(history);
  const wifi = history.wifi || {};
  const ble = history.bluetooth || history.ble || {};
  const aps = wifi.access_points || [];
  const clients = wifi.clients || [];
  const devices = ble.devices || [];
  const wifiSubjects = historySubjectsFor(history, "wifi");
  const wifiApSubjects = wifiSubjects.filter((item) => ["wifi_ssid", "wifi_bssid"].includes(String(item.subject_type || "")));
  const wifiClientSubjects = wifiSubjects.filter((item) => ["wifi_client", "wifi_client_group"].includes(String(item.subject_type || "")));
  const aprsisSubjects = historySubjectsFor(history, "aprsis");
  const rayhunterSubjects = historySubjectsFor(history, "rayhunter");
  const rtl433Subjects = historySubjectsFor(history, "rtl433");
  const adsbSubjects = historySubjectsFor(history, "adsb");
  const noaaSubjects = historySubjectsFor(history, "noaa");
  const usgsSubjects = historySubjectsFor(history, "usgs");
  const swpcSubjects = historySubjectsFor(history, "swpc");
  const pwsSubjects = historySubjectsFor(history, "pws");
  const lanSubjects = historySubjectsFor(history, "lan");
  const monitorEmpty = document.getElementById("history-wifi-monitor-empty");
  if (monitorEmpty) {
    monitorEmpty.textContent = wifiMonitorHistorySummaryText(wifi, clients);
  }
  renderHistoryTable("history-wifi-aps", wifiApSubjects, (item) => wifiApSubjectHistoryCells(item), historySearch);
  renderHistoryTable("history-wifi-clients", wifiClientSubjects, (item) => wifiClientSubjectHistoryCells(item), historySearch);
  renderHistoryTable("history-bluetooth-devices", devices, (item) => [
    item.grouped_randomized
      ? `${item.randomized_group_count || 0} ${item.name || "randomized devices found"}`
      : annotatedDetailLink(item, item.mac || "", "bluetooth-device", item.mac || ""),
    bleDeviceIdentity(item),
    bluetoothServiceList(item.service_uuids),
    item.model_number || "",
    item.serial_number || "",
    item.firmware_revision || "",
    item.pnp_id || "",
    item.first_seen || "",
    item.last_seen || "",
    signalRange(item),
    `${item.seen_count || 0} / ${item.update_count || 0}`,
    sessionCount(item),
    item.grouped_randomized ? "" : subjectAnnotationButton({
      collector: "bluetooth",
      subject_type: "bluetooth_device",
      subject_id: item.mac || "",
      subject: item.mac || "Bluetooth device",
      annotation: item.annotation
    })
  ], historySearch);
  renderHistoryTable("history-aprsis-subjects", aprsisSubjects, (item) => [
    detailLink(item.subject || "", "aprsis-subject", item.subject || ""),
    subjectTypeLabel(item),
    item.first_seen || "",
    item.last_seen || "",
    aprsisSubjectCounts(item),
    aprsisSubjectPosition(item),
    aprsisSubjectActivity(item),
    aprsisSubjectRoute(item)
  ], historySearch);
  renderHistoryTable("history-rayhunter-subjects", rayhunterSubjects, (item) => [
    detailLink(item.subject || "", "rayhunter-subject", subjectData(item).endpoint || item.subject || ""),
    item.first_seen || "",
    item.last_seen || "",
    subjectData(item).warning_count || 0,
    subjectData(item).events_in_window || 0,
    subjectData(item).recording_id || ""
  ], historySearch);
  renderHistoryTable("history-rtl433-subjects", rtl433Subjects, (item) => [
    detailLink(item.subject || "", "rtl433-subject", subjectData(item).subject_key || item.subject_id || ""),
    rtl433CategoryText(subjectData(item)),
    item.first_seen || "",
    item.last_seen || "",
    rtl433SubjectActivity(item),
    rtl433SignalText(subjectData(item)),
    rtl433DetailsText(subjectData(item))
  ], historySearch);
  renderHistoryTable("history-adsb-subjects", adsbSubjects, (item) => [
    detailLink(item.subject || "", "adsb-subject", subjectData(item).icao || item.subject_id || ""),
    item.first_seen || "",
    item.last_seen || "",
    adsbPositionText(subjectData(item)),
    adsbAltitudeText(subjectData(item)),
    adsbDistanceText(subjectData(item)),
    adsbSpeedTrackText(subjectData(item)),
    subjectData(item).seen_count || 0
  ], historySearch);
  renderHistoryTable("history-noaa-subjects", noaaSubjects, (item) => [
    detailLink(item.subject || "", "noaa-subject", subjectData(item).event_id || item.subject_id || ""),
    subjectTypeLabel(item),
    item.first_seen || "",
    item.last_seen || "",
    noaaSubjectSeverity(item),
    subjectData(item).area_desc || "",
    noaaSubjectTiming(item),
    noaaSubjectSource(item)
  ], historySearch);
  renderHistoryTable("history-usgs-subjects", usgsSubjects, (item) => [
    detailLink(item.subject || "", "usgs-subject", subjectData(item).event_id || item.subject_id || ""),
    usgsMagnitudeText(subjectData(item)),
    item.first_seen || "",
    item.last_seen || "",
    subjectData(item).event_time || "",
    usgsSubjectLocation(item),
    usgsSubjectDepthDistance(item),
    usgsSubjectStatus(item)
  ], historySearch);
  renderHistoryTable("history-swpc-subjects", swpcSubjects, (item) => [
    detailLink(item.subject || "", "swpc-subject", subjectData(item).event_id || item.subject_id || ""),
    subjectTypeLabel(item),
    item.first_seen || "",
    item.last_seen || "",
    subjectData(item).event_time || subjectData(item).peak_time || subjectData(item).issue_time || "",
    swpcLevelText(subjectData(item)),
    subjectData(item).summary || "",
    swpcSubjectSource(item)
  ], historySearch);
  renderHistoryTable("history-pws-subjects", pwsSubjects, (item) => [
    detailLink(item.subject || "", "pws-subject", subjectData(item).station_id || item.subject_id || ""),
    item.first_seen || "",
    item.last_seen || "",
    subjectData(item).event_time || "",
    pwsWeatherText(subjectData(item)),
    pwsWindText(subjectData(item)),
    pwsRainText(subjectData(item)),
    pwsSubjectSource(item)
  ], historySearch);
  renderHistoryTable("history-lan-subjects", lanSubjects, (item) => [
    annotatedDetailLink(item, item.subject || "", "lan-subject", subjectData(item).subject_key || item.subject_id || ""),
    subjectTypeLabel(item),
    item.first_seen || "",
    item.last_seen || "",
    lanSubjectIpMac(item),
    lanSubjectIdentity(item),
    lanSubjectInterfaceState(item),
    lanSubjectActivity(item),
    subjectAnnotationButton({
      ...item,
      collector: "lan",
      subject_type: item.subject_type || "",
      subject_id: item.subject_id || "",
      subject: item.subject || item.subject_id || "LAN subject"
    })
  ], historySearch);
  updateTabCounts();
}


function wifiApSubjectHistoryCells(item) {
  const data = subjectData(item);
  const isSsid = item.subject_type === "wifi_ssid";
  const ssid = data.ssid || item.subject || "(blank)";
  const bssid = data.bssid || item.subject_id || "";
  const identity = isSsid
    ? `${data.bssid_count || (data.bssids || []).length || 0} BSSID${Number(data.bssid_count || (data.bssids || []).length || 0) === 1 ? "" : "s"}`
    : detailLink(bssid, "wifi-bssid", bssid);
  return [
    annotatedDetailLink(item, item.subject || ssid, "wifi-ssid", ssid),
    identity,
    vendorLabel(data),
    item.first_seen || "",
    item.last_seen || "",
    channelFreqList(data.channels),
    valueList(data.encryption).join(", "),
    signalRange(data),
    data.observations || 0,
    isSsid ? "" : subjectAnnotationButton({
      collector: "wifi",
      subject_type: item.subject_type || "wifi_bssid",
      subject_id: item.subject_id || bssid,
      subject: item.subject || ssid || bssid || "Wi-Fi AP",
      annotation: item.annotation
    })
  ];
}

function wifiClientSubjectHistoryCells(item) {
  const data = subjectData(item);
  const grouped = item.subject_type === "wifi_client_group" || data.grouped_randomized;
  const mac = data.mac || item.subject_id || "";
  return [
    grouped ? item.subject || `${data.randomized_group_count || 0} randomized Wi-Fi client MACs` : annotatedDetailLink(item, item.subject || mac, "wifi-client", mac),
    vendorLabel(data),
    ssidList(data.ssids, grouped),
    item.first_seen || "",
    item.last_seen || "",
    signalRange(data),
    data.probe_count || 0,
    data.association_count || 0,
    data.deauth_count || 0,
    data.disassoc_count || 0,
    grouped ? "" : subjectAnnotationButton({
      collector: "wifi",
      subject_type: item.subject_type || "wifi_client",
      subject_id: item.subject_id || mac,
      subject: item.subject || mac || "Wi-Fi client",
      annotation: item.annotation
    })
  ];
}

function updateDeviceHistoryStatus(history) {
  const wifi = history.wifi || {};
  const ble = history.bluetooth || history.ble || {};
  const aps = wifi.access_points || [];
  const clients = wifi.clients || [];
  const devices = ble.devices || [];
  const subjectCounts = history.subject_counts || {};
  const subjects = Array.isArray(history.subjects) ? history.subjects : [];
  const directSubjects = subjects.filter((item) =>
    ["aprsis", "rayhunter", "rtl433", "adsb", "noaa", "usgs", "swpc", "pws", "lan"].includes(String(item.collector || ""))
  );
  const window = history.window || {};
  const refreshedAt = history.generated_at || history.refreshed_at;
  const visible = [...aps, ...clients, ...devices, ...directSubjects];
  const totalAps = Number(wifi.total_access_points || aps.length);
  const totalClients = Number(wifi.total_clients || clients.length);
  const totalBluetooth = Number(ble.total_devices || devices.length);
  const totalSubjects = Number(history.total_subjects || subjectCounts.total || subjects.length || 0);
  const totalShown = totalSubjects || (totalAps + totalClients + totalBluetooth);
  const displayedShown = visible.length;
  const rawEvents = history.records_read || 0;
  const newestSeen = latestSeenStatusText(visible, ["last_seen", "timestamp"]);
  const refreshedEpoch = history.generated_at_epoch || history.refreshed_at_epoch;
  const normalState = derivedStatusState(refreshedAt, refreshedEpoch, "ok");
  setHistoryStatus(
    [
      derivedStatusPrefix(window, refreshedAt, refreshedEpoch),
      newestSeen,
      `${totalShown} subjects in view`,
      displayedShown < totalShown ? `${displayedShown} loaded for display` : "",
      `${rawEvents} raw events processed`,
      `${totalAps} APs`,
      `${totalClients} Wi-Fi clients`,
      `${totalBluetooth} Bluetooth devices`,
      `${directSubjects.length} direct collector subjects`
    ].filter(Boolean).join(" | "),
    derivedDataStatusState(visible, ["last_seen", "timestamp"], normalState)
  );
}

function historySubjectsFor(history, collector) {
  return (Array.isArray((history || {}).subjects) ? history.subjects : [])
    .filter((item) => String(item.collector || "") === collector);
}

function subjectData(item) {
  return (item || {}).data || {};
}

function subjectTypeLabel(item) {
  return String((item || {}).subject_type || "")
    .replace(/^(aprsis|rayhunter|rtl433|adsb|wifi|bluetooth)_/, "")
    .replace(/^pws_/, "")
    .replace(/^swpc_/, "")
    .replace(/_/g, " ");
}

function aprsisSubjectCounts(item) {
  const data = subjectData(item);
  return [
    `${data.packet_count || 0} pkt`,
    data.position_count ? `${data.position_count} pos` : "",
    data.weather_count ? `${data.weather_count} wx` : "",
    data.object_count ? `${data.object_count} obj` : "",
    data.message_count ? `${data.message_count} msg` : "",
    data.status_count ? `${data.status_count} status` : ""
  ].filter(Boolean).join("; ");
}

function aprsisSubjectPosition(item) {
  const data = subjectData(item);
  const lat = Number(data.latitude !== undefined ? data.latitude : data.last_latitude);
  const lon = Number(data.longitude !== undefined ? data.longitude : data.last_longitude);
  const first = formatLatLon(data.first_latitude, data.first_longitude);
  const latest = formatLatLon(lat, lon);
  const parts = [];
  if (first && latest && first !== latest) {
    parts.push(`first ${first}`);
    parts.push(`latest ${latest}`);
  } else if (latest) {
    parts.push(latest);
  }
  if (data.position_span_km !== undefined) parts.push(`span ${Number(data.position_span_km).toFixed(2)} km`);
  if (data.movement_km !== undefined) parts.push(`move ${Number(data.movement_km).toFixed(2)} km`);
  return parts.join("; ");
}

function aprsisSubjectActivity(item) {
  const data = subjectData(item);
  if (data.weather_summary) return normalizeAprsWeatherSummary(data.weather_summary);
  const parts = [];
  if (data.temperature_f !== undefined) parts.push(`${data.temperature_f} F`);
  if (data.latest_wind_speed_mph !== undefined) parts.push(`wind ${data.latest_wind_speed_mph} mph`);
  if (data.latest_wind_gust_mph !== undefined) parts.push(`gust ${data.latest_wind_gust_mph} mph`);
  if (data.max_speed_kmh !== undefined) parts.push(`max ${Number(data.max_speed_kmh).toFixed(1)} km/h`);
  if (data.object_name) parts.push(`object ${data.object_name}`);
  if (data.message || data.comment) parts.push(data.message || data.comment);
  return parts.join("; ");
}

function aprsisSubjectRoute(item) {
  const data = subjectData(item);
  const server = aprsisServerText(data);
  return [
    data.via_path ? `via ${data.via_path}` : "",
    data.q_construct || "",
    data.igate ? `igate ${data.igate}` : "",
    data.feed_name ? `feed ${data.feed_name}` : "",
    server ? `server ${server}` : "",
    data.host ? `host ${data.host}` : "",
    compactList(data.sample_igates || [], 3),
    aprsisAdditionalSamples(data.sample_servers, data.server_name, "servers", 3)
  ].filter(Boolean).join("; ");
}

function aprsisServerText(data) {
  const item = data || {};
  const name = String(item.server_name || "").trim();
  const address = String(item.server_address || "").trim();
  if (name && address) return `${name} (${address})`;
  return name || address;
}

function rtl433SubjectActivity(item) {
  const data = subjectData(item);
  return [
    data.event_count ? `${data.event_count} event(s)` : "",
    data.burst_count ? `${data.burst_count} burst(s)` : ""
  ].filter(Boolean).join("; ");
}

function noaaSubjectSeverity(item) {
  const data = subjectData(item);
  return [
    data.severity || "",
    data.urgency ? `urgency ${data.urgency}` : "",
    data.certainty ? `certainty ${data.certainty}` : ""
  ].filter(Boolean).join("; ");
}

function noaaSubjectTiming(item) {
  const data = subjectData(item);
  return [
    data.alert_kind === "tsunami" ? noaaTsunamiText(data) : "",
    data.event_time ? `event ${data.event_time}` : "",
    data.effective ? `effective ${data.effective}` : "",
    data.onset ? `onset ${data.onset}` : "",
    data.expires ? `expires ${data.expires}` : "",
    data.updated ? `updated ${data.updated}` : ""
  ].filter(Boolean).join("; ");
}

function noaaSubjectSource(item) {
  const data = subjectData(item);
  return [
    data.source || "",
    data.basin ? data.basin.replace(/_/g, " ") : "",
    data.internet_fed ? "internet-fed" : ""
  ].filter(Boolean).join("; ");
}

function usgsSubjectLocation(item) {
  const data = subjectData(item);
  return formatLatLon(data.latitude, data.longitude) || data.place || "";
}

function usgsSubjectDepthDistance(item) {
  const data = subjectData(item);
  return [
    data.depth_km !== undefined ? `depth ${data.depth_km} km` : "",
    data.distance_km !== undefined ? `${Number(data.distance_km).toFixed(1)} km away` : ""
  ].filter(Boolean).join("; ");
}

function usgsSubjectStatus(item) {
  const data = subjectData(item);
  return [
    data.status || "",
    data.alert_color ? `alert ${data.alert_color}` : "",
    Number(data.tsunami || 0) ? "tsunami" : ""
  ].filter(Boolean).join("; ");
}

function swpcSubjectSource(item) {
  const data = subjectData(item);
  return [
    data.source || "",
    data.product_id ? `product ${data.product_id}` : ""
  ].filter(Boolean).join("; ");
}

function pwsSubjectSource(item) {
  const data = subjectData(item);
  return [
    data.source || "",
    data.mac_address || "",
    data.model || ""
  ].filter(Boolean).join("; ");
}

function lanSubjectIpMac(item) {
  const data = subjectData(item);
  return [
    compactList(data.ips || data.gateway_ips || (data.ip ? [data.ip] : data.gateway_ip ? [data.gateway_ip] : []), 3),
    data.mac || ""
  ].filter(Boolean).join(" / ");
}

function lanSubjectIdentity(item) {
  const data = subjectData(item);
  return [
    data.hostname || compactList(data.hostnames || [], 2),
    data.vendor_name || data.vendor_prefix || ""
  ].filter(Boolean).join("; ");
}

function lanSubjectInterfaceState(item) {
  const data = subjectData(item);
  return [
    data.interface || compactList(data.interfaces || [], 3),
    data.family || compactList(data.families || [], 2),
    data.state || compactList(data.states || [], 2)
  ].filter(Boolean).join("; ");
}

function lanSubjectActivity(item) {
  const data = subjectData(item);
  return [
    data.gateway ? "gateway" : "",
    data.observation_count ? `${data.observation_count} observation(s)` : "",
    data.change_count ? `${data.change_count} change(s)` : "",
    data.gateway_ip ? `gateway ${data.gateway_ip}` : "",
    compactList(data.sources || [], 3)
  ].filter(Boolean).join("; ");
}

function vendorLabel(item) {
  if (!item) return "";
  const prefix = item.vendor_prefix || item.vendor_oui;
  if (item.vendor_name && prefix) return `${item.vendor_name} (${prefix})`;
  return item.vendor_name || prefix || "";
}

function detailLink(label, type, key) {
  const text = String(label || key || "");
  if (!key) return text;
  const button = document.createElement("button");
  button.type = "button";
  button.className = "detail-link";
  button.textContent = text;
  button.title = "Open detail view";
  button.addEventListener("click", () => openDetail(type, key));
  return {node: button, text};
}

function externalLink(label, href) {
  const text = String(label || href || "");
  const url = String(href || "").trim();
  if (!/^https?:\/\//i.test(url)) return text;
  const link = document.createElement("a");
  link.href = url;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = text;
  return {node: link, text};
}

function setupDetailPanel() {
  const backdrop = document.getElementById("detail-backdrop");
  const close = document.getElementById("detail-close");
  if (!backdrop || !close) return;
  close.addEventListener("click", closeDetail);
  backdrop.addEventListener("click", (event) => {
    if (event.target === backdrop) closeDetail();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !backdrop.hidden) closeDetail();
  });
}

function openDetail(type, key) {
  const backdrop = document.getElementById("detail-backdrop");
  const title = document.getElementById("detail-title");
  const kind = document.getElementById("detail-kind");
  const body = document.getElementById("detail-body");
  if (!backdrop || !title || !kind || !body) return;

  const detail = buildDetail(type, key);
  title.textContent = detail.title;
  kind.textContent = detail.kind;
  body.innerHTML = "";
  detail.sections.forEach((section) => body.appendChild(section));
  backdrop.hidden = false;
}

function closeDetail() {
  const backdrop = document.getElementById("detail-backdrop");
  if (backdrop) backdrop.hidden = true;
}

function buildDetail(type, key) {
  if (type === "bluetooth-device") return buildBluetoothDetail(key);
  if (type === "wifi-ssid") return buildWifiSsidDetail(key);
  if (type === "wifi-bssid") return buildWifiBssidDetail(key);
  if (type === "wifi-client") return buildWifiClientDetail(key);
  if (type === "aprsis-subject") return buildAprsisSubjectDetail(key);
  if (type === "rayhunter-subject") return buildRayhunterSubjectDetail(key);
  if (type === "noaa-subject") return buildNoaaSubjectDetail(key);
  if (type === "usgs-subject") return buildUsgsSubjectDetail(key);
  if (type === "swpc-subject") return buildSwpcSubjectDetail(key);
  if (type === "pws-subject") return buildPwsSubjectDetail(key);
  if (type === "adsb-subject") return buildAdsbSubjectDetail(key);
  if (type === "rtl433-subject") return buildRtl433SubjectDetail(key);
  if (type === "lan-subject") return buildLanSubjectDetail(key);
  return {
    kind: "Detail",
    title: String(key || "Unknown"),
    sections: [detailMessage("No detail renderer is available for this item.")]
  };
}

function buildRayhunterSubjectDetail(key) {
  const subject = findRayhunterHistorySubject(key);
  const reports = relatedReportsFor("rayhunter-subject", key);
  if (!subject) return missingDetail("Rayhunter Subject", key, reports);
  const data = subjectData(subject);
  return {
    kind: "Rayhunter Subject",
    title: subject.subject || data.endpoint || key,
    sections: [
      detailSection("Endpoint", [
        ["Endpoint", data.endpoint || key],
        ["Type", subjectTypeLabel(subject)]
      ]),
      detailSection("Status", [
        ["Warnings", data.warning_count],
        ["Status Events", data.events_in_window],
        ["Warning Events", data.warning_events_in_window],
        ["Latest Event", data.latest_event],
        ["Reason", data.reason]
      ]),
      detailSection("System", [
        ["Version", data.rayhunter_version],
        ["OS", data.device_os],
        ["GPS", data.gps_mode],
        ["Storage", data.storage],
        ["Memory", data.memory],
        ["Battery", data.battery]
      ]),
      detailSection("Recording", [
        ["ID", data.recording_id],
        ["Size", data.recording_size],
        ["Start", data.recording_start],
        ["Last Message", data.recording_last_message]
      ]),
      detailSection("Observed", [
        ["First Seen", subject.first_seen || data.first_seen],
        ["Last Seen", subject.last_seen || data.last_seen]
      ]),
      reportsSection(reports)
    ]
  };
}

function buildAprsisSubjectDetail(key) {
  const subject = findAprsisHistorySubject(key);
  const reports = relatedReportsFor("aprsis-subject", key);
  if (!subject) return missingDetail("APRS-IS Subject", key, reports);
  const data = subjectData(subject);
  return {
    kind: "APRS-IS Subject",
    title: subject.subject || data.callsign || key,
    sections: [
      detailSection("Subject", [
        ["Callsign / Object", subject.subject || data.callsign || key],
        ["Type", subjectTypeLabel(subject)],
        ["Latest Packet", data.packet_type],
        ["Internet-fed", data.internet_fed ? "yes" : ""]
      ]),
      detailSection("Observed", [
        ["First Seen", subject.first_seen || data.first_seen],
        ["Last Seen", subject.last_seen || data.last_seen],
        ["Packets", aprsisSubjectCounts(subject)]
      ]),
      detailSection("Position / Activity", [
        ["Position", aprsisSubjectPosition(subject)],
        ["Trip", aprsisTripText(data)],
        ["Weather / Motion", aprsisSubjectActivity(subject)]
      ]),
      detailSection("Route Samples", [
        ["First Position", aprsisPositionTimeText(data.first_position_at, data.first_latitude, data.first_longitude)],
        ["Last Position", aprsisPositionTimeText(data.last_position_at, data.last_latitude ?? data.latitude, data.last_longitude ?? data.longitude)],
        ["Recent Positions", compactList(data.position_samples || [], 8)]
      ]),
      detailSection("Packet Samples", [
        ["Latest Payload", data.payload],
        ["Latest Raw", data.raw],
        ["Recent Packets", compactList(data.packet_samples || [], 6)]
      ]),
      detailSection("Weather", [
        ["Latest", normalizeAprsWeatherSummary(data.weather_summary)],
        ["Temperature", aprsisTemperatureEvidenceText(data)],
        ["Wind", aprsisWindEvidenceText(data)],
        ["Rain", aprsisRainEvidenceText(data)],
        ["Humidity", data.humidity_percent ? `${data.humidity_percent}%` : ""],
        ["Pressure", data.pressure_hpa ? `${data.pressure_hpa} hPa` : ""]
      ]),
      detailSection("Feed / Server", [
        ["Feed", data.feed_name],
        ["Role", aprsisDistinctFeedRole(data.feed_name, data.feed_role) || data.feed_role],
        ["Backend Server", aprsisServerText(data)],
        ["Preferred Server", compactList(data.preferred_servers || [], 4)],
        ["Sample Servers", compactList(data.sample_servers || [], 5)],
        ["Configured Host", data.host],
        ["Filter", data.filter],
        ["Igate", data.igate],
        ["Sample Igates", compactList(data.sample_igates || [], 5)]
      ]),
      reportsSection(reports)
    ]
  };
}

function buildNoaaSubjectDetail(key) {
  const subject = findNoaaHistorySubject(key);
  const live = subject ? null : findNoaaLiveEvent(key);
  const data = subject ? subjectData(subject) : (live || {});
  const reports = relatedReportsFor("noaa-subject", key);
  if (!subject && !live) return missingDetail("NOAA Subject", key, reports);
  return {
    kind: subject ? "NOAA Subject" : "Live NOAA Event",
    title: (subject || {}).subject || data.event || data.headline || key,
    sections: [
      !subject ? detailMessage("Live row shown; Subject History/Reports have not materialized this item in the loaded view yet.") : null,
      detailSection("Alert", [
        ["Event", data.event],
        ["Headline", data.headline],
        ["Type", subject ? subjectTypeLabel(subject) : noaaLiveTypeLabel(data)],
        ["Kind", data.alert_kind],
        ["Severity", subject ? noaaSubjectSeverity(subject) : noaaSeverityText(data)],
        ["Status", data.status],
        ["Message Type", data.message_type],
        ["NHC System", data.nhc_system],
        ["Advisory", data.nhc_advisory_number],
        ["Storm ID", data.nhc_storm_id]
      ]),
      (noaaProductsText(data) || noaaProductLinksNode(data)) ? detailSection("NHC Products", [
        ["Products", noaaProductsText(data)],
        ["Product URLs", noaaProductLinksNode(data)]
      ]) : null,
      data.alert_kind === "tsunami" ? detailSection("Tsunami", [
        ["Message", data.message_number],
        ["Category", data.tsunami_category],
        ["Magnitude", noaaTsunamiText(data)],
        ["Depth", numericEvidence(data.depth_km) !== null ? `${numericEvidence(data.depth_km).toFixed(1)} km` : ""],
        ["Event Time", data.event_time],
        ["Incident", data.incident_id],
        ["Identifier", data.tsunami_identifier],
        ["Product Code", data.product_code],
        ["CAP URL", data.cap_url],
        ["JSON URL", data.json_url],
        ["Resources", compactList(data.resource_urls || [], 8)],
        ["Maps", compactList(data.map_urls || [], 4)]
      ]) : null,
      detailSection("Area / Timing", [
        ["Area", data.area_desc],
        ["Coordinates", formatLatLon(data.latitude, data.longitude)],
        ["Effective", data.effective],
        ["Onset", data.onset],
        ["Expires", data.expires],
        ["Ends", data.ends],
        ["Updated", data.updated],
        ["Forecast Generated", data.forecast_generated],
        ["Forecast Window", data.forecast_window_hours ? `${data.forecast_window_hours}h` : ""]
      ]),
      detailSection("Forecast", [
        ["Current", data.current_forecast],
        ["Temperature", noaaForecastTemperatureText(data)],
        ["Precipitation", noaaForecastPrecipText(data)],
        ["Wind", noaaForecastWindText(data)],
        ["Next Precip", noaaForecastNextPrecipText(data)],
        ["Changes", noaaForecastDeltaText(data)],
        ["Previous Forecast", data.previous_forecast_generated],
        ["Period", timeRangeText(data.first_period_start, data.last_period_end)]
      ]),
      detailSection("Source", [
        ["Source", data.source],
        ["Basin", data.basin],
        ["URL", data.source_url],
        ["Internet-fed", data.internet_fed ? "yes" : ""],
        ["Updates", data.update_count]
      ]),
      detailSection("Observed", [
        ["First Seen", (subject || {}).first_seen || data.first_seen],
        ["Last Seen", (subject || {}).last_seen || data.last_seen]
      ]),
      reportsSection(reports)
    ].filter(Boolean)
  };
}

function buildUsgsSubjectDetail(key) {
  const subject = findUsgsHistorySubject(key);
  const reports = relatedReportsFor("usgs-subject", key);
  if (!subject) return missingDetail("USGS Subject", key, reports);
  const data = subjectData(subject);
  return {
    kind: "USGS Subject",
    title: subject.subject || data.place || key,
    sections: [
      detailSection("Earthquake", [
        ["Event ID", data.event_id],
        ["Magnitude", usgsMagnitudeText(data)],
        ["Place", data.place],
        ["Status", data.status],
        ["Alert", usgsAlertText(data)]
      ]),
      detailSection("Location", [
        ["Coordinates", usgsSubjectLocation(subject)],
        ["Depth", data.depth_km !== undefined ? `${data.depth_km} km` : ""],
        ["Distance", data.distance_km !== undefined ? `${Number(data.distance_km).toFixed(1)} km` : ""]
      ]),
      detailSection("Timing", [
        ["Event Time", data.event_time],
        ["Updated", data.updated],
        ["First Seen", subject.first_seen || data.first_seen],
        ["Last Seen", subject.last_seen || data.last_seen],
        ["Updates", data.update_count]
      ]),
      detailSection("Source", [
        ["Feed", data.feed_label || data.feed],
        ["Scope", usgsScopeText(data)],
        ["URL", data.detail_url],
        ["Internet-fed", data.internet_fed ? "yes" : ""]
      ]),
      reportsSection(reports)
    ]
  };
}

function buildSwpcSubjectDetail(key) {
  const subject = findSwpcHistorySubject(key);
  const reports = relatedReportsFor("swpc-subject", key);
  if (!subject) return missingDetail("SWPC Subject", key, reports);
  const data = subjectData(subject);
  return {
    kind: "SWPC Subject",
    title: subject.subject || data.event || key,
    sections: [
      detailSection("Event", [
        ["Event ID", data.event_id],
        ["Type", subjectTypeLabel(subject)],
        ["Event", data.event],
        ["Level", swpcLevelText(data)],
        ["Summary", data.summary]
      ]),
      detailSection("Timing", [
        ["Event Time", data.event_time],
        ["Start", data.start_time],
        ["Peak", data.peak_time],
        ["End", data.end_time],
        ["Issue Time", data.issue_time],
        ["First Seen", subject.first_seen || data.first_seen],
        ["Last Seen", subject.last_seen || data.last_seen],
        ["Updates", data.update_count]
      ]),
      detailSection("Source", [
        ["Source", data.source],
        ["Product", data.product_id],
        ["URL", data.source_url]
      ]),
      reportsSection(reports)
    ]
  };
}

function buildPwsSubjectDetail(key) {
  const subject = findPwsHistorySubject(key);
  const live = subject ? null : findPwsLiveEvent(key);
  const data = subject ? subjectData(subject) : (live || {});
  const reports = relatedReportsFor("pws-subject", key);
  if (!subject && !live) return missingDetail("PWS Subject", key, reports);
  return {
    kind: subject ? "PWS Subject" : "Live PWS Event",
    title: (subject || {}).subject || data.station_id || data.station_name || key,
    sections: [
      !subject ? detailMessage("Live row shown; Subject History/Reports have not materialized this item in the loaded view yet.") : null,
      detailSection("Station", [
        ["Station", data.station_id],
        ["Name", data.station_name],
        ["MAC", data.mac_address],
        ["Model", data.model],
        ["Location", data.location_name],
        ["Coordinates", formatLatLon(data.latitude, data.longitude)],
        ["Elevation", pwsElevationText(data)]
      ]),
      detailSection("Weather", [
        ["Sample Time", displayTimestamp(data, "event_time")],
        ["API Date", displayTimestamp(data, "ambient_date")],
        ["Timezone", data.timezone],
        ["Temperature", pwsWeatherText(data, {includeIndoor: false})],
        ["Indoor", pwsIndoorText(data)],
        ["Wind", pwsWindText(data)],
        ["Rain", pwsRainText(data)],
        ["Last Rain", pwsLastRainText(data)],
        ["Pressure", pwsPressureText(data)],
        ["Solar / UV", pwsSolarText(data)],
        ["Battery", data.battery]
      ]),
      detailSection("Observed", [
        ["First Seen", (subject || {}).first_seen || data.first_seen],
        ["Last Seen", (subject || {}).last_seen || data.last_seen],
        ["Observations", data.observation_count],
        ["Updates", data.update_count]
      ]),
      detailSection("Source", [
        ["Source", data.source],
        ["URL", data.source_url]
      ]),
      reportsSection(reports)
    ].filter(Boolean)
  };
}

function buildAdsbSubjectDetail(key) {
  const subject = findAdsbHistorySubject(key);
  const live = subject ? null : findAdsbLiveEvent(key);
  const data = subject ? subjectData(subject) : (live || {});
  const reports = relatedReportsFor("adsb-subject", key);
  if (!subject && !live) return missingDetail("ADS-B Subject", key, reports);
  return {
    kind: subject ? "ADS-B Subject" : "Live ADS-B Aircraft",
    title: (subject || {}).subject || [data.callsign, data.airline_icao ? `(${data.airline_icao})` : "", data.icao].filter(Boolean).join(" ") || key,
    sections: [
      !subject ? detailMessage("Live row shown; Subject History/Reports have not materialized this item in the loaded view yet.") : null,
      detailSection("Aircraft", [
        ["ICAO", data.icao],
        ["Callsign", data.callsign],
        ["Airline ICAO", data.airline_icao],
        ["Category", data.category],
        ["Squawk", data.squawk],
        ["Emergency", data.emergency ? "yes" : ""]
      ]),
      detailSection("Position / Motion", [
        ["Position", adsbPositionText(data)],
        ["Altitude", adsbAltitudeText(data)],
        ["Air / Ground", adsbAirGroundText(data)],
        ["CPR", adsbCprText(data)],
        ["Position Source", data.position_source || ""],
        ["State / Motion", adsbStateMotionText(data)],
        ["Distance", adsbDistanceText(data)],
        ["Path Span", data.path_span_km !== undefined ? `${data.path_span_km} km` : ""],
        ["Approach Context", adsbApproachText(data)]
      ]),
      detailSection("Observed", [
        ["First Seen", (subject || {}).first_seen || data.first_seen],
        ["Last Seen", (subject || {}).last_seen || data.last_seen],
        ["Updates", data.seen_count],
        ["Positions", data.position_count],
        ["Messages", data.messages],
        ["RSSI", data.rssi_dbfs !== undefined ? `${data.rssi_dbfs} dBFS` : ""],
        ["Local Passes", data.session_count || data.pass_count],
        ["Pass Spans", compactList(data.session_spans || [], 6)],
        ["Route Samples", compactList(data.route_samples || [], 6)]
      ]),
      detailSection("Source", [
        ["Decoder", data.decoder],
        ["Source", data.source]
      ]),
      reportsSection(reports)
    ].filter(Boolean)
  };
}

function buildRtl433SubjectDetail(key) {
  const subject = findRtl433HistorySubject(key);
  const live = subject ? null : findRtl433LiveEvent(key);
  const data = subject ? subjectData(subject) : (live || {});
  const reports = relatedReportsFor("rtl433-subject", key);
  if (!subject && !live) return missingDetail("RTL-433 Subject", key, reports);
  return {
    kind: subject ? "RTL-433 Subject" : "Live RTL-433 Event",
    title: (subject || {}).subject || rtl433SubjectLabel(data) || key,
    sections: [
      !subject ? detailMessage("Live row shown; Subject History/Reports have not materialized this item in the loaded view yet.") : null,
      detailSection("Subject", [
        ["Model", data.model],
        ["ID", data.id],
        ["Channel", data.channel],
        ["Protocol", data.protocol],
        ["Category", rtl433CategoryText(data)],
        ["Subject Key", data.subject_key || key]
      ]),
      detailSection("Signal", [
        ["Frequency / Signal", rtl433SignalText(data)],
        ["Frequency Plan", data.frequency_plan],
        ["Event Time", displayTimestamp(data, "event_time") || data.event_time]
      ]),
      rtl433TpmsDetailSection(data),
      detailSection("Observed", [
        ["First Seen", (subject || {}).first_seen || data.first_seen],
        ["Last Seen", (subject || {}).last_seen || data.last_seen],
        ["Events", data.event_count || data.seen_count],
        ["Bursts", data.burst_count],
        ["Sample Times", compactList(data.sample_times || [], 8)]
      ]),
      detailSection("Patterns", [
        ["Day / Night", counterMapText(data.day_night_counts, "")],
        ["Hours", counterMapText(data.hour_histogram, "h")],
        ["Weekdays", counterMapText(data.weekday_histogram, "")],
        ["Frequencies", counterMapText(data.frequency_counts, " MHz")],
        ["Burst Gaps", rtl433BurstGapText(data)],
        ["Recent Observations", rtl433RecentObservationsText(data.recent_observations)]
      ]),
      detailSection("Decoded Fields", [
        ["Latest Fields", rtl433DetailsText(data)],
        ["Raw", rtl433RawDetailText(data.raw || data.latest_raw || data.sample_fields || {})]
      ]),
      reportsSection(reports)
    ].filter(Boolean)
  };
}


function rtl433TpmsDetailSection(data) {
  if (String((data || {}).category || "").toLowerCase() !== "tpms") return null;
  return detailSection("TPMS", [
    ["Interpretation", data.tpms_interpretation],
    ["Pressure", rtl433TpmsPressureText(data)],
    ["Temperature", rtl433TpmsTemperatureText(data)],
    ["Battery", data.battery_status || compactList(data.tpms_battery_statuses || [], 6)],
    ["Status", data.tpms_status || compactList(data.tpms_statuses || [], 6)],
    ["Position", data.tpms_position],
    ["Samples", rtl433TpmsSamplesText(data.tpms_samples)]
  ]);
}

function rtl433TpmsPressureText(data) {
  const item = data || {};
  const parts = [];
  if (item.pressure_psi !== undefined) parts.push(`${item.pressure_psi} psi`);
  if (item.pressure_psi_min !== undefined || item.pressure_psi_max !== undefined) {
    parts.push(`range ${valueOrDash(item.pressure_psi_min)}-${valueOrDash(item.pressure_psi_max)} psi`);
  }
  if (item.pressure_kpa !== undefined) parts.push(`${item.pressure_kpa} kPa`);
  return parts.join("; ");
}

function rtl433TpmsTemperatureText(data) {
  const item = data || {};
  const parts = [];
  if (item.temperature_f !== undefined) parts.push(`${item.temperature_f} F`);
  if (item.temperature_f_min !== undefined || item.temperature_f_max !== undefined) {
    parts.push(`range ${valueOrDash(item.temperature_f_min)}-${valueOrDash(item.temperature_f_max)} F`);
  }
  if (item.temperature_c !== undefined) parts.push(`${item.temperature_c} C`);
  return parts.join("; ");
}

function rtl433TpmsSamplesText(samples) {
  return compactList((samples || []).map((sample) => {
    const parts = [
      sample.time || "",
      sample.pressure_psi !== undefined ? `${sample.pressure_psi} psi` : "",
      sample.temperature_f !== undefined ? `${sample.temperature_f} F` : "",
      sample.battery_status ? `battery ${sample.battery_status}` : "",
      sample.tpms_status ? `status ${sample.tpms_status}` : ""
    ].filter(Boolean);
    return parts.join(" | ");
  }), 8);
}

function valueOrDash(value) {
  return value === undefined || value === null || value === "" ? "?" : value;
}

function rtl433RawDetailText(raw) {
  const rows = Object.keys(raw || {}).sort().map((key) => `${key}: ${rtl433ValueText(raw[key])}`);
  return rows.length ? compactList(rows, 16) : "";
}

function buildLanSubjectDetail(key) {
  const subject = findLanHistorySubject(key);
  const reports = relatedReportsFor("lan-subject", key);
  if (!subject) return missingDetail("LAN Subject", key, reports);
  const data = subjectData(subject);
  return {
    kind: "LAN Subject",
    title: subject.subject || data.hostname || data.mac || data.gateway_ip || key,
    sections: [
      detailSection("Identity", [
        ["Annotation", annotationText(subject) || annotationText(data)],
        ["Type", subjectTypeLabel(subject)],
        ["MAC", data.mac],
        ["IPs", compactList(data.ips || data.gateway_ips || (data.ip ? [data.ip] : data.gateway_ip ? [data.gateway_ip] : []), 8)],
        ["Hostnames", compactList(data.hostnames || (data.hostname ? [data.hostname] : []), 8)],
        ["MAC Aliases", compactList(data.mac_aliases || [], 8)],
        ["Vendor", data.vendor_name || data.vendor_prefix],
        ["Gateway", data.gateway ? "yes" : ""]
      ]),
      detailSection("Network", [
        ["Interfaces", compactList(data.interfaces || (data.interface ? [data.interface] : []), 8)],
        ["Families", compactList(data.families || (data.family ? [data.family] : []), 8)],
        ["States", compactList(data.states || (data.state ? [data.state] : []), 8)],
        ["Sources", compactList(data.sources || [], 8)],
        ["Services", compactList(data.services || [], 8)],
        ["Locations", compactList(data.locations || [], 4)],
        ["Servers", compactList(data.servers || [], 4)],
        ["Gateway IPs", compactList(data.gateway_ips || (data.gateway_ip ? [data.gateway_ip] : []), 8)]
      ]),
      detailSection("Observed", [
        ["First Seen", subject.first_seen || data.first_seen],
        ["Last Seen", subject.last_seen || data.last_seen],
        ["Observations", data.observation_count],
        ["Changes", data.change_count],
        ["Latest Change", data.change_type]
      ]),
      data.grouped_randomized ? groupMembersTable(data, "lan") : null,
      reportsSection(reports)
    ].filter(Boolean)
  };
}

function buildBluetoothDetail(mac) {
  const device = findBluetoothHistoryDevice(mac);
  const reports = relatedReportsFor("bluetooth-device", mac);
  if (!device) {
    return missingDetail("Bluetooth Device", mac, reports);
  }
  return {
    kind: "Bluetooth Device",
    title: mac,
    sections: [
      detailSection("Identity", [
        ["Annotation", annotationText(device)],
        ["MAC", device.mac],
        ["Type", bluetoothDeviceType(device)],
        ["Transport", valueList(device.transports).join(", ")],
        ["Identity", bleDeviceIdentity(device)],
        ["Find My", device.findmy_accessory ? (device.findmy_label || "Apple Find My accessory") : ""],
        ["Find My Payload", findmyPayloadText(device)],
        ["Services / UUIDs", bluetoothServiceList(device.service_uuids)],
        ["Model", device.model_number],
        ["Serial", device.serial_number],
        ["Firmware", device.firmware_revision],
        ["PnP ID", device.pnp_id]
      ]),
      detailSection("Observed", [
        ["First Seen", device.first_seen],
        ["Last Seen", device.last_seen],
        ["Signal", signalRange(device)],
        ["BLE Seen", Number(device.seen_count || 0)],
        ["BLE Updates", Number(device.update_count || 0)],
        ["BLE Lost", Number(device.lost_count || 0)],
        ["Classic Seen", Number(device.classic_seen_count || 0)],
        ["Sessions", sessionCount(device)],
        ["Insights", device.finding_count]
      ]),
      device.grouped_randomized ? groupMembersTable(device, "bluetooth") : null,
      reportsSection(reports)
    ].filter(Boolean)
  };
}

function bluetoothDeviceType(device) {
  const item = device || {};
  const transports = valueList(item.transports).map((value) => String(value || "").toLowerCase());
  const types = [];
  if (transports.some((value) => value.includes("ble")) || Number(item.seen_count || 0) || Number(item.update_count || 0) || Number(item.lost_count || 0)) {
    types.push("BLE");
  }
  if (transports.some((value) => value.includes("classic")) || Number(item.classic_seen_count || 0)) {
    types.push("Classic");
  }
  return types.length ? types.join(" + ") : "Unknown";
}

function findmyPayloadText(device) {
  const item = device || {};
  return [
    item.findmy_payload_type ? `type ${item.findmy_payload_type}` : "",
    item.findmy_status ? `status ${item.findmy_status}` : "",
    item.findmy_hint ? `hint ${item.findmy_hint}` : ""
  ].filter(Boolean).join(", ");
}

function buildWifiSsidDetail(ssid) {
  const aps = wifiHistoryAccessPoints().filter((ap) =>
    (ap.ssid || "(blank)") === (ssid || "(blank)")
  );
  const reports = relatedReportsFor("wifi-ssid", ssid || "(blank)");
  if (!aps.length) return missingDetail("Wi-Fi SSID", ssid, reports);
  const vendors = uniqueValues(aps.map(vendorLabel));
  const channels = uniqueValues(aps.flatMap(wifiApChannels));
  const encryption = uniqueValues(aps.flatMap(wifiApEncryption));
  return {
    kind: "Wi-Fi SSID",
    title: ssid || "(blank)",
    sections: [
      detailSection("Network", [
        ["SSID", ssid || "(blank)"],
        ["BSSIDs", aps.length],
        ["Vendors", vendors.join(", ")],
        ["Channels / Freq", channelFreqList(channels)],
        ["Encryption", encryption.join(", ")],
        ["Strongest Signal", strongestSignalText(aps)]
      ]),
      detailApTable(aps),
      reportsSection(reports)
    ]
  };
}

function buildWifiBssidDetail(bssid) {
  const ap = findWifiHistoryAp(bssid);
  const reports = relatedReportsFor("wifi-bssid", bssid);
  if (!ap) return missingDetail("Wi-Fi BSSID", bssid, reports);
  return {
    kind: "Wi-Fi BSSID",
    title: bssid,
    sections: [
      detailSection("Access Point", [
        ["Annotation", annotationText(ap)],
        ["SSID", ap.ssid || "(blank)"],
        ["BSSID", ap.bssid],
        ["Vendor", vendorLabel(ap)],
        ["Channels / Freq", channelFreqList(wifiApChannels(ap))],
        ["Encryption", wifiApEncryption(ap).join(", ")],
        ["Signal", signalRange(ap)]
      ]),
      detailSection("Observed", [
        ["First Seen", ap.first_seen],
        ["Last Seen", ap.last_seen],
        ["Seen", ap.observations],
        ["Sessions", sessionCount(ap)],
        ["Insights", ap.finding_count]
      ]),
      reportsSection(reports)
    ]
  };
}

function buildWifiClientDetail(mac) {
  const client = findWifiHistoryClient(mac);
  const reports = relatedReportsFor("wifi-client", mac);
  if (!client) return missingDetail("Wi-Fi Client", mac, reports);
  return {
    kind: "Wi-Fi Client",
    title: mac,
    sections: [
      detailSection("Identity", [
        ["Annotation", annotationText(client)],
        ["MAC", client.mac],
        ["Vendor", vendorLabel(client)],
        ["Probed SSIDs", ssidList(client.ssids, client.randomized_mac)]
      ]),
      detailSection("Monitor Activity", [
        ["Probe Requests", client.probe_count || 0],
        ["Associations", client.association_count || 0],
        ["Deauth Frames", client.deauth_count || 0],
        ["Disassociation Frames", client.disassoc_count || 0],
        ["Signal", signalRange(client)]
      ]),
      detailSection("Observed", [
        ["First Seen", client.first_seen],
        ["Last Seen", client.last_seen],
        ["Findings", client.finding_count || 0]
      ]),
      client.grouped_randomized ? groupMembersTable(client, "wifi") : null,
      reportsSection(reports)
    ].filter(Boolean)
  };
}

function missingDetail(kind, key, reports) {
  return {
    kind,
    title: String(key || "Unknown"),
    sections: [
      detailMessage("No matching Subject History row is loaded for this item."),
      reportsSection(reports)
    ]
  };
}

function findNoaaLiveEvent(key) {
  const normalized = String(key || "").toLowerCase();
  return (rows.noaa || []).find((item) => {
    const values = [
      noaaLiveEventKey(item),
      item.event_id,
      item.source_event_id,
      item.source_url,
      item.event,
      item.headline
    ];
    return values.some((value) => String(value || "").toLowerCase() === normalized);
  });
}

function findPwsLiveEvent(key) {
  const normalized = String(key || "").toLowerCase();
  return (rows.pws || []).find((item) => {
    const values = [
      pwsLiveEventKey(item),
      item.station_id,
      item.station_name,
      item.mac_address
    ];
    return values.some((value) => String(value || "").toLowerCase() === normalized);
  });
}

function findAdsbLiveEvent(key) {
  const normalized = String(key || "").toUpperCase();
  return (rows.adsb || []).find((item) => adsbLiveEventKey(item) === normalized);
}

function findRtl433LiveEvent(key) {
  const normalized = String(key || "").toLowerCase();
  return (rows.rtl433 || []).find((item) => rtl433LiveEventKey(item) === normalized);
}

function noaaLiveTypeLabel(item) {
  const type = String((item || {}).event_type || (item || {}).alert_kind || "");
  return type.replace(/^noaa_/, "").replace(/_/g, " ");
}

function detailSection(title, rows) {
  const section = document.createElement("section");
  section.className = "detail-section";
  const heading = document.createElement("h3");
  heading.textContent = title;
  section.appendChild(heading);
  const list = document.createElement("dl");
  list.className = "detail-list";
  rows
    .filter((row) => row[1] !== "" && row[1] !== null && row[1] !== undefined)
    .forEach(([label, value]) => {
      const term = document.createElement("dt");
      term.textContent = label;
      const detail = document.createElement("dd");
      appendDetailValue(detail, label, value);
      list.appendChild(term);
      list.appendChild(detail);
    });
  section.appendChild(list);
  return section;
}

function appendDetailValue(detail, label, value) {
  if (value instanceof Node) {
    detail.appendChild(value);
    return;
  }
  if (value && value.node instanceof Node) {
    detail.appendChild(value.node);
    return;
  }
  const text = String(value);
  if (String(label || "").toLowerCase().includes("url") && /^https?:\/\//i.test(text)) {
    detail.appendChild(externalLink(text, text).node);
    return;
  }
  appendMapLinkedText(detail, text);
}

function detailApTable(aps) {
  const section = document.createElement("section");
  section.className = "detail-section";
  const heading = document.createElement("h3");
  heading.textContent = "BSSID Radios";
  section.appendChild(heading);
  const table = document.createElement("table");
  table.className = "detail-table detail-bssid-radios";
  table.innerHTML = "<thead><tr><th>BSSID</th><th>Vendor</th><th>Channels / Freq</th><th>Encryption</th><th>Signal</th><th>Last Seen</th></tr></thead>";
  const tbody = document.createElement("tbody");
  aps
    .slice()
    .sort(compareWifiAccessPoints)
    .forEach((ap) => {
      const tr = document.createElement("tr");
      [
        detailLink(ap.bssid || "", "wifi-bssid", ap.bssid || ""),
        vendorLabel(ap),
        channelFreqList(wifiApChannels(ap)),
        wifiApEncryption(ap).join(", "),
        signalRange(ap),
        ap.last_seen || ""
      ].forEach((value) => {
        const td = document.createElement("td");
        appendTableCellValue(td, value);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  table.appendChild(tbody);
  section.appendChild(table);
  return section;
}

function groupMembersTable(item, source) {
  const members = groupMembers(item);
  if (!members.length) return detailMessage("No bounded member evidence is available for this grouped row.");
  const section = document.createElement("section");
  section.className = "detail-section";
  const heading = document.createElement("h3");
  heading.textContent = "Grouped Members";
  section.appendChild(heading);
  const table = document.createElement("table");
  table.className = "detail-table detail-group-members";
  table.innerHTML = "<thead><tr><th>MAC</th><th>Identity</th><th>First Seen</th><th>Last Seen</th><th>Counts</th><th>Signal</th><th>State</th></tr></thead>";
  const tbody = document.createElement("tbody");
  members.slice(0, 24).forEach((member) => {
    const tr = document.createElement("tr");
    [
      member.mac || "",
      groupMemberIdentityText(member, source),
      member.first_seen || "",
      member.last_seen || "",
      groupMemberCountsText(member, source),
      signalRange(member),
      groupMemberStateText(member, source)
    ].forEach((value) => {
      const td = document.createElement("td");
      appendTableCellValue(td, value);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  section.appendChild(table);
  return section;
}

function groupMembers(item) {
  return Array.isArray((item || {}).group_members) ? (item || {}).group_members : [];
}

function groupMemberIdentityText(member, source) {
  if (source === "wifi") {
    return [member.identity || "", ssidList(member.ssids || [], true)].filter(Boolean).join("; ");
  }
  if (source === "bluetooth") {
    return [member.identity || "", compactList(member.names || [], 4), bluetoothServiceList(member.service_uuids || [])].filter(Boolean).join("; ");
  }
  if (source === "lan") {
    return [member.identity || "", compactList(member.ips || [], 4), compactList(member.sources || [], 4)].filter(Boolean).join("; ");
  }
  return member.identity || "";
}

function groupMemberCountsText(member, source) {
  if (source === "wifi") {
    return [
      member.probe_count ? `${member.probe_count} probe` : "",
      member.association_count ? `${member.association_count} assoc` : "",
      member.deauth_count ? `${member.deauth_count} deauth` : "",
      member.disassoc_count ? `${member.disassoc_count} disassoc` : ""
    ].filter(Boolean).join("; ");
  }
  if (source === "bluetooth") {
    return [
      member.seen_count ? `${member.seen_count} seen` : "",
      member.update_count ? `${member.update_count} upd` : "",
      member.lost_count ? `${member.lost_count} lost` : "",
      member.classic_seen_count ? `${member.classic_seen_count} classic` : "",
      member.session_count ? `${member.session_count} sess` : ""
    ].filter(Boolean).join("; ");
  }
  if (source === "lan") {
    return [
      member.observation_count ? `${member.observation_count} obs` : "",
      member.identify_count ? `${member.identify_count} ident` : "",
      member.change_count ? `${member.change_count} change` : ""
    ].filter(Boolean).join("; ");
  }
  return "";
}

function groupMemberStateText(member, source) {
  if (source === "bluetooth" && member.active_session) return "active session";
  if (source === "lan") return compactList(member.interfaces || [], 4);
  return "";
}

function reportsSection(reports) {
  const section = document.createElement("section");
  section.className = "detail-section";
  const heading = document.createElement("h3");
  heading.textContent = "Related Reports";
  section.appendChild(heading);
  if (!reports.length) {
    const message = document.createElement("div");
    message.className = "status-strip muted";
    message.textContent = "No related report rows in the current view.";
    section.appendChild(message);
    return section;
  }
  const table = document.createElement("table");
  table.className = "detail-table detail-related-reports";
  table.innerHTML = "<thead><tr><th>Score</th><th>Category</th><th>Report</th><th>Summary</th><th>Last Seen</th></tr></thead>";
  const tbody = document.createElement("tbody");
  reports.forEach((report) => {
    const tr = document.createElement("tr");
    [
      report.score || 0,
      categoryForType(report.type || "report"),
      report.title || "",
      report.summary || "",
      report.last_seen || ""
    ].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  section.appendChild(table);
  return section;
}

function detailMessage(text) {
  const message = document.createElement("div");
  message.className = "status-strip muted";
  message.textContent = text;
  return message;
}

function relatedReportsFor(type, key) {
  const reports = (latestReports || {}).reports || [];
  return reports.filter((report) => reportMatchesDetail(report, type, key));
}

function reportMatchesDetail(report, type, key) {
  const evidence = (report || {}).evidence || {};
  const reportType = String((report || {}).type || "").toLowerCase();
  const normalizedKey = String(key || "").toLowerCase();
  if (type === "bluetooth-device") {
    return String(evidence.mac || "").toLowerCase() === normalizedKey ||
      valueList(evidence.sample_macs).some((mac) => String(mac).toLowerCase() === normalizedKey);
  }
  if (type === "wifi-bssid") {
    const ap = findWifiHistoryAp(key);
    return String(evidence.bssid || "").toLowerCase() === normalizedKey ||
      valueList(evidence.bssids).some((bssid) => String(bssid).toLowerCase() === normalizedKey) ||
      (ap && reportType === "wifi_ssid_profile" && evidence.ssid &&
        String(evidence.ssid || "(blank)").toLowerCase() ===
          String(ap.ssid || "(blank)").toLowerCase());
  }
  if (type === "wifi-client") {
    return String(evidence.mac || "").toLowerCase() === normalizedKey ||
      String(evidence.client_mac || "").toLowerCase() === normalizedKey ||
      String(evidence.transmitter_mac || "").toLowerCase() === normalizedKey;
  }
  if (type === "wifi-ssid") {
    return String(evidence.ssid || "(blank)").toLowerCase() === normalizedKey;
  }
  if (type === "aprsis-subject") {
    return String(evidence.callsign || "").toLowerCase() === normalizedKey ||
      String((report || {}).subject || "").toLowerCase().includes(normalizedKey);
  }
  if (type === "rayhunter-subject") {
    return String(evidence.endpoint || "").toLowerCase() === normalizedKey ||
      String((report || {}).subject || "").toLowerCase().includes(normalizedKey);
  }
  if (type === "noaa-subject") {
    return String(evidence.event_id || "").toLowerCase() === normalizedKey ||
      String(evidence.source_event_id || "").toLowerCase() === normalizedKey ||
      String(evidence.source_url || "").toLowerCase() === normalizedKey ||
      noaaLiveEventKey({
        ...evidence,
        event_type: evidence.alert_kind === "forecast"
          ? "noaa_forecast_summary"
          : evidence.alert_kind === "tsunami"
          ? "noaa_tsunami_alert"
          : evidence.alert_kind === "tropical" || evidence.alert_kind === "tropical_outlook"
          ? "noaa_tropical_advisory"
          : "noaa_weather_alert"
      }).toLowerCase() === normalizedKey ||
      String((report || {}).subject || "").toLowerCase().includes(normalizedKey);
  }
  if (type === "usgs-subject") {
    return String(evidence.event_id || "").toLowerCase() === normalizedKey ||
      String((report || {}).subject || "").toLowerCase().includes(normalizedKey);
  }
  if (type === "swpc-subject") {
    return String(evidence.event_id || "").toLowerCase() === normalizedKey ||
      String((report || {}).subject || "").toLowerCase().includes(normalizedKey);
  }
  if (type === "pws-subject") {
    return String(evidence.station_id || "").toLowerCase() === normalizedKey ||
      String(evidence.station_name || "").toLowerCase() === normalizedKey ||
      String(evidence.mac_address || "").toLowerCase() === normalizedKey ||
      String((report || {}).subject || "").toLowerCase().includes(normalizedKey);
  }
  if (type === "adsb-subject") {
    return String(evidence.icao || "").toLowerCase() === normalizedKey ||
      String(evidence.callsign || "").toLowerCase() === normalizedKey ||
      String((report || {}).subject || "").toLowerCase().includes(normalizedKey);
  }
  if (type === "rtl433-subject") {
    return String(evidence.subject_key || "").toLowerCase() === normalizedKey ||
      String(evidence.model || "").toLowerCase() === normalizedKey ||
      String(evidence.id || "").toLowerCase() === normalizedKey ||
      String((report || {}).subject || "").toLowerCase().includes(normalizedKey);
  }
  if (type === "lan-subject") {
    return String(evidence.subject_key || "").toLowerCase() === normalizedKey ||
      String(evidence.mac || "").toLowerCase() === normalizedKey ||
      String(evidence.gateway_ip || "").toLowerCase() === normalizedKey ||
      valueList(evidence.gateway_ips).some((item) => String(item || "").toLowerCase() === normalizedKey) ||
      String((report || {}).subject || "").toLowerCase().includes(normalizedKey);
  }
  return false;
}

function wifiHistoryAccessPoints() {
  const wifi = (latestDeviceHistory || {}).wifi || {};
  const historyAps = wifi.access_points || [];
  return historyAps.length ? historyAps : [...rows.aps.values()];
}

function bluetoothHistoryDevices() {
  const bluetooth = (latestDeviceHistory || {}).bluetooth ||
    (latestDeviceHistory || {}).ble ||
    {};
  const historyDevices = bluetooth.devices || [];
  if (historyDevices.length) return historyDevices;
  const liveDevices = [...rows.ble.values()];
  const classicDevices = [...rows.btClassic.values()];
  return [...liveDevices, ...classicDevices];
}

function findWifiHistoryAp(bssid) {
  const normalized = String(bssid || "").toLowerCase();
  return wifiHistoryAccessPoints().find((ap) =>
    String(ap.bssid || "").toLowerCase() === normalized
  );
}

function findWifiHistoryClient(mac) {
  const normalized = String(mac || "").toLowerCase();
  const wifi = (latestDeviceHistory || {}).wifi || {};
  const historyClients = wifi.clients || [];
  const clients = historyClients.length ? historyClients : rows.monitorEvents;
  return clients.find((client) => {
    const data = client || {};
    return String(data.mac || data.client_mac || data.transmitter_mac || "").toLowerCase() === normalized ||
      String(data.group_key || "").toLowerCase() === normalized ||
      valueList(data.sample_macs).some((item) => String(item || "").toLowerCase() === normalized) ||
      groupMembers(data).some((item) => String(item.mac || "").toLowerCase() === normalized);
  });
}

function findBluetoothHistoryDevice(mac) {
  const normalized = String(mac || "").toLowerCase();
  return bluetoothHistoryDevices().find((device) => {
    const data = device || {};
    return String(data.mac || "").toLowerCase() === normalized ||
      String(data.group_key || "").toLowerCase() === normalized ||
      valueList(data.sample_macs).some((item) => String(item || "").toLowerCase() === normalized) ||
      groupMembers(data).some((item) => String(item.mac || "").toLowerCase() === normalized);
  });
}

function aprsisHistorySubjects() {
  return historySubjectsFor(latestDeviceHistory || {}, "aprsis");
}

function rayhunterHistorySubjects() {
  return historySubjectsFor(latestDeviceHistory || {}, "rayhunter");
}

function noaaHistorySubjects() {
  return historySubjectsFor(latestDeviceHistory || {}, "noaa");
}

function usgsHistorySubjects() {
  return historySubjectsFor(latestDeviceHistory || {}, "usgs");
}

function swpcHistorySubjects() {
  return historySubjectsFor(latestDeviceHistory || {}, "swpc");
}

function pwsHistorySubjects() {
  return historySubjectsFor(latestDeviceHistory || {}, "pws");
}

function adsbHistorySubjects() {
  return historySubjectsFor(latestDeviceHistory || {}, "adsb");
}

function rtl433HistorySubjects() {
  return historySubjectsFor(latestDeviceHistory || {}, "rtl433");
}

function lanHistorySubjects() {
  return historySubjectsFor(latestDeviceHistory || {}, "lan");
}

function findRayhunterHistorySubject(key) {
  const normalized = String(key || "").toLowerCase();
  return rayhunterHistorySubjects().find((subject) => {
    const data = subjectData(subject);
    return String(subject.subject || "").toLowerCase() === normalized ||
      String(subject.subject_id || "").toLowerCase() === normalized ||
      String(data.endpoint || "").toLowerCase() === normalized;
  });
}

function findAprsisHistorySubject(key) {
  const normalized = String(key || "").toLowerCase();
  return aprsisHistorySubjects().find((subject) => {
    const data = subjectData(subject);
    return String(subject.subject || "").toLowerCase() === normalized ||
      String(subject.subject_id || "").toLowerCase() === normalized ||
      String(data.callsign || "").toLowerCase() === normalized ||
      String(data.object_name || "").toLowerCase() === normalized;
  });
}

function findNoaaHistorySubject(key) {
  const normalized = String(key || "").toLowerCase();
  return noaaHistorySubjects().find((subject) => {
    const data = subjectData(subject);
    return String(subject.subject || "").toLowerCase() === normalized ||
      String(subject.subject_id || "").toLowerCase() === normalized ||
      String(data.event_id || "").toLowerCase() === normalized ||
      String(data.source_event_id || "").toLowerCase() === normalized ||
      String(data.incident_id || "").toLowerCase() === normalized ||
      String(data.tsunami_identifier || "").toLowerCase() === normalized ||
      String(data.source_url || "").toLowerCase() === normalized ||
      String(data.headline || "").toLowerCase() === normalized;
  });
}

function findUsgsHistorySubject(key) {
  const normalized = String(key || "").toLowerCase();
  return usgsHistorySubjects().find((subject) => {
    const data = subjectData(subject);
    return String(subject.subject || "").toLowerCase() === normalized ||
      String(subject.subject_id || "").toLowerCase() === normalized ||
      String(data.event_id || "").toLowerCase() === normalized;
  });
}

function findSwpcHistorySubject(key) {
  const normalized = String(key || "").toLowerCase();
  return swpcHistorySubjects().find((subject) => {
    const data = subjectData(subject);
    return String(subject.subject || "").toLowerCase() === normalized ||
      String(subject.subject_id || "").toLowerCase() === normalized ||
      String(data.event_id || "").toLowerCase() === normalized ||
      String(data.summary || "").toLowerCase() === normalized;
  });
}

function findPwsHistorySubject(key) {
  const normalized = String(key || "").toLowerCase();
  return pwsHistorySubjects().find((subject) => {
    const data = subjectData(subject);
    return String(subject.subject || "").toLowerCase() === normalized ||
      String(subject.subject_id || "").toLowerCase() === normalized ||
      String(data.station_id || "").toLowerCase() === normalized ||
      String(data.station_name || "").toLowerCase() === normalized ||
      String(data.mac_address || "").toLowerCase() === normalized;
  });
}

function findAdsbHistorySubject(key) {
  const normalized = String(key || "").toUpperCase();
  return adsbHistorySubjects().find((subject) => {
    const data = subjectData(subject);
    return String(subject.subject_id || "").toUpperCase() === normalized ||
      String(data.icao || "").toUpperCase() === normalized;
  });
}

function findRtl433HistorySubject(key) {
  const normalized = String(key || "").toLowerCase();
  return rtl433HistorySubjects().find((subject) => {
    const data = subjectData(subject);
    return String(subject.subject || "").toLowerCase() === normalized ||
      String(subject.subject_id || "").toLowerCase() === normalized ||
      String(data.subject_key || "").toLowerCase() === normalized;
  });
}

function findLanHistorySubject(key) {
  const normalized = String(key || "").toLowerCase();
  return lanHistorySubjects().find((subject) => {
    const data = subjectData(subject);
    return String(subject.subject || "").toLowerCase() === normalized ||
      String(subject.subject_id || "").toLowerCase() === normalized ||
      String(data.subject_key || "").toLowerCase() === normalized ||
      String(data.mac || "").toLowerCase() === normalized ||
      String(data.gateway_ip || "").toLowerCase() === normalized ||
      valueList(data.gateway_ips).some((item) => String(item || "").toLowerCase() === normalized) ||
      valueList(data.sample_macs).some((item) => String(item || "").toLowerCase() === normalized) ||
      groupMembers(data).some((item) => String(item.mac || "").toLowerCase() === normalized);
  });
}

function uniqueValues(values) {
  return [...new Set(valueList(values)
    .map((value) => String(value || "").trim())
    .filter(Boolean))].sort();
}

function strongestSignalText(items) {
  const values = (items || [])
    .map((item) => Number(item.signal_max))
    .filter((value) => !Number.isNaN(value));
  if (!values.length) return "";
  return `${Math.max(...values)} dBm`;
}

function setHistoryStatus(text, state) {
  const status = document.getElementById("history-status");
  if (!status) return;
  status.textContent = text;
  status.className = `status-strip ${state || "muted"}`;
}

function ssidList(ssids, randomized) {
  const items = valueList(ssids);
  const values = items.slice(0, uiNumber("max_history_ssids"));
  const suffix = items.length > values.length ? ` +${items.length - values.length}` : "";
  const prefix = randomized ? "randomized MAC | " : "";
  return `${prefix}${values.join(", ")}${suffix}`;
}

function signalRange(item) {
  const latest = formatSignal(
    item.signal_latest !== undefined ? item.signal_latest : item.rssi
  );
  const min = formatSignal(item.signal_min);
  const max = formatSignal(item.signal_max);
  if (!latest && !min && !max) return "";
  return `${latest} (${min}/${max})`;
}

function sessionCount(item) {
  if (!item) return 0;
  if (item.session_count !== undefined && item.session_count !== null) {
    return Number(item.session_count) || 0;
  }
  return (item.sessions || []).length;
}

function wifiApChannels(ap) {
  const item = ap || {};
  if (Array.isArray(item.channels)) return item.channels;
  if (item.channel !== undefined && item.channel !== null && item.channel !== "") {
    return [item.channel];
  }
  return [];
}

function wifiApEncryption(ap) {
  const value = (ap || {}).encryption;
  if (Array.isArray(value)) return value;
  if (value !== undefined && value !== null && value !== "") return [value];
  return [];
}

function channelFreq(channel, explicitBand) {
  if (channel === undefined || channel === null || channel === "") return "";
  const band = explicitBand || bandForChannel(channel);
  return band ? `${channel} / ${band}` : String(channel);
}

function channelFreqList(channels) {
  return valueList(channels).map((channel) => channelFreq(channel)).join(", ");
}

function bandForChannel(channel) {
  const value = Number(channel);
  if (!Number.isFinite(value)) return "";
  if (value >= 1 && value <= 14) return "2.4";
  if (value >= 30 && value <= 196) return "5";
  return "";
}

function renderHistoryAnalysis(analysis) {
  latestHistoryAnalysis = analysis;
  renderCombinedInsights();
}

function renderCombinedInsights() {
  const observations = ((latestHistoryAnalysis || {}).observations || []).map(normalizeObservationInsight);
  rows.insights = sortInsights(observations);
  updateInsightsStatus();
  renderInsights();
}

function sortInsights(items) {
  return (items || []).sort((left, right) => {
    const leftMs = recordTimestampMs(left, "timestamp");
    const rightMs = recordTimestampMs(right, "timestamp");
    if (leftMs && rightMs && leftMs !== rightMs) return rightMs - leftMs;
    if (leftMs && !rightMs) return -1;
    if (!leftMs && rightMs) return 1;
    const timestamp = String(right.timestamp || "").localeCompare(String(left.timestamp || ""));
    if (timestamp !== 0) return timestamp;
    return severityRank(right.severity) - severityRank(left.severity);
  });
}

function normalizeFindingInsight(finding) {
  const detail = finding.detail || "";
  return {
    timestamp: finding.timestamp || "",
    timestamp_epoch: finding.timestamp_epoch,
    severity: finding.severity || "",
    source: finding.source || "",
    type: finding.type || "finding",
    category: categoryForType(finding.type || "finding"),
    title: finding.title || "",
    detail,
    evidence_text: evidenceText(finding.attributes || {}, detail),
    activity_state: finding.activity_state || "",
    last_seen: finding.last_seen || finding.timestamp || "",
    last_seen_epoch: finding.last_seen_epoch || finding.timestamp_epoch,
    origin: "live event",
  };
}

function normalizeObservationInsight(observation) {
  const detail = observation.detail || "";
  return {
    timestamp: observation.timestamp || "",
    timestamp_epoch: observation.timestamp_epoch,
    severity: observation.severity || "",
    source: observation.source || "",
    type: observation.type || "observation",
    category: categoryForType(observation.type || "observation"),
    title: observation.title || "",
    detail,
    evidence_text: evidenceText(observation.evidence || {}, detail),
    activity_state: observation.activity_state || "",
    last_seen: observation.last_seen || "",
    last_seen_epoch: observation.last_seen_epoch,
    age_minutes: observation.age_minutes,
    origin: "subject history",
    score: observation.score || 0,
  };
}

function updateInsightsStatus() {
  const source = latestHistoryAnalysis || latestFindingsHistory || {};
  const window = source.window || {};
  const insightsWindow = source.insights_window || {};
  const refreshedAt = source.generated_at || source.refreshed_at;
  const refreshedEpoch = source.generated_at_epoch || source.refreshed_at_epoch;
  const total = rows.insights.length;
  const visible = rows.insights.filter(insightMatchesFilters).filter(insightMatchesSearch);
  const warnings = rows.insights.filter((item) => item.severity === "warning").length;
  const errors = rows.insights.filter((item) => item.severity === "error" || item.severity === "alert").length;
  const newestSeen = latestSeenStatusText(visible, ["last_seen", "timestamp"]);
  const normalState = derivedStatusState(
    refreshedAt,
    refreshedEpoch,
    visible.some((item) => item.severity === "warning" || item.severity === "error" || item.severity === "alert") ? "warning" : "ok"
  );
  setInsightsStatus(
    [
      insightsWindow.label || "",
      derivedStatusPrefix(window, refreshedAt, refreshedEpoch),
      newestSeen,
      `${visible.length} shown`,
      `${total} insights`,
      `${warnings} warnings`,
      `${errors} errors`
    ].filter(Boolean).join(" | "),
    derivedDataStatusState(visible, ["last_seen", "timestamp"], normalState)
  );
}

function categoryForType(type) {
  const text = String(type || "");
  if (text.includes("privacy")) return "privacy";
  if (text.includes("encryption") || text.includes("security") || text.includes("evil")) return "security";
  if (text.includes("strong") || text.includes("rssi") || text.includes("signal")) return "signal";
  if (text.includes("presence") || text.includes("returned") || text.includes("lost") || text.includes("linger") || text.includes("recurring") || text.includes("cluster") || text.endsWith("_new")) return "presence";
  if (text.includes("probe") || text.includes("deauth") || text.includes("randomized")) return "behavior";
  if (text.includes("identity") || text.includes("identify")) return "identity";
  if (text.includes("collector") || text.includes("missing")) return "collector";
  return "analysis";
}

function severityRank(severity) {
  return {"error": 3, "alert": 3, "warning": 2, "info": 1}[String(severity || "").toLowerCase()] || 0;
}

function reportEvidenceText(report) {
  return reportEvidenceItems(report)
    .map((item) => `${item.label}: ${item.value}`)
    .join(" | ");
}

function reportEvidenceItems(report) {
  const evidence = (report || {}).evidence || {};
  const source = String((report || {}).source || "").toLowerCase();
  const type = String((report || {}).type || "").toLowerCase();
  let items;
  if (source === "bluetooth" || type.startsWith("ble_")) {
    items = bluetoothReportEvidenceItems(evidence);
  } else if (source === "wifi" || type.startsWith("wifi_ap") || type.includes("ssid")) {
    items = wifiApReportEvidenceItems(evidence);
  } else if (source === "wifi_monitor" || type.startsWith("wifi_client")) {
    items = wifiClientReportEvidenceItems(evidence);
  } else if (source === "adsb" || type.startsWith("adsb")) {
    items = adsbReportEvidenceItems(evidence, type);
  } else if (source === "rayhunter" || type.startsWith("rayhunter")) {
    items = rayhunterReportEvidenceItems(evidence);
  } else if (source === "aprsis" || type.startsWith("aprsis")) {
    items = aprsisReportEvidenceItems(evidence);
  } else if (source === "noaa" || type.startsWith("noaa")) {
    items = noaaReportEvidenceItems(evidence);
  } else if (source === "usgs" || type.startsWith("usgs")) {
    items = usgsReportEvidenceItems(evidence);
  } else if (source === "swpc" || type.startsWith("swpc")) {
    items = swpcReportEvidenceItems(evidence);
  } else if (source === "pws" || type.startsWith("pws")) {
    items = pwsReportEvidenceItems(evidence);
  } else if (source === "rtl433" || type.startsWith("rtl433")) {
    items = rtl433ReportEvidenceItems(evidence, type);
  } else if (source === "lan" || type.startsWith("lan")) {
    items = lanReportEvidenceItems(evidence);
  } else {
    items = genericEvidenceItems(evidence, (report || {}).summary || "");
  }
  return dedupeReportEvidenceItems(items, report);
}

function dedupeReportEvidenceItems(items, report) {
  const context = reportDedupeContext(report);
  return (items || [])
    .map((item) => {
      const value = dedupeEvidenceValue(item, context);
      if (!value) return null;
      const key = normalizedEvidenceText(`${item.label}: ${value}`);
      if (key && context.seen.has(key)) return null;
      if (key) context.seen.add(key);
      return {...item, value};
    })
    .filter(Boolean);
}

function reportDedupeContext(report) {
  const visible = [
    sourceLabel((report || {}).source),
    (report || {}).confidence || "",
    compactList((report || {}).reason_tags || [], 6),
    (report || {}).title || "",
    (report || {}).subject || "",
    reportSummaryText(report),
    (report || {}).last_seen || ""
  ].filter(Boolean);
  return {
    text: normalizedEvidenceText(visible.join(" | ")),
    seen: new Set()
  };
}

function dedupeEvidenceValue(item, context) {
  const value = String((item || {}).value || "");
  if (!value) return "";
  const label = String((item || {}).label || "");
  if (["Pattern", "Observed", "Activity"].includes(label)) return value;
  const separator = label === "Findings" ? "," : ";";
  const segments = value.split(separator).map((part) => part.trim()).filter(Boolean);
  if (segments.length <= 1) {
    return evidenceSegmentAlreadyShown(value, context) ? "" : value;
  }
  const seen = new Set();
  const kept = segments.filter((segment) => {
    const normalized = normalizedEvidenceText(segment);
    if (!normalized || seen.has(normalized)) return false;
    seen.add(normalized);
    return !evidenceSegmentAlreadyShown(segment, context);
  });
  return kept.join(`${separator} `);
}

function evidenceSegmentAlreadyShown(segment, context) {
  const text = String(segment || "").trim();
  if (!text || text.includes("://")) return false;
  const candidates = [
    normalizedEvidenceText(text),
    normalizedEvidenceText(
      text.replace(/^(mac|id|source id|event|kind|area|source|feed|server|gateway|host|ip|iface|interface|vendor)\s+/i, "")
    )
  ].filter((item, index, array) => item && array.indexOf(item) === index);
  return candidates.some((candidate) => {
    if (candidate.length < 4) return false;
    return context.text.includes(candidate);
  });
}

function normalizedEvidenceText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, "")
    .replace(/[.,()]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function renderReportEvidenceCell(cell, items) {
  const evidenceItems = items || [];
  if (!evidenceItems.length) {
    cell.textContent = "";
    return;
  }
  const list = document.createElement("dl");
  list.className = "evidence-list";
  evidenceItems.forEach((item) => {
    const term = document.createElement("dt");
    term.textContent = item.label;
    const detail = document.createElement("dd");
    if (item.nowrap) detail.classList.add("evidence-nowrap");
    if (item.href) {
      const link = document.createElement("a");
      link.href = item.href;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = item.value;
      detail.appendChild(link);
    } else {
      appendMapLinkedText(detail, item.value);
    }
    list.appendChild(term);
    list.appendChild(detail);
  });
  cell.appendChild(list);
}

function evidenceText(evidence, detail) {
  return genericEvidenceText(evidence, detail);
}

function bluetoothReportEvidenceItems(evidence) {
  const parts = [];
  const signal = signalRangeText(evidence.signal_min, evidence.signal_max);
  const foldedSignal = findingsMentionStrongSignal(evidence.findings);
  const findings = findingsText(evidence.findings, signal, foldedSignal);
  if (findings) parts.push({label: "Findings", value: findings});
  const pattern = presencePatternText(evidence);
  if (pattern) parts.push({label: "Pattern", value: pattern});
  const observed = observedSessionText(evidence);
  if (observed) parts.push({label: "Observed", value: observed});
  const activity = bluetoothActivityText(evidence);
  if (activity) parts.push({label: "Activity", value: activity});
  const services = bluetoothServiceList(evidence.service_uuids);
  if (services) parts.push({label: "Services / UUIDs", value: services});
  if (signal && !foldedSignal) parts.push({label: "Signal", value: signal});
  if (evidence.sample_macs && evidence.sample_macs.length) {
    parts.push({label: "Samples", value: compactList(evidence.sample_macs, 6)});
  }
  return withCommonEvidenceItems(parts.length ? parts : genericEvidenceItems(evidence, ""), evidence);
}

function bluetoothActivityText(evidence) {
  const parts = [];
  if (evidence.address_count) {
    parts.push(`${evidence.address_count} private/randomized address(es)`);
  }
  if (evidence.active_addresses) {
    parts.push(`${evidence.active_addresses} active`);
  }
  return parts.join("; ");
}

function wifiApReportEvidenceItems(evidence) {
  const parts = [];
  const signal = signalRangeText(null, evidence.signal_max || evidence.strongest_signal);
  const foldedSignal = findingsMentionStrongSignal(evidence.findings);
  const findings = findingsText(evidence.findings, signal, foldedSignal);
  if (findings) parts.push({label: "Findings", value: findings});
  const radio = [
    evidence.channels && evidence.channels.length ? `channels ${compactList(evidence.channels, 8)}` : "",
    evidence.bands && evidence.bands.length ? `bands ${compactList(evidence.bands, 4)}` : "",
    evidence.bssid_count ? `${evidence.bssid_count} BSSIDs` : "",
    evidence.encryption && evidence.encryption.length ? `security ${compactList(evidence.encryption, 6)}` : "",
    signal && !foldedSignal ? `signal ${signal}` : ""
  ].filter(Boolean).join("; ");
  if (radio) parts.push({label: "Radio", value: radio});
  if (evidence.vendors && evidence.vendors.length) {
    parts.push({label: "Vendors", value: compactList(evidence.vendors, 4)});
  }
  const pattern = presencePatternText(evidence);
  if (pattern) parts.push({label: "Pattern", value: pattern});
  const observed = reportSessionSummaryText(evidence);
  if (observed) parts.push({label: "Observed", value: observed});
  return withCommonEvidenceItems(parts.length ? parts : genericEvidenceItems(evidence, ""), evidence);
}

function wifiClientReportEvidenceItems(evidence) {
  const parts = [];
  const client = [
    evidence.mac ? `MAC ${evidence.mac}` : "",
    evidence.vendor || ""
  ].filter(Boolean).join("; ");
  if (client) parts.push({label: "Client", value: client});
  const probes = [
    evidence.probe_count ? `${evidence.probe_count} probes` : "",
    evidence.probed_ssids && evidence.probed_ssids.length ? `SSIDs ${compactList(evidence.probed_ssids, 6)}` : ""
  ].filter(Boolean).join("; ");
  if (probes) parts.push({label: "Probes", value: probes});
  const activity = [
    evidence.association_count ? `${evidence.association_count} associations` : "",
    evidence.deauth_count ? `${evidence.deauth_count} deauth` : "",
    evidence.disassoc_count ? `${evidence.disassoc_count} disassoc` : ""
  ].filter(Boolean).join("; ");
  if (activity) parts.push({label: "Activity", value: activity});
  if (evidence.first_seen || evidence.last_seen) {
    parts.push({label: "Observed", value: timeRangeText(evidence.first_seen, evidence.last_seen)});
  }
  return withCommonEvidenceItems(parts.length ? parts : genericEvidenceItems(evidence, ""), evidence);
}

function adsbReportEvidenceItems(evidence, type) {
  if (type === "adsb_aircraft_population") {
    return adsbPopulationReportEvidenceItems(evidence);
  }
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const identity = [
    evidence.icao ? `ICAO ${evidence.icao}` : "",
    evidence.callsign ? `callsign ${evidence.callsign}` : "",
    evidence.airline_icao ? `airline ${evidence.airline_icao}` : "",
    evidence.squawk ? `squawk ${evidence.squawk}` : "",
    evidence.air_ground || ""
  ].filter(Boolean).join("; ");
  if (identity) parts.push({label: "Identity", value: identity});
  const altitude = [
    evidence.altitude_ft !== undefined ? `latest ${evidence.altitude_ft} ft` : "",
    evidence.min_altitude_ft !== undefined ? `min ${evidence.min_altitude_ft} ft` : "",
    evidence.altitude_baro_ft !== undefined ? `baro ${evidence.altitude_baro_ft} ft` : "",
    evidence.altitude_geom_ft !== undefined ? `geom ${evidence.altitude_geom_ft} ft` : ""
  ].filter(Boolean).join("; ");
  if (altitude) parts.push({label: "Altitude", value: altitude});
  const position = [
    evidence.distance_km !== undefined ? `${evidence.distance_km} km latest` : "",
    evidence.min_distance_km !== undefined ? `${evidence.min_distance_km} km closest` : "",
    evidence.path_span_km !== undefined ? `path ${evidence.path_span_km} km` : "",
    evidence.position_count ? `${evidence.position_count} position(s)` : "",
    evidence.position_source ? `source ${evidence.position_source}` : "",
    adsbApproachText(evidence)
  ].filter(Boolean).join("; ");
  if (position) parts.push({label: "Position", value: position});
  const motion = [
    evidence.speed_kt !== undefined ? `${evidence.speed_kt} kt` : "",
    evidence.track_deg !== undefined ? `track ${evidence.track_deg} deg` : "",
    evidence.seen_count ? `${evidence.seen_count} update(s)` : "",
    evidence.session_count ? `${evidence.session_count} local pass(es)` : "",
    evidence.session_spans && evidence.session_spans.length ? `passes ${compactList(evidence.session_spans, 4)}` : "",
    evidence.route_samples && evidence.route_samples.length ? `route ${compactList(evidence.route_samples, 4)}` : ""
  ].filter(Boolean).join("; ");
  if (motion) parts.push({label: "Motion", value: motion});
  if (evidence.observed) parts.push({label: "Observed", value: evidence.observed});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}


function adsbApproachText(item) {
  const data = item || {};
  const context = data.approach_context || "";
  const parts = [context];
  if (data.approach_distance_km !== undefined) parts.push(`${data.approach_distance_km} km`);
  if (data.approach_altitude_ft !== undefined) parts.push(`${data.approach_altitude_ft} ft`);
  if (data.approach_vertical_rate_fpm !== undefined) parts.push(`${data.approach_vertical_rate_fpm} fpm`);
  return parts.filter(Boolean).join("; ");
}

function adsbPopulationReportEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const activity = [
    evidence.aircraft_count ? `${evidence.aircraft_count} aircraft` : "",
    evidence.positioned_count ? `${evidence.positioned_count} with position` : "",
    evidence.emergency_count ? `${evidence.emergency_count} emergency` : "",
    evidence.low_nearby_count ? `${evidence.low_nearby_count} low nearby` : ""
  ].filter(Boolean).join("; ");
  if (activity) parts.push({label: "Activity", value: activity});
  const closest = [
    evidence.closest_aircraft || "",
    evidence.closest_km !== undefined && evidence.closest_km !== "" ? `${evidence.closest_km} km closest` : ""
  ].filter(Boolean).join("; ");
  if (closest) parts.push({label: "Closest", value: closest});
  const lastSeen = displayTimestamp({last_seen_epoch: evidence.last_seen}, "last_seen");
  if (lastSeen) parts.push({label: "Last Seen", value: lastSeen});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function rayhunterReportEvidenceItems(evidence) {
  const parts = [];
  if (evidence.warning_count !== undefined) {
    parts.push({label: "Status", value: `${evidence.warning_count} warning(s)`});
  }
  const system = [
    evidence.rayhunter_version ? `version ${evidence.rayhunter_version}` : "",
    evidence.device_os ? `OS ${evidence.device_os}` : "",
    evidence.gps_mode ? `GPS ${evidence.gps_mode}` : ""
  ].filter(Boolean).join("; ");
  if (system) parts.push({label: "System", value: system});
  const resources = [
    evidence.storage ? `storage ${evidence.storage}` : "",
    evidence.memory ? `RAM ${evidence.memory}` : "",
    evidence.battery ? `battery ${evidence.battery}` : ""
  ].filter(Boolean).join("; ");
  if (resources) parts.push({label: "Resources", value: resources});
  const recording = [
    evidence.recording_id ? `ID ${evidence.recording_id}` : "",
    evidence.recording_size || "",
    evidence.recording_start ? `start ${evidence.recording_start}` : "",
    evidence.recording_last_message ? `last message ${evidence.recording_last_message}` : ""
  ].filter(Boolean).join("; ");
  if (recording) parts.push({label: "Recording", value: recording});
  return withCommonEvidenceItems(parts.length ? parts : genericEvidenceItems(evidence, ""), evidence);
}

function aprsisReportEvidenceItems(evidence) {
  if (evidence.population_kind) return aprsisPopulationReportEvidenceItems(evidence);
  if (evidence.period || evidence.coverage) return aprsisWeatherPeriodEvidenceItems(evidence);
  const parts = [];
  const isWeatherStation = Number(evidence.weather_count || 0) > 0;
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const activity = aprsisReportActivityText(evidence);
  if (activity) parts.push({label: "Activity", value: activity});
  const observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  if (observed) parts.push({label: "Observed", value: observed});
  const route = [
    evidence.via_path ? `via ${evidence.via_path}` : "",
    evidence.q_construct || "",
    evidence.igate ? `igate ${evidence.igate}` : "",
    aprsisAdditionalSamples(evidence.sample_igates, evidence.igate, "igates", 4)
  ].filter(Boolean).join("; ");
  const position = aprsisReportPositionText(evidence);
  const trip = aprsisTripText(evidence);
  const packets = aprsisPacketSamplesText(evidence);
  const weather = aprsisReportWeatherText(evidence);
  const place = [
    position,
    trip,
    weather,
    packets
  ].filter(Boolean).join("; ");
  if (place) parts.push({label: isWeatherStation ? "Weather" : "Position", value: place});
  const feedRole = aprsisDistinctFeedRole(evidence.feed_name, evidence.feed_role);
  const feed = [
    route,
    evidence.feed_name ? `feed ${evidence.feed_name}` : "",
    feedRole,
    aprsisAdditionalSamples(evidence.sample_feeds, evidence.feed_name, "feeds", 3),
    evidence.server_name || evidence.server_address ? `server ${aprsisServerText(evidence)}` : "",
    aprsisAdditionalSamples(evidence.sample_servers, evidence.server_name, "servers", 3),
    (evidence.preferred_servers || []).length ? `preferred ${compactList(evidence.preferred_servers, 3)}` : "",
    evidence.host || evidence.port ? `${evidence.host || "feed"}:${evidence.port || ""}` : "",
    evidence.filter ? `filter ${evidence.filter}` : "",
    evidence.geofence_enforced && evidence.geofence_radius_km ? `local radius ${evidence.geofence_radius_km} km` : "",
    evidence.distance_from_filter_km ? `${evidence.distance_from_filter_km} km from center` : ""
  ].filter(Boolean).join("; ");
  if (feed) parts.push({label: "Route / Feed", value: feed});
  return withCommonEvidenceItems(parts.length ? parts : genericEvidenceItems(evidence, ""), evidence);
}

function aprsisWeatherPeriodEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const period = [
    evidence.period || "",
    evidence.coverage || "",
    timeRangeText(evidence.first_seen, evidence.last_seen)
  ].filter(Boolean).join("; ");
  if (period) parts.push({label: "Period", value: period});
  const weather = [
    evidence.temperature || "",
    evidence.rain || "",
    evidence.wind || "",
    evidence.pressure || ""
  ].filter(Boolean).join("; ");
  if (weather) parts.push({label: "Weather", value: weather});
  const station = [
    evidence.callsign || "",
    evidence.location ? `location ${evidence.location}` : "",
    evidence.source || ""
  ].filter(Boolean).join("; ");
  if (station) parts.push({label: "Station", value: station});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function aprsisPopulationReportEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const activity = [
    evidence.station_count ? `${evidence.station_count} station(s)` : "",
    evidence.packet_count ? `${evidence.packet_count} packet(s)` : "",
    evidence.weather_count ? `${evidence.weather_count} weather` : "",
    evidence.position_count ? `${evidence.position_count} position` : "",
    evidence.stations && evidence.stations.length ? `stations ${compactList(evidence.stations, 8)}` : ""
  ].filter(Boolean).join("; ");
  if (activity) parts.push({label: "Activity", value: activity});
  const weather = [
    aprsisTemperatureEvidenceText(evidence),
    aprsisWindEvidenceText(evidence),
    aprsisRainEvidenceText(evidence),
    evidence.rain_active_stations ? `${evidence.rain_active_stations} rain-active station(s)` : ""
  ].filter(Boolean).join("; ");
  const motion = [
    evidence.position_span_km !== undefined ? `max span ${Number(evidence.position_span_km).toFixed(2)} km` : "",
    evidence.max_speed_kmh !== undefined ? `max ${Number(evidence.max_speed_kmh).toFixed(1)} km/h` : ""
  ].filter(Boolean).join("; ");
  if (weather || motion) parts.push({label: weather ? "Weather" : "Motion", value: weather || motion});
  const observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  if (observed) parts.push({label: "Observed", value: observed});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function aprsisAdditionalSamples(values, primary, label, limit) {
  const primaryText = String(primary || "").trim().toLowerCase();
  const items = (Array.isArray(values) ? values : []).filter((item) => {
    const text = String(item || "").trim();
    return text && text.toLowerCase() !== primaryText;
  });
  return items.length ? `${label} ${compactList(items, limit)}` : "";
}

function aprsisReportActivityText(evidence) {
  const parts = [];
  if (evidence.callsign) parts.push(evidence.callsign);
  if (evidence.packet_count) parts.push(`${evidence.packet_count} packet(s)`);
  if (evidence.position_count) parts.push(`${evidence.position_count} position`);
  if (evidence.weather_count) parts.push(`${evidence.weather_count} weather`);
  if (evidence.object_count) parts.push(`${evidence.object_count} object`);
  if (evidence.message_count) parts.push(`${evidence.message_count} message`);
  if (evidence.status_count) parts.push(`${evidence.status_count} status`);
  return parts.join("; ");
}

function aprsisTripText(data) {
  const parts = [];
  if (data.trip_rollup) parts.push(data.trip_rollup);
  const span = numericEvidence(data.position_span_km);
  const movement = numericEvidence(data.movement_km);
  const maxSpeed = numericEvidence(data.max_speed_kmh);
  if (span !== null && span > 0) parts.push(`span ${span.toFixed(2)} km`);
  if (movement !== null && movement > 0) parts.push(`first/latest ${movement.toFixed(2)} km`);
  if (maxSpeed !== null && maxSpeed > 0) parts.push(`max ${maxSpeed.toFixed(1)} km/h`);
  return parts.join("; ");
}

function aprsisPositionTimeText(time, latitude, longitude) {
  const position = formatLatLon(latitude, longitude);
  return [time || "", position].filter(Boolean).join("; ");
}

function aprsisPacketSamplesText(evidence) {
  const samples = Array.isArray(evidence.packet_samples) ? evidence.packet_samples : [];
  return samples.length ? `packets ${compactList(samples, 3)}` : "";
}

function aprsisReportPositionText(evidence) {
  const parts = [];
  const first = formatLatLon(evidence.first_latitude, evidence.first_longitude);
  const latest = formatLatLon(
    evidence.last_latitude !== undefined ? evidence.last_latitude : evidence.latitude,
    evidence.last_longitude !== undefined ? evidence.last_longitude : evidence.longitude
  );
  if (first && latest && first !== latest) {
    parts.push(`first ${first}`);
    parts.push(`latest ${latest}`);
  } else if (latest) {
    parts.push(latest);
  }
  const span = numericEvidence(evidence.position_span_km);
  const movement = numericEvidence(evidence.movement_km);
  const step = numericEvidence(evidence.max_step_km);
  if (span !== null && span > 0) parts.push(`span ${span.toFixed(2)} km`);
  if (movement !== null && movement > 0) parts.push(`first/latest ${movement.toFixed(2)} km`);
  if (step !== null && step > 0) parts.push(`max step ${step.toFixed(2)} km`);
  const motion = aprsisMotionEvidenceText(evidence);
  if (motion) parts.push(motion);
  if (evidence.first_position_at || evidence.last_position_at) {
    parts.push(timeRangeText(evidence.first_position_at, evidence.last_position_at));
  }
  const maxSpeed = numericEvidence(evidence.max_speed_kmh);
  if (maxSpeed !== null && maxSpeed > 0) parts.push(`max ${maxSpeed.toFixed(1)} km/h`);
  return parts.join("; ");
}

function aprsisReportWeatherText(evidence) {
  const parts = [];
  if (evidence.weather_summary) parts.push(normalizeAprsWeatherSummary(evidence.weather_summary));
  const temp = aprsisTemperatureEvidenceText(evidence);
  if (temp) parts.push(temp);
  const wind = aprsisWindEvidenceText(evidence);
  if (wind) parts.push(wind);
  const rain = aprsisRainEvidenceText(evidence);
  if (rain) parts.push(rain);
  if (evidence.humidity_percent) parts.push(`humidity ${evidence.humidity_percent}%`);
  if (evidence.pressure_hpa) parts.push(`${evidence.pressure_hpa} hPa`);
  return parts.join("; ");
}

function aprsisMotionEvidenceText(evidence) {
  const speed = numericEvidence(evidence.speed_kmh);
  const course = numericEvidence(evidence.course_deg);
  const parts = [];
  if (speed !== null) parts.push(`${speed.toFixed(1)} km/h`);
  if (course !== null) parts.push(`${course.toFixed(0)} deg`);
  return parts.join("; ");
}

function aprsisTemperatureEvidenceText(evidence) {
  const latest = numericEvidence(evidence.temperature_f);
  const min = numericEvidence(evidence.temperature_min_f);
  const max = numericEvidence(evidence.temperature_max_f);
  const change = numericEvidence(evidence.temperature_change_f);
  const parts = [];
  if (latest !== null) parts.push(`${latest.toFixed(0)} F latest`);
  if (min !== null && max !== null) parts.push(`range ${min.toFixed(0)}-${max.toFixed(0)} F`);
  if (change !== null && change !== 0) {
    parts.push(`net ${change > 0 ? "+" : ""}${change.toFixed(0)} F first-to-latest`);
  }
  return parts.join(", ");
}

function aprsisWindEvidenceText(evidence) {
  const wind = numericEvidence(evidence.wind_speed_max_mph);
  const gust = numericEvidence(evidence.wind_gust_max_mph);
  const parts = [];
  if (wind !== null && wind > 0) parts.push(`max wind ${wind.toFixed(0)} mph`);
  if (gust !== null && gust > 0) parts.push(`max gust ${gust.toFixed(0)} mph`);
  return parts.join(", ");
}

function aprsisRainEvidenceText(evidence) {
  const latest = numericEvidence(evidence.rain_1h_in);
  const max = numericEvidence(evidence.rain_1h_max_in);
  const parts = [];
  if (latest !== null) parts.push(`1h rate ${latest.toFixed(2)} in/hr`);
  if (max !== null) parts.push(`max 1h rate ${max.toFixed(2)} in/hr`);
  const transition = latestRainTransition(evidence);
  if (transition) parts.push(transition);
  return parts.join(", ");
}

function latestRainTransition(evidence) {
  const explicit = String(evidence.rain_last_transition || "").trim().toLowerCase();
  if (["started", "stopped"].includes(explicit)) {
    const when = rainTransitionTimestamp(evidence, explicit);
    return when ? `${explicit} ${when}` : explicit;
  }
  const candidates = [];
  if (evidence.rain_started) {
    candidates.push({
      state: "started",
      epoch: numericEvidence(evidence.rain_started_epoch) || 0,
      when: evidence.rain_started_at || ""
    });
  }
  if (evidence.rain_stopped) {
    candidates.push({
      state: "stopped",
      epoch: numericEvidence(evidence.rain_stopped_epoch) || 0,
      when: evidence.rain_stopped_at || ""
    });
  }
  if (!candidates.length) return "";
  candidates.sort((a, b) => b.epoch - a.epoch);
  const latest = candidates[0];
  const when = latest.state === "stopped"
    ? rainTransitionTimestamp(evidence, latest.state) || latest.when
    : latest.when;
  return when ? `${latest.state} ${when}` : latest.state;
}

function rainTransitionTimestamp(evidence, state) {
  if (state === "stopped") {
    const stopped = evidence.rain_episode_stopped_at || evidence.rain_last_transition_at || "";
    const started = evidence.rain_episode_started_at || "";
    if (stopped && started) return `${stopped}; episode started ${started}`;
    return stopped;
  }
  return evidence.rain_last_transition_at || evidence.rain_episode_started_at || "";
}

function noaaReportEvidenceItems(evidence) {
  if (evidence.population_kind) return noaaPopulationReportEvidenceItems(evidence);
  if (evidence.period || evidence.counts) return noaaPeriodEvidenceItems(evidence);
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const event = [
    evidence.event_id ? `ID ${evidence.event_id}` : "",
    evidence.source_event_id && evidence.source_event_id !== evidence.event_id ? `source ID ${evidence.source_event_id}` : "",
    evidence.alert_kind ? `kind ${evidence.alert_kind}` : "",
    evidence.severity || "",
    evidence.urgency ? `urgency ${evidence.urgency}` : "",
    evidence.certainty ? `certainty ${evidence.certainty}` : "",
    evidence.status || "",
    evidence.message_type ? `message ${evidence.message_type}` : "",
    updateEvidenceText(evidence.updated, evidence.update_count)
  ].filter(Boolean).join("; ");
  if (event) parts.push({label: "Event", value: event});
  const packageInfo = [
    evidence.nhc_system || "",
    evidence.nhc_advisory_number ? `advisory ${evidence.nhc_advisory_number}` : "",
    evidence.nhc_storm_id ? `storm ID ${evidence.nhc_storm_id}` : "",
    evidence.nhc_product_count ? `${evidence.nhc_product_count} product(s)` : "",
    evidence.nhc_product_types && evidence.nhc_product_types.length
      ? compactList(evidence.nhc_product_types, 6)
      : ""
  ].filter(Boolean).join("; ");
  if (packageInfo) parts.push({label: "Package", value: packageInfo});
  const tsunami = noaaTsunamiEvidenceText(evidence);
  if (tsunami) parts.push({label: "Tsunami", value: tsunami});
  const forecast = noaaForecastEvidenceText(evidence);
  if (forecast) parts.push({label: "Forecast", value: forecast});
  const isForecast = evidence.alert_kind === "forecast";
  const timing = [
    !isForecast && evidence.effective ? `effective ${evidence.effective}` : "",
    evidence.onset ? `onset ${evidence.onset}` : "",
    evidence.first_period_start ? `from ${evidence.first_period_start}` : "",
    evidence.next_precip_start ? `next precip ${evidence.next_precip_start}` : "",
    !isForecast && evidence.expires ? `expires ${evidence.expires}` : "",
    evidence.last_period_end ? `through ${evidence.last_period_end}` : "",
    evidence.ends ? `ends ${evidence.ends}` : ""
  ].filter(Boolean).join("; ");
  if (timing) parts.push({label: "Timing", value: timing});
  const observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  if (observed) parts.push({label: "Observed", value: observed});
  const source = [
    evidence.area_desc ? `area ${evidence.area_desc}` : "",
    evidence.source || "",
    evidence.source_url || ""
  ].filter(Boolean).join("; ");
  if (source) {
    parts.push({
      label: "Source",
      value: source,
      href: evidence.source_url || "",
      nowrap: Boolean(evidence.source_url)
    });
  }
  return withCommonEvidenceItems(parts.length ? parts : genericEvidenceItems(evidence, ""), evidence);
}

function noaaPeriodEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const period = [
    evidence.period || "",
    evidence.counts || "",
    timeRangeText(evidence.first_seen, evidence.last_seen)
  ].filter(Boolean).join("; ");
  if (period) parts.push({label: "Period", value: period});
  const hazards = [
    evidence.tropical_systems && evidence.tropical_systems.length ? `tropical ${compactList(evidence.tropical_systems, 4)}` : "",
    evidence.basins && evidence.basins.length ? `basins ${compactList(evidence.basins, 4)}` : "",
    evidence.nws_hazards || "",
    evidence.tsunami || "",
    evidence.forecast_count ? `${evidence.forecast_count} forecast subject(s)` : "",
    evidence.sources && evidence.sources.length ? `sources ${compactList(evidence.sources, 4)}` : ""
  ].filter(Boolean).join("; ");
  if (hazards) parts.push({label: "Hazards", value: hazards});
  const trend = [
    evidence.change || "",
    evidence.latest || ""
  ].filter(Boolean).join("; ");
  if (trend) parts.push({label: "Trend", value: trend});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function noaaTsunamiEvidenceText(data) {
  if ((data || {}).alert_kind !== "tsunami") return "";
  const magnitude = numericEvidence((data || {}).magnitude);
  const depth = numericEvidence((data || {}).depth_km);
  return [
    data.message_number ? `message ${data.message_number}` : "",
    data.tsunami_category || "",
    magnitude !== null ? `M${magnitude.toFixed(1)}${data.magnitude_type ? ` ${data.magnitude_type}` : ""}` : "",
    depth !== null ? `depth ${depth.toFixed(1)} km` : "",
    formatLatLon(data.latitude, data.longitude),
    data.event_time ? `event ${data.event_time}` : "",
    data.incident_id ? `incident ${data.incident_id}` : ""
  ].filter(Boolean).join("; ");
}

function noaaForecastEvidenceText(data) {
  if ((data || {}).alert_kind !== "forecast") return "";
  return [
    data.current_forecast || "",
    noaaForecastTemperatureText(data),
    noaaForecastPrecipText(data),
    noaaForecastWindText(data),
    noaaForecastDeltaText(data),
    data.forecast_window_hours ? `${data.forecast_window_hours}h window` : "",
    data.forecast_hour_count ? `${data.forecast_hour_count} period(s)` : ""
  ].filter(Boolean).join("; ");
}


function noaaForecastDeltaText(data) {
  const item = data || {};
  const findings = valueList(item.forecast_delta_findings);
  const parts = [];
  if (item.forecast_change_direction) parts.push(item.forecast_change_direction);
  if (item.forecast_delta_summary) parts.push(item.forecast_delta_summary);
  else if (findings.length) parts.push(compactList(findings, 6));
  const temp = noaaDeltaValueText(item.current_temperature_delta_f, "F current temp");
  const tempMin = noaaDeltaValueText(item.temperature_min_delta_f, "F low");
  const tempMax = noaaDeltaValueText(item.temperature_max_delta_f, "F high");
  const rain = noaaDeltaValueText(item.max_precip_probability_delta, "% max precip");
  const nextRain = noaaDeltaValueText(item.next_precip_probability_delta, "% next precip");
  const wind = noaaDeltaValueText(item.max_wind_delta_mph, "mph wind");
  [temp, tempMin, tempMax, rain, nextRain, wind].filter(Boolean).forEach((value) => parts.push(value));
  return parts.join("; ");
}

function noaaDeltaValueText(value, label) {
  const number = numericEvidence(value);
  if (number === null || number === 0) return "";
  return `${number > 0 ? "+" : ""}${number.toFixed(Math.abs(number) % 1 ? 1 : 0)} ${label}`;
}

function noaaForecastTemperatureText(data) {
  const latest = numericEvidence((data || {}).current_temperature_f);
  const min = numericEvidence((data || {}).temperature_min_f);
  const max = numericEvidence((data || {}).temperature_max_f);
  const change = numericEvidence((data || {}).temperature_change_f);
  const parts = [];
  if (latest !== null) parts.push(`${latest.toFixed(0)} F current`);
  if (min !== null && max !== null) parts.push(`range ${min.toFixed(0)}-${max.toFixed(0)} F`);
  if (change !== null && change !== 0) {
    parts.push(`net ${change > 0 ? "+" : ""}${change.toFixed(0)} F`);
  }
  return parts.join(", ");
}

function noaaForecastPrecipText(data) {
  const current = numericEvidence((data || {}).current_precip_probability);
  const max = numericEvidence((data || {}).max_precip_probability);
  const threshold = numericEvidence((data || {}).precip_probability_threshold);
  const parts = [];
  if (current !== null) parts.push(`${current.toFixed(0)}% current`);
  if (max !== null) parts.push(`${max.toFixed(0)}% max`);
  if (threshold !== null) parts.push(`threshold ${threshold.toFixed(0)}%`);
  return parts.join(", ");
}

function noaaForecastWindText(data) {
  const wind = numericEvidence((data || {}).max_wind_mph);
  return wind !== null ? `up to ${wind.toFixed(0)} mph` : "";
}

function noaaForecastNextPrecipText(data) {
  const probability = numericEvidence((data || {}).next_precip_probability);
  const start = (data || {}).next_precip_start || "";
  const end = (data || {}).next_precip_end || "";
  const forecast = (data || {}).next_precip_forecast || "";
  const parts = [
    probability !== null ? `${probability.toFixed(0)}%` : "",
    start ? `start ${start}` : "",
    end ? `end ${end}` : "",
    forecast
  ];
  return parts.filter(Boolean).join("; ");
}

function noaaPopulationReportEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const event = [
    evidence.event_count ? `${evidence.event_count} subject(s)` : "",
    evidence.product_count ? `${evidence.product_count} product(s)` : "",
    evidence.events && evidence.events.length ? compactList(evidence.events, 5) : "",
    evidence.update_count ? `${evidence.update_count} update(s)` : ""
  ].filter(Boolean).join("; ");
  if (event) parts.push({label: "Events", value: event});
  const scope = [
    evidence.basins && evidence.basins.length ? `basins ${compactList(evidence.basins, 4)}` : "",
    evidence.areas && evidence.areas.length ? `areas ${compactList(evidence.areas, 4)}` : "",
    evidence.sources && evidence.sources.length ? `sources ${compactList(evidence.sources, 4)}` : "",
    evidence.severity_counts && evidence.severity_counts.length ? `severity ${compactList(evidence.severity_counts, 4)}` : ""
  ].filter(Boolean).join("; ");
  if (scope) parts.push({label: "Scope", value: scope});
  const observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  if (observed) parts.push({label: "Observed", value: observed});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function usgsReportEvidenceItems(evidence) {
  if (evidence.population_kind) return usgsPopulationReportEvidenceItems(evidence);
  if (evidence.period || evidence.counts) return usgsPeriodEvidenceItems(evidence);
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const event = [
    evidence.event_id ? `ID ${evidence.event_id}` : "",
    evidence.event_time ? `time ${evidence.event_time}` : "",
    updateEvidenceText(evidence.updated, evidence.update_count),
    evidence.feed_label || evidence.feed || "",
    evidence.scope ? `scope ${evidence.scope}` : "",
    evidence.global_major ? "global major" : "",
    evidence.status || ""
  ].filter(Boolean).join("; ");
  if (event) parts.push({label: "Event", value: event});
  const location = [
    formatLatLon(evidence.latitude, evidence.longitude),
    evidence.depth_km !== undefined ? `depth ${evidence.depth_km} km` : "",
    evidence.distance_km !== undefined ? `${evidence.distance_km} km from point` : ""
  ].filter(Boolean).join("; ");
  if (location) parts.push({label: "Location", value: location});
  const shaking = [
    evidence.cdi !== undefined ? `CDI felt ${evidence.cdi}` : "",
    evidence.mmi !== undefined ? `MMI modeled ${evidence.mmi}` : "",
    evidence.felt !== undefined ? `${evidence.felt} felt report(s)` : "",
    evidence.alert_color ? `alert ${evidence.alert_color}` : "",
    evidence.tsunami ? "tsunami flag" : ""
  ].filter(Boolean).join("; ");
  if (shaking) parts.push({label: "Shaking", value: shaking});
  const observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  if (observed) parts.push({label: "Observed", value: observed});
  if (evidence.detail_url) {
    parts.push({
      label: "Detail",
      value: evidence.detail_url,
      href: evidence.detail_url,
      nowrap: true
    });
  }
  return withCommonEvidenceItems(parts.length ? parts : genericEvidenceItems(evidence, ""), evidence);
}

function usgsPeriodEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const period = [
    evidence.period || "",
    evidence.counts || "",
    timeRangeText(evidence.first_seen, evidence.last_seen)
  ].filter(Boolean).join("; ");
  if (period) parts.push({label: "Period", value: period});
  const seismic = [
    evidence.magnitude || "",
    evidence.distance_depth || "",
    evidence.alert_colors && evidence.alert_colors.length ? `alerts ${compactList(evidence.alert_colors, 4)}` : "",
    evidence.scopes && evidence.scopes.length ? `scopes ${compactList(evidence.scopes, 4)}` : "",
    evidence.feeds && evidence.feeds.length ? `feeds ${compactList(evidence.feeds, 4)}` : ""
  ].filter(Boolean).join("; ");
  if (seismic) parts.push({label: "Seismic", value: seismic});
  const latest = [
    evidence.latest || "",
    evidence.event_ids && evidence.event_ids.length ? `IDs ${compactList(evidence.event_ids, 5)}` : ""
  ].filter(Boolean).join("; ");
  if (latest) parts.push({label: "Latest", value: latest});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function usgsPopulationReportEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const activity = [
    evidence.event_count ? `${evidence.event_count} earthquake(s)` : "",
    evidence.notable_count ? `${evidence.notable_count} notable` : "",
    evidence.event_ids && evidence.event_ids.length ? `IDs ${compactList(evidence.event_ids, 6)}` : ""
  ].filter(Boolean).join("; ");
  if (activity) parts.push({label: "Activity", value: activity});
  const range = [
    evidence.magnitude_min !== undefined && evidence.magnitude_max !== undefined ? `M${Number(evidence.magnitude_min).toFixed(1)}-${Number(evidence.magnitude_max).toFixed(1)}` : "",
    evidence.nearest_distance_km !== undefined ? `nearest ${Number(evidence.nearest_distance_km).toFixed(1)} km` : "",
    evidence.shallowest_depth_km !== undefined ? `shallowest ${Number(evidence.shallowest_depth_km).toFixed(1)} km` : "",
    evidence.alert_colors && evidence.alert_colors.length ? `alerts ${compactList(evidence.alert_colors, 4)}` : ""
  ].filter(Boolean).join("; ");
  if (range) parts.push({label: "Range", value: range});
  const observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  if (observed) parts.push({label: "Observed", value: observed});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function swpcReportEvidenceItems(evidence) {
  if (evidence.population_kind) return swpcPopulationReportEvidenceItems(evidence);
  if (evidence.period || evidence.counts) return swpcPeriodEvidenceItems(evidence);
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const event = [
    evidence.event_id ? `ID ${evidence.event_id}` : "",
    evidence.event_kind ? `kind ${String(evidence.event_kind).replace(/_/g, " ")}` : "",
    evidence.product_id ? `product ${evidence.product_id}` : "",
    evidence.summary || ""
  ].filter(Boolean).join("; ");
  if (event) parts.push({label: "Event", value: event});
  const level = [
    evidence.xray_class || "",
    evidence.scale_label || "",
    evidence.scale_family && evidence.scale_value !== undefined ? `${evidence.scale_family}${evidence.scale_value}` : "",
    formatKpIndex(evidence.kp_index),
    evidence.xray_flux_peak !== undefined ? `peak flux ${evidence.xray_flux_peak}` : ""
  ].filter(Boolean).join("; ");
  if (level) parts.push({label: "Level", value: level});
  const timing = [
    evidence.event_time ? `event ${evidence.event_time}` : "",
    evidence.start_time ? `start ${evidence.start_time}` : "",
    evidence.peak_time ? `peak ${evidence.peak_time}` : "",
    evidence.end_time ? `end ${evidence.end_time}` : "",
    evidence.issue_time ? `issued ${evidence.issue_time}` : "",
    updateEvidenceText("", evidence.update_count)
  ].filter(Boolean).join("; ");
  if (timing) parts.push({label: "Timing", value: timing});
  const observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  if (observed) parts.push({label: "Observed", value: observed});
  const source = [
    evidence.source || "",
    evidence.source_url || ""
  ].filter(Boolean).join("; ");
  if (source) {
    parts.push({
      label: "Source",
      value: source,
      href: evidence.source_url || "",
      nowrap: Boolean(evidence.source_url)
    });
  }
  return withCommonEvidenceItems(parts.length ? parts : genericEvidenceItems(evidence, ""), evidence);
}

function swpcPeriodEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const period = [
    evidence.period || "",
    evidence.counts || "",
    timeRangeText(evidence.first_seen, evidence.last_seen)
  ].filter(Boolean).join("; ");
  if (period) parts.push({label: "Period", value: period});
  const level = [
    evidence.scale || "",
    evidence.scale_labels && evidence.scale_labels.length ? compactList(evidence.scale_labels, 5) : "",
    evidence.kinds && evidence.kinds.length ? `kinds ${compactList(evidence.kinds, 5)}` : ""
  ].filter(Boolean).join("; ");
  if (level) parts.push({label: "Level", value: level});
  const latest = [
    evidence.latest || "",
    evidence.events && evidence.events.length ? compactList(evidence.events, 5) : ""
  ].filter(Boolean).join("; ");
  if (latest) parts.push({label: "Latest", value: latest});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function swpcPopulationReportEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const event = [
    evidence.event_count ? `${evidence.event_count} product(s)` : "",
    evidence.kind_counts && evidence.kind_counts.length ? `kinds ${compactList(evidence.kind_counts, 5)}` : "",
    evidence.events && evidence.events.length ? compactList(evidence.events, 5) : ""
  ].filter(Boolean).join("; ");
  if (event) parts.push({label: "Events", value: event});
  const level = [
    evidence.alert_count ? `${evidence.alert_count} alert-threshold` : "",
    evidence.critical_count ? `${evidence.critical_count} critical` : "",
    evidence.highest_xray_class ? `highest flare ${evidence.highest_xray_class}` : "",
    evidence.max_kp !== undefined ? `max Kp ${Number(evidence.max_kp).toFixed(1)}` : "",
    evidence.scale_labels && evidence.scale_labels.length ? compactList(evidence.scale_labels, 5) : ""
  ].filter(Boolean).join("; ");
  if (level) parts.push({label: "Level", value: level});
  const observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  if (observed) parts.push({label: "Observed", value: observed});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function pwsReportEvidenceItems(evidence) {
  if (evidence.population_kind) return pwsPopulationReportEvidenceItems(evidence);
  if (evidence.period || evidence.coverage) return pwsPeriodEvidenceItems(evidence);
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const station = [
    evidence.station_id || "",
    evidence.station_name && evidence.station_name !== evidence.station_id ? evidence.station_name : "",
    evidence.mac_address ? `MAC ${evidence.mac_address}` : "",
    evidence.model || "",
    evidence.battery ? `battery ${evidence.battery}` : ""
  ].filter(Boolean).join("; ");
  if (station) parts.push({label: "Station", value: station});
  if (evidence.location) parts.push({label: "Location", value: evidence.location});
  const sample = [
    evidence.sample_time || "",
    evidence.observations ? `${evidence.observations} observation(s)` : ""
  ].filter(Boolean).join("; ");
  if (sample) parts.push({label: "Sample", value: sample});
  const observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  if (observed) parts.push({label: "Observed", value: observed});
  const weather = [
    evidence.weather || "",
    evidence.wind || "",
    evidence.rain || "",
    evidence.rain_transition || "",
    evidence.pressure || "",
    evidence.solar || ""
  ].filter(Boolean).join("; ");
  if (weather) parts.push({label: "Weather", value: weather});
  if (evidence.source) {
    parts.push({
      label: "Source",
      value: evidence.source,
      href: firstUrlFromText(evidence.source),
      nowrap: Boolean(firstUrlFromText(evidence.source))
    });
  }
  return withCommonEvidenceItems(parts.length ? parts : genericEvidenceItems(evidence, ""), evidence);
}

function pwsPeriodEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const period = [
    evidence.period || "",
    evidence.coverage || "",
    timeRangeText(evidence.first_seen, evidence.last_seen)
  ].filter(Boolean).join("; ");
  if (period) parts.push({label: "Period", value: period});
  const weather = [
    evidence.temperature || "",
    evidence.rain || "",
    evidence.wind || "",
    evidence.pressure || "",
    evidence.solar || ""
  ].filter(Boolean).join("; ");
  if (weather) parts.push({label: "Weather", value: weather});
  if (evidence.station_id) parts.push({label: "Station", value: evidence.station_id});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function pwsPopulationReportEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const stations = [
    evidence.station_count ? `${evidence.station_count} station(s)` : "",
    evidence.stations && evidence.stations.length ? compactList(evidence.stations, 8) : ""
  ].filter(Boolean).join("; ");
  if (stations) parts.push({label: "Stations", value: stations});
  const maxRain = numericEvidence(evidence.max_rain_1h_in);
  const maxGust = numericEvidence(evidence.max_gust_mph);
  const weather = [
    maxRain !== null ? `max 1h rain rate ${maxRain.toFixed(2)} in/hr` : "",
    maxGust !== null ? `max gust ${maxGust.toFixed(0)} mph` : ""
  ].filter(Boolean).join("; ");
  if (weather) parts.push({label: "Weather", value: weather});
  const observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  if (observed) parts.push({label: "Observed", value: observed});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function rtl433ReportEvidenceItems(evidence, type) {
  if (type === "rtl433_device_population") {
    return rtl433PopulationReportEvidenceItems(evidence);
  }
  if (type === "rtl433_device_profile") {
    return rtl433DeviceProfileReportEvidenceItems(evidence);
  }
  if (type === "rtl433_tpms_cluster") {
    return rtl433TpmsClusterReportEvidenceItems(evidence);
  }
  return genericEvidenceItems(evidence, "");
}

function rtl433DeviceProfileReportEvidenceItems(evidence) {
  const parts = [];
  const profileFindings = valueList(evidence.findings).filter((item) => {
    const text = String(item || "").toLowerCase();
    return !text.includes("decode event") && !text.includes("clustered transmission");
  });
  const findings = findingsText(profileFindings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const identity = [
    evidence.model || "",
    evidence.id ? `ID ${evidence.id}` : "",
    evidence.channel ? `channel ${evidence.channel}` : "",
    evidence.protocol ? `protocol ${evidence.protocol}` : "",
    evidence.category || ""
  ].filter(Boolean).join("; ");
  if (identity) parts.push({label: "Identity", value: identity});
  const pattern = [
    rtl433WeekdayEvidenceText(evidence.weekday_histogram, 3),
    rtl433HourEvidenceText(evidence.hour_histogram, 3),
    rtl433DayNightEvidenceText(evidence.day_night_counts)
  ].filter(Boolean).join("; ");
  if (pattern) parts.push({label: "Pattern", value: pattern});
  const observed = rtl433ObservedText(evidence);
  if (observed) parts.push({label: "Observed", value: observed});
  const activity = [
    evidence.events ? `${evidence.events} event(s)` : "",
    evidence.bursts ? `${evidence.bursts} clustered repeat(s)` : "",
    rtl433BurstGapText(evidence)
  ].filter(Boolean).join("; ");
  if (activity) parts.push({label: "Activity", value: activity});
  const tpms = rtl433TpmsEvidenceText(evidence);
  if (tpms) parts.push({label: "TPMS", value: tpms});
  const rf = [
    rtl433BandText(evidence.latest_frequency_mhz || (Array.isArray(evidence.frequencies_mhz) ? evidence.frequencies_mhz[0] : null)),
    rtl433SignalWithoutFrequency(evidence.latest_signal)
  ].filter(Boolean).join("; ");
  if (rf) parts.push({label: "RF", value: rf});
  const fields = rtl433LatestFieldsText(evidence.latest_fields);
  if (fields) parts.push({label: "Fields", value: fields});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}


function counterMapText(map, suffix) {
  if (!map || typeof map !== "object" || Array.isArray(map)) return "";
  const rows = Object.keys(map).map((key) => `${key}${suffix || ""}: ${map[key]}`);
  return rows.length ? compactList(rows, 12) : "";
}


function rtl433TpmsEvidenceText(evidence) {
  if (String((evidence || {}).category || "").toLowerCase() !== "tpms") return "";
  return [
    rtl433TpmsPressureText(evidence),
    rtl433TpmsTemperatureText(evidence),
    evidence.battery_status ? `battery ${evidence.battery_status}` : "",
    evidence.tpms_status ? `status ${evidence.tpms_status}` : "",
    evidence.tpms_position ? `position ${evidence.tpms_position}` : "",
    rtl433BandText(evidence.latest_frequency_mhz || (Array.isArray(evidence.frequencies_mhz) ? evidence.frequencies_mhz[0] : null)),
    evidence.tpms_samples && evidence.tpms_samples.length ? `samples ${rtl433TpmsSamplesText(evidence.tpms_samples)}` : ""
  ].filter(Boolean).join("; ");
}

function rtl433BandText(frequency) {
  const value = Number(frequency);
  return Number.isFinite(value) ? `${Math.round(value)} MHz band` : "";
}

function rtl433SignalWithoutFrequency(text) {
  return String(text || "")
    .replace(/^\s*[-\d.]+\s*MHz\s*,?\s*/i, "")
    .trim();
}

function rtl433TpmsClusterReportEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const sensors = valueList(evidence.sensors);
  const identity = [
    evidence.sensor_count ? `${evidence.sensor_count} sensor ID(s)` : "",
    sensors.length ? compactList(sensors, 8) : ""
  ].filter(Boolean).join("; ");
  if (identity) parts.push({label: "Sensors", value: identity});
  if (evidence.interpretation) parts.push({label: "Interpretation", value: evidence.interpretation});
  if (evidence.pressure_samples && evidence.pressure_samples.length) {
    parts.push({label: "Pressure", value: compactList(evidence.pressure_samples, 8)});
  }
  const rf = counterMapText(evidence.frequency_counts, " MHz");
  if (rf) parts.push({label: "RF", value: rf});
  return withCommonEvidenceItems(parts.length ? parts : genericEvidenceItems(evidence, ""), evidence);
}

function rtl433BurstGapText(data) {
  const avg = numericEvidence((data || {}).burst_gap_avg_sec);
  const min = numericEvidence((data || {}).burst_gap_min_sec);
  const max = numericEvidence((data || {}).burst_gap_max_sec);
  if (avg === null && min === null && max === null) return "";
  const parts = [];
  if (avg !== null) parts.push(`avg ${avg.toFixed(1)}s`);
  if (min !== null && max !== null) parts.push(`range ${min.toFixed(1)}-${max.toFixed(1)}s`);
  return `repeat gap ${parts.join(", ")}`;
}

function rtl433RecentObservationsText(observations) {
  const rows = (Array.isArray(observations) ? observations : []).map((item) => {
    const parts = [
      item.time || "",
      item.rssi_db !== undefined ? `RSSI ${item.rssi_db}` : "",
      item.snr_db !== undefined ? `SNR ${item.snr_db}` : "",
      item.id ? `ID ${item.id}` : "",
      item.channel ? `channel ${item.channel}` : ""
    ].filter(Boolean);
    return parts.join(", ");
  });
  return rows.length ? compactList(rows, 8) : "";
}

function rtl433RecentObservationsSummaryText(observations) {
  return rtl433RecentObservationsText(observations);
}

function rtl433ObservedText(evidence) {
  const item = evidence || {};
  const observed = timeRangeText(item.first_seen, item.last_seen) || String(item.observed || "").trim();
  const recent = rtl433RecentObservationsSummaryText(item.recent_observations);
  return [observed, recent ? `recently ${recent}` : ""].filter(Boolean).join("; ");
}

function rtl433InterpretationText(evidence) {
  return String((evidence || {}).tpms_interpretation || "").trim();
}

function rtl433DayNightEvidenceText(counts) {
  if (!counts || typeof counts !== "object" || Array.isArray(counts)) return "";
  const day = Number(counts.day || 0);
  const night = Number(counts.night || 0);
  if (night && !day) return "nighttime only";
  if (day && !night) return "daytime only";
  if (day || night) return "seen during the day and at night";
  return "";
}

function rtl433HourLabel(value) {
  const hour = Number(value);
  if (!Number.isFinite(hour)) return String(value || "");
  const suffix = hour < 12 ? "am" : "pm";
  const display = hour % 12 || 12;
  return `${display}${suffix}`;
}

function rtl433ListJoin(items) {
  const values = (items || []).filter(Boolean);
  if (!values.length) return "";
  if (values.length === 1) return values[0];
  if (values.length === 2) return `${values[0]} and ${values[1]}`;
  return `${values.slice(0, -1).join(", ")}, and ${values[values.length - 1]}`;
}

function rtl433HourEvidenceText(map, limit = 3) {
  if (!map || typeof map !== "object" || Array.isArray(map)) return "";
  const rows = Object.keys(map)
    .slice(0, limit)
    .map((key) => rtl433HourLabel(key));
  return rows.length ? `usually active ${rtl433ListJoin(rows)}` : "";
}

function rtl433WeekdayEvidenceText(map, limit = 3) {
  if (!map || typeof map !== "object" || Array.isArray(map)) return "";
  const rows = Object.keys(map)
    .slice(0, limit)
    .map((key) => String(key));
  return rows.length ? `seen ${rtl433ListJoin(rows)}` : "";
}

function rtl433LatestFieldsText(fields) {
  if (!fields || typeof fields !== "object") return "";
  const preferred = [
    "temperature_C", "temperature_F", "humidity", "moisture", "battery_ok",
    "button", "state", "status", "mod", "mic", "rssi", "snr", "noise"
  ];
  const seen = new Set();
  const parts = [];
  preferred.forEach((key) => {
    if (fields[key] === undefined || fields[key] === null || fields[key] === "") return;
    seen.add(key);
    parts.push(`${key}: ${fields[key]}`);
  });
  Object.keys(fields).sort().forEach((key) => {
    if (seen.has(key) || ["time", "model", "id", "channel", "freq", "protocol"].includes(key)) return;
    const value = fields[key];
    if (value === undefined || value === null || value === "") return;
    parts.push(`${key}: ${value}`);
  });
  return compactList(parts, 6);
}

function rtl433PopulationReportEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const counts = [
    rtl433CountText(evidence.device_count, "device"),
    rtl433CountText(evidence.security_count, "security"),
    rtl433CountText(evidence.tpms_count, "TPMS"),
    rtl433CountText(evidence.utility_count, "utility"),
    rtl433CountText(evidence.weather_count, "weather")
  ].filter(Boolean).join("; ");
  if (counts) parts.push({label: "Counts", value: counts});
  const lastSeen = displayTimestamp({last_seen_epoch: evidence.last_seen}, "last_seen");
  if (lastSeen) parts.push({label: "Last Seen", value: lastSeen});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function rtl433CountText(value, label) {
  const count = Number(value || 0);
  if (!count) return "";
  return `${count} ${label}${count === 1 || label === "TPMS" ? "" : "s"}`;
}

function lanReportEvidenceItems(evidence) {
  if (evidence.population_kind) return lanPopulationReportEvidenceItems(evidence);
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const identity = [
    evidence.mac ? `MAC ${evidence.mac}` : "",
    evidence.ips && evidence.ips.length ? `IP ${compactList(evidence.ips, 4)}` : "",
    evidence.hostnames && evidence.hostnames.length ? `host ${compactList(evidence.hostnames, 3)}` : "",
    evidence.vendor || ""
  ].filter(Boolean).join("; ");
  if (identity) parts.push({label: "Identity", value: identity});
  const network = [
    evidence.gateway_ip || (evidence.gateway_ips && evidence.gateway_ips.length)
      ? `gateway ${evidence.gateway_ip || compactList(evidence.gateway_ips, 4)}`
      : "",
    evidence.family || (evidence.families && evidence.families.length ? compactList(evidence.families, 3) : ""),
    evidence.interface || (evidence.interfaces && evidence.interfaces.length ? `iface ${compactList(evidence.interfaces, 3)}` : ""),
    evidence.states && evidence.states.length ? `state ${compactList(evidence.states, 3)}` : "",
    evidence.sources && evidence.sources.length ? `source ${compactList(evidence.sources, 3)}` : "",
    evidence.services && evidence.services.length ? `service ${compactList(evidence.services, 3)}` : ""
  ].filter(Boolean).join("; ");
  if (network) parts.push({label: "Network", value: network});
  const service = [
    evidence.locations && evidence.locations.length ? `location ${compactList(evidence.locations, 2)}` : "",
    evidence.servers && evidence.servers.length ? `server ${compactList(evidence.servers, 2)}` : ""
  ].filter(Boolean).join("; ");
  if (service) parts.push({label: "Services", value: service});
  const activity = [
    evidence.observation_count ? `${evidence.observation_count} observation(s)` : "",
    evidence.change_count ? `${evidence.change_count} change(s)` : "",
    evidence.gateway ? "gateway device" : "",
    evidence.gateways && evidence.gateways.length ? `gateways ${compactList(evidence.gateways, 3)}` : ""
  ].filter(Boolean).join("; ");
  if (activity) parts.push({label: "Activity", value: activity});
  const observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  if (observed) parts.push({label: "Observed", value: observed});
  return withCommonEvidenceItems(parts.length ? parts : genericEvidenceItems(evidence, ""), evidence);
}

function lanPopulationReportEvidenceItems(evidence) {
  const parts = [];
  const findings = findingsText(evidence.findings, "", false);
  if (findings) parts.push({label: "Findings", value: findings});
  const activity = [
    evidence.subject_count ? `${evidence.subject_count} subject(s)` : "",
    evidence.device_count ? `${evidence.device_count} device(s)` : "",
    evidence.gateway_count ? `${evidence.gateway_count} gateway(s)` : "",
    evidence.changed_count ? `${evidence.changed_count} changed` : ""
  ].filter(Boolean).join("; ");
  if (activity) parts.push({label: "Activity", value: activity});
  const scope = [
    evidence.vendors && evidence.vendors.length ? `vendors ${compactList(evidence.vendors, 5)}` : "",
    evidence.services && evidence.services.length ? `services ${compactList(evidence.services, 5)}` : "",
    evidence.interfaces && evidence.interfaces.length ? `interfaces ${compactList(evidence.interfaces, 5)}` : ""
  ].filter(Boolean).join("; ");
  if (scope) parts.push({label: "Scope", value: scope});
  const observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  if (observed) parts.push({label: "Observed", value: observed});
  return parts.length ? parts : genericEvidenceItems(evidence, "");
}

function updateEvidenceText(updated, updateCount) {
  const parts = [];
  if (updated) parts.push(`updated ${updated}`);
  const count = Number(updateCount || 0);
  if (count) parts.push(`${count} update${count === 1 ? "" : "s"}`);
  return parts.join("; ");
}

function firstUrlFromText(value) {
  const match = String(value || "").match(/https?:\/\/\S+/i);
  return match ? match[0] : "";
}

function formatLatLon(latitude, longitude) {
  const lat = Number(latitude);
  const lon = Number(longitude);
  if (Number.isFinite(lat) && Number.isFinite(lon)) {
    return formatCoordinatePair(lat, lon);
  }
  if (Number.isFinite(lat)) return `lat ${lat.toFixed(5)}`;
  if (Number.isFinite(lon)) return `lon ${lon.toFixed(5)}`;
  return "";
}

function formatCoordinatePair(latitude, longitude) {
  const lat = Number(latitude);
  const lon = Number(longitude);
  if (!validLatLon(lat, lon)) return "";
  return `${lat.toFixed(5)}, ${lon.toFixed(5)}`;
}

function validLatLon(latitude, longitude) {
  return Number.isFinite(latitude) &&
    Number.isFinite(longitude) &&
    latitude >= -90 &&
    latitude <= 90 &&
    longitude >= -180 &&
    longitude <= 180;
}

function mapUrlForLatLon(latitude, longitude, radiusKm) {
  const lat = Number(latitude);
  const lon = Number(longitude);
  if (!validLatLon(lat, lon)) return "";
  const zoom = mapZoomForRadius(radiusKm);
  return `https://www.openstreetmap.org/?mlat=${lat.toFixed(6)}&mlon=${lon.toFixed(6)}#map=${zoom}/${lat.toFixed(6)}/${lon.toFixed(6)}`;
}

function mapZoomForRadius(radiusKm) {
  const radius = Number(radiusKm);
  if (!Number.isFinite(radius) || radius <= 0) return 14;
  if (radius >= 500) return 5;
  if (radius >= 250) return 6;
  if (radius >= 100) return 8;
  if (radius >= 50) return 9;
  if (radius >= 20) return 10;
  if (radius >= 10) return 11;
  if (radius >= 5) return 12;
  return 14;
}

function mapLink(label, latitude, longitude, radiusKm) {
  const text = String(label || formatCoordinatePair(latitude, longitude) || "");
  const href = mapUrlForLatLon(latitude, longitude, radiusKm);
  if (!href) return text;
  const link = document.createElement("a");
  link.href = href;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.title = "Open in OpenStreetMap";
  link.textContent = text;
  return {node: link, text};
}

function coordinateTokenLooksPrecise(value) {
  const text = String(value || "");
  const decimal = text.match(/\.(\d+)$/);
  return Boolean(decimal && decimal[1].length >= 3);
}

function coordinateContextLooksExplicit(text, start, end) {
  const before = text.slice(Math.max(0, start - 48), start);
  const after = text.slice(end, Math.min(text.length, end + 48));
  return /\b(lat|lon|latitude|longitude|coord|coords|coordinate|coordinates|position|location|center|centre)\b/i.test(`${before} ${after}`);
}

function coordinatePairLooksLikeTime(text, start, end) {
  return text[start - 1] === ":" || text[end] === ":";
}

function shouldLinkCoordinatePair(text, match, isRangeFilter) {
  if (isRangeFilter) return true;
  const start = match.index;
  const end = start + match[0].length;
  if (coordinatePairLooksLikeTime(text, start, end)) return false;
  const hasCoordinatePrecision = coordinateTokenLooksPrecise(match[5]) &&
    coordinateTokenLooksPrecise(match[6]);
  return hasCoordinatePrecision || coordinateContextLooksExplicit(text, start, end);
}

function appendMapLinkedText(parent, value) {
  const text = String(value === null || value === undefined ? "" : value);
  if (!text) return;
  const pattern = /(r\/(-?\d+(?:\.\d+)?)\/(-?\d+(?:\.\d+)?)\/(\d+(?:\.\d+)?))|(-?\d{1,3}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)/ig;
  let lastIndex = 0;
  let appended = false;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    const isRangeFilter = Boolean(match[1]);
    const lat = Number(isRangeFilter ? match[2] : match[5]);
    const lon = Number(isRangeFilter ? match[3] : match[6]);
    const radius = isRangeFilter ? Number(match[4]) : undefined;
    if (!validLatLon(lat, lon)) continue;
    if (!shouldLinkCoordinatePair(text, match, isRangeFilter)) continue;
    if (match.index > lastIndex) {
      parent.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
    }
    const link = mapLink(match[0], lat, lon, radius);
    if (link && link.node instanceof Node) {
      parent.appendChild(link.node);
    } else {
      parent.appendChild(document.createTextNode(match[0]));
    }
    lastIndex = pattern.lastIndex;
    appended = true;
  }
  if (!appended) {
    parent.appendChild(document.createTextNode(text));
    return;
  }
  if (lastIndex < text.length) {
    parent.appendChild(document.createTextNode(text.slice(lastIndex)));
  }
}

function numericEvidence(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function withCommonEvidenceItems(parts, evidence) {
  return [...(parts || [])];
}

function presencePatternText(evidence) {
  const parts = [];
  if (evidence.days_seen && evidence.days_seen.length) {
    parts.push(`seen ${compactList(evidence.days_seen, 7)}`);
  }
  if (evidence.common_hours && evidence.common_hours.length) {
    parts.push(`usually active ${compactList(evidence.common_hours, 3)}`);
  } else if (evidence.presence_hours && evidence.presence_hours.length) {
    parts.push(`active during ${compactList(evidence.presence_hours, 3)}`);
  }
  if (evidence.common_start_hours && evidence.common_start_hours.length) {
    parts.push(`usually starts ${compactList(evidence.common_start_hours, 3)}`);
  }
  return parts.join("; ");
}

function findingsText(findings, signal, includeSignal) {
  const items = valueList(findings);
  if (!items.length) return "";
  const parts = [compactList(items, 5)];
  if (includeSignal && signal) parts.push(signal);
  return parts.filter(Boolean).join("; ");
}

function findingsMentionStrongSignal(findings) {
  return valueList(findings).some((item) => {
    const text = String(item || "").toLowerCase();
    return text.includes("strong") && text.includes("signal");
  });
}

function observedSessionText(evidence) {
  let observed = "";
  if (evidence.presence_spans && evidence.presence_spans.length) {
    observed = compactList(evidence.presence_spans, 4);
  } else if (evidence.first_seen || evidence.last_seen) {
    observed = timeRangeText(evidence.first_seen, evidence.last_seen);
  }

  const session = sessionText(evidence.sessions, evidence.active_session);
  return [observed, session].filter(Boolean).join("; ");
}


function reportSessionSummaryText(evidence) {
  const session = sessionText(evidence.sessions, evidence.active_session);
  if (session) return session;
  return timeRangeText(evidence.first_seen, evidence.last_seen);
}

function sessionText(count, active) {
  const sessions = Number(count || 0);
  const sessionPart = sessions ? `${sessions} visit${sessions === 1 ? "" : "s"}` : "";
  const activePart = active === true ? "currently present" : active === false ? "not currently present" : "";
  return [sessionPart, activePart].filter(Boolean).join("; ");
}

function signalRangeText(min, max) {
  const hasMin = min !== null && min !== undefined && min !== "";
  const hasMax = max !== null && max !== undefined && max !== "";
  if (hasMin && hasMax) return `${min} to ${max} dBm`;
  if (hasMax) return `up to ${max} dBm`;
  if (hasMin) return `${min} dBm`;
  return "";
}

function timeRangeText(first, last) {
  if (first && last && first !== last) return `${first} to ${last}`;
  return first || last || "";
}

function compactList(values, limit) {
  const items = valueList(values);
  if (!items.length) return "";
  const shown = items.slice(0, limit);
  const suffix = items.length > shown.length ? ` +${items.length - shown.length}` : "";
  return `${shown.join(", ")}${suffix}`;
}

function genericEvidenceText(evidence, detail) {
  return genericEvidenceItems(evidence, detail)
    .map((item) => `${item.label}: ${item.value}`)
    .join(" | ");
}

function genericEvidenceItems(evidence, detail) {
  if (!evidence) return [];
  const parts = [];
  const detailText = String(detail || "").toLowerCase();
  Object.keys(evidence).sort().forEach((key) => {
    if (key.endsWith("_epoch")) return;
    if (internalEvidenceKey(key)) return;
    const value = evidenceDisplayValue(evidence, key);
    if (value === "" || value === null || value === undefined) return;
    if (!alwaysShowEvidenceKey(key) && evidenceValueAlreadyShown(value, detailText)) return;
    if (Array.isArray(value)) {
      parts.push({label: evidenceLabel(key), value: value.join(", ")});
    } else {
      parts.push({label: evidenceLabel(key), value: String(value)});
    }
  });
  return parts;
}

function internalEvidenceKey(key) {
  return ["identity_key", "internet_fed", "findmy_accessory"].includes(key);
}

function evidenceDisplayValue(evidence, key) {
  if (key === "service_uuids") {
    return bluetoothServiceList(evidence[key]);
  }
  if ((key.endsWith("_seen") || key === "timestamp") && evidence[key]) {
    return evidence[key];
  }
  return evidence[key];
}

function evidenceLabel(key) {
  if (key === "service_uuids") return "Services / UUIDs";
  if (key === "findmy_accessory") return "Find My";
  if (key === "findmy_label") return "Find My";
  if (key === "findmy_payload_type") return "Find My Type";
  if (key === "findmy_status") return "Find My Status";
  if (key === "findmy_hint") return "Find My Hint";
  return key;
}

function alwaysShowEvidenceKey(key) {
  return ["first_seen", "last_seen", "presence_spans"].includes(key);
}

function evidenceValueAlreadyShown(value, detailText) {
  if (!detailText) return false;
  const values = Array.isArray(value) ? value : [value];
  return values.some((item) => {
    const text = String(item === null || item === undefined ? "" : item).trim().toLowerCase();
    return text.length >= 2 && detailText.includes(text);
  });
}

function updateSubtabPanel(group) {
  if (group !== "history") return;
  const mode = activeSubtabs.history || "all";
  document.querySelectorAll(".history-source-panel").forEach((panel) => {
    panel.classList.toggle("active", mode === "all" || panel.dataset.source === mode);
  });
}

function wifiApMatchesSearch(item) {
  return rowMatchesSearch([
    item.ssid || "",
    item.bssid || "",
    vendorLabel(item),
    channelFreq(item.channel, item.frequency_band),
    item.encryption || "",
    formatSignal(item.rssi),
    item.last_seen || ""
  ], wifiSearch);
}

function renderCollectorHealth(statuses) {
  latestCollectorStatuses = statuses || [];
  renderCollectorTabStatusDots();
  updateTabCounts();
  const tbody = document.getElementById("collector-health");
  tbody.innerHTML = "";
  latestCollectorStatuses.forEach((item) => {
    updateCollectorTabStatus(item);
    if (item.key === "rtl433") updateRtl433FrequencyStateFromStatus(item);
  });
  collectorHealthGroups(latestCollectorStatuses).forEach((group) => {
    if (!group.items.length) return;
    appendTableGroupRow(tbody, group.label, group.items.length, "table-group-row collector-state-group-row");
    group.items.forEach((item) => {
      const tr = document.createElement("tr");
      [
        ["name", item.name],
        ["state", collectorDisplayState(item)],
        ["hardware", hardwareSummary(item)],
        ["software", softwareSummary(item.key)],
        ["events", item.events_this_session],
        ["last-event", item.last_event || ""],
        ["warning", displayWarning(item)]
      ].forEach(([key, value]) => {
        const td = document.createElement("td");
        td.className = `collector-health-col-${key}`;
        td.textContent = value;
        tr.appendChild(td);
      });
      const control = document.createElement("td");
      control.className = "collector-health-col-control";
      const state = String(item.state || "");
      const disabled = state === "DISABLED";
      const running = state === "ONLINE" || state === "RETRYING" || state === "DETECTING";
      const stopped = state === "STOPPED" || state === "OFFLINE";
      if (!disabled && !running) {
        const start = document.createElement("button");
        start.textContent = "Start";
        start.addEventListener("click", () => {
          const payload = collectorControlPayload(item.key, "start");
          const detail = item.key === "rtl433"
            ? rtl433StartRequestedDetail(payload.overrides || {})
            : "Start requested";
          setCollectorBanner(item.key, "STARTING", detail);
          if (item.key === "rtl433" && payload.overrides && payload.overrides.frequency_plan) {
            updateRtl433FrequencyState({
              clear_frequency_state: true,
              frequency_summary: payload.overrides.frequency_plan,
              submitted_plan: payload.overrides.frequency_plan,
              tune_pending: true
            });
          }
          socket.emit("collector_control", payload);
        });
        control.appendChild(start);
      }
      if (!disabled && !stopped) {
        const stop = document.createElement("button");
        stop.textContent = "Stop";
        stop.addEventListener("click", () => {
          setCollectorBanner(item.key, "STOPPING", "Stop requested");
          socket.emit("collector_control", collectorControlPayload(item.key, "stop"));
        });
        control.appendChild(stop);
      }
      tr.appendChild(control);
      tbody.appendChild(tr);
    });
  });
  maybeRefreshEmptyDerivedViews("collector events");
}

function renderCollectorTabStatusDots() {
  const statusByKey = new Map((latestCollectorStatuses || []).map((item) => [item.key, item]));
  setTabStatusDots("wifi", [statusByKey.get("wifi")]);
  setTabStatusDots("wifi_monitor", [statusByKey.get("wifi_monitor")]);
  setTabStatusDots("rtl433", [statusByKey.get("rtl433")]);
  setTabStatusDots("adsb", [statusByKey.get("adsb")]);
  setTabStatusDots("rayhunter", [statusByKey.get("rayhunter")]);
  setTabStatusDots("aprsis", [statusByKey.get("aprsis")]);
  setTabStatusDots("noaa", [statusByKey.get("noaa")]);
  setTabStatusDots("usgs", [statusByKey.get("usgs")]);
  setTabStatusDots("swpc", [statusByKey.get("swpc")]);
  setTabStatusDots("pws", [statusByKey.get("pws")]);
  setTabStatusDots("lan", [statusByKey.get("lan")]);
  setTabStatusDots("bluetooth", [
    statusByKey.get("ble"),
    statusByKey.get("bt_classic")
  ]);
}

function setTabStatusDots(tab, statuses) {
  const container = document.querySelector(`[data-status-tab="${tab}"]`);
  if (!container) return;
  container.innerHTML = "";
  (statuses || []).forEach((item) => {
    const dot = document.createElement("span");
    const online = item && item.state === "ONLINE";
    const name = item ? (item.tab_label || item.name || item.key) : "Collector";
    const state = item ? displayState(item.state) : "Unknown";
    dot.className = `tab-status-dot ${online ? "online" : "offline"}`;
    dot.title = `${name}: ${state}`;
    dot.setAttribute("aria-label", `${name}: ${state}`);
    dot.setAttribute("role", "img");
    container.appendChild(dot);
  });
}

function updateCollectorTabStatus(item) {
  const status = document.getElementById(`${item.key}-status`);
  const visualState = item.state;
  if (status) {
    status.textContent = collectorDisplayState(item);
    status.className = `badge ${badgeClassForState(visualState)}`;
  }
  updateCollectorActionButtons(item);
  if (hasActiveTransientCollectorBanner(item.key)) return;
  setCollectorBanner(item.key, visualState, collectorStatusDetailForBanner(item));
}

function collectorDisplayState(item) {
  return displayState(item.state);
}

function updateCollectorActionButtons(item) {
  if (item.key !== "bt_classic") return;
  const state = String(item.state || "");
  const running = state === "ONLINE" || state === "RETRYING" || state === "DETECTING";
  const start = document.getElementById("bt-classic-start");
  const stop = document.getElementById("bt-classic-stop");
  if (start) start.style.display = running ? "none" : "";
  if (stop) stop.style.display = running ? "" : "none";
}

function collectorStatusDetailForBanner(item) {
  const detail = collectorStatusDetail(item);
  if ((item || {}).key === "ble" && rows.bleScanDetail) {
    return [detail, rows.bleScanDetail].filter(Boolean).join(" | ");
  }
  return detail;
}

function collectorStatusDetail(item) {
  if (item.key === "aprsis" && Array.isArray(item.feed_statuses) && item.feed_statuses.length) {
    return item.feed_statuses
      .map((feed) => aprsisStatusDetail(feed, {includeState: true}))
      .filter(Boolean)
      .join("\n");
  }
  const hardware = hardwareSummary(item);
  const cleanWarning = displayWarning(item);
  const warning = cleanWarning ? ` | ${cleanWarning}` : "";
  return `${hardware}${warning}`.replace(/^\s*\|\s*/, "") || cleanWarning || "";
}

function eventStatusDetail(key, activeHardware, warning) {
  return collectorStatusDetail({
    key,
    hardware: activeHardware,
    warning
  });
}

function displayWarning(item) {
  const warning = String((item || {}).warning || "").trim();
  if (!warning) return "";
  return warningIsValidationDetail(warning) ? "" : warning;
}

function warningIsValidationDetail(warning) {
  const text = String(warning || "").toLowerCase();
  return text.includes("validation") || text.includes(" exited ") || text.includes(" exit ");
}

function displayState(state) {
  if (state === "DISABLED") return "DISABLED";
  if (state === "IDLE") return "IDLE / on demand";
  return String(state || "Unknown").replace(/_/g, " ");
}

function setCollectorBanner(key, state, detail) {
  const banner = document.getElementById(`${key}-banner`);
  if (!banner) return;
  const label = displayState(state);
  const detailText = String(detail || "");
  const detailHasOwnState = key === "aprsis" && /^[A-Z][A-Z /_-]*:\s+feed\s+/m.test(detailText);
  const bannerText = detailText
    ? (detailHasOwnState ? detailText : `${label}: ${detailText}`)
    : label;
  banner.textContent = "";
  appendMapLinkedText(banner, bannerText);
  banner.className = `status-strip ${bannerClassForState(state)}`;
}

function setTransientCollectorBanner(key, state, detail, visibleMs) {
  const duration = Number.isFinite(Number(visibleMs)) ? Number(visibleMs) : 12000;
  transientCollectorBanners.set(key, Date.now() + duration);
  setCollectorBanner(key, state, detail);
  setTimeout(() => {
    if (hasActiveTransientCollectorBanner(key)) return;
    transientCollectorBanners.delete(key);
  }, duration + 100);
}

function hasActiveTransientCollectorBanner(key) {
  const until = transientCollectorBanners.get(key);
  if (!until) return false;
  if (Date.now() <= until) return true;
  transientCollectorBanners.delete(key);
  return false;
}

function badgeClassForState(state) {
  if (state === "ONLINE") return "ok";
  if (state === "RETRYING" || state === "STARTING" || state === "STOPPING") return "warning";
  if (state === "OFFLINE") return "alert";
  return "muted";
}

function bannerClassForState(state) {
  if (state === "ONLINE") return "ok";
  if (state === "RETRYING" || state === "STARTING" || state === "STOPPING" || state === "collector_retrying") return "warning";
  if (state === "OFFLINE" || state === "collector_offline") return "alert";
  return "muted";
}

function renderSystemStatus(status) {
  if (!status) return;
  latestSystemStatus = status;
  updateBrowserTitle();
  if (latestCollectorStatuses.length) renderCollectorHealth(latestCollectorStatuses);
  else updateTabCounts();
}

function hardwareSummary(item) {
  const detected = (latestSystemStatus.hardware || {})[item.key] || {};
  if (item.key === "wifi") {
    return availabilitySummary(
      "Wi-Fi interfaces",
      wirelessAvailabilityRecords(detected),
      cleanActiveHardware(item.hardware)
    );
  }
  if (item.key === "wifi_monitor") {
    const active = item.hardware && item.hardware !== "Wi-Fi adapter already in monitor mode";
    const monitorRecords = Array.isArray(detected.interfaces) ? detected.interfaces : [];
    const wireless = Array.isArray(detected.wireless_interfaces)
      ? detected.wireless_interfaces.join(", ")
      : "";
    const summary = availabilitySummary(
      "Monitor-mode interfaces",
      monitorRecords,
      active ? cleanActiveHardware(item.hardware) : ""
    );
    return [
      summary,
      wireless ? `wireless interfaces present: ${wireless}` : null,
      detected.interface ? `configured: ${detected.interface}` : null,
      detected.auto_start === false ? "on demand" : null
    ].filter(Boolean).join(", ");
  }
  if (item.key === "ble") {
    return availabilitySummary(
      "Bluetooth adapters",
      bluetoothAvailabilityRecords(detected),
      cleanActiveHardware(item.hardware)
    );
  }
  if (item.key === "bt_classic") {
    return availabilitySummary(
      "Bluetooth adapters",
      bluetoothAvailabilityRecords(detected),
      cleanActiveHardware(item.hardware)
    );
  }
  if (item.key === "rayhunter") {
    return [
      detected.enabled === false ? "disabled" : "",
      detected.endpoint ? `endpoint: ${detected.endpoint}` : "no endpoint configured"
    ].filter(Boolean).join(", ");
  }
  if (item.key === "aprsis") {
    const feeds = Array.isArray(detected.feeds) ? detected.feeds : [];
    if (feeds.length) {
      return [
        detected.enabled === false ? "disabled" : "",
        internetStatusText(),
        `${feeds.length} feed${feeds.length === 1 ? "" : "s"}`,
        feeds.map(aprsisFeedSummary).filter(Boolean).join("; ")
      ].filter(Boolean).join(", ");
    }
    return [
      detected.enabled === false ? "disabled" : "",
      internetStatusText(),
      detected.host ? `feed: ${detected.host}:${detected.port || ""}` : "no feed configured",
      detected.filter ? `filter: ${detected.filter}` : "no filter configured"
    ].filter(Boolean).join(", ");
  }
  if (detected.internet_source) {
    return [
      detected.enabled === false ? "disabled" : "",
      internetStatusText(),
      cleanActiveHardware(item.hardware)
    ].filter(Boolean).join(", ");
  }
  if (item.key === "lan") {
    return [
      detected.enabled === false ? "disabled" : "",
      "local OS neighbor/default-route state"
    ].filter(Boolean).join(", ");
  }
  if (item.key === "rtl433") {
    return [
      detected.enabled === false ? "disabled" : "",
      detected.device_index !== undefined ? `RTL-SDR index ${detected.device_index}` : "",
      detected.frequency_plan ? `plan ${detected.frequency_plan}` : ""
    ].filter(Boolean).join(", ");
  }
  return item.hardware || "";
}

function internetStatusText() {
  const internet = latestSystemStatus.internet || {};
  if (!internet.state && internet.online === undefined) return "";
  return `internet ${internet.online ? "online" : "offline"}`;
}

function aprsisFeedSummary(feed) {
  const geofence = feed.geofence || {};
  const feedName = String(feed.name || "").trim();
  const feedRole = aprsisDistinctFeedRole(feedName, feed.role);
  return [
    feedName,
    feedRole,
    feed.host ? `${feed.host}:${feed.port || ""}` : "",
    (feed.preferred_servers || []).length ? `preferred ${compactList(feed.preferred_servers, 3)}` : "",
    feed.filter ? `filter ${feed.filter}` : ""
  ].filter(Boolean).join(" ");
}

function aprsisDistinctFeedRole(name, role) {
  const roleText = String(role || "").trim();
  if (!roleText) return "";
  const nameText = String(name || "").trim();
  return roleText.toLowerCase() === nameText.toLowerCase() ? "" : roleText;
}

function availabilitySummary(label, records, active) {
  if (active) {
    records.forEach((item) => {
      if (item.name === active) item.available = true;
    });
  }
  const entries = records.map((item) => `${item.name}: ${item.available ? "available" : "unavailable"}`);
  if (!entries.length && !active) return `${label}: unavailable`;
  if (active) entries.push(`active: ${active}`);
  return `${label}: ${entries.join(", ")}`;
}

function bluetoothAvailabilityRecords(detected) {
  if (Array.isArray(detected.adapters)) return detected.adapters;
  return [];
}

function wirelessAvailabilityRecords(detected) {
  if (Array.isArray(detected.interfaces)) return detected.interfaces;
  return [];
}

function cleanActiveHardware(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  if (text.includes("adapter for") || text.includes("interface for")) return "";
  if (text.includes("required")) return "";
  return text;
}

function softwareSummary(key) {
  const detected = (latestSystemStatus.hardware || {})[key] || {};
  if (key === "wifi") {
    return wifiScanToolStatus(detected);
  }
  if (key === "wifi_monitor") {
    return [
      executableStatus("iw", detected.iw),
      packageStatus("scapy", detected.scapy)
    ].filter(Boolean).join(", ");
  }
  if (key === "rtl433") {
    return executableStatus("rtl_433", detected.rtl_433);
  }
  if (key === "ble") {
    return packageStatus("bleak", detected.bleak);
  }
  if (key === "bt_classic") {
    return [
      executableStatus("hcitool", detected.hcitool),
      executableStatus("bluetoothctl", detected.bluetoothctl)
    ].filter(Boolean).join(", ");
  }
  if (key === "rayhunter") {
    return "HTTP endpoint, gzip-aware";
  }
  if (key === "aprsis") {
    return "APRS-IS TCP feed";
  }
  if (key === "lan") {
    return [
      toolRoleStatus("ip", detected.ip, "required"),
      toolRoleStatus("arp", detected.arp, "recommended"),
      toolRoleStatus("arp-scan", detected.arp_scan, "optional"),
      toolRoleStatus("avahi-browse", detected.avahi_browse, "optional")
    ].filter(Boolean).join(", ");
  }
  return "";
}

function executableStatus(name, found) {
  if (found === undefined) return "";
  return `${name}: ${found ? "located" : "missing"}`;
}

function toolRoleStatus(name, found, role) {
  if (found === undefined) return "";
  const suffix = role ? ` ${role}` : "";
  return `${name}${suffix}: ${found ? "available" : "missing"}`;
}

function wifiScanToolStatus(detected) {
  if (detected.iw === undefined && detected.iwlist === undefined) return "";
  return `iw/iwlist: ${(detected.iw || detected.iwlist) ? "located" : "missing"}`;
}

function packageStatus(name, installed) {
  if (installed === undefined) return "";
  return `${name}: ${installed ? "installed" : "missing"}`;
}

function formatSignal(value) {
  if (value === null || value === undefined || value === "") return "";
  const number = Number(value);
  if (Number.isNaN(number)) return value;
  return String(Math.round(number));
}

function prependList(id, text) {
  const list = document.getElementById(id);
  const item = document.createElement("li");
  item.textContent = text;
  list.prepend(item);
  while (list.children.length > uiNumber("max_event_log_items")) list.removeChild(list.lastChild);
}
