const socket = createLocalEventSocket();
const rows = {
  signals: new Map(),
  ble: new Map(),
  btClassic: new Map(),
  bleIdentify: [],
  aps: new Map(),
  monitorEvents: [],
  insights: [],
  reports: []
};
let COLLECTOR_SUBTABS = [
  {value: "all", label: "All"},
  {value: "wifi", label: "Wi-Fi Scan"},
  {value: "wifi_monitor", label: "Wi-Fi Monitor"},
  {value: "bluetooth", label: "Bluetooth"},
  {value: "rtlsdr", label: "RTL-SDR"},
  {value: "system", label: "System"}
];
let COLLECTOR_SOURCE_GROUPS = {
  bluetooth: {label: "Bluetooth", members: ["ble", "ble_identify", "bt_classic"]},
};
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
let activeWindow = "default";
let findingsHistoryLoaded = false;
let derivedRefreshInFlight = false;
let autoDerivedRefreshTimer = null;
let derivedStatusTicker = null;
let nextAutoDerivedRefreshAtMs = null;
let lastDerivedRefreshError = "";
let lastWakeRefreshAtMs = 0;
let emptyDerivedRefreshRequestedAtMs = 0;
let emptyDerivedRefreshAttempts = 0;
let derivedRefreshMode = "";
const transientCollectorBanners = new Map();
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
let uiConfig = {
  max_live_rows: 200,
  max_history_rows: 500,
  max_event_log_items: 100,
  max_rendered_findings: 1000,
  max_history_ssids: 8,
  bluetooth_live_recent_sec: 600,
  derived_stale_after_min: 15,
  derived_auto_refresh_min: 15,
  insights_recent_after_min: 30
};

function fetchJson(url, options) {
  const requestOptions = {
    cache: "no-store",
    ...(options || {})
  };
  return fetch(url, requestOptions).then((response) => {
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
  });
}

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    document.querySelector(`#tab-${button.dataset.tab}`).classList.add("active");
  });
});

const viewWindowFilter = document.getElementById("view-window-filter");
if (viewWindowFilter) {
  activeWindow = viewWindowFilter.value || "default";
  viewWindowFilter.addEventListener("change", () => {
    activeWindow = viewWindowFilter.value || "default";
    findingsHistoryLoaded = false;
    emptyDerivedRefreshRequestedAtMs = 0;
    emptyDerivedRefreshAttempts = 0;
    loadDerivedViews();
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
const reportsTypeFilter = document.getElementById("reports-type-filter");
if (reportsTypeFilter) {
  reportsTypeFilter.addEventListener("change", () => renderReports(latestReports || {}));
}
const wifiSearch = document.getElementById("wifi-search");
if (wifiSearch) {
  wifiSearch.addEventListener("input", renderWifiTables);
}
const bleSearch = document.getElementById("ble-search");
if (bleSearch) {
  bleSearch.addEventListener("input", renderBleTable);
}
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
setInterval(() => {
  renderBleTable();
}, 30000);
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
socket.on("findings_snapshot", renderFindingsSnapshot);
socket.on("skannr_event", handleEvent);
buildSubtabs();
loadCollectorMetadata();
loadViewMetadata();
setInterval(updateDerivedStatusLines, 60000);
setInterval(renderLiveTables, 30000);
["focus", "pageshow", "online"].forEach((eventName) => {
  window.addEventListener(eventName, refreshAfterBrowserWake);
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refreshAfterBrowserWake();
});

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

  setTimeout(() => {
    const source = new EventSource("/events");
    source.onopen = () => emitLocal("connect");
    source.onerror = () => emitLocal("disconnect");
    ["collector_status", "system_status", "findings_snapshot", "skannr_event"].forEach((name) => {
      source.addEventListener(name, (message) => {
        try {
          emitLocal(name, JSON.parse(message.data));
        } catch (_error) {
          // Ignore malformed records; the next event will refresh the dashboard.
        }
      });
    });
  }, 0);
  return api;
}

function setSocketState(text, cls) {
  const node = document.getElementById("socket-state");
  const target = displayConnectionHost();
  node.textContent = text === "Connected" ? `Connected to ${target}` : `Disconnected from ${target}`;
  node.className = `badge ${cls}`;
}

function displayConnectionHost() {
  const host = window.location.hostname || "this host";
  return host || "this host";
}

function handleEvent(event) {
  if (event.collector === "findings") renderFindingEvent(event);
  if (event.collector === "rtlsdr") renderRtlsdrEvent(event);
  if (event.collector === "ble") renderBleEvent(event);
  if (event.collector === "ble_identify") renderBleIdentifyEvent(event);
  if (event.collector === "bt_classic") renderBtClassicEvent(event);
  if (event.collector === "wifi") renderWifiEvent(event);
  if (event.collector === "wifi_monitor") renderWifiMonitorEvent(event);
  if (event.collector === "system" && event.type === "system_status") renderSystemStatus(event.data);
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
  const tbody = document.getElementById("insights-list");
  if (!tbody) return;
  renderInsightsHeader();
  tbody.innerHTML = "";
  rows.insights.filter(insightMatchesFilters).filter(insightMatchesSearch).slice(0, uiNumber("max_rendered_findings")).forEach((insight) => {
    const tr = document.createElement("tr");
    insightCells(insight).forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function renderInsightsHeader() {
  const head = document.getElementById("insights-head");
  if (!head) return;
  const tr = document.createElement("tr");
  const labels = ["Time", "Severity"];
  if (showInsightSourceColumn()) labels.push("Source");
  labels.push("Activity", "Category", "Insight", "Details");
  labels.forEach((label) => {
    const th = document.createElement("th");
    th.textContent = label;
    tr.appendChild(th);
  });
  head.innerHTML = "";
  head.appendChild(tr);
}

function insightCells(insight) {
  const cells = [
      insight.timestamp || "",
      insight.severity || ""
    ];
  if (showInsightSourceColumn()) cells.push(sourceLabel(insight.source));
  cells.push(
      activityLabel(insight),
      insight.category || "",
      insight.title || "",
      insightDetails(insight)
  );
  return cells;
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
  renderReportsHeader();
  const tbody = document.getElementById("reports-list");
  if (!tbody) return;
  tbody.innerHTML = "";
  rows.reports
    .filter(reportMatchesSubtab)
    .filter(reportMatchesTypeFilter)
    .filter(reportMatchesSearch)
    .slice(0, uiNumber("max_rendered_findings"))
    .forEach((report) => {
      const tr = document.createElement("tr");
      reportColumns(report).forEach((column) => {
        const td = document.createElement("td");
        td.className = `report-col-${column.key}`;
        if (column.key === "evidence") {
          renderReportEvidenceCell(td, reportEvidenceItems(report));
        } else {
          td.textContent = column.value;
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  updateReportsStatus(latestReports);
  updateReportsSummary(
    rows.reports
      .filter(reportMatchesSubtab)
      .filter(reportMatchesTypeFilter)
      .filter(reportMatchesSearch)
  );
}

function renderReportsHeader() {
  const head = document.getElementById("reports-head");
  if (!head) return;
  const tr = document.createElement("tr");
  reportColumns({}).forEach((column) => {
    const th = document.createElement("th");
    th.className = `report-col-${column.key}`;
    th.textContent = column.label;
    tr.appendChild(th);
  });
  head.innerHTML = "";
  head.appendChild(tr);
}

function reportCells(report) {
  return reportColumns(report).map((column) => column.value);
}

function reportColumns(report) {
  const columns = [
    {key: "generated", label: "Generated", value: report.timestamp || ""},
    {key: "severity", label: "Severity", value: report.severity || ""},
    {key: "score", label: "Score", value: report.score || 0}
  ];
  if (showReportsSourceColumn()) columns.push({key: "source", label: "Source", value: sourceLabel(report.source)});
  columns.push(
    {key: "type", label: "Type", value: categoryForType(report.type || "report")},
    {key: "report", label: "Report", value: report.title || ""},
    {key: "subject", label: "Subject", value: report.subject || ""},
    {key: "summary", label: "Summary", value: report.summary || ""},
    {key: "evidence", label: "Evidence", value: reportEvidenceText(report)},
    {key: "last-seen", label: "Last Seen", value: report.last_seen || ""}
  );
  return columns;
}

function loadDerivedViews() {
  fetchJson(`/derived_views${windowQuery()}`)
    .then(renderDerivedViews)
    .catch((error) => setDerivedStatus(`Derived views unavailable: ${error}`, "alert"));
}

function windowQuery() {
  return `?days=${encodeURIComponent(activeWindow || "default")}`;
}

function windowRequestOptions() {
  return {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({days: activeWindow || "default"})
  };
}

function refreshDerivedViews(mode) {
  const refreshMode = mode || "manual";
  const label = derivedRefreshLabel(refreshMode);
  if (derivedRefreshInFlight) {
    setDerivedStatus(`${label} skipped; refresh already running`, "warning");
    return Promise.resolve(null);
  }
  derivedRefreshInFlight = true;
  derivedRefreshMode = refreshMode;
  nextAutoDerivedRefreshAtMs = null;
  setDerivedStatus(`${label} running`, "warning");
  let failed = false;
  return fetchJson("/derived_views/refresh", windowRequestOptions())
    .then((bundle) => {
      validateDerivedBundleShape(bundle);
      lastDerivedRefreshError = "";
      renderDerivedViews(bundle);
    })
    .catch((error) => {
      failed = true;
      lastDerivedRefreshError = `Derived refresh failed: ${error}`;
      setDerivedStatus(`Derived refresh failed: ${error}`, "alert");
    })
    .finally(() => {
      derivedRefreshInFlight = false;
      derivedRefreshMode = "";
      scheduleAutoDerivedRefresh();
      if (!failed) updateDerivedStatusLines();
    });
}

function renderDerivedViews(bundle) {
  renderFindingsHistory(bundle.findings || {});
  renderDeviceHistory(bundle.device_history || {});
  hydrateLiveScanTablesFromHistory(bundle.device_history || {});
  renderHistoryAnalysis(bundle.history_analysis || {});
  renderReports(bundle.reports || {});
  renderCombinedInsights();
  if (derivedHistoryHasRows()) {
    emptyDerivedRefreshAttempts = 0;
  }
  maybeRefreshEmptyDerivedViews("derived views loaded");
}

function renderLiveTables() {
  renderBleTable();
}

function maybeRefreshEmptyDerivedViews(reason) {
  if (derivedRefreshInFlight || derivedHistoryHasRows() || !liveScanRowsSeen()) {
    return;
  }
  if (emptyDerivedRefreshAttempts >= 3) return;
  const now = Date.now();
  if (now - emptyDerivedRefreshRequestedAtMs < 60000) return;
  emptyDerivedRefreshRequestedAtMs = now;
  emptyDerivedRefreshAttempts += 1;
  setDerivedStatus(`Refreshing derived views after new scan data (${reason})`, "warning");
  setTimeout(() => refreshDerivedViews("catch-up"), 1000);
}

function derivedHistoryHasRows() {
  const history = latestDeviceHistory || {};
  const wifi = history.wifi || {};
  const bluetooth = history.bluetooth || history.ble || {};
  return Boolean(
    (wifi.access_points || []).length ||
    (wifi.clients || []).length ||
    (bluetooth.devices || []).length
  );
}

function liveScanRowsSeen() {
  return Boolean(
    rows.aps.size ||
    rows.ble.size ||
    rows.btClassic.size ||
    collectorScanEventsSeen()
  );
}

function collectorScanEventsSeen() {
  const scanCollectors = new Set(["wifi", "ble", "bt_classic"]);
  return (latestCollectorStatuses || []).some((item) => {
    return scanCollectors.has(item.key) && Number(item.events_this_session || 0) > 0;
  });
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
  (bluetooth.devices || []).forEach((item) => {
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
  if (bleChanged) renderBleTable();
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
  if (latestReports) updateReportsStatus(latestReports);
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
    manual: "Manual refresh"
  }[mode] || "Derived refresh";
}

function autoRefreshText() {
  if (derivedRefreshInFlight) {
    return `${derivedRefreshLabel(derivedRefreshMode).toLowerCase()} running`;
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
  if (derivedRefreshInFlight) {
    scheduleAutoDerivedRefresh();
    return;
  }
  derivedRefreshInFlight = true;
  derivedRefreshMode = "automatic";
  nextAutoDerivedRefreshAtMs = null;
  setDerivedStatus(`${derivedRefreshLabel(derivedRefreshMode)} running`, "warning");
  let failed = false;
  fetchJson("/derived_views/refresh", windowRequestOptions())
    .then((bundle) => {
      validateDerivedBundleShape(bundle);
      lastDerivedRefreshError = "";
      renderDerivedViews(bundle);
    })
    .catch((error) => {
      failed = true;
      lastDerivedRefreshError = `Automatic refresh failed: ${error}`;
      setDerivedStatus(`Automatic refresh failed: ${error}`, "alert");
    })
    .finally(() => {
      derivedRefreshInFlight = false;
      derivedRefreshMode = "";
      scheduleAutoDerivedRefresh();
      if (!failed) updateDerivedStatusLines();
    });
}

function refreshAfterBrowserWake() {
  const now = Date.now();
  if (now - lastWakeRefreshAtMs < 10000 || derivedRefreshInFlight) return;
  lastWakeRefreshAtMs = now;
  renderLiveTables();
  loadDerivedViews();
  updateDerivedStatusLines();
}

function shouldRunStaleDerivedRefresh() {
  const intervalMin = uiNonNegativeNumber("derived_auto_refresh_min");
  const staleMin = uiNonNegativeNumber("derived_stale_after_min");
  if (intervalMin <= 0 || staleMin <= 0 || derivedRefreshInFlight) return false;
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
  const epoch = Number(summary.refreshed_at_epoch || summary.generated_at_epoch);
  if (Number.isFinite(epoch) && epoch > 0) return epoch * 1000;
  return null;
}

function recordTimestampMs(item, key) {
  if (!item) return null;
  const epoch = Number(item[`${key}_epoch`]);
  if (Number.isFinite(epoch) && epoch > 0) return epoch * 1000;
  return null;
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
  const match = collectorEntryForSource(key);
  return match ? match.label : (source || "");
}

function showInsightSourceColumn() {
  return (activeSubtabs.insights || "all") === "all";
}

function updateReportsStatus(bundle) {
  const source = bundle || {};
  const window = source.window || {};
  const refreshedAt = source.refreshed_at || source.generated_at;
  const refreshedEpoch = source.refreshed_at_epoch || source.generated_at_epoch;
  const total = rows.reports.length;
  const visible = rows.reports
    .filter(reportMatchesSubtab)
    .filter(reportMatchesTypeFilter)
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

function reportMatchesTypeFilter(report) {
  const mode = reportsTypeFilter ? reportsTypeFilter.value : "all";
  if (mode === "all") return true;
  return reportFilterType(report) === mode;
}

function reportMatchesSearch(report) {
  return rowMatchesSearch(reportCells(report), reportsSearch);
}

function showReportsSourceColumn() {
  return (activeSubtabs.reports || "all") === "all";
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
    const key = reportFilterType(report);
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const top = Object.entries(counts)
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, 4)
    .map(([key, count]) => `${reportFilterTypeLabel(key)}: ${count}`);
  summary.textContent = `Top report types in this view: ${top.join(" | ")}`;
}

function reportFilterType(report) {
  const text = String(report.type || "").toLowerCase();
  if (text.includes("new")) return "new";
  return categoryForType(text || "report");
}

function reportFilterTypeLabel(type) {
  return {
    security: "Security",
    presence: "Presence",
    signal: "Signal",
    new: "New",
    behavior: "Behavior",
    identity: "Identity",
    collector: "Collector",
    analysis: "Analysis"
  }[type] || type;
}

function sortReports(items) {
  return (items || []).sort((left, right) => {
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
      button.textContent = entry.label;
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
}

function subtabEntriesForGroup(group) {
  if (group === "history") {
    return COLLECTOR_SUBTABS.filter((entry) => entry.value !== "system");
  }
  return COLLECTOR_SUBTABS;
}

function loadCollectorMetadata() {
  fetch("/collector_metadata")
    .then((response) => response.json())
    .then((metadata) => {
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
  setCollectorBanner(key, action === "start" ? "STARTING" : "STOPPING", `${action} requested`);
  socket.emit("collector_control", {key, action});
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
  fetch("/view_metadata")
    .then((response) => response.json())
    .then((metadata) => {
      applyDashboardMetadata(metadata || {});
      if (!Array.isArray(metadata.options) || !metadata.options.length) {
        loadDerivedViews();
        return;
      }
      const selected = activeWindow || metadata.active || "default";
      viewWindowFilter.innerHTML = "";
      metadata.options.forEach((entry) => appendSelectOption(viewWindowFilter, entry.value, entry.label));
      activeWindow = metadata.options.some((entry) => entry.value === selected) ? selected : (metadata.active || "default");
      viewWindowFilter.value = activeWindow;
      findingsHistoryLoaded = false;
      loadDerivedViews();
    })
    .catch(() => {
      // Keep the small static fallback selector if metadata is not available.
      loadDerivedViews();
    });
}

function applyDashboardMetadata(metadata) {
  applyAppVersion(metadata.version);
  if (metadata.ui) {
    uiConfig = {...uiConfig, ...metadata.ui};
  }
  configureAutoDerivedRefresh();
  applyRtlsdrDefaults((metadata.collectors || {}).rtlsdr || {});
}

function applyAppVersion(version) {
  const node = document.getElementById("app-version");
  if (!node) return;
  node.textContent = version ? `v${version}` : "";
}

function applyRtlsdrDefaults(config) {
  setInputValue("rtlsdr-start", config.scan_start_mhz);
  setInputValue("rtlsdr-end", config.scan_end_mhz);
  setInputValue("rtlsdr-step", config.step_khz);
  setInputValue("rtlsdr-gain", config.gain);
  setInputValue("rtlsdr-threshold", config.threshold_db);
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

function renderRtlsdrEvent(event) {
  document.getElementById("rtlsdr-status").textContent = event.type;
  if (event.type === "scanner_started") {
    setCollectorBanner("rtlsdr", "ONLINE", `${event.data.range} | gain=${event.data.gain}`);
  }
  if (event.type === "baseline_ready") {
    document.getElementById("baseline-state").textContent = `Detection active (${event.data.bins} bins)`;
  }
  if (event.type === "signal_detected") {
    const item = {
      ...event.data,
      first_seen: event.timestamp,
      first_seen_epoch: event.timestamp_epoch,
      last_seen: event.timestamp,
      last_seen_epoch: event.timestamp_epoch
    };
    rows.signals.set(item.frequency_mhz, item);
    prependList("rtlsdr-events", `${event.timestamp} detected ${item.frequency_mhz} MHz +${item.above_floor_db} dB`);
  }
  if (event.type === "signal_lost") {
    rows.signals.delete(event.data.frequency_mhz);
    prependList("rtlsdr-events", `${event.timestamp} lost ${event.data.frequency_mhz} MHz`);
  }
  renderSchemaTable("rtlsdr-signals", [...rows.signals.values()], "rtlsdrSignals");
}

function renderBleEvent(event) {
  document.getElementById("ble-status").textContent = event.type;
  if (event.type === "collector_offline" || event.type === "collector_retrying") {
    setCollectorBanner("ble", event.type, eventStatusDetail("ble", event.data.adapter, event.data.reason || event.data.warning || ""));
  }
  if (event.type === "scanner_started") {
    setCollectorBanner("ble", "ONLINE", eventStatusDetail("ble", event.data.adapter, ""));
  }
  if (!["device_seen", "device_updated"].includes(event.type)) return;
  const data = event.data;
  const key = data.mac;
  const current = rows.ble.get(key) || {};
  const merged = {
    ...current,
    ...data,
    last_seen: event.timestamp,
    last_seen_epoch: event.timestamp_epoch
  };
  rows.ble.set(key, merged);
  renderBleTable();
  maybeRefreshEmptyDerivedViews("Bluetooth scan");
}

function renderBleTable() {
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
    td.colSpan = 7;
    td.textContent = "No recently seen BLE devices";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  devices.forEach((item) => {
    const tr = document.createElement("tr");
    [
      item.mac,
      bleDeviceName(item),
      formatSignal(item.rssi),
      item.manufacturer || "",
      bluetoothServiceList(item.service_uuids),
      item.last_seen || ""
    ].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value || "";
      tr.appendChild(td);
    });
    const actionCell = document.createElement("td");
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
    bleDeviceName(item),
    item.manufacturer,
    formatSignal(item.rssi),
    bluetoothServiceList(item.service_uuids),
    item.last_seen
  ], bleSearch);
}

function bluetoothServiceList(uuids) {
  return (uuids || []).map(bluetoothServiceLabel).join(", ");
}

function bluetoothServiceLabel(uuid) {
  const shortId = bluetoothAssignedNumber(uuid);
  if (!shortId) return customBluetoothUuidLabel(uuid);
  const name = BLUETOOTH_SERVICE_NAMES[shortId.toLowerCase()];
  if (name) return `${name} (${shortId.toUpperCase()})`;
  return shortId.length === 4 ? `Unknown service (${shortId.toUpperCase()})` : String(uuid || "");
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
  if (compact.length > 8) return `Vendor service ${compact.slice(0, 8)}...`;
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
    renderBtClassicTable();
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
    renderBtClassicTable();
    maybeRefreshEmptyDerivedViews("Bluetooth classic scan");
  }
}

function renderBtClassicTable() {
  renderSchemaTable("bt-classic-devices", [...rows.btClassic.values()], "btClassicDevices");
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
    renderBleTable();
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

function bleDeviceName(item) {
  const direct = bluetoothDisplayName(item.name, item.mac);
  if (direct) return direct;
  if (Array.isArray(item.names) && item.names.length) {
    return item.names
      .map((name) => bluetoothDisplayName(name, item.mac))
      .filter(Boolean)
      .join(", ");
  }
  return "";
}

function bluetoothDisplayName(name, mac) {
  const value = String(name || "").trim();
  if (!value || bluetoothNameLooksLikeAddress(value, mac) || bluetoothNameLooksLikeCommandError(value)) return "";
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
    renderWifiTables();
    maybeRefreshEmptyDerivedViews("Wi-Fi scan");
  }
}

function renderWifiMonitorEvent(event) {
  document.getElementById("wifi_monitor-status").textContent = event.type;
  if (event.type === "monitor_started") {
    const data = event.data || {};
    setCollectorBanner("wifi_monitor", "ONLINE", `${data.interface} available, active: ${data.interface} | channels ${formatChannelList(data.channels)} | dwell ${data.dwell_sec}s`);
    setWifiMonitorPlan(`Bands ${formatChannelList(data.supported_bands)} | channels ${formatChannelList(data.channels)}`, "ok");
  }
  if (event.type === "monitor_channel_changed") {
    const data = event.data || {};
    setWifiMonitorPlan(`${data.interface} listening on channel ${data.channel} (${data.band} GHz)`, "ok");
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
    renderWifiMonitorTable();
  }
}

function renderWifiMonitorTable() {
  renderSchemaTable("wifi-monitor-events", rows.monitorEvents, "wifiMonitorEvents");
}

function setWifiMonitorPlan(text, state) {
  const node = document.getElementById("wifi-monitor-plan");
  if (!node) return;
  node.textContent = text;
  node.className = `status-strip ${state || "muted"}`;
}

function formatChannelList(values) {
  if (!values || !values.length) return "none";
  return values.join(", ");
}

function renderWifiTables() {
  const aps = [...rows.aps.values()]
    .filter(wifiApMatchesSearch)
    .sort(compareWifiAccessPoints);
  renderSchemaTable("wifi-aps", aps, "wifiAccessPoints", {
    preserveOrder: true
  });
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
  const monitorEmpty = document.getElementById("history-wifi-monitor-empty");
  if (monitorEmpty) {
    monitorEmpty.textContent = clients.length
      ? `${clients.length} Wi-Fi client/probe histories in this view`
      : "No Wi-Fi client/probe history in this view. Wi-Fi Monitor must be running in monitor mode to collect clients, probes, deauth, and association frames.";
  }
  renderHistoryTable("history-wifi-aps", aps, (item) => [
    item.ssid || "(blank)",
    item.bssid || "",
    vendorLabel(item),
    item.first_seen || "",
    item.last_seen || "",
    channelFreqList(item.channels),
    (item.encryption || []).join(", "),
    signalRange(item),
    item.observations || 0,
    item.finding_count || 0
  ], historySearch);
  renderHistoryTable("history-wifi-clients", clients, (item) => [
    item.mac || "",
    vendorLabel(item),
    ssidList(item.ssids, item.randomized_mac),
    item.first_seen || "",
    item.last_seen || "",
    signalRange(item),
    item.probe_count || 0,
    item.association_count || 0,
    item.deauth_count || 0,
    item.disassoc_count || 0,
    item.finding_count || 0
  ], historySearch);
  renderHistoryTable("history-bluetooth-devices", devices, (item) => [
    item.mac || "",
    (item.transports || []).join(", "),
    bleDeviceName(item),
    item.manufacturer_name || item.manufacturer || item.vendor_name || "",
    item.model_number || "",
    item.serial_number || "",
    item.firmware_revision || "",
    item.pnp_id || "",
    item.first_seen || "",
    item.last_seen || "",
    signalRange(item),
    item.seen_count || 0,
    item.update_count || 0,
    item.lost_count || 0,
    item.classic_seen_count || 0,
    (item.sessions || []).length,
    item.finding_count || 0
  ], historySearch);
}

function updateDeviceHistoryStatus(history) {
  const wifi = history.wifi || {};
  const ble = history.bluetooth || history.ble || {};
  const aps = wifi.access_points || [];
  const clients = wifi.clients || [];
  const devices = ble.devices || [];
  const window = history.window || {};
  const refreshedAt = history.refreshed_at || history.generated_at;
  const visible = [...aps, ...clients, ...devices];
  const shown = visible.length;
  const rawEvents = history.records_read || 0;
  const newestSeen = latestSeenStatusText(visible, ["last_seen", "timestamp"]);
  const refreshedEpoch = history.refreshed_at_epoch || history.generated_at_epoch;
  const normalState = derivedStatusState(refreshedAt, refreshedEpoch, "ok");
  setHistoryStatus(
    [
      derivedStatusPrefix(window, refreshedAt, refreshedEpoch),
      newestSeen,
      `${shown} devices/APs shown`,
      `${rawEvents} raw events processed`,
      `${aps.length} APs`,
      `${clients.length} Wi-Fi clients`,
      `${devices.length} Bluetooth devices`
    ].filter(Boolean).join(" | "),
    derivedDataStatusState(visible, ["last_seen", "timestamp"], normalState)
  );
}

function vendorLabel(item) {
  if (!item) return "";
  const prefix = item.vendor_prefix || item.vendor_oui;
  if (item.vendor_name && prefix) return `${item.vendor_name} (${prefix})`;
  return item.vendor_name || prefix || "";
}

function setHistoryStatus(text, state) {
  const status = document.getElementById("history-status");
  if (!status) return;
  status.textContent = text;
  status.className = `status-strip ${state || "muted"}`;
}

function ssidList(ssids, randomized) {
  const values = (ssids || []).slice(0, uiNumber("max_history_ssids"));
  const suffix = (ssids || []).length > values.length ? ` +${(ssids || []).length - values.length}` : "";
  const prefix = randomized ? "randomized MAC | " : "";
  return `${prefix}${values.join(", ")}${suffix}`;
}

function signalRange(item) {
  const latest = formatSignal(item.signal_latest);
  const min = formatSignal(item.signal_min);
  const max = formatSignal(item.signal_max);
  if (!latest && !min && !max) return "";
  return `${latest} (${min}/${max})`;
}

function channelFreq(channel, explicitBand) {
  if (channel === undefined || channel === null || channel === "") return "";
  const band = explicitBand || bandForChannel(channel);
  return band ? `${channel} / ${band}` : String(channel);
}

function channelFreqList(channels) {
  return (channels || []).map((channel) => channelFreq(channel)).join(", ");
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
  const findings = ((latestFindingsHistory || {}).findings || []).map(normalizeFindingInsight);
  const observations = ((latestHistoryAnalysis || {}).observations || []).map(normalizeObservationInsight);
  rows.insights = sortInsights(findings.concat(observations));
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
    origin: "device history",
    score: observation.score || 0,
  };
}

function updateInsightsStatus() {
  const source = latestHistoryAnalysis || latestFindingsHistory || {};
  const window = source.window || {};
  const insightsWindow = source.insights_window || {};
  const refreshedAt = source.refreshed_at || source.generated_at;
  const refreshedEpoch = source.refreshed_at_epoch || source.generated_at_epoch;
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
  if (text.includes("encryption") || text.includes("security") || text.includes("evil")) return "security";
  if (text.includes("strong") || text.includes("rssi") || text.includes("signal")) return "signal";
  if (text.includes("presence") || text.includes("returned") || text.includes("lost") || text.includes("linger") || text.endsWith("_new")) return "presence";
  if (text.includes("probe") || text.includes("deauth") || text.includes("randomized") || text.includes("recurring")) return "behavior";
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
  if (source === "bluetooth" || type.startsWith("ble_")) {
    return bluetoothReportEvidenceItems(evidence);
  }
  if (source === "wifi" || type.startsWith("wifi_ap") || type.includes("ssid")) {
    return wifiApReportEvidenceItems(evidence);
  }
  if (source === "wifi_monitor" || type.startsWith("wifi_client")) {
    return wifiClientReportEvidenceItems(evidence);
  }
  return genericEvidenceItems(evidence, (report || {}).summary || "");
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
    detail.textContent = item.value;
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
  if (signal && !foldedSignal) parts.push({label: "Signal", value: signal});
  if (evidence.sample_macs && evidence.sample_macs.length) {
    parts.push({label: "Samples", value: compactList(evidence.sample_macs, 6)});
  }
  return parts.length ? parts : genericEvidenceItems(evidence, "");
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
  const signal = signalRangeText(null, evidence.signal_max);
  const foldedSignal = findingsMentionStrongSignal(evidence.findings);
  const findings = findingsText(evidence.findings, signal, foldedSignal);
  if (findings) parts.push({label: "Findings", value: findings});
  const radio = [
    evidence.channels && evidence.channels.length ? `channels ${compactList(evidence.channels, 8)}` : "",
    evidence.bssids && evidence.bssids.length ? `${evidence.bssids.length} BSSIDs` : "",
    evidence.encryption && evidence.encryption.length ? `security ${compactList(evidence.encryption, 6)}` : ""
  ].filter(Boolean).join("; ");
  if (radio) parts.push({label: "Radio", value: radio});
  if (evidence.vendors && evidence.vendors.length) {
    parts.push({label: "Vendors", value: compactList(evidence.vendors, 4)});
  }
  const pattern = presencePatternText(evidence);
  if (pattern) parts.push({label: "Pattern", value: pattern});
  const observed = observedSessionText(evidence);
  if (observed) parts.push({label: "Observed", value: observed});
  if (signal && !foldedSignal) parts.push({label: "Signal", value: signal});
  if (evidence.bssids && evidence.bssids.length) {
    parts.push({label: "BSSIDs", value: compactList(evidence.bssids, 8)});
  }
  return parts.length ? parts : genericEvidenceItems(evidence, "");
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
  return parts.length ? parts : genericEvidenceItems(evidence, "");
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
  if (!findings || !findings.length) return "";
  const parts = [compactList(findings, 5)];
  if (includeSignal && signal) parts.push(signal);
  return parts.filter(Boolean).join("; ");
}

function findingsMentionStrongSignal(findings) {
  if (!findings || !findings.length) return false;
  return findings.some((item) => {
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
  const items = Array.isArray(values) ? values.filter((item) => item !== "" && item !== null && item !== undefined) : [];
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
    const value = evidenceDisplayValue(evidence, key);
    if (value === "" || value === null || value === undefined) return;
    if (!alwaysShowEvidenceKey(key) && evidenceValueAlreadyShown(value, detailText)) return;
    if (Array.isArray(value)) {
      parts.push({label: key, value: value.join(", ")});
    } else {
      parts.push({label: key, value: String(value)});
    }
  });
  return parts;
}

function evidenceDisplayValue(evidence, key) {
  if ((key.endsWith("_seen") || key === "timestamp") && evidence[key]) {
    return evidence[key];
  }
  return evidence[key];
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
  const tbody = document.getElementById("collector-health");
  tbody.innerHTML = "";
  latestCollectorStatuses.forEach((item) => {
    updateCollectorTabStatus(item);
    const tr = document.createElement("tr");
    [
      item.name,
      collectorDisplayState(item),
      hardwareSummary(item),
      softwareSummary(item.key),
      item.events_this_session,
      item.last_event || "",
      displayWarning(item)
    ].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      tr.appendChild(td);
    });
    const control = document.createElement("td");
    const state = String(item.state || "");
    const running = state === "ONLINE" || state === "RETRYING" || state === "DETECTING";
    const stopped = state === "STOPPED" || state === "OFFLINE";
    if (!running) {
      const start = document.createElement("button");
      start.textContent = "Start";
      start.addEventListener("click", () => {
        setCollectorBanner(item.key, "STARTING", "Start requested");
        socket.emit("collector_control", {key: item.key, action: "start"});
      });
      control.appendChild(start);
    }
    if (!stopped) {
      const stop = document.createElement("button");
      stop.textContent = "Stop";
      stop.addEventListener("click", () => {
        setCollectorBanner(item.key, "STOPPING", "Stop requested");
        socket.emit("collector_control", {key: item.key, action: "stop"});
      });
      control.appendChild(stop);
    }
    tr.appendChild(control);
    tbody.appendChild(tr);
  });
  maybeRefreshEmptyDerivedViews("collector events");
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
  setCollectorBanner(item.key, visualState, collectorStatusDetail(item));
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

function collectorStatusDetail(item) {
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
  if (state === "IDLE") return "IDLE / on demand";
  return String(state || "Unknown").replace(/_/g, " ");
}

function setCollectorBanner(key, state, detail) {
  const banner = document.getElementById(`${key}-banner`);
  if (!banner) return;
  const label = displayState(state);
  banner.textContent = detail ? `${label}: ${detail}` : label;
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
  if (latestCollectorStatuses.length) renderCollectorHealth(latestCollectorStatuses);
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
  return item.hardware || "";
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
  if (key === "rtlsdr") {
    return [
      executableStatus("rtl_power", detected.rtl_power),
      executableStatus("rtl_test", detected.rtl_test)
    ].filter(Boolean).join(", ");
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
  return "";
}

function executableStatus(name, found) {
  if (found === undefined) return "";
  return `${name}: ${found ? "located" : "missing"}`;
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
