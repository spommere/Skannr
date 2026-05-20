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
const transientCollectorBanners = new Map();
let uiConfig = {
  max_live_rows: 200,
  max_history_rows: 500,
  max_event_log_items: 100,
  max_rendered_findings: 1000,
  max_history_ssids: 8,
  derived_stale_after_min: 15,
  insights_recent_after_min: 30,
  wifi_signal_bands: [
    {value: "strong", label: "Strong (>= -60)", min: -60},
    {value: "okay", label: "Okay (-60 to -70)", min: -70, max: -60},
    {value: "poor", label: "Poor (-70 to -80)", min: -80, max: -70},
    {value: "very_poor", label: "Very Poor (-80 or worse)", max: -80}
  ]
};

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
  insightsRefreshButton.addEventListener("click", refreshDerivedViews);
}
const reportsRefreshButton = document.getElementById("reports-refresh");
if (reportsRefreshButton) {
  reportsRefreshButton.addEventListener("click", refreshDerivedViews);
}
const reportsSearch = document.getElementById("reports-search");
if (reportsSearch) {
  reportsSearch.addEventListener("input", () => renderReports(latestReports || {}));
}
const wifiSsidFilter = document.getElementById("wifi-ssid-filter");
if (wifiSsidFilter) {
  wifiSsidFilter.addEventListener("change", renderWifiTables);
}
const wifiEncryptionFilter = document.getElementById("wifi-encryption-filter");
if (wifiEncryptionFilter) {
  wifiEncryptionFilter.addEventListener("change", renderWifiTables);
}
const wifiSignalFilter = document.getElementById("wifi-signal-filter");
if (wifiSignalFilter) {
  wifiSignalFilter.addEventListener("change", renderWifiTables);
}
const bleMacFilter = document.getElementById("ble-mac-filter");
if (bleMacFilter) {
  bleMacFilter.addEventListener("change", renderBleTable);
}
const bleIdentifyButton = document.getElementById("ble-identify-button");
if (bleIdentifyButton) {
  bleIdentifyButton.addEventListener("click", requestBleIdentify);
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
const historyRefreshButton = document.getElementById("history-refresh");
if (historyRefreshButton) {
  historyRefreshButton.addEventListener("click", refreshDerivedViews);
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
renderBleIdentifyDevices();
setInterval(updateDerivedStatusLines, 60000);

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
  rows.reports.filter(reportMatchesSubtab).filter(reportMatchesSearch).slice(0, uiNumber("max_rendered_findings")).forEach((report) => {
    const tr = document.createElement("tr");
    reportColumns(report).forEach((column) => {
      const td = document.createElement("td");
      td.className = `report-col-${column.key}`;
      td.textContent = column.value;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  updateReportsStatus(latestReports);
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
    {key: "severity", label: "Severity", value: report.severity || ""}
  ];
  if (showReportsSourceColumn()) columns.push({key: "source", label: "Source", value: sourceLabel(report.source)});
  columns.push(
    {key: "type", label: "Type", value: categoryForType(report.type || "report")},
    {key: "report", label: "Report", value: report.title || ""},
    {key: "summary", label: "Summary", value: report.summary || ""},
    {key: "evidence", label: "Evidence", value: evidenceText(report.evidence || {}, report.summary || "")},
    {key: "last-seen", label: "Last Seen", value: report.last_seen || ""}
  );
  return columns;
}

function loadDerivedViews() {
  fetch(`/derived_views${windowQuery()}`)
    .then((response) => response.json())
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

function refreshDerivedViews() {
  setDerivedStatus("Refreshing derived data", "warning");
  fetch("/derived_views/refresh", windowRequestOptions())
    .then((response) => response.json())
    .then(renderDerivedViews)
    .catch((error) => setDerivedStatus(`Derived refresh failed: ${error}`, "alert"));
}

function renderDerivedViews(bundle) {
  renderFindingsHistory(bundle.findings || {});
  renderDeviceHistory(bundle.device_history || {});
  renderHistoryAnalysis(bundle.history_analysis || {});
  renderReports(bundle.reports || {});
  renderCombinedInsights();
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
  if (latestFindingsHistory || latestHistoryAnalysis) updateInsightsStatus();
  if (latestReports) updateReportsStatus(latestReports);
  if (latestDeviceHistory) updateDeviceHistoryStatus(latestDeviceHistory);
}

function derivedStatusPrefix(window, generatedAt, generatedAtEpoch) {
  const parts = [((window || {}).label || "Selected range")];
  if (generatedAt) parts.push(`refreshed ${generatedAt}`);
  const stale = derivedStaleText(generatedAt, generatedAtEpoch);
  if (stale) parts.push(stale);
  return parts.join(" | ");
}

function derivedStatusState(generatedAt, generatedAtEpoch, normalState) {
  return derivedStaleText(generatedAt, generatedAtEpoch) && normalState !== "alert" ? "warning" : normalState;
}

function derivedStaleText(generatedAt, generatedAtEpoch) {
  const threshold = uiNonNegativeNumber("derived_stale_after_min");
  if (!generatedAt || threshold <= 0) return "";
  const timestampMs = Number.isFinite(Number(generatedAtEpoch)) ? Number(generatedAtEpoch) * 1000 : parseSkannrTimestampMs(generatedAt);
  if (!timestampMs) return "";
  const ageMin = Math.floor((Date.now() - timestampMs) / 60000);
  if (ageMin < threshold) return "";
  return `stale: refreshed ${ageMin} min ago`;
}

function parseSkannrTimestampMs(text) {
  const value = String(text || "").trim();
  if (!value) return null;
  const legacyUtc = value.endsWith("Z") ? value : null;
  const local = value.includes(" ") ? value.replace(" ", "T") : value;
  const parsed = new Date(legacyUtc || local);
  return Number.isNaN(parsed.getTime()) ? null : parsed.getTime();
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
  const visible = rows.reports.filter(reportMatchesSubtab).filter(reportMatchesSearch);
  const warnings = rows.reports.filter((item) => item.severity === "warning").length;
  setReportsStatus(
    `${derivedStatusPrefix(window, refreshedAt, refreshedEpoch)} | ${visible.length} shown | ${total} reports | ${warnings} warnings`,
    derivedStatusState(refreshedAt, refreshedEpoch, visible.some((item) => item.severity === "warning" || item.severity === "error" || item.severity === "alert") ? "warning" : "ok")
  );
}

function reportMatchesSubtab(report) {
  const mode = activeSubtabs.reports || "all";
  if (mode === "all") return true;
  return sourceMatchesSubtab(report.source, mode);
}

function reportMatchesSearch(report) {
  return rowMatchesSearch(reportCells(report), reportsSearch);
}

function showReportsSourceColumn() {
  return (activeSubtabs.reports || "all") === "all";
}

function sortReports(items) {
  return (items || []).sort((left, right) => {
    const severity = severityRank(right.severity) - severityRank(left.severity);
    if (severity !== 0) return severity;
    const score = Number(right.score || 0) - Number(left.score || 0);
    if (score !== 0) return score;
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
  const mode = insightsActivityFilter ? insightsActivityFilter.value : "important";
  if (mode === "all") return true;
  const severity = String(insight.severity || "").toLowerCase();
  const isImportantSeverity = severity === "warning" || severity === "error" || severity === "alert";
  if (mode === "important") {
    return isImportantSeverity || ["active", "recent", "recurring"].includes(activityState(insight));
  }
  if (mode === "recent") {
    return isImportantSeverity || ["active", "recent", "recurring"].includes(activityState(insight));
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
  const timestamp = insight.last_seen || insight.timestamp;
  const timestampMs = parseSkannrTimestampMs(timestamp);
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

function updateWifiSsidFilter() {
  if (!wifiSsidFilter) return;
  const selected = wifiSsidFilter.value || "all";
  const ssids = currentWifiSsids();
  wifiSsidFilter.innerHTML = "";
  appendSelectOption(wifiSsidFilter, "all", "All");
  if (ssids.has("")) appendSelectOption(wifiSsidFilter, "__blank__", "(blank)");
  [...ssids].filter((ssid) => ssid).sort().forEach((ssid) => appendSelectOption(wifiSsidFilter, ssid, ssid));
  wifiSsidFilter.value = selected === "__blank__" && ssids.has("") ? selected : (ssids.has(selected) ? selected : "all");
}

function updateWifiEncryptionFilter() {
  if (!wifiEncryptionFilter) return;
  const selected = wifiEncryptionFilter.value || "all";
  const values = new Set();
  rows.aps.forEach((item) => {
    if (item.encryption) values.add(item.encryption);
  });
  wifiEncryptionFilter.innerHTML = "";
  appendSelectOption(wifiEncryptionFilter, "all", "All");
  [...values].sort().forEach((value) => appendSelectOption(wifiEncryptionFilter, value, value));
  wifiEncryptionFilter.value = values.has(selected) ? selected : "all";
}

function currentWifiSsids() {
  const ssids = new Set();
  rows.aps.forEach((item) => ssids.add(item.ssid || ""));
  return ssids;
}

function appendSelectOption(select, value, label) {
  const option = document.createElement("option");
  option.value = value;
  option.textContent = label;
  select.appendChild(option);
}

function buildSubtabs() {
  document.querySelectorAll(".subtabs[data-subtab-group]").forEach((container) => {
    const group = container.dataset.subtabGroup;
    const selected = activeSubtabs[group] || "all";
    container.innerHTML = "";
    COLLECTOR_SUBTABS.forEach((entry) => {
      const button = document.createElement("button");
      button.className = `subtab ${entry.value === selected ? "active" : ""}`;
      button.dataset.subtab = entry.value;
      button.textContent = entry.label;
      button.addEventListener("click", () => {
        container.querySelectorAll(".subtab").forEach((item) => item.classList.remove("active"));
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
  applyWifiSignalBands();
  applyRtlsdrDefaults((metadata.collectors || {}).rtlsdr || {});
}

function applyAppVersion(version) {
  const node = document.getElementById("app-version");
  if (!node) return;
  node.textContent = version ? `v${version}` : "";
}

function applyWifiSignalBands() {
  if (!wifiSignalFilter) return;
  const selected = wifiSignalFilter.value || "all";
  const bands = Array.isArray(uiConfig.wifi_signal_bands) ? uiConfig.wifi_signal_bands : [];
  wifiSignalFilter.innerHTML = "";
  appendSelectOption(wifiSignalFilter, "all", "All");
  bands.forEach((band) => {
    if (band && band.value) appendSelectOption(wifiSignalFilter, band.value, band.label || band.value);
  });
  wifiSignalFilter.value = bands.some((band) => band && band.value === selected) ? selected : "all";
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
    setCollectorBanner("rtlsdr", "RUNNING", `primary | ${event.data.range} | gain=${event.data.gain}`);
  }
  if (event.type === "baseline_ready") {
    document.getElementById("baseline-state").textContent = `Detection active (${event.data.bins} bins)`;
  }
  if (event.type === "signal_detected") {
    const item = {...event.data, first_seen: event.timestamp, last_seen: event.timestamp};
    rows.signals.set(item.frequency_mhz, item);
    prependList("rtlsdr-events", `${event.timestamp} detected ${item.frequency_mhz} MHz +${item.above_floor_db} dB`);
  }
  if (event.type === "signal_lost") {
    rows.signals.delete(event.data.frequency_mhz);
    prependList("rtlsdr-events", `${event.timestamp} lost ${event.data.frequency_mhz} MHz`);
  }
  renderTable("rtlsdr-signals", [...rows.signals.values()], (item) => [
    item.frequency_mhz, item.power_dbm, item.above_floor_db, item.first_seen || "", item.last_seen || ""
  ]);
}

function renderBleEvent(event) {
  document.getElementById("ble-status").textContent = event.type;
  if (event.type === "collector_offline" || event.type === "collector_retrying" || event.type === "hardware_fallback") {
    setCollectorBanner("ble", event.type, event.data.reason || event.data.warning || "");
  }
  if (event.type === "scanner_started") {
    setCollectorBanner("ble", "RUNNING", `${tierLabel(event.data.tier)} | Adapter ${event.data.adapter}`);
  }
  if (!["device_seen", "device_updated"].includes(event.type)) return;
  const data = event.data;
  const key = data.mac;
  const current = rows.ble.get(key) || {};
  const merged = {...current, ...data, last_seen: event.timestamp};
  rows.ble.set(key, merged);
  updateBleMacFilter();
  renderBleTable();
  renderBleIdentifyDevices();
}

function updateBleMacFilter() {
  if (!bleMacFilter) return;
  const selected = bleMacFilter.value || "all";
  const macs = new Set();
  rows.ble.forEach((item) => {
    if (item.mac) macs.add(item.mac);
  });
  bleMacFilter.innerHTML = "";
  appendSelectOption(bleMacFilter, "all", "All");
  [...macs].sort().forEach((mac) => appendSelectOption(bleMacFilter, mac, mac));
  bleMacFilter.value = macs.has(selected) ? selected : "all";
}

function renderBleTable() {
  renderTable("ble-devices", [...rows.ble.values()].filter(bleDeviceMatchesFilters), (item) => [
    item.mac, bleDeviceName(item), formatSignal(item.rssi), item.manufacturer || "",
    (item.service_uuids || []).join(", "), item.last_seen || ""
  ]);
}

function bleDeviceMatchesFilters(item) {
  const mode = bleMacFilter ? bleMacFilter.value : "all";
  if (mode === "all") return true;
  return item.mac === mode;
}

function renderBtClassicEvent(event) {
  document.getElementById("bt_classic-status").textContent = event.type;
  const data = event.data || {};
  if (event.type === "scanner_started") {
    setCollectorBanner("bt_classic", "RUNNING", `${tierLabel(data.tier)} | Adapter ${data.adapter}`);
  }
  if (event.type === "classic_scan_started") {
    setBtClassicScanState(`Scanning on ${data.adapter || "adapter"}...`, "warning");
  }
  if (event.type === "classic_scan_completed") {
    const count = Number(data.devices || 0);
    const label = count === 1 ? "1 device" : `${count} devices`;
    setBtClassicScanState(`Last scan completed at ${event.timestamp}: ${label} found in ${data.duration_sec || "?"}s`, count ? "ok" : "muted");
  }
  if (event.type === "hardware_fallback" || event.type === "collector_offline" || event.type === "collector_retrying") {
    setCollectorBanner("bt_classic", event.type, data.reason || data.warning || "");
  }
  if (event.type === "classic_device_seen" || event.type === "classic_device_updated") {
    const key = data.mac;
    const current = rows.btClassic.get(key) || {};
    rows.btClassic.set(key, {...current, ...data, last_seen: event.timestamp});
    renderBtClassicTable();
  }
  if (event.type === "classic_device_lost") {
    const current = rows.btClassic.get(data.mac) || data;
    rows.btClassic.set(data.mac, {...current, last_seen: event.timestamp, state: "lost"});
    renderBtClassicTable();
  }
}

function renderBtClassicTable() {
  renderTable("bt-classic-devices", [...rows.btClassic.values()], (item) => [
    item.mac || "",
    bluetoothDisplayName(item.name, item.mac),
    item.vendor_name || item.vendor_prefix || "",
    item.class || "",
    item.clock_offset || "",
    item.last_seen || ""
  ]);
}

function setBtClassicScanState(text, state) {
  const node = document.getElementById("bt-classic-scan-state");
  if (!node) return;
  node.textContent = text;
  node.className = `status-strip ${state || "muted"}`;
}

function requestBleIdentify() {
  const macInput = document.getElementById("ble-identify-mac");
  const timeoutInput = document.getElementById("ble-identify-timeout");
  const mac = macInput ? macInput.value.trim() : "";
  const timeout = timeoutInput ? Number(timeoutInput.value) : 10;
  identifyBleMac(mac, timeout);
}

function identifyBleMac(mac, timeout) {
  if (!mac) {
    setTransientCollectorBanner("ble_identify", "identify_failed", "Enter a BLE MAC address");
    return;
  }
  const normalizedTimeout = Number(timeout);
  const macInput = document.getElementById("ble-identify-mac");
  const timeoutInput = document.getElementById("ble-identify-timeout");
  if (macInput) macInput.value = mac;
  if (timeoutInput && Number.isFinite(normalizedTimeout)) timeoutInput.value = normalizedTimeout;
  setTransientCollectorBanner("ble_identify", "IDENTIFYING", `Identifying ${mac}`, 5000);
  fetch("/ble_identify", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({mac, timeout_sec: Number.isFinite(normalizedTimeout) ? normalizedTimeout : 10})
  }).then((response) => {
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  }).catch((error) => {
    setTransientCollectorBanner("ble_identify", "identify_failed", `Identify request failed: ${error}`);
  });
}

function renderBleIdentifyEvent(event) {
  document.getElementById("ble_identify-status").textContent = event.type;
  const data = event.data || {};
  if (event.type === "identify_started") {
    setTransientCollectorBanner("ble_identify", "IDENTIFYING", `${data.mac} via ${data.adapter || "adapter"}`, 5000);
  } else if (event.type === "identify_result") {
    setTransientCollectorBanner("ble_identify", "STOPPED", `${data.mac}: ${data.manufacturer_name || data.model_number || "identified"}`);
    rows.bleIdentify.unshift({...data, event_type: event.type, timestamp: event.timestamp});
    rows.bleIdentify = rows.bleIdentify.slice(0, uiNumber("max_live_rows"));
    mergeBleIdentifyResult(data, event.timestamp);
    renderBleIdentifyTable();
    renderBleIdentifyDevices();
  } else if (event.type === "identify_failed" || event.type === "collector_offline") {
    setTransientCollectorBanner("ble_identify", event.type, data.reason || "Identify failed");
    rows.bleIdentify.unshift({...data, event_type: event.type, timestamp: event.timestamp});
    rows.bleIdentify = rows.bleIdentify.slice(0, uiNumber("max_live_rows"));
    renderBleIdentifyTable();
  }
}

function renderBleIdentifyTable() {
  renderTable("ble-identify-results", rows.bleIdentify, (item) => [
    item.timestamp || "",
    item.mac || "",
    item.event_type === "identify_result" ? "identified" : (item.reason || item.event_type || ""),
    item.manufacturer_name || "",
    item.model_number || "",
    item.firmware_revision || "",
    item.hardware_revision || "",
    item.software_revision || ""
  ]);
}

function mergeBleIdentifyResult(data, timestamp) {
  if (!data || !data.mac) return;
  const current = rows.ble.get(data.mac) || {};
  rows.ble.set(data.mac, {
    ...current,
    ...data,
    last_seen: current.last_seen || timestamp
  });
}

function renderBleIdentifyDevices() {
  const tbody = document.getElementById("ble-identify-devices");
  if (!tbody) return;
  tbody.innerHTML = "";
  const devices = knownBleIdentifyDevices().slice(0, uiNumber("max_history_rows"));
  if (!devices.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.textContent = "No BLE Scan or Device History devices available yet";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  devices.forEach((item) => {
    const tr = document.createElement("tr");
    [
      item.mac || "",
      bleDeviceName(item),
      item.manufacturer_name || item.manufacturer || "",
      formatSignal(item.rssi !== undefined ? item.rssi : item.signal_latest),
      item.last_seen || "",
      bleIdentitySummary(item)
    ].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      tr.appendChild(td);
    });
    const actionCell = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Identify";
    button.addEventListener("click", () => identifyBleMac(item.mac || "", currentBleIdentifyTimeout()));
    actionCell.appendChild(button);
    tr.appendChild(actionCell);
    tbody.appendChild(tr);
  });
}

function knownBleIdentifyDevices() {
  const merged = new Map();
  const historyDevices = ((((latestDeviceHistory || {}).bluetooth || (latestDeviceHistory || {}).ble || {}).devices) || []);
  historyDevices.filter((item) => !item.transports || (item.transports || []).includes("ble")).forEach((item) => mergeKnownBleDevice(merged, item));
  rows.ble.forEach((item) => mergeKnownBleDevice(merged, item));
  return [...merged.values()].sort(compareBleIdentifyDevices);
}

function mergeKnownBleDevice(merged, item) {
  if (!item || !item.mac) return;
  const current = merged.get(item.mac) || {};
  merged.set(item.mac, {...current, ...item});
}

function compareBleIdentifyDevices(left, right) {
  const leftSeen = left.last_seen || "";
  const rightSeen = right.last_seen || "";
  if (leftSeen !== rightSeen) return rightSeen.localeCompare(leftSeen);
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

function bleIdentitySummary(item) {
  const values = [
    item.manufacturer_name,
    item.model_number,
    item.firmware_revision,
    item.hardware_revision,
    item.software_revision
  ].filter(Boolean);
  return values.join(" | ");
}

function currentBleIdentifyTimeout() {
  const timeoutInput = document.getElementById("ble-identify-timeout");
  const timeout = timeoutInput ? Number(timeoutInput.value) : 10;
  return Number.isFinite(timeout) ? timeout : 10;
}

function renderWifiEvent(event) {
  document.getElementById("wifi-status").textContent = event.type;
  if (event.type === "interface_mode") {
    const mode = "managed scan";
    const tier = event.data.warning ? "fallback" : "primary";
    setCollectorBanner("wifi", event.data.warning ? "hardware_fallback" : "RUNNING", `${tier} | ${event.data.interface} ${mode}${event.data.warning ? `: ${event.data.warning}` : ""}`);
  }
  if (event.type === "collector_retrying" || event.type === "collector_offline") {
    setCollectorBanner("wifi", event.type, event.data.reason || "");
  }
  if (event.type === "scan_started") {
    setCollectorBanner("wifi", "RUNNING", `${event.data.interface}: ${event.data.note}`);
  }
  if (event.type === "scan_empty") {
    setCollectorBanner("wifi", "collector_retrying", `${event.data.interface}: no SSIDs found; ${event.data.diagnostics || ""}`);
  }
  if (event.type === "ap_beacon") {
    rows.aps.set(event.data.bssid, {...event.data, last_seen: event.timestamp});
    updateWifiSsidFilter();
    updateWifiEncryptionFilter();
    renderWifiTables();
  }
}

function renderWifiMonitorEvent(event) {
  document.getElementById("wifi_monitor-status").textContent = event.type;
  if (event.type === "monitor_started") {
    const data = event.data || {};
    setCollectorBanner("wifi_monitor", "RUNNING", `primary | ${data.interface} | channels ${formatChannelList(data.channels)} | dwell ${data.dwell_sec}s`);
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
    rows.monitorEvents.unshift({...event.data, event_type: event.type, last_seen: event.timestamp});
    rows.monitorEvents = rows.monitorEvents.slice(0, uiNumber("max_live_rows"));
    renderWifiMonitorTable();
  }
}

function renderWifiMonitorTable() {
  renderTable("wifi-monitor-events", rows.monitorEvents, (item) => [
    item.event_type || "",
    item.channel || "",
    item.client_mac || "",
    item.ap_mac || item.bssid || "",
    item.ssid || item.ssid_probed || "",
    formatSignal(item.rssi),
    item.last_seen || ""
  ]);
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
  renderTable("wifi-aps", [...rows.aps.values()].filter(wifiApMatchesFilters), (item) => [
    item.ssid || "", item.bssid || "", vendorLabel(item), channelFreq(item.channel, item.frequency_band), item.encryption || "", formatSignal(item.rssi), item.last_seen
  ]);
}

function renderDeviceHistory(history) {
  latestDeviceHistory = history;
  updateDeviceHistoryStatus(history);
  const wifi = history.wifi || {};
  const ble = history.bluetooth || history.ble || {};
  const aps = wifi.access_points || [];
  const clients = wifi.clients || [];
  const devices = ble.devices || [];
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
    item.firmware_revision || "",
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
  renderBleIdentifyDevices();
}

function updateDeviceHistoryStatus(history) {
  const wifi = history.wifi || {};
  const ble = history.bluetooth || history.ble || {};
  const aps = wifi.access_points || [];
  const clients = wifi.clients || [];
  const devices = ble.devices || [];
  const window = history.window || {};
  const refreshedAt = history.refreshed_at || history.generated_at;
  setHistoryStatus(
    `${derivedStatusPrefix(window, refreshedAt, history.refreshed_at_epoch || history.generated_at_epoch)} | ${history.records_read || 0} records | ${aps.length} APs | ${clients.length} Wi-Fi clients | ${devices.length} Bluetooth devices`,
    derivedStatusState(refreshedAt, history.refreshed_at_epoch || history.generated_at_epoch, "ok")
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
    const leftMs = parseSkannrTimestampMs(left.timestamp);
    const rightMs = parseSkannrTimestampMs(right.timestamp);
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
    severity: finding.severity || "",
    source: finding.source || "",
    type: finding.type || "finding",
    category: categoryForType(finding.type || "finding"),
    title: finding.title || "",
    detail,
    evidence_text: evidenceText(finding.attributes || {}, detail),
    activity_state: finding.activity_state || "",
    last_seen: finding.last_seen || finding.timestamp || "",
    origin: "live event",
  };
}

function normalizeObservationInsight(observation) {
  const detail = observation.detail || "";
  return {
    timestamp: observation.timestamp || "",
    severity: observation.severity || "",
    source: observation.source || "",
    type: observation.type || "observation",
    category: categoryForType(observation.type || "observation"),
    title: observation.title || "",
    detail,
    evidence_text: evidenceText(observation.evidence || {}, detail),
    activity_state: observation.activity_state || "",
    last_seen: observation.last_seen || "",
    age_minutes: observation.age_minutes,
    origin: "device history",
    score: observation.score || 0,
  };
}

function updateInsightsStatus() {
  const source = latestHistoryAnalysis || latestFindingsHistory || {};
  const window = source.window || {};
  const refreshedAt = source.refreshed_at || source.generated_at;
  const refreshedEpoch = source.refreshed_at_epoch || source.generated_at_epoch;
  const total = rows.insights.length;
  const visible = rows.insights.filter(insightMatchesFilters).filter(insightMatchesSearch);
  const warnings = rows.insights.filter((item) => item.severity === "warning").length;
  const errors = rows.insights.filter((item) => item.severity === "error" || item.severity === "alert").length;
  setInsightsStatus(
    `${derivedStatusPrefix(window, refreshedAt, refreshedEpoch)} | ${visible.length} shown | ${total} insights | ${warnings} warnings | ${errors} errors`,
    derivedStatusState(refreshedAt, refreshedEpoch, visible.some((item) => item.severity === "warning" || item.severity === "error" || item.severity === "alert") ? "warning" : "ok")
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

function evidenceText(evidence, detail) {
  if (!evidence) return "";
  const parts = [];
  const detailText = String(detail || "").toLowerCase();
  Object.keys(evidence).sort().forEach((key) => {
    const value = evidence[key];
    if (evidenceValueAlreadyShown(value, detailText)) return;
    if (Array.isArray(value)) {
      parts.push(`${key}: ${value.join(", ")}`);
    } else {
      parts.push(`${key}: ${value}`);
    }
  });
  return parts.join(" | ");
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

function wifiApMatchesFilters(item) {
  return wifiSsidMatches(item.ssid || "") &&
    wifiEncryptionMatches(item.encryption || "") &&
    wifiSignalMatches(item.rssi);
}

function wifiSsidMatches(ssid) {
  const mode = wifiSsidFilter ? wifiSsidFilter.value : "all";
  if (mode === "all") return true;
  if (mode === "__blank__") return !ssid;
  return ssid === mode;
}

function wifiEncryptionMatches(encryption) {
  const mode = wifiEncryptionFilter ? wifiEncryptionFilter.value : "all";
  if (mode === "all") return true;
  return encryption === mode;
}

function wifiSignalMatches(value) {
  const mode = wifiSignalFilter ? wifiSignalFilter.value : "all";
  if (mode === "all") return true;
  const signal = Number(value);
  if (Number.isNaN(signal)) return false;
  const bands = Array.isArray(uiConfig.wifi_signal_bands) ? uiConfig.wifi_signal_bands : [];
  const band = bands.find((entry) => entry && entry.value === mode);
  if (!band) return true;
  if (band.min !== undefined && signal < Number(band.min)) return false;
  if (band.max !== undefined) {
    if (band.min === undefined) return signal <= Number(band.max);
    return signal < Number(band.max);
  }
  return true;
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
      displayState(item.state),
      hardwareSummary(item),
      softwareSummary(item.key),
      item.events_this_session,
      item.last_event || "",
      item.warning || ""
    ].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      tr.appendChild(td);
    });
    const control = document.createElement("td");
    if (item.key === "ble_identify") {
      control.textContent = "Manual";
    } else {
      const state = String(item.state || "");
      const running = state.startsWith("RUNNING") || state === "RETRYING" || state === "DETECTING";
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
    }
    tr.appendChild(control);
    tbody.appendChild(tr);
  });
}

function updateCollectorTabStatus(item) {
  const status = document.getElementById(`${item.key}-status`);
  const visualState = item.warning && String(item.state).startsWith("RUNNING") ? "hardware_fallback" : item.state;
  if (status) {
    status.textContent = displayState(item.state);
    status.className = `badge ${badgeClassForState(visualState)}`;
  }
  updateCollectorActionButtons(item);
  if (hasActiveTransientCollectorBanner(item.key)) return;
  setCollectorBanner(item.key, visualState, collectorStatusDetail(item));
}

function updateCollectorActionButtons(item) {
  if (item.key !== "bt_classic") return;
  const state = String(item.state || "");
  const running = state.startsWith("RUNNING") || state === "RETRYING" || state === "DETECTING";
  const start = document.getElementById("bt-classic-start");
  const stop = document.getElementById("bt-classic-stop");
  if (start) start.style.display = running ? "none" : "";
  if (stop) stop.style.display = running ? "" : "none";
}

function collectorStatusDetail(item) {
  const hardware = hardwareSummary(item);
  const warning = item.warning ? ` | ${item.warning}` : "";
  return `${hardware}${warning}`.replace(/^\s*\|\s*/, "") || item.warning || "";
}

function tierLabel(state) {
  if (state === "RUNNING_TIER1") return "primary";
  if (state === "RUNNING_TIER2") return "fallback";
  if (state === "RUNNING") return "Running";
  return String(state || "Unknown").replace(/_/g, " ");
}

function displayState(state) {
  if (state === "RUNNING_TIER1") return "RUNNING primary";
  if (state === "RUNNING_TIER2") return "RUNNING fallback";
  return tierLabel(state);
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
  if (String(state).startsWith("RUNNING")) return "ok";
  if (state === "RETRYING" || state === "STARTING" || state === "STOPPING" || state === "hardware_fallback") return "warning";
  if (state === "OFFLINE") return "alert";
  return "muted";
}

function bannerClassForState(state) {
  if (String(state).startsWith("RUNNING") || state === "RUNNING") return "ok";
  if (state === "RETRYING" || state === "STARTING" || state === "STOPPING" || state === "hardware_fallback" || state === "collector_retrying") return "warning";
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
    return [
      detected.preferred_detected === undefined ? null : `${detected.preferred_interface || "preferred interface"}: ${detected.preferred_detected ? "found" : "missing"}`,
      detected.fallback_detected === undefined ? null : `${detected.fallback_interface || "fallback interface"}: ${detected.fallback_detected ? "found" : "missing"}`,
      item.hardware ? `active: ${item.hardware}` : null
    ].filter(Boolean).join(", ");
  }
  if (item.key === "wifi_monitor") {
    const active = item.hardware && item.hardware !== "Wi-Fi adapter already in monitor mode";
    return [
      detected.interface ? `configured: ${detected.interface}` : null,
      active ? `active: ${item.hardware}` : null,
      detected.auto_start === false ? "on demand" : null
    ].filter(Boolean).join(", ");
  }
  if (item.key === "ble") {
    return [
      detected.preferred_detected === undefined ? null : `${detected.preferred_adapter || "preferred adapter"}: ${detected.preferred_detected ? "found" : "missing"}`,
      detected.fallback_detected === undefined ? null : `${detected.fallback_adapter || "fallback adapter"}: ${detected.fallback_detected ? "found" : "missing"}`,
      item.hardware ? `active: ${item.hardware}` : null
    ].filter(Boolean).join(", ");
  }
  if (item.key === "ble_identify" || item.key === "bt_classic") {
    return [
      detected.preferred_detected === undefined ? null : `${detected.preferred_adapter || "preferred adapter"}: ${detected.preferred_detected ? "found" : "missing"}`,
      detected.fallback_detected === undefined ? null : `${detected.fallback_adapter || "fallback adapter"}: ${detected.fallback_detected ? "found" : "missing"}`,
      detected.auto_start === false ? "on demand" : null,
      item.hardware ? `active: ${item.hardware}` : null
    ].filter(Boolean).join(", ");
  }
  return item.hardware || "";
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
  if (key === "ble" || key === "ble_identify") {
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

function renderTable(id, items, cellBuilder) {
  const tbody = document.getElementById(id);
  if (!tbody) return;
  tbody.innerHTML = "";
  items.slice(-uiNumber("max_live_rows")).reverse().forEach((item) => {
    const tr = document.createElement("tr");
    cellBuilder(item).forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function renderHistoryTable(id, items, cellBuilder, searchInput) {
  const tbody = document.getElementById(id);
  tbody.innerHTML = "";
  items.filter((item) => rowMatchesSearch(cellBuilder(item), searchInput)).slice(0, uiNumber("max_history_rows")).forEach((item) => {
    const tr = document.createElement("tr");
    cellBuilder(item).forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function rowMatchesSearch(values, input) {
  if (!input) return true;
  const needle = String(input.value || "").trim().toLowerCase();
  if (!needle) return true;
  return values.some((value) => String(value === null || value === undefined ? "" : value).toLowerCase().includes(needle));
}

function prependList(id, text) {
  const list = document.getElementById(id);
  const item = document.createElement("li");
  item.textContent = text;
  list.prepend(item);
  while (list.children.length > uiNumber("max_event_log_items")) list.removeChild(list.lastChild);
}
