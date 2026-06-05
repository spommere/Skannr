const TABLE_SCHEMAS = {
  rtlsdrSignals: [
    (item) => item.frequency_mhz,
    (item) => item.power_dbm,
    (item) => item.above_floor_db,
    (item) => item.first_seen || "",
    (item) => item.last_seen || ""
  ],
  btClassicDevices: [
    (item) => detailLink(item.mac || "", "bluetooth-device", item.mac || ""),
    (item) => bluetoothDisplayName(item.name, item.mac),
    (item) => item.vendor_name || item.vendor_prefix || "",
    (item) => item.class || "",
    (item) => item.clock_offset || "",
    (item) => item.last_seen || ""
  ],
  bleIdentifyResults: [
    (item) => item.timestamp || "",
    (item) => item.mac || "",
    (item) =>
      item.event_type === "identify_result"
        ? "identified"
        : (item.reason || item.event_type || ""),
    (item) => item.manufacturer_name || "",
    (item) => item.model_number || "",
    (item) => item.serial_number || "",
    (item) => item.firmware_revision || "",
    (item) => item.hardware_revision || "",
    (item) => item.software_revision || "",
    (item) => item.pnp_id || ""
  ],
  wifiMonitorEvents: [
    (item) => item.event_type || "",
    (item) => item.channel || "",
    (item) => item.client_mac || "",
    (item) => item.ap_mac || item.bssid || "",
    (item) => item.ssid || item.ssid_probed || "",
    (item) => formatSignal(item.rssi),
    (item) => item.last_seen || ""
  ],
  aprsisEvents: [
    (item) => item.last_seen || "",
    (item) => item.packet_type || item.event_type || "",
    (item) => aprsisSubjectLink(item),
    (item) => formatAprsisTarget(item),
    (item) => formatAprsisRoute(item),
    (item) => formatAprsisText(item),
    (item) => formatAprsisPosition(item),
    (item) => formatAprsisMotion(item)
  ],
  noaaEvents: [
    (item) => item.last_seen || "",
    (item) => item.alert_kind || item.event_type || "",
    (item) => noaaSeverityText(item),
    (item) => noaaEventTimeText(item),
    (item) => noaaSubjectLink(item),
    (item) => item.area_desc || "",
    (item) => noaaTimingText(item),
    (item) => item.source || ""
  ],
  usgsEvents: [
    (item) => item.last_seen || "",
    (item) => item.event_time || item.last_seen || "",
    (item) => usgsSubjectLink(item),
    (item) => usgsMagnitudeText(item),
    (item) => item.place || "",
    (item) => usgsDistanceText(item),
    (item) => item.depth_km !== undefined ? `${item.depth_km} km` : "",
    (item) => usgsAlertText(item),
    (item) => item.status || ""
  ],
  swpcEvents: [
    (item) => item.last_seen || "",
    (item) => item.event_time || item.peak_time || item.issue_time || "",
    (item) => swpcKindText(item),
    (item) => swpcLevelText(item),
    (item) => swpcSubjectLink(item),
    (item) => swpcTimingText(item),
    (item) => swpcDetailsText(item)
  ],
  lanEvents: [
    (item) => item.last_seen || "",
    (item) => item.event_type || "",
    (item) => lanSubjectLink(item),
    (item) => lanIdentityText(item),
    (item) => lanInterfaceStateText(item),
    (item) => compactList(item.sources || (item.source ? [item.source] : []), 3),
    (item) => lanGatewayText(item),
    (item) => item.change_type || ""
  ],
  wifiAccessPoints: [
    (item) => detailLink(item.ssid || "(blank)", "wifi-ssid", item.ssid || "(blank)"),
    (item) => detailLink(item.bssid || "", "wifi-bssid", item.bssid || ""),
    (item) => vendorLabel(item),
    (item) => channelFreq(item.channel, item.frequency_band),
    (item) => item.encryption || "",
    (item) => formatSignal(item.rssi),
    (item) => item.last_seen
  ]
};

function schemaCells(schemaName, item) {
  return TABLE_SCHEMAS[schemaName].map((value) => value(item));
}

function renderSchemaTable(id, items, schemaName, options) {
  renderTable(id, items, (item) => schemaCells(schemaName, item), options);
}

function renderTable(id, items, cellBuilder, options) {
  const tbody = document.getElementById(id);
  if (!tbody) return;
  tbody.innerHTML = "";
  const maxRows = uiNumber("max_live_rows");
  const keepIncomingOrder = options && options.preserveOrder;
  const ordered = keepIncomingOrder
    ? items.slice(0, maxRows)
    : items.slice(-maxRows).reverse();
  ordered.forEach((item) => {
    const tr = document.createElement("tr");
    cellBuilder(item).forEach((value) => {
      const td = document.createElement("td");
      appendTableCellValue(td, value);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function renderHistoryTable(id, items, cellBuilder, searchInput) {
  const tbody = document.getElementById(id);
  tbody.innerHTML = "";
  const maxRows = uiNumber("max_history_rows");
  const rows = [];
  for (const item of items) {
    const cells = cellBuilder(item);
    if (!rowMatchesSearch(cells, searchInput)) continue;
    rows.push(cells);
    if (rows.length >= maxRows) break;
  }
  rows.forEach((cells) => {
    const tr = document.createElement("tr");
    cells.forEach((value) => {
      const td = document.createElement("td");
      appendTableCellValue(td, value);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function rowMatchesSearch(values, input) {
  if (!input) return true;
  const needle = String(input.value || "").trim().toLowerCase();
  if (!needle) return true;
  return values.some((value) =>
    tableCellSearchText(value)
      .toLowerCase()
      .includes(needle)
  );
}

function appendTableCellValue(cell, value) {
  if (value instanceof Node) {
    cell.appendChild(value);
    return;
  }
  if (value && value.node instanceof Node) {
    cell.appendChild(value.node);
    return;
  }
  cell.textContent = tableCellSearchText(value);
}

function tableCellSearchText(value) {
  if (value instanceof Node) return value.textContent || "";
  if (value && value.node instanceof Node) {
    return value.text || value.node.textContent || "";
  }
  return String(value === null || value === undefined ? "" : value);
}
