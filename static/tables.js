const TABLE_SCHEMAS = {
  rtlsdrSignals: [
    (item) => item.frequency_mhz,
    (item) => item.power_dbm,
    (item) => item.above_floor_db,
    (item) => item.first_seen || "",
    (item) => item.last_seen || ""
  ],
  btClassicDevices: [
    (item) => item.mac || "",
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
  wifiAccessPoints: [
    (item) => item.ssid || "",
    (item) => item.bssid || "",
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
      td.textContent = value;
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
  return values.some((value) =>
    String(value === null || value === undefined ? "" : value)
      .toLowerCase()
      .includes(needle)
  );
}
