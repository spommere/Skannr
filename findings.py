"""Live findings generated from the event stream.

Findings are the immediate, low-memory layer. They are produced while collectors
run, persisted as JSONL, and later materialized for the Insights/Reports views.
Longer historical interpretation belongs in device_history.py, history_analysis.py,
and reports.py.
"""

import time
from collections import deque

from bus import utc_now
from log_utils import utc_epoch


DEFAULT_FINDINGS_CONFIG = {
    "enabled": True,
    "max_items": 200,
    "bootstrap_events": 1000,
    "strong_wifi_rssi": -50,
    "strong_wifi_ap_rssi": -45,
    "strong_ble_rssi": -55,
    "rssi_change_db": 12,
    "return_after_sec": 300,
    "lost_after_sec": 300,
    "burst_window_sec": 30,
    "burst_count": 5,
    "cooldown_sec": 120,
    "persistent_signal_sec": 60,
}


class FindingsEngine:
    """Deterministic findings engine for Skannr events.

    The engine is deliberately not an LLM and not a database. It keeps small
    in-memory maps for recent devices, APs, frequencies, and collector state,
    then emits normalized findings when explicit rules match.
    """

    def __init__(self, config=None):
        self.config = DEFAULT_FINDINGS_CONFIG.copy()
        self.config.update(config or {})
        self.enabled = bool(self.config.get("enabled", True))
        self.max_items = int(self.config.get("max_items", 200))
        self.recent = deque(maxlen=self.max_items)
        self._counter = 0
        self._last_emitted = {}
        self.wifi_clients = {}
        self.wifi_aps = {}
        self.wifi_probe_history = {}
        self.ble_devices = {}
        self.bt_classic_devices = {}
        self.rtlsdr_signals = {}
        self.collector_states = {}

    def bootstrap(self, events):
        """Replay persisted events to rebuild state without replaying old noise."""
        if not self.enabled:
            return None
        replayed = 0
        for event in sorted(
            events or [], key=lambda item: self._to_epoch(item.get("timestamp"))
        ):
            if event.get("collector") == "findings":
                continue
            self.process(event, emit=False)
            replayed += 1
        if not replayed:
            return None
        summary = self._finding(
            utc_now(),
            "info",
            "system",
            "findings_history_loaded",
            "Findings history loaded",
            "Rebuilt findings state from {} persisted events".format(replayed),
            "findings-history-loaded",
            force=True,
        )
        self.recent.appendleft(summary)
        return summary

    def seed_device_history(self, history):
        """Seed known devices from materialized history without emitting noise.

        The live findings engine is intentionally in-memory. After a restart,
        a BSSID or MAC may be known in Device History even when its raw event is
        outside the small bootstrap replay window. Seeding those identities as
        inactive makes the next sighting read as "returned" instead of "new".
        """
        wifi = (history or {}).get("wifi") or {}
        for ap in wifi.get("access_points") or []:
            bssid = ap.get("bssid")
            if not bssid or bssid in self.wifi_aps:
                continue
            self.wifi_aps[bssid] = {
                "active": False,
                "last_seen": ap.get("last_seen") or ap.get("first_seen") or "",
                "last_seen_epoch": self._to_epoch(
                    ap.get("last_seen") or ap.get("first_seen")
                )
                or 0,
                "ssid": ap.get("ssid") or "",
                "rssi": ap.get("signal_latest"),
                "channel": (ap.get("channels") or [None])[-1]
                if isinstance(ap.get("channels"), list)
                else None,
                "source": "wifi_monitor"
                if "wifi_monitor" in (ap.get("sources") or [])
                else "wifi",
                "vendor_oui": ap.get("vendor_oui") or "",
                "vendor_prefix": ap.get("vendor_prefix")
                or ap.get("vendor_oui")
                or "",
                "vendor_name": ap.get("vendor_name") or "",
            }
        for client in wifi.get("clients") or []:
            mac = client.get("mac")
            if not mac or mac in self.wifi_clients:
                continue
            self.wifi_clients[mac] = {
                "active": False,
                "last_seen": client.get("last_seen")
                or client.get("first_seen")
                or "",
                "last_seen_epoch": self._to_epoch(
                    client.get("last_seen") or client.get("first_seen")
                )
                or 0,
                "ssid": "",
                "rssi": client.get("signal_latest"),
                "blank_reported": bool(client.get("blank_ssid_count")),
                "source": "wifi_monitor"
                if "wifi_monitor" in (client.get("sources") or [])
                else "wifi",
                "vendor_oui": client.get("vendor_oui") or "",
                "vendor_prefix": client.get("vendor_prefix")
                or client.get("vendor_oui")
                or "",
                "vendor_name": client.get("vendor_name") or "",
            }

    def process(self, event, emit=True):
        """Process one event and return zero or more new findings."""
        if not self.enabled:
            return []

        timestamp = event.get("timestamp") or utc_now()
        now = self._to_epoch(timestamp)
        findings = []
        if emit:
            # Presence expiration is checked opportunistically when new events
            # arrive. There is no separate timer thread for this engine.
            findings.extend(self._expire_presence(timestamp, now))

        collector = event.get("collector")
        event_type = event.get("type")
        if collector in ("wifi", "wifi_monitor"):
            findings.extend(
                self._process_wifi(
                    collector, event_type, event, timestamp, now, emit
                )
            )
        elif collector == "ble":
            findings.extend(
                self._process_ble(event_type, event, timestamp, now, emit)
            )
        elif collector == "ble_identify":
            findings.extend(
                self._process_ble_identify(event_type, event, timestamp, emit)
            )
        elif collector == "bt_classic":
            findings.extend(
                self._process_bt_classic(
                    event_type, event, timestamp, now, emit
                )
            )
        elif collector == "rtlsdr":
            findings.extend(
                self._process_rtlsdr(event_type, event, timestamp, emit)
            )
        elif collector == "system":
            findings.extend(
                self._process_system(event_type, event, timestamp, emit)
            )

        if emit:
            for finding in findings:
                self.recent.appendleft(finding)
        return findings

    def snapshot(self):
        """Return newest-first findings for browser refresh/reconnect."""
        return list(self.recent)

    def _process_wifi(self, source, event_type, event, timestamp, now, emit):
        """Dispatch Wi-Fi scan and monitor events into rule handlers."""
        data = event.get("data") or {}
        if event_type == "probe_request":
            return self._wifi_probe_request(source, data, timestamp, now, emit)
        if event_type == "ap_beacon":
            return self._wifi_ap_beacon(source, data, timestamp, now, emit)
        if event_type in ("deauth_seen", "disassoc_seen"):
            return self._wifi_disruption(
                source, event_type, data, timestamp, emit
            )
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning(
                source, event_type, data, timestamp, emit
            )
        if event_type == "interface_mode" and data.get("warning"):
            return self._finding_list(
                timestamp,
                "warning",
                source,
                "wifi_fallback_mode",
                "Wi-Fi fallback mode",
                data.get("warning"),
                "wifi-fallback-mode",
                emit,
            )
        return []

    def _wifi_probe_request(self, source, data, timestamp, now, emit):
        findings = []
        mac = data.get("client_mac") or "unknown"
        ssid = data.get("ssid_probed") or ""
        rssi = self._to_number(data.get("rssi"))
        previous = self.wifi_clients.get(mac)
        # Return/new/strong checks compare the new sighting to the in-memory
        # state. Device History seeding makes this survive normal restarts.
        was_active = bool(previous and previous.get("active", True))
        was_strong = self._is_strong(
            previous.get("rssi") if previous else None,
            self.config["strong_wifi_rssi"],
        )
        blank_reported = bool(previous and previous.get("blank_reported"))
        title = "New Wi-Fi client"
        finding_type = "wifi_client_new"
        detail = "Client {} sent a probe request".format(mac)
        if previous and (not was_active or self._is_return(previous, now)):
            title = "Wi-Fi client returned"
            finding_type = "wifi_client_returned"
            detail = "Client {} was seen again".format(mac)
        if ssid:
            detail += " for SSID '{}'".format(ssid)

        self.wifi_clients[mac] = {
            "active": True,
            "last_seen": timestamp,
            "last_seen_epoch": now,
            "ssid": ssid,
            "rssi": rssi,
            "blank_reported": blank_reported or not ssid,
            "source": source,
            "vendor_oui": data.get("vendor_oui") or "",
            "vendor_prefix": data.get("vendor_prefix")
            or data.get("vendor_oui")
            or "",
            "vendor_name": data.get("vendor_name") or "",
        }

        if previous is None or not was_active or self._is_return(previous, now):
            findings.extend(
                self._finding_list(
                    timestamp,
                    "info",
                    source,
                    finding_type,
                    title,
                    detail,
                    "wifi-client-presence:{}".format(mac),
                    emit,
                    self.wifi_client_attributes(mac, ssid, data),
                )
            )

        if not ssid and not blank_reported:
            findings.extend(
                self._finding_list(
                    timestamp,
                    "info",
                    source,
                    "wifi_probe_blank_ssid",
                    "Blank Wi-Fi probe",
                    "Client {} sent a probe request without an SSID".format(
                        mac
                    ),
                    "wifi-blank-probe:{}".format(mac),
                    emit,
                    self.wifi_client_attributes(mac, "", data),
                )
            )

        if self._is_randomized_mac(mac) and previous is None:
            findings.extend(
                self._finding_list(
                    timestamp,
                    "info",
                    source,
                    "wifi_randomized_mac",
                    "Possible randomized Wi-Fi MAC",
                    "{} has the locally administered MAC bit set".format(mac),
                    "wifi-random-mac:{}".format(mac),
                    emit,
                    self.wifi_client_attributes(mac, ssid, data),
                )
            )

        if (
            self._is_strong(rssi, self.config["strong_wifi_rssi"])
            and not was_strong
        ):
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    source,
                    "wifi_client_strong",
                    "Strong nearby Wi-Fi client",
                    "{} probe RSSI is {} dBm".format(mac, rssi),
                    "wifi-client-strong:{}".format(mac),
                    emit,
                    self.wifi_client_attributes(mac, ssid, data),
                )
            )

        findings.extend(
            self._wifi_probe_burst(source, mac, ssid, timestamp, now, emit)
        )
        return findings

    def _wifi_probe_burst(self, source, mac, ssid, timestamp, now, emit):
        """Detect a burst of probe requests from one client MAC."""
        history = self.wifi_probe_history.setdefault(mac, deque())
        history.append(now)
        window = float(self.config["burst_window_sec"])
        while history and now - history[0] > window:
            history.popleft()
        if len(history) < int(self.config["burst_count"]):
            return []
        return self._finding_list(
            timestamp,
            "warning",
            source,
            "wifi_probe_burst",
            "Wi-Fi probe burst",
            "Client {} sent {} probe requests in {} seconds".format(
                mac, len(history), int(window)
            ),
            "wifi-probe-burst:{}".format(mac),
            emit,
            self.wifi_client_attributes(
                mac, ssid, self.wifi_clients.get(mac) or {}
            ),
        )

    def wifi_client_attributes(self, mac, ssid, data):
        """Return Wi-Fi client evidence fields shared by finding types."""
        return {
            "ssid": ssid,
            "mac": mac,
            "vendor_oui": data.get("vendor_oui") or "",
            "vendor_prefix": data.get("vendor_prefix")
            or data.get("vendor_oui")
            or "",
            "vendor_name": data.get("vendor_name") or "",
        }

    def wifi_ap_attributes(self, bssid, ssid, data):
        """Return Wi-Fi AP evidence fields shared by finding types."""
        return {
            "ssid": ssid,
            "bssid": bssid,
            "vendor_oui": data.get("vendor_oui") or "",
            "vendor_prefix": data.get("vendor_prefix")
            or data.get("vendor_oui")
            or "",
            "vendor_name": data.get("vendor_name") or "",
        }

    def _wifi_ap_beacon(self, source, data, timestamp, now, emit):
        findings = []
        bssid = data.get("bssid") or "unknown"
        ssid = data.get("ssid") or ""
        rssi = self._to_number(data.get("rssi"))
        previous = self.wifi_aps.get(bssid)
        # BSSID is the stable AP identity. SSID is descriptive and may be blank.
        was_active = bool(previous and previous.get("active", True))
        was_strong = self._is_strong(
            previous.get("rssi") if previous else None,
            self.config["strong_wifi_ap_rssi"],
        )
        title = "New Wi-Fi access point"
        finding_type = "wifi_ap_new"
        detail = "BSSID {}".format(bssid)
        if previous and (not was_active or self._is_return(previous, now)):
            title = "Wi-Fi access point returned"
            finding_type = "wifi_ap_returned"
            detail = "BSSID {} was seen again".format(bssid)
        if ssid:
            detail += " advertises SSID '{}'".format(ssid)
        if data.get("channel") is not None:
            detail += " on channel {}".format(data.get("channel"))

        self.wifi_aps[bssid] = {
            "active": True,
            "last_seen": timestamp,
            "last_seen_epoch": now,
            "ssid": ssid,
            "rssi": rssi,
            "channel": data.get("channel"),
            "source": source,
            "vendor_oui": data.get("vendor_oui") or "",
            "vendor_prefix": data.get("vendor_prefix")
            or data.get("vendor_oui")
            or "",
            "vendor_name": data.get("vendor_name") or "",
        }

        if previous is None or not was_active or self._is_return(previous, now):
            findings.extend(
                self._finding_list(
                    timestamp,
                    "info",
                    source,
                    finding_type,
                    title,
                    detail,
                    "wifi-ap-presence:{}".format(bssid),
                    emit,
                    self.wifi_ap_attributes(bssid, ssid, data),
                )
            )

        if (
            self._is_strong(rssi, self.config["strong_wifi_ap_rssi"])
            and not was_strong
        ):
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    source,
                    "wifi_ap_strong",
                    "Strong nearby Wi-Fi access point",
                    "{} RSSI is {} dBm".format(ssid or bssid, rssi),
                    "wifi-ap-strong:{}".format(bssid),
                    emit,
                    self.wifi_ap_attributes(bssid, ssid, data),
                )
            )

        return findings

    def _wifi_disruption(self, source, event_type, data, timestamp, emit):
        title = (
            "Wi-Fi deauth frame observed"
            if event_type == "deauth_seen"
            else "Wi-Fi disassociation frame observed"
        )
        detail = "Client {} AP {} channel {}".format(
            data.get("client_mac") or "unknown",
            data.get("ap_mac") or "unknown",
            data.get("channel") or "unknown",
        )
        return self._finding_list(
            timestamp,
            "warning",
            source,
            event_type,
            title,
            detail,
            "{}:{}:{}".format(
                event_type, data.get("client_mac"), data.get("ap_mac")
            ),
            emit,
            {
                "mac": data.get("client_mac") or "",
                "bssid": data.get("ap_mac") or "",
            },
        )

    def _process_ble(self, event_type, event, timestamp, now, emit):
        """Dispatch passive BLE scan events into presence/signal rules."""
        data = event.get("data") or {}
        if event_type == "device_seen":
            return self._ble_device_seen(data, timestamp, now, emit)
        if event_type == "device_updated":
            return self._ble_device_updated(data, timestamp, now, emit)
        if event_type == "device_lost":
            return self._ble_device_lost(data, timestamp, emit)
        if event_type == "hardware_fallback":
            return self._finding_list(
                timestamp,
                "warning",
                "ble",
                "ble_fallback_mode",
                "BLE fallback adapter",
                data.get("warning") or "Using fallback BLE adapter",
                "ble-fallback-mode",
                emit,
            )
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning(
                "ble", event_type, data, timestamp, emit
            )
        return []

    def _ble_device_seen(self, data, timestamp, now, emit):
        findings = []
        mac = data.get("mac") or "unknown"
        name = data.get("name") or ""
        rssi = self._to_number(data.get("rssi"))
        previous = self.ble_devices.get(mac)
        was_active = bool(previous and previous.get("active", True))
        was_strong = self._is_strong(
            previous.get("rssi") if previous else None,
            self.config["strong_ble_rssi"],
        )
        title = "New named BLE device" if name else "New BLE device"
        finding_type = "ble_device_new"
        detail = "{} ({})".format(name, mac) if name else mac
        if previous and (not was_active or self._is_return(previous, now)):
            title = "BLE device returned"
            finding_type = "ble_device_returned"
            detail = "{} was seen again".format(name or mac)

        self.ble_devices[mac] = {
            "active": True,
            "last_seen": timestamp,
            "last_seen_epoch": now,
            "name": name,
            "rssi": rssi,
            "manufacturer": data.get("manufacturer") or "",
        }

        if previous is None or not was_active or self._is_return(previous, now):
            findings.extend(
                self._finding_list(
                    timestamp,
                    "info",
                    "ble",
                    finding_type,
                    title,
                    detail,
                    "ble-device-presence:{}".format(mac),
                    emit,
                    self.ble_attributes(mac, name, data),
                )
            )

        if (
            self._is_strong(rssi, self.config["strong_ble_rssi"])
            and not was_strong
        ):
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "ble",
                    "ble_device_strong",
                    "Strong nearby BLE device",
                    "{} RSSI is {} dBm".format(name or mac, rssi),
                    "ble-device-strong:{}".format(mac),
                    emit,
                    self.ble_attributes(mac, name, data),
                )
            )

        return findings

    def _ble_device_updated(self, data, timestamp, now, emit):
        mac = data.get("mac") or "unknown"
        current = self.ble_devices.get(mac, {})
        old_rssi = self._to_number(current.get("rssi"))
        new_rssi = self._to_number(data.get("rssi"))
        # Keep the latest RSSI even when the change is too small to emit.
        current["active"] = True
        current["last_seen"] = timestamp
        current["last_seen_epoch"] = now
        current["rssi"] = new_rssi
        if data.get("manufacturer"):
            current["manufacturer"] = data.get("manufacturer")
        self.ble_devices[mac] = current

        if (
            old_rssi is None
            or new_rssi is None
            or abs(new_rssi - old_rssi) < float(self.config["rssi_change_db"])
        ):
            return []

        direction = "stronger" if new_rssi > old_rssi else "weaker"
        return self._finding_list(
            timestamp,
            "info",
            "ble",
            "ble_rssi_change",
            "BLE signal changed",
            "{} moved {}: {} dBm to {} dBm".format(
                mac, direction, old_rssi, new_rssi
            ),
            "ble-rssi-change:{}".format(mac),
            emit,
            self.ble_attributes(mac, current.get("name") or "", current),
        )

    def _ble_device_lost(self, data, timestamp, emit):
        mac = data.get("mac") or "unknown"
        known = self.ble_devices.get(mac, {})
        known["active"] = False
        self.ble_devices[mac] = known
        label = known.get("name") or mac
        return self._finding_list(
            timestamp,
            "info",
            "ble",
            "ble_device_lost",
            "BLE device disappeared",
            "{} has not been seen recently".format(label),
            "ble-device-lost:{}".format(mac),
            emit,
            self.ble_attributes(mac, known.get("name") or "", known),
        )

    def ble_attributes(self, mac, name, data):
        """Return BLE evidence fields shared by finding types."""
        return {
            "mac": mac,
            "name": name,
            "manufacturer": data.get("manufacturer") or "",
        }

    def _process_ble_identify(self, event_type, event, timestamp, emit):
        """Turn active BLE identity attempts into searchable Insights."""
        data = event.get("data") or {}
        mac = data.get("mac") or "unknown"
        if event_type == "identify_result":
            detail = (
                "{} {} {}".format(
                    data.get("manufacturer_name") or "",
                    data.get("model_number") or "",
                    data.get("firmware_revision") or "",
                ).strip()
                or "Device Information Service fields were read"
            )
            return self._finding_list(
                timestamp,
                "info",
                "ble_identify",
                "ble_identity_read",
                "BLE device identified",
                detail,
                "ble-identify:{}".format(mac),
                emit,
                {
                    "mac": mac,
                    "manufacturer_name": data.get("manufacturer_name") or "",
                    "model_number": data.get("model_number") or "",
                    "firmware_revision": data.get("firmware_revision") or "",
                    "hardware_revision": data.get("hardware_revision") or "",
                    "software_revision": data.get("software_revision") or "",
                },
            )
        if event_type == "identify_failed":
            return self._finding_list(
                timestamp,
                "warning",
                "ble_identify",
                "ble_identity_failed",
                "BLE identify failed",
                data.get("reason")
                or "Device Information Service was not readable",
                "ble-identify-failed:{}".format(mac),
                emit,
                {"mac": mac},
            )
        return []

    def _process_bt_classic(self, event_type, event, timestamp, now, emit):
        """Turn classic Bluetooth inquiry results into Bluetooth insights."""
        data = event.get("data") or {}
        if event_type in ("classic_device_seen", "classic_device_updated"):
            mac = data.get("mac") or "unknown"
            name = data.get("name") or ""
            previous = self.bt_classic_devices.get(mac)
            was_active = bool(previous and previous.get("active", True))
            self.bt_classic_devices[mac] = {
                "active": True,
                "last_seen": timestamp,
                "last_seen_epoch": now,
                "name": name,
                "rssi": None,
                "manufacturer": data.get("vendor_name") or "",
                "transport": "classic",
            }
            if (
                previous is None
                or not was_active
                or self._is_return(previous, now)
            ):
                title = (
                    "New classic Bluetooth device"
                    if previous is None
                    else "Classic Bluetooth device returned"
                )
                detail = "{} ({})".format(name, mac) if name else mac
                return self._finding_list(
                    timestamp,
                    "info",
                    "bt_classic",
                    "bt_classic_device_seen",
                    title,
                    detail,
                    "bt-classic-presence:{}".format(mac),
                    emit,
                    self.bt_classic_attributes(mac, data),
                )
        if event_type == "classic_device_lost":
            mac = data.get("mac") or "unknown"
            known = self.bt_classic_devices.get(mac, {})
            known["active"] = False
            self.bt_classic_devices[mac] = known
            label = known.get("name") or mac
            return self._finding_list(
                timestamp,
                "info",
                "bt_classic",
                "bt_classic_device_lost",
                "Classic Bluetooth device disappeared",
                "{} has not been seen recently".format(label),
                "bt-classic-lost:{}".format(mac),
                emit,
                self.bt_classic_attributes(mac, known),
            )
        if event_type == "hardware_fallback":
            return self._finding_list(
                timestamp,
                "warning",
                "bt_classic",
                "bt_classic_fallback_mode",
                "Bluetooth classic fallback adapter",
                data.get("warning") or "Using fallback Bluetooth adapter",
                "bt-classic-fallback-mode",
                emit,
            )
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning(
                "bt_classic", event_type, data, timestamp, emit
            )
        return []

    def bt_classic_attributes(self, mac, data):
        """Return classic Bluetooth evidence fields shared by findings."""
        return {
            "mac": mac,
            "name": data.get("name") or "",
            "transport": "classic",
            "vendor_prefix": data.get("vendor_prefix") or "",
            "vendor_name": data.get("vendor_name")
            or data.get("manufacturer")
            or "",
            "class": data.get("class") or "",
        }

    def _process_rtlsdr(self, event_type, event, timestamp, emit):
        """Track RTL-SDR signal intervals from signal_detected/lost events."""
        data = event.get("data") or {}
        if event_type == "signal_detected":
            frequency = data.get("frequency_mhz")
            self.rtlsdr_signals[frequency] = {
                "first_seen": timestamp,
                "first_seen_epoch": self._to_epoch(timestamp),
                "persistent_reported": False,
            }
            return self._finding_list(
                timestamp,
                "warning",
                "rtlsdr",
                "rtlsdr_signal_detected",
                "RTL-SDR signal detected",
                "{} MHz is {} dB above baseline".format(
                    frequency, data.get("above_floor_db")
                ),
                "rtlsdr-signal:{}".format(frequency),
                emit,
            )
        if event_type == "signal_lost":
            frequency = data.get("frequency_mhz")
            self.rtlsdr_signals.pop(frequency, None)
            return self._finding_list(
                timestamp,
                "info",
                "rtlsdr",
                "rtlsdr_signal_lost",
                "RTL-SDR signal lost",
                "{} MHz returned below threshold".format(frequency),
                "rtlsdr-signal-lost:{}".format(frequency),
                emit,
            )
        if event_type == "collector_offline":
            return self._collector_warning(
                "rtlsdr", event_type, data, timestamp, emit
            )
        return []

    def _process_system(self, event_type, event, timestamp, emit):
        data = event.get("data") or {}
        if event_type == "system_status":
            return self._process_system_status(data, timestamp, emit)
        if event_type not in (
            "collector_loaded",
            "collector_started",
            "collector_stopped",
            "collector_already_running",
        ):
            return []
        key = data.get("key")
        state = data.get("state")
        if not key or not state:
            return []
        previous = self.collector_states.get(key)
        self.collector_states[key] = state
        if state == previous:
            return []
        if state == "STOPPED":
            return self._collector_state_finding(
                timestamp,
                "info",
                key,
                data,
                "collector_stopped",
                "stopped",
                emit,
            )
        if state == "OFFLINE":
            return self._collector_state_finding(
                timestamp,
                "warning",
                key,
                data,
                "collector_offline",
                "offline",
                emit,
            )
        if state == "RETRYING":
            return self._collector_state_finding(
                timestamp,
                "warning",
                key,
                data,
                "collector_retrying",
                "retrying",
                emit,
            )
        return []

    def _collector_state_finding(
        self, timestamp, severity, key, data, finding_type, state_text, emit
    ):
        """Attach lifecycle findings to the collector they are about."""
        name = data.get("name") or key
        warning = data.get("warning") or data.get("reason") or ""
        title = "{} {}".format(name, state_text)
        detail = warning or "{} is {}".format(name, state_text)
        return self._finding_list(
            timestamp,
            severity,
            key,
            finding_type,
            title,
            detail,
            "{}:{}".format(finding_type, key),
            emit,
            {"collector": key},
        )

    def _process_system_status(self, data, timestamp, emit):
        findings = []
        # System-status findings are dependency/configuration findings. They
        # should be sourced to the collector they affect, not to generic system.
        hardware = data.get("hardware") or {}
        wifi = hardware.get("wifi") or {}
        ble = hardware.get("ble") or {}
        rtlsdr = hardware.get("rtlsdr") or {}
        wifi_monitor = hardware.get("wifi_monitor") or {}
        bt_classic = hardware.get("bt_classic") or {}

        if wifi.get("iw") is False and wifi.get("iwlist") is False:
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "wifi",
                    "missing_executable",
                    "iw/iwlist missing",
                    "Wi-Fi scan needs iw or iwlist for managed AP scans",
                    "wifi:missing-executable:iw-iwlist",
                    emit,
                )
            )
        if wifi_monitor.get("iw") is False:
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "wifi_monitor",
                    "missing_executable",
                    "iw missing",
                    "Wi-Fi monitor channel detection executable was not located",
                    "wifi-monitor:missing-executable:iw",
                    emit,
                )
            )
        if wifi_monitor.get("scapy") is False:
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "wifi_monitor",
                    "missing_python_package",
                    "scapy missing",
                    "Wi-Fi monitor packet capture package is not installed",
                    "wifi-monitor:missing-package:scapy",
                    emit,
                )
            )
        if ble.get("bleak") is False:
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "ble",
                    "missing_python_package",
                    "bleak missing",
                    "BLE scanning package is not installed",
                    "ble:missing-package:bleak",
                    emit,
                )
            )
        if (
            bt_classic.get("hcitool") is False
            and bt_classic.get("bluetoothctl") is False
        ):
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "bt_classic",
                    "missing_executable",
                    "Bluetooth classic scanner missing",
                    "Classic Bluetooth scan needs hcitool or bluetoothctl",
                    "bt-classic:missing-executable",
                    emit,
                )
            )
        if rtlsdr.get("rtl_power") is False:
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "rtlsdr",
                    "missing_executable",
                    "rtl_power missing",
                    "RTL-SDR spectrum executable was not located",
                    "rtlsdr:missing-executable:rtl_power",
                    emit,
                )
            )
        if rtlsdr.get("rtl_test") is False:
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "rtlsdr",
                    "missing_executable",
                    "rtl_test missing",
                    "RTL-SDR device validation executable was not located",
                    "rtlsdr:missing-executable:rtl_test",
                    emit,
                )
            )

        findings.extend(self._rtlsdr_persistent_signals(timestamp, emit))
        return findings

    def _rtlsdr_persistent_signals(self, timestamp, emit):
        findings = []
        now = self._to_epoch(timestamp)
        threshold = float(self.config["persistent_signal_sec"])
        for frequency, data in self.rtlsdr_signals.items():
            if data.get("persistent_reported"):
                continue
            duration = now - data.get("first_seen_epoch", now)
            if duration < threshold:
                continue
            data["persistent_reported"] = True
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "rtlsdr",
                    "rtlsdr_signal_persistent",
                    "RTL-SDR signal persisted",
                    "{} MHz has stayed above baseline for at least {} seconds".format(
                        frequency, int(threshold)
                    ),
                    "rtlsdr-signal-persistent:{}".format(frequency),
                    emit,
                )
            )
        return findings

    def _collector_warning(self, source, event_type, data, timestamp, emit):
        reason = (
            data.get("reason")
            or data.get("warning")
            or data.get("error")
            or event_type
        )
        title = "{} {}".format(
            source.upper(),
            "offline" if event_type == "collector_offline" else "retrying",
        )
        return self._finding_list(
            timestamp,
            "warning",
            source,
            event_type,
            title,
            reason,
            "{}:{}".format(source, event_type),
            emit,
        )

    def _expire_presence(self, timestamp, now):
        findings = []
        lost_after = float(self.config["lost_after_sec"])
        for mac, data in self.wifi_clients.items():
            if (
                data.get("active", True)
                and now - data.get("last_seen_epoch", now) > lost_after
            ):
                data["active"] = False
                source = data.get("source") or "wifi"
                findings.extend(
                    self._finding_list(
                        timestamp,
                        "info",
                        source,
                        "wifi_client_lost",
                        "Wi-Fi client disappeared",
                        "{} has not sent probes recently".format(mac),
                        "wifi-client-lost:{}".format(mac),
                        True,
                        self.wifi_client_attributes(
                            mac, data.get("ssid") or "", data
                        ),
                    )
                )
        for bssid, data in self.wifi_aps.items():
            if (
                data.get("active", True)
                and now - data.get("last_seen_epoch", now) > lost_after
            ):
                data["active"] = False
                source = data.get("source") or "wifi"
                findings.extend(
                    self._finding_list(
                        timestamp,
                        "info",
                        source,
                        "wifi_ap_lost",
                        "Wi-Fi access point disappeared",
                        "{} has not beaconed recently".format(
                            data.get("ssid") or bssid
                        ),
                        "wifi-ap-lost:{}".format(bssid),
                        True,
                        self.wifi_ap_attributes(
                            bssid, data.get("ssid") or "", data
                        ),
                    )
                )
        return findings

    def _finding_list(
        self,
        timestamp,
        severity,
        source,
        finding_type,
        title,
        detail,
        key,
        emit,
        attributes=None,
    ):
        """Return a one-item list or empty list for handlers that extend()."""
        if not emit and finding_type != "findings_history_loaded":
            return []
        finding = self._finding(
            timestamp,
            severity,
            source,
            finding_type,
            title,
            detail,
            key,
            attributes=attributes,
        )
        if finding and (emit or finding_type == "findings_history_loaded"):
            return [finding]
        return []

    def _finding(
        self,
        timestamp,
        severity,
        source,
        finding_type,
        title,
        detail,
        key,
        force=False,
        attributes=None,
    ):
        """Create one finding unless the cooldown suppresses a duplicate."""
        now = self._to_epoch(timestamp)
        last = self._last_emitted.get(key)
        cooldown = float(self.config.get("cooldown_sec", 120))
        if (
            not force
            and last
            and last.get("severity") == severity
            and now - last.get("epoch", 0) < cooldown
        ):
            return None
        self._last_emitted[key] = {"epoch": now, "severity": severity}
        self._counter += 1
        return {
            "id": "{}-{}".format(timestamp, self._counter),
            "timestamp": timestamp,
            "severity": severity,
            "source": source,
            "type": finding_type,
            "title": title,
            "detail": detail or "",
            "key": key,
            "attributes": attributes or {},
        }

    def _is_return(self, previous, now):
        return now - previous.get("last_seen_epoch", now) >= float(
            self.config["return_after_sec"]
        )

    def _to_epoch(self, timestamp):
        if isinstance(timestamp, (int, float)):
            return float(timestamp)
        parsed = utc_epoch(timestamp)
        if parsed is not None:
            return parsed
        return time.time()

    def _to_number(self, value):
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _is_strong(self, rssi, threshold):
        value = self._to_number(rssi)
        return value is not None and value >= float(threshold)

    def _is_randomized_mac(self, mac):
        try:
            first_octet = int(str(mac).split(":", 1)[0], 16)
        except (TypeError, ValueError):
            return False
        return bool(first_octet & 0x02)
