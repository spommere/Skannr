"""Live findings generated from the event stream.

Findings are the immediate, low-memory layer. They are produced while collectors
run, persisted as JSONL, and later materialized for the Insights/Reports views.
Longer historical interpretation belongs in device_history.py, history_analysis.py,
and reports.py.
"""

import math
from collections import deque

from .bus import local_now
from .collectors.aprsis import clean_aprs_data
from .collectors.lan import clean_lan_data
from .collectors.noaa import clean_noaa_data, tsunami_is_alertworthy
from .collectors.pws import clean_pws_data
from .collectors.rayhunter import clean_rayhunter_data, clean_rayhunter_field
from .collectors.swpc import clean_swpc_data, number_or_none, swpc_event_is_alert
from .collectors.usgs import clean_usgs_data
from .log_utils import event_time_epoch, now_epoch, timestamp_epoch


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
    "ble_live_identity_required": True,
    "ble_live_service_identity": False,
    "burst_window_sec": 30,
    "burst_count": 5,
    "cooldown_sec": 120,
    "persistent_signal_sec": 60,
    "aprs_move_km": 0.3,
    "aprs_temp_change_f": 5,
    "aprs_rain_1h_high_in": 0.25,
    "aprs_wind_high_mph": 25,
    "aprs_gust_high_mph": 35,
    "pws_temp_change_f": 5,
    "pws_rain_1h_high_in": 0.25,
    "pws_wind_high_mph": 25,
    "pws_gust_high_mph": 35,
    "swpc_warning_xray_class": "X1.0",
    "swpc_warning_radio_blackout": "R3",
    "swpc_warning_solar_radiation_storm": "S3",
    "swpc_warning_geomagnetic_storm": "G3",
    "swpc_warning_kp": 7,
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
        self.aprs_stations = {}
        self.noaa_alerts = {}
        self.usgs_events = {}
        self.swpc_events = {}
        self.rayhunter_endpoints = {}
        self.lan_devices = {}
        self.lan_gateways = {}
        self.pws_stations = {}

    def bootstrap(self, events):
        """Replay persisted events to rebuild state without replaying old noise."""
        if not self.enabled:
            return None
        replayed = 0
        for event in sorted(
            events or [], key=lambda item: event_time_epoch(item) or 0
        ):
            if event.get("collector") == "findings":
                continue
            self.process(event, emit=False)
            replayed += 1
        if not replayed:
            return None
        timestamp_epoch_value = now_epoch()
        summary = self._finding(
            local_now(timestamp_epoch_value),
            "info",
            "system",
            "findings_history_loaded",
            "Findings history loaded",
            "Rebuilt findings state from {} persisted events".format(replayed),
            "findings-history-loaded",
            force=True,
            timestamp_epoch_value=timestamp_epoch_value,
        )
        self.recent.appendleft(summary)
        return summary

    def seed_device_history(self, history):
        """Seed previously seen devices from materialized history without noise.

        The live findings engine is intentionally in-memory. After a restart,
        a BSSID or MAC may already exist in Device History even when its raw
        event is outside the small bootstrap replay window. Seeding those
        identities as inactive makes the next sighting read as "returned"
        instead of "new".
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
                "strong_reported": self._is_strong(
                    ap.get("signal_max")
                    if ap.get("signal_max") is not None
                    else ap.get("signal_latest"),
                    self.config["strong_wifi_ap_rssi"],
                ),
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

        now = event_time_epoch(event) or now_epoch()
        timestamp = event.get("timestamp") or local_now(now)
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
        elif collector == "rayhunter":
            findings.extend(
                self._process_rayhunter(event_type, event, timestamp, emit)
            )
        elif collector == "aprsis":
            findings.extend(
                self._process_aprsis(event_type, event, timestamp, now, emit)
            )
        elif collector == "noaa":
            findings.extend(
                self._process_noaa(event_type, event, timestamp, emit)
            )
        elif collector == "usgs":
            findings.extend(
                self._process_usgs(event_type, event, timestamp, emit)
            )
        elif collector == "swpc":
            findings.extend(
                self._process_swpc(event_type, event, timestamp, emit)
            )
        elif collector == "pws":
            findings.extend(
                self._process_pws(event_type, event, timestamp, now, emit)
            )
        elif collector == "lan":
            findings.extend(
                self._process_lan(event_type, event, timestamp, emit)
            )
        elif collector == "lan_identify":
            findings.extend(
                self._process_lan_identify(event_type, event, timestamp, emit)
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
        was_strong = self._is_strong(
            previous.get("rssi") if previous else None,
            self.config["strong_wifi_ap_rssi"],
        )
        strong_now = self._is_strong(rssi, self.config["strong_wifi_ap_rssi"])
        strong_reported = bool(previous and previous.get("strong_reported"))
        title = "New Wi-Fi access point"
        finding_type = "wifi_ap_new"
        detail = "BSSID {}".format(bssid)
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
            "strong_reported": strong_reported or strong_now,
        }

        if previous is None:
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

        if strong_now and not was_strong and not strong_reported:
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
            "service_uuids": data.get("service_uuids") or [],
        }

        if (
            self.ble_live_finding_worthy(data)
            and (previous is None or not was_active or self._is_return(previous, now))
        ):
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
            self.ble_live_finding_worthy(data, signal=True)
            and self._is_strong(rssi, self.config["strong_ble_rssi"])
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
        if data.get("name"):
            current["name"] = data.get("name")
        if data.get("service_uuids"):
            current["service_uuids"] = data.get("service_uuids")
        self.ble_devices[mac] = current

        if (
            old_rssi is None
            or new_rssi is None
            or abs(new_rssi - old_rssi) < float(self.config["rssi_change_db"])
            or not self.ble_live_finding_worthy(current, signal=True)
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
        if not self.ble_live_finding_worthy(known):
            return []
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
            "service_uuids": data.get("service_uuids") or [],
        }

    def ble_live_finding_worthy(self, data, signal=False):
        """Return true when a BLE subject deserves an individual live Insight."""
        if not self.config.get("ble_live_identity_required", True):
            return True
        name = str((data or {}).get("name") or "").strip()
        mac = str((data or {}).get("mac") or "").strip().lower().replace("-", ":")
        if name and name.lower().replace("-", ":") != mac:
            return True
        if self.config.get("ble_live_service_identity", False):
            return bool((data or {}).get("service_uuids"))
        return False

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

    def _process_rayhunter(self, event_type, event, timestamp, emit):
        """Turn Rayhunter endpoint status into recent Insights."""
        data = clean_rayhunter_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning(
                "rayhunter", event_type, data, timestamp, emit
            )
        if event_type != "rayhunter_status":
            return []
        warning_count = self._to_number(data.get("warning_count")) or 0
        endpoint = data.get("endpoint") or "default"
        attributes = self.rayhunter_attributes(data)
        current = {
            "warning_count": warning_count,
            "latest_event": data.get("latest_event") or "",
            "summary": clean_rayhunter_field(data.get("summary")),
        }
        previous = self.rayhunter_endpoints.get(endpoint) or {}
        self.rayhunter_endpoints[endpoint] = current
        if warning_count <= 0:
            if previous == current:
                return []
            detail = clean_rayhunter_field(data.get("summary")) or (
                "Rayhunter endpoint {} is reachable; 0 warnings".format(endpoint)
            )
            if data.get("latest_event") and data.get("latest_event") not in detail:
                detail += "; latest event {}".format(data.get("latest_event"))
            return self._finding_list(
                timestamp,
                "info",
                "rayhunter",
                "rayhunter_status",
                "Rayhunter reachable",
                detail,
                "rayhunter-status:{}".format(endpoint),
                emit,
                attributes,
            )
        detail = clean_rayhunter_field(data.get("summary")) or (
            "{} Rayhunter warning(s)".format(int(warning_count))
        )
        if data.get("latest_event") and data.get("latest_event") not in detail:
            detail += "; latest event {}".format(data.get("latest_event"))
        if data.get("endpoint") and data.get("endpoint") not in detail:
            detail += "; endpoint {}".format(data.get("endpoint"))
        return self._finding_list(
            timestamp,
            "warning",
            "rayhunter",
            "rayhunter_warning",
            "Rayhunter warning present",
            detail,
            "rayhunter-warning:{}".format(endpoint),
            emit,
            attributes,
        )

    def rayhunter_attributes(self, data):
        """Return structured Rayhunter fields for Insights evidence."""
        fields = (
            "endpoint",
            "warning_count",
            "latest_event",
            "rayhunter_version",
            "storage",
            "memory",
            "battery",
            "recording_id",
            "recording_size",
            "recording_start",
            "recording_last_message",
            "recording_artifacts",
            "device_os",
            "gps_mode",
        )
        return {
            key: data.get(key)
            for key in fields
            if data.get(key) not in (None, "", [])
        }

    def _process_aprsis(self, event_type, event, timestamp, now, emit):
        """Turn filtered APRS-IS packets into situational Insights."""
        data = clean_aprs_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("aprsis", event_type, data, timestamp, emit)
        if event_type == "collector_online":
            detail = "APRS-IS feed online"
            if data.get("filter"):
                detail += "; filter {}".format(data.get("filter"))
            return self._finding_list(
                timestamp,
                "info",
                "aprsis",
                "aprsis_feed_online",
                "APRS-IS feed online",
                detail,
                "aprsis-online:{}".format(data.get("filter") or "default"),
                emit,
                self.aprsis_attributes(data),
            )
        if not str(event_type or "").startswith("aprs_"):
            return []
        callsign = data.get("callsign") or "unknown"
        packet_type = data.get("packet_type") or event_type.replace("aprs_", "")
        findings = []
        findings.extend(
            self.aprsis_pattern_findings(
                data, packet_type, callsign, timestamp, now, emit
            )
        )
        self.aprsis_update_station_state(callsign, data, now)
        return findings

    def aprsis_pattern_findings(
        self, data, packet_type, callsign, timestamp, now, emit
    ):
        """Return live APRS movement/weather pattern findings for one station."""
        findings = []
        previous = self.aprs_stations.get(callsign) or {}
        latitude = self._to_number(data.get("latitude"))
        longitude = self._to_number(data.get("longitude"))
        if latitude is not None and longitude is not None:
            distance = self._distance_km(
                previous.get("latitude"),
                previous.get("longitude"),
                latitude,
                longitude,
            )
            if distance is not None and distance >= float(self.config["aprs_move_km"]):
                attributes = self.aprsis_attributes(data)
                attributes["movement_km"] = round(distance, 3)
                findings.extend(
                    self._finding_list(
                        timestamp,
                        "info",
                        "aprsis",
                        "aprsis_station_moved",
                        "APRS station moved through area",
                        (
                            "{} moved {:.2f} km through the configured APRS area; "
                            "latest {:.5f}, {:.5f}; internet-fed"
                        ).format(callsign, distance, latitude, longitude),
                        "aprsis-moved:{}".format(callsign),
                        emit,
                        attributes,
                    )
                )
        if packet_type == "weather" or data.get("weather_summary"):
            findings.extend(
                self.aprsis_weather_pattern_findings(
                    data, callsign, previous, timestamp, emit
                )
            )
        return findings

    def aprsis_weather_pattern_findings(
        self, data, callsign, previous, timestamp, emit
    ):
        """Return live APRS weather transition findings for one station."""
        findings = []
        temperature = self._to_number(data.get("temperature_f"))
        previous_temperature = previous.get("temperature_f")
        if temperature is not None and previous_temperature is not None:
            delta = temperature - previous_temperature
            if abs(delta) >= float(self.config["aprs_temp_change_f"]):
                attributes = self.aprsis_attributes(data)
                attributes["temperature_change_f"] = round(delta, 1)
                findings.extend(
                    self._finding_list(
                        timestamp,
                        "info",
                        "aprsis",
                        "aprsis_weather_temperature_change",
                        "APRS weather temperature changed",
                        "{} temperature changed {:+.0f} F to {:.0f} F; internet-fed".format(
                            callsign, delta, temperature
                        ),
                        "aprsis-temp-change:{}".format(callsign),
                        emit,
                        attributes,
                    )
                )
        rain_1h = self._to_number(data.get("rain_1h_in"))
        previous_rain = previous.get("rain_1h_in")
        if rain_1h is not None:
            if rain_1h >= float(self.config["aprs_rain_1h_high_in"]):
                findings.extend(
                    self._finding_list(
                        timestamp,
                        "warning",
                        "aprsis",
                        "aprsis_weather_high_rain",
                        "APRS weather high rain rate",
                        "{} reported {:.2f} in/hr rain rate; internet-fed".format(
                            callsign, rain_1h
                        ),
                        "aprsis-high-rain:{}".format(callsign),
                        emit,
                        self.aprsis_attributes(data),
                    )
                )
            if previous_rain is not None and previous_rain <= 0 < rain_1h:
                findings.extend(
                    self._finding_list(
                        timestamp,
                        "info",
                        "aprsis",
                        "aprsis_weather_rain_started",
                        "APRS weather rain started",
                        "{} rain started; 1h rain rate {:.2f} in/hr; internet-fed".format(
                            callsign, rain_1h
                        ),
                        "aprsis-rain-started:{}".format(callsign),
                        emit,
                        self.aprsis_attributes(data),
                    )
                )
            if previous_rain is not None and previous_rain > 0 and rain_1h <= 0:
                findings.extend(
                    self._finding_list(
                        timestamp,
                        "info",
                        "aprsis",
                        "aprsis_weather_rain_stopped",
                        "APRS weather rain stopped",
                        "{} rain stopped; 1h rain rate returned to {:.2f} in/hr; internet-fed".format(
                            callsign, rain_1h
                        ),
                        "aprsis-rain-stopped:{}".format(callsign),
                        emit,
                        self.aprsis_attributes(data),
                    )
                )
        wind = self._to_number(data.get("wind_speed_mph"))
        gust = self._to_number(data.get("wind_gust_mph"))
        wind_high = wind is not None and wind >= float(
            self.config["aprs_wind_high_mph"]
        )
        gust_high = gust is not None and gust >= float(
            self.config["aprs_gust_high_mph"]
        )
        if wind_high or gust_high:
            parts = []
            if wind is not None:
                parts.append("wind {:.0f} mph".format(wind))
            if gust is not None:
                parts.append("gust {:.0f} mph".format(gust))
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "aprsis",
                    "aprsis_weather_high_wind",
                    "APRS weather high wind",
                    "{} reported {}; internet-fed".format(callsign, ", ".join(parts)),
                    "aprsis-high-wind:{}".format(callsign),
                    emit,
                    self.aprsis_attributes(data),
                )
            )
        return findings

    def aprsis_update_station_state(self, callsign, data, now):
        """Remember latest APRS position/weather fields for live pattern checks."""
        state = self.aprs_stations.setdefault(callsign, {})
        state["last_seen_epoch"] = now
        for key in (
            "latitude",
            "longitude",
            "temperature_f",
            "rain_1h_in",
            "wind_speed_mph",
            "wind_gust_mph",
        ):
            value = self._to_number(data.get(key))
            if value is not None:
                state[key] = value

    def aprsis_finding_title(self, packet_type):
        """Return the APRS-IS Insight title for a packet class."""
        labels = {
            "position": "APRS station in configured area",
            "object": "APRS object in configured area",
            "message": "APRS message in configured area",
            "status": "APRS status in configured area",
            "weather": "APRS weather activity in configured area",
            "telemetry": "APRS telemetry in configured area",
        }
        return labels.get(packet_type, "APRS activity in configured area")

    def aprsis_finding_detail(self, data, packet_type):
        """Return a compact APRS-IS Insight detail string."""
        callsign = data.get("callsign") or "unknown"
        parts = [callsign]
        if data.get("object_name"):
            parts.append("object {}".format(data.get("object_name")))
        if data.get("addressee"):
            parts.append("to {}".format(data.get("addressee")))
        if data.get("destination") and not data.get("addressee"):
            parts.append("dst {}".format(data.get("destination")))
        if data.get("weather_summary"):
            parts.append(data.get("weather_summary"))
        if data.get("message"):
            parts.append(data.get("message"))
        elif data.get("comment"):
            parts.append(data.get("comment"))
        else:
            parts.append(packet_type)
        latitude = self._to_number(data.get("latitude"))
        longitude = self._to_number(data.get("longitude"))
        if latitude is not None and longitude is not None:
            parts.append("{:.5f}, {:.5f}".format(latitude, longitude))
        elif latitude is not None:
            parts.append("lat {:.5f}".format(latitude))
        speed_kmh = self._to_number(data.get("speed_kmh"))
        course_deg = self._to_number(data.get("course_deg"))
        if speed_kmh is not None:
            parts.append("{} km/h".format(data.get("speed_kmh")))
        if course_deg is not None:
            parts.append("{} deg".format(data.get("course_deg")))
        if data.get("filter"):
            parts.append("APRS-IS filter {}".format(data.get("filter")))
        if data.get("feed_name"):
            parts.append("feed {}".format(data.get("feed_name")))
        parts.append("internet-fed")
        return "; ".join(str(part) for part in parts if part)

    def aprsis_attributes(self, data):
        """Return structured APRS-IS fields for Insights evidence."""
        fields = (
            "callsign",
            "destination",
            "via_path",
            "q_construct",
            "igate",
            "packet_type",
            "aprs_format",
            "mic_e_message",
            "weather_summary",
            "object_name",
            "addressee",
            "message",
            "comment",
            "latitude",
            "longitude",
            "movement_km",
            "position_span_km",
            "speed_kmh",
            "speed_knots",
            "course_deg",
            "wind_direction_deg",
            "wind_speed_mph",
            "wind_gust_mph",
            "temperature_f",
            "temperature_change_f",
            "rain_1h_in",
            "rain_24h_in",
            "rain_since_midnight_in",
            "humidity_percent",
            "pressure_hpa",
            "luminosity_w_m2",
            "snow_in",
            "symbol",
            "symbol_code",
            "symbol_table",
            "host",
            "port",
            "filter",
            "feed_name",
            "feed_role",
            "distance_from_filter_km",
            "geofence_enforced",
            "geofence_radius_km",
            "internet_fed",
        )
        return {
            key: data.get(key)
            for key in fields
            if data.get(key) not in (None, "", [])
        }

    def _process_noaa(self, event_type, event, timestamp, emit):
        """Turn NOAA/NWS/NHC/tsunami.gov feed changes into live Insights."""
        data = clean_noaa_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("noaa", event_type, data, timestamp, emit)
        if event_type not in (
            "noaa_weather_alert",
            "noaa_tropical_advisory",
            "noaa_forecast_summary",
            "noaa_tsunami_alert",
        ):
            return []
        event_id = data.get("event_id") or data.get("headline") or "unknown"
        previous = self.noaa_alerts.get(event_id) or {}
        current = {
            "severity": data.get("severity") or "",
            "status": data.get("status") or "",
            "headline": data.get("headline") or "",
            "updated": data.get("updated") or "",
            "event_time": data.get("event_time") or "",
        }
        self.noaa_alerts[event_id] = current
        if previous == current:
            return []
        findings = []
        severity = "warning" if self.noaa_is_warning(data) else "info"
        title = (
            "NOAA tropical advisory"
            if event_type == "noaa_tropical_advisory"
            else "NOAA tsunami alert"
            if event_type == "noaa_tsunami_alert"
            else "NOAA forecast"
            if event_type == "noaa_forecast_summary"
            else "NOAA weather alert"
        )
        detail = self.noaa_detail(data)
        findings.extend(
            self._finding_list(
                timestamp,
                severity,
                "noaa",
                event_type,
                title,
                detail,
                "noaa-alert:{}".format(event_id),
                emit,
                self.noaa_attributes(data),
            )
        )
        old_rank = self.noaa_severity_rank(previous.get("severity"))
        new_rank = self.noaa_severity_rank(data.get("severity"))
        if previous and new_rank > old_rank:
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "noaa",
                    "noaa_alert_upgraded",
                    "NOAA alert upgraded",
                    "{} changed severity from {} to {}".format(
                        data.get("event") or data.get("headline") or event_id,
                        previous.get("severity") or "unknown",
                        data.get("severity") or "unknown",
                    ),
                    "noaa-alert-upgrade:{}".format(event_id),
                    emit,
                    self.noaa_attributes(data),
                )
            )
        return findings

    def noaa_is_warning(self, data):
        """Return True for NOAA records worth showing as warning Insights."""
        severities = {
            str(item or "").lower()
            for item in self.config.get("noaa_upgrade_severities") or []
        }
        severity = str((data or {}).get("severity") or "").lower()
        kind = str((data or {}).get("alert_kind") or "").lower()
        if kind == "forecast":
            return False
        if kind == "tropical_outlook":
            return False
        if kind == "tsunami":
            return tsunami_is_alertworthy(data)
        event = str((data or {}).get("event") or "").lower()
        return (
            severity in severities
            or kind == "tropical"
            or any(word in event for word in ("warning", "watch", "tornado"))
        )

    def noaa_severity_rank(self, value):
        """Return coarse NOAA severity rank."""
        return {
            "minor": 1,
            "moderate": 2,
            "severe": 3,
            "extreme": 4,
        }.get(str(value or "").lower(), 0)

    def noaa_detail(self, data):
        """Return compact NOAA finding detail."""
        if data.get("alert_kind") == "forecast":
            parts = [
                data.get("headline") or data.get("summary") or data.get("event") or "",
                data.get("area_desc") or "",
                data.get("next_precip_start")
                and "next precip {}% at {}".format(
                    data.get("next_precip_probability") or "?",
                    data.get("next_precip_start"),
                ),
                data.get("max_precip_probability")
                and "max precip {}%".format(data.get("max_precip_probability")),
                data.get("max_wind_mph")
                and "max wind {} mph".format(data.get("max_wind_mph")),
                data.get("source") or "NWS",
            ]
            return "; ".join(str(part) for part in parts if part)
        parts = [
            data.get("event") or data.get("headline") or "",
            data.get("severity") or "",
            data.get("area_desc") or "",
            data.get("headline") if data.get("headline") != data.get("event") else "",
            data.get("expires") and "expires {}".format(data.get("expires")),
            data.get("source") or "NOAA",
            "internet-fed",
        ]
        return "; ".join(str(part) for part in parts if part)

    def noaa_attributes(self, data):
        """Return structured NOAA evidence fields for Insights."""
        fields = (
            "event_id",
            "event",
            "headline",
            "severity",
            "urgency",
            "certainty",
            "status",
            "message_type",
            "category",
            "alert_kind",
            "area_desc",
            "effective",
            "onset",
            "expires",
            "ends",
            "updated",
            "source",
            "source_url",
            "basin",
            "latitude",
            "longitude",
            "forecast_generated",
            "forecast_window_hours",
            "forecast_soon_hours",
            "forecast_hour_count",
            "current_forecast",
            "current_temperature_f",
            "current_precip_probability",
            "temperature_min_f",
            "temperature_max_f",
            "temperature_change_f",
            "max_precip_probability",
            "precip_probability_threshold",
            "precip_likely_soon",
            "next_precip_start",
            "next_precip_end",
            "next_precip_probability",
            "next_precip_forecast",
            "max_wind_mph",
            "first_period_start",
            "last_period_end",
            "internet_fed",
        )
        return {
            key: data.get(key)
            for key in fields
            if data.get(key) not in (None, "", [])
        }

    def _process_usgs(self, event_type, event, timestamp, emit):
        """Turn USGS earthquake feed changes into live Insights."""
        data = clean_usgs_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("usgs", event_type, data, timestamp, emit)
        if event_type != "usgs_earthquake":
            return []
        event_id = data.get("event_id") or "unknown"
        previous = self.usgs_events.get(event_id) or {}
        current = {
            "magnitude": self._to_number(data.get("magnitude")),
            "updated_epoch": data.get("updated_epoch"),
        }
        self.usgs_events[event_id] = current
        if previous == current:
            return []
        findings = []
        severity = "warning" if self.usgs_is_warning(data) else "info"
        findings.extend(
            self._finding_list(
                timestamp,
                severity,
                "usgs",
                "usgs_earthquake",
                "USGS earthquake",
                self.usgs_detail(data),
                "usgs-earthquake:{}".format(event_id),
                emit,
                self.usgs_attributes(data),
            )
        )
        old_mag = self._to_number(previous.get("magnitude"))
        new_mag = self._to_number(data.get("magnitude"))
        if old_mag is not None and new_mag is not None and new_mag - old_mag >= 0.3:
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning" if self.usgs_is_warning(data) else "info",
                    "usgs",
                    "usgs_earthquake_magnitude_updated",
                    "USGS earthquake magnitude updated",
                    "{} magnitude changed from {:.1f} to {:.1f}".format(
                        data.get("place") or event_id, old_mag, new_mag
                    ),
                    "usgs-earthquake-update:{}".format(event_id),
                    emit,
                    self.usgs_attributes(data),
                )
            )
        return findings

    def usgs_is_warning(self, data):
        """Return True for USGS earthquake warning Insights."""
        magnitude = self._to_number((data or {}).get("magnitude")) or 0
        distance = self._to_number((data or {}).get("distance_km"))
        threshold = float(self.config.get("usgs_warning_magnitude", 4.0))
        radius = float(self.config.get("usgs_warning_distance_km", 100))
        if int((data or {}).get("tsunami") or 0):
            return True
        if str((data or {}).get("alert_color") or "").lower() in ("yellow", "orange", "red"):
            return True
        if distance is not None:
            return distance <= radius and magnitude >= threshold
        return magnitude >= threshold

    def usgs_detail(self, data):
        """Return compact USGS finding detail."""
        parts = []
        magnitude = self._to_number(data.get("magnitude"))
        if magnitude is not None:
            parts.append("M{:.1f}".format(magnitude))
        if data.get("place"):
            parts.append(data.get("place"))
        distance = self._to_number(data.get("distance_km"))
        if distance is not None:
            parts.append("{:.1f} km from configured point".format(distance))
        if data.get("depth_km") is not None:
            parts.append("depth {} km".format(data.get("depth_km")))
        if data.get("alert_color"):
            parts.append("alert {}".format(data.get("alert_color")))
        if data.get("tsunami"):
            parts.append("tsunami flag")
        parts.append("internet-fed")
        return "; ".join(str(part) for part in parts if part)

    def usgs_attributes(self, data):
        """Return structured USGS evidence fields for Insights."""
        fields = (
            "event_id",
            "magnitude",
            "place",
            "latitude",
            "longitude",
            "depth_km",
            "distance_km",
            "event_time",
            "updated",
            "status",
            "felt",
            "cdi",
            "mmi",
            "alert_color",
            "tsunami",
            "detail_url",
            "internet_fed",
        )
        return {
            key: data.get(key)
            for key in fields
            if data.get(key) not in (None, "", [])
        }

    def _process_swpc(self, event_type, event, timestamp, emit):
        """Turn SWPC space-weather feed changes into live Insights."""
        data = clean_swpc_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("swpc", event_type, data, timestamp, emit)
        if event_type != "swpc_event":
            return []
        event_id = data.get("event_id") or data.get("summary") or "swpc"
        previous = self.swpc_events.get(event_id) or {}
        current = {
            "summary": data.get("summary") or "",
            "scale_label": data.get("scale_label") or "",
            "scale_value": data.get("scale_value"),
            "xray_class": data.get("xray_class") or "",
            "kp_index": data.get("kp_index"),
        }
        self.swpc_events[event_id] = current
        severity = "warning" if self.swpc_is_warning(data) else "info"
        findings = []
        if not previous:
            findings.extend(
                self._finding_list(
                    timestamp,
                    severity,
                    "swpc",
                    "swpc_event",
                    self.swpc_title(data),
                    self.swpc_detail(data),
                    "swpc-event:{}".format(event_id),
                    emit,
                    self.swpc_attributes(data),
                )
            )
        elif not self.swpc_importance_changed(previous, data):
            return []
        if previous and self.swpc_importance_changed(previous, data):
            findings.extend(
                self._finding_list(
                    timestamp,
                    severity,
                    "swpc",
                    "swpc_event_updated",
                    "SWPC event updated",
                    self.swpc_detail(data),
                    "swpc-event-update:{}".format(event_id),
                    emit,
                    self.swpc_attributes(data),
                )
            )
        return findings

    def swpc_is_warning(self, data):
        """Return True for SWPC records worth showing as warning Insights."""
        return swpc_event_is_alert(
            data,
            {
                "alert_min_xray_class": self.config.get(
                    "swpc_warning_xray_class", "X1.0"
                ),
                "alert_min_radio_blackout": self.config.get(
                    "swpc_warning_radio_blackout", "R3"
                ),
                "alert_min_solar_radiation_storm": self.config.get(
                    "swpc_warning_solar_radiation_storm", "S3"
                ),
                "alert_min_geomagnetic_storm": self.config.get(
                    "swpc_warning_geomagnetic_storm", "G3"
                ),
                "alert_min_kp": self.config.get("swpc_warning_kp", 7),
            },
        )

    def swpc_importance_changed(self, previous, data):
        """Return True when a retained SWPC event changed impact level."""
        return any(
            previous.get(key) != data.get(key)
            for key in ("scale_label", "scale_value", "xray_class", "kp_index")
        )

    def swpc_title(self, data):
        """Return compact SWPC finding title."""
        return "SWPC {}".format(data.get("event") or "space-weather event")

    def swpc_detail(self, data):
        """Return compact SWPC finding detail."""
        kp = number_or_none(data.get("kp_index"))
        parts = [
            data.get("summary") or "",
            data.get("xray_class") or "",
            data.get("scale_label") or "",
            kp is not None and "Kp {:.1f}".format(kp),
            data.get("event_time") or data.get("peak_time") or "",
            data.get("source") or "SWPC",
        ]
        return "; ".join(str(part) for part in parts if part)

    def swpc_attributes(self, data):
        """Return structured SWPC evidence fields for Insights."""
        fields = (
            "event_id",
            "event_kind",
            "event",
            "summary",
            "scale_family",
            "scale_value",
            "scale_label",
            "kp_index",
            "xray_class",
            "xray_flux_peak",
            "event_time",
            "start_time",
            "end_time",
            "peak_time",
            "issue_time",
            "source",
            "source_url",
            "product_id",
            "internet_fed",
        )
        return {
            key: data.get(key)
            for key in fields
            if data.get(key) not in (None, "", [])
        }

    def _process_pws(self, event_type, event, timestamp, now, emit):
        """Turn PWS weather samples into live Insights."""
        data = clean_pws_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("pws", event_type, data, timestamp, emit)
        if event_type == "collector_online":
            detail = "PWS feed online"
            if data.get("station_id"):
                detail += "; station {}".format(data.get("station_id"))
            return self._finding_list(
                timestamp,
                "info",
                "pws",
                "pws_feed_online",
                "PWS feed online",
                detail,
                "pws-online:{}".format(data.get("station_id") or "ambient"),
                emit,
                self.pws_attributes(data),
            )
        if event_type != "pws_weather":
            return []
        station = data.get("station_id") or data.get("station_name") or "PWS"
        previous = self.pws_stations.get(station) or {}
        findings = []
        findings.extend(
            self.pws_weather_pattern_findings(data, station, previous, timestamp, emit)
        )
        self.pws_update_station_state(station, data, now)
        return findings

    def pws_weather_pattern_findings(self, data, station, previous, timestamp, emit):
        """Return live PWS weather transition findings."""
        findings = []
        temperature = self._to_number(data.get("temperature_f"))
        previous_temperature = previous.get("temperature_f")
        if temperature is not None and previous_temperature is not None:
            delta = temperature - previous_temperature
            if abs(delta) >= float(self.config["pws_temp_change_f"]):
                attributes = self.pws_attributes(data)
                attributes["temperature_change_f"] = round(delta, 1)
                findings.extend(
                    self._finding_list(
                        timestamp,
                        "info",
                        "pws",
                        "pws_weather_temperature_change",
                        "PWS temperature changed",
                        "{} temperature changed {:+.0f} F to {:.0f} F".format(
                            station, delta, temperature
                        ),
                        "pws-temp-change:{}".format(station),
                        emit,
                        attributes,
                    )
                )
        rain_1h = self._to_number(data.get("rain_1h_in"))
        previous_rain = previous.get("rain_1h_in")
        if rain_1h is not None:
            if rain_1h >= float(self.config["pws_rain_1h_high_in"]):
                findings.extend(
                    self._finding_list(
                        timestamp,
                        "warning",
                        "pws",
                        "pws_weather_high_rain",
                        "PWS high rain rate",
                        "{} reported {:.2f} in/hr rain rate".format(station, rain_1h),
                        "pws-high-rain:{}".format(station),
                        emit,
                        self.pws_attributes(data),
                    )
                )
            if previous_rain is not None and previous_rain <= 0 < rain_1h:
                findings.extend(
                    self._finding_list(
                        timestamp,
                        "info",
                        "pws",
                        "pws_weather_rain_started",
                        "PWS rain started",
                        "{} rain started; 1h rain rate {:.2f} in/hr".format(
                            station, rain_1h
                        ),
                        "pws-rain-started:{}".format(station),
                        emit,
                        self.pws_attributes(data),
                    )
                )
            if previous_rain is not None and previous_rain > 0 and rain_1h <= 0:
                findings.extend(
                    self._finding_list(
                        timestamp,
                        "info",
                        "pws",
                        "pws_weather_rain_stopped",
                        "PWS rain stopped",
                        "{} rain stopped; 1h rain rate returned to {:.2f} in/hr".format(
                            station, rain_1h
                        ),
                        "pws-rain-stopped:{}".format(station),
                        emit,
                        self.pws_attributes(data),
                    )
                )
        wind = self._to_number(data.get("wind_speed_mph"))
        gust = self._to_number(data.get("wind_gust_mph"))
        wind_high = wind is not None and wind >= float(self.config["pws_wind_high_mph"])
        gust_high = gust is not None and gust >= float(self.config["pws_gust_high_mph"])
        if wind_high or gust_high:
            parts = []
            if wind is not None:
                parts.append("wind {:.0f} mph".format(wind))
            if gust is not None:
                parts.append("gust {:.0f} mph".format(gust))
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "pws",
                    "pws_weather_high_wind",
                    "PWS high wind",
                    "{} reported {}".format(station, ", ".join(parts)),
                    "pws-high-wind:{}".format(station),
                    emit,
                    self.pws_attributes(data),
                )
            )
        return findings

    def pws_update_station_state(self, station, data, now):
        """Remember latest PWS fields for live transition checks."""
        state = self.pws_stations.setdefault(station, {})
        state["last_seen_epoch"] = now
        for key in (
            "temperature_f",
            "rain_1h_in",
            "wind_speed_mph",
            "wind_gust_mph",
        ):
            value = self._to_number(data.get(key))
            if value is not None:
                state[key] = value

    def pws_detail(self, data):
        """Return compact PWS Insight detail."""
        parts = [
            data.get("station_id") or data.get("station_name") or "PWS",
            data.get("weather_summary") or "",
        ]
        latitude = self._to_number(data.get("latitude"))
        longitude = self._to_number(data.get("longitude"))
        if latitude is not None and longitude is not None:
            parts.append("{:.5f}, {:.5f}".format(latitude, longitude))
        if data.get("event_time"):
            parts.append("sample {}".format(data.get("event_time")))
        parts.append(data.get("source") or "Ambient Weather")
        return "; ".join(str(part) for part in parts if part)

    def pws_attributes(self, data):
        """Return structured PWS fields for Insights evidence."""
        fields = (
            "station_id",
            "station_name",
            "mac_address",
            "model",
            "latitude",
            "longitude",
            "event_time",
            "temperature_f",
            "humidity_percent",
            "dewpoint_f",
            "feels_like_f",
            "wind_direction_deg",
            "wind_speed_mph",
            "wind_gust_mph",
            "max_daily_gust_mph",
            "rain_1h_in",
            "rain_event_in",
            "rain_day_in",
            "pressure_rel_inhg",
            "pressure_abs_inhg",
            "solar_w_m2",
            "uv_index",
            "battery",
            "weather_summary",
            "source",
            "source_url",
        )
        return {
            key: data.get(key)
            for key in fields
            if data.get(key) not in (None, "", [])
        }

    def _process_lan(self, event_type, event, timestamp, emit):
        """Turn passive LAN observations into live Insights."""
        data = clean_lan_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("lan", event_type, data, timestamp, emit)
        if event_type in ("lan_gateway_seen", "lan_gateway_changed"):
            return self._process_lan_gateway(event_type, data, timestamp, emit)
        if event_type not in ("lan_device_seen", "lan_device_changed"):
            return []
        key = (
            data.get("subject_key")
            or data.get("mac")
            or data.get("ip")
            or "unknown"
        )
        self.lan_devices[key] = data
        if event_type == "lan_device_changed":
            return []
        return self._finding_list(
            timestamp,
            "info",
            "lan",
            "lan_device_new",
            "New LAN device",
            self.lan_device_detail(data),
            "lan-device:lan_device_new:{}".format(key),
            emit,
            self.lan_attributes(data),
        )

    def _process_lan_gateway(self, event_type, data, timestamp, emit):
        """Return default-gateway LAN findings."""
        key = "{}:{}".format(data.get("family") or "", data.get("interface") or "")
        self.lan_gateways[key] = data
        changed = event_type == "lan_gateway_changed"
        return self._finding_list(
            timestamp,
            "warning" if changed else "info",
            "lan",
            "lan_gateway_changed" if changed else "lan_gateway_seen",
            "LAN default gateway changed" if changed else "LAN default gateway seen",
            self.lan_gateway_detail(data),
            "lan-gateway:{}".format(key),
            emit,
            self.lan_attributes(data),
        )

    def lan_device_detail(self, data):
        """Return compact LAN device finding detail."""
        parts = [
            data.get("hostname") or "",
            data.get("mac") or "",
            ", ".join(data.get("ips") or []) or data.get("ip") or "",
            data.get("vendor_name") or "",
            data.get("interface") or "",
            data.get("state") or "",
            "gateway" if data.get("gateway") else "",
        ]
        return "; ".join(str(part) for part in parts if part)

    def lan_gateway_detail(self, data):
        """Return compact LAN gateway finding detail."""
        parts = [
            data.get("family") or "",
            data.get("gateway_ip") or "",
            data.get("interface") or "",
            data.get("mac") or "",
            data.get("vendor_name") or "",
        ]
        return "; ".join(str(part) for part in parts if part)

    def lan_attributes(self, data):
        """Return structured LAN evidence fields for Insights."""
        fields = (
            "subject_key",
            "mac",
            "ip",
            "ips",
            "hostname",
            "hostnames",
            "interface",
            "interfaces",
            "state",
            "states",
            "sources",
            "vendor_oui",
            "vendor_prefix",
            "vendor_name",
            "gateway",
            "gateways",
            "gateway_ip",
            "family",
            "change_type",
        )
        return {
            key: data.get(key)
            for key in fields
            if data.get(key) not in (None, "", [])
        }

    def _process_lan_identify(self, event_type, event, timestamp, emit):
        """Turn on-demand LAN Identify results into compact Insights."""
        data = clean_lan_data(event.get("data") or {})
        if event_type == "collector_offline":
            return self._collector_warning(
                "lan_identify", event_type, data, timestamp, emit
            )
        if event_type == "identify_failed":
            return self._finding_list(
                timestamp,
                "warning",
                "lan_identify",
                "lan_identify_failed",
                "LAN identify failed",
                self.lan_identify_detail(data),
                "lan-identify-failed:{}".format(
                    data.get("subject_key") or data.get("ip") or data.get("target") or "unknown"
                ),
                emit,
                self.lan_identify_attributes(data),
            )
        if event_type != "identify_result":
            return []
        return self._finding_list(
            timestamp,
            "info",
            "lan_identify",
            "lan_identify_result",
            "LAN identify result",
            self.lan_identify_detail(data),
            "lan-identify:{}".format(
                data.get("subject_key") or data.get("ip") or data.get("target") or "unknown"
            ),
            emit,
            self.lan_identify_attributes(data),
        )

    def lan_identify_detail(self, data):
        """Return compact LAN Identify finding detail."""
        parts = [
            data.get("ip") or data.get("target") or "",
            ", ".join(data.get("open_ports") or []) or "",
            ", ".join(data.get("http_titles") or []) or "",
            ", ".join(data.get("http_hints") or []) or "",
            ", ".join(data.get("identify_errors") or []) or "",
            data.get("reason") or "",
        ]
        return "; ".join(str(part) for part in parts if part)

    def lan_identify_attributes(self, data):
        """Return structured LAN Identify evidence fields for Insights."""
        fields = (
            "subject_key",
            "target",
            "ip",
            "mac",
            "open_ports",
            "service_banners",
            "http_urls",
            "http_titles",
            "http_headers",
            "http_scripts",
            "http_hints",
            "identify_errors",
            "reason",
            "duration_sec",
        )
        return {
            key: data.get(key)
            for key in fields
            if data.get(key) not in (None, "", [])
        }

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
        timestamp_epoch_value=None,
    ):
        """Create one finding unless the cooldown suppresses a duplicate."""
        now = (
            int(float(timestamp_epoch_value))
            if timestamp_epoch_value is not None
            else self._to_epoch(timestamp)
        )
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
            "timestamp_epoch": now,
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
        parsed = timestamp_epoch(timestamp)
        if parsed is not None:
            return parsed
        return now_epoch()

    def _to_number(self, value):
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _distance_km(self, lat1, lon1, lat2, lon2):
        """Return great-circle distance in kilometers for movement checks."""
        values = [self._to_number(value) for value in (lat1, lon1, lat2, lon2)]
        if any(value is None for value in values):
            return None
        lat1, lon1, lat2, lon2 = [math.radians(value) for value in values]
        delta_lat = lat2 - lat1
        delta_lon = lon2 - lon1
        root = (
            math.sin(delta_lat / 2.0) ** 2
            + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2.0) ** 2
        )
        return 6371.0 * 2.0 * math.asin(min(1.0, math.sqrt(root)))

    def _is_strong(self, rssi, threshold):
        value = self._to_number(rssi)
        return value is not None and value >= float(threshold)

    def _is_randomized_mac(self, mac):
        try:
            first_octet = int(str(mac).split(":", 1)[0], 16)
        except (TypeError, ValueError):
            return False
        return bool(first_octet & 0x02)
