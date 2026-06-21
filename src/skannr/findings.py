"""Live findings generated from the event stream.

Findings are the immediate, low-memory layer. They are produced while collectors
run, persisted as JSONL, and later materialized for the Insights/Reports views.
Longer historical interpretation belongs in device_history.py, history_analysis.py,
and reports.py.
"""

import fnmatch
import math
from collections import deque

from .bus import local_now
from .collectors.adsb import clean_adsb_data
from .collectors.aprsis import clean_aprs_data
from .collectors.lan import clean_lan_data
from .collectors.noaa import clean_noaa_data, tsunami_is_alertworthy
from .collectors.pws import clean_pws_data
from .collectors.rayhunter import clean_rayhunter_data, clean_rayhunter_field
from .collectors.rtl433 import clean_rtl433_data
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
    "wifi_monitor_emit_client_new": False,
    "wifi_monitor_emit_client_returned": False,
    "wifi_monitor_emit_client_lost": False,
    "wifi_monitor_emit_blank_probe": False,
    "wifi_monitor_emit_randomized_mac": False,
    "wifi_monitor_emit_probe_burst": False,
    "wifi_monitor_emit_strong_client": False,
    "wifi_monitor_emit_ap_presence": False,
    "wifi_monitor_emit_strong_ap": False,
    "wifi_monitor_probe_burst_once": True,
    "sensitive_ssids": [],
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
    "adsb_low_altitude_ft": 1500,
    "adsb_nearby_radius_km": 10,
    "adsb_emit_new_aircraft": True,
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
        self.wifi_probe_burst_active = set()
        self.ble_devices = {}
        self.bt_classic_devices = {}
        self.collector_states = {}
        self.aprs_stations = {}
        self.noaa_alerts = {}
        self.usgs_events = {}
        self.swpc_events = {}
        self.rayhunter_endpoints = {}
        self.lan_devices = {}
        self.lan_gateways = {}
        self.pws_stations = {}
        self.adsb_aircraft = {}
        self.rtl433_subjects = {}

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
        elif collector == "rtl433":
            findings.extend(
                self._process_rtl433(event_type, event, timestamp, emit)
            )
        elif collector == "adsb":
            findings.extend(
                self._process_adsb(event_type, event, timestamp, emit)
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

        if (
            (previous is None and self.emit_wifi_monitor_client_new(source))
            or (
                previous
                and (not was_active or self._is_return(previous, now))
                and self.emit_wifi_monitor_client_returned(source)
            )
            or (
                source != "wifi_monitor"
                and (previous is None or not was_active or self._is_return(previous, now))
            )
        ):
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

        if (
            not ssid
            and not blank_reported
            and self.emit_wifi_monitor_blank_probe(source)
        ):
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

        if (
            self._is_randomized_mac(mac)
            and previous is None
            and self.emit_wifi_monitor_randomized_mac(source)
        ):
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
            and self.emit_wifi_monitor_strong_client(source)
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
            self._wifi_sensitive_probe(source, mac, ssid, timestamp, emit, data)
        )
        findings.extend(
            self._wifi_probe_burst(source, mac, ssid, timestamp, now, emit)
        )
        return findings

    def _wifi_sensitive_probe(self, source, mac, ssid, timestamp, emit, data):
        """Detect probes for explicitly configured sensitive SSID patterns."""
        if source != "wifi_monitor" or not ssid:
            return []
        if not self.matches_sensitive_ssid(ssid):
            return []
        return self._finding_list(
            timestamp,
            "warning",
            source,
            "wifi_sensitive_ssid_probe",
            "Sensitive SSID probed",
            "Client {} probed for sensitive SSID '{}'".format(mac, ssid),
            "wifi-sensitive-probe:{}:{}".format(mac, ssid.lower()),
            emit,
            self.wifi_client_attributes(mac, ssid, data),
        )

    def _wifi_probe_burst(self, source, mac, ssid, timestamp, now, emit):
        """Detect a burst of probe requests from one client MAC."""
        if source == "wifi_monitor" and not self.config.get(
            "wifi_monitor_emit_probe_burst", False
        ):
            return []
        history = self.wifi_probe_history.setdefault(mac, deque())
        history.append(now)
        window = float(self.config["burst_window_sec"])
        while history and now - history[0] > window:
            history.popleft()
        if len(history) < int(self.config["burst_count"]):
            self.wifi_probe_burst_active.discard(mac)
            return []
        if (
            self.config.get("wifi_monitor_probe_burst_once", True)
            and source == "wifi_monitor"
            and mac in self.wifi_probe_burst_active
        ):
            return []
        self.wifi_probe_burst_active.add(mac)
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

        if previous is None and self.emit_wifi_monitor_ap_presence(source):
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
            strong_now
            and not was_strong
            and not strong_reported
            and self.emit_wifi_monitor_strong_ap(source)
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
        transmitter = data.get("transmitter_mac") or data.get("client_mac") or "unknown"
        receiver = data.get("receiver_mac") or data.get("ap_mac") or "unknown"
        detail = "Transmitter {} receiver {} channel {}".format(
            transmitter,
            receiver,
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
                event_type, transmitter, receiver
            ),
            emit,
            {
                "mac": transmitter,
                "bssid": data.get("bssid") or data.get("ap_mac") or "",
                "receiver_mac": receiver,
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
            "findmy_accessory": bool(data.get("findmy_accessory")),
            "findmy_label": data.get("findmy_label") or "",
            "findmy_payload_type": data.get("findmy_payload_type") or "",
            "findmy_status": data.get("findmy_status") or "",
            "findmy_hint": data.get("findmy_hint") or "",
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
        for field in (
            "findmy_accessory",
            "findmy_label",
            "findmy_payload_type",
            "findmy_status",
            "findmy_hint",
        ):
            if data.get(field):
                current[field] = data.get(field)
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
            "findmy_accessory": bool(data.get("findmy_accessory")),
            "findmy_label": data.get("findmy_label") or "",
            "findmy_payload_type": data.get("findmy_payload_type") or "",
            "findmy_status": data.get("findmy_status") or "",
            "findmy_hint": data.get("findmy_hint") or "",
        }

    def ble_live_finding_worthy(self, data, signal=False):
        """Return true when a BLE subject deserves an individual live Insight."""
        if not self.config.get("ble_live_identity_required", True):
            return True
        name = str((data or {}).get("name") or "").strip()
        mac = str((data or {}).get("mac") or "").strip().lower().replace("-", ":")
        if name and name.lower().replace("-", ":") != mac:
            return True
        if (data or {}).get("findmy_accessory"):
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

    def matches_sensitive_ssid(self, ssid):
        """Return True when an SSID matches configured sensitive patterns."""
        text = str(ssid or "").strip().lower()
        if not text:
            return False
        for pattern in self.config.get("sensitive_ssids") or []:
            candidate = str(pattern or "").strip().lower()
            if not candidate:
                continue
            if fnmatch.fnmatch(text, candidate) or candidate in text:
                return True
        return False

    def _collector_warning(self, source, event_type, data, timestamp, emit):
        """Return a normalized collector health finding."""
        severity = "warning" if event_type in ("collector_offline", "collector_retrying") else "info"
        state = "offline" if event_type == "collector_offline" else "retrying" if event_type == "collector_retrying" else event_type.replace("_", " ")
        name = data.get("name") or data.get("collector") or source
        detail = data.get("warning") or data.get("reason") or data.get("message") or "{} is {}".format(name, state)
        return self._finding_list(
            timestamp,
            severity,
            source,
            event_type,
            "{} {}".format(name, state),
            detail,
            "{}:{}".format(source, event_type),
            emit,
            {"collector": source},
        )

    def _process_aprsis(self, event_type, event, timestamp, now, emit):
        data = clean_aprs_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("aprsis", event_type, data, timestamp, emit)
        callsign = data.get("callsign") or data.get("object_name") or ""
        if not callsign:
            return []
        previous = self.aprs_stations.get(callsign)
        self.aprs_stations[callsign] = data
        if previous is not None:
            return []
        return self._finding_list(
            timestamp, "info", "aprsis", "aprsis_subject_seen",
            "New APRS-IS subject", "{} observed on APRS-IS".format(callsign),
            "aprsis-subject:{}".format(callsign), emit, data
        )

    def _process_noaa(self, event_type, event, timestamp, emit):
        data = clean_noaa_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("noaa", event_type, data, timestamp, emit)
        event_id = data.get("event_id") or data.get("source_event_id") or data.get("headline") or event_type
        self.noaa_alerts[event_id] = data
        alertish = event_type in ("noaa_weather_alert", "noaa_tsunami_alert", "noaa_tropical_advisory")
        if event_type == "noaa_tsunami_alert":
            alertish = tsunami_is_alertworthy(data)
        if not alertish:
            return []
        title = data.get("headline") or data.get("event") or "NOAA alert"
        return self._finding_list(
            timestamp, "warning", "noaa", event_type, title,
            data.get("description") or data.get("summary") or title,
            "noaa:{}".format(event_id), emit, data
        )

    def _process_usgs(self, event_type, event, timestamp, emit):
        data = clean_usgs_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("usgs", event_type, data, timestamp, emit)
        event_id = data.get("event_id") or data.get("id")
        if not event_id:
            return []
        self.usgs_events[event_id] = data
        magnitude = self._to_number(data.get("magnitude") or data.get("mag"))
        if magnitude is None or magnitude < 5.0:
            return []
        title = data.get("title") or "USGS earthquake"
        return self._finding_list(
            timestamp, "warning", "usgs", "usgs_significant_earthquake",
            title, "Magnitude {} earthquake reported".format(magnitude),
            "usgs:{}".format(event_id), emit, data
        )

    def _process_swpc(self, event_type, event, timestamp, emit):
        data = clean_swpc_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("swpc", event_type, data, timestamp, emit)
        event_id = data.get("event_id") or data.get("product_id") or data.get("message_id") or event_type
        self.swpc_events[event_id] = data
        if not swpc_event_is_alert(data):
            return []
        title = data.get("title") or data.get("message") or "SWPC space weather alert"
        return self._finding_list(
            timestamp, "warning", "swpc", "swpc_alert", title,
            data.get("summary") or title, "swpc:{}".format(event_id), emit, data
        )

    def _process_pws(self, event_type, event, timestamp, now, emit):
        data = clean_pws_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("pws", event_type, data, timestamp, emit)
        station = data.get("station_id") or data.get("station_name") or "pws"
        self.pws_stations[station] = data
        return []

    def _process_rayhunter(self, event_type, event, timestamp, emit):
        data = clean_rayhunter_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("rayhunter", event_type, data, timestamp, emit)
        endpoint = clean_rayhunter_field(data.get("endpoint") or data.get("url") or "rayhunter")
        self.rayhunter_endpoints[endpoint] = data
        status_text = " ".join(str(data.get(key) or "") for key in ("status", "warning", "error", "recording"))
        if not any(word in status_text.lower() for word in ("warn", "error", "fail", "missing")):
            return []
        return self._finding_list(
            timestamp, "warning", "rayhunter", "rayhunter_status_warning",
            "Rayhunter status warning", status_text.strip() or "Rayhunter reported a warning",
            "rayhunter:{}".format(endpoint), emit, data
        )

    def _process_lan(self, event_type, event, timestamp, emit):
        data = clean_lan_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("lan", event_type, data, timestamp, emit)
        key = data.get("subject_key") or data.get("mac") or data.get("ip") or data.get("hostname")
        if key:
            self.lan_devices[key] = data
        if event_type == "lan_gateway_seen":
            gateway = data.get("gateway_ip") or data.get("ip") or key or "gateway"
            self.lan_gateways[gateway] = data
        return []

    def _process_lan_identify(self, event_type, event, timestamp, emit):
        data = clean_lan_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("lan_identify", event_type, data, timestamp, emit)
        if event_type != "identify_failed":
            return []
        target = data.get("ip") or data.get("mac") or data.get("subject_key") or "LAN subject"
        return self._finding_list(
            timestamp, "warning", "lan_identify", "lan_identify_failed",
            "LAN identify failed", data.get("reason") or "LAN identify failed for {}".format(target),
            "lan-identify-failed:{}".format(target), emit, data
        )

    def _process_rtl433(self, event_type, event, timestamp, emit):
        """Generate compact findings from decoded rtl_433 events."""
        data = clean_rtl433_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("rtl433", event_type, data, timestamp, emit)
        if event_type != "rtl433_event":
            return []
        key = data.get("subject_key") or data.get("model") or data.get("id")
        if not key:
            return []
        previous = self.rtl433_subjects.get(key)
        self.rtl433_subjects[key] = data
        label = " ".join(
            part
            for part in (
                data.get("model") or "",
                data.get("id") or "",
                data.get("channel") or "",
            )
            if part
        ).strip() or "RTL-433 device"
        category = data.get("category") or "device"
        severity = "warning" if category in ("tpms", "security") else "info"
        title = "RTL-433 decoded signal"
        if previous is None:
            title = "New RTL-433 decoded subject"
        detail = "{} decoded by rtl_433 ({})".format(label, category)
        return self._finding_list(
            timestamp,
            severity,
            "rtl433",
            "rtl433_decoded_subject",
            title,
            detail,
            "rtl433:{}:{}".format(category, key),
            emit,
            data,
        )

    def _process_adsb(self, event_type, event, timestamp, emit):
        """Generate focused findings from decoded ADS-B aircraft state."""
        data = clean_adsb_data(event.get("data") or {})
        if event_type in ("collector_offline", "collector_retrying"):
            return self._collector_warning("adsb", event_type, data, timestamp, emit)
        if event_type != "adsb_aircraft":
            return []
        icao = data.get("icao")
        if not icao:
            return []
        previous = self.adsb_aircraft.get(icao)
        self.adsb_aircraft[icao] = data
        findings = []
        label = "{} {}".format(data.get("callsign") or "", icao).strip()
        if previous is None and self.config.get("adsb_emit_new_aircraft", True):
            findings.extend(
                self._finding_list(
                    timestamp,
                    "info",
                    "adsb",
                    "adsb_aircraft_new",
                    "New ADS-B aircraft",
                    "{} observed".format(label),
                    "adsb-aircraft-new:{}".format(icao),
                    emit,
                    data,
                )
            )
        if data.get("emergency"):
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "adsb",
                    "adsb_emergency_squawk",
                    "ADS-B emergency squawk",
                    "{} squawk {}".format(label, data.get("squawk") or "emergency"),
                    "adsb-emergency:{}".format(icao),
                    emit,
                    data,
                )
            )
        if self.adsb_low_nearby(data):
            findings.extend(
                self._finding_list(
                    timestamp,
                    "warning",
                    "adsb",
                    "adsb_low_nearby",
                    "Low nearby ADS-B aircraft",
                    "{} at {} ft, {} km".format(
                        label,
                        data.get("altitude_ft"),
                        data.get("distance_km"),
                    ),
                    "adsb-low-nearby:{}".format(icao),
                    emit,
                    data,
                )
            )
        return findings

    def adsb_low_nearby(self, data):
        """Return True for low aircraft near the observer."""
        altitude = self._to_number(data.get("altitude_ft"))
        distance = self._to_number(data.get("distance_km"))
        if altitude is None or distance is None:
            return False
        return (
            altitude <= float(self.config.get("adsb_low_altitude_ft", 1500))
            and distance <= float(self.config.get("adsb_nearby_radius_km", 10))
        )

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
        return findings

    def _expire_presence(self, timestamp, now):
        """Expire stale live-presence state opportunistically.

        The findings engine has no timer thread, so new events advance stale
        in-memory presence state. Expiration is intentionally conservative: it
        marks stale identities inactive so later sightings can become returned
        findings, and only emits lost findings where existing policy permits it.
        """
        findings = []
        lost_after = float(self.config.get("lost_after_sec", 300))

        for mac, state in list(self.wifi_clients.items()):
            if not state.get("active", False):
                continue
            if now - float(state.get("last_seen_epoch") or now) < lost_after:
                continue
            state["active"] = False
            self.wifi_clients[mac] = state
            source = state.get("source") or "wifi_monitor"
            if self.emit_wifi_monitor_client_lost(source):
                ssid = state.get("ssid") or ""
                detail = "Client {} has not been seen recently".format(mac)
                if ssid:
                    detail += " after probing for SSID {}".format(ssid)
                findings.extend(
                    self._finding_list(
                        timestamp,
                        "info",
                        source,
                        "wifi_client_lost",
                        "Wi-Fi client disappeared",
                        detail,
                        "wifi-client-lost:{}".format(mac),
                        True,
                        self.wifi_client_attributes(mac, ssid, state),
                    )
                )

        for collection in (self.wifi_aps, self.ble_devices, self.bt_classic_devices):
            for key, state in list(collection.items()):
                if not state.get("active", False):
                    continue
                if now - float(state.get("last_seen_epoch") or now) < lost_after:
                    continue
                state["active"] = False
                collection[key] = state

        return findings

    def emit_wifi_monitor_client_new(self, source):
        return source != "wifi_monitor" or bool(
            self.config.get("wifi_monitor_emit_client_new", False)
        )

    def emit_wifi_monitor_client_returned(self, source):
        return source != "wifi_monitor" or bool(
            self.config.get("wifi_monitor_emit_client_returned", False)
        )

    def emit_wifi_monitor_client_lost(self, source):
        return source != "wifi_monitor" or bool(
            self.config.get("wifi_monitor_emit_client_lost", False)
        )

    def emit_wifi_monitor_blank_probe(self, source):
        return source != "wifi_monitor" or bool(
            self.config.get("wifi_monitor_emit_blank_probe", False)
        )

    def emit_wifi_monitor_randomized_mac(self, source):
        return source != "wifi_monitor" or bool(
            self.config.get("wifi_monitor_emit_randomized_mac", False)
        )

    def emit_wifi_monitor_strong_client(self, source):
        return source != "wifi_monitor" or bool(
            self.config.get("wifi_monitor_emit_strong_client", False)
        )

    def emit_wifi_monitor_ap_presence(self, source):
        return source != "wifi_monitor" or bool(
            self.config.get("wifi_monitor_emit_ap_presence", False)
        )

    def emit_wifi_monitor_strong_ap(self, source):
        return source != "wifi_monitor" or bool(
            self.config.get("wifi_monitor_emit_strong_ap", False)
        )

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
