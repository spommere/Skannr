"""Live alert rules for operator-attention events.

Findings explain notable observations. Alerts are narrower: they are the small
set of live conditions that should be visible from any dashboard tab.
"""

import fnmatch
import re
from collections import deque

from .bus import local_now
from .collectors.lan import clean_lan_data
from .collectors.noaa import (
    clean_noaa_data,
    stable_noaa_event_key,
    tsunami_is_alertworthy,
)
from .collectors.pws import clean_pws_data
from .collectors.rtl433 import clean_rtl433_data
from .collectors.swpc import (
    clean_swpc_data,
    number_or_none,
    swpc_event_is_alert,
    swpc_event_is_critical,
)
from .collectors.usgs import clean_usgs_data
from .log_utils import event_time_epoch, now_epoch


DEFAULT_ALERT_CONFIG = {
    "enabled": True,
    "max_items": 50,
    "active_ttl_sec": 3600,
    "dedupe_sec": 900,
    "ack_memory_ttl_sec": 604800,
    "ack_memory_alert_types": ["noaa_hazard"],
    "_disabled_noaa_sources": [],
    "pushover": {
        "enabled": False,
        "userkey": "",
        "appkey": "",
    },
    "drone_wifi": {
        "enabled": True,
        "level": "critical",
        "min_rssi": -80,
        "ssid_patterns": [
            "RID-*",
            "DJI*",
            "Mavic*",
            "Phantom*",
            "Inspire*",
            "Spark*",
            "Mini*",
            "Autel*",
            "Parrot*",
        ],
        "vendor_patterns": [
            "DJI",
            "SZ DJI",
            "Autel",
            "Parrot",
            "Yuneec",
        ],
        "oui_prefixes": [
            "60:60:1f",
        ],
    },
    "aprs_weather": {
        "enabled": True,
        "level": "warning",
        "critical_level": "critical",
        "rain_1h_in": 1.0,
        "critical_rain_1h_in": 2.0,
        "wind_gust_mph": 40,
        "critical_wind_gust_mph": 60,
    },
    "pws_weather": {
        "enabled": True,
        "level": "warning",
        "critical_level": "critical",
        "rain_1h_in": 1.0,
        "critical_rain_1h_in": 2.0,
        "wind_gust_mph": 40,
        "critical_wind_gust_mph": 60,
    },
    "rayhunter_warning": {
        "enabled": True,
        "level": "critical",
    },
    "wifi_disruption": {
        "enabled": True,
        "level": "critical",
        "window_sec": 60,
        "count": 5,
        "broadcast_count": 3,
        "distinct_receiver_count": 3,
        "single_receiver_count": 50,
        "suppress_known_ap_self_deauth": True,
    },
    "wifi_open_sensitive": {
        "enabled": True,
        "level": "critical",
        "ssid_patterns": [],
    },
    "ble_tracker": {
        "enabled": True,
        "level": "critical",
        "min_rssi": -85,
        "name_patterns": [
            "*airtag*",
            "*find my*",
            "*tile*",
            "*chipolo*",
            "*smarttag*",
            "*tracker*",
            "*pebblebee*",
            "*orbit*",
        ],
        "manufacturer_patterns": [],
        "service_uuid_patterns": [
            "fd44",
        ],
    },
    "collector_issue": {
        "enabled": False,
        "level": "warning",
        "ignored_reason_patterns": [
            "*No monitor-mode Wi-Fi interface found*",
        ],
    },
    "noaa_hazard": {
        "enabled": True,
        "level": "warning",
        "critical_level": "critical",
        "critical_events": [
            "*tsunami warning*",
            "*tornado warning*",
            "*hurricane warning*",
            "*flash flood warning*",
        ],
        "critical_severities": ["Extreme"],
    },
    "usgs_earthquake": {
        "enabled": True,
        "level": "warning",
        "critical_level": "critical",
        "warning_magnitude_nearby": 4.0,
        "critical_magnitude_nearby": 5.0,
        "warning_magnitude_global": 6.5,
        "critical_magnitude_global": 7.5,
        "nearby_radius_km": 100,
        "critical_alert_colors": ["orange", "red"],
    },
    "swpc_space_weather": {
        "enabled": True,
        "level": "warning",
        "critical_level": "critical",
        "alert_min_xray_class": "X1.0",
        "critical_min_xray_class": "X5.0",
        "alert_min_radio_blackout": "R3",
        "critical_min_radio_blackout": "R4",
        "alert_min_solar_radiation_storm": "S3",
        "critical_min_solar_radiation_storm": "S4",
        "alert_min_geomagnetic_storm": "G3",
        "critical_min_geomagnetic_storm": "G4",
        "alert_min_kp": 7,
        "critical_min_kp": 8,
    },
    "lan_gateway_change": {
        "enabled": True,
        "level": "warning",
    },
    "lan_new_device": {
        "enabled": False,
        "level": "warning",
    },
    "adsb_aircraft": {
        "enabled": True,
        "level": "warning",
        "critical_level": "critical",
        "nearby_radius_km": 10,
        "low_altitude_ft": 1500,
    },
    "rtl433_signal": {
        "enabled": False,
        "level": "warning",
        "categories": ["tpms", "security"],
        "model_patterns": [],
        "protocols": [],
    },
}

LEVEL_PRIORITY = {
    "info": 0,
    "warning": 1,
    "critical": 2,
}

ACK_KEY_VERSION = 3
POLL_FEED_ACK_ALERT_TYPES = {
    "noaa_hazard",
    "usgs_earthquake",
    "swpc_space_weather",
}


class AlertEngine:
    """Deterministic live alert engine.

    The engine keeps only a bounded in-memory active-alert set. Alert events are
    still persisted by main.py, so the raw audit trail remains under
    runtime/logs/alerts/*.jsonl.
    """

    def __init__(self, config=None):
        self.config = merge_config(DEFAULT_ALERT_CONFIG, config or {})
        self.enabled = bool(self.config.get("enabled", True))
        self.max_items = int(self.config.get("max_items", 50))
        self.active_ttl_sec = float(self.config.get("active_ttl_sec", 3600))
        self.dedupe_sec = float(self.config.get("dedupe_sec", 900))
        self.ack_memory_ttl_sec = float(self.config.get("ack_memory_ttl_sec", 604800))
        self.ack_memory_alert_types = POLL_FEED_ACK_ALERT_TYPES | {
            str(item or "").strip()
            for item in self.config.get("ack_memory_alert_types") or []
            if str(item or "").strip()
        }
        self.disabled_noaa_sources = {
            str(item or "").strip().lower()
            for item in self.config.get("_disabled_noaa_sources") or []
            if str(item or "").strip()
        }
        self.active = {}
        self.ack_memory = {}
        self.recent = deque(maxlen=self.max_items)
        self._counter = 0
        self.wifi_disruptions = {}
        self.known_bssids = {}  # normalized_bssid -> ssid (from subject history)
        self.dirty = False

    def set_known_bssids(self, bssid_to_ssid):
        """Update the known-AP index for wifi_disruption cross-referencing.

        Args:
            bssid_to_ssid: dict mapping normalized BSSID string to SSID string.
        """
        self.known_bssids = bssid_to_ssid

    def process(self, event, emit=True):
        """Process one live event and return newly emitted alert events."""
        if not self.enabled:
            return []
        now = event_time_epoch(event) or now_epoch()
        timestamp = event.get("timestamp") or local_now(now)
        self.expire(now)
        alerts = []
        collector = event.get("collector")
        event_type = event.get("type")
        data = event.get("data") or {}
        if collector in ("wifi", "wifi_monitor"):
            alerts.extend(self.process_wifi(collector, event_type, data, timestamp, now, emit))
        elif collector == "ble":
            alerts.extend(self.process_ble(event_type, data, timestamp, now, emit))
        elif collector == "aprsis":
            alerts.extend(self.process_aprsis(event_type, data, timestamp, now, emit))
        elif collector == "rayhunter":
            alerts.extend(self.process_rayhunter(event_type, data, timestamp, now, emit))
        elif collector == "noaa":
            alerts.extend(self.process_noaa(event_type, data, timestamp, now, emit))
        elif collector == "usgs":
            alerts.extend(self.process_usgs(event_type, data, timestamp, now, emit))
        elif collector == "swpc":
            alerts.extend(self.process_swpc(event_type, data, timestamp, now, emit))
        elif collector == "pws":
            alerts.extend(self.process_pws(event_type, data, timestamp, now, emit))
        elif collector == "adsb":
            alerts.extend(self.process_adsb(event_type, data, timestamp, now, emit))
        elif collector == "rtl433":
            alerts.extend(self.process_rtl433(event_type, data, timestamp, now, emit))
        elif collector == "lan":
            alerts.extend(self.process_lan(event_type, data, timestamp, now, emit))
        elif collector == "system":
            alerts.extend(self.process_system(event_type, data, timestamp, now, emit))
        return alerts

    def snapshot(self):
        """Return active alerts newest/highest first for browser reconnects."""
        self.expire(now_epoch())
        alerts = list(self.active.values())
        alerts.sort(
            key=lambda item: (
                LEVEL_PRIORITY.get(item.get("level"), 0),
                item.get("last_seen_epoch") or 0,
            ),
            reverse=True,
        )
        return [public_alert(item) for item in alerts[: self.max_items]]

    def export_state(self):
        """Return restart-persistent alert state."""
        now = now_epoch()
        self.expire(now)
        alerts = list(self.active.values())
        alerts.sort(key=lambda item: item.get("last_seen_epoch") or 0, reverse=True)
        self.prune_ack_memory(now)
        return {
            "version": 1,
            "saved_at": local_now(now),
            "saved_at_epoch": now,
            "active": [dict(item) for item in alerts[: self.max_items]],
            "ack_memory": dict(self.ack_memory),
        }

    def load_state(self, state):
        """Restore active/ACKed alert state from a previous process."""
        if not isinstance(state, dict):
            return
        now = now_epoch()
        cutoff = now - self.active_ttl_sec if self.active_ttl_sec > 0 else None
        active = {}
        max_sequence = 0
        ack_memory = {}
        self.load_ack_memory(state.get("ack_memory"), ack_memory, now)
        for item in state.get("active") or []:
            if not isinstance(item, dict):
                continue
            key = normalized_key(item.get("id"))
            if not key:
                continue
            try:
                last_seen = float(item.get("last_seen_epoch") or 0)
            except (TypeError, ValueError):
                last_seen = 0
            if cutoff is not None and last_seen and last_seen < cutoff:
                continue
            alert = dict(item)
            original_key = key
            key = self.canonical_alert_key(alert, key)
            alert["id"] = key
            alert["acked"] = bool(alert.get("acked"))
            alert["evidence"] = clean_evidence(alert.get("evidence") or {})
            alert["count"] = int(float(alert.get("count") or 1))
            if self.alert_source_disabled(alert):
                self.dirty = True
                continue
            if (
                alert.get("acked")
                and self.is_nhc_noaa_alert(alert)
                and (
                    original_key != key
                    or int(float(alert.get("ack_key_version") or 0)) < ACK_KEY_VERSION
                )
            ):
                # Older builds keyed NHC ACKs by advisory family, so an ACK for
                # Amanda Public Advisory 10 could suppress Public Advisory 11.
                # During migration to exact item IDs, require a fresh ACK.
                alert["acked"] = False
                alert.pop("acked_at", None)
                alert.pop("acked_at_epoch", None)
                alert.pop("ack_key_version", None)
            if alert.get("acked"):
                self.remember_ack(alert, last_seen or now, ack_memory)
            # Give restored active alerts a fresh dedupe window so restart does
            # not immediately re-emit the same condition as a new alert.
            alert["last_emitted_epoch"] = now
            try:
                max_sequence = max(max_sequence, int(alert.get("sequence") or 0))
            except (TypeError, ValueError):
                pass
            if key in active:
                active[key] = self.merge_alert_records(active[key], alert)
            else:
                active[key] = alert
        self.active = active
        self.ack_memory = ack_memory
        self.prune_ack_memory(now)
        self._counter = max(self._counter, max_sequence)
        self.dirty = False

    def process_wifi(self, source, event_type, data, timestamp, now, emit):
        """Return Wi-Fi alert events from AP and disruption observations."""
        if event_type == "ap_beacon":
            return self.wifi_ap_alerts(source, data, timestamp, now, emit)
        if event_type in ("deauth_seen", "disassoc_seen"):
            return self.wifi_disruption_alerts(source, event_type, data, timestamp, now, emit)
        if event_type in ("collector_offline", "collector_retrying"):
            return self.collector_issue_alert(source, event_type, data, timestamp, now, emit)
        return []

    def wifi_ap_alerts(self, source, data, timestamp, now, emit):
        """Return AP-level alerts such as drone or sensitive open SSID."""
        alerts = []
        drone_rule = self.rule("drone_wifi")
        if drone_rule.get("enabled", True) and self.matches_drone_wifi(data, drone_rule):
            ssid = data.get("ssid") or "(blank)"
            bssid = data.get("bssid") or "unknown"
            rssi = self.to_number(data.get("rssi"))
            remote_id = self.is_remote_id_ssid(ssid)
            title = (
                "Drone Remote ID broadcast seen"
                if remote_id
                else "Drone Wi-Fi AP seen"
            )
            summary = "{}: {}; {}; {}".format(
                "Drone Remote ID broadcast" if remote_id else "Drone Wi-Fi AP seen",
                ssid,
                bssid,
                self.wifi_signal_summary(data),
            )
            alerts.extend(
                self.emit_alert(
                    "wifi_drone",
                    "wifi-drone:{}".format(normalized_key(bssid)),
                    drone_rule.get("level", "critical"),
                    source,
                    title,
                    ssid,
                    summary,
                    timestamp,
                    now,
                    emit,
                    {
                        "ssid": ssid,
                        "bssid": bssid,
                        "vendor_name": data.get("vendor_name") or "",
                        "vendor_prefix": data.get("vendor_prefix")
                        or data.get("vendor_oui")
                        or "",
                        "rssi": rssi,
                        "channel": data.get("channel"),
                        "frequency_mhz": data.get("frequency_mhz"),
                        "encryption": data.get("encryption") or "",
                        "remote_id": remote_id,
                        "confidence": self.drone_confidence(data, drone_rule),
                    },
                )
            )
        sensitive_rule = self.rule("wifi_open_sensitive")
        if sensitive_rule.get("enabled", True) and self.matches_sensitive_open_wifi(
            data, sensitive_rule
        ):
            ssid = data.get("ssid") or "(blank)"
            bssid = data.get("bssid") or "unknown"
            alerts.extend(
                self.emit_alert(
                    "wifi_sensitive_open",
                    "wifi-sensitive-open:{}:{}".format(ssid.lower(), normalized_key(bssid)),
                    sensitive_rule.get("level", "critical"),
                    source,
                    "Sensitive SSID is open",
                    ssid,
                    "Sensitive SSID '{}' is being advertised as open by {}".format(
                        ssid, bssid
                    ),
                    timestamp,
                    now,
                    emit,
                    {
                        "ssid": ssid,
                        "bssid": bssid,
                        "encryption": data.get("encryption") or "",
                        "rssi": self.to_number(data.get("rssi")),
                    },
                )
            )
        return alerts

    def matches_drone_wifi(self, data, rule):
        """Return True when AP fields match configured drone indicators."""
        rssi = self.to_number(data.get("rssi"))
        min_rssi = self.to_number(rule.get("min_rssi"))
        if rssi is not None and min_rssi is not None and rssi < min_rssi:
            return False
        ssid_match = pattern_match(data.get("ssid"), rule.get("ssid_patterns"))
        vendor_match = pattern_match(
            "{} {}".format(data.get("vendor_name") or "", data.get("vendor_prefix") or ""),
            rule.get("vendor_patterns"),
        )
        oui_match = normalized_oui(data.get("bssid")) in {
            normalized_oui(item) for item in rule.get("oui_prefixes") or []
        }
        return ssid_match or vendor_match or oui_match

    def drone_confidence(self, data, rule):
        """Return a compact confidence label for drone alerts."""
        ssid_match = pattern_match(data.get("ssid"), rule.get("ssid_patterns"))
        vendor_match = pattern_match(data.get("vendor_name"), rule.get("vendor_patterns"))
        oui_match = normalized_oui(data.get("bssid")) in {
            normalized_oui(item) for item in rule.get("oui_prefixes") or []
        }
        matches = sum(bool(item) for item in (ssid_match, vendor_match, oui_match))
        return "High" if matches >= 2 else "Medium"

    def is_remote_id_ssid(self, ssid):
        """Return True for drone Remote ID SSIDs such as DJI RID-* broadcasts."""
        return str(ssid or "").strip().upper().startswith("RID-")

    def matches_sensitive_open_wifi(self, data, rule):
        """Return True for configured sensitive SSIDs advertised as open."""
        patterns = rule.get("ssid_patterns") or []
        if not patterns or not pattern_match(data.get("ssid"), patterns):
            return False
        return wifi_is_open(data.get("encryption"))

    def wifi_disruption_alerts(self, source, event_type, data, timestamp, now, emit):
        """Alert only when deauth/disassociation frames look attack-like."""
        rule = self.rule("wifi_disruption")
        if not rule.get("enabled", True):
            return []
        transmitter = (
            data.get("transmitter_mac")
            or data.get("client_mac")
            or data.get("ap_mac")
            or data.get("bssid")
            or "unknown"
        )
        receiver = (
            data.get("receiver_mac")
            or data.get("ap_mac")
            or data.get("client_mac")
            or "unknown"
        )
        bssid = data.get("bssid") or data.get("ap_mac") or transmitter
        receiver_key = normalized_key(receiver)
        broadcast = bool(data.get("receiver_is_broadcast")) or self.is_broadcast_mac(receiver)
        key = "{}:{}".format(event_type, normalized_key(transmitter))
        history = self.wifi_disruptions.setdefault(key, deque())
        history.append(
            {
                "timestamp": now,
                "receiver": receiver_key,
                "bssid": normalized_key(bssid),
                "broadcast": broadcast,
                "channel": data.get("channel"),
                "rssi": self.to_number(data.get("rssi")),
            }
        )
        window = float(rule.get("window_sec", 60))
        while history and now - history[0]["timestamp"] > window:
            history.popleft()
        total_count = len(history)
        min_total = int(rule.get("count", 5))
        broadcast_count = sum(1 for item in history if item.get("broadcast"))
        distinct_receivers = {
            item.get("receiver")
            for item in history
            if item.get("receiver") and item.get("receiver") != "unknown"
        }
        per_receiver_count = sum(
            1 for item in history if item.get("receiver") == receiver_key
        )
        required_broadcast = int(rule.get("broadcast_count", 3))
        required_receivers = int(rule.get("distinct_receiver_count", 3))
        required_single = int(rule.get("single_receiver_count", 50))
        attack_pattern = None
        if broadcast_count >= required_broadcast and total_count >= min_total:
            attack_pattern = "broadcast"
        elif (
            len(distinct_receivers) >= required_receivers
            and total_count >= min_total
        ):
            attack_pattern = "multi-receiver"
        elif per_receiver_count >= required_single:
            attack_pattern = "high-rate single-receiver"
        if not attack_pattern:
            return []
        # Suppress when transmitter and receiver are both known BSSIDs of the
        # same SSID (e.g., band steering — one radio deauthing the other).
        # This is normal AP behavior, not an attack.
        if self.known_bssids and rule.get("suppress_known_ap_self_deauth", True):
            tx_ssid = self.known_bssids.get(normalized_key(transmitter))
            rx_ssid = self.known_bssids.get(normalized_key(receiver))
            if tx_ssid and rx_ssid and tx_ssid == rx_ssid:
                return []
        title = "Wi-Fi disruption burst"
        summary = "{} attack-like {} frame(s) in {:.0f}s; transmitter {}; receivers {}; pattern {}".format(
            total_count,
            "deauth" if event_type == "deauth_seen" else "disassociation",
            window,
            transmitter,
            len(distinct_receivers) or 1,
            attack_pattern,
        )
        return self.emit_alert(
            "wifi_disruption_burst",
            "wifi-disruption:{}:{}:{}".format(
                event_type, normalized_key(transmitter), attack_pattern
            ),
            rule.get("level", "critical"),
            source,
            title,
            transmitter,
            summary,
            timestamp,
            now,
            emit,
            {
                "event_type": event_type,
                "bssid": bssid,
                "transmitter_mac": transmitter,
                "receiver_mac": receiver,
                "receiver_is_broadcast": broadcast,
                "attack_pattern": attack_pattern,
                "count": total_count,
                "broadcast_count": broadcast_count,
                "distinct_receiver_count": len(distinct_receivers),
                "single_receiver_count": per_receiver_count,
                "window_sec": window,
                "channel": data.get("channel"),
                "rssi": self.to_number(data.get("rssi")),
            },
        )

    @staticmethod
    def is_broadcast_mac(mac):
        """Return True for broadcast destination MACs."""
        return str(mac or "").lower() == "ff:ff:ff:ff:ff:ff"

    def process_ble(self, event_type, data, timestamp, now, emit):
        """Return BLE tracker-style alerts."""
        if event_type not in ("device_seen", "device_updated"):
            if event_type in ("collector_offline", "collector_retrying"):
                return self.collector_issue_alert("ble", event_type, data, timestamp, now, emit)
            return []
        rule = self.rule("ble_tracker")
        if not rule.get("enabled", True):
            return []
        if not self.matches_ble_tracker(data, rule):
            return []
        mac = data.get("mac") or "unknown"
        name = data.get("name") or data.get("findmy_label") or mac
        summary = "Tracker-like BLE device seen nearby: {}; {}; {}".format(
            name,
            mac,
            self.ble_signal_summary(data),
        )
        return self.emit_alert(
            "ble_tracker",
            "ble-tracker:{}".format(normalized_key(mac)),
            rule.get("level", "critical"),
            "ble",
            "Tracker-like BLE device nearby",
            name,
            summary,
            timestamp,
            now,
            emit,
            {
                "mac": mac,
                "name": data.get("name") or "",
                "manufacturer": data.get("manufacturer") or "",
                "service_uuids": data.get("service_uuids") or [],
                "findmy_accessory": bool(data.get("findmy_accessory")),
                "findmy_label": data.get("findmy_label") or "",
                "findmy_payload_type": data.get("findmy_payload_type") or "",
                "findmy_status": data.get("findmy_status") or "",
                "findmy_hint": data.get("findmy_hint") or "",
                "rssi": self.to_number(data.get("rssi")),
                "confidence": "High"
                if data.get("name") or data.get("findmy_accessory")
                else "Medium",
            },
        )

    def matches_ble_tracker(self, data, rule):
        """Return True when BLE fields match configured tracker indicators."""
        rssi = self.to_number(data.get("rssi"))
        min_rssi = self.to_number(rule.get("min_rssi"))
        if rssi is not None and min_rssi is not None and rssi < min_rssi:
            return False
        if data.get("findmy_accessory"):
            return True
        if pattern_match(data.get("name"), rule.get("name_patterns")):
            return True
        if pattern_match(data.get("manufacturer"), rule.get("manufacturer_patterns")):
            return True
        uuids = " ".join(str(item or "") for item in data.get("service_uuids") or [])
        return pattern_match(uuids, rule.get("service_uuid_patterns"))

    def process_aprsis(self, event_type, data, timestamp, now, emit):
        """Return APRS-IS weather alerts."""
        if event_type in ("collector_offline", "collector_retrying"):
            return self.collector_issue_alert("aprsis", event_type, data, timestamp, now, emit)
        packet_type = data.get("packet_type") or event_type.replace("aprs_", "")
        if packet_type != "weather" and not data.get("weather_summary"):
            return []
        rule = self.rule("aprs_weather")
        if not rule.get("enabled", True):
            return []
        rain = self.to_number(data.get("rain_1h_in"))
        gust = self.to_number(data.get("wind_gust_mph"))
        reasons = []
        critical = False
        if rain is not None and rain >= float(rule.get("rain_1h_in", 1.0)):
            reasons.append("1h rain rate {:.2f} in/hr".format(rain))
            if rain >= float(rule.get("critical_rain_1h_in", 2.0)):
                critical = True
        if gust is not None and gust >= float(rule.get("wind_gust_mph", 40)):
            reasons.append("gust {:.0f} mph".format(gust))
            if gust >= float(rule.get("critical_wind_gust_mph", 60)):
                critical = True
        if not reasons:
            return []
        callsign = data.get("callsign") or "weather station"
        level = rule.get("critical_level", "critical") if critical else rule.get("level", "warning")
        summary = "APRS-IS weather alert for {}: {}".format(
            callsign, "; ".join(reasons)
        )
        return self.emit_alert(
            "aprs_weather",
            "aprs-weather:{}".format(callsign.upper()),
            level,
            "aprsis",
            "APRS-IS severe weather",
            callsign,
            summary,
            timestamp,
            now,
            emit,
            {
                "callsign": callsign,
                "rain_1h_in": rain,
                "wind_gust_mph": gust,
                "weather_summary": data.get("weather_summary") or "",
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "feed_name": data.get("feed_name") or "",
            },
        )

    def process_pws(self, event_type, data, timestamp, now, emit):
        """Return PWS weather alerts."""
        if event_type in ("collector_offline", "collector_retrying"):
            return self.collector_issue_alert("pws", event_type, data, timestamp, now, emit)
        if event_type != "pws_weather":
            return []
        rule = self.rule("pws_weather")
        if not rule.get("enabled", True):
            return []
        data = clean_pws_data(data)
        rain = self.to_number(data.get("rain_1h_in"))
        gust = self.to_number(data.get("wind_gust_mph"))
        reasons = []
        critical = False
        if rain is not None and rain >= float(rule.get("rain_1h_in", 1.0)):
            reasons.append("1h rain rate {:.2f} in/hr".format(rain))
            if rain >= float(rule.get("critical_rain_1h_in", 2.0)):
                critical = True
        if gust is not None and gust >= float(rule.get("wind_gust_mph", 40)):
            reasons.append("gust {:.0f} mph".format(gust))
            if gust >= float(rule.get("critical_wind_gust_mph", 60)):
                critical = True
        if not reasons:
            return []
        station = data.get("station_id") or data.get("station_name") or "PWS"
        level = rule.get("critical_level", "critical") if critical else rule.get("level", "warning")
        summary = "PWS weather alert for {}: {}".format(
            station, "; ".join(reasons)
        )
        return self.emit_alert(
            "pws_weather",
            "pws-weather:{}".format(station),
            level,
            "pws",
            "PWS severe weather",
            station,
            summary,
            timestamp,
            now,
            emit,
            {
                "station_id": station,
                "rain_1h_in": rain,
                "wind_gust_mph": gust,
                "weather_summary": data.get("weather_summary") or "",
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "source": data.get("source") or "",
                "source_url": data.get("source_url") or "",
            },
        )

    def process_rayhunter(self, event_type, data, timestamp, now, emit):
        """Return Rayhunter warning alerts."""
        if event_type in ("collector_offline", "collector_retrying"):
            return self.collector_issue_alert("rayhunter", event_type, data, timestamp, now, emit)
        if event_type != "rayhunter_status":
            return []
        rule = self.rule("rayhunter_warning")
        if not rule.get("enabled", True):
            return []
        warning_count = self.to_int(data.get("warning_count"))
        if warning_count <= 0:
            return []
        endpoint = data.get("endpoint") or data.get("url") or "Rayhunter"
        summary = "Rayhunter reported {} warning(s) at {}".format(
            warning_count, endpoint
        )
        return self.emit_alert(
            "rayhunter_warning",
            "rayhunter-warning:{}".format(endpoint),
            rule.get("level", "critical"),
            "rayhunter",
            "Rayhunter warning present",
            endpoint,
            summary,
            timestamp,
            now,
            emit,
            {
                "endpoint": endpoint,
                "warning_count": warning_count,
                "summary": data.get("summary") or "",
            },
        )

    def process_noaa(self, event_type, data, timestamp, now, emit):
        """Return NOAA hazard alerts."""
        if event_type in ("collector_offline", "collector_retrying"):
            return self.collector_issue_alert("noaa", event_type, data, timestamp, now, emit)
        if event_type not in (
            "noaa_weather_alert",
            "noaa_tropical_advisory",
            "noaa_tsunami_alert",
        ):
            return []
        rule = self.rule("noaa_hazard")
        if not rule.get("enabled", True):
            return []
        data = clean_noaa_data(data)
        if self.noaa_source_disabled(event_type, data):
            return []
        if not self.noaa_matches_alert(data, rule):
            return []
        event_id = data.get("event_id") or data.get("headline") or data.get("event") or "noaa"
        critical = self.noaa_is_critical(data, rule)
        level = rule.get("critical_level", "critical") if critical else rule.get("level", "warning")
        event_name = data.get("event") or data.get("headline") or "NOAA hazard"
        feed_source = self.noaa_feed_source(event_type, data)
        summary = "{}: {}; {}".format(
            feed_source,
            event_name,
            data.get("area_desc") or data.get("severity") or "active hazard",
        )
        return self.emit_alert(
            "noaa_hazard",
            self.noaa_alert_key(event_type, data, event_id),
            level,
            feed_source,
            "{} hazard".format(feed_source),
            event_name,
            summary,
            timestamp,
            now,
            emit,
            {
                "event_id": event_id,
                "event": data.get("event") or "",
                "headline": data.get("headline") or "",
                "severity": data.get("severity") or "",
                "urgency": data.get("urgency") or "",
                "certainty": data.get("certainty") or "",
                "alert_kind": data.get("alert_kind") or "",
                "area_desc": data.get("area_desc") or "",
                "basin": data.get("basin") or "",
                "nhc_system": data.get("nhc_system") or "",
                "nhc_storm_id": data.get("nhc_storm_id") or "",
                "nhc_advisory_number": data.get("nhc_advisory_number") or "",
                "nhc_package_key": data.get("nhc_package_key") or "",
                "nhc_product_types": data.get("nhc_product_types") or [],
                "tsunami_identifier": data.get("tsunami_identifier") or "",
                "incident_id": data.get("incident_id") or "",
                "tsunami_category": data.get("tsunami_category") or "",
                "message_number": data.get("message_number") or "",
                "magnitude": data.get("magnitude"),
                "magnitude_type": data.get("magnitude_type") or "",
                "depth_km": data.get("depth_km"),
                "event_time": data.get("event_time") or "",
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "effective": data.get("effective") or "",
                "onset": data.get("onset") or "",
                "expires": data.get("expires") or "",
                "updated": data.get("updated") or "",
                "source": data.get("source") or "",
                "source_url": data.get("source_url") or "",
            },
        )

    def noaa_alert_key(self, event_type, data, event_id):
        """Return a stable NOAA alert key from feed source, area, and event."""
        return "noaa-hazard:{}".format(stable_noaa_event_key(data, event_type))

    def noaa_feed_source(self, event_type, data):
        """Return the NOAA-family feed source for alert display."""
        source = str((data or {}).get("source") or "").strip()
        if source:
            return source
        if event_type == "noaa_tsunami_alert" or (data or {}).get("alert_kind") == "tsunami":
            return "NOAA Tsunami"
        if event_type == "noaa_tropical_advisory" or (data or {}).get("alert_kind") == "tropical":
            return "NHC"
        if event_type == "noaa_weather_alert":
            return "NWS"
        return "NOAA"

    def noaa_matches_alert(self, data, rule):
        """Return True when NOAA data should become an alert."""
        severity = str((data or {}).get("severity") or "").lower()
        kind = str((data or {}).get("alert_kind") or "").lower()
        event = "{} {}".format(
            (data or {}).get("event") or "",
            (data or {}).get("headline") or "",
        )
        if kind == "tropical_outlook":
            return False
        if kind == "tsunami":
            return tsunami_is_alertworthy(data)
        if kind == "tropical":
            return True
        if severity in {"severe", "extreme"}:
            return True
        return pattern_match(event, rule.get("critical_events"))

    def noaa_is_critical(self, data, rule):
        """Return True when a NOAA alert should use the critical level."""
        severity = str((data or {}).get("severity") or "").lower()
        critical_severities = {
            str(item or "").lower()
            for item in rule.get("critical_severities") or []
        }
        event = "{} {}".format(
            (data or {}).get("event") or "",
            (data or {}).get("headline") or "",
        )
        return severity in critical_severities or pattern_match(
            event, rule.get("critical_events")
        )

    def process_usgs(self, event_type, data, timestamp, now, emit):
        """Return USGS earthquake alerts."""
        if event_type in ("collector_offline", "collector_retrying"):
            return self.collector_issue_alert("usgs", event_type, data, timestamp, now, emit)
        if event_type != "usgs_earthquake":
            return []
        rule = self.rule("usgs_earthquake")
        if not rule.get("enabled", True):
            return []
        data = clean_usgs_data(data)
        magnitude = self.to_number(data.get("magnitude"))
        distance = self.to_number(data.get("distance_km"))
        if magnitude is None:
            return []
        nearby_radius = float(rule.get("nearby_radius_km", 100))
        nearby = distance is not None and distance <= nearby_radius
        global_warning_mag = float(rule.get("warning_magnitude_global", 6.5))
        global_critical_mag = float(rule.get("critical_magnitude_global", 7.5))
        global_major = magnitude >= global_warning_mag
        alert_color = str(data.get("alert_color") or "").lower()
        critical = bool(data.get("tsunami")) or alert_color in {
            str(item or "").lower()
            for item in rule.get("critical_alert_colors") or []
        }
        if nearby and magnitude >= float(rule.get("critical_magnitude_nearby", 5.0)):
            critical = True
        if global_major and magnitude >= global_critical_mag:
            critical = True
        warning = critical or (
            nearby and magnitude >= float(rule.get("warning_magnitude_nearby", 4.0))
        ) or global_major
        if not warning:
            return []
        level = rule.get("critical_level", "critical") if critical else rule.get("level", "warning")
        place = data.get("place") or data.get("event_id") or "earthquake"
        summary = "USGS earthquake M{:.1f}: {}".format(magnitude, place)
        if global_major and not nearby:
            summary += "; global major earthquake"
        if distance is not None:
            summary += "; {:.1f} km from configured point".format(distance)
        if data.get("tsunami"):
            summary += "; tsunami flag"
        return self.emit_alert(
            "usgs_earthquake",
            "usgs-earthquake:{}".format(data.get("event_id") or place),
            level,
            "usgs",
            "USGS earthquake",
            place,
            summary,
            timestamp,
            now,
            emit,
            {
                "event_id": data.get("event_id") or "",
                "magnitude": magnitude,
                "place": place,
                "event_time": data.get("event_time") or "",
                "updated": data.get("updated") or "",
                "feed": data.get("feed") or "",
                "scope": data.get("scope") or "",
                "global_major": bool(data.get("global_major")) or global_major,
                "distance_km": distance,
                "depth_km": data.get("depth_km"),
                "alert_color": data.get("alert_color") or "",
                "tsunami": data.get("tsunami"),
                "detail_url": data.get("detail_url") or "",
            },
        )

    def process_swpc(self, event_type, data, timestamp, now, emit):
        """Return SWPC space-weather alerts."""
        if event_type in ("collector_offline", "collector_retrying"):
            return self.collector_issue_alert("swpc", event_type, data, timestamp, now, emit)
        if event_type != "swpc_event":
            return []
        rule = self.rule("swpc_space_weather")
        if not rule.get("enabled", True):
            return []
        data = clean_swpc_data(data)
        if not swpc_event_is_alert(data, rule):
            return []
        critical = swpc_event_is_critical(data, rule)
        level = rule.get("critical_level", "critical") if critical else rule.get("level", "warning")
        event_id = data.get("event_id") or data.get("summary") or "swpc"
        subject = data.get("xray_class") or data.get("scale_label") or data.get("event") or "SWPC"
        summary = self.swpc_alert_summary(data)
        return self.emit_alert(
            "swpc_space_weather",
            "swpc:{}:{}".format(data.get("event_kind") or "event", event_id),
            level,
            "swpc",
            "SWPC space-weather event",
            subject,
            summary,
            timestamp,
            now,
            emit,
            {
                "event_id": event_id,
                "event_kind": data.get("event_kind") or "",
                "event": data.get("event") or "",
                "summary": data.get("summary") or "",
                "scale_family": data.get("scale_family") or "",
                "scale_value": data.get("scale_value"),
                "scale_label": data.get("scale_label") or "",
                "kp_index": data.get("kp_index"),
                "xray_class": data.get("xray_class") or "",
                "event_time": data.get("event_time") or "",
                "peak_time": data.get("peak_time") or "",
                "source": data.get("source") or "",
                "source_url": data.get("source_url") or "",
            },
        )

    def swpc_alert_summary(self, data):
        """Return compact SWPC alert summary."""
        parts = [
            data.get("event") or "SWPC event",
            data.get("summary") or "",
            data.get("xray_class") or "",
            data.get("scale_label") or "",
        ]
        kp = number_or_none(data.get("kp_index"))
        if kp is not None:
            parts.append("Kp {:.1f}".format(kp))
        if data.get("event_time"):
            parts.append("event {}".format(data.get("event_time")))
        return "; ".join(str(part) for part in parts if part)

    def process_lan(self, event_type, data, timestamp, now, emit):
        """Return LAN alerts."""
        if event_type in ("collector_offline", "collector_retrying"):
            return self.collector_issue_alert("lan", event_type, data, timestamp, now, emit)
        data = clean_lan_data(data)
        if event_type == "lan_gateway_changed":
            return self.lan_gateway_alert(data, timestamp, now, emit)
        if event_type == "lan_device_seen":
            return self.lan_new_device_alert(data, timestamp, now, emit)
        return []

    def lan_gateway_alert(self, data, timestamp, now, emit):
        """Return alert for default gateway changes."""
        rule = self.rule("lan_gateway_change")
        if not rule.get("enabled", True):
            return []
        subject = data.get("gateway_ip") or data.get("interface") or "gateway"
        summary = "LAN default gateway changed: {}".format(
            "; ".join(
                str(part)
                for part in (
                    data.get("family") or "",
                    data.get("gateway_ip") or "",
                    data.get("interface") or "",
                    data.get("mac") or "",
                    data.get("vendor_name") or "",
                )
                if part
            )
        )
        return self.emit_alert(
            "lan_gateway_change",
            "lan-gateway:{}".format(data.get("subject_key") or subject),
            rule.get("level", "warning"),
            "lan",
            "LAN default gateway changed",
            subject,
            summary,
            timestamp,
            now,
            emit,
            {
                "gateway_ip": data.get("gateway_ip") or "",
                "family": data.get("family") or "",
                "interface": data.get("interface") or "",
                "mac": data.get("mac") or "",
                "vendor_name": data.get("vendor_name") or "",
            },
        )

    def lan_new_device_alert(self, data, timestamp, now, emit):
        """Return optional alert for newly observed LAN devices."""
        rule = self.rule("lan_new_device")
        if not rule.get("enabled", False):
            return []
        subject = data.get("hostname") or data.get("mac") or data.get("ip") or "LAN device"
        summary = "New LAN device observed: {}".format(
            "; ".join(
                str(part)
                for part in (
                    data.get("hostname") or "",
                    data.get("mac") or "",
                    ", ".join(data.get("ips") or []),
                    data.get("vendor_name") or "",
                )
                if part
            )
        )
        return self.emit_alert(
            "lan_new_device",
            "lan-device:{}".format(data.get("subject_key") or subject),
            rule.get("level", "warning"),
            "lan",
            "New LAN device",
            subject,
            summary,
            timestamp,
            now,
            emit,
            {
                "subject_key": data.get("subject_key") or "",
                "mac": data.get("mac") or "",
                "ips": data.get("ips") or [],
                "hostname": data.get("hostname") or "",
                "vendor_name": data.get("vendor_name") or "",
            },
        )

    def process_adsb(self, event_type, data, timestamp, now, emit):
        """Return ADS-B alerts for emergency or low nearby aircraft."""
        if event_type == "collector_offline" or event_type == "collector_retrying":
            return self.collector_issue_alert("adsb", event_type, data, timestamp, now, emit)
        if event_type != "adsb_aircraft":
            return []
        rule = self.rule("adsb_aircraft")
        if not rule.get("enabled", True):
            return []
        icao = str(data.get("icao") or "").upper()
        if not icao:
            return []
        callsign = str(data.get("callsign") or "").strip()
        subject = "{} {}".format(callsign, icao).strip()
        alerts = []
        if data.get("emergency"):
            alerts.append(
                self.emit_alert(
                    "adsb_aircraft",
                    "adsb:emergency:{}".format(icao),
                    rule.get("critical_level", "critical"),
                    "adsb",
                    "ADS-B emergency aircraft",
                    subject,
                    self.adsb_alert_summary(data),
                    timestamp,
                    now,
                    emit,
                    self.adsb_alert_details(data),
                )
            )
        altitude = number_or_none(data.get("altitude_ft"))
        distance = number_or_none(data.get("distance_km"))
        low_altitude = number_or_none(rule.get("low_altitude_ft"))
        nearby = number_or_none(rule.get("nearby_radius_km"))
        if (
            altitude is not None
            and distance is not None
            and low_altitude is not None
            and nearby is not None
            and altitude <= low_altitude
            and distance <= nearby
        ):
            alerts.append(
                self.emit_alert(
                    "adsb_aircraft",
                    "adsb:low-nearby:{}".format(icao),
                    rule.get("level", "warning"),
                    "adsb",
                    "Low nearby aircraft",
                    subject,
                    self.adsb_alert_summary(data),
                    timestamp,
                    now,
                    emit,
                    self.adsb_alert_details(data),
                )
            )
        return [alert for alert in alerts if alert]

    def process_rtl433(self, event_type, data, timestamp, now, emit):
        """Return optional rtl_433 alerts for configured decoded signals."""
        if event_type == "collector_offline" or event_type == "collector_retrying":
            return self.collector_issue_alert("rtl433", event_type, data, timestamp, now, emit)
        if event_type != "rtl433_event":
            return []
        rule = self.rule("rtl433_signal")
        if not rule.get("enabled", False):
            return []
        data = clean_rtl433_data(data)
        category = str(data.get("category") or "").lower()
        categories = {
            str(item or "").strip().lower()
            for item in rule.get("categories") or []
            if str(item or "").strip()
        }
        protocol = str(data.get("protocol") or "")
        protocols = {str(item or "").strip() for item in rule.get("protocols") or []}
        matched = (
            (categories and category in categories)
            or (protocols and protocol in protocols)
            or pattern_match(data.get("model"), rule.get("model_patterns"))
        )
        if not matched:
            return []
        subject = " ".join(
            part
            for part in (
                data.get("model") or "",
                data.get("id") or "",
                data.get("channel") or "",
            )
            if part
        ).strip() or "RTL-433 device"
        alert = self.emit_alert(
            "rtl433_signal",
            "rtl433:{}:{}".format(category or "device", data.get("subject_key") or subject),
            rule.get("level", "warning"),
            "rtl433",
            "RTL-433 decoded signal",
            subject,
            "{} event decoded by rtl_433.".format(category or "device"),
            timestamp,
            now,
            emit,
            {
                "model": data.get("model") or "",
                "id": data.get("id") or "",
                "channel": data.get("channel") or "",
                "protocol": data.get("protocol") or "",
                "category": category,
                "frequency_mhz": data.get("frequency_mhz") or "",
                "rssi_db": data.get("rssi_db") or "",
                "snr_db": data.get("snr_db") or "",
            },
        )
        return [alert] if alert else []

    def adsb_alert_summary(self, data):
        """Return compact ADS-B alert text."""
        parts = []
        if data.get("callsign"):
            parts.append(data.get("callsign"))
        if data.get("icao"):
            parts.append(data.get("icao"))
        if data.get("squawk"):
            parts.append("squawk {}".format(data.get("squawk")))
        if data.get("altitude_ft") not in (None, ""):
            parts.append("alt {} ft".format(data.get("altitude_ft")))
        if data.get("distance_km") not in (None, ""):
            parts.append("{:.1f} km away".format(float(data.get("distance_km"))))
        if data.get("ground_speed_kt") not in (None, ""):
            parts.append("{} kt".format(data.get("ground_speed_kt")))
        return "; ".join(str(part) for part in parts if part) or "ADS-B aircraft event"

    def adsb_alert_details(self, data):
        """Return structured ADS-B alert details."""
        return {
            "icao": data.get("icao") or "",
            "callsign": data.get("callsign") or "",
            "squawk": data.get("squawk") or "",
            "altitude_ft": data.get("altitude_ft"),
            "distance_km": data.get("distance_km"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "ground_speed_kt": data.get("ground_speed_kt"),
            "track_deg": data.get("track_deg"),
            "vertical_rate_fpm": data.get("vertical_rate_fpm"),
            "emergency": bool(data.get("emergency")),
            "source": data.get("source") or "",
        }

    def process_system(self, event_type, data, timestamp, now, emit):
        """Return alerts from collector lifecycle status."""
        return []

    def collector_issue_alert(self, source, event_type, data, timestamp, now, emit):
        """Return an alert when a collector reports offline/retrying state."""
        rule = self.rule("collector_issue")
        if not rule.get("enabled", True):
            return []
        name = data.get("name") or data.get("key") or source
        state = str(data.get("state") or event_type).replace("collector_", "")
        reason = data.get("warning") or data.get("reason") or "{} is {}".format(name, state)
        if pattern_match(reason, rule.get("ignored_reason_patterns")):
            return []
        return self.emit_alert(
            "collector_issue",
            "collector-issue:{}:{}".format(source, state),
            rule.get("level", "warning"),
            source,
            "Collector {}".format(state),
            name,
            reason,
            timestamp,
            now,
            emit,
            {
                "collector": source,
                "state": state.upper(),
                "reason": reason,
            },
        )

    def emit_alert(
        self,
        alert_type,
        key,
        level,
        source,
        title,
        subject,
        summary,
        timestamp,
        now,
        emit,
        evidence=None,
    ):
        """Create or update one active alert and return an event when due."""
        level = normalized_level(level)
        key = normalized_key(key)
        key = self.collapse_equivalent_active_alert(key, alert_type)
        previous = self.active.get(key)
        remembered_ack = self.ack_memory.get(key)
        should_emit = bool(emit)
        emit_reason = "new"
        if previous:
            emit_reason = "repeat"
            previous["source"] = source
            previous["title"] = title
            previous["subject"] = subject
            previous["last_seen"] = timestamp
            previous["last_seen_epoch"] = now
            previous["summary"] = summary
            previous["evidence"] = clean_evidence(evidence or {})
            if LEVEL_PRIORITY[level] > LEVEL_PRIORITY.get(previous.get("level"), 0):
                previous["level"] = level
                previous["acked"] = False
                previous.pop("acked_at", None)
                previous.pop("acked_at_epoch", None)
                previous.pop("ack_key_version", None)
                self.ack_memory.pop(key, None)
                should_emit = bool(emit)
                emit_reason = "escalated"
            elif previous.get("acked"):
                self.remember_ack(previous, now)
                should_emit = False
            elif now - float(previous.get("last_emitted_epoch") or 0) < self.dedupe_sec:
                should_emit = False
            if should_emit:
                previous["count"] = int(previous.get("count") or 0) + 1
            alert = previous
        else:
            self._counter += 1
            acked = bool(
                remembered_ack
                and self.ack_memory_enabled(alert_type)
                and LEVEL_PRIORITY[level]
                <= LEVEL_PRIORITY.get(remembered_ack.get("level"), 0)
            )
            alert = {
                "id": key,
                "sequence": self._counter,
                "alert_type": alert_type,
                "level": level,
                "source": source,
                "title": title,
                "subject": subject,
                "summary": summary,
                "first_seen": timestamp,
                "first_seen_epoch": now,
                "last_seen": timestamp,
                "last_seen_epoch": now,
                "last_emitted_epoch": 0,
                "acked": acked,
                "count": 1,
                "evidence": clean_evidence(evidence or {}),
            }
            if acked:
                alert["acked_at_epoch"] = remembered_ack.get("acked_at_epoch")
                alert["acked_at"] = remembered_ack.get("acked_at")
                alert["ack_key_version"] = remembered_ack.get(
                    "ack_key_version", ACK_KEY_VERSION
                )
                should_emit = False
            elif remembered_ack:
                self.ack_memory.pop(key, None)
            self.active[key] = alert
        self.dirty = True
        if not should_emit:
            return []
        alert["last_emitted_epoch"] = now
        public = public_alert(alert)
        self.recent.appendleft(public)
        return [alert_event(public, emit_reason)]

    def canonical_alert_key(self, alert, fallback):
        """Return current canonical ID for a persisted alert."""
        alert = alert or {}
        if alert.get("alert_type") != "noaa_hazard":
            return normalized_key(fallback)
        evidence = dict(alert.get("evidence") or {})
        if evidence.get("alert_kind") == "tsunami":
            event_type = "noaa_tsunami_alert"
        elif evidence.get("source") == "NHC" or evidence.get("alert_kind") == "tropical":
            event_type = "noaa_tropical_advisory"
        else:
            event_type = "noaa_weather_alert"
        data = {
            "source": evidence.get("source") or "",
            "event": evidence.get("event") or alert.get("subject") or "",
            "headline": evidence.get("headline") or alert.get("subject") or "",
            "summary": alert.get("summary") or "",
            "area_desc": evidence.get("area_desc") or "",
            "incident_id": evidence.get("incident_id") or "",
            "tsunami_identifier": evidence.get("tsunami_identifier") or "",
            "basin": evidence.get("basin")
            or canonical_nhc_basin(evidence.get("area_desc")),
            "nhc_package_key": evidence.get("nhc_package_key") or "",
            "alert_kind": evidence.get("alert_kind") or "",
            "event_id": evidence.get("event_id") or "",
        }
        return normalized_key("noaa-hazard:{}".format(stable_noaa_event_key(data, event_type)))

    def is_nhc_noaa_alert(self, alert):
        """Return True when a persisted alert came from an NHC NOAA item."""
        if (alert or {}).get("alert_type") != "noaa_hazard":
            return False
        evidence = dict((alert or {}).get("evidence") or {})
        return evidence.get("source") == "NHC" or evidence.get("alert_kind") == "tropical"

    def alert_source_disabled(self, alert):
        """Return True when a restored alert belongs to a disabled source."""
        if (alert or {}).get("alert_type") != "noaa_hazard":
            return False
        evidence = dict((alert or {}).get("evidence") or {})
        if evidence.get("alert_kind") == "tsunami":
            event_type = "noaa_tsunami_alert"
        elif self.is_nhc_noaa_alert(alert):
            event_type = "noaa_tropical_advisory"
        else:
            event_type = "noaa_weather_alert"
        data = {
            "source": evidence.get("source") or (alert or {}).get("source") or "",
            "event": evidence.get("event") or (alert or {}).get("subject") or "",
            "headline": evidence.get("headline") or (alert or {}).get("subject") or "",
            "area_desc": evidence.get("area_desc") or "",
            "incident_id": evidence.get("incident_id") or "",
            "tsunami_identifier": evidence.get("tsunami_identifier") or "",
            "basin": evidence.get("basin") or "",
            "alert_kind": evidence.get("alert_kind") or "",
        }
        return self.noaa_source_disabled(event_type, data)

    def noaa_source_disabled(self, event_type, data):
        """Return True when a NOAA event comes from a disabled NOAA subfeed."""
        disabled = self.disabled_noaa_sources
        if not disabled:
            return False
        if "noaa" in disabled:
            return True
        data = data or {}
        source = str(data.get("source") or "").strip().lower()
        alert_kind = str(data.get("alert_kind") or "").strip().lower()
        basin = str(data.get("basin") or "").strip()
        is_nhc = (
            source == "nhc"
            or event_type == "noaa_tropical_advisory"
            or alert_kind in ("tropical", "tropical_outlook")
            or bool(basin)
        )
        is_tsunami = (
            source in ("ntwc", "ptwc", "noaa tsunami")
            or event_type == "noaa_tsunami_alert"
            or alert_kind == "tsunami"
        )
        is_nws = source == "nws" or event_type == "noaa_weather_alert"
        return (
            ("nhc" in disabled and is_nhc)
            or ("nws" in disabled and is_nws)
            or ("tsunami" in disabled and is_tsunami)
        )

    def collapse_equivalent_active_alert(self, key, alert_type):
        """Collapse old persisted IDs that now map to this canonical key."""
        if alert_type != "noaa_hazard":
            return key
        for active_key, active_alert in list(self.active.items()):
            if active_key == key:
                continue
            if (active_alert or {}).get("alert_type") != alert_type:
                continue
            if self.canonical_alert_key(active_alert, active_key) != key:
                continue
            old = self.active.pop(active_key)
            old["id"] = key
            if key in self.active:
                self.active[key] = self.merge_alert_records(self.active[key], old)
            else:
                self.active[key] = old
            self.dirty = True
        return key

    def merge_alert_records(self, current, incoming):
        """Merge duplicate active alerts without losing ACK state."""
        if not current:
            return incoming
        if not incoming:
            return current
        current = dict(current)
        incoming = dict(incoming)
        current_first = float(current.get("first_seen_epoch") or 0)
        incoming_first = float(incoming.get("first_seen_epoch") or 0)
        if incoming_first and (not current_first or incoming_first < current_first):
            current["first_seen"] = incoming.get("first_seen")
            current["first_seen_epoch"] = incoming.get("first_seen_epoch")
        current_last = float(current.get("last_seen_epoch") or 0)
        incoming_last = float(incoming.get("last_seen_epoch") or 0)
        if incoming_last >= current_last:
            for field in ("last_seen", "last_seen_epoch", "summary", "subject", "title", "evidence"):
                if incoming.get(field) not in (None, ""):
                    current[field] = incoming.get(field)
        if LEVEL_PRIORITY.get(incoming.get("level"), 0) > LEVEL_PRIORITY.get(current.get("level"), 0):
            current["level"] = incoming.get("level")
            current["acked"] = False
            current.pop("acked_at", None)
            current.pop("acked_at_epoch", None)
            current.pop("ack_key_version", None)
        elif incoming.get("acked"):
            current["acked"] = True
            if incoming.get("acked_at_epoch", 0) >= current.get("acked_at_epoch", 0):
                current["acked_at"] = incoming.get("acked_at")
                current["acked_at_epoch"] = incoming.get("acked_at_epoch")
                current["ack_key_version"] = incoming.get(
                    "ack_key_version", ACK_KEY_VERSION
                )
        current["count"] = max(int(current.get("count") or 1), int(incoming.get("count") or 1))
        return current

    def ack(self, alert_id):
        """Acknowledge one active alert and return its public state."""
        key = str(alert_id or "").strip()
        alert = self.active.get(key) or self.active.get(normalized_key(key))
        if not alert:
            return None
        epoch = now_epoch()
        alert["acked"] = True
        alert["acked_at_epoch"] = epoch
        alert["acked_at"] = local_now(epoch)
        alert["ack_key_version"] = ACK_KEY_VERSION
        self.remember_ack(alert, epoch)
        self.dirty = True
        return public_alert(alert)

    def ack_all(self):
        """Acknowledge every active alert and return the number changed."""
        epoch = now_epoch()
        changed = 0
        for alert in self.active.values():
            if alert.get("acked"):
                continue
            alert["acked"] = True
            alert["acked_at_epoch"] = epoch
            alert["acked_at"] = local_now(epoch)
            alert["ack_key_version"] = ACK_KEY_VERSION
            self.remember_ack(alert, epoch)
            changed += 1
        if changed:
            self.dirty = True
        return changed

    def expire(self, now):
        """Drop active alerts that have not been seen within the active TTL."""
        if self.active_ttl_sec <= 0:
            return
        cutoff = now - self.active_ttl_sec
        for key, alert in list(self.active.items()):
            if float(alert.get("last_seen_epoch") or 0) < cutoff:
                if alert.get("acked"):
                    self.remember_ack(alert, now)
                self.active.pop(key, None)
                self.dirty = True
        self.prune_ack_memory(now)

    def ack_memory_enabled(self, alert_type):
        """Return True when ACKs should suppress future re-alerts for this type."""
        return alert_type in self.ack_memory_alert_types

    def remember_ack(self, alert, now, memory=None):
        """Remember ACKs for long-running alert families such as NHC advisories."""
        if not self.ack_memory_enabled((alert or {}).get("alert_type")):
            return
        key = normalized_key((alert or {}).get("id"))
        if not key:
            return
        target = self.ack_memory if memory is None else memory
        acked_at_epoch = float((alert or {}).get("acked_at_epoch") or now or now_epoch())
        target[key] = {
            "alert_type": (alert or {}).get("alert_type") or "",
            "level": normalized_level((alert or {}).get("level")),
            "ack_key_version": ACK_KEY_VERSION,
            "acked_at_epoch": acked_at_epoch,
            "acked_at": (alert or {}).get("acked_at") or local_now(acked_at_epoch),
            "last_seen_epoch": float((alert or {}).get("last_seen_epoch") or now or acked_at_epoch),
        }

    def load_ack_memory(self, state, target, now):
        """Load persisted ACK memory entries."""
        if not isinstance(state, dict):
            return
        cutoff = now - self.ack_memory_ttl_sec if self.ack_memory_ttl_sec > 0 else None
        for key, item in state.items():
            if not isinstance(item, dict):
                continue
            normalized = normalized_key(key)
            if not normalized:
                continue
            if not self.ack_memory_enabled(item.get("alert_type")):
                continue
            if (
                item.get("alert_type") == "noaa_hazard"
                and int(float(item.get("ack_key_version") or 0)) < ACK_KEY_VERSION
            ):
                continue
            try:
                remembered = float(item.get("last_seen_epoch") or item.get("acked_at_epoch") or 0)
            except (TypeError, ValueError):
                remembered = 0
            if cutoff is not None and remembered and remembered < cutoff:
                continue
            target[normalized] = {
                "alert_type": item.get("alert_type") or "",
                "level": normalized_level(item.get("level")),
                "ack_key_version": int(float(item.get("ack_key_version") or ACK_KEY_VERSION)),
                "acked_at_epoch": float(item.get("acked_at_epoch") or remembered or now),
                "acked_at": item.get("acked_at") or "",
                "last_seen_epoch": remembered or now,
            }

    def prune_ack_memory(self, now):
        """Drop old ACK memory entries."""
        if self.ack_memory_ttl_sec <= 0:
            return
        cutoff = now - self.ack_memory_ttl_sec
        for key, item in list(self.ack_memory.items()):
            try:
                remembered = float(item.get("last_seen_epoch") or item.get("acked_at_epoch") or 0)
            except (TypeError, ValueError):
                remembered = 0
            if remembered and remembered < cutoff:
                self.ack_memory.pop(key, None)
                self.dirty = True

    def rule(self, name):
        """Return a named alert rule config."""
        return self.config.get(name) or {}

    def wifi_signal_summary(self, data):
        """Return AP signal/channel/security text for alert summaries."""
        parts = []
        if data.get("rssi") is not None:
            parts.append("{} dBm".format(data.get("rssi")))
        if data.get("channel") is not None:
            parts.append("channel {}".format(data.get("channel")))
        if data.get("encryption"):
            parts.append(str(data.get("encryption")))
        if data.get("vendor_name"):
            parts.append(str(data.get("vendor_name")))
        return "; ".join(parts) or "Wi-Fi AP"

    def ble_signal_summary(self, data):
        """Return BLE signal/manufacturer text for alert summaries."""
        parts = []
        if data.get("rssi") is not None:
            parts.append("{} dBm".format(data.get("rssi")))
        if data.get("manufacturer"):
            parts.append(str(data.get("manufacturer")))
        if data.get("service_uuids"):
            parts.append("services {}".format(", ".join(data.get("service_uuids") or [])))
        return "; ".join(parts) or "BLE advertisement"

    def to_number(self, value):
        """Return a float for numeric-looking values."""
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def to_int(self, value):
        """Return an int for numeric-looking values."""
        number = self.to_number(value)
        return int(number) if number is not None else 0


def merge_config(base, override):
    """Deep-merge alert config dictionaries."""
    output = {}
    for key, value in base.items():
        output[key] = value.copy() if isinstance(value, dict) else value
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(output.get(key), dict):
            merged = output[key].copy()
            merged.update(value)
            output[key] = merged
        else:
            output[key] = value
    return output


def alert_event(alert, emit_reason=None):
    """Wrap one alert for the normal Skannr event stream."""
    data = dict(alert or {})
    if emit_reason:
        data["emit_reason"] = emit_reason
    return {
        "collector": "alerts",
        "type": "alert",
        "severity": "error" if alert.get("level") == "critical" else "warning",
        "timestamp": alert.get("last_seen"),
        "timestamp_epoch": alert.get("last_seen_epoch"),
        "data": data,
    }


def public_alert(alert):
    """Return browser/persistence-safe alert fields."""
    return {
        key: value
        for key, value in (alert or {}).items()
        if key not in ("last_emitted_epoch", "ack_key_version")
    }


def clean_evidence(evidence):
    """Drop empty evidence fields while keeping false and zero."""
    return {
        key: value
        for key, value in (evidence or {}).items()
        if value not in (None, "", [])
    }


def normalized_level(level):
    """Return a supported alert level."""
    text = str(level or "warning").lower()
    return text if text in LEVEL_PRIORITY else "warning"


def normalized_key(value):
    """Return a compact stable key fragment."""
    return re.sub(r"[^a-z0-9_.:-]+", "-", str(value or "").strip().lower()).strip("-")


def canonical_nhc_basin(value):
    """Return an NHC basin config key for old persisted display labels."""
    text = re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()
    return {
        "atlantic": "atlantic",
        "eastern pacific": "eastern_pacific",
        "central pacific": "central_pacific",
    }.get(text, "")


def normalized_oui(value):
    """Normalize a MAC/OUI string to six uppercase hex digits."""
    compact = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))[:6]
    return compact.upper()


def pattern_match(value, patterns):
    """Return True when text matches any configured substring/glob pattern."""
    text = str(value or "").strip().lower()
    if not text:
        return False
    for pattern in patterns or []:
        candidate = str(pattern or "").strip().lower()
        if not candidate:
            continue
        if "*" in candidate or "?" in candidate:
            if fnmatch.fnmatch(text, candidate):
                return True
        elif candidate in text:
            return True
    return False


def wifi_is_open(encryption):
    """Return True for open/unencrypted AP labels."""
    if isinstance(encryption, list):
        text = " ".join(str(item or "") for item in encryption).lower()
    else:
        text = str(encryption or "").lower()
    return "open" in text and "wpa" not in text and "wep" not in text
