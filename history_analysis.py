import json
import os
from datetime import datetime

from bus import utc_now
from log_utils import utc_epoch


DEFAULT_ANALYSIS_CONFIG = {
    "new_device_window_sec": 3600,
    "strong_wifi_rssi": -50,
    "strong_ble_rssi": -55,
    "many_bssid_count": 2,
    "wifi_same_ap_bssid_prefix_bytes": 5,
    "wifi_same_ap_max_last_byte_span": 16,
    "many_probe_ssid_count": 5,
    "blank_probe_count": 10,
    "deauth_count": 5,
    "randomized_mac_count": 10,
    "ble_linger_sec": 3600,
    "ble_lost_count": 3,
    "ble_recurring_min_sessions": 3,
    "ble_recurring_window_min": 30,
    "recent_activity_window_sec": 1800,
    "wifi_short_lived_sec": 900,
    "sensitive_ssids": [],
}


class HistoryAnalyzer:
    """Deterministic analysis rules over the persisted Device History summary."""

    def __init__(self, config=None):
        self.config = DEFAULT_ANALYSIS_CONFIG.copy()
        self.config.update(config or {})
        self._counter = 0

    def analyze(self, history):
        """Return ranked observations with concrete evidence and no LLM step."""
        generated_at = utc_now()
        observations = []
        wifi = history.get("wifi") or {}
        ble = history.get("bluetooth") or history.get("ble") or {}
        aps = wifi.get("access_points") or []
        clients = wifi.get("clients") or []
        ble_devices = ble.get("devices") or []

        observations.extend(self.analyze_wifi_aps(aps, generated_at))
        observations.extend(self.analyze_wifi_clients(clients, generated_at))
        observations.extend(self.analyze_ble_devices(ble_devices, generated_at))
        observations.extend(self.analyze_population(clients, generated_at))

        observations.sort(key=lambda item: (self.severity_rank(item["severity"]), item.get("score", 0), item.get("timestamp", "")), reverse=True)
        return {
            "generated_at": generated_at,
            "history_generated_at": history.get("generated_at"),
            "observations": observations,
            "counts": {
                "total": len(observations),
                "warning": sum(1 for item in observations if item["severity"] == "warning"),
                "info": sum(1 for item in observations if item["severity"] == "info"),
            },
        }

    def analyze_wifi_aps(self, aps, timestamp):
        """Look for AP patterns such as multiple BSSIDs, weak crypto, and channel drift."""
        observations = []
        by_ssid = {}
        for ap in aps:
            ssid = ap.get("ssid") or "(blank)"
            by_ssid.setdefault(ssid, []).append(ap)
            encryptions = self.list_values(ap.get("encryption"))
            channels = self.list_values(ap.get("channels"))
            ssid_history = self.list_values(ap.get("ssids"))
            bssid = ap.get("bssid") or "unknown"
            source = self.wifi_source_for(ap)
            signal_max = self.to_number(ap.get("signal_max"))
            duration = self.duration_seconds(ap.get("first_seen"), ap.get("last_seen"))
            evidence = self.wifi_ap_evidence(ap, ssid, bssid)
            if self.has_weak_crypto(encryptions):
                observations.append(self.observation(
                    timestamp,
                    "warning",
                    source,
                    "weak_wifi_encryption",
                    "Weak or open Wi-Fi encryption",
                    "{} ({}) advertises {}".format(ssid, bssid, ", ".join(encryptions)),
                    self.with_extra_evidence(evidence, {"encryption": encryptions}),
                    70,
                ))
            if self.has_crypto_mismatch(encryptions):
                observations.append(self.observation(
                    timestamp,
                    "warning",
                    source,
                    "wifi_bssid_security_changed",
                    "BSSID encryption changed",
                    "{} ({}) has mixed encryption history: {}".format(ssid, bssid, ", ".join(encryptions)),
                    self.with_extra_evidence(evidence, {"encryption": encryptions}),
                    82,
                ))
            if len(ssid_history) > 1:
                observations.append(self.observation(
                    timestamp,
                    "warning",
                    source,
                    "wifi_bssid_ssid_changed",
                    "BSSID advertised multiple SSIDs",
                    "{} has advertised SSIDs: {}".format(bssid, ", ".join(ssid_history)),
                    self.with_extra_evidence(evidence, {"ssids": ssid_history, "current_ssid": ssid}),
                    68,
                ))
            if len(channels) > 1:
                observations.append(self.observation(
                    timestamp,
                    "info",
                    source,
                    "wifi_bssid_channel_change",
                    "BSSID seen on multiple channels",
                    "{} ({}) was seen on channels {}".format(ssid, bssid, ", ".join(channels)),
                    self.with_extra_evidence(evidence, {"channels": channels}),
                    30 + min(len(channels), 5),
                ))
            if self.is_new(ap, timestamp) and signal_max is not None and signal_max >= float(self.config["strong_wifi_rssi"]):
                observations.append(self.observation(
                    timestamp,
                    "warning",
                    source,
                    "new_strong_wifi_ap",
                    "New strong Wi-Fi access point",
                    "{} ({}) first seen recently with max RSSI {} dBm".format(ssid, bssid, ap.get("signal_max")),
                    self.with_extra_evidence(evidence, {"signal_max": ap.get("signal_max"), "first_seen": ap.get("first_seen")}),
                    65,
                ))
            if self.is_new(ap, timestamp) and signal_max is not None and signal_max >= float(self.config["strong_wifi_rssi"]) and 0 < duration <= float(self.config["wifi_short_lived_sec"]):
                observations.append(self.observation(
                    timestamp,
                    "warning",
                    source,
                    "wifi_short_lived_strong_ap",
                    "Short-lived strong Wi-Fi access point",
                    "{} ({}) was strong and visible for about {} minutes".format(ssid, bssid, max(1, int(duration / 60))),
                    self.with_extra_evidence(evidence, {"signal_max": signal_max, "duration_sec": duration}),
                    72,
                ))

        for ssid, ssid_aps in by_ssid.items():
            if ssid == "(blank)" or len(ssid_aps) < int(self.config["many_bssid_count"]):
                continue
            bssids = [ap.get("bssid") for ap in ssid_aps if ap.get("bssid")]
            encryptions = sorted(set(value for ap in ssid_aps for value in self.list_values(ap.get("encryption"))))
            channels = sorted(set(value for ap in ssid_aps for value in self.list_values(ap.get("channels"))))
            new_aps = [ap for ap in ssid_aps if self.is_new(ap, timestamp)]
            strong_new_aps = [ap for ap in new_aps if self.to_number(ap.get("signal_max")) is not None and self.to_number(ap.get("signal_max")) >= float(self.config["strong_wifi_rssi"])]
            vendor_ouis = sorted(set(value for ap in ssid_aps for value in self.list_values(ap.get("vendor_oui"))))
            vendor_prefixes = sorted(set(value for ap in ssid_aps for value in self.list_values(ap.get("vendor_prefix"))))
            vendor_names = sorted(set(value for ap in ssid_aps for value in self.list_values(ap.get("vendor_name"))))
            same_ap_family = self.same_ap_bssid_family(bssids)
            same_vendor_sibling_pairs = self.same_vendor_sibling_bssid_pairs(bssids)
            vendor_mismatch = self.vendor_mismatch(vendor_ouis, vendor_prefixes, vendor_names)
            crypto_mismatch = self.has_crypto_mismatch(encryptions)
            # Dual-band APs and mesh nodes commonly expose one SSID through
            # several neighboring BSSIDs. Multi-AP systems can have multiple
            # base radios, where each base radio still has adjacent 2.4/5 GHz
            # BSSIDs. Treat those as normal unless security or vendor drifts.
            likely_normal_multiband = (same_ap_family or same_vendor_sibling_pairs) and not crypto_mismatch and not vendor_mismatch
            severity = "warning" if crypto_mismatch or vendor_mismatch or (strong_new_aps and not likely_normal_multiband) else "info"
            title = "Possible evil twin candidate" if severity == "warning" else "SSID seen on multiple BSSIDs"
            source = "wifi_monitor" if any("wifi_monitor" in self.list_values(ap.get("sources")) for ap in ssid_aps) else "wifi"
            observations.append(self.observation(
                timestamp,
                severity,
                source,
                "wifi_ssid_multiple_bssids",
                title,
                "SSID '{}' has {} BSSIDs; encryption={}, channels={}, new={}, strong_new={}".format(ssid, len(bssids), ", ".join(encryptions) or "unknown", ", ".join(channels) or "unknown", len(new_aps), len(strong_new_aps)),
                {"ssid": ssid, "bssids": bssids, "encryption": encryptions, "channels": channels, "vendor_ouis": vendor_ouis, "vendor_prefixes": vendor_prefixes, "vendor_names": vendor_names, "new_bssids": [ap.get("bssid") for ap in new_aps], "strong_new_bssids": [ap.get("bssid") for ap in strong_new_aps], "same_ap_bssid_family": same_ap_family, "same_vendor_sibling_bssid_pairs": same_vendor_sibling_pairs, "vendor_mismatch": vendor_mismatch},
                88 if severity == "warning" and strong_new_aps else (80 if severity == "warning" else 45),
            ))
        return observations

    def analyze_wifi_clients(self, clients, timestamp):
        """Look for probe behavior that reveals unusual client activity."""
        observations = []
        for client in clients:
            mac = client.get("mac") or "unknown"
            ssids = self.list_values(client.get("ssids"))
            source = self.wifi_source_for(client)
            evidence = self.wifi_client_evidence(client, mac)
            if len(ssids) >= int(self.config["many_probe_ssid_count"]):
                observations.append(self.observation(
                    timestamp,
                    "warning",
                    source,
                    "wifi_client_many_probed_ssids",
                    "Wi-Fi client probed many SSIDs",
                    "{} probed {} SSIDs".format(mac, len(ssids)),
                    self.with_extra_evidence(evidence, {"ssids": ssids[:25], "ssid_count": len(ssids)}),
                    70 + min(len(ssids), 20),
                ))
            sensitive = sorted(set(ssids) & set(self.config.get("sensitive_ssids") or []))
            if sensitive:
                observations.append(self.observation(
                    timestamp,
                    "warning",
                    source,
                    "wifi_client_sensitive_ssid_probe",
                    "Wi-Fi client probed watched SSID",
                    "{} probed watched SSID(s): {}".format(mac, ", ".join(sensitive)),
                    self.with_extra_evidence(evidence, {"ssids": sensitive}),
                    85,
                ))
            if int(client.get("blank_ssid_count") or 0) >= int(self.config["blank_probe_count"]):
                observations.append(self.observation(
                    timestamp,
                    "info",
                    source,
                    "wifi_client_blank_probe_repeated",
                    "Repeated blank Wi-Fi probes",
                    "{} sent {} blank probes".format(mac, client.get("blank_ssid_count")),
                    self.with_extra_evidence(evidence, {"blank_ssid_count": client.get("blank_ssid_count")}),
                    35,
                ))
            if int(client.get("deauth_count") or 0) >= int(self.config.get("deauth_count", 5)):
                observations.append(self.observation(
                    timestamp,
                    "warning",
                    source,
                    "wifi_client_deauth_activity",
                    "Repeated Wi-Fi deauth frames",
                    "{} was involved in {} deauth frames".format(mac, client.get("deauth_count")),
                    self.with_extra_evidence(evidence, {"deauth_count": client.get("deauth_count")}),
                    75,
                ))
        return observations

    def analyze_ble_devices(self, devices, timestamp):
        """Look for BLE devices that are strong, lingering, or repeatedly lost."""
        observations = []
        for device in devices:
            mac = device.get("mac") or "unknown"
            name = ", ".join(self.list_values(device.get("names"))) or mac
            evidence = self.ble_evidence(device, mac)
            transports = self.list_values(device.get("transports"))
            source = "bt_classic" if transports == ["classic"] else "ble"
            signal_max = self.to_number(device.get("signal_max"))
            if signal_max is not None and signal_max >= float(self.config["strong_ble_rssi"]):
                observations.append(self.observation(
                    timestamp,
                    "warning",
                    source,
                    "ble_device_strong",
                    "Strong nearby BLE device",
                    "{} max RSSI is {} dBm".format(name, signal_max),
                    self.with_extra_evidence(evidence, {"signal_max": signal_max}),
                    60,
                ))
            duration = self.duration_seconds(device.get("first_seen"), device.get("last_seen"))
            if duration >= float(self.config["ble_linger_sec"]):
                observations.append(self.observation(
                    timestamp,
                    "info",
                    source,
                    "ble_device_lingered",
                    "BLE device lingered nearby",
                    "{} was observed for at least {} minutes".format(name, int(duration / 60)),
                    self.with_extra_evidence(evidence, {"duration_sec": duration, "first_seen": device.get("first_seen"), "last_seen": device.get("last_seen")}),
                    40,
                ))
            if int(device.get("lost_count") or 0) >= int(self.config["ble_lost_count"]):
                observations.append(self.observation(
                    timestamp,
                    "info",
                    source,
                    "ble_device_repeated_loss",
                    "BLE device repeatedly disappeared",
                    "{} disappeared {} times".format(name, device.get("lost_count")),
                    self.with_extra_evidence(evidence, {"lost_count": device.get("lost_count")}),
                    35,
                ))
            pattern = self.ble_presence_pattern(device)
            if pattern:
                observations.append(self.observation(
                    timestamp,
                    "info",
                    source,
                    "ble_recurring_presence_pattern",
                    "Recurring BLE presence pattern",
                    "{} usually appears around {} and leaves around {}".format(name, pattern["arrival"], pattern["departure"]),
                    self.with_extra_evidence(evidence, pattern),
                    55 + min(pattern.get("session_count", 0), 20),
                ))
        return observations

    def analyze_population(self, clients, timestamp):
        """Look for population-level Wi-Fi patterns."""
        observations = []
        randomized = [client.get("mac") for client in clients if client.get("randomized_mac")]
        if len(randomized) >= int(self.config["randomized_mac_count"]):
            source = "wifi_monitor" if any("wifi_monitor" in self.list_values(client.get("sources")) for client in clients) else "wifi"
            observations.append(self.observation(
                timestamp,
                "warning",
                source,
                "wifi_randomized_mac_churn",
                "Many randomized Wi-Fi MACs observed",
                "{} locally administered client MACs are in device history".format(len(randomized)),
                {"mac_count": len(randomized), "sample": randomized[:25]},
                75,
            ))
        return observations

    def observation(self, timestamp, severity, source, obs_type, title, detail, evidence, score):
        """Build one normalized observation row."""
        self._counter += 1
        return {
            "id": "{}-{}".format(timestamp, self._counter),
            "timestamp": timestamp,
            "severity": severity,
            "source": source,
            "type": obs_type,
            "title": title,
            "detail": detail,
            "evidence": evidence,
            "score": score,
            **self.activity_metadata(obs_type, evidence, timestamp),
        }

    def wifi_ap_evidence(self, ap, ssid, bssid):
        """Return identity evidence common to Wi-Fi AP observations."""
        return {
            "ssid": ssid,
            "bssid": bssid,
            "vendor_oui": ap.get("vendor_oui") or "",
            "vendor_prefix": ap.get("vendor_prefix") or ap.get("vendor_oui") or "",
            "vendor_name": ap.get("vendor_name") or "",
            "first_seen": ap.get("first_seen") or "",
            "last_seen": ap.get("last_seen") or "",
        }

    def wifi_client_evidence(self, client, mac):
        """Return identity evidence common to Wi-Fi client observations."""
        return {
            "mac": mac,
            "vendor_oui": client.get("vendor_oui") or "",
            "vendor_prefix": client.get("vendor_prefix") or client.get("vendor_oui") or "",
            "vendor_name": client.get("vendor_name") or "",
            "first_seen": client.get("first_seen") or "",
            "last_seen": client.get("last_seen") or "",
        }

    def ble_evidence(self, device, mac):
        """Return identity evidence common to BLE observations."""
        return {
            "mac": mac,
            "names": self.list_values(device.get("names")),
            "manufacturer": device.get("manufacturer") or "",
            "manufacturer_name": device.get("manufacturer_name") or "",
            "vendor_prefix": device.get("vendor_prefix") or "",
            "vendor_name": device.get("vendor_name") or "",
            "transports": self.list_values(device.get("transports")),
            "classic_class": device.get("classic_class") or "",
            "model_number": device.get("model_number") or "",
            "firmware_revision": device.get("firmware_revision") or "",
            "first_seen": device.get("first_seen") or "",
            "last_seen": device.get("last_seen") or "",
        }

    def with_extra_evidence(self, base, extra):
        """Merge identity evidence with rule-specific fields."""
        merged = dict(base or {})
        merged.update(extra or {})
        return merged

    def same_ap_bssid_family(self, bssids):
        """Return True for adjacent BSSIDs that look like one AP family.

        Consumer APs often derive per-band/per-radio BSSIDs by incrementing the
        final byte, so 2.4 GHz and 5 GHz radios can look like ...:18 and ...:19.
        This helper prevents that normal pattern from being called evil-twin by
        itself.
        """
        normalized = [self.normalized_mac(value) for value in bssids]
        normalized = [value for value in normalized if value]
        if len(normalized) < 2:
            return False

        prefix_bytes = int(self.config.get("wifi_same_ap_bssid_prefix_bytes", 5))
        prefix_len = max(1, min(prefix_bytes, 5)) * 2
        prefixes = set(value[:prefix_len] for value in normalized)
        if len(prefixes) != 1:
            return False

        last_bytes = [int(value[-2:], 16) for value in normalized]
        max_span = int(self.config.get("wifi_same_ap_max_last_byte_span", 16))
        return max(last_bytes) - min(last_bytes) <= max_span

    def same_vendor_sibling_bssid_pairs(self, bssids):
        """Return True when each BSSID has an adjacent same-OUI sibling.

        Mesh or multi-AP deployments often expose one SSID from several base
        radios. The base radios may not share the first five MAC bytes, but the
        2.4/5 GHz pair for each base radio commonly differs only in the last
        byte. That pattern is weak evidence for normal infrastructure, not an
        evil twin by itself.
        """
        normalized = sorted(value for value in (self.normalized_mac(item) for item in bssids) if value)
        if len(normalized) < 2:
            return False
        oui_values = set(value[:6] for value in normalized)
        if len(oui_values) != 1:
            return False

        max_span = int(self.config.get("wifi_same_ap_max_last_byte_span", 16))
        for value in normalized:
            prefix = value[:-2]
            last = int(value[-2:], 16)
            has_sibling = False
            for other in normalized:
                if other == value or other[:-2] != prefix:
                    continue
                if abs(int(other[-2:], 16) - last) <= max_span:
                    has_sibling = True
                    break
            if not has_sibling:
                return False
        return True

    def normalized_mac(self, value):
        """Return a compact lower-case MAC string or empty string."""
        compact = "".join(ch for ch in str(value or "") if ch.lower() in "0123456789abcdef")
        return compact.lower() if len(compact) == 12 else ""

    def vendor_mismatch(self, vendor_ouis, vendor_prefixes, vendor_names):
        """Detect vendor drift while preferring resolved vendor names.

        A single manufacturer can own many OUI blocks. If every BSSID resolves
        to the same vendor name, different OUI prefixes alone should not turn a
        normal multi-AP network into an evil-twin warning.
        """
        oui_values = self.vendor_value_set(vendor_ouis)
        prefix_values = self.vendor_value_set(vendor_prefixes)
        name_values = self.vendor_value_set(vendor_names)
        if len(name_values) == 1:
            return False
        if len(name_values) > 1:
            return True
        return len(oui_values) > 1 or len(prefix_values) > 1 or len(name_values) > 1

    def vendor_value_set(self, values):
        """Normalize vendor evidence while ignoring unknown placeholders."""
        cleaned = set()
        for value in self.list_values(values):
            text = str(value or "").strip().lower()
            if text and text not in ("unknown", "locally administered / randomized"):
                cleaned.add(text)
        return cleaned

    def activity_metadata(self, obs_type, evidence, timestamp):
        """Attach coarse activity state used by the Insights default view."""
        if "recurring" in str(obs_type or ""):
            return {"activity_state": "recurring", "last_seen": (evidence or {}).get("last_seen"), "age_minutes": None}
        last_seen = (evidence or {}).get("last_seen")
        age = self.age_minutes(last_seen, timestamp)
        if age is None:
            return {"activity_state": "unknown", "last_seen": last_seen, "age_minutes": None}
        state = "recent" if age <= (float(self.config.get("recent_activity_window_sec", 1800)) / 60.0) else "stale"
        return {"activity_state": state, "last_seen": last_seen, "age_minutes": int(age)}

    def age_minutes(self, seen_at, timestamp):
        """Return age in minutes between last_seen and analysis timestamp."""
        seen = self.to_epoch(seen_at)
        now = self.to_epoch(timestamp)
        if seen is None or now is None or now < seen:
            return None
        return (now - seen) / 60.0

    def wifi_source_for(self, record):
        """Attribute Wi-Fi observations to monitor capture when relevant."""
        sources = self.list_values((record or {}).get("sources"))
        return "wifi_monitor" if "wifi_monitor" in sources else "wifi"

    def ble_presence_pattern(self, device):
        """Return a coarse recurring arrival/departure pattern for BLE sessions."""
        sessions = [session for session in (device.get("sessions") or []) if session.get("start") and session.get("end")]
        min_sessions = int(self.config.get("ble_recurring_min_sessions", 3))
        if len(sessions) < min_sessions:
            return None
        starts = [self.minute_of_day(session.get("start")) for session in sessions]
        ends = [self.minute_of_day(session.get("end")) for session in sessions]
        starts = [value for value in starts if value is not None]
        ends = [value for value in ends if value is not None]
        if len(starts) < min_sessions or len(ends) < min_sessions:
            return None
        window = int(self.config.get("ble_recurring_window_min", 30))
        start_center, start_count = self.cluster_minutes(starts, window)
        end_center, end_count = self.cluster_minutes(ends, window)
        if start_count < min_sessions or end_count < min_sessions:
            return None
        durations = [self.to_number(session.get("duration_sec")) for session in sessions]
        durations = [value for value in durations if value is not None and value > 0]
        return {
            "arrival": self.format_minute(start_center),
            "departure": self.format_minute(end_center),
            "arrival_matches": start_count,
            "departure_matches": end_count,
            "session_count": len(sessions),
            "typical_duration_min": int((sum(durations) / len(durations)) / 60) if durations else 0,
        }

    def minute_of_day(self, timestamp):
        """Convert a timestamp into local minute-of-day for pattern grouping."""
        for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                parsed = datetime.strptime(str(timestamp), pattern)
                return parsed.hour * 60 + parsed.minute
            except ValueError:
                pass
        return None

    def cluster_minutes(self, values, window):
        """Find the densest time-of-day cluster within a +/- window."""
        if not values:
            return None, 0
        best_center = values[0]
        best_matches = []
        for center in values:
            matches = [value for value in values if self.circular_minute_distance(center, value) <= window]
            if len(matches) > len(best_matches):
                best_center = center
                best_matches = matches
        if not best_matches:
            return best_center, 0
        return int(sum(best_matches) / len(best_matches)), len(best_matches)

    def circular_minute_distance(self, left, right):
        """Return distance between two minutes on a 24-hour clock."""
        distance = abs(left - right)
        return min(distance, 1440 - distance)

    def format_minute(self, minute):
        """Format minute-of-day as HH:MM."""
        if minute is None:
            return "unknown"
        minute = int(minute) % 1440
        return "{:02d}:{:02d}".format(minute // 60, minute % 60)

    def has_weak_crypto(self, encryptions):
        """Treat open/WEP as weak, and legacy WPA as weaker than WPA2/WPA3."""
        lowered = [value.lower() for value in encryptions]
        return any(value in ("open", "wep", "wep/unknown", "wpa") for value in lowered)

    def has_crypto_mismatch(self, encryptions):
        """Flag SSIDs with both strong and weak/open encryption present."""
        lowered = [value.lower() for value in encryptions]
        has_strong = any("wpa2" in value or "wpa3" in value or "rsn" in value for value in lowered)
        return has_strong and self.has_weak_crypto(encryptions)

    def is_new(self, item, timestamp):
        """Return true when first_seen is within the configured recent window."""
        first_seen = self.to_epoch(item.get("first_seen"))
        now = self.to_epoch(timestamp)
        if first_seen is None or now is None:
            return False
        return now - first_seen <= float(self.config["new_device_window_sec"])

    def duration_seconds(self, first_seen, last_seen):
        """Return observed duration in seconds for Skannr timestamps."""
        first = self.to_epoch(first_seen)
        last = self.to_epoch(last_seen)
        if first is None or last is None or last < first:
            return 0
        return last - first

    def list_values(self, value):
        """Normalize a stored scalar/list into clean strings."""
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        text = str(value).strip()
        return [text] if text else []

    def to_number(self, value):
        """Parse numeric values from history fields."""
        if value is None or value == "":
            return None
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        return int(number) if number.is_integer() else number

    def to_epoch(self, timestamp):
        """Parse Skannr local or legacy UTC timestamps into epoch seconds."""
        return utc_epoch(timestamp)

    def severity_rank(self, severity):
        """Sort warnings above informational observations."""
        return {"warning": 2, "info": 1}.get(severity, 0)


def save_analysis(path, analysis):
    """Persist the latest analysis snapshot for offline inspection."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(analysis, fh, indent=2, sort_keys=True)
