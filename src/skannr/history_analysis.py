"""Deterministic insight rules over the materialized subject/device summary.

This is the short-horizon "what looks notable" layer. It uses explicit rules
and evidence fields so results are reproducible and can be inspected without an
LLM or a database.
"""

import logging
import time
from datetime import datetime

from .bus import local_now
from .identity_policy import bluetooth_property_like_name, locally_administered_mac
from .log_utils import now_epoch, record_time_epoch, save_json_atomic, timestamp_epoch

# Per-subject session-window cap for bundle correlation.  Pair scans are
# O(windows_a × windows_b) per cross-collector pair, so each subject keeps
# only its most recent windows; long retention (7-day session arrays) would
# otherwise make the 15-min derived refresh prohibitively slow on a Pi.
MAX_BUNDLE_WINDOWS_PER_SUBJECT = 50

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
    "ble_ignore_stale_single_seen_sec": 3600,
    "ble_population_min_count": 10,
    "ble_population_min_strong_count": 3,
    "recent_activity_window_sec": 1800,
    "rtl433_recent_min_events": 1,
    "bundle_correlation_enabled": True,
    "bundle_correlation_sync_margin_sec": 300,
    "bundle_correlation_min_cooccurrences": 3,
    "bundle_correlation_min_bundle_size": 2,
    "bundle_correlation_max_bundles": 10,
    "bundle_correlation_sources": ["ble", "wifi"],
    "bundle_correlation_min_sessions_per_device": 2,
    "bundle_correlation_max_subjects_per_source": 100,
    "bundle_correlation_max_window_span_sec": 3600,
    "wifi_short_lived_sec": 900,
    "sensitive_ssids": [],
}


class HistoryAnalyzer:
    """Deterministic analysis rules over the persisted subject/device summary."""

    def __init__(self, config=None):
        self.config = DEFAULT_ANALYSIS_CONFIG.copy()
        self.config.update(config or {})
        self._counter = 0
        self._generated_at_epoch = None

    def analyze(self, history, bundle_history=None):
        """Return ranked observations with concrete evidence and no LLM step.

        *bundle_history* is an optional second input for the bundle
        correlation rule.  When set it carries session arrays and a longer
        lookback window (multi-hour co-movement), while *history* stays the
        compact tactical input for the other rules.
        """
        generated_at_epoch = self.history_generated_epoch(history)
        self._generated_at_epoch = generated_at_epoch
        generated_at = local_now(generated_at_epoch)
        observations = []
        # Subject History's device view is the only input here. That keeps
        # analysis cheap after materialization and avoids another raw-log scan.
        wifi = history.get("wifi") or {}
        ble = history.get("bluetooth") or history.get("ble") or {}
        aps = wifi.get("access_points") or []
        clients = wifi.get("clients") or []
        ble_devices = ble.get("devices") or []

        observations.extend(self.analyze_wifi_aps(aps, generated_at))
        observations.extend(self.analyze_wifi_clients(clients, generated_at))
        observations.extend(self.analyze_ble_devices(ble_devices, generated_at))
        observations.extend(self.analyze_population(clients, generated_at))
        observations.extend(
            self.analyze_rtl433((history.get("rtl433") or []), generated_at)
        )
        if self.config.get("bundle_correlation_enabled", True):
            observations.extend(
                self.analyze_bundle_correlation(
                    bundle_history or history, generated_at
                )
            )

        # Show the most urgent/recent-looking rows first while preserving the
        # raw score as the secondary ordering inside each severity.
        observations.sort(
            key=lambda item: (
                self.severity_rank(item["severity"]),
                item.get("score", 0),
                item.get("timestamp_epoch") or 0,
            ),
            reverse=True,
        )
        return {
            "generated_at": generated_at,
            "generated_at_epoch": generated_at_epoch,
            "history_generated_at": history.get("generated_at"),
            "history_generated_at_epoch": history.get("generated_at_epoch"),
            "observations": observations,
            "counts": {
                "total": len(observations),
                "warning": sum(
                    1 for item in observations if item["severity"] == "warning"
                ),
                "info": sum(1 for item in observations if item["severity"] == "info"),
            },
        }

    def history_generated_epoch(self, history):
        """Use the subject/device snapshot time as the analysis freshness time."""
        try:
            value = float((history or {}).get("generated_at_epoch"))
        except (TypeError, ValueError):
            return now_epoch()
        return int(value) if value > 0 else now_epoch()

    def analyze_wifi_aps(self, aps, timestamp):
        """Look for AP patterns such as multiple BSSIDs, weak crypto, and channel drift."""
        observations = []
        by_ssid = {}
        for ap in aps:
            # Analyze each BSSID first. Grouped SSID analysis below handles
            # multi-radio/mesh/evil-twin patterns across BSSIDs.
            ssid = ap.get("ssid") or "(blank)"
            by_ssid.setdefault(ssid, []).append(ap)
            encryptions = self.list_values(ap.get("encryption"))
            channels = self.list_values(ap.get("channels"))
            ssid_history = self.list_values(ap.get("ssids"))
            bssid = ap.get("bssid") or "unknown"
            source = self.wifi_source_for(ap)
            signal_max = self.to_number(ap.get("signal_max"))
            duration = self.record_duration_seconds(ap)
            evidence = self.wifi_ap_evidence(ap, ssid, bssid)
            if self.has_weak_crypto(encryptions):
                # Open/WEP/legacy-WPA are actionable even if the AP is old.
                observations.append(
                    self.observation(
                        timestamp,
                        "warning",
                        source,
                        "weak_wifi_encryption",
                        "Weak or open Wi-Fi encryption",
                        "{} ({}) advertises {}".format(
                            ssid, bssid, ", ".join(encryptions)
                        ),
                        self.with_extra_evidence(evidence, {"encryption": encryptions}),
                        70,
                    )
                )
            if self.has_crypto_mismatch(encryptions):
                # A single BSSID moving between weak and strong security is more
                # suspicious than WPA2 versus WPA2/WPA3 parser detail.
                observations.append(
                    self.observation(
                        timestamp,
                        "warning",
                        source,
                        "wifi_bssid_security_changed",
                        "BSSID encryption changed",
                        "{} ({}) has mixed encryption history: {}".format(
                            ssid, bssid, ", ".join(encryptions)
                        ),
                        self.with_extra_evidence(evidence, {"encryption": encryptions}),
                        82,
                    )
                )
            if len(ssid_history) > 1:
                # BSSID-to-SSID changes are uncommon for normal home APs and can
                # indicate reconfiguration or spoofing.
                observations.append(
                    self.observation(
                        timestamp,
                        "warning",
                        source,
                        "wifi_bssid_ssid_changed",
                        "BSSID advertised multiple SSIDs",
                        "{} has advertised SSIDs: {}".format(
                            bssid, ", ".join(ssid_history)
                        ),
                        self.with_extra_evidence(
                            evidence,
                            {"ssids": ssid_history, "current_ssid": ssid},
                        ),
                        68,
                    )
                )
            if len(channels) > 1:
                # Channel changes are common enough to keep informational, but
                # they are useful context for troubleshooting and AP identity.
                observations.append(
                    self.observation(
                        timestamp,
                        "info",
                        source,
                        "wifi_bssid_channel_change",
                        "BSSID seen on multiple channels",
                        "{} ({}) was seen on channels {}".format(
                            ssid, bssid, ", ".join(channels)
                        ),
                        self.with_extra_evidence(evidence, {"channels": channels}),
                        30 + min(len(channels), 5),
                    )
                )
            if (
                self.is_new(ap, timestamp)
                and signal_max is not None
                and signal_max >= float(self.config["strong_wifi_rssi"])
            ):
                observations.append(
                    self.observation(
                        timestamp,
                        "warning",
                        source,
                        "new_strong_wifi_ap",
                        "New strong Wi-Fi access point",
                        "{} ({}) first seen recently with max RSSI {} dBm".format(
                            ssid, bssid, ap.get("signal_max")
                        ),
                        self.with_extra_evidence(
                            evidence,
                            {
                                "signal_max": ap.get("signal_max"),
                                "first_seen": ap.get("first_seen"),
                            },
                        ),
                        65,
                    )
                )
            if (
                self.is_new(ap, timestamp)
                and signal_max is not None
                and signal_max >= float(self.config["strong_wifi_rssi"])
                and 0 < duration <= float(self.config["wifi_short_lived_sec"])
            ):
                observations.append(
                    self.observation(
                        timestamp,
                        "warning",
                        source,
                        "wifi_short_lived_strong_ap",
                        "Short-lived strong Wi-Fi access point",
                        "{} ({}) was strong and visible for about {} minutes".format(
                            ssid, bssid, max(1, int(duration / 60))
                        ),
                        self.with_extra_evidence(
                            evidence,
                            {
                                "signal_max": signal_max,
                                "duration_sec": duration,
                            },
                        ),
                        72,
                    )
                )

        for ssid, ssid_aps in by_ssid.items():
            # SSID-level analysis is where false positives are easiest. Normal
            # routers often have one BSSID per band, and extenders/mesh nodes
            # add more. The warning path therefore requires stronger evidence
            # such as vendor mismatch, weak/strong crypto mismatch, or a strong
            # new BSSID that does not look like the same AP family.
            if ssid == "(blank)" or len(ssid_aps) < int(
                self.config["many_bssid_count"]
            ):
                continue
            bssids = [ap.get("bssid") for ap in ssid_aps if ap.get("bssid")]
            encryptions = sorted(
                set(
                    value
                    for ap in ssid_aps
                    for value in self.list_values(ap.get("encryption"))
                )
            )
            channels = sorted(
                set(
                    value
                    for ap in ssid_aps
                    for value in self.list_values(ap.get("channels"))
                )
            )
            new_aps = [ap for ap in ssid_aps if self.is_new(ap, timestamp)]
            strong_new_aps = [
                ap
                for ap in new_aps
                if self.to_number(ap.get("signal_max")) is not None
                and self.to_number(ap.get("signal_max"))
                >= float(self.config["strong_wifi_rssi"])
            ]
            vendor_ouis = sorted(
                set(
                    value
                    for ap in ssid_aps
                    for value in self.list_values(ap.get("vendor_oui"))
                )
            )
            vendor_prefixes = sorted(
                set(
                    value
                    for ap in ssid_aps
                    for value in self.list_values(ap.get("vendor_prefix"))
                )
            )
            vendor_names = sorted(
                set(
                    value
                    for ap in ssid_aps
                    for value in self.list_values(ap.get("vendor_name"))
                )
            )
            same_ap_family = self.same_ap_bssid_family(bssids)
            same_vendor_sibling_pairs = self.same_vendor_sibling_bssid_pairs(bssids)
            vendor_mismatch = self.vendor_mismatch(
                vendor_ouis, vendor_prefixes, vendor_names
            )
            crypto_mismatch = self.has_crypto_mismatch(encryptions)
            same_vendor_name = len(self.vendor_value_set(vendor_names)) == 1
            # Dual-band APs and mesh nodes commonly expose one SSID through
            # several neighboring BSSIDs. Multi-AP systems can have multiple
            # base radios, where each base radio still has adjacent 2.4/5 GHz
            # BSSIDs. Same-vendor, same-security sets are also common for
            # Apple/eero/mesh deployments even when OUI blocks differ.
            likely_normal_multiband = (
                (same_ap_family or same_vendor_sibling_pairs or same_vendor_name)
                and not crypto_mismatch
                and not vendor_mismatch
            )
            severity = (
                "warning"
                if crypto_mismatch
                or vendor_mismatch
                or (strong_new_aps and not likely_normal_multiband)
                else "info"
            )
            title = (
                "Possible evil twin candidate"
                if severity == "warning"
                else "SSID seen on multiple BSSIDs"
            )
            source = (
                "wifi_monitor"
                if any(
                    "wifi_monitor" in self.list_values(ap.get("sources"))
                    for ap in ssid_aps
                )
                else "wifi"
            )
            observations.append(
                self.observation(
                    timestamp,
                    severity,
                    source,
                    "wifi_ssid_multiple_bssids",
                    title,
                    "SSID '{}' has {} BSSIDs; encryption={}, channels={}, new={}, strong_new={}".format(
                        ssid,
                        len(bssids),
                        ", ".join(encryptions) or "unknown",
                        ", ".join(channels) or "unknown",
                        len(new_aps),
                        len(strong_new_aps),
                    ),
                    {
                        "ssid": ssid,
                        "bssids": bssids,
                        "encryption": encryptions,
                        "channels": channels,
                        "vendor_ouis": vendor_ouis,
                        "vendor_prefixes": vendor_prefixes,
                        "vendor_names": vendor_names,
                        "new_bssids": [ap.get("bssid") for ap in new_aps],
                        "strong_new_bssids": [ap.get("bssid") for ap in strong_new_aps],
                        "same_ap_bssid_family": same_ap_family,
                        "same_vendor_sibling_bssid_pairs": same_vendor_sibling_pairs,
                        "same_vendor_name": same_vendor_name,
                        "vendor_mismatch": vendor_mismatch,
                    },
                    (
                        88
                        if severity == "warning" and strong_new_aps
                        else (80 if severity == "warning" else 45)
                    ),
                )
            )
        return observations

    def analyze_wifi_clients(self, clients, timestamp):
        """Look for probe behavior that reveals unusual client activity."""
        observations = []
        for client in clients:
            # Wi-Fi clients only exist when monitor mode has observed management
            # frames. Managed AP scan cannot see probes or deauth/disassoc.
            mac = client.get("mac") or "unknown"
            ssids = self.list_values(client.get("ssids"))
            source = self.wifi_source_for(client)
            evidence = self.wifi_client_evidence(client, mac)
            if len(ssids) >= int(self.config["many_probe_ssid_count"]):
                observations.append(
                    self.observation(
                        timestamp,
                        "warning",
                        source,
                        "wifi_client_many_probed_ssids",
                        "Wi-Fi client probed many SSIDs",
                        "{} probed {} SSIDs".format(mac, len(ssids)),
                        self.with_extra_evidence(
                            evidence,
                            {"ssids": ssids[:25], "ssid_count": len(ssids)},
                        ),
                        70 + min(len(ssids), 20),
                    )
                )
            sensitive = sorted(
                set(ssids) & set(self.config.get("sensitive_ssids") or [])
            )
            if sensitive:
                # The watch list is user-defined in config/skannr.yaml; Skannr does not
                # ship with any sensitive SSIDs by default.
                observations.append(
                    self.observation(
                        timestamp,
                        "warning",
                        source,
                        "wifi_client_sensitive_ssid_probe",
                        "Wi-Fi client probed watched SSID",
                        "{} probed watched SSID(s): {}".format(
                            mac, ", ".join(sensitive)
                        ),
                        self.with_extra_evidence(evidence, {"ssids": sensitive}),
                        85,
                    )
                )
            if int(client.get("blank_ssid_count") or 0) >= int(
                self.config["blank_probe_count"]
            ):
                observations.append(
                    self.observation(
                        timestamp,
                        "info",
                        source,
                        "wifi_client_blank_probe_repeated",
                        "Repeated blank Wi-Fi probes",
                        "{} sent {} blank probes".format(
                            mac, client.get("blank_ssid_count")
                        ),
                        self.with_extra_evidence(
                            evidence,
                            {"blank_ssid_count": client.get("blank_ssid_count")},
                        ),
                        35,
                    )
                )
            if int(client.get("deauth_count") or 0) >= int(
                self.config.get("deauth_count", 5)
            ):
                observations.append(
                    self.observation(
                        timestamp,
                        "warning",
                        source,
                        "wifi_client_deauth_activity",
                        "Repeated Wi-Fi deauth frames",
                        "{} was involved in {} deauth frames".format(
                            mac, client.get("deauth_count")
                        ),
                        self.with_extra_evidence(
                            evidence,
                            {"deauth_count": client.get("deauth_count")},
                        ),
                        75,
                    )
                )
        return observations

    def analyze_ble_devices(self, devices, timestamp):
        """Look for recent BLE patterns without flooding on randomized MACs."""
        observations = []
        recent_devices = [
            device
            for device in devices
            if self.device_seen_within(
                device, float(self.config.get("recent_activity_window_sec", 1800))
            )
        ]
        population = self.ble_population_observation(recent_devices, timestamp)
        if population:
            observations.append(population)
        for device in devices:
            # Bluetooth history merges BLE, BLE Identify, and Classic transport
            # observations when they share an address.
            if self.low_value_stale_ble_device(device):
                continue
            recent = self.device_seen_within(
                device, float(self.config.get("recent_activity_window_sec", 1800))
            )
            worthy = self.ble_individual_insight_worthy(device)
            mac = device.get("mac") or "unknown"
            name = ", ".join(self.list_values(device.get("names"))) or mac
            evidence = self.ble_evidence(device, mac)
            transports = self.list_values(device.get("transports"))
            source = "bt_classic" if transports == ["classic"] else "ble"
            signal_max = self.to_number(device.get("signal_max"))
            if (
                recent
                and worthy
                and signal_max is not None
                and signal_max >= float(self.config["strong_ble_rssi"])
            ):
                observations.append(
                    self.observation(
                        timestamp,
                        "warning",
                        source,
                        "ble_device_strong",
                        "Strong nearby BLE device",
                        "{} max RSSI is {} dBm".format(name, signal_max),
                        self.with_extra_evidence(evidence, {"signal_max": signal_max}),
                        60,
                    )
                )
            duration = self.record_duration_seconds(device)
            if recent and worthy and duration >= float(self.config["ble_linger_sec"]):
                observations.append(
                    self.observation(
                        timestamp,
                        "info",
                        source,
                        "ble_device_lingered",
                        "BLE device lingered nearby",
                        "{} was observed for at least {} minutes".format(
                            name, int(duration / 60)
                        ),
                        self.with_extra_evidence(
                            evidence,
                            {
                                "duration_sec": duration,
                                "first_seen": device.get("first_seen"),
                                "last_seen": device.get("last_seen"),
                            },
                        ),
                        40,
                    )
                )
            if (
                recent
                and worthy
                and int(device.get("lost_count") or 0)
                >= int(self.config["ble_lost_count"])
            ):
                observations.append(
                    self.observation(
                        timestamp,
                        "info",
                        source,
                        "ble_device_repeated_loss",
                        "BLE device repeatedly disappeared",
                        "{} disappeared {} times".format(
                            name, device.get("lost_count")
                        ),
                        self.with_extra_evidence(
                            evidence, {"lost_count": device.get("lost_count")}
                        ),
                        35,
                    )
                )
            pattern = self.ble_presence_pattern(device)
            if pattern and worthy:
                # This is the deterministic "comes around at about the same
                # time" rule. It is based on closed sessions, not live sightings.
                observations.append(
                    self.observation(
                        timestamp,
                        "info",
                        source,
                        "ble_recurring_presence_pattern",
                        "Recurring BLE presence pattern",
                        "{} usually appears around {} and leaves around {}".format(
                            name, pattern["arrival"], pattern["departure"]
                        ),
                        self.with_extra_evidence(evidence, pattern),
                        55 + min(pattern.get("session_count", 0), 20),
                    )
                )
        return observations

    def ble_population_observation(self, devices, timestamp):
        """Return one recent BLE population Insight for anonymous/randomized churn."""
        if not devices:
            return None
        strong_threshold = float(self.config["strong_ble_rssi"])
        strong_devices = [
            device
            for device in devices
            if self.to_number(device.get("signal_max")) is not None
            and self.to_number(device.get("signal_max")) >= strong_threshold
        ]
        anonymous_devices = [
            device
            for device in devices
            if not self.ble_individual_insight_worthy(device)
        ]
        anonymous_strong = [
            device
            for device in strong_devices
            if not self.ble_individual_insight_worthy(device)
        ]
        min_count = int(self.config.get("ble_population_min_count", 10))
        min_strong = int(self.config.get("ble_population_min_strong_count", 3))
        if len(devices) < min_count and len(anonymous_strong) < min_strong:
            return None
        strongest = sorted(
            strong_devices,
            key=lambda item: self.to_number(item.get("signal_max")) or -999,
            reverse=True,
        )
        latest = self.latest_record(devices)
        latest_epoch = record_time_epoch(latest or {}, "last_seen")
        manufacturers = self.top_ble_manufacturers(devices, limit=5)
        strongest_signal = (
            self.to_number(strongest[0].get("signal_max")) if strongest else None
        )
        window_min = int(
            float(self.config.get("recent_activity_window_sec", 1800)) / 60
        )
        parts = [
            "{} BLE device(s) seen in the last {} min".format(len(devices), window_min),
            "{} anonymous/randomized".format(len(anonymous_devices)),
            "{} strong".format(len(strong_devices)),
        ]
        if strongest_signal is not None:
            parts.append("strongest {} dBm".format(strongest_signal))
        evidence = {
            "device_count": len(devices),
            "anonymous_count": len(anonymous_devices),
            "strong_count": len(strong_devices),
            "anonymous_strong_count": len(anonymous_strong),
            "manufacturers": manufacturers,
            "sample_macs": [
                device.get("mac") for device in strongest[:12] if device.get("mac")
            ],
            "signal_max": strongest_signal,
            "last_seen": (latest or {}).get("last_seen"),
            "last_seen_epoch": latest_epoch,
        }
        severity = (
            "warning"
            if len(anonymous_strong) >= min_strong
            or len(strong_devices) >= max(min_strong, 5)
            else "info"
        )
        return self.observation(
            timestamp,
            severity,
            "ble",
            "ble_population_activity",
            "Nearby BLE population",
            "; ".join(parts) + ".",
            evidence,
            55 + min(len(strong_devices), 25) + min(len(anonymous_devices), 15),
        )

    def top_ble_manufacturers(self, devices, limit=5):
        """Return compact manufacturer counts for BLE population Insights."""
        counts = {}
        for device in devices or []:
            label = (
                device.get("manufacturer")
                or device.get("manufacturer_name")
                or device.get("vendor_name")
                or device.get("vendor_prefix")
                or "unknown"
            )
            label = str(label or "").strip() or "unknown"
            counts[label] = counts.get(label, 0) + 1
        return [
            "{} ({})".format(label, count)
            for label, count in sorted(
                counts.items(), key=lambda item: (-item[1], item[0])
            )[:limit]
        ]

    def ble_individual_insight_worthy(self, device):
        """Return true when a BLE subject has identity worth an individual row."""
        if not isinstance(device, dict):
            return False
        transports = set(
            value.lower() for value in self.list_values(device.get("transports"))
        )
        if "classic" in transports or "bt_classic" in transports:
            return True
        if self.meaningful_bluetooth_names(device):
            return True
        for field in (
            "model_number",
            "serial_number",
            "firmware_revision",
            "hardware_revision",
            "software_revision",
            "pnp_id",
        ):
            if device.get(field):
                return True
        return bool(self.list_values(device.get("service_uuids")))

    def device_seen_within(self, record, max_age_sec):
        """Return true when a subject was active inside a recent horizon."""
        last_seen = record_time_epoch(record or {}, "last_seen")
        if last_seen is None or self._generated_at_epoch is None:
            return False
        return self._generated_at_epoch - last_seen <= float(max_age_sec)

    def low_value_stale_ble_device(self, device):
        """Suppress old one-off anonymous BLE rows from short-horizon Insights."""
        if not isinstance(device, dict):
            return True
        transports = set(
            value.lower() for value in self.list_values(device.get("transports"))
        )
        if "classic" in transports or "bt_classic" in transports:
            return False
        if self.meaningful_bluetooth_names(device):
            return False
        for field in (
            "model_number",
            "serial_number",
            "firmware_revision",
            "hardware_revision",
            "software_revision",
            "pnp_id",
        ):
            if device.get(field):
                return False
        observations = (
            int(device.get("seen_count") or 0)
            + int(device.get("update_count") or 0)
            + int(device.get("lost_count") or 0)
            + int(device.get("classic_seen_count") or 0)
            + int(device.get("classic_update_count") or 0)
            + int(device.get("classic_lost_count") or 0)
        )
        if observations > 1:
            return False
        last_seen = record_time_epoch(device, "last_seen")
        if last_seen is None:
            return False
        return self._generated_at_epoch - last_seen > float(
            self.config["ble_ignore_stale_single_seen_sec"]
        )

    def meaningful_bluetooth_names(self, device):
        """Return names that are more useful than an address echo."""
        mac = str((device or {}).get("mac") or "").strip().lower().replace("-", ":")
        names = self.list_values((device or {}).get("names"))
        if (device or {}).get("name"):
            names.append(str((device or {}).get("name")).strip())
        useful = []
        for name in names:
            text = str(name or "").strip()
            if not text:
                continue
            if text.lower().replace("-", ":") == mac:
                continue
            if bluetooth_property_like_name(text):
                continue
            useful.append(text)
        return sorted(set(useful))

    def analyze_population(self, clients, timestamp):
        """Look for population-level Wi-Fi patterns."""
        observations = []
        randomized_clients = [
            client for client in clients if client.get("randomized_mac")
        ]
        randomized = [client.get("mac") for client in randomized_clients]
        if len(randomized) >= int(self.config["randomized_mac_count"]):
            source = (
                "wifi_monitor"
                if any(
                    "wifi_monitor" in self.list_values(client.get("sources"))
                    for client in clients
                )
                else "wifi"
            )
            latest = self.latest_record(randomized_clients)
            observations.append(
                self.observation(
                    timestamp,
                    "warning",
                    source,
                    "wifi_randomized_mac_churn",
                    "Many randomized Wi-Fi MACs observed",
                    "{} locally administered client MACs are in device history".format(
                        len(randomized)
                    ),
                    {
                        "mac_count": len(randomized),
                        "sample": randomized[:25],
                        "last_seen": (latest or {}).get("last_seen"),
                        "last_seen_epoch": record_time_epoch(latest, "last_seen"),
                    },
                    75,
                )
            )
        return observations

    def analyze_rtl433(self, events, timestamp):
        """Return tactical observations for decoded rtl_433 subjects."""
        observations = []
        min_events = int(self.config.get("rtl433_recent_min_events", 1))
        for event in events or []:
            if (event or {}).get("type") != "rtl433_subject_summary":
                continue
            data = (event or {}).get("data") or {}
            event_count = self.to_int(data.get("event_count")) or 0
            category = data.get("category") or "device"
            if event_count < min_events and category not in ("tpms", "security"):
                continue
            title = "RTL-433 decoded device activity"
            severity = "warning" if category in ("tpms", "security") else "info"
            label = (
                " ".join(
                    part
                    for part in (
                        data.get("model") or "",
                        data.get("id") or "",
                        data.get("channel") or "",
                    )
                    if part
                ).strip()
                or "RTL-433 device"
            )
            detail = "{}; {}; {} event(s)".format(
                label,
                self.rtl433_category_label(category),
                event_count,
            )
            evidence = {
                "model": data.get("model") or "",
                "id": data.get("id") or "",
                "channel": data.get("channel") or "",
                "protocol": data.get("protocol") or "",
                "category": category,
                "event_count": event_count,
                "burst_count": data.get("burst_count") or 0,
                "frequency_mhz": data.get("latest_frequency_mhz") or "",
                "rssi_db": data.get("latest_rssi_db") or "",
                "snr_db": data.get("latest_snr_db") or "",
                "first_seen": data.get("first_seen") or "",
                "first_seen_epoch": data.get("first_seen_epoch"),
                "last_seen": data.get("last_seen") or "",
                "last_seen_epoch": data.get("last_seen_epoch"),
            }
            score = 62 if category in ("tpms", "security") else 25
            if self.to_int(data.get("burst_count")):
                score += 8
            observations.append(
                self.observation(
                    timestamp,
                    severity,
                    "rtl433",
                    "rtl433_decoded_subject",
                    title,
                    detail,
                    evidence,
                    score,
                )
            )
        return observations

    def rtl433_category_label(self, category):
        """Return operator-facing rtl_433 category text."""
        labels = {
            "tpms": "TPMS-like",
            "security": "garage/security/remote-like",
            "weather": "weather/sensor",
            "utility": "utility/meter",
        }
        return labels.get(category, "decoded ISM-band")

    def observation(
        self,
        timestamp,
        severity,
        source,
        obs_type,
        title,
        detail,
        evidence,
        score,
    ):
        """Build one normalized observation row."""
        self._counter += 1
        metadata = self.activity_metadata(obs_type, evidence, timestamp)
        display_timestamp = metadata.get("last_seen") or timestamp
        display_epoch = (
            metadata.get("last_seen_epoch")
            or self._generated_at_epoch
            or self.to_epoch(timestamp)
        )
        return {
            "id": "{}-{}".format(display_timestamp, self._counter),
            "timestamp": display_timestamp,
            "timestamp_epoch": display_epoch,
            "generated_at": timestamp,
            "generated_at_epoch": self._generated_at_epoch or self.to_epoch(timestamp),
            "severity": severity,
            "source": source,
            "type": obs_type,
            "title": title,
            "detail": detail,
            "evidence": evidence,
            "score": score,
            **metadata,
        }

    def latest_record(self, records):
        """Return the record with the newest last_seen timestamp."""
        newest = None
        newest_epoch = None
        for record in records or []:
            epoch = record_time_epoch(record, "last_seen")
            if epoch is None:
                continue
            if newest_epoch is None or epoch > newest_epoch:
                newest = record
                newest_epoch = epoch
        return newest

    def wifi_ap_evidence(self, ap, ssid, bssid):
        """Return identity evidence common to Wi-Fi AP observations."""
        return {
            "ssid": ssid,
            "bssid": bssid,
            "vendor_oui": ap.get("vendor_oui") or "",
            "vendor_prefix": ap.get("vendor_prefix") or ap.get("vendor_oui") or "",
            "vendor_name": ap.get("vendor_name") or "",
            "first_seen": ap.get("first_seen") or "",
            "first_seen_epoch": record_time_epoch(ap, "first_seen"),
            "last_seen": ap.get("last_seen") or "",
            "last_seen_epoch": record_time_epoch(ap, "last_seen"),
        }

    def wifi_client_evidence(self, client, mac):
        """Return identity evidence common to Wi-Fi client observations."""
        return {
            "mac": mac,
            "vendor_oui": client.get("vendor_oui") or "",
            "vendor_prefix": client.get("vendor_prefix")
            or client.get("vendor_oui")
            or "",
            "vendor_name": client.get("vendor_name") or "",
            "first_seen": client.get("first_seen") or "",
            "first_seen_epoch": record_time_epoch(client, "first_seen"),
            "last_seen": client.get("last_seen") or "",
            "last_seen_epoch": record_time_epoch(client, "last_seen"),
        }

    def ble_evidence(self, device, mac):
        """Return identity evidence common to BLE observations."""
        return {
            "mac": mac,
            "names": self.list_values(device.get("names")),
            "manufacturer": device.get("manufacturer") or "",
            "manufacturer_name": device.get("manufacturer_name") or "",
            "service_uuids": self.list_values(device.get("service_uuids")),
            "findmy_accessory": bool(device.get("findmy_accessory")),
            "findmy_label": device.get("findmy_label") or "",
            "findmy_payload_type": device.get("findmy_payload_type") or "",
            "findmy_status": device.get("findmy_status") or "",
            "findmy_hint": device.get("findmy_hint") or "",
            "vendor_prefix": device.get("vendor_prefix") or "",
            "vendor_name": device.get("vendor_name") or "",
            "transports": self.list_values(device.get("transports")),
            "classic_class": device.get("classic_class") or "",
            "model_number": device.get("model_number") or "",
            "firmware_revision": device.get("firmware_revision") or "",
            "first_seen": device.get("first_seen") or "",
            "first_seen_epoch": record_time_epoch(device, "first_seen"),
            "last_seen": device.get("last_seen") or "",
            "last_seen_epoch": record_time_epoch(device, "last_seen"),
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
        normalized = sorted(
            value for value in (self.normalized_mac(item) for item in bssids) if value
        )
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
        compact = "".join(
            ch for ch in str(value or "") if ch.lower() in "0123456789abcdef"
        )
        return compact.lower() if len(compact) == 12 else ""

    def vendor_mismatch(self, vendor_ouis, vendor_prefixes, vendor_names):
        """Detect vendor drift while preferring resolved vendor names.

        A single manufacturer can own many OUI blocks. If every BSSID resolves
        to the same vendor name, different OUI prefixes alone should not turn a
        normal multi-AP network into an evil-twin warning.
        """
        oui_values = self.vendor_prefix_value_set(vendor_ouis)
        prefix_values = self.vendor_prefix_value_set(vendor_prefixes)
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
            if text and text not in (
                "unknown",
                "locally administered / randomized",
            ):
                cleaned.add(text)
        return cleaned

    def vendor_prefix_value_set(self, values):
        """Normalize vendor prefixes while ignoring locally administered MACs.

        Randomized/local BSSIDs intentionally do not carry an IEEE-assigned OUI.
        Comparing those prefixes as if they were vendors creates false evil-twin
        warnings for normal neighbor APs or mesh nodes that use local BSSIDs.
        """
        cleaned = set()
        for value in self.list_values(values):
            text = str(value or "").strip()
            if not text or text.lower() in (
                "unknown",
                "locally administered / randomized",
            ):
                continue
            if self.is_locally_administered_prefix(text):
                continue
            cleaned.add(text.lower())
        return cleaned

    def is_locally_administered_prefix(self, value):
        """Return True when the first MAC octet has the local-admin bit set."""
        compact = "".join(
            ch for ch in str(value or "") if ch.lower() in "0123456789abcdef"
        )
        if len(compact) < 2:
            return False
        try:
            return bool(int(compact[:2], 16) & 0x02)
        except ValueError:
            return False

    def activity_metadata(self, obs_type, evidence, timestamp):
        """Attach coarse activity state used by the Insights default view."""
        if "recurring" in str(obs_type or ""):
            return {
                "activity_state": "recurring",
                "last_seen": (evidence or {}).get("last_seen"),
                "last_seen_epoch": record_time_epoch(evidence, "last_seen"),
                "age_minutes": None,
            }
        last_seen = (evidence or {}).get("last_seen")
        last_seen_epoch = record_time_epoch(evidence, "last_seen")
        age = self.age_minutes(
            last_seen_epoch or last_seen,
            self._generated_at_epoch or timestamp,
        )
        if age is None:
            return {
                "activity_state": "unknown",
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
                "age_minutes": None,
            }
        state = (
            "recent"
            if age
            <= (float(self.config.get("recent_activity_window_sec", 1800)) / 60.0)
            else "stale"
        )
        return {
            "activity_state": state,
            "last_seen": last_seen,
            "last_seen_epoch": last_seen_epoch,
            "age_minutes": int(age),
        }

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
        # Only closed sessions have both arrival and departure timestamps. The
        # current active session is useful in Reports, but not for recurring
        # arrival/departure inference yet.
        sessions = [
            session
            for session in (device.get("sessions") or [])
            if session.get("start") and session.get("end")
        ]
        min_sessions = int(self.config.get("ble_recurring_min_sessions", 3))
        if len(sessions) < min_sessions:
            return None
        starts = [self.minute_of_day(session, "start") for session in sessions]
        ends = [self.minute_of_day(session, "end") for session in sessions]
        starts = [value for value in starts if value is not None]
        ends = [value for value in ends if value is not None]
        if len(starts) < min_sessions or len(ends) < min_sessions:
            return None
        window = int(self.config.get("ble_recurring_window_min", 30))
        # The cluster search treats time of day as circular, so 23:55 and 00:05
        # can still be grouped together.
        start_center, start_count = self.cluster_minutes(starts, window)
        end_center, end_count = self.cluster_minutes(ends, window)
        if start_count < min_sessions or end_count < min_sessions:
            return None
        durations = [
            self.to_number(session.get("duration_sec")) for session in sessions
        ]
        durations = [value for value in durations if value is not None and value > 0]
        return {
            "arrival": self.format_minute(start_center),
            "departure": self.format_minute(end_center),
            "arrival_matches": start_count,
            "departure_matches": end_count,
            "session_count": len(sessions),
            "typical_duration_min": (
                int((sum(durations) / len(durations)) / 60) if durations else 0
            ),
        }

    def minute_of_day(self, record, field=None):
        """Convert a timestamp into local minute-of-day for pattern grouping."""
        epoch = record_time_epoch(record, field) if field else timestamp_epoch(record)
        if epoch is not None:
            parsed = datetime.fromtimestamp(epoch)
            return parsed.hour * 60 + parsed.minute
        return None

    def cluster_minutes(self, values, window):
        """Find the densest time-of-day cluster within a +/- window."""
        if not values:
            return None, 0
        best_center = values[0]
        best_matches = []
        for center in values:
            matches = [
                value
                for value in values
                if self.circular_minute_distance(center, value) <= window
            ]
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
        has_strong = any(
            "wpa2" in value or "wpa3" in value or "rsn" in value for value in lowered
        )
        return has_strong and self.has_weak_crypto(encryptions)

    def is_new(self, item, timestamp):
        """Return true when first_seen is within the configured recent window."""
        first_seen = record_time_epoch(item, "first_seen")
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

    def record_duration_seconds(self, record):
        """Return duration from a history record's epoch time bounds."""
        first = record_time_epoch(record, "first_seen")
        last = record_time_epoch(record, "last_seen")
        if first is None or last is None or last < first:
            return 0
        return last - first

    # ------------------------------------------------------------------
    # Cross-collector device bundle correlation
    # ------------------------------------------------------------------

    def analyze_bundle_correlation(self, history, timestamp):
        """Find groups of devices from different collectors that repeatedly
        appear together in tight time windows.

        Returns a list of ``device_bundle`` observation dicts.
        """
        observations = []
        if not self.config.get("bundle_correlation_enabled", True):
            return observations

        sources = self._canonical_bundle_sources(
            self.config.get("bundle_correlation_sources", ["ble", "wifi"]))
        sync_margin = float(self.config.get(
            "bundle_correlation_sync_margin_sec", 300))
        min_cooccur = int(self.config.get(
            "bundle_correlation_min_cooccurrences", 3))
        min_size = int(self.config.get(
            "bundle_correlation_min_bundle_size", 2))
        max_bundles = int(self.config.get(
            "bundle_correlation_max_bundles", 10))
        max_span = int(self.config.get(
            "bundle_correlation_max_window_span_sec", 3600))
        min_sessions = int(self.config.get(
            "bundle_correlation_min_sessions_per_device", 2))
        max_per_source = int(self.config.get(
            "bundle_correlation_max_subjects_per_source", 100))

        # Phase 1: extract time windows from every enabled source.  The
        # per-source subject cap is applied inside extraction (before session
        # parsing) so unselected subjects never cost window parsing.
        all_subjects = []
        windows_by_key = {}

        for source in sources:
            subjects, windows = self._extract_bundle_windows(
                history, source, max_span, min_sessions, max_per_source)
            all_subjects.extend(subjects)
            windows_by_key.update(windows)

        if len(all_subjects) < min_size:
            return observations

        # Build a key→subject lookup
        subject_by_key = {s["key"]: s for s in all_subjects}

        # Phase 2: count synchronized co-occurrences
        pair_counts = self._count_cooccurrences(
            all_subjects, windows_by_key, sync_margin)

        # Build qualifying-pairs dict (only edges ≥ min_cooccur)
        qualifying = {
            pair: count for pair, count in pair_counts.items()
            if count >= min_cooccur
        }

        # Phase 3: build clique bundles from qualifying pairs
        bundles = self._build_clique_bundles(
            all_subjects, subject_by_key, qualifying, min_size)

        if not bundles:
            return observations

        # Phase 4: emit one observation per bundle, best first.  The
        # observation's last_seen is the true latest co-occurrence end, not
        # the analysis generation time — otherwise stale bundles would be
        # stamped "recent" in the tactical feed.
        bundle_obs = []
        for bundle in bundles:
            ends = [
                window[1]
                for key in bundle
                for window in windows_by_key.get(key, [])
            ]
            last_seen = max(ends) if ends else timestamp
            obs = self._bundle_observation(
                bundle, qualifying, subject_by_key, timestamp,
                last_seen=last_seen)
            if obs:
                bundle_obs.append(obs)

        bundle_obs.sort(key=lambda o: o["score"], reverse=True)
        return bundle_obs[:max_bundles]

    @staticmethod
    def _canonical_bundle_sources(sources):
        """Normalize source aliases and drop synonyms.

        "bluetooth" reads the same bucket as "ble", and "wifi_monitor"
        subjects live in the same ``history["wifi"]`` structure as managed
        Wi-Fi — without canonicalization both aliases would duplicate every
        subject and produce phantom cross-collector self-pairs.
        """
        canonical = []
        for source in sources or []:
            if source in ("ble", "bluetooth"):
                key = "ble"
            elif source in ("wifi", "wifi_monitor"):
                key = "wifi"
            else:
                key = source
            if key not in canonical:
                canonical.append(key)
        return canonical

    def _extract_bundle_windows(self, history, source, max_span,
                                min_sessions, max_per_source=0):
        """Return (subjects, windows_by_key) for one canonical collector source.

        Uses per-device sessions when available; falls back to a single
        ``first_seen``–``last_seen`` window for subjects whose total span
        is ≤ *max_span*.  Subjects with fewer than *min_sessions* sessions
        are skipped (filters stationary background devices); sessionless
        subjects (Wi-Fi clients have no session arrays) participate via the
        span fallback.  *max_per_source* caps candidates per source BEFORE
        window parsing, by session count, for predictable runtime.
        """
        subjects = []
        windows_by_key = {}

        if source == "ble":
            ble = history.get("bluetooth") or history.get("ble") or {}
            records = [
                dev for dev in (ble.get("devices") or [])
                if not locally_administered_mac(
                    (dev.get("mac") or "unknown").lower())
                and not dev.get("grouped_randomized")
            ]
            if max_per_source > 0 and len(records) > max_per_source:
                records.sort(
                    key=lambda d: d.get("session_count")
                    or len(d.get("sessions") or []),
                    reverse=True)
                records = records[:max_per_source]
            for dev in records:
                mac = (dev.get("mac") or "unknown").lower()
                key = "ble:{}".format(mac)
                windows = self._subject_windows(
                    dev, max_span, min_sessions)
                if not windows:
                    continue
                names = self.list_values(dev.get("names"))
                vendor = dev.get("vendor_name") or ""
                # Skip anonymous BLE devices: no vendor and no name → noise
                if not vendor and not names:
                    continue
                label = names[0] if names else (vendor if vendor else mac)
                subjects.append({
                    "key": key, "collector": "ble",
                    "subject_id": mac,
                    "display_label": "BLE: {}".format(label),
                    "vendor_name": vendor, "names": names,
                })
                windows_by_key[key] = windows

        elif source == "wifi":
            wifi = history.get("wifi") or {}
            candidates = []
            for kind, record in (
                    [("ap", item) for item in (wifi.get("access_points") or [])]
                    + [("client", item)
                       for item in (wifi.get("clients") or [])]):
                mac = ((record.get("bssid") or record.get("mac"))
                       or "unknown").lower()
                if locally_administered_mac(mac):
                    continue
                candidates.append((kind, record))
            if max_per_source > 0 and len(candidates) > max_per_source:
                candidates.sort(
                    key=lambda item: item[1].get("session_count")
                    or len(item[1].get("sessions") or []),
                    reverse=True)
                candidates = candidates[:max_per_source]
            for kind, record in candidates:
                if kind == "ap":
                    bssid = ((record.get("bssid") or record.get("mac"))
                             or "unknown").lower()
                    key = "wifi_ap:{}".format(bssid)
                    windows = self._subject_windows(
                        record, max_span, min_sessions)
                    if not windows:
                        continue
                    ssid = record.get("ssid") or ""
                    vendor = record.get("vendor_name") or ""
                    label = ssid if ssid else (vendor if vendor else bssid)
                    subjects.append({
                        "key": key, "collector": "wifi",
                        "subject_id": bssid,
                        "display_label": "Wi-Fi AP: {}".format(label),
                        "vendor_name": vendor,
                        "names": [ssid] if ssid else [],
                    })
                    windows_by_key[key] = windows
                else:
                    mac = (record.get("mac") or "unknown").lower()
                    key = "wifi_client:{}".format(mac)
                    windows = self._subject_windows(
                        record, max_span, min_sessions)
                    if not windows:
                        continue
                    vendor = record.get("vendor_name") or ""
                    label = vendor if vendor else mac
                    subjects.append({
                        "key": key, "collector": "wifi",
                        "subject_id": mac,
                        "display_label": "Wi-Fi client: {}".format(label),
                        "vendor_name": vendor, "names": [],
                    })
                    windows_by_key[key] = windows

        return subjects, windows_by_key

    def _subject_windows(self, record, max_span, min_sessions):
        """Extract ``[(start, end), …]`` from a subject record.

        Sessions are preferred.  Sessionless subjects (Wi-Fi clients never
        get session arrays) fall back to the whole ``first_seen``–
        ``last_seen`` span as a single window when the total span ≤
        *max_span*.  Sessionful subjects with fewer than *min_sessions*
        sessions are excluded — a device with one session has no movement
        pattern to correlate.  Windows are capped to the most recent
        ``MAX_BUNDLE_WINDOWS_PER_SUBJECT`` for predictable pair-scan cost.
        """
        sessions = record.get("sessions") or []
        windows = []
        if sessions:
            if len(sessions) < min_sessions:
                return []  # stationary device, skip
            for s in sessions:
                start = record_time_epoch(s, "start")
                end = record_time_epoch(s, "end")
                if (start is not None and end is not None
                        and start <= end):
                    windows.append((int(start), int(end)))
        if not windows:
            start = record_time_epoch(record, "first_seen")
            end = record_time_epoch(record, "last_seen")
            if (start is not None and end is not None
                    and start <= end
                    and (end - start) <= max_span):
                windows.append((int(start), int(end)))
        windows.sort(key=lambda item: item[0])
        return windows[-MAX_BUNDLE_WINDOWS_PER_SUBJECT:]

    @staticmethod
    def _windows_synchronized(a_start, a_end, b_start, b_end, sync_margin):
        """True when two sessions arrived and departed together."""
        return (abs(a_start - b_start) <= sync_margin and
                abs(a_end - b_end) <= sync_margin)

    def _count_cooccurrences(self, subjects, windows_by_key, sync_margin):
        """Count synchronized co-occurrences between cross-collector pairs.

        Two sessions count as co-occurring only when they *arrived* and
        *departed* within *sync_margin* seconds of each other — simple
        temporal overlap is not enough.  This filters out stationary
        background devices whose one long session overlaps everything.

        The stored count is the minimum of the two directional counts
        ("A-windows with ≥1 synchronized B-window" and vice versa) so the
        result is symmetric and independent of subject iteration order.

        Returns ``{(key_a, key_b): count}`` for cross-collector pairs only.
        """
        def directional(wins_a, wins_b):
            count = 0
            for wa in wins_a:
                for wb in wins_b:
                    if self._windows_synchronized(
                            wa[0], wa[1], wb[0], wb[1], sync_margin):
                        count += 1
                        break  # at most one per A-window
            return count

        pairs = {}
        for i, subj_a in enumerate(subjects):
            wins_a = windows_by_key.get(subj_a["key"], [])
            if not wins_a:
                continue
            for subj_b in subjects[i + 1:]:
                if subj_a["collector"] == subj_b["collector"]:
                    continue
                wins_b = windows_by_key.get(subj_b["key"], [])
                if not wins_b:
                    continue
                count = min(
                    directional(wins_a, wins_b),
                    directional(wins_b, wins_a),
                )
                if count > 0:
                    ka, kb = subj_a["key"], subj_b["key"]
                    if ka > kb:
                        ka, kb = kb, ka
                    pairs[(ka, kb)] = count
        return pairs

    def _build_clique_bundles(self, subjects, subject_by_key, qualifying,
                              min_size):
        """Build clique bundles from qualifying co-occurring pairs.

        Unlike connected components (which allow transitive chaining),
        a clique requires *every* pair of devices to co-occur directly.
        Uses greedy construction: seeds from the strongest pairs, expands
        by adding devices that co-occur with all current members.
        """
        if not qualifying:
            return []

        # One adjacency set per subject so clique-expansion membership tests
        # are set operations instead of per-test tuple construction.
        adjacency = {}
        for (ka, kb) in qualifying:
            adjacency.setdefault(ka, set()).add(kb)
            adjacency.setdefault(kb, set()).add(ka)

        # Sort pairs strongest-first
        sorted_pairs = sorted(qualifying.items(),
                              key=lambda item: item[1], reverse=True)
        placed = set()
        bundles = []

        for (ka, kb), _ in sorted_pairs:
            if ka in placed or kb in placed:
                continue
            # Seed a candidate clique with this pair
            clique = {ka, kb}
            clique_collectors = set()
            sa = subject_by_key.get(ka)
            sb = subject_by_key.get(kb)
            if sa:
                clique_collectors.add(sa["collector"])
            if sb:
                clique_collectors.add(sb["collector"])

            # Try adding other devices that co-occur with ALL current members
            for subj in subjects:
                sk = subj["key"]
                if sk in clique:
                    continue
                if clique <= adjacency.get(sk, set()):
                    clique.add(sk)
                    clique_collectors.add(subj["collector"])

            if len(clique) >= min_size and len(clique_collectors) >= 2:
                bundles.append(sorted(clique))
                placed.update(clique)

        return bundles

    def _bundle_label(self, bundle_keys, subject_by_key):
        """Short human label summarising a bundle."""
        parts = []
        for key in bundle_keys[:5]:
            subj = subject_by_key.get(key)
            if subj:
                parts.append(subj["display_label"])
        if len(bundle_keys) > 5:
            parts.append("+{} more".format(len(bundle_keys) - 5))
        return " / ".join(parts)

    def _bundle_observation(self, bundle_keys, qualifying,
                            subject_by_key, timestamp, last_seen=None):
        """Build one ``device_bundle`` observation dict.

        Only qualifying edges (≥ min_cooccurrences) are used for scoring
        and evidence — weak pairs within the clique are not shown.
        *last_seen* is the true latest co-occurrence end (not the analysis
        generation time) so activity metadata ages the row honestly.
        """
        if not bundle_keys:
            return None

        devices = []
        collectors = set()
        for key in bundle_keys:
            subj = subject_by_key.get(key)
            if not subj:
                continue
            collectors.add(subj["collector"])
            devices.append({
                "collector": subj["collector"],
                "subject_id": subj["subject_id"],
                "display_label": subj["display_label"],
                "vendor_name": subj["vendor_name"],
                "names": subj.get("names") or [],
            })

        if len(collectors) < 2:
            return None

        # Score from qualifying edges only
        edge_weights = []
        pair_evidence = {}
        for i in range(len(bundle_keys)):
            for j in range(i + 1, len(bundle_keys)):
                ka, kb = bundle_keys[i], bundle_keys[j]
                if ka > kb:
                    ka, kb = kb, ka
                count = qualifying.get((ka, kb), 0)
                if count:
                    edge_weights.append(count)
                    sa = subject_by_key.get(bundle_keys[i], {})
                    sb = subject_by_key.get(bundle_keys[j], {})
                    label_a = sa.get("subject_id", bundle_keys[i])
                    label_b = sb.get("subject_id", bundle_keys[j])
                    pair_evidence[
                        "{} <-> {}".format(label_a, label_b)] = count

        cooccurrence_count = min(edge_weights) if edge_weights else 0
        collector_count = len(collectors)

        score = 65 + min(cooccurrence_count, 20)
        if collector_count > 2:
            score += (collector_count - 2) * 5

        label = self._bundle_label(bundle_keys, subject_by_key)
        title = "Device bundle: {} devices across {} collectors".format(
            len(bundle_keys), collector_count)
        detail = label

        # Build readable strings for the frontend (generic evidence
        # formatter renders objects as "[object Object]")
        device_list = ", ".join(
            d["display_label"] for d in devices)
        pairs_list = ", ".join(
            "{}: {}".format(k, v) for k, v in pair_evidence.items())

        evidence = {
            "_devices": devices,
            "device_list": device_list,
            "cooccurrence_pairs": pairs_list,
            "min_cooccurrence_count": cooccurrence_count,
            "collector_count": collector_count,
            "bundle_size": len(bundle_keys),
            "last_seen": last_seen if last_seen is not None else timestamp,
        }

        first_collector = devices[0]["collector"] if devices else "ble"

        return self.observation(
            timestamp, "warning", first_collector,
            "device_bundle", title, detail, evidence, score)

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

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
        """Return epoch seconds for internal time calculations."""
        return timestamp_epoch(timestamp)

    def severity_rank(self, severity):
        """Sort warnings above informational observations."""
        return {"warning": 2, "info": 1}.get(severity, 0)


def save_analysis(path, analysis):
    """Persist the latest analysis snapshot for offline inspection."""
    save_json_atomic(path, analysis)
