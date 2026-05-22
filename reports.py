"""Longer-window report generation from materialized Device History.

Insights are meant to move quickly. Reports are the slower summary layer for
questions such as "what recurring Bluetooth presence happened this week?" or
"which APs/clients were notable during this retained window?"
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta
import json
import os

from bus import local_now
from log_utils import (
    format_epoch,
    now_epoch,
    record_time_epoch,
    timestamp_epoch,
    window_metadata,
    window_since_epoch,
)


DEFAULT_REPORT_CONFIG = {
    "ble_long_presence_sec": 3600,
    "ble_recurring_min_days": 2,
    "ble_private_address_group_min_count": 3,
    "new_device_window_sec": 3600,
    "ble_strong_rssi": -55,
    "wifi_strong_rssi": -50,
    "wifi_many_bssid_count": 2,
    "wifi_monitor_event_count": 5,
}


class ReportsBuilder:
    """Build slower report-style interpretations from Device History.

    Reports are intentionally separate from Insights. Insights answer "what is
    notable now?", while reports summarize repeated or long-running patterns
    over the selected retained-log window.
    """

    def __init__(self, config=None, window_days=None):
        self.config = DEFAULT_REPORT_CONFIG.copy()
        self.config.update(config or {})
        self.window_days = window_days
        self._counter = 0
        self._generated_at_epoch = None

    def build(self, history):
        """Return a report bundle for Bluetooth, Wi-Fi scan, and monitor data."""
        generated_at_epoch = now_epoch()
        self._generated_at_epoch = generated_at_epoch
        generated_at = local_now(generated_at_epoch)
        # Reports never read raw JSONL directly. The Refresh path in main.py
        # first updates Device History, then hands the summary to this builder.
        wifi = (history or {}).get("wifi") or {}
        bluetooth = (
            (history or {}).get("bluetooth") or (history or {}).get("ble") or {}
        )
        reports = []
        reports.extend(
            self.ble_reports(bluetooth.get("devices") or [], generated_at)
        )
        reports.extend(
            self.wifi_ap_reports(wifi.get("access_points") or [], generated_at)
        )
        reports.extend(
            self.wifi_client_reports(wifi.get("clients") or [], generated_at)
        )
        reports.sort(
            key=lambda item: (
                self.severity_rank(item["severity"]),
                item.get("score", 0),
                item.get("last_seen_epoch") or 0,
            ),
            reverse=True,
        )
        return {
            "generated_at": generated_at,
            "generated_at_epoch": generated_at_epoch,
            "history_generated_at": (history or {}).get("generated_at"),
            "window": window_metadata(self.window_days),
            "reports": reports,
            "counts": self.counts(reports),
        }

    def ble_reports(self, devices, timestamp):
        """Summarize Bluetooth presence as one profile row per device/cluster."""
        reports = []
        contexts = [self.ble_context(device) for device in devices]
        private_groups = defaultdict(list)
        private_group_min = int(
            self.config.get("ble_private_address_group_min_count", 3)
        )
        for context in contexts:
            if context["private_candidate"]:
                # Many unnamed Apple/Microsoft/etc. BLE addresses in one window
                # are often address rotation, not dozens of stable devices.
                private_groups[context["manufacturer"] or "Unknown"].append(
                    context
                )

        grouped_private_macs = set()
        for manufacturer, members in sorted(private_groups.items()):
            if len(members) < private_group_min:
                continue
            grouped_private_macs.update(member["mac"] for member in members)
            reports.append(
                self.ble_private_address_group_report(
                    timestamp, manufacturer, members
                )
            )

        for context in contexts:
            device = context["device"]
            mac = context["mac"]
            sessions = context["sessions"]
            days = context["days"]
            hours = context["hours"]
            start_hours = context["start_hours"]
            longest = context["longest"]
            signal_max = context["signal_max"]
            spans = context["presence_spans"]
            private_grouped = mac in grouped_private_macs
            finding_labels = []

            if sessions and len(days) >= int(
                self.config["ble_recurring_min_days"]
            ):
                finding_labels.append("Recurring presence")

            if longest >= float(self.config["ble_long_presence_sec"]):
                finding_labels.append("Long presence")

            if (
                not private_grouped
                and signal_max is not None
                and signal_max >= float(self.config["ble_strong_rssi"])
            ):
                finding_labels.append("Strong nearby signal")

            if (
                self.is_new_recent(device, timestamp)
                and not private_grouped
                and not context["private_candidate"]
            ):
                finding_labels.append("New named/static device")
            if not finding_labels:
                continue

            score = self.score_ble_profile(context, finding_labels)
            severity = self.severity_for_score(score)
            evidence = self.with_evidence(
                self.ble_evidence(
                    device,
                    sessions,
                    days,
                    hours,
                    start_hours,
                    spans,
                ),
                {
                    "findings": finding_labels,
                    "longest_session_sec": int(longest),
                },
            )
            reports.append(
                self.report(
                    timestamp,
                    severity,
                    "bluetooth",
                    "ble_device_profile",
                    "Bluetooth device profile",
                    self.ble_profile_summary(context, finding_labels),
                    evidence,
                    score,
                    device.get("last_seen"),
                    subject=self.bluetooth_subject(device, mac),
                )
            )
        return reports

    def score_ble_profile(self, context, finding_labels):
        """Return 0-100 attention score for one stable Bluetooth profile.

        Score is an "operator attention" rank, not a probability that the
        device is malicious. BLE profiles become more important when a device
        stays nearby for a long time, repeats across days, follows a predictable
        schedule, is still active, is physically close by RSSI, or is newly seen.
        The weights are additive so combined weak signals can outrank a single
        low-value rule, while the final cap keeps the scale readable.
        """
        score = 0
        longest = float(context.get("longest") or 0)
        days_seen = len(context.get("days") or [])
        signal_max = context.get("signal_max")
        active = bool((context.get("device") or {}).get("active_session"))

        # Duration is the strongest BLE signal because a long nearby presence is
        # usually more actionable than a brief advertisement burst.
        if longest >= 8 * 3600:
            score += 50
        elif longest >= 4 * 3600:
            score += 40
        elif longest >= float(self.config["ble_long_presence_sec"]):
            score += 25

        # Recurrence matters, but less than duration: repeated days suggest a
        # pattern worth reviewing even when each individual visit is short.
        if days_seen >= 5:
            score += 35
        elif days_seen >= 3:
            score += 25
        elif days_seen >= int(self.config["ble_recurring_min_days"]):
            score += 15

        # Stable start/activity windows make the row more intelligence-like:
        # "shows up around this time" is more useful than just "seen before".
        if days_seen >= int(self.config["ble_recurring_min_days"]):
            if context.get("start_hours"):
                score += 10
            if context.get("hours"):
                score += 10

        # Active devices should float up because the operator can still act on
        # them now, while stale rows can stay lower unless other factors matter.
        if active:
            score += 15

        # RSSI is treated as proximity. Very strong BLE is rare enough to rank
        # highly, but weak far-away devices should not dominate the report.
        if signal_max is not None:
            if signal_max >= -45:
                score += 30
            elif signal_max >= -55:
                score += 20
            elif signal_max >= -70:
                score += 10

        # A new named/static device gets attention because it is more likely to
        # represent one physical device than an unnamed private address.
        if "New named/static device" in finding_labels:
            score += 30

        return min(score, 100)

    def ble_context(self, device):
        """Precompute Bluetooth fields used by several report policies."""
        mac = device.get("mac") or "unknown"
        sessions = self.sessions_in_window(self.device_sessions(device))
        days = self.presence_days(sessions)
        hours = self.session_hour_counts(sessions)
        start_hours = self.hour_counts(
            [record_time_epoch(session, "start") for session in sessions]
        )
        longest = max(
            [float(session.get("duration_sec") or 0) for session in sessions]
            or [0]
        )
        signal_max = self.to_number(device.get("signal_max"))
        manufacturer = (
            device.get("manufacturer_name")
            or device.get("manufacturer")
            or device.get("vendor_name")
            or ""
        )
        return {
            "device": device,
            "mac": mac,
            "label": self.bluetooth_label(device, mac),
            "sessions": sessions,
            "days": days,
            "hours": hours,
            "start_hours": start_hours,
            "presence_spans": self.session_spans(sessions),
            "longest": longest,
            "signal_max": signal_max,
            "manufacturer": manufacturer,
            "private_candidate": self.is_private_ble_candidate(
                device, mac, sessions
            ),
        }

    def ble_profile_summary(self, context, finding_labels):
        """Return a readable one-line summary for a stable BLE device."""
        parts = []
        longest = float(context.get("longest") or 0)
        signal_max = context.get("signal_max")
        sessions = context.get("sessions") or []
        active = bool((context.get("device") or {}).get("active_session"))
        if "New named/static device" in finding_labels:
            visits = len(sessions)
            if visits > 1:
                parts.append(
                    "New Bluetooth device, seen in {} visits".format(visits)
                )
            else:
                parts.append("New Bluetooth device")
        if "Recurring presence" in finding_labels:
            days = len(context.get("days") or [])
            parts.append("recurring presence across {} day(s)".format(days))
        if "Long presence" in finding_labels:
            phrase = "nearby for about {}".format(self.duration_text(longest))
            if active:
                phrase += " and still present"
            parts.append(phrase)
        if "Strong nearby signal" in finding_labels and signal_max is not None:
            parts.append("strong signal reached {} dBm".format(int(signal_max)))
        summary = "; ".join(parts)
        return summary[:1].upper() + summary[1:] + "." if summary else ""

    def ble_private_cluster_summary(self, manufacturer, count, active):
        """Return a readable one-line summary for a BLE private-address group."""
        summary = "{} private/randomized BLE address(es)".format(count)
        if active:
            summary += "; {} still active".format(len(active))
        if manufacturer:
            summary = summary[0].upper() + summary[1:]
        return summary + "."

    def bluetooth_subject(self, device, mac):
        """Return the identity string shown once in the Reports Subject column."""
        parts = []
        names = [
            str(name).strip()
            for name in (device.get("names") or [])
            if str(name).strip()
        ]
        if names:
            parts.append(names[0])
        if mac:
            parts.append(mac)
        manufacturer = (
            device.get("manufacturer_name")
            or device.get("manufacturer")
            or device.get("vendor_name")
            or ""
        )
        if manufacturer:
            parts.append(manufacturer)
        return " - ".join(parts)

    def bluetooth_cluster_subject(self, manufacturer, count):
        """Return the subject for a private/randomized BLE address cluster."""
        if manufacturer:
            return "{} - {} private/randomized addresses".format(
                manufacturer, count
            )
        return "{} private/randomized addresses".format(count)

    def ble_private_address_group_report(
        self, timestamp, manufacturer, members
    ):
        """Summarize likely BLE privacy-address churn as one report row."""
        macs = sorted(member["mac"] for member in members)
        active = [
            member["mac"]
            for member in members
            if member["device"].get("active_session")
        ]
        all_days = sorted(
            set(day for member in members for day in member["days"] if day)
        )
        hour_counts = Counter()
        start_hour_counts = Counter()
        sessions = []
        signal_values = []
        for member in members:
            hour_counts.update(member["hours"])
            start_hour_counts.update(member["start_hours"])
            sessions.extend(member["sessions"])
            value = member["signal_max"]
            if value is not None:
                signal_values.append(value)
        signal_max = max(signal_values) if signal_values else None
        first_seen_member = min(
            members,
            key=lambda member: record_time_epoch(member["device"], "first_seen")
            or float("inf"),
            default={},
        )
        first_seen_device = first_seen_member.get("device") or {}
        last_seen_member = max(
            members,
            key=lambda member: record_time_epoch(member["device"], "last_seen")
            or 0,
            default={},
        )
        last_seen_device = last_seen_member.get("device") or {}
        last_seen = last_seen_device.get("last_seen") or ""
        evidence = {
            "manufacturer": manufacturer,
            "address_count": len(members),
            "active_addresses": len(active),
            "findings": ["Private/randomized address cluster"],
            "sample_macs": macs[:12],
            "days_seen": all_days,
            "presence_hours": self.hour_labels(hour_counts),
            "common_hours": self.common_hours(hour_counts),
            "common_start_hours": self.common_hours(start_hour_counts),
            "presence_spans": self.session_spans(sessions),
            "signal_max": int(signal_max) if signal_max is not None else "",
            "first_seen": self.display_time(first_seen_device, "first_seen"),
            "first_seen_epoch": record_time_epoch(
                first_seen_device, "first_seen"
            ),
            "last_seen": last_seen,
            "last_seen_epoch": record_time_epoch(last_seen_device, "last_seen"),
        }
        score = self.score_ble_private_cluster(
            len(members), len(active), signal_max
        )
        return self.report(
            timestamp,
            self.severity_for_score(score),
            "bluetooth",
            "ble_private_address_cluster",
            "Bluetooth private-address cluster",
            self.ble_private_cluster_summary(
                manufacturer, len(members), active
            ),
            evidence,
            score,
            last_seen,
            subject=self.bluetooth_cluster_subject(manufacturer, len(members)),
        )

    def score_ble_private_cluster(
        self, address_count, active_count, signal_max
    ):
        """Return attention score for a BLE private/randomized address cluster.

        Private-address clusters are summarized by manufacturer because each
        individual address is weak identity evidence. The cluster still deserves
        attention when address churn is large, some addresses are active now, or
        the strongest signal is nearby. The cap is slightly below stable devices
        because the row is less specific unless proximity/activity is strong.
        """
        score = 0
        # Large address counts indicate churn density in the selected window.
        if address_count >= 100:
            score += 35
        elif address_count >= 50:
            score += 25
        elif address_count >= 10:
            score += 15
        # Currently active rotating addresses are more actionable than a purely
        # historical cluster.
        if active_count:
            score += 10
        # Strong cluster RSSI suggests at least one nearby physical device.
        if signal_max is not None:
            if signal_max >= -45:
                score += 30
            elif signal_max >= -55:
                score += 20
        return min(score, 95)

    def wifi_ap_profile_summary(self, ap, findings, signal_max):
        """Return the final summary sentence for one Wi-Fi AP profile."""
        parts = []
        if "New access point" in findings:
            parts.append("new access point")
        if "Strong signal" in findings:
            if signal_max is not None:
                parts.append(
                    "strong signal reached {} dBm".format(int(signal_max))
                )
            else:
                parts.append("strong signal")
        if "Wi-Fi AP encryption varied" in findings:
            parts.append("security changed during the report window")
        if "Wi-Fi AP security detail varied" in findings:
            parts.append("security detail varied during the report window")
        if "Multiple channels" in findings:
            parts.append("seen on multiple channels")
        if not parts:
            return "Access point activity summarized."
        sentence = "; ".join(parts)
        return sentence[:1].upper() + sentence[1:] + "."

    def wifi_ssid_profile_summary(self, ssid, bssids, vendors, encryption):
        """Return the final summary sentence for an SSID-level Wi-Fi profile."""
        vendor_text = ""
        if vendors:
            vendor_text = " from {}".format(", ".join(vendors[:3]))
            if len(vendors) > 3:
                vendor_text += " and {} more".format(len(vendors) - 3)
        security_text = ""
        if encryption:
            security_text = " using {}".format(", ".join(encryption))
        return "{} was observed on {} BSSID(s){}{}.".format(
            ssid,
            len(bssids),
            vendor_text,
            security_text,
        )

    def wifi_ap_subject(self, ap):
        """Return identity for the Reports Subject column."""
        ssid = ap.get("ssid") or "blank SSID"
        bssid = ap.get("bssid") or ""
        vendor = ap.get("vendor_name") or ap.get("vendor_prefix") or ""
        return " - ".join(part for part in (ssid, bssid, vendor) if part)

    def wifi_ap_reports(self, aps, timestamp):
        """Summarize Wi-Fi as AP profiles plus SSID-level profiles."""
        reports = []
        by_ssid = defaultdict(list)
        for ap in aps:
            by_ssid[ap.get("ssid") or "(blank)"].append(ap)
            signal_max = self.to_number(ap.get("signal_max"))
            evidence = self.wifi_ap_evidence(ap)
            findings = []
            forced_warning = False
            if self.is_new_recent(ap, timestamp):
                findings.append("New access point")
            if signal_max is not None and signal_max >= float(
                self.config["wifi_strong_rssi"]
            ):
                findings.append("Strong signal")
            encryptions = self.normalized_wifi_encryption_values(
                ap.get("encryption") or []
            )
            variation = self.wifi_encryption_variation(encryptions)
            if variation:
                # Report security drift only after canonicalization suppresses
                # parser wording differences such as WPA2 versus WPA2/RSN.
                findings.append(variation["title"])
                forced_warning = variation["severity"] == "warning"
                evidence = self.with_evidence(
                    evidence, {"encryption": encryptions}
                )
            if len(ap.get("channels") or []) > 1:
                findings.append("Multiple channels")
            if findings:
                score = self.score_wifi_ap_profile(
                    ap, findings, signal_max, encryptions
                )
                severity = (
                    "warning"
                    if forced_warning
                    else self.severity_for_score(score)
                )
                reports.append(
                    self.report(
                        timestamp,
                        severity,
                        "wifi",
                        "wifi_ap_profile",
                        "Wi-Fi access point profile",
                        self.wifi_ap_profile_summary(ap, findings, signal_max),
                        self.with_evidence(evidence, {"findings": findings}),
                        score,
                        ap.get("last_seen"),
                        subject=self.wifi_ap_subject(ap),
                    )
                )

        for ssid, ssid_aps in by_ssid.items():
            if ssid == "(blank)" or len(ssid_aps) < int(
                self.config["wifi_many_bssid_count"]
            ):
                continue
            bssids = [ap.get("bssid") for ap in ssid_aps if ap.get("bssid")]
            last_seen_ap = max(
                ssid_aps,
                key=lambda ap: record_time_epoch(ap, "last_seen") or 0,
            )
            vendors = sorted(
                set(
                    ap.get("vendor_name") or ap.get("vendor_prefix") or ""
                    for ap in ssid_aps
                    if ap.get("vendor_name") or ap.get("vendor_prefix")
                )
            )
            encryption = sorted(
                set(
                    value
                    for ap in ssid_aps
                    for value in self.normalized_wifi_encryption_values(
                        ap.get("encryption") or []
                    )
                    if value
                )
            )
            findings = ["Multiple BSSIDs"]
            if any(
                "locally administered" in vendor.lower() for vendor in vendors
            ):
                findings.append("Locally administered/randomized BSSIDs")
            score = self.score_wifi_ssid_profile(
                ssid_aps, bssids, vendors, encryption
            )
            reports.append(
                self.report(
                    timestamp,
                    self.severity_for_score(score),
                    "wifi",
                    "wifi_ssid_profile",
                    "Wi-Fi SSID profile",
                    self.wifi_ssid_profile_summary(
                        ssid, bssids, vendors, encryption
                    ),
                    {
                        "ssid": ssid,
                        "findings": findings,
                        "bssids": bssids,
                        "channels": sorted(
                            set(
                                v
                                for ap in ssid_aps
                                for v in (ap.get("channels") or [])
                            )
                        ),
                        "vendors": vendors,
                        "encryption": encryption,
                    },
                    score,
                    last_seen_ap.get("last_seen"),
                    subject="{} - {} BSSIDs".format(ssid, len(bssids)),
                )
            )
        return reports

    def score_wifi_ap_profile(self, ap, findings, signal_max, encryptions):
        """Return 0-100 attention score for one Wi-Fi AP/BSSID profile.

        Wi-Fi AP score combines novelty, proximity, security posture, radio
        drift, and persistence. It is intentionally not an "evil twin" score:
        normal strong home APs may rank high as important context, while weak
        security or security drift can independently push severity to warning.
        """
        score = 0
        # New APs deserve attention, but not as much as weak security or very
        # strong physical proximity.
        if "New access point" in findings:
            score += 25
        # Stronger RSSI means the AP is likely nearby. Very strong APs are
        # pushed up because they are physically relevant to the observer.
        if signal_max is not None:
            if signal_max >= -25:
                score += 45
            elif signal_max >= -40:
                score += 35
            elif signal_max >= -55:
                score += 20
            elif signal_max >= -70:
                score += 10
        values = set(encryptions or [])
        # Weak security dominates AP score. Meaningful encryption variation is
        # also important; generic WPA2/WPA3 parser detail is filtered earlier.
        if values & {"open", "WEP/unknown", "WPA"}:
            score += 50
        elif "Wi-Fi AP encryption varied" in findings:
            score += 35
        elif "Wi-Fi AP security detail varied" in findings:
            score += 20
        # A BSSID appearing on multiple channels is unusual enough to note, but
        # not enough by itself to make a high-priority report.
        if "Multiple channels" in findings:
            score += 15
        active = bool(ap.get("active_session"))
        if active:
            score += 10
        # APs continuously observed for hours are useful context and should
        # sort above brief appearances with the same other findings.
        longest = self.longest_session_seconds(self.device_sessions(ap))
        if longest >= 8 * 3600:
            score += 25
        elif longest >= 4 * 3600:
            score += 15
        return min(score, 100)

    def score_wifi_ssid_profile(self, ssid_aps, bssids, vendors, encryption):
        """Return 0-100 attention score for an SSID-level Wi-Fi profile.

        SSID score is about network-name behavior, not one radio. Multiple
        BSSIDs are normal for mesh/extender systems, so same-vendor/same-security
        SSIDs stay moderate. Scores rise when there are many BSSIDs, vendor
        diversity, locally administered/randomized BSSIDs, mixed security, broad
        channel/band spread, or a very strong member.
        """
        score = 0
        count = len(bssids)
        # More BSSIDs means more network surface, but this is intentionally
        # moderate so normal multi-band mesh systems do not look alarming.
        if count >= 6:
            score += 30
        elif count >= 3:
            score += 20
        elif count >= 2:
            score += 10
        # Multiple vendors for one SSID is more suspicious than same-vendor
        # multi-BSSID behavior.
        if len(vendors) > 1:
            score += 25
        # Locally administered/randomized BSSIDs are worth surfacing for SSIDs,
        # especially when combined with many BSSIDs or vendor diversity.
        if any("locally administered" in vendor.lower() for vendor in vendors):
            score += 15
        values = set(encryption or [])
        # Mixed security on one SSID is a higher-value signal than uniform WPA2.
        if values & {"open", "WEP/unknown", "WPA"} and len(values) > 1:
            score += 35
        elif len(values) > 1:
            score += 20
        channels = sorted(
            {
                str(channel)
                for ap in ssid_aps
                for channel in (ap.get("channels") or [])
            }
        )
        bands = {self.band_for_channel(channel) for channel in channels}
        bands.discard("")
        # A spread across bands/channels is normal for mesh, but helps rank the
        # SSID profile when combined with other signals.
        if len(bands) > 1:
            score += 15
        elif len(channels) > 1:
            score += 10
        strongest = max(
            (
                self.to_number(ap.get("signal_max"))
                for ap in ssid_aps
                if self.to_number(ap.get("signal_max")) is not None
            ),
            default=None,
        )
        # Very strong members make the SSID physically relevant nearby.
        if strongest is not None:
            if strongest >= -40:
                score += 25
            elif strongest >= -55:
                score += 15
        return min(score, 100)

    def wifi_client_reports(self, clients, timestamp):
        """Summarize monitor-mode client/probe/deauth activity when present."""
        reports = []
        for client in clients:
            # These rows are sourced to wifi_monitor because managed Wi-Fi scan
            # does not observe clients, probes, or disconnect management frames.
            evidence = self.wifi_client_evidence(client)
            total_monitor = sum(
                int(client.get(key) or 0)
                for key in (
                    "probe_count",
                    "association_count",
                    "deauth_count",
                    "disassoc_count",
                )
            )
            mac = client.get("mac") or "unknown"
            if int(client.get("probe_count") or 0) >= int(
                self.config["wifi_monitor_event_count"]
            ):
                reports.append(
                    self.report(
                        timestamp,
                        "info",
                        "wifi_monitor",
                        "wifi_client_probe_activity",
                        "Wi-Fi client probe activity in report window",
                        "{} sent {} probe request(s)".format(
                            mac, client.get("probe_count")
                        ),
                        evidence,
                        62,
                        client.get("last_seen"),
                    )
                )
            if int(client.get("deauth_count") or 0) or int(
                client.get("disassoc_count") or 0
            ):
                reports.append(
                    self.report(
                        timestamp,
                        "warning",
                        "wifi_monitor",
                        "wifi_client_disconnect_activity",
                        "Wi-Fi disconnect activity in report window",
                        "{} had deauth={} disassoc={}".format(
                            mac,
                            client.get("deauth_count") or 0,
                            client.get("disassoc_count") or 0,
                        ),
                        evidence,
                        80,
                        client.get("last_seen"),
                    )
                )
            if total_monitor and self.is_new_recent(client, timestamp):
                reports.append(
                    self.report(
                        timestamp,
                        "info",
                        "wifi_monitor",
                        "wifi_client_new_recent",
                        "New Wi-Fi client activity",
                        "{} was first seen recently at {}".format(
                            mac,
                            self.display_time(client, "first_seen")
                            or "unknown time",
                        ),
                        evidence,
                        55,
                        client.get("last_seen"),
                    )
                )
        return reports

    def report(
        self,
        timestamp,
        severity,
        source,
        report_type,
        title,
        summary,
        evidence,
        score,
        last_seen,
        subject="",
    ):
        """Build one normalized report row."""
        self._counter += 1
        last_seen_epoch = record_time_epoch(evidence or {}, "last_seen")
        last_seen_display = (
            format_epoch(last_seen_epoch)
            if last_seen_epoch is not None
            else last_seen or ""
        )
        return {
            "id": "{}-{}".format(timestamp, self._counter),
            "timestamp": timestamp,
            "timestamp_epoch": self._generated_at_epoch
            or timestamp_epoch(timestamp),
            "severity": severity,
            "source": source,
            "type": report_type,
            "title": title,
            "subject": subject
            or self.default_report_subject(source, evidence or {}),
            "summary": summary,
            "evidence": evidence or {},
            "score": score,
            "last_seen": last_seen_display,
            "last_seen_epoch": last_seen_epoch,
        }

    def default_report_subject(self, source, evidence):
        """Return a concise subject for report rows without custom subjects."""
        if source == "wifi":
            if evidence.get("ssid") and evidence.get("bssid"):
                return "{} - {}".format(evidence["ssid"], evidence["bssid"])
            if evidence.get("ssid"):
                return evidence["ssid"]
            if evidence.get("bssid"):
                return evidence["bssid"]
        if source == "wifi_monitor" and evidence.get("mac"):
            return evidence["mac"]
        return ""

    def ble_evidence(
        self,
        device,
        sessions,
        days,
        hours,
        start_hours,
        spans,
    ):
        """Return compact Bluetooth report evidence."""
        return {
            "mac": device.get("mac") or "",
            "names": device.get("names") or [],
            "manufacturer": device.get("manufacturer_name")
            or device.get("manufacturer")
            or device.get("vendor_name")
            or "",
            "first_seen": self.display_time(device, "first_seen"),
            "first_seen_epoch": record_time_epoch(device, "first_seen"),
            "last_seen": self.display_time(device, "last_seen"),
            "last_seen_epoch": record_time_epoch(device, "last_seen"),
            "sessions": len(sessions),
            "active_session": bool(device.get("active_session")),
            "days_seen": days,
            "presence_hours": self.hour_labels(hours),
            "common_hours": self.common_hours(hours),
            "common_start_hours": self.common_hours(start_hours),
            "presence_spans": spans,
            "signal_max": device.get("signal_max"),
            "signal_min": device.get("signal_min"),
        }

    def wifi_ap_evidence(self, ap):
        """Return compact AP report evidence."""
        sessions = self.sessions_in_window(self.device_sessions(ap))
        hours = self.session_hour_counts(sessions)
        start_hours = self.hour_counts(
            [record_time_epoch(session, "start") for session in sessions]
        )
        return {
            "ssid": ap.get("ssid") or "",
            "bssid": ap.get("bssid") or "",
            "vendor": ap.get("vendor_name") or ap.get("vendor_prefix") or "",
            "first_seen": self.display_time(ap, "first_seen"),
            "first_seen_epoch": record_time_epoch(ap, "first_seen"),
            "last_seen": self.display_time(ap, "last_seen"),
            "last_seen_epoch": record_time_epoch(ap, "last_seen"),
            "channels": ap.get("channels") or [],
            "encryption": ap.get("encryption") or [],
            "signal_max": ap.get("signal_max"),
            "sessions": len(sessions),
            "active_session": bool(ap.get("active_session")),
            "days_seen": self.presence_days(sessions),
            "presence_hours": self.hour_labels(hours),
            "common_hours": self.common_hours(hours),
            "common_start_hours": self.common_hours(start_hours),
            "presence_spans": self.session_spans(sessions),
        }

    def wifi_client_evidence(self, client):
        """Return compact Wi-Fi client report evidence."""
        return {
            "mac": client.get("mac") or "",
            "vendor": client.get("vendor_name")
            or client.get("vendor_prefix")
            or "",
            "first_seen": self.display_time(client, "first_seen"),
            "first_seen_epoch": record_time_epoch(client, "first_seen"),
            "last_seen": self.display_time(client, "last_seen"),
            "last_seen_epoch": record_time_epoch(client, "last_seen"),
            "probed_ssids": client.get("ssids") or [],
            "probe_count": client.get("probe_count") or 0,
            "association_count": client.get("association_count") or 0,
            "deauth_count": client.get("deauth_count") or 0,
            "disassoc_count": client.get("disassoc_count") or 0,
        }

    def with_evidence(self, evidence, extra):
        """Return a report evidence copy with normalized rule-specific fields."""
        merged = dict(evidence or {})
        merged.update(extra or {})
        return merged

    def display_time(self, record, field):
        """Format a history timestamp from its epoch companion when present."""
        epoch = record_time_epoch(record, field)
        if epoch is not None:
            return format_epoch(epoch)
        return (record or {}).get(field) or ""

    def device_sessions(self, device):
        """Return closed sessions plus the current open session, if any."""
        sessions = list((device or {}).get("sessions") or [])
        active = (device or {}).get("active_session")
        if isinstance(active, dict):
            active_copy = dict(active)
            active_copy["active"] = True
            sessions.append(active_copy)
        if not sessions and (device or {}).get("first_seen"):
            # Older summaries did not store explicit sessions. Keep reports
            # useful by exposing one approximate span from first_seen to last_seen.
            sessions.append(
                {
                    "start": device.get("first_seen"),
                    "end": device.get("last_seen") or device.get("first_seen"),
                    "duration_sec": None,
                    "approximate": True,
                }
            )
        return sessions

    def sessions_in_window(self, sessions):
        """Return BLE sessions that overlap the selected report window.

        The returned copy clips duration_sec to the selected window. That keeps a
        last-24-hours report from counting hours that happened before the window.
        """
        since = window_since_epoch(self.window_days)
        if since is None:
            return [
                self.session_with_duration(session)
                for session in sessions or []
            ]
        output = []
        for session in sessions or []:
            clipped = self.clip_session_to_window(session, since)
            if clipped:
                output.append(clipped)
        return output

    def clip_session_to_window(self, session, since):
        """Return a session copy if any observed portion overlaps the window."""
        start, end = self.session_bounds(session)
        if start is None or end is None or end < since:
            return None
        clipped = dict(session)
        clipped_start = max(start, since)
        clipped["duration_sec"] = max(0, int(end - clipped_start))
        clipped["window_clipped"] = start < since
        return clipped

    def session_with_duration(self, session):
        """Return a session copy with duration filled when older data omitted it."""
        copied = dict(session or {})
        if copied.get("duration_sec") is None:
            start, end = self.session_bounds(copied)
            if start is not None and end is not None:
                copied["duration_sec"] = max(0, int(end - start))
        return copied

    def presence_days(self, sessions):
        """Return weekday labels for every day overlapped by BLE sessions."""
        days = []
        seen = set()
        for session in sessions or []:
            for day in self.session_days(session):
                if day not in seen:
                    seen.add(day)
                    days.append(day)
        return days

    def session_days(self, session):
        """Return local weekday labels touched by one session."""
        start, end = self.session_bounds(session)
        if start is None or end is None:
            return []
        days = []
        current = datetime.fromtimestamp(start).replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )
        final = datetime.fromtimestamp(end).replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )
        while current <= final:
            days.append(current.strftime("%a"))
            current = current + self.one_day()
        return days

    def session_hour_counts(self, sessions):
        """Count each local hour overlapped by BLE presence sessions."""
        counts = Counter()
        for session in sessions or []:
            start, end = self.session_bounds(session)
            if start is None or end is None:
                continue
            current = datetime.fromtimestamp(start).replace(
                minute=0,
                second=0,
                microsecond=0,
            )
            final = datetime.fromtimestamp(end).replace(
                minute=0,
                second=0,
                microsecond=0,
            )
            while current <= final:
                counts[current.hour] += 1
                current = current + self.one_hour()
        return counts

    def session_spans(self, sessions, limit=8):
        """Return recent local presence spans for report evidence."""
        spans = []
        sessions = self.merge_overlapping_sessions(sessions)
        ordered = sorted(
            sessions or [],
            key=lambda item: self.session_bounds(item)[1] or 0,
            reverse=True,
        )
        for session in ordered[:limit]:
            span = self.session_span_text(session)
            if span:
                spans.append(span)
        return spans

    def merge_overlapping_sessions(self, sessions):
        """Collapse overlapping sessions before rendering report evidence.

        Device History keeps active sessions separate from closed sessions, and
        randomized BLE reports group multiple addresses together. Both cases can
        otherwise produce several evidence spans with the same end time. Reports
        should show the covered presence intervals, not every overlapping
        internal session fragment.
        """
        normalized = []
        for session in sessions or []:
            start, end = self.session_bounds(session)
            if start is None or end is None:
                continue
            item = dict(session)
            item["_start_epoch"] = start
            item["_end_epoch"] = end
            normalized.append(item)
        normalized.sort(
            key=lambda item: (item["_start_epoch"], item["_end_epoch"])
        )

        merged = []
        for session in normalized:
            if not merged or session["_start_epoch"] > merged[-1]["_end_epoch"]:
                merged.append(session)
                continue
            current = merged[-1]
            if session["_end_epoch"] > current["_end_epoch"]:
                current["_end_epoch"] = session["_end_epoch"]
                current["end_epoch"] = session["_end_epoch"]
                current["end"] = format_epoch(session["_end_epoch"])
            current["active"] = bool(
                current.get("active") or session.get("active")
            )
            current["approximate"] = bool(
                current.get("approximate") or session.get("approximate")
            )
        for session in merged:
            session.pop("_start_epoch", None)
            session.pop("_end_epoch", None)
        return merged

    def session_span_text(self, session):
        """Format one BLE session as a compact local date/time span."""
        start, end = self.session_bounds(session)
        if start is None or end is None:
            return ""
        start_dt = datetime.fromtimestamp(start)
        end_dt = datetime.fromtimestamp(end)
        if start_dt.date() == end_dt.date():
            text = "{} {}-{}".format(
                start_dt.strftime("%a"),
                start_dt.strftime("%H:%M"),
                end_dt.strftime("%H:%M"),
            )
        else:
            text = "{}-{}".format(
                start_dt.strftime("%a %H:%M"),
                end_dt.strftime("%a %H:%M"),
            )
        if session.get("active"):
            text += " active"
        if session.get("approximate"):
            text += " approximate"
        return text

    def session_bounds(self, session):
        """Return epoch start/end for one session, tolerating missing end."""
        start = record_time_epoch(session, "start")
        end = record_time_epoch(session, "end") or start
        if start is None or end is None:
            return None, None
        if end < start:
            end = start
        return start, end

    def one_day(self):
        """Return one day as a timedelta for Python 3.6 compatibility."""
        return timedelta(days=1)

    def one_hour(self):
        """Return one hour as a timedelta for Python 3.6 compatibility."""
        return timedelta(hours=1)

    def is_new_recent(self, item, timestamp):
        """Return True when first_seen is recent relative to report generation.

        The selected report window can be 7 or 30 days, so using it as the
        definition of "new" makes stable devices look new after a rebuild. Keep
        "new" tied to a short explicit threshold instead.
        """
        threshold = float(self.config.get("new_device_window_sec", 3600))
        if threshold <= 0:
            return False
        first = record_time_epoch(item, "first_seen")
        generated = self._generated_at_epoch or timestamp_epoch(timestamp)
        generated = generated or now_epoch()
        return first is not None and 0 <= generated - first <= threshold

    def normalized_wifi_encryption_values(self, values):
        """Collapse equivalent Wi-Fi security labels before report rules."""
        normalized = []
        for value in values or []:
            item = self.normalize_wifi_encryption(value)
            if item and item not in normalized:
                normalized.append(item)
        return normalized

    def normalize_wifi_encryption(self, value):
        """Match Device History's Wi-Fi encryption canonicalization."""
        text = str(value or "").strip()
        if not text:
            return ""
        lowered = text.lower()
        if lowered in ("open", "none"):
            return "open"
        if "wep" in lowered:
            return "WEP/unknown"
        parts = set(
            part.strip().upper()
            for part in text.replace(",", "/").split("/")
            if part.strip()
        )
        if "SAE" in parts or "WPA3" in parts:
            return "WPA2/WPA3" if "WPA2" in parts or "RSN" in parts else "WPA3"
        if "WPA2" in parts or "RSN" in parts:
            return "WPA2"
        if "WPA" in parts:
            return "WPA"
        return text

    def wifi_encryption_variation(self, encryptions):
        """Classify Wi-Fi encryption variation after parser normalization.

        WPA2 and WPA2/WPA3 frequently differ only because one scan path parsed
        SAE detail and another saw a generic RSN block. Suppress that parser
        detail drift; warn only on real weak/strong mixtures.
        """
        values = set(encryptions or [])
        if len(values) <= 1:
            return None
        if values <= {"WPA2", "WPA2/WPA3"}:
            return None
        weak = {"open", "WEP/unknown", "WPA"}
        if values & weak:
            return {
                "severity": "warning",
                "type": "wifi_ap_encryption_varied",
                "title": "Wi-Fi AP encryption varied",
                "score": 82,
            }
        return {
            "severity": "info",
            "type": "wifi_ap_security_detail_varied",
            "title": "Wi-Fi AP security detail varied",
            "score": 45,
        }

    def hour_counts(self, timestamps):
        """Count local hour buckets for recurring-presence summaries."""
        counts = Counter()
        for value in timestamps:
            epoch = timestamp_epoch(value)
            if epoch is None:
                continue
            counts[datetime.fromtimestamp(epoch).hour] += 1
        return counts

    def common_hours(self, counts):
        """Return compact labels for the most common local hour buckets."""
        return self.hour_range_labels(
            [hour for hour, _count in counts.most_common(3)]
        )

    def hour_labels(self, counts):
        """Return compact local hour ranges touched by presence sessions."""
        return self.hour_range_labels(counts.keys())

    def hour_range_labels(self, hours):
        """Collapse adjacent hour buckets into readable local ranges.

        Presence summaries count activity by hour bucket. Showing every bucket
        separately is noisy for long sessions, so adjacent buckets such as
        04:00-05:00, 05:00-06:00, 06:00-07:00 are rendered as 04:00-07:00.
        """
        normalized = sorted(
            {int(hour) % 24 for hour in hours if hour is not None}
        )
        if not normalized:
            return []

        ranges = []
        start = previous = normalized[0]
        for hour in normalized[1:]:
            if hour == previous + 1:
                previous = hour
                continue
            ranges.append((start, previous))
            start = previous = hour
        ranges.append((start, previous))

        # If activity crosses midnight, merge the leading 00:00 run with the
        # trailing 23:00 run into one wraparound range, e.g. 22:00-02:00.
        if len(ranges) > 1 and ranges[0][0] == 0 and ranges[-1][1] == 23:
            first = ranges.pop(0)
            last = ranges.pop()
            ranges.append((last[0], first[1]))

        return [
            "{:02d}:00-{:02d}:00".format(start, (end + 1) % 24)
            for start, end in ranges
        ]

    def common_hour_text(self, counts):
        """Return a readable phrase for the most common activity hours."""
        hours = self.common_hours(counts)
        return ", ".join(hours) if hours else "no consistent hour"

    def day_name(self, timestamp):
        """Return a local weekday label for one timestamp."""
        epoch = timestamp_epoch(timestamp)
        if epoch is None:
            return ""
        return datetime.fromtimestamp(epoch).strftime("%a")

    def bluetooth_label(self, device, mac):
        """Prefer a known name, then manufacturer, then MAC."""
        names = [
            name
            for name in (device.get("names") or [])
            if self.valid_bluetooth_name(name)
        ]
        if names:
            return "{} ({})".format(", ".join(names[:2]), mac)
        manufacturer = (
            device.get("manufacturer_name")
            or device.get("manufacturer")
            or device.get("vendor_name")
        )
        if manufacturer:
            return "{} ({})".format(manufacturer, mac)
        return mac

    def is_private_ble_candidate(self, device, mac, sessions):
        """Return True for BLE records that look like privacy-address churn.

        BLE devices commonly rotate private addresses while still advertising a
        manufacturer ID. Without names, identity reads, Classic data, or
        recurring sessions, those addresses are better reported as a
        manufacturer/address cluster than as many separate physical devices.
        """
        transports = set(device.get("transports") or [])
        names = [
            name
            for name in (device.get("names") or [])
            if self.valid_bluetooth_name(name)
        ]
        has_identity = any(
            device.get(field)
            for field in (
                "model_number",
                "firmware_revision",
                "hardware_revision",
                "software_revision",
                "classic_class",
            )
        )
        if names or has_identity or "classic" in transports:
            return False
        if len(sessions or []) > 1:
            return False
        return self.is_ble_private_address(mac) or bool(
            device.get("manufacturer_name") or device.get("manufacturer")
        )

    def valid_bluetooth_name(self, value):
        """Reject command diagnostics that older summaries may contain."""
        text = str(value or "").strip()
        if not text:
            return False
        lowered = text.lower()
        bad_fragments = (
            "command '['",
            "timed out after",
            "operation already in progress",
            "failed to connect",
            "input/output error",
        )
        return not any(fragment in lowered for fragment in bad_fragments)

    def is_ble_private_address(self, mac):
        """Detect BLE random/private-looking addresses from the first octet.

        BLE address type is not always preserved by Linux user-space APIs, but
        the top bits of the displayed address are still useful weak evidence.
        This is intentionally only one signal; manufacturer/name/session context
        decides whether a report is grouped.
        """
        try:
            first_octet = int(str(mac).split(":", 1)[0], 16)
        except (TypeError, ValueError):
            return False
        return (first_octet & 0xC0) in (0x00, 0x40, 0xC0) or bool(
            first_octet & 0x02
        )

    def ap_label(self, ap):
        """Return a concise AP label."""
        ssid = ap.get("ssid") or "(blank)"
        bssid = ap.get("bssid") or "unknown"
        return "{} ({})".format(ssid, bssid)

    def duration_text(self, seconds):
        """Format seconds as an approximate human duration."""
        seconds = int(seconds or 0)
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        if hours and minutes:
            return "{}h {}m".format(hours, minutes)
        if hours:
            return "{}h".format(hours)
        return "{}m".format(max(1, minutes))

    def longest_session_seconds(self, sessions):
        """Return longest observed session duration for scoring."""
        return max(
            [
                float(
                    self.session_with_duration(session).get("duration_sec") or 0
                )
                for session in sessions or []
            ]
            or [0]
        )

    def band_for_channel(self, channel):
        """Return a coarse Wi-Fi band label for report scoring."""
        try:
            number = int(str(channel).strip())
        except (TypeError, ValueError):
            return ""
        if 1 <= number <= 14:
            return "2.4"
        if number >= 30:
            return "5"
        return ""

    def severity_for_score(self, score):
        """Promote high-attention profiles to warning severity.

        A warning here means "high attention" rather than confirmed malicious
        behavior. Specific security rules can still force warning before this
        helper is used.
        """
        return "warning" if int(score or 0) >= 75 else "info"

    def counts(self, reports):
        """Compute report counters for the UI."""
        return {
            "total": len(reports),
            "warning": sum(
                1 for item in reports if item.get("severity") == "warning"
            ),
            "info": sum(
                1 for item in reports if item.get("severity") == "info"
            ),
        }

    def severity_rank(self, severity):
        """Sort warnings before informational reports."""
        return {"warning": 2, "error": 3, "alert": 3, "info": 1}.get(
            severity, 0
        )

    def to_number(self, value):
        """Parse numeric fields while tolerating blanks."""
        try:
            return float(value)
        except (TypeError, ValueError):
            return None


def save_reports(path, reports):
    """Persist generated reports for cheap startup/page loads."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(reports, fh, indent=2, sort_keys=True)
