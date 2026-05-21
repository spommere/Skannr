"""Longer-window report generation from materialized Device History.

Insights are meant to move quickly. Reports are the slower summary layer for
questions such as "what recurring Bluetooth presence happened this week?" or
"which APs/clients were notable during this retained window?"
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta
import json
import os
import time

from bus import utc_now
from log_utils import utc_epoch, window_metadata, window_since_epoch


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

    def build(self, history):
        """Return a report bundle for Bluetooth, Wi-Fi scan, and monitor data."""
        generated_at = utc_now()
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
                item.get("last_seen") or "",
            ),
            reverse=True,
        )
        return {
            "generated_at": generated_at,
            "history_generated_at": (history or {}).get("generated_at"),
            "window": window_metadata(self.window_days),
            "reports": reports,
            "counts": self.counts(reports),
        }

    def ble_reports(self, devices, timestamp):
        """Summarize recurring, long, strong, and new Bluetooth presence."""
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
            label = context["label"]
            sessions = context["sessions"]
            days = context["days"]
            hours = context["hours"]
            start_hours = context["start_hours"]
            longest = context["longest"]
            signal_max = context["signal_max"]
            spans = context["presence_spans"]
            evidence = self.ble_evidence(
                device,
                sessions,
                days,
                hours,
                start_hours,
                spans,
            )
            private_grouped = mac in grouped_private_macs

            if sessions and len(days) >= int(
                self.config["ble_recurring_min_days"]
            ):
                # This summarizes repeated presence by day/hour, which is more
                # useful for longitudinal review than a fast-scrolling insight.
                hour_text = self.common_hour_text(hours)
                reports.append(
                    self.report(
                        timestamp,
                        "info",
                        "bluetooth",
                        "ble_recurring_presence",
                        "Recurring Bluetooth presence",
                        "{} was present on {} day(s), most often during {}".format(
                            label, len(days), hour_text
                        ),
                        evidence,
                        65 + min(len(days), 14),
                        device.get("last_seen"),
                    )
                )

            if longest >= float(self.config["ble_long_presence_sec"]):
                reports.append(
                    self.report(
                        timestamp,
                        "warning",
                        "bluetooth",
                        "ble_long_presence",
                        "Long Bluetooth presence",
                        "{} stayed nearby for about {}".format(
                            label, self.duration_text(longest)
                        ),
                        evidence,
                        82,
                        device.get("last_seen"),
                    )
                )

            if (
                not private_grouped
                and signal_max is not None
                and signal_max >= float(self.config["ble_strong_rssi"])
            ):
                # Avoid separate strong-signal rows for addresses already folded
                # into a randomized/private-address cluster.
                reports.append(
                    self.report(
                        timestamp,
                        "info",
                        "bluetooth",
                        "ble_strong_presence",
                        "Strong Bluetooth signal in report window",
                        "{} reached {} dBm".format(label, int(signal_max)),
                        evidence,
                        55,
                        device.get("last_seen"),
                    )
                )

            if (
                self.is_new_recent(device, timestamp)
                and not context["private_candidate"]
            ):
                # New private/randomized addresses are noisy, so only named or
                # static-looking devices get individual "new" report rows.
                reports.append(
                    self.report(
                        timestamp,
                        "info",
                        "bluetooth",
                        "ble_new_recent",
                        "New named/static Bluetooth device",
                        "{} was first seen recently at {}".format(
                            label, device.get("first_seen") or "unknown time"
                        ),
                        evidence,
                        58,
                        device.get("last_seen"),
                    )
                )
        return reports

    def ble_context(self, device):
        """Precompute Bluetooth fields used by several report policies."""
        mac = device.get("mac") or "unknown"
        sessions = self.sessions_in_window(self.device_sessions(device))
        days = self.presence_days(sessions)
        hours = self.session_hour_counts(sessions)
        start_hours = self.hour_counts(
            [session.get("start") for session in sessions]
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
        spans = []
        signal_values = []
        for member in members:
            hour_counts.update(member["hours"])
            start_hour_counts.update(member["start_hours"])
            spans.extend(member["presence_spans"])
            value = member["signal_max"]
            if value is not None:
                signal_values.append(value)
        signal_max = max(signal_values) if signal_values else None
        last_seen = max(
            (member["device"].get("last_seen") or "" for member in members),
            default="",
        )
        evidence = {
            "manufacturer": manufacturer,
            "address_count": len(members),
            "active_addresses": len(active),
            "sample_macs": macs[:12],
            "days_seen": all_days,
            "presence_hours": self.hour_labels(hour_counts),
            "common_hours": self.common_hours(hour_counts),
            "common_start_hours": self.common_hours(start_hour_counts),
            "presence_spans": spans[:8],
            "signal_max": int(signal_max) if signal_max is not None else "",
            "last_seen": last_seen,
        }
        signal_text = (
            "; strongest {} dBm".format(int(signal_max))
            if signal_max is not None
            else ""
        )
        return self.report(
            timestamp,
            "info",
            "bluetooth",
            "ble_private_address_cluster",
            "Bluetooth randomized/private address cluster",
            "{} had {} unnamed BLE address(es) in the report window{}; most often {}".format(
                manufacturer,
                len(members),
                signal_text,
                self.common_hour_text(hour_counts),
            ),
            evidence,
            68 + min(len(members), 20),
            last_seen,
        )

    def wifi_ap_reports(self, aps, timestamp):
        """Summarize AP changes and longer-window Wi-Fi scan patterns."""
        reports = []
        by_ssid = defaultdict(list)
        for ap in aps:
            by_ssid[ap.get("ssid") or "(blank)"].append(ap)
            label = self.ap_label(ap)
            signal_max = self.to_number(ap.get("signal_max"))
            evidence = self.wifi_ap_evidence(ap)
            if self.is_new_recent(ap, timestamp):
                reports.append(
                    self.report(
                        timestamp,
                        "info",
                        "wifi",
                        "wifi_ap_new_recent",
                        "New Wi-Fi access point",
                        "{} was first seen recently at {}".format(
                            label, ap.get("first_seen") or "unknown time"
                        ),
                        evidence,
                        55,
                        ap.get("last_seen"),
                    )
                )
            if signal_max is not None and signal_max >= float(
                self.config["wifi_strong_rssi"]
            ):
                reports.append(
                    self.report(
                        timestamp,
                        "info",
                        "wifi",
                        "wifi_ap_strong_in_window",
                        "Strong Wi-Fi access point in report window",
                        "{} reached {} dBm".format(label, int(signal_max)),
                        evidence,
                        50,
                        ap.get("last_seen"),
                    )
                )
            encryptions = self.normalized_wifi_encryption_values(
                ap.get("encryption") or []
            )
            variation = self.wifi_encryption_variation(encryptions)
            if variation:
                # Report security drift only after canonicalization suppresses
                # parser wording differences such as WPA2 versus WPA2/RSN.
                reports.append(
                    self.report(
                        timestamp,
                        variation["severity"],
                        "wifi",
                        variation["type"],
                        variation["title"],
                        "{} used encryption values {}".format(
                            label, ", ".join(encryptions)
                        ),
                        self.with_evidence(
                            evidence, {"encryption": encryptions}
                        ),
                        variation["score"],
                        ap.get("last_seen"),
                    )
                )
            if len(ap.get("channels") or []) > 1:
                reports.append(
                    self.report(
                        timestamp,
                        "info",
                        "wifi",
                        "wifi_ap_channel_varied",
                        "Wi-Fi AP seen on multiple channels",
                        "{} was seen on channels {}".format(
                            label,
                            ", ".join(
                                str(item) for item in ap.get("channels") or []
                            ),
                        ),
                        evidence,
                        45,
                        ap.get("last_seen"),
                    )
                )

        for ssid, ssid_aps in by_ssid.items():
            if ssid == "(blank)" or len(ssid_aps) < int(
                self.config["wifi_many_bssid_count"]
            ):
                continue
            bssids = [ap.get("bssid") for ap in ssid_aps if ap.get("bssid")]
            reports.append(
                self.report(
                    timestamp,
                    "info",
                    "wifi",
                    "wifi_ssid_multiple_bssids_report",
                    "SSID has multiple BSSIDs in report window",
                    "'{}' was seen on {} BSSIDs".format(ssid, len(bssids)),
                    {
                        "ssid": ssid,
                        "bssids": bssids,
                        "channels": sorted(
                            set(
                                v
                                for ap in ssid_aps
                                for v in (ap.get("channels") or [])
                            )
                        ),
                    },
                    48,
                    max(
                        (ap.get("last_seen") or "" for ap in ssid_aps),
                        default="",
                    ),
                )
            )
        return reports

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
                            mac, client.get("first_seen") or "unknown time"
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
    ):
        """Build one normalized report row."""
        self._counter += 1
        return {
            "id": "{}-{}".format(timestamp, self._counter),
            "timestamp": timestamp,
            "severity": severity,
            "source": source,
            "type": report_type,
            "title": title,
            "summary": summary,
            "evidence": evidence or {},
            "score": score,
            "last_seen": last_seen or "",
        }

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
            "first_seen": device.get("first_seen") or "",
            "last_seen": device.get("last_seen") or "",
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
            [session.get("start") for session in sessions]
        )
        return {
            "ssid": ap.get("ssid") or "",
            "bssid": ap.get("bssid") or "",
            "vendor": ap.get("vendor_name") or ap.get("vendor_prefix") or "",
            "first_seen": ap.get("first_seen") or "",
            "last_seen": ap.get("last_seen") or "",
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
            "first_seen": client.get("first_seen") or "",
            "last_seen": client.get("last_seen") or "",
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
        start = utc_epoch((session or {}).get("start"))
        end = utc_epoch(
            (session or {}).get("end") or (session or {}).get("start")
        )
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
            start = utc_epoch(copied.get("start"))
            end = utc_epoch(copied.get("end") or copied.get("start"))
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
        ordered = sorted(
            sessions or [],
            key=lambda item: utc_epoch(item.get("end") or item.get("start"))
            or 0,
            reverse=True,
        )
        for session in ordered[:limit]:
            span = self.session_span_text(session)
            if span:
                spans.append(span)
        return spans

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
        start = utc_epoch((session or {}).get("start"))
        end = utc_epoch(
            (session or {}).get("end") or (session or {}).get("start")
        )
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
        first = utc_epoch(item.get("first_seen"))
        generated = utc_epoch(timestamp) or time.time()
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
            epoch = utc_epoch(value)
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
        epoch = utc_epoch(timestamp)
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
