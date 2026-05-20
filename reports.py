from collections import Counter, defaultdict
from datetime import datetime
import json
import os
import time

from bus import utc_now
from log_utils import utc_epoch, window_metadata, window_since_epoch


DEFAULT_REPORT_CONFIG = {
    "ble_long_presence_sec": 3600,
    "ble_recurring_min_days": 2,
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
        wifi = (history or {}).get("wifi") or {}
        bluetooth = (history or {}).get("bluetooth") or (history or {}).get("ble") or {}
        reports = []
        reports.extend(self.ble_reports(bluetooth.get("devices") or [], generated_at))
        reports.extend(self.wifi_ap_reports(wifi.get("access_points") or [], generated_at))
        reports.extend(self.wifi_client_reports(wifi.get("clients") or [], generated_at))
        reports.sort(key=lambda item: (self.severity_rank(item["severity"]), item.get("score", 0), item.get("last_seen") or ""), reverse=True)
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
        for device in devices:
            mac = device.get("mac") or "unknown"
            label = self.bluetooth_label(device, mac)
            sessions = self.sessions_in_window(self.device_sessions(device))
            days = sorted(set(self.day_name(session.get("start")) for session in sessions if session.get("start")))
            hours = self.hour_counts([session.get("start") for session in sessions])
            longest = max([float(session.get("duration_sec") or 0) for session in sessions] or [0])
            signal_max = self.to_number(device.get("signal_max"))
            evidence = self.ble_evidence(device, sessions, days, hours)

            if sessions and len(days) >= int(self.config["ble_recurring_min_days"]):
                hour_text = self.common_hour_text(hours)
                reports.append(self.report(
                    timestamp,
                    "info",
                    "bluetooth",
                    "ble_recurring_presence",
                    "Recurring Bluetooth presence",
                    "{} was seen on {} day(s), most often {}".format(label, len(days), hour_text),
                    evidence,
                    65 + min(len(days), 14),
                    device.get("last_seen"),
                ))

            if longest >= float(self.config["ble_long_presence_sec"]):
                reports.append(self.report(
                    timestamp,
                    "warning",
                    "bluetooth",
                    "ble_long_presence",
                    "Long Bluetooth presence",
                    "{} stayed nearby for about {}".format(label, self.duration_text(longest)),
                    evidence,
                    82,
                    device.get("last_seen"),
                ))

            if signal_max is not None and signal_max >= float(self.config["ble_strong_rssi"]):
                reports.append(self.report(
                    timestamp,
                    "info",
                    "bluetooth",
                    "ble_strong_presence",
                    "Strong Bluetooth signal in report window",
                    "{} reached {} dBm".format(label, int(signal_max)),
                    evidence,
                    55,
                    device.get("last_seen"),
                ))

            if self.is_new_in_window(device):
                reports.append(self.report(
                    timestamp,
                    "info",
                    "bluetooth",
                    "ble_new_in_window",
                    "New Bluetooth device in report window",
                    "{} was first seen {}".format(label, device.get("first_seen") or "during this window"),
                    evidence,
                    58,
                    device.get("last_seen"),
                ))
        return reports

    def wifi_ap_reports(self, aps, timestamp):
        """Summarize AP changes and longer-window Wi-Fi scan patterns."""
        reports = []
        by_ssid = defaultdict(list)
        for ap in aps:
            by_ssid[ap.get("ssid") or "(blank)"].append(ap)
            label = self.ap_label(ap)
            signal_max = self.to_number(ap.get("signal_max"))
            evidence = self.wifi_ap_evidence(ap)
            if self.is_new_in_window(ap):
                reports.append(self.report(
                    timestamp,
                    "info",
                    "wifi",
                    "wifi_ap_new_in_window",
                    "New Wi-Fi access point in report window",
                    "{} was first seen {}".format(label, ap.get("first_seen") or "during this window"),
                    evidence,
                    55,
                    ap.get("last_seen"),
                ))
            if signal_max is not None and signal_max >= float(self.config["wifi_strong_rssi"]):
                reports.append(self.report(
                    timestamp,
                    "info",
                    "wifi",
                    "wifi_ap_strong_in_window",
                    "Strong Wi-Fi access point in report window",
                    "{} reached {} dBm".format(label, int(signal_max)),
                    evidence,
                    50,
                    ap.get("last_seen"),
                ))
            if len(ap.get("encryption") or []) > 1:
                reports.append(self.report(
                    timestamp,
                    "warning",
                    "wifi",
                    "wifi_ap_encryption_varied",
                    "Wi-Fi AP encryption varied",
                    "{} used encryption values {}".format(label, ", ".join(ap.get("encryption") or [])),
                    evidence,
                    82,
                    ap.get("last_seen"),
                ))
            if len(ap.get("channels") or []) > 1:
                reports.append(self.report(
                    timestamp,
                    "info",
                    "wifi",
                    "wifi_ap_channel_varied",
                    "Wi-Fi AP seen on multiple channels",
                    "{} was seen on channels {}".format(label, ", ".join(str(item) for item in ap.get("channels") or [])),
                    evidence,
                    45,
                    ap.get("last_seen"),
                ))

        for ssid, ssid_aps in by_ssid.items():
            if ssid == "(blank)" or len(ssid_aps) < int(self.config["wifi_many_bssid_count"]):
                continue
            bssids = [ap.get("bssid") for ap in ssid_aps if ap.get("bssid")]
            reports.append(self.report(
                timestamp,
                "info",
                "wifi",
                "wifi_ssid_multiple_bssids_report",
                "SSID has multiple BSSIDs in report window",
                "'{}' was seen on {} BSSIDs".format(ssid, len(bssids)),
                {"ssid": ssid, "bssids": bssids, "channels": sorted(set(v for ap in ssid_aps for v in (ap.get("channels") or [])))},
                48,
                max((ap.get("last_seen") or "" for ap in ssid_aps), default=""),
            ))
        return reports

    def wifi_client_reports(self, clients, timestamp):
        """Summarize monitor-mode client/probe/deauth activity when present."""
        reports = []
        for client in clients:
            evidence = self.wifi_client_evidence(client)
            total_monitor = sum(int(client.get(key) or 0) for key in ("probe_count", "association_count", "deauth_count", "disassoc_count"))
            mac = client.get("mac") or "unknown"
            if int(client.get("probe_count") or 0) >= int(self.config["wifi_monitor_event_count"]):
                reports.append(self.report(
                    timestamp,
                    "info",
                    "wifi_monitor",
                    "wifi_client_probe_activity",
                    "Wi-Fi client probe activity in report window",
                    "{} sent {} probe request(s)".format(mac, client.get("probe_count")),
                    evidence,
                    62,
                    client.get("last_seen"),
                ))
            if int(client.get("deauth_count") or 0) or int(client.get("disassoc_count") or 0):
                reports.append(self.report(
                    timestamp,
                    "warning",
                    "wifi_monitor",
                    "wifi_client_disconnect_activity",
                    "Wi-Fi disconnect activity in report window",
                    "{} had deauth={} disassoc={}".format(mac, client.get("deauth_count") or 0, client.get("disassoc_count") or 0),
                    evidence,
                    80,
                    client.get("last_seen"),
                ))
            if total_monitor and self.is_new_in_window(client):
                reports.append(self.report(
                    timestamp,
                    "info",
                    "wifi_monitor",
                    "wifi_client_new_in_window",
                    "New Wi-Fi client activity in report window",
                    "{} was first seen {}".format(mac, client.get("first_seen") or "during this window"),
                    evidence,
                    55,
                    client.get("last_seen"),
                ))
        return reports

    def report(self, timestamp, severity, source, report_type, title, summary, evidence, score, last_seen):
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

    def ble_evidence(self, device, sessions, days, hours):
        """Return compact Bluetooth report evidence."""
        return {
            "mac": device.get("mac") or "",
            "names": device.get("names") or [],
            "manufacturer": device.get("manufacturer_name") or device.get("manufacturer") or device.get("vendor_name") or "",
            "first_seen": device.get("first_seen") or "",
            "last_seen": device.get("last_seen") or "",
            "sessions": len(sessions),
            "active_session": bool(device.get("active_session")),
            "days_seen": days,
            "common_hours": self.common_hours(hours),
            "signal_max": device.get("signal_max"),
            "signal_min": device.get("signal_min"),
        }

    def wifi_ap_evidence(self, ap):
        """Return compact AP report evidence."""
        return {
            "ssid": ap.get("ssid") or "",
            "bssid": ap.get("bssid") or "",
            "vendor": ap.get("vendor_name") or ap.get("vendor_prefix") or "",
            "first_seen": ap.get("first_seen") or "",
            "last_seen": ap.get("last_seen") or "",
            "channels": ap.get("channels") or [],
            "encryption": ap.get("encryption") or [],
            "signal_max": ap.get("signal_max"),
        }

    def wifi_client_evidence(self, client):
        """Return compact Wi-Fi client report evidence."""
        return {
            "mac": client.get("mac") or "",
            "vendor": client.get("vendor_name") or client.get("vendor_prefix") or "",
            "first_seen": client.get("first_seen") or "",
            "last_seen": client.get("last_seen") or "",
            "probed_ssids": client.get("ssids") or [],
            "probe_count": client.get("probe_count") or 0,
            "association_count": client.get("association_count") or 0,
            "deauth_count": client.get("deauth_count") or 0,
            "disassoc_count": client.get("disassoc_count") or 0,
        }

    def device_sessions(self, device):
        """Return closed sessions plus the current open session, if any."""
        sessions = list((device or {}).get("sessions") or [])
        active = (device or {}).get("active_session")
        if isinstance(active, dict):
            active_copy = dict(active)
            active_copy["active"] = True
            sessions.append(active_copy)
        return sessions

    def sessions_in_window(self, sessions):
        """Return BLE sessions that overlap the selected report window.

        The returned copy clips duration_sec to the selected window. That keeps a
        last-24-hours report from counting hours that happened before the window.
        """
        since = window_since_epoch(self.window_days)
        if since is None:
            return [self.session_with_duration(session) for session in sessions or []]
        output = []
        for session in sessions or []:
            clipped = self.clip_session_to_window(session, since)
            if clipped:
                output.append(clipped)
        return output

    def clip_session_to_window(self, session, since):
        """Return a session copy if any observed portion overlaps the window."""
        start = utc_epoch((session or {}).get("start"))
        end = utc_epoch((session or {}).get("end") or (session or {}).get("start"))
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

    def is_new_in_window(self, item):
        """Return True when first_seen falls inside the selected report window."""
        since = window_since_epoch(self.window_days)
        if since is None:
            return False
        first = utc_epoch(item.get("first_seen"))
        return first is not None and first >= since

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
        """Return the top local hour labels from a Counter."""
        return ["{:02d}:00-{:02d}:00".format(hour, (hour + 1) % 24) for hour, _count in counts.most_common(3)]

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
        names = [name for name in (device.get("names") or []) if name]
        if names:
            return "{} ({})".format(", ".join(names[:2]), mac)
        manufacturer = device.get("manufacturer_name") or device.get("manufacturer") or device.get("vendor_name")
        if manufacturer:
            return "{} ({})".format(manufacturer, mac)
        return mac

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
            "warning": sum(1 for item in reports if item.get("severity") == "warning"),
            "info": sum(1 for item in reports if item.get("severity") == "info"),
        }

    def severity_rank(self, severity):
        """Sort warnings before informational reports."""
        return {"warning": 2, "error": 3, "alert": 3, "info": 1}.get(severity, 0)

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
