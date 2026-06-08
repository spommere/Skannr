"""Longer-window report generation from materialized Subject History.

Insights are meant to move quickly. Reports are the slower summary layer for
questions such as "what recurring Bluetooth presence happened this week?" or
"which APs/clients were notable during this retained window?"
"""

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from .bus import local_now
from .collectors.aprsis import clean_aprs_data
from .collectors.lan import clean_lan_data
from .collectors.noaa import clean_noaa_data, tsunami_is_alertworthy
from .collectors.pws import clean_pws_data
from .collectors.rayhunter import clean_rayhunter_data, clean_rayhunter_field
from .collectors.swpc import (
    clean_swpc_data,
    number_or_none,
    swpc_event_is_alert,
    swpc_event_is_critical,
    xray_class_to_flux,
)
from .collectors.usgs import clean_usgs_data
from .log_utils import (
    format_epoch,
    now_epoch,
    record_time_epoch,
    save_json_atomic,
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
    "wifi_signal_swing_db": 15,
    "wifi_many_bssid_count": 2,
    "wifi_recurring_min_days": 2,
    "wifi_long_presence_sec": 4 * 3600,
    "wifi_intermit_min_sessions": 3,
    "wifi_monitor_event_count": 5,
    "aprs_mobile_min_distance_km": 0.3,
    "aprs_weather_temp_change_f": 5,
    "aprs_weather_high_rain_1h_in": 0.25,
    "aprs_weather_high_wind_mph": 25,
    "aprs_weather_high_gust_mph": 35,
    "pws_weather_temp_change_f": 5,
    "pws_weather_high_rain_1h_in": 0.25,
    "pws_weather_high_wind_mph": 25,
    "pws_weather_high_gust_mph": 35,
    "noaa_high_severities": ["Severe", "Extreme"],
    "usgs_nearby_radius_km": 100,
    "usgs_warning_magnitude": 4.0,
    "swpc_report_xray_class": "X1.0",
    "swpc_report_radio_blackout": "R3",
    "swpc_report_solar_radiation_storm": "S3",
    "swpc_report_geomagnetic_storm": "G3",
    "swpc_report_kp": 7,
    "lan_report_new_devices": True,
    "lan_report_gateway_changes": True,
}


class ReportsBuilder:
    """Build slower report-style interpretations from Subject History.

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
        """Return a report bundle for RF history and external status sources."""
        generated_at_epoch = self.history_generated_epoch(history)
        self._generated_at_epoch = generated_at_epoch
        generated_at = local_now(generated_at_epoch)
        # Reports never read raw JSONL directly. The Refresh path in main.py
        # first updates Subject History, then hands that summary to this builder.
        wifi = (history or {}).get("wifi") or {}
        bluetooth = (history or {}).get("bluetooth") or (history or {}).get("ble") or {}
        reports = []
        reports.extend(self.ble_reports(bluetooth.get("devices") or [], generated_at))
        reports.extend(
            self.wifi_ap_reports(wifi.get("access_points") or [], generated_at)
        )
        reports.extend(
            self.wifi_client_reports(wifi.get("clients") or [], generated_at)
        )
        reports.extend(
            self.rayhunter_reports((history or {}).get("rayhunter") or [], generated_at)
        )
        reports.extend(
            self.aprsis_reports((history or {}).get("aprsis") or [], generated_at)
        )
        reports.extend(
            self.noaa_reports((history or {}).get("noaa") or [], generated_at)
        )
        reports.extend(
            self.usgs_reports((history or {}).get("usgs") or [], generated_at)
        )
        reports.extend(
            self.swpc_reports((history or {}).get("swpc") or [], generated_at)
        )
        reports.extend(
            self.pws_reports((history or {}).get("pws") or [], generated_at)
        )
        reports.extend(
            self.lan_reports((history or {}).get("lan") or [], generated_at)
        )
        reports.extend(self.privacy_reports(wifi, bluetooth, generated_at))
        reports.extend(self.scanner_quality_reports(history or {}, generated_at))
        for report in reports:
            self.enrich_report_metadata(report)
        reports.sort(
            key=lambda item: (
                self.report_scope_rank(item),
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
            "history_generated_at_epoch": (history or {}).get("generated_at_epoch"),
            "window": window_metadata(self.window_days),
            "reports": reports,
            "counts": self.counts(reports),
        }

    def history_generated_epoch(self, history):
        """Use the Subject History snapshot time as the report freshness time."""
        try:
            value = float((history or {}).get("generated_at_epoch"))
        except (TypeError, ValueError):
            return now_epoch()
        return int(value) if value > 0 else now_epoch()

    def rayhunter_reports(self, events, timestamp):
        """Return one report row for the latest Rayhunter endpoint status."""
        if not events:
            return []
        latest = max(
            events,
            key=lambda item: record_time_epoch(item, "timestamp") or 0,
        )
        data = clean_rayhunter_data(latest.get("data") or {})
        event_type = latest.get("type") or ""
        last_seen = latest.get("timestamp") or ""
        last_seen_epoch = record_time_epoch(latest, "timestamp")
        endpoint = clean_rayhunter_field(data.get("endpoint")) or ""
        status_events = self.to_int(data.get("events_in_window")) or len(events)
        if event_type in ("collector_offline", "collector_retrying"):
            severity = "warning"
            title = "Rayhunter collector not healthy"
            warning_count = ""
            summary = self.rayhunter_summary_with_event_count(
                clean_rayhunter_field(data.get("reason"))
                or clean_rayhunter_field(data.get("warning"))
                or "Rayhunter collector is not healthy.",
                status_events,
            )
            findings = ["Rayhunter collector not healthy"]
            score = 75
        else:
            warning_count = self.to_int(data.get("warning_count"))
            severity = "warning" if warning_count > 0 else "info"
            title = (
                "Rayhunter warning present"
                if warning_count > 0
                else "Rayhunter status"
            )
            summary = self.rayhunter_warning_summary(
                warning_count, status_events
            )
            findings = (
                ["Rayhunter warning"]
                if warning_count > 0
                else ["Rayhunter reachable", "No warnings"]
            )
            score = 88 if warning_count > 0 else 35
        evidence = {
            "endpoint": endpoint,
            "warning_count": warning_count,
            "latest_event": data.get("latest_event") or "",
            "rayhunter_version": data.get("rayhunter_version") or "",
            "storage": data.get("storage") or "",
            "memory": data.get("memory") or "",
            "battery": data.get("battery") or "",
            "recording_id": data.get("recording_id") or "",
            "recording_size": data.get("recording_size") or "",
            "recording_start": data.get("recording_start") or "",
            "recording_last_message": data.get("recording_last_message") or "",
            "device_os": data.get("device_os") or "",
            "gps_mode": data.get("gps_mode") or "",
            "findings": findings,
            "last_seen_epoch": last_seen_epoch,
        }
        evidence = {
            key: value
            for key, value in evidence.items()
            if value not in ("", [], None)
        }
        return [
            self.report(
                timestamp,
                severity,
                "rayhunter",
                "rayhunter_status",
                title,
                summary,
                evidence,
                self.score_with_recency(score, last_seen_epoch),
                last_seen,
                subject=self.rayhunter_subject(endpoint),
            )
        ]

    def rayhunter_subject(self, endpoint):
        """Return a compact Rayhunter report subject."""
        endpoint = clean_rayhunter_field(endpoint) or ""
        return "Rayhunter {}".format(endpoint) if endpoint else "Rayhunter"

    def rayhunter_warning_summary(self, warning_count, status_events):
        """Return the compact Rayhunter status summary shown in Reports."""
        warning_label = "warning" if warning_count == 1 else "warnings"
        summary = "{} {}.".format(warning_count, warning_label)
        return self.rayhunter_summary_with_event_count(summary, status_events)

    def rayhunter_summary_with_event_count(self, summary, status_events):
        """Append the selected-window Rayhunter event count to a summary."""
        summary = (clean_rayhunter_field(summary) or "").rstrip(".")
        if not summary:
            summary = "Rayhunter status"
        if status_events:
            event_label = "status event" if status_events == 1 else "status events"
            return "{}. {} {}.".format(summary, status_events, event_label)
        return "{}.".format(summary)

    def aprsis_reports(self, events, timestamp):
        """Return APRS-IS report rows grouped by source callsign."""
        reports = []
        station_entries = []
        for event in events or []:
            data = clean_aprs_data(event.get("data") or {})
            event_type = event.get("type") or ""
            if event_type == "aprsis_collector_summary":
                report = self.aprsis_collector_report(data, event, timestamp)
                if report:
                    reports.append(report)
            else:
                station_entries.append((data, event))
        reports.extend(self.aprsis_population_reports(station_entries, timestamp))
        for data, event in station_entries:
            report = self.aprsis_station_report(data, event, timestamp)
            if report:
                reports.append(report)
        return reports

    def aprsis_population_reports(self, entries, timestamp):
        """Return area-level APRS-IS population rows before station rows."""
        subjects = [
            (data, event)
            for data, event in entries or []
            if self.to_int(data.get("packet_count")) > 0
        ]
        if not subjects:
            return []
        reports = []
        weather = [
            (data, event)
            for data, event in subjects
            if self.to_int(data.get("weather_count")) > 0
        ]
        if len(weather) >= 2:
            reports.append(self.aprsis_weather_population_report(weather, timestamp))

        mobile = [
            (data, event)
            for data, event in subjects
            if self.aprsis_station_is_mobile(data)
        ]
        if len(mobile) >= 2:
            reports.append(self.aprsis_mobile_population_report(mobile, timestamp))
        return [report for report in reports if report]

    def aprsis_station_is_mobile(self, data):
        """Return True when an APRS station looks mobile within the window."""
        if not self.to_int(data.get("position_count")):
            return False
        return (
            bool(data.get("movement_detected"))
            or (self.to_number(data.get("position_span_km")) or 0)
            >= float(self.config["aprs_mobile_min_distance_km"])
            or (self.to_number(data.get("max_speed_kmh")) or 0) >= 5
        )

    def aprsis_weather_population_report(self, entries, timestamp):
        """Return an area-level APRS weather-station report row."""
        datasets = [data for data, _event in entries or []]
        first_seen, last_seen, last_seen_epoch = self.population_time_range(entries)
        rain_max = self.max_numeric(datasets, "rain_1h_max_in")
        wind_max = self.max_numeric(datasets, "wind_speed_max_mph")
        gust_max = self.max_numeric(datasets, "wind_gust_max_mph")
        temp_min = self.min_numeric(
            datasets, "temperature_min_f", fallback_key="temperature_f"
        )
        temp_max = self.max_numeric(
            datasets, "temperature_max_f", fallback_key="temperature_f"
        )
        active_rain = sum(1 for data in datasets if data.get("rain_active"))
        findings = ["APRS weather station population"]
        if active_rain:
            findings.append("{} station(s) reporting active rain".format(active_rain))
        if rain_max is not None and rain_max >= float(
            self.config["aprs_weather_high_rain_1h_in"]
        ):
            findings.append("High rain rate")
        if wind_max is not None and wind_max >= float(
            self.config["aprs_weather_high_wind_mph"]
        ):
            findings.append("High wind")
        if gust_max is not None and gust_max >= float(
            self.config["aprs_weather_high_gust_mph"]
        ):
            findings.append("High wind gust")
        station_count = len(datasets)
        packet_count = sum(self.to_int(data.get("packet_count")) for data in datasets)
        report_count = sum(self.to_int(data.get("weather_count")) for data in datasets)
        summary_parts = [
            "{} weather station(s)".format(station_count),
            "{} weather report(s)".format(report_count),
        ]
        if temp_min is not None and temp_max is not None:
            summary_parts.append("temperature {:.0f}-{:.0f} F".format(temp_min, temp_max))
        if rain_max is not None:
            summary_parts.append("max rain rate {:.2f} in/hr".format(rain_max))
        if gust_max is not None:
            summary_parts.append("max gust {:.0f} mph".format(gust_max))
        evidence = self.clean_evidence(
            {
                "findings": self.unique_ordered(findings),
                "population_kind": "aprs_weather",
                "station_count": station_count,
                "packet_count": packet_count,
                "weather_count": report_count,
                "stations": self.population_subjects(datasets, "callsign"),
                "temperature_min_f": temp_min,
                "temperature_max_f": temp_max,
                "rain_1h_max_in": rain_max,
                "wind_speed_max_mph": wind_max,
                "wind_gust_max_mph": gust_max,
                "rain_active_stations": active_rain,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        score = 45 + min(station_count * 5, 20)
        if rain_max is not None and rain_max >= float(
            self.config["aprs_weather_high_rain_1h_in"]
        ):
            score += 25
        if gust_max is not None and gust_max >= float(
            self.config["aprs_weather_high_gust_mph"]
        ):
            score += 20
        return self.report(
            timestamp,
            "warning" if self.aprsis_warning_findings(findings) else "info",
            "aprsis",
            "aprsis_weather_population",
            "APRS weather station pattern",
            "; ".join(summary_parts) + ".",
            evidence,
            self.score_with_recency(score, last_seen_epoch, cap=95),
            last_seen,
            subject="APRS-IS weather stations",
            report_scope="population",
        )

    def aprsis_mobile_population_report(self, entries, timestamp):
        """Return an area-level APRS mobile-station report row."""
        datasets = [data for data, _event in entries or []]
        first_seen, last_seen, last_seen_epoch = self.population_time_range(entries)
        max_span = self.max_numeric(datasets, "position_span_km")
        max_speed = self.max_numeric(datasets, "max_speed_kmh")
        station_count = len(datasets)
        packet_count = sum(self.to_int(data.get("packet_count")) for data in datasets)
        position_count = sum(
            self.to_int(data.get("position_count")) for data in datasets
        )
        findings = ["Mobile stations moved through area"]
        summary_parts = [
            "{} mobile station(s)".format(station_count),
            "{} position report(s)".format(position_count),
        ]
        if max_span is not None:
            summary_parts.append("max span {:.2f} km".format(max_span))
        if max_speed is not None:
            summary_parts.append("max speed {:.1f} km/h".format(max_speed))
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "population_kind": "aprs_mobile",
                "station_count": station_count,
                "packet_count": packet_count,
                "position_count": position_count,
                "stations": self.population_subjects(datasets, "callsign"),
                "position_span_km": max_span,
                "max_speed_kmh": max_speed,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        score = 50 + min(station_count * 7, 25)
        return self.report(
            timestamp,
            "info",
            "aprsis",
            "aprsis_mobile_population",
            "APRS mobile station pattern",
            "; ".join(summary_parts) + ".",
            evidence,
            self.score_with_recency(score, last_seen_epoch, cap=90),
            last_seen,
            subject="APRS-IS mobile stations",
            report_scope="population",
        )

    def aprsis_collector_report(self, data, event, timestamp):
        """Return a collector-health row only when APRS-IS is not online."""
        collector_state = str(data.get("collector_state") or "").upper()
        if collector_state not in ("OFFLINE", "RETRYING"):
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        reason = data.get("reason") or "APRS-IS feed is offline."
        evidence = self.aprsis_clean_evidence(
            {
                "findings": ["APRS-IS collector offline"],
                "collector_state": collector_state,
                "reason": reason,
                "host": data.get("host") or "",
                "port": data.get("port") or "",
                "filter": data.get("filter") or "",
                "feed_name": data.get("feed_name") or "",
                "feed_role": data.get("feed_role") or "",
                "geofence_enforced": data.get("geofence_enforced"),
                "geofence_radius_km": data.get("geofence_radius_km"),
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
                "internet_fed": True,
            }
        )
        return self.report(
            timestamp,
            "warning",
            "aprsis",
            "aprsis_collector_offline",
            "APRS-IS feed offline",
            reason,
            evidence,
            self.score_with_recency(75, last_seen_epoch),
            last_seen,
            subject="APRS-IS collector",
        )

    def aprsis_station_report(self, data, event, timestamp):
        """Return one APRS-IS report row for a callsign/object source."""
        callsign = data.get("callsign") or "unknown"
        packet_count = self.to_int(data.get("packet_count"))
        if packet_count <= 0:
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        findings = self.aprsis_station_findings(data)
        report_type, title = self.aprsis_station_report_kind(data, findings)
        score = self.score_aprsis_station(data, findings, last_seen_epoch)
        severity = "warning" if self.aprsis_warning_findings(findings) else "info"
        evidence = self.aprsis_station_evidence(
            data, findings, last_seen, last_seen_epoch
        )
        return self.report(
            timestamp,
            severity,
            "aprsis",
            report_type,
            title,
            self.aprsis_station_summary_text(data, findings),
            evidence,
            score,
            last_seen,
            subject=self.aprsis_subject(data),
        )

    def aprsis_station_findings(self, data):
        """Return deterministic APRS patterns detected for one callsign."""
        findings = []
        position_count = self.to_int(data.get("position_count"))
        weather_count = self.to_int(data.get("weather_count"))
        object_count = self.to_int(data.get("object_count"))
        message_count = self.to_int(data.get("message_count"))
        movement_span = self.to_number(data.get("position_span_km")) or 0
        max_speed = self.to_number(data.get("max_speed_kmh")) or 0
        if weather_count:
            findings.append("Weather station in configured area")
        if position_count:
            findings.append("Position in configured area")
            if (
                bool(data.get("movement_detected"))
                or movement_span >= float(self.config["aprs_mobile_min_distance_km"])
                or max_speed >= 5
            ):
                findings.append("Mobile station moved through area")
        if object_count:
            findings.append("APRS object activity")
        if message_count:
            findings.append("APRS message activity")
        temp_change = abs(self.to_number(data.get("temperature_change_f")) or 0)
        if temp_change >= float(self.config["aprs_weather_temp_change_f"]):
            findings.append("Weather temperature changed")
        if (self.to_number(data.get("rain_1h_max_in")) or 0) >= float(
            self.config["aprs_weather_high_rain_1h_in"]
        ):
            findings.append("High rain rate")
        transition = self.aprsis_latest_rain_transition(data)
        if transition:
            findings.append(self.aprsis_transition_finding(*transition))
        if (self.to_number(data.get("wind_speed_max_mph")) or 0) >= float(
            self.config["aprs_weather_high_wind_mph"]
        ):
            findings.append("High wind")
        if (self.to_number(data.get("wind_gust_max_mph")) or 0) >= float(
            self.config["aprs_weather_high_gust_mph"]
        ):
            findings.append("High wind gust")
        return self.unique_ordered(findings)

    def aprsis_station_report_kind(self, data, findings):
        """Classify one APRS callsign report row."""
        if self.to_int(data.get("weather_count")):
            return "aprsis_weather_station", "APRS weather station activity"
        if "Mobile station moved through area" in findings:
            return "aprsis_mobile_station", "APRS mobile station moved through area"
        if self.to_int(data.get("position_count")):
            return "aprsis_position_station", "APRS station position activity"
        if self.to_int(data.get("object_count")):
            return "aprsis_object_station", "APRS object activity"
        if self.to_int(data.get("message_count")):
            return "aprsis_message_station", "APRS message activity"
        return "aprsis_station_activity", "APRS station activity"

    def aprsis_station_summary_text(self, data, findings):
        """Return the concise Reports summary for one APRS callsign."""
        packet_count = self.to_int(data.get("packet_count"))
        if self.to_int(data.get("weather_count")):
            return self.aprsis_weather_summary_text(packet_count, data)
        if self.to_int(data.get("position_count")):
            return self.aprsis_position_summary_text(packet_count, data)
        parts = [
            "{} APRS packet(s) in the configured area".format(packet_count)
        ]
        if data.get("object_name"):
            parts.append("object {}".format(data.get("object_name")))
        if data.get("message"):
            parts.append("latest message {}".format(data.get("message")))
        elif data.get("comment"):
            parts.append(data.get("comment"))
        return "{}.".format("; ".join(parts))

    def aprsis_position_summary_text(self, packet_count, data):
        """Return a movement-oriented APRS summary."""
        parts = [
            "{} APRS packet(s), including {} position report(s)".format(
                packet_count,
                self.to_int(data.get("position_count")),
            )
        ]
        position = self.aprsis_position_text(data)
        if position:
            parts.append("latest {}".format(position))
        movement = self.aprsis_movement_text(data)
        if movement:
            parts.append(movement)
        motion = self.aprsis_motion_text(data)
        if motion:
            parts.append(motion)
        return "{}.".format("; ".join(parts))

    def aprsis_weather_summary_text(self, packet_count, data):
        """Return a weather-pattern APRS summary."""
        parts = [
            "{} APRS packet(s), including {} weather report(s)".format(
                packet_count,
                self.to_int(data.get("weather_count")),
            )
        ]
        weather_summary = self.aprsis_weather_summary_display(data.get("weather_summary"))
        if weather_summary:
            parts.append("latest {}".format(weather_summary))
        temperature = self.aprsis_temperature_range_text(data)
        if temperature:
            parts.append(temperature)
        wind = self.aprsis_wind_text(data)
        if wind:
            parts.append(wind)
        rain = self.aprsis_rain_text(data)
        if rain:
            parts.append(rain)
        position = self.aprsis_position_text(data)
        if position:
            parts.append("latest position {}".format(position))
        observed = self.aprsis_observed_text(data)
        if observed:
            parts.append("observed {}".format(observed))
        return "{}.".format("; ".join(parts))

    def score_aprsis_station(self, data, findings, last_seen_epoch):
        """Return an operator-attention score for an APRS callsign row."""
        score = 25 + min(self.to_int(data.get("packet_count")), 20)
        if "Mobile station moved through area" in findings:
            score += 25
        elif self.to_int(data.get("position_count")):
            score += 10
        if "Weather station in configured area" in findings:
            score += 15
        if "Weather temperature changed" in findings:
            score += 10
        if "High rain rate" in findings:
            score += 25
        if "High wind" in findings or "High wind gust" in findings:
            score += 20
        if self.aprsis_has_finding_prefix(findings, ("Rain started", "Rain stopped")):
            score += 8
        if "APRS object activity" in findings:
            score += 10
        if "APRS message activity" in findings:
            score += 10
        return self.score_with_recency(score, last_seen_epoch, cap=95)

    def aprsis_warning_findings(self, findings):
        """Return True for APRS weather conditions that should sort as warnings."""
        warning_labels = {
            "High rain rate",
            "High wind",
            "High wind gust",
        }
        return bool(warning_labels & set(findings or []))

    def aprsis_station_evidence(self, data, findings, last_seen, last_seen_epoch):
        """Return compact APRS evidence for one callsign report."""
        evidence = {
            "findings": findings,
            "callsign": data.get("callsign") or "",
            "packet_count": self.to_int(data.get("packet_count")),
            "position_count": self.to_int(data.get("position_count")),
            "weather_count": self.to_int(data.get("weather_count")),
            "object_count": self.to_int(data.get("object_count")),
            "message_count": self.to_int(data.get("message_count")),
            "status_count": self.to_int(data.get("status_count")),
            "first_seen": data.get("first_seen") or "",
            "first_seen_epoch": data.get("first_seen_epoch"),
            "last_seen": last_seen,
            "last_seen_epoch": last_seen_epoch,
            "destination": data.get("destination") or "",
            "via_path": data.get("via_path") or "",
            "q_construct": data.get("q_construct") or "",
            "igate": data.get("igate") or "",
            "sample_destinations": data.get("sample_destinations") or [],
            "sample_paths": data.get("sample_paths") or [],
            "sample_igates": data.get("sample_igates") or [],
            "sample_feeds": data.get("sample_feeds") or [],
            "sample_feed_roles": data.get("sample_feed_roles") or [],
            "sample_servers": data.get("sample_servers") or [],
            "sample_objects": data.get("sample_objects") or [],
            "sample_messages": data.get("sample_messages") or [],
            "object_name": data.get("object_name") or "",
            "addressee": data.get("addressee") or "",
            "message": data.get("message") or "",
            "comment": data.get("comment") or "",
            "first_latitude": data.get("first_latitude"),
            "first_longitude": data.get("first_longitude"),
            "last_latitude": data.get("last_latitude"),
            "last_longitude": data.get("last_longitude"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "position_span_km": data.get("position_span_km"),
            "movement_km": data.get("movement_km"),
            "max_step_km": data.get("max_step_km"),
            "speed_kmh": data.get("speed_kmh"),
            "max_speed_kmh": data.get("max_speed_kmh"),
            "course_deg": data.get("course_deg"),
            "weather_summary": self.aprsis_weather_summary_display(
                data.get("weather_summary")
            ),
            "temperature_f": data.get("temperature_f"),
            "temperature_min_f": data.get("temperature_min_f"),
            "temperature_max_f": data.get("temperature_max_f"),
            "temperature_change_f": data.get("temperature_change_f"),
            "wind_speed_mph": data.get("wind_speed_mph"),
            "wind_speed_max_mph": data.get("wind_speed_max_mph"),
            "wind_gust_mph": data.get("wind_gust_mph"),
            "wind_gust_max_mph": data.get("wind_gust_max_mph"),
            "rain_1h_in": data.get("rain_1h_in"),
            "rain_1h_max_in": data.get("rain_1h_max_in"),
            "rain_started": data.get("rain_started"),
            "rain_started_at": data.get("rain_started_at") or "",
            "rain_started_epoch": data.get("rain_started_epoch"),
            "rain_stopped": data.get("rain_stopped"),
            "rain_stopped_at": data.get("rain_stopped_at") or "",
            "rain_stopped_epoch": data.get("rain_stopped_epoch"),
            "rain_active": data.get("rain_active"),
            "rain_last_transition": data.get("rain_last_transition") or "",
            "rain_last_transition_at": data.get("rain_last_transition_at") or "",
            "rain_last_transition_epoch": data.get("rain_last_transition_epoch"),
            "rain_episode_started_at": data.get("rain_episode_started_at") or "",
            "rain_episode_started_epoch": data.get("rain_episode_started_epoch"),
            "rain_episode_stopped_at": data.get("rain_episode_stopped_at") or "",
            "rain_episode_stopped_epoch": data.get("rain_episode_stopped_epoch"),
            "humidity_percent": data.get("humidity_percent"),
            "pressure_hpa": data.get("pressure_hpa"),
            "host": data.get("host") or "",
            "port": data.get("port") or "",
            "filter": data.get("filter") or "",
            "feed_name": data.get("feed_name") or "",
            "feed_role": data.get("feed_role") or "",
            "server_name": data.get("server_name") or "",
            "server_address": data.get("server_address") or "",
            "preferred_servers": data.get("preferred_servers") or [],
            "distance_from_filter_km": data.get("distance_from_filter_km"),
            "geofence_enforced": data.get("geofence_enforced"),
            "geofence_radius_km": data.get("geofence_radius_km"),
            "internet_fed": True,
        }
        return self.aprsis_clean_evidence(evidence)

    def aprsis_clean_evidence(self, evidence):
        """Drop empty APRS evidence fields while preserving numeric zeroes."""
        return {
            key: value
            for key, value in (evidence or {}).items()
            if value not in ("", [], None)
        }

    def clean_evidence(self, evidence):
        """Drop empty evidence fields while preserving numeric zeroes."""
        return {
            key: value
            for key, value in (evidence or {}).items()
            if value not in ("", [], None)
        }

    def population_time_range(self, entries):
        """Return first/last display times for aggregate report rows."""
        first_epochs = []
        last_epochs = []
        for data, event in entries or []:
            first_epoch = (
                self.to_number(data.get("first_seen_epoch"))
                or record_time_epoch(data, "first_seen")
                or record_time_epoch(event, "timestamp")
            )
            last_epoch = (
                self.to_number(data.get("last_seen_epoch"))
                or record_time_epoch(data, "last_seen")
                or record_time_epoch(event, "timestamp")
            )
            if first_epoch is not None:
                first_epochs.append(first_epoch)
            if last_epoch is not None:
                last_epochs.append(last_epoch)
        first_epoch = min(first_epochs) if first_epochs else None
        last_epoch = max(last_epochs) if last_epochs else None
        first_seen = format_epoch(first_epoch) if first_epoch is not None else ""
        last_seen = format_epoch(last_epoch) if last_epoch is not None else ""
        return first_seen, last_seen, last_epoch

    def population_values(self, datasets, key, limit=12):
        """Return compact unique string values for aggregate evidence."""
        values = []
        seen = set()
        for data in datasets or []:
            raw = data.get(key)
            raw_values = raw if isinstance(raw, list) else [raw]
            for value in raw_values:
                text = str(value or "").strip()
                if not text or text in seen:
                    continue
                seen.add(text)
                values.append(text)
                if len(values) >= limit:
                    return values
        return values

    def population_subjects(self, datasets, key, limit=12):
        """Return sorted unique subject identifiers for aggregate evidence."""
        return sorted(self.population_values(datasets, key, limit=1000))[:limit]

    def min_numeric(self, datasets, key, fallback_key=None):
        """Return the minimum numeric value for a data key."""
        values = self.numeric_values(datasets, key, fallback_key=fallback_key)
        return min(values) if values else None

    def max_numeric(self, datasets, key, fallback_key=None):
        """Return the maximum numeric value for a data key."""
        values = self.numeric_values(datasets, key, fallback_key=fallback_key)
        return max(values) if values else None

    def numeric_values(self, datasets, key, fallback_key=None):
        """Return numeric values for a key with an optional fallback key."""
        values = []
        for data in datasets or []:
            value = self.to_number(data.get(key))
            if value is None and fallback_key:
                value = self.to_number(data.get(fallback_key))
            if value is not None:
                values.append(value)
        return values

    def counter_labels(self, counter, limit=8):
        """Return compact counter labels sorted by count then name."""
        return [
            "{} {}".format(key, count)
            for key, count in sorted(
                (counter or {}).items(),
                key=lambda item: (-item[1], str(item[0])),
            )[:limit]
            if key
        ]

    def highest_xray_class(self, datasets):
        """Return the strongest SWPC X-ray class label in a product set."""
        best = ("", 0.0)
        for data in datasets or []:
            label = str(data.get("xray_class") or "").strip().upper()
            flux = xray_class_to_flux(label) if label else None
            if flux is not None and flux > best[1]:
                best = (label, flux)
        return best[0]

    def aprsis_subject(self, data):
        """Return the APRS report subject centered on the source callsign."""
        callsign = data.get("callsign") or "unknown"
        return "APRS {}".format(callsign)

    def aprsis_position_text(self, data):
        """Return latest APRS coordinates as compact text."""
        latitude = self.to_number(data.get("latitude"))
        longitude = self.to_number(data.get("longitude"))
        if latitude is not None and longitude is not None:
            return "{:.5f}, {:.5f}".format(latitude, longitude)
        if latitude is not None:
            return "lat {:.5f}".format(latitude)
        if longitude is not None:
            return "lon {:.5f}".format(longitude)
        return ""

    def aprsis_movement_text(self, data):
        """Return APRS movement span text when available."""
        span = self.to_number(data.get("position_span_km"))
        movement = self.to_number(data.get("movement_km"))
        if span is not None and span > 0:
            return "movement span {:.2f} km".format(span)
        if movement is not None and movement > 0:
            return "first-to-latest movement {:.2f} km".format(movement)
        return ""

    def aprsis_motion_text(self, data):
        """Return APRS latest/max motion text."""
        parts = []
        speed = self.to_number(data.get("speed_kmh"))
        max_speed = self.to_number(data.get("max_speed_kmh"))
        course = self.to_number(data.get("course_deg"))
        if speed is not None:
            parts.append("latest {:.1f} km/h".format(speed))
        if max_speed is not None and max_speed > 0:
            parts.append("max {:.1f} km/h".format(max_speed))
        if course is not None:
            parts.append("{:.0f} deg".format(course))
        return ", ".join(parts)

    def aprsis_temperature_range_text(self, data):
        """Return compact APRS temperature range and net-change text."""
        minimum = self.to_number(data.get("temperature_min_f"))
        maximum = self.to_number(data.get("temperature_max_f"))
        change = self.to_number(data.get("temperature_change_f"))
        parts = []
        if minimum is not None and maximum is not None:
            parts.append("temperature range {:.0f}-{:.0f} F".format(minimum, maximum))
        if change is not None and change:
            parts.append("net {:+.0f} F first-to-latest".format(change))
        return ", ".join(parts)

    def aprsis_wind_text(self, data):
        """Return compact APRS wind text."""
        wind = self.to_number(data.get("wind_speed_max_mph"))
        gust = self.to_number(data.get("wind_gust_max_mph"))
        parts = []
        if wind is not None and wind:
            parts.append("max wind {:.0f} mph".format(wind))
        if gust is not None and gust:
            parts.append("max gust {:.0f} mph".format(gust))
        return ", ".join(parts)

    def aprsis_rain_text(self, data):
        """Return compact APRS rain text."""
        rain = self.to_number(data.get("rain_1h_max_in"))
        parts = []
        if rain is not None:
            parts.append("max 1h rain rate {:.2f} in/hr".format(rain))
        transition = self.aprsis_latest_rain_transition(data, lower_label=True)
        if transition:
            parts.append(self.aprsis_transition_text(*transition))
        return ", ".join(parts)

    def aprsis_weather_summary_display(self, value):
        """Return APRS weather summary text with one-hour rain shown as a rate."""
        text = str(value or "")
        return re.sub(
            r"\brain 1h ([0-9]+(?:\.[0-9]+)?) in\b",
            r"1h rain rate \1 in/hr",
            text,
        )

    def aprsis_latest_rain_transition(self, data, lower_label=False):
        """Return the latest retained APRS rain-rate transition."""
        explicit = str(data.get("rain_last_transition") or "").strip().lower()
        if explicit in ("started", "stopped"):
            label = "rain {}".format(explicit) if lower_label else "Rain {}".format(explicit)
            return label, self.aprsis_rain_transition_timestamp(data, explicit)

        candidates = []
        if data.get("rain_started"):
            candidates.append(
                (
                    self.to_number(data.get("rain_started_epoch")) or 0,
                    "started",
                    data.get("rain_started_at") or "",
                )
            )
        if data.get("rain_stopped"):
            candidates.append(
                (
                    self.to_number(data.get("rain_stopped_epoch")) or 0,
                    "stopped",
                    data.get("rain_stopped_at") or "",
                )
            )
        if not candidates:
            return None
        _epoch, state, timestamp = max(candidates, key=lambda item: item[0])
        label = "rain {}".format(state) if lower_label else "Rain {}".format(state)
        if state == "stopped":
            timestamp = self.aprsis_rain_transition_timestamp(data, state) or timestamp
        return label, timestamp

    def aprsis_rain_transition_timestamp(self, data, state):
        """Return transition timestamp with episode context when available."""
        if state == "stopped":
            stopped = data.get("rain_episode_stopped_at") or data.get(
                "rain_last_transition_at"
            )
            started = data.get("rain_episode_started_at") or ""
            if stopped and started:
                return "{}; episode started {}".format(stopped, started)
            return stopped or ""
        return data.get("rain_last_transition_at") or data.get(
            "rain_episode_started_at"
        ) or ""

    def aprsis_transition_text(self, label, timestamp):
        """Return a transition label with retained report timing when available."""
        return "{} at {}".format(label, timestamp) if timestamp else label

    def aprsis_transition_finding(self, label, timestamp):
        """Return a report finding that can stand alone in the Reasons column."""
        return "{} at {}".format(label, timestamp) if timestamp else label

    def aprsis_has_finding_prefix(self, findings, prefixes):
        """Return True when timestamped findings still match their base label."""
        return any(
            str(finding or "").startswith(prefix)
            for finding in findings or []
            for prefix in prefixes
        )

    def aprsis_observed_text(self, data):
        """Return the retained first/latest APRS observation range."""
        first = data.get("first_seen") or ""
        last = data.get("last_seen") or ""
        if first and last and first != last:
            return "{} to {}".format(first, last)
        return first or last

    def noaa_reports(self, events, timestamp):
        """Return NOAA/NWS/NHC/tsunami.gov report rows."""
        reports = []
        alert_entries = []
        for event in events or []:
            data = clean_noaa_data((event or {}).get("data") or {})
            event_type = (event or {}).get("type") or ""
            if event_type == "noaa_collector_summary":
                report = self.noaa_collector_report(data, event, timestamp)
                if report:
                    reports.append(report)
            else:
                alert_entries.append((data, event))
        reports.extend(self.noaa_population_reports(alert_entries, timestamp))
        for data, event in alert_entries:
            report = self.noaa_alert_report(data, event, timestamp)
            if report:
                reports.append(report)
        return reports

    def noaa_population_reports(self, entries, timestamp):
        """Return NOAA/NHC area/product population rows before event rows."""
        subjects = [
            (data, event)
            for data, event in entries or []
            if data.get("event_id") or data.get("event") or data.get("headline")
        ]
        if not subjects:
            return []
        reports = []
        tropical = [
            (data, event)
            for data, event in subjects
            if data.get("alert_kind") == "tropical"
        ]
        if len(tropical) >= 2:
            reports.append(self.noaa_tropical_population_report(tropical, timestamp))
        hazards = [
            (data, event)
            for data, event in subjects
            if data.get("alert_kind") not in ("tropical", "tropical_outlook", "forecast")
        ]
        if len(hazards) >= 2:
            reports.append(self.noaa_hazard_population_report(hazards, timestamp))
        return [report for report in reports if report]

    def noaa_tropical_population_report(self, entries, timestamp):
        """Return a population report for active tropical-cyclone products."""
        datasets = [data for data, _event in entries or []]
        first_seen, last_seen, last_seen_epoch = self.population_time_range(entries)
        event_count = len(datasets)
        product_count = sum(
            self.to_int(data.get("nhc_product_count")) or 1
            for data in datasets
        )
        basins = self.population_values(datasets, "basin")
        products = self.population_values(datasets, "event", limit=8)
        sources = self.population_values(datasets, "source")
        update_count = sum(self.to_int(data.get("update_count")) for data in datasets)
        findings = ["Tropical cyclone product set"]
        summary_parts = [
            "{} tropical advisory package(s)".format(event_count),
            "{} product(s)".format(product_count) if product_count != event_count else "",
            "basins {}".format(", ".join(basins)) if basins else "",
            "sources {}".format(", ".join(sources)) if sources else "",
        ]
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "population_kind": "noaa_tropical",
                "event_count": event_count,
                "product_count": product_count,
                "events": products,
                "basins": basins,
                "sources": sources,
                "update_count": update_count,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        return self.report(
            timestamp,
            "warning",
            "noaa",
            "noaa_tropical_population",
            "NOAA tropical cyclone episode",
            "; ".join(part for part in summary_parts if part) + ".",
            evidence,
            self.score_with_recency(75 + min(event_count * 2, 15), last_seen_epoch),
            last_seen,
            subject="NOAA/NHC tropical products",
            report_scope="population",
        )

    def noaa_hazard_population_report(self, entries, timestamp):
        """Return a population report for multiple or high NOAA hazards."""
        if not entries:
            return None
        datasets = [data for data, _event in entries or []]
        first_seen, last_seen, last_seen_epoch = self.population_time_range(entries)
        event_count = len(datasets)
        high = [
            data
            for data in datasets
            if self.noaa_warning_findings(self.noaa_findings(data))
        ]
        event_names = self.population_values(datasets, "event", limit=8)
        areas = self.population_values(datasets, "area_desc", limit=6)
        severity_counts = Counter(
            str(data.get("severity") or "unknown") for data in datasets
        )
        findings = ["NOAA hazard population"]
        if high:
            findings.append("{} high-attention hazard(s)".format(len(high)))
        summary_parts = [
            "{} NOAA hazard subject(s)".format(event_count),
            "{} warning/high-severity".format(len(high)) if high else "",
            "areas {}".format(", ".join(areas)) if areas else "",
        ]
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "population_kind": "noaa_hazards",
                "event_count": event_count,
                "events": event_names,
                "areas": areas,
                "severity_counts": self.counter_labels(severity_counts),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        return self.report(
            timestamp,
            "warning" if high else "info",
            "noaa",
            "noaa_hazard_population",
            "NOAA area hazard pattern",
            "; ".join(part for part in summary_parts if part) + ".",
            evidence,
            self.score_with_recency(55 + len(high) * 12, last_seen_epoch, cap=95),
            last_seen,
            subject="NOAA/NWS hazards",
            report_scope="population",
        )

    def noaa_collector_report(self, data, event, timestamp):
        """Return NOAA collector-health row only when not healthy."""
        state = str(data.get("collector_state") or "").upper()
        if state not in ("OFFLINE", "RETRYING"):
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        evidence = self.clean_evidence(
            {
                "findings": ["NOAA collector offline"],
                "collector_state": state,
                "reason": data.get("reason") or "",
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        return self.report(
            timestamp,
            "warning",
            "noaa",
            "noaa_collector_offline",
            "NOAA feed offline",
            data.get("reason") or "NOAA feed is offline.",
            evidence,
            self.score_with_recency(75, last_seen_epoch),
            last_seen,
            subject="NOAA collector",
        )

    def noaa_alert_report(self, data, event, timestamp):
        """Return one NOAA alert/advisory report row."""
        event_id = data.get("event_id") or ""
        if not event_id and not data.get("headline") and not data.get("event"):
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        findings = self.noaa_findings(data)
        score = self.score_noaa_alert(data, findings, last_seen_epoch)
        severity = "warning" if self.noaa_warning_findings(findings) else "info"
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "event_id": event_id,
                "source_event_id": data.get("source_event_id") or "",
                "event": data.get("event") or "",
                "headline": data.get("headline") or "",
                "severity": data.get("severity") or "",
                "urgency": data.get("urgency") or "",
                "certainty": data.get("certainty") or "",
                "status": data.get("status") or "",
                "message_type": data.get("message_type") or "",
                "alert_kind": data.get("alert_kind") or "",
                "area_desc": data.get("area_desc") or "",
                "basin": data.get("basin") or "",
                "nhc_system": data.get("nhc_system") or "",
                "nhc_storm_id": data.get("nhc_storm_id") or "",
                "nhc_advisory_number": data.get("nhc_advisory_number") or "",
                "nhc_package_key": data.get("nhc_package_key") or "",
                "nhc_product_count": data.get("nhc_product_count"),
                "nhc_product_types": data.get("nhc_product_types") or [],
                "nhc_product_urls": data.get("nhc_product_urls") or [],
                "effective": data.get("effective") or "",
                "onset": data.get("onset") or "",
                "expires": data.get("expires") or "",
                "ends": data.get("ends") or "",
                "updated": data.get("updated") or "",
                "source": data.get("source") or "",
                "source_url": data.get("source_url") or "",
                "cap_url": data.get("cap_url") or "",
                "json_url": data.get("json_url") or "",
                "tsunami_identifier": data.get("tsunami_identifier") or "",
                "incident_id": data.get("incident_id") or "",
                "tsunami_category": data.get("tsunami_category") or "",
                "message_number": data.get("message_number") or "",
                "event_time": data.get("event_time") or "",
                "magnitude": data.get("magnitude"),
                "magnitude_type": data.get("magnitude_type") or "",
                "depth_km": data.get("depth_km"),
                "product_code": data.get("product_code") or "",
                "resource_urls": data.get("resource_urls") or [],
                "map_urls": data.get("map_urls") or [],
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "forecast_generated": data.get("forecast_generated") or "",
                "forecast_window_hours": data.get("forecast_window_hours"),
                "forecast_soon_hours": data.get("forecast_soon_hours"),
                "forecast_hour_count": data.get("forecast_hour_count"),
                "current_forecast": data.get("current_forecast") or "",
                "current_temperature_f": data.get("current_temperature_f"),
                "current_precip_probability": data.get("current_precip_probability"),
                "temperature_min_f": data.get("temperature_min_f"),
                "temperature_max_f": data.get("temperature_max_f"),
                "temperature_change_f": data.get("temperature_change_f"),
                "max_precip_probability": data.get("max_precip_probability"),
                "precip_probability_threshold": data.get(
                    "precip_probability_threshold"
                ),
                "precip_likely_soon": data.get("precip_likely_soon"),
                "next_precip_start": data.get("next_precip_start") or "",
                "next_precip_end": data.get("next_precip_end") or "",
                "next_precip_probability": data.get("next_precip_probability"),
                "next_precip_forecast": data.get("next_precip_forecast") or "",
                "max_wind_mph": data.get("max_wind_mph"),
                "first_period_start": data.get("first_period_start") or "",
                "last_period_end": data.get("last_period_end") or "",
                "update_count": data.get("update_count") or 0,
                "first_seen": data.get("first_seen") or "",
                "first_seen_epoch": data.get("first_seen_epoch"),
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
                "internet_fed": True,
            }
        )
        return self.report(
            timestamp,
            severity,
            "noaa",
            "noaa_alert",
            self.noaa_report_title(data),
            self.noaa_summary_text(data),
            evidence,
            score,
            last_seen,
            subject=self.noaa_subject(data),
        )

    def noaa_findings(self, data):
        """Return deterministic NOAA report findings."""
        findings = []
        kind = data.get("alert_kind") or ""
        severity = data.get("severity") or ""
        event = data.get("event") or data.get("headline") or ""
        if kind == "tsunami":
            findings.append(
                "Tsunami hazard" if tsunami_is_alertworthy(data) else "Tsunami information"
            )
        elif kind == "tropical":
            findings.append("Tropical cyclone advisory")
        elif kind == "tropical_outlook":
            findings.append("Tropical weather outlook")
        elif kind == "forecast":
            findings.append("Point forecast context")
            if data.get("precip_likely_soon"):
                findings.append("Precipitation likely soon")
            max_wind = self.to_number(data.get("max_wind_mph"))
            if max_wind is not None and max_wind >= 25:
                findings.append("Breezy forecast")
        else:
            findings.append("Weather hazard")
        if str(severity).lower() in {
            str(item or "").lower()
            for item in self.config.get("noaa_high_severities") or []
        }:
            findings.append("High NOAA severity")
        if "warning" in str(event).lower():
            findings.append("Warning present")
        if data.get("message_type"):
            findings.append("NOAA {}".format(data.get("message_type")))
        return self.unique_ordered(findings)

    def noaa_warning_findings(self, findings):
        """Return True for NOAA findings that should sort as warnings."""
        warning_labels = {
            "Tsunami hazard",
            "Tropical cyclone advisory",
            "High NOAA severity",
            "Warning present",
        }
        return bool(warning_labels & set(findings or []))

    def score_noaa_alert(self, data, findings, last_seen_epoch):
        """Return attention score for a NOAA alert/advisory."""
        score = 35
        if "Tsunami hazard" in findings:
            score += 45
        if "Tropical cyclone advisory" in findings:
            score += 30
        if "High NOAA severity" in findings:
            score += 30
        if "Warning present" in findings:
            score += 20
        if "Precipitation likely soon" in findings:
            score += 10
        if "Breezy forecast" in findings:
            score += 5
        if str(data.get("urgency") or "").lower() == "immediate":
            score += 15
        return self.score_with_recency(score, last_seen_epoch, cap=98)

    def noaa_report_title(self, data):
        """Return NOAA report title."""
        if data.get("alert_kind") == "tropical":
            return "NOAA tropical advisory"
        if data.get("alert_kind") == "tropical_outlook":
            return "NOAA tropical outlook"
        if data.get("alert_kind") == "forecast":
            return "NOAA point forecast"
        if data.get("alert_kind") == "tsunami":
            return "NOAA tsunami alert" if tsunami_is_alertworthy(data) else "NOAA tsunami information"
        return "NOAA weather alert"

    def noaa_summary_text(self, data):
        """Return compact NOAA report summary."""
        parts = [
            data.get("severity") or "",
            data.get("area_desc") or "",
            data.get("magnitude")
            and data.get("alert_kind") == "tsunami"
            and "M{:.1f}".format(float(data.get("magnitude"))),
            data.get("depth_km")
            and data.get("alert_kind") == "tsunami"
            and "depth {:.1f} km".format(float(data.get("depth_km"))),
            data.get("message_number")
            and data.get("alert_kind") == "tsunami"
            and "message {}".format(data.get("message_number")),
            data.get("headline")
            if data.get("alert_kind") == "forecast"
            else "",
            data.get("headline")
            if data.get("alert_kind") != "forecast"
            and data.get("headline") != data.get("event")
            else "",
            data.get("expires")
            and data.get("alert_kind") != "forecast"
            and "expires {}".format(data.get("expires")),
        ]
        return "{}.".format("; ".join(str(part) for part in parts if part))

    def noaa_subject(self, data):
        """Return NOAA report subject."""
        label = data.get("event") or data.get("headline") or data.get("event_id") or "NOAA"
        return label

    def usgs_reports(self, events, timestamp):
        """Return USGS earthquake report rows."""
        reports = []
        earthquake_entries = []
        for event in events or []:
            data = clean_usgs_data((event or {}).get("data") or {})
            event_type = (event or {}).get("type") or ""
            if event_type == "usgs_collector_summary":
                report = self.usgs_collector_report(data, event, timestamp)
                if report:
                    reports.append(report)
            else:
                earthquake_entries.append((data, event))
        reports.extend(self.usgs_population_reports(earthquake_entries, timestamp))
        for data, event in earthquake_entries:
            report = self.usgs_earthquake_report(data, event, timestamp)
            if report:
                reports.append(report)
        return reports

    def usgs_population_reports(self, entries, timestamp):
        """Return cross-earthquake USGS rows before event rows."""
        quakes = [
            (data, event)
            for data, event in entries or []
            if data.get("event_id")
        ]
        if len(quakes) < 2:
            return []
        return [self.usgs_earthquake_population_report(quakes, timestamp)]

    def usgs_earthquake_population_report(self, entries, timestamp):
        """Return a population report for seismic activity in the window."""
        datasets = [data for data, _event in entries or []]
        first_seen, last_seen, last_seen_epoch = self.population_time_range(entries)
        magnitudes = [self.to_number(data.get("magnitude")) for data in datasets]
        magnitudes = [value for value in magnitudes if value is not None]
        distances = [self.to_number(data.get("distance_km")) for data in datasets]
        distances = [value for value in distances if value is not None]
        depths = [self.to_number(data.get("depth_km")) for data in datasets]
        depths = [value for value in depths if value is not None]
        alert_colors = self.population_values(datasets, "alert_color")
        event_ids = self.population_values(datasets, "event_id", limit=10)
        notable = sum(
            1
            for data in datasets
            if self.usgs_warning_findings(self.usgs_findings(data))
        )
        findings = ["USGS earthquake population"]
        if notable:
            findings.append("{} notable earthquake(s)".format(notable))
        summary_parts = ["{} earthquake(s)".format(len(datasets))]
        if magnitudes:
            summary_parts.append(
                "magnitude {:.1f}-{:.1f}".format(min(magnitudes), max(magnitudes))
            )
        if distances:
            summary_parts.append("nearest {:.1f} km".format(min(distances)))
        if depths:
            summary_parts.append("shallowest {:.1f} km".format(min(depths)))
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "population_kind": "usgs_earthquakes",
                "event_count": len(datasets),
                "event_ids": event_ids,
                "magnitude_min": min(magnitudes) if magnitudes else None,
                "magnitude_max": max(magnitudes) if magnitudes else None,
                "nearest_distance_km": min(distances) if distances else None,
                "shallowest_depth_km": min(depths) if depths else None,
                "notable_count": notable,
                "alert_colors": alert_colors,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        return self.report(
            timestamp,
            "warning" if notable else "info",
            "usgs",
            "usgs_earthquake_population",
            "USGS seismic activity pattern",
            "; ".join(summary_parts) + ".",
            evidence,
            self.score_with_recency(
                45 + min(len(datasets) * 4, 20) + min(notable * 10, 30),
                last_seen_epoch,
                cap=95,
            ),
            last_seen,
            subject="USGS earthquakes",
            report_scope="population",
        )

    def usgs_collector_report(self, data, event, timestamp):
        """Return USGS collector-health row only when not healthy."""
        state = str(data.get("collector_state") or "").upper()
        if state not in ("OFFLINE", "RETRYING"):
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        evidence = self.clean_evidence(
            {
                "findings": ["USGS collector offline"],
                "collector_state": state,
                "reason": data.get("reason") or "",
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        return self.report(
            timestamp,
            "warning",
            "usgs",
            "usgs_collector_offline",
            "USGS feed offline",
            data.get("reason") or "USGS feed is offline.",
            evidence,
            self.score_with_recency(75, last_seen_epoch),
            last_seen,
            subject="USGS collector",
        )

    def usgs_earthquake_report(self, data, event, timestamp):
        """Return one USGS earthquake report row."""
        event_id = data.get("event_id") or ""
        if not event_id:
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        findings = self.usgs_findings(data)
        score = self.score_usgs_earthquake(data, findings, last_seen_epoch)
        severity = "warning" if self.usgs_warning_findings(findings) else "info"
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "event_id": event_id,
                "magnitude": data.get("magnitude"),
                "place": data.get("place") or "",
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "depth_km": data.get("depth_km"),
                "distance_km": data.get("distance_km"),
                "event_time": data.get("event_time") or "",
                "updated": data.get("updated") or "",
                "status": data.get("status") or "",
                "feed": data.get("feed") or "",
                "scope": data.get("scope") or "",
                "feed_label": data.get("feed_label") or "",
                "global_major": data.get("global_major"),
                "felt": data.get("felt"),
                "cdi": data.get("cdi"),
                "mmi": data.get("mmi"),
                "alert_color": data.get("alert_color") or "",
                "tsunami": data.get("tsunami"),
                "detail_url": data.get("detail_url") or "",
                "update_count": data.get("update_count") or 0,
                "first_seen": data.get("first_seen") or "",
                "first_seen_epoch": data.get("first_seen_epoch"),
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
                "internet_fed": True,
            }
        )
        return self.report(
            timestamp,
            severity,
            "usgs",
            "usgs_earthquake",
            "USGS earthquake",
            self.usgs_summary_text(data),
            evidence,
            score,
            last_seen,
            subject=self.usgs_subject(data),
        )

    def usgs_findings(self, data):
        """Return deterministic USGS report findings."""
        if data.get("global_major") or "global" in str(data.get("scope") or ""):
            findings = ["Global major earthquake"]
        else:
            findings = ["Earthquake in configured query area"]
        magnitude = self.to_number(data.get("magnitude")) or 0
        distance = self.to_number(data.get("distance_km"))
        if distance is not None and distance <= float(
            self.config.get("usgs_nearby_radius_km", 100)
        ):
            findings.append("Nearby earthquake")
        if magnitude >= float(self.config.get("usgs_warning_magnitude", 4.0)):
            findings.append("Notable magnitude")
        if data.get("tsunami"):
            findings.append("Tsunami flag")
        if data.get("alert_color"):
            findings.append("USGS alert color {}".format(data.get("alert_color")))
        return self.unique_ordered(findings)

    def usgs_warning_findings(self, findings):
        """Return True for USGS findings that should sort as warnings."""
        return any(
            str(item or "").startswith(
                ("Nearby earthquake", "Notable magnitude", "Tsunami flag", "USGS alert color")
            )
            or str(item or "") == "Global major earthquake"
            for item in findings or []
        )

    def score_usgs_earthquake(self, data, findings, last_seen_epoch):
        """Return attention score for a USGS earthquake."""
        magnitude = self.to_number(data.get("magnitude")) or 0
        score = 25 + int(max(0, magnitude) * 10)
        if "Nearby earthquake" in findings:
            score += 20
        if "Tsunami flag" in findings:
            score += 35
        alert = str(data.get("alert_color") or "").lower()
        if alert == "yellow":
            score += 20
        elif alert == "orange":
            score += 35
        elif alert == "red":
            score += 45
        return self.score_with_recency(score, last_seen_epoch, cap=98)

    def usgs_summary_text(self, data):
        """Return compact USGS report summary."""
        parts = []
        distance = self.to_number(data.get("distance_km"))
        if distance is not None:
            parts.append("{:.1f} km from configured point".format(distance))
        if data.get("global_major") or "global" in str(data.get("scope") or ""):
            parts.append("global major feed")
        if data.get("depth_km") is not None:
            parts.append("depth {} km".format(data.get("depth_km")))
        if data.get("event_time"):
            parts.append("event {}".format(data.get("event_time")))
        if data.get("alert_color"):
            parts.append("alert {}".format(data.get("alert_color")))
        if data.get("tsunami"):
            parts.append("tsunami flag")
        return "{}.".format("; ".join(str(part) for part in parts if part))

    def usgs_subject(self, data):
        """Return USGS report subject."""
        label = data.get("place") or data.get("event_id") or "earthquake"
        magnitude = self.to_number(data.get("magnitude"))
        if magnitude is not None:
            return "M{:.1f} {}".format(magnitude, label)
        return label

    def swpc_reports(self, events, timestamp):
        """Return SWPC space-weather report rows."""
        reports = []
        swpc_entries = []
        for event in events or []:
            data = clean_swpc_data((event or {}).get("data") or {})
            event_type = (event or {}).get("type") or ""
            if event_type == "swpc_collector_summary":
                report = self.swpc_collector_report(data, event, timestamp)
                if report:
                    reports.append(report)
            else:
                swpc_entries.append((data, event))
        reports.extend(self.swpc_population_reports(swpc_entries, timestamp))
        for data, event in swpc_entries:
            report = self.swpc_event_report(data, event, timestamp)
            if report:
                reports.append(report)
        return reports

    def swpc_population_reports(self, entries, timestamp):
        """Return cross-product SWPC rows before event rows."""
        products = [
            (data, event)
            for data, event in entries or []
            if data.get("event_id") or data.get("event") or data.get("summary")
        ]
        if len(products) < 2:
            return []
        return [self.swpc_space_weather_population_report(products, timestamp)]

    def swpc_space_weather_population_report(self, entries, timestamp):
        """Return a population report for related space-weather products."""
        datasets = [data for data, _event in entries or []]
        first_seen, last_seen, last_seen_epoch = self.population_time_range(entries)
        kind_counts = Counter(data.get("event_kind") or "unknown" for data in datasets)
        alert_count = sum(
            1
            for data in datasets
            if swpc_event_is_alert(data, self.swpc_report_thresholds())
        )
        critical_count = sum(1 for data in datasets if swpc_event_is_critical(data))
        max_kp = self.max_numeric(datasets, "kp_index")
        highest_xray = self.highest_xray_class(datasets)
        scale_labels = self.population_values(datasets, "scale_label")
        events = self.population_values(datasets, "event", limit=8)
        findings = ["SWPC space-weather product set"]
        if alert_count:
            findings.append("{} alert-threshold product(s)".format(alert_count))
        if critical_count:
            findings.append("{} critical SWPC product(s)".format(critical_count))
        summary_parts = [
            "{} SWPC product(s)".format(len(datasets)),
            "kinds {}".format(", ".join(self.counter_labels(kind_counts, limit=5))),
        ]
        if highest_xray:
            summary_parts.append("highest flare {}".format(highest_xray))
        if max_kp is not None:
            summary_parts.append("max Kp {:.1f}".format(max_kp))
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "population_kind": "swpc_space_weather",
                "event_count": len(datasets),
                "events": events,
                "kind_counts": self.counter_labels(kind_counts, limit=8),
                "alert_count": alert_count,
                "critical_count": critical_count,
                "highest_xray_class": highest_xray,
                "max_kp": max_kp,
                "scale_labels": scale_labels,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        return self.report(
            timestamp,
            "warning" if alert_count else "info",
            "swpc",
            "swpc_space_weather_population",
            "SWPC space-weather episode",
            "; ".join(part for part in summary_parts if part) + ".",
            evidence,
            self.score_with_recency(
                45 + min(len(datasets) * 3, 20) + min(alert_count * 15, 35),
                last_seen_epoch,
                cap=98,
            ),
            last_seen,
            subject="SWPC space weather",
            report_scope="population",
        )

    def swpc_collector_report(self, data, event, timestamp):
        """Return SWPC collector-health row only when not healthy."""
        state = str(data.get("collector_state") or "").upper()
        if state not in ("OFFLINE", "RETRYING"):
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        evidence = self.clean_evidence(
            {
                "findings": ["SWPC collector offline"],
                "collector_state": state,
                "reason": data.get("reason") or "",
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        return self.report(
            timestamp,
            "warning",
            "swpc",
            "swpc_collector_offline",
            "SWPC feed offline",
            data.get("reason") or "SWPC feed is offline.",
            evidence,
            self.score_with_recency(75, last_seen_epoch),
            last_seen,
            subject="SWPC collector",
        )

    def swpc_event_report(self, data, event, timestamp):
        """Return one SWPC event report row."""
        event_id = data.get("event_id") or ""
        if not event_id and not data.get("summary"):
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        findings = self.swpc_findings(data)
        warning = self.swpc_warning_findings(findings)
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "event_id": event_id,
                "event_kind": data.get("event_kind") or "",
                "event": data.get("event") or "",
                "summary": data.get("summary") or "",
                "scale_family": data.get("scale_family") or "",
                "scale_value": data.get("scale_value"),
                "scale_label": data.get("scale_label") or "",
                "kp_index": data.get("kp_index"),
                "xray_class": data.get("xray_class") or "",
                "xray_flux_peak": data.get("xray_flux_peak"),
                "event_time": data.get("event_time") or "",
                "start_time": data.get("start_time") or "",
                "end_time": data.get("end_time") or "",
                "peak_time": data.get("peak_time") or "",
                "issue_time": data.get("issue_time") or "",
                "product_id": data.get("product_id") or "",
                "source": data.get("source") or "",
                "source_url": data.get("source_url") or "",
                "update_count": data.get("update_count") or 0,
                "first_seen": data.get("first_seen") or "",
                "first_seen_epoch": data.get("first_seen_epoch"),
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        return self.report(
            timestamp,
            "warning" if warning else "info",
            "swpc",
            "swpc_space_weather",
            self.swpc_report_title(data),
            self.swpc_summary_text(data),
            evidence,
            self.score_swpc_event(data, findings, last_seen_epoch),
            last_seen,
            subject=self.swpc_subject(data),
        )

    def swpc_findings(self, data):
        """Return deterministic SWPC report findings."""
        findings = []
        kind = data.get("event_kind") or ""
        if kind == "xray_flare":
            findings.append("X-class solar flare")
        elif kind == "radio_blackout":
            findings.append("Radio blackout")
        elif kind == "solar_radiation_storm":
            findings.append("Solar radiation storm")
        elif kind == "geomagnetic_storm":
            findings.append("Geomagnetic storm")
        elif kind == "cme_watch":
            findings.append("CME watch/update")
        else:
            findings.append("SWPC product")
        if swpc_event_is_alert(data, self.swpc_report_thresholds()):
            findings.append("Alert threshold crossed")
        if swpc_event_is_critical(data):
            findings.append("Critical SWPC level")
        return self.unique_ordered(findings)

    def swpc_report_thresholds(self):
        """Return threshold config using the names expected by SWPC helpers."""
        return {
            "alert_min_xray_class": self.config.get(
                "swpc_report_xray_class", "X1.0"
            ),
            "alert_min_radio_blackout": self.config.get(
                "swpc_report_radio_blackout", "R3"
            ),
            "alert_min_solar_radiation_storm": self.config.get(
                "swpc_report_solar_radiation_storm", "S3"
            ),
            "alert_min_geomagnetic_storm": self.config.get(
                "swpc_report_geomagnetic_storm", "G3"
            ),
            "alert_min_kp": self.config.get("swpc_report_kp", 7),
        }

    def swpc_warning_findings(self, findings):
        """Return True for SWPC findings that should sort as warnings."""
        return "Alert threshold crossed" in set(findings or [])

    def score_swpc_event(self, data, findings, last_seen_epoch):
        """Return attention score for an SWPC event."""
        score = 30
        if "X-class solar flare" in findings:
            score += 35
        if "Radio blackout" in findings:
            score += 30
        if "Solar radiation storm" in findings:
            score += 25
        if "Geomagnetic storm" in findings:
            score += 25
        if "CME watch/update" in findings:
            score += 15
        if "Alert threshold crossed" in findings:
            score += 20
        if "Critical SWPC level" in findings:
            score += 15
        kp = self.to_number(data.get("kp_index"))
        if kp is not None:
            score += int(max(0, kp - 4) * 5)
        return self.score_with_recency(score, last_seen_epoch, cap=98)

    def swpc_report_title(self, data):
        """Return compact SWPC report title."""
        return "SWPC {}".format(data.get("event") or "space-weather event")

    def swpc_summary_text(self, data):
        """Return compact SWPC report summary."""
        parts = [
            data.get("summary") or "",
            data.get("xray_class") or "",
            data.get("scale_label") or "",
        ]
        kp = number_or_none(data.get("kp_index"))
        if kp is not None:
            parts.append("Kp {:.1f}".format(kp))
        if data.get("event_time"):
            parts.append("event {}".format(data.get("event_time")))
        if data.get("source"):
            parts.append(data.get("source"))
        return "{}.".format("; ".join(str(part) for part in parts if part))

    def swpc_subject(self, data):
        """Return SWPC report subject."""
        parts = [
            data.get("event") or "SWPC event",
            data.get("xray_class") or data.get("scale_label") or "",
        ]
        kp = number_or_none(data.get("kp_index"))
        if kp is not None:
            parts.append("Kp {:.1f}".format(kp))
        return " ".join(str(part) for part in parts if part)

    def pws_reports(self, events, timestamp):
        """Return PWS weather station report rows."""
        reports = []
        station_entries = []
        for event in events or []:
            data = clean_pws_data((event or {}).get("data") or {})
            event_type = (event or {}).get("type") or ""
            if event_type == "pws_collector_summary":
                report = self.pws_collector_report(data, event, timestamp)
                if report:
                    reports.append(report)
            else:
                station_entries.append((data, event))
        if len(station_entries) >= 2:
            reports.append(self.pws_population_report(station_entries, timestamp))
        for data, event in station_entries:
            report = self.pws_station_report(data, event, timestamp)
            if report:
                reports.append(report)
        return [report for report in reports if report]

    def pws_population_report(self, entries, timestamp):
        """Return a population report when multiple PWS stations are configured."""
        datasets = [data for data, _event in entries or []]
        first_seen, last_seen, last_seen_epoch = self.population_time_range(entries)
        station_ids = self.population_values(datasets, "station_id", limit=8)
        max_rain = self.max_numeric(datasets, "rain_1h_max_in")
        max_gust = self.max_numeric(datasets, "wind_gust_max_mph")
        findings = ["PWS station population"]
        summary_parts = ["{} PWS station(s)".format(len(datasets))]
        if max_rain is not None:
            summary_parts.append("max 1h rain rate {:.2f} in/hr".format(max_rain))
        if max_gust is not None:
            summary_parts.append("max gust {:.0f} mph".format(max_gust))
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "population_kind": "pws_stations",
                "station_count": len(datasets),
                "stations": station_ids,
                "max_rain_1h_in": max_rain,
                "max_gust_mph": max_gust,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        return self.report(
            timestamp,
            "warning"
            if self.to_number(max_rain) is not None
            and max_rain >= float(self.config.get("pws_weather_high_rain_1h_in", 0.25))
            else "info",
            "pws",
            "pws_weather_population",
            "PWS weather station pattern",
            "; ".join(summary_parts) + ".",
            evidence,
            self.score_with_recency(45 + min(len(datasets) * 4, 20), last_seen_epoch),
            last_seen,
            subject="PWS stations",
            report_scope="population",
        )

    def pws_collector_report(self, data, event, timestamp):
        """Return PWS collector-health row only when not healthy."""
        state = str(data.get("collector_state") or "").upper()
        if state not in ("OFFLINE", "RETRYING"):
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        evidence = self.clean_evidence(
            {
                "findings": ["PWS collector offline"],
                "collector_state": state,
                "reason": data.get("reason") or "",
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        return self.report(
            timestamp,
            "warning",
            "pws",
            "pws_collector_offline",
            "PWS feed offline",
            data.get("reason") or "PWS feed is offline.",
            evidence,
            self.score_with_recency(75, last_seen_epoch),
            last_seen,
            subject="PWS collector",
        )

    def pws_station_report(self, data, event, timestamp):
        """Return one PWS station report row."""
        station = data.get("station_id") or data.get("station_name") or ""
        if not station:
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        findings = self.pws_findings(data)
        warning = self.pws_warning_findings(findings)
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "station_id": station,
                "station_name": data.get("station_name") or "",
                "mac_address": data.get("mac_address") or "",
                "model": data.get("model") or "",
                "location": self.pws_location_text(data),
                "sample_time": self.pws_sample_time_text(data),
                "weather": self.pws_weather_text(data),
                "wind": self.pws_wind_text(data),
                "rain": self.pws_rain_text(data),
                "pressure": self.pws_pressure_text(data),
                "solar": self.pws_solar_text(data),
                "rain_transition": self.pws_rain_transition_text(data),
                "battery": data.get("battery") or "",
                "observations": data.get("observation_count") or 0,
                "first_seen": data.get("first_seen") or "",
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
                "source": self.pws_source_text(data),
            }
        )
        return self.report(
            timestamp,
            "warning" if warning else "info",
            "pws",
            "pws_weather_station",
            "PWS weather station",
            self.pws_summary_text(data),
            evidence,
            self.score_pws_station(data, findings, last_seen_epoch),
            last_seen,
            subject=station,
        )

    def pws_findings(self, data):
        """Return deterministic PWS report findings."""
        findings = ["PWS weather station"]
        temp_change = self.to_number(data.get("temperature_change_f"))
        if temp_change is not None and abs(temp_change) >= float(
            self.config.get("pws_weather_temp_change_f", 5)
        ):
            findings.append("Temperature changed {:+.0f} F".format(temp_change))
        rain_max = self.to_number(data.get("rain_1h_max_in"))
        if rain_max is not None and rain_max >= float(
            self.config.get("pws_weather_high_rain_1h_in", 0.25)
        ):
            findings.append("High 1h rain rate")
        wind_max = self.to_number(data.get("wind_speed_max_mph"))
        gust_max = self.to_number(data.get("wind_gust_max_mph"))
        if wind_max is not None and wind_max >= float(
            self.config.get("pws_weather_high_wind_mph", 25)
        ):
            findings.append("High wind")
        if gust_max is not None and gust_max >= float(
            self.config.get("pws_weather_high_gust_mph", 35)
        ):
            findings.append("High gust")
        if data.get("rain_last_transition"):
            findings.append("Rain {}".format(data.get("rain_last_transition")))
        return self.unique_ordered(findings)

    def pws_warning_findings(self, findings):
        """Return True for PWS findings that should sort as warnings."""
        return any(
            str(item or "").startswith(("High 1h rain", "High wind", "High gust"))
            for item in findings or []
        )

    def score_pws_station(self, data, findings, last_seen_epoch):
        """Return attention score for a PWS station report."""
        score = 35
        if "High 1h rain rate" in findings:
            score += 30
        if "High wind" in findings:
            score += 18
        if "High gust" in findings:
            score += 22
        if any(str(item or "").startswith("Temperature changed") for item in findings):
            score += 8
        if data.get("rain_last_transition"):
            score += 8
        return self.score_with_recency(score, last_seen_epoch, cap=95)

    def pws_summary_text(self, data):
        """Return compact PWS report summary."""
        parts = [
            self.pws_weather_text(data),
            self.pws_wind_text(data),
            self.pws_rain_text(data),
            self.pws_rain_transition_text(data),
            data.get("event_time") and "sample {}".format(data.get("event_time")),
        ]
        return "{}.".format("; ".join(str(part) for part in parts if part))

    def pws_weather_text(self, data):
        """Return temperature/humidity text."""
        parts = []
        temp = self.to_number(data.get("temperature_f"))
        if temp is not None:
            parts.append("temp {:.0f} F".format(temp))
        feels = self.to_number(data.get("feels_like_f"))
        if feels is not None:
            parts.append("feels {:.0f} F".format(feels))
        dew = self.to_number(data.get("dewpoint_f"))
        if dew is not None:
            parts.append("dew {:.0f} F".format(dew))
        temp_min = self.to_number(data.get("temperature_min_f"))
        temp_max = self.to_number(data.get("temperature_max_f"))
        if temp_min is not None and temp_max is not None and temp_min != temp_max:
            parts.append("range {:.0f}-{:.0f} F".format(temp_min, temp_max))
        humidity = self.to_number(data.get("humidity_percent"))
        if humidity is not None:
            parts.append("humidity {:.0f}%".format(humidity))
        indoor = self.pws_indoor_text(data)
        if indoor:
            parts.append("indoor {}".format(indoor))
        return ", ".join(parts)

    def pws_indoor_text(self, data):
        """Return indoor temperature/humidity text."""
        parts = []
        temp = self.to_number(data.get("indoor_temperature_f"))
        humidity = self.to_number(data.get("indoor_humidity_percent"))
        feels = self.to_number(data.get("indoor_feels_like_f"))
        dew = self.to_number(data.get("indoor_dewpoint_f"))
        if temp is not None:
            parts.append("{:.0f} F".format(temp))
        if humidity is not None:
            parts.append("{:.0f}%".format(humidity))
        if feels is not None:
            parts.append("feels {:.0f} F".format(feels))
        if dew is not None:
            parts.append("dew {:.0f} F".format(dew))
        return ", ".join(parts)

    def pws_wind_text(self, data):
        """Return wind/gust text."""
        parts = []
        wind = self.to_number(data.get("wind_speed_mph"))
        gust = self.to_number(data.get("wind_gust_mph"))
        gust_max = self.to_number(data.get("wind_gust_max_mph"))
        direction = self.to_number(data.get("wind_direction_deg"))
        avg_dir = self.to_number(data.get("wind_direction_avg_10m_deg"))
        avg_speed = self.to_number(data.get("wind_speed_avg_10m_mph"))
        if direction is not None:
            parts.append("dir {:.0f} deg".format(direction))
        if wind is not None:
            parts.append("wind {:.0f} mph".format(wind))
        if avg_dir is not None or avg_speed is not None:
            avg_parts = []
            if avg_dir is not None:
                avg_parts.append("{:.0f} deg".format(avg_dir))
            if avg_speed is not None:
                avg_parts.append("{:.1f} mph".format(avg_speed))
            parts.append("10m avg {}".format(" ".join(avg_parts)))
        if gust is not None:
            parts.append("gust {:.0f} mph".format(gust))
        if gust_max is not None and (gust is None or gust_max != gust):
            parts.append("max gust {:.0f} mph".format(gust_max))
        return ", ".join(parts)

    def pws_rain_text(self, data):
        """Return rain-rate/total text."""
        parts = []
        rain = self.to_number(data.get("rain_1h_in"))
        rain_max = self.to_number(data.get("rain_1h_max_in"))
        event = self.to_number(data.get("rain_event_in"))
        day = self.to_number(data.get("rain_day_in"))
        week = self.to_number(data.get("rain_week_in"))
        month = self.to_number(data.get("rain_month_in"))
        year = self.to_number(data.get("rain_year_in"))
        if rain is not None:
            parts.append("1h rain rate {:.2f} in/hr".format(rain))
        if rain_max is not None and (rain is None or rain_max != rain):
            parts.append("max rate {:.2f} in/hr".format(rain_max))
        if event is not None:
            parts.append("event {:.2f} in".format(event))
        if day is not None:
            parts.append("daily rain {:.2f} in".format(day))
        if week is not None:
            parts.append("week {:.2f} in".format(week))
        if month is not None:
            parts.append("month {:.2f} in".format(month))
        if year is not None:
            parts.append("year {:.2f} in".format(year))
        last_rain = self.pws_last_rain_text(data)
        if last_rain:
            parts.append("last rain {}".format(last_rain))
        return ", ".join(parts)

    def pws_pressure_text(self, data):
        """Return pressure text."""
        rel = self.to_number(data.get("pressure_rel_inhg"))
        abs_value = self.to_number(data.get("pressure_abs_inhg"))
        parts = []
        if rel is not None:
            parts.append("rel {:.2f} inHg".format(rel))
        if abs_value is not None:
            parts.append("abs {:.2f} inHg".format(abs_value))
        return ", ".join(parts)

    def pws_solar_text(self, data):
        """Return solar/UV text."""
        parts = []
        solar = self.to_number(data.get("solar_w_m2"))
        uv = self.to_number(data.get("uv_index"))
        if solar is not None:
            parts.append("{:.0f} W/m2".format(solar))
        if uv is not None:
            parts.append("UV {:.1f}".format(uv))
        return ", ".join(parts)

    def pws_location_text(self, data):
        """Return coordinate text."""
        parts = []
        if data.get("location_name"):
            parts.append(data.get("location_name"))
        lat = self.to_number(data.get("latitude"))
        lon = self.to_number(data.get("longitude"))
        if lat is not None and lon is not None:
            parts.append("{:.5f}, {:.5f}".format(lat, lon))
        elevation_ft = self.to_number(data.get("elevation_ft"))
        elevation_m = self.to_number(data.get("elevation_m"))
        if elevation_ft is not None:
            parts.append("elev {:.0f} ft".format(elevation_ft))
        elif elevation_m is not None:
            parts.append("elev {:.0f} m".format(elevation_m))
        return "; ".join(parts)

    def pws_sample_time_text(self, data):
        """Return sample time and source timezone text."""
        sample_time = data.get("event_time") or self.pws_epoch_text(
            data, "event_time_epoch"
        )
        return "; ".join(
            item
            for item in (
                sample_time,
                data.get("timezone") and "tz {}".format(data.get("timezone")),
            )
            if item
        )

    def pws_rain_transition_text(self, data):
        """Return last PWS rain transition text."""
        transition = data.get("rain_last_transition")
        when = data.get("rain_last_transition_at")
        if not transition:
            return ""
        if str(transition).lower() == "stopped":
            stopped = data.get("rain_episode_stopped_at") or when or ""
            started = data.get("rain_episode_started_at") or ""
            if stopped and started:
                return "rain stopped {}; episode started {}".format(
                    stopped, started
                )
        return "rain {}{}".format(transition, " {}".format(when) if when else "")

    def pws_last_rain_text(self, data):
        """Return last-rain timestamp in Skannr local display format."""
        return self.pws_epoch_text(data, "last_rain_epoch", "last_rain_time")

    def pws_epoch_text(self, data, epoch_key, fallback_key=None):
        """Return a timestamp field in Skannr local display format."""
        epoch = self.to_number((data or {}).get(epoch_key))
        if epoch:
            return local_now(epoch)
        return (data or {}).get(fallback_key) if fallback_key else ""

    def pws_source_text(self, data):
        """Return source and URL as one compact evidence row."""
        return "; ".join(
            item
            for item in (
                data.get("source") or "",
                data.get("source_url") or "",
            )
            if item
        )

    def lan_reports(self, events, timestamp):
        """Return LAN device and gateway report rows."""
        reports = []
        gateway_entries = []
        device_entries = []
        for event in events or []:
            data = clean_lan_data((event or {}).get("data") or {})
            event_type = (event or {}).get("type") or ""
            if event_type == "lan_collector_summary":
                report = self.lan_collector_report(data, event, timestamp)
                if report:
                    reports.append(report)
            elif event_type == "lan_gateway_summary":
                gateway_entries.append((data, event))
            else:
                device_entries.append((data, event))
        reports.extend(
            self.lan_population_reports(gateway_entries, device_entries, timestamp)
        )
        for data, event in gateway_entries:
            report = self.lan_gateway_report(data, event, timestamp)
            if report:
                reports.append(report)
        for data, event in device_entries:
            report = self.lan_device_report(data, event, timestamp)
            if report:
                reports.append(report)
        return reports

    def lan_population_reports(self, gateways, devices, timestamp):
        """Return a LAN population row before device/gateway rows."""
        entries = list(gateways or []) + list(devices or [])
        if len(entries) < 2:
            return []
        datasets = [data for data, _event in entries]
        first_seen, last_seen, last_seen_epoch = self.population_time_range(entries)
        device_count = len(devices or [])
        gateway_count = len(gateways or [])
        changed = sum(1 for data in datasets if self.to_int(data.get("change_count")))
        vendors = self.population_values(datasets, "vendor_name", limit=8)
        services = sorted(
            set(
                value
                for data in datasets
                for value in self.list_values(data.get("services"))
                if value
            )
        )[:8]
        interfaces = sorted(
            set(
                value
                for data in datasets
                for value in self.list_values(data.get("interfaces"))
                + self.list_values(data.get("interface"))
                if value
            )
        )[:8]
        findings = ["LAN subject population"]
        if changed:
            findings.append("{} LAN subject(s) changed".format(changed))
        summary_parts = [
            "{} LAN device(s)".format(device_count),
            "{} gateway subject(s)".format(gateway_count) if gateway_count else "",
            "{} changed".format(changed) if changed else "",
        ]
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "population_kind": "lan_subjects",
                "subject_count": len(entries),
                "device_count": device_count,
                "gateway_count": gateway_count,
                "changed_count": changed,
                "vendors": vendors,
                "services": services,
                "interfaces": interfaces,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        return [
            self.report(
                timestamp,
                "warning" if changed else "info",
                "lan",
                "lan_subject_population",
                "LAN subject population",
                "; ".join(part for part in summary_parts if part) + ".",
                evidence,
                self.score_with_recency(45 + min(len(entries) * 3, 25), last_seen_epoch),
                last_seen,
                subject="LAN subjects",
                report_scope="population",
            )
        ]

    def lan_collector_report(self, data, event, timestamp):
        """Return LAN collector-health row only when not healthy."""
        state = str(data.get("collector_state") or "").upper()
        if state not in ("OFFLINE", "RETRYING"):
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        evidence = self.clean_evidence(
            {
                "findings": ["LAN collector offline"],
                "collector_state": state,
                "reason": data.get("reason") or "",
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        return self.report(
            timestamp,
            "warning",
            "lan",
            "lan_collector_offline",
            "LAN collector offline",
            data.get("reason") or "LAN collector is offline.",
            evidence,
            self.score_with_recency(75, last_seen_epoch),
            last_seen,
            subject="LAN collector",
        )

    def lan_gateway_report(self, data, event, timestamp):
        """Return default-gateway LAN report rows."""
        if not self.config.get("lan_report_gateway_changes", True):
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        findings = ["Default gateway observed"]
        if self.to_int(data.get("change_count")):
            findings.append("Default gateway changed")
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "subject_key": data.get("subject_key") or "",
                "gateway_ip": data.get("gateway_ip") or "",
                "gateway_ips": data.get("gateway_ips") or [],
                "family": data.get("family") or "",
                "families": data.get("families") or [],
                "interface": data.get("interface") or "",
                "interfaces": data.get("interfaces") or [],
                "mac": data.get("mac") or "",
                "vendor": data.get("vendor_name") or data.get("vendor_prefix") or "",
                "change_count": data.get("change_count") or 0,
                "first_seen": data.get("first_seen") or "",
                "first_seen_epoch": data.get("first_seen_epoch"),
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
            }
        )
        score = 85 if "Default gateway changed" in findings else 55
        return self.report(
            timestamp,
            "warning" if "Default gateway changed" in findings else "info",
            "lan",
            "lan_gateway_profile",
            "LAN default gateway",
            self.lan_gateway_summary_text(data, findings),
            evidence,
            self.score_with_recency(score, last_seen_epoch),
            last_seen,
            subject=self.lan_gateway_subject(data),
        )

    def lan_device_report(self, data, event, timestamp):
        """Return LAN device report rows."""
        if not self.config.get("lan_report_new_devices", True):
            return None
        last_seen = data.get("last_seen") or event.get("timestamp") or ""
        last_seen_epoch = (
            self.to_number(data.get("last_seen_epoch"))
            or record_time_epoch(event, "timestamp")
        )
        findings = ["LAN device observed"]
        if data.get("gateway"):
            findings.append("Gateway device")
        if self.to_int(data.get("change_count")):
            findings.append("LAN identity changed")
        if self.to_int(data.get("identify_count")):
            findings.append("LAN Identify enrichment")
        evidence = self.clean_evidence(
            {
                "findings": findings,
                "subject_key": data.get("subject_key") or "",
                "mac": data.get("mac") or "",
                "ips": data.get("ips") or [],
                "hostnames": data.get("hostnames") or [],
                "interfaces": data.get("interfaces") or [],
                "states": data.get("states") or [],
                "sources": data.get("sources") or [],
                "mac_aliases": data.get("mac_aliases") or [],
                "services": data.get("services") or [],
                "locations": data.get("locations") or [],
                "servers": data.get("servers") or [],
                "open_ports": data.get("open_ports") or [],
                "http_titles": data.get("http_titles") or [],
                "http_scripts": data.get("http_scripts") or [],
                "http_hints": data.get("http_hints") or [],
                "service_banners": data.get("service_banners") or [],
                "vendor": data.get("vendor_name") or data.get("vendor_prefix") or "",
                "gateway": data.get("gateway"),
                "gateways": data.get("gateways") or [],
                "observation_count": data.get("observation_count") or 0,
                "identify_count": data.get("identify_count") or 0,
                "change_count": data.get("change_count") or 0,
                "first_seen": data.get("first_seen") or "",
                "first_seen_epoch": data.get("first_seen_epoch"),
                "last_seen": last_seen,
                "last_seen_epoch": last_seen_epoch,
                "last_identified": data.get("last_identified") or "",
                "last_identified_epoch": data.get("last_identified_epoch"),
            }
        )
        score = 45 + min(self.to_int(data.get("observation_count")), 15)
        if "Gateway device" in findings:
            score += 20
        if "LAN identity changed" in findings:
            score += 25
        return self.report(
            timestamp,
            "warning" if "LAN identity changed" in findings else "info",
            "lan",
            "lan_device_profile",
            "LAN device profile",
            self.lan_device_summary_text(data, findings),
            evidence,
            self.score_with_recency(score, last_seen_epoch, cap=95),
            last_seen,
            subject=self.lan_device_subject(data),
        )

    def lan_gateway_summary_text(self, data, findings):
        """Return compact LAN gateway summary."""
        parts = [
            ", ".join(data.get("families") or []) or data.get("family") or "",
            (
                "via {}".format(", ".join(data.get("interfaces") or []))
                if data.get("interfaces")
                else data.get("interface") and "via {}".format(data.get("interface"))
            ),
            data.get("vendor_name") or data.get("vendor_prefix") or "",
            "changed" if "Default gateway changed" in findings else "",
        ]
        return "{}.".format("; ".join(str(part) for part in parts if part))

    def lan_device_summary_text(self, data, findings):
        """Return compact LAN device summary."""
        parts = [
            ", ".join(data.get("ips") or []),
            data.get("vendor_name") or data.get("vendor_prefix") or "",
            "services {}".format(", ".join(data.get("services")[:3])) if data.get("services") else "",
            "http {}".format(", ".join(data.get("http_titles")[:2])) if data.get("http_titles") else "",
            "ports {}".format(", ".join(data.get("open_ports")[:3])) if data.get("open_ports") else "",
            "gateway" if data.get("gateway") else "",
            "{} observation(s)".format(data.get("observation_count") or 0),
            "{} identify".format(data.get("identify_count")) if data.get("identify_count") else "",
            "changed" if "LAN identity changed" in findings else "",
        ]
        return "{}.".format("; ".join(str(part) for part in parts if part))

    def lan_gateway_subject(self, data):
        """Return LAN gateway report subject."""
        return "LAN gateway {}".format(
            data.get("mac")
            or data.get("gateway_ip")
            or ", ".join(data.get("gateway_ips") or [])
            or data.get("subject_key")
            or ""
        )

    def lan_device_subject(self, data):
        """Return LAN device report subject."""
        label = (
            data.get("hostname")
            or data.get("mac")
            or data.get("ip")
            or data.get("subject_key")
            or "device"
        )
        return "LAN {}".format(label)

    def privacy_reports(self, wifi, bluetooth, timestamp):
        """Return aggregate privacy-exposure rows inside Reports."""
        aps = (wifi or {}).get("access_points") or []
        devices = (bluetooth or {}).get("devices") or []
        named_ble = [
            device
            for device in devices
            if any(self.valid_bluetooth_name(name) for name in device.get("names") or [])
        ]
        uuid_ble = [
            device
            for device in devices
            if self.list_values(device.get("service_uuids"))
        ]
        stable_ble = [
            device
            for device in devices
            if not self.low_confidence_stale_ble_noise(self.ble_context(device))
        ]
        weak_wifi = [
            ap
            for ap in aps
            if set(self.normalized_wifi_encryption_values(ap.get("encryption") or []))
            & {"open", "WEP/unknown", "WPA"}
        ]
        if not named_ble and not uuid_ble and not weak_wifi:
            return []
        findings = []
        if named_ble:
            findings.append("{} named BLE device(s) advertise identity".format(len(named_ble)))
        if uuid_ble:
            findings.append("{} BLE device(s) advertise service UUIDs".format(len(uuid_ble)))
        if weak_wifi:
            findings.append("{} weak/open Wi-Fi profile(s) visible".format(len(weak_wifi)))
        evidence = {
            "findings": findings,
            "named_ble_devices": len(named_ble),
            "service_uuid_ble_devices": len(uuid_ble),
            "stable_ble_devices": len(stable_ble),
            "weak_wifi_profiles": len(weak_wifi),
        }
        score = min(85, 35 + len(named_ble) * 2 + len(uuid_ble) + len(weak_wifi) * 8)
        return [
            self.report(
                timestamp,
                "warning" if weak_wifi else "info",
                "privacy",
                "privacy_exposure_summary",
                "Privacy exposure summary",
                "; ".join(findings) + ".",
                evidence,
                score,
                timestamp,
                subject="Local RF privacy exposure",
            )
        ]

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
                # are often address rotation, not dozens of stable devices. Use
                # manufacturer plus advertised UUID/name hints to avoid merging
                # unrelated devices that happen to share one company id.
                private_groups[self.ble_private_cluster_key(context)].append(context)

        grouped_private_macs = set()
        for cluster_key, members in sorted(private_groups.items()):
            if len(members) < private_group_min:
                continue
            grouped_private_macs.update(member["mac"] for member in members)
            cluster_label = self.ble_private_cluster_label(cluster_key)
            reports.append(
                self.ble_private_address_group_report(timestamp, cluster_label, members)
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
            if (
                not private_grouped
                and self.low_confidence_stale_ble_noise(context)
            ):
                continue

            if sessions and len(days) >= int(self.config["ble_recurring_min_days"]):
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

        return self.score_with_recency(
            score,
            record_time_epoch(context.get("device") or {}, "last_seen"),
        )

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
            [float(session.get("duration_sec") or 0) for session in sessions] or [0]
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
            "private_candidate": self.is_private_ble_candidate(device, mac, sessions),
        }

    def low_confidence_stale_ble_noise(self, context):
        """Suppress stale one-off anonymous BLE privacy addresses from Reports."""
        device = context.get("device") or {}
        if not context.get("private_candidate"):
            return False
        if len(context.get("days") or []) > 1:
            return False
        if self.list_values(device.get("service_uuids")):
            return False
        if any(
            self.valid_bluetooth_name(name)
            for name in self.list_values(device.get("names"))
        ):
            return False
        observations = (
            int(device.get("seen_count") or 0)
            + int(device.get("update_count") or 0)
            + int(device.get("lost_count") or 0)
        )
        if observations > 1:
            return False
        last_seen = record_time_epoch(device, "last_seen")
        if last_seen is None:
            return False
        return self.generated_at_epoch() - last_seen > 3600

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
                parts.append("New Bluetooth device, seen in {} visits".format(visits))
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

    def ble_private_cluster_key(self, context):
        """Return a coarse BLE identity fingerprint for private-address churn."""
        device = context.get("device") or {}
        manufacturer = context.get("manufacturer") or "Unknown"
        names = tuple(
            sorted(
                name.lower()
                for name in self.list_values(device.get("names"))
                if self.valid_bluetooth_name(name)
            )[:2]
        )
        services = tuple(
            sorted(
                self.short_bluetooth_uuid(value)
                for value in self.list_values(device.get("service_uuids"))
                if self.short_bluetooth_uuid(value)
            )[:4]
        )
        return (manufacturer, names, services)

    def ble_private_cluster_label(self, cluster_key):
        """Return a concise label for a BLE private-address fingerprint."""
        manufacturer, names, services = cluster_key
        parts = [manufacturer or "Unknown"]
        if names:
            parts.append("/".join(names))
        if services:
            parts.append("UUID {}".format(",".join(value.upper() for value in services)))
        return " | ".join(part for part in parts if part)

    def short_bluetooth_uuid(self, value):
        """Normalize a Bluetooth UUID to a compact uppercase-ish key."""
        text = str(value or "").strip().lower()
        compact = "".join(char for char in text if char in "0123456789abcdef")
        if len(compact) == 4:
            return compact
        if compact.startswith("0000") and len(compact) >= 8:
            return compact[4:8]
        return compact[:8] if compact else ""

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
            return "{} - {} private/randomized addresses".format(manufacturer, count)
        return "{} private/randomized addresses".format(count)

    def ble_private_address_group_report(self, timestamp, cluster_label, members):
        """Summarize likely BLE privacy-address churn as one report row."""
        macs = sorted(member["mac"] for member in members)
        manufacturers = sorted(
            set(member["manufacturer"] for member in members if member["manufacturer"])
        )
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
        service_uuids = set()
        for member in members:
            hour_counts.update(member["hours"])
            start_hour_counts.update(member["start_hours"])
            sessions.extend(member["sessions"])
            service_uuids.update(
                self.list_values(member["device"].get("service_uuids"))
            )
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
            key=lambda member: record_time_epoch(member["device"], "last_seen") or 0,
            default={},
        )
        last_seen_device = last_seen_member.get("device") or {}
        last_seen = last_seen_device.get("last_seen") or ""
        evidence = {
            "cluster": cluster_label,
            "manufacturer": ", ".join(manufacturers),
            "address_count": len(members),
            "active_addresses": len(active),
            "findings": ["Private/randomized address cluster", "BLE presence cluster"],
            "sample_macs": macs[:12],
            "service_uuids": sorted(service_uuids),
            "days_seen": all_days,
            "presence_hours": self.hour_labels(hour_counts),
            "common_hours": self.common_hours(hour_counts),
            "common_start_hours": self.common_hours(start_hour_counts),
            "presence_spans": self.session_spans(sessions),
            "signal_max": int(signal_max) if signal_max is not None else "",
            "first_seen": self.display_time(first_seen_device, "first_seen"),
            "first_seen_epoch": record_time_epoch(first_seen_device, "first_seen"),
            "last_seen": last_seen,
            "last_seen_epoch": record_time_epoch(last_seen_device, "last_seen"),
        }
        score = self.score_ble_private_cluster(
            len(members),
            len(active),
            signal_max,
            evidence.get("last_seen_epoch"),
        )
        return self.report(
            timestamp,
            self.severity_for_score(score),
            "bluetooth",
            "ble_private_address_cluster",
            "Bluetooth private-address cluster",
            self.ble_private_cluster_summary(cluster_label, len(members), active),
            evidence,
            score,
            last_seen,
            subject=self.bluetooth_cluster_subject(cluster_label, len(members)),
        )

    def score_ble_private_cluster(
        self, address_count, active_count, signal_max, last_seen_epoch
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
        return self.score_with_recency(score, last_seen_epoch, cap=95)

    def wifi_ap_profile_summary(self, ap, findings, signal_max):
        """Return the final summary sentence for one Wi-Fi AP profile."""
        parts = []
        if "New access point" in findings:
            parts.append("new access point")
        if "Strong signal" in findings:
            if signal_max is not None:
                parts.append("strong signal reached {} dBm".format(int(signal_max)))
            else:
                parts.append("strong signal")
        if "Signal variation" in findings:
            parts.append("signal varied during the report window")
        if "Recurring AP presence" in findings:
            parts.append("recurring AP presence")
        if "Long AP presence" in findings:
            parts.append("long AP presence")
        if "Intermittent AP presence" in findings:
            parts.append("multiple AP presence windows")
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
        return "Observed on {} BSSID(s){}{}.".format(
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

        many_bssid_count = int(self.config["wifi_many_bssid_count"])
        for ap in aps:
            signal_max = self.to_number(ap.get("signal_max"))
            evidence = self.wifi_ap_evidence(ap)
            findings = []
            forced_warning = False
            sessions = self.sessions_in_window(self.device_sessions(ap))
            days = self.presence_days(sessions)
            longest = self.longest_session_seconds(sessions)
            if self.is_new_recent(ap, timestamp):
                findings.append("New access point")
            if len(days) >= int(self.config.get("wifi_recurring_min_days", 2)):
                findings.append("Recurring AP presence")
            if longest >= float(self.config.get("wifi_long_presence_sec", 4 * 3600)):
                findings.append("Long AP presence")
            if len(sessions) >= int(self.config.get("wifi_intermit_min_sessions", 3)):
                findings.append("Intermittent AP presence")
            if signal_max is not None and signal_max >= float(
                self.config["wifi_strong_rssi"]
            ):
                findings.append("Strong signal")
            signal_min = self.to_number(ap.get("signal_min"))
            if signal_min is not None and signal_max is not None:
                if signal_max - signal_min >= float(
                    self.config.get("wifi_signal_swing_db", 15)
                ):
                    findings.append("Signal variation")
            encryptions = self.normalized_wifi_encryption_values(
                ap.get("encryption") or []
            )
            variation = self.wifi_encryption_variation(encryptions)
            if variation:
                # Report security drift only after canonicalization suppresses
                # parser wording differences such as WPA2 versus WPA2/RSN.
                findings.append(variation["title"])
                forced_warning = variation["severity"] == "warning"
                evidence = self.with_evidence(evidence, {"encryption": encryptions})
            if len(ap.get("channels") or []) > 1:
                findings.append("Multiple channels")
            if findings:
                ssid = ap.get("ssid") or "(blank)"
                ssid_group = by_ssid.get(ssid) or []
                ssid_profile_covers_ap = (
                    ssid != "(blank)" and len(ssid_group) >= many_bssid_count
                )
                if ssid_profile_covers_ap and not forced_warning:
                    continue
                score = self.score_wifi_ap_profile(
                    ap, findings, signal_max, encryptions
                )
                severity = (
                    "warning" if forced_warning else self.severity_for_score(score)
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
            if ssid == "(blank)" or len(ssid_aps) < many_bssid_count:
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
            if any("locally administered" in vendor.lower() for vendor in vendors):
                findings.append("Locally administered/randomized BSSIDs")
            channels = self.sorted_channel_values(
                v for ap in ssid_aps for v in (ap.get("channels") or [])
            )
            ssid_sessions = [
                session
                for ap in ssid_aps
                for session in self.sessions_in_window(self.device_sessions(ap))
            ]
            ssid_days = self.presence_days(ssid_sessions)
            ssid_hours = self.session_hour_counts(ssid_sessions)
            ssid_start_hours = self.hour_counts(
                [
                    record_time_epoch(session, "start")
                    for session in ssid_sessions
                ]
            )
            if len(ssid_days) >= int(self.config.get("wifi_recurring_min_days", 2)):
                findings.append("Recurring SSID presence")
            bands = sorted(
                set(
                    self.band_for_channel(channel)
                    for channel in channels
                    if self.band_for_channel(channel)
                )
            )
            strongest = max(
                (
                    self.to_number(ap.get("signal_max"))
                    for ap in ssid_aps
                    if self.to_number(ap.get("signal_max")) is not None
                ),
                default=None,
            )
            score = self.score_wifi_ssid_profile(
                ssid_aps,
                bssids,
                vendors,
                encryption,
                findings,
                record_time_epoch(last_seen_ap, "last_seen"),
            )
            reports.append(
                self.report(
                    timestamp,
                    self.severity_for_score(score),
                    "wifi",
                    "wifi_ssid_profile",
                    "Wi-Fi SSID profile",
                    self.wifi_ssid_profile_summary(ssid, bssids, vendors, encryption),
                    {
                        "ssid": ssid,
                        "findings": findings,
                        "bssid_count": len(bssids),
                        "channels": channels,
                        "bands": bands,
                        "vendors": vendors,
                        "encryption": encryption,
                        "days_seen": ssid_days,
                        "presence_hours": self.hour_labels(ssid_hours),
                        "common_hours": self.common_hours(ssid_hours),
                        "common_start_hours": self.common_hours(ssid_start_hours),
                        "presence_spans": self.session_spans(ssid_sessions),
                        "strongest_signal": int(strongest)
                        if strongest is not None
                        else "",
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
        if "Recurring AP presence" in findings:
            score += 15
        if "Long AP presence" in findings:
            score += 20
        if "Intermittent AP presence" in findings:
            score += 10
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
        if "Signal variation" in findings:
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
        return self.score_with_recency(
            score,
            record_time_epoch(ap, "last_seen"),
        )

    def score_wifi_ssid_profile(
        self, ssid_aps, bssids, vendors, encryption, findings, last_seen_epoch=None
    ):
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
        if "Recurring SSID presence" in (findings or []):
            score += 15
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
        channels = self.sorted_channel_values(
            channel for ap in ssid_aps for channel in (ap.get("channels") or [])
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
        return self.score_with_recency(score, last_seen_epoch)

    def score_with_recency(self, score, last_seen_epoch, cap=100):
        """Apply last-seen age to a report attention score.

        Reports are sorted as an operator work queue. Base scoring captures how
        interesting the behavior was in the selected window, but old activity
        should not keep outranking fresh activity forever. This adjustment keeps
        current and recent rows near the top while still allowing older rows
        with strong behavioral signals to remain visible.
        """
        return self.clamp_score(
            score + self.recency_score_adjustment(last_seen_epoch), cap
        )

    def recency_score_adjustment(self, last_seen_epoch):
        """Return the score delta for how recently the profile was observed."""
        if last_seen_epoch is None:
            return 0
        age_sec = max(0, self.generated_at_epoch() - int(last_seen_epoch))
        if age_sec <= 24 * 3600:
            return 15
        if age_sec <= 3 * 24 * 3600:
            return 5
        if age_sec <= 7 * 24 * 3600:
            return -15
        return -30

    def generated_at_epoch(self):
        """Return the report build timestamp used for age calculations."""
        return self._generated_at_epoch or now_epoch()

    def clamp_score(self, score, cap=100):
        """Keep report scores inside the visible 0..cap range."""
        return max(0, min(int(score or 0), int(cap)))

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
                        "{} probe request(s)".format(
                            client.get("probe_count")
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
                        "deauth={}; disassoc={}".format(
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
                        "First seen recently at {}".format(
                            self.display_time(client, "first_seen") or "unknown time",
                        ),
                        evidence,
                        55,
                        client.get("last_seen"),
                    )
                )
        return reports

    def scanner_quality_reports(self, history, timestamp):
        """Report collection gaps that affect intelligence confidence."""
        wifi = (history or {}).get("wifi") or {}
        bluetooth = (history or {}).get("bluetooth") or (history or {}).get("ble") or {}
        reports = []
        reports.extend(
            self.collector_quality_report(
                timestamp,
                "wifi",
                "Wi-Fi scan coverage",
                "wifi_scan_quality",
                wifi.get("access_points") or [],
                "APs",
            )
        )
        reports.extend(
            self.collector_quality_report(
                timestamp,
                "bluetooth",
                "Bluetooth scan coverage",
                "bluetooth_scan_quality",
                bluetooth.get("devices") or [],
                "Bluetooth devices",
            )
        )
        return reports

    def collector_quality_report(
        self, timestamp, source, title, report_type, records, noun
    ):
        """Return a scanner-quality row only when coverage looks stale or empty."""
        records = [record for record in records or [] if isinstance(record, dict)]
        newest = max(
            (record_time_epoch(record, "last_seen") for record in records),
            default=None,
        )
        generated = self.generated_at_epoch()
        findings = []
        severity = "info"
        score = 25
        if not records:
            findings.append("No retained {} in selected view".format(noun))
            severity = "warning"
            score = 75
        elif newest is not None and generated - newest > 2 * 3600:
            findings.append("{} stale for {}".format(noun, self.duration_text(generated - newest)))
            severity = "warning"
            score = 70
        if not findings:
            return []
        evidence = {
            "findings": findings,
            "record_count": len(records),
            "last_seen": format_epoch(newest) if newest is not None else "",
            "last_seen_epoch": newest,
        }
        return [
            self.report(
                timestamp,
                severity,
                source,
                report_type,
                title,
                "; ".join(findings) + ".",
                evidence,
                self.score_with_recency(score, newest),
                evidence.get("last_seen"),
                subject=title,
            )
        ]

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
        report_scope=None,
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
            "timestamp_epoch": self._generated_at_epoch or timestamp_epoch(timestamp),
            "severity": severity,
            "source": source,
            "type": report_type,
            "title": title,
            "subject": subject or self.default_report_subject(source, evidence or {}),
            "summary": summary,
            "evidence": evidence or {},
            "score": score,
            "last_seen": last_seen_display,
            "last_seen_epoch": last_seen_epoch,
            "report_scope": report_scope
            or self.inferred_report_scope(source, report_type),
        }

    def inferred_report_scope(self, source, report_type):
        """Classify a report as population, collector/quality, or subject."""
        report_type = str(report_type or "").lower()
        population_types = {
            "ble_private_address_cluster",
            "privacy_exposure_summary",
            "wifi_ssid_profile",
        }
        if (
            report_type in population_types
            or report_type.endswith("_population")
            or report_type.endswith("_episode")
        ):
            return "population"
        if "collector" in report_type:
            return "collector"
        if "quality" in report_type:
            return "quality"
        if str(source or "").lower() == "privacy":
            return "population"
        return "subject"

    def enrich_report_metadata(self, report):
        """Attach display-oriented confidence and reason tags to one report."""
        report["reason_tags"] = self.report_reason_tags(report)
        report["confidence"] = self.report_confidence(report)

    def report_reason_tags(self, report):
        """Return compact reason tags from normalized report evidence."""
        evidence = (report or {}).get("evidence") or {}
        report_type = str((report or {}).get("type") or "").lower()
        report_scope = str((report or {}).get("report_scope") or "").lower()
        findings = " ".join(str(item or "") for item in evidence.get("findings") or [])
        text = "{} {}".format(report_type, findings).lower()
        tags = []
        if report_scope == "population":
            tags.append("pattern")
        candidates = [
            ("recurring", ("recurring",)),
            ("long", ("long",)),
            ("intermittent", ("intermittent",)),
            ("strong", ("strong", "signal")),
            ("new", ("new",)),
            ("security", ("security", "encryption", "open", "wep", "wpa")),
            ("multi-BSSID", ("multiple bssids", "wifi_ssid_profile")),
            ("channel", ("multiple channels", "channel")),
            ("RSSI swing", ("signal variation", "rssi")),
            ("randomized", ("randomized", "private-address", "private_address")),
            ("cluster", ("cluster",)),
            ("scanner", ("scanner", "collector", "quality")),
            ("privacy", ("privacy", "exposure")),
            ("mobile", ("mobile",)),
            ("movement", ("moved", "movement")),
            ("weather", ("weather",)),
            ("rain", ("rain",)),
            ("wind", ("wind", "gust")),
            ("message", ("message",)),
            ("object", ("object",)),
            ("hazard", ("hazard", "warning present", "noaa_alert")),
            ("earthquake", ("earthquake", "usgs_earthquake")),
            ("tsunami", ("tsunami",)),
            ("tropical", ("tropical", "hurricane", "cyclone")),
            ("LAN", ("lan_", "gateway", "default gateway")),
        ]
        for label, needles in candidates:
            if any(needle in text for needle in needles):
                tags.append(label)
        return self.unique_ordered(tags)

    def report_confidence(self, report):
        """Return High/Medium/Low evidence quality for operator triage."""
        evidence = (report or {}).get("evidence") or {}
        source = str((report or {}).get("source") or "").lower()
        report_type = str((report or {}).get("type") or "").lower()
        sessions = int(evidence.get("sessions") or 0)
        days = len(evidence.get("days_seen") or [])
        if (report or {}).get("report_scope") == "population":
            if source in ("aprsis", "noaa", "usgs", "swpc"):
                return "High"
            return "Medium"
        if source == "wifi":
            if report_type == "wifi_ssid_profile":
                if days >= 2 and int(evidence.get("bssid_count") or 0) >= 2:
                    return "High"
                return "Medium"
            if evidence.get("bssid") and (days >= 2 or sessions >= 2):
                return "High"
            return "Medium" if evidence.get("bssid") or evidence.get("ssid") else "Low"
        if source == "bluetooth":
            if report_type == "ble_private_address_cluster":
                if evidence.get("service_uuids") and days >= 2:
                    return "Medium"
                return "Low"
            if evidence.get("names") or evidence.get("model_number") or evidence.get("serial_number"):
                return "High"
            if days >= 2 or sessions >= 2:
                return "Medium"
            if evidence.get("service_uuids") or evidence.get("manufacturer"):
                return "Medium"
            return "Low"
        if source == "wifi_monitor":
            return "Medium"
        if source == "system":
            return "High" if (report or {}).get("severity") == "warning" else "Medium"
        if source == "privacy":
            return "Medium"
        if source == "rayhunter":
            return "High" if evidence.get("warning_count") else "Medium"
        if source == "aprsis":
            if evidence.get("weather_count") or evidence.get("position_count"):
                return "High" if evidence.get("packet_count") else "Medium"
            return "Medium"
        if source in ("noaa", "usgs"):
            return "High"
        if source == "swpc":
            return "High" if evidence.get("event_id") else "Medium"
        if source == "lan":
            if evidence.get("mac") or evidence.get("gateway_ip"):
                return "Medium"
            return "Low"
        return "Medium"

    def unique_ordered(self, values):
        """Return values once, preserving first occurrence."""
        output = []
        seen = set()
        for value in values or []:
            if value in seen:
                continue
            seen.add(value)
            output.append(value)
        return output

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
            "service_uuids": self.list_values(device.get("service_uuids")),
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
            "channels": self.sorted_channel_values(ap.get("channels") or []),
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
            "vendor": client.get("vendor_name") or client.get("vendor_prefix") or "",
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

    def list_values(self, value):
        """Normalize stored scalar/list fields into clean report strings."""
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        text = str(value).strip()
        return [text] if text else []

    def sorted_channel_values(self, values):
        """Return de-duplicated Wi-Fi channels with numeric ordering."""
        cleaned = {
            str(value).strip()
            for value in values or []
            if str(value).strip()
        }
        return sorted(cleaned, key=self.channel_sort_key)

    def channel_sort_key(self, value):
        """Sort channel labels numerically when possible, then lexically."""
        text = str(value).strip()
        try:
            return (0, int(text))
        except (TypeError, ValueError):
            return (1, text)

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
            return [self.session_with_duration(session) for session in sessions or []]
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
        normalized.sort(key=lambda item: (item["_start_epoch"], item["_end_epoch"]))

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
            current["active"] = bool(current.get("active") or session.get("active"))
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
        return self.hour_range_labels([hour for hour, _count in counts.most_common(3)])

    def hour_labels(self, counts):
        """Return compact local hour ranges touched by presence sessions."""
        return self.hour_range_labels(counts.keys())

    def hour_range_labels(self, hours):
        """Collapse adjacent hour buckets into readable local ranges.

        Presence summaries count activity by hour bucket. Showing every bucket
        separately is noisy for long sessions, so adjacent buckets such as
        04:00-05:00, 05:00-06:00, 06:00-07:00 are rendered as 04:00-07:00.
        """
        normalized = sorted({int(hour) % 24 for hour in hours if hour is not None})
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
            "{:02d}:00-{:02d}:00".format(start, (end + 1) % 24) for start, end in ranges
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
        return (first_octet & 0xC0) in (0x00, 0x40, 0xC0) or bool(first_octet & 0x02)

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
                float(self.session_with_duration(session).get("duration_sec") or 0)
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
            "warning": sum(1 for item in reports if item.get("severity") == "warning"),
            "info": sum(1 for item in reports if item.get("severity") == "info"),
        }

    def severity_rank(self, severity):
        """Sort warnings before informational reports."""
        return {"warning": 2, "error": 3, "alert": 3, "info": 1}.get(severity, 0)

    def report_scope_rank(self, report):
        """Sort cross-subject rows ahead of per-subject detail rows."""
        return {
            "population": 3,
            "collector": 2,
            "quality": 2,
            "subject": 1,
        }.get(str((report or {}).get("report_scope") or "").lower(), 1)

    def to_number(self, value):
        """Parse numeric fields while tolerating blanks."""
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def to_int(self, value):
        """Parse integer-like fields while tolerating blanks."""
        number = self.to_number(value)
        return int(number) if number is not None else 0


def save_reports(path, reports):
    """Persist generated reports for cheap startup/page loads."""
    save_json_atomic(path, reports)
