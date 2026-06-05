"""Collector-neutral subject history built from retained collector JSONL logs.

Subject History is the base layer for longer-lived intelligence products. Raw
collector logs remain the audit trail, but derived views should reason about
stable subjects: SSIDs/BSSIDs, Bluetooth identities, APRS callsigns, Rayhunter
endpoints, and RTL-SDR frequencies.
"""

import copy
import os
from collections import Counter, defaultdict

from .bus import local_now
from .collectors.lan import clean_lan_data
from .collectors.noaa import clean_noaa_data, stable_noaa_event_key
from .collectors.aprsis import aprsis_distance_km, aprsis_float, clean_aprs_data
from .collectors.rayhunter import clean_rayhunter_data, clean_rayhunter_field
from .collectors.swpc import clean_swpc_data, number_or_none, swpc_event_is_alert
from .collectors.usgs import clean_usgs_data
from .device_history import DeviceHistoryBuilder
from .log_utils import (
    count_jsonl_files,
    empty_jsonl_checkpoint,
    event_in_window,
    event_time_epoch,
    has_jsonl_checkpoint,
    now_epoch,
    read_incremental_jsonl_events,
    record_time_epoch,
    save_json_atomic,
    timestamp_epoch,
    window_metadata,
)


class SubjectHistoryBuilder:
    """Build one materialized subject-history summary for all collectors."""

    DEVICE_COLLECTORS = DeviceHistoryBuilder.COLLECTORS
    DIRECT_COLLECTORS = (
        "aprsis",
        "rayhunter",
        "rtlsdr",
        "noaa",
        "usgs",
        "swpc",
        "lan",
    )
    COLLECTORS = DEVICE_COLLECTORS + DIRECT_COLLECTORS

    def __init__(
        self,
        log_dir,
        state_path=None,
        device_history_state_path=None,
        window_days=None,
    ):
        self.log_dir = log_dir
        self.state_path = state_path or os.path.join(
            log_dir, "device_history", "subject_history.json"
        )
        self.device_history_state_path = device_history_state_path or os.path.join(
            log_dir, "device_history", "device_history.json"
        )
        self.window_days = window_days

    def build(self, device_history_summary=None, persist=True):
        """Return a display-ready Subject History summary."""
        summary = self.build_summary(device_history_summary=device_history_summary)
        if persist:
            self.save_summary(summary)
        return self.display_summary(summary, self.window_days)

    def build_summary(self, device_history_summary=None):
        """Build the materialized summary for the selected view window.

        Wi-Fi/Bluetooth use the existing incremental Device History fold because
        it owns session, signal, vendor, and live-overlay behavior. APRS-IS,
        Rayhunter, and RTL-SDR are folded here so Reports no longer have separate
        raw-log readers for each collector.
        """
        device_history_summary = copy.deepcopy(device_history_summary or {})
        (
            direct_observations,
            direct_checkpoint,
            direct_records,
            direct_incremental_records,
        ) = self.build_direct_observations()
        aprsis_events, aprsis_records = self.build_aprsis_history(
            direct_observations.get("aprsis") or [], None
        )
        rayhunter_events, rayhunter_records = self.build_rayhunter_history(
            direct_observations.get("rayhunter") or [], None
        )
        rtlsdr_events, rtlsdr_records = self.build_rtlsdr_history(
            direct_observations.get("rtlsdr") or [], None
        )
        noaa_events, noaa_records = self.build_noaa_history(
            direct_observations.get("noaa") or [], None
        )
        usgs_events, usgs_records = self.build_usgs_history(
            direct_observations.get("usgs") or [], None
        )
        swpc_events, swpc_records = self.build_swpc_history(
            direct_observations.get("swpc") or [], None
        )
        lan_events, lan_records = self.build_lan_history(
            direct_observations.get("lan") or [], None
        )
        generated_at_epoch = now_epoch()
        raw_records = self.raw_records_by_collector(
            device_history_summary,
            {
                "aprsis": aprsis_records,
                "rayhunter": rayhunter_records,
                "rtlsdr": rtlsdr_records,
                "noaa": noaa_records,
                "usgs": usgs_records,
                "swpc": swpc_records,
                "lan": lan_records,
            },
        )
        incremental_records = self.incremental_records_by_collector(
            device_history_summary, direct_incremental_records
        )
        summary = {
            "schema": "subject_history.v1",
            "generated_at": local_now(generated_at_epoch),
            "generated_at_epoch": generated_at_epoch,
            "log_dir": self.log_dir,
            "state_path": self.state_path,
            "device_history_state_path": self.device_history_state_path,
            "window": window_metadata(None),
            "materialized_window": window_metadata(None),
            "files_read": sum(
                count_jsonl_files(self.log_dir, collector)
                for collector in self.COLLECTORS
            ),
            "records_read": sum(raw_records.values()),
            "incremental_records_read": sum(incremental_records.values()),
            "raw_records_read": raw_records,
            "incremental_records_read_by_collector": incremental_records,
            "raw_log_files": {
                collector: count_jsonl_files(self.log_dir, collector)
                for collector in self.COLLECTORS
            },
            "checkpoint": self.merge_jsonl_checkpoints(
                device_history_summary.get("checkpoint"), direct_checkpoint
            ),
            "direct_observations": direct_observations,
            "wifi": copy.deepcopy(
                device_history_summary.get("wifi")
                or {"access_points": [], "clients": []}
            ),
            "ble": copy.deepcopy(
                device_history_summary.get("ble") or {"devices": []}
            ),
            "bluetooth": copy.deepcopy(
                device_history_summary.get("bluetooth")
                or device_history_summary.get("ble")
                or {"devices": []}
            ),
            "aprsis": aprsis_events,
            "rayhunter": rayhunter_events,
            "rtlsdr": rtlsdr_events,
            "noaa": noaa_events,
            "usgs": usgs_events,
            "swpc": swpc_events,
            "lan": lan_events,
        }
        summary["subjects"] = self.build_subject_records(summary)
        summary["subject_counts"] = self.count_subjects(summary["subjects"])
        return summary

    def raw_records_by_collector(self, device_history_summary, direct_records):
        """Return collector record counts using the best available source."""
        counts = {}
        source = (device_history_summary or {}).get("raw_records_read") or {}
        for collector in self.DEVICE_COLLECTORS:
            counts[collector] = int(source.get(collector) or 0)
        for collector, value in direct_records.items():
            counts[collector] = int(value or 0)
        return counts

    def incremental_records_by_collector(self, device_history_summary, direct_records):
        """Return per-refresh record counts across device and direct collectors."""
        counts = {}
        source = (
            (device_history_summary or {}).get(
                "incremental_records_read_by_collector"
            )
            or {}
        )
        for collector in self.DEVICE_COLLECTORS:
            counts[collector] = int(source.get(collector) or 0)
        for collector, value in direct_records.items():
            counts[collector] = int(value or 0)
        return counts

    def merge_jsonl_checkpoints(self, *checkpoints):
        """Merge device and direct collector offsets into one Subject checkpoint."""
        merged = empty_jsonl_checkpoint()
        for checkpoint in checkpoints:
            if not isinstance(checkpoint, dict):
                continue
            for collector, files in (checkpoint.get("collectors") or {}).items():
                merged["collectors"][collector] = copy.deepcopy(files or {})
        for collector in self.COLLECTORS:
            merged["collectors"].setdefault(collector, {})
        return merged

    def display_summary(self, summary, window_days):
        """Return the selected-window view without rereading raw logs."""
        summary = summary or {}
        output = {
            key: value
            for key, value in summary.items()
            if key
            not in (
                "wifi",
                "ble",
                "bluetooth",
                "aprsis",
                "rayhunter",
                "rtlsdr",
            "noaa",
            "usgs",
            "swpc",
            "lan",
            "subjects",
                "subject_counts",
                "direct_observations",
            )
        }
        device_display = DeviceHistoryBuilder(
            self.log_dir,
            state_path=self.device_history_state_path,
            window_days=window_days,
        ).display_summary(summary, window_days)
        output["wifi"] = device_display.get("wifi") or {
            "access_points": [],
            "clients": [],
        }
        output["ble"] = device_display.get("ble") or {"devices": []}
        output["bluetooth"] = device_display.get("bluetooth") or output["ble"]
        direct_observations = summary.get("direct_observations") or {}
        output["aprsis"], _ = self.build_aprsis_history(
            direct_observations.get("aprsis") or [], window_days
        )
        output["rayhunter"], _ = self.build_rayhunter_history(
            direct_observations.get("rayhunter") or [], window_days
        )
        output["rtlsdr"], _ = self.build_rtlsdr_history(
            direct_observations.get("rtlsdr") or [], window_days
        )
        output["noaa"], _ = self.build_noaa_history(
            direct_observations.get("noaa") or [], window_days
        )
        output["usgs"], _ = self.build_usgs_history(
            direct_observations.get("usgs") or [], window_days
        )
        output["swpc"], _ = self.build_swpc_history(
            direct_observations.get("swpc") or [], window_days
        )
        output["lan"], _ = self.build_lan_history(
            direct_observations.get("lan") or [], window_days
        )
        output["subjects"] = self.build_subject_records(output)
        output["subject_counts"] = self.count_subjects(output["subjects"])
        output["window"] = window_metadata(window_days)
        output["materialized_window"] = summary.get("window") or window_metadata(
            window_days
        )
        output["raw_logs_incremental"] = True
        return output

    def save_summary(self, summary):
        """Persist the subject-history summary."""
        save_json_atomic(self.state_path, summary)

    def load_persisted_summary(self):
        """Load persisted subject history if present."""
        try:
            import json

            with open(self.state_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def build_direct_observations(self):
        """Fold direct collectors incrementally into compact retained events."""
        previous = self.load_persisted_summary()
        previous_observations = (
            previous.get("direct_observations")
            if isinstance(previous, dict)
            else None
        )
        use_previous = (
            isinstance(previous_observations, dict)
            and has_jsonl_checkpoint(previous)
        )
        observations = self.normalized_direct_observations(
            previous_observations if use_previous else {}
        )
        checkpoint = (
            copy.deepcopy(previous.get("checkpoint") or empty_jsonl_checkpoint())
            if use_previous
            else empty_jsonl_checkpoint()
        )
        incremental_records = defaultdict(int)
        for collector in self.DIRECT_COLLECTORS:
            for event in read_incremental_jsonl_events(
                self.log_dir, collector, checkpoint
            ):
                observation = self.direct_observation_from_event(collector, event)
                if observation is None:
                    continue
                observations[collector].append(observation)
                incremental_records[collector] += 1
        total_records = {
            collector: len(observations.get(collector) or [])
            for collector in self.DIRECT_COLLECTORS
        }
        return (
            observations,
            checkpoint,
            total_records,
            {
                collector: int(incremental_records.get(collector) or 0)
                for collector in self.DIRECT_COLLECTORS
            },
        )

    def normalized_direct_observations(self, source):
        """Return durable direct observations in the current event shape."""
        observations = {collector: [] for collector in self.DIRECT_COLLECTORS}
        if not isinstance(source, dict):
            return observations
        for collector in self.DIRECT_COLLECTORS:
            for event in source.get(collector) or []:
                observation = self.direct_observation_from_event(collector, event)
                if observation is not None:
                    observations[collector].append(observation)
        return observations

    def direct_observation_from_event(self, collector, event):
        """Return one compact direct-collector event, or None if not reportable."""
        if not isinstance(event, dict):
            return None
        event_type = event.get("type") or ""
        if not self.supported_direct_event_type(collector, event_type):
            return None
        epoch = event_time_epoch(event)
        if epoch is None:
            return None
        data = self.clean_direct_data(collector, event.get("data") or {})
        if event_type.startswith("aprs_") and not data.get("callsign"):
            return None
        severity = event.get("severity") or "info"
        return {
            "collector": collector,
            "type": event_type,
            "timestamp": event.get("timestamp") or local_now(epoch),
            "timestamp_epoch": epoch,
            "severity": severity,
            "data": data,
        }

    def supported_direct_event_type(self, collector, event_type):
        """Return True for direct collector events that feed Subject History."""
        if collector == "aprsis":
            return event_type in (
                "collector_online",
                "collector_offline",
                "collector_retrying",
            ) or event_type.startswith("aprs_")
        if collector == "rayhunter":
            return event_type in (
                "rayhunter_status",
                "collector_offline",
                "collector_retrying",
            )
        if collector == "rtlsdr":
            return event_type in (
                "scanner_started",
                "baseline_ready",
                "signal_detected",
                "signal_lost",
                "collector_offline",
                "collector_retrying",
            )
        if collector == "noaa":
            return event_type in (
                "noaa_weather_alert",
                "noaa_tropical_advisory",
                "collector_offline",
                "collector_retrying",
            )
        if collector == "usgs":
            return event_type in (
                "usgs_earthquake",
                "collector_offline",
                "collector_retrying",
            )
        if collector == "swpc":
            return event_type in (
                "swpc_event",
                "collector_offline",
                "collector_retrying",
            )
        if collector == "lan":
            return event_type in (
                "lan_device_seen",
                "lan_device_changed",
                "lan_gateway_seen",
                "lan_gateway_changed",
                "collector_offline",
                "collector_retrying",
            )
        return False

    def clean_direct_data(self, collector, data):
        """Scrub direct collector payloads before they become durable history."""
        if collector == "aprsis":
            return clean_aprs_data(data)
        if collector == "rayhunter":
            return clean_rayhunter_data(data)
        if collector == "rtlsdr":
            return self.clean_rtlsdr_data(data)
        if collector == "noaa":
            return clean_noaa_data(data)
        if collector == "usgs":
            return clean_usgs_data(data)
        if collector == "swpc":
            return clean_swpc_data(data)
        if collector == "lan":
            return clean_lan_data(data)
        return {}

    def clean_rtlsdr_data(self, data):
        """Return compact RTL-SDR fields needed for frequency history."""
        if not isinstance(data, dict):
            return {}
        cleaned = {}
        for key in (
            "frequency_mhz",
            "power_dbm",
            "above_floor_db",
            "range",
            "gain",
            "threshold_db",
            "baseline_period_sec",
            "bins",
        ):
            value = data.get(key)
            if value not in (None, "", [], {}):
                cleaned[key] = value
        reason = data.get("reason")
        if reason not in (None, ""):
            cleaned["reason"] = str(reason)[:180]
        return cleaned

    def build_aprsis_history(self, observations, window_days):
        """Return compact per-callsign APRS-IS summaries for this view window."""
        records_read = 0
        stations = {}
        latest_health = {}
        latest_health_epoch = None
        latest_epoch = None
        for event in sorted(
            observations or [], key=lambda item: event_time_epoch(item) or 0
        ):
            if not event_in_window(event, window_days):
                continue
            event_type = event.get("type") or ""
            if event_type not in (
                "collector_online",
                "collector_offline",
                "collector_retrying",
            ) and not event_type.startswith("aprs_"):
                continue
            epoch = event_time_epoch(event)
            if epoch is None:
                continue
            records_read += 1
            data = clean_aprs_data(event.get("data") or {})
            if event_type in (
                "collector_online",
                "collector_offline",
                "collector_retrying",
            ):
                latest_health = dict(data)
                latest_health["collector_state"] = {
                    "collector_online": "ONLINE",
                    "collector_offline": "OFFLINE",
                    "collector_retrying": "RETRYING",
                }.get(event_type, "")
                latest_health_epoch = epoch
                latest_epoch = epoch if latest_epoch is None else max(latest_epoch, epoch)
                continue

            callsign = data.get("callsign") or "unknown"
            station = stations.setdefault(
                callsign,
                self.aprsis_station_summary_template(callsign, data, epoch),
            )
            self.aprsis_update_station_summary(station, data, event_type, epoch)
            latest_epoch = epoch if latest_epoch is None else max(latest_epoch, epoch)
        if not records_read:
            return [], 0

        output = []
        for station in sorted(
            stations.values(),
            key=lambda item: (
                item.get("last_seen_epoch") or 0,
                item.get("packet_count") or 0,
            ),
            reverse=True,
        ):
            summary = self.aprsis_finalize_station_summary(station)
            output.append(
                {
                    "collector": "aprsis",
                    "type": "aprsis_station_summary",
                    "timestamp": local_now(summary.get("last_seen_epoch") or latest_epoch),
                    "timestamp_epoch": summary.get("last_seen_epoch") or latest_epoch,
                    "severity": "info",
                    "data": clean_aprs_data(summary),
                }
            )

        if latest_health and (
            latest_health.get("collector_state") != "ONLINE" or not output
        ):
            health = dict(latest_health)
            health["events_in_window"] = records_read
            health["last_seen"] = local_now(latest_health_epoch)
            health["last_seen_epoch"] = latest_health_epoch
            health["internet_fed"] = True
            output.append(
                {
                    "collector": "aprsis",
                    "type": "aprsis_collector_summary",
                    "timestamp": local_now(latest_health_epoch),
                    "timestamp_epoch": latest_health_epoch,
                    "severity": "warning"
                    if latest_health.get("collector_state") != "ONLINE"
                    else "info",
                    "data": clean_aprs_data(health),
                }
            )
        return output, records_read

    def aprsis_station_summary_template(self, callsign, data, epoch):
        """Return an empty retained APRS summary for one source callsign."""
        return {
            "callsign": callsign,
            "host": data.get("host") or "",
            "port": data.get("port") or "",
            "filter": data.get("filter") or "",
            "feed_name": data.get("feed_name") or "",
            "feed_role": data.get("feed_role") or "",
            "server_name": data.get("server_name") or "",
            "server_address": data.get("server_address") or "",
            "preferred_servers": data.get("preferred_servers") or [],
            "packet_count": 0,
            "position_count": 0,
            "object_count": 0,
            "message_count": 0,
            "status_count": 0,
            "weather_count": 0,
            "other_count": 0,
            "sample_destinations": [],
            "sample_paths": [],
            "sample_igates": [],
            "sample_feeds": [],
            "sample_feed_roles": [],
            "sample_servers": [],
            "sample_objects": [],
            "sample_messages": [],
            "first_seen": local_now(epoch),
            "first_seen_epoch": epoch,
            "last_seen": local_now(epoch),
            "last_seen_epoch": epoch,
            "internet_fed": True,
        }

    def aprsis_update_station_summary(self, station, data, event_type, epoch):
        """Fold one decoded APRS packet into its callsign summary."""
        packet_type = data.get("packet_type") or event_type.replace("aprs_", "")
        station["packet_count"] += 1
        count_key = "{}_count".format(packet_type)
        if count_key in station:
            station[count_key] += 1
        else:
            station["other_count"] += 1
        if epoch < station.get("first_seen_epoch", epoch):
            station["first_seen_epoch"] = epoch
            station["first_seen"] = local_now(epoch)
        if epoch >= station.get("last_seen_epoch", 0):
            self.aprsis_update_latest_station_fields(
                station, data, packet_type, epoch
            )

        self.aprsis_sample(station, "sample_destinations", data.get("destination"))
        self.aprsis_sample(station, "sample_paths", data.get("via_path"))
        self.aprsis_sample(station, "sample_igates", data.get("igate"))
        self.aprsis_sample(station, "sample_feeds", data.get("feed_name"))
        self.aprsis_sample(station, "sample_feed_roles", data.get("feed_role"))
        self.aprsis_sample(station, "sample_servers", data.get("server_name"))
        self.aprsis_sample(station, "sample_objects", data.get("object_name"))
        self.aprsis_sample(
            station,
            "sample_messages",
            data.get("message") or data.get("comment"),
        )
        self.aprsis_update_position_summary(station, data)
        self.aprsis_update_weather_summary(station, data, epoch)

    def aprsis_update_latest_station_fields(self, station, data, packet_type, epoch):
        """Store latest decoded APRS fields that make report rows readable."""
        station["last_seen_epoch"] = epoch
        station["last_seen"] = local_now(epoch)
        station["packet_type"] = packet_type
        for key in (
            "destination",
            "path",
            "via_path",
            "q_construct",
            "igate",
            "host",
            "port",
            "filter",
            "feed_name",
            "feed_role",
            "server_name",
            "server_address",
            "preferred_servers",
            "distance_from_filter_km",
            "geofence_enforced",
            "geofence_latitude",
            "geofence_longitude",
            "geofence_radius_km",
            "aprs_format",
            "mic_e_message",
            "object_name",
            "addressee",
            "message",
            "comment",
            "weather_summary",
            "symbol",
            "symbol_code",
            "symbol_table",
            "latitude",
            "longitude",
            "speed_knots",
            "speed_kmh",
            "course_deg",
            "wind_direction_deg",
            "wind_speed_mph",
            "wind_gust_mph",
            "temperature_f",
            "rain_1h_in",
            "rain_24h_in",
            "rain_since_midnight_in",
            "humidity_percent",
            "pressure_hpa",
            "luminosity_w_m2",
            "snow_in",
        ):
            if data.get(key) not in (None, "", []):
                station[key] = data.get(key)

    def aprsis_update_position_summary(self, station, data):
        """Update bounded position and movement statistics for a station."""
        latitude = aprsis_float(data.get("latitude"))
        longitude = aprsis_float(data.get("longitude"))
        if latitude is None or longitude is None:
            return
        if station.get("first_latitude") is None:
            station["first_latitude"] = latitude
            station["first_longitude"] = longitude
        previous = station.get("_last_position")
        if previous:
            step = aprsis_distance_km(previous[0], previous[1], latitude, longitude)
            if step is not None:
                station["max_step_km"] = max(
                    float(station.get("max_step_km") or 0), step
                )
        station["_last_position"] = (latitude, longitude)
        station["last_latitude"] = latitude
        station["last_longitude"] = longitude
        station["min_latitude"] = min(
            float(station.get("min_latitude", latitude)), latitude
        )
        station["max_latitude"] = max(
            float(station.get("max_latitude", latitude)), latitude
        )
        station["min_longitude"] = min(
            float(station.get("min_longitude", longitude)), longitude
        )
        station["max_longitude"] = max(
            float(station.get("max_longitude", longitude)), longitude
        )
        speed = aprsis_float(data.get("speed_kmh"))
        if speed is not None:
            station["max_speed_kmh"] = max(
                float(station.get("max_speed_kmh") or 0), speed
            )

    def aprsis_update_weather_summary(self, station, data, epoch):
        """Update bounded weather statistics for a station."""
        if (data.get("packet_type") or "") != "weather" and not data.get(
            "weather_summary"
        ):
            return
        station["weather_station"] = True
        temperature = aprsis_float(data.get("temperature_f"))
        if temperature is not None:
            if station.get("_first_temperature_f") is None:
                station["_first_temperature_f"] = temperature
            station["temperature_min_f"] = min(
                float(station.get("temperature_min_f", temperature)), temperature
            )
            station["temperature_max_f"] = max(
                float(station.get("temperature_max_f", temperature)), temperature
            )
            station["temperature_change_f"] = round(
                temperature - float(station.get("_first_temperature_f", temperature)),
                1,
            )
        wind_speed = aprsis_float(data.get("wind_speed_mph"))
        if wind_speed is not None:
            station["wind_speed_max_mph"] = max(
                float(station.get("wind_speed_max_mph") or 0), wind_speed
            )
            station["latest_wind_speed_mph"] = wind_speed
        wind_gust = aprsis_float(data.get("wind_gust_mph"))
        if wind_gust is not None:
            station["wind_gust_max_mph"] = max(
                float(station.get("wind_gust_max_mph") or 0), wind_gust
            )
            station["latest_wind_gust_mph"] = wind_gust
        rain_1h = aprsis_float(data.get("rain_1h_in"))
        if rain_1h is not None:
            previous_rain = station.get("_last_rain_1h_in")
            if previous_rain is not None and previous_rain <= 0 < rain_1h:
                station["rain_started"] = True
                station["rain_started_at"] = local_now(epoch)
                station["rain_started_epoch"] = epoch
                station["rain_episode_started_at"] = local_now(epoch)
                station["rain_episode_started_epoch"] = epoch
                station["_rain_current_start_at"] = local_now(epoch)
                station["_rain_current_start_epoch"] = epoch
                station["rain_last_transition"] = "started"
                station["rain_last_transition_at"] = local_now(epoch)
                station["rain_last_transition_epoch"] = epoch
            if previous_rain is not None and previous_rain > 0 and rain_1h <= 0:
                station["rain_stopped"] = True
                station["rain_stopped_at"] = local_now(epoch)
                station["rain_stopped_epoch"] = epoch
                station["rain_episode_started_at"] = (
                    station.get("_rain_current_start_at")
                    or station.get("rain_episode_started_at")
                    or ""
                )
                station["rain_episode_started_epoch"] = (
                    station.get("_rain_current_start_epoch")
                    or station.get("rain_episode_started_epoch")
                )
                station["rain_episode_stopped_at"] = local_now(epoch)
                station["rain_episode_stopped_epoch"] = epoch
                station.pop("_rain_current_start_at", None)
                station.pop("_rain_current_start_epoch", None)
                station["rain_last_transition"] = "stopped"
                station["rain_last_transition_at"] = local_now(epoch)
                station["rain_last_transition_epoch"] = epoch
            station["rain_1h_max_in"] = max(
                float(station.get("rain_1h_max_in") or 0), rain_1h
            )
            station["latest_rain_1h_in"] = rain_1h
            station["rain_active"] = rain_1h > 0
            station["_last_rain_1h_in"] = rain_1h

    def aprsis_finalize_station_summary(self, station):
        """Return a JSON-safe APRS station summary with movement fields."""
        summary = {
            key: value
            for key, value in station.items()
            if not str(key).startswith("_")
        }
        if all(
            summary.get(key) is not None
            for key in (
                "min_latitude",
                "min_longitude",
                "max_latitude",
                "max_longitude",
            )
        ):
            span = aprsis_distance_km(
                summary["min_latitude"],
                summary["min_longitude"],
                summary["max_latitude"],
                summary["max_longitude"],
            )
            if span is not None:
                summary["position_span_km"] = round(span, 3)
        if all(
            summary.get(key) is not None
            for key in (
                "first_latitude",
                "first_longitude",
                "last_latitude",
                "last_longitude",
            )
        ):
            movement = aprsis_distance_km(
                summary["first_latitude"],
                summary["first_longitude"],
                summary["last_latitude"],
                summary["last_longitude"],
            )
            if movement is not None:
                summary["movement_km"] = round(movement, 3)
        if summary.get("max_step_km") is not None:
            summary["max_step_km"] = round(float(summary["max_step_km"]), 3)
        if summary.get("max_speed_kmh") is not None:
            summary["max_speed_kmh"] = round(float(summary["max_speed_kmh"]), 1)
        span = float(summary.get("position_span_km") or 0)
        speed = float(summary.get("max_speed_kmh") or 0)
        summary["movement_detected"] = bool(span >= 0.3 or speed >= 5.0)
        return summary

    def aprsis_sample(self, station, key, value, limit=8):
        """Append one compact APRS sample value without growing unbounded lists."""
        if value in (None, "", []):
            return
        text = str(value).strip()
        if not text or text in station[key]:
            return
        if len(station[key]) < limit:
            station[key].append(text)

    def build_rayhunter_history(self, observations, window_days):
        """Return the latest Rayhunter endpoint status for this view window."""
        latest = None
        latest_epoch = None
        records_read = 0
        warning_events = 0
        for event in observations or []:
            if not event_in_window(event, window_days):
                continue
            event_type = event.get("type")
            if event_type not in (
                "rayhunter_status",
                "collector_offline",
                "collector_retrying",
            ):
                continue
            records_read += 1
            data = event.get("data") or {}
            try:
                warning_count = int(float(data.get("warning_count") or 0))
            except (TypeError, ValueError):
                warning_count = 0
            if event_type != "rayhunter_status" or warning_count > 0:
                warning_events += 1
            epoch = event_time_epoch(event)
            if epoch is None:
                continue
            if latest_epoch is None or epoch >= latest_epoch:
                latest = copy.deepcopy(event)
                latest_epoch = epoch
        if not latest:
            return [], records_read
        latest.setdefault("data", {})
        latest["data"] = clean_rayhunter_data(latest["data"])
        latest["data"]["events_in_window"] = records_read
        latest["data"]["warning_events_in_window"] = warning_events
        return [latest], records_read

    def build_rtlsdr_history(self, observations, window_days):
        """Return compact per-frequency RTL-SDR summaries for this view window."""
        frequencies = {}
        latest_health = None
        latest_health_epoch = None
        records_read = 0
        fingerprints = defaultdict(set)
        for event in observations or []:
            if not event_in_window(event, window_days):
                continue
            event_type = event.get("type") or ""
            if event_type not in (
                "scanner_started",
                "baseline_ready",
                "signal_detected",
                "signal_lost",
                "collector_offline",
                "collector_retrying",
            ):
                continue
            epoch = event_time_epoch(event)
            if epoch is None:
                continue
            records_read += 1
            data = event.get("data") or {}
            if event_type in ("collector_offline", "collector_retrying"):
                latest_health = {
                    "collector_state": "OFFLINE"
                    if event_type == "collector_offline"
                    else "RETRYING",
                    "reason": data.get("reason") or "",
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                }
                latest_health_epoch = epoch
                continue
            if event_type not in ("signal_detected", "signal_lost"):
                continue
            frequency = data.get("frequency_mhz")
            if frequency in (None, ""):
                continue
            key = str(frequency)
            record = frequencies.setdefault(
                key,
                {
                    "frequency_mhz": frequency,
                    "first_seen": local_now(epoch),
                    "first_seen_epoch": epoch,
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                    "signal_count": 0,
                    "lost_count": 0,
                    "active": False,
                },
            )
            if epoch < record.get("first_seen_epoch", epoch):
                record["first_seen_epoch"] = epoch
                record["first_seen"] = local_now(epoch)
            if epoch >= record.get("last_seen_epoch", 0):
                record["last_seen_epoch"] = epoch
                record["last_seen"] = local_now(epoch)
            if event_type == "signal_detected":
                record["signal_count"] += 1
                record["active"] = True
                self.update_max_numeric(record, "power_dbm_max", data.get("power_dbm"))
                self.update_max_numeric(
                    record, "above_floor_db_max", data.get("above_floor_db")
                )
            elif event_type == "signal_lost":
                record["lost_count"] += 1
                record["active"] = False
        output = [
            {
                "collector": "rtlsdr",
                "type": "rtlsdr_frequency_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": "warning" if record.get("active") else "info",
                "data": record,
            }
            for record in sorted(
                frequencies.values(),
                key=lambda item: item.get("last_seen_epoch") or 0,
                reverse=True,
            )
        ]
        if latest_health and not output:
            output.append(
                {
                    "collector": "rtlsdr",
                    "type": "rtlsdr_collector_summary",
                    "timestamp": local_now(latest_health_epoch),
                    "timestamp_epoch": latest_health_epoch,
                    "severity": "warning",
                    "data": latest_health,
                }
            )
        return output, records_read

    def build_noaa_history(self, observations, window_days):
        """Return compact per-alert NOAA summaries for this view window."""
        alerts = {}
        latest_health = None
        latest_health_epoch = None
        records_read = 0
        fingerprints = defaultdict(set)
        for event in observations or []:
            if not event_in_window(event, window_days):
                continue
            event_type = event.get("type") or ""
            if event_type not in (
                "noaa_weather_alert",
                "noaa_tropical_advisory",
                "collector_offline",
                "collector_retrying",
            ):
                continue
            epoch = event_time_epoch(event)
            if epoch is None:
                continue
            records_read += 1
            data = clean_noaa_data(event.get("data") or {})
            if event_type in ("collector_offline", "collector_retrying"):
                latest_health = {
                    "collector_state": "OFFLINE"
                    if event_type == "collector_offline"
                    else "RETRYING",
                    "reason": data.get("reason") or "",
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                    "internet_fed": True,
                }
                latest_health_epoch = epoch
                continue
            event_id = stable_noaa_event_key(data, event_type)
            source_event_id = data.get("event_id") or data.get("headline") or "unknown"
            record = alerts.setdefault(
                event_id,
                {
                    "event_id": event_id,
                    "source_event_id": source_event_id,
                    "event_type": event_type,
                    "first_seen": local_now(epoch),
                    "first_seen_epoch": epoch,
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                    "update_count": 0,
                    "internet_fed": True,
                },
            )
            fingerprint = data.get("fingerprint") or "|".join(
                str(data.get(field) or "")
                for field in ("event", "headline", "updated", "summary", "source_url")
            )
            if fingerprint not in fingerprints[event_id]:
                fingerprints[event_id].add(fingerprint)
                record["update_count"] += 1
            if epoch < record.get("first_seen_epoch", epoch):
                record["first_seen_epoch"] = epoch
                record["first_seen"] = local_now(epoch)
            if epoch >= record.get("last_seen_epoch", 0):
                record.update(data)
                record["event_id"] = event_id
                record["source_event_id"] = source_event_id
                record["event_type"] = event_type
                record["last_seen_epoch"] = epoch
                record["last_seen"] = local_now(epoch)
        output = [
            {
                "collector": "noaa",
                "type": "noaa_alert_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": "warning"
                if str(record.get("severity") or "").lower() in ("severe", "extreme")
                else "info",
                "data": clean_noaa_data(record),
            }
            for record in sorted(
                alerts.values(),
                key=lambda item: item.get("last_seen_epoch") or 0,
                reverse=True,
            )
        ]
        if latest_health and not output:
            output.append(
                {
                    "collector": "noaa",
                    "type": "noaa_collector_summary",
                    "timestamp": local_now(latest_health_epoch),
                    "timestamp_epoch": latest_health_epoch,
                    "severity": "warning",
                    "data": clean_noaa_data(latest_health),
                }
            )
        return output, records_read

    def build_usgs_history(self, observations, window_days):
        """Return compact per-event USGS earthquake summaries."""
        earthquakes = {}
        latest_health = None
        latest_health_epoch = None
        records_read = 0
        for event in observations or []:
            if not event_in_window(event, window_days):
                continue
            event_type = event.get("type") or ""
            if event_type not in (
                "usgs_earthquake",
                "collector_offline",
                "collector_retrying",
            ):
                continue
            epoch = event_time_epoch(event)
            if epoch is None:
                continue
            records_read += 1
            data = clean_usgs_data(event.get("data") or {})
            if event_type in ("collector_offline", "collector_retrying"):
                latest_health = {
                    "collector_state": "OFFLINE"
                    if event_type == "collector_offline"
                    else "RETRYING",
                    "reason": data.get("reason") or "",
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                    "internet_fed": True,
                }
                latest_health_epoch = epoch
                continue
            event_id = data.get("event_id") or "unknown"
            record = earthquakes.setdefault(
                event_id,
                {
                    "event_id": event_id,
                    "first_seen": local_now(epoch),
                    "first_seen_epoch": epoch,
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                    "update_count": 0,
                    "internet_fed": True,
                },
            )
            record["update_count"] += 1
            if epoch < record.get("first_seen_epoch", epoch):
                record["first_seen_epoch"] = epoch
                record["first_seen"] = local_now(epoch)
            if epoch >= record.get("last_seen_epoch", 0):
                record.update(data)
                record["event_id"] = event_id
                record["last_seen_epoch"] = epoch
                record["last_seen"] = local_now(epoch)
        output = [
            {
                "collector": "usgs",
                "type": "usgs_earthquake_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": "warning"
                if record.get("tsunami") or str(record.get("alert_color") or "").lower() in ("yellow", "orange", "red")
                else "info",
                "data": clean_usgs_data(record),
            }
            for record in sorted(
                earthquakes.values(),
                key=lambda item: item.get("last_seen_epoch") or 0,
                reverse=True,
            )
        ]
        if latest_health and not output:
            output.append(
                {
                    "collector": "usgs",
                    "type": "usgs_collector_summary",
                    "timestamp": local_now(latest_health_epoch),
                    "timestamp_epoch": latest_health_epoch,
                    "severity": "warning",
                    "data": clean_usgs_data(latest_health),
                }
            )
        return output, records_read

    def build_swpc_history(self, observations, window_days):
        """Return compact per-event SWPC space-weather summaries."""
        events = {}
        latest_health = None
        latest_health_epoch = None
        records_read = 0
        for event in observations or []:
            if not event_in_window(event, window_days):
                continue
            event_type = event.get("type") or ""
            if event_type not in (
                "swpc_event",
                "collector_offline",
                "collector_retrying",
            ):
                continue
            epoch = event_time_epoch(event)
            if epoch is None:
                continue
            records_read += 1
            data = clean_swpc_data(event.get("data") or {})
            if event_type in ("collector_offline", "collector_retrying"):
                latest_health = {
                    "collector_state": "OFFLINE"
                    if event_type == "collector_offline"
                    else "RETRYING",
                    "reason": data.get("reason") or "",
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                    "internet_fed": True,
                }
                latest_health_epoch = epoch
                continue
            event_id = data.get("event_id") or data.get("summary") or "swpc"
            record = events.setdefault(
                event_id,
                {
                    "event_id": event_id,
                    "first_seen": local_now(epoch),
                    "first_seen_epoch": epoch,
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                    "update_count": 0,
                    "internet_fed": True,
                },
            )
            record["update_count"] += 1
            if epoch < record.get("first_seen_epoch", epoch):
                record["first_seen_epoch"] = epoch
                record["first_seen"] = local_now(epoch)
            if epoch >= record.get("last_seen_epoch", 0):
                record.update(data)
                record["event_id"] = event_id
                record["last_seen_epoch"] = epoch
                record["last_seen"] = local_now(epoch)
        output = [
            {
                "collector": "swpc",
                "type": "swpc_event_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": "warning" if swpc_event_is_alert(record) else "info",
                "data": clean_swpc_data(record),
            }
            for record in sorted(
                events.values(),
                key=lambda item: item.get("last_seen_epoch") or 0,
                reverse=True,
            )
        ]
        if latest_health and not output:
            output.append(
                {
                    "collector": "swpc",
                    "type": "swpc_collector_summary",
                    "timestamp": local_now(latest_health_epoch),
                    "timestamp_epoch": latest_health_epoch,
                    "severity": "warning",
                    "data": clean_swpc_data(latest_health),
                }
            )
        return output, records_read

    def build_lan_history(self, observations, window_days):
        """Return compact per-device and per-gateway LAN summaries."""
        devices = {}
        gateways = {}
        latest_health = None
        latest_health_epoch = None
        records_read = 0
        for event in observations or []:
            if not event_in_window(event, window_days):
                continue
            event_type = event.get("type") or ""
            if event_type not in (
                "lan_device_seen",
                "lan_device_changed",
                "lan_gateway_seen",
                "lan_gateway_changed",
                "collector_offline",
                "collector_retrying",
            ):
                continue
            epoch = event_time_epoch(event)
            if epoch is None:
                continue
            records_read += 1
            data = clean_lan_data(event.get("data") or {})
            if event_type in ("collector_offline", "collector_retrying"):
                latest_health = {
                    "collector_state": "OFFLINE"
                    if event_type == "collector_offline"
                    else "RETRYING",
                    "reason": data.get("reason") or "",
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                }
                latest_health_epoch = epoch
                continue
            if event_type.startswith("lan_gateway"):
                key = "{}:{}".format(data.get("family") or "", data.get("interface") or "")
                record = gateways.setdefault(
                    key,
                    {
                        "subject_key": key,
                        "first_seen": local_now(epoch),
                        "first_seen_epoch": epoch,
                        "last_seen": local_now(epoch),
                        "last_seen_epoch": epoch,
                        "change_count": 0,
                    },
                )
                self.update_lan_gateway_summary(record, data, event_type, epoch)
                continue
            key = data.get("subject_key") or data.get("mac") or data.get("ip") or "unknown"
            record = devices.setdefault(
                key,
                {
                    "subject_key": key,
                    "mac": data.get("mac") or "",
                    "first_seen": local_now(epoch),
                    "first_seen_epoch": epoch,
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                    "observation_count": 0,
                    "change_count": 0,
                    "ips": [],
                    "hostnames": [],
                    "interfaces": [],
                    "states": [],
                    "sources": [],
                    "gateways": [],
                },
            )
            self.update_lan_device_summary(record, data, event_type, epoch)
        output = []
        for record in sorted(
            devices.values(),
            key=lambda item: item.get("last_seen_epoch") or 0,
            reverse=True,
        ):
            output.append(
                {
                    "collector": "lan",
                    "type": "lan_device_summary",
                    "timestamp": record.get("last_seen"),
                    "timestamp_epoch": record.get("last_seen_epoch"),
                    "severity": "info",
                    "data": clean_lan_data(record),
                }
            )
        for record in sorted(
            gateways.values(),
            key=lambda item: item.get("last_seen_epoch") or 0,
            reverse=True,
        ):
            output.append(
                {
                    "collector": "lan",
                    "type": "lan_gateway_summary",
                    "timestamp": record.get("last_seen"),
                    "timestamp_epoch": record.get("last_seen_epoch"),
                    "severity": "warning" if record.get("change_count") else "info",
                    "data": clean_lan_data(record),
                }
            )
        if latest_health and not output:
            output.append(
                {
                    "collector": "lan",
                    "type": "lan_collector_summary",
                    "timestamp": local_now(latest_health_epoch),
                    "timestamp_epoch": latest_health_epoch,
                    "severity": "warning",
                    "data": clean_lan_data(latest_health),
                }
            )
        return output, records_read

    def update_lan_device_summary(self, record, data, event_type, epoch):
        """Fold one LAN device observation into its subject summary."""
        record["observation_count"] = int(record.get("observation_count") or 0) + 1
        if event_type == "lan_device_changed":
            record["change_count"] = int(record.get("change_count") or 0) + 1
        if epoch < record.get("first_seen_epoch", epoch):
            record["first_seen_epoch"] = epoch
            record["first_seen"] = local_now(epoch)
        if epoch >= record.get("last_seen_epoch", 0):
            record["last_seen_epoch"] = epoch
            record["last_seen"] = local_now(epoch)
            for key in (
                "mac",
                "ip",
                "hostname",
                "interface",
                "state",
                "vendor_oui",
                "vendor_prefix",
                "vendor_name",
                "change_type",
            ):
                if data.get(key) not in (None, "", []):
                    record[key] = data.get(key)
            if data.get("gateway"):
                record["gateway"] = True
        for key in ("ips", "hostnames", "interfaces", "states", "sources", "gateways"):
            for value in data.get(key) or []:
                self.sample_direct_value(record, key, value, 16)

    def update_lan_gateway_summary(self, record, data, event_type, epoch):
        """Fold one default-gateway observation into its subject summary."""
        if event_type == "lan_gateway_changed":
            record["change_count"] = int(record.get("change_count") or 0) + 1
        if epoch < record.get("first_seen_epoch", epoch):
            record["first_seen_epoch"] = epoch
            record["first_seen"] = local_now(epoch)
        if epoch >= record.get("last_seen_epoch", 0):
            record["last_seen_epoch"] = epoch
            record["last_seen"] = local_now(epoch)
            for key in (
                "gateway_ip",
                "interface",
                "family",
                "mac",
                "vendor_name",
                "vendor_prefix",
                "change_type",
            ):
                if data.get(key) not in (None, "", []):
                    record[key] = data.get(key)

    def sample_direct_value(self, record, key, value, limit=8):
        """Append one distinct direct-collector sample value."""
        if value in (None, "", []):
            return
        text = str(value).strip()
        if not text:
            return
        record.setdefault(key, [])
        if text not in record[key] and len(record[key]) < limit:
            record[key].append(text)

    def update_max_numeric(self, record, key, value):
        """Update a max numeric field when a collector reports a number."""
        try:
            number = float(value)
        except (TypeError, ValueError):
            return
        old = record.get(key)
        record[key] = number if old is None else max(float(old), number)

    def build_subject_records(self, summary):
        """Return normalized subject rows for every collector family."""
        subjects = []
        wifi = (summary or {}).get("wifi") or {}
        self.add_wifi_subjects(subjects, wifi)
        bluetooth = (summary or {}).get("bluetooth") or (summary or {}).get("ble") or {}
        self.add_bluetooth_subjects(subjects, bluetooth)
        self.add_aprsis_subjects(subjects, (summary or {}).get("aprsis") or [])
        self.add_rayhunter_subjects(subjects, (summary or {}).get("rayhunter") or [])
        self.add_rtlsdr_subjects(subjects, (summary or {}).get("rtlsdr") or [])
        self.add_noaa_subjects(subjects, (summary or {}).get("noaa") or [])
        self.add_usgs_subjects(subjects, (summary or {}).get("usgs") or [])
        self.add_swpc_subjects(subjects, (summary or {}).get("swpc") or [])
        self.add_lan_subjects(subjects, (summary or {}).get("lan") or [])
        subjects.sort(
            key=lambda item: (
                item.get("last_seen_epoch") or 0,
                item.get("collector") or "",
                item.get("subject_id") or "",
            ),
            reverse=True,
        )
        return subjects

    def add_wifi_subjects(self, subjects, wifi):
        """Add SSID, BSSID, and client MAC subjects."""
        aps = [item for item in (wifi or {}).get("access_points") or [] if isinstance(item, dict)]
        clients = [
            item for item in (wifi or {}).get("clients") or [] if isinstance(item, dict)
        ]
        by_ssid = defaultdict(list)
        for ap in aps:
            ssid = ap.get("ssid") or "(blank)"
            by_ssid[ssid].append(ap)
            subjects.append(
                self.subject_record(
                    "wifi",
                    "wifi_bssid",
                    ap.get("bssid") or "unknown",
                    self.wifi_ap_subject(ap),
                    ap,
                    {
                        "ssid": ap.get("ssid") or "",
                        "bssid": ap.get("bssid") or "",
                        "observations": ap.get("observations") or 0,
                        "channels": ap.get("channels") or [],
                        "signal_max": ap.get("signal_max"),
                    },
                )
            )
        for ssid, ssid_aps in by_ssid.items():
            if ssid == "(blank)":
                continue
            first = min(
                ssid_aps,
                key=lambda item: record_time_epoch(item, "first_seen") or float("inf"),
            )
            last = max(
                ssid_aps,
                key=lambda item: record_time_epoch(item, "last_seen") or 0,
            )
            bssids = [ap.get("bssid") for ap in ssid_aps if ap.get("bssid")]
            subjects.append(
                self.subject_record(
                    "wifi",
                    "wifi_ssid",
                    "ssid:{}".format(ssid),
                    ssid,
                    {
                        "first_seen": first.get("first_seen"),
                        "first_seen_epoch": record_time_epoch(first, "first_seen"),
                        "last_seen": last.get("last_seen"),
                        "last_seen_epoch": record_time_epoch(last, "last_seen"),
                    },
                    {
                        "ssid": ssid,
                        "bssid_count": len(bssids),
                        "bssids": bssids[:24],
                        "observations": sum(int(ap.get("observations") or 0) for ap in ssid_aps),
                    },
                )
            )
        for client in clients:
            subjects.append(
                self.subject_record(
                    "wifi",
                    "wifi_client",
                    client.get("mac") or "unknown",
                    client.get("mac") or "unknown",
                    client,
                    {
                        "mac": client.get("mac") or "",
                        "probe_count": client.get("probe_count") or 0,
                        "association_count": client.get("association_count") or 0,
                        "signal_max": client.get("signal_max"),
                    },
                )
            )

    def add_bluetooth_subjects(self, subjects, bluetooth):
        """Add Bluetooth identity subjects keyed by MAC."""
        for device in (bluetooth or {}).get("devices") or []:
            if not isinstance(device, dict):
                continue
            mac = device.get("mac") or "unknown"
            names = [
                str(name).strip()
                for name in device.get("names") or []
                if str(name).strip()
            ]
            label = " - ".join([names[0], mac]) if names else mac
            subjects.append(
                self.subject_record(
                    "bluetooth",
                    "bluetooth_device",
                    mac,
                    label,
                    device,
                    {
                        "mac": mac,
                        "names": names[:6],
                        "seen_count": device.get("seen_count") or 0,
                        "transports": device.get("transports") or [],
                        "signal_max": device.get("signal_max"),
                    },
                )
            )

    def add_aprsis_subjects(self, subjects, events):
        """Add APRS callsign/object subjects."""
        for event in events:
            data = clean_aprs_data((event or {}).get("data") or {})
            if (event or {}).get("type") == "aprsis_collector_summary":
                subject_id = data.get("host") or "aprsis"
                subject = "APRS-IS {}".format(subject_id)
                subject_type = "aprsis_collector"
            else:
                subject_id = data.get("callsign") or "unknown"
                subject = subject_id
                if data.get("weather_station"):
                    subject_type = "aprsis_weather_station"
                elif data.get("object_count"):
                    subject_type = "aprsis_object"
                else:
                    subject_type = "aprsis_station"
            subjects.append(
                self.subject_record(
                    "aprsis",
                    subject_type,
                    subject_id,
                    subject,
                    {
                        "first_seen": data.get("first_seen"),
                        "first_seen_epoch": data.get("first_seen_epoch"),
                        "last_seen": data.get("last_seen") or event.get("timestamp"),
                        "last_seen_epoch": data.get("last_seen_epoch")
                        or event.get("timestamp_epoch"),
                    },
                    {
                        "callsign": data.get("callsign") or "",
                        "packet_count": data.get("packet_count") or 0,
                        "position_count": data.get("position_count") or 0,
                        "weather_count": data.get("weather_count") or 0,
                        "object_count": data.get("object_count") or 0,
                        "message_count": data.get("message_count") or 0,
                        "status_count": data.get("status_count") or 0,
                        "packet_type": data.get("packet_type") or "",
                        "weather_station": bool(data.get("weather_station")),
                        "movement_detected": bool(data.get("movement_detected")),
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "last_latitude": data.get("last_latitude"),
                        "last_longitude": data.get("last_longitude"),
                        "position_span_km": data.get("position_span_km"),
                        "movement_km": data.get("movement_km"),
                        "max_speed_kmh": data.get("max_speed_kmh"),
                        "max_step_km": data.get("max_step_km"),
                        "weather_summary": data.get("weather_summary") or "",
                        "temperature_f": data.get("temperature_f"),
                        "temperature_min_f": data.get("temperature_min_f"),
                        "temperature_max_f": data.get("temperature_max_f"),
                        "temperature_change_f": data.get("temperature_change_f"),
                        "wind_direction_deg": data.get("wind_direction_deg"),
                        "wind_speed_mph": data.get("wind_speed_mph"),
                        "wind_gust_mph": data.get("wind_gust_mph"),
                        "latest_wind_speed_mph": data.get("latest_wind_speed_mph"),
                        "latest_wind_gust_mph": data.get("latest_wind_gust_mph"),
                        "latest_rain_1h_in": data.get("latest_rain_1h_in"),
                        "rain_1h_max_in": data.get("rain_1h_max_in"),
                        "rain_started": data.get("rain_started"),
                        "rain_started_at": data.get("rain_started_at") or "",
                        "rain_started_epoch": data.get("rain_started_epoch"),
                        "rain_stopped": data.get("rain_stopped"),
                        "rain_stopped_at": data.get("rain_stopped_at") or "",
                        "rain_stopped_epoch": data.get("rain_stopped_epoch"),
                        "rain_active": bool(data.get("rain_active")),
                        "rain_last_transition": data.get("rain_last_transition") or "",
                        "rain_last_transition_at": data.get("rain_last_transition_at")
                        or "",
                        "rain_last_transition_epoch": data.get(
                            "rain_last_transition_epoch"
                        ),
                        "rain_episode_started_at": data.get(
                            "rain_episode_started_at"
                        )
                        or "",
                        "rain_episode_started_epoch": data.get(
                            "rain_episode_started_epoch"
                        ),
                        "rain_episode_stopped_at": data.get(
                            "rain_episode_stopped_at"
                        )
                        or "",
                        "rain_episode_stopped_epoch": data.get(
                            "rain_episode_stopped_epoch"
                        ),
                        "humidity_percent": data.get("humidity_percent"),
                        "pressure_hpa": data.get("pressure_hpa"),
                        "luminosity_w_m2": data.get("luminosity_w_m2"),
                        "destination": data.get("destination") or "",
                        "via_path": data.get("via_path") or "",
                        "q_construct": data.get("q_construct") or "",
                        "igate": data.get("igate") or "",
                        "object_name": data.get("object_name") or "",
                        "message": data.get("message") or "",
                        "comment": data.get("comment") or "",
                        "feed_name": data.get("feed_name") or "",
                        "feed_role": data.get("feed_role") or "",
                        "server_name": data.get("server_name") or "",
                        "server_address": data.get("server_address") or "",
                        "preferred_servers": data.get("preferred_servers") or [],
                        "host": data.get("host") or "",
                        "filter": data.get("filter") or "",
                        "sample_igates": data.get("sample_igates") or [],
                        "sample_feeds": data.get("sample_feeds") or [],
                        "sample_servers": data.get("sample_servers") or [],
                        "sample_objects": data.get("sample_objects") or [],
                        "sample_messages": data.get("sample_messages") or [],
                        "internet_fed": True,
                    },
                )
            )

    def add_rayhunter_subjects(self, subjects, events):
        """Add Rayhunter endpoint subjects."""
        for event in events:
            data = clean_rayhunter_data((event or {}).get("data") or {})
            endpoint = clean_rayhunter_field(data.get("endpoint")) or "rayhunter"
            subjects.append(
                self.subject_record(
                    "rayhunter",
                    "rayhunter_endpoint",
                    endpoint,
                    "Rayhunter {}".format(endpoint),
                    {
                        "first_seen": event.get("timestamp"),
                        "first_seen_epoch": event.get("timestamp_epoch"),
                        "last_seen": event.get("timestamp"),
                        "last_seen_epoch": event.get("timestamp_epoch"),
                    },
                    {
                        "endpoint": endpoint,
                        "warning_count": data.get("warning_count") or 0,
                        "events_in_window": data.get("events_in_window") or 0,
                        "warning_events_in_window": data.get(
                            "warning_events_in_window"
                        )
                        or 0,
                        "latest_event": data.get("latest_event") or "",
                        "rayhunter_version": data.get("rayhunter_version") or "",
                        "storage": data.get("storage") or "",
                        "memory": data.get("memory") or "",
                        "battery": data.get("battery") or "",
                        "recording_id": data.get("recording_id") or "",
                        "recording_size": data.get("recording_size") or "",
                        "recording_start": data.get("recording_start") or "",
                        "recording_last_message": data.get(
                            "recording_last_message"
                        )
                        or "",
                        "device_os": data.get("device_os") or "",
                        "gps_mode": data.get("gps_mode") or "",
                        "reason": data.get("reason") or data.get("warning") or "",
                    },
                )
            )

    def add_rtlsdr_subjects(self, subjects, events):
        """Add RTL-SDR frequency subjects."""
        for event in events:
            data = (event or {}).get("data") or {}
            frequency = data.get("frequency_mhz") or data.get("collector_state") or "rtlsdr"
            subjects.append(
                self.subject_record(
                    "rtlsdr",
                    "rtlsdr_frequency"
                    if data.get("frequency_mhz") not in (None, "")
                    else "rtlsdr_collector",
                    str(frequency),
                    str(frequency),
                    {
                        "first_seen": data.get("first_seen") or event.get("timestamp"),
                        "first_seen_epoch": data.get("first_seen_epoch")
                        or event.get("timestamp_epoch"),
                        "last_seen": data.get("last_seen") or event.get("timestamp"),
                        "last_seen_epoch": data.get("last_seen_epoch")
                        or event.get("timestamp_epoch"),
                    },
                    {
                        "frequency_mhz": data.get("frequency_mhz"),
                        "signal_count": data.get("signal_count") or 0,
                        "active": bool(data.get("active")),
                    },
                )
            )

    def add_noaa_subjects(self, subjects, events):
        """Add NOAA alert/advisory subjects."""
        for event in events:
            data = clean_noaa_data((event or {}).get("data") or {})
            event_type = (event or {}).get("type") or ""
            subject_id = stable_noaa_event_key(data, event_type)
            subject = data.get("event") or data.get("headline") or subject_id
            if event_type == "noaa_collector_summary":
                subject_type = "noaa_collector"
                subject = "NOAA collector"
            elif data.get("alert_kind") == "tropical":
                subject_type = "noaa_tropical_advisory"
            elif data.get("alert_kind") == "tropical_outlook":
                subject_type = "noaa_tropical_outlook"
            elif data.get("alert_kind") == "tsunami":
                subject_type = "noaa_tsunami_alert"
            else:
                subject_type = "noaa_weather_alert"
            subjects.append(
                self.subject_record(
                    "noaa",
                    subject_type,
                    subject_id,
                    subject,
                    {
                        "first_seen": data.get("first_seen") or event.get("timestamp"),
                        "first_seen_epoch": data.get("first_seen_epoch")
                        or event.get("timestamp_epoch"),
                        "last_seen": data.get("last_seen") or event.get("timestamp"),
                        "last_seen_epoch": data.get("last_seen_epoch")
                        or event.get("timestamp_epoch"),
                    },
                    {
                        "event_id": data.get("event_id") or "",
                        "source_event_id": data.get("source_event_id") or "",
                        "event": data.get("event") or "",
                        "headline": data.get("headline") or "",
                        "severity": data.get("severity") or "",
                        "urgency": data.get("urgency") or "",
                        "certainty": data.get("certainty") or "",
                        "status": data.get("status") or "",
                        "message_type": data.get("message_type") or "",
                        "category": data.get("category") or "",
                        "alert_kind": data.get("alert_kind") or "",
                        "area_desc": data.get("area_desc") or "",
                        "effective": data.get("effective") or "",
                        "onset": data.get("onset") or "",
                        "expires": data.get("expires") or "",
                        "ends": data.get("ends") or "",
                        "updated": data.get("updated") or "",
                        "summary": data.get("summary") or "",
                        "instruction": data.get("instruction") or "",
                        "source": data.get("source") or "",
                        "source_url": data.get("source_url") or "",
                        "basin": data.get("basin") or "",
                        "update_count": data.get("update_count") or 0,
                        "internet_fed": True,
                        "reason": data.get("reason") or "",
                    },
                )
            )

    def add_usgs_subjects(self, subjects, events):
        """Add USGS earthquake subjects."""
        for event in events:
            data = clean_usgs_data((event or {}).get("data") or {})
            event_type = (event or {}).get("type") or ""
            subject_id = data.get("event_id") or "usgs"
            subject = data.get("place") or subject_id
            subject_type = (
                "usgs_collector"
                if event_type == "usgs_collector_summary"
                else "usgs_earthquake"
            )
            subjects.append(
                self.subject_record(
                    "usgs",
                    subject_type,
                    subject_id,
                    subject,
                    {
                        "first_seen": data.get("first_seen") or event.get("timestamp"),
                        "first_seen_epoch": data.get("first_seen_epoch")
                        or event.get("timestamp_epoch"),
                        "last_seen": data.get("last_seen") or event.get("timestamp"),
                        "last_seen_epoch": data.get("last_seen_epoch")
                        or event.get("timestamp_epoch"),
                    },
                    {
                        "event_id": data.get("event_id") or "",
                        "magnitude": data.get("magnitude"),
                        "place": data.get("place") or "",
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "depth_km": data.get("depth_km"),
                        "distance_km": data.get("distance_km"),
                        "event_time": data.get("event_time") or "",
                        "event_time_epoch": data.get("event_time_epoch"),
                        "updated": data.get("updated") or "",
                        "updated_epoch": data.get("updated_epoch"),
                        "status": data.get("status") or "",
                        "felt": data.get("felt"),
                        "cdi": data.get("cdi"),
                        "mmi": data.get("mmi"),
                        "alert_color": data.get("alert_color") or "",
                        "tsunami": data.get("tsunami"),
                        "detail_url": data.get("detail_url") or "",
                        "update_count": data.get("update_count") or 0,
                        "internet_fed": True,
                        "reason": data.get("reason") or "",
                    },
                )
            )

    def add_swpc_subjects(self, subjects, events):
        """Add SWPC space-weather subjects."""
        for event in events:
            data = clean_swpc_data((event or {}).get("data") or {})
            event_type = (event or {}).get("type") or ""
            subject_id = data.get("event_id") or "swpc"
            if event_type == "swpc_collector_summary":
                subject = "SWPC collector"
                subject_type = "swpc_collector"
            else:
                subject = self.swpc_subject_label(data)
                subject_type = "swpc_{}".format(data.get("event_kind") or "event")
            subjects.append(
                self.subject_record(
                    "swpc",
                    subject_type,
                    subject_id,
                    subject,
                    {
                        "first_seen": data.get("first_seen") or event.get("timestamp"),
                        "first_seen_epoch": data.get("first_seen_epoch")
                        or event.get("timestamp_epoch"),
                        "last_seen": data.get("last_seen") or event.get("timestamp"),
                        "last_seen_epoch": data.get("last_seen_epoch")
                        or event.get("timestamp_epoch"),
                    },
                    {
                        "event_id": data.get("event_id") or "",
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
                        "event_time_epoch": data.get("event_time_epoch"),
                        "start_time": data.get("start_time") or "",
                        "end_time": data.get("end_time") or "",
                        "peak_time": data.get("peak_time") or "",
                        "issue_time": data.get("issue_time") or "",
                        "product_id": data.get("product_id") or "",
                        "source": data.get("source") or "",
                        "source_url": data.get("source_url") or "",
                        "update_count": data.get("update_count") or 0,
                        "internet_fed": True,
                        "reason": data.get("reason") or "",
                    },
                )
            )

    def swpc_subject_label(self, data):
        """Return compact SWPC subject text."""
        parts = [
            data.get("event") or "SWPC event",
            data.get("xray_class") or data.get("scale_label") or "",
        ]
        kp = number_or_none(data.get("kp_index"))
        if kp is not None:
            parts.append("Kp {:.1f}".format(kp))
        return " ".join(str(part) for part in parts if part)

    def add_lan_subjects(self, subjects, events):
        """Add LAN device and gateway subjects."""
        for event in events:
            data = clean_lan_data((event or {}).get("data") or {})
            event_type = (event or {}).get("type") or ""
            if event_type == "lan_collector_summary":
                subject_id = "lan"
                subject = "LAN collector"
                subject_type = "lan_collector"
            elif event_type == "lan_gateway_summary":
                subject_id = data.get("subject_key") or data.get("gateway_ip") or "gateway"
                subject = "Gateway {}".format(data.get("gateway_ip") or subject_id)
                subject_type = "lan_gateway"
            else:
                subject_id = data.get("subject_key") or data.get("mac") or data.get("ip") or "unknown"
                label = data.get("hostname") or data.get("mac") or data.get("ip") or subject_id
                subject = "LAN {}".format(label)
                subject_type = "lan_device"
            subjects.append(
                self.subject_record(
                    "lan",
                    subject_type,
                    subject_id,
                    subject,
                    {
                        "first_seen": data.get("first_seen") or event.get("timestamp"),
                        "first_seen_epoch": data.get("first_seen_epoch")
                        or event.get("timestamp_epoch"),
                        "last_seen": data.get("last_seen") or event.get("timestamp"),
                        "last_seen_epoch": data.get("last_seen_epoch")
                        or event.get("timestamp_epoch"),
                    },
                    {
                        "subject_key": data.get("subject_key") or "",
                        "mac": data.get("mac") or "",
                        "ip": data.get("ip") or "",
                        "ips": data.get("ips") or [],
                        "hostname": data.get("hostname") or "",
                        "hostnames": data.get("hostnames") or [],
                        "interface": data.get("interface") or "",
                        "interfaces": data.get("interfaces") or [],
                        "state": data.get("state") or "",
                        "states": data.get("states") or [],
                        "sources": data.get("sources") or [],
                        "vendor_oui": data.get("vendor_oui") or "",
                        "vendor_prefix": data.get("vendor_prefix") or "",
                        "vendor_name": data.get("vendor_name") or "",
                        "gateway": bool(data.get("gateway")),
                        "gateways": data.get("gateways") or [],
                        "gateway_ip": data.get("gateway_ip") or "",
                        "family": data.get("family") or "",
                        "observation_count": data.get("observation_count") or 0,
                        "change_count": data.get("change_count") or 0,
                        "change_type": data.get("change_type") or "",
                        "reason": data.get("reason") or "",
                    },
                )
            )

    def subject_record(self, collector, subject_type, subject_id, subject, time_source, data):
        """Return one normalized subject-history row."""
        return {
            "collector": collector,
            "subject_type": subject_type,
            "subject_id": str(subject_id or ""),
            "subject": str(subject or subject_id or ""),
            "first_seen": (time_source or {}).get("first_seen"),
            "first_seen_epoch": record_time_epoch(time_source or {}, "first_seen")
            or timestamp_epoch((time_source or {}).get("first_seen_epoch")),
            "last_seen": (time_source or {}).get("last_seen"),
            "last_seen_epoch": record_time_epoch(time_source or {}, "last_seen")
            or timestamp_epoch((time_source or {}).get("last_seen_epoch")),
            "data": {
                key: value
                for key, value in (data or {}).items()
                if value not in (None, "", [], {})
            },
        }

    def count_subjects(self, subjects):
        """Return compact subject counts by collector and type."""
        by_collector = Counter()
        by_type = Counter()
        for subject in subjects or []:
            if not isinstance(subject, dict):
                continue
            by_collector[subject.get("collector") or "unknown"] += 1
            by_type[subject.get("subject_type") or "unknown"] += 1
        return {
            "total": sum(by_collector.values()),
            "by_collector": dict(sorted(by_collector.items())),
            "by_type": dict(sorted(by_type.items())),
        }

    def wifi_ap_subject(self, ap):
        """Return a readable Wi-Fi AP subject."""
        parts = [
            ap.get("ssid") or "blank SSID",
            ap.get("bssid") or "",
            ap.get("vendor_name") or "",
        ]
        return " - ".join(part for part in parts if part)
