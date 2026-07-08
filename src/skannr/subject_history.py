"""Collector-neutral subject history built from retained collector JSONL logs.

Subject History is the base layer for longer-lived intelligence products. Raw
collector logs remain the audit trail, but derived views should reason about
stable subjects: SSIDs/BSSIDs, Bluetooth identities, APRS callsigns, Rayhunter
endpoints, RF decoder subjects, aircraft, weather stations, and LAN devices.
"""

import copy
import datetime
import math
import os
from collections import Counter, defaultdict

from .bus import local_now
from .collectors import subject_history_event_contract_by_key
from .collectors.lan import clean_lan_data
from .collectors.noaa import (
    clean_noaa_data,
    stable_noaa_event_key,
    tsunami_is_alertworthy,
)
from .collectors.adsb import clean_adsb_data, distance_km
from .collectors.aprsis import aprsis_distance_km, aprsis_float, clean_aprs_data
from .collectors.pws import clean_pws_data
from .collectors.rayhunter import clean_rayhunter_data, clean_rayhunter_field
from .collectors.rtl433 import clean_rtl433_data
from .collectors.swpc import (
    clean_swpc_data,
    number_or_none,
    swpc_event_is_alert,
    swpc_event_is_critical,
    swpc_scale_label,
    xray_class_to_flux,
)
from .collectors.usgs import clean_usgs_data
from .wifi_ble_postprocessor import WiFiBLEPostprocessor
from .identity_policy import (
    bluetooth_group_label,
    bluetooth_grouping_candidate,
    bluetooth_identity_bucket,
    lan_group_label,
    low_identity_bluetooth_record,
    low_identity_lan_record,
    low_identity_wifi_client,
    meaningful_bluetooth_names,
    wifi_client_group_label,
)
from .log_utils import (
    count_jsonl_files,
    current_jsonl_checkpoint,
    empty_jsonl_checkpoint,
    event_in_window,
    event_time_epoch,
    has_jsonl_checkpoint,
    now_epoch,
    read_incremental_jsonl_events,
    record_time_epoch,
    sanitize_json_line,
    save_json_atomic,
    timestamp_epoch,
    window_metadata,
)


class SubjectHistoryBuilder:
    """Build one materialized subject-history summary for all collectors."""

    DIRECT_OBSERVATION_VERSION = 3

    DEVICE_COLLECTORS = WiFiBLEPostprocessor.COLLECTORS
    DIRECT_COLLECTORS = (
        "aprsis",
        "rayhunter",
        "rtl433",
        "adsb",
        "noaa",
        "usgs",
        "swpc",
        "pws",
        "lan",
        "lan_identify",
    )
    COLLECTORS = DEVICE_COLLECTORS + DIRECT_COLLECTORS

    def __init__(
        self,
        log_dir,
        state_path=None,
        device_history_state_path=None,
        direct_state_path=None,
        window_days=None,
        enabled_collectors=None,
        progress_callback=None,
        reference_epoch=None,
    ):
        self.log_dir = log_dir
        self.reference_epoch = reference_epoch
        self.state_path = state_path or os.path.join(
            log_dir, "device_history", "subject_history.json"
        )
        self.device_history_state_path = device_history_state_path or os.path.join(
            log_dir, "device_history", "device_history.json"
        )
        self.direct_state_path = direct_state_path or os.path.join(
            log_dir, "device_history", "subject_history_direct_state.json"
        )
        self.window_days = window_days
        self.enabled_collectors = (
            set(enabled_collectors) if enabled_collectors is not None else None
        )
        self.progress_callback = progress_callback
        self.subject_history_event_contract = subject_history_event_contract_by_key()

    def collector_enabled(self, collector):
        """Return True when this collector should participate in this build."""
        return self.enabled_collectors is None or collector in self.enabled_collectors

    def active_device_collectors(self):
        """Return enabled Device History collectors."""
        return tuple(
            collector
            for collector in self.DEVICE_COLLECTORS
            if self.collector_enabled(collector)
        )

    def active_direct_collectors(self):
        """Return enabled direct Subject History collectors."""
        return tuple(
            collector
            for collector in self.DIRECT_COLLECTORS
            if self.collector_enabled(collector)
        )

    def active_collectors(self):
        """Return enabled collectors covered by Subject History."""
        return self.active_device_collectors() + self.active_direct_collectors()

    def build(self, persist=True):
        """Return a display-ready Subject History summary."""
        summary = self.build_summary()
        if persist:
            self.save_summary(summary)
        return self.display_summary(summary, self.window_days)

    def build_summary(self):
        """Build the materialized summary for the selected view window.

        Reads raw JSONL for all collectors. Wi-Fi/BLE observations are
        processed through WiFiBLEPostprocessor, which handles session
        tracking, vendor enrichment, and privacy grouping. Direct collectors
        use registry-based per-collector builders.
        """
        previous_summary = self.load_persisted_summary() or {}
        if self.progress_callback:
            self.progress_callback("Wi-Fi / BLE device history")
        wifi_ble = WiFiBLEPostprocessor(
            self.log_dir,
            state_path=self.device_history_state_path,
            window_days=self.window_days,
            progress_callback=self.progress_callback,
            reference_epoch=self.reference_epoch,
        )
        wifi_ble_result = wifi_ble.build_summary()
        try:
            wifi_ble.save_summary(wifi_ble_result)
        except OSError as exc:
            logging.exception("failed to persist device history: %s", exc)
        wifi_ble_display = wifi_ble.display_summary(wifi_ble_result, self.window_days)
        if self.progress_callback:
            self.progress_callback("Reading direct collector logs")
        (
            direct_observations,
            direct_checkpoint,
            direct_records,
            direct_incremental_records,
            direct_read_stats,
        ) = self.build_direct_observations()
        if self.progress_callback:
            self.progress_callback("Building collector histories")
        aprsis_events, aprsis_records = self.build_or_keep_direct_history(
            previous_summary,
            "aprsis",
            self.build_aprsis_history,
            direct_observations.get("aprsis") or [],
            None,
        )
        rayhunter_events, rayhunter_records = self.build_or_keep_direct_history(
            previous_summary,
            "rayhunter",
            self.build_rayhunter_history,
            direct_observations.get("rayhunter") or [],
            None,
        )
        rtl433_events, rtl433_records = self.build_or_keep_direct_history(
            previous_summary,
            "rtl433",
            self.build_rtl433_history,
            direct_observations.get("rtl433") or [],
            None,
        )
        adsb_events, adsb_records = self.build_or_keep_direct_history(
            previous_summary,
            "adsb",
            self.build_adsb_history,
            direct_observations.get("adsb") or [],
            None,
        )
        noaa_events, noaa_records = self.build_or_keep_direct_history(
            previous_summary,
            "noaa",
            self.build_noaa_history,
            direct_observations.get("noaa") or [],
            None,
        )
        usgs_events, usgs_records = self.build_or_keep_direct_history(
            previous_summary,
            "usgs",
            self.build_usgs_history,
            direct_observations.get("usgs") or [],
            None,
        )
        swpc_events, swpc_records = self.build_or_keep_direct_history(
            previous_summary,
            "swpc",
            self.build_swpc_history,
            direct_observations.get("swpc") or [],
            None,
        )
        pws_events, pws_records = self.build_or_keep_direct_history(
            previous_summary,
            "pws",
            self.build_pws_history,
            direct_observations.get("pws") or [],
            None,
        )
        lan_enabled = self.collector_enabled("lan") or self.collector_enabled(
            "lan_identify"
        )
        if lan_enabled:
            lan_events, lan_records = self.build_or_keep_direct_history(
                previous_summary,
                "lan",
                self.build_lan_history,
                (direct_observations.get("lan") or [])
                + (direct_observations.get("lan_identify") or []),
                None,
            )
        else:
            lan_events = copy.deepcopy((previous_summary or {}).get("lan") or [])
            lan_records = 0
        previous_generated_epoch = 0
        try:
            previous_generated_epoch = int(
                (previous_summary or {}).get("generated_at_epoch") or 0
            )
        except (TypeError, ValueError):
            previous_generated_epoch = 0
        generated_at_epoch = max(now_epoch(), previous_generated_epoch + 1)
        raw_records = self.raw_records_by_collector(
            wifi_ble_result,
            {
                "aprsis": aprsis_records,
                "rayhunter": rayhunter_records,
                "rtl433": rtl433_records,
                "adsb": adsb_records,
                "noaa": noaa_records,
                "usgs": usgs_records,
                "swpc": swpc_records,
                "pws": pws_records,
                "lan": lan_records,
                "lan_identify": direct_records.get("lan_identify") or 0,
            },
        )
        incremental_records = self.incremental_records_by_collector(
            wifi_ble_result, direct_incremental_records
        )
        summary = {
            "schema": "subject_history.v1",
            "direct_observation_version": self.DIRECT_OBSERVATION_VERSION,
            "generated_at": local_now(generated_at_epoch),
            "generated_at_epoch": generated_at_epoch,
            "log_dir": self.log_dir,
            "state_path": self.state_path,
            "device_history_state_path": self.device_history_state_path,
            "direct_state_path": self.direct_state_path,
            "window": window_metadata(None),
            "materialized_window": window_metadata(None),
            "files_read": sum(
                count_jsonl_files(self.log_dir, collector)
                for collector in self.active_collectors()
            ),
            "records_read": sum(raw_records.values()),
            "incremental_records_read": sum(incremental_records.values()),
            "raw_records_read": raw_records,
            "incremental_records_read_by_collector": incremental_records,
            "incremental_jsonl_read_stats": self.merge_incremental_read_stats(
                wifi_ble_result.get("incremental_jsonl_read_stats"),
                direct_read_stats,
            ),
            "raw_log_files": {
                collector: count_jsonl_files(self.log_dir, collector)
                for collector in self.active_collectors()
            },
            "checkpoint": self.merge_jsonl_checkpoints(
                wifi_ble_result.get("checkpoint"), direct_checkpoint
            ),
            "direct_observation_state_path": self.direct_state_path,
            "device_history_embedded": False,
            "aprsis": aprsis_events,
            "rayhunter": rayhunter_events,
            "rtl433": rtl433_events,
            "adsb": adsb_events,
            "noaa": noaa_events,
            "usgs": usgs_events,
            "swpc": swpc_events,
            "pws": pws_events,
            "lan": lan_events,
        }
        # Store wifi/ble in summary so it persists to subject_history.json
        summary["wifi"] = wifi_ble_display.get("wifi") or {
            "access_points": [],
            "clients": [],
        }
        summary["ble"] = wifi_ble_display.get("ble") or {"devices": []}
        summary["bluetooth"] = wifi_ble_display.get("bluetooth") or summary["ble"]
        subject_input = dict(summary)
        subject_input["wifi"] = wifi_ble_display.get("wifi") or {
            "access_points": [],
            "clients": [],
        }
        subject_input["ble"] = wifi_ble_display.get("ble") or {"devices": []}
        subject_input["bluetooth"] = (
            wifi_ble_display.get("bluetooth") or subject_input["ble"]
        )
        summary["subjects"] = self.build_subject_records(subject_input)
        summary["subject_counts"] = self.count_subjects(summary["subjects"])
        self.save_direct_observation_state(
            {
                "aprsis": aprsis_events,
                "rayhunter": rayhunter_events,
                "rtl433": rtl433_events,
                "adsb": adsb_events,
                "noaa": noaa_events,
                "usgs": usgs_events,
                "swpc": swpc_events,
                "pws": pws_events,
                "lan": lan_events,
                "lan_identify": [],
            },
            direct_checkpoint,
            direct_records,
            direct_incremental_records,
            direct_read_stats,
            generated_at_epoch,
        )
        return summary

    def build_or_keep_direct_history(
        self, previous_summary, collector, builder, observations, window_days
    ):
        """Merge new direct observations into the compact retained history."""
        previous_events = copy.deepcopy((previous_summary or {}).get(collector) or [])
        if not self.collector_enabled(collector) and not observations:
            return previous_events, 0
        new_events, records_read = builder(observations, window_days)
        if not observations:
            return previous_events, 0
        return (
            self.merge_direct_compact_history(collector, previous_events, new_events),
            records_read,
        )

    def merge_direct_compact_history(self, collector, previous_events, new_events):
        """Merge compact direct summary rows without replaying old raw events."""
        merged = {}
        for event in (previous_events or []) + (new_events or []):
            if not isinstance(event, dict):
                continue
            key = self.direct_compact_event_key(collector, event)
            if not key:
                continue
            old = merged.get(key)
            if old is None:
                merged[key] = copy.deepcopy(event)
                continue
            merged[key] = self.merge_direct_compact_event(collector, old, event)
        return sorted(
            merged.values(),
            key=lambda item: event_time_epoch(item) or 0,
            reverse=True,
        )

    def merge_direct_compact_event(self, collector, old, new):
        """Merge two compact direct summary rows for the same subject."""
        old = copy.deepcopy(old or {})
        new = copy.deepcopy(new or {})
        old_data = self.clean_direct_data(collector, old.get("data") or {})
        new_data = self.clean_direct_data(collector, new.get("data") or {})
        old_epoch = event_time_epoch(old) or old_data.get("last_seen_epoch") or 0
        new_epoch = event_time_epoch(new) or new_data.get("last_seen_epoch") or 0
        latest_event = new if (new_epoch or 0) >= (old_epoch or 0) else old
        latest_data = new_data if (new_epoch or 0) >= (old_epoch or 0) else old_data
        older_data = old_data if latest_data is new_data else new_data
        merged = copy.deepcopy(latest_event)
        data = copy.deepcopy(latest_data)

        for key, value in older_data.items():
            if key not in data and value not in (None, "", []):
                data[key] = copy.deepcopy(value)

        self.merge_direct_time_bounds(data, old_data, new_data, old_epoch, new_epoch)
        self.merge_direct_counters(data, old_data, new_data)
        self.merge_direct_lists(data, old_data, new_data)
        self.merge_direct_numeric_extremes(data, old_data, new_data)
        if (
            collector == "noaa"
            and latest_data is new_data
            and (data.get("alert_kind") or "") == "forecast"
        ):
            data.update(self.noaa_forecast_delta_fields(older_data, latest_data))

        merged["data"] = self.clean_direct_data(collector, data)
        latest_epoch = data.get("last_seen_epoch") or new_epoch or old_epoch
        if latest_epoch:
            merged["timestamp_epoch"] = latest_epoch
            merged["timestamp"] = data.get("last_seen") or local_now(latest_epoch)
        merged["severity"] = self.direct_compact_severity(collector, merged)
        return merged

    def merge_direct_time_bounds(self, data, old_data, new_data, old_epoch, new_epoch):
        """Preserve earliest first_seen and latest last_seen fields."""
        first_candidates = []
        for source, fallback in ((old_data, old_epoch), (new_data, new_epoch)):
            epoch = self.direct_epoch_candidate(
                source.get("first_seen_epoch"), fallback
            )
            if epoch is not None:
                first_candidates.append(
                    (epoch, source.get("first_seen") or local_now(epoch))
                )
        if first_candidates:
            first_epoch, first_text = min(first_candidates, key=lambda item: item[0])
            data["first_seen_epoch"] = first_epoch
            data["first_seen"] = first_text

        last_candidates = []
        for source, fallback in ((old_data, old_epoch), (new_data, new_epoch)):
            epoch = self.direct_epoch_candidate(source.get("last_seen_epoch"), fallback)
            if epoch is not None:
                last_candidates.append(
                    (epoch, source.get("last_seen") or local_now(epoch))
                )
        if last_candidates:
            last_epoch, last_text = max(last_candidates, key=lambda item: item[0])
            data["last_seen_epoch"] = last_epoch
            data["last_seen"] = last_text

    def direct_epoch_candidate(self, value, fallback=None):
        """Return a numeric epoch candidate for direct compact merge ordering."""
        for candidate in (value, fallback):
            if candidate in (None, ""):
                continue
            if isinstance(candidate, (int, float)):
                return int(candidate)
            text = str(candidate).strip()
            try:
                return int(float(text))
            except (TypeError, ValueError):
                pass
            epoch = timestamp_epoch(text)
            if epoch is not None:
                return epoch
        return None

    def merge_direct_counters(self, data, old_data, new_data):
        """Add known per-refresh counter fields across compact rows."""
        for key in set(old_data) | set(new_data):
            if not self.direct_counter_key(key):
                continue
            old_value = self.safe_int(old_data.get(key))
            new_value = self.safe_int(new_data.get(key))
            if old_value is None and new_value is None:
                continue
            data[key] = int(old_value or 0) + int(new_value or 0)

    def safe_int(self, value):
        """Return an int for numeric compact fields, or None when absent."""
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None

    def direct_counter_key(self, key):
        """Return True when a compact summary key is an additive counter."""
        key = str(key or "")
        if not key:
            return False
        if key.startswith("previous_") or key.endswith("_delta"):
            return False
        return (
            key.endswith("_count")
            or key.endswith("_total")
            or key in ("events_in_window", "warning_events_in_window")
        )

    def merge_direct_lists(self, data, old_data, new_data):
        """Merge compact sample/list fields without duplicating entries."""
        for key in set(old_data) | set(new_data):
            if not isinstance(old_data.get(key), list) and not isinstance(
                new_data.get(key), list
            ):
                continue
            data[key] = []
            limit = self.direct_list_limit(key)
            for value in (old_data.get(key) or []) + (new_data.get(key) or []):
                self.sample_direct_value(data, key, value, limit)

    def direct_list_limit(self, key):
        """Return a conservative retained-list limit for direct compact fields."""
        key = str(key or "")
        if key in ("sample_fields",):
            return 6
        if key.startswith("sample_"):
            return 12
        return 24

    def merge_direct_numeric_extremes(self, data, old_data, new_data):
        """Preserve min/max numeric extremes across compact rows."""
        for key in set(old_data) | set(new_data):
            if self.direct_counter_key(key):
                continue
            old_value = number_or_none(old_data.get(key))
            new_value = number_or_none(new_data.get(key))
            if old_value is None and new_value is None:
                continue
            values = [
                value
                for value in (old_value, new_value)
                if isinstance(value, (int, float))
            ]
            if not values:
                continue
            if self.direct_min_key(key):
                data[key] = min(values)
            elif self.direct_max_key(key):
                data[key] = max(values)

    def direct_min_key(self, key):
        """Return True for numeric fields that should retain the minimum."""
        key = str(key or "")
        return (
            key.startswith("min_")
            or "_min_" in key
            or key.endswith("_min")
            or key.startswith("nearest_")
            or key.startswith("shallowest_")
        )

    def direct_max_key(self, key):
        """Return True for numeric fields that should retain the maximum."""
        key = str(key or "")
        return (
            key.startswith("max_")
            or "_max_" in key
            or key.endswith("_max")
            or key.startswith("highest_")
        )

    def direct_compact_severity(self, collector, event):
        """Return severity for a merged direct compact row."""
        data = event.get("data") or {}
        event_type = event.get("type") or ""
        if collector == "rtl433":
            return "warning" if data.get("category") in ("tpms", "security") else "info"
        if collector == "rayhunter":
            return (
                "warning"
                if int(
                    data.get("warning_events_in_window")
                    or data.get("warning_count")
                    or 0
                )
                else event.get("severity") or "info"
            )
        if collector == "adsb":
            return (
                "warning" if data.get("emergency") else event.get("severity") or "info"
            )
        if collector == "noaa":
            severe = str(data.get("severity") or "").lower() in ("severe", "extreme")
            return (
                "warning"
                if severe
                or data.get("nws_hazard_count")
                or data.get("tsunami_incident_count")
                or data.get("tropical_system_count")
                else event.get("severity") or "info"
            )
        if collector == "usgs":
            return (
                "warning"
                if data.get("tsunami")
                or data.get("global_major")
                or data.get("notable_count")
                else event.get("severity") or "info"
            )
        if collector == "swpc":
            return (
                "warning"
                if data.get("alert_count") or data.get("critical_count")
                else event.get("severity") or "info"
            )
        if collector == "lan":
            return (
                "warning"
                if event_type == "lan_gateway_summary" and data.get("change_count")
                else event.get("severity") or "info"
            )
        return event.get("severity") or "info"

    def direct_compact_event_key(self, collector, event):
        """Return a stable key for one compact direct summary row."""
        event_type = event.get("type") or ""
        data = event.get("data") or {}
        if collector == "aprsis":
            return (
                event_type,
                data.get("callsign")
                or data.get("station")
                or data.get("feed_name")
                or "aprsis",
                data.get("period_kind") or "",
                data.get("period_key") or "",
            )
        if collector == "rayhunter":
            return (
                event_type,
                clean_rayhunter_field(data.get("endpoint")) or "rayhunter",
            )
        if collector == "rtl433":
            return (
                event_type,
                data.get("subject_key")
                or "|".join(
                    str(data.get(key) or "")
                    for key in ("model", "id", "channel", "protocol")
                )
                or "rtl433",
            )
        if collector == "adsb":
            return (
                event_type,
                data.get("icao")
                or data.get("icao24")
                or data.get("hex")
                or data.get("address")
                or data.get("flight")
                or "adsb",
            )
        if collector == "noaa":
            return (event_type, stable_noaa_event_key(data, event_type))
        if collector == "usgs":
            return (event_type, data.get("event_id") or "usgs")
        if collector == "swpc":
            return (
                event_type,
                data.get("event_id")
                or data.get("event_key")
                or data.get("message_id")
                or data.get("product_id")
                or data.get("event")
                or data.get("summary")
                or "swpc",
                data.get("period_kind") or "",
                data.get("period_key") or "",
            )
        if collector == "pws":
            return (
                event_type,
                data.get("station_id") or data.get("station_name") or "pws",
                data.get("period_kind") or "",
                data.get("period_key") or "",
            )
        if collector == "lan":
            return (
                event_type,
                data.get("subject_key")
                or data.get("mac")
                or data.get("gateway_ip")
                or data.get("ip")
                or "lan",
            )
        return (event_type, str(data.get("subject_key") or data.get("id") or collector))

    def raw_records_by_collector(self, device_history_summary, direct_records):
        """Return collector record counts using the best available source."""
        counts = {}
        source = (device_history_summary or {}).get("raw_records_read") or {}
        for collector in self.DEVICE_COLLECTORS:
            counts[collector] = (
                int(source.get(collector) or 0)
                if self.collector_enabled(collector)
                else 0
            )
        for collector, value in direct_records.items():
            counts[collector] = int(value or 0)
        return counts

    def incremental_records_by_collector(self, device_history_summary, direct_records):
        """Return per-refresh record counts across device and direct collectors."""
        counts = {}
        source = (device_history_summary or {}).get(
            "incremental_records_read_by_collector"
        ) or {}
        for collector in self.DEVICE_COLLECTORS:
            counts[collector] = (
                int(source.get(collector) or 0)
                if self.collector_enabled(collector)
                else 0
            )
        for collector, value in direct_records.items():
            counts[collector] = int(value or 0)
        return counts

    def merge_incremental_read_stats(self, *stats_items):
        """Merge per-collector incremental JSONL reader stats."""
        merged = {}
        for stats in stats_items:
            if not isinstance(stats, dict):
                continue
            for collector, values in stats.items():
                if not isinstance(values, dict):
                    continue
                target = merged.setdefault(
                    collector,
                    {
                        "pending_bytes": 0,
                        "bytes_read": 0,
                        "raw_lines": 0,
                        "decoded_records": 0,
                        "invalid_lines": 0,
                        "files": 0,
                        "max_line_bytes": 0,
                        "event_types": {},
                    },
                )
                for key in (
                    "pending_bytes",
                    "bytes_read",
                    "raw_lines",
                    "decoded_records",
                    "invalid_lines",
                    "files",
                ):
                    target[key] += int(values.get(key) or 0)
                target["max_line_bytes"] = max(
                    int(target.get("max_line_bytes") or 0),
                    int(values.get("max_line_bytes") or 0),
                )
                event_types = target.setdefault("event_types", {})
                for event_type, count in (values.get("event_types") or {}).items():
                    event_types[event_type] = int(
                        event_types.get(event_type) or 0
                    ) + int(count or 0)
        return merged

    def merge_jsonl_checkpoints(self, *checkpoints):
        """Merge device and direct collector offsets into one Subject checkpoint."""
        merged = empty_jsonl_checkpoint()
        for checkpoint in checkpoints:
            if not isinstance(checkpoint, dict):
                continue
            for collector, files in (checkpoint.get("collectors") or {}).items():
                merged["collectors"][collector] = copy.deepcopy(files or {})
        for collector in self.active_collectors():
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
                "rtl433",
                "adsb",
                "noaa",
                "usgs",
                "swpc",
                "pws",
                "lan",
                "subjects",
                "subject_counts",
                "direct_observations",
            )
        }
        output["wifi"] = summary.get("wifi") or {
            "access_points": [],
            "clients": [],
        }
        output["ble"] = summary.get("ble") or {"devices": []}
        output["bluetooth"] = summary.get("bluetooth") or output["ble"]
        for collector in (
            "aprsis",
            "rayhunter",
            "rtl433",
            "adsb",
            "noaa",
            "usgs",
            "swpc",
            "pws",
            "lan",
        ):
            output[collector] = copy.deepcopy((summary or {}).get(collector) or [])
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

    def save_direct_observation_state(
        self,
        histories,
        checkpoint,
        total_records,
        incremental_records,
        read_stats,
        generated_at_epoch,
    ):
        """Persist compact direct histories as one file per collector."""
        state_files = {}
        for collector in self.DIRECT_COLLECTORS:
            path = self.collector_direct_state_path(collector)
            state_files[collector] = path
            history = histories.get(collector) or []
            collector_state = {
                "schema": "subject_history_direct_collector_state.v2",
                "collector": collector,
                "direct_observation_version": self.DIRECT_OBSERVATION_VERSION,
                "generated_at": local_now(generated_at_epoch),
                "generated_at_epoch": generated_at_epoch,
                "log_dir": self.log_dir,
                "state_path": path,
                "checkpoint": {
                    "collectors": {
                        collector: copy.deepcopy(
                            ((checkpoint or {}).get("collectors") or {}).get(collector)
                            or {}
                        )
                    }
                },
                "history": history,
                "history_records": len(history),
                "records_read": int((total_records or {}).get(collector) or 0),
                "incremental_records_read": int(
                    (incremental_records or {}).get(collector) or 0
                ),
                "incremental_jsonl_read_stats": (read_stats or {}).get(collector) or {},
            }
            save_json_atomic(path, collector_state)
        state = {
            "schema": "subject_history_direct_state.v3",
            "direct_observation_version": self.DIRECT_OBSERVATION_VERSION,
            "generated_at": local_now(generated_at_epoch),
            "generated_at_epoch": generated_at_epoch,
            "log_dir": self.log_dir,
            "state_path": self.direct_state_path,
            "checkpoint": checkpoint,
            "state_files": state_files,
            "records_read": total_records,
            "incremental_records_read_by_collector": incremental_records,
            "incremental_jsonl_read_stats": read_stats,
            "retains_compact_history": True,
        }
        save_json_atomic(self.direct_state_path, state)

    def collector_direct_state_path(self, collector):
        """Return the per-collector retained direct state path."""
        directory = os.path.dirname(self.direct_state_path)
        return os.path.join(
            directory, "subject_history_direct_{}.json".format(collector)
        )

    def load_persisted_summary(self):
        """Load persisted subject history if present."""
        try:
            import json

            with open(self.state_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def build_direct_observations(self):
        """Read only new direct raw events since the compact-state checkpoint."""
        previous = self.load_direct_observation_state()
        use_previous = (
            isinstance(previous, dict)
            and previous.get("direct_observation_version")
            == self.DIRECT_OBSERVATION_VERSION
        )
        observations = {collector: [] for collector in self.DIRECT_COLLECTORS}
        checkpoint = (
            copy.deepcopy(previous.get("checkpoint") or empty_jsonl_checkpoint())
            if use_previous
            else empty_jsonl_checkpoint()
        )
        previous_records = (previous.get("records_read") or {}) if use_previous else {}
        previous_direct_state = previous if use_previous else {}
        self.recover_empty_enabled_direct_checkpoints(
            checkpoint, previous_records, previous_direct_state
        )
        self.recover_newer_direct_events_after_advanced_checkpoint(
            checkpoint, previous_direct_state
        )
        disabled_with_pending = self.disabled_direct_collectors_with_pending_events(
            checkpoint
        )
        incremental_records = defaultdict(int)
        read_stats = {}
        collectors_to_read = tuple(
            dict.fromkeys(
                self.active_direct_collectors() + tuple(disabled_with_pending)
            )
        )
        for collector in collectors_to_read:
            for event in read_incremental_jsonl_events(
                self.log_dir, collector, checkpoint, read_stats=read_stats
            ):
                observation = self.direct_observation_from_event(collector, event)
                if observation is None:
                    continue
                observations[collector].append(observation)
                incremental_records[collector] += 1
        self.advance_disabled_direct_checkpoints(
            checkpoint, preserve_collectors=disabled_with_pending
        )
        total_records = {
            collector: int((previous_records or {}).get(collector) or 0)
            + int(incremental_records.get(collector) or 0)
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
            read_stats,
        )

    def advance_disabled_direct_checkpoints(self, checkpoint, preserve_collectors=None):
        """Advance disabled direct collectors without replaying old raw logs."""
        if self.enabled_collectors is None:
            return
        preserve_collectors = set(preserve_collectors or ())
        current = current_jsonl_checkpoint(self.log_dir, self.DIRECT_COLLECTORS)
        current_collectors = current.get("collectors") or {}
        checkpoint.setdefault("collectors", {})
        for collector in self.DIRECT_COLLECTORS:
            if self.collector_enabled(collector) or collector in preserve_collectors:
                continue
            checkpoint["collectors"][collector] = copy.deepcopy(
                current_collectors.get(collector) or {}
            )

    def disabled_direct_collectors_with_pending_events(self, checkpoint):
        """Return disabled direct collectors with new durable events pending."""
        if self.enabled_collectors is None:
            return set()
        pending = set()
        for collector in self.DIRECT_COLLECTORS:
            if self.collector_enabled(collector):
                continue
            if self.direct_collector_has_pending_supported_event(collector, checkpoint):
                pending.add(collector)
        return pending

    def direct_collector_has_pending_supported_event(self, collector, checkpoint):
        """Return True when checkpoint-pending bytes contain durable events."""
        probe_checkpoint = copy.deepcopy(checkpoint or empty_jsonl_checkpoint())
        for event in read_incremental_jsonl_events(
            self.log_dir, collector, probe_checkpoint
        ):
            if self.direct_observation_from_event(collector, event) is not None:
                return True
        return False

    def recover_empty_enabled_direct_checkpoints(
        self, checkpoint, previous_records, previous
    ):
        """Re-read today's raw file when an enabled direct collector has no retained state.

        Disabled direct collectors intentionally advance checkpoints so old logs are
        not replayed when the collector is enabled later. If a collector writes raw
        events while its retained state still says zero records, keep recovery
        bounded to the newest daily file so today's observations are not lost.
        """
        if self.enabled_collectors is None:
            return
        checkpoint.setdefault("collectors", {})
        for collector in self.active_direct_collectors():
            if int((previous_records or {}).get(collector) or 0) > 0:
                continue
            if (previous or {}).get(collector):
                continue
            files = checkpoint["collectors"].get(collector) or {}
            if not files:
                continue
            latest = sorted(files)[-1]
            state = files.get(latest) or {}
            if int(state.get("offset") or 0) <= 0:
                continue
            path = os.path.join(self.log_dir, collector, latest)
            if not self.direct_log_file_has_supported_event(collector, path):
                continue
            repaired = dict(state)
            repaired["offset"] = 0
            files[latest] = repaired
            checkpoint["collectors"][collector] = files

    def direct_log_file_has_supported_event(self, collector, path):
        """Return True when one JSONL file contains durable direct events."""
        try:
            import json

            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        event = json.loads(sanitize_json_line(line))
                    except ValueError:
                        continue
                    if self.direct_observation_from_event(collector, event) is not None:
                        return True
        except OSError:
            return False
        return False

    def recover_newer_direct_events_after_advanced_checkpoint(
        self, checkpoint, previous
    ):
        """Re-read the newest file when retained rows lag already-checkpointed data."""
        if not isinstance(previous, dict):
            return
        checkpoint.setdefault("collectors", {})
        for collector in self.DIRECT_COLLECTORS:
            previous_events = previous.get(collector) or []
            if not previous_events:
                continue
            files = checkpoint["collectors"].get(collector) or {}
            if not files:
                continue
            latest = sorted(files)[-1]
            state = files.get(latest) or {}
            if int(state.get("offset") or 0) <= 0:
                continue
            path = os.path.join(self.log_dir, collector, latest)
            try:
                if os.path.getsize(path) > int(state.get("offset") or 0):
                    continue
            except OSError:
                continue
            latest_epoch = self.latest_supported_direct_event_epoch(collector, path)
            previous_epoch = max(
                (event_time_epoch(event) or 0) for event in previous_events
            )
            if latest_epoch is None or latest_epoch <= previous_epoch:
                continue
            repaired = dict(state)
            repaired["offset"] = 0
            files[latest] = repaired
            checkpoint["collectors"][collector] = files

    def latest_supported_direct_event_epoch(self, collector, path):
        """Return the newest durable direct-event epoch in one JSONL file."""
        latest = None
        try:
            import json

            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        event = json.loads(sanitize_json_line(line))
                    except ValueError:
                        continue
                    observation = self.direct_observation_from_event(collector, event)
                    if observation is None:
                        continue
                    epoch = event_time_epoch(observation)
                    if epoch is None:
                        continue
                    latest = epoch if latest is None else max(latest, epoch)
        except OSError:
            return None
        return latest

    def load_direct_observation_state(self):
        """Load direct-state metadata, migrating old retained-observation files."""
        state = self.read_json_file(self.direct_state_path)
        if isinstance(state, dict):
            state = copy.deepcopy(state)
            records = dict(state.get("records_read") or {})
            for collector in self.DIRECT_COLLECTORS:
                collector_state = self.read_json_file(
                    self.collector_direct_state_path(collector)
                )
                if not isinstance(collector_state, dict):
                    continue
                if collector not in records:
                    records[collector] = int(collector_state.get("records_read") or 0)
            state["records_read"] = records
            return state
        previous = self.load_persisted_summary()
        if isinstance(previous, dict) and previous.get("checkpoint"):
            return {
                "direct_observation_version": previous.get(
                    "direct_observation_version"
                ),
                "checkpoint": previous.get("checkpoint"),
                "records_read": previous.get("raw_records_read") or {},
            }
        return None

    def read_json_file(self, path):
        """Read one JSON object, returning None when absent or invalid."""
        try:
            import json

            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def normalized_direct_observations(self, source):
        """Return durable direct observations in the current event shape."""
        observations = {collector: [] for collector in self.DIRECT_COLLECTORS}
        if not isinstance(source, dict):
            return observations
        for collector in self.DIRECT_COLLECTORS:
            if collector == "adsb":
                observations[collector] = self.compact_adsb_observations(
                    source.get(collector) or []
                )
                continue
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
        contract = self.subject_history_event_contract.get(collector) or {}
        text = str(event_type or "")
        return text in (contract.get("types") or ()) or any(
            text.startswith(prefix) for prefix in (contract.get("prefixes") or ())
        )

    def clean_direct_data(self, collector, data):
        """Scrub direct collector payloads before they become durable history."""
        if collector == "aprsis":
            cleaned = clean_aprs_data(data)
        elif collector == "rayhunter":
            cleaned = clean_rayhunter_data(data)
        elif collector == "rtl433":
            cleaned = clean_rtl433_data(data)
        elif collector == "adsb":
            cleaned = clean_adsb_data(data)
        elif collector == "noaa":
            cleaned = clean_noaa_data(data)
        elif collector == "usgs":
            cleaned = clean_usgs_data(data)
        elif collector == "swpc":
            cleaned = clean_swpc_data(data)
        elif collector == "pws":
            cleaned = clean_pws_data(data)
        elif collector in ("lan", "lan_identify"):
            cleaned = clean_lan_data(data)
        else:
            cleaned = {}
        return self.normalize_direct_compact_data(cleaned)

    def normalize_direct_compact_data(self, data):
        """Normalize compact merge fields after collector-specific scrubbing."""
        normalized = copy.deepcopy(data or {})
        for key in list(normalized):
            if str(key).endswith("_epoch"):
                epoch = self.direct_epoch_candidate(normalized.get(key))
                if epoch is None:
                    normalized.pop(key, None)
                else:
                    normalized[key] = epoch
            elif self.direct_counter_key(key):
                value = self.safe_int(normalized.get(key))
                if value is None:
                    normalized.pop(key, None)
                else:
                    normalized[key] = value
        return normalized

    def build_aprsis_history(self, observations, window_days):
        """Return compact per-callsign APRS-IS summaries for this view window."""
        records_read = 0
        stations = {}
        weather_daily = {}
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
                latest_epoch = (
                    epoch if latest_epoch is None else max(latest_epoch, epoch)
                )
                continue

            callsign = data.get("callsign") or "unknown"
            station = stations.setdefault(
                callsign,
                self.aprsis_station_summary_template(callsign, data, epoch),
            )
            self.aprsis_update_station_summary(station, data, event_type, epoch)
            if self.aprsis_is_weather_packet(data, event_type):
                day_key, day_label = self.period_key(epoch, "daily")
                daily_record = weather_daily.setdefault(
                    (callsign, day_key),
                    self.new_aprsis_weather_period_record(
                        callsign, data, epoch, "daily", day_key, day_label
                    ),
                )
                self.update_aprsis_weather_period_record(daily_record, data, epoch)
            latest_epoch = epoch if latest_epoch is None else max(latest_epoch, epoch)
        if not records_read:
            return [], 0

        weather_periods = self.build_aprsis_weather_period_summaries(
            sorted(
                weather_daily.values(),
                key=lambda item: (
                    item.get("callsign") or "",
                    item.get("period_start_epoch") or 0,
                ),
            )
        )
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
                    "timestamp": local_now(
                        summary.get("last_seen_epoch") or latest_epoch
                    ),
                    "timestamp_epoch": summary.get("last_seen_epoch") or latest_epoch,
                    "severity": "info",
                    "data": clean_aprs_data(summary),
                }
            )

        output.extend(
            {
                "collector": "aprsis",
                "type": "aprsis_weather_period_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": "info",
                "data": clean_aprs_data(record),
            }
            for record in sorted(
                weather_periods,
                key=lambda item: (
                    {"weekly": 0, "monthly": 1, "yearly": 2}.get(
                        item.get("period_kind"), 9
                    ),
                    -(item.get("period_start_epoch") or 0),
                    item.get("callsign") or "",
                ),
            )
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
                    "severity": (
                        "warning"
                        if latest_health.get("collector_state") != "ONLINE"
                        else "info"
                    ),
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
            "position_samples": [],
            "packet_samples": [],
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
            self.aprsis_update_latest_station_fields(station, data, packet_type, epoch)

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
        self.aprsis_sample_packet(station, data, epoch)
        self.aprsis_update_position_summary(station, data, epoch)
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
            "payload",
            "raw",
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

    def aprsis_update_position_summary(self, station, data, epoch):
        """Update bounded position and movement statistics for a station."""
        latitude = aprsis_float(data.get("latitude"))
        longitude = aprsis_float(data.get("longitude"))
        if latitude is None or longitude is None:
            return
        if station.get("first_latitude") is None:
            station["first_latitude"] = latitude
            station["first_longitude"] = longitude
            station["first_position_at"] = local_now(epoch)
            station["first_position_epoch"] = epoch
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
        station["last_position_at"] = local_now(epoch)
        station["last_position_epoch"] = epoch
        self.aprsis_sample_position(station, data, latitude, longitude, epoch)
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
            if previous_rain is None and rain_1h > 0:
                station["rain_started"] = True
                station["rain_started_at"] = local_now(epoch)
                station["rain_started_epoch"] = epoch
                station["rain_episode_started_at"] = local_now(epoch)
                station["rain_episode_started_epoch"] = epoch
                station.pop("rain_stopped", None)
                station.pop("rain_stopped_at", None)
                station.pop("rain_stopped_epoch", None)
                station.pop("rain_episode_stopped_at", None)
                station.pop("rain_episode_stopped_epoch", None)
                station["rain_last_transition"] = "started"
                station["rain_last_transition_at"] = local_now(epoch)
                station["rain_last_transition_epoch"] = epoch
            if previous_rain is not None and previous_rain <= 0 < rain_1h:
                station["rain_started"] = True
                station["rain_started_at"] = local_now(epoch)
                station["rain_started_epoch"] = epoch
                station["rain_episode_started_at"] = local_now(epoch)
                station["rain_episode_started_epoch"] = epoch
                station.pop("rain_stopped", None)
                station.pop("rain_stopped_at", None)
                station.pop("rain_stopped_epoch", None)
                station.pop("rain_episode_stopped_at", None)
                station.pop("rain_episode_stopped_epoch", None)
                station["rain_last_transition"] = "started"
                station["rain_last_transition_at"] = local_now(epoch)
                station["rain_last_transition_epoch"] = epoch
            if previous_rain is not None and previous_rain > 0 and rain_1h <= 0:
                station["rain_stopped"] = True
                station["rain_stopped_at"] = local_now(epoch)
                station["rain_stopped_epoch"] = epoch
                station["rain_episode_started_at"] = (
                    station.get("rain_episode_started_at") or ""
                )
                station["rain_episode_started_epoch"] = station.get(
                    "rain_episode_started_epoch"
                )
                station["rain_episode_stopped_at"] = local_now(epoch)
                station["rain_episode_stopped_epoch"] = epoch
                station.pop("rain_started", None)
                station.pop("rain_started_at", None)
                station.pop("rain_started_epoch", None)
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
            key: value for key, value in station.items() if not str(key).startswith("_")
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
        movement = float(summary.get("movement_km") or 0)
        position_count = int(summary.get("position_count") or 0)
        summary["movement_detected"] = bool(span >= 0.3 or speed >= 5.0)
        if summary["movement_detected"]:
            if movement >= 0.3 and position_count <= 4:
                summary["trip_rollup"] = "pass-through path"
            elif span >= 0.3:
                summary["trip_rollup"] = "mobile path through area"
            else:
                summary["trip_rollup"] = "moving station"
        elif position_count >= 3:
            summary["trip_rollup"] = "repeated local presence"
        return summary

    def aprsis_sample_packet(self, station, data, epoch):
        """Retain a bounded recent APRS packet drilldown sample."""
        packet = data.get("raw") or "{}>{}:{}".format(
            data.get("callsign") or "",
            data.get("path") or data.get("destination") or "",
            data.get("payload") or "",
        )
        packet = " ".join(str(packet or "").split())[:300]
        if not packet:
            return
        label = "{} {}".format(local_now(epoch), packet).strip()
        self.aprsis_sample(station, "packet_samples", label, 10)

    def aprsis_sample_position(self, station, data, latitude, longitude, epoch):
        """Retain a bounded recent APRS route-point sample."""
        parts = [
            local_now(epoch),
            "{:.5f},{:.5f}".format(latitude, longitude),
        ]
        speed = aprsis_float(data.get("speed_kmh"))
        course = aprsis_float(data.get("course_deg"))
        if speed is not None:
            parts.append("{:.1f} km/h".format(speed))
        if course is not None:
            parts.append("{:.0f} deg".format(course))
        if data.get("comment"):
            parts.append(str(data.get("comment"))[:80])
        self.aprsis_sample(station, "position_samples", " | ".join(parts), 12)

    def aprsis_sample(self, station, key, value, limit=8):
        """Append one compact APRS sample value without growing unbounded lists."""
        if value in (None, "", []):
            return
        text = str(value).strip()
        if not text or text in station[key]:
            return
        station[key].append(text)
        del station[key][:-limit]

    def aprsis_is_weather_packet(self, data, event_type):
        """Return True when an APRS event contains weather station data."""
        packet_type = data.get("packet_type") or event_type.replace("aprs_", "")
        return packet_type == "weather" or bool(data.get("weather_summary"))

    def new_aprsis_weather_period_record(self, callsign, data, epoch, kind, key, label):
        """Return a new APRS weather aggregate record."""
        record = {
            "callsign": callsign,
            "period_kind": kind,
            "period_key": key,
            "period_label": label,
            "weather_station": True,
            "internet_fed": True,
            "sample_count": 0,
            "day_count": 1 if kind == "daily" else 0,
            **self.period_time_fields(epoch),
        }
        self.update_aprsis_weather_period_metadata(record, data)
        return record

    def update_aprsis_weather_period_metadata(self, record, data):
        """Copy latest APRS weather station metadata into an aggregate record."""
        for key in (
            "callsign",
            "destination",
            "via_path",
            "q_construct",
            "igate",
            "feed_name",
            "feed_role",
            "server_name",
            "server_address",
            "host",
            "port",
            "filter",
            "latitude",
            "longitude",
            "weather_summary",
        ):
            if data.get(key) not in (None, "", []):
                record[key] = data.get(key)

    def update_aprsis_weather_period_record(self, record, data, epoch):
        """Fold one APRS weather packet into a daily aggregate."""
        record["sample_count"] = int(record.get("sample_count") or 0) + 1
        self.update_aprsis_weather_period_metadata(record, data)
        if epoch < record.get("first_seen_epoch", epoch):
            record["first_seen_epoch"] = epoch
            record["first_seen"] = local_now(epoch)
        if epoch >= record.get("last_seen_epoch", 0):
            record["last_seen_epoch"] = epoch
            record["last_seen"] = local_now(epoch)
            for key in (
                "weather_summary",
                "temperature_f",
                "humidity_percent",
                "pressure_hpa",
                "wind_direction_deg",
                "wind_speed_mph",
                "wind_gust_mph",
                "rain_1h_in",
                "rain_24h_in",
                "rain_since_midnight_in",
                "luminosity_w_m2",
            ):
                if data.get(key) not in (None, "", []):
                    record[key] = data.get(key)
        self.update_min_max_numeric(
            record, "temperature_min_f", "temperature_max_f", data.get("temperature_f")
        )
        self.update_pws_average(
            record, "temperature", data.get("temperature_f"), "temperature_avg_f"
        )
        self.update_pws_first_latest_change(
            record,
            "temperature",
            data.get("temperature_f"),
            epoch,
            "temperature_change_f",
        )
        self.update_min_max_numeric(
            record,
            "humidity_min_percent",
            "humidity_max_percent",
            data.get("humidity_percent"),
        )
        self.update_pws_average(
            record, "humidity", data.get("humidity_percent"), "humidity_avg_percent"
        )
        self.update_min_max_numeric(
            record, "pressure_min_hpa", "pressure_max_hpa", data.get("pressure_hpa")
        )
        self.update_pws_average(
            record, "pressure_hpa", data.get("pressure_hpa"), "pressure_avg_hpa"
        )
        self.update_pws_first_latest_change(
            record,
            "pressure_hpa",
            data.get("pressure_hpa"),
            epoch,
            "pressure_change_hpa",
            digits=1,
        )
        self.update_max_numeric(
            record, "wind_speed_max_mph", data.get("wind_speed_mph")
        )
        self.update_max_numeric(record, "wind_gust_max_mph", data.get("wind_gust_mph"))
        self.update_pws_wind_direction(record, data.get("wind_direction_deg"))
        self.update_max_numeric(record, "rain_1h_max_in", data.get("rain_1h_in"))
        self.update_max_numeric(record, "rain_24h_max_in", data.get("rain_24h_in"))
        self.update_max_numeric(
            record, "rain_since_midnight_max_in", data.get("rain_since_midnight_in")
        )
        self.update_pws_rain_episode_totals(record, data.get("rain_1h_in"), epoch)
        self.update_max_numeric(
            record, "luminosity_max_w_m2", data.get("luminosity_w_m2")
        )

    def limit_period_summaries(self, records, weekly=4, monthly=12):
        """Limit rolling period summaries while keeping all yearly rows."""
        grouped = defaultdict(list)
        for record in records or []:
            grouped[record.get("period_kind") or ""].append(record)
        output = []
        for kind, items in grouped.items():
            sorted_items = sorted(
                items,
                key=lambda item: item.get("period_start_epoch") or 0,
                reverse=True,
            )
            if kind == "weekly":
                output.extend(sorted_items[:weekly])
            elif kind == "monthly":
                output.extend(sorted_items[:monthly])
            else:
                output.extend(sorted_items)
        return output

    def build_aprsis_weather_period_summaries(self, daily_records):
        """Roll APRS daily weather summaries into weekly/monthly/yearly rows."""
        periods = {}
        for day in daily_records or []:
            epoch = day.get("period_start_epoch") or day.get("first_seen_epoch")
            if epoch is None:
                continue
            callsign = day.get("callsign") or "unknown"
            for kind in ("weekly", "monthly", "yearly"):
                key, label = self.period_key(epoch, kind)
                record = periods.setdefault(
                    (callsign, kind, key),
                    self.new_aprsis_weather_period_record(
                        callsign, day, epoch, kind, key, label
                    ),
                )
                self.update_aprsis_weather_period_from_day(record, day)
        return self.limit_period_summaries(
            [self.finalize_pws_period_record(record) for record in periods.values()]
        )

    def update_aprsis_weather_period_from_day(self, record, day):
        """Fold one APRS weather daily aggregate into a longer period."""
        self.update_aprsis_weather_period_metadata(record, day)
        record["day_count"] = int(record.get("day_count") or 0) + 1
        record["sample_count"] = int(record.get("sample_count") or 0) + int(
            day.get("sample_count") or 0
        )
        self.update_period_bounds_from_day(record, day)
        for target_min, target_max in (
            ("temperature_min_f", "temperature_max_f"),
            ("humidity_min_percent", "humidity_max_percent"),
            ("pressure_min_hpa", "pressure_max_hpa"),
        ):
            self.update_min_max_numeric(
                record, target_min, target_max, day.get(target_min)
            )
            self.update_min_max_numeric(
                record, target_min, target_max, day.get(target_max)
            )
        self.update_pws_weighted_average(record, "temperature", day)
        self.update_pws_weighted_average(record, "humidity", day)
        self.update_aprsis_pressure_weighted_average(record, day)
        self.update_pws_first_latest_from_day(
            record, "temperature", day, "temperature_change_f"
        )
        self.update_pws_first_latest_from_day(
            record, "pressure_hpa", day, "pressure_change_hpa", digits=1
        )
        self.update_max_numeric(
            record, "wind_speed_max_mph", day.get("wind_speed_max_mph")
        )
        self.update_max_numeric(
            record, "wind_gust_max_mph", day.get("wind_gust_max_mph")
        )
        self.update_max_numeric(record, "rain_1h_max_in", day.get("rain_1h_max_in"))
        self.update_max_numeric(record, "rain_24h_max_in", day.get("rain_24h_max_in"))
        self.update_max_numeric(
            record, "rain_since_midnight_max_in", day.get("rain_since_midnight_max_in")
        )
        self.update_max_numeric(
            record, "luminosity_max_w_m2", day.get("luminosity_max_w_m2")
        )
        self.update_pws_wind_direction(record, day.get("wind_direction_avg_deg"))
        record["rain_episode_count"] = int(record.get("rain_episode_count") or 0) + int(
            day.get("rain_episode_count") or 0
        )
        record["rain_active_sample_count"] = int(
            record.get("rain_active_sample_count") or 0
        ) + int(day.get("rain_active_sample_count") or 0)
        record["rain_active_span_sec"] = float(
            record.get("rain_active_span_sec") or 0
        ) + float(day.get("rain_active_span_sec") or 0)
        if (day.get("last_seen_epoch") or 0) >= record.get("last_seen_epoch", 0):
            for key in (
                "temperature_f",
                "humidity_percent",
                "pressure_hpa",
                "weather_summary",
                "rain_1h_in",
                "wind_speed_mph",
                "wind_gust_mph",
            ):
                if day.get(key) not in (None, "", []):
                    record[key] = day.get(key)

    def update_aprsis_pressure_weighted_average(self, record, day):
        """Fold APRS daily pressure average into a longer weighted average."""
        value = day.get("pressure_avg_hpa")
        try:
            number = float(value)
            weight = max(1, int(day.get("sample_count") or 1))
        except (TypeError, ValueError):
            return
        record["_pressure_hpa_weighted_sum"] = (
            float(record.get("_pressure_hpa_weighted_sum") or 0) + number * weight
        )
        record["_pressure_hpa_weighted_count"] = (
            int(record.get("_pressure_hpa_weighted_count") or 0) + weight
        )
        record["pressure_avg_hpa"] = round(
            record["_pressure_hpa_weighted_sum"]
            / record["_pressure_hpa_weighted_count"],
            1,
        )

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

    def build_rtl433_history(self, observations, window_days):
        """Return compact per-device rtl_433 decoded-subject summaries."""
        subjects = {}
        latest_health = None
        latest_health_epoch = None
        records_read = 0
        for event in observations or []:
            if not event_in_window(event, window_days):
                continue
            event_type = event.get("type") or ""
            epoch = event_time_epoch(event)
            if epoch is None:
                continue
            records_read += 1
            data = clean_rtl433_data(event.get("data") or {})
            if event_type in (
                "collector_online",
                "collector_offline",
                "collector_retrying",
                "scanner_started",
            ):
                latest_health = {
                    "collector_state": (
                        "ONLINE"
                        if event_type in ("collector_online", "scanner_started")
                        else (
                            "OFFLINE"
                            if event_type == "collector_offline"
                            else "RETRYING"
                        )
                    ),
                    "frequency_plan": data.get("frequency_plan") or "",
                    "frequency_summary": data.get("frequency_summary") or "",
                    "reason": data.get("reason") or "",
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                }
                latest_health_epoch = epoch
                if event_type != "rtl433_event":
                    continue
            if event_type != "rtl433_event":
                continue
            key = (
                data.get("subject_key")
                or data.get("model")
                or data.get("id")
                or "unknown"
            )
            record = subjects.setdefault(
                key,
                {
                    "subject_key": key,
                    "model": data.get("model") or "",
                    "id": data.get("id") or "",
                    "channel": data.get("channel") or "",
                    "protocol": data.get("protocol"),
                    "category": data.get("category") or "device",
                    "first_seen": local_now(epoch),
                    "first_seen_epoch": epoch,
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                    "event_count": 0,
                    "burst_count": 0,
                    "sample_times": [],
                    "sample_fields": [],
                    "frequencies_mhz": [],
                    "hour_histogram": {},
                    "weekday_histogram": {},
                    "day_night_counts": {},
                    "frequency_counts": {},
                    "recent_observations": [],
                    "burst_gaps_sec": [],
                    "tpms_samples": [],
                    "tpms_statuses": [],
                    "tpms_battery_statuses": [],
                },
            )
            record["event_count"] += 1
            if epoch < record.get("first_seen_epoch", epoch):
                record["first_seen_epoch"] = epoch
                record["first_seen"] = local_now(epoch)
            previous_last = record.get("last_seen_epoch") or 0
            if previous_last and epoch - previous_last <= 120:
                record["burst_count"] = int(record.get("burst_count") or 0) + 1
                self.rtl433_record_burst_gap(record, epoch - previous_last)
            if epoch >= previous_last:
                record["last_seen_epoch"] = epoch
                record["last_seen"] = local_now(epoch)
                for field in ("model", "id", "channel", "category"):
                    if data.get(field):
                        record[field] = data.get(field)
                record["protocol"] = data.get("protocol", record.get("protocol"))
                record["latest_raw"] = data.get("raw") or {}
                record["latest_frequency_mhz"] = data.get("frequency_mhz")
                record["latest_tuned_frequency_mhz"] = data.get(
                    "tuned_frequency_mhz"
                ) or data.get("frequency_mhz")
                record["latest_rssi_db"] = data.get("rssi_db")
                record["latest_snr_db"] = data.get("snr_db")
                record["latest_noise_db"] = data.get("noise_db")
            self.sample_direct_value(record, "sample_times", local_now(epoch), 12)
            frequency = data.get("frequency_mhz")
            if frequency not in (None, ""):
                self.sample_direct_value(record, "frequencies_mhz", frequency, 12)
            raw = data.get("raw") or {}
            if raw:
                self.sample_direct_value(record, "sample_fields", raw, 6)
            self.rtl433_update_pattern_evidence(record, data, epoch)
            self.rtl433_update_tpms_evidence(record, data, epoch)
        for record in subjects.values():
            self.rtl433_finalize_pattern_evidence(record)
        output = [
            {
                "collector": "rtl433",
                "type": "rtl433_subject_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": (
                    "warning"
                    if record.get("category") in ("tpms", "security")
                    else "info"
                ),
                "data": record,
            }
            for record in sorted(
                subjects.values(),
                key=lambda item: item.get("last_seen_epoch") or 0,
                reverse=True,
            )
        ]
        if latest_health:
            output.append(
                {
                    "collector": "rtl433",
                    "type": "rtl433_collector_summary",
                    "timestamp": local_now(latest_health_epoch),
                    "timestamp_epoch": latest_health_epoch,
                    "severity": (
                        "warning"
                        if latest_health.get("collector_state") != "ONLINE"
                        else "info"
                    ),
                    "data": latest_health,
                }
            )
        return output, records_read

    def rtl433_update_tpms_evidence(self, record, data, epoch):
        """Fold one TPMS decode into retained tire-pressure evidence."""
        if (data.get("category") or record.get("category")) != "tpms":
            return
        record["category"] = "tpms"
        for key in (
            "pressure_kpa",
            "pressure_psi",
            "pressure_bar",
            "temperature_c",
            "temperature_f",
            "battery_status",
            "tpms_status",
            "tpms_position",
        ):
            if data.get(key) not in (None, "", []):
                record[key] = data.get(key)
        self.update_min_max_numeric(
            record, "pressure_psi_min", "pressure_psi_max", data.get("pressure_psi")
        )
        self.update_min_max_numeric(
            record, "pressure_kpa_min", "pressure_kpa_max", data.get("pressure_kpa")
        )
        self.update_min_max_numeric(
            record, "temperature_f_min", "temperature_f_max", data.get("temperature_f")
        )
        self.update_min_max_numeric(
            record, "temperature_c_min", "temperature_c_max", data.get("temperature_c")
        )
        self.sample_direct_value(record, "tpms_statuses", data.get("tpms_status"), 8)
        self.sample_direct_value(
            record, "tpms_battery_statuses", data.get("battery_status"), 8
        )
        sample = {
            "time": local_now(epoch),
            "pressure_psi": data.get("pressure_psi"),
            "pressure_kpa": data.get("pressure_kpa"),
            "temperature_f": data.get("temperature_f"),
            "battery_status": data.get("battery_status"),
            "tpms_status": data.get("tpms_status"),
            "frequency_mhz": data.get("frequency_mhz")
            or data.get("tuned_frequency_mhz"),
        }
        self.append_recent_record(record.setdefault("tpms_samples", []), sample, 12)
        event_count = int(record.get("event_count") or 0)
        burst_count = int(record.get("burst_count") or 0)
        if burst_count and event_count >= 2:
            record["tpms_interpretation"] = "possible vehicle/pass-through TPMS cluster"
        elif event_count >= 2:
            record["tpms_interpretation"] = "repeated TPMS sensor"
        else:
            record["tpms_interpretation"] = "single TPMS sensor decode"

    def rtl433_update_pattern_evidence(self, record, data, epoch):
        """Fold one rtl_433 decode into bounded pattern evidence."""
        dt = datetime.datetime.fromtimestamp(float(epoch))
        hour = "{:02d}".format(dt.hour)
        weekday = dt.strftime("%a")
        bucket = "day" if 6 <= dt.hour < 18 else "night"
        self.increment_counter_map(record.setdefault("hour_histogram", {}), hour)
        self.increment_counter_map(record.setdefault("weekday_histogram", {}), weekday)
        self.increment_counter_map(record.setdefault("day_night_counts", {}), bucket)
        frequency = data.get("frequency_mhz") or data.get("tuned_frequency_mhz")
        if frequency not in (None, ""):
            self.increment_counter_map(
                record.setdefault("frequency_counts", {}),
                self.rtl433_frequency_label(frequency),
            )
        observation = {
            "time": local_now(epoch),
            "frequency_mhz": frequency,
            "rssi_db": data.get("rssi_db"),
            "snr_db": data.get("snr_db"),
            "model": data.get("model") or "",
            "id": data.get("id") or "",
            "channel": data.get("channel") or "",
            "category": data.get("category") or "",
        }
        raw = data.get("raw") or {}
        if raw:
            observation["fields"] = {
                key: raw.get(key)
                for key in sorted(raw)[:8]
                if raw.get(key) not in (None, "", [], {})
            }
        self.append_recent_record(
            record.setdefault("recent_observations", []), observation, 12
        )

    def rtl433_record_burst_gap(self, record, gap):
        """Retain bounded short-gap timing evidence for repeated decodes."""
        try:
            value = round(float(gap), 1)
        except (TypeError, ValueError):
            return
        if value < 0:
            return
        gaps = record.setdefault("burst_gaps_sec", [])
        gaps.append(value)
        del gaps[:-12]

    def rtl433_finalize_pattern_evidence(self, record):
        """Convert retained rtl_433 counters into stable compact summaries."""
        for key in (
            "hour_histogram",
            "weekday_histogram",
            "day_night_counts",
            "frequency_counts",
        ):
            record[key] = self.sorted_counter_map(record.get(key) or {})
        gaps = [float(value) for value in record.get("burst_gaps_sec") or []]
        if gaps:
            record["burst_gap_min_sec"] = round(min(gaps), 1)
            record["burst_gap_max_sec"] = round(max(gaps), 1)
            record["burst_gap_avg_sec"] = round(sum(gaps) / len(gaps), 1)
        record["recent_observation_count"] = len(
            record.get("recent_observations") or []
        )

    def rtl433_frequency_label(self, value):
        """Return a stable MHz label for rtl_433 frequency histograms."""
        try:
            number = float(value)
        except (TypeError, ValueError):
            return str(value)
        return "{:.3f}".format(number).rstrip("0").rstrip(".")

    def increment_counter_map(self, counter, key, amount=1):
        """Increment a compact string-keyed counter map."""
        if key in (None, ""):
            return
        text = str(key)
        counter[text] = int(counter.get(text) or 0) + int(amount)

    def sorted_counter_map(self, counter):
        """Return a counter map in count-descending display order."""
        return {
            key: value
            for key, value in sorted(
                (counter or {}).items(),
                key=lambda item: (-int(item[1] or 0), str(item[0])),
            )[:24]
        }

    def append_recent_record(self, records, record, limit):
        """Append one compact recent record with a stable cap."""
        compact = {
            key: value
            for key, value in (record or {}).items()
            if value not in (None, "", [], {})
        }
        if not compact:
            return
        records.append(compact)
        del records[:-limit]

    def compact_adsb_observations(self, observations):
        """Fold retained ADS-B observations into one summary per aircraft."""
        aircraft = {}
        latest_health = None
        latest_health_epoch = None
        for event in observations or []:
            if not isinstance(event, dict):
                continue
            event_type = event.get("type") or ""
            epoch = event_time_epoch(event)
            if epoch is None:
                continue
            data = clean_adsb_data(event.get("data") or {})
            if event_type == "adsb_aircraft_summary":
                icao = data.get("icao")
                if not icao:
                    continue
                record = aircraft.setdefault(icao, {})
                record.update(data)
                record.setdefault("icao", icao)
                continue
            if event_type == "adsb_collector_summary":
                if latest_health_epoch is None or epoch >= latest_health_epoch:
                    latest_health = copy.deepcopy(event)
                    latest_health_epoch = epoch
                continue
            if event_type in (
                "collector_online",
                "collector_offline",
                "collector_retrying",
            ):
                if latest_health_epoch is None or epoch >= latest_health_epoch:
                    latest_health = {
                        "collector": "adsb",
                        "type": "adsb_collector_summary",
                        "timestamp": local_now(epoch),
                        "timestamp_epoch": epoch,
                        "severity": (
                            "warning" if event_type != "collector_online" else "info"
                        ),
                        "data": {
                            "collector_state": (
                                "ONLINE"
                                if event_type == "collector_online"
                                else (
                                    "OFFLINE"
                                    if event_type == "collector_offline"
                                    else "RETRYING"
                                )
                            ),
                            "source": data.get("source") or "",
                            "reason": data.get("reason") or "",
                            "decoder": data.get("decoder") or "",
                            "device_index": data.get("device_index"),
                            "poll_interval_sec": data.get("poll_interval_sec"),
                            "decoder_health": self.adsb_decoder_health_label(
                                event_type, data
                            ),
                            "rtlsdr_scheduling": self.adsb_rtlsdr_scheduling_text(data),
                            "last_seen": local_now(epoch),
                            "last_seen_epoch": epoch,
                        },
                    }
                    latest_health_epoch = epoch
                continue
            if event_type != "adsb_aircraft":
                continue
            icao = data.get("icao")
            if not icao:
                continue
            record = aircraft.setdefault(
                icao,
                {
                    "icao": icao,
                    "first_seen": local_now(epoch),
                    "first_seen_epoch": epoch,
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                    "seen_count": 0,
                    "position_count": 0,
                    "sample_callsigns": [],
                    "sample_squawks": [],
                    "route_samples": [],
                    "session_spans": [],
                    "emergency": False,
                },
            )
            self.update_adsb_summary(record, data, epoch)
        output = [
            {
                "collector": "adsb",
                "type": "adsb_aircraft_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": "warning" if record.get("emergency") else "info",
                "data": clean_adsb_data(record),
            }
            for record in sorted(
                aircraft.values(),
                key=lambda item: item.get("last_seen_epoch") or 0,
                reverse=True,
            )
        ]
        if latest_health:
            output.append(latest_health)
        return output

    def update_adsb_summary(self, record, data, epoch):
        """Fold one ADS-B aircraft event into a compact aircraft summary."""
        if epoch < record.get("first_seen_epoch", epoch):
            record["first_seen_epoch"] = epoch
            record["first_seen"] = local_now(epoch)
        if epoch >= record.get("last_seen_epoch", 0):
            record["last_seen_epoch"] = epoch
            record["last_seen"] = local_now(epoch)
            for key in (
                "callsign",
                "airline_icao",
                "category",
                "position_source",
                "air_ground",
                "cpr_type",
                "squawk",
                "lat",
                "lon",
                "altitude_ft",
                "altitude_baro_ft",
                "altitude_geom_ft",
                "ground_speed_kt",
                "track_deg",
                "vertical_rate_fpm",
                "distance_km",
                "rssi_dbfs",
                "source",
            ):
                if data.get(key) not in (None, ""):
                    record[key] = data.get(key)
        record["seen_count"] = int(record.get("seen_count") or 0) + 1
        if data.get("lat") is not None and data.get("lon") is not None:
            record["position_count"] = int(record.get("position_count") or 0) + 1
            self.update_adsb_path(record, data.get("lat"), data.get("lon"))
        self.update_min_max_numeric(
            record, "min_altitude_ft", "max_altitude_ft", data.get("altitude_ft")
        )
        self.update_max_numeric(
            record, "max_ground_speed_kt", data.get("ground_speed_kt")
        )
        self.update_min_numeric(record, "min_distance_km", data.get("distance_km"))
        self.aprsis_sample(record, "sample_callsigns", data.get("callsign"), limit=6)
        self.aprsis_sample(record, "sample_squawks", data.get("squawk"), limit=6)
        if data.get("emergency"):
            record["emergency"] = True
        self.update_adsb_session_summary(record, epoch)
        self.update_adsb_route_sample(record, data, epoch)
        self.update_adsb_approach_context(record, data)

    def adsb_decoder_health_label(self, event_type, data):
        """Return compact ADS-B decoder process health text."""
        if event_type == "collector_online":
            decoder = data.get("decoder") or "decoder"
            source = data.get("source") or "aircraft.json"
            return "{} online reading {}".format(decoder, source)
        reason = data.get("reason") or ""
        if event_type == "collector_retrying":
            return "decoder retrying{}".format(": {}".format(reason) if reason else "")
        if event_type == "collector_offline":
            return "decoder offline{}".format(": {}".format(reason) if reason else "")
        return ""

    def adsb_rtlsdr_scheduling_text(self, data):
        """Return operator guidance for ADS-B/RTL-433 one-dongle scheduling."""
        decoder = data.get("decoder") or "ADS-B decoder"
        device = data.get("device_index")
        if device in (None, ""):
            return "ADS-B shares RTL-SDR ownership with RTL-433 unless separate devices are configured."
        return "{} uses RTL-SDR device {}; configure RTL-433 for another device or stop one collector when only one dongle is attached.".format(
            decoder, device
        )

    def update_adsb_session_summary(self, record, epoch):
        """Fold ADS-B updates into compact pass/session evidence."""
        previous = record.get("_last_update_epoch")
        if previous is None or epoch - previous > 600:
            record["pass_count"] = int(record.get("pass_count") or 0) + 1
            record["_active_pass_start_epoch"] = epoch
            record["_active_pass_start"] = local_now(epoch)
        record["_last_update_epoch"] = epoch
        record["session_count"] = int(record.get("pass_count") or 0)
        start = record.get("_active_pass_start") or local_now(epoch)
        span = (
            "{} to {}".format(start, local_now(epoch))
            if start != local_now(epoch)
            else start
        )
        samples = record.setdefault("session_spans", [])
        if samples and samples[-1].startswith(str(start)):
            samples[-1] = span
        else:
            samples.append(span)
            del samples[:-8]

    def update_adsb_route_sample(self, record, data, epoch):
        """Retain bounded route samples for an ADS-B aircraft."""
        lat = data.get("lat")
        lon = data.get("lon")
        if lat is None or lon is None:
            return
        parts = [local_now(epoch), "{:.5f},{:.5f}".format(float(lat), float(lon))]
        if data.get("altitude_ft") not in (None, ""):
            parts.append("{} ft".format(data.get("altitude_ft")))
        if data.get("ground_speed_kt") not in (None, ""):
            parts.append("{} kt".format(data.get("ground_speed_kt")))
        if data.get("track_deg") not in (None, ""):
            parts.append("{} deg".format(data.get("track_deg")))
        self.aprsis_sample(record, "route_samples", " | ".join(parts), limit=12)
        record["route_sample_count"] = len(record.get("route_samples") or [])

    def update_adsb_approach_context(self, record, data):
        """Retain compact local approach/departure context when useful."""
        altitude = self.safe_float(data.get("altitude_ft"))
        distance = self.safe_float(data.get("distance_km"))
        vertical = self.safe_float(data.get("vertical_rate_fpm"))
        if altitude is None or distance is None:
            return
        if altitude <= 5000 and distance <= 25:
            if vertical is not None and vertical < -128:
                label = "nearby descending/approach-like track"
            elif vertical is not None and vertical > 128:
                label = "nearby climbing/departure-like track"
            else:
                label = "nearby low-altitude track"
            record["approach_context"] = label
            record["approach_distance_km"] = round(distance, 1)
            record["approach_altitude_ft"] = round(altitude)
            if vertical is not None:
                record["approach_vertical_rate_fpm"] = round(vertical)

    def build_adsb_history(self, observations, window_days):
        """Return compact per-aircraft ADS-B summaries for this view window."""
        aircraft = {}
        latest_health = None
        latest_health_epoch = None
        records_read = 0
        for event in self.compact_adsb_observations(observations or []):
            if not event_in_window(event, window_days):
                continue
            event_type = event.get("type") or ""
            epoch = event_time_epoch(event)
            if epoch is None:
                continue
            records_read += 1
            data = clean_adsb_data(event.get("data") or {})
            if event_type == "adsb_collector_summary":
                latest_health = data
                latest_health_epoch = epoch
                continue
            if event_type != "adsb_aircraft_summary":
                continue
            icao = data.get("icao")
            if not icao:
                continue
            aircraft[icao] = data
        output = [
            {
                "collector": "adsb",
                "type": "adsb_aircraft_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": "warning" if record.get("emergency") else "info",
                "data": clean_adsb_data(record),
            }
            for record in sorted(
                aircraft.values(),
                key=lambda item: item.get("last_seen_epoch") or 0,
                reverse=True,
            )
        ]
        if latest_health:
            output.append(
                {
                    "collector": "adsb",
                    "type": "adsb_collector_summary",
                    "timestamp": local_now(latest_health_epoch),
                    "timestamp_epoch": latest_health_epoch,
                    "severity": (
                        "warning"
                        if latest_health.get("collector_state") != "ONLINE"
                        else "info"
                    ),
                    "data": latest_health,
                }
            )
        return output, records_read

    def update_adsb_path(self, record, lat, lon):
        """Update first/latest position and path span for an aircraft."""
        latitude = self.safe_float(lat)
        longitude = self.safe_float(lon)
        if latitude is None or longitude is None:
            return
        if record.get("_first_position") is None:
            record["_first_position"] = [latitude, longitude]
            record["first_lat"] = latitude
            record["first_lon"] = longitude
        previous = record.get("_latest_position")
        record["_latest_position"] = [latitude, longitude]
        record["lat"] = latitude
        record["lon"] = longitude
        first = record.get("_first_position")
        if first:
            span = distance_km(first[0], first[1], latitude, longitude)
            if span is not None:
                record["path_span_km"] = span

    def update_min_numeric(self, record, key, value):
        """Update a minimum numeric field when a collector reports a number."""
        try:
            number = float(value)
        except (TypeError, ValueError):
            return
        old = record.get(key)
        record[key] = number if old is None else min(float(old), number)

    def build_noaa_history(self, observations, window_days):
        """Return compact per-alert NOAA summaries for this view window."""
        alerts = {}
        latest_health = None
        latest_health_epoch = None
        records_read = 0
        fingerprints = defaultdict(set)
        previous_forecasts = {}
        retained_events = []
        for event in observations or []:
            if not event_in_window(event, window_days):
                continue
            event_type = event.get("type") or ""
            if event_type not in (
                "noaa_weather_alert",
                "noaa_tropical_advisory",
                "noaa_forecast_summary",
                "noaa_tsunami_alert",
                "collector_offline",
                "collector_retrying",
            ):
                continue
            epoch = event_time_epoch(event)
            if epoch is None:
                continue
            retained_events.append((epoch, event_type, event))
        for epoch, event_type, event in sorted(
            retained_events, key=lambda item: item[0]
        ):
            records_read += 1
            data = clean_noaa_data(event.get("data") or {})
            if event_type in ("collector_offline", "collector_retrying"):
                latest_health = {
                    "collector_state": (
                        "OFFLINE" if event_type == "collector_offline" else "RETRYING"
                    ),
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
            if data.get("alert_kind") == "tropical_outlook":
                # Older NOAA rows included feed timestamp/link churn in their
                # fingerprint. For outlook state, count material text changes,
                # not every refreshed "no tropical cyclones" publication.
                fingerprint = "|".join(
                    str(data.get(field) or "")
                    for field in ("event", "headline", "severity", "summary", "basin")
                )
            else:
                fingerprint = data.get("fingerprint") or "|".join(
                    str(data.get(field) or "")
                    for field in (
                        "event",
                        "headline",
                        "updated",
                        "summary",
                        "source_url",
                    )
                )
            if data.get("alert_kind") == "forecast":
                previous = previous_forecasts.get(event_id)
                if previous:
                    data.update(self.noaa_forecast_delta_fields(previous, data))
                previous_forecasts[event_id] = copy.deepcopy(data)
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
                "type": record.get("event_type") or "noaa_alert_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": (
                    "warning"
                    if (
                        str(record.get("severity") or "").lower()
                        in ("severe", "extreme")
                        or (
                            record.get("alert_kind") == "tsunami"
                            and tsunami_is_alertworthy(record)
                        )
                    )
                    else "info"
                ),
                "data": clean_noaa_data(record),
            }
            for record in sorted(
                alerts.values(),
                key=lambda item: item.get("last_seen_epoch") or 0,
                reverse=True,
            )
        ]
        output.extend(
            {
                "collector": "noaa",
                "type": "noaa_period_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": (
                    "warning"
                    if record.get("tropical_system_count")
                    or record.get("nws_hazard_count")
                    or record.get("tsunami_incident_count")
                    else "info"
                ),
                "data": clean_noaa_data(record),
            }
            for record in sorted(
                self.limit_period_summaries(
                    self.add_noaa_period_comparisons(
                        self.build_noaa_period_summaries(alerts.values())
                    )
                ),
                key=lambda item: (
                    {"monthly": 0, "yearly": 1}.get(item.get("period_kind"), 9),
                    -(item.get("period_start_epoch") or 0),
                ),
            )
        )
        if latest_health:
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

    def noaa_forecast_delta_fields(self, previous, current):
        """Return compact previous-vs-current NWS point forecast deltas."""
        deltas = {}
        numeric_pairs = (
            (
                "current_temperature_f",
                "previous_current_temperature_f",
                "current_temperature_delta_f",
                5,
                "current temperature",
            ),
            (
                "temperature_min_f",
                "previous_temperature_min_f",
                "temperature_min_delta_f",
                5,
                "low temperature",
            ),
            (
                "temperature_max_f",
                "previous_temperature_max_f",
                "temperature_max_delta_f",
                5,
                "high temperature",
            ),
            (
                "max_precip_probability",
                "previous_max_precip_probability",
                "max_precip_probability_delta",
                20,
                "rain probability",
            ),
            (
                "next_precip_probability",
                "previous_next_precip_probability",
                "next_precip_probability_delta",
                20,
                "near-term rain probability",
            ),
            ("max_wind_mph", "previous_max_wind_mph", "max_wind_delta_mph", 5, "wind"),
        )
        findings = []
        for key, previous_key, delta_key, threshold, label in numeric_pairs:
            old = self.safe_float((previous or {}).get(key))
            new = self.safe_float((current or {}).get(key))
            if old is None or new is None:
                continue
            delta = round(new - old, 1)
            deltas[previous_key] = old
            deltas[delta_key] = delta
            if abs(delta) < threshold:
                continue
            if label == "rain probability":
                findings.append(
                    "Rain probability increased"
                    if delta > 0
                    else "Rain probability decreased"
                )
            elif label == "near-term rain probability":
                findings.append(
                    "Near-term rain probability increased"
                    if delta > 0
                    else "Near-term rain probability decreased"
                )
            elif label == "wind":
                findings.append(
                    "Stronger wind forecast" if delta > 0 else "Lower wind forecast"
                )
            else:
                findings.append("Large {} shift".format(label))
        hazard_delta = self.noaa_forecast_hazard_delta(previous, current)
        if hazard_delta:
            findings.append(hazard_delta)
        previous_generated = (previous or {}).get("forecast_generated") or ""
        if previous_generated:
            deltas["previous_forecast_generated"] = previous_generated
        previous_epoch = (previous or {}).get("forecast_generated_epoch")
        if previous_epoch not in (None, ""):
            deltas["previous_forecast_generated_epoch"] = previous_epoch
        if findings:
            deltas["forecast_delta_findings"] = self.unique_text_list(findings, 8)
            deltas["forecast_delta_summary"] = "; ".join(
                deltas["forecast_delta_findings"]
            )
            direction = self.noaa_forecast_change_direction(deltas, hazard_delta)
            if direction:
                deltas["forecast_change_direction"] = direction
        return deltas

    def noaa_forecast_hazard_delta(self, previous, current):
        """Return a conservative forecast text hazard delta label."""
        old = self.noaa_forecast_hazard_terms(previous)
        new = self.noaa_forecast_hazard_terms(current)
        added = sorted(new - old)
        cleared = sorted(old - new)
        if added:
            return "Forecast hazard text added: {}".format(", ".join(added[:4]))
        if cleared:
            return "Forecast hazard text cleared: {}".format(", ".join(cleared[:4]))
        return ""

    def noaa_forecast_hazard_terms(self, data):
        """Return weather hazard terms found in compact forecast text."""
        text = " ".join(
            str((data or {}).get(key) or "")
            for key in (
                "headline",
                "summary",
                "current_forecast",
                "description",
                "next_precip_forecast",
            )
        ).lower()
        terms = []
        for label, needles in (
            ("coastal flood", ("coastal flood",)),
            ("high surf", ("high surf", "surf")),
            ("gale", ("gale",)),
            ("small craft", ("small craft",)),
            ("thunderstorm", ("thunderstorm", "t-storm")),
            ("heavy rain", ("heavy rain", "rain heavy")),
            ("winter weather", ("snow", "ice", "freezing rain", "winter")),
        ):
            if any(needle in text for needle in needles):
                terms.append(label)
        return set(terms)

    def noaa_forecast_change_direction(self, deltas, hazard_delta):
        """Return deterioration/improvement text for meaningful forecast deltas."""
        worse = 0
        better = 0
        for key in (
            "max_precip_probability_delta",
            "next_precip_probability_delta",
            "max_wind_delta_mph",
        ):
            value = self.safe_float(deltas.get(key))
            if value is None:
                continue
            if value > 0:
                worse += 1
            elif value < 0:
                better += 1
        if hazard_delta.startswith("Forecast hazard text added"):
            worse += 1
        elif hazard_delta.startswith("Forecast hazard text cleared"):
            better += 1
        if worse and not better:
            return "deteriorating"
        if better and not worse:
            return "improving"
        if worse or better:
            return "mixed changes"
        return ""

    def unique_text_list(self, values, limit):
        """Return distinct compact strings preserving order."""
        output = []
        for value in values or []:
            text = " ".join(str(value or "").split())
            if text and text not in output:
                output.append(text)
            if len(output) >= limit:
                break
        return output

    def build_noaa_period_summaries(self, alerts):
        """Build monthly/yearly NOAA hazard/tropical/tsunami summaries."""
        periods = {}
        for item in alerts or []:
            kind = item.get("alert_kind") or ""
            if kind == "tropical_outlook":
                continue
            epoch = (
                item.get("event_time_epoch")
                or item.get("updated_epoch")
                or item.get("effective_epoch")
                or item.get("last_seen_epoch")
                or item.get("first_seen_epoch")
            )
            if epoch is None:
                continue
            for period_kind in ("monthly", "yearly"):
                key, label = self.period_key(epoch, period_kind)
                record = periods.setdefault(
                    (period_kind, key),
                    {
                        "period_kind": period_kind,
                        "period_key": key,
                        "period_label": label,
                        "internet_fed": True,
                        "event_count": 0,
                        "tropical_system_count": 0,
                        "nhc_product_count_total": 0,
                        "nws_hazard_count": 0,
                        "tsunami_incident_count": 0,
                        "tsunami_message_count": 0,
                        "forecast_count": 0,
                        "basins": [],
                        "tropical_systems": [],
                        "hazard_events": [],
                        "hazard_areas": [],
                        "hazard_severities": [],
                        "tsunami_incidents": [],
                        "sources": [],
                        "_tropical_systems": set(),
                        "_tsunami_incidents": set(),
                        **self.period_time_fields(epoch),
                    },
                )
                self.update_noaa_period_record(record, item, epoch)
        output = []
        for record in periods.values():
            systems = sorted(record.pop("_tropical_systems", set()))
            incidents = sorted(record.pop("_tsunami_incidents", set()))
            record["tropical_system_count"] = len(systems)
            record["tsunami_incident_count"] = len(incidents)
            record["tropical_systems"] = systems[:24]
            record["tsunami_incidents"] = incidents[:24]
            output.append(record)
        return output

    def update_noaa_period_record(self, record, item, epoch):
        """Fold one unique NOAA subject into a monthly/yearly summary."""
        record["event_count"] = int(record.get("event_count") or 0) + 1
        kind = item.get("alert_kind") or ""
        source = item.get("source") or ""
        self.sample_direct_value(record, "sources", source, 12)
        if kind == "tropical":
            system = (
                item.get("nhc_system")
                or item.get("nhc_storm_id")
                or item.get("event")
                or item.get("headline")
            )
            if system:
                record["_tropical_systems"].add(str(system))
            self.sample_direct_value(record, "basins", item.get("basin"), 12)
            record["nhc_product_count_total"] = int(
                record.get("nhc_product_count_total") or 0
            ) + int(item.get("nhc_product_count") or 1)
        elif kind == "tsunami":
            incident = (
                item.get("incident_id")
                or item.get("tsunami_identifier")
                or item.get("event_id")
            )
            if incident:
                record["_tsunami_incidents"].add(str(incident))
            record["tsunami_message_count"] = (
                int(record.get("tsunami_message_count") or 0) + 1
            )
        elif kind == "forecast":
            record["forecast_count"] = int(record.get("forecast_count") or 0) + 1
        else:
            record["nws_hazard_count"] = int(record.get("nws_hazard_count") or 0) + 1
            self.sample_direct_value(record, "hazard_events", item.get("event"), 16)
            self.sample_direct_value(record, "hazard_areas", item.get("area_desc"), 16)
            self.sample_direct_value(
                record, "hazard_severities", item.get("severity"), 8
            )
        event_seen = item.get("last_seen_epoch") or epoch
        if event_seen >= record.get("last_seen_epoch", 0):
            record["last_seen_epoch"] = event_seen
            record["last_seen"] = local_now(event_seen)
            for key in ("event_id", "event", "headline", "source", "alert_kind"):
                if item.get(key) not in (None, "", []):
                    record["latest_{}".format(key)] = item.get(key)
        first_seen = item.get("first_seen_epoch") or epoch
        if first_seen < record.get("first_seen_epoch", first_seen):
            record["first_seen_epoch"] = first_seen
            record["first_seen"] = local_now(first_seen)

    def add_noaa_period_comparisons(self, records):
        """Add previous-period count deltas where retained history has one."""
        by_kind = defaultdict(list)
        for record in records or []:
            by_kind[record.get("period_kind")].append(record)
        output = []
        for _kind, items in by_kind.items():
            items = sorted(items, key=lambda item: item.get("period_start_epoch") or 0)
            previous = None
            for item in items:
                if previous is not None:
                    previous_count = int(previous.get("event_count") or 0)
                    current_count = int(item.get("event_count") or 0)
                    item["previous_event_count"] = previous_count
                    item["event_count_delta"] = current_count - previous_count
                output.append(item)
                previous = item
        return output

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
                    "collector_state": (
                        "OFFLINE" if event_type == "collector_offline" else "RETRYING"
                    ),
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
                "severity": (
                    "warning"
                    if record.get("tsunami")
                    or record.get("global_major")
                    or str(record.get("alert_color") or "").lower()
                    in ("yellow", "orange", "red")
                    else "info"
                ),
                "data": clean_usgs_data(record),
            }
            for record in sorted(
                earthquakes.values(),
                key=lambda item: item.get("last_seen_epoch") or 0,
                reverse=True,
            )
        ]
        output.extend(
            {
                "collector": "usgs",
                "type": "usgs_earthquake_period_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": "warning" if record.get("notable_count") else "info",
                "data": clean_usgs_data(record),
            }
            for record in sorted(
                self.limit_period_summaries(
                    self.build_usgs_period_summaries(earthquakes.values())
                ),
                key=lambda item: (
                    {"weekly": 0, "monthly": 1, "yearly": 2}.get(
                        item.get("period_kind"), 9
                    ),
                    -(item.get("period_start_epoch") or 0),
                ),
            )
        )
        if latest_health:
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

    def build_usgs_period_summaries(self, earthquakes):
        """Build weekly/monthly/yearly unique-earthquake summaries."""
        periods = {}
        for quake in earthquakes or []:
            epoch = (
                quake.get("event_time_epoch")
                or quake.get("last_seen_epoch")
                or quake.get("first_seen_epoch")
            )
            if epoch is None:
                continue
            for kind in ("weekly", "monthly", "yearly"):
                key, label = self.period_key(epoch, kind)
                record = periods.setdefault(
                    (kind, key),
                    {
                        "period_kind": kind,
                        "period_key": key,
                        "period_label": label,
                        "internet_fed": True,
                        "event_count": 0,
                        "local_count": 0,
                        "global_major_count": 0,
                        "notable_count": 0,
                        "tsunami_count": 0,
                        "event_ids": [],
                        "alert_colors": [],
                        "scopes": [],
                        "feeds": [],
                        **self.period_time_fields(epoch),
                    },
                )
                self.update_usgs_period_record(record, quake, epoch)
        return list(periods.values())

    def update_usgs_period_record(self, record, quake, epoch):
        """Fold one unique earthquake into a USGS period summary."""
        record["event_count"] = int(record.get("event_count") or 0) + 1
        if quake.get("global_major") or str(quake.get("scope") or "") == "global":
            record["global_major_count"] = (
                int(record.get("global_major_count") or 0) + 1
            )
        else:
            record["local_count"] = int(record.get("local_count") or 0) + 1
        magnitude = self.safe_float(quake.get("magnitude"))
        if magnitude is not None and magnitude >= 4.0:
            record["notable_count"] = int(record.get("notable_count") or 0) + 1
        if quake.get("tsunami"):
            record["tsunami_count"] = int(record.get("tsunami_count") or 0) + 1
        self.update_min_max_numeric(record, "magnitude_min", "magnitude_max", magnitude)
        nearest = self.safe_float(quake.get("distance_km"))
        if nearest is not None:
            old = record.get("nearest_distance_km")
            record["nearest_distance_km"] = (
                nearest if old is None else min(float(old), nearest)
            )
        depth = self.safe_float(quake.get("depth_km"))
        if depth is not None:
            old = record.get("shallowest_depth_km")
            record["shallowest_depth_km"] = (
                depth if old is None else min(float(old), depth)
            )
        for list_key, value in (
            ("event_ids", quake.get("event_id")),
            ("alert_colors", quake.get("alert_color")),
            ("scopes", quake.get("scope")),
            ("feeds", quake.get("feed")),
        ):
            self.sample_direct_value(record, list_key, value, 24)
        event_seen = (
            quake.get("last_seen_epoch") or quake.get("event_time_epoch") or epoch
        )
        if event_seen >= record.get("last_seen_epoch", 0):
            record["last_seen_epoch"] = event_seen
            record["last_seen"] = local_now(event_seen)
            for key in (
                "event_id",
                "place",
                "magnitude",
                "event_time",
                "depth_km",
                "alert_color",
            ):
                if quake.get(key) not in (None, "", []):
                    record["latest_{}".format(key)] = quake.get(key)
        first_seen = quake.get("first_seen_epoch") or epoch
        if first_seen < record.get("first_seen_epoch", first_seen):
            record["first_seen_epoch"] = first_seen
            record["first_seen"] = local_now(first_seen)

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
                    "collector_state": (
                        "OFFLINE" if event_type == "collector_offline" else "RETRYING"
                    ),
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
        output.extend(
            {
                "collector": "swpc",
                "type": "swpc_event_period_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": "warning" if record.get("alert_count") else "info",
                "data": clean_swpc_data(record),
            }
            for record in sorted(
                self.limit_period_summaries(
                    self.build_swpc_period_summaries(events.values())
                ),
                key=lambda item: (
                    {"weekly": 0, "monthly": 1, "yearly": 2}.get(
                        item.get("period_kind"), 9
                    ),
                    -(item.get("period_start_epoch") or 0),
                ),
            )
        )
        if latest_health:
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

    def build_swpc_period_summaries(self, events):
        """Build weekly/monthly/yearly unique SWPC event summaries."""
        periods = {}
        for item in events or []:
            epoch = (
                item.get("event_time_epoch")
                or item.get("start_time_epoch")
                or item.get("peak_time_epoch")
                or item.get("issue_epoch")
                or item.get("last_seen_epoch")
                or item.get("first_seen_epoch")
            )
            if epoch is None:
                continue
            for kind in ("weekly", "monthly", "yearly"):
                key, label = self.period_key(epoch, kind)
                record = periods.setdefault(
                    (kind, key),
                    {
                        "period_kind": kind,
                        "period_key": key,
                        "period_label": label,
                        "internet_fed": True,
                        "event_count": 0,
                        "alert_count": 0,
                        "critical_count": 0,
                        "xray_flare_count": 0,
                        "radio_blackout_count": 0,
                        "solar_radiation_storm_count": 0,
                        "geomagnetic_storm_count": 0,
                        "events": [],
                        "kind_counts": [],
                        "scale_labels": [],
                        "_kind_counter": Counter(),
                        **self.period_time_fields(epoch),
                    },
                )
                self.update_swpc_period_record(record, item, epoch)
        output = []
        for record in periods.values():
            counter = record.pop("_kind_counter", Counter())
            record["kind_counts"] = self.counter_labels(counter, limit=8)
            output.append(record)
        return output

    def update_swpc_period_record(self, record, item, epoch):
        """Fold one unique SWPC event into a period summary."""
        record["event_count"] = int(record.get("event_count") or 0) + 1
        kind = item.get("event_kind") or "unknown"
        record["_kind_counter"][kind] += 1
        if swpc_event_is_alert(item):
            record["alert_count"] = int(record.get("alert_count") or 0) + 1
        if swpc_event_is_critical(item):
            record["critical_count"] = int(record.get("critical_count") or 0) + 1
        if kind == "xray_flare":
            record["xray_flare_count"] = int(record.get("xray_flare_count") or 0) + 1
            record["highest_xray_class"] = self.higher_xray_class(
                record.get("highest_xray_class"), item.get("xray_class")
            )
        elif kind == "radio_blackout":
            record["radio_blackout_count"] = (
                int(record.get("radio_blackout_count") or 0) + 1
            )
            self.update_scale_max(record, "max_radio_blackout", item)
        elif kind == "solar_radiation_storm":
            record["solar_radiation_storm_count"] = (
                int(record.get("solar_radiation_storm_count") or 0) + 1
            )
            self.update_scale_max(record, "max_solar_radiation_storm", item)
        elif kind == "geomagnetic_storm":
            record["geomagnetic_storm_count"] = (
                int(record.get("geomagnetic_storm_count") or 0) + 1
            )
            self.update_scale_max(record, "max_geomagnetic_storm", item)
        kp = number_or_none(item.get("kp_index"))
        if kp is not None:
            old = record.get("max_kp")
            record["max_kp"] = kp if old is None else max(float(old), kp)
        self.sample_direct_value(
            record, "events", item.get("event") or item.get("summary"), 24
        )
        self.sample_direct_value(record, "scale_labels", item.get("scale_label"), 24)
        event_seen = item.get("last_seen_epoch") or epoch
        if event_seen >= record.get("last_seen_epoch", 0):
            record["last_seen_epoch"] = event_seen
            record["last_seen"] = local_now(event_seen)
            for key in (
                "event_id",
                "event",
                "event_kind",
                "scale_label",
                "xray_class",
                "kp_index",
            ):
                if item.get(key) not in (None, "", []):
                    record["latest_{}".format(key)] = item.get(key)
        first_seen = item.get("first_seen_epoch") or epoch
        if first_seen < record.get("first_seen_epoch", first_seen):
            record["first_seen_epoch"] = first_seen
            record["first_seen"] = local_now(first_seen)

    def higher_xray_class(self, current, candidate):
        """Return the stronger GOES X-ray flare class label."""
        current_flux = xray_class_to_flux(current) if current else None
        candidate_flux = xray_class_to_flux(candidate) if candidate else None
        if candidate_flux is None:
            return current or ""
        if current_flux is None or candidate_flux > current_flux:
            return str(candidate or "").upper()
        return current or ""

    def update_scale_max(self, record, key, item):
        """Update a max R/S/G scale field from one SWPC item."""
        value = number_or_none(item.get("scale_value"))
        if value is None:
            return
        old = record.get(key)
        record[key] = int(value) if old is None else max(int(old), int(value))
        family = item.get("scale_family") or ""
        label = swpc_scale_label(family, record[key])
        if label:
            record["{}_label".format(key)] = label

    def build_pws_history(self, observations, window_days):
        """Return compact per-station PWS summaries."""
        stations = {}
        daily = {}
        latest_health = None
        latest_health_epoch = None
        records_read = 0
        for event in sorted(
            observations or [], key=lambda item: event_time_epoch(item) or 0
        ):
            if not event_in_window(event, window_days):
                continue
            event_type = event.get("type") or ""
            if event_type not in (
                "pws_weather",
                "collector_offline",
                "collector_retrying",
            ):
                continue
            epoch = event_time_epoch(event)
            if epoch is None:
                continue
            records_read += 1
            data = clean_pws_data(event.get("data") or {})
            if event_type in ("collector_offline", "collector_retrying"):
                latest_health = {
                    "collector_state": (
                        "OFFLINE" if event_type == "collector_offline" else "RETRYING"
                    ),
                    "reason": data.get("reason") or "",
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                }
                latest_health_epoch = epoch
                continue
            station_id = (
                data.get("station_id")
                or data.get("station_name")
                or data.get("mac_address")
                or "unknown"
            )
            record = stations.setdefault(
                station_id,
                {
                    "station_id": station_id,
                    "first_seen": local_now(epoch),
                    "first_seen_epoch": epoch,
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                    "observation_count": 0,
                    "update_count": 0,
                    "sample_battery": [],
                },
            )
            self.update_pws_weather_summary(record, data, epoch)
            day_key, day_label = self.pws_period_key(epoch, "daily")
            day_record = daily.setdefault(
                (station_id, day_key),
                self.new_pws_period_record(
                    station_id, data, epoch, "daily", day_key, day_label
                ),
            )
            self.update_pws_period_record(day_record, data, epoch)
        daily_records = sorted(
            daily.values(),
            key=lambda item: (
                item.get("station_id") or "",
                item.get("period_start_epoch") or 0,
            ),
        )
        period_records = self.limit_period_summaries(
            self.build_pws_period_summaries(daily_records)
        )
        output = [
            {
                "collector": "pws",
                "type": "pws_weather_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": "info",
                "data": clean_pws_data(record),
            }
            for record in sorted(
                stations.values(),
                key=lambda item: item.get("last_seen_epoch") or 0,
                reverse=True,
            )
        ]
        output.extend(
            {
                "collector": "pws",
                "type": "pws_weather_period_summary",
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "severity": "info",
                "data": clean_pws_data(record),
            }
            for record in sorted(
                period_records,
                key=lambda item: (
                    {"weekly": 0, "monthly": 1, "yearly": 2}.get(
                        item.get("period_kind"), 9
                    ),
                    -(item.get("period_start_epoch") or 0),
                    item.get("station_id") or "",
                ),
            )
        )
        if latest_health:
            output.append(
                {
                    "collector": "pws",
                    "type": "pws_collector_summary",
                    "timestamp": local_now(latest_health_epoch),
                    "timestamp_epoch": latest_health_epoch,
                    "severity": "warning",
                    "data": clean_pws_data(latest_health),
                }
            )
        return output, records_read

    def period_key(self, epoch, kind):
        """Return a stable local-time aggregate key and label."""
        dt = datetime.datetime.fromtimestamp(float(epoch))
        if kind == "weekly":
            iso_year, iso_week, _weekday = dt.isocalendar()
            key = "{:04d}-W{:02d}".format(iso_year, iso_week)
            return key, "week {}".format(key)
        if kind == "monthly":
            key = dt.strftime("%Y-%m")
            return key, "month {}".format(key)
        if kind == "yearly":
            key = dt.strftime("%Y")
            return key, "year {}".format(key)
        key = dt.strftime("%Y-%m-%d")
        return key, key

    def pws_period_key(self, epoch, kind):
        """Return a stable local-time PWS aggregate key and label."""
        return self.period_key(epoch, kind)

    def period_time_fields(self, epoch):
        """Return common first/last fields for a one-event period record."""
        return {
            "period_start": local_now(epoch),
            "period_start_epoch": epoch,
            "period_end": local_now(epoch),
            "period_end_epoch": epoch,
            "first_seen": local_now(epoch),
            "first_seen_epoch": epoch,
            "last_seen": local_now(epoch),
            "last_seen_epoch": epoch,
        }

    def update_period_bounds_from_day(self, record, day):
        """Expand period start/end and first/last fields using one daily record."""
        first_epoch = day.get("period_start_epoch") or day.get("first_seen_epoch")
        last_epoch = day.get("period_end_epoch") or day.get("last_seen_epoch")
        if first_epoch is not None and first_epoch < record.get(
            "period_start_epoch", first_epoch
        ):
            record["period_start_epoch"] = first_epoch
            record["period_start"] = local_now(first_epoch)
        if last_epoch is not None and last_epoch >= record.get("period_end_epoch", 0):
            record["period_end_epoch"] = last_epoch
            record["period_end"] = local_now(last_epoch)
        if first_epoch is not None and first_epoch < record.get(
            "first_seen_epoch", first_epoch
        ):
            record["first_seen_epoch"] = first_epoch
            record["first_seen"] = local_now(first_epoch)
        if last_epoch is not None and last_epoch >= record.get("last_seen_epoch", 0):
            record["last_seen_epoch"] = last_epoch
            record["last_seen"] = local_now(last_epoch)

    def new_pws_period_record(self, station_id, data, epoch, kind, key, label):
        """Return a new PWS aggregate record."""
        record = {
            "station_id": station_id,
            "station_name": data.get("station_name") or "",
            "mac_address": data.get("mac_address") or "",
            "model": data.get("model") or "",
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "location_name": data.get("location_name") or "",
            "elevation_m": data.get("elevation_m"),
            "elevation_ft": data.get("elevation_ft"),
            "timezone": data.get("timezone") or "",
            "source": data.get("source") or "",
            "source_url": data.get("source_url") or "",
            "period_kind": kind,
            "period_key": key,
            "period_label": label,
            "period_start": local_now(epoch),
            "period_start_epoch": epoch,
            "period_end": local_now(epoch),
            "period_end_epoch": epoch,
            "first_seen": local_now(epoch),
            "first_seen_epoch": epoch,
            "last_seen": local_now(epoch),
            "last_seen_epoch": epoch,
            "sample_count": 0,
            "day_count": 1 if kind == "daily" else 0,
        }
        self.update_pws_latest_metadata(record, data)
        return record

    def update_pws_latest_metadata(self, record, data):
        """Copy latest station metadata into a PWS aggregate record."""
        for key in (
            "station_id",
            "station_name",
            "mac_address",
            "model",
            "latitude",
            "longitude",
            "location_name",
            "elevation_m",
            "elevation_ft",
            "timezone",
            "source",
            "source_url",
        ):
            if data.get(key) not in (None, "", []):
                record[key] = data.get(key)

    def update_pws_period_record(self, record, data, epoch):
        """Fold one PWS sample into a daily aggregate record."""
        record["sample_count"] = int(record.get("sample_count") or 0) + 1
        self.update_pws_latest_metadata(record, data)
        if epoch < record.get("first_seen_epoch", epoch):
            record["first_seen_epoch"] = epoch
            record["first_seen"] = local_now(epoch)
        if epoch >= record.get("last_seen_epoch", 0):
            record["last_seen_epoch"] = epoch
            record["last_seen"] = local_now(epoch)
            for key in (
                "event_time",
                "event_time_epoch",
                "ambient_date",
                "ambient_date_epoch",
                "battery",
                "weather_summary",
            ):
                if data.get(key) not in (None, "", []):
                    record[key] = data.get(key)
        self.update_min_max_numeric(
            record, "temperature_min_f", "temperature_max_f", data.get("temperature_f")
        )
        self.update_pws_average(
            record, "temperature", data.get("temperature_f"), "temperature_avg_f"
        )
        self.update_pws_first_latest_change(
            record,
            "temperature",
            data.get("temperature_f"),
            epoch,
            "temperature_change_f",
        )
        self.update_min_max_numeric(
            record,
            "humidity_min_percent",
            "humidity_max_percent",
            data.get("humidity_percent"),
        )
        self.update_pws_average(
            record, "humidity", data.get("humidity_percent"), "humidity_avg_percent"
        )
        self.update_min_max_numeric(
            record, "dewpoint_min_f", "dewpoint_max_f", data.get("dewpoint_f")
        )
        self.update_pws_average(
            record, "dewpoint", data.get("dewpoint_f"), "dewpoint_avg_f"
        )
        self.update_min_max_numeric(
            record,
            "pressure_rel_min_inhg",
            "pressure_rel_max_inhg",
            data.get("pressure_rel_inhg"),
        )
        self.update_pws_first_latest_change(
            record,
            "pressure_rel",
            data.get("pressure_rel_inhg"),
            epoch,
            "pressure_rel_change_inhg",
            digits=3,
        )
        self.update_max_numeric(
            record, "wind_speed_max_mph", data.get("wind_speed_mph")
        )
        self.update_max_numeric(record, "wind_gust_max_mph", data.get("wind_gust_mph"))
        self.update_max_numeric(
            record, "max_daily_gust_mph", data.get("max_daily_gust_mph")
        )
        self.update_pws_wind_direction(record, data.get("wind_direction_deg"))
        self.update_max_numeric(record, "rain_1h_max_in", data.get("rain_1h_in"))
        self.update_max_numeric(record, "rain_period_total_in", data.get("rain_day_in"))
        self.update_pws_rain_episode_totals(record, data.get("rain_1h_in"), epoch)
        self.update_max_numeric(record, "solar_max_w_m2", data.get("solar_w_m2"))
        self.update_max_numeric(record, "uv_max_index", data.get("uv_index"))

    def update_pws_average(self, record, prefix, value, output_key):
        """Update a numeric average accumulator."""
        try:
            number = float(value)
        except (TypeError, ValueError):
            return
        sum_key = "_{}_sum".format(prefix)
        count_key = "_{}_count".format(prefix)
        record[sum_key] = float(record.get(sum_key) or 0) + number
        record[count_key] = int(record.get(count_key) or 0) + 1
        record[output_key] = round(record[sum_key] / record[count_key], 2)

    def update_pws_first_latest_change(
        self, record, prefix, value, epoch, output_key, digits=1
    ):
        """Track first/latest numeric values and their change."""
        try:
            number = float(value)
        except (TypeError, ValueError):
            return
        first_epoch_key = "_{}_first_epoch".format(prefix)
        first_key = "_{}_first".format(prefix)
        latest_epoch_key = "_{}_latest_epoch".format(prefix)
        latest_key = "_{}_latest".format(prefix)
        if record.get(first_epoch_key) is None or epoch < record.get(first_epoch_key):
            record[first_epoch_key] = epoch
            record[first_key] = number
        if record.get(latest_epoch_key) is None or epoch >= record.get(
            latest_epoch_key
        ):
            record[latest_epoch_key] = epoch
            record[latest_key] = number
        if record.get(first_key) is not None and record.get(latest_key) is not None:
            record[output_key] = round(
                float(record[latest_key]) - float(record[first_key]), digits
            )

    def update_pws_wind_direction(self, record, value):
        """Update a circular mean wind direction."""
        try:
            degrees = float(value)
        except (TypeError, ValueError):
            return
        radians = math.radians(degrees)
        record["_wind_dir_sin_sum"] = float(
            record.get("_wind_dir_sin_sum") or 0
        ) + math.sin(radians)
        record["_wind_dir_cos_sum"] = float(
            record.get("_wind_dir_cos_sum") or 0
        ) + math.cos(radians)
        record["_wind_dir_count"] = int(record.get("_wind_dir_count") or 0) + 1
        angle = math.degrees(
            math.atan2(record["_wind_dir_sin_sum"], record["_wind_dir_cos_sum"])
        )
        record["wind_direction_avg_deg"] = round(angle % 360, 1)

    def update_pws_rain_episode_totals(self, record, rain, epoch):
        """Track observed rain episodes and approximate rain-active sample span."""
        try:
            current = float(rain) > 0
        except (TypeError, ValueError):
            return
        previous = record.get("_last_rain_active")
        previous_epoch = record.get("_last_sample_epoch")
        if previous_epoch is not None and previous:
            delta = max(0, float(epoch) - float(previous_epoch))
            record["rain_active_span_sec"] = float(
                record.get("rain_active_span_sec") or 0
            ) + min(delta, 600)
        if previous is None:
            if current:
                record["rain_episode_count"] = (
                    int(record.get("rain_episode_count") or 0) + 1
                )
        elif not previous and current:
            record["rain_episode_count"] = (
                int(record.get("rain_episode_count") or 0) + 1
            )
        if current:
            record["rain_active_sample_count"] = (
                int(record.get("rain_active_sample_count") or 0) + 1
            )
        record["_last_rain_active"] = current
        record["_last_sample_epoch"] = epoch

    def finalize_pws_period_record(self, record):
        """Return one display-safe PWS aggregate record."""
        record = dict(record or {})
        if record.get("rain_active_span_sec") is not None:
            record["rain_active_span_min"] = round(
                float(record.get("rain_active_span_sec") or 0) / 60.0, 1
            )
        record["coverage_days"] = max(1, int(record.get("day_count") or 1))
        for key in list(record):
            if key.startswith("_"):
                record.pop(key, None)
        return record

    def build_pws_period_summaries(self, daily_records):
        """Roll daily PWS summaries into weekly, monthly, and yearly summaries."""
        periods = {}
        for day in daily_records or []:
            epoch = day.get("period_start_epoch") or day.get("first_seen_epoch")
            if epoch is None:
                continue
            station_id = day.get("station_id") or day.get("station_name") or "unknown"
            for kind in ("weekly", "monthly", "yearly"):
                key, label = self.pws_period_key(epoch, kind)
                record = periods.setdefault(
                    (station_id, kind, key),
                    self.new_pws_period_record(
                        station_id, day, epoch, kind, key, label
                    ),
                )
                self.update_pws_period_from_day(record, day)
        return [self.finalize_pws_period_record(record) for record in periods.values()]

    def update_pws_period_from_day(self, record, day):
        """Fold one daily aggregate into a longer PWS period aggregate."""
        self.update_pws_latest_metadata(record, day)
        record["day_count"] = int(record.get("day_count") or 0) + 1
        record["sample_count"] = int(record.get("sample_count") or 0) + int(
            day.get("sample_count") or 0
        )
        first_epoch = day.get("period_start_epoch") or day.get("first_seen_epoch")
        last_epoch = day.get("period_end_epoch") or day.get("last_seen_epoch")
        if first_epoch is not None and first_epoch < record.get(
            "period_start_epoch", first_epoch
        ):
            record["period_start_epoch"] = first_epoch
            record["period_start"] = local_now(first_epoch)
        if last_epoch is not None and last_epoch >= record.get("period_end_epoch", 0):
            record["period_end_epoch"] = last_epoch
            record["period_end"] = local_now(last_epoch)
        for source_key, target_min, target_max in (
            ("temperature", "temperature_min_f", "temperature_max_f"),
            ("humidity", "humidity_min_percent", "humidity_max_percent"),
            ("dewpoint", "dewpoint_min_f", "dewpoint_max_f"),
            ("pressure_rel", "pressure_rel_min_inhg", "pressure_rel_max_inhg"),
        ):
            self.update_min_max_numeric(
                record, target_min, target_max, day.get(target_min)
            )
            self.update_min_max_numeric(
                record, target_min, target_max, day.get(target_max)
            )
            self.update_pws_weighted_average(record, source_key, day)
        self.update_pws_first_latest_from_day(
            record, "temperature", day, "temperature_change_f"
        )
        self.update_pws_first_latest_from_day(
            record, "pressure_rel", day, "pressure_rel_change_inhg", digits=3
        )
        self.update_max_numeric(record, "rain_1h_max_in", day.get("rain_1h_max_in"))
        if day.get("rain_period_total_in") is not None:
            record["rain_period_total_in"] = round(
                float(record.get("rain_period_total_in") or 0)
                + float(day.get("rain_period_total_in") or 0),
                3,
            )
        record["rain_episode_count"] = int(record.get("rain_episode_count") or 0) + int(
            day.get("rain_episode_count") or 0
        )
        record["rain_active_sample_count"] = int(
            record.get("rain_active_sample_count") or 0
        ) + int(day.get("rain_active_sample_count") or 0)
        record["rain_active_span_sec"] = float(
            record.get("rain_active_span_sec") or 0
        ) + float(day.get("rain_active_span_sec") or 0)
        self.update_max_numeric(
            record, "wind_speed_max_mph", day.get("wind_speed_max_mph")
        )
        self.update_max_numeric(
            record, "wind_gust_max_mph", day.get("wind_gust_max_mph")
        )
        self.update_max_numeric(
            record, "max_daily_gust_mph", day.get("max_daily_gust_mph")
        )
        self.update_max_numeric(record, "solar_max_w_m2", day.get("solar_max_w_m2"))
        self.update_max_numeric(record, "uv_max_index", day.get("uv_max_index"))
        self.update_pws_wind_direction(record, day.get("wind_direction_avg_deg"))
        if last_epoch is not None and last_epoch >= record.get("last_seen_epoch", 0):
            record["last_seen_epoch"] = last_epoch
            record["last_seen"] = local_now(last_epoch)
            for key in (
                "event_time",
                "event_time_epoch",
                "ambient_date",
                "ambient_date_epoch",
                "battery",
                "weather_summary",
            ):
                if day.get(key) not in (None, "", []):
                    record[key] = day.get(key)
        if first_epoch is not None and first_epoch < record.get(
            "first_seen_epoch", first_epoch
        ):
            record["first_seen_epoch"] = first_epoch
            record["first_seen"] = local_now(first_epoch)

    def update_pws_weighted_average(self, record, prefix, day):
        """Fold a daily average into a longer weighted average."""
        value = day.get("{}_avg_f".format(prefix))
        output_key = "{}_avg_f".format(prefix)
        if prefix == "humidity":
            value = day.get("humidity_avg_percent")
            output_key = "humidity_avg_percent"
        elif prefix == "pressure_rel":
            return
        try:
            number = float(value)
            weight = max(1, int(day.get("sample_count") or 1))
        except (TypeError, ValueError):
            return
        sum_key = "_{}_weighted_sum".format(prefix)
        count_key = "_{}_weighted_count".format(prefix)
        record[sum_key] = float(record.get(sum_key) or 0) + number * weight
        record[count_key] = int(record.get(count_key) or 0) + weight
        record[output_key] = round(record[sum_key] / record[count_key], 2)

    def update_pws_first_latest_from_day(
        self, record, prefix, day, output_key, digits=1
    ):
        """Fold daily first/latest values into a longer period change field."""
        first_key = "_{}_first".format(prefix)
        latest_key = "_{}_latest".format(prefix)
        first_epoch_key = "_{}_first_epoch".format(prefix)
        latest_epoch_key = "_{}_latest_epoch".format(prefix)
        day_first = day.get(first_key)
        day_latest = day.get(latest_key)
        day_first_epoch = day.get(first_epoch_key)
        day_latest_epoch = day.get(latest_epoch_key)
        if day_first is None or day_latest is None:
            return
        if record.get(first_epoch_key) is None or day_first_epoch < record.get(
            first_epoch_key
        ):
            record[first_epoch_key] = day_first_epoch
            record[first_key] = day_first
        if record.get(latest_epoch_key) is None or day_latest_epoch >= record.get(
            latest_epoch_key
        ):
            record[latest_epoch_key] = day_latest_epoch
            record[latest_key] = day_latest
        record[output_key] = round(
            float(record[latest_key]) - float(record[first_key]), digits
        )

    def update_pws_weather_summary(self, record, data, epoch):
        """Fold one PWS sample into its station summary."""
        record["observation_count"] = int(record.get("observation_count") or 0) + 1
        record["update_count"] = int(record.get("update_count") or 0) + 1
        if epoch < record.get("first_seen_epoch", epoch):
            record["first_seen_epoch"] = epoch
            record["first_seen"] = local_now(epoch)
        if epoch >= record.get("last_seen_epoch", 0):
            previous_rain = record.get("latest_rain_1h_in")
            rain = data.get("rain_1h_in")
            record["last_seen_epoch"] = epoch
            record["last_seen"] = local_now(epoch)
            for key in (
                "station_id",
                "station_name",
                "mac_address",
                "model",
                "latitude",
                "longitude",
                "location_name",
                "elevation_m",
                "elevation_ft",
                "event_time",
                "event_time_epoch",
                "ambient_date",
                "timezone",
                "temperature_f",
                "humidity_percent",
                "dewpoint_f",
                "feels_like_f",
                "indoor_temperature_f",
                "indoor_humidity_percent",
                "indoor_dewpoint_f",
                "indoor_feels_like_f",
                "wind_direction_deg",
                "wind_direction_avg_10m_deg",
                "wind_speed_mph",
                "wind_speed_avg_10m_mph",
                "wind_gust_mph",
                "max_daily_gust_mph",
                "rain_1h_in",
                "rain_event_in",
                "rain_day_in",
                "rain_week_in",
                "rain_month_in",
                "rain_year_in",
                "rain_total_in",
                "last_rain_time",
                "last_rain_epoch",
                "pressure_rel_inhg",
                "pressure_abs_inhg",
                "solar_w_m2",
                "uv_index",
                "weather_summary",
                "source",
                "source_url",
            ):
                if data.get(key) not in (None, "", []):
                    record[key] = data.get(key)
            if data.get("battery"):
                self.sample_direct_value(
                    record, "sample_battery", data.get("battery"), 8
                )
            record["latest_rain_1h_in"] = rain
            self.update_pws_rain_transition(record, previous_rain, rain, epoch)
        if (
            record.get("first_temperature_f") is None
            and data.get("temperature_f") is not None
        ):
            record["first_temperature_f"] = data.get("temperature_f")
        self.update_min_max_numeric(
            record, "temperature_min_f", "temperature_max_f", data.get("temperature_f")
        )
        if (
            record.get("temperature_f") is not None
            and record.get("first_temperature_f") is not None
        ):
            try:
                record["temperature_change_f"] = round(
                    float(record.get("temperature_f"))
                    - float(record.get("first_temperature_f")),
                    1,
                )
            except (TypeError, ValueError):
                pass
        self.update_max_numeric(record, "rain_1h_max_in", data.get("rain_1h_in"))
        self.update_max_numeric(
            record, "wind_speed_max_mph", data.get("wind_speed_mph")
        )
        self.update_max_numeric(record, "wind_gust_max_mph", data.get("wind_gust_mph"))

    def update_pws_rain_transition(self, record, previous_rain, rain, epoch):
        """Track simple PWS rain start/stop transitions."""
        try:
            previous = float(previous_rain) if previous_rain is not None else None
            current = float(rain) if rain is not None else None
        except (TypeError, ValueError):
            return
        if current is None:
            return
        record["rain_active"] = current > 0
        if previous is None:
            if current > 0:
                record["rain_started"] = True
                record["rain_started_at"] = local_now(epoch)
                record["rain_started_epoch"] = epoch
                record["rain_episode_started_at"] = local_now(epoch)
                record["rain_episode_started_epoch"] = epoch
                record.pop("rain_stopped", None)
                record.pop("rain_stopped_at", None)
                record.pop("rain_stopped_epoch", None)
                record.pop("rain_episode_stopped_at", None)
                record.pop("rain_episode_stopped_epoch", None)
                record["rain_last_transition"] = "started"
                record["rain_last_transition_at"] = local_now(epoch)
                record["rain_last_transition_epoch"] = epoch
            return
        if previous <= 0 < current:
            record["rain_started"] = True
            record["rain_started_at"] = local_now(epoch)
            record["rain_started_epoch"] = epoch
            record["rain_episode_started_at"] = local_now(epoch)
            record["rain_episode_started_epoch"] = epoch
            record.pop("rain_stopped", None)
            record.pop("rain_stopped_at", None)
            record.pop("rain_stopped_epoch", None)
            record.pop("rain_episode_stopped_at", None)
            record.pop("rain_episode_stopped_epoch", None)
            record["rain_last_transition"] = "started"
            record["rain_last_transition_at"] = local_now(epoch)
            record["rain_last_transition_epoch"] = epoch
        elif previous > 0 and current <= 0:
            record["rain_stopped"] = True
            record["rain_stopped_at"] = local_now(epoch)
            record["rain_stopped_epoch"] = epoch
            record["rain_episode_stopped_at"] = local_now(epoch)
            record["rain_episode_stopped_epoch"] = epoch
            record.pop("rain_started", None)
            record.pop("rain_started_at", None)
            record.pop("rain_started_epoch", None)
            record["rain_last_transition"] = "stopped"
            record["rain_last_transition_at"] = local_now(epoch)
            record["rain_last_transition_epoch"] = epoch

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
                "identify_result",
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
                    "collector_state": (
                        "OFFLINE" if event_type == "collector_offline" else "RETRYING"
                    ),
                    "reason": data.get("reason") or "",
                    "last_seen": local_now(epoch),
                    "last_seen_epoch": epoch,
                }
                latest_health_epoch = epoch
                continue
            if event_type.startswith("lan_gateway"):
                key = (
                    data.get("subject_key")
                    or ("mac:{}".format(data.get("mac")) if data.get("mac") else "")
                    or (
                        "ip:{}".format(data.get("gateway_ip"))
                        if data.get("gateway_ip")
                        else ""
                    )
                    or "{}:{}".format(
                        data.get("family") or "", data.get("interface") or ""
                    )
                )
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
            key = (
                data.get("subject_key")
                or data.get("mac")
                or data.get("ip")
                or "unknown"
            )
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
                    "services": [],
                    "locations": [],
                    "servers": [],
                    "messages": [],
                    "open_ports": [],
                    "service_banners": [],
                    "http_urls": [],
                    "http_titles": [],
                    "http_headers": [],
                    "http_scripts": [],
                    "http_hints": [],
                    "identify_errors": [],
                    "identify_count": 0,
                },
            )
            if event_type == "identify_result":
                self.update_lan_identify_summary(record, data, epoch)
            else:
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
        if latest_health:
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
        for key in (
            "ips",
            "hostnames",
            "interfaces",
            "states",
            "sources",
            "mac_aliases",
            "gateways",
            "services",
            "locations",
            "servers",
            "messages",
        ):
            for value in data.get(key) or []:
                self.sample_direct_value(record, key, value, 16)

    def update_lan_identify_summary(self, record, data, epoch):
        """Fold one on-demand LAN Identify result into a LAN device summary."""
        record["identify_count"] = int(record.get("identify_count") or 0) + 1
        if epoch < record.get("first_seen_epoch", epoch):
            record["first_seen_epoch"] = epoch
            record["first_seen"] = local_now(epoch)
        if epoch >= record.get("last_seen_epoch", 0):
            record["last_seen_epoch"] = epoch
            record["last_seen"] = local_now(epoch)
        record["last_identified_epoch"] = epoch
        record["last_identified"] = local_now(epoch)
        for key in ("mac", "ip"):
            if data.get(key) and not record.get(key):
                record[key] = data.get(key)
        self.sample_direct_value(
            record, "ips", data.get("ip") or data.get("target"), 16
        )
        self.sample_direct_value(record, "sources", "lan-identify", 16)
        for key in (
            "open_ports",
            "service_banners",
            "http_urls",
            "http_titles",
            "http_headers",
            "http_scripts",
            "http_hints",
            "identify_errors",
        ):
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
            for key in ("gateway_ips", "interfaces", "families", "sources"):
                for value in data.get(key) or []:
                    self.sample_direct_value(record, key, value, 16)

    def sample_direct_value(self, record, key, value, limit=8):
        """Append one distinct direct-collector sample value."""
        if value in (None, "", []):
            return
        text = str(value).strip()
        if not text:
            return
        record.setdefault(key, [])
        if text not in record[key]:
            record[key].append(text)
            del record[key][:-limit]

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

    def update_max_numeric(self, record, key, value):
        """Update a max numeric field when a collector reports a number."""
        try:
            number = float(value)
        except (TypeError, ValueError):
            return
        old = record.get(key)
        record[key] = number if old is None else max(float(old), number)

    def update_min_max_numeric(self, record, min_key, max_key, value):
        """Update min/max numeric fields when a collector reports a number."""
        try:
            number = float(value)
        except (TypeError, ValueError):
            return
        old_min = record.get(min_key)
        old_max = record.get(max_key)
        record[min_key] = number if old_min is None else min(float(old_min), number)
        record[max_key] = number if old_max is None else max(float(old_max), number)

    def safe_float(self, value):
        """Return a float for numeric values, otherwise None."""
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def build_subject_records(self, summary):
        """Return normalized subject rows for every collector family."""
        subjects = []
        wifi = (summary or {}).get("wifi") or {}
        self.add_wifi_subjects(subjects, wifi)
        bluetooth = (summary or {}).get("bluetooth") or (summary or {}).get("ble") or {}
        self.add_bluetooth_subjects(subjects, bluetooth)
        self.add_aprsis_subjects(subjects, (summary or {}).get("aprsis") or [])
        self.add_rayhunter_subjects(subjects, (summary or {}).get("rayhunter") or [])
        self.add_rtl433_subjects(subjects, (summary or {}).get("rtl433") or [])
        self.add_adsb_subjects(subjects, (summary or {}).get("adsb") or [])
        self.add_noaa_subjects(subjects, (summary or {}).get("noaa") or [])
        self.add_usgs_subjects(subjects, (summary or {}).get("usgs") or [])
        self.add_swpc_subjects(subjects, (summary or {}).get("swpc") or [])
        self.add_pws_subjects(subjects, (summary or {}).get("pws") or [])
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

    def grouped_subject_time_source(self, records):
        """Return first/last fields spanning a grouped low-identity subject."""
        first = min(
            records,
            key=lambda item: record_time_epoch(item, "first_seen") or float("inf"),
            default={},
        )
        last = max(
            records,
            key=lambda item: record_time_epoch(item, "last_seen") or 0,
            default={},
        )
        return {
            "first_seen": first.get("first_seen"),
            "first_seen_epoch": record_time_epoch(first, "first_seen"),
            "last_seen": last.get("last_seen"),
            "last_seen_epoch": record_time_epoch(last, "last_seen"),
        }

    def grouped_sample_macs(self, records, limit=12):
        """Return a bounded MAC sample from aggregate or individual records."""
        sample = []
        for record in records or []:
            values = record.get("sample_macs") or [record.get("mac")]
            if not isinstance(values, list):
                values = [values]
            for mac in values:
                if mac and mac not in sample:
                    sample.append(mac)
                if len(sample) >= limit:
                    return sample
        return sample

    def grouped_member_summaries(self, records, source, limit=24):
        """Return bounded per-member evidence for grouped privacy subjects."""
        members = []
        for record in records or []:
            source_members = record.get("group_members")
            candidates = (
                source_members
                if isinstance(source_members, list) and source_members
                else [self.group_member_summary(record, source)]
            )
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                member = {
                    key: value
                    for key, value in candidate.items()
                    if value not in (None, "", [], {})
                }
                mac = str(member.get("mac") or "").strip().lower()
                if not mac or any(
                    str(item.get("mac") or "").lower() == mac for item in members
                ):
                    continue
                members.append(member)
                if len(members) >= limit:
                    return members
        return members

    def group_member_summary(self, record, source):
        """Return one compact member summary from an individual grouped record."""
        member = {
            "mac": record.get("mac") or "",
            "first_seen": record.get("first_seen") or "",
            "first_seen_epoch": record.get("first_seen_epoch"),
            "last_seen": record.get("last_seen") or "",
            "last_seen_epoch": record.get("last_seen_epoch"),
            "signal_min": record.get("signal_min"),
            "signal_max": record.get("signal_max"),
        }
        if source == "wifi":
            member.update(
                {
                    "identity": record.get("vendor_name")
                    or record.get("vendor_prefix")
                    or "",
                    "ssids": (record.get("ssids") or [])[:8],
                    "probe_count": record.get("probe_count") or 0,
                    "association_count": record.get("association_count") or 0,
                    "deauth_count": record.get("deauth_count") or 0,
                    "disassoc_count": record.get("disassoc_count") or 0,
                }
            )
        elif source == "bluetooth":
            names = list(
                record.get("names")
                or ([record.get("name")] if record.get("name") else [])
            )
            member.update(
                {
                    "identity": (
                        names[0]
                        if names
                        else (
                            record.get("manufacturer")
                            or record.get("manufacturer_name")
                            or ""
                        )
                    ),
                    "names": names[:6],
                    "service_uuids": (record.get("service_uuids") or [])[:8],
                    "seen_count": record.get("seen_count") or 0,
                    "update_count": record.get("update_count") or 0,
                    "lost_count": record.get("lost_count") or 0,
                    "classic_seen_count": record.get("classic_seen_count") or 0,
                    "session_count": record.get("session_count") or 0,
                    "active_session": bool(record.get("active_session")),
                }
            )
        elif source == "lan":
            member.update(
                {
                    "identity": record.get("hostname")
                    or record.get("vendor_name")
                    or record.get("vendor_prefix")
                    or "",
                    "ips": (
                        record.get("ips")
                        or ([record.get("ip")] if record.get("ip") else [])
                    )[:8],
                    "sources": (record.get("sources") or [])[:8],
                    "interfaces": (
                        record.get("interfaces")
                        or (
                            [record.get("interface")] if record.get("interface") else []
                        )
                    )[:8],
                    "observation_count": record.get("observation_count") or 0,
                    "identify_count": record.get("identify_count") or 0,
                    "change_count": record.get("change_count") or 0,
                }
            )
        return member

    def grouped_record_count(self, records):
        """Return represented identity count for grouped/individual records."""
        total = 0
        for record in records or []:
            try:
                total += max(
                    1,
                    int(
                        record.get("randomized_group_count")
                        or record.get("device_count")
                        or 1
                    ),
                )
            except (TypeError, ValueError):
                total += 1
        return total

    def grouped_list_values(self, records, key, limit=32):
        """Merge list/scalar evidence from grouped records."""
        values = []
        for record in records or []:
            source = record.get(key)
            if not isinstance(source, list):
                source = [source]
            for value in source:
                if value in (None, "", [], {}):
                    continue
                if value not in values:
                    values.append(value)
                if len(values) >= limit:
                    return values
        return values

    def grouped_sum(self, records, *keys):
        """Return the sum of integer counters across grouped records."""
        total = 0
        for record in records or []:
            for key in keys:
                total += int(record.get(key) or 0)
        return total

    def grouped_signal_value(self, records, key, reducer):
        """Return a grouped signal min/max value."""
        values = [
            record.get(key)
            for record in records or []
            if isinstance(record.get(key), (int, float))
        ]
        return reducer(values) if values else None

    def add_wifi_subjects(self, subjects, wifi):
        """Add SSID, BSSID, and client MAC subjects."""
        aps = [
            item
            for item in (wifi or {}).get("access_points") or []
            if isinstance(item, dict)
        ]
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
                        "vendor_name": ap.get("vendor_name") or "",
                        "vendor_prefix": ap.get("vendor_prefix") or "",
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
                        "observations": sum(
                            int(ap.get("observations") or 0) for ap in ssid_aps
                        ),
                    },
                )
            )
        randomized_clients = [
            client for client in clients if low_identity_wifi_client(client)
        ]
        if randomized_clients:
            subjects.append(
                self.subject_record(
                    "wifi",
                    "wifi_client_group",
                    "randomized:wifi_clients",
                    "{} found".format(wifi_client_group_label()),
                    self.grouped_subject_time_source(randomized_clients),
                    {
                        "grouped_randomized": True,
                        "randomized_group_count": self.grouped_record_count(
                            randomized_clients
                        ),
                        "sample_macs": self.grouped_sample_macs(randomized_clients),
                        "group_members": self.grouped_member_summaries(
                            randomized_clients, "wifi"
                        ),
                        "ssids": self.grouped_list_values(
                            randomized_clients, "ssids", 50
                        ),
                        "probe_count": self.grouped_sum(
                            randomized_clients, "probe_count"
                        ),
                        "association_count": self.grouped_sum(
                            randomized_clients, "association_count"
                        ),
                        "deauth_count": self.grouped_sum(
                            randomized_clients, "deauth_count"
                        ),
                        "disassoc_count": self.grouped_sum(
                            randomized_clients, "disassoc_count"
                        ),
                        "signal_min": self.grouped_signal_value(
                            randomized_clients, "signal_min", min
                        ),
                        "signal_max": self.grouped_signal_value(
                            randomized_clients, "signal_max", max
                        ),
                        "blank_ssid_count": sum(
                            1 for c in randomized_clients if not c.get("ssids")
                        ),
                    },
                )
            )
        for client in clients:
            if low_identity_wifi_client(client):
                continue
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
                        "vendor_name": client.get("vendor_name") or "",
                        "vendor_prefix": client.get("vendor_prefix") or "",
                        "ssids": list(client.get("ssids") or [])[:20],
                    },
                )
            )

    def add_bluetooth_subjects(self, subjects, bluetooth):
        """Add Bluetooth identity subjects keyed by MAC.

        Grouping is decided by WiFiBLEPostprocessor.compact_bluetooth_devices_for_storage.
        This method only maps the postprocessor output to Subject History records.
        """
        for device in (bluetooth or {}).get("devices") or []:
            if not isinstance(device, dict):
                continue
            if device.get("grouped_randomized"):
                # ── Group record ────────────────────────────────────
                bucket = bluetooth_identity_bucket(device)
                label = bluetooth_group_label(device)
                subject_id = device.get("mac") or "randomized:{}:{}".format(
                    bucket[0], bucket[1].lower()
                )
                subjects.append(
                    self.subject_record(
                        "bluetooth",
                        "bluetooth_device_group",
                        subject_id,
                        "{} found".format(label),
                        self.grouped_subject_time_source([device]),
                        {
                            "grouped_randomized": True,
                            "randomized_group_count": self.grouped_record_count(
                                [device]
                            ),
                            "identity_bucket": bucket[0],
                            "identity_label": bucket[1],
                            "sample_macs": self.grouped_sample_macs([device]),
                            "group_members": self.grouped_member_summaries(
                                [device], "bluetooth"
                            ),
                            "service_uuids": self.grouped_list_values(
                                [device], "service_uuids", 32
                            ),
                            "seen_count": self.grouped_sum([device], "seen_count"),
                            "update_count": self.grouped_sum([device], "update_count"),
                            "lost_count": self.grouped_sum([device], "lost_count"),
                            "session_count": self.grouped_sum(
                                [device], "session_count"
                            ),
                            "signal_min": self.grouped_signal_value(
                                [device], "signal_min", min
                            ),
                            "signal_max": self.grouped_signal_value(
                                [device], "signal_max", max
                            ),
                        },
                    )
                )
            else:
                # ── Individual device ──────────────────────────────
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
            event_type = (event or {}).get("type") or ""
            if event_type == "aprsis_weather_period_summary":
                continue
            if event_type == "aprsis_collector_summary":
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
                        "rain_episode_started_at": data.get("rain_episode_started_at")
                        or "",
                        "rain_episode_started_epoch": data.get(
                            "rain_episode_started_epoch"
                        ),
                        "rain_episode_stopped_at": data.get("rain_episode_stopped_at")
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
                        "position_samples": data.get("position_samples") or [],
                        "packet_samples": data.get("packet_samples") or [],
                        "first_position_at": data.get("first_position_at") or "",
                        "first_position_epoch": data.get("first_position_epoch"),
                        "last_position_at": data.get("last_position_at") or "",
                        "last_position_epoch": data.get("last_position_epoch"),
                        "trip_rollup": data.get("trip_rollup") or "",
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
                        "warning_events_in_window": data.get("warning_events_in_window")
                        or 0,
                        "latest_event": data.get("latest_event") or "",
                        "rayhunter_version": data.get("rayhunter_version") or "",
                        "storage": data.get("storage") or "",
                        "memory": data.get("memory") or "",
                        "battery": data.get("battery") or "",
                        "recording_id": data.get("recording_id") or "",
                        "recording_size": data.get("recording_size") or "",
                        "recording_start": data.get("recording_start") or "",
                        "recording_last_message": data.get("recording_last_message")
                        or "",
                        "device_os": data.get("device_os") or "",
                        "gps_mode": data.get("gps_mode") or "",
                        "reason": data.get("reason") or data.get("warning") or "",
                    },
                )
            )

    def add_rtl433_subjects(self, subjects, events):
        """Add rtl_433 decoded device subjects."""
        for event in events:
            data = clean_rtl433_data((event or {}).get("data") or {})
            if (event or {}).get("type") == "rtl433_collector_summary":
                subject_id = "rtl433"
                subject = "RTL-433 collector"
                subject_type = "rtl433_collector"
            else:
                subject_id = data.get("subject_key") or data.get("model") or "unknown"
                label = " ".join(
                    part
                    for part in (
                        data.get("model") or "",
                        data.get("id") or "",
                        data.get("channel") or "",
                    )
                    if part not in (None, "")
                ).strip()
                subject = label or subject_id
                subject_type = "rtl433_device"
            subjects.append(
                self.subject_record(
                    "rtl433",
                    subject_type,
                    str(subject_id),
                    subject,
                    {
                        "first_seen": data.get("first_seen") or event.get("timestamp"),
                        "first_seen_epoch": data.get("first_seen_epoch")
                        or event.get("timestamp_epoch"),
                        "last_seen": data.get("last_seen") or event.get("timestamp"),
                        "last_seen_epoch": data.get("last_seen_epoch")
                        or event.get("timestamp_epoch"),
                    },
                    data,
                )
            )

    def add_adsb_subjects(self, subjects, events):
        """Add ADS-B aircraft subjects."""
        for event in events:
            data = clean_adsb_data((event or {}).get("data") or {})
            if (event or {}).get("type") == "adsb_collector_summary":
                subject_id = "adsb"
                subject = "ADS-B collector"
                subject_type = "adsb_collector"
            else:
                subject_id = data.get("icao") or "unknown"
                subject = "{} {}".format(data.get("callsign") or "", subject_id).strip()
                subject_type = "adsb_aircraft"
            subjects.append(
                self.subject_record(
                    "adsb",
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
                    data,
                )
            )

    def add_noaa_subjects(self, subjects, events):
        """Add NOAA alert/advisory subjects."""
        for event in events:
            data = clean_noaa_data((event or {}).get("data") or {})
            event_type = (event or {}).get("type") or ""
            if event_type == "noaa_period_summary":
                continue
            subject_id = stable_noaa_event_key(data, event_type)
            subject = data.get("event") or data.get("headline") or subject_id
            if event_type == "noaa_collector_summary":
                subject_type = "noaa_collector"
                subject = "NOAA collector"
            elif data.get("alert_kind") == "forecast":
                subject_type = "noaa_forecast"
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
                        "cap_url": data.get("cap_url") or "",
                        "json_url": data.get("json_url") or "",
                        "tsunami_identifier": data.get("tsunami_identifier") or "",
                        "incident_id": data.get("incident_id") or "",
                        "tsunami_category": data.get("tsunami_category") or "",
                        "message_number": data.get("message_number") or "",
                        "event_time": data.get("event_time") or "",
                        "event_time_epoch": data.get("event_time_epoch"),
                        "magnitude": data.get("magnitude"),
                        "magnitude_type": data.get("magnitude_type") or "",
                        "depth_km": data.get("depth_km"),
                        "product_code": data.get("product_code") or "",
                        "resource_urls": data.get("resource_urls") or [],
                        "map_urls": data.get("map_urls") or [],
                        "basin": data.get("basin") or "",
                        "nhc_system": data.get("nhc_system") or "",
                        "nhc_storm_id": data.get("nhc_storm_id") or "",
                        "nhc_advisory_number": data.get("nhc_advisory_number") or "",
                        "nhc_package_key": data.get("nhc_package_key") or "",
                        "nhc_product_count": data.get("nhc_product_count"),
                        "nhc_product_types": data.get("nhc_product_types") or [],
                        "nhc_product_titles": data.get("nhc_product_titles") or [],
                        "nhc_product_urls": data.get("nhc_product_urls") or [],
                        "nhc_products": data.get("nhc_products") or [],
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "forecast_generated": data.get("forecast_generated") or "",
                        "forecast_generated_epoch": data.get(
                            "forecast_generated_epoch"
                        ),
                        "forecast_window_hours": data.get("forecast_window_hours"),
                        "forecast_soon_hours": data.get("forecast_soon_hours"),
                        "forecast_hour_count": data.get("forecast_hour_count"),
                        "current_forecast": data.get("current_forecast") or "",
                        "current_temperature_f": data.get("current_temperature_f"),
                        "current_precip_probability": data.get(
                            "current_precip_probability"
                        ),
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
                        "forecast_delta_findings": data.get("forecast_delta_findings")
                        or [],
                        "forecast_delta_summary": data.get("forecast_delta_summary")
                        or "",
                        "forecast_change_direction": data.get(
                            "forecast_change_direction"
                        )
                        or "",
                        "previous_forecast_generated": data.get(
                            "previous_forecast_generated"
                        )
                        or "",
                        "previous_current_temperature_f": data.get(
                            "previous_current_temperature_f"
                        ),
                        "previous_temperature_min_f": data.get(
                            "previous_temperature_min_f"
                        ),
                        "previous_temperature_max_f": data.get(
                            "previous_temperature_max_f"
                        ),
                        "previous_max_precip_probability": data.get(
                            "previous_max_precip_probability"
                        ),
                        "previous_next_precip_probability": data.get(
                            "previous_next_precip_probability"
                        ),
                        "previous_max_wind_mph": data.get("previous_max_wind_mph"),
                        "current_temperature_delta_f": data.get(
                            "current_temperature_delta_f"
                        ),
                        "temperature_min_delta_f": data.get("temperature_min_delta_f"),
                        "temperature_max_delta_f": data.get("temperature_max_delta_f"),
                        "max_precip_probability_delta": data.get(
                            "max_precip_probability_delta"
                        ),
                        "next_precip_probability_delta": data.get(
                            "next_precip_probability_delta"
                        ),
                        "max_wind_delta_mph": data.get("max_wind_delta_mph"),
                        "first_period_start": data.get("first_period_start") or "",
                        "last_period_end": data.get("last_period_end") or "",
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
            if event_type == "usgs_earthquake_period_summary":
                continue
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
            if event_type == "swpc_event_period_summary":
                continue
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

    def add_pws_subjects(self, subjects, events):
        """Add PWS station subjects."""
        for event in events:
            data = clean_pws_data((event or {}).get("data") or {})
            event_type = (event or {}).get("type") or ""
            if event_type == "pws_collector_summary":
                subject_id = "pws"
                subject = "PWS collector"
                subject_type = "pws_collector"
            elif event_type == "pws_weather_period_summary":
                continue
            else:
                subject_id = (
                    data.get("station_id") or data.get("mac_address") or "unknown"
                )
                subject = (
                    data.get("station_id") or data.get("station_name") or subject_id
                )
                subject_type = "pws_weather_station"
            subjects.append(
                self.subject_record(
                    "pws",
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
                        "station_id": data.get("station_id") or "",
                        "station_name": data.get("station_name") or "",
                        "mac_address": data.get("mac_address") or "",
                        "model": data.get("model") or "",
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "location_name": data.get("location_name") or "",
                        "elevation_m": data.get("elevation_m"),
                        "elevation_ft": data.get("elevation_ft"),
                        "event_time": data.get("event_time") or "",
                        "event_time_epoch": data.get("event_time_epoch"),
                        "ambient_date": data.get("ambient_date") or "",
                        "timezone": data.get("timezone") or "",
                        "temperature_f": data.get("temperature_f"),
                        "humidity_percent": data.get("humidity_percent"),
                        "dewpoint_f": data.get("dewpoint_f"),
                        "feels_like_f": data.get("feels_like_f"),
                        "indoor_temperature_f": data.get("indoor_temperature_f"),
                        "indoor_humidity_percent": data.get("indoor_humidity_percent"),
                        "indoor_dewpoint_f": data.get("indoor_dewpoint_f"),
                        "indoor_feels_like_f": data.get("indoor_feels_like_f"),
                        "temperature_min_f": data.get("temperature_min_f"),
                        "temperature_max_f": data.get("temperature_max_f"),
                        "temperature_change_f": data.get("temperature_change_f"),
                        "wind_direction_deg": data.get("wind_direction_deg"),
                        "wind_direction_avg_10m_deg": data.get(
                            "wind_direction_avg_10m_deg"
                        ),
                        "wind_speed_mph": data.get("wind_speed_mph"),
                        "wind_speed_avg_10m_mph": data.get("wind_speed_avg_10m_mph"),
                        "wind_gust_mph": data.get("wind_gust_mph"),
                        "max_daily_gust_mph": data.get("max_daily_gust_mph"),
                        "wind_speed_max_mph": data.get("wind_speed_max_mph"),
                        "wind_gust_max_mph": data.get("wind_gust_max_mph"),
                        "rain_1h_in": data.get("rain_1h_in"),
                        "latest_rain_1h_in": data.get("latest_rain_1h_in"),
                        "rain_1h_max_in": data.get("rain_1h_max_in"),
                        "rain_event_in": data.get("rain_event_in"),
                        "rain_day_in": data.get("rain_day_in"),
                        "rain_week_in": data.get("rain_week_in"),
                        "rain_month_in": data.get("rain_month_in"),
                        "rain_year_in": data.get("rain_year_in"),
                        "rain_total_in": data.get("rain_total_in"),
                        "last_rain_time": data.get("last_rain_time") or "",
                        "last_rain_epoch": data.get("last_rain_epoch"),
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
                        "rain_episode_started_at": data.get("rain_episode_started_at")
                        or "",
                        "rain_episode_started_epoch": data.get(
                            "rain_episode_started_epoch"
                        ),
                        "rain_episode_stopped_at": data.get("rain_episode_stopped_at")
                        or "",
                        "rain_episode_stopped_epoch": data.get(
                            "rain_episode_stopped_epoch"
                        ),
                        "pressure_rel_inhg": data.get("pressure_rel_inhg"),
                        "pressure_abs_inhg": data.get("pressure_abs_inhg"),
                        "solar_w_m2": data.get("solar_w_m2"),
                        "uv_index": data.get("uv_index"),
                        "battery": data.get("battery") or "",
                        "sample_battery": data.get("sample_battery") or [],
                        "weather_summary": data.get("weather_summary") or "",
                        "source": data.get("source") or "",
                        "source_url": data.get("source_url") or "",
                        "observation_count": data.get("observation_count") or 0,
                        "update_count": data.get("update_count") or 0,
                        "reason": data.get("reason") or "",
                    },
                )
            )

    def add_lan_subjects(self, subjects, events):
        """Add LAN device and gateway subjects."""
        grouped_lan = []
        for event in events:
            raw_data = (event or {}).get("data") or {}
            data = clean_lan_data(raw_data)
            self.preserve_subject_annotation_overlay(data, raw_data, event)
            event_type = (event or {}).get("type") or ""
            if event_type in (
                "lan_device_summary",
                "lan_device_seen",
                "lan_device_changed",
            ) and low_identity_lan_record(data):
                grouped = dict(data)
                grouped.setdefault(
                    "first_seen", data.get("first_seen") or event.get("timestamp")
                )
                grouped.setdefault(
                    "first_seen_epoch",
                    data.get("first_seen_epoch") or event.get("timestamp_epoch"),
                )
                grouped.setdefault(
                    "last_seen", data.get("last_seen") or event.get("timestamp")
                )
                grouped.setdefault(
                    "last_seen_epoch",
                    data.get("last_seen_epoch") or event.get("timestamp_epoch"),
                )
                grouped_lan.append(grouped)
                continue
            if event_type == "lan_collector_summary":
                subject_id = "lan"
                subject = "LAN collector"
                subject_type = "lan_collector"
            elif event_type == "lan_gateway_summary":
                subject_id = (
                    data.get("subject_key") or data.get("gateway_ip") or "gateway"
                )
                subject = "Gateway {}".format(
                    data.get("mac")
                    or data.get("gateway_ip")
                    or ", ".join(data.get("gateway_ips") or [])
                    or subject_id
                )
                subject_type = "lan_gateway"
            else:
                subject_id = (
                    data.get("subject_key")
                    or data.get("mac")
                    or data.get("ip")
                    or "unknown"
                )
                label = (
                    data.get("hostname")
                    or data.get("mac")
                    or data.get("ip")
                    or subject_id
                )
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
                        "services": data.get("services") or [],
                        "locations": data.get("locations") or [],
                        "servers": data.get("servers") or [],
                        "messages": data.get("messages") or [],
                        "open_ports": data.get("open_ports") or [],
                        "service_banners": data.get("service_banners") or [],
                        "http_urls": data.get("http_urls") or [],
                        "http_titles": data.get("http_titles") or [],
                        "http_headers": data.get("http_headers") or [],
                        "http_scripts": data.get("http_scripts") or [],
                        "http_hints": data.get("http_hints") or [],
                        "identify_errors": data.get("identify_errors") or [],
                        "vendor_oui": data.get("vendor_oui") or "",
                        "vendor_prefix": data.get("vendor_prefix") or "",
                        "vendor_name": data.get("vendor_name") or "",
                        "gateway": bool(data.get("gateway")),
                        "gateways": data.get("gateways") or [],
                        "gateway_ip": data.get("gateway_ip") or "",
                        "gateway_ips": data.get("gateway_ips") or [],
                        "family": data.get("family") or "",
                        "families": data.get("families") or [],
                        "observation_count": data.get("observation_count") or 0,
                        "identify_count": data.get("identify_count") or 0,
                        "change_count": data.get("change_count") or 0,
                        "change_type": data.get("change_type") or "",
                        "last_identified": data.get("last_identified") or "",
                        "last_identified_epoch": data.get("last_identified_epoch"),
                        "reason": data.get("reason") or "",
                        "annotation": data.get("annotation") or {},
                        "custom_name": data.get("custom_name") or "",
                    },
                )
            )
        if grouped_lan:
            subjects.append(
                self.subject_record(
                    "lan",
                    "lan_device_group",
                    "randomized:lan_private_macs",
                    "{} found".format(lan_group_label()),
                    self.grouped_subject_time_source(grouped_lan),
                    {
                        "grouped_randomized": True,
                        "randomized_group_count": len(grouped_lan),
                        "sample_macs": self.grouped_sample_macs(grouped_lan),
                        "group_members": self.grouped_member_summaries(
                            grouped_lan, "lan"
                        ),
                        "ips": self.grouped_list_values(grouped_lan, "ips", 32),
                        "sources": self.grouped_list_values(grouped_lan, "sources", 16),
                        "interfaces": self.grouped_list_values(
                            grouped_lan, "interfaces", 16
                        ),
                        "observation_count": self.grouped_sum(
                            grouped_lan, "observation_count"
                        ),
                        "identify_count": self.grouped_sum(
                            grouped_lan, "identify_count"
                        ),
                        "change_count": self.grouped_sum(grouped_lan, "change_count"),
                    },
                )
            )

    def preserve_subject_annotation_overlay(self, data, *sources):
        """Carry user annotation overlay fields through collector data cleaners."""
        if not isinstance(data, dict):
            return
        for source in sources:
            if not isinstance(source, dict):
                continue
            annotation = source.get("annotation")
            if isinstance(annotation, dict) and annotation.get("custom_name"):
                data["annotation"] = copy.deepcopy(annotation)
                data["custom_name"] = annotation.get("custom_name")
                return
            custom_name = source.get("custom_name")
            if custom_name:
                data["custom_name"] = str(custom_name)
                data["annotation"] = {"custom_name": str(custom_name)}
                return

    def subject_record(
        self, collector, subject_type, subject_id, subject, time_source, data
    ):
        """Return one normalized subject-history row."""
        clean_data = {
            key: value
            for key, value in (data or {}).items()
            if value not in (None, "", [], {})
        }
        record = {
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
            "data": clean_data,
        }
        annotation = clean_data.get("annotation") or (time_source or {}).get(
            "annotation"
        )
        custom_name = clean_data.get("custom_name") or (time_source or {}).get(
            "custom_name"
        )
        if isinstance(annotation, dict) and annotation.get("custom_name"):
            record["annotation"] = annotation
            record["custom_name"] = annotation.get("custom_name")
        elif custom_name:
            record["annotation"] = {"custom_name": custom_name}
            record["custom_name"] = custom_name
        return record

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
