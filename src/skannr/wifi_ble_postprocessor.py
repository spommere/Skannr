"""Wi-Fi/BLE observation post-processor for Subject History.

Raw logs are the audit trail, but the dashboard should not reread hundreds of
thousands of raw rows on every startup or Refresh click. This post-processor
folds raw Wi-Fi/BLE events into compact summaries and then advances those
summaries from saved byte offsets on later refreshes.
"""

import copy
import json
import os
from collections import defaultdict

from .bus import local_now
from .log_utils import (
    count_jsonl_files,
    current_jsonl_checkpoint,
    event_time_epoch,
    event_in_window,
    format_epoch,
    has_jsonl_checkpoint,
    now_epoch,
    record_time_epoch,
    read_incremental_jsonl_events,
    read_jsonl_events,
    save_json_atomic,
    timestamp_epoch,
    window_metadata,
)
from .identity_policy import (
    bluetooth_group_label,
    bluetooth_grouping_candidate,
    bluetooth_identity_bucket,
    bluetooth_manufacturer_label,
    bluetooth_property_like_name,
    low_identity_bluetooth_record,
    low_identity_wifi_client,
    numeric_epoch,
)
from .oui_lookup import normalize_oui, vendor_info, vendor_name, vendor_prefix


class WiFiBLEPostprocessor:
    """Build a windowed device-history view and maintain durable first_seen data."""

    COLLECTORS = ("wifi", "wifi_monitor", "ble", "ble_identify", "bt_classic")
    WIFI_AP_SESSION_GAP_SEC = 300
    # Drop AP sessions older than this (default 7 days).  At least
    # MIN_AP_SESSIONS are kept per AP so short histories survive.
    WIFI_AP_MAX_SESSION_AGE_SEC = 604800
    WIFI_AP_MIN_SESSIONS = 24
    BLE_STALE_SINGLE_SEEN_PRUNE_SEC = 3600
    # Second-tier: low-count anonymous devices inactive longer than this
    # are also noise — they never reached the grouping threshold and
    # never will.  Default: ≤10 sightings, stale for 24 hours.
    BLE_LOW_COUNT_PRUNE_MAX_SEEN = 10
    BLE_LOW_COUNT_PRUNE_STALE_SEC = 86400
    GROUP_SAMPLE_MAC_LIMIT = 12
    GROUP_SAMPLE_VALUE_LIMIT = 50

    def __init__(
        self,
        log_dir,
        state_path=None,
        window_days=None,
        progress_callback=None,
        reference_epoch=None,
    ):
        self.log_dir = log_dir
        self.state_path = state_path or os.path.join(
            log_dir, "device_history", "device_history.json"
        )
        self.window_days = window_days
        self.progress_callback = progress_callback
        self.reference_epoch = reference_epoch  # for historical snapshots
        self._time_cache = {}

    def _now(self):
        """Return reference_epoch if set, else current wall-clock time."""
        return self.reference_epoch or now_epoch()

    def build(self, persist=True, merge_previous=True):
        """Return materialized Device History, updating it incrementally.

        Once a persisted summary exists, raw JSONL logs are no longer treated as
        the primary store. Refresh reads only bytes past the stored per-file
        offsets, folds those new events into the summary, and saves the updated
        materialized state. Older raw log content stays available for manual
        inspection but is not reread during normal startup/refresh.
        """
        summary = self.build_summary(merge_previous=merge_previous)
        if persist:
            self.save_summary(summary)
        return self.display_summary(summary, self.window_days)

    def build_summary(self, merge_previous=True):
        """Return the full materialized summary without persisting or filtering."""
        previous = self.load_persisted_summary() if merge_previous else None
        if previous and has_jsonl_checkpoint(previous):
            # Normal fast path: a modern summary already knows how far each
            # collector log file was processed, so only new bytes are scanned.
            if (
                not self.has_history_records(previous)
                and self.raw_history_files_exist()
            ):
                return self.full_build()
            return self.incremental_update(previous)
        if previous and self.has_history_records(previous):
            # Older Skannr builds wrote a useful summary before checkpoints
            # existed. Trust that materialized state and start tracking new log
            # bytes from the current EOF instead of rereading old logs.
            previous = copy.deepcopy(previous)
            previous["checkpoint"] = current_jsonl_checkpoint(
                self.log_dir, self.COLLECTORS
            )
            generated_at_epoch = now_epoch()
            previous["generated_at"] = local_now(generated_at_epoch)
            previous["generated_at_epoch"] = generated_at_epoch
            previous["cached"] = False
            previous["incremental_records_read"] = 0
            return previous
        return self.full_build()

    def full_build(self):
        """Parse current retained logs once to create the durable summary."""
        wifi_aps = {}
        wifi_clients = {}
        ble_devices = {}
        files_by_collector = {
            collector: count_jsonl_files(self.log_dir, collector)
            for collector in self.COLLECTORS
        }
        files_read = sum(files_by_collector.values())
        records_by_collector = defaultdict(int)
        records_read = 0

        # Wi-Fi scan and Wi-Fi monitor both produce AP beacons, but only monitor
        # mode produces clients/probes/deauth. apply_wifi_event() handles both
        # sources and records the source set on each device.
        if self.progress_callback:
            self.progress_callback("Wi-Fi Scan")
        for event in self.read_all_events("wifi"):
            records_read += 1
            records_by_collector["wifi"] += 1
            self.apply_wifi_event(event, wifi_aps, wifi_clients)

        if self.progress_callback:
            self.progress_callback("Wi-Fi Monitor")
        for event in self.read_all_events("wifi_monitor"):
            records_read += 1
            records_by_collector["wifi_monitor"] += 1
            self.apply_wifi_event(event, wifi_aps, wifi_clients)

        # BLE, BLE Identify, and Classic Bluetooth are merged into one
        # Bluetooth device history because a physical device may show up through
        # more than one Bluetooth capture method over time.
        if self.progress_callback:
            self.progress_callback("BLE")
        for event in self.read_all_events("ble"):
            records_read += 1
            records_by_collector["ble"] += 1
            self.apply_ble_event(event, ble_devices)

        if self.progress_callback:
            self.progress_callback("BLE Identify")
        for event in self.read_all_events("ble_identify"):
            records_read += 1
            records_by_collector["ble_identify"] += 1
            self.apply_ble_identify_event(event, ble_devices)

        if self.progress_callback:
            self.progress_callback("BT Classic")
        for event in self.read_all_events("bt_classic"):
            records_read += 1
            records_by_collector["bt_classic"] += 1
            self.apply_bt_classic_event(event, ble_devices)

        generated_at_epoch = now_epoch()
        summary = {
            "generated_at": local_now(generated_at_epoch),
            "generated_at_epoch": generated_at_epoch,
            "log_dir": self.log_dir,
            "state_path": self.state_path,
            "window": window_metadata(None),
            "files_read": files_read,
            "records_read": records_read,
            "raw_log_files": files_by_collector,
            "raw_records_read": dict(records_by_collector),
            "wifi": {
                "access_points": self.sorted_records(wifi_aps.values()),
                "clients": self.compact_wifi_clients_for_storage(
                    self.sorted_records(wifi_clients.values())
                ),
            },
            "ble": {
                "devices": self.compact_bluetooth_devices_for_storage(
                    self.sorted_records(ble_devices.values())
                ),
            },
            "bluetooth": {
                "devices": [],
            },
            "checkpoint": current_jsonl_checkpoint(self.log_dir, self.COLLECTORS),
        }
        summary["bluetooth"] = {"devices": summary["ble"]["devices"]}
        return summary

    def incremental_update(self, previous):
        """Fold only not-yet-processed JSONL bytes into a persisted summary."""
        summary = copy.deepcopy(previous)
        # Persisted JSON cannot store sets, but the event-folding code uses sets
        # for values that accumulate over time. Convert records back to the
        # mutable shape before applying incremental events.
        wifi_aps = self.record_map(
            ((summary.get("wifi") or {}).get("access_points") or []),
            "bssid",
            ["ssids", "channels", "encryption", "sources"],
        )
        wifi_clients = self.record_map(
            ((summary.get("wifi") or {}).get("clients") or []),
            "mac",
            ["ssids", "sources"],
        )
        ble_devices = self.record_map(
            (
                (summary.get("ble") or summary.get("bluetooth") or {}).get("devices")
                or []
            ),
            "mac",
            ["names", "service_uuids", "transports"],
        )
        records_by_collector = defaultdict(int)
        records_read = 0
        read_stats = {}
        checkpoint = summary.get("checkpoint") or current_jsonl_checkpoint(
            self.log_dir, ()
        )

        for event in read_incremental_jsonl_events(
            self.log_dir, "wifi", checkpoint, read_stats=read_stats
        ):
            records_read += 1
            records_by_collector["wifi"] += 1
            self.apply_wifi_event(event, wifi_aps, wifi_clients)
        for event in read_incremental_jsonl_events(
            self.log_dir, "wifi_monitor", checkpoint, read_stats=read_stats
        ):
            records_read += 1
            records_by_collector["wifi_monitor"] += 1
            self.apply_wifi_event(event, wifi_aps, wifi_clients)
        for event in read_incremental_jsonl_events(
            self.log_dir, "ble", checkpoint, read_stats=read_stats
        ):
            records_read += 1
            records_by_collector["ble"] += 1
            self.apply_ble_event(event, ble_devices)
        for event in read_incremental_jsonl_events(
            self.log_dir, "ble_identify", checkpoint, read_stats=read_stats
        ):
            records_read += 1
            records_by_collector["ble_identify"] += 1
            self.apply_ble_identify_event(event, ble_devices)
        for event in read_incremental_jsonl_events(
            self.log_dir, "bt_classic", checkpoint, read_stats=read_stats
        ):
            records_read += 1
            records_by_collector["bt_classic"] += 1
            self.apply_bt_classic_event(event, ble_devices)
        bluetooth_devices = self.compact_bluetooth_devices_for_storage(
            self.sorted_records(ble_devices.values())
        )
        wifi_clients_compact = self.compact_wifi_clients_for_storage(
            self.sorted_records(wifi_clients.values())
        )
        files_by_collector = {
            collector: count_jsonl_files(self.log_dir, collector)
            for collector in self.COLLECTORS
        }

        generated_at_epoch = now_epoch()
        summary.update(
            {
                "generated_at": local_now(generated_at_epoch),
                "generated_at_epoch": generated_at_epoch,
                "log_dir": self.log_dir,
                "state_path": self.state_path,
                "window": window_metadata(None),
                "files_read": sum(files_by_collector.values()),
                "records_read": int(summary.get("records_read") or 0) + records_read,
                "incremental_records_read": records_read,
                "raw_log_files": files_by_collector,
                "incremental_records_read_by_collector": dict(records_by_collector),
                "incremental_jsonl_read_stats": read_stats,
                "checkpoint": checkpoint,
                "cached": False,
                "wifi": {
                    "access_points": self.sorted_records(wifi_aps.values()),
                    "clients": wifi_clients_compact,
                },
                "ble": {
                    "devices": bluetooth_devices,
                },
                "bluetooth": {
                    "devices": bluetooth_devices,
                },
            }
        )
        return summary

    def read_events(self, collector):
        """Yield parsed events for one collector in the selected view window."""
        for event in read_jsonl_events(self.log_dir, collector, self.window_days):
            yield event

    def read_all_events(self, collector):
        """Yield parsed events for one collector without applying the view window."""
        for event in read_jsonl_events(self.log_dir, collector, None):
            yield event

    def window_metadata(self):
        """Describe the log range used for this derived summary."""
        return window_metadata(self.window_days)

    def apply_wifi_event(self, event, wifi_aps, wifi_clients):
        """Fold one raw Wi-Fi event into AP or client history."""
        event_type = event.get("type")
        data = event.get("data") or {}
        timestamp_epoch_value = event_time_epoch(event)
        timestamp = self.event_timestamp(event, timestamp_epoch_value)
        if event_type == "ap_beacon":
            # AP identity is the BSSID. The SSID can be blank or can change, so
            # keep both the current display SSID and the all-time SSID set.
            bssid = self.clean(data.get("bssid")) or "unknown"
            ssid = self.clean(data.get("ssid"))
            key = bssid
            item = wifi_aps.setdefault(
                key,
                {
                    "ssid": ssid,
                    "ssids": set(),
                    "bssid": bssid,
                    "vendor_oui": vendor_info(bssid)["vendor_oui"],
                    "vendor_prefix": vendor_info(bssid)["vendor_prefix"],
                    "vendor_name": self.clean(data.get("vendor_name")),
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "channels": set(),
                    "encryption": set(),
                    "signal_latest": None,
                    "signal_min": None,
                    "signal_max": None,
                    "observations": 0,
                    "finding_count": 0,
                    "sources": set(),
                    "sessions": [],
                    "active_session": None,
                },
            )
            self.add_set_value(item["sources"], event.get("collector"))
            if ssid:
                item["ssid"] = ssid
                item["ssids"].add(ssid)
            # Vendor fields were added after the first Skannr logs existed.
            # Refill missing values from the local OUI registry as records are
            # touched by newer events.
            if not item.get("vendor_oui"):
                item["vendor_oui"] = vendor_info(bssid)["vendor_oui"]
            if not item.get("vendor_prefix"):
                item["vendor_prefix"] = vendor_info(bssid)["vendor_prefix"]
            if data.get("vendor_name"):
                item["vendor_name"] = self.clean(data.get("vendor_name"))
            if data.get("vendor_prefix"):
                item["vendor_prefix"] = self.clean(data.get("vendor_prefix"))
            self.update_time_bounds(item, timestamp, timestamp_epoch_value)
            self.add_set_value(item["channels"], data.get("channel"))
            self.add_set_value(
                item["encryption"],
                self.normalize_wifi_encryption(data.get("encryption")),
            )
            self.update_signal(item, data.get("rssi"))
            self.extend_wifi_ap_session(item, timestamp, timestamp_epoch_value, data)
            item["observations"] += 1
        elif event_type == "probe_request":
            # Probe requests identify a client, not an AP. They are generated by
            # wifi_monitor only, but the history schema keeps clients under Wi-Fi
            # so Reports can summarize probe activity next to AP history.
            mac = self.clean(data.get("client_mac")) or "unknown"
            ssid = self.clean(data.get("ssid_probed"))
            item = self.wifi_client_record(wifi_clients, mac, timestamp, data)
            self.add_set_value(item["sources"], event.get("collector"))
            if data.get("vendor_oui"):
                item["vendor_oui"] = self.clean(data.get("vendor_oui"))
            if data.get("vendor_prefix"):
                item["vendor_prefix"] = self.clean(data.get("vendor_prefix"))
            if data.get("vendor_name"):
                item["vendor_name"] = self.clean(data.get("vendor_name"))
            self.update_time_bounds(item, timestamp, timestamp_epoch_value)
            if ssid:
                item["ssids"].add(ssid)
            else:
                item["blank_ssid_count"] += 1
            self.update_signal(item, data.get("rssi"))
            item["probe_count"] += 1
        elif event_type in ("association_seen", "deauth_seen", "disassoc_seen"):
            # Monitor-mode management frames do not always carry an SSID, so
            # count them against the client MAC and leave AP relationship
            # analysis to later report/insight rules.
            mac = self.clean(data.get("client_mac")) or "unknown"
            item = self.wifi_client_record(wifi_clients, mac, timestamp, data)
            self.add_set_value(item["sources"], event.get("collector"))
            self.update_time_bounds(item, timestamp, timestamp_epoch_value)
            self.update_signal(item, data.get("rssi"))
            if event_type == "association_seen":
                item["association_count"] += 1
            elif event_type == "deauth_seen":
                item["deauth_count"] += 1
            elif event_type == "disassoc_seen":
                item["disassoc_count"] += 1

    def wifi_client_record(self, wifi_clients, mac, timestamp, data):
        """Return or create the Wi-Fi client history record for a MAC."""
        return wifi_clients.setdefault(
            mac,
            {
                "mac": mac,
                "vendor_oui": self.clean(data.get("vendor_oui")),
                "vendor_prefix": self.clean(data.get("vendor_prefix")),
                "vendor_name": self.clean(data.get("vendor_name")),
                "first_seen": timestamp,
                "last_seen": timestamp,
                "ssids": set(),
                "blank_ssid_count": 0,
                "signal_latest": None,
                "signal_min": None,
                "signal_max": None,
                "probe_count": 0,
                "association_count": 0,
                "deauth_count": 0,
                "disassoc_count": 0,
                "randomized_mac": self.is_randomized_mac(mac),
                "finding_count": 0,
                "sources": set(),
            },
        )

    def apply_ble_event(self, event, ble_devices):
        """Fold one raw BLE event into device history."""
        event_type = event.get("type")
        if event_type not in ("device_seen", "device_updated", "device_lost"):
            return
        data = event.get("data") or {}
        timestamp_epoch_value = event_time_epoch(event)
        timestamp = self.event_timestamp(event, timestamp_epoch_value)
        mac = self.clean(data.get("mac")) or "unknown"
        item = ble_devices.setdefault(
            mac,
            {
                "mac": mac,
                "names": set(),
                "first_seen": timestamp,
                "last_seen": timestamp,
                "signal_latest": None,
                "signal_min": None,
                "signal_max": None,
                "seen_count": 0,
                "update_count": 0,
                "lost_count": 0,
                "manufacturer": None,
                "service_uuids": set(),
                "findmy_accessory": False,
                "findmy_label": "",
                "findmy_payload_type": "",
                "findmy_status": "",
                "findmy_hint": "",
                "sessions": [],
                "active_session": None,
                "finding_count": 0,
                "transports": set(["ble"]),
            },
        )
        item["transports"].add("ble")
        self.update_time_bounds(item, timestamp, timestamp_epoch_value)
        # Bluetooth names can arrive late through scan responses. Keep a set so
        # a device can gain a display name without losing earlier anonymous
        # observations.
        name = self.clean_bluetooth_name(data.get("name"))
        if name:
            item["names"].add(name)
        if data.get("manufacturer"):
            item["manufacturer"] = self.clean(data.get("manufacturer"))
        if data.get("adv_data_hex") and not item.get("adv_data_hex"):
            item["adv_data_hex"] = data["adv_data_hex"]
        for uuid in data.get("service_uuids") or []:
            self.add_set_value(item["service_uuids"], uuid)
        for field in (
            "findmy_label",
            "findmy_payload_type",
            "findmy_status",
            "findmy_hint",
        ):
            if data.get(field):
                item[field] = self.clean(data.get(field))
        if data.get("findmy_accessory"):
            item["findmy_accessory"] = True
        self.update_signal(item, data.get("rssi"))
        if event_type == "device_seen":
            # Sessions are the basis for "comes and goes" analysis. A seen event
            # opens a session, updates extend it, and lost closes it.
            item["seen_count"] += 1
            self.open_ble_session(item, timestamp, timestamp_epoch_value, data)
        elif event_type == "device_updated":
            item["update_count"] += 1
            self.extend_ble_session(item, timestamp, timestamp_epoch_value, data)
        elif event_type == "device_lost":
            item["lost_count"] = int(item.get("lost_count") or 0) + 1
            self.close_ble_session(item, timestamp, timestamp_epoch_value, data)

    def apply_ble_identify_event(self, event, ble_devices):
        """Fold active BLE Identify results into the BLE device record."""
        if event.get("type") != "identify_result":
            return
        data = event.get("data") or {}
        timestamp_epoch_value = event_time_epoch(event)
        timestamp = self.event_timestamp(event, timestamp_epoch_value)
        mac = self.clean(data.get("mac")) or "unknown"
        item = ble_devices.setdefault(
            mac,
            {
                "mac": mac,
                "names": set(),
                "first_seen": timestamp,
                "last_seen": timestamp,
                "signal_latest": None,
                "signal_min": None,
                "signal_max": None,
                "seen_count": 0,
                "update_count": 0,
                "lost_count": 0,
                "manufacturer": None,
                "service_uuids": set(),
                "findmy_accessory": False,
                "findmy_label": "",
                "findmy_payload_type": "",
                "findmy_status": "",
                "findmy_hint": "",
                "sessions": [],
                "active_session": None,
                "finding_count": 0,
                "transports": set(["ble"]),
            },
        )
        item["transports"].add("ble")
        self.update_time_bounds(item, timestamp, timestamp_epoch_value)
        item["identify_count"] = int(item.get("identify_count") or 0) + 1
        # Device Information Service fields are optional. Preserve only fields
        # that were actually read so failed reads do not erase known metadata.
        for field in (
            "manufacturer_name",
            "model_number",
            "serial_number",
            "firmware_revision",
            "hardware_revision",
            "software_revision",
            "pnp_id",
        ):
            if data.get(field):
                item[field] = self.clean(data.get(field))

    def apply_bt_classic_event(self, event, ble_devices):
        """Fold classic Bluetooth inquiry results into Bluetooth history."""
        event_type = event.get("type")
        if event_type not in (
            "classic_device_seen",
            "classic_device_updated",
            "classic_device_lost",
        ):
            return
        data = event.get("data") or {}
        timestamp_epoch_value = event_time_epoch(event)
        timestamp = self.event_timestamp(event, timestamp_epoch_value)
        mac = self.clean(data.get("mac")) or "unknown"
        item = ble_devices.setdefault(
            mac,
            {
                "mac": mac,
                "names": set(),
                "first_seen": timestamp,
                "last_seen": timestamp,
                "signal_latest": None,
                "signal_min": None,
                "signal_max": None,
                "seen_count": 0,
                "update_count": 0,
                "lost_count": 0,
                "classic_seen_count": 0,
                "classic_update_count": 0,
                "classic_lost_count": 0,
                "manufacturer": None,
                "vendor_prefix": "",
                "vendor_name": "",
                "service_uuids": set(),
                "sessions": [],
                "active_session": None,
                "finding_count": 0,
                "transports": set(["classic"]),
            },
        )
        item.setdefault("transports", set()).add("classic")
        self.update_time_bounds(item, timestamp, timestamp_epoch_value)
        # Classic inquiry may reveal a user-friendly name where BLE only had a
        # rotating/randomized address. Keep it on the same Bluetooth record when
        # the address matches.
        name = self.clean_bluetooth_name(data.get("name"))
        if name:
            item["names"].add(name)
        if data.get("vendor_prefix"):
            item["vendor_prefix"] = self.clean(data.get("vendor_prefix"))
        if data.get("vendor_name"):
            item["vendor_name"] = self.clean(data.get("vendor_name"))
            if not item.get("manufacturer"):
                item["manufacturer"] = self.clean(data.get("vendor_name"))
        if data.get("class"):
            item["classic_class"] = self.clean(data.get("class"))
        if data.get("clock_offset"):
            item["classic_clock_offset"] = self.clean(data.get("clock_offset"))
        if event_type == "classic_device_seen":
            item["classic_seen_count"] = int(item.get("classic_seen_count") or 0) + 1
        elif event_type == "classic_device_updated":
            item["classic_update_count"] = (
                int(item.get("classic_update_count") or 0) + 1
            )
        elif event_type == "classic_device_lost":
            item["classic_lost_count"] = int(item.get("classic_lost_count") or 0) + 1

    def apply_finding_event(self, event, finding_counts):
        """Count related findings by stable device identity when available."""
        finding = event.get("data") or {}
        attributes = finding.get("attributes") or {}
        source = finding.get("source") or ""
        if source in ("wifi", "wifi_monitor"):
            if attributes.get("bssid"):
                finding_counts["wifi-ap:{}".format(attributes["bssid"])] += 1
            if attributes.get("mac"):
                finding_counts["wifi-client:{}".format(attributes["mac"])] += 1
        elif source in ("ble", "ble_identify", "bt_classic"):
            if attributes.get("mac"):
                finding_counts["ble:{}".format(attributes["mac"])] += 1

    def apply_finding_event_to_records(
        self, event, wifi_aps, wifi_clients, ble_devices
    ):
        """Increment finding counters directly during an incremental refresh."""
        finding = event.get("data") or {}
        attributes = finding.get("attributes") or {}
        source = finding.get("source") or ""
        if source in ("wifi", "wifi_monitor"):
            bssid = attributes.get("bssid")
            if bssid and bssid in wifi_aps:
                wifi_aps[bssid]["finding_count"] = (
                    int(wifi_aps[bssid].get("finding_count") or 0) + 1
                )
            mac = attributes.get("mac")
            if mac and mac in wifi_clients:
                wifi_clients[mac]["finding_count"] = (
                    int(wifi_clients[mac].get("finding_count") or 0) + 1
                )
        elif source in ("ble", "ble_identify", "bt_classic"):
            mac = attributes.get("mac")
            if mac and mac in ble_devices:
                ble_devices[mac]["finding_count"] = (
                    int(ble_devices[mac].get("finding_count") or 0) + 1
                )

    def attach_finding_counts(
        self, wifi_aps, wifi_clients, ble_devices, finding_counts
    ):
        """Copy finding counters into the records shown by the UI."""
        for bssid, item in wifi_aps.items():
            item["finding_count"] = finding_counts.get("wifi-ap:{}".format(bssid), 0)
        for mac, item in wifi_clients.items():
            item["finding_count"] = finding_counts.get("wifi-client:{}".format(mac), 0)
        for mac, item in ble_devices.items():
            item["finding_count"] = finding_counts.get("ble:{}".format(mac), 0)

    def sorted_records(self, records):
        """Convert mutable in-memory records to JSON-safe dashboard records."""
        output = []
        for item in records:
            converted = {}
            for key, value in item.items():
                converted[key] = self.serialize_value(value)
            self.add_epoch_fields(converted)
            output.append(converted)
        return sorted(
            output,
            key=lambda item: record_time_epoch(item, "last_seen") or 0,
            reverse=True,
        )

    def serialize_value(self, value):
        """Recursively convert sets inside records and open sessions to lists."""
        if isinstance(value, set):
            return self.sorted_json_values(value)
        if isinstance(value, list):
            return [self.serialize_value(item) for item in value]
        if isinstance(value, dict):
            return {key: self.serialize_value(item) for key, item in value.items()}
        return value

    def sorted_json_values(self, values):
        """Sort mixed historical scalar values without cross-type comparisons."""
        return sorted(
            (self.serialize_value(item) for item in values),
            key=lambda item: (type(item).__name__, str(item)),
        )

    def compact_wifi_clients_for_storage(self, records):
        """Fold low-identity randomized Wi-Fi clients before persistence."""
        kept = []
        group = None
        for record in records or []:
            if not isinstance(record, dict):
                continue
            if self.keep_individual_wifi_client(record):
                kept.append(record)
                continue
            group = self.update_wifi_client_storage_group(group, record)
        if group:
            kept.append(group)
        return sorted(
            kept,
            key=lambda item: record_time_epoch(item, "last_seen") or 0,
            reverse=True,
        )

    def keep_individual_wifi_client(self, record):
        """Return True when a Wi-Fi client should stay as a durable row."""
        if not low_identity_wifi_client(record):
            return True
        if int(record.get("finding_count") or 0) > 0:
            return True
        return False

    def update_wifi_client_storage_group(self, group, record):
        """Fold one randomized Wi-Fi client record into the persisted group."""
        if group is None:
            group = {
                "mac": "randomized:wifi_clients",
                "grouped_randomized": True,
                "randomized_mac": True,
                "identity_bucket": "randomized",
                "identity_label": "Wi-Fi client MAC",
                "randomized_group_count": 0,
                "device_count": 0,
                "sample_macs": [],
                "group_members": [],
                "ssids": [],
                "sources": [],
                "first_seen": record.get("first_seen"),
                "first_seen_epoch": record.get("first_seen_epoch"),
                "last_seen": record.get("last_seen"),
                "last_seen_epoch": record.get("last_seen_epoch"),
                "signal_latest": record.get("signal_latest"),
                "signal_min": record.get("signal_min"),
                "signal_max": record.get("signal_max"),
                "probe_count": 0,
                "blank_ssid_count": 0,
                "association_count": 0,
                "deauth_count": 0,
                "disassoc_count": 0,
                "finding_count": 0,
            }
        count = self.group_record_count(record)
        group["randomized_group_count"] = (
            int(group.get("randomized_group_count") or 0) + count
        )
        group["device_count"] = int(group.get("device_count") or 0) + count
        self.merge_group_samples(
            group,
            record,
            "sample_macs",
            record.get("sample_macs") or [record.get("mac")],
            self.GROUP_SAMPLE_MAC_LIMIT,
        )
        self.merge_group_members(group, record, "wifi")
        self.merge_group_samples(
            group,
            record,
            "ssids",
            record.get("ssids") or [],
            self.GROUP_SAMPLE_VALUE_LIMIT,
        )
        self.merge_group_samples(
            group, record, "sources", record.get("sources") or [], 12
        )
        self.increment_group_counts(
            group,
            record,
            (
                "probe_count",
                "blank_ssid_count",
                "association_count",
                "deauth_count",
                "disassoc_count",
                "finding_count",
            ),
        )
        self.update_storage_group_time_bounds(group, record)
        self.update_storage_group_signal_bounds(group, record)
        return group

    # ── Temporal-density grouping ──────────────────────────────────────
    # Only count MACs seen recently toward the privacy-group threshold.
    # Stale MACs from days ago are excluded so that genuinely separate
    # devices (e.g. floodlights keeping the same name for weeks) do not
    # accidentally trip the grouping threshold.
    GROUP_DENSITY_THRESHOLD = 5
    GROUP_DENSITY_WINDOW_HOURS = 4

    def _active_record_count(self, records):
        """Count records whose last_seen_epoch falls within the density window."""
        if not records:
            return 0
        cutoff = self._now() - (self.GROUP_DENSITY_WINDOW_HOURS * 3600)
        count = 0
        for record in records:
            last = record.get("last_seen_epoch")
            if last is not None and last >= cutoff:
                count += 1
        return count

    def compact_bluetooth_devices_for_storage(self, records):
        """Fold multi-MAC low-identity BLE privacy churn before persistence.

        Seven gated passes, single file, no split responsibility.
        """
        # ── Gate 1: route records ────────────────────────────────────
        # Already-grouped records go straight to candidates.
        # High-identity records go to kept.  Low-identity individuals
        # are deferred into name or manufacturer buckets for density
        # evaluation.
        kept = []
        candidates = defaultdict(list)
        name_candidates = defaultdict(list)
        mfr_candidates = defaultdict(list)
        candidate_groups = set()  # storage keys that already have a group

        for record in records or []:
            if not isinstance(record, dict):
                continue
            if self.keep_individual_bluetooth_device(record):
                kept.append(record)
                continue
            if not bluetooth_grouping_candidate(record):
                kept.append(record)
                continue
            bucket = bluetooth_identity_bucket(record)
            storage_key = self.bluetooth_storage_group_key(record)
            if record.get("grouped_randomized"):
                candidates[storage_key].append(record)
                candidate_groups.add(storage_key)
            elif bucket[0] == "name":
                name_candidates[bucket[1].lower()].append(record)
            elif bucket[0] == "manufacturer":
                mfr_candidates[storage_key].append(record)
            else:
                candidates[storage_key].append(record)

        # ── Gate 2: temporal density check ───────────────────────────
        # Only MACs seen within GROUP_DENSITY_WINDOW_HOURS count toward
        # the threshold.  Stale MACs from days ago are excluded so that
        # genuinely separate devices (e.g. floodlights) do not trip the
        # threshold.
        def _density_ok(recs):
            return self._active_record_count(recs) >= self.GROUP_DENSITY_THRESHOLD

        # ── Pre-dedup: remove individuals whose MAC is already in a ──
        # group.  Incremental events can resurrect individual rows for
        # MACs that were already folded into a group; without this step
        # those individuals dilute the density count and trigger
        # incorrect stale-group removal in Gate 4.
        group_macs = set()
        for storage_key in candidate_groups:
            for rec in candidates[storage_key]:
                if not rec.get("grouped_randomized"):
                    continue
                for m in rec.get("group_members") or []:
                    mac = (m.get("mac") or "").strip().lower()
                    if mac:
                        group_macs.add(mac)
        if group_macs:
            name_candidates = defaultdict(
                list,
                {
                    k: [
                        r
                        for r in recs
                        if (r.get("mac") or "").strip().lower() not in group_macs
                    ]
                    for k, recs in name_candidates.items()
                },
            )
            mfr_candidates = defaultdict(
                list,
                {
                    k: [
                        r
                        for r in recs
                        if (r.get("mac") or "").strip().lower() not in group_macs
                    ]
                    for k, recs in mfr_candidates.items()
                },
            )

        # ── Gate 3: dissolve stale groups ───────────────────────────
        # An existing group whose active-member count has fallen below
        # threshold is dissolved; its members become individuals again.
        for storage_key in list(candidate_groups):
            group_recs = candidates[storage_key]
            recs_without_group = [
                r for r in group_recs if not r.get("grouped_randomized")
            ]
            # Count active distinct MACs across the group members
            active_macs = set()
            cutoff = self._now() - (self.GROUP_DENSITY_WINDOW_HOURS * 3600)
            for rec in group_recs:
                if rec.get("grouped_randomized"):
                    for m in rec.get("group_members") or []:
                        last = m.get("last_seen_epoch")
                        if last is not None and last >= cutoff:
                            active_macs.add((m.get("mac") or "").strip().lower())
                else:
                    last = rec.get("last_seen_epoch")
                    if last is not None and last >= cutoff:
                        active_macs.add((rec.get("mac") or "").strip().lower())
            if len(active_macs) < self.GROUP_DENSITY_THRESHOLD:
                # Dissolve: keep group members as individuals, remove group.
                # Extract members from the group record itself — pre-existing
                # individuals (recs_without_group) may be empty because Gate 6
                # already deduplicated them.  Without this the dissolved
                # group's MACs vanish from device history on the next build.
                del candidates[storage_key]
                candidate_groups.discard(storage_key)
                for rec in group_recs:
                    if rec.get("grouped_randomized"):
                        for m in rec.get("group_members") or []:
                            if not isinstance(m, dict):
                                continue
                            mac = str(m.get("mac") or "").strip().lower()
                            if not mac:
                                continue
                            kept.append(
                                {
                                    "mac": mac,
                                    "first_seen": (
                                        m.get("first_seen")
                                        or rec.get("first_seen")
                                        or ""
                                    ),
                                    "first_seen_epoch": (
                                        m.get("first_seen_epoch")
                                        or rec.get("first_seen_epoch")
                                    ),
                                    "last_seen": (
                                        m.get("last_seen") or rec.get("last_seen") or ""
                                    ),
                                    "last_seen_epoch": (
                                        m.get("last_seen_epoch")
                                        or rec.get("last_seen_epoch")
                                    ),
                                    "signal_min": m.get("signal_min"),
                                    "signal_max": m.get("signal_max"),
                                    "randomized_mac": True,
                                    "grouped_randomized": False,
                                }
                            )
                kept.extend(recs_without_group)

        # ── Gate 4: fold qualified individuals into groups ──────────
        # Name-based candidates that meet the temporal density threshold
        # are folded into a group (new or existing).
        for name_key, recs in name_candidates.items():
            if not recs:
                continue  # all pre-deduped; skip to avoid stale-pop
            storage_key = "name:{}".format(name_key)
            if _density_ok(recs):
                candidates[storage_key].extend(recs)
            else:
                kept.extend(recs)
                # If a stale group exists for this name but density is
                # now below threshold, remove it.
                candidates.pop(storage_key, None)

        for storage_key, recs in mfr_candidates.items():
            if not recs:
                continue
            if _density_ok(recs):
                candidates[storage_key].extend(recs)
            else:
                kept.extend(recs)
                candidates.pop(storage_key, None)

        # ── Gate 5: form groups ─────────────────────────────────────
        compacted = []
        for storage_key, recs in candidates.items():
            represented = sum(self.group_record_count(r) for r in recs)
            if represented <= 1:
                compacted.extend(recs)
                continue
            group = None
            for rec in recs:
                group = self.update_bluetooth_storage_group(group, rec)
            compacted.append(group)

        # ── Gate 6: dedup ───────────────────────────────────────────
        # Remove low-identity individual records whose MAC already
        # appears inside a group.  This prevents incremental events
        # from resurrecting individual rows for MACs that were already
        # folded into a group (which would otherwise dilute the density
        # count and trigger incorrect dissolution on the next build).
        group_macs = set()
        for item in compacted:
            if not item.get("grouped_randomized"):
                continue
            for m in item.get("group_members") or []:
                mac = (m.get("mac") or "").strip().lower()
                if mac:
                    group_macs.add(mac)
        if group_macs:
            compacted = [
                item
                for item in compacted
                if item.get("grouped_randomized")
                or not low_identity_bluetooth_record(item)
                or (item.get("mac") or "").strip().lower() not in group_macs
            ]
        compacted.extend(kept)

        # ── Gate 7: sort ────────────────────────────────────────────
        return sorted(
            compacted,
            key=lambda item: record_time_epoch(item, "last_seen") or 0,
            reverse=True,
        )

    def keep_individual_bluetooth_device(self, record):
        """Return True when a Bluetooth row has enough identity to keep."""
        if record.get("grouped_randomized"):
            return False
        if int(record.get("finding_count") or 0) > 0:
            return True
        return not low_identity_bluetooth_record(record)

    def bluetooth_storage_group_key(self, record):
        """Return the persisted low-identity Bluetooth aggregate key."""
        bucket = bluetooth_identity_bucket(record)
        return "{}:{}".format(bucket[0], bucket[1].lower())

    def update_bluetooth_storage_group(self, group, record):
        """Fold one low-identity Bluetooth record into a persisted group."""
        bucket = bluetooth_identity_bucket(record)
        if group is None:
            group = {
                "mac": "randomized:{}:{}".format(bucket[0], bucket[1].lower()),
                "grouped_randomized": True,
                "randomized_mac": True,
                "identity_bucket": bucket[0],
                "identity_label": bucket[1],
                "name": bluetooth_group_label(record),
                "manufacturer": bluetooth_manufacturer_label(record),
                "findmy_accessory": bool(record.get("findmy_accessory")),
                "transports": [],
                "sample_macs": [],
                "group_members": [],
                "service_uuids": [],
                "names": [],
                "first_seen": record.get("first_seen"),
                "first_seen_epoch": record.get("first_seen_epoch"),
                "last_seen": record.get("last_seen"),
                "last_seen_epoch": record.get("last_seen_epoch"),
                "signal_latest": record.get("signal_latest"),
                "signal_min": record.get("signal_min"),
                "signal_max": record.get("signal_max"),
                "seen_count": 0,
                "update_count": 0,
                "lost_count": 0,
                "identify_count": 0,
                "classic_seen_count": 0,
                "classic_update_count": 0,
                "classic_lost_count": 0,
                "finding_count": 0,
                "session_count": 0,
                "active_session": False,
                "randomized_group_count": 0,
                "device_count": 0,
            }
        count = self.group_record_count(record)
        group["randomized_group_count"] = (
            int(group.get("randomized_group_count") or 0) + count
        )
        group["device_count"] = int(group.get("device_count") or 0) + count
        self.increment_group_counts(
            group,
            record,
            (
                "seen_count",
                "update_count",
                "lost_count",
                "identify_count",
                "classic_seen_count",
                "classic_update_count",
                "classic_lost_count",
                "finding_count",
            ),
        )
        group["session_count"] = int(
            group.get("session_count") or 0
        ) + self.record_session_count(record)
        group["active_session"] = bool(group.get("active_session")) or bool(
            record.get("active_session")
        )
        self.merge_group_samples(
            group,
            record,
            "sample_macs",
            record.get("sample_macs") or [record.get("mac")],
            self.GROUP_SAMPLE_MAC_LIMIT,
        )
        self.merge_group_members(group, record, "bluetooth")
        self.merge_group_samples(
            group, record, "service_uuids", record.get("service_uuids") or [], 32
        )
        self.merge_group_samples(group, record, "names", record.get("names") or [], 12)
        self.merge_group_samples(
            group, record, "transports", record.get("transports") or [], 8
        )
        if record.get("findmy_accessory"):
            group["findmy_accessory"] = True
        if record.get("manufacturer") and not group.get("manufacturer"):
            group["manufacturer"] = record.get("manufacturer")
        self.update_storage_group_time_bounds(group, record)
        self.update_storage_group_signal_bounds(group, record)
        return group

    def merge_group_members(self, group, record, source, limit=24):
        """Retain bounded per-member evidence for grouped privacy rows."""
        members = group.setdefault("group_members", [])
        source_members = record.get("group_members")
        if isinstance(source_members, list) and source_members:
            candidates = source_members
        else:
            candidates = [self.group_member_summary(record, source)]
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            member = {
                key: value
                for key, value in candidate.items()
                if value not in (None, "", [], {})
            }
            mac = str(member.get("mac") or "").strip().lower()
            if not mac:
                continue
            existing = next(
                (item for item in members if str(item.get("mac") or "").lower() == mac),
                None,
            )
            if existing:
                self.merge_group_member_summary(existing, member)
                continue
            if len(members) < limit:
                members.append(member)

    def group_member_summary(self, record, source):
        """Return one compact per-MAC member summary for a grouped row."""
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
                    "session_count": record.get("session_count")
                    or self.record_session_count(record),
                    "active_session": bool(record.get("active_session")),
                }
            )
        return member

    def merge_group_member_summary(self, target, source):
        """Merge repeated compact member summaries from persisted aggregates."""
        for time_key in ("first_seen", "last_seen"):
            epoch_key = "{}_epoch".format(time_key)
            old_epoch = record_time_epoch(target, time_key)
            new_epoch = source.get(epoch_key)
            if (
                time_key == "first_seen"
                and new_epoch
                and (not old_epoch or new_epoch < old_epoch)
            ):
                target[time_key] = source.get(time_key) or target.get(time_key)
                target[epoch_key] = new_epoch
            if (
                time_key == "last_seen"
                and new_epoch
                and (not old_epoch or new_epoch >= old_epoch)
            ):
                target[time_key] = source.get(time_key) or target.get(time_key)
                target[epoch_key] = new_epoch
        for field in ("signal_min", "signal_max"):
            values = [
                value
                for value in (target.get(field), source.get(field))
                if isinstance(value, (int, float))
            ]
            if values:
                target[field] = min(values) if field == "signal_min" else max(values)
        for field in (
            "probe_count",
            "association_count",
            "deauth_count",
            "disassoc_count",
            "seen_count",
            "update_count",
            "lost_count",
            "classic_seen_count",
            "session_count",
        ):
            if source.get(field) is not None:
                target[field] = int(target.get(field) or 0) + int(
                    source.get(field) or 0
                )
        target["active_session"] = bool(target.get("active_session")) or bool(
            source.get("active_session")
        )
        for field in ("ssids", "names", "service_uuids"):
            self.merge_group_samples(target, source, field, source.get(field) or [], 8)
        if source.get("identity") and not target.get("identity"):
            target["identity"] = source.get("identity")

    def group_record_count(self, record):
        """Return represented identity count for an individual or aggregate row."""
        try:
            return max(
                1,
                int(
                    record.get("randomized_group_count")
                    or record.get("device_count")
                    or 1
                ),
            )
        except (TypeError, ValueError):
            return 1

    def record_session_count(self, record):
        """Return compact session count without retaining session bodies."""
        if record.get("session_count") is not None:
            try:
                return int(record.get("session_count") or 0)
            except (TypeError, ValueError):
                return 0
        sessions = record.get("sessions")
        return len(sessions) if isinstance(sessions, list) else 0

    def increment_group_counts(self, group, record, fields):
        """Add numeric counters from one record to an aggregate row."""
        for field in fields:
            group[field] = int(group.get(field) or 0) + int(record.get(field) or 0)

    def merge_group_samples(self, group, record, field, values, limit):
        """Merge bounded sample evidence into an aggregate row."""
        sample = group.setdefault(field, [])
        source = values if isinstance(values, (list, tuple, set)) else [values]
        for value in source:
            if value in (None, "", [], {}):
                continue
            if value not in sample and len(sample) < limit:
                sample.append(value)

    def update_storage_group_time_bounds(self, group, record):
        """Expand aggregate first/last timestamps from one folded record."""
        first_epoch = record_time_epoch(record, "first_seen")
        last_epoch = record_time_epoch(record, "last_seen")
        group_first = record_time_epoch(group, "first_seen")
        group_last = record_time_epoch(group, "last_seen")
        if first_epoch and (not group_first or first_epoch < group_first):
            group["first_seen_epoch"] = first_epoch
            group["first_seen"] = record.get("first_seen")
        if last_epoch and (not group_last or last_epoch >= group_last):
            group["last_seen_epoch"] = last_epoch
            group["last_seen"] = record.get("last_seen")
            group["signal_latest"] = record.get("signal_latest")

    def update_storage_group_signal_bounds(self, group, record):
        """Expand aggregate signal range from one folded record."""
        for field, reducer in (("signal_min", min), ("signal_max", max)):
            values = [
                value
                for value in (group.get(field), record.get(field))
                if isinstance(value, (int, float))
            ]
            if values:
                group[field] = reducer(values)

    def load_persisted_summary(self):
        """Load the durable device-history file if it exists."""
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
                self.sanitize_bluetooth_names(loaded)
                return loaded
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def sanitize_bluetooth_names(self, summary):
        """Remove command diagnostics that older builds stored as names."""
        bluetooth = (summary or {}).get("bluetooth") or {}
        ble = (summary or {}).get("ble") or {}
        devices = ble.get("devices") or bluetooth.get("devices") or []
        for device in devices:
            device["names"] = self.clean_bluetooth_name_list(device.get("names"))
            self.add_epoch_fields(device)
            active = device.get("active_session")
            if isinstance(active, dict):
                active["names"] = self.clean_bluetooth_name_list(active.get("names"))
                self.add_epoch_fields(active)
            for session in device.get("sessions") or []:
                if isinstance(session, dict):
                    session["names"] = self.clean_bluetooth_name_list(
                        session.get("names")
                    )
                    self.add_epoch_fields(session)
        if devices:
            summary.setdefault("ble", {})["devices"] = devices
            summary.setdefault("bluetooth", {})["devices"] = devices

    def save_summary(self, summary):
        """Persist the merged summary so first_seen survives restarts."""
        save_json_atomic(self.state_path, summary)

    def prune_low_value_bluetooth_devices(self, summary):
        """Drop stale anonymous one-off BLE addresses from the materialized cache."""
        if not isinstance(summary, dict):
            return summary, 0
        bluetooth = summary.get("bluetooth") or summary.get("ble") or {}
        devices = bluetooth.get("devices") or []
        if not devices:
            return summary, 0
        generated_at = timestamp_epoch(summary.get("generated_at_epoch")) or now_epoch()
        kept = []
        pruned = 0
        for device in devices:
            if self.low_value_stale_bluetooth_device(device, generated_at):
                pruned += 1
            elif self.low_count_stale_bluetooth_device(device, generated_at):
                pruned += 1
            else:
                kept.append(device)
        if pruned:
            summary.setdefault("ble", {})["devices"] = kept
            summary.setdefault("bluetooth", {})["devices"] = kept
            summary["pruned_bluetooth_devices"] = (
                int(summary.get("pruned_bluetooth_devices") or 0) + pruned
            )
        return summary, pruned

    def prune_stale_ap_sessions(self, summary):
        """Drop Wi-Fi AP sessions older than ``WIFI_AP_MAX_SESSION_AGE_SEC``.

        Keeps at least ``WIFI_AP_MIN_SESSIONS`` per AP so short histories
        are not wiped entirely.  Returns (summary, total_pruned).
        """
        if not isinstance(summary, dict):
            return summary, 0
        wifi = summary.get("wifi") or {}
        aps = wifi.get("access_points") or []
        if not aps:
            return summary, 0
        generated_at = timestamp_epoch(summary.get("generated_at_epoch")) or now_epoch()
        cutoff = generated_at - self.WIFI_AP_MAX_SESSION_AGE_SEC
        total_pruned = 0
        for ap in aps:
            sessions = ap.get("sessions") or []
            if not sessions:
                continue
            kept = []
            for s in sessions:
                start = s.get("start_epoch")
                if start is None:
                    kept.append(s)
                    continue
                if start >= cutoff:
                    kept.append(s)
            # Ensure we never drop below the minimum.
            if len(kept) < self.WIFI_AP_MIN_SESSIONS:
                # Keep the most recent sessions (they're in chronological order).
                kept = sessions[-self.WIFI_AP_MIN_SESSIONS :]
            pruned = len(sessions) - len(kept)
            if pruned > 0:
                ap["sessions"] = kept
                total_pruned += pruned
        return summary, total_pruned

    def low_value_stale_bluetooth_device(self, device, generated_at_epoch):
        """Return True for no-name private BLE rows that are cache noise."""
        if not isinstance(device, dict):
            return False
        transports = set(str(item).lower() for item in device.get("transports") or [])
        if "classic" in transports or "bt_classic" in transports:
            return False
        if self.clean_bluetooth_name_list(device.get("names")):
            return False
        if device.get("name") and self.clean_bluetooth_name(device.get("name")):
            return False
        for field in (
            "manufacturer_name",
            "model_number",
            "serial_number",
            "firmware_revision",
            "hardware_revision",
            "software_revision",
            "pnp_id",
            "service_uuids",
            "findmy_label",
            "findmy_payload_type",
            "findmy_status",
            "findmy_hint",
        ):
            if device.get(field):
                return False
        if int(device.get("seen_count") or 0) != 1:
            return False
        if int(device.get("update_count") or 0) > 0:
            return False
        if device.get("active_session"):
            return False
        last_seen = record_time_epoch(device, "last_seen")
        if last_seen is None:
            return False
        return generated_at_epoch - last_seen > self.BLE_STALE_SINGLE_SEEN_PRUNE_SEC

    def low_count_stale_bluetooth_device(self, device, generated_at_epoch):
        """Return True for low-count anonymous BLE devices that never reached
        the grouping threshold and are now stale.

        These are randomized MACs seen a handful of times (≤
        ``BLE_LOW_COUNT_PRUNE_MAX_SEEN``) with no identity fields, inactive
        for more than ``BLE_LOW_COUNT_PRUNE_STALE_SEC``.  They are cache
        noise — they will never form a group and carry no useful history.
        """
        if not isinstance(device, dict):
            return False
        transports = set(str(item).lower() for item in device.get("transports") or [])
        if "classic" in transports or "bt_classic" in transports:
            return False
        # Must have zero identity — same check as tier-1 pruning.
        if self.clean_bluetooth_name_list(device.get("names")):
            return False
        if device.get("name") and self.clean_bluetooth_name(device.get("name")):
            return False
        for field in (
            "manufacturer_name",
            "model_number",
            "serial_number",
            "firmware_revision",
            "hardware_revision",
            "software_revision",
            "pnp_id",
            "service_uuids",
            "findmy_label",
            "findmy_payload_type",
            "findmy_status",
            "findmy_hint",
        ):
            if device.get(field):
                return False
        # Skip groups — only prune individual low-identity devices.
        if device.get("grouped_randomized"):
            return False
        # Must have seen_count within the low-count band (above the
        # single-seen tier-1 rule, but below the grouping threshold).
        seen = int(device.get("seen_count") or 0)
        if seen < 2 or seen > self.BLE_LOW_COUNT_PRUNE_MAX_SEEN:
            return False
        if device.get("active_session"):
            return False
        last_seen = record_time_epoch(device, "last_seen")
        if last_seen is None:
            return False
        return generated_at_epoch - last_seen > self.BLE_LOW_COUNT_PRUNE_STALE_SEC

    def has_history_records(self, summary):
        """Return True when an older summary has useful materialized data."""
        wifi = (summary or {}).get("wifi") or {}
        ble = (summary or {}).get("ble") or {}
        bluetooth = (summary or {}).get("bluetooth") or {}
        return bool(
            wifi.get("access_points")
            or wifi.get("clients")
            or ble.get("devices")
            or bluetooth.get("devices")
        )

    def raw_history_files_exist(self):
        """Return True when retained collector JSONL files can rebuild history.

        An empty materialized summary with a checkpoint can happen after manual
        cache cleanup or path moves. If raw logs are still present, prefer a
        full rebuild over trusting the empty checkpoint.
        """
        return any(
            count_jsonl_files(self.log_dir, collector) for collector in self.COLLECTORS
        )

    def display_summary(self, summary, window_days):
        """Return a windowed view derived from the materialized summary only."""
        # The materialized file can grow large over weeks of BLE/Wi-Fi history.
        # A full deepcopy here made cached /derived_views loads expensive even
        # when no raw logs were scanned. Build the display payload from shallow
        # top-level metadata plus copied records that actually belong to the
        # selected View window.
        output = {
            key: value
            for key, value in (summary or {}).items()
            if key not in ("wifi", "ble", "bluetooth")
        }
        source_wifi = (summary or {}).get("wifi") or {}
        source_ble = (summary or {}).get("ble") or {}
        source_bluetooth = (summary or {}).get("bluetooth") or {}
        bluetooth_devices = (
            source_ble.get("devices") or source_bluetooth.get("devices") or []
        )
        output["wifi"] = {
            "access_points": self.display_records(
                source_wifi.get("access_points") or [], window_days
            ),
            "clients": self.display_records(
                source_wifi.get("clients") or [], window_days
            ),
        }
        output["ble"] = {
            "devices": self.display_records(bluetooth_devices, window_days),
        }
        output["bluetooth"] = {"devices": output["ble"]["devices"]}
        output["window"] = window_metadata(window_days)
        output["materialized_window"] = summary.get("window") or window_metadata(None)
        output["raw_logs_incremental"] = True
        self.enrich_wifi_vendor_names(output)
        return output

    def enrich_wifi_vendor_names(self, summary):
        """Fill vendor names from OUI data for old materialized records too."""
        wifi = summary.get("wifi") or {}
        for record in wifi.get("access_points") or []:
            if not record.get("vendor_prefix"):
                record["vendor_prefix"] = vendor_prefix(
                    record.get("bssid") or record.get("vendor_oui")
                )
            if not record.get("vendor_name"):
                record["vendor_name"] = vendor_name(
                    record.get("bssid") or record.get("vendor_oui")
                )
        for record in wifi.get("clients") or []:
            if not record.get("vendor_prefix"):
                record["vendor_prefix"] = vendor_prefix(
                    record.get("mac") or record.get("vendor_oui")
                )
            if not record.get("vendor_name"):
                record["vendor_name"] = vendor_name(
                    record.get("mac") or record.get("vendor_oui")
                )

    def display_records(self, records, window_days):
        """Return copied records visible in the selected dashboard window."""
        filtered = []
        for record in records:
            if not isinstance(record, dict):
                continue
            if window_days is not None and not self.record_in_window(
                record, window_days
            ):
                continue
            # Shallow-copy each returned record so display enrichment can add
            # compatibility fields without mutating the persisted cache object.
            filtered.append(dict(record))
        return filtered

    def record_in_window(self, record, window_days):
        """Return True when a materialized record was seen in this window."""
        if window_days is None:
            return True
        event = {
            "timestamp": record.get("last_seen"),
            "timestamp_epoch": record.get("last_seen_epoch"),
            "data": record,
        }
        return event_in_window(event, window_days)

    def records_in_window(self, records, window_days):
        """Filter materialized records by last_seen without reading raw logs."""
        filtered = []
        for record in records:
            event = {
                "timestamp": record.get("last_seen"),
                "timestamp_epoch": record.get("last_seen_epoch"),
                "data": record,
            }
            if event_in_window(event, window_days):
                filtered.append(record)
        return filtered

    def record_map(self, records, key, set_fields):
        """Convert persisted records back to mutable records used while folding events."""
        mapped = {}
        for record in records:
            record_key = record.get(key)
            if not record_key:
                continue
            item = copy.deepcopy(record)
            for field in set_fields:
                value = item.get(field)
                # JSON stores accumulated values as lists. The folding code
                # expects sets to avoid duplicate SSIDs/channels/names.
                if isinstance(value, set):
                    continue
                if isinstance(value, list):
                    item[field] = set(value)
                elif value:
                    item[field] = {value}
                else:
                    item[field] = set()
            if "names" in set_fields:
                item["names"] = set(self.clean_bluetooth_name_list(item.get("names")))
            self.restore_active_session(item)
            mapped[record_key] = item
        return mapped

    def restore_active_session(self, item):
        """Restore persisted open sessions to the mutable shape used here."""
        session = item.get("active_session")
        if not isinstance(session, dict):
            return
        if "channels" in session:
            channels = session.get("channels")
            if isinstance(channels, list):
                session["channels"] = set(channels)
            elif channels and not isinstance(channels, set):
                session["channels"] = {channels}
            elif channels is None:
                session["channels"] = set()
        names = session.get("names")
        if names is None:
            return
        if isinstance(names, set):
            return
        if isinstance(names, list):
            session["names"] = set(self.clean_bluetooth_name_list(names))
        elif names:
            name = self.clean_bluetooth_name(names)
            session["names"] = {name} if name else set()
        else:
            session["names"] = set()

    def merge_persisted_summary(self, current, previous, merge_counts=True):
        """Merge older durable history without double-counting current logs."""
        if not previous:
            return
        current["wifi"]["access_points"] = self.merge_record_lists(
            current["wifi"]["access_points"],
            ((previous.get("wifi") or {}).get("access_points") or []),
            "bssid",
            ["ssids", "channels", "encryption", "sources"],
            ["observations", "finding_count"],
            merge_counts,
        )
        current["wifi"]["clients"] = self.merge_record_lists(
            current["wifi"]["clients"],
            ((previous.get("wifi") or {}).get("clients") or []),
            "mac",
            ["ssids", "sources"],
            [
                "probe_count",
                "blank_ssid_count",
                "association_count",
                "deauth_count",
                "disassoc_count",
                "finding_count",
            ],
            merge_counts,
        )
        current["ble"]["devices"] = self.merge_record_lists(
            current["ble"]["devices"],
            ((previous.get("ble") or {}).get("devices") or []),
            "mac",
            ["names", "service_uuids", "transports"],
            [
                "seen_count",
                "update_count",
                "lost_count",
                "identify_count",
                "classic_seen_count",
                "classic_update_count",
                "classic_lost_count",
                "finding_count",
            ],
            merge_counts,
        )
        current["bluetooth"] = {"devices": current["ble"]["devices"]}

    def enrich_from_persisted_summary(self, current, previous):
        """Preserve all-time identity fields for devices visible in the window.

        Windowed views should not pull in old devices or all-time counters, but
        first_seen is still useful as durable device identity context.
        """
        if not previous:
            return
        current["wifi"]["access_points"] = self.enrich_record_list(
            current["wifi"]["access_points"],
            ((previous.get("wifi") or {}).get("access_points") or []),
            "bssid",
        )
        current["wifi"]["clients"] = self.enrich_record_list(
            current["wifi"]["clients"],
            ((previous.get("wifi") or {}).get("clients") or []),
            "mac",
        )
        current["ble"]["devices"] = self.enrich_record_list(
            current["ble"]["devices"],
            ((previous.get("ble") or {}).get("devices") or []),
            "mac",
        )
        current["bluetooth"] = {"devices": current["ble"]["devices"]}

    def enrich_record_list(self, current_records, previous_records, key):
        """Attach durable first_seen and stable metadata without old counts."""
        previous_by_key = {
            record.get(key): record for record in previous_records if record.get(key)
        }
        for record in current_records:
            old = previous_by_key.get(record.get(key))
            if not old:
                continue
            if old.get("first_seen") and (
                not record.get("first_seen")
                or self.is_earlier(old["first_seen"], record["first_seen"])
            ):
                record["first_seen"] = old["first_seen"]
            for field in (
                "ssid",
                "vendor_oui",
                "vendor_prefix",
                "vendor_name",
                "manufacturer",
                "manufacturer_name",
                "model_number",
                "serial_number",
                "firmware_revision",
                "hardware_revision",
                "software_revision",
                "pnp_id",
                "classic_class",
                "classic_clock_offset",
                "service_uuids",
                "findmy_label",
                "findmy_payload_type",
                "findmy_status",
                "findmy_hint",
            ):
                if not record.get(field) and old.get(field):
                    record[field] = old[field]
            if old.get("randomized_mac"):
                record["randomized_mac"] = True
            if old.get("findmy_accessory"):
                record["findmy_accessory"] = True
        return sorted(
            current_records,
            key=lambda item: record_time_epoch(item, "last_seen") or 0,
            reverse=True,
        )

    def merge_record_lists(
        self,
        current_records,
        previous_records,
        key,
        list_fields,
        count_fields,
        merge_counts=True,
    ):
        """Merge previous persisted records into fresh raw-log records.

        For normal all-log refreshes, counts use max() rather than addition
        because raw logs may already be represented in the persisted summary.
        When saving a windowed refresh, callers can keep current raw-log counts
        so the selected View range does not suppress durable counters.
        """
        merged = {
            record.get(key): record for record in current_records if record.get(key)
        }
        for old in previous_records:
            old_key = old.get(key)
            if not old_key:
                continue
            if old_key not in merged:
                # Device was seen only in the older durable summary. Keep it so
                # first_seen survives even after raw logs age out or are not
                # reread.
                merged[old_key] = old
                continue
            new = merged[old_key]
            self.merge_time_fields(new, old)
            self.merge_signal_fields(new, old)
            for field in list_fields:
                new[field] = self.sorted_json_values(
                    set(new.get(field) or []) | set(old.get(field) or [])
                )
            for field in count_fields:
                if merge_counts:
                    new[field] = max(int(new.get(field) or 0), int(old.get(field) or 0))
            for field in (
                "ssid",
                "vendor_oui",
                "vendor_prefix",
                "vendor_name",
                "manufacturer",
                "manufacturer_name",
                "model_number",
                "serial_number",
                "firmware_revision",
                "hardware_revision",
                "software_revision",
                "pnp_id",
                "classic_class",
                "classic_clock_offset",
            ):
                if not new.get(field) and old.get(field):
                    new[field] = old[field]
            if old.get("randomized_mac"):
                new["randomized_mac"] = True
            if old.get("sessions"):
                new["sessions"] = self.merge_sessions(
                    new.get("sessions") or [], old.get("sessions") or []
                )
            if old.get("active_session") and not new.get("active_session"):
                new["active_session"] = old["active_session"]
        return sorted(
            merged.values(),
            key=lambda item: record_time_epoch(item, "last_seen") or 0,
            reverse=True,
        )

    def extend_wifi_ap_session(self, item, timestamp, timestamp_epoch_value, data):
        """Track AP presence windows from beacon timing gaps.

        Wi-Fi AP scans do not produce explicit lost events in raw logs. Treat a
        long gap between beacons as a disappearance/return boundary so reports
        can show AP presence spans instead of only first_seen/last_seen.
        """
        if not timestamp:
            return
        active = item.get("active_session")
        if active:
            gap = self.duration_seconds(
                active.get("end"),
                timestamp,
                active.get("end_epoch"),
                timestamp_epoch_value,
            )
            if gap > self.WIFI_AP_SESSION_GAP_SEC:
                item.setdefault("sessions", []).append(dict(active))
                active = None
                item["active_session"] = None
        if not active:
            active = {
                "start": timestamp,
                "start_epoch": timestamp_epoch_value,
                "end": timestamp,
                "end_epoch": timestamp_epoch_value,
                "duration_sec": 0,
                "signal_min": None,
                "signal_max": None,
                "channels": set(),
            }
            item["active_session"] = active
        active["end"] = timestamp
        active["end_epoch"] = timestamp_epoch_value
        active["duration_sec"] = self.duration_seconds(
            active.get("start"),
            timestamp,
            active.get("start_epoch"),
            timestamp_epoch_value,
        )
        self.update_session_signal(active, data.get("rssi"))
        self.add_set_value(active["channels"], data.get("channel"))

    def open_ble_session(self, item, timestamp, timestamp_epoch_value, data):
        """Start a BLE presence session when a device appears."""
        if not timestamp:
            return
        if item.get("active_session"):
            # Duplicate seen events inside one presence interval should extend
            # the active session rather than create overlapping sessions.
            self.extend_ble_session(item, timestamp, timestamp_epoch_value, data)
            return
        session = {
            "start": timestamp,
            "start_epoch": timestamp_epoch_value,
            "end": timestamp,
            "end_epoch": timestamp_epoch_value,
            "duration_sec": 0,
            "signal_min": None,
            "signal_max": None,
            "names": set(),
        }
        self.update_session_signal(session, data.get("rssi"))
        name = self.clean_bluetooth_name(data.get("name"))
        if name:
            session["names"].add(name)
        item["active_session"] = session

    def extend_ble_session(self, item, timestamp, timestamp_epoch_value, data):
        """Extend the current BLE presence session."""
        if not timestamp:
            return
        if not item.get("active_session"):
            self.open_ble_session(item, timestamp, timestamp_epoch_value, data)
            return
        session = item["active_session"]
        session["end"] = timestamp
        session["end_epoch"] = timestamp_epoch_value
        session["duration_sec"] = self.duration_seconds(
            session.get("start"),
            timestamp,
            session.get("start_epoch"),
            timestamp_epoch_value,
        )
        self.update_session_signal(session, data.get("rssi"))
        name = self.clean_bluetooth_name(data.get("name"))
        if name:
            session["names"].add(name)

    def close_ble_session(self, item, timestamp, timestamp_epoch_value, data):
        """Close the current BLE session and store it in session history."""
        if not item.get("active_session"):
            return
        self.extend_ble_session(item, timestamp, timestamp_epoch_value, data)
        session = item.pop("active_session", None)
        if not session:
            return
        stored = dict(session)
        stored["names"] = sorted(stored.get("names") or [])
        item.setdefault("sessions", []).append(stored)

    def update_session_signal(self, session, value):
        """Maintain min/max RSSI for one BLE presence session."""
        signal = self.to_number(value)
        if signal is None:
            return
        session["signal_min"] = (
            signal
            if session["signal_min"] is None
            else min(session["signal_min"], signal)
        )
        session["signal_max"] = (
            signal
            if session["signal_max"] is None
            else max(session["signal_max"], signal)
        )

    def merge_sessions(self, current, previous):
        """Merge BLE sessions by start/end timestamps."""
        merged = {}
        for session in list(current or []) + list(previous or []):
            key = "{}|{}".format(session.get("start"), session.get("end"))
            if key.strip("|"):
                merged[key] = session
        return sorted(
            merged.values(),
            key=lambda item: record_time_epoch(item, "start") or 0,
            reverse=True,
        )

    def duration_seconds(
        self, first_seen, last_seen, first_epoch=None, last_epoch=None
    ):
        """Return duration in seconds between two Skannr timestamps."""
        first = first_epoch if first_epoch is not None else self.time_key(first_seen)
        last = last_epoch if last_epoch is not None else self.time_key(last_seen)
        if not first or not last or last < first:
            return 0
        return int(last - first)

    def merge_time_fields(self, new, old):
        """Preserve earliest first_seen and latest last_seen across summaries."""
        old_first = record_time_epoch(old, "first_seen")
        new_first = record_time_epoch(new, "first_seen")
        if old_first is not None and (new_first is None or old_first < new_first):
            new["first_seen"] = old["first_seen"]
            new["first_seen_epoch"] = old_first
        old_last = record_time_epoch(old, "last_seen")
        new_last = record_time_epoch(new, "last_seen")
        if old_last is not None and (new_last is None or old_last > new_last):
            new["last_seen"] = old["last_seen"]
            new["last_seen_epoch"] = old_last

    def merge_signal_fields(self, new, old):
        """Merge signal range while keeping current latest when available."""
        old_min = self.to_number(old.get("signal_min"))
        old_max = self.to_number(old.get("signal_max"))
        new_min = self.to_number(new.get("signal_min"))
        new_max = self.to_number(new.get("signal_max"))
        if old_min is not None:
            new["signal_min"] = old_min if new_min is None else min(new_min, old_min)
        if old_max is not None:
            new["signal_max"] = old_max if new_max is None else max(new_max, old_max)
        if new.get("signal_latest") is None and old.get("signal_latest") is not None:
            new["signal_latest"] = old.get("signal_latest")

    def event_timestamp(self, event, timestamp_epoch_value):
        """Return the UI display timestamp derived from an event epoch."""
        if timestamp_epoch_value is not None:
            return format_epoch(timestamp_epoch_value)
        return (event or {}).get("timestamp") or ""

    def update_time_bounds(self, item, timestamp, timestamp_epoch_value=None):
        """Maintain display and epoch first_seen/last_seen fields."""
        if not timestamp:
            return
        if timestamp_epoch_value is None:
            timestamp_epoch_value = self.time_key(timestamp)
        if item.get("first_seen") and item.get("first_seen_epoch") is None:
            item["first_seen_epoch"] = (
                timestamp_epoch_value
                if item["first_seen"] == timestamp
                else self.time_key(item["first_seen"])
            )
        if item.get("last_seen") and item.get("last_seen_epoch") is None:
            item["last_seen_epoch"] = (
                timestamp_epoch_value
                if item["last_seen"] == timestamp
                else self.time_key(item["last_seen"])
            )

        first_epoch = record_time_epoch(item, "first_seen")
        last_epoch = record_time_epoch(item, "last_seen")
        if first_epoch is None or timestamp_epoch_value < first_epoch:
            item["first_seen"] = timestamp
            item["first_seen_epoch"] = timestamp_epoch_value
        if last_epoch is None or timestamp_epoch_value > last_epoch:
            item["last_seen"] = timestamp
            item["last_seen_epoch"] = timestamp_epoch_value

    def add_epoch_fields(self, item):
        """Add numeric epoch fields next to local display timestamps."""
        for field in ("first_seen", "last_seen", "start", "end"):
            value = item.get(field)
            if not value:
                continue
            epoch_field = "{}_epoch".format(field)
            if item.get(epoch_field) is None:
                item[epoch_field] = self.time_key(value)

    def time_key(self, timestamp):
        """Return sortable epoch time for current local Skannr timestamps."""
        if timestamp in self._time_cache:
            return self._time_cache[timestamp]
        parsed = timestamp_epoch(timestamp)
        value = parsed if parsed is not None else 0
        if len(self._time_cache) < 100000:
            # Device-history refreshes touch the same timestamps many times.
            # Bound the cache so a very large log set does not grow unbounded.
            self._time_cache[timestamp] = value
        return value

    def is_earlier(self, left, right):
        """Return True when left is chronologically earlier than right."""
        if self.is_sortable_timestamp(left) and self.is_sortable_timestamp(right):
            return str(left) < str(right)
        left_epoch = self.time_key(left)
        right_epoch = self.time_key(right)
        if left_epoch is not None and right_epoch is not None:
            return left_epoch < right_epoch
        return str(left) < str(right)

    def is_later(self, left, right):
        """Return True when left is chronologically later than right."""
        if self.is_sortable_timestamp(left) and self.is_sortable_timestamp(right):
            return str(left) > str(right)
        left_epoch = self.time_key(left)
        right_epoch = self.time_key(right)
        if left_epoch is not None and right_epoch is not None:
            return left_epoch > right_epoch
        return str(left) > str(right)

    def is_sortable_timestamp(self, timestamp):
        """Return True for the current 'YYYY-MM-DD HH:MM:SS' timestamp shape."""
        text = str(timestamp or "")
        return (
            len(text) >= 19
            and text[4:5] == "-"
            and text[7:8] == "-"
            and text[10:11] == " "
        )

    def update_signal(self, item, value):
        """Maintain latest/min/max RSSI when the raw event carries a number."""
        signal = self.to_number(value)
        if signal is None:
            return
        item["signal_latest"] = signal
        item["signal_min"] = (
            signal if item["signal_min"] is None else min(item["signal_min"], signal)
        )
        item["signal_max"] = (
            signal if item["signal_max"] is None else max(item["signal_max"], signal)
        )

    def add_set_value(self, values, value):
        """Add a non-empty normalized value to a set."""
        cleaned = self.clean(value)
        if cleaned:
            values.add(cleaned)

    def normalize_wifi_encryption(self, value):
        """Canonicalize equivalent Wi-Fi security labels before comparison.

        Different scan paths and older logs can describe the same AP as
        "WPA2", "WPA2/RSN", or a transitional "WPA2/WPA3". Reports should only
        flag real security drift, not parser vocabulary drift.
        """
        text = self.clean(value)
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

    def clean(self, value):
        """Normalize display values from logs without losing useful strings."""
        if value is None:
            return ""
        return str(value).strip()

    def clean_bluetooth_name(self, value):
        """Normalize Bluetooth names and reject command/error diagnostics."""
        text = self.clean(value)
        if not text:
            return ""
        lowered = text.lower()
        bad_fragments = (
            "command '['",
            "timed out after",
            "no route to host",
            "host is down",
            "input/output error",
            "operation already in progress",
            "failed to connect",
        )
        if any(fragment in lowered for fragment in bad_fragments):
            return ""
        if bluetooth_property_like_name(text):
            return ""
        return text

    def clean_bluetooth_name_list(self, values):
        """Return sorted valid Bluetooth names from a scalar/list/set field."""
        if isinstance(values, (list, set, tuple)):
            candidates = values
        elif values:
            candidates = [values]
        else:
            candidates = []
        cleaned = []
        for value in candidates:
            name = self.clean_bluetooth_name(value)
            if name and name not in cleaned:
                cleaned.append(name)
        return sorted(cleaned)

    def to_number(self, value):
        """Parse numeric RSSI values; return None for empty/non-numeric data."""
        if value is None or value == "":
            return None
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        return int(number) if number.is_integer() else number

    def is_randomized_mac(self, mac):
        """Detect locally administered Wi-Fi MACs."""
        try:
            first_octet = int(str(mac).split(":", 1)[0], 16)
        except (TypeError, ValueError):
            return False
        return bool(first_octet & 0x02)

    def vendor_for(self, mac):
        """Return MAC OUI prefix for lightweight vendor comparison."""
        return normalize_oui(mac) or ""

    def vendor_prefix_for(self, mac):
        """Return the longest matched IEEE prefix, falling back to OUI."""
        return vendor_prefix(mac) or self.vendor_for(mac)
