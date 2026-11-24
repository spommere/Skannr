"""OpenDroneID broadcast framing and compact observation helpers.

This module decodes the public ASTM/OpenDroneID message fields used by the
Bluetooth service-data and Wi-Fi beacon transports. It does not verify the
claimed identity or authenticate a broadcast.
"""

import math
import time


REMOTE_ID_BLE_UUID = "0000fffa-0000-1000-8000-00805f9b34fb"
REMOTE_ID_WIFI_OUI = b"\xfa\x0b\xbc"
REMOTE_ID_WIFI_TYPE = 0x0D
ODID_MESSAGE_SIZE = 25


def bytes_value(value):
    """Normalize bytes-like or hexadecimal input to bytes."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        try:
            return bytes.fromhex(value.replace(":", "").replace(" ", ""))
        except ValueError:
            return b""
    try:
        return bytes(value)
    except (TypeError, ValueError):
        return b""


def normalize_uuid(value):
    """Return a normalized Bluetooth UUID string."""
    text = str(value or "").strip().lower()
    compact = text.replace("-", "")
    if len(compact) == 4:
        return "0000{}-0000-1000-8000-00805f9b34fb".format(compact)
    if len(compact) == 8:
        return "{}-0000-1000-8000-00805f9b34fb".format(compact)
    return text


def message_blocks(payload):
    """Extract 25-byte ODID messages from a raw or packed message payload."""
    payload = bytes_value(payload)
    if len(payload) == ODID_MESSAGE_SIZE:
        return [payload]
    blocks = []
    # Message Pack: 0xF message-type header, 25-byte message size, count.
    if len(payload) >= 3 and payload[0] >> 4 == 0xF:
        size = payload[1]
        count = min(payload[2], 9)
        if size == ODID_MESSAGE_SIZE and len(payload) >= 3 + size * count:
            for index in range(count):
                start = 3 + index * size
                blocks.append(payload[start : start + size])
    if not blocks and len(payload) % ODID_MESSAGE_SIZE == 0:
        for start in range(0, len(payload), ODID_MESSAGE_SIZE):
            block = payload[start : start + ODID_MESSAGE_SIZE]
            if block and block[0] >> 4 != 0xF:
                blocks.append(block)
    return blocks


def decode_message(message):
    """Decode recognized fields from one 25-byte OpenDroneID message."""
    message = bytes_value(message)
    if len(message) != ODID_MESSAGE_SIZE:
        return None
    message_type = (message[0] >> 4) & 0x0F
    result = {"message_type": message_type}
    if message_type == 0:  # Basic ID
        result["ua_type"] = message[1] & 0x0F
        result["id_type"] = (message[1] >> 4) & 0x0F
        uas_id = message[2:22].split(b"\x00", 1)[0].decode("ascii", "replace").strip()
        if uas_id:
            result["uas_id"] = uas_id[:20]
    elif message_type == 1:  # Location / vector
        status = (message[1] >> 4) & 0x0F
        if status != 15:
            latitude = int.from_bytes(message[5:9], "little", signed=True) / 1e7
            longitude = int.from_bytes(message[9:13], "little", signed=True) / 1e7
            if -90 <= latitude <= 90 and -180 <= longitude <= 180:
                result["latitude"] = latitude
                result["longitude"] = longitude
        altitude_baro_raw = int.from_bytes(message[13:15], "little")
        altitude_geo_raw = int.from_bytes(message[15:17], "little")
        height_raw = int.from_bytes(message[17:19], "little")
        altitude_baro = altitude_baro_raw * 0.5 - 1000
        altitude_geo = altitude_geo_raw * 0.5 - 1000
        height = height_raw * 0.5 - 1000
        multiplier = message[1] & 0x01
        speed_raw = message[3]
        speed = speed_raw * 0.25 if not multiplier else speed_raw * 0.75 + 63.75
        direction = message[2] + (180 if message[1] & 0x02 else 0)
        if direction <= 360 and direction != 255:
            result["track_deg"] = direction
        if speed_raw != 255:
            result["speed_mps"] = round(speed, 2)
        vertical_raw = int.from_bytes(message[4:5], "little", signed=True)
        if vertical_raw != -128:
            result["vertical_speed_mps"] = round(vertical_raw * 0.5, 1)
        for key, value in (
            ("altitude_baro_m", altitude_baro if altitude_baro_raw != 65535 else None),
            ("altitude_geo_m", altitude_geo if altitude_geo_raw != 65535 else None),
            ("height_m", height if height_raw != 65535 else None),
        ):
            if value is not None and value > -1000:
                result[key] = round(value, 1)
        timestamp = int.from_bytes(message[21:23], "little")
        if timestamp != 65535:
            result["timestamp_seconds"] = round(timestamp / 10.0, 1)
    elif message_type == 2:  # Authentication page; retained as unverified bytes.
        result["auth_type"] = (message[1] >> 4) & 0x0F
        result["auth_page"] = message[1] & 0x0F
        result["auth_data_hex"] = message[2:].hex().upper()
        result["auth_status"] = "unverified"
    elif message_type == 3:  # Self ID
        result["description_type"] = message[1] & 0x0F
        description = message[2:25].split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
        if description:
            result["description"] = description[:20]
    elif message_type == 4:  # System
        operator_lat = int.from_bytes(message[2:6], "little", signed=True) / 1e7
        operator_lon = int.from_bytes(message[6:10], "little", signed=True) / 1e7
        if -90 <= operator_lat <= 90 and -180 <= operator_lon <= 180:
            result["operator_latitude"] = operator_lat
            result["operator_longitude"] = operator_lon
    elif message_type == 5:  # Operator ID
        operator_id = message[2:22].split(b"\x00", 1)[0].decode("ascii", "replace").strip()
        if operator_id:
            result["operator_id"] = operator_id[:20]
    else:
        return None
    return result


def decode_ble_service_data(service_data):
    """Decode OpenDroneID service-data entries from Bleak AdvertisementData."""
    if not isinstance(service_data, dict):
        return []
    decoded = []
    for uuid, raw in service_data.items():
        if normalize_uuid(uuid) != REMOTE_ID_BLE_UUID:
            continue
        payloads = raw if isinstance(raw, (list, tuple)) else [raw]
        for payload_value in payloads:
            payload = bytes_value(payload_value)
            # Bluetooth service data begins with app code 0x0D and a rolling counter.
            if len(payload) < 2 or payload[0] != REMOTE_ID_WIFI_TYPE:
                continue
            for block in message_blocks(payload[2:]):
                item = decode_message(block)
                if item:
                    item["transport"] = "BLE"
                    decoded.append(item)
    return decoded


def decode_wifi_vendor_payload(payload):
    """Decode a Wi-Fi vendor-specific IE payload beginning with OUI/type."""
    payload = bytes_value(payload)
    if len(payload) < 5 or payload[:3] != REMOTE_ID_WIFI_OUI:
        return []
    if payload[3] != REMOTE_ID_WIFI_TYPE:
        return []
    decoded = []
    for block in message_blocks(payload[5:]):
        item = decode_message(block)
        if item:
            item["transport"] = "Wi-Fi Beacon"
            decoded.append(item)
    return decoded


class RemoteIDTracker:
    """Join message types from one transmitter into bounded live observations."""

    def __init__(self, event_interval_sec=5, max_age_sec=30):
        self.event_interval_sec = max(1.0, float(event_interval_sec))
        self.max_age_sec = max(5.0, float(max_age_sec))
        self.subjects = {}

    def observe(
        self, transmitter, messages, source, rssi=None, observer_location=None,
        store_observer_location=False, now=None,
    ):
        """Merge decoded message fields and return a rate-limited event payload."""
        now = time.time() if now is None else float(now)
        transmitter = str(transmitter or "unknown").upper()
        for key, value in list(self.subjects.items()):
            if now - value.get("last_message_epoch", now) > self.max_age_sec:
                self.subjects.pop(key, None)
        if len(self.subjects) >= 512 and transmitter not in self.subjects:
            oldest = min(
                self.subjects,
                key=lambda key: self.subjects[key].get("last_message_epoch", 0),
            )
            self.subjects.pop(oldest, None)
        state = self.subjects.get(transmitter)
        if state and now - state.get("last_message_epoch", 0) > self.max_age_sec:
            state = None
        if state is None:
            state = {"fields": {}, "track": [], "observer_track": [], "first_seen_epoch": now}
            self.subjects[transmitter] = state
        fields = state["fields"]
        got_position = False
        for message in messages or []:
            if not isinstance(message, dict):
                continue
            fields.update(message)
            if "latitude" in message and "longitude" in message:
                got_position = True
        if not messages:
            return None
        state["last_message_epoch"] = now
        state["last_rssi"] = rssi
        if got_position:
            state["last_position_epoch"] = now
            sample = {
                "timestamp_epoch": int(now),
                "latitude": fields.get("latitude"),
                "longitude": fields.get("longitude"),
            }
            for key, source_key in (("altitude_m", "altitude_geo_m"),):
                if fields.get(source_key) is not None:
                    sample[key] = fields[source_key]
            if not state["track"] or (
                sample["timestamp_epoch"] != state["track"][-1]["timestamp_epoch"]
                or sample["latitude"] != state["track"][-1]["latitude"]
                or sample["longitude"] != state["track"][-1]["longitude"]
            ):
                state["track"].append(sample)
                state["track"] = state["track"][-24:]
        if store_observer_location and isinstance(observer_location, dict):
            try:
                sample = {
                    "timestamp_epoch": int(now),
                    "latitude": float(observer_location["latitude"]),
                    "longitude": float(observer_location["longitude"]),
                }
            except (KeyError, TypeError, ValueError):
                sample = None
            if sample and (
                not state["observer_track"]
                or sample["timestamp_epoch"] != state["observer_track"][-1]["timestamp_epoch"]
            ):
                state["observer_track"].append(sample)
                state["observer_track"] = state["observer_track"][-24:]
        if now - state.get("last_emit_epoch", 0) < self.event_interval_sec:
            return None
        state["last_emit_epoch"] = now
        uas_id = fields.get("uas_id")
        result = dict(fields)
        result.update(
            {
                "transmitter": transmitter,
                "subject_key": uas_id or transmitter,
                "source": source,
                "rssi": rssi,
                "first_seen_epoch": int(state["first_seen_epoch"]),
                "last_seen_epoch": int(now),
                "seen_count": 1,
                "track": list(state["track"]),
            }
        )
        if got_position:
            result["position_count"] = 1
        if fields.get("latitude") is not None and fields.get("longitude") is not None:
            result["position_age_sec"] = max(0, int(now - state.get("last_position_epoch", now)))
            if result["position_age_sec"] > 5:
                result.pop("latitude", None)
                result.pop("longitude", None)
        if store_observer_location and isinstance(observer_location, dict):
            try:
                result["observer_latitude"] = float(observer_location["latitude"])
                result["observer_longitude"] = float(observer_location["longitude"])
            except (KeyError, TypeError, ValueError):
                pass
            result["observer_track"] = list(state["observer_track"])
        return clean_remote_id_data(result)


def clean_remote_id_data(data):
    """Keep bounded public Remote ID fields and optional location samples."""
    if not isinstance(data, dict):
        return {}
    text_fields = (
        "uas_id", "transmitter", "subject_key", "transport", "description",
        "operator_id", "source", "first_seen", "last_seen", "auth_data_hex",
        "auth_status",
    )
    number_fields = (
        "latitude", "longitude", "altitude_baro_m", "altitude_geo_m", "height_m",
        "track_deg", "speed_mps", "vertical_speed_mps", "distance_m",
        "observer_latitude", "observer_longitude", "position_age_sec",
        "first_seen_epoch", "last_seen_epoch", "seen_count", "position_count",
        "message_type", "ua_type", "id_type", "timestamp_epoch",
        "operator_latitude", "operator_longitude", "description_type",
        "auth_type", "auth_page",
        "rssi",
    )
    cleaned = {}
    for key in text_fields:
        value = data.get(key)
        if value not in (None, ""):
            cleaned[key] = " ".join(str(value).split())[:160]
    for key in number_fields:
        try:
            value = float(data.get(key))
        except (TypeError, ValueError):
            continue
        if not math.isfinite(value):
            continue
        if key in ("latitude", "observer_latitude", "operator_latitude") and not -90 <= value <= 90:
            continue
        if key in ("longitude", "observer_longitude", "operator_longitude") and not -180 <= value <= 180:
            continue
        cleaned[key] = int(value) if key in (
            "seen_count", "position_count", "message_type", "ua_type", "id_type",
            "first_seen_epoch", "last_seen_epoch", "timestamp_epoch",
            "description_type", "auth_type", "auth_page",
        ) else value
    for key in ("track", "observer_track"):
        samples = []
        for sample in data.get(key) or []:
            if not isinstance(sample, dict):
                continue
            try:
                epoch = int(float(sample.get("timestamp_epoch")))
                lat = float(sample.get("latitude"))
                lon = float(sample.get("longitude"))
            except (TypeError, ValueError):
                continue
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                continue
            item = {"timestamp_epoch": epoch, "latitude": lat, "longitude": lon}
            for field in ("altitude_m", "distance_m"):
                try:
                    item[field] = float(sample[field])
                except (KeyError, TypeError, ValueError):
                    pass
            samples.append(item)
        if samples:
            unique = {sample["timestamp_epoch"]: sample for sample in samples}
            cleaned[key] = [unique[epoch] for epoch in sorted(unique)[-24:]]
    return cleaned
