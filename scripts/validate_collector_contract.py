#!/usr/bin/env python3
"""Validate Skannr collector acquisition and identity contracts."""

import os
import sys
import glob
import logging
import time
import datetime


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from skannr.alerts import AlertEngine
from skannr.collectors.metadata import (
    ACQUISITION_LISTEN,
    ACQUISITION_POLL,
    ACQUISITION_SCAN,
    acquisition_mode,
    all_source_definitions,
    collector_definitions,
)
from skannr.collectors.ble import BLECollector
from skannr.collectors.noaa import stable_noaa_event_key
from skannr.collectors.pws import PWSCollector
from skannr.collectors.swpc import SWPCCollector, clean_swpc_data
from skannr.collectors.usgs import USGSCollector
from skannr.log_utils import format_epoch
from skannr.reports import ReportsBuilder
from skannr.subject_history import SubjectHistoryBuilder


def assert_equal(actual, expected, label):
    if actual != expected:
        raise AssertionError("{}: expected {!r}, got {!r}".format(label, expected, actual))


def assert_not_equal(left, right, label):
    if left == right:
        raise AssertionError("{}: both values were {!r}".format(label, left))


def test_ble_findmy_payload_detection():
    class Advertisement:
        manufacturer_data = {0x004C: b"\x12\x34\xAB\xCD\x00"}

    fields = BLECollector({}, None).findmy_accessory_fields(Advertisement())
    assert_equal(fields.get("findmy_accessory"), True, "BLE Find My marker")
    assert_equal(
        fields.get("findmy_payload_type"),
        "0x12",
        "BLE Find My payload type",
    )
    assert_equal(fields.get("findmy_status"), "0x34", "BLE Find My status")
    assert_equal(fields.get("findmy_hint"), "0xABCD", "BLE Find My hint")

    alert = AlertEngine({}).process(
        {
            "collector": "ble",
            "type": "device_seen",
            "data": {
                "mac": "AA:BB:CC:DD:EE:FF",
                "rssi": -55,
                "manufacturer": "Apple, Inc. (0x004C)",
                **fields,
            },
        },
        emit=True,
    )
    assert_equal(len(alert), 1, "BLE Find My tracker alert emits")
    assert_equal(
        alert[0]["data"]["evidence"].get("findmy_accessory"),
        True,
        "BLE Find My alert evidence",
    )


def test_acquisition_modes():
    expected = {
        "wifi": ACQUISITION_SCAN,
        "wifi_monitor": ACQUISITION_LISTEN,
        "ble": ACQUISITION_SCAN,
        "bt_classic": ACQUISITION_SCAN,
        "rtlsdr": ACQUISITION_SCAN,
        "rayhunter": ACQUISITION_POLL,
        "aprsis": ACQUISITION_LISTEN,
        "noaa": ACQUISITION_POLL,
        "usgs": ACQUISITION_POLL,
        "swpc": ACQUISITION_POLL,
        "pws": ACQUISITION_SCAN,
        "lan": ACQUISITION_SCAN,
    }
    actual = {
        item["key"]: item["acquisition_mode"]
        for item in collector_definitions({}, include_system=False)
    }
    for key, mode in expected.items():
        assert_equal(actual.get(key), mode, "collector acquisition mode {}".format(key))
    sources = {
        item["key"]: item
        for item in all_source_definitions({}, include_system=False)
    }
    assert_equal(
        sources["ble_identify"]["acquisition_mode"],
        ACQUISITION_SCAN,
        "BLE Identify action acquisition mode",
    )
    assert_equal(
        sources["ble_identify"]["source_group"],
        "bluetooth",
        "BLE Identify action source group",
    )
    assert_equal(acquisition_mode("unexpected", ACQUISITION_POLL), ACQUISITION_POLL, "invalid mode fallback")


def test_config_templates_do_not_expose_subject_history_flag():
    for path in glob.glob(os.path.join(ROOT, "config.example", "collectors", "*.yaml")):
        with open(path, "r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if line.strip().startswith("has_subject_history:"):
                    raise AssertionError(
                        "{}:{}: has_subject_history is internal metadata".format(
                            os.path.relpath(path, ROOT), line_number
                        )
                    )


def test_noaa_identity():
    forecast_11 = {
        "source": "NHC",
        "basin": "eastern_pacific",
        "event": "Tropical Storm Amanda Forecast Advisory Number 11",
        "summary": "EP012026",
    }
    forecast_12 = {
        "source": "NHC",
        "basin": "eastern_pacific",
        "event": "Tropical Storm Amanda Forecast Advisory Number 12",
        "summary": "EP012026",
    }
    wind_11 = {
        "source": "NHC",
        "basin": "eastern_pacific",
        "event": "Tropical Storm Amanda Wind Speed Probabilities Number 11",
        "summary": "EP012026",
    }
    outlook_old = {
        "source": "NHC",
        "basin": "central_pacific",
        "event": "Tropical Weather Outlook",
        "summary": "There are no tropical cyclones at this time.",
        "source_url": "https://www.nhc.noaa.gov/text/old.shtml",
    }
    outlook_new = {
        "source": "NHC",
        "basin": "central_pacific",
        "event": "Tropical Weather Outlook",
        "summary": "There are no tropical cyclones at this time.",
        "source_url": "https://www.nhc.noaa.gov/text/new.shtml",
    }
    beach_sf = {
        "source": "NWS",
        "area_desc": "San Francisco",
        "event": "Beach Hazards Statement",
    }
    beach_sc = {
        "source": "NWS",
        "area_desc": "Santa Cruz",
        "event": "Beach Hazards Statement",
    }
    tsunami_info = {
        "source": "NTWC",
        "alert_kind": "tsunami",
        "incident_id": "tgacbc",
        "event": "Tsunami Information",
        "headline": "Tsunami Information Statement Number 2",
        "area_desc": "Mindanao, Philippine Islands",
        "severity": "Minor",
    }
    tsunami_update = {
        **tsunami_info,
        "headline": "Tsunami Information Statement Number 3",
        "message_number": "3",
    }
    tsunami_warning = {
        **tsunami_info,
        "event": "Tsunami Warning",
        "headline": "Tsunami Warning Number 1",
        "severity": "Severe",
    }

    forecast_11_key = stable_noaa_event_key(forecast_11, "noaa_tropical_advisory")
    assert_equal(
        forecast_11_key,
        "nhc:eastern_pacific:amanda:advisory-11",
        "NHC advisory package subject key",
    )
    assert_not_equal(
        forecast_11_key,
        stable_noaa_event_key(forecast_12, "noaa_tropical_advisory"),
        "NHC advisory number separates subjects",
    )
    assert_equal(
        forecast_11_key,
        stable_noaa_event_key(wind_11, "noaa_tropical_advisory"),
        "NHC product family collapses within one advisory package",
    )
    assert_equal(
        stable_noaa_event_key(outlook_old, "noaa_tropical_advisory"),
        stable_noaa_event_key(outlook_new, "noaa_tropical_advisory"),
        "generic NHC outlook URL churn does not create new subject",
    )
    assert_not_equal(
        stable_noaa_event_key(beach_sf, "noaa_weather_alert"),
        stable_noaa_event_key(beach_sc, "noaa_weather_alert"),
        "NWS event+area separates subjects",
    )
    assert_equal(
        stable_noaa_event_key(tsunami_info, "noaa_tsunami_alert"),
        stable_noaa_event_key(tsunami_update, "noaa_tsunami_alert"),
        "tsunami.gov message updates collapse by incident ID",
    )

    engine = AlertEngine({})
    now = int(time.time())
    assert_equal(
        engine.noaa_alert_key("noaa_tropical_advisory", forecast_11, "unused"),
        "noaa-hazard:{}".format(forecast_11_key),
        "NOAA alert key follows subject key",
    )
    assert_equal(
        engine.noaa_matches_alert(tsunami_info, {}),
        False,
        "tsunami information statements do not alert",
    )
    assert_equal(
        engine.noaa_matches_alert(tsunami_warning, {}),
        True,
        "tsunami warning statements alert",
    )
    persisted_key = "noaa-hazard:{}".format(forecast_11_key)
    engine.load_state(
        {
            "active": [
                {
                    "id": persisted_key,
                    "alert_type": "noaa_hazard",
                    "level": "warning",
                    "source": "NHC",
                    "title": "NHC hazard",
                    "subject": forecast_11["event"],
                    "summary": "NHC: {}".format(forecast_11["event"]),
                    "first_seen_epoch": now - 10,
                    "last_seen_epoch": now - 10,
                    "evidence": {
                        "source": "NHC",
                        "event": forecast_11["event"],
                        "headline": forecast_11["event"],
                        "area_desc": "Eastern Pacific",
                        "alert_kind": "tropical",
                    },
                }
            ]
        }
    )
    engine.process(
        {
            "collector": "noaa",
            "type": "noaa_tropical_advisory",
            "timestamp_epoch": now,
            "data": {
                **forecast_11,
                "alert_kind": "tropical",
                "basin": "eastern_pacific",
                "source": "NHC",
            },
        },
        emit=True,
    )
    assert_equal(
        sorted(engine.active.keys()),
        [persisted_key],
        "Persisted NHC alert area labels collapse into current basin key",
    )


def test_noaa_ack_survives_restart_for_same_item():
    now = int(time.time())
    advisory = {
        "source": "NHC",
        "basin": "eastern_pacific",
        "event": "Tropical Storm Amanda Public Advisory Number 10",
        "headline": "Tropical Storm Amanda Public Advisory Number 10",
        "alert_kind": "tropical",
        "summary": "Issued at 800 PM PDT Thu Jun 04 2026",
        "updated": "Fri, 05 Jun 2026 02:32:13 GMT",
        "source_url": "https://www.nhc.noaa.gov/text/refresh/MIATCPEP1+shtml/050232.shtml",
    }
    first = AlertEngine({})
    emitted = first.process(
        {
            "collector": "noaa",
            "type": "noaa_tropical_advisory",
            "timestamp_epoch": now,
            "data": advisory,
        },
        emit=True,
    )
    assert_equal(len(emitted), 1, "NOAA first alert emits")
    alert_id = emitted[0]["data"]["id"]
    first.ack(alert_id)
    state = first.export_state()

    second = AlertEngine({})
    second.load_state(state)
    emitted = second.process(
        {
            "collector": "noaa",
            "type": "noaa_tropical_advisory",
            "timestamp_epoch": now + 60,
            "data": advisory,
        },
        emit=True,
    )
    assert_equal(emitted, [], "ACKed NOAA restart duplicate does not emit")
    assert_equal(
        second.active[alert_id]["acked"],
        True,
        "ACKed NOAA restart duplicate stays ACKed",
    )
    assert_equal(
        second.active[alert_id]["count"],
        1,
        "ACKed NOAA restart duplicate does not increment Seen",
    )


def test_disabled_nhc_suppresses_noaa_alerts():
    now = int(time.time())
    advisory = {
        "source": "NHC",
        "basin": "eastern_pacific",
        "event": "Tropical Storm Amanda Public Advisory Number 10",
        "headline": "Tropical Storm Amanda Public Advisory Number 10",
        "alert_kind": "tropical",
        "summary": "Issued at 800 PM PDT Thu Jun 04 2026",
        "updated": "Fri, 05 Jun 2026 02:32:13 GMT",
        "source_url": "https://www.nhc.noaa.gov/text/refresh/MIATCPEP1+shtml/050232.shtml",
    }
    enabled = AlertEngine({})
    emitted = enabled.process(
        {
            "collector": "noaa",
            "type": "noaa_tropical_advisory",
            "timestamp_epoch": now,
            "data": advisory,
        },
        emit=True,
    )
    assert_equal(len(emitted), 1, "NHC advisory normally alerts")
    alert_id = emitted[0]["data"]["id"]

    disabled = AlertEngine({"_disabled_noaa_sources": ["nhc"]})
    emitted = disabled.process(
        {
            "collector": "noaa",
            "type": "noaa_tropical_advisory",
            "timestamp_epoch": now,
            "data": advisory,
        },
        emit=True,
    )
    assert_equal(emitted, [], "Disabled NHC live advisory does not alert")
    disabled.load_state(
        {
            "active": [
                {
                    "id": alert_id,
                    "alert_type": "noaa_hazard",
                    "level": "warning",
                    "source": "NHC",
                    "title": "NHC hazard",
                    "subject": advisory["event"],
                    "summary": "NHC: {}".format(advisory["event"]),
                    "first_seen_epoch": now - 10,
                    "last_seen_epoch": now - 10,
                    "evidence": {
                        "source": "NHC",
                        "event": advisory["event"],
                        "headline": advisory["headline"],
                        "area_desc": "Eastern Pacific",
                        "basin": "eastern_pacific",
                        "alert_kind": "tropical",
                    },
                }
            ]
        }
    )
    assert_equal(disabled.active, {}, "Disabled NHC restored alert is dropped")


def assert_poll_alert_ack_memory(event, expected_type, label):
    now = int(time.time())
    first = AlertEngine({"ack_memory_alert_types": []})
    emitted = first.process({**event, "timestamp_epoch": now}, emit=True)
    assert_equal(len(emitted), 1, "{} first alert emits".format(label))
    alert_id = emitted[0]["data"]["id"]
    assert_equal(
        emitted[0]["data"]["alert_type"],
        expected_type,
        "{} alert type".format(label),
    )
    first.ack(alert_id)
    state = first.export_state()
    state["active"] = []

    second = AlertEngine({"ack_memory_alert_types": []})
    second.load_state(state)
    emitted = second.process({**event, "timestamp_epoch": now + 60}, emit=True)
    assert_equal(emitted, [], "{} ACK memory suppresses restart duplicate".format(label))
    assert_equal(
        second.active[alert_id]["acked"],
        True,
        "{} restored from ACK memory as ACKed".format(label),
    )


def test_poll_alert_ack_memory_defaults():
    assert_poll_alert_ack_memory(
        {
            "collector": "usgs",
            "type": "usgs_earthquake",
            "data": {
                "event_id": "us-test-ack",
                "magnitude": 5.1,
                "place": "10 km S of Testville",
                "distance_km": 10,
                "event_time": "2026-06-05T10:00:00Z",
            },
        },
        "usgs_earthquake",
        "USGS poll alert",
    )
    assert_poll_alert_ack_memory(
        {
            "collector": "swpc",
            "type": "swpc_event",
            "data": {
                "event_id": "swpc-r3-test-ack",
                "event_kind": "radio_blackout",
                "event": "Radio blackout",
                "summary": "R3 radio blackout observed",
                "scale_family": "R",
                "scale_value": 3,
                "scale_label": "R3",
                "event_time": "2026-06-05T10:00:00Z",
                "source": "SWPC",
            },
        },
        "swpc_space_weather",
        "SWPC poll alert",
    )


def test_poll_event_fingerprints():
    usgs = USGSCollector({"latitude": 0, "longitude": 0}, None)
    usgs_fields = (
        "event_time_epoch",
        "magnitude",
        "place",
        "updated_epoch",
        "status",
        "felt",
        "cdi",
        "mmi",
        "alert_color",
        "tsunami",
    )
    assert_not_equal(
        usgs.fingerprint({"event_time_epoch": 100, "magnitude": 5.1}, usgs_fields),
        usgs.fingerprint({"event_time_epoch": 200, "magnitude": 5.1}, usgs_fields),
        "USGS fingerprint includes event time",
    )

    swpc = SWPCCollector({}, None)
    swpc_fields = (
        "event_kind",
        "event_time_epoch",
        "summary",
        "message",
        "scale_family",
        "scale_value",
        "xray_class",
    )
    assert_not_equal(
        swpc.fingerprint(
            {"event_kind": "radio_blackout", "event_time_epoch": 100, "scale_family": "R", "scale_value": 3},
            swpc_fields,
        ),
        swpc.fingerprint(
            {"event_kind": "radio_blackout", "event_time_epoch": 200, "scale_family": "R", "scale_value": 3},
            swpc_fields,
        ),
        "SWPC product fingerprint includes event time",
    )


def test_swpc_scale_label_backfill():
    for family, expected in (("G", "G3"), ("R", "R3"), ("S", "S3")):
        data = clean_swpc_data(
            {
                "event_kind": "swpc_product",
                "scale_family": family,
                "scale_value": 3,
                "summary": "{}3 test event".format(family),
            }
        )
        assert_equal(
            data.get("scale_label"),
            expected,
            "SWPC {} scale label backfill".format(family),
        )


def test_swpc_partial_feed_failure():
    class PartialSWPCCollector(SWPCCollector):
        def feed_sources(self):
            return [
                {"name": "alerts", "kind": "alerts"},
                {"name": "planetary_k", "kind": "planetary_k"},
            ]

        def poll_alert_products(self):
            raise RuntimeError("alerts unavailable")

        def poll_planetary_k(self):
            return [{"event_id": "kp-ok", "fingerprint": "kp-ok"}]

    collector = PartialSWPCCollector({}, None)
    logging.disable(logging.CRITICAL)
    try:
        events = collector.poll_once()
    finally:
        logging.disable(logging.NOTSET)
    assert_equal(len(events), 1, "SWPC partial feed failure keeps successful events")
    assert_equal(
        collector._last_subfeed_errors,
        ["alerts: alerts unavailable"],
        "SWPC partial feed failure records warning text",
    )


def test_pws_ambient_sample_normalization():
    sample = {
        "macAddress": "E8:DB:84:E4:03:A2",
        "lastData": {
            "dateutc": 1780702860000,
            "tempinf": 77.9,
            "battin": 1,
            "humidityin": 74,
            "baromrelin": 30.092,
            "baromabsin": 28.553,
            "tempf": 74.5,
            "battout": 1,
            "humidity": 86,
            "winddir": 262,
            "winddir_avg10m": 223,
            "windspeedmph": 0,
            "windspdmph_avg10m": 1.1,
            "windgustmph": 2.2,
            "maxdailygust": 6.9,
            "hourlyrainin": 0,
            "eventrainin": 0.1,
            "dailyrainin": 0.01,
            "weeklyrainin": 0.4,
            "monthlyrainin": 0.4,
            "yearlyrainin": 29.63,
            "solarradiation": 84.53,
            "uv": 0,
            "batt_co2": 1,
            "feelsLike": 75.69,
            "dewPoint": 70.03,
            "feelsLikein": 78.9,
            "dewPointin": 68.9,
            "lastRain": "2026-06-05T15:30:00.000Z",
            "tz": "Pacific/Honolulu",
            "date": "2026-06-05T23:41:00.000Z",
        },
        "info": {
            "name": "KHIKAILU239",
            "coords": {
                "coords": {"lon": -155.978209, "lat": 19.706678},
                "address": "73-1222 Akamai St, Kailua-Kona, HI 96740, USA",
                "location": "Kailua-Kona",
                "elevation": 449.2904052734375,
            },
        },
    }
    collector = PWSCollector({"station_id": "GW0154"}, None)
    data = collector.weather_data(sample, 0, 1)
    assert_equal(data["station_id"], "GW0154", "PWS configured station ID")
    assert_equal(data["latitude"], 19.706678, "PWS nested latitude")
    assert_equal(data["longitude"], -155.978209, "PWS nested longitude")
    assert_equal(data["rain_1h_in"], 0.0, "PWS hourly rain rate")
    assert_equal(data["indoor_temperature_f"], 77.9, "PWS indoor temperature")
    assert_equal(data["rain_year_in"], 29.63, "PWS yearly rain total")
    assert_equal(
        data["ambient_date"],
        format_epoch(data["ambient_date_epoch"]),
        "PWS Ambient API date is local display time",
    )
    assert_equal(
        data["last_rain_time"],
        format_epoch(data["last_rain_epoch"]),
        "PWS last rain is local display time",
    )
    if "address" in data:
        raise AssertionError("PWS data must not retain Ambient street address")


def test_pws_period_rollups():
    def epoch(year, month, day, hour):
        dt = datetime.datetime(year, month, day, hour, 0, 0)
        return int(time.mktime(dt.timetuple()))

    def event(ts, temp, rain_rate, daily_rain, pressure, gust):
        return {
            "collector": "pws",
            "type": "pws_weather",
            "timestamp": format_epoch(ts),
            "timestamp_epoch": ts,
            "severity": "info",
            "data": {
                "station_id": "GW0154",
                "station_name": "GW0154",
                "event_time": format_epoch(ts),
                "event_time_epoch": ts,
                "temperature_f": temp,
                "humidity_percent": 80,
                "pressure_rel_inhg": pressure,
                "wind_speed_mph": 3,
                "wind_gust_mph": gust,
                "rain_1h_in": rain_rate,
                "rain_day_in": daily_rain,
                "source": "Ambient Weather",
            },
        }

    observations = [
        event(epoch(2026, 6, 1, 10), 70, 0.0, 0.0, 30.00, 5),
        event(epoch(2026, 6, 1, 11), 74, 0.2, 0.1, 29.95, 9),
        event(epoch(2026, 6, 2, 10), 78, 0.0, 0.2, 29.90, 12),
    ]
    events, records = SubjectHistoryBuilder("/tmp").build_pws_history(
        observations, None
    )
    assert_equal(records, 3, "PWS rollup record count")
    weekly = [
        (item.get("data") or {})
        for item in events
        if item.get("type") == "pws_weather_period_summary"
        and (item.get("data") or {}).get("period_kind") == "weekly"
    ]
    assert_equal(len(weekly), 1, "PWS weekly rollup count")
    assert_equal(weekly[0].get("sample_count"), 3, "PWS weekly sample count")
    assert_equal(weekly[0].get("coverage_days"), 2, "PWS weekly coverage days")
    assert_equal(
        weekly[0].get("rain_period_total_in"), 0.3, "PWS weekly rain total"
    )
    assert_equal(
        weekly[0].get("temperature_change_f"), 8.0, "PWS weekly temp change"
    )
    reports = ReportsBuilder().pws_reports(
        events, format_epoch(epoch(2026, 6, 2, 12))
    )
    if not any(report.get("type") == "pws_weather_weekly_pattern" for report in reports):
        raise AssertionError("PWS weekly report missing")


def test_feed_period_rollup_reports():
    ts = format_epoch(int(time.mktime(datetime.datetime(2026, 6, 8, 12, 0, 0).timetuple())))
    generated = format_epoch(
        int(time.mktime(datetime.datetime(2026, 6, 8, 12, 5, 0).timetuple()))
    )
    builder = ReportsBuilder()

    aprs_reports = builder.aprsis_reports(
        [
            {
                "collector": "aprsis",
                "type": "aprsis_weather_period_summary",
                "timestamp": ts,
                "timestamp_epoch": int(time.time()),
                "data": {
                    "callsign": "GW0154",
                    "period_kind": "weekly",
                    "period_label": "week 2026-W23",
                    "sample_count": 3,
                    "coverage_days": 2,
                    "temperature_min_f": 70,
                    "temperature_max_f": 78,
                    "temperature_change_f": 8,
                    "rain_1h_max_in": 0.4,
                    "wind_gust_max_mph": 18,
                    "pressure_min_hpa": 1010.1,
                    "pressure_max_hpa": 1012.2,
                    "pressure_change_hpa": 1.1,
                    "last_seen": ts,
                },
            }
        ],
        generated,
    )
    if not any(
        report.get("type") == "aprsis_weather_weekly_pattern"
        for report in aprs_reports
    ):
        raise AssertionError("APRS weather weekly report missing")

    noaa_reports = builder.noaa_reports(
        [
            {
                "collector": "noaa",
                "type": "noaa_period_summary",
                "timestamp": ts,
                "data": {
                    "period_kind": "monthly",
                    "period_label": "2026-06",
                    "event_count": 3,
                    "tropical_system_count": 1,
                    "nws_hazard_count": 1,
                    "tsunami_incident_count": 1,
                    "forecast_count": 1,
                    "tropical_systems": ["Amanda"],
                    "basins": ["eastern_pacific"],
                    "sources": ["NHC", "NWS", "PTWC"],
                    "last_seen": ts,
                },
            }
        ],
        generated,
    )
    if not any(report.get("type") == "noaa_monthly_pattern" for report in noaa_reports):
        raise AssertionError("NOAA monthly report missing")

    usgs_reports = builder.usgs_reports(
        [
            {
                "collector": "usgs",
                "type": "usgs_earthquake_period_summary",
                "timestamp": ts,
                "data": {
                    "period_kind": "weekly",
                    "period_label": "week 2026-W23",
                    "event_count": 2,
                    "local_count": 1,
                    "global_major_count": 1,
                    "notable_count": 1,
                    "tsunami_count": 1,
                    "magnitude_min": 4.2,
                    "magnitude_max": 7.1,
                    "nearest_distance_km": 80,
                    "shallowest_depth_km": 10,
                    "event_ids": ["us-test"],
                    "last_seen": ts,
                },
            }
        ],
        generated,
    )
    if not any(
        report.get("type") == "usgs_earthquake_weekly_pattern"
        for report in usgs_reports
    ):
        raise AssertionError("USGS weekly report missing")

    swpc_reports = builder.swpc_reports(
        [
            {
                "collector": "swpc",
                "type": "swpc_event_period_summary",
                "timestamp": ts,
                "data": {
                    "period_kind": "weekly",
                    "period_label": "week 2026-W23",
                    "event_count": 2,
                    "alert_count": 1,
                    "critical_count": 1,
                    "xray_flare_count": 1,
                    "geomagnetic_storm_count": 1,
                    "highest_xray_class": "X1.2",
                    "max_kp": 7.0,
                    "max_geomagnetic_storm_label": "G3",
                    "kind_counts": ["xray_flare 1", "geomagnetic_storm 1"],
                    "last_seen": ts,
                },
            }
        ],
        generated,
    )
    if not any(
        report.get("type") == "swpc_space_weather_weekly_pattern"
        for report in swpc_reports
    ):
        raise AssertionError("SWPC weekly report missing")

    swpc_history, records_read = SubjectHistoryBuilder("/tmp").build_swpc_history(
        [
            {
                "collector": "swpc",
                "type": "swpc_event",
                "timestamp": ts,
                "timestamp_epoch": int(time.time()),
                "data": {
                    "event_id": "swpc-x1-test",
                    "event_kind": "xray_flare",
                    "event": "X-class solar flare",
                    "event_time": ts,
                    "event_time_epoch": int(time.time()),
                    "xray_class": "X1.2",
                    "summary": "X1.2 flare",
                    "source": "SWPC",
                    "source_url": "https://services.swpc.noaa.gov/",
                },
            },
            {
                "collector": "swpc",
                "type": "swpc_event",
                "timestamp": ts,
                "timestamp_epoch": int(time.time()),
                "data": {
                    "event_id": "swpc-g3-test",
                    "event_kind": "geomagnetic_storm",
                    "event": "Geomagnetic storm",
                    "event_time": ts,
                    "event_time_epoch": int(time.time()),
                    "scale_family": "G",
                    "scale_value": 3,
                    "scale_label": "G3",
                    "kp_index": 7,
                    "summary": "G3 storm",
                    "source": "SWPC",
                    "source_url": "https://services.swpc.noaa.gov/",
                },
            },
        ],
        None,
    )
    assert_equal(records_read, 2, "SWPC rollup source records")
    if not any(
        item.get("type") == "swpc_event_period_summary"
        and (item.get("data") or {}).get("period_kind") == "weekly"
        and (item.get("data") or {}).get("kind_counts")
        for item in swpc_history
    ):
        raise AssertionError("SWPC Subject History weekly period row missing")


def main():
    test_ble_findmy_payload_detection()
    test_acquisition_modes()
    test_config_templates_do_not_expose_subject_history_flag()
    test_noaa_identity()
    test_noaa_ack_survives_restart_for_same_item()
    test_disabled_nhc_suppresses_noaa_alerts()
    test_poll_alert_ack_memory_defaults()
    test_poll_event_fingerprints()
    test_swpc_scale_label_backfill()
    test_swpc_partial_feed_failure()
    test_pws_ambient_sample_normalization()
    test_pws_period_rollups()
    test_feed_period_rollup_reports()
    print("collector contract ok")


if __name__ == "__main__":
    main()
