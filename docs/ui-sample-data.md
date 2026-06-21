# Fake UI Sample Data

Generated from the event shapes observed in `/tmp/pi4` and `/tmp/hampi4`, but all values below are fictional. Do not replace these examples with raw collector values from a live site. Use RFC 5737 example IP ranges, locally administered fake MAC addresses, generic coordinates, and invented callsigns, IDs, SSIDs, hostnames, and annotations.

## Sampling Coverage

The source logs contained representative events for these Skannr collectors and derived views:

| Area | Covered by sample source |
| --- | --- |
| Wi-Fi scan | access points, stations, RSSI, channel, SSID/BSSID, randomized clients |
| Wi-Fi monitor | probe, association, deauthentication/disassociation style client observations |
| Bluetooth LE | advertisements, manufacturer/service identity, Apple manufacturer-only and Find My accessory buckets |
| LAN | ARP/neighbor/host observations, identified hosts, low-identity private MAC grouping |
| RTL-433 | decoded device events, tuned frequency, RSSI/SNR/noise, frequency-plan metadata |
| ADS-B | aircraft subjects and track summaries |
| APRS-IS | station subjects and packet summaries |
| NOAA, SWPC, USGS, PWS | weather, space-weather, earthquake, and local station report summaries |
| Rayhunter | cellular collection health and findings |

## Live Feed Samples

These rows are intended for screenshots or docs that explain the live collector feeds. They should look like current UI rows, not fixtures to import into runtime logs.

| Collector | Last Seen | Subject | Category | Frequency / Signal | Details |
| --- | --- | --- | --- | --- | --- |
| Wi-Fi scan | 2026-06-12 09:14:03 | `ExampleNet-Office` | access point | ch 6; RSSI -47 dBm | BSSID `02:AA:BB:10:20:30`, security WPA2/WPA3, vendor Example Networks |
| Wi-Fi monitor | 2026-06-12 09:14:10 | `Randomized Wi-Fi clients` | client group | RSSI -61 to -72 dBm | 37 locally administered client MACs probed `ExampleNet-Guest` |
| Bluetooth LE | 2026-06-12 09:14:15 | `Apple Find My accessory group` | device group | RSSI -68 dBm | 12 private addresses with Find My identity fingerprint |
| Bluetooth LE | 2026-06-12 09:14:18 | `Example Beacon 7` | device | RSSI -59 dBm | services `180F`, manufacturer Example Labs, annotation `warehouse sensor` |
| LAN | 2026-06-12 09:14:22 | `sample-host-4` | host | `192.0.2.44` | MAC `02:11:22:33:44:04`, mDNS name `sample-host-4.local` |
| RTL-433 | 2026-06-12 09:14:35 | `Springfield-SoilId 1234` | device | tuned 915.000 MHz; RSSI -11.2 dB; SNR 10.7 dB | moisture 38%, temperature 21.4 C, protocol 142 |
| ADS-B | 2026-06-12 09:14:41 | `ABC123` | aircraft | altitude 7,800 ft; speed 214 kt | callsign `SKN123`, distance 12.4 km, heading 281 deg |
| APRS-IS | 2026-06-12 09:14:50 | `N0CALL-7` | station | packet path `WIDE1-1,WIDE2-1` | comment `Example mobile station`, distance 4.8 km |
| NOAA | 2026-06-12 09:15:00 | `Example County Forecast` | weather | station `KXYZ` | advisory summary updated, expires 2026-06-12 18:00 |
| USGS | 2026-06-12 09:15:12 | `M2.4 Example Ridge` | earthquake | depth 8.2 km | 37.123, -122.456, reviewed |
| SWPC | 2026-06-12 09:15:18 | `K-index watch` | space weather | Kp 4 | minor geomagnetic activity possible |
| PWS | 2026-06-12 09:15:21 | `PWS-Example-1` | weather station | 20.8 C; humidity 56% | wind 7 kt from 240 deg, pressure 1016 hPa |
| Rayhunter | 2026-06-12 09:15:30 | `cellular-monitor` | collector | LTE band sample | 1 warning finding, modem online |

## Subject History Samples

Subject History should show durable subjects. For collectors that produce many randomized identifiers, the durable subject is a grouped identity rather than each short-lived address.

| Collector | Subject column | Identity / key | Last seen | Counts | Notes |
| --- | --- | --- | --- | --- | --- |
| Wi-Fi scan | `Office AP` `ExampleNet-Office` | SSID `ExampleNet-Office`, BSSID `02:AA:BB:10:20:30` | 2026-06-12 09:14:03 | 184 seen | Annotation is shown before the true subject; link still uses the original subject |
| Wi-Fi monitor | `Randomized Wi-Fi clients` | probe fingerprint `apple-private-probers` | 2026-06-12 09:14:10 | 4934 randomized clients | One grouped row, not thousands of locally administered MAC rows |
| Bluetooth | `Apple manufacturer-only devices` | manufacturer bucket `apple-generic-private` | 2026-06-12 09:14:12 | 312 randomized devices | Kept separate from Find My because the identity means something different |
| Bluetooth | `Apple Find My accessory group` | service/manufacturer bucket `apple-findmy-private` | 2026-06-12 09:14:15 | 19 randomized devices | One row for the Find My accessory identity group |
| Bluetooth | `warehouse sensor` `Example Beacon 7` | MAC `02:55:66:77:88:07`, services `180F` | 2026-06-12 09:14:18 | 44 BLE updates | User annotation survives log pruning |
| LAN | `sample-host-4` | IP `192.0.2.44`, MAC `02:11:22:33:44:04` | 2026-06-12 09:14:22 | 28 seen | Hostname and MAC are visible when stable |
| LAN | `Private LAN clients` | locally administered MAC bucket | 2026-06-12 09:14:26 | 84 low-identity clients | Grouped only when host identity is weak |
| RTL-433 | `Springfield-SoilId 1234` | model `Springfield-Soil`, id `1234` | 2026-06-12 09:14:35 | 6 decoded events | Frequency / Signal shows tuned dongle frequency when present |
| ADS-B | `SKN123` | ICAO `ABC123` | 2026-06-12 09:14:41 | 833 reports | Distinct aircraft remain distinct subjects |
| APRS-IS | `N0CALL-7` | callsign `N0CALL-7` | 2026-06-12 09:14:50 | 31 packets | APRS station can later support annotation if needed |

## Insight Samples

| Severity | Source | Title | Detail | Evidence |
| --- | --- | --- | --- | --- |
| warning | Wi-Fi monitor | High randomized client activity | 4934 locally administered client addresses were grouped into 1 durable Wi-Fi client identity. | 8 probe SSIDs, RSSI range -48 to -82 dBm |
| info | Bluetooth | Apple Find My accessory observed | Find My accessory identity group seen repeatedly with private BLE addresses. | 19 addresses, manufacturer Apple, service fingerprint present |
| info | RTL-433 | Soil sensor active on 915 MHz | Springfield soil sensor decoded while dongle reported tuned frequency 915.000 MHz. | RSSI -11.2 dB, SNR 10.7 dB, 6 events |
| info | ADS-B | Busy local aircraft picture | 833 ADS-B reports rolled into 871 aircraft subjects in the current history window. | altitude and callsign fields present |
| warning | Rayhunter | Cellular monitor finding | Collector reported a modem/network condition that should be reviewed. | finding id `sample-rayhunter-1` |

## Report Samples

Reports are the higher-level intelligence product. They should be regenerated from Subject History and Insights, not independently re-parse collector-specific special cases. The current UI renders cross-subject patterns and subject reports in separate sections with the same columns. The `Report` cell shows source on the first line and report title on the next line. The `Subject` cell shows the hyperlinked subject on the first line and the summary below it.

| Subject | Report | Score | Confidence | Reasons | Evidence | Last Seen |
| --- | --- | ---: | --- | --- | --- | --- |
| 90 | High | randomized, population | Wi-Fi/BLE<br>Cross-subject pattern | `Randomized nearby devices`<br>Wi-Fi and BLE both show high randomized-device activity; grouped identities prevent noisy per-MAC rows. | Pattern: many private Wi-Fi and BLE identities; Observed: 4934 Wi-Fi clients, 312 Bluetooth devices | 2026-06-12 09:14:15 |
| 82 | High | identity, private-address | Bluetooth<br>Bluetooth identity | `Apple Find My accessory group`<br>Find My identity was observed across multiple private addresses and should be treated separately from generic Apple advertisements. | Identity: Apple Find My accessory; Activity: 19 private addresses; Signal: -82 to -55 dBm | 2026-06-12 09:14:15 |
| 76 | Medium | recurring, rf | RTL-433<br>RF device | `Springfield-SoilId 1234`<br>Soil sensor decoded on tuned 915.000 MHz with stable model/id fields. | RF: tuned 915.000 MHz, RSSI -11.2 dB, SNR 10.7 dB; Decoded: moisture 38%, temperature 21.4 C | 2026-06-12 09:14:35 |
| 70 | Medium | activity | ADS-B<br>Air activity | `Local aircraft activity`<br>Aircraft subjects are high volume but durable, so they remain individual report entries. | Population: 871 aircraft subjects; Motion: altitude/callsign fields present | 2026-06-12 09:14:41 |
| 68 | Medium | inventory | LAN<br>Network inventory | `sample-host-4`<br>Stable LAN host has IP, hostname, and MAC evidence suitable for inventory-style reporting. | Identity: `sample-host-4.local`; Network: `192.0.2.44`, `02:11:22:33:44:04`; Seen: 28 observations | 2026-06-12 09:14:22 |

## Sanitization Rules For Future Samples

Use these rules whenever generating screenshots, docs examples, or test-like prose from live Skannr data:

| Data type | Replacement pattern |
| --- | --- |
| MAC/BSSID/client MAC | `02:xx:xx:xx:xx:nn` locally administered fake addresses |
| IPv4 | `192.0.2.x`, `198.51.100.x`, or `203.0.113.x` |
| IPv6 | `2001:db8::/32` |
| SSID | `ExampleNet-*` |
| Hostname | `sample-host-*`, `example-*.local` |
| ADS-B ICAO/callsign | `ABC123`, `SKN123` |
| APRS callsign | `N0CALL-*` |
| Coordinates | generic rounded coordinates, never home/site coordinates |
| URLs | `https://example.invalid/...` |
| User annotation | plausible labels such as `warehouse sensor`, not real names |

## Notes For Documentation Writers

- Subject History examples should show annotations as labels, but the underlying subject must remain unchanged for hyperlinks and detail lookups.
- Report examples should match the current merged cell layout: Source plus title in the Report cell, and hyperlinked subject plus summary in the Subject cell.
- Wi-Fi scan, Wi-Fi monitor, Bluetooth, and weak LAN private MAC observations should demonstrate grouped randomized identities. Bluetooth examples should not show Transport or Insights as main-table columns; those belong in detail context when needed.
- ADS-B, APRS-IS, RTL-433, weather, earthquake, and space-weather subjects should normally remain distinct because their subject keys are durable.
- RTL-433 examples should use the dongle tuned frequency when available, because the decoded payload frequency may differ from the actual tuned center.
- If fake samples are regenerated, keep them manually reviewed. Automated sanitization can miss environment-specific names in free-text fields.
