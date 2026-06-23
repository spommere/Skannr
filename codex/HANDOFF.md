# Skannr Handoff - 2026-06-22

## Update - 2026-06-22

### Wi-Fi Monitor Safety Rework

This session replaced the recent Wi-Fi monitor auto-repair logic with a more
conservative model aimed at surviving `wlan0` / `wlan1` swaps after reboot
without risking host lockout.

What changed:

- `src/skannr/collectors/wifi_monitor.py`
  - removed runtime edits to `/etc/NetworkManager/NetworkManager.conf`
  - removed default-route migration logic
  - removed broad fallback guessing across arbitrary wireless interfaces
  - `prepare_monitor_mode: true` now prefers creating a separate monitor
    interface on the selected phy with `iw phy <phy> interface add monX type monitor`
  - auto-selection with `interface: auto` now considers only USB/external
    adapters that advertise monitor-mode support and are not the current
    default-route interface
  - if no safe candidate exists, Wi-Fi Monitor stays offline instead of guessing
  - in-place conversion remains available only behind
    `allow_in_place_monitor_mode: true`
- `src/skannr/collectors/hardware.py`
  - added shared helpers to map interfaces to phys and probe monitor-mode
    support from `iw phy <phy> info`
- `src/skannr/collectors/wifi.py`
  - managed Wi-Fi now prefers the current default-route interface when it has
    to auto-pick a scan interface, reducing conflict with the monitor adapter

Documentation updated:

- `README.md`
- `DESIGN.md`
- `config.example/collectors/wifi_monitor.yaml`

Validation done here:

- `python -m py_compile src/skannr/collectors/hardware.py src/skannr/collectors/wifi.py src/skannr/collectors/wifi_monitor.py`

Not done here:

- no runtime testing on Pi hardware
- no NetworkManager profile inspection on the live Pi

Open follow-up on the Pi:

- verify boot behavior with only one Wi-Fi adapter present
- verify boot behavior with built-in plus dongle when `wlan0` / `wlan1` swap
- verify whether the dongle driver supports separate `monX` interface creation
- if not, decide whether `allow_in_place_monitor_mode: true` is acceptable on
  that host
