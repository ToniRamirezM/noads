# NoAds

A network-wide, ad-blocking DNS sinkhole that runs on a single ESP32-S3 board
(developed on the **LilyGo T-Display S3**). Think of a tiny Pi-hole you can power from a USB charger.

Point your router's DHCP DNS at the board and every device on your network stops
resolving known ad, tracker and malware domains.

## Features

- DNS server on UDP/53 that answers blocked domains with `NXDOMAIN` and forwards everything else to an upstream resolver (default `1.1.1.1`).
- Blocklist in `hosts` format, downloaded over HTTPS with **certificate validation** (default: [StevenBlack/hosts](https://github.com/StevenBlack/hosts), ~70k domains). Refreshed every 24 h, stored in flash (LittleFS) so it survives reboots.
- Blocks a domain and all of its subdomains.
- DNS response cache (2048 entries, honours TTLs).
- Allowlist for domains you never want blocked.
- Automatic WiFi reconnection; reboots itself if the connection stays down.
- Optional status screen (T-Display S3): queries, blocked count, last blocked domain, cache hits.
- Two buttons: pause/resume filtering, force a blocklist refresh.

## Hardware

- Tested on: **LilyGo T-Display S3** (ESP32-S3, 16 MB flash, 8 MB PSRAM, 170x320 ST7789).
- Other ESP32-S3 boards with **PSRAM** should work with the `headless` build (see below); you may need to adjust the PlatformIO `board` and the PSRAM/flash settings in `platformio.ini`. The blocklist (~72k domains, 8 bytes each) and DNS cache live in PSRAM.
- 2.4 GHz WiFi only (ESP32 limitation).

## Quick start

1. Install [PlatformIO](https://platformio.org/install) (CLI or VS Code extension).
2. Clone this repository.
3. Create your WiFi credentials file:
   ```sh
   cp include/secrets.h.example include/secrets.h
   # edit include/secrets.h with your SSID and password
   ```
   `include/secrets.h` is git-ignored.
4. Build and flash:
   ```sh
   pio run -e tdisplay-s3 -t upload      # with the T-Display S3 screen
   pio run -e headless -t upload         # no display code
   pio device monitor                    # serial log, 115200 baud
   ```
   PlatformIO auto-detects the serial port. If it picks the wrong one, set `upload_port` in `platformio.ini`.
5. On first boot the board downloads the blocklist (this takes a few seconds) and the screen shows its IP address.
6. **Give the board a fixed IP**: reserve its IP in your router's DHCP settings (by MAC address).
7. Set your router's DHCP **DNS server** to the board's IP.
   - Use the board as the **only** DNS server. If you add a secondary public DNS, some systems (macOS in particular) will use it and bypass the filter.
   - Your devices pick up the change when they renew their DHCP lease (or reconnect to the network).

> If the board is off, nothing on your network can resolve names. If that is a problem for you,
> keep the router setting easy to revert, or run two boards.

## Configuration

User settings are in `include/`:

| File | What it controls |
| --- | --- |
| `secrets.h` | WiFi SSID and password (you create it from `secrets.h.example`) |
| `config.h` | Upstream DNS, blocklist URL, refresh interval, cache size, NTP servers, `ENABLE_DISPLAY` |
| `allowlist.h` | Domains that must never be blocked (subdomains included) |
| `ca_roots.h` | Root certificates trusted for the blocklist download |

Re-flash after editing any of them.

### Using another blocklist

Set `BLOCKLIST_URL` in `config.h`. The list must be in `hosts` format (`0.0.0.0 domain` lines).
The server's certificate must chain to one of the roots in `ca_roots.h`. The bundled roots are
ISRG Root X1 (Let's Encrypt), DigiCert Global Root G2 and USERTrust (RSA and ECC), which covers
GitHub and most large hosts. If the download fails with a TLS error, add the right root CA.
The firmware refuses to download without a valid certificate and a synced clock (NTP); in that case it keeps the previous list.

### Display (optional)

The screen code can be disabled:

- build the `headless` environment (`pio run -e headless -t upload`), or
- set `ENABLE_DISPLAY` to `0` in `config.h`.

Buttons keep working without a display. The display pin setup in `platformio.ini` is specific to the T-Display S3;
for another screen, change the `TFT_*` build flags (see [TFT_eSPI](https://github.com/Bodmer/TFT_eSPI)) and
the layout in `drawScreen()`.

### Buttons (T-Display S3)

| Button | GPIO | Action |
| --- | --- | --- |
| Bottom | 0 | Pause / resume filtering |
| Top | 14 | Refresh the blocklist now |

## Limitations

- DNS-level blocking cannot remove ads served from the same domain as the content (first-party ads, e.g. most YouTube ads).
- Pair it with a browser extension like uBlock Origin for those.
- Encrypted DNS (DoH/DoT) configured in a browser or OS bypasses any DNS sinkhole.
- IPv4 DNS transport only; AAAA and HTTPS (type 65) queries are filtered like A queries.
- Some sites detect blocked domains and show an anti-adblock message; add the offending domain to the allowlist.
- No web UI or query log: the serial monitor is the only log.

## Restoring the original firmware

Flashing replaces whatever was on the board. If you want to be able to go back, read the flash
**before** the first upload:

```sh
esptool.py --chip esp32s3 --port <port> read_flash 0 0x1000000 backup.bin   # 16 MB
esptool.py --chip esp32s3 --port <port> write_flash 0 backup.bin            # restore
```

## How it works

A request arrives on UDP/53. The name is checked against a sorted array of 64-bit FNV-1a hashes
(binary search, parent domains included). Blocked names get an `NXDOMAIN` reply; the rest are looked up
in the cache or forwarded to the upstream resolver, and the answer is cached and relayed to the client.
Hashing keeps 72k domains in under 600 KB of PSRAM. The trade-off is a tiny chance of false positives from hash collisions (64-bit, negligible at this list size).

## Credits and license

- Blocklist: [StevenBlack/hosts](https://github.com/StevenBlack/hosts) (MIT), downloaded at runtime, not bundled.
- Display driver: [TFT_eSPI](https://github.com/Bodmer/TFT_eSPI).

Released under the MIT License, see [LICENSE](LICENSE).
