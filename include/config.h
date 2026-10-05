#pragma once
// NoAds user settings. Edit and re-flash.
#include <Arduino.h>
#include <IPAddress.h>

// Set to 0 to build without any display code (headless boards, or boards with a
// different screen). Buttons still work. Also selectable with the "headless"
// PlatformIO environment.
#ifndef ENABLE_DISPLAY
#define ENABLE_DISPLAY 1
#endif

// Upstream DNS server used for everything that is not blocked (and for the
// device's own lookups: NTP and the blocklist download).
static const IPAddress UPSTREAM_DNS(1, 1, 1, 1);

// Blocklist in "hosts" format (lines like "0.0.0.0 ads.example.com").
// The host must be reachable over HTTPS with a certificate chained to one of
// the roots in ca_roots.h.
static const char* BLOCKLIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

// How often the blocklist is re-downloaded (the button also forces an update).
static const uint32_t REFRESH_HOURS = 24;

// Maximum number of domains kept in memory (8 bytes each, stored in PSRAM).
static const size_t MAX_DOMAINS = 400000;

// DNS response cache: number of slots (~530 bytes each, stored in PSRAM).
static const size_t CACHE_SLOTS = 2048;

// NTP servers (the clock is needed to validate TLS certificates).
static const char* NTP_SERVER_1 = "time.cloudflare.com";
static const char* NTP_SERVER_2 = "pool.ntp.org";
