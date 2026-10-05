// NoAds: ad-blocking DNS sinkhole for the LilyGo T-Display S3 (ESP32-S3, 8 MB PSRAM)
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <LittleFS.h>
#include <algorithm>
#if !__has_include("secrets.h")
#error "Missing include/secrets.h: copy include/secrets.h.example to include/secrets.h and set your WiFi credentials."
#endif
#include "secrets.h"
#include "config.h"
#include "allowlist.h"
#if ENABLE_DISPLAY
#include <TFT_eSPI.h>
#endif
#include "ca_roots.h"
#include <lwip/dns.h>
#include <time.h>

// ---------- Configuration (user settings live in include/config.h) ----------
static const char* BLOCKLIST_FILE = "/blocklist.bin";
static const uint32_t REFRESH_MS = REFRESH_HOURS * 3600UL * 1000;
// Pins of the LilyGo T-Display S3: display power, bottom button, top button
static const int PIN_POWER_ON = 15, PIN_BTN_PAUSE = 0, PIN_BTN_REFRESH = 14;

// ---------- State ----------
#if ENABLE_DISPLAY
TFT_eSPI tft;
#endif
WiFiUDP server, upstream;

static uint64_t* g_list = nullptr;  // sorted hashes (in PSRAM)
static size_t g_count = 0;
static SemaphoreHandle_t g_mux;
static volatile bool g_needUpdate = false;
static volatile bool g_updating = false;
static volatile bool g_paused = false;
static uint32_t g_total = 0, g_blocked = 0;
static char g_lastBlocked[64] = "-";


// ---------- Blocklist ----------
static uint64_t fnv1a(const char* s, size_t n) {
  uint64_t h = 1469598103934665603ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 1099511628211ULL; }
  return h;
}

// Blocks the domain or any of its parent domains (a.b.c -> a.b.c, b.c, c)
static bool isBlocked(const char* name) {
  bool hit = false;
  xSemaphoreTake(g_mux, portMAX_DELAY);
  for (const char* p = name; p && *p && !hit; p = strchr(p, '.')) {
    if (*p == '.') p++;
    hit = g_count && std::binary_search(g_list, g_list + g_count, fnv1a(p, strlen(p)));
    if (!strchr(p, '.')) break;
  }
  xSemaphoreGive(g_mux);
  return hit;
}

// Exceptions: the domain or any of its parents is in ALLOWLIST
static bool isAllowed(const char* name) {
  for (const char* p = name; p && *p; p = strchr(p, '.')) {
    if (*p == '.') p++;
    for (const char* a : ALLOWLIST) if (!strcmp(p, a)) return true;
    if (!strchr(p, '.')) break;
  }
  return false;
}

static void swapList(uint64_t* nl, size_t n) {
  xSemaphoreTake(g_mux, portMAX_DELAY);
  uint64_t* old = g_list;
  g_list = nl; g_count = n;
  xSemaphoreGive(g_mux);
  if (old) free(old);
}

static bool loadListFromFlash() {
  File f = LittleFS.open(BLOCKLIST_FILE, "r");
  if (!f || f.size() < 8) return false;
  size_t n = f.size() / 8;
  uint64_t* buf = (uint64_t*)ps_malloc(n * 8);
  if (!buf) return false;
  if (f.read((uint8_t*)buf, n * 8) != n * 8) { free(buf); return false; }
  swapList(buf, n);
  return true;
}

static bool downloadList() {
  WiFiClientSecure client;
  // Certificate validation needs the correct time (the ESP32 has no battery-backed clock)
  for (int i = 0; time(nullptr) < 1700000000 && i < 100; i++) vTaskDelay(pdMS_TO_TICKS(100));
  if (time(nullptr) < 1700000000) { Serial.println("blocklist: no NTP time, download cancelled"); return false; }
  client.setCACert(ROOT_CAS);
  HTTPClient http;
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  if (!http.begin(client, BLOCKLIST_URL)) return false;
  Serial.printf("blocklist: connecting (heap %u, psram %u)\n", ESP.getFreeHeap(), ESP.getFreePsram());
  uint32_t t0 = millis();
  int code = http.GET();
  Serial.printf("blocklist: GET -> %d, size %d, %u ms\n", code, http.getSize(), (unsigned)(millis() - t0));
  if (code != 200) { Serial.printf("blocklist: HTTP %d\n", code); http.end(); return false; }

  uint64_t* buf = (uint64_t*)ps_malloc(MAX_DOMAINS * 8);
  if (!buf) { http.end(); return false; }
  size_t n = 0;
  WiFiClient* s = http.getStreamPtr();
  s->setTimeout(5000);
  uint32_t lines = 0, bytes = 0, lastData = millis();
  uint8_t* rb = (uint8_t*)malloc(4096);
  char line[256]; size_t ll = 0;
  if (!rb) { free(buf); http.end(); return false; }

  // Read in blocks (byte-by-byte over TLS is ~100x slower) and split lines by hand.
  // Stops when data stops arriving: the server may keep the connection open.
  while (millis() - lastData < 8000) {
    int avail = s->available();
    if (avail <= 0) {
      if (!http.connected()) break;
      vTaskDelay(pdMS_TO_TICKS(5));
      continue;
    }
    int r = s->read(rb, avail < 4096 ? avail : 4096);
    if (r <= 0) continue;
    lastData = millis();
    bytes += r;
    for (int i = 0; i < r; i++) {
      char c = rb[i];
      if (c != '\n') { if (ll < sizeof line - 1) line[ll++] = c; continue; }
      line[ll] = 0; ll = 0; lines++;
      if (strncmp(line, "0.0.0.0 ", 8) != 0) continue;
      char* d = line + 8;
      char* e = d;
      while (*e && *e != ' ' && *e != '#' && *e != '\r' && *e != '\t') { *e = tolower(*e); e++; }
      *e = 0;
      size_t dl = e - d;
      if (!dl || !strcmp(d, "0.0.0.0") || !strcmp(d, "localhost")) continue;
      if (n < MAX_DOMAINS) buf[n++] = fnv1a(d, dl);
    }
    vTaskDelay(1);  // yield the CPU so the watchdog does not fire
  }
  free(rb);
  Serial.printf("blocklist: %u bytes in %u ms\n", (unsigned)bytes, (unsigned)(millis() - t0));
  Serial.printf("blocklist: %u lines read, %u domains\n", (unsigned)lines, (unsigned)n);
  http.end();
  if (n < 1000) { free(buf); Serial.println("blocklist: too short, discarded"); return false; }

  std::sort(buf, buf + n);
  n = std::unique(buf, buf + n) - buf;
  File f = LittleFS.open(BLOCKLIST_FILE, "w");
  if (f) { f.write((uint8_t*)buf, n * 8); f.close(); }
  swapList(buf, n);
  Serial.printf("blocklist: %u domains\n", (unsigned)n);
  return true;
}

static void updaterTask(void*) {
  uint32_t last = 0;
  for (;;) {
    if (WiFi.status() == WL_CONNECTED && (g_needUpdate || (last && millis() - last > REFRESH_MS))) {
      g_needUpdate = false; g_updating = true;
      if (downloadList()) last = millis();
      g_updating = false;
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

static uint8_t buf[1500];

// ---------- DNS cache ----------
// Stores complete responses (<=512 B) in PSRAM, honouring the TTL. Hash table probing 4 slots per lookup.
struct CacheEntry { uint64_t key; uint32_t stored, expires; uint16_t len; uint8_t data[512]; };
static CacheEntry* g_cache = nullptr;
static uint32_t g_cacheHits = 0;

static inline uint16_t rd16(const uint8_t* p) { return (p[0] << 8) | p[1]; }
static inline uint32_t rd32(const uint8_t* p) { return ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }
static inline void wr32(uint8_t* p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

static size_t skipName(const uint8_t* p, size_t len, size_t i) {
  while (i < len) {
    uint8_t l = p[i];
    if (l == 0) return i + 1;
    if ((l & 0xC0) == 0xC0) return i + 2 <= len ? i + 2 : 0;
    i += l + 1;
  }
  return 0;
}

// Walks the response records (skipping OPT), records where each TTL lives and returns the smallest.
// Returns 0xFFFFFFFF if there are no records or the response is invalid.
static uint32_t scanTtls(const uint8_t* p, size_t len, uint16_t* offs, int& cnt) {
  cnt = 0;
  if (len < 12) return 0xFFFFFFFF;
  uint16_t qd = rd16(p + 4), rrs = rd16(p + 6) + rd16(p + 8) + rd16(p + 10);
  size_t i = 12;
  for (int q = 0; q < qd; q++) { i = skipName(p, len, i); if (!i || i + 4 > len) return 0xFFFFFFFF; i += 4; }
  uint32_t mn = 0xFFFFFFFF;
  for (int r = 0; r < rrs; r++) {
    i = skipName(p, len, i);
    if (!i || i + 10 > len) return 0xFFFFFFFF;
    uint16_t type = rd16(p + i), rdl = rd16(p + i + 8);
    if (type != 41 && cnt < 64) {
      offs[cnt++] = i + 4;
      uint32_t t = rd32(p + i + 4);
      if (t < mn) mn = t;
    }
    i += 10 + rdl;
    if (i > len) return 0xFFFFFFFF;
  }
  return mn;
}

static void cacheStore(uint64_t key, const uint8_t* r, size_t len) {
  if (!g_cache || len < 12 || len > sizeof(CacheEntry::data)) return;
  uint8_t rcode = r[3] & 0x0F;
  if (!(r[2] & 0x80) || (r[2] & 0x02) || (rcode != 0 && rcode != 3)) return;  // not a response, truncated, or an error
  uint16_t offs[64]; int cnt;
  uint32_t ttl = scanTtls(r, len, offs, cnt);
  if (ttl == 0xFFFFFFFF) return;
  ttl = ttl < 5 ? 5 : (ttl > 3600 ? 3600 : ttl);
  uint32_t now = millis();
  CacheEntry* best = nullptr;
  for (int k = 0; k < 4; k++) {
    CacheEntry* e = &g_cache[(key + k) % CACHE_SLOTS];
    if (e->len && e->key == key) { best = e; break; }
    if (!e->len || (int32_t)(now - e->expires) >= 0) { if (!best) best = e; continue; }
    if (!best || (int32_t)(e->expires - best->expires) < 0) best = e;
  }
  best->key = key; best->stored = now; best->expires = now + ttl * 1000; best->len = len;
  memcpy(best->data, r, len);
}

// If a fresh response exists, leaves it in buf (with the current query's ID and RD, TTLs reduced by the elapsed time). Returns its length or 0.
static size_t cacheLookup(uint64_t key) {
  if (!g_cache) return 0;
  uint32_t now = millis();
  for (int k = 0; k < 4; k++) {
    CacheEntry* e = &g_cache[(key + k) % CACHE_SLOTS];
    if (!e->len || e->key != key) continue;
    if ((int32_t)(now - e->expires) >= 0) { e->len = 0; return 0; }
    uint16_t id = rd16(buf); uint8_t rd = buf[2] & 1;
    memcpy(buf, e->data, e->len);
    buf[0] = id >> 8; buf[1] = id; buf[2] = (buf[2] & ~1) | rd;
    uint16_t offs[64]; int cnt;
    scanTtls(buf, e->len, offs, cnt);
    uint32_t elapsed = (now - e->stored) / 1000;
    for (int i = 0; i < cnt; i++) {
      uint32_t t = rd32(buf + offs[i]);
      wr32(buf + offs[i], t > elapsed ? t - elapsed : 1);
    }
    return e->len;
  }
  return 0;
}

// ---------- DNS ----------
struct Pending { bool used; IPAddress ip; uint16_t port, origId, upId; uint32_t t; uint64_t key; };
static Pending pend[32];

// Decodes the QNAME as lowercase "a.b.c". Returns the offset after the question (QTYPE+QCLASS) or 0 if invalid.
static size_t parseQuestion(const uint8_t* q, size_t len, char* name, size_t cap, uint16_t& qtype) {
  size_t i = 12, o = 0;
  while (i < len && q[i]) {
    uint8_t l = q[i++];
    if (l & 0xC0 || i + l > len || o + l + 2 > cap) return 0;
    if (o) name[o++] = '.';
    for (uint8_t k = 0; k < l; k++) name[o++] = tolower(q[i++]);
  }
  name[o] = 0;
  if (i + 5 > len) return 0;
  qtype = rd16(q + i + 1);
  return i + 5;
}

static void sendBlocked(IPAddress ip, uint16_t port, size_t qlen, size_t qend, uint16_t qtype) {
  // NXDOMAIN response: same header+question, QR=1, RA=1, no records.
  // (macOS discards 0.0.0.0 answers and retries on the secondary DNS, bypassing the filter.)
  buf[2] = 0x80 | (buf[2] & 0x01);  // QR + copied RD
  buf[3] = 0x83;                    // RA + rcode 3 (NXDOMAIN)
  buf[6] = buf[7] = buf[8] = buf[9] = buf[10] = buf[11] = 0;
  server.beginPacket(ip, port); server.write(buf, qend); server.endPacket();
}

static void handleClient() {
  int len = server.parsePacket();
  if (len < 12 || len > (int)sizeof buf) { if (len > 0) server.flush(); return; }
  server.read(buf, len);
  IPAddress cip = server.remoteIP(); uint16_t cport = server.remotePort();
  if (buf[2] & 0x80) return;  // not a query

  char name[256]; uint16_t qtype = 0;
  size_t qend = rd16(buf + 4) == 1 ? parseQuestion(buf, len, name, sizeof name, qtype) : 0;
  g_total++;
  if (qend && !g_paused && (qtype == 1 || qtype == 28 || qtype == 65) && !isAllowed(name) && isBlocked(name)) {
    g_blocked++;
    strlcpy(g_lastBlocked, name, sizeof g_lastBlocked);
    sendBlocked(cip, cport, len, qend, qtype);
    return;
  }

  uint64_t key = 0;
  if (qend) {
    key = fnv1a(name, strlen(name)) ^ ((uint64_t)qtype * 0x9E3779B97F4A7C15ULL) ^ (rd16(buf + 10) ? 1 : 0);
    if (size_t cl = cacheLookup(key)) {
      g_cacheHits++;
      server.beginPacket(cip, cport); server.write(buf, cl); server.endPacket();
      return;
    }
  }

  // Forward to the upstream DNS
  int slot = -1; uint32_t now = millis();
  for (int i = 0; i < 32; i++) if (!pend[i].used || now - pend[i].t > 3000) { slot = i; break; }
  if (slot < 0) return;
  pend[slot] = {true, cip, cport, rd16(buf), (uint16_t)esp_random(), now, key};
  buf[0] = pend[slot].upId >> 8; buf[1] = pend[slot].upId;
  upstream.beginPacket(UPSTREAM_DNS, 53); upstream.write(buf, len); upstream.endPacket();
}

static void handleUpstream() {
  int len = upstream.parsePacket();
  if (len < 12 || len > (int)sizeof buf) { if (len > 0) upstream.flush(); return; }
  upstream.read(buf, len);
  if (upstream.remoteIP() != UPSTREAM_DNS) return;
  uint16_t id = rd16(buf);
  for (auto& p : pend) if (p.used && p.upId == id) {
    if (p.key) cacheStore(p.key, buf, len);
    buf[0] = p.origId >> 8; buf[1] = p.origId;
    server.beginPacket(p.ip, p.port); server.write(buf, len); server.endPacket();
    p.used = false;
    return;
  }
}

// ---------- Display (optional) and buttons ----------
#if ENABLE_DISPLAY
static void row(int y, const char* label, const String& v, uint16_t c = TFT_WHITE) {
  tft.setTextPadding(0);
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK); tft.drawString(label, 8, y, 2);
  tft.setTextPadding(215);  // clear the full width so no remnants of the previous text are left
  tft.setTextColor(c, TFT_BLACK); tft.drawString(v, 100, y, 2);
}

// Header: shield + name + status pill with a blinking dot (heartbeat)
static void drawHeader() {
  static int last = -1;
  const uint16_t bar = tft.color565(18, 22, 30);
  const uint16_t accent = g_paused ? tft.color565(255, 160, 0) : tft.color565(40, 200, 100);
  if (last != (int)g_paused) {
    last = g_paused;
    tft.setTextPadding(0);
    tft.fillRect(0, 0, 320, 34, bar);
    tft.drawFastHLine(0, 34, 320, accent);
    // shield (with a check mark or a pause symbol)
    tft.fillRoundRect(8, 4, 20, 15, 3, accent);
    tft.fillTriangle(8, 17, 27, 17, 18, 30, accent);
    if (!g_paused) {
      tft.drawLine(13, 14, 17, 19, bar); tft.drawLine(14, 14, 18, 19, bar);
      tft.drawLine(17, 19, 24, 9, bar);  tft.drawLine(18, 19, 25, 9, bar);
    } else {
      tft.fillRect(13, 9, 3, 12, bar); tft.fillRect(20, 9, 3, 12, bar);
    }
    tft.setTextColor(TFT_WHITE, bar);
    tft.drawString("NoAds", 38, 4, 4);
    // status pill
    tft.fillRoundRect(206, 6, 106, 22, 11, accent);
    tft.setTextColor(bar, accent);
    tft.drawString(g_paused ? "PAUSED" : "ACTIVE", 238, 10, 2);
  }
  tft.fillCircle(222, 17, 4, ((millis() / 700) & 1) ? TFT_WHITE : bar);  // heartbeat
}

static void drawScreen() {
  bool ok = WiFi.status() == WL_CONNECTED;
  drawHeader();
  row(40, "IP", ok ? WiFi.localIP().toString() : "connecting...", ok ? TFT_WHITE : TFT_YELLOW);
  row(58, "List", g_updating ? String("downloading...") : String(g_count) + " domains", g_updating ? TFT_YELLOW : TFT_WHITE);
  row(76, "Queries", String(g_total));
  float pct = g_total ? 100.0f * g_blocked / g_total : 0;
  row(94, "Blocked", String(g_blocked) + " (" + String(pct, 1) + "%)", TFT_RED);
  row(112, "Last", String(g_lastBlocked).substring(0, 26), TFT_CYAN);
  row(130, "Cache", String(g_cacheHits) + " hits");
  // Button legend: down triangle = GPIO 0 (pause), up triangle = GPIO 14 (refresh)
  tft.setTextPadding(0);
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.fillTriangle(10, 154, 20, 154, 15, 164, TFT_DARKGREY);   // down
  tft.drawString("pause/resume", 26, 152, 2);
  tft.fillTriangle(175, 164, 185, 164, 180, 154, TFT_DARKGREY);  // up
  tft.drawString("refresh list", 191, 152, 2);
}
#endif

static bool pressed(int pin, bool& prev) {
  bool now = digitalRead(pin) == LOW, edge = now && !prev;
  prev = now;
  return edge;
}

// The router hands out this ESP32 as the DNS server; for its own lookups (NTP, blocklist download) use the upstream.
static void useUpstreamDns() {
  ip_addr_t d;
  IP_ADDR4(&d, UPSTREAM_DNS[0], UPSTREAM_DNS[1], UPSTREAM_DNS[2], UPSTREAM_DNS[3]);
  dns_setserver(0, &d);
}

// If WiFi drops: retry every 10 s; if it stays down for 1 min, reboot.
static void watchWifi() {
  static uint32_t lastCheck = 0, downSince = 0, lastRetry = 0;
  static bool wasDown = false;
  uint32_t now = millis();
  if (now - lastCheck < 1000) return;
  lastCheck = now;
  if (WiFi.status() == WL_CONNECTED) {
    if (wasDown) {  // just reconnected: reopen the UDP sockets
      server.stop(); upstream.stop();
      server.begin(53); upstream.begin(40053);
      wasDown = false;
      Serial.printf("WiFi recovered: %s\n", WiFi.localIP().toString().c_str());
    }
    downSince = 0;
    useUpstreamDns();
    return;
  }
  if (!downSince) { downSince = now; wasDown = true; Serial.println("WiFi down"); }
  if (now - lastRetry > 10000) { lastRetry = now; WiFi.disconnect(); WiFi.begin(WIFI_SSID, WIFI_PASS); }
  if (now - downSince > 60000) ESP.restart();
}

void setup() {
  Serial.begin(115200);
#if ENABLE_DISPLAY
  pinMode(PIN_POWER_ON, OUTPUT); digitalWrite(PIN_POWER_ON, HIGH);
#endif
  pinMode(PIN_BTN_PAUSE, INPUT_PULLUP); pinMode(PIN_BTN_REFRESH, INPUT_PULLUP);
#if ENABLE_DISPLAY
  tft.init(); tft.setRotation(1); tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_GREEN, TFT_BLACK); tft.drawString("NoAds", 8, 4, 4);
  tft.setTextColor(TFT_WHITE, TFT_BLACK); tft.drawString("Starting...", 8, 50, 2);
#endif

  g_mux = xSemaphoreCreateMutex();
  LittleFS.begin(true);
  if (!loadListFromFlash()) g_needUpdate = true;
  Serial.printf("blocklist in flash: %u domains\n", (unsigned)g_count);
#if ENABLE_DISPLAY
  tft.drawString(String("List: ") + g_count + " domains", 8, 70, 2);
  tft.drawString(String("Connecting to ") + WIFI_SSID + "...", 8, 90, 2);
#endif

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);  // lower DNS latency
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  for (uint32_t t0 = millis(); WiFi.status() != WL_CONNECTED; delay(200)) {
    if (millis() - t0 > 60000) ESP.restart();  // no WiFi after 1 min: reboot
  }
  Serial.printf("IP: %s\n", WiFi.localIP().toString().c_str());

  g_cache = (CacheEntry*)ps_calloc(CACHE_SLOTS, sizeof(CacheEntry));
  configTime(0, 0, NTP_SERVER_1, NTP_SERVER_2);
  useUpstreamDns();
  server.begin(53);
  upstream.begin(40053);
  xTaskCreatePinnedToCore(updaterTask, "updater", 20000, nullptr, 1, nullptr, 0);
#if ENABLE_DISPLAY
  tft.fillScreen(TFT_BLACK);
#endif
}

void loop() {
#if ENABLE_DISPLAY
  static uint32_t lastDraw = 0;
#endif
  static bool b1 = false, b2 = false;
  watchWifi();
  handleClient();
  handleUpstream();
  if (pressed(PIN_BTN_PAUSE, b1)) g_paused = !g_paused;
  if (pressed(PIN_BTN_REFRESH, b2)) g_needUpdate = true;
#if ENABLE_DISPLAY
  if (millis() - lastDraw > 500) { lastDraw = millis(); drawScreen(); }
#endif
  delay(1);
}
