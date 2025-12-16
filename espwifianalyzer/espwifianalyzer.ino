/* ✅ ESP32 WiFi UART Analyzer — Final CLI (v3) — patched
   Tek dosya Arduino IDE sketch (ESP32)
*/

#include <WiFi.h>
#include "esp_wifi.h"
#include <vector>

/* ========== CONFIG ========== */
#define BAUD 115200
#define MAX_OBS 1200
#define BODY_COPY 128
#define RING_SIZE 256
#define RSSI_MIN -90

/* ========== DATA STRUCTS ========== */
struct Observation {
  unsigned long ts;
  String type, src, dst, bssid;
  int rssi, channel;
  bool has_rsn;
  bool has_wps;
};

struct RawRec {
  uint32_t ts;
  int8_t rssi;
  uint8_t ch;
  uint8_t src[6], dst[6], bssid[6];
  uint8_t type, subtype;
  uint16_t body_len;
  uint8_t body[BODY_COPY];
  uint16_t frame_len;
};

/* ========== GLOBALS ========== */
volatile uint16_t ring_head = 0, ring_tail = 0;
RawRec ringbuf[RING_SIZE];

volatile bool snifferRunning = false;
String snifferMode = "all";
String focusBSSID = "";
bool channelHop = false;
TaskHandle_t hopTaskHandle = NULL;
int hopIntervalMs = 300;
int forcedChannel = 1;

std::vector<Observation> observations;
uint32_t frameCount = 0;

bool detect_rsnwps = true;

uint32_t ch_pkt_count[14];
uint64_t ch_payload_bytes[14];

bool pcapStreaming = false;

/* ========== HELPERS ========== */
String macToStr(const uint8_t *mac) {
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
  return String(buf);
}

String normalizeMac(String mac) {
  mac.toUpperCase();
  mac.replace(":", ""); mac.replace("-", ""); mac.replace(".", ""); mac.trim();
  return mac;
}

void printHeader(){
  Serial.println("\n╔════════════════════════════════════════════════╗");
  Serial.println("║    ESP32 WiFi UART Analyzer — Final CLI v3     ║");
  Serial.println("╚════════════════════════════════════════════════╝\n");
}

void printHelp(){
  Serial.println("Commands:");
  Serial.println(" help                      -> Show this help");
  Serial.println(" scan                      -> Scan nearby Wi-Fi APs");
  Serial.println(" start all                 -> Start sniffer (all channels)");
  Serial.println(" start focus <BSSID>       -> Start sniffer focused on BSSID (AA:BB:..)");
  Serial.println(" stop                      -> Stop sniffer");
  Serial.println(" hop on / hop off          -> Enable/disable channel hopping");
  Serial.println(" ch <n>                    -> Force channel (1..13)");
  Serial.println(" status                    -> Show status");
  Serial.println(" export                    -> Export observations CSV to serial");
  Serial.println(" clear                     -> Clear stored observations");
  Serial.println(" detect on / detect off    -> Enable/disable RSN/WPS detection");
  Serial.println(" pcap start / pcap stop    -> Start/stop PCAP streaming over serial");
  Serial.println(" airtime                   -> Print channel packet/byte/airtime stats\n");
}

/* New: printStatus (EXPLICITLY ADDED) */
void printStatus() {
  Serial.println("---- Status ----");
  Serial.printf("Sniffer running : %s\n", snifferRunning ? "YES":"NO");
  Serial.printf("Mode            : %s\n", snifferMode.c_str());
  Serial.printf("Focus BSSID     : %s\n", focusBSSID.length() ? focusBSSID.c_str() : "-");
  Serial.printf("Channel hop     : %s\n", channelHop ? "ON":"OFF");
  Serial.printf("Forced channel  : %d\n", forcedChannel);
  Serial.printf("PCAP streaming  : %s\n", pcapStreaming ? "YES":"NO");
  Serial.printf("Observations    : %u\n", (unsigned)observations.size());
  Serial.printf("Frames captured : %u\n", (unsigned)frameCount);
  Serial.printf("Detect RSN/WPS  : %s\n", detect_rsnwps ? "ON":"OFF");
  Serial.println("----------------\n");
}

/* ========== ISR (promiscuous) ========== */
void IRAM_ATTR sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if(!snifferRunning) return;
  wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t*)buf;
  if(!ppkt || !ppkt->payload) return;

  int payload_len = ppkt->rx_ctrl.sig_len;
  if(payload_len <= 0) payload_len = 24 + BODY_COPY;
  if(payload_len <= 24) return;

  uint16_t next = (ring_head + 1) % RING_SIZE;
  if(next == ring_tail) return; // full

  // Write into current head slot
  RawRec &r = ringbuf[ring_head];
  uint8_t *p = ppkt->payload;
  uint16_t fc = p[0] | (p[1] << 8);

  r.ts = (uint32_t)millis();
  r.rssi = ppkt->rx_ctrl.rssi;
  r.ch = ppkt->rx_ctrl.channel;
  r.type = (fc >> 2) & 0x3;
  r.subtype = (fc >> 4) & 0xF;

  memcpy(r.dst, p + 4, 6);
  memcpy(r.src, p + 10, 6);
  memcpy(r.bssid, p + 16, 6);

  int avail = payload_len - 24;
  if(avail > 0){
    int to_copy = avail;
    if(to_copy > BODY_COPY) to_copy = BODY_COPY;
    memcpy(r.body, p + 24, to_copy);
    r.body_len = to_copy;
  } else {
    r.body_len = 0;
  }
  r.frame_len = payload_len;

  // advance head (atomic-ish)
  ring_head = next;
}

/* Pop single raw record from ring (main thread) - made atomic */
bool popRaw(RawRec &out){
  noInterrupts();
  if(ring_head == ring_tail){
    interrupts();
    return false;
  }
  uint16_t t = ring_tail;
  // copy slot into out while interrupts disabled to avoid races
  out = ringbuf[t];
  ring_tail = (ring_tail + 1) % RING_SIZE;
  interrupts();
  return true;
}

/* ========== Channel hop task ========== */
void hopTask(void *p){
  while(channelHop){
    for(int ch=1; ch<=13 && channelHop; ++ch){
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      vTaskDelay(hopIntervalMs / portTICK_PERIOD_MS);
    }
  }
  vTaskDelete(NULL);
}

/* ========== Sniffer control ========== */
void startSniffer(){
  if(snifferRunning){ Serial.println("[WARN] Sniffer already running"); return; }

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();

  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
  esp_wifi_set_promiscuous(true);

  snifferRunning = true;

  if(!channelHop) esp_wifi_set_channel(forcedChannel, WIFI_SECOND_CHAN_NONE);
  else if(hopTaskHandle == NULL) xTaskCreate(hopTask,"hopTask",2048,NULL,1,&hopTaskHandle);

  Serial.println("[OK] Sniffer started");
}

void stopSniffer(){
  if(!snifferRunning){ Serial.println("[WARN] Sniffer not running"); return; }

  channelHop = false;
  if(hopTaskHandle){ vTaskDelete(hopTaskHandle); hopTaskHandle = NULL; }

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);

  snifferRunning = false;
  Serial.println("[OK] Sniffer stopped");
  printHelp();
}

/* ========== SCAN & UTILS ========== */
void scanNetworks(){
  Serial.println("[SCAN] scanning nearby APs (may take a couple seconds)...");
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(120);
  int n = WiFi.scanNetworks(false, true);
  if(n <= 0){ Serial.println("[SCAN] No APs found"); return; }
  for(int i=0;i<n;i++){
    Serial.printf("[AP] SSID:'%s'  BSSID:%s  RSSI:%d  CH:%d  ENC:%s\n",
      WiFi.SSID(i).c_str(), WiFi.BSSIDstr(i).c_str(), WiFi.RSSI(i), WiFi.channel(i),
      (WiFi.encryptionType(i)==WIFI_AUTH_OPEN) ? "OPEN":"SEC");
  }
  Serial.println("[SCAN] done\n");
}

void setForcedChannel(int ch){
  if(ch < 1 || ch > 13){ Serial.println("[ERR] channel must be 1..13"); return; }
  forcedChannel = ch;
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  Serial.printf("[OK] forced channel -> %d\n", ch);
}

void enableHop(bool en){
  if(en){
    channelHop = true;
    if(snifferRunning && hopTaskHandle==NULL) xTaskCreate(hopTask,"hopTask",2048,NULL,1,&hopTaskHandle);
    Serial.println("[OK] channel hop ON");
  } else {
    channelHop = false;
    if(hopTaskHandle){ vTaskDelete(hopTaskHandle); hopTaskHandle=NULL; }
    Serial.println("[OK] channel hop OFF");
    esp_wifi_set_channel(forcedChannel, WIFI_SECOND_CHAN_NONE);
  }
}

/* ========== RSN/WPS IE parsing ========== */
void parseIEs(const RawRec &r, bool &has_rsn, bool &has_wps){
  has_rsn = false; has_wps = false;
  int i = 0;
  while(i + 2 <= r.body_len){
    uint8_t id = r.body[i++];
    uint8_t len = r.body[i++];
    if(i + len > r.body_len) break;
    if(id == 48){ // RSN IE
      has_rsn = true;
    } else if(id == 221){
      if(len >= 4){
        uint8_t oui0 = r.body[i];
        uint8_t oui1 = r.body[i+1];
        uint8_t oui2 = r.body[i+2];
        if(oui0==0x00 && oui1==0x50 && oui2==0xF2){
          has_wps = true;
        }
      }
    }
    i += len;
  }
}

/* ========== PCAP streaming helpers ========== */
void write_le32_uint32(uint32_t v){
  uint8_t b[4];
  b[0] = v & 0xFF; b[1] = (v>>8)&0xFF; b[2] = (v>>16)&0xFF; b[3] = (v>>24)&0xFF;
  Serial.write(b,4);
}
void write_le32_uint16(uint16_t v){
  uint8_t b[2];
  b[0] = v & 0xFF; b[1] = (v>>8)&0xFF;
  Serial.write(b,2);
}

void pcap_write_global_header(){
  uint8_t gh[24] = {
    0xd4,0xc3,0xb2,0xa1,
    0x02,0x00,
    0x04,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0xff,0xff,0x00,0x00,
    0x7f,0x00,0x00,0x00
  };
  Serial.write(gh, sizeof(gh));
  Serial.flush();
}

void pcap_write_packet(const RawRec &r){
  uint8_t radiotap[8] = {0x00,0x00,0x08,0x00, 0x00,0x00,0x00,0x00};
  uint8_t hdr24[24] = {0};
  uint16_t fc = (r.subtype << 4) | (r.type << 2);
  hdr24[0] = fc & 0xFF; hdr24[1] = (fc>>8)&0xFF;
  memcpy(hdr24 + 4, r.dst, 6);
  memcpy(hdr24 + 10, r.src, 6);
  memcpy(hdr24 + 16, r.bssid, 6);

  uint32_t incl_len = sizeof(radiotap) + sizeof(hdr24) + r.body_len;
  uint32_t orig_len = incl_len;
  uint32_t ts_sec = r.ts / 1000;
  uint32_t ts_usec = (r.ts % 1000) * 1000;

  write_le32_uint32(ts_sec);
  write_le32_uint32(ts_usec);
  write_le32_uint32(incl_len);
  write_le32_uint32(orig_len);
  Serial.write(radiotap, sizeof(radiotap));
  Serial.write(hdr24, sizeof(hdr24));
  if(r.body_len) Serial.write(r.body, r.body_len);
  Serial.flush();
}

void pcap_start(){
  if(pcapStreaming){ Serial.println("[WARN] pcap already streaming"); return; }
  pcapStreaming = true;
  Serial.println("[PCAP] streaming started -> writing global header (binary)");
  pcap_write_global_header();
}

void pcap_stop(){
  if(!pcapStreaming){ Serial.println("[WARN] pcap not streaming"); return; }
  pcapStreaming = false;
  Serial.println("[PCAP] streaming stopped");
}

/* ========== Airtime reporting ========== */
void printAirtime(){
  Serial.println("---- Channel Stats (pkts / bytes / airtime est ms @1Mbps) ----");
  for(int ch=1; ch<=13; ++ch){
    uint32_t pk = ch_pkt_count[ch];
    uint64_t bytes = ch_payload_bytes[ch];
    double airtime_ms = (double)bytes * 8.0 / 1000.0;
    Serial.printf("CH %02d: pkts=%u  bytes=%llu  airtime_ms~%.1f\n",
      ch, (unsigned)pk, (unsigned long long)bytes, airtime_ms);
  }
  Serial.println("-----------------------------------------------------------");
}

/* ========== HIGH LEVEL COMMANDS ========== */
void handleStartFocus(String mac){
  mac.trim();
  if(!mac.length()){ Serial.println("[ERR] start focus <BSSID> — missing BSSID"); return; }
  focusBSSID = normalizeMac(mac);
  snifferMode = "focus";
  int n = WiFi.scanNetworks(false, true);
  for(int i=0;i<n;i++){
    if(normalizeMac(WiFi.BSSIDstr(i)) == focusBSSID){
      setForcedChannel(WiFi.channel(i));
      Serial.printf("[INFO] found AP channel %d for %s — set forced channel\n", WiFi.channel(i), mac.c_str());
      break;
    }
  }
  startSniffer();
  Serial.printf("[OK] Focus mode on for %s\n", mac.c_str());
}

void exportObservations(){
  Serial.println("ts,type,src,dst,bssid,rssi,channel,rsn,wps");
  for(auto &o:observations){
    Serial.printf("%lu,%s,%s,%s,%s,%d,%d,%s,%s\n",
      o.ts, o.type.c_str(), o.src.c_str(), o.dst.c_str(), o.bssid.c_str(),
      o.rssi, o.channel, o.has_rsn ? "RSN":"-", o.has_wps ? "WPS":"-");
  }
  Serial.println("[EXPORT DONE]");
}

/* ========== COMMAND PARSER ========== */
void parseCommand(String cmd){
  cmd.trim();
  if(cmd.length() == 0) return;
  if(cmd.equalsIgnoreCase("help")) { printHelp(); return; }
  if(cmd.equalsIgnoreCase("scan")) { scanNetworks(); return; }
  if(cmd.equalsIgnoreCase("start all")) { snifferMode="all"; startSniffer(); return; }
  if(cmd.startsWith("start focus")) { handleStartFocus(cmd.substring(12)); return; }
  if(cmd.equalsIgnoreCase("stop")) { stopSniffer(); return; }
  if(cmd.equalsIgnoreCase("hop on")) { enableHop(true); return; }
  if(cmd.equalsIgnoreCase("hop off")) { enableHop(false); return; }
  if(cmd.startsWith("ch ")) { setForcedChannel(cmd.substring(3).toInt()); return; }
  if(cmd.equalsIgnoreCase("status")) { printStatus(); return; }
  if(cmd.equalsIgnoreCase("export")) { exportObservations(); return; }
  if(cmd.equalsIgnoreCase("clear")) { observations.clear(); Serial.println("[OK] cleared"); return; }
  if(cmd.equalsIgnoreCase("detect on")) { detect_rsnwps = true; Serial.println("[OK] RSN/WPS detection ON"); return; }
  if(cmd.equalsIgnoreCase("detect off")) { detect_rsnwps = false; Serial.println("[OK] RSN/WPS detection OFF"); return; }
  if(cmd.equalsIgnoreCase("pcap start")) { pcap_start(); return; }
  if(cmd.equalsIgnoreCase("pcap stop")) { pcap_stop(); return; }
  if(cmd.equalsIgnoreCase("airtime")) { printAirtime(); return; }
  Serial.println("[ERR] Unknown command (type 'help')");
}

/* ========== SETUP & LOOP ========== */
void setup(){
  Serial.begin(BAUD);
  delay(200);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  printHeader();
  printHelp();
  for(int i=0;i<14;i++){ ch_pkt_count[i]=0; ch_payload_bytes[i]=0; }
}

void loop(){
  if(Serial.available()){
    String line = Serial.readStringUntil('\n');
    parseCommand(line);
  }

  RawRec r;
  while(popRaw(r)){
    frameCount++;

    if(r.rssi < RSSI_MIN) continue;

    if(r.ch >=1 && r.ch <= 13){
      ch_pkt_count[r.ch] += 1;
      ch_payload_bytes[r.ch] += r.frame_len;
    }

    String src = macToStr(r.src);
    String dst = macToStr(r.dst);
    String bssid = macToStr(r.bssid);
    String bnorm = normalizeMac(bssid);

    if(snifferMode.equalsIgnoreCase("focus")){
      String nsrc = normalizeMac(src);
      String ndst = normalizeMac(dst);
      if(!(bnorm == focusBSSID || nsrc == focusBSSID || ndst == focusBSSID)) continue;
    }

    String type = "OTHER";
    if(r.type == 0){
      if(r.subtype == 8) type = "BEACON";
      else if(r.subtype == 4) type = "PROBE_REQ";
      else if(r.subtype == 5) type = "PROBE_RESP";
      else type = "MGMT";
    } else if(r.type == 2) type = "DATA";
    else if(r.type == 1) type = "CTRL";

    bool has_rsn=false, has_wps=false;
    if(detect_rsnwps && (type == "BEACON" || type == "PROBE_RESP")){
      parseIEs(r, has_rsn, has_wps);
    }

    char linebuf[220];
    snprintf(linebuf, sizeof(linebuf), "[%05lu] %-9s | RSSI:%3d | CH:%02d | %s -> %s | %s",
             r.ts % 100000, type.c_str(), r.rssi, r.ch, src.c_str(), dst.c_str(), bssid.c_str());
    Serial.println(linebuf);

    if(pcapStreaming){
      pcap_write_packet(r);
    }

    Observation ob;
    ob.ts = r.ts;
    ob.type = type;
    ob.src = src;
    ob.dst = dst;
    ob.bssid = bssid;
    ob.rssi = r.rssi;
    ob.channel = r.ch;
    ob.has_rsn = has_rsn;
    ob.has_wps = has_wps;
    observations.push_back(ob);

    if((int)observations.size() > MAX_OBS){
      int removeCount = 200;
      if(removeCount > (int)observations.size()) removeCount = observations.size();
      observations.erase(observations.begin(), observations.begin() + removeCount);
    }
  }

  delay(2);
}
