// ============================================================================
// wireguard_service.cpp -- Stufe 7.3: Backend einbinden (kein Tunnel).
// Unbedingtes #include zieht die WireGuard-ESP32-Lib in Build/Link (Arduino-
// Library-Discovery braucht das ungeguarded). begin() startet KEINEN Tunnel -
// das ist 7.4 (Underlay-Bindung aus der NetworkRegistry).
// ============================================================================
#include "wireguard_service.h"
#include "src/WireGuard/WireGuard-ESP32.h"   // vendored (7.4a) - quoted include, damit
                                             // Arduino NICHT die installierte Lib zieht
#include "egress_policy.h"      // egressResolve (Policy -> NetIface)
#include "network_registry.h"   // NetIface
#include "network_platform.h"   // netIfaceNativeHandle/Name + netIfacePrepareEgress (kein ECM-Wissen hier)
#include "lwip/netif.h"          // ifaceUp(): netif_is_up/netif_is_link_up
#include "zone_runtime.h"       // Netzzonen: zoneRuntimeReachableCidrsFrom -> AllowedIPs der Client-Konfig
#include <Preferences.h>
#include <cstdio>               // 7.4d.4: sscanf (Client-IP-Ableitung)
#include <cstring>              // 7.4d.4: memset (Client-Key aus RAM wischen)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"      // 7.4d.1: Heap-Instrumentierung

extern "C" {
#include "src/WireGuard/wireguard.h"           // 7.4d.4: Keypair/Base64 fuer Client-QR
#include "src/WireGuard/wireguard-platform.h"  // wireguard_platform_init (DRBG-Seed)
}

// Backend-Objekt vorhalten (zieht die Lib in Build/Link). Kein begin() des Tunnels.
static WireGuard s_wg;

WireGuardService wireguardService;

void WireGuardService::begin() {
    // 7.3: bewusst leer - nur Backend im Build. Tunnel-Lifecycle folgt 7.4.
}

bool WireGuardService::backendAvailable() const {
    return true;   // 7.3: Backend ist Pflicht-Abhaengigkeit (siehe Header)
}

bool WireGuardService::isUp() const {
    return s_wg.is_initialized() && s_wg.isPeerUp();   // 7.4d: Handshake mit Peer?
}

String WireGuardService::statusText() const {
    if (isUp()) return "Tunnel verbunden";
    return cfg_.active ? "Backend eingebunden - getrennt" : "Backend eingebunden - inaktiv";
}

// ---- 7.4c: Persistenz (NVS "wg") -------------------------------------------
void WireGuardService::loadConfig() {
    Preferences p;
    p.begin("wg", true);
    cfg_.mode          = p.getString("mode", "server");   // 7.9
    cfg_.active        = p.getBool("active", false);
    cfg_.underlay      = p.getString("underlay", "auto");
    cfg_.localIp       = p.getString("localip", "10.9.0.1");   // 7.8: Default, kein Tippen noetig
    cfg_.keepalive     = (uint16_t)p.getUShort("keepalive", 25);
    cfg_.fullTunnel    = p.getBool("fulltun", false);
    // Server-Rolle
    cfg_.peerPublicKey = p.getString("peerpub", "");
    cfg_.endpointPort  = (uint16_t)p.getUShort("epport", 51820);
    cfg_.allowedIps    = p.getString("allowed", "0.0.0.0/0");
    cfg_.lanGateway    = p.getBool("langw", false);   // 7.6
    cfg_.lanTarget     = p.getString("lantgt", "wifi");   // 7.8
    // Client-Rolle (7.9)
    cfg_.clientEndpoint   = p.getString("cliep", "");
    cfg_.clientPort       = (uint16_t)p.getUShort("cliport", 51820);
    cfg_.clientPeerPub    = p.getString("clipub", "");
    cfg_.clientAllowedIps = p.getString("cliallow", "0.0.0.0/0");
    privKey_           = p.getString("privkey", "");
    psk_               = p.getString("psk", "");
    p.end();
    loadClients();   // 7.9.2: Client-Liste (+ Migration alter Einzel-Peer)
}

String WireGuardService::saveConfig(const WireGuardConfig& cfg, const String& privKeyOrEmpty, const String& pskOrEmpty) {
    cfg_ = cfg;
    // Underlay auf erlaubte Policy-Namen begrenzen.
    if (cfg_.underlay != "modem" && cfg_.underlay != "wifi") cfg_.underlay = "auto";
    if (cfg_.lanTarget != "ap" && cfg_.lanTarget != "both")  cfg_.lanTarget = "wifi";   // 7.8
    if (cfg_.mode != "client") cfg_.mode = "server";   // 7.9
    // Secrets nur ersetzen, wenn ein neuer Wert eingegeben wurde (leer = behalten).
    if (privKeyOrEmpty.length() > 0) privKey_ = privKeyOrEmpty;
    if (pskOrEmpty.length() > 0)     psk_     = pskOrEmpty;

    Preferences p;
    p.begin("wg", false);
    p.putString("mode", cfg_.mode);   // 7.9
    p.putBool("active", cfg_.active);
    p.putString("underlay", cfg_.underlay);
    p.putString("localip", cfg_.localIp);
    p.putUShort("keepalive", cfg_.keepalive);
    p.putBool("fulltun", cfg_.fullTunnel);
    p.putString("peerpub", cfg_.peerPublicKey);
    p.putUShort("epport", cfg_.endpointPort);
    p.putString("allowed", cfg_.allowedIps);
    p.putBool("langw", cfg_.lanGateway);   // 7.6
    p.putString("lantgt", cfg_.lanTarget);   // 7.8
    p.putString("cliep", cfg_.clientEndpoint);      // 7.9 Client-Rolle
    p.putUShort("cliport", cfg_.clientPort);
    p.putString("clipub", cfg_.clientPeerPub);
    p.putString("cliallow", cfg_.clientAllowedIps);
    p.putString("privkey", privKey_);
    p.putString("psk", psk_);
    p.end();
    return "WireGuard-Konfiguration gespeichert.";
}

// 7.4b: Underlay-Auswahl auflloesen und melden (kein Tunnel). sel = Policy
// (auto/modem/wifi) oder direkt eine NetIface-id.
String WireGuardService::underlayDiagJson(const String& sel) {
    NetIface iface;
    String j = "{\"requested\":\""; j += sel; j += "\",";
    if (!egressResolve(sel, iface)) {
        j += "\"resolved\":\"\",\"up\":false,\"native\":\"none\"}";
        return j;
    }
    void* nat = netIfaceNativeHandle(iface.id);
    j += "\"resolved\":\""; j += iface.id; j += "\",";
    j += "\"up\":";  j += iface.up ? "true" : "false"; j += ",";
    j += "\"ip\":\""; j += iface.ip; j += "\",";
    j += "\"native\":\""; j += (nat ? "available" : "none"); j += "\",";
    j += "\"nativeName\":\""; j += netIfaceNativeName(iface.id); j += "\"}";
    return j;
}

// ---- 7.8: MCU-Schluessel selbst erzeugen (kein Tippen) -----------------------
bool WireGuardService::ensureMcuKey() {
    if (privKey_.length()) return true;
    wireguard_platform_init();   // DRBG-Seed (sonst crasht wireguard_gen_keypair)
    uint8_t priv[32], pub[32];
    if (!wireguard_gen_keypair(priv, pub)) return false;
    char b[64]; size_t bl = sizeof(b);
    wireguard_base64_encode(priv, 32, b, &bl);
    privKey_ = String(b);
    memset(priv, 0, sizeof(priv));
    saveConfig(cfg_, privKey_, "");   // persistieren (PSK leer = behalten)
    return true;
}

String WireGuardService::mcuPublicKey() {
    if (privKey_.length() == 0) return "";
    uint8_t priv[32]; size_t l = sizeof(priv);
    if (!wireguard_base64_decode(privKey_.c_str(), priv, &l) || l != 32) return "";
    uint8_t pub[32];
    bool ok = wireguard_pub_from_priv(priv, pub);
    memset(priv, 0, sizeof(priv));
    if (!ok) return "";
    char b[64]; size_t bl = sizeof(b);
    wireguard_base64_encode(pub, 32, b, &bl);
    return String(b);
}

// 7.8: CIDR(s) der gewaehlten LAN-Ziele (wifi-sta und/oder eigener AP) fuer die Client-AllowedIPs.
String WireGuardService::lanCidrsForClient() {
    String r;
    if (cfg_.lanTarget == "wifi" || cfg_.lanTarget == "both") {
        String c = netIfaceSubnetCidr("wifi-sta"); if (c.length()) { if (r.length()) r += ", "; r += c; }
    }
    if (cfg_.lanTarget == "ap" || cfg_.lanTarget == "both") {
        String c = netIfaceSubnetCidr("wifi-ap");  if (c.length()) { if (r.length()) r += ", "; r += c; }
    }
    return r;
}

// ---- Zonen 0.1: Netzsicht fuer die Registry ---------------------------------
String WireGuardService::peerAllowedCidrs() {
    if (cfg_.mode == "client") return cfg_.clientAllowedIps;
    String r;
    for (size_t i = 0; i < clients_.size(); i++) {
        if (!clients_[i].ip.length()) continue;
        if (r.length()) r += ", ";
        r += clients_[i].ip + "/32";
    }
    return r;
}
String WireGuardService::clientConfigCidrs() {
    if (cfg_.mode == "client" || !cfg_.localIp.length()) return "";
    // Muss mit generateClientConfig() uebereinstimmen (dort werden genau diese AllowedIPs geschrieben).
    String allowed = cfg_.localIp + "/32";
    if (cfg_.lanGateway) { String lan = lanCidrsForClient(); if (lan.length()) allowed += ", " + lan; }
    String zoneNets = zoneRuntimeDesiredCidrsFrom("wg-server");
    if (zoneNets.length()) allowed += ", " + zoneNets;
    return allowed;
}
void* WireGuardService::nativeNetif() const { return s_wg.is_initialized() ? s_wg.netifHandle() : nullptr; }
// "up" = routingfaehig: lwIP-netif existiert UND ist up + link up (WireGuard.cpp setzt beides direkt nach
// netif_add; ein initialisiertes Handle allein waere nur "angelegt").
bool  WireGuardService::ifaceUp() const {
    if (!s_wg.is_initialized()) return false;
    struct netif* n = (struct netif*)s_wg.netifHandle();
    return n && netif_is_up(n) && netif_is_link_up(n);
}

// ---- 7.4d.4: "Client hinzufuegen (QR)" --------------------------------------
String WireGuardService::generateClientConfig(const String& endpointHostForClient, const String& name) {
    if (privKey_.length() == 0 && !ensureMcuKey()) { lastError_ = "MCU-Schluessel-Erzeugung fehlgeschlagen."; return ""; }
    if (cfg_.localIp.length() == 0) cfg_.localIp = "10.9.0.1";   // 7.8: Default statt Fehler
    String host = endpointHostForClient; host.trim();
    if (host.length() == 0)         { lastError_ = "Kein Endpoint-Hostname (DynDNS-Domain leer)."; return ""; }
    if ((int)clients_.size() >= WIREGUARD_MAX_PEERS) { lastError_ = "Maximale Client-Zahl erreicht (" + String(WIREGUARD_MAX_PEERS) + ")."; return ""; }

    // DRBG seeden, sonst crasht wireguard_gen_keypair -> mbedtls_ctr_drbg_random (siehe 7.4d.3).
    wireguard_platform_init();

    // Server-Public-Key aus MCU-Private-Key ableiten.
    uint8_t mcuPriv[32]; size_t mcuPrivLen = sizeof(mcuPriv);
    if (!wireguard_base64_decode(privKey_.c_str(), mcuPriv, &mcuPrivLen) || mcuPrivLen != 32) {
        lastError_ = "MCU Private Key ungueltig (Base64)."; return "";
    }
    uint8_t mcuPub[32];
    if (!wireguard_pub_from_priv(mcuPriv, mcuPub)) { lastError_ = "Server-Public-Key nicht ableitbar."; return ""; }

    // Frisches Client-Schluesselpaar auf dem Geraet.
    uint8_t cliPriv[32], cliPub[32];
    if (!wireguard_gen_keypair(cliPriv, cliPub)) { lastError_ = "Client-Schluessel-Erzeugung fehlgeschlagen."; return ""; }

    char b64[64]; size_t l;
    l = sizeof(b64); wireguard_base64_encode(mcuPub,  32, b64, &l); String serverPubB64(b64);
    l = sizeof(b64); wireguard_base64_encode(cliPub,  32, b64, &l); String cliPubB64(b64);
    l = sizeof(b64); wireguard_base64_encode(cliPriv, 32, b64, &l); String cliPrivB64(b64);

    // 7.9.2: naechste freie Tunnel-IP + Client an die LISTE anhaengen (nichts ueberschreiben).
    String clientIp = nextClientIp();
    WgClient nc;
    nc.name = name.length() ? name : ("Geraet " + String((int)clients_.size() + 1));
    nc.pub  = cliPubB64;
    nc.ip   = clientIp;
    clients_.push_back(nc);
    saveClients();
    cfg_.mode = "server";        // "Geraet hinzufuegen" ist eine Server-Operation
    saveConfig(cfg_, "", "");    // Secrets leer = behalten

    uint16_t port = cfg_.endpointPort ? cfg_.endpointPort : 51820;
    uint16_t ka   = cfg_.keepalive ? cfg_.keepalive : 25;
    // AllowedIPs des Clients: immer die Server-Tunnel-IP. Bei LAN-Gateway zusaetzlich das
    // LAN-Subnetz (dann routet der Client LAN-Traffic durch den Tunnel; der MCU NAT'et ihn).
    String allowed = cfg_.localIp + "/32";
    if (cfg_.lanGateway) {
        String lan = lanCidrsForClient();
        if (lan.length()) allowed += ", " + lan;
    }
    // Netzzonen: alle Ziel-Netze, fuer die eine Policy wg-server -> X (ROUTE/NAT) installiert ist, in
    // AllowedIPs aufnehmen -- dann routet der Client sie automatisch in den Tunnel (kein Handeintrag mehr,
    // z. B. 192.168.110.0/24 fuers Firmen-VPN). clientConfigCidrs() spiegelt genau diese Menge zurueck.
    {
        String zoneNets = zoneRuntimeDesiredCidrsFrom("wg-server");   // GEWUENSCHT (persistent), nicht Laufzeitzustand
        if (zoneNets.length()) allowed += ", " + zoneNets;
    }
    String conf;
    conf  = "[Interface]\n";
    conf += "PrivateKey = " + cliPrivB64 + "\n";
    conf += "Address = " + clientIp + "/32\n\n";
    conf += "[Peer]\n";
    conf += "PublicKey = " + serverPubB64 + "\n";
    conf += "Endpoint = " + host + ":" + String(port) + "\n";
    conf += "AllowedIPs = " + allowed + "\n";
    conf += "PersistentKeepalive = " + String(ka) + "\n";

    // Client-Private-Key aus dem RAM wischen (bleibt nur im zurueckgegebenen conf-String).
    memset(cliPriv, 0, sizeof(cliPriv));
    memset(mcuPriv, 0, sizeof(mcuPriv));
    lastError_ = "";
    return conf;
}

// ---- 7.9.2: Client-Liste (Server-Rolle) -------------------------------------
void WireGuardService::loadClients() {
    clients_.clear();
    Preferences p; p.begin("wg", true);
    String blob = p.getString("clients", "");
    p.end();
    int start = 0;
    while (start < (int)blob.length()) {
        int nl = blob.indexOf('\n', start);
        String line = (nl < 0) ? blob.substring(start) : blob.substring(start, nl);
        start = (nl < 0) ? blob.length() : nl + 1;
        line.trim();
        if (!line.length()) continue;
        int p1 = line.indexOf('|'); int p2 = (p1 < 0) ? -1 : line.indexOf('|', p1 + 1);
        if (p1 < 0 || p2 < 0) continue;
        WgClient c; c.name = line.substring(0, p1); c.pub = line.substring(p1 + 1, p2); c.ip = line.substring(p2 + 1);
        clients_.push_back(c);
    }
    // Migration: alte Einzel-Peer-Config (peerPublicKey/allowedIps) -> ein Listen-Client,
    // damit ein bereits eingerichtetes Geraet nach dem Update erhalten bleibt.
    if (clients_.empty() && cfg_.peerPublicKey.length()) {
        WgClient c; c.name = "Geraet 1"; c.pub = cfg_.peerPublicKey;
        c.ip = cfg_.allowedIps; int s = c.ip.indexOf('/'); if (s >= 0) c.ip = c.ip.substring(0, s);
        c.ip.trim(); if (!c.ip.length()) c.ip = "10.9.0.2";
        clients_.push_back(c);
        saveClients();
    }
}

void WireGuardService::saveClients() {
    String blob;
    for (size_t i = 0; i < clients_.size(); i++) {
        String nm = clients_[i].name; nm.replace("|", " "); nm.replace("\n", " ");
        blob += nm + "|" + clients_[i].pub + "|" + clients_[i].ip + "\n";
    }
    Preferences p; p.begin("wg", false);
    p.putString("clients", blob);
    p.end();
}

String WireGuardService::nextClientIp() {
    int a = 10, b = 9, c = 0, d = 1;
    sscanf(cfg_.localIp.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);
    String base = String(a) + "." + String(b) + "." + String(c) + ".";
    for (int host = 2; host <= 254; host++) {
        if (host == d) continue;   // Server-IP auslassen
        String cand = base + String(host);
        bool used = false;
        for (size_t i = 0; i < clients_.size(); i++) if (clients_[i].ip == cand) { used = true; break; }
        if (!used) return cand;
    }
    return base + "2";
}

// Nach begin() (Peer[0] ist bereits angelegt): restliche Clients als Peers ergaenzen und die
// Laufzeit-Peer-Indizes merken (fuer den Handshake-Status je Client).
void WireGuardService::addAllServerPeers() {
    if (clients_.empty()) return;
    clients_[0].peerIdx = s_wg.firstPeerIndex();
    for (size_t i = 1; i < clients_.size(); i++) {
        IPAddress aip; aip.fromString(clients_[i].ip);
        clients_[i].peerIdx = s_wg.addServerPeer(clients_[i].pub.c_str(), aip);
    }
}

String WireGuardService::clientsJson() {
    bool running = (cfg_.mode != "client") && s_wg.is_initialized();
    String j = "[";
    for (size_t i = 0; i < clients_.size(); i++) {
        if (i) j += ",";
        bool up = running && s_wg.isPeerUpIndex(clients_[i].peerIdx);
        long rxAgo = -1, txAgo = -1;   // Sekunden seit letztem Datenpaket; -1 = nie
        if (running && clients_[i].peerIdx >= 0) {
            uint32_t rxa = 0, txa = 0;
            if (s_wg.peerStats(clients_[i].peerIdx, rxa, txa)) {
                rxAgo = (rxa == 0xFFFFFFFFu) ? -1 : (long)(rxa / 1000);
                txAgo = (txa == 0xFFFFFFFFu) ? -1 : (long)(txa / 1000);
            }
        }
        String nm = clients_[i].name; nm.replace("\\", "\\\\"); nm.replace("\"", "\\\"");
        j += "{\"i\":"; j += String((int)i);
        j += ",\"name\":\""; j += nm; j += "\"";
        j += ",\"ip\":\""; j += clients_[i].ip; j += "\"";
        j += ",\"up\":"; j += up ? "true" : "false";
        j += ",\"rxAgo\":"; j += String(rxAgo);
        j += ",\"txAgo\":"; j += String(txAgo); j += "}";
    }
    j += "]";
    return j;
}

bool WireGuardService::deleteClient(int index) {
    if (index < 0 || index >= (int)clients_.size()) return false;
    clients_.erase(clients_.begin() + index);
    saveClients();
    // Neustart, falls der Server laeuft, damit die Peer-Liste neu gesetzt wird.
    if (cfg_.active && cfg_.mode != "client") { disconnect(); connect(); }
    return true;
}

// ---- 7.4d: manueller Tunnel-Lifecycle ---------------------------------------
static void wgConnectTrampoline(void* arg) {
    ((WireGuardService*)arg)->runConnectBlocking();
    vTaskDelete(nullptr);
}

String WireGuardService::connect() {
    if (connecting_)           return "Verbindungsaufbau laeuft bereits.";
    if (s_wg.is_initialized()) return "Bereits aktiv - erst trennen.";
    if (!cfg_.active)                 return "VPN nicht aktiv (Haken setzen).";
    if (privKey_.length() == 0 && !ensureMcuKey()) return "MCU-Schluessel-Erzeugung fehlgeschlagen.";
    if (cfg_.mode == "client") {
        if (cfg_.clientEndpoint.length() == 0) return "Ziel-Server (Endpoint) fehlt.";
        if (cfg_.clientPeerPub.length() == 0)  return "Public Key der Gegenstelle fehlt.";
    } else {
        if (clients_.empty())                  return "Noch kein Client - erst 'Geraet hinzufuegen'.";
    }
    if (cfg_.localIp.length() == 0)     cfg_.localIp = "10.9.0.1";   // 7.8: Default
    // 7.4d.2: Endpoint-Host LEER = Server-/Responder-Modus (Peer verbindet zu uns auf
    // endpointPort = Listen-Port). Sonst Client-Modus (wir verbinden zum Endpoint).

    NetIface iface;
    if (!egressResolve(cfg_.underlay, iface)) return "Kein Underlay-Interface verfuegbar.";
    void* nat = netIfaceNativeHandle(iface.id);
    if (!nat) return "Underlay-netif nicht aufloesbar (" + iface.id + ").";

    lastUnderlay_      = iface.id;
    pendingUnderlay_   = nat;
    lastError_         = "";
    heapBeforeConnect_ = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    pendingGen_        = ++connectGen_;
    connecting_        = true;
    // Eigener Task: begin() macht DNS + Crypto synchron (Stack), darf den Webserver nicht blockieren.
    // 7.4d.3: Stack 12288 -> 16384. begin() laeuft nur mit gueltigem Key komplett durch
    // (device_init: curve25519 + blake2s tief auf dem Stack); Reset-Grund in /sysinfo.json
    // unterscheidet danach PANIC (Bad-Access/Stack) von Watchdog.
    if (xTaskCreatePinnedToCore(wgConnectTrampoline, "wg_conn", 16384, this, 5, nullptr, 1) != pdPASS) {
        connecting_ = false;
        return "Task konnte nicht gestartet werden.";
    }
    return "";
}

void WireGuardService::runConnectBlocking() {
    uint32_t myGen = pendingGen_;
    // Endpoint-DNS ueber das gewaehlte Underlay erreichbar machen - gekapselt in
    // network_platform (kein ECM-Wissen hier). Fuer den Isolationstest kann der Endpoint
    // auch numerisch sein -> dann faellt DNS ganz weg. Der Tunnel-Egress haengt am
    // udp_bind_netif (7.4b), nicht hieran.
    netIfacePrepareEgress(lastUnderlay_);

    // 7.9: Rollen-abhaengige Felder. Server: kein Endpoint (lauscht), Peer = zugelassenes
    // Client-Geraet. Client: Endpoint = Ziel-Server, Peer = dessen Public Key.
    bool client = (cfg_.mode == "client");
    if (!client && clients_.empty()) { lastError_ = "Noch kein Client - erst 'Geraet hinzufuegen'."; connecting_ = false; return; }
    // Server: Peer[0] = erster Client der Liste; die restlichen werden nach begin() ergaenzt.
    String ep     = client ? cfg_.clientEndpoint   : String("");
    uint16_t port = client ? cfg_.clientPort       : cfg_.endpointPort;
    String peer   = client ? cfg_.clientPeerPub    : clients_[0].pub;
    String allow  = client ? cfg_.clientAllowedIps : (clients_[0].ip + "/32");

    s_wg.setPresharedKey(psk_.length() ? psk_.c_str() : nullptr);
    s_wg.setRouteDefault(cfg_.fullTunnel);   // 7.4d: Split = kein Default-Route-Uebernahme
    s_wg.setAllowedIps(allow.length() ? allow.c_str() : nullptr);  // 7.4d.1
    s_wg.setKeepalive(cfg_.keepalive);       // 7.4d.1

    IPAddress lip;
    if (!lip.fromString(cfg_.localIp)) { lastError_ = "Tunnel-IP ungueltig."; connecting_ = false; return; }

    bool ok = s_wg.begin(lip, privKey_.c_str(), ep.c_str(),
                         peer.c_str(), port, pendingUnderlay_);
    heapAfterBegin_ = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);

    if (!ok) { lastError_ = "begin() fehlgeschlagen (Key/Endpoint/DNS pruefen)."; connecting_ = false; return; }

    // 7.4d.1: wurde waehrenddessen disconnect() gerufen? Dann den gerade aufgebauten
    // Tunnel sofort wieder abbauen - kein Tunnel darf nach einem Disconnect hochkommen.
    if (connectGen_ != myGen) { s_wg.end(); connecting_ = false; return; }

    // 7.9.2: im Server-Modus die restlichen Clients (ab Index 1) als Peers ergaenzen.
    if (!client) addAllServerPeers();

    // 7.6/7.8 LAN-Gateway: NAPT auf dem/den gewaehlten LAN-Interface(s) (wifi-sta und/oder
    // eigener AP) aktivieren, damit weitergeleitete Tunnel-Pakete auf die jeweilige ESP-LAN-IP
    // maskiert werden. Erst NACH dem Cancel-Check. Scheitern (Netz aus) ist nicht fatal.
    naptOn_ = false;
    lanCidr_ = "";
    if (!client && cfg_.lanGateway) {   // 7.9: LAN-Gateway ist eine Server-Rollen-Funktion
        // 7.9.8 FIX: esp-lwip markiert das PRIVATE/Input-netif mit NAPT (nicht das Output!).
        // Also NAPT aufs WG-netif. Ein Flag genuegt fuer alle LAN-Ziele - ip_napt_forward nimmt
        // die IP des tatsaechlich gewaehlten Ausgangs (st1 bzw. eigener AP) als NAT-Adresse.
        naptOn_  = netIfaceSetNaptNative(s_wg.netifHandle(), true);
        lanCidr_ = lanCidrsForClient();
    }
    // NAPT-Fehlschlag (z.B. Netz aus) ist NICHT fatal: der Tunnel zum MCU steht weiter.
    // Kein lastError_ setzen (sonst faelschlich Status "Fehler"); die UI zeigt lanGw&&!napt.
    connecting_ = false;
}

// 7.9.1: Autostart + Selbstheilung. Aus loop() aufgerufen. Wenn die Rolle aktiv ist, aber
// nicht laeuft (Boot, oder nach einem Fehlschlag), wird mit 10s-Backoff neu gestartet. So
// laeuft der Server automatisch, sobald "aktiv" gespeichert ist - keine manuellen Buttons.
void WireGuardService::supervise() {
    if (!cfg_.active) return;                               // nicht gewuenscht
    if (connecting_ || s_wg.is_initialized()) return;       // startet gerade / laeuft schon
    uint32_t now = millis();
    if (lastStartAttempt_ != 0 && (now - lastStartAttempt_) < 10000) return;   // Backoff
    lastStartAttempt_ = now;
    connect();   // Fehler (z.B. noch kein Client) landen in lastError_; naechster Tick erneut
}

void WireGuardService::disconnect() {
    connectGen_++;   // 7.4d.1: laufenden Connect-Versuch annullieren (Cancel)
    // 7.9.8: NAPT auf dem WG-netif abschalten - VOR s_wg.end() (danach ist das netif weg).
    if (naptOn_) { netIfaceSetNaptNative(s_wg.netifHandle(), false); naptOn_ = false; lanCidr_ = ""; }
    if (s_wg.is_initialized()) s_wg.end();
    lastError_  = "";
    connecting_ = false;
    heapAfterDisconnect_ = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
}

VpnStatus WireGuardService::vpnStatus() {
    VpnStatus s;
    bool init = s_wg.is_initialized();
    bool peer = init && s_wg.isPeerUp();
    bool serverMode = (cfg_.mode != "client");
    s.service = "WireGuard";
    s.role    = serverMode ? "server" : "client";
    s.active  = cfg_.active;
    if (lastError_.length())       s.state = VpnState::Error;
    else if (peer)                 s.state = VpnState::Connected;
    else if (init && serverMode)   s.state = VpnState::Listening;
    else if (init || connecting_)  s.state = VpnState::Connecting;
    else                           s.state = cfg_.active ? VpnState::Disconnected : VpnState::Inactive;
    s.stateText = vpnStateName(s.state);
    s.endpoint  = serverMode ? (String("Listen-Port ") + String(cfg_.endpointPort))
                             : (cfg_.clientEndpoint + ":" + String(cfg_.clientPort));
    s.underlay  = lastUnderlay_;
    s.tunnelIp  = cfg_.localIp;
    if (serverMode) {
        if (naptOn_)             s.detail = "LAN-Gateway aktiv -> " + lanCidr_;
        else if (cfg_.lanGateway) s.detail = "LAN-Gateway gewuenscht (Zielnetz aus?)";
    }
    s.error = lastError_;
    return s;
}

String WireGuardService::statusJson() {
    bool init = s_wg.is_initialized();
    bool peer = init && s_wg.isPeerUp();
    bool serverMode = (cfg_.mode != "client");
    String st;
    if (lastError_.length())              st = "Fehler";
    else if (peer)                        st = "verbunden";
    else if (init && serverMode)          st = "laeuft (wartet auf Clients)";
    else if (init || connecting_)         st = "verbindet";
    else                                  st = "getrennt";

    String j = "{";
    j += "\"state\":\"";    j += st;            j += "\",";
    j += "\"mode\":\"";     j += serverMode ? "server" : "client"; j += "\",";
    j += "\"underlay\":\""; j += lastUnderlay_; j += "\",";
    j += "\"wgip\":\"";     j += cfg_.localIp;  j += "\",";
    j += "\"endpoint\":\""; j += (serverMode ? String("(Listen-Port ") + String(cfg_.endpointPort) + ")"
                                             : cfg_.clientEndpoint + ":" + String(cfg_.clientPort)); j += "\",";
    j += "\"peerUp\":";     j += peer ? "true" : "false"; j += ",";
    j += "\"lanGw\":";      j += cfg_.lanGateway ? "true" : "false"; j += ",";   // 7.6 gewuenscht
    j += "\"napt\":";       j += naptOn_ ? "true" : "false"; j += ",";           // 7.6 aktiv
    j += "\"lanCidr\":\"";  j += lanCidr_;      j += "\",";
    j += "\"lanTarget\":\"";j += cfg_.lanTarget; j += "\",";                      // 7.8
    j += "\"mcuPub\":\"";   j += mcuPublicKey(); j += "\",";                      // 7.8 (zum Anzeigen/Kopieren)
    j += "\"error\":\"";    j += lastError_;    j += "\",";
    // 7.4d.1: Heap-Instrumentierung (nur beobachten, nicht optimieren)
    j += "\"heapFree\":";    j += String((uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));         j += ",";
    j += "\"heapLargest\":"; j += String((uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)); j += ",";
    j += "\"heapMin\":";     j += String((uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));  j += ",";
    j += "\"heapBeforeConnect\":"; j += String(heapBeforeConnect_);    j += ",";
    j += "\"heapAfterBegin\":";    j += String(heapAfterBegin_);       j += ",";
    j += "\"heapAfterDisconnect\":"; j += String(heapAfterDisconnect_); j += "";
    j += "}";
    return j;
}
