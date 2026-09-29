// ============================================================================
// serial_console.cpp  --  Serielle Kommando-Konsole (siehe serial_console.h)
//
// Minimaler Zeilen-Parser + Dispatch auf die schon vorhandene Kern-Logik. KEINE
// eigene Modem-/DynDNS-Logik -- nur lesend/aufrufend. Hinweis: connect/disconnect/
// reset/test rufen synchrone Treiber-Funktionen und blockieren die loop() kurz
// (wie der jeweilige Web-Handler auch) -- das ist fuer eine interaktive Konsole ok.
// ============================================================================
#include "serial_console.h"

#include <Arduino.h>
#include <Preferences.h>       // Baudrate (NVS "cfg"/"uartbaud")
#include <string.h>
#include <esp_heap_caps.h>
#include <esp_system.h>        // esp_reset_reason
#include <sys/socket.h>        // ipsec fetch: TCP-Test durch den Tunnel
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "web_ui.h"            // dyndns*-Globals + (via web_ui.h) ec200a_modem.h
#include "ec200a_ecm.h"        // ec200aEcm (Status-Anzeige)
#include "modem_datalink.h"    // neutrale Datenlink-Weiche (ppp|ecm)
#include "modem_sim.h"         // SIM-PIN: Status/Sperre auf der Karte ('pin')
#include "modem_clock.h"       // Systemzeit aus dem Netz ('time')
#include "acme_client.h"       // Let's Encrypt ('acme', 'acme now')
#include "cert_store.h"         // Zertifikatsherkunft ('cert', Notbetrieb)
void saveWebHttpsEnabled(bool enabled);   // Definition in der .ino (NVS wifi/webhttps) -- 'web http|https'
#include "wan_policy.h"        // Netzzugang ('wan')
#include "ipsec_service.h"     // IPsec-Diagnose ('ipsec', 'ipsec connect|disconnect')
#include "ipsec_runtime.h"
#include "ipsec_crypto_caps.h"   // ipsecPfsSupported(): Faehigkeit des Clients (getrennt vom Peer-Verhalten)
#include "weird_http.h"          // weirdHttpUrlDecode: PSK-Selbsttest (Formular-Dekodierung wie der Web-Handler)
#include <ctype.h>
#include "ipsec_config_fields.h" // 'ipsec config|fields|get|set|save' -- derselbe Feld-Layer wie die Web-UI
#include "vpn_status.h"
#include "aes_engine.h"        // 'ipsec aes' / 'ipsec aesbench' -- AES-Backend + Vergleich unter Last
#include "settings_backup.h"   // 'backup' / 'restore'
#include "setup_guard.h"       // setupUartEnabled(): UART-Zugriffsschutz (Konsole an/aus)
#include "wireguard_service.h" // 'wg ...' -- WireGuard-Konfiguration/Steuerung ueber UART (UI-Paritaet)
#include "network_mode.h"      // 'lan' -- Router-LAN-Subnetz/Forwarding/AP-Kanal
#include "wifi_caps.h"         // 'wlan' -- WLAN-Stack-Modus
#include "camera_stream_service.h" // 'video' -- Live-Bildrate
#include "rtsp_server.h"       // 'video' -- RTSP-Status
#include "usb_device_service.h" // 'usbdev' -- WeirdOS als UVC-Webcam am PC (UI-Paritaet)
#include "usb_ports.h"          // 'usbports' -- USB-Port-Mapping des Boards
#include "platform.h"           // 'platform' -- Board-Profil (zentrale Board-Wahrheit, auch initial per UART setzbar)
// UI-Paritaet: diese Persistenz-Helfer leben in der .ino (externe Bindung), hier deklariert.
void saveDyndnsPrefs();
void saveWifiCredentials(const String& ssid, const String& password);
void saveTargetEnabled(bool enabled);
void saveApPreference(bool keep);
#include "zone_planner_adapter.h"   // 'zones' / 'zones plan' -- Netzzonen Phase 0 (read-only Planner-Vorschau)
#include "zone_lwip_hooks.h"        // 'zones routes|route|filter|counters' -- Netzzonen 0.3 (Zielrouten, Forward-Hook, Zaehler)
#include "zone_runtime.h"           // 'zones policies|policy|apply' -- Netzzonen 0.5 (Policy-Runtime)
#include "net_scan.h"               // 'net ping|portscan' -- generische L3/L4-Diagnose ueber lwIP-Routing (auch VPN-Netze)

// Freie Funktion aus der .ino (kein Header):
void dyndnsForceNow();

// ---- Restore-Aufnahme: nach 'restore' werden Zeilen bis 'END' gesammelt und dann eingespielt ----
static bool   s_restoreMode = false;
static String s_restoreBuf;
static int    s_restoreLines = 0;
static void cmdBackup() {
    Serial.println(F("BEGIN WEIRDOS-BACKUP  (Zeilen kopieren; Secrets wie PIN/PSK/Passwoerter sind NICHT enthalten)"));
    Serial.print(settingsBackupExport());
    Serial.println(F("END WEIRDOS-BACKUP"));
}
static void cmdRestoreStart() {
    s_restoreMode = true; s_restoreBuf = ""; s_restoreLines = 0;
    s_restoreBuf.reserve(4096);
    Serial.println(F("RESTORE: jetzt die Sicherung zeilenweise einfuegen (ab 'WEIRDOS-BACKUP v1'),"));
    Serial.println(F("         abschliessen mit einer Zeile 'END' -- abbrechen mit 'ABORT'."));
}
static void restoreLine(const char* line) {
    if (!strcmp(line, "ABORT")) { s_restoreMode = false; s_restoreBuf = ""; Serial.println(F("RESTORE abgebrochen, nichts geschrieben.")); return; }
    if (!strcmp(line, "END") || !strcmp(line, "END WEIRDOS-BACKUP")) {
        s_restoreMode = false;
        int n = settingsBackupImport(s_restoreBuf);
        s_restoreBuf = "";
        Serial.printf("RESTORE: %d Eintraege aus %d Zeilen uebernommen. Secrets (PIN/PSK/Passwoerter) neu setzen. 'reboot' zum Aktivieren.\r\n", n, s_restoreLines);
        return;
    }
    if (!strncmp(line, "BEGIN ", 6)) return;   // Kopfzeile aus 'backup' ueberspringen
    s_restoreBuf += line; s_restoreBuf += '\n'; s_restoreLines++;
    if ((s_restoreLines % 20) == 0) Serial.printf("RESTORE: %d Zeilen ...\r\n", s_restoreLines);
}

// ---- IPsec-Konfigurationsentwurf der Konsole: 'ipsec set' aendert den Entwurf, 'ipsec save' prueft
//      und speichert ihn ueber DENSELBEN Pfad wie die Web-UI (IpsecService::saveConfig). Secrets liegen
//      nur im Entwurf und werden nach dem Speichern geloescht. ----
static bool        s_draftLive = false;
static IpsecConfig s_draft;
static String      s_draftPsk, s_draftEapPass;    // leer = bestehendes Secret behalten
static bool        s_pemMode = false;             // 'ipsec set ca-pem|extra-pem' ohne Wert: Zeilen bis 'END' sammeln
static String      s_pemKey;                      // welcher PEM-Block gerade eingefuegt wird (ca-pem = Anker, extra-pem = Kettenmaterial)
static String      s_pemBuf;
static IpsecConfig& draft() { if (!s_draftLive) { s_draft = ipsecService.config(); s_draftLive = true; } return s_draft; }
static void draftDiscard() { s_draftLive = false; s_draft = IpsecConfig(); s_draftPsk = ""; s_draftEapPass = ""; }
static void pemLine(const char* line) {
    if (!strcmp(line, "ABORT")) { s_pemMode = false; s_pemBuf = ""; Serial.println(s_pemKey + ": abgebrochen, Entwurf unveraendert."); return; }
    if (!strcmp(line, "END")) {
        s_pemMode = false;
        String& dst = (s_pemKey == "extra-pem") ? draft().extraPem : draft().caPem;
        dst = s_pemBuf; dst.trim(); s_pemBuf = "";
        Serial.printf("%s: %u Zeichen in den Entwurf uebernommen ('ipsec save' speichert).\r\n", s_pemKey.c_str(), (unsigned)dst.length());
        return;
    }
    s_pemBuf += line; s_pemBuf += '\n';
}

// ---------------------------------------------------------------------------
static char   s_line[1024];   // Backup-Zeilen (base64) koennen lang sein
static size_t s_len   = 0;
static bool   s_hello = false;

static const char* resetReasonStr() {
    switch (esp_reset_reason()) {
        case ESP_RST_POWERON:  return "POWERON";
        case ESP_RST_SW:       return "SW";
        case ESP_RST_PANIC:    return "PANIC";
        case ESP_RST_TASK_WDT: return "TASK_WDT";
        case ESP_RST_INT_WDT:  return "INT_WDT";
        case ESP_RST_BROWNOUT: return "BROWNOUT";
        case ESP_RST_DEEPSLEEP:return "DEEPSLEEP";
        default:               return "OTHER";
    }
}

static String currentWanIp() { return modemLinkWanIp(); }   // neutrale Weiche (ppp|ecm)

static void cmdStatus() {
    Serial.println(F("--- status ---"));
    Serial.print  (F("modem : ")); Serial.println(modemStatusText());
    Serial.print  (F("mode  : ")); Serial.println(modemLinkModeName());
    bool up = modemLinkIsUp();
    Serial.print  (F("link  : ")); Serial.println(up ? "UP" : "down");
    String ip = currentWanIp();
    Serial.print  (F("wan-ip: ")); Serial.println(ip.length() ? ip : String("-"));
    String ip6 = ecmWanIp6();   // nur ECM kann IPv6 (PPP-IPv6 ist im lwIP aus)
    Serial.print  (F("wan-ip6: ")); Serial.println(ip6.length() ? ("[" + ip6 + "]") : String("- (nur ECM)"));
    Serial.printf ("heap  : intern frei %u k, groesster %u k\r\n",
        (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024),
        (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024));
    Serial.printf ("psram : frei %u k, groesster %u k\r\n",
        (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024),
        (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) / 1024));
    Serial.printf ("uptime: %lu s   reset: %s\r\n",
        (unsigned long)(millis() / 1000), resetReasonStr());
}

// Befehlsliste als EINE Quelle: fuer 'help' auf der Konsole UND fuer die Web-UI
// (Einrichtung > Setup > UART), damit beide nie auseinanderlaufen.
static const char kHelpText[] =
        "Befehle:\r\n"
        "  help / ?          diese Liste\r\n"
        "  status            Modem/Link/WAN-IP/Heap/PSRAM/Uptime\r\n"
        "  connect           Modem-Datenpfad starten (PPP oder ECM je 'mode')\r\n"
        "  disconnect        Modem-Datenpfad trennen\r\n"
        "  reset             Modem soft-rebooten (AT+CFUN=1,1)\r\n"
        "  usbcycle          USB-Root-Port deaktivieren/aktivieren (Modem re-enumeriert, bootet nicht; Link-Recovery Stufe 1)\r\n"
        "  test              Internet-Erreichbarkeitstest\r\n"
        "  ip                aktuelle WAN-IP\r\n"
        "  at <cmd>          AT-Kommando ans Modem (IF3) senden\r\n"
        "  apn               APN/Zugangsdaten zeigen\r\n"
        "  apn <name> [u p]  APN setzen (public-IPv4 erreichbar: o2 netpublic | Telekom internet.t-d1.de)\r\n"
        "  band              LTE-Bandprofil/Netzmodus zeigen\r\n"
        "  band auto|low|mid Bandprofil setzen (auto=ALLE Baender) + anwenden\r\n"
        "  band custom <hex> eigene LTE-Bitmaske | band net auto|lte|gsm\r\n"
        "  pdp [ip|ipv4v6]   PDP-Typ zeigen/setzen (ipv4v6 = IPv6, nur mit ECM)\r\n"
        "  mode [ppp|ecm]    Datenschicht zeigen/umschalten (rebootet den ESP; ecm = IPv6-faehig)\r\n"
        "  nat [nic|routing] ECM-Betriebsart zeigen/setzen (nic = oeffentliche IP am ESP; Modem-Reboot)\r\n"
        "  wan [auto|cellular|wifi]  Netzzugang (WanPolicy) zeigen/setzen\r\n"
        "  ipsec             IPsec-Diagnose: Config/Policy, Status, Peer, UDP-Zaehler, IKE-Log\r\n"
        "  ipsec connect|disconnect  Verbindung planen/trennen (wie die Web-Buttons)\r\n"
        "  ipsec rekey               Child-SA jetzt neu schluesseln (CREATE_CHILD_SA, Test)\r\n"
        "  ipsec ikerekey            IKE-SA jetzt neu schluesseln (CREATE_CHILD_SA mit IKE-Proposal + neuer D-H, Test)\r\n"
        "  ipsec psk-selftest        PSK-Byte-Audit: Sonderzeichen-Roundtrip Web-Dekodierung + NVS (synthetisch, ohne echtes Secret)\r\n"
        "  ipsec psk-verify <wert>   gespeicherten PSK bytegenau mit <wert> vergleichen (Ausgabe nur gleich/ungleich)\r\n"
        "  ipsec pfs on|off          PFS fuer den Child-Rekey speichern (Alias fuer set pfs + save)\r\n"
        "  ipsec config              komplette IPsec-Konfiguration zeigen (Secrets maskiert; Entwurf falls ungespeichert)\r\n"
        "  ipsec fields              alle Schluessel mit Typ/erlaubten Werten (identisch mit der Web-UI)\r\n"
        "  ipsec get <key>           einen Wert lesen\r\n"
        "  ipsec set <key> <wert>    einen Wert im Entwurf setzen (Pruefung wie Web-UI); 'set ca-pem' / 'set extra-pem' ohne Wert = Einfuegemodus bis END\r\n"
        "                            Trust-Modell: 'set trust-mode public|public-plus|own|none' (ca-pem = Vertrauensanker, extra-pem = Kettenmaterial)\r\n"
        "  ipsec save                Entwurf pruefen + speichern (wie 'Speichern': kein Reconnect, manueller Stop bleibt)\r\n"
        "  ipsec save-reconnect      speichern + neu verbinden (wie 'Speichern & neu verbinden')\r\n"
        "  ipsec discard             Entwurf verwerfen\r\n"
        "  ipsec ping <ip>           innerer ICMP-Echo durch den Tunnel (wie Test-Ping im Web)\r\n"
        "  ipsec fetch <ip>[:port]   HTTP GET durch den Tunnel (TCP-Test ueber ipsec0, z.B. 192.168.178.1)\r\n"
        "  ipsec aes [hw|soft|dma]   AES-Backend zeigen/setzen (hw=Register ohne DMA, Vorgabe)\r\n"
        "  ipsec aesbench [len] [n]  AES-Backends unter Last vergleichen (Fehler/Zeit/DMA-Heap)\r\n"
        "  wg                WireGuard zeigen/steuern (mode|on|off|set|psk|save|connect|disconnect|clients|addclient|delclient)\r\n"
        "  wlan              WLAN zeigen/setzen (connect <ssid> <pass>|off|ap on|off|stack auto|on|off)\r\n"
        "  lan               LAN-Allgemein (subnet <cidr>|forwarding none|napt|apchannel auto|1..13)\r\n"
        "  setup             Setup/Zugriffsschutz (captive|reset|resethold|fullreset|fullhold|uart on|off)\r\n"
        "  video             Video (fps <1..30>); Stream/Aufloesung/Ports ueber die Web-UI\r\n"
        "  dyndns            DynDNS zeigen/setzen (on|off|set <key> <wert>|pass <wert>|now)\r\n"
        "  platform          Board-Profil (esp32-p4-pico | xiao-esp32-s3 | custom): platform set <id> | export | import <json>\r\n"
        "  usbports          USB-Anschluesse des Boards (count <n> | set <i> <dm> <dp> [name] | enable <i> on|off)\r\n"
        "  usbdev            WeirdOS als USB-Geraet am PC (port <USBn> | export camera0|testpattern0 uvc|off | fps <n>), Status\r\n"
        "  ipsec user ...    IPsec-Server-Benutzer (list|add <name>|del <index>)\r\n"
        "  zones             Netzzonen (Phase 0): Attachments, erreichbare Netze, Capabilities (read-only)\r\n"
        "  zones napt        NAPT-Flags aller netifs (existiert die globale NAPT-Tabelle?)\r\n"
        "  zones plan <quelle> <ziel> [allow|deny|route|nat]  Planner-Vorschau (effektiver Modus + Grund, nichts wird installiert)\r\n"
        "  zones routes      Zielrouten, Test-Filter, Forward-Zaehler + ob die lwIP-Hooks (eigenes liblwip.a) gelinkt sind\r\n"
        "  zones route add <a.b.c.d/n> <iface-id>  Zielroute setzen (0.3-Test; del <netz> | clear | rebind nach Tunnel-Reconnect); Ausgang down = BLOCK, nie Standardroute\r\n"
        "  zones filter deny <in|*> <out|*>       Forward zwischen zwei Interfaces verwerfen (0.3-Test; allow = Regel weg | clear)\r\n"
        "  zones counters [reset]                 weitergeleitet/verworfen je (Eingang -> Ausgang)\r\n"
        "  zones policies                         Zonen-Policies (Intent persistent) + effektive Plaene + installierte Routen/Paare/NAT (0.5)\r\n"
        "  zones policy <quelle> <ziel> [allow|deny|route|nat]  Policy setzen: kompiliert + installiert Route/Forward/NAT sofort; del <quelle> <ziel> entfernt\r\n"
        "  zones apply                            Policies neu kompilieren + installieren (passiert automatisch bei Registry-Aenderung)\r\n"
        "  pin               SIM-PIN: gespeichert? + Karten-Status (Sperre, Restversuche)\r\n"
        "  pin set <pin>     SIM-PIN in WeirdOS speichern | pin clear -> loeschen\r\n"
        "  pin enable|disable <pin> | pin change <alt> <neu>  Sperre auf der Karte (nur getrennt)\r\n"
        "  web [http|https]  Verwaltungs-Transport zeigen/setzen (Aussperr-Schutz; wirkt nach reboot)\r\n"
        "  time              Systemzeit (UTC) + letzte Netz-Synchronisation\r\n"
        "  acme [now]        Let's-Encrypt-Status zeigen | Zertifikatsbezug jetzt starten\r\n"
        "  acme domain <d> | email <e> | staging on|off | tos | on | off | clear   Let's-Encrypt-Config\r\n"
        "  cert [self|acme|upload|selfsign|renew on|off]   Zertifikatsherkunft (Notbetrieb; UI = voll)\r\n"
        "  ipsec mtu [n]     ipsec0-MTU zeigen/setzen (Experiment; Uplink-MTU wird mit angezeigt)\r\n"
        "  sockets           offene lwIP-Sockets (Typ/lokal/Gegenstelle) -- Tabelle voll = kein Webzugriff mehr\r\n"
        "  net ping <ip>     ICMP-Echo auf beliebige IPv4 (Routing durch lwIP/Zonen, auch VPN-Netze)\r\n"
        "  net sweep <cidr|attachment[@netz/prefix]> [auto|arp|icmp]  Host-Sweep (ARP nur lokal L2, sonst ICMP; max. 512 Ziele, sonst Ablehnung); 'net sweep' = Stand\r\n"
        "  net targets       moegliche Sweep-Ziele aus der Registry (Attachments + Netze)\r\n"
        "  net resolve <ip> [from <attachment>]  lokaler Routing-Befund (Ausgang, Zonenroute, TSr) + optional Forward-Policy der Quelle\r\n"
        "  net portscan <ip> [udp] [von bis]  TCP/UDP-Portscan (ohne Bereich: Common-Ports; max. 4096 TCP / 512 UDP je Lauf, sonst Ablehnung); 'net portscan' = Stand\r\n"
        "  backup            komplette Einstellungen als Text ausgeben (ohne Secrets) -- Rettungsweg ohne Web\r\n"
        "  restore           Sicherung zeilenweise einfuegen, Ende mit 'END' (ABORT bricht ab), dann 'reboot'\r\n"
        "  reboot            ESP neustarten";

const char* serialConsoleHelpText() { return kHelpText; }

static void cmdHelp() { Serial.println(kHelpText); }

// ---- Baudrate (NVS "cfg"/"uartbaud"), wirkt beim naechsten Serial.begin() = Neustart ----------
static const uint32_t kBaudDefault = 115200;
static bool isKnownBaud(uint32_t b) {
    static const uint32_t ok[] = {9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600};
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) if (ok[i] == b) return true;
    return false;
}

uint32_t serialConsoleBaud() {
    Preferences p;
    p.begin("cfg", true);
    uint32_t b = p.getUInt("uartbaud", kBaudDefault);
    p.end();
    return isKnownBaud(b) ? b : kBaudDefault;
}

bool serialConsoleSetBaud(uint32_t baud) {
    if (!isKnownBaud(baud)) return false;
    Preferences p;
    p.begin("cfg", false);
    p.putUInt("uartbaud", baud);
    p.end();
    return true;
}

// Ehrliche Angabe, WORAN die Konsole haengt: bei "USB CDC On Boot" ist Serial der native
// USB-Serial/JTAG-Port (virtueller COM-Port) -- die Baudrate ist dort nur ein Nominalwert ohne
// Wirkung auf der Leitung. Sonst UART0 ueber einen USB-UART-Wandler, Baudrate wirksam.
const char* serialConsoleInterfaceName() {
#if defined(ARDUINO_USB_CDC_ON_BOOT) && ARDUINO_USB_CDC_ON_BOOT
    return "USB-Serial/JTAG (nativer USB-Port, virtueller COM-Port)";
#else
    return "UART0 (ueber USB-UART-Wandler)";
#endif
}

bool serialConsoleBaudMatters() {
#if defined(ARDUINO_USB_CDC_ON_BOOT) && ARDUINO_USB_CDC_ON_BOOT
    return false;
#else
    return true;
#endif
}

static void cmdConnect()    { Serial.println(modemLinkConnect()); }     // neutrale Weiche (ppp|ecm)
static void cmdDisconnect() { Serial.println(modemLinkDisconnect()); }  // neutrale Weiche (ppp|ecm)

// APN/Zugangsdaten setzen (persistent) -- SIM-Wechsel ohne Reflash/Web-UI.
//   apn                          -> aktuelle Config zeigen
//   apn <name>                   -> APN setzen, ohne Auth (z.B. o2 'netpublic', Telekom 'internet.telekom')
//   apn <name> <user> <pass>     -> APN + PAP-Auth (z.B. Telekom: internet.telekom t-mobile tm)
static void cmdApn(const char* rest) {
    while (*rest == ' ') rest++;
    if (!*rest) {
        Serial.printf("apn : %s\r\n", modemApn.length() ? modemApn.c_str() : "(leer)");
        Serial.printf("auth: %s  user:'%s' pass:'%s'\r\n",
            modemAuth == "2" ? "CHAP" : modemAuth == "1" ? "PAP" : "keine",
            modemUser.c_str(), modemPass.c_str());
        Serial.printf("pdp : %s\r\n", modemPdpType.c_str());
        Serial.println(F("setzen: 'apn <name>' (ohne Auth) | 'apn <name> <user> <pass>' (PAP)"));
        return;
    }
    char buf[128]; strncpy(buf, rest, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char* name = strtok(buf, " ");
    char* user = strtok(nullptr, " ");
    char* pass = strtok(nullptr, " ");
    if (!name) return;
    modemApn = name;
    if (user && pass) { modemAuth = "1"; modemUser = user; modemPass = pass; }   // PAP
    else              { modemAuth = "0"; modemUser = "";   modemPass = "";   }   // keine
    saveModemPrefs();
    Serial.printf("gespeichert: apn='%s' auth=%s user='%s'\r\n",
        modemApn.c_str(), modemAuth == "1" ? "PAP" : "keine", modemUser.c_str());
    Serial.println(F("aktiv machen: 'disconnect' dann 'connect' (oder 'reboot')."));
}

// LTE-Bandwahl setzen (persistent) + sofort anwenden -- P4 hat keine Web-UI.
//   band                  -> aktuelles Profil/Netzmodus zeigen
//   band auto|low|mid     -> Bandprofil (auto=alle, low=<1GHz, mid=B3)
//   band custom <hex>     -> eigene LTE-Bitmaske (ohne 0x), z.B. 'band custom 1a0080800d5'
//   band net auto|lte|gsm -> nwscanmode
// Anwenden geht nur ohne aktive Verbindung (vorher 'disconnect').
static void cmdBand(const char* rest) {
    while (*rest == ' ') rest++;
    if (!*rest) {
        Serial.printf("bandprofil: %s%s\r\n", modemBandProfile.c_str(),
            modemBandProfile == "custom" ? (" (" + modemBandCustom + ")").c_str() : "");
        Serial.printf("netmodus  : %s\r\n", modemNetMode.c_str());
        Serial.println(F("setzen: 'band auto|low|mid' | 'band custom <hex>' | 'band net auto|lte|gsm'"));
        return;
    }
    char buf[64]; strncpy(buf, rest, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char* a = strtok(buf, " ");
    char* b = strtok(nullptr, " ");
    if (!a) return;
    if (!strcmp(a, "net")) {
        if (!b || (strcmp(b, "auto") && strcmp(b, "lte") && strcmp(b, "gsm"))) {
            Serial.println(F("netmodus: 'band net auto|lte|gsm'")); return;
        }
        modemNetMode = b;
    } else if (!strcmp(a, "custom")) {
        if (!b) { Serial.println(F("hex fehlt: 'band custom 1a0080800d5'")); return; }
        modemBandProfile = "custom"; modemBandCustom = b;
    } else if (!strcmp(a, "auto") || !strcmp(a, "low") || !strcmp(a, "mid")) {
        modemBandProfile = a;
    } else {
        Serial.println(F("? 'band auto|low|mid' | 'band custom <hex>' | 'band net auto|lte|gsm'")); return;
    }
    saveModemPrefs();
    Serial.printf("gespeichert: profil=%s net=%s -> wende an ...\r\n",
        modemBandProfile.c_str(), modemNetMode.c_str());
    Serial.println(modemApplyBands());   // CFUN-Zyklus, Modem sucht neu
}

// PDP-Typ setzen (persistent) -- fuer IPv6 auf 'ipv4v6' noetig (nur ECM nutzt IPv6).
//   pdp            -> aktuellen Typ zeigen
//   pdp ip         -> nur IPv4
//   pdp ipv4v6     -> IPv4 + IPv6
static void cmdPdp(const char* rest) {
    while (*rest == ' ') rest++;
    if (!*rest) {
        Serial.printf("pdp: %s\r\n", modemPdpType.c_str());
        Serial.println(F("setzen: 'pdp ip' | 'pdp ipv4v6' (IPv6 nur mit Datenschicht ECM)"));
        return;
    }
    if      (!strcasecmp(rest, "ipv4v6") || !strcasecmp(rest, "ipv6")) modemPdpType = "IPV4V6";
    else if (!strcasecmp(rest, "ip")     || !strcasecmp(rest, "ipv4")) modemPdpType = "IP";
    else { Serial.println(F("? 'pdp ip' | 'pdp ipv4v6'")); return; }
    saveModemPrefs();
    Serial.printf("gespeichert: pdp=%s\r\n", modemPdpType.c_str());
    Serial.println(F("aktiv machen: 'disconnect' dann 'connect' (ECM fuer IPv6)."));
}

// Datenschicht ppp<->ecm umschalten (persistent) -- headless-Pendant zu /modem-datalink.
// ECM ist IPv6-faehig (PPP nicht). Schaltet das Modem per usbnet um + Reboot, wie die WebUI.
//   mode           -> aktuelle Datenschicht zeigen
//   mode ppp|ecm   -> umschalten (Modem startet neu ~15-30s)
static void cmdMode(const char* rest) {
    while (*rest == ' ') rest++;
    if (!*rest) {
        Serial.printf("mode: %s (%s)\r\n", modemDataMode.c_str(), modemLinkModeName());
        Serial.println(F("setzen: 'mode ppp' | 'mode ecm' (ECM = IPv6-faehig)"));
        return;
    }
    String oldMode = modemDataMode;
    if      (!strcasecmp(rest, "ecm")) modemDataMode = "ecm";
    else if (!strcasecmp(rest, "ppp")) modemDataMode = "ppp";
    else { Serial.println(F("? 'mode ppp' | 'mode ecm'")); return; }
    saveModemPrefs();
    Serial.printf("gespeichert: mode=%s\r\n", modemDataMode.c_str());
    if (modemDataMode == oldMode) return;
    // Modem-usbnet passend setzen (1=ECM, 3=RNDIS->PPP) + Modem rebooten, damit usbnet greift.
    // Danach den ESP SELBST neu starten: der Live-Uebergang verklemmt sonst (usbnet-Wechsel
    // "OUT timeout" -> IF3 INVALID_STATE, haengender PPP-Lock). Ein frischer ESP-Boot bringt den
    // gewaehlten Pfad zuverlaessig per Auto-Retry hoch (hardwareverifiziert 2026-08-28). mode ist
    // oben schon persistent gespeichert -> ueberlebt den Reset.
    if (oldMode == "ecm") { ecmStopSupervisor(); ec200aEcm.stop(); }
    else                  { modemDisconnect(); }
    Serial.println(ecmSwitchModemUsbnet(modemDataMode == "ecm" ? 1 : 3));   // 1=ECM, 3=RNDIS(->PPP)
    Serial.println(modemReset());                                          // AT+CFUN=1,1 -> usbnet wirkt
    Serial.println(F("Mode umgeschaltet -> ESP startet jetzt neu, Pfad kommt danach sauber hoch."));
    Serial.flush(); delay(400); ESP.restart();
}

// SIM-PIN: in WeirdOS gespeicherte PIN (wird beim Verbinden gesendet) + Sperre auf der Karte.
//   pin                      -> Status
//   pin set <pin> | pin clear
//   pin enable <pin> | pin disable <pin> | pin change <alt> <neu>   (nur bei getrennter Verbindung)
static void cmdPin(const char* rest) {
    while (*rest == ' ') rest++;
    String a(rest); a.trim();
    if (!a.length()) {
        Serial.printf("pin gespeichert : %s\r\n", modemSimPin.length() ? "ja" : "nein");
        Serial.printf("SIM-Status      : %s\r\n", modemSimLastStatus().length() ? modemSimLastStatus().c_str() : "(noch nicht geprueft)");
        if (modemLinkIsUp()) Serial.println(F("Karten-Status nur bei getrennter Verbindung ('disconnect')."));
        else                 Serial.println(modemSimPinManage("status", "", ""));
        Serial.println(F("setzen: 'pin set <pin>' | 'pin clear' | Karte: 'pin enable|disable <pin>' | 'pin change <alt> <neu>'"));
        return;
    }
    int sp = a.indexOf(' ');
    String cmd  = (sp < 0) ? a : a.substring(0, sp);
    String args = (sp < 0) ? String("") : a.substring(sp + 1); args.trim();
    if (cmd == "set") {
        if (!args.length()) { Serial.println(F("? pin set <pin>")); return; }
        modemSimPin = args; saveModemPrefs();
        Serial.println(F("gespeichert (wird beim naechsten Verbinden gesendet, hoechstens einmal je Start)."));
        return;
    }
    if (cmd == "clear") { modemSimPin = ""; saveModemPrefs(); Serial.println(F("gespeicherte PIN geloescht.")); return; }
    if (cmd == "enable" || cmd == "disable" || cmd == "change") {
        if (modemLinkIsUp()) { Serial.println(F("nur bei getrennter Verbindung ('disconnect').")); return; }
        String p1 = args, p2 = "";
        int s2 = args.indexOf(' ');
        if (s2 >= 0) { p1 = args.substring(0, s2); p2 = args.substring(s2 + 1); p2.trim(); }
        Serial.println(modemSimPinManage(cmd, p1, p2));
        return;
    }
    Serial.println(F("? 'pin' | 'pin set <pin>' | 'pin clear' | 'pin enable|disable <pin>' | 'pin change <alt> <neu>'"));
}

// ECM-Betriebsart des Modem-NIC (nic = oeffentliche IP direkt am ESP | routing = Modem-NAT).
static void cmdNat(const char* rest) {
    while (*rest == ' ') rest++;
    if (!*rest) {
        Serial.printf("nat: %s\r\n", modemNatMode.c_str());
        Serial.println(F("setzen: 'nat nic' | 'nat routing' (Modem-Reboot, nur ECM)"));
        return;
    }
    String old = modemNatMode;
    if      (!strcasecmp(rest, "nic"))     modemNatMode = "nic";
    else if (!strcasecmp(rest, "routing")) modemNatMode = "routing";
    else { Serial.println(F("? 'nat nic' | 'nat routing'")); return; }
    saveModemPrefs();
    Serial.printf("gespeichert: nat=%s\r\n", modemNatMode.c_str());
    if (modemNatMode == old) return;
    if (modemDataMode != "ecm") { Serial.println(F("wirkt nur bei Datenschicht ECM ('mode ecm').")); return; }
    ecmStopSupervisor(); ec200aEcm.stop();
    Serial.println(ecmSwitchModemNat(modemNatMode == "routing" ? 0 : 1));
    Serial.println(modemReset());
    startModemDataSupervisor();
    Serial.println(F("Modem startet neu (~15-30 s), ECM kommt danach mit der neuen Betriebsart hoch."));
}

// Netzzugang (WanPolicy): auto | cellular | wifi -- dieselbe Wahl wie WAN > Netzzugang.
// ---- IPsec-Diagnose ueber die serielle Konsole (gleiche Daten wie Uebersicht + /ipsec-status.json) --
// TCP-Test DURCH den Tunnel: HTTP GET / an <ip>[:port] (z.B. FRITZ!Box 192.168.178.1) ueber lwIP-
// Sockets -> lwIP routet ueber ipsec0. Beweist TCP (Handshake, Pruefsummen, MSS) unabhaengig vom Browser.
// Generische Netzdiagnose (Ziel = beliebige IPv4, Routing durch lwIP/Zonen-Runtime, keine WLAN-Bindung):
//   net ping <ip>                          ICMP-Echo (esp_ping, 800 ms)
//   net portscan <ip> [udp] [von bis]      TCP-/UDP-Portscan starten (ohne Bereich: Common-Liste)
//   net portscan                           Stand/Ergebnis des laufenden bzw. letzten Scans
static void cmdNet(const char* rest) {
    while (*rest == ' ') rest++;
    char buf[96]; strncpy(buf, rest, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char* op = strtok(buf, " "); char* a = strtok(nullptr, " "); char* b = strtok(nullptr, " "); char* c = strtok(nullptr, " "); char* d = strtok(nullptr, " ");
    if (op && !strcmp(op, "ping") && a) { Serial.println(netPingJson(String(a))); return; }
    if (op && !strcmp(op, "sweep")) {
        if (!a) { Serial.println(netScanJson()); return; }
        String err = netScanStartTarget(String(a), b ? String(b) : String("auto"));
        Serial.println(err.length() ? ("Fehler: " + err) : String("Sweep gestartet -- Stand mit 'net sweep'"));
        return;
    }
    if (op && !strcmp(op, "targets")) { Serial.println(netScanTargetsJson()); return; }
    if (op && !strcmp(op, "resolve") && a) {
        String from = (b && !strcmp(b, "from") && c) ? String(c) : String("");
        Serial.println(netDiagResolveJson(String(a), from)); return;
    }
    if (op && !strcmp(op, "portscan")) {
        if (!a) { Serial.println(netPortScanJson()); return; }
        bool udp = false; int from = 0, to = 0;
        const char* p1 = b; const char* p2 = c;
        if (b && !strcmp(b, "udp")) { udp = true; p1 = c; p2 = d; }
        if (p1 && p2) { from = atoi(p1); to = atoi(p2); }
        String err = netPortScanStart(String(a), from, to, udp);
        if (err.length()) { Serial.println("Fehler: " + err); return; }
        if (from && to) Serial.printf("Portscan gestartet: %s %s Bereich %d-%d -- Stand mit 'net portscan'\r\n", a, udp ? "UDP" : "TCP", from, to);
        else Serial.printf("Portscan gestartet: %s %s Common-Ports -- Stand mit 'net portscan'\r\n", a, udp ? "UDP" : "TCP");
        return;
    }
    Serial.println(F("? 'net ping <ip>' | 'net sweep <cidr|attachment[@netz/prefix]> [auto|arp|icmp]' | 'net sweep' (Stand) | 'net targets' | 'net resolve <ip> [from <attachment>]' | 'net portscan <ip> [udp] [von bis]' | 'net portscan' (Stand). Ziel darf in jedem gerouteten Netz liegen."));
}

// ---- WLAN ueber UART (UI-Paritaet) ---------------------------------------------------------
//   wlan                       Status
//   wlan connect <ssid> <pass> Zugangsdaten speichern + Client aktivieren (Neustart noetig)
//   wlan off                   WLAN-Client aus
//   wlan ap on|off             Setup-AP dauerhaft an/aus
//   wlan stack auto|on|off     WLAN-Stack-Modus
static void cmdWlan(const char* rest) {
    while (*rest == ' ') rest++;
    char buf[128]; strncpy(buf, rest, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char* op = strtok(buf, " ");
    if (!op || !*op) {
        Serial.printf("wlan  : Client=%s AP-dauerhaft=%s Stack=%s\r\n", targetNetworkEnabled ? "an" : "aus", keepApAlways ? "an" : "aus", wifiStackModeToStr(wifiStackMode()));
        Serial.print(F("ssid  : ")); Serial.println(configuredSsid.length() ? configuredSsid : String("(keine)"));
        Serial.println(F("setzen: wlan connect <ssid> <pass> | wlan off | wlan ap on|off | wlan stack auto|on|off  (Neustart: 'reboot')"));
        return;
    }
    char* a = strtok(nullptr, " "); char* b = strtok(nullptr, " ");
    if (!strcmp(op, "connect") && a && b) { saveWifiCredentials(String(a), String(b)); saveTargetEnabled(true); markRestartRequired("WLAN-Zugangsdaten"); Serial.println(F("gespeichert + Client an. Neustart: 'reboot'.")); return; }
    if (!strcmp(op, "off"))               { saveTargetEnabled(false); markRestartRequired("WLAN-Client"); Serial.println(F("WLAN-Client aus. Neustart: 'reboot'.")); return; }
    if (!strcmp(op, "ap") && a)           { saveApPreference(!strcmp(a, "on")); markRestartRequired("Setup-AP dauerhaft"); Serial.printf("Setup-AP dauerhaft: %s. Neustart: 'reboot'.\r\n", !strcmp(a, "on") ? "an" : "aus"); return; }
    if (!strcmp(op, "stack") && a)        { wifiStackModeSave(wifiStackModeFromStr(String(a))); markRestartRequired("WLAN-Stack"); Serial.printf("WLAN-Stack: %s. Neustart: 'reboot'.\r\n", wifiStackModeToStr(wifiStackMode())); return; }
    Serial.println(F("? 'wlan' | 'wlan connect <ssid> <pass>' | 'wlan off' | 'wlan ap on|off' | 'wlan stack auto|on|off'"));
}

// ---- LAN-Allgemein ueber UART (network_mode) -----------------------------------------------
static void cmdLan(const char* rest) {
    while (*rest == ' ') rest++;
    char buf[96]; strncpy(buf, rest, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char* op = strtok(buf, " "); char* a = strtok(nullptr, " ");
    NetworkModeConfig c = networkMode.config();
    if (!op || !*op) {
        Serial.printf("lan   : subnet=%s forwarding=%s ap-kanal=%s%u\r\n", c.lanSubnet.c_str(), c.forwarding.c_str(), c.apChannelPol == "fixed" ? "fest " : "auto", (unsigned)c.apChannel);
        Serial.println(F("setzen: lan subnet <a.b.c.d/n> | lan forwarding none|napt | lan apchannel auto|1..13"));
        return;
    }
    if (!strcmp(op, "subnet") && a)     { c.lanSubnet = a; networkMode.saveConfig(c); markRestartRequired("LAN-Subnetz"); Serial.printf("lan subnet = %s (gespeichert)\r\n", c.lanSubnet.c_str()); return; }
    if (!strcmp(op, "forwarding") && a) { c.forwarding = (!strcmp(a, "napt")) ? "napt" : "none"; networkMode.saveConfig(c); markRestartRequired("Forwarding/NAT"); Serial.printf("lan forwarding = %s (gespeichert)\r\n", c.forwarding.c_str()); return; }
    if (!strcmp(op, "apchannel") && a)  { if (!strcmp(a, "auto")) { c.apChannelPol = "follow"; } else { int ch = atoi(a); if (ch < 1 || ch > 13) { Serial.println(F("Kanal 1..13 oder auto")); return; } c.apChannelPol = "fixed"; c.apChannel = (uint8_t)ch; } networkMode.saveConfig(c); markRestartRequired("AP-Kanal"); Serial.println(F("AP-Kanal gespeichert.")); return; }
    Serial.println(F("? 'lan' | 'lan subnet <cidr>' | 'lan forwarding none|napt' | 'lan apchannel auto|1..13'"));
}

// ---- Setup/Zugriffsschutz ueber UART (setup_guard) -----------------------------------------
static void cmdSetup(const char* rest) {
    while (*rest == ' ') rest++;
    char buf[64]; strncpy(buf, rest, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char* op = strtok(buf, " "); char* a = strtok(nullptr, " ");
    SetupGuardConfig sg = setupGuardGet();
    if (!op || !*op) {
        Serial.printf("setup : captive=%s reset=%s(%lus) fullreset=%s(%lus) uart=%s\r\n",
                      sg.captiveMode.c_str(), sg.resetEnabled ? "an" : "aus", (unsigned long)(sg.resetHoldMs/1000),
                      sg.fullEnabled ? "an" : "aus", (unsigned long)(sg.fullHoldMs/1000), sg.uartEnabled ? "an" : "aus");
        Serial.println(F("setzen: setup captive auto|off | reset on|off | resethold <s> | fullreset on|off | fullhold <s> | uart on|off"));
        return;
    }
    if (!strcmp(op, "captive") && a)  { sg.captiveMode = (!strcmp(a, "off")) ? "off" : "auto"; }
    else if (!strcmp(op, "reset") && a)     { sg.resetEnabled = !strcmp(a, "on"); }
    else if (!strcmp(op, "resethold") && a) { sg.resetHoldMs = (uint32_t)atoi(a) * 1000UL; }
    else if (!strcmp(op, "fullreset") && a) { sg.fullEnabled = !strcmp(a, "on"); }
    else if (!strcmp(op, "fullhold") && a)  { sg.fullHoldMs = (uint32_t)atoi(a) * 1000UL; }
    else if (!strcmp(op, "uart") && a)      { sg.uartEnabled = !strcmp(a, "on"); if (!sg.uartEnabled) Serial.println(F("ACHTUNG: UART wird nach dem Speichern deaktiviert -- Freischaltung dann nur ueber die Web-UI!")); }
    else { Serial.println(F("? setup captive auto|off | reset on|off | resethold <s> | fullreset on|off | fullhold <s> | uart on|off")); return; }
    setupGuardSave(sg);
    Serial.println(F("gespeichert."));
}

// ---- Video/Server ueber UART (Live-Bildrate) -----------------------------------------------
static void cmdVideo(const char* rest) {
    while (*rest == ' ') rest++;
    char buf[64]; strncpy(buf, rest, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char* op = strtok(buf, " "); char* a = strtok(nullptr, " ");
    if (!op || !*op) {
        Serial.printf("video : stream=%s fps=%d\r\n", streamEnabled ? "an" : "aus", cameraTargetFps);
        Serial.println(F("setzen: video fps <1..30>   (Stream an/aus + Aufloesung/Ports weiter ueber die Web-UI, Server > Video)"));
        return;
    }
    if (!strcmp(op, "transport") && a) { String st = a; if (st != "off" && st != "http" && st != "rtsp") { Serial.println(F("transport off|http|rtsp")); return; } streamType = st; streamEnabled = (st == "http"); rtspEnabled = (st == "rtsp"); Preferences p; p.begin("camera", false); p.putString("strmtype", streamType); p.putBool("strm", streamEnabled); p.putBool("rtspen", rtspEnabled); p.end(); markRestartRequired("Video-Transport"); Serial.printf("video transport = %s (gespeichert, wirkt nach 'reboot')\r\n", st.c_str()); return; }
    if (!strcmp(op, "rtspport") && a) { int pt = atoi(a); if (pt < 1 || pt > 65535) { Serial.println(F("Port 1..65535")); return; } rtspPort = pt; Preferences p; p.begin("camera", false); p.putInt("rtspport", rtspPort); p.end(); markRestartRequired("RTSP-Port"); Serial.printf("video rtspport = %d (gespeichert, wirkt nach 'reboot')\r\n", pt); return; }
    if (!strcmp(op, "rtsptransport") && a) { rtspTransport = (!strcmp(a, "udp")) ? "udp" : "tcp"; Preferences p; p.begin("camera", false); p.putString("rtsptr", rtspTransport); p.end(); markRestartRequired("RTSP-Transport"); Serial.printf("video rtsptransport = %s (gespeichert, wirkt nach 'reboot')\r\n", rtspTransport.c_str()); return; }
    if (!strcmp(op, "fps") && a) { int f = atoi(a); if (f < 1 || f > 30) { Serial.println(F("fps 1..30")); return; } cameraStream.setTargetFps(f); cameraTargetFps = f; Serial.printf("video fps = %d\r\n", f); return; }
    Serial.println(F("? 'video' | 'video fps <n>' | 'video transport off|http|rtsp' | 'video rtspport <n>' | 'video rtsptransport tcp|udp'"));
}

// ---- USB-Geraet am PC (UVC) ueber UART -----------------------------------------------------
//   usbdev                     Status (Port, Host, Stream, Frames)
//   usbdev uvc on|off          Webcam anbieten (wirkt nach 'reboot')
//   usbdev source test|camera  Testbild oder camera0
//   usbdev fps <1..30>         angebotene Bildrate
// ---- USB-Anschluesse des Boards (Mapping) ueber UART ---------------------------------------
//   usbports                          Mapping + Chip-Paare zeigen
//   usbports count <n>                Anzahl Ports (1..3)
//   usbports set <i> <dm> <dp> [name] Pins (-1 -1 = dedizierte HS-Pads) + Name fuer USB<i>
//   usbports enable <i> on|off
static void cmdUsbPorts(const char* rest) {
    while (*rest == ' ') rest++;
    char buf[80]; strncpy(buf, rest, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char* op = strtok(buf, " ");
    if (!op || !*op) { Serial.print(usbPortsText()); Serial.println(F("setzen: usbports count <n> | set <i> <dm> <dp> [name] | enable <i> on|off   (wirkt nach 'reboot')")); return; }
    UsbPortEntry e[USB_PORTS_MAX]; int n = usbPortsCount();
    for (int i = 0; i < n; i++) e[i] = usbPort(i);
    if (!strcmp(op, "count")) { char* a = strtok(nullptr, " "); int c = a ? atoi(a) : 0; if (c < 1 || c > USB_PORTS_MAX) { Serial.println(F("Anzahl 1..3")); return; }
        for (int i = n; i < c; i++) { e[i] = UsbPortEntry(); e[i].id = String("USB") + i; e[i].label = e[i].id; e[i].dm = -1; e[i].dp = -1; e[i].enabled = false; } n = c; }
    else if (!strcmp(op, "set")) { char* a = strtok(nullptr, " "); char* m = strtok(nullptr, " "); char* p = strtok(nullptr, " "); char* l = strtok(nullptr, "");
        int i = a ? atoi(a) : -1; if (i < 0 || i >= n || !m || !p) { Serial.println(F("? usbports set <i> <dm> <dp> [name]")); return; }
        e[i].dm = (int8_t)atoi(m); e[i].dp = (int8_t)atoi(p); if (l) { while (*l == ' ') l++; if (*l) e[i].label = l; } }
    else if (!strcmp(op, "enable")) { char* a = strtok(nullptr, " "); char* v = strtok(nullptr, " "); int i = a ? atoi(a) : -1; if (i < 0 || i >= n || !v) { Serial.println(F("? usbports enable <i> on|off")); return; } e[i].enabled = !strcmp(v, "on"); }
    else { Serial.println(F("? usbports | count <n> | set <i> <dm> <dp> [name] | enable <i> on|off")); return; }
    String err = usbPortsSave(n, e);
    if (err.length()) { Serial.println("Fehler: " + err); return; }
    markRestartRequired("USB-Anschluesse (Mapping)");
    Serial.print(usbPortsText()); Serial.println(F("gespeichert, wirkt nach 'reboot'."));
}

//   usbdev port <USBn>                          USB-Anschluss zum PC (aus dem Mapping)
//   usbdev export camera0|testpattern0 uvc|off  Geraet als Webcam bereitstellen (genau eines)
//   usbdev fps <1..30>
static void cmdUsbDev(const char* rest) {
    while (*rest == ' ') rest++;
    char buf[64]; strncpy(buf, rest, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char* op = strtok(buf, " "); char* a = strtok(nullptr, " "); char* b = strtok(nullptr, " ");
    if (!op || !*op) { Serial.print(usbDeviceService.statusText()); Serial.println(F("setzen: usbdev port <fs26|fs24|hs|native> | export camera0|testpattern0 uvc|off | fps <n>   (wirkt nach 'reboot')")); return; }
    UsbDeviceConfig c = usbDeviceService.config();
    if (!strcmp(op, "port") && a) { if (!UsbDeviceService::portValid(String(a))) { Serial.println(F("? Port unbekannt/aus -- siehe 'usbports'")); return; } c.port = a; }
    else if (!strcmp(op, "export") && a && b) {
        if (strcmp(a, "camera0") && strcmp(a, "testpattern0")) { Serial.println(F("? export camera0|testpattern0 uvc|off (microphone0/usb-network: noch nicht implementiert)")); return; }
        if (!strcmp(b, "uvc")) c.cam = a; else if (c.cam == a) c.cam = "";
    }
    else if (!strcmp(op, "fps") && a) c.fps = (uint8_t)atoi(a);
    else { Serial.println(F("? usbdev port <p> | export <geraet> uvc|off | fps <n>")); return; }
    usbDeviceService.saveConfig(c); markRestartRequired("USB-Geraet (Bereitstellen an USB)");
    const UsbDeviceConfig& n = usbDeviceService.config();
    Serial.printf("usbdev: port=%s uvc<-%s fps=%u (gespeichert, wirkt nach 'reboot')\r\n", n.port.c_str(), n.cam.length() ? n.cam.c_str() : "aus", (unsigned)n.fps);
}

// WireGuard ueber UART (UI-Paritaet, Fallback ohne Web). Ein Backend -> eine Rolle (server|client).
//   wg                         Status + Konfiguration zeigen (Secrets maskiert)
//   wg mode server|client      Rolle setzen (schaltet die andere Rolle ab)
//   wg on | off                aktivieren/deaktivieren (+ sofort verbinden/trennen)
//   wg set <key> <wert>        Feld setzen: underlay, localip, keepalive, fulltunnel(on|off);
//                              Server: port, allowed, langw(on|off), lantgt(wifi|ap|both);
//                              Client: endpoint, port, peerpub, allowed
//   wg psk <wert>              Pre-Shared Key setzen (nur gespeichert, nie ausgegeben)
//   wg save                    speichern + anwenden (wie der Web-Button)
//   wg connect | disconnect    manuell verbinden/trennen
static WireGuardConfig s_wgDraft; static bool s_wgDraftLoaded = false;
static WireGuardConfig& wgDraft() { if (!s_wgDraftLoaded) { s_wgDraft = wireguardService.config(); s_wgDraftLoaded = true; } return s_wgDraft; }
static void cmdWg(const char* rest) {
    while (*rest == ' ') rest++;
    char buf[160]; strncpy(buf, rest, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char* op = strtok(buf, " ");
    if (!op || !*op) {
        const WireGuardConfig& w = wireguardService.config();
        Serial.printf("wg    : mode=%s aktiv=%d up=%d underlay=%s localip=%s keepalive=%u fulltunnel=%d\r\n",
                      w.mode.c_str(), w.active, wireguardService.isUp(), w.underlay.c_str(), w.localIp.c_str(), (unsigned)w.keepalive, w.fullTunnel);
        if (w.mode == "client") Serial.printf("client: endpoint=%s:%u peerpub=%s allowed=%s\r\n", w.clientEndpoint.c_str(), (unsigned)w.clientPort, w.clientPeerPub.length()?"gesetzt":"(leer)", w.clientAllowedIps.c_str());
        else Serial.printf("server: port=%u allowed=%s langw=%d lantgt=%s clients=%d\r\n", (unsigned)w.endpointPort, w.allowedIps.c_str(), w.lanGateway, w.lanTarget.c_str(), wireguardService.clientCount());
        Serial.printf("keys  : mcuPriv=%s psk=%s\r\n", wireguardService.privateKeySet()?"gesetzt":"(leer)", wireguardService.pskSet()?"gesetzt":"(leer)");
        Serial.println(F("setzen: wg mode|on|off|set <key> <wert>|psk <wert>|save|connect|disconnect  (Entwurf, 'wg save' schreibt)"));
        return;
    }
    char* a = strtok(nullptr, " ");
    char* b = strtok(nullptr, " ");
    if (!strcmp(op, "connect"))    { Serial.println(wireguardService.connect().length() ? ("Fehler: " + wireguardService.lastError()) : String("Verbindung wird aufgebaut.")); return; }
    if (!strcmp(op, "disconnect")) { wireguardService.disconnect(); Serial.println(F("getrennt.")); return; }
    if (!strcmp(op, "clients"))    { Serial.println(wireguardService.clientsJson()); return; }
    if (!strcmp(op, "delclient") && a) { Serial.println(wireguardService.deleteClient(atoi(a)) ? F("Client entfernt.") : F("kein Client mit diesem Index.")); return; }
    if (!strcmp(op, "addclient")) {
        // Endpoint-Host = DynDNS-Domain (wie im Web); erzeugt Schluesselpaar + Peer, liefert die .conf
        // EINMALIG inkl. Client-Private-Key. Serielle Leitung ist physischer, lokaler Zugang.
        String name = a ? String(a) : String("");
        String conf = wireguardService.generateClientConfig(dyndnsDomain, name);
        if (!conf.length()) { Serial.println("Fehler: " + wireguardService.lastError()); return; }
        Serial.println(F("--- WireGuard Client-Konfiguration (enthaelt Private-Key, nur einmalig) ---"));
        Serial.println(conf);
        Serial.println(F("--- Ende ---"));
        return;
    }
    WireGuardConfig& d = wgDraft();
    if (!strcmp(op, "mode") && a)      { d.mode = (!strcmp(a, "client")) ? "client" : "server"; Serial.printf("Entwurf: mode=%s ('wg save')\r\n", d.mode.c_str()); return; }
    if (!strcmp(op, "on"))             { d.active = true;  Serial.println(F("Entwurf: aktiv=1 ('wg save')")); return; }
    if (!strcmp(op, "off"))            { d.active = false; Serial.println(F("Entwurf: aktiv=0 ('wg save')")); return; }
    if (!strcmp(op, "psk") && a)       { Serial.println(wireguardService.saveConfig(d, "", String(a)).length() ? String("gesetzt+gespeichert") : String("PSK gesetzt+gespeichert")); s_wgDraftLoaded = false; return; }
    if (!strcmp(op, "save"))           { String m = wireguardService.saveConfig(d, "", ""); s_wgDraftLoaded = false; Serial.println(m); if (d.active) { wireguardService.disconnect(); String e = wireguardService.connect(); Serial.println(e.length() ? ("Start: " + e) : String("Start: ok")); } else wireguardService.disconnect(); return; }
    if (!strcmp(op, "set") && a) {
        String v = b ? String(b) : String("");
        if      (!strcmp(a, "underlay"))   d.underlay = (v == "modem" || v == "wifi") ? v : String("auto");
        else if (!strcmp(a, "localip"))    d.localIp = v;
        else if (!strcmp(a, "keepalive"))  d.keepalive = (uint16_t)v.toInt();
        else if (!strcmp(a, "fulltunnel")) d.fullTunnel = (v == "on" || v == "1" || v == "full");
        else if (!strcmp(a, "port"))       { if (d.mode == "client") d.clientPort = (uint16_t)v.toInt(); else d.endpointPort = (uint16_t)v.toInt(); }
        else if (!strcmp(a, "allowed"))    { if (d.mode == "client") d.clientAllowedIps = v; else d.allowedIps = v; }
        else if (!strcmp(a, "endpoint"))   d.clientEndpoint = v;
        else if (!strcmp(a, "peerpub"))    d.clientPeerPub = v;
        else if (!strcmp(a, "langw"))      d.lanGateway = (v == "on" || v == "1");
        else if (!strcmp(a, "lantgt"))     d.lanTarget = (v == "ap" || v == "both") ? v : String("wifi");
        else { Serial.println(F("? key: underlay|localip|keepalive|fulltunnel|port|allowed|endpoint|peerpub|langw|lantgt")); return; }
        Serial.printf("Entwurf: %s = %s ('wg save')\r\n", a, v.c_str());
        return;
    }
    Serial.println(F("? 'wg' | 'wg mode server|client' | 'wg on|off' | 'wg set <key> <wert>' | 'wg psk <wert>' | 'wg save' | 'wg connect|disconnect'"));
}

// Netzzonen Phase 0: 'zones' | 'zones show' | 'zones plan <quelle> <ziel> [intent]' (0.2, read-only)
// | 'zones routes' | 'zones route add|del|clear' | 'zones filter deny|allow|clear' | 'zones counters [reset]' (0.3).
static void cmdZones(const char* rest) {
    while (*rest == ' ') rest++;
    if (!*rest || !strcmp(rest, "show")) { Serial.println(zoneAttachmentsText()); return; }
    if (!strcmp(rest, "routes")) { Serial.print(zoneRoutesText()); Serial.print(zoneFiltersText()); Serial.println(zoneCountersText()); return; }
    if (!strncmp(rest, "route", 5)) {
        char buf[96]; strncpy(buf, rest + 5, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
        char* op = strtok(buf, " "); char* a = strtok(nullptr, " "); char* b = strtok(nullptr, " ");
        String r = "?";
        if (op && !strcmp(op, "add") && a && b) r = zoneRouteAdd(String(a), String(b), "konsole");
        else if (op && !strcmp(op, "del") && a) r = zoneRouteDel(String(a));
        else if (op && !strcmp(op, "clear")) { zoneRouteClear(); r = ""; }
        else if (op && !strcmp(op, "rebind")) { int u = zoneRouteRebind(); r = u ? ("nicht aufloesbar: " + String(u) + " Route(n) bleiben BLOCK") : String(""); }
        if (r == "?") { Serial.println(F("zones route add <a.b.c.d/n> <iface-id> | del <a.b.c.d/n> | clear | rebind (nach Tunnel-Reconnect)   (iface-id: ipsec0, wg0, wifi-ap, ...)")); return; }
        Serial.println(r.length() ? ("Fehler: " + r) : String("ok")); Serial.print(zoneRoutesText()); return;
    }
    if (!strncmp(rest, "napt", 4)) {
        Serial.print(zoneNaptText()); return;
    }
    if (!strncmp(rest, "filter", 6)) {
        char buf[96]; strncpy(buf, rest + 6, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
        char* op = strtok(buf, " "); char* a = strtok(nullptr, " "); char* b = strtok(nullptr, " ");
        String r = "?";
        if (op && !strcmp(op, "deny") && a && b) r = zoneFilterDeny(String(a), String(b));
        else if (op && !strcmp(op, "allow") && a && b) r = zoneFilterAllow(String(a), String(b));
        else if (op && !strcmp(op, "clear")) { zoneFilterClear(); r = ""; }
        if (r == "?") { Serial.println(F("zones filter deny <in-iface|*> <out-iface|*> | allow <in> <out> (Regel entfernen) | clear")); return; }
        Serial.println(r.length() ? ("Fehler: " + r) : String("ok")); Serial.print(zoneFiltersText()); return;
    }
    if (!strncmp(rest, "counters", 8)) {
        if (strstr(rest + 8, "reset")) { zoneCountersReset(); Serial.println(F("Zaehler zurueckgesetzt.")); }
        Serial.println(zoneCountersText()); return;
    }
    // 0.5 Policy-Runtime: 'zones policies' | 'zones policy <src> <dst> allow|deny|route|nat' | 'zones policy del <src> <dst>' | 'zones apply'
    if (!strcmp(rest, "policies")) { Serial.println(zoneRuntimeText()); Serial.print(zoneRoutesText()); return; }
    if (!strcmp(rest, "apply")) { zoneRuntimeApply(); Serial.println(zoneRuntimeText()); Serial.print(zoneRoutesText()); return; }
    if (!strncmp(rest, "policy", 6)) {
        char buf[96]; strncpy(buf, rest + 6, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
        char* a = strtok(buf, " "); char* b = strtok(nullptr, " "); char* c = strtok(nullptr, " ");
        String r;
        if (a && !strcmp(a, "del") && b && c) r = zoneRuntimeDelPolicy(String(b), String(c));
        else if (a && b) r = zoneRuntimeSetPolicy(String(a), String(b), c ? String(c) : String("allow"));
        else { Serial.println(F("zones policy <quelle> <ziel> [allow|deny|route|nat] | zones policy del <quelle> <ziel>   (ids siehe 'zones')")); return; }
        Serial.println(r.length() ? ("Fehler: " + r) : String("ok -- kompiliert und installiert"));
        Serial.println(zoneRuntimeText()); Serial.print(zoneRoutesText()); return;
    }
    if (!strncmp(rest, "plan", 4)) {
        char buf[96]; strncpy(buf, rest + 4, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
        char* s = strtok(buf, " "); char* d = strtok(nullptr, " "); char* in = strtok(nullptr, " ");
        if (!s || !d) { Serial.println(F("zones plan <quelle> <ziel> [allow|deny|route|nat]  -- ids siehe 'zones'")); return; }
        bool ok; ZoneIntent intent = zoneIntentParse(in ? String(in) : String(""), ok);
        if (!ok) { Serial.println(F("Intent: allow (ALLOW_AUTO) | deny | route (ROUTE_ONLY) | nat (NAT_ONLY)")); return; }
        Serial.println(zonePlanText(String(s), String(d), intent));
        return;
    }
    Serial.println(F("? 'zones' | 'zones plan <quelle> <ziel> [allow|deny|route|nat]' | 'zones policies' | 'zones policy <quelle> <ziel> [allow|deny|route|nat]' | 'zones policy del <quelle> <ziel>' | 'zones apply' | 'zones routes' | 'zones route add|del|clear|rebind' | 'zones filter deny|allow|clear' | 'zones counters [reset]'"));
}

static void cmdIpsecFetch(const char* arg) {
    String a = arg; a.trim();
    if (!a.length()) { Serial.println(F("ipsec fetch <ip>[:port]")); return; }
    int colon = a.indexOf(':'); String host = (colon > 0) ? a.substring(0, colon) : a;
    uint16_t port = (colon > 0) ? (uint16_t)a.substring(colon + 1).toInt() : 80;
    struct sockaddr_in d; memset(&d, 0, sizeof(d)); d.sin_family = AF_INET; d.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &d.sin_addr) != 1) { Serial.println(F("fetch: keine IPv4-Adresse")); return; }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { Serial.printf("fetch: socket() fehlgeschlagen (errno %d = %s) -> 'sockets' zeigt die Belegung\r\n", errno, strerror(errno)); return; }
    struct timeval tv; tv.tv_sec = 4; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    uint32_t t0 = millis();
    if (connect(fd, (struct sockaddr*)&d, sizeof(d)) != 0) { Serial.printf("fetch: connect %s:%u fehlgeschlagen (errno %d) nach %lu ms\r\n", host.c_str(), port, errno, (unsigned long)(millis() - t0)); close(fd); return; }
    Serial.printf("fetch: TCP verbunden mit %s:%u nach %lu ms\r\n", host.c_str(), port, (unsigned long)(millis() - t0));
    String req = "GET / HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    if (send(fd, req.c_str(), req.length(), 0) != (ssize_t)req.length()) { Serial.println(F("fetch: send fehlgeschlagen")); close(fd); return; }
    char buf[513]; size_t total = 0; String first;
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        if (!first.length()) { buf[n] = 0; String s(buf); int nl = s.indexOf('\n'); first = (nl > 0) ? s.substring(0, nl) : s; first.trim(); }
        total += (size_t)n;
        if (total > 65536) break;
    }
    close(fd);
    Serial.printf("fetch: %u Bytes in %lu ms; erste Zeile: %s\r\n", (unsigned)total, (unsigned long)(millis() - t0), first.length() ? first.c_str() : "(nichts empfangen)");
}

// Belegung der lwIP-Socket-Tabelle (CONFIG_LWIP_MAX_SOCKETS): Typ, lokale Adresse, Gegenstelle.
// Diagnose fuer "socket() fehlgeschlagen" (Tabelle voll -> auch der Webserver nimmt nichts mehr an).
static void cmdSockets() {
    int open = 0;
    for (int fd = 0; fd < 64; fd++) {
        int type = 0; socklen_t tl = sizeof(type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tl) != 0) continue;
        open++;
        struct sockaddr_in6 la, pa; socklen_t ll = sizeof(la), pl = sizeof(pa);
        char lb[64] = "-", pb[64] = "-";
        if (getsockname(fd, (struct sockaddr*)&la, &ll) == 0) {
            if (la.sin6_family == AF_INET) { char t[20]; inet_ntop(AF_INET, &((struct sockaddr_in*)&la)->sin_addr, t, sizeof(t)); snprintf(lb, sizeof(lb), "%s:%u", t, (unsigned)ntohs(((struct sockaddr_in*)&la)->sin_port)); }
            else { char t[48]; inet_ntop(AF_INET6, &la.sin6_addr, t, sizeof(t)); snprintf(lb, sizeof(lb), "[%s]:%u", t, (unsigned)ntohs(la.sin6_port)); }
        }
        if (getpeername(fd, (struct sockaddr*)&pa, &pl) == 0) {
            if (pa.sin6_family == AF_INET) { char t[20]; inet_ntop(AF_INET, &((struct sockaddr_in*)&pa)->sin_addr, t, sizeof(t)); snprintf(pb, sizeof(pb), "%s:%u", t, (unsigned)ntohs(((struct sockaddr_in*)&pa)->sin_port)); }
            else { char t[48]; inet_ntop(AF_INET6, &pa.sin6_addr, t, sizeof(t)); snprintf(pb, sizeof(pb), "[%s]:%u", t, (unsigned)ntohs(pa.sin6_port)); }
        }
        Serial.printf("  fd %2d  %-6s local %-40s peer %s\r\n", fd,
                      type == SOCK_STREAM ? "TCP" : type == SOCK_DGRAM ? "UDP" : type == SOCK_RAW ? "RAW" : "?", lb, pb);
    }
    Serial.printf("sockets: %d offen (Limit CONFIG_LWIP_MAX_SOCKETS=16)\r\n", open);
}

static void cmdIpsec(const char* rest) {
    while (*rest == ' ') rest++;
    if (!strncmp(rest, "fetch", 5)) { cmdIpsecFetch(rest + 5); return; }
    // IPsec-Server-Benutzer (EAP): Konfiguration ist verfuegbar, auch wenn die Server-Runtime noch fehlt.
    if (!strncmp(rest, "user", 4)) {
        const char* u = rest + 4; while (*u == ' ') u++;
        char ub[80]; strncpy(ub, u, sizeof(ub) - 1); ub[sizeof(ub) - 1] = 0;
        char* op = strtok(ub, " "); char* a = strtok(nullptr, " ");
        if (!op || !*op || !strcmp(op, "list")) { Serial.println(ipsecService.usersJson()); return; }
        if (!strcmp(op, "add") && a) { String e = ipsecService.addUser(String(a)); Serial.println(e.length() ? ("Fehler: " + e) : String("Benutzer hinzugefuegt.")); return; }
        if (!strcmp(op, "del") && a) { Serial.println(ipsecService.deleteUser(atoi(a)) ? F("Benutzer entfernt.") : F("kein Benutzer mit diesem Index.")); return; }
        Serial.println(F("ipsec user [list] | ipsec user add <name> | ipsec user del <index>")); return;
    }
    // PSK-Byte-Audit (PO-Auftrag): (1) synthetischer Roundtrip Browser-Encoding -> Formular-Dekodierung
    // -> NVS -> zurueck mit Sonderzeichen, ohne das echte Secret; (2) Byte-Vergleich des gespeicherten
    // PSK mit einem eingegebenen Wert (nur gleich/ungleich). Nie wird ein PSK ausgegeben.
    if (!strcmp(rest, "psk-selftest")) {
        static const char* samples[] = { "p+ss w0rd=&%25%", "a b+c d", "#hash?q=1&x=2", "\"quote\\back'tick`", "~!*()-_.", "16CharsExactly!!", "trail  ", "  lead" };
        int fails = 0;
        for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
            String s = samples[i];
            // encodeURIComponent-Nachbildung (unreserviert: A-Z a-z 0-9 - _ . ! ~ * ' ( ) )
            String enc; for (size_t k = 0; k < s.length(); k++) { unsigned char c = (unsigned char)s[k];
                if (isalnum(c) || strchr("-_.!~*'()", c)) enc += (char)c; else { char b[4]; snprintf(b, sizeof(b), "%%%02X", c); enc += b; } }
            String dec = weirdHttpUrlDecode(enc);
            bool okWeb = (dec.length() == s.length()) && memcmp(dec.c_str(), s.c_str(), s.length()) == 0;
            Preferences p; bool okNvs = false;
            if (p.begin("ipsec-selft", false)) { p.putString("k", s); String r = p.getString("k", ""); p.remove("k"); p.end();
                okNvs = (r.length() == s.length()) && memcmp(r.c_str(), s.c_str(), s.length()) == 0; }
            if (!okWeb || !okNvs) fails++;
            Serial.printf("  Muster %u: %u Bytes -> Web-Dekodierung %s, NVS-Roundtrip %s\r\n", (unsigned)i + 1, (unsigned)s.length(), okWeb ? "OK" : "FEHLER", okNvs ? "OK" : "FEHLER");
        }
        Serial.println(fails ? "PSK-Selbsttest: FEHLER (siehe oben)" : "PSK-Selbsttest: OK -- Sonderzeichen ueberleben Web-Formular und NVS bytegenau.");
        Serial.println(F("Hinweis: die Konsole selbst filtert Bytes ausserhalb 0x20..0x7E und trimmt Leerzeichen am Rand ('ipsec set psk'); ueber die Web-UI gilt das nicht."));
        return;
    }
    if (!strncmp(rest, "psk-verify", 10)) {
        String v = rest + 10; v.trim();
        if (!v.length()) { Serial.println(F("ipsec psk-verify <wert>: vergleicht bytegenau mit dem gespeicherten PSK (Ausgabe nur gleich/ungleich).")); return; }
        if (!ipsecService.pskSet()) { Serial.println(F("PSK: nicht gesetzt.")); return; }
        Serial.printf("PSK: %s (gespeichert %u Bytes, eingegeben %u Bytes)\r\n", ipsecService.pskEquals(v) ? "IDENTISCH" : "NICHT identisch", (unsigned)ipsecService.pskLength(), (unsigned)v.length());
        return;
    }
    if (!strncmp(rest, "crypttest", 9)) { String v = rest + 9; v.trim(); Serial.println(ipsecRuntime.cryptoSelfTest(v.length() ? v.toInt() : 1408)); return; }
    if (!strncmp(rest, "aesbench", 8)) {   // Vergleich HW-Block / HW-DMA / Software UNTER Last
        String v = rest + 8; v.trim(); int sp = v.indexOf(' ');
        int len = v.length() ? v.substring(0, sp < 0 ? v.length() : sp).toInt() : 1408;
        int rounds = (sp >= 0) ? v.substring(sp + 1).toInt() : 100;
        Serial.print(aesBench(len, rounds)); return;
    }
    if (!strncmp(rest, "aes", 3)) {        // Backend zeigen/setzen: hw | soft | dma
        String v = rest + 3; v.trim();
        if (v == "hw")   aesEngineSetBackend(AesBackend::HW_BLOCK);
        else if (v == "soft") aesEngineSetBackend(AesBackend::SOFT);
        else if (v == "dma")  aesEngineSetBackend(AesBackend::HW_DMA);
        else if (v.length()) { Serial.println(F("ipsec aes hw|soft|dma")); return; }
        Serial.printf("AES-Backend: %s\r\n", aesBackendName(aesEngineBackend()));
        return;
    }
    if (!strncmp(rest, "mtu", 3)) {
        String v = rest + 3; v.trim();
        if (v.length()) {
            bool ok = ipsecRuntime.setTunnelMtu(v.toInt());
            Serial.println(ok ? "ipsec0-MTU gesetzt (wirkt auf neue TCP-Verbindungen; Browser neu laden)" : "MTU 576..1500");
        }
        Serial.printf("ipsec0-MTU: %d   Uplink-MTU (Default-Interface): %d\r\n", ipsecRuntime.tunnelMtu(), ipsecRuntime.uplinkMtu());
        return;
    }
    // ---- Konfigurations-Paritaet mit der Web-UI (ipsec_config_fields) ----
    if (!strcmp(rest, "config")) {
        const IpsecConfig& c = s_draftLive ? s_draft : ipsecService.config();
        Serial.println(s_draftLive ? F("--- IPsec-Konfiguration (ENTWURF, ungespeichert -- 'ipsec save') ---") : F("--- IPsec-Konfiguration (gespeichert) ---"));
        Serial.print(ipsecConfigDump(c, s_draftPsk.length() ? true : ipsecService.pskSet(), s_draftPsk.length() ? s_draftPsk.length() : ipsecService.pskLength(),
                                     s_draftEapPass.length() ? true : ipsecService.eapPassSet()));
        return;
    }
    if (!strcmp(rest, "fields")) {
        int n = 0; const IpsecFieldDef* t = ipsecFieldTable(n);
        for (int i = 0; i < n; i++) { char l[40]; snprintf(l, sizeof(l), "  %-16s ", t[i].key); Serial.print(l); Serial.print(ipsecFieldAllowed(t[i])); Serial.print(F("  -- ")); Serial.println(t[i].help); }
        return;
    }
    if (!strncmp(rest, "get ", 4)) {
        String k = rest + 4; k.trim(); const IpsecFieldDef* f = ipsecFieldFind(k);
        if (!f) { Serial.println("unbekannter Schluessel '" + k + "' -- 'ipsec fields'"); return; }
        if (f->type == IpsecFieldType::Secret) { Serial.println(String(f->key) + " = " + ((!strcmp(f->key, "psk") ? ipsecService.pskSet() : ipsecService.eapPassSet()) ? "gesetzt" : "NICHT gesetzt")); return; }
        String v = ipsecFieldGet(s_draftLive ? s_draft : ipsecService.config(), *f);
        Serial.println(String(f->key) + " = " + (v.length() ? v : String("(leer)")) + (s_draftLive ? " [Entwurf]" : ""));
        return;
    }
    if (!strncmp(rest, "set ", 4)) {
        String kv = rest + 4; kv.trim();
        int sp = kv.indexOf(' '); String k = sp < 0 ? kv : kv.substring(0, sp); String v = sp < 0 ? String("") : kv.substring(sp + 1); v.trim();
        const IpsecFieldDef* f = ipsecFieldFind(k);
        if (!f) { Serial.println("unbekannter Schluessel '" + k + "' -- 'ipsec fields'"); return; }
        if (f->type == IpsecFieldType::Secret) {
            if (!v.length()) { Serial.println(String(f->key) + ": Wert fehlt"); return; }
            draft(); if (!strcmp(f->key, "psk")) s_draftPsk = v; else s_draftEapPass = v;
            Serial.println(String(f->key) + " im Entwurf gesetzt (" + String(v.length()) + " Zeichen; 'ipsec save' speichert)."); return;
        }
        if ((!strcmp(f->key, "ca-pem") || !strcmp(f->key, "extra-pem")) && !v.length()) {
            s_pemMode = true; s_pemKey = f->key; s_pemBuf = ""; draft();
            Serial.println(s_pemKey + ": PEM-Zeilen einfuegen, abschliessen mit 'END' (ABORT bricht ab; leerer Block = 'END' sofort)."); return; }
        String e = ipsecFieldSet(draft(), *f, v);
        if (e.length()) Serial.println("Nicht uebernommen: " + e);
        else Serial.println(String(f->key) + " = " + ipsecFieldGet(s_draft, *f) + " [Entwurf; 'ipsec save' speichert]");
        return;
    }
    if (!strcmp(rest, "discard")) { draftDiscard(); Serial.println(F("Entwurf verworfen.")); return; }
    if (!strcmp(rest, "save") || !strcmp(rest, "save-reconnect")) {
        if (!s_draftLive) { Serial.println(F("Kein Entwurf -- zuerst 'ipsec set <key> <wert>'.")); return; }
        String e = ipsecService.saveConfig(s_draft, s_draftPsk, s_draftEapPass);   // Pruefung + NVS wie die Web-UI
        if (e.length()) { Serial.println(e); return; }
        draftDiscard();
        if (!strcmp(rest, "save-reconnect")) { String r = ipsecService.requestReconnect(); Serial.println(r.length() ? r : String("Gespeichert; Neuverbinden geplant (loop-Task).")); }
        else Serial.println(F("Gespeichert (kein Reconnect; eine laufende Verbindung behaelt die alte Konfiguration, ein manueller Stop bleibt)."));
        return;
    }
    if (!strcmp(rest, "reconnect"))  { String e = ipsecService.requestReconnect(); Serial.println(e.length() ? e : String("IPsec: Neuverbinden geplant (loop-Task).")); return; }
    if (!strcmp(rest, "connect"))    { String e = ipsecService.requestReconnect(); Serial.println(e.length() ? e : String("IPsec: (Neu-)Start geplant (loop-Task).")); return; }
    if (!strcmp(rest, "disconnect")) { ipsecService.requestDisconnect(); Serial.println(F("IPsec: Trennung geplant (kein Autostart bis connect).")); return; }
    if (!strcmp(rest, "rekey"))      { ipsecService.requestRekey(); Serial.println(F("IPsec: Child-SA-Rekey geplant (loop-Task).")); return; }
    if (!strcmp(rest, "ikerekey"))   { ipsecService.requestIkeRekey(); Serial.println(F("IPsec: IKE-SA-Rekey geplant (loop-Task).")); return; }
    if (!strcmp(rest, "pfs on") || !strcmp(rest, "pfs off")) {   // Convenience-Alias: 'set pfs' + 'save' ueber den Feld-Layer
        IpsecConfig c = ipsecService.config();
        const IpsecFieldDef* pfsDef = ipsecFieldFind("pfs");   // nullptr, wenn IPsec nicht im Build ist (Stub-Tabelle leer)
        if (!pfsDef) { Serial.println(F("IPsec nicht im Build enthalten (WEIRDOS_FEATURE_IPSEC=0).")); return; }
        String fe = ipsecFieldSet(c, *pfsDef, !strcmp(rest, "pfs on") ? "1" : "0");
        String e = fe.length() ? fe : ipsecService.saveConfig(c, "", "");   // leere Secrets = behalten
        Serial.println(e.length() ? e : String("PFS ") + (c.pfs ? "AN" : "aus") + " gespeichert -- wirkt beim naechsten Verbinden ('ipsec connect'); Nachweis: 'ipsec rekey' -> IKE-Log 'rekey sent (PFS)' + Ping");
        return;
    }
    if (!strncmp(rest, "ping ", 5))  { String ip = rest + 5; ip.trim(); Serial.println(ipsecService.testPingJson(ip)); return; }   // innerer ICMP-Echo durch den Tunnel (Owner = loop-Task)
    const IpsecConfig& c = ipsecService.config();
    VpnStatus s = ipsecService.vpnStatus();
    Serial.printf("ipsec : mode=%s aktiv=%d autoconn=%d proto=%s auth=%s underlay=%s natT=%d\r\n",
                  c.mode.c_str(), c.active ? 1 : 0, c.autoConnect ? 1 : 0, c.proto.c_str(), c.auth.c_str(), c.underlay.c_str(), c.natT ? 1 : 0);
    Serial.print(F("server: ")); Serial.print(c.serverHost); Serial.print(':'); Serial.println(c.serverPort);
    Serial.printf("policy: ikeEnc=%s ikeHash=%s dh=%s espEnc=%s espHash=%s pfs=%d\r\n",
                  c.ikeEnc.c_str(), c.ikeHash.c_str(), c.ikeDh.c_str(), c.espEnc.c_str(), c.espHash.c_str(), c.pfs ? 1 : 0);
    // Faehigkeit (Client) und Verhalten (Peer) getrennt -- ein "Peer: nicht akzeptiert" ist KEIN Client-Mangel.
    Serial.printf("pfs   : %s, Konfiguration: %s%s\r\n", ipsecPfsSupported() ? "unterstuetzt" : "nicht implementiert", c.pfs ? "an" : "aus",
                  ipsecRuntime.peerPfsRejected() ? ", Peer: PFS beim letzten Child-Rekey nicht akzeptiert -> fuer diese Gegenstelle PFS deaktivieren" : "");
    // Identitaeten + PSK-Status (nie der PSK selbst): AUTHENTICATION_FAILED der Gegenstelle heisst
    // falscher PSK oder falsche/fehlende IDi (FRITZ!Box: IDi = VPN-Benutzername als keyid).
    Serial.printf("ident : IDi = %s   IDr erwartet = %s   psk=%s (%u Zeichen)\r\n",
                  IpsecService::idText(c.localIdType, c.localId).c_str(),
                  IpsecService::idText(c.remoteIdType, c.remoteId).c_str(),
                  ipsecService.pskSet() ? "gesetzt" : "FEHLT", (unsigned)ipsecService.pskLength());
    Serial.printf("tunnel: localTunnelIp='%s' remoteSubnets='%s'\r\n", c.localTunnelIp.c_str(), c.remoteSubnets.c_str());
    Serial.print(F("status: ")); Serial.print(s.stateText); Serial.print(F("  (")); Serial.print(vpnStateName(s.state)); Serial.println(')');
    Serial.print(F("underlay/quell-IP: ")); Serial.print(s.underlay.length() ? s.underlay : String("-"));
    Serial.print(F("   peer: ")); Serial.println(s.peer.length() ? s.peer : String("-"));
    Serial.print(F("detail: ")); Serial.println(s.detail.length() ? s.detail : String("-"));
    Serial.print(F("fehler: ")); Serial.println(s.error.length() ? s.error : String("-"));
    Serial.print(F("diag  : ")); Serial.println(ipsecRuntime.diagJson());   // UDP-Zaehler, lastRxFrom, IKE-Log, offered/negotiated
}

static void cmdWan(const char* rest) {
    while (*rest == ' ') rest++;
    if (!*rest) {
        Serial.printf("wan: %s\r\n", wanPreference().c_str());
        Serial.println(F("setzen: 'wan auto' | 'wan cellular' | 'wan wifi'"));
        return;
    }
    WanPolicy p;
    if      (!strcasecmp(rest, "auto"))     p.preference = "auto";
    else if (!strcasecmp(rest, "cellular")) p.preference = "cellular";
    else if (!strcasecmp(rest, "wifi"))     p.preference = "wifi";
    else { Serial.println(F("? 'wan auto|cellular|wifi'")); return; }
    String err = wanSaveConfig(p);
    Serial.println(err.length() ? err : ("gespeichert: wan=" + p.preference + " (wirkt sofort)"));
}

static void handleLine(char* line) {
    // links/rechts trimmen
    while (*line == ' ' || *line == '\t') line++;
    size_t n = strlen(line);
    while (n && (line[n-1] == ' ' || line[n-1] == '\t')) line[--n] = 0;
    if (n == 0) return;

    // Zugriffsschutz: ist die UART-Konsole deaktiviert (Einrichtung > Setup > UART), nimmt sie KEINE
    // Befehle an und gibt auch keine Befehlsliste aus -- Freischaltung nur ueber die Web-UI.
    if (!setupUartEnabled()) {
        Serial.println(F("[UART deaktiviert -- Zugriffsschutz. Freischaltung nur ueber die Web-UI: Einrichtung > Setup > UART]"));
        return;
    }

    if      (!strcmp(line, "help") || !strcmp(line, "?")) cmdHelp();
    else if (!strcmp(line, "status"))     cmdStatus();
    else if (!strcmp(line, "connect"))    cmdConnect();
    else if (!strcmp(line, "disconnect")) cmdDisconnect();
    else if (!strcmp(line, "reset"))      Serial.println(modemReset());
    else if (!strcmp(line, "usbcycle"))   Serial.println(modemUsbRootPortCycle(nullptr));   // Root-Port deaktivieren/aktivieren (Link-Recovery Stufe 1 von Hand)
    else if (!strcmp(line, "test"))       Serial.println(modemRunInternetTest());
    else if (!strcmp(line, "ip")) {
        String ip = currentWanIp();
        Serial.println(ip.length() ? ip : String("(kein Link)"));
        String ip6 = ecmWanIp6();
        if (ip6.length()) {   // Connect-Ziel von aussen (nur ECM) - in [] fuer Browser/curl
            Serial.print(F("IPv6: [")); Serial.print(ip6); Serial.println(F("]"));
            Serial.print(F("URL : http://[")); Serial.print(ip6); Serial.println(F("]/  (Stream: :81/stream)"));
        }
    }
    else if (!strcmp(line, "reboot")) {
        Serial.println(F("reboot ...")); Serial.flush(); delay(200); ESP.restart();
    }
    else if (!strncmp(line, "acme", 4)) {
        const char* rest = line + 4; while (*rest == ' ') rest++;
        if (!strcmp(rest, "now")) {
            if (acmeStart("manuell (Konsole)")) Serial.println(F("ACME-Lauf gestartet."));
            else Serial.println("ACME nicht gestartet: " + acmeLastError());
        }
        // Konfiguration ueber die Konsole (fuer den Hardware-Test ohne Web): domain/email/staging/tos/on/off
        else if (!strncmp(rest, "domain ", 7))  { AcmeConfig c = acmeConfig(); c.domain = String(rest + 7); c.domain.trim(); acmeSaveConfig(c); Serial.println("Domain: " + c.domain); }
        else if (!strncmp(rest, "email ", 6))   { AcmeConfig c = acmeConfig(); c.email  = String(rest + 6); c.email.trim();  acmeSaveConfig(c); Serial.println("E-Mail: " + c.email); }
        else if (!strcmp(rest, "staging on"))   { AcmeConfig c = acmeConfig(); c.staging = true;  acmeSaveConfig(c); Serial.println(F("Staging AN (Test-CA, Cert nicht browser-gueltig).")); }
        else if (!strcmp(rest, "staging off"))  { AcmeConfig c = acmeConfig(); c.staging = false; acmeSaveConfig(c); Serial.println(F("Staging aus (Produktion).")); }
        else if (!strcmp(rest, "tos"))          { AcmeConfig c = acmeConfig(); c.tos = true;  acmeSaveConfig(c); Serial.println(F("Nutzungsbedingungen akzeptiert.")); }
        else if (!strcmp(rest, "on"))           { AcmeConfig c = acmeConfig(); if (c.domain.length() == 0) { c.domain = dyndnsDomain; acmeSaveConfig(c); } certSetSource(CertSource::Acme); Serial.println("Let's Encrypt AN, Domain " + acmeConfig().domain + " (Herkunft=ACME). 'acme now' oder Auto-Bezug; aktiv nach 'reboot'."); }
        else if (!strcmp(rest, "off"))          { certSetSource(CertSource::SelfSigned); Serial.println(F("Let's Encrypt aus -> Herkunft self-signed (aktiv nach 'reboot').")); }
        else if (!strcmp(rest, "clear"))        { acmeClearCert(); Serial.println(F("Zertifikat geloescht (zurueck zu self-signed, nach Neustart).")); }
        else {
            const AcmeConfig& c = acmeConfig();
            Serial.printf("acme: %s, Domain %s, %s, ToS %s\r\n", c.enabled ? "AN" : "aus",
                          c.domain.length() ? c.domain.c_str() : "-", c.staging ? "Staging" : "Produktion", c.tos ? "ja" : "nein");
            Serial.printf("Zertifikat: %s%s\r\n", acmeHasCert() ? "vorhanden " : "keins",
                          acmeHasCert() ? (acmeCertSubject() + ", bis " + systemClockIsoOf(acmeCertNotAfter())).c_str() : "");
            Serial.printf("Status: %s%s\r\n", acmeRunning() ? "laeuft: " : "", acmeStateText().c_str());
            if (acmeLastError().length()) Serial.println("Letzter Fehler: " + acmeLastError());
        }
    }
    else if (!strncmp(line, "cert", 4)) {
        // Notbetrieb ueber Serial: Herkunft umschalten + self-signed erzeugen. Upload/Eintragen
        // laeuft ueber die UI (PEM ist zu gross fuer die Konsole).
        const char* rest = line + 4; while (*rest == ' ') rest++;
        if (!strcmp(rest, "self"))       { certSetSource(CertSource::SelfSigned); Serial.println(F("Herkunft: self-signed (aktiv nach 'reboot').")); }
        else if (!strcmp(rest, "acme"))  { certSetSource(CertSource::Acme); Serial.println(F("Herkunft: Let's Encrypt (aktiv nach 'reboot'; ToS/Domain via 'acme').")); }
        else if (!strcmp(rest, "upload")){ if (certUploadPresent()) { certSetSource(CertSource::Upload); Serial.println(F("Herkunft: eigenes Zertifikat (aktiv nach 'reboot').")); } else Serial.println(F("Kein eigenes Zertifikat hinterlegt -- zuerst in der UI hochladen.")); }
        else if (!strcmp(rest, "selfsign")) { Serial.println(certRegenerateSelfSigned(dyndnsDomain.length() ? dyndnsDomain.c_str() : nullptr) ? F("Neues self-signed erzeugt (aktiv nach 'reboot').") : F("Erzeugung fehlgeschlagen.")); }
        else if (!strcmp(rest, "renew on"))  { certSetSelfSignedRenew(true);  Serial.println(F("self-signed Auto-Erneuerung AN.")); }
        else if (!strcmp(rest, "renew off")) { certSetSelfSignedRenew(false); Serial.println(F("self-signed Auto-Erneuerung aus.")); }
        else {
            CertSource s = certSource();
            Serial.printf("Herkunft: %s\r\n", s == CertSource::Acme ? "Let's Encrypt" : (s == CertSource::Upload ? "eigenes Zertifikat" : "self-signed"));
            Serial.printf("self-signed: %s, bis %s, Auto-Erneuerung %s\r\n",
                          certSelfSignedSubject().length() ? certSelfSignedSubject().c_str() : "keins",
                          certSelfSignedNotAfter() ? systemClockIsoOf(certSelfSignedNotAfter()).c_str() : "-",
                          certSelfSignedRenew() ? "an" : "aus");
            Serial.printf("eigenes: %s%s\r\n", certUploadPresent() ? "vorhanden " : "keins",
                          certUploadPresent() ? (certUploadSubject() + ", bis " + systemClockIsoOf(certUploadNotAfter())).c_str() : "");
            Serial.println(F("setzen: 'cert self|acme|upload' | 'cert selfsign' | 'cert renew on|off' (wirkt nach 'reboot')"));
        }
    }
    else if (!strncmp(line, "web", 3)) {
        // Aussperr-Schutz: der P4 ist nur ueber LTE erreichbar. Startet die Verwaltung nach einem
        // Transportwechsel nicht (oder der Link nicht), laesst sich HTTP/HTTPS hier zurueckschalten.
        const char* rest = line + 3; while (*rest == ' ') rest++;
        if (!strcmp(rest, "http") || !strcmp(rest, "https")) {
            bool https = !strcmp(rest, "https");
            saveWebHttpsEnabled(https);
            Serial.printf("Verwaltung -> %s (ab Neustart). 'reboot' zum Uebernehmen.\r\n", https ? "HTTPS:443" : "HTTP:80");
        } else {
            Serial.printf("web: Verwaltung %s (konfiguriert %s)\r\n",
                          webHttpsEnabled ? "HTTPS:443" : "HTTP:80", webHttpsEnabled ? "https" : "http");
            Serial.println(F("setzen: 'web http' | 'web https' (wirkt nach 'reboot')"));
        }
    }
    else if (!strcmp(line, "time")) {
        Serial.print(F("Systemzeit (UTC): ")); Serial.println(systemClockIso());
        Serial.printf("letzte Netz-Synchronisation: %s\r\n",
                      modemClockLastSyncMs() ? (String((millis() - modemClockLastSyncMs()) / 1000) + " s her").c_str() : "nie");
    }
    else if (!strcmp(line, "at") || !strncmp(line, "at ", 3)) {
        const char* cmd = (n > 3) ? (line + 3) : "AT";
        Serial.println(modemAtTest(3, 0x0F, 0x86, String(cmd)));   // IF3 = AT-Port
    }
    else if (!strcmp(line, "apn") || !strncmp(line, "apn ", 4)) cmdApn(line + 3);
    else if (!strcmp(line, "band") || !strncmp(line, "band ", 5)) cmdBand(line + 4);
    else if (!strcmp(line, "pdp")  || !strncmp(line, "pdp ", 4))  cmdPdp(line + 3);
    else if (!strcmp(line, "mode") || !strncmp(line, "mode ", 5)) cmdMode(line + 4);
    else if (!strcmp(line, "nat")  || !strncmp(line, "nat ", 4))  cmdNat(line + 3);
    else if (!strcmp(line, "wan")  || !strncmp(line, "wan ", 4))  cmdWan(line + 3);
    else if (!strcmp(line, "ipsec") || !strncmp(line, "ipsec ", 6)) cmdIpsec(line + 5);
    else if (!strcmp(line, "wg") || !strncmp(line, "wg ", 3)) cmdWg(line + 2);
    else if (!strcmp(line, "wlan") || !strncmp(line, "wlan ", 5)) cmdWlan(line + 4);
    else if (!strcmp(line, "lan") || !strncmp(line, "lan ", 4)) cmdLan(line + 3);
    else if (!strcmp(line, "setup") || !strncmp(line, "setup ", 6)) cmdSetup(line + 5);
    else if (!strcmp(line, "video") || !strncmp(line, "video ", 6)) cmdVideo(line + 5);
    else if (!strcmp(line, "usbdev") || !strncmp(line, "usbdev ", 7)) cmdUsbDev(line + 6);
    else if (!strcmp(line, "usbports") || !strncmp(line, "usbports ", 9)) cmdUsbPorts(line + 8);
    else if (!strcmp(line, "platform") || !strncmp(line, "platform ", 9)) {
        const char* a = line + 8; while (*a == ' ') a++;
        if (!*a) { Serial.print(platformText()); Serial.println(F("setzen: platform set <esp32-p4-pico|xiao-esp32-s3|custom>   (wirkt nach 'reboot')")); }
        else if (!strncmp(a, "set ", 4)) { String e = platformSet(String(a + 4)); if (e.length()) Serial.println("Fehler: " + e); else { markRestartRequired("Plattform-Profil"); Serial.print(platformText()); Serial.println(F("gespeichert, wirkt nach 'reboot'.")); } }
        else if (!strcmp(a, "export")) Serial.println(platformConfigJson(false));   // ohne eingebettetes SVG (Zeilenlaenge)
        else if (!strncmp(a, "import ", 7)) {
            String e = platformConfigImport(String(a + 7));
            if (e.length()) Serial.println("Fehler: " + e);
            else { markRestartRequired("Plattform (Import)"); Serial.print(platformText()); Serial.println(F("importiert, wirkt nach 'reboot'.")); }
        }
        else Serial.println(F("? 'platform' | 'platform set <id>' | 'platform export' | 'platform import <json>'"));
    }
    else if (!strcmp(line, "zones") || !strncmp(line, "zones ", 6)) cmdZones(line + 5);
    else if (!strcmp(line, "backup"))  cmdBackup();
    else if (!strcmp(line, "sockets")) cmdSockets();
    else if (!strcmp(line, "net") || !strncmp(line, "net ", 4)) cmdNet(line + 3);
    else if (!strcmp(line, "restore")) cmdRestoreStart();
    else if (!strcmp(line, "pin")  || !strncmp(line, "pin ", 4))  cmdPin(line + 3);
    else if (!strncmp(line, "dyndns", 6)) {
        char rb[160]; strncpy(rb, line + 6, sizeof(rb) - 1); rb[sizeof(rb) - 1] = 0;
        char* op = strtok(rb, " "); char* a = strtok(nullptr, " ");
        if (op && !strcmp(op, "now")) { dyndnsForceNow(); Serial.println(F("DynDNS-Update angestossen.")); }
        else if (op && !strcmp(op, "on"))  { dyndnsEnabled = true;  saveDyndnsPrefs(); Serial.println(F("DynDNS AN (gespeichert).")); }
        else if (op && !strcmp(op, "off")) { dyndnsEnabled = false; saveDyndnsPrefs(); Serial.println(F("DynDNS aus (gespeichert).")); }
        else if (op && !strcmp(op, "pass") && a) { dyndnsPass = a; saveDyndnsPrefs(); Serial.println(F("Passwort gesetzt (gespeichert).")); }
        else if (op && !strcmp(op, "set") && a) {
            char* v = strtok(nullptr, " "); String val = v ? String(v) : String("");
            if      (!strcmp(a, "url"))    dyndnsUrl = val;
            else if (!strcmp(a, "domain")) dyndnsDomain = val;
            else if (!strcmp(a, "user"))   dyndnsUser = val;
            else if (!strcmp(a, "egress")) dyndnsEgress = (val == "modem" || val == "wifi") ? val : String("auto");
            else { Serial.println(F("? key: url|domain|user|egress (Passwort: 'dyndns pass <wert>')")); return; }
            dyndnsProvider = "custom"; saveDyndnsPrefs();
            Serial.printf("dyndns %s = %s (gespeichert)\r\n", a, val.c_str());
        }
        else if (!op || !*op) {
            Serial.printf("dyndns: %s  egress=%s\r\n", dyndnsEnabled ? "AN" : "aus", dyndnsEgress.length() ? dyndnsEgress.c_str() : "auto");
            Serial.print(F("domain: ")); Serial.println(dyndnsDomain.length() ? dyndnsDomain : String("-"));
            Serial.print(F("url   : ")); Serial.println(dyndnsUrl.length() ? dyndnsUrl : String("-"));
            Serial.print(F("user  : ")); Serial.println(dyndnsUser.length() ? dyndnsUser : String("-"));
            Serial.print(F("pass  : ")); Serial.println(dyndnsPass.length() ? F("gesetzt") : F("(leer)"));
            Serial.println(F("setzen: dyndns on|off | set url|domain|user|egress <wert> | pass <wert> | now"));
        }
        else Serial.println(F("? 'dyndns' | 'dyndns on|off' | 'dyndns set <key> <wert>' | 'dyndns pass <wert>' | 'dyndns now'"));
    }
    else {
        Serial.print(F("? unbekannt: ")); Serial.println(line);
        Serial.println(F("'help' fuer Befehle."));
    }
}

void serialConsoleTick() {
    if (!s_hello) {   // einmaliger Hinweis, sobald die Konsole das erste Mal laeuft
        s_hello = true;
        if (setupUartEnabled()) Serial.println(F("\r\n[Serielle Konsole bereit -- 'help' fuer Befehle]"));
        else Serial.println(F("\r\n[Serielle Konsole DEAKTIVIERT (Zugriffsschutz) -- Freischaltung ueber die Web-UI: Einrichtung > Setup > UART]"));
    }
    while (Serial.available() > 0) {
        int c = Serial.read();
        if (c < 0) break;
        if (c == '\n' || c == '\r') {
            if (s_len > 0) { s_line[s_len] = 0; if (s_restoreMode) restoreLine(s_line); else if (s_pemMode) pemLine(s_line); else handleLine(s_line); s_len = 0; }
        } else if (c < 0x20 || c > 0x7E) {
            // Steuer-/Nicht-ASCII-Bytes verwerfen: beim Oeffnen des Ports (Monitor/Skript) liegt ein
            // Stoerbyte in der Leitung, das den ERSTEN Befehl unkenntlich machte ("? unbekannt: ?ipsec").
            // Backup/Restore-Zeilen sind reines Base64/ASCII, Umlaute gibt es in Befehlen nicht.
            continue;
        } else if (s_len < sizeof(s_line) - 1) {
            s_line[s_len++] = (char)c;
        } else {
            s_len = 0;   // ueberlange Zeile verwerfen
        }
    }
}
