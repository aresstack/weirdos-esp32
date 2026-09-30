// ============================================================================
// web_ui.h  --  Schnittstelle der View-Schicht (Weboberflaeche)
//
// Saubere Schichtentrennung analog zum Modem-Treiber: web_ui.cpp rendert nur
// HTML/CSS/JS und kennt die App-Logik nicht direkt, sondern greift ueber die
// hier deklarierten extern-Globals (Konfiguration/Zustand) und App-Hooks auf
// die .ino zu. Die .ino haelt Routing (server.on(...)) und Aktionen (handle*)
// und ruft zum Rendern sendAppPage()/sendPinGate().
// ============================================================================
#ifndef WEB_UI_H
#define WEB_UI_H

#include <Arduino.h>
#include "ec200a_modem.h"   // Modem-Globals, LTE_BANDS, modemStatusText, modemProfileLteMask

// ---- Board-Capabilities (ehrliches Gate; keine Behauptung ueber jedes Board) --
// Seit dem Schalterkasten (weirdos_features.h) ist BLE ein Baustein: WEIRDOS_FEATURE_BLE
// ist nur 1, wenn der SoC BLE hat UND der Baustein gewaehlt ist. Der alte Name bleibt
// als Alias, damit ui_bluetooth.cpp und die .ino unveraendert weiterlaufen.
#include "weirdos_features.h"
#define WEIRDOS_HAS_BT WEIRDOS_FEATURE_BLE

// Der globale Arduino-WebServer ist entfallen (Control-Plane = WeirdHttpEsp). Die
// View schreibt ausschliesslich ueber WeirdUiWriter/WeirdHttpResponse.

// ---- App-Konfiguration/-Zustand, den die View liest (Def. in der .ino) ----
// DEVICE_HOSTNAME/PIN_DEFAULT sind in der .ino jetzt OHNE 'static' definiert
// (externe Bindung), FRAME_SIZE_OPTION_COUNT als 'extern const int'.
extern const char* DEVICE_HOSTNAME;
extern String deviceHostname;   // konfigurierbare Router-URL (<name>.local)
extern bool g_cryptoMemPsram;   // 7.9.14: mbedTLS-Speicher-Policy (PSRAM vs intern), UI-Schalter
extern const char* PIN_DEFAULT;
extern const int   FRAME_SIZE_OPTION_COUNT;

extern bool keepApAlways, targetNetworkEnabled, cameraReady, streamEnabled,
            multiStreamEnabled, webWanEnabled, dyndnsEnabled, wifiOffOnMobile,
            setupApActive, diagEnabled;
extern bool webHttpsEnabled;   // Management-Transport HTTPS (UI-Schalter, System > Sicherheit)
extern volatile uint32_t g_httpRenderStage;   // In-Band-Crash-Marker fuer sendAppPage (Absturzstelle)
extern String g_restartReasons;              // "Neustart erforderlich" (gelbe Box auf jeder Seite); leer = nichts offen
void   markRestartRequired(const String& why);   // Einstellung wirkt erst beim Boot -> Box zeigen (Grund dedupliziert)
extern String devicePin, streamKey, streamUser, configuredSsid, cpuProfile,
              dyndnsProvider, dyndnsUrl, dyndnsDomain, dyndnsUser, dyndnsPass, dyndnsEgress;
extern String streamPath;   // konfigurierbarer MJPEG-Stream-Pfad (Default "/stream")
extern int cameraConfiguredMaxIndex, cameraActiveMaxIndex, cameraCurrentIndex,
           cameraTargetFps, cameraBufferQuality, cameraCurrentQuality;
extern int streamPort;      // konfigurierbarer MJPEG-Stream-Port (Default 81)
// H.264 (Server > Video > Stream): Ziel-Bitrate in kbit/s (den LTE-Uplink ausnutzen, nicht die
// Qualitaet druecken) + adaptive Bildrate (bei Stau Frames auslassen statt Verzoegerung aufbauen).
extern int  h264Kbit;       // Default 6000 (Cat-4-Upload gemessen 6-8 Mbit/s)
// Globale Frame-Politik ALLER Streams (Server > Video > Bild, neben der Bildrate): veraltete Frames
// verwerfen = Bildrate folgt der Bandbreite (MJPEG-Verhalten). Wird an cameraStream.setDropStale() gereicht.
extern bool streamDropStale;   // Default true (NVS camera/dropstale)
// Live-Statistik des laufenden H.264-Streams (vom Encode-Task je Sekunde gesetzt; 0 = kein Stream).
extern volatile uint32_t g_h264StatFps, g_h264StatKbit, g_h264StatSkips;
extern String streamType;   // Video-Transport: "off" | "http" (Port 81: MJPEG + /video.mp4) | "rtsp" (Port 554: /mjpeg + /h264)
extern bool   rtspEnabled;  // = (streamType == "rtsp")
extern int    rtspPort;     // RTSP-Port (Default 554)
extern String rtspTransport;// "tcp" = nur TCP interleaved (1 Socket/Client) | "udp" = zusaetzlich RTP/AVP ueber UDP (2 Sockets mehr je Client)

// ---- App-Hooks (Definition in der .ino), die die View aufruft -------------
void   logEvent(const String& text);   // App-Ereignis-Ringpuffer (System > Ereignisse), auch ohne Serial sichtbar
String eventLogText();                 // der Ring als Text -- Konsolen-Dump der CDC-Lebensader (usb_device_service)
String createSizeOptionsHtml(int maxIndex, int selectedIndex);
String wifiStatusText();
bool   wifiPortalConnected();   // WLAN im Zustand PORTAL_WIFI_CONNECTED?

// ---- Statische View-Assets (Definition in web_ui_assets.cpp) --------------
extern const char PAGE_STYLE[];   // Basis-CSS (auch von .ino-Handlern genutzt)
extern const char APP_STYLE[];    // CSS der App-Oberflaeche
extern const char APP_SCRIPT[];   // JavaScript der App-Oberflaeche

// ---- Neutraler UI-Writer: entkoppelt die Renderer vom Arduino-`server` -----
// Die Renderer schreiben AUSSCHLIESSLICH ueber diesen Writer; er sitzt auf
// WeirdHttpResponse::write() (das seinerseits beginChunked/end kapselt). Damit
// braucht die HTML-Control-Plane keinen Arduino-WebServer mehr -- ein spaeterer
// Adapterwechsel (Esp/HTTPS) trifft nur web_ui.cpp, nicht die 20 Renderer.
// write(const char*) streamt Literale OHNE String-Allokation (fragmentierter Heap!).
class WeirdHttpResponse;   // Vorwaertsdeklaration; Definition nur in web_ui.cpp noetig
class WeirdUiWriter {
public:
    explicit WeirdUiWriter(WeirdHttpResponse& res) : res_(res) {}
    void write(const char* s);          // Literale/PROGMEM (ESP32: Flash ist lesbar) -> keine Kopie
    void write(const String& s);        // dynamische Fragmente
    void writeProgmem(const char* s);   // explizit fuer PAGE_STYLE/APP_STYLE/APP_SCRIPT
private:
    WeirdHttpResponse& res_;
};

// ---- Skin / Geruest + Helfer (Definition in web_ui.cpp) -------------------
// sendPinGate/sendAppPage RENDERN nur; die Auth-/WAN-Entscheidung faellt VORHER
// im Handler (Root/Captive/Probe), nicht hier drin.
void   sendPinGate(WeirdHttpResponse& res, bool wrongPin);
// Erzwungene Erst-Einrichtung: Werks-PIN ist noch aktiv -> statt der App eine Seite, die NUR das
// Setzen einer eigenen PIN erlaubt (POST /pin-change). error = Hinweis bei abgelehnter Eingabe.
void   sendPinSetupGate(WeirdHttpResponse& res, const String& error);
String createStatusBlock();
void   sendAppPage(WeirdHttpResponse& res, const String& page = String());   // page = "tab" oder "tab/psub" (?p=), leer = Uebersicht
void   sendAppCss(WeirdHttpResponse& res);   // /app.css (PAGE_STYLE+APP_STYLE, gecacht; URL mit ?v=uiAssetVersion())
void   sendAppJs(WeirdHttpResponse& res);    // /app.js  (APP_SCRIPT, gecacht)
const char* uiAssetVersion();               // Hash der Assets (Cache-Busting)
String escapeHtml(const String& value);

// Einheitliches Geheimnis-Feld (PSK, Passwoerter, Schluessel) -- EIN Element fuer alle Seiten (DRY):
// der gespeicherte Wert verlaesst das Geraet nie. Angezeigt werden Punkte in der gespeicherten LAENGE
// (Platzhalter) und ein Auge-Button, der nur die EIGENE Eingabe sichtbar macht; leer lassen =
// gespeicherten Wert behalten. Markup: label + .field-wrap > input.secret-input + button.secret-eye
// + .secret-hint (JS in web_ui_assets: Auge-Toggle, secretSaved() nach erfolgreichem Speichern).
void writeSecretField(WeirdUiWriter& w, const char* id, const char* name, const String& label,
                      const char* tip, bool isSet, size_t len, const char* unsetHint);
String escapeJson(const String& value);

// Section-Titel mit rechtsbuendigem Icon-Button in derselben Zeile (Aktualisieren, Zuruecksetzen ...).
//   id       = Button-id (oder "" wenn keine) -- fuer getElementById-gebundenes JS
//   extraCls = zusaetzliche Klasse(n) neben icon-action (oder "") -- fuer querySelectorAll-gebundenes
//              JS (z.B. "js-mj-refresh"). Getrennte Parameter, weil zwei class-Attribute im selben
//              Tag vom Browser verworfen werden (das war der Grund, warum der Mobilfunk-Refresh
//              zunaechst nicht band).
//   icon     = HTML-Entity, z.B. UI_ICON_REFRESH / UI_ICON_RESET
//   tooltip  = title + aria-label (Klartext, wird nicht escaped -> keine Nutzerdaten)
#define UI_ICON_REFRESH "&#x21bb;"   // im Kreis drehender Pfeil
#define UI_ICON_RESET   "&#x232b;"   // Loeschen/zuruecksetzen
String uiTitleWithAction(const char* title, const char* id, const char* extraCls, const char* icon, const char* tooltip);
// Einheitlicher Hinweis "Baustein nicht in diesem Build" (gelbe Box) -- EIN Muster fuer alle
// Seiten statt schwarzer Platzhalter. was = Klartext-Subjekt ("Die Kamera"), makro =
// "WEIRDOS_FEATURE_CAMERA=0", weiter = was trotzdem funktioniert ("" = Satz entfaellt).
String uiBausteinFehlt(const char* was, const char* makro, const char* weiter);

// ---- Menueaufbau (web_ui_menu.cpp) + Content je Oberpunkt (ui_*.cpp) ------
// Alle Renderer schreiben ueber den neutralen WeirdUiWriter (kein globaler server).
void renderMenu(WeirdUiWriter& w);       // Sidebar-Navigation
void renderOverview(WeirdUiWriter& w);   // Uebersicht
void renderSetupPortal(WeirdUiWriter& w); // Einrichtung > Setup-Portal (Captive-Portal-Sicherung + Werksreset)
void renderPlatform(WeirdUiWriter& w);    // Einrichtung > Plattform (Board-Profil, Pinout-SVG, USB-Port-Mapping; ui_platform.cpp)
void renderNetmode(WeirdUiWriter& w);    // Einrichtung > Assistent (Betriebsmodi; Phase 1: Config/Anzeige)
void renderWanAccessChoice(WeirdUiWriter& w); // WAN > Netzzugang: Zugang waehlen (WanPolicy, Radiogruppe) + Zustand (ui_wan.cpp)
void renderWanInterfaces(WeirdUiWriter& w);   // Uebersicht > Interfaces: technische Registry (ui_wan.cpp)
void renderInternet(WeirdUiWriter& w);   // WAN > Modem (Zugangsdaten/IPv6/DNS/Datenschicht/Frequenzen), Firewall & NAT
void renderDienste(WeirdUiWriter& w);    // Dienste (DynDNS)
void renderVpnServer(WeirdUiWriter& w);  // Server > VPN (WireGuard-Server + IPsec-Tab)
void renderVpnClient(WeirdUiWriter& w);  // Dienste > VPN (WireGuard-Client + IPsec-Tab)
void renderBluetooth(WeirdUiWriter& w);  // IoT > Bluetooth (BLE-Suche; ohne BT-Funk ehrlicher Hinweis)
void renderPeripherie(WeirdUiWriter& w); // Peripherie (Platzhalter - keine Geraete-/GPIO-Logik)
void renderLanGeneral(WeirdUiWriter& w); // LAN > Allgemein (Router-LAN-Subnetz + Captive-DNS)
void renderWlan(WeirdUiWriter& w);        // LAN > WLAN (Tabs: Funknetz, Sicherheit)
void renderZones(WeirdUiWriter& w);       // LAN > Netzzonen (Phase 1: Verbindungen ALLOW/DENY ueber die Zonen-Runtime, ui_zones.cpp)
void renderNetScanBody(WeirdUiWriter& w, bool wifiOn, bool wifiHw); // D3: Netzwerk-Diagnose (Netz allgemein + Funk WLAN-only) - Body-only (ui_netscan.cpp), Section: Diagnose > Netzwerk
void renderVideoServer(WeirdUiWriter& w);// Server > Video-Server (Stream/Bild; frueher "Kamera")
void renderVideoLive(WeirdUiWriter& w);  // Livebild-Block (ui_video.cpp), Section: Diagnose > Video
void renderDiag(WeirdUiWriter& w);       // Diagnose: System / Modem / Netzwerk / Video (je mit Tabs)
void renderSystem(WeirdUiWriter& w);     // Ereignisse, Update, Energie, Sicherheit, Sicherung

#endif // WEB_UI_H
