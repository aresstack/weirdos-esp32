// ============================================================================
// peripheral_registry.cpp -- Persistente Zuordnung + Live-Discovery.
// Die gewuenschte Geraetezuordnung (z.B. cellular0 -> USB0) ist die Source of
// Truth und liegt im NVS. Der erkannte Zustand ("detected") kommt weiter aus dem
// Live-Zustand (Modem/Kamera). Es wird KEIN USB-Host-/Runtime-Verhalten umgebaut -
// der Port ist heute (S3, nur USB0) rein deklarativ.
// ============================================================================
#include "peripheral_registry.h"
#include <Preferences.h>
#include "web_ui.h"        // cameraReady + (via ec200a_modem.h) modemDeviceHandle/pppIsUp/modemDataMode
#include "ec200a_ecm.h"    // ec200aEcm
#include "camera_manager.h" // cameraManager (ist eine FrameSource) -- einzige Aufloesung camera0->
#include "wifi_caps.h"     // wifiPresent() -- WLAN-Funk vorhanden? (P4: nein)
#include "usb_ports.h"     // USB-Port-Mapping des Boards (Nutzer-Konfig) -> verfuegbare Ports/Beschriftung

String periphModemPort = "USB0";   // Default-Zuordnung fuer cellular0

// ---- Persistenz ------------------------------------------------------------
// Nur bekannte Ports zulassen, sonst Default "USB0". Wird beim Laden UND Speichern
// angewandt, damit die Runtime-Config immer gueltig ist (z.B. gespeichertes "USB1"
// auf einer S3-Firmware, die nur USB0 kennt, faellt sauber auf USB0 zurueck).
static String periphNormalizePort(const String& port) {
    String avail[4];
    int n = periphAvailablePorts(avail, 4);
    for (int i = 0; i < n; i++) if (avail[i] == port) return port;
    return "USB0";
}

void periphLoadConfig() {
    Preferences p;
    p.begin("periph", true);
    String saved = p.getString("modemport", "USB0");
    p.end();
    // Nur kanonisieren, nicht zwingend zurueckschreiben - die Runtime muss nur gueltig sein.
    periphModemPort = periphNormalizePort(saved);
}

void periphSaveModemPort(const String& port) {
    periphModemPort = periphNormalizePort(port);

    Preferences p;
    p.begin("periph", false);
    p.putString("modemport", periphModemPort);
    p.end();
}

// USB-Ports kommen aus dem vom Nutzer gepflegten Mapping (usb_ports.*): nur aktive, gueltige Ports.
int periphAvailablePorts(String out[], int maxOut) {
    int n = 0;
    for (int i = 0; i < usbPortsCount() && n < maxOut; i++) if (usbPortUsable(usbPort(i).id)) out[n++] = usbPort(i).id;
    if (n == 0 && maxOut > 0) out[n++] = "USB0";   // nie leer (Fallback, z.B. alles deaktiviert)
    return n;
}

// ---- Modellaufbau ----------------------------------------------------------
static void addCap(PeriphDev& d, const char* kind, const String& name, const String& status) {
    if (d.capCount >= (int)(sizeof(d.caps) / sizeof(d.caps[0]))) return;
    d.caps[d.capCount].kind   = kind;
    d.caps[d.capCount].name   = name;
    d.caps[d.capCount].status = status;
    d.capCount++;
}

void periphBuildModel(PeriphModel& m) {
    // Sauber zuruecksetzen, nicht auf ein jungfraeuliches Objekt vom Aufrufer bauen
    // (spaeter kann die Registry langlebig/persistent sein).
    m = PeriphModel{};

    bool modemPresent = (modemDeviceHandle() != nullptr);

    // ---- USB-Ports: cellular0 ist genau EINEM Port zugeordnet ----------------
    String ports[4];
    int np = periphAvailablePorts(ports, 4);
    for (int i = 0; i < np && m.portCount < (int)(sizeof(m.ports)/sizeof(m.ports[0])); i++) {
        PeriphPort& p = m.ports[m.portCount++];
        p.id = ports[i];
        { int ui = usbPortIndex(ports[i]); p.kind = (ui >= 0) ? (String("USB ") + usbPort(ui).label + (usbPortIsHighSpeed(ports[i]) ? " (HS)" : " (FS)")) : String("USB-Host"); }

        if (ports[i] == periphModemPort) {
            // Zugeordnetes Modem. "detected" = ist das Modem gerade am USB da?
            // (Der S3-USB-Host unterscheidet keine Ports -> Discovery am zugeordneten Port.)
            PeriphDev& d = p.devs[p.devCount++];
            d.name     = "EC200A-EU";
            d.logical  = "cellular0";
            d.devClass = "cellular";
            d.assigned = true;
            d.detected = modemPresent;

            addCap(d, "Modem", "cellular0", modemPresent ? "vorhanden" : "-");

            bool activeUp = (modemDataMode == "ecm") ? ec200aEcm.isUp() : pppIsUp();
            String ifname = (modemDataMode == "ecm") ? "modem-ecm" : "modem-ppp";
            addCap(d, "Network", ifname, activeUp ? "verbunden" : "getrennt");
        }
        // Andere Ports bleiben ohne zugeordnetes Geraet (leer).
    }

    // ---- Camera-Port: onboard-Bildsensor ------------------------------------
    if (m.portCount < (int)(sizeof(m.ports)/sizeof(m.ports[0]))) {
        PeriphPort& p = m.ports[m.portCount++];
        p.id = "Camera-Port";
        p.kind = "DVP/CSI";

        PeriphDev& d = p.devs[p.devCount++];
        d.name     = "Bildsensor";
        d.logical  = "camera0";
        d.devClass = "camera";
        d.assigned = true;            // fest verbauter Onboard-Sensor
        d.detected = cameraReady;

        addCap(d, "FrameSource", "camera0", cameraReady ? "bereit" : "-");
    }

    // ---- WLAN-Funk: Onboard-Radio (S3 hat es; der P4 NICHT -> nur via ESP-Hosted+C6) ---
    // Analog zur Kamera immer als Onboard-Geraet gefuehrt; "detected" = Funk vorhanden.
    // Speist das AP-Gating im Assistenten (wifi_caps) -> auf dem P4 als "nicht erkannt".
    if (m.portCount < (int)(sizeof(m.ports)/sizeof(m.ports[0]))) {
        PeriphPort& p = m.ports[m.portCount++];
        p.id = "WLAN-Funk";
        p.kind = "WiFi";

        PeriphDev& d = p.devs[p.devCount++];
        d.name     = "Onboard-WLAN";
        d.logical  = "wlan0";
        d.devClass = "wifi";
        d.assigned = true;
        d.detected = wifiPresent();

        addCap(d, "Network", "wlan0", wifiPresent() ? "vorhanden" : "-");
    }

    // ---- USB-Funkadapter: REIN INFORMATIV. ESP-IDF/Arduino-WiFi spricht nur mit Onboard-Funk
    // oder einem SPI/SDIO-ESP-Hosted-Companion, NIE mit USB -- ein per VID/PID erkannter USB-
    // WLAN-Stick ist daher sichtbar, aber mangels Treiber NICHT nutzbar. detected=true heisst
    // NUR "USB-Geraet mit bekanntem WLAN-Chipsatz gefunden", NICHT "als WLAN nutzbar" (siehe
    // wifi_caps.h/usbWifiAdapterDetected()). Wird deshalb NICHT in wifiStackShouldInit() eingerechnet.
    {
        uint16_t uvid = 0, upid = 0;
        const char* chip = usbWifiAdapterDetected(&uvid, &upid);
        if (m.portCount < (int)(sizeof(m.ports)/sizeof(m.ports[0]))) {
            PeriphPort& p = m.ports[m.portCount++];
            p.id = "USB-Funkadapter";
            p.kind = "USB";

            PeriphDev& d = p.devs[p.devCount++];
            d.name     = chip ? chip : "USB-Funkadapter";
            d.logical  = "usbwifi0";
            d.devClass = "wifi";
            d.assigned = false;          // kein fest zugeordnetes Geraet, reine Erkennung
            d.detected = (chip != nullptr);

            addCap(d, "Network", "usbwifi0",
                   chip ? "erkannt - kein Treiber, aktuell nicht nutzbar" : "-");
        }
    }

    // ---- Audio-Codec: Onboard (P4-Pico: ES8311 + SMD-Mikro + Verstaerker/Speaker-Header) ---
    // Logische Geraete microphone0 (audio.capture) + speaker0 (audio.playback). ES8311/I2S
    // bleiben Backend-Detail (kein /dev/es8311). Runtime (Capture/Playback) folgt spaeter -
    // HIER nur Registrierung + Capabilities, damit das Geraete-Menue sie fuehrt. Nur P4 hat
    // den Onboard-Codec (der S3 dieses Projekts nicht).
#if defined(CONFIG_IDF_TARGET_ESP32P4)
    if (m.portCount < (int)(sizeof(m.ports)/sizeof(m.ports[0]))) {
        PeriphPort& p = m.ports[m.portCount++];
        p.id = "Audio-Codec";
        p.kind = "I2S/ES8311";

        if (p.devCount < (int)(sizeof(p.devs)/sizeof(p.devs[0]))) {
            PeriphDev& dmic = p.devs[p.devCount++];
            dmic.name     = "Onboard-Mikrofon";
            dmic.logical  = "microphone0";
            dmic.devClass = "audio-input";
            dmic.assigned = true;
            dmic.detected = true;            // fest verbautes SMD-Mikro am ES8311 (real vorhanden)
            addCap(dmic, "AudioSource", "microphone0", "Mikrofon vorhanden");
        }
        if (p.devCount < (int)(sizeof(p.devs)/sizeof(p.devs[0]))) {
            PeriphDev& dspk = p.devs[p.devCount++];
            dspk.name     = "Audio-Ausgang (Codec)";   // Ausgangs-/Verstaerker-Pfad, KEIN Lautsprecher behauptet
            dspk.logical  = "speaker0";
            dspk.devClass = "audio-output";
            dspk.assigned = true;
            // "detected" = der Ausgangs-/Codec-Pfad ist fest vorhanden (ES8311 + Verstaerker +
            // MX1.25-Header). Ob am Header wirklich ein Lautsprecher haengt, wird NICHT erkannt.
            dspk.detected = true;
            addCap(dspk, "AudioSink", "speaker0", "Ausgangspfad vorhanden (Lautsprecher extern)");
        }
    }
#endif
}

// ---- Geraeteklasse (Source of Truth = Registry, NICHT Namensraten) ---------
// Der HTTP-/dev-Layer fragt hier statt per startsWith(<name>) zu raten. Jedes Geraet
// setzt seine Klasse in periphBuildModel(); hier nur der Lookup ueber den logischen Namen.
String periphClassOf(const String& logical) {
    PeriphModel m;
    periphBuildModel(m);
    for (int pi = 0; pi < m.portCount; pi++)
        for (int di = 0; di < m.ports[pi].devCount; di++) {
            const PeriphDev& d = m.ports[pi].devs[di];
            if (d.logical == logical)
                return d.devClass.length() ? d.devClass : String("device");
        }
    return "device";
}

// ---- FrameSource-Aufloesung ------------------------------------------------
// Enumeriert alle FrameSource-Capabilities aus dem Live-Modell (kind == "FrameSource").
int periphFrameSources(PeriphFrameSourceInfo out[], int maxOut) {
    PeriphModel m;
    periphBuildModel(m);
    int n = 0;
    for (int pi = 0; pi < m.portCount && n < maxOut; pi++) {
        const PeriphPort& p = m.ports[pi];
        for (int di = 0; di < p.devCount && n < maxOut; di++) {
            const PeriphDev& d = p.devs[di];
            for (int ci = 0; ci < d.capCount && n < maxOut; ci++) {
                if (d.caps[ci].kind != "FrameSource") continue;
                out[n].logicalName = d.caps[ci].name;   // stabiler Name (z.B. "camera0")
                out[n].deviceName  = d.name;
                out[n].portId      = p.id;
                out[n].detected    = d.detected;
                n++;
            }
        }
    }
    return n;
}

// Die EINZIGE Zuordnung logischer Name -> konkrete FrameSource. Heute nur camera0.
// Spaeter hier (und NUR hier) camera1/uvc0 ergaenzen -- ohne UI/Video/Server-Umbau.
FrameSource* periphResolveFrameSource(const String& logicalName) {
    if (logicalName == "camera0") return &cameraManager;
    return nullptr;
}
