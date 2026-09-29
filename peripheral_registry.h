// ============================================================================
// peripheral_registry.h -- Hardware-/Geraete-/Capability-Registry (Stufe 5).
//
// Modell der Hardware-Topologie nach
//   HardwarePort/Bus -> Device -> Capability
// Bewusst NICHT "Port -> genau ein Device": ein Port/Bus (USB-Hub, I2C, SPI)
// kann mehrere Geraete tragen.
//
// ACHTUNG - Stand jetzt: das ist noch KEINE echte Source of Truth, sondern ein
// read-only LIVE-SNAPSHOT. periphBuildModel() liest jedes Mal neu die alten
// Globals/Subsysteme (Modem/Kamera); die Wahrheit liegt weiter dort. Es aendert
// KEIN Runtime-Verhalten. Erst mit dem persistenten Schritt (gewuenschte
// Geraetezuordnung, z.B. USB-Port-Auswahl des Modems) wird die Registry selbst
// zur Source of Truth.
// ============================================================================
#ifndef PERIPHERAL_REGISTRY_H
#define PERIPHERAL_REGISTRY_H

#include <Arduino.h>

// Eine Faehigkeit, die ein Geraet bereitstellt (Modem, Netzinterface, Bildquelle ...).
struct PeriphCap {
    String kind;     // "Modem" | "Network" | "FrameSource"
    String name;     // z.B. "modem-ecm", "camera0"
    String status;   // menschenlesbarer Live-Status
};

// Ein Geraet an einem Port/Bus. Zugeordnet (Config: gewuenschte Zuordnung) und
// erkannt (Runtime: Discovery) sind bewusst getrennt - so bleibt das Modell auch
// bei USB-Hubs/mehreren Modems korrekt (zugeordnetes Geraet != gerade erkanntes).
struct PeriphDev {
    String     name;        // "EC200A-EU", "Bildsensor"
    String     logical;     // logischer Registry-Name, z.B. "cellular0" ("" wenn keiner)
    String     devClass;    // Geraeteklasse, vom Geraet selbst gesetzt (NICHT vom Namen geraten):
                            // "camera" | "cellular" | "wifi" | "audio-input" | "audio-output" | "device"
    bool       assigned = false;   // per Config diesem Port zugeordnet?
    bool       detected = false;   // aktuell an diesem Port erkannt?
    PeriphCap  caps[4];
    int        capCount = 0;
};

// Ein Hardware-Port/Bus, der >=1 Geraet tragen kann.
struct PeriphPort {
    String     id;          // "USB0", "Camera-Port"
    String     kind;        // "USB", "DVP/CSI" ...
    PeriphDev  devs[3];
    int        devCount = 0;
};

// Gesamtmodell (feste Kapazitaet, kein Heap).
struct PeriphModel {
    PeriphPort ports[6];   // USB(bis 2) + Camera + WLAN + USB-Funkadapter(Info) + Audio-Codec (P4)
    int        portCount = 0;
};

// ---- Persistente Config (Source of Truth fuer die gewuenschte Zuordnung) -----
// Port, dem das logische Modem-Geraet "cellular0" zugeordnet ist (Default "USB0").
// Heute auf dem S3 effektiv nur "USB0"; beim P4 kann "USB1" hinzukommen. Die
// WAN->Modem-Seite schreibt in genau diese Variable (keine zweite Wahrheit).
extern String periphModemPort;

void periphLoadConfig();                    // aus NVS laden (in setup() aufrufen)
void periphSaveModemPort(const String& p);  // cellular0 -> Port zuordnen + persistieren

// Verfuegbare Hardware-Ports (capability-basiert) in out[] schreiben; Anzahl zurueck.
int  periphAvailablePorts(String out[], int maxOut);

// Baut das aktuelle Hardware-Modell (Config + Live-Discovery). read-only Snapshot.
void periphBuildModel(PeriphModel& m);

// Geraeteklasse eines logischen Namens aus der Registry (Source of Truth) -- der
// HTTP-/dev-Layer raet NICHT mehr per Namenspraefix (startsWith), sondern fragt hier.
// "device" wenn der Name nicht im Modell steht.
String periphClassOf(const String& logical);

// ---- FrameSource-Aufloesung (fuer Video-Server UND KI/Objekterkennung) --------
// Die Registry ist die EINZIGE Stelle, die einen logischen FrameSource-Namen
// (z.B. "camera0") auf eine konkrete FrameSource abbildet. Konsumenten (Video-UI,
// Video-Server, spaeter ObjectDetectionService) duerfen cameraManager NICHT per
// String-Vergleich waehlen -- sie fragen hier. Heute: camera0 -> cameraManager;
// spaeter camera1 -> Esp32P4MipiCamera, uvc0 -> UsbUvcCamera (ohne Umbau hier).
class FrameSource;   // Vorwaertsdeklaration -- kein schweres camera-Include im Header

struct PeriphFrameSourceInfo {
    String logicalName;   // stabiler Capability-Name, z.B. "camera0" (NICHT die Beschreibung)
    String deviceName;    // menschenlesbar, z.B. "Bildsensor"
    String portId;        // z.B. "Camera-Port"
    bool   detected;      // aktuell erkannt/bereit?
};

// Erkannte FrameSources aus dem Modell in out[] schreiben; Anzahl zurueck.
int periphFrameSources(PeriphFrameSourceInfo out[], int maxOut);

// Logischen Namen auf die konkrete FrameSource aufloesen; nullptr wenn unbekannt/fehlt.
FrameSource* periphResolveFrameSource(const String& logicalName);

#endif // PERIPHERAL_REGISTRY_H
