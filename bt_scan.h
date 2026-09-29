// ============================================================================
// bt_scan.h -- 8.0: Bluetooth-LE-Geraetesuche + best-effort-Kopplung (WLAN-Monitor-Analog).
//
// WICHTIG - Hardware-Grenze: Der ESP32-S3 hat NUR Bluetooth LE, KEIN Bluetooth
// Classic (BR/EDR). Damit ist echtes A2DP/HFP-Audio bzw. Mikrofon (klassisches
// BT-Audio-Profil) auf dieser Hardware UNMOEGLICH - unabhaengig von der Software.
// Machbar und hier implementiert: BLE-Scan (Geraetesuche mit Name/Adresse/RSSI/
// Services) und ein best-effort BLE-Verbindungs-/Pairing-Versuch.
//
// On-demand: Der BT-Stack (NimBLE) wird NICHT beim Boot, sondern erst beim ersten
// Scan/Connect initialisiert - er belegt spuerbar internen RAM, und der ist auf dem
// S3 knapp. btStackRelease() gibt ihn wieder frei.
// ============================================================================
#ifndef BT_SCAN_H
#define BT_SCAN_H

#include <Arduino.h>

// BLE-Scan im Hintergrund-Task starten (idempotent: ignoriert, wenn schon aktiv).
// seconds = aktive Scandauer (gekappt auf sinnvolle Grenzen).
void   btScanStart(int seconds);

// Scan-Zustand + gefundene Geraete:
// {"running":bool,"initialized":bool,"secs":n,"count":n,"heap":..,"psram":..,
//  "devices":[{"addr":"..","name":"..","rssi":n,"appearance":n,"svc":n,"svc0":"..","mfg":"..","rnd":bool}]}
String btScanJson();

// Kurzstatus (fuer Live-Poll): initialisiert?, laeuft gerade ein Scan/Connect?, letztes
// Connect-Ergebnis, Heap/PSRAM. {"initialized":bool,"busy":bool,"connResult":"..","heap":..,"psram":..}
String btStatusJson();

// Best-effort BLE-Verbindungs-/Pairing-Versuch zu einer Adresse (Hintergrund-Task).
// Ergebnis erscheint in btStatusJson().connResult. EXPERIMENTELL (siehe problems.md).
void   btConnectTest(const String& addr);

// BT-Stack deinitialisieren und internen RAM zurueckgeben (nur wenn kein Scan/Connect laeuft).
void   btStackRelease();

// Laeuft gerade ein BLE-Scan/Connect? Fuer die gegenseitige Sperre mit dem WLAN-Funk-Recon
// (net_scan): beide nutzen das 2,4-GHz-Funkteil, nicht gleichzeitig starten.
bool   btBusy();

#endif // BT_SCAN_H
