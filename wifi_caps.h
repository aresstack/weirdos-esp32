// ============================================================================
// wifi_caps.h -- WLAN-Funk-Capabilities als LAUFZEIT-Query (nicht Compile-Flag)
// + der EINE Nutzer-Schalter, ob der WLAN-/esp_hosted-Stack ueberhaupt geladen wird.
//
// Ob ein echter Repeater moeglich ist, haengt an der REAL vorhandenen Funk-Hardware
// und deren Treiber, NICHT am SoC. Deshalb runtime-abgefragt und (kuenftig) aus der
// Peripherie-Registry gespeist: jedes erkannte Funkmodul traegt Capability-Bits;
// ein USB-WLAN-Adapter mit WDS-faehigem Treiber (z.B. am ESP32-P4) kann repeaterCapable
// auf true heben. Onboard-ESP32(-S3)-WLAN kann KEIN transparentes L2-Bridging
// (WDS / 4-Address-Mode) -> heute false.
//
// Wichtig (Ehrlichkeit): zwei Radios allein reichen NICHT. Transparentes Bridging ueber
// die Client-Seite braucht 4-Address/WDS-Support im TREIBER (ein normaler 3-Address-STA
// kann fremde MACs nicht dahinter bridgen). Das Bit wird nur gesetzt, wenn ein erkannter
// Treiber WDS wirklich meldet -- sonst versprechen wir Repeater, der nicht laeuft.
//
// EIN Nutzer-Schalter statt zwei Funktionen: frueher gab es boardHasWifi() (.ino, reines
// Compile-Flag) UND wifiPresent() (hier, identische Logik) parallel -- konsolidiert.
// Dazu ein persistenter Auto/An/Aus-Modus (wifiStackShouldInit() ist die EINE Boot-
// Entscheidung, ob esp_wifi/esp_hosted ueberhaupt angefasst wird).
// ============================================================================
#pragma once
#include <Arduino.h>

// Ist ueberhaupt lokale WLAN-Funk-HARDWARE vorhanden? false auf dem ESP32-P4 (kein
// natives WLAN; nur ueber ESP-Hosted+C6, hier nicht bestueckt), true auf S3 & Co.
// Reine Hardware-Tatsache (heute kompilierzeit-bekannt je SoC) -- NICHT der Nutzer-Wunsch;
// dafuer siehe wifiStackShouldInit(). Ersetzt das fruehere boardHasWifi() in der .ino.
bool wifiPresent();

// Anzahl aktuell erkannter WLAN-Funkmodule (0 wenn kein WLAN, sonst 1 = onboard).
// Spaeter aus der Peripherie-Registry (Onboard + erkannte USB-WLAN-Adapter). Nutzen:
// Repeater-Gate UND AP-Kanal-Logik (zwei Radios -> AP und STA auf getrennten Kanaelen).
int wifiRadioCount();

// true, wenn ein erkanntes Funkmodul transparentes L2-Bridging (WDS/4-Address) meldet.
// Heute (nur Onboard-S3-WLAN): false. Runtime-Hook fuer kuenftige WDS-faehige Adapter.
bool repeaterCapable();

// ---- Nutzer-Schalter: soll der WLAN-Stack ueberhaupt geladen werden? -------------------
// Auto (Default) = nur wenn wifiPresent() (echte Onboard-Funk-Hardware). An = erzwingen
// (auch ohne erkannte Hardware -- z.B. fuer eine kuenftige Boardvariante mit ESP-Hosted-
// Companion-Chip). Aus = nie, auch wenn Hardware erkannt wuerde.
enum class WifiStackMode : uint8_t { Auto = 0, On = 1, Off = 2 };

void          wifiStackModeLoad();              // NVS "wifi"/"stackmode" laden (einmal beim Boot)
WifiStackMode wifiStackMode();                   // aktuell geladener/gesetzter Wert
void          wifiStackModeSave(WifiStackMode mode);   // speichert + haelt wifiStackMode() aktuell
const char*   wifiStackModeToStr(WifiStackMode mode);  // "auto"|"on"|"off" (fuer JSON/NVS)
WifiStackMode wifiStackModeFromStr(const String& s);   // Kehrfunktion, unbekannt -> Auto

// Die EINE Boot-Entscheidung: soll esp_wifi/esp_hosted initialisiert werden (WiFi.mode(),
// startAccessPoint(), beginWifiConnection()/requestWifiScan()) -- oder nur der blanke
// lwIP/tcpip-Unterbau (fuer PPP + Webserver)? Ersetzt boardHasWifi() an den Boot-Gates.
bool wifiStackShouldInit();

// LAUFZEIT-Wahrheit: wurde der WLAN-Stack in diesem Boot tatsaechlich hochgefahren? setup()
// setzt das genau einmal. Jede WLAN-Aktion, die den Treiber lazy initialisieren wuerde (AP
// starten, verbinden, scannen, WiFi.mode) MUSS daran gegated sein: auf dem P4 zieht schon der
// erste solche Aufruf den ESP-Hosted-SDIO-Transport hoch, dessen Puffer ~150 KB internen Heap
// brauchen -> "assert failed: sdio_mempool_create" -> Reboot (Log scratch_14: alle 30 s durch
// die Setup-AP-Automatik). Reine Getter (status/localIP) sind ohne Init harmlos.
void wifiStackMarkActive(bool on);
bool wifiStackActive();

// ---- USB-WLAN-Adapter: rein informative Erkennung, KEIN Treiber -------------------------
// ESP-IDF/Arduino-WiFi spricht ausschliesslich mit Onboard-Funk oder einem SPI/SDIO-ESP-
// Hosted-Companion-Chip -- NIEMALS mit einem USB-Geraet. Ein per USB gestecktes WLAN-
// Dongle ist daher per VID/PID SICHTBAR (die Geraete-Registry zeigt es), aber NICHT
// nutzbar (kein Treiber in dieser Firmware) -- und faellt darum NICHT unter Auto/An.
// Rueckgabe: Chipsatz-Label (z.B. "Realtek RTL8188EUS") wenn ein bekannter WLAN-Chipsatz
// am USB haengt, sonst nullptr. vid/pid optional befuellt.
const char* usbWifiAdapterDetected(uint16_t* vid = nullptr, uint16_t* pid = nullptr);
