// ============================================================================
// setup_guard.h -- "Einrichtung": Captive-Portal-Sicherung + Werksreset-Config.
//
// Zwei Sicherheitsfunktionen fuer ein Geraet OHNE Werksreset-Schalter:
//
//  1) Captive-Portal als Lockout-Schutz. Der Setup-AP (4.3.2.1 + DNS-Hijack) wird
//     ERZWUNGEN, solange KEIN WAN erreichbar ist (weder WLAN-Zielnetz verbunden
//     noch Modem-Datenpfad oben). Kommt WAN hoch, tritt der AP wieder zurueck
//     (sofern nicht "AP dauerhaft an"). Per Checkbox laesst sich das Portal unter
//     Warnhinweis GANZ abschalten (mode = "off") -- dann traegt der Werksreset.
//
//  2) Werksreset ueber die BOOT-Taste (GPIO0): ~N s halten -> Netzwerk/Zugang
//     zuruecksetzen und neu starten. Abschaltbar, Haltezeit konfigurierbar.
//     (GPIO0 ist Strapping-Pin: nur im LAUFENDEN Betrieb halten, nicht beim Boot.)
//
// Dieses Modul haelt nur Config + Persistenz (NVS "setup"); die Laufzeit-Haken
// (AP-Policy, GPIO-Poll, Reset-Wipe) liegen im Sketch, wo WLAN-Status/AP leben.
// ============================================================================
#pragma once
#include <Arduino.h>

#define FACTORY_RESET_PIN       0        // BOOT-Taste auf dem XIAO-ESP32-S3
#define CAPTIVE_MODE_DEFAULT    "auto"   // "auto" (Lockout-Schutz) | "off" (bewusst deaktiviert)
#define RESET_ENABLED_DEFAULT   true
#define RESET_HOLD_MS_DEFAULT    20000UL // Stufe 1 (Netzwerk/Zugang): 20 s halten
#define FULLRESET_ENABLED_DEFAULT true
#define FULLRESET_HOLD_MS_DEFAULT 40000UL // Stufe 2 (ALLES inkl. PIN): 40 s halten

#define UART_ENABLED_DEFAULT    true    // serielle Konsole nimmt Befehle an (Fallback-Zugang)

struct SetupGuardConfig {
    String   captiveMode  = CAPTIVE_MODE_DEFAULT;  // "auto" | "off"
    bool     resetEnabled = RESET_ENABLED_DEFAULT; // Stufe 1: Netzwerk/Zugang per BOOT-Taste
    uint32_t resetHoldMs  = RESET_HOLD_MS_DEFAULT;  // Haltezeit Stufe 1
    bool     fullEnabled  = FULLRESET_ENABLED_DEFAULT; // Stufe 2: kompletter Wipe (PIN + alles)
    uint32_t fullHoldMs   = FULLRESET_HOLD_MS_DEFAULT;  // Haltezeit Stufe 2 (> Stufe 1)
    bool     uartEnabled  = UART_ENABLED_DEFAULT;  // serielle Konsole nimmt Befehle an? (aus = Zugriffsschutz)
};

void   setupGuardLoadConfig();                    // in setup() aufrufen (NVS laden)
String setupGuardSave(const SetupGuardConfig& c); // persistieren (NVS "setup"); "" = ok
const SetupGuardConfig& setupGuardGet();

inline bool setupCaptiveAuto() { return setupGuardGet().captiveMode != "off"; }
inline bool setupCaptiveOff()  { return setupGuardGet().captiveMode == "off"; }
inline bool setupUartEnabled() { return setupGuardGet().uartEnabled; }
