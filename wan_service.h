// ============================================================================
// wan_service.h -- Generalisierte WAN-Seite + Internet-Erreichbarkeitscheck.
//
// Loest ueber die EgressPolicy (WAN-Auswahl aus der Betriebsart: auto|modem|wifi)
// das AKTIVE WAN-Interface auf und prueft periodisch, ob darueber ECHTES Internet
// erreichbar ist (nicht nur der lokale Router). Der Check laeuft in einem eigenen
// FreeRTOS-Task mit kurzem Timeout -> er blockiert weder loop() noch Webserver.
//
// Genutzt von: Uebersicht + WAN-Seite (Anzeige) und dem IPsec-Autostart-Guard
// (kein connect() ohne bestaetigtes Internet -> keine Boot-/Loop-Freezes).
// ============================================================================
#pragma once
#include <Arduino.h>

class WanService {
public:
    void   begin();                 // startet den Hintergrund-Check-Task (idempotent)
    bool   everChecked() const;     // wurde schon mindestens einmal geprueft?
    bool   wanUp() const;           // ist ein WAN-Interface (per Policy) oben mit IP?
    bool   internetOk() const;      // echtes Internet ueber das WAN erreichbar?
    String ifaceId() const;         // aufgeloestes WAN-Interface ("modem-ecm"/"wifi-sta"/"-")
    String ip() const;              // dessen Quell-IP ("-" wenn down)
    uint32_t lastCheckAgeMs() const;// Alter des letzten Checks (ms)
    String statusJson() const;      // fuer /wan-status.json + UI (keine Secrets)
};

extern WanService wanService;
