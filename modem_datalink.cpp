// ============================================================================
// modem_datalink.cpp  --  Dispatch der neutralen Datenlink-API auf PPP/ECM.
// Siehe modem_datalink.h. KEINE eigene Logik -- nur die eine ppp|ecm-Weiche.
//
// Baustein MODEM (weirdos_features.h): bei WEIRDOS_FEATURE_MODEM=0 bleibt nur der Stub am Ende.
// ============================================================================
#include "weirdos_features.h"   // WEIRDOS_FEATURE_MODEM -- der Schalter dieses Bausteins
#include "modem_datalink.h"     // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_MODEM
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_MODEM=1) -- unveraendert
// ============================================================================

#include "ec200a_modem.h"   // modemDataMode, modemConnect/Disconnect (=pppStart/Stop),
                            // startPppSupervisor, pppStop, pppIsUp/pppIpStr
#include "ec200a_ecm.h"     // ec200aEcm, ecmStartSupervisor/StopSupervisor, ecmWanIp

// Freie Funktion aus der .ino (kein Header): DynDNS sofort anstossen, sobald ein
// Datenlink synchron hochkommt (ECM). PPP ist async (NEG) -> die DynDNS-Loop macht das.
void dyndnsForceNow();

// ECM konfiguriert UND kein aktiver PPP-Rueckfall (ec200a_ecm: 3x ECM-Start fehlgeschlagen).
static inline bool isEcm() { return modemDataMode == "ecm" && !ecmFallbackActive(); }

String modemLinkConnect() {
    String msg;
    // Manuelles Verbinden bei ECM-Einstellung hebt einen PPP-Rueckfall auf: ECM erneut versuchen.
    if (modemDataMode == "ecm" && ecmFallbackActive()) { ecmFallbackReset(); pppStop(); }
    if (isEcm()) {
        ecmStartSupervisor();
        bool ok = ec200aEcm.begin();
        msg = ok ? ("ECM: " + ec200aEcm.statusText())
                 : String("ECM-Start fehlgeschlagen - Modem im usbnet=1(ECM)-Modus? Serielles [ECM]-Log lesen.");
    } else {
        msg = modemConnect();   // == pppStart()
    }
    if (modemLinkIsUp()) dyndnsForceNow();   // synchron oben (ECM) -> IP sofort melden
    return msg;
}

String modemLinkDisconnect() {
    if (isEcm()) { ecmStopSupervisor(); ec200aEcm.stop(); return "ECM getrennt."; }
    return modemDisconnect();   // == pppStop()
}

bool modemLinkIsUp() {
    return isEcm() ? ec200aEcm.isUp() : pppIsUp();
}

String modemLinkWanIp() {
    if (isEcm()) return ec200aEcm.isUp() ? ecmWanIp() : String("");
    return pppIsUp() ? pppIpStr() : String("");
}

void startModemDataSupervisor() {
    if (isEcm()) { Serial.println("[Datenschicht] ECM gewaehlt -> ECM-Supervisor (PPP aus)."); ecmStartSupervisor(); }
    else         { Serial.println("[Datenschicht] PPP gewaehlt -> PPP-Supervisor.");            startPppSupervisor(); }
}

void stopModemDataSupervisor() {
    if (isEcm()) { ecmStopSupervisor(); ec200aEcm.stop(); }
    else         { pppStop(); }
}

const char* modemLinkModeName() {
    if (modemDataMode == "ecm" && ecmFallbackActive()) return "PPP (Rueckfall, ECM-Start fehlgeschlagen)";
    return isEcm() ? "CDC-ECM" : "PPP";
}

#else  // !WEIRDOS_FEATURE_MODEM
// ============================================================================
// Stub: keine Datenlink-Weiche ohne Modem (WEIRDOS_FEATURE_MODEM=0)
// Kein Bezug auf PPP/ECM und KEIN dyndnsForceNow() (freie Funktion der .ino) -- der Stub haengt
// an nichts. Konsumenten: .ino (Handler, setup), serial_console, ui_wan, Geraete-Descriptor.
// ============================================================================
static const char* const kLinkNotBuilt = "Modem nicht im Build enthalten (WEIRDOS_FEATURE_MODEM=0)";

String modemLinkConnect()    { return kLinkNotBuilt; }
String modemLinkDisconnect() { return kLinkNotBuilt; }
bool   modemLinkIsUp()       { return false; }
String modemLinkWanIp()      { return ""; }

void   startModemDataSupervisor() { Serial.println("[Datenschicht] Modem nicht im Build enthalten (WEIRDOS_FEATURE_MODEM=0) -- kein Supervisor."); }
void   stopModemDataSupervisor()  {}

const char* modemLinkModeName()   { return "Modem nicht im Build enthalten"; }   // Anzeige (ui_wan, Konsole, Descriptor)

#endif // WEIRDOS_FEATURE_MODEM
