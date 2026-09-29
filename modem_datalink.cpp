// ============================================================================
// modem_datalink.cpp  --  Dispatch der neutralen Datenlink-API auf PPP/ECM.
// Siehe modem_datalink.h. KEINE eigene Logik -- nur die eine ppp|ecm-Weiche.
// ============================================================================
#include "modem_datalink.h"

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
