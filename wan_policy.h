// ============================================================================
// wan_policy.h -- System-WAN-Wahl als LOGISCHE Praeferenz (Uplink).
//
// Der Nutzer waehlt NICHT zwischen internen Interfaces (modem-ecm/modem-ppp/
// wifi-sta), sondern zwischen logischen Internetzugaengen:
//   auto     -- Mobilfunk bevorzugt, WLAN als Fallback (Default)
//   cellular -- Mobilfunk bevorzugen (Fallback WLAN)
//   wifi     -- WLAN bevorzugen (Fallback Mobilfunk)
//
// "Mobilfunk" loest INTERN auf die konfigurierte Datenschicht auf (modemDataMode):
//   PPP  -> modem-ppp,  CDC-ECM -> modem-ecm.
// Der Fallback ist fachlich Mobilfunk->WLAN -- NICHT ecm->ppp->wlan (wer ECM
// konfiguriert, bekommt nicht heimlich PPP). Diese Policy ist die EINZIGE
// systemweite WAN-Wahl (WanService konsumiert sie). Reiner Lookup, kein Routing.
// ============================================================================
#pragma once
#include <Arduino.h>
#include "network_registry.h"

struct WanPolicy {
    String preference = "auto";   // "auto" | "cellular" | "wifi"
};

void   wanLoadConfig();                       // aus NVS laden (in setup()); Default "auto"
String wanSaveConfig(const WanPolicy& p);     // persistieren (NVS "wanpol"); "" = ok
const WanPolicy& wanPolicyGet();
String wanPreference();                       // "auto" | "cellular" | "wifi"

// Loest die Praeferenz auf das aktive konkrete Interface auf (Mobilfunk -> Datenschicht).
// true wenn ein Kandidat up ist + IP hat.
bool   wanResolve(NetIface& out);

// Konkretes Mobilfunk-Interface fuer die aktuell konfigurierte Datenschicht (modem-ppp|modem-ecm).
String wanCellularIfaceId();

String wanStatusJson();                       // Praeferenz + aufgeloester Zustand (Diagnose, keine Secrets)
