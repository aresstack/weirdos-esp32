// ============================================================================
// egress_policy.h -- Geordnete Egress-Auswahl (Stufe 7.2b).
//
// Eine EgressPolicy ist eine GEORDNETE Praeferenz konkreter Interfaces. resolve()
// liefert das erste aktuell verfuegbare (up) Interface aus der NetworkRegistry -
// und fuehrt selbst KEINEN HTTP-Request aus (das macht spaeter der Consumer/Transport).
//
// Policy-Namen entsprechen der bestehenden DynDNS-Auswahl:
//   "auto"  -> [Mobilfunk-WAN, WLAN-STA]   (Mobilfunk bevorzugt, sonst WLAN-Fallback)
//   "modem" -> [Mobilfunk-WAN]
//   "wifi"  -> [WLAN-STA]
// "Mobilfunk-WAN" ist eine LOGISCHE Auswahl -> aktueller Mobilfunk-Datenpfad
// (modem-ecm falls up, sonst modem-ppp); kein erfundenes zweites Interface.
// ============================================================================
#ifndef EGRESS_POLICY_H
#define EGRESS_POLICY_H

#include <Arduino.h>
#include "network_registry.h"

// Loest die Policy auf das erste verfuegbare konkrete Interface auf.
// true + out gefuellt, wenn eines up ist; sonst false.
bool   egressResolve(const String& policy, NetIface& out);

// id des aufgeloesten Interface ("" wenn keines up ist).
String egressResolvedId(const String& policy);

#endif // EGRESS_POLICY_H
