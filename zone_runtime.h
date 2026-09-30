// ============================================================================
// zone_runtime.h -- Netzzonen Phase 0.5: Policy-Runtime (zone_forwarder).
//
// Persistiert werden NUR Intents (Quell-Attachment, Ziel-Attachment, DENY/ALLOW_AUTO/ROUTE_ONLY/
// NAT_ONLY), nie der effektive Plan. Bei jeder Registry-Aenderung (Tunnel up/down, neue CP-IP,
// geaenderte TSi/TSr/AllowedIPs, Reconnect/Rekey) und bei jeder Intent-Aenderung kompiliert die
// Runtime alle Intents neu (zoneCompilePolicies, per-Policy-NAT) und installiert atomar:
//   * Zielrouten (Planner-Routen; Ziel-Attachment down -> BLOCK-Eintrag, kein Rueckfall),
//   * Forward-Paare (ROUTE/NAT) fuer den Forward-Hook (Policy-Modus: alles andere DENY),
//   * NAT: napt-Flag auf dem nativen Eingangsinterface jeder NAT-Policy (NAT-Domain), die
//     Uebersetzung selbst entscheidet der Forward-Pfad je Paar (weirdos_ip4_nat_wanted).
// ALLOW_AUTO waehlt automatisch NAT, wenn Routing nicht nachweisbar ist; ROUTE_ONLY wird nie NAT.
// Kein eigenes Conntrack: Antworten laufen ueber die esp-lwIP-NAPT-Tabelle (DNAT-Flag).
// Noch keine grosse UI: Konsole 'zones policy|policies|apply' + /zones.json.
// ============================================================================
#ifndef ZONE_RUNTIME_H
#define ZONE_RUNTIME_H

#include <Arduino.h>
#include "zone_planner.h"

#define ZONE_INTENT_MAX 32

void   zoneRuntimeBegin();                 // Intents aus NVS laden (setup)
void   zoneRuntimePoll();                  // aus loop(): Registry-Fingerprint pruefen, bei Aenderung neu kompilieren + installieren
bool   zoneRuntimeApply();                 // sofort neu kompilieren + installieren; false = Commit verschoben (Runtime belegt/kein Speicher)

// Intents verwalten (persistent). Rueckgabe "" = ok, sonst Fehlertext.
String zoneRuntimeSetPolicy(const String& src, const String& dst, const String& intentWord);
String zoneRuntimeDelPolicy(const String& src, const String& dst);
int    zoneRuntimeIntentCount();

// Diagnose (D1): effektiver Plan der Policy src -> dst, falls ein Intent existiert (mode/reason/natSource).
bool   zoneRuntimePlanFor(const String& src, const String& dst, String& mode, String& reason, String& natSource);
// Existiert ein nicht-DENY-Intent src -> dst? UNABHAENGIG vom kompilierten Plan -- fuer fruehe
// Abfragen direkt nach dem Boot (Mini-DHCP Option 121), bevor der erste Apply gelaufen ist.
bool   zoneRuntimeIntentAllows(const String& src, const String& dst);
// WireGuard-Client-Konfig: die Ziel-Prefixe (CSV "a.b.c.d/n, ...") aller Policies mit dieser Quelle,
// die effektiv ROUTE oder NAT sind -- genau die Netze, die der Client in AllowedIPs (den Tunnel) routen
// muss. Leer wenn keine. Kein Duplikat.
String zoneRuntimeReachableCidrsFrom(const String& srcAttachment);
// GEWUENSCHTE Ziel-Netze (persistent, zuletzt bekannt) aller Nicht-DENY-Intents mit dieser Quelle --
// unabhaengig vom aktuellen Linkzustand des Ziels. Das ist die Quelle fuer WireGuard-AllowedIPs in
// erzeugten Client-Konfigs (PO: AllowedIPs = Konfigurationswunsch, nicht Laufzeitzustand).
String zoneRuntimeDesiredCidrsFrom(const String& srcAttachment);
String zoneRuntimeText();                  // Intents + effektive Plaene + Installationszustand
String zoneRuntimeJson();                  // dito als JSON (/zones.json)

#endif // ZONE_RUNTIME_H
