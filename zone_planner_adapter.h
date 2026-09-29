// ============================================================================
// zone_planner_adapter.h -- Bruecke Registry (Attachments + Prefixe) -> Planner (Phase 0.2).
//
// Der Planner (zone_planner.*) ist reine Datenlogik ohne Arduino. Dieser Adapter baut aus dem
// Live-Snapshot der NetworkRegistry die ZpAttachment-Liste (Quellnetze, Capabilities,
// erreichbare Prefixe) und liefert Plan-Ergebnisse als Text/JSON fuer Konsole und Diagnose.
// Read-only: es wird NICHTS installiert (Routen/Filter/NAPT kommen erst mit 0.3-0.5).
//
// Regel (PO, Fassung 4): CP-SUBNET des IPsec-Gateways wird nur dann als erreichbar
// uebernommen, wenn ein ausgehandelter TSr es deckt.
// ============================================================================
#ifndef ZONE_PLANNER_ADAPTER_H
#define ZONE_PLANNER_ADAPTER_H

#include <Arduino.h>
#include "zone_planner.h"

// Registry-Snapshot -> Planner-Attachments. Rueckgabe: Anzahl.
int zoneAdapterBuild(ZpAttachment* out, int maxOut);

// "deny|allow|route|nat" (auch ALLOW_AUTO/ROUTE_ONLY/NAT_ONLY/DENY) -> Intent; ok=false bei Unbekannt.
ZoneIntent zoneIntentParse(const String& s, bool& ok);

// Plan einer einzelnen Paarung als Policy-Menge mit genau dieser Policy (Stufe 2, damit
// dieselben Cross-Regeln greifen). Text fuer die Konsole, JSON fuer /zones-plan.json.
String zonePlanText(const String& src, const String& dst, ZoneIntent intent);
String zonePlanJson(const String& src, const String& dst, ZoneIntent intent);

// Uebersicht der Attachments + Prefixe fuer die Konsole ('zones show').
String zoneAttachmentsText();

#endif // ZONE_PLANNER_ADAPTER_H
