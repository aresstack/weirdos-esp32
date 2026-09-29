// ============================================================================
// network_forwarding.h -- Zone/Forwarding-Layer (STRUKTUR-STUB, keine Runtime).
//
// Vervollstaendigt das Datenmodell "Geraet -> Interface -> Rolle/Zone -> Forwarding":
//   - NetIface.roles (network_registry.h) sagt, WOFUER ein Interface taugt (WAN/LAN).
//   - NetworkZone gruppiert Interfaces logisch (WAN-Zone, LAN-Zone, spaeter GUEST/IOT).
//   - ForwardingPolicy beschreibt, WIE zwischen Zonen weitergeleitet wird.
//
// STAND: reine Typen als Verortung. KEINE Implementierung -- kein Routing, kein NAPT,
// keine Bridge. Der lauffaehige Default (network_mode.* Phase 1) bleibt unangetastet;
// diese Enums existieren, damit spaetere Slices hier andocken statt neu zu erfinden.
// ============================================================================
#ifndef NETWORK_FORWARDING_H
#define NETWORK_FORWARDING_H

#include <Arduino.h>

// Logische Zone eines Interfaces (grobkoerniger als die roles-Bits, fuer Forwarding-Regeln).
enum NetworkZone : uint8_t {
    ZONE_WAN = 0,   // Internet-Uplink-Seite (z.B. modem-ecm/-ppp, wifi-sta)
    ZONE_LAN = 1,   // lokales Netz (z.B. wifi-ap)
    // ZONE_GUEST, ZONE_IOT -- bewusst spaeter.
};

// Wie wird zwischen zwei Zonen (typ. LAN -> WAN) weitergeleitet.
enum ForwardingPolicy : uint8_t {
    FWD_NONE  = 0,  // kein Forwarding (heutiger Default: AP hat kein Internet)
    FWD_NAPT  = 1,  // NAPT/Masquerade (Router-Mode; braucht lwIP-NAPT)
    FWD_BRIDGE = 2, // transparente L2-Bruecke (WDS) -- nicht generisch moeglich, spaeter
};

// Mapping-Hilfe (STUB): Zone-Zugehoerigkeit aus den Rollen-Bits ableiten. Rein informativ,
// beeinflusst KEIN Routing. Ein Interface kann WAN- und LAN-faehig sein; hier gewinnt LAN
// nur, wenn es NICHT WAN-faehig ist (WAN hat Vorrang fuer die Uplink-Sicht).
static inline NetworkZone networkZoneFromRoles(uint8_t roles) {
    // NETROLE_WAN==1, NETROLE_LAN==2 (network_registry.h)
    if (roles & 1u) return ZONE_WAN;
    return ZONE_LAN;
}

#endif // NETWORK_FORWARDING_H
