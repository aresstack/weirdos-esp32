// ============================================================================
// vpn_status.h -- EIN Statusmodell fuer alle VPN-Dienste (WireGuard, IPsec/IKEv2, spaeter mehr).
//
// Jeder Dienst fuellt einen VpnStatus (nicht jedes Feld muss belegt sein); die Uebersichtsseite
// zeigt alle Tunnel in EINER Tabelle (/vpn-status.json). Die Dienst-Seiten unter Dienste/Server
// > VPN zeigen KEINEN Status mehr -- nur Konfiguration und Werkzeuge (Test-Ping, IKE-Protokoll).
// ============================================================================
#ifndef VPN_STATUS_H
#define VPN_STATUS_H
#include <Arduino.h>

enum class VpnState { Inactive, Disconnected, Connecting, Listening, Connected, Error };
const char* vpnStateName(VpnState s);   // "inaktiv" | "getrennt" | "verbindet" | "wartet auf Clients" | "verbunden" | "Fehler"

struct VpnStatus {
    String   service;              // "WireGuard" | "IPsec/IKEv2"
    String   role;                 // "client" | "server"
    bool     active = false;       // konfiguriert/eingeschaltet
    VpnState state  = VpnState::Inactive;
    String   stateText;            // menschenlesbar, dienstspezifisch (z.B. IKE-Zustand)
    String   endpoint;             // Gegenstelle (Client) bzw. Listen-Port (Server)
    String   underlay;             // Egress-Interface / gebundene Quell-IP
    String   tunnelIp;             // eigene Tunnel-IP
    String   peer;                 // Peer-Adresse (aufgeloest)
    String   detail;               // z.B. ausgehandelte Suite, NAT-T, LAN-Gateway
    bool     hasTraffic = false;   // tx/rx gueltig
    uint32_t txPackets = 0, rxPackets = 0, txBytes = 0, rxBytes = 0;
    String   error;                // letzter Fehler ("" = keiner)

    String toJson() const;
};

// Alle Dienste einsammeln -> {"ok":true,"vpn":[{...},{...}]}
String vpnStatusJsonAll();

#endif // VPN_STATUS_H
