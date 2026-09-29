// ============================================================================
// ipsec_runtime.h -- WeirdIKE/ESP IKEv2 Client-Runtime auf dem ESP32 (Stufe 8.2d/e).
//
// Verdrahtet den portablen WeirdIKE-Kern (src/weirdike) mit ESP-IDF-mbedTLS (Crypto) und einem
// an das gewaehlte Egress (WLAN-STA/Modem) gebundenen lwIP-UDP-Socket (Transport). Besitzt den
// Socket selbst und demuxt UDP/4500 (NAT-T): IKE (Non-ESP-Marker) -> WeirdIKE-Core; ESP-in-UDP ->
// esp_session; 0xFF -> Keepalive ignorieren. Nach CHILD_ESTABLISHED steht esp_session; testPing()
// faehrt einen echten inneren ICMP-Echo durch den Tunnel (Fallback vor generischem ipsec0).
//
// KEINE Secrets in Logs/Status. Portiert vom CI-bewiesenen esp_natt_itest.c (WeirdIKE-Repo).
// ============================================================================
#ifndef IPSEC_RUNTIME_H
#define IPSEC_RUNTIME_H

#include <Arduino.h>
#include "ipsec_service.h"   // IpsecConfig + IpsecPingResult

// Zonen 0.1: Netzsicht des IPsec-Tunnels (Registry-Attachment "ipsec-client").
struct IpsecNetInfo {
    bool    up = false;
    String  local;            // Tunnel-Adresse des Geraets ("" wenn keine)
    uint8_t addrSource = 0;   // 0 keine, 1 konfiguriert, 2 CP (IKE Config Mode), 3 TSi
    int     mtu = 0;
    String  tsi;              // ausgehandelter lokaler Selektor als "a.b.c.d/n" oder "any"; "" = kein Prefix-Bereich (unbekannt)
    int     nTsr = 0;         // ausgehandelte entfernte Selektoren (Wahrheit fuer Routing)
    String  tsr[4];
    int     nCpSub = 0;       // vom Gateway gemeldete INTERNAL_IP4_SUBNET (nur Information)
    String  cpSub[4];
};

class IpsecRuntime {
public:
    // Startet den Client (mode=client, proto=ikev2, auth=psk). "" = gestartet, sonst Fehlertext.
    String start(const IpsecConfig& cfg, const String& psk, const String& eapPass);
    void   stop();
    void   poll();                       // aus loop(): weirdike_poll + Socket-Demux
    bool   rekeyNow();                   // AP5: Child-SA-Rekey (CREATE_CHILD_SA) sofort; nur aus supervise()
    bool   ikeRekeyNow();                // IKE-SA-Rekey (CREATE_CHILD_SA mit IKE-Proposal + KE) sofort; nur aus supervise()
    bool   isUp() const;                 // CHILD_ESTABLISHED + esp_session bereit
    bool   peerPfsRejected() const;      // Gegenstelle hat einen PFS-Child-Rekey ohne D-H/KE beantwortet (Peer-Verhalten, latched)
    bool   isActive() const;             // gestartet (Handshake laeuft oder up)
    String stateText() const;            // menschenlesbarer IKE-Zustand
    String diagJson() const;             // Diagnose (OHNE Secrets)
    void   fillVpnStatus(struct VpnStatus& s) const;   // Runtime-Anteil des einheitlichen VPN-Status

    // Diagnose-Tunnel-Ping: inneres IPv4/ICMP localTunnelIp -> target durch esp_session.
    IpsecPingResult testPing(const String& targetIp);

    // 8.2f: Tunnel als lwIP-Schnittstelle "ipsec0" (fuer Interface-Registry/Uebersicht).
    bool   tunnelUp() const;
    String tunnelIp() const;       // zugewiesene/konfigurierte Tunnel-Adresse ("" wenn down)
    String tunnelRoute() const;    // Diagnosetext: "ipsec0 a.b.c.d/24 (vom Gateway (TSr))"
    bool   tunnelContains(const String& ip) const;   // liegt die IP im gerouteten ipsec0-Netz? (Zone VPN)
    int    tunnelMtu() const;                        // aktuelle ipsec0-MTU
    bool   setTunnelMtu(int mtu);                    // Experiment (Konsole): 576..1500, wirkt auf neue TCP-Verbindungen
    int    uplinkMtu() const;                        // MTU des Default-Interfaces (PPP/ECM)
    // Zonen 0.1: Netzsicht des Tunnels fuer die Registry -- lokale Adresse (Attachment) und
    // ausgehandelte Selektoren (TSi = Absender-Akzeptanz/Rueckweg, TSr = erreichbare Netze)
    // getrennt; CP-SUBNET nur als Information. Keine Schluessel, keine Secrets.
    bool   tunnelNetInfo(IpsecNetInfo& out) const;
    void*  nativeNetif() const;                      // lwIP-netif von ipsec0 (nullptr wenn nicht angelegt)
    String cryptoSelfTest(int len);                  // esp_seal-Primitiven einzeln (Diagnose 1408-B-Seal-Fehler)

private:
    struct Impl;                          // Details (WeirdIKE-Handles) in der .cpp gekapselt
};

extern IpsecRuntime ipsecRuntime;

// Nach einem Panic/WDT-Reset: letzten IPsec-Schritt (RTC-Marker) auf die Konsole melden und die
// Marker loeschen. Einmal im Boot aufrufen (IpsecService::begin), nachdem Serial bereit ist.
void ipsecRuntimeBootReport();

#endif // IPSEC_RUNTIME_H
