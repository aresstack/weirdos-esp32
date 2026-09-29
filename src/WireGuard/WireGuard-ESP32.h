/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once
#include <IPAddress.h>

class WireGuard
{
private:
    bool _is_initialized = false;
    const char* _psk = nullptr;      // WeirdOS 7.4d: Preshared Key (nullptr = keiner)
    bool _routeDefault = false;      // WeirdOS 7.4d: Full-Tunnel (wg als Default-Route)?
    const char* _allowedCidr = nullptr;  // WeirdOS 7.4d.1: AllowedIPs (erste CIDR); nullptr = 0.0.0.0/0
    uint16_t _keepalive = 0;         // WeirdOS 7.4d.1: Persistent Keepalive (s)
public:
    bool begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort);
    // WeirdOS 7.4b: Underlay explizit binden (rohes lwIP-netif als void*, aus network_platform).
    bool begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort, void* underlayNetif);
    void end();
    bool is_initialized() const { return this->_is_initialized; }
    // WeirdOS 7.4d/7.4d.1: vor begin() setzen.
    void setPresharedKey(const char* psk) { _psk = psk; }
    void setRouteDefault(bool on) { _routeDefault = on; }
    void setAllowedIps(const char* cidr) { _allowedCidr = cidr; }
    void setKeepalive(uint16_t s) { _keepalive = s; }
    bool isPeerUp();                 // Handshake mit dem (ersten) Peer erfolgt?

    // WeirdOS 7.9.2 Multi-Client: nach begin() weitere Server-Peers hinzufuegen (kein Endpoint,
    // allowed_ip = Client-Tunnel-IP/32). Rueckgabe: Peer-Index oder -1. Und Handshake-Status je Index.
    int  addServerPeer(const char* publicKeyB64, const IPAddress& allowedIp);
    bool isPeerUpIndex(int index);
    int  firstPeerIndex() const;     // Index des in begin() angelegten Peers (-1 wenn keiner)
    // 7.9.3 Diagnose: Alter (ms) des letzten empfangenen/gesendeten DATENpakets pro Peer.
    // 0xFFFFFFFF = noch nie. false, wenn Peer ungueltig.
    bool peerStats(int index, uint32_t& rxAgeMs, uint32_t& txAgeMs);

    // WeirdOS 7.9.8: das erzeugte lwIP-netif als opaker Handle (fuer NAPT auf dem WG-Input-netif;
    // kein Suchen nach dem dynamischen Namen "wg5"). nullptr wenn nicht initialisiert.
    void* netifHandle() const;
};
