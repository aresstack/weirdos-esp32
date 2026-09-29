// ============================================================================
// wireguard_service.h -- WireGuard-Backend-Integration (Stufe 7.3).
//
// Stufe 7.3 ist NUR Build/Initialisierung: das WireGuard-Backend wird in den Build
// eingebunden - es wird KEIN Tunnel automatisch gestartet (das ist 7.4: WireGuard-
// Service, das ein Underlay aus der NetworkRegistry bindet und wg0 erzeugt; 7.5
// registriert wg0 in der NetworkRegistry).
//
// Backend = WireGuard-ESP32 (lwIP), 7.4a VENDORED nach esp32-modem-host/src/WireGuard
// (inkl. der IDF-5-Patches, siehe dortige VENDOR.md). Der Sketch inkludiert die
// vendored Fassung per Anfuehrungszeichen-Pfad -> immer im Build, keine externe Lib
// noetig. WEIRDOS_HAS_WIREGUARD bleibt 1 (Backend ist fester Bestandteil).
// ============================================================================
#ifndef WIREGUARD_SERVICE_H
#define WIREGUARD_SERVICE_H

#include <Arduino.h>
#include <vector>

#define WEIRDOS_HAS_WIREGUARD 1

// 7.9.2 Multi-Client: ein zugelassenes Client-Geraet (Server-Rolle). peerIdx ist der
// Laufzeit-Index im WireGuard-Backend (nur waehrend der Server laeuft; -1 sonst).
struct WgClient {
    String name;      // Anzeigename
    String pub;       // Public Key (base64)
    String ip;        // Tunnel-IP (10.9.0.x)
    int    peerIdx = -1;
};

// 7.4c: fachliche Tunnel-Konfiguration (KEINE lwIP-/esp_netif-Typen, kein struct netif*).
// Private Key + Preshared Key sind Secrets und liegen NICHT in dieser Struktur.
struct WireGuardConfig {
    // 7.9: EIN Backend, aber Server- und Client-Rolle getrennt gespeichert (kein gegenseitiges
    // Ueberschreiben). mode entscheidet, welche Rolle beim Verbinden laeuft.
    String   mode         = "server";      // "server" | "client" - aktive Rolle
    bool     active       = false;         // Rolle freigeschaltet (kein Autostart)
    String   underlay     = "auto";        // gemeinsam: auto|modem|wifi (Policy)
    String   localIp      = "";            // gemeinsam: eigene Tunnel-IP (wg-Interface)
    uint16_t keepalive    = 25;            // gemeinsam: Persistent Keepalive (s), 0 = aus
    bool     fullTunnel   = false;         // gemeinsam: false = Split, true = Full Tunnel

    // --- Server-Rolle (die MCU stellt ein VPN bereit) ---
    String   peerPublicKey= "";            // Public Key des zugelassenen Client-Geraets
    uint16_t endpointPort = 51820;         // Listen-Port
    String   allowedIps   = "0.0.0.0/0";   // erlaubte Quelle (Client-Tunnel-IP/32)
    bool     lanGateway   = false;         // 7.6: Clients duerfen aufs lokale LAN (NAPT)
    String   lanTarget    = "wifi";        // 7.8: LAN-Gateway-Ziel: wifi | ap | both

    // --- Client-Rolle (die MCU verbindet sich in ein fremdes Netz) ---
    String   clientEndpoint  = "";         // Ziel-Server (Host)
    uint16_t clientPort      = 51820;      // Ziel-Server Port
    String   clientPeerPub   = "";         // Public Key der Gegenstelle (Ziel-Server)
    String   clientAllowedIps= "0.0.0.0/0";// was durch den Tunnel geroutet wird
};

#include "vpn_status.h"

class WireGuardService {
public:
    void   begin();                    // 7.3: nur Backend verfuegbar machen, KEIN Tunnel
    bool   backendAvailable() const;   // WireGuard-Backend im Build vorhanden?
    bool   isUp() const;               // Tunnel aktiv? (7.4d)
    String statusText() const;         // menschenlesbarer Status fuer die UI

    // 7.4b: Underlay-Auswahl auf konkretes NetIface + natives netif aufloesen (JSON,
    // kein Handshake). Service kennt nur id + opaken Native-Handle (kein lwIP).
    String underlayDiagJson(const String& sel);

    // 7.4c: Persistenz. Secrets (Priv-Key/PSK): leerer Wert beim Speichern = behalten,
    // werden NIE nach aussen gegeben (nur *Set()-Flags).
    void   loadConfig();
    String saveConfig(const WireGuardConfig& cfg, const String& privKeyOrEmpty, const String& pskOrEmpty);
    const WireGuardConfig& config() const { return cfg_; }
    bool   privateKeySet() const { return privKey_.length() > 0; }
    bool   pskSet() const        { return psk_.length() > 0; }
    size_t privateKeyLength() const { return privKey_.length(); }   // nur die Laenge (UI-Punkte), nie der Wert
    size_t pskLength() const        { return psk_.length(); }

    // 7.4d: manueller Lifecycle. connect() validiert + loest Underlay auf + startet den
    // Handshake in einem eigenen Task; Rueckgabe "" = gestartet, sonst Fehlertext.
    // 7.4d.4: "Client hinzufuegen (QR)". Erzeugt ein Client-Schluesselpaar AUF dem Geraet,
    // traegt den Client-Public-Key als Peer ein (persistiert, ueberschreibt den alten Peer),
    // und liefert die fertige Client-.conf (inkl. Client-Private-Key - nur hier einmalig, nie
    // gespeichert). endpointHostForClient = advertise-Hostname (z.B. DynDNS-Domain). Leerer
    // Rueckgabestring = Fehler (siehe lastError_). Nur sinnvoll im Server-Modus.
    // 7.9.2: fuegt ein NEUES Client-Geraet zur Liste hinzu (ueberschreibt nichts) und liefert
    // dessen fertige .conf. name = Anzeigename (leer -> automatisch). Leerer Rueckgabestring = Fehler.
    String generateClientConfig(const String& endpointHostForClient, const String& name);
    String clientsJson();               // Liste [{name, ip, up}] fuer die UI
    bool   deleteClient(int index);     // Client entfernen (+ Neustart, falls aktiv)
    int    clientCount() const { return (int)clients_.size(); }

    // Zonen 0.1 (Registry-Attachment wg-server/wg-client). Alles read-only, keine Secrets.
    bool   isServerRole() const { return cfg_.mode != "client"; }
    bool   ifaceUp() const;          // wg0 existiert und lauscht (Server: auch OHNE verbundenen Peer) -- Registry-Attachment "up"; isUp() = Peer-Handshake
    String tunnelLocalIp() const { return cfg_.localIp; }
    String peerAllowedCidrs();       // Server: Tunnel-IP/32 je Client-Geraet; Client: was wir durch den Tunnel routen (clientAllowedIps)
    String clientConfigCidrs();      // Server: AllowedIPs, die in ERZEUGTE Client-Konfigurationen geschrieben werden (Server-IP/32 [+ LAN bei LAN-Gateway])
    void*  nativeNetif() const;      // lwIP-netif von wg0 (nullptr wenn nicht initialisiert)
    String lastError() const { return lastError_; }

    // 7.8 Vereinfachung: MCU erzeugt bei Bedarf ihr eigenes Schluesselpaar selbst (der User
    // muss nie einen Private Key eintippen). ensureMcuKey() legt eins an, falls keins da ist.
    bool   ensureMcuKey();
    String mcuPublicKey();   // abgeleiteter Public Key des MCU (zum Anzeigen/Kopieren); "" wenn kein Key

    String connect();
    void   disconnect();
    // 7.9.1: Autostart + Selbstheilung. Regelmaessig aus loop() aufrufen: wenn aktiv, aber
    // nicht laufend, wird (mit Backoff) neu gestartet. Ersetzt die manuellen Start/Stop-Buttons.
    void   supervise();
    String statusJson();          // Status fuer die UI (state/underlay/wgip/endpoint/peerUp)
    VpnStatus vpnStatus();        // einheitliches VPN-Statusmodell (vpn_status.h) fuer die Uebersicht
    void   runConnectBlocking();  // intern (Task-Trampolin) - fuehrt begin() synchron aus

private:
    WireGuardConfig cfg_;
    String          privKey_;   // Secret - nie nach aussen
    String          psk_;       // Secret - nie nach aussen
    String            lastUnderlay_;
    String            lastError_;
    void*             pendingUnderlay_ = nullptr;
    volatile bool     connecting_ = false;
    volatile uint32_t connectGen_ = 0;   // 7.4d.1: Disconnect annulliert laufenden Connect
    uint32_t          pendingGen_ = 0;
    uint32_t          heapBeforeConnect_ = 0, heapAfterBegin_ = 0, heapAfterDisconnect_ = 0;  // 7.4d.1 Instrumentierung
    uint32_t          lastStartAttempt_ = 0;   // 7.9.1: Backoff fuer den Auto-Restart-Supervisor
    bool              up_ = false;
    bool              naptOn_ = false;         // 7.6: NAPT aktiv auf mind. einem LAN-Interface?
    String            lanCidr_;                // 7.6/7.8: erkannte LAN-Subnetz(e) (Status/Diag)
    String            lanCidrsForClient();     // 7.8: CIDR(s) der gewaehlten LAN-Ziele fuer AllowedIPs
    std::vector<WgClient> clients_;            // 7.9.2: zugelassene Client-Geraete (Server-Rolle)
    void              loadClients();           // aus NVS (+ Migration alter Einzel-Peer)
    void              saveClients();           // nach NVS
    String            nextClientIp();          // naechste freie Tunnel-IP (server+1, +2, ...)
    void              addAllServerPeers();     // nach begin(): Peers 2..N ergaenzen, peerIdx setzen
};

extern WireGuardService wireguardService;

#endif // WIREGUARD_SERVICE_H
