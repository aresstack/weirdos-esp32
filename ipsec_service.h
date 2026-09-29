// ============================================================================
// ipsec_service.h -- IPsec/IKEv2 (+ L2TP/IPsec) Backend, analog zu WireGuardService.
//
// Stufe 8.1. Wie bei WireGuard 7.9 sind Client- und Server-Rolle getrennt gespeichert;
// mode entscheidet die aktive Rolle. Der Client-Modus ist die wichtigste Rolle (MCU haengt
// sich in ein fremdes IPsec-VPN). Diese Klasse ist bewusst lwIP-/ESP-IDF-frei (nur fachliche
// Config + Persistenz + Status), genau wie WireGuardService.
//
// EHRLICHER STAND: Config-Verwaltung, Persistenz (Secrets nie zum Browser), Validierung und
// Status sind funktionsfaehig. Die eigentliche IKEv2/ESP-RUNTIME (Handshake + ESP-Datenpfad)
// ist NOCH NICHT implementiert - es gibt keine portierbare strongSwan-artige Lib fuer ESP32.
// connect() meldet das ehrlich. Siehe problems.md fuer den Weg dahin. Die Informations-
// architektur (Server/Client-Tabs, Formulare, Endpoints) ist damit vollstaendig und testbar.
// ============================================================================
#ifndef IPSEC_SERVICE_H
#define IPSEC_SERVICE_H

#include <Arduino.h>
#include <vector>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#define WEIRDOS_HAS_IPSEC 1

// Ein zugelassener Client (Server-Rolle) - EAP/PSK-Identity + optionale feste virtuelle IP.
struct IpsecUser {
    String name;    // Anzeige-/Login-Name (EAP-Identity)
    String ip;      // optionale feste virtuelle IP aus dem Pool ("" = automatisch)
};

// Fachliche IPsec-Konfiguration (KEINE lwIP-/esp_netif-Typen). Secrets (PSK, EAP-Passwort)
// liegen NICHT in dieser Struktur - sie werden separat und nie nach aussen gehalten.
struct IpsecConfig {
    String   mode        = "client";   // "client" | "server" - aktive Rolle (Client zuerst)
    bool     active      = false;      // Rolle freigeschaltet
    bool     autoConnect = true;       // Autostart beim Boot + automatisches Neuverbinden nach Aenderungen;
                                       // aus = Verbindung nur ueber 'Neu verbinden'
    String   underlay    = "auto";     // auto|modem|wifi (Egress-Policy, wie WireGuard)
    String   proto       = "ikev2";    // "ikev2" (pures IKEv2/IPsec) | "l2tp" (L2TP/IPsec)

    // --- Client-Rolle (MCU verbindet sich in ein fremdes IPsec-VPN) ---
    String   serverHost   = "";                       // Gateway (Host/IP), z.B. FRITZ!Box DDNS
    uint16_t serverPort   = 500;                      // IKE-Port (500, NAT-T 4500)
    String   auth         = "psk";                    // "psk" | "eap" (User/Pass) | "cert"
    bool     natT         = true;                     // NAT-Traversal (UDP-4500) zulassen (fuer WAN/NAT)
    String   localId      = "";                       // eigene IKE-Identity (leer -> aus Quell-IP)
    String   localIdType  = "sourceip";               // keyid|fqdn|rfc822|ipv4|sourceip (Vorgabe: eigene Uplink-IP, kein Wert noetig)
    String   remoteId     = "";                       // erwartete Server-Identity (leer -> akzeptiere IDr)
    String   remoteIdType = "none";                   // none|keyid|fqdn|rfc822|ipv4 (Vorgabe: keine feste Server-Identitaet)
    String   localTunnelIp= "";                       // eigene Tunnel-/TSi-Adresse (Inner-IP im VPN)
    String   eapUser      = "";                       // EAP-/XAuth-/L2TP-Benutzername
    // Trust-Modell fuer das Server-Zertifikat bei Benutzer+Passwort (WeirdIKE weirdike_trust_mode_t):
    //   public      = eingebaute oeffentliche Root-CAs (Host-Truststore = ESP-IDF-Zertifikatsbundle, offline)
    //   public-plus = Host-Truststore + Zusatz: caPem = zusaetzliche Anker, extraPem = Kettenmaterial
    //   own         = NUR eigene Vertrauensanker (caPem), Host-Truststore ungenutzt (heutiges Verhalten)
    //   none        = KEINE Vertrauenspruefung (nicht empfohlen; die IKE-AUTH-Signatur wird weiter geprueft)
    // Genau ZWEI PEM-Bloecke: caPem = Vertrauensanker (Kette darf dort enden; CA, Zwischen-CA als
    // expliziter Anker oder das exakte/selbstsignierte Serverzertifikat), extraPem = Kettenmaterial
    // (Zwischenzertifikate), das nie selbst eine Kette beendet. Kein drittes Feld, keine Flags.
    String   trustMode    = "public";
    String   extraPem     = "";
    String   caPem        = "";                       // CA-Zertifikat(e) (PEM), gegen die sich der VPN-Server bei
                                                      // EAP ausweisen MUSS (RFC 7296 2.16) -- Pflicht bei auth=eap
    String   remoteSubnets= "0.0.0.0/0";              // Traffic Selector TSr (Heimnetz der FRITZ!Box)
    // --- IKEv2-Richtlinie im Raster des LANCOM Advanced VPN Client (Kennungen: ipsec_crypto_caps.h,
    //     CSV = Mehrfachauswahl). Beim Speichern wird jede Auswahl gegen die Faehigkeitstabelle
    //     geprueft: nicht Implementiertes ist in der UI ausgegraut UND wird hier abgelehnt.
    //     HEUTE bietet WeirdIKE fest AES-CBC-256 + SHA-256|SHA-512 + DH14 und ESP AES-CBC-256/SHA-256
    //     an; der Leitungs-Filter (nur Gewaehltes anbieten) folgt mit dem WeirdIKE-Slice "Proposal-Policy".
    String   ikeDh        = "dh14";             // DH-Gruppen (IKE_SA_INIT)
    String   ikeEnc       = "aes256cbc";        // IKE-SA-Verschluesselung
    String   ikeHash      = "sha256";           // IKE-SA-Hash (PRF + Integritaet) -- LANCOM DEFAULT: SHA-256 + SHA1 (SHA1 seit AP9 waehlbar; Vorgabe bleibt SHA-256)
    String   espEnc       = "aes256cbc";        // Child-SA-Verschluesselung (ESP)
    String   espHash      = "sha256";           // Child-SA-Hash (ESP-Integritaet)
    bool     pfs          = false;              // PFS beim Child-Rekey (CREATE_CHILD_SA mit KE, DH14) -- CI-bewiesen, Hardware-Nachweis offen
    // C1/C2/D: Lebensdauern und Liveness (0 = WeirdIKE-Vorgabe bzw. aus). LANCOM-Referenz: IKE 8 h, IPsec 8 h.
    uint16_t ikeLifetimeS   = 28800;   // IKE-SA-Rekey durch uns nach n Sekunden (0 = nur auf Anforderung/Peer)
    uint16_t childLifetimeS = 3300;    // Child-SA-Rekey nach n Sekunden (Soft-Lifetime)
    uint16_t childLifetimeMb= 0;       // Child-SA-Rekey nach n MiB ESP-Verkehr (0 = kein Byte-Limit); Zeit UND Bytes gelten
    bool     dpd            = true;    // Dead Peer Detection (eigene Proben); Peer-Proben werden immer beantwortet
    uint16_t dpdIntervalS   = 30;      // Sekunden Eingangsstille bis zur Probe
    uint16_t dpdRetries     = 5;       // Wiederholungen einer Probe, bevor der Peer als tot gilt
    uint16_t nattKeepaliveS = 20;      // NAT-T-Keepalive (UDP/4500) in Sekunden

    // --- Server-Rolle (MCU stellt ein IPsec-VPN bereit) ---
    uint16_t listenPort   = 500;
    String   poolSubnet   = "10.10.0.0/24";           // virtuelle IPs fuer Clients
    String   serverIdent  = "";                       // eigene Identity als Server
};

#include "vpn_status.h"

// Ergebnis eines Diagnose-Tunnel-Pings (inneres ICMP durch die Child-SA). Hier definiert (nicht in
// ipsec_runtime.h), damit die Service-Klasse es als Wert halten kann, ohne die lwIP-/ESP-lastige
// Runtime-Header einzuziehen (die ihrerseits ipsec_service.h einbindet -> sonst Zirkel).
struct IpsecPingResult {
    bool     ok      = false;
    uint32_t rttMs   = 0;
    uint32_t txSeq   = 0;    // ESP TX sequence used
    uint32_t rxSeq   = 0;    // ESP RX sequence of the reply (peer-side)
    String   stage;         // wie weit gekommen / wo gescheitert
    String   detail;        // Klartext-Fehlerstufe
};

class IpsecService {
public:
    void   begin();                     // Backend/Config verfuegbar machen (kein Auto-Connect)
    bool   runtimeAvailable() const;    // IKEv2/ESP-Runtime vorhanden? (aktuell: false)
    bool   isUp() const;                // Tunnel aktiv?
    String statusText() const;          // menschenlesbarer Status fuer die UI

    // Persistenz. Secrets (PSK/EAP-Passwort): leerer Wert beim Speichern = behalten, werden
    // NIE nach aussen gegeben (nur *Set()-Flags).
    void   loadConfig();
    String saveConfig(const IpsecConfig& cfg, const String& pskOrEmpty, const String& eapPassOrEmpty);
    const IpsecConfig& config() const { return cfg_; }
    bool   pskSet() const     { return psk_.length() > 0; }
    size_t pskLength() const  { return psk_.length(); }   // nur die Laenge (Diagnose), nie der Wert
    // Byte-Vergleich des gespeicherten PSK mit einem Eingabewert (Konsole 'ipsec psk-verify'): liefert
    // NUR gleich/ungleich, nie den Wert. Zweck: "16 Zeichen" beweist nur die Laenge, nicht die Bytes.
    bool   pskEquals(const String& v) const { lock(); bool eq = (psk_.length() == v.length()) && (memcmp(psk_.c_str(), v.c_str(), v.length()) == 0); unlock(); return eq; }
    bool   eapPassSet() const { return eapPass_.length() > 0; }
    size_t eapPassLength() const { return eapPass_.length(); }   // nur die Laenge (UI-Punkte), nie der Wert

    // ---- Verantwortlichkeiten (getrennt) ----
    // saveConfig()        : NUR validieren + NVS schreiben (Ergebnis geprueft) + cfg_ unter Mutex
    //                       uebernehmen + Beobachter aufrufen. Kein Runtime-Zugriff, kein Connect.
    // requestConnect()    : plant (Neu-)Start mit der GESPEICHERTEN Config, hebt manuellen Stop auf.
    // requestReconnect()  : dasselbe -- "Neu verbinden" uebernimmt geaenderte Einstellungen.
    // requestDisconnect() : plant Stop + manualStop (kein Autostart, bis requestConnect kommt).
    // supervise()         : EINZIGER Besitzer der WeirdIKE-Runtime (loop-Task): fuehrt Kommandos aus,
    //                       pumpt, Autostart. HTTP-Task und loop-Task teilen cfg_/psk_ nur ueber den Mutex.
    // Observer: Beobachter registrieren sich mit Funktionszeiger; saveConfig() ruft nach erfolgreicher
    // Persistenz JEDEN Beobachter synchron auf (wie ein Interrupt, im speichernden Task). Der
    // eingebaute Lifecycle-Beobachter (begin()) plant daraufhin Neu-Verbinden/Trennen -- ausgefuehrt
    // wird das weiterhin nur in supervise() (loop-Task).
    typedef void (*ConfigObserver)(const IpsecConfig& cfg, void* ctx);
    bool   addConfigObserver(ConfigObserver cb, void* ctx);
    String requestConnect();
    String requestReconnect() { return requestConnect(); }
    void   requestDisconnect();
    void   requestDeactivate();         // Feature aus: Runtime stoppen ohne manualStop (intern/Observer)
    void   requestRekey();              // Child-SA-Rekey sofort ausloesen (Konsole 'ipsec rekey'; nur loop-Task fuehrt aus)
    void   requestIkeRekey();           // IKE-SA-Rekey sofort ausloesen (Konsole 'ipsec ikerekey'; nur loop-Task fuehrt aus)
    void   supervise();
    bool   manualStop() const { return manualStop_; }
    // Von saveConfig()/Observer aufgerufen (HTTP-Task): signalisiert NUR "Config wurde gespeichert".
    // Ob daraufhin (neu) verbunden wird, entscheidet supervise() im loop-Task anhand des echten
    // Runtime-Zustands -- kein Runtime-Read aus einem fremden Task (AP1.2).
    void   signalConfigSaved();
    String statusJson();                // Status fuer die UI
    VpnStatus vpnStatus();              // einheitliches VPN-Statusmodell (vpn_status.h) fuer die Uebersicht
    String testPingJson(const String& targetIp);   // 8.2e: Diagnose-Tunnel-Ping (Fallback); merkt sich das Ziel
    // Single-Owner-Invariante: supervise() (loop-Task) ist der EINZIGE Besitzer der Runtime. Ein
    // fremder Task (HTTP) stellt den Ping an und wartet; laeuft der Aufrufer bereits im Besitzer-Task
    // (serielle Konsole aus loop()), wird derselbe owner-only Pfad unmittelbar ausgefuehrt --
    // sonst wartet der loop-Task auf sich selbst (Timeout, HW-Gate 2026-09-07).
    IpsecPingResult pingOwnerPath(const String& targetIp);   // NUR aus dem Besitzer-Task aufrufen
    TaskHandle_t ownerTask_ = nullptr;                        // vom ersten supervise() gesetzt

    // Zuletzt gepingte Ziele (Dropdown auf der IPsec-Seite). Persistenz im NVS des Geraets, NICHT im
    // Browser -- ueberlebt Neustart und Browserwechsel. Neuestes zuerst, begrenzt (IPSEC_PING_HIST_MAX).
    String pingHistoryJson() const;                 // {"ok":true,"targets":[...]}
    void   rememberPingTarget(const String& ip);    // nach vorne sortieren / aufnehmen, speichern
    bool   forgetPingTarget(const String& ip);      // Eintrag entfernen (SHIFT+ENTF im Dropdown)

    // Server-Rolle: zugelassene Benutzer/Clients (EAP/PSK-Identities).
    String usersJson();
    String addUser(const String& name);
    bool   deleteUser(int index);
    int    userCount() const { return (int)users_.size(); }

    String lastError() const { return lastError_; }
    // Identitaet als Leitungsform: KEY_ID("fritz9352"), FQDN("..."), IPv4(aktuelle Uplink-IP) ...
    // Typen: eigene = keyid|fqdn|rfc822|ipv4|sourceip, Server = none|keyid|fqdn|rfc822|ipv4.
    // "auto" existiert nur noch als Alt-Zustand "nicht festgelegt" (blockiert Verbinden).
    static String idText(const String& type, const String& value);
    static String policyError(const IpsecConfig& c);   // Richtlinie vs. ipsec_crypto_caps ("" = ok)

private:
    IpsecConfig cfg_;
    String      psk_;        // Secret - nie nach aussen
    String      eapPass_;    // Secret - nie nach aussen
    String      lastError_;
    bool        up_ = false;
    uint32_t    lastStartAttempt_ = 0;
    // Kommandoslot HTTP-Task -> loop-Task (unter Mutex; das juengste Kommando gewinnt, bewusst:
    // "Trennen" nach "Verbinden" soll trennen). Ausfuehrung ausschliesslich in supervise().
    enum class Cmd : uint8_t { None, Connect, Disconnect, Rekey, IkeRekey };   // Rekey: Child-SA, IkeRekey: IKE-SA jetzt neu schluesseln (Test/Konsole)
    Cmd         cmd_ = Cmd::None;
    bool        manualStop_ = false;    // Benutzer hat getrennt -> kein Autostart bis requestConnect()
    bool        configSaved_ = false;   // Config frisch gespeichert -> supervise() versoehnt Desired/Runtime
    // Diagnose-Ping-Slot (HTTP-Task stellt an, loop-Task/supervise() fuehrt aus -> EIN Besitzer des
    // ESP-Datenpfads, kein paralleler Socket-/Session-Zugriff aus zwei Tasks, AP1.1).
    bool           pingReq_  = false;
    bool           pingDone_ = false;
    String         pingTarget_;
    IpsecPingResult pingResult_;
    static const int kMaxObservers = 4;
    struct Observer { ConfigObserver cb; void* ctx; };
    Observer    observers_[kMaxObservers];
    int         observerCount_ = 0;
    void        notifyConfigChanged();
    static void lifecycleObserver(const IpsecConfig& cfg, void* ctx);   // eingebauter Beobachter
    mutable SemaphoreHandle_t mtx_ = nullptr;
    void        lock() const;
    void        unlock() const;
    String      validateCfg(const IpsecConfig& c, bool pskPresent, bool eapPassPresent) const;
    String      startNow();             // echter Runtime-Start (nur aus supervise(), mit Config-Snapshot)
    std::vector<IpsecUser> users_;
    std::vector<String>    pingHist_;    // zuletzt gepingte Ziele, neuestes zuerst
    void        loadUsers();
    void        loadPingHistory();
    void        savePingHistory();
    void        saveUsers();
    String      validate() const;   // Client/Server-Pflichtfelder pruefen; "" = ok
};

extern IpsecService ipsecService;

#endif // IPSEC_SERVICE_H
