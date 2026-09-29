// access_policy.h -- Zugangsregel je Dienst: aus welcher ZONE darf ein Dienst benutzt werden?
//
// Zonen (aus der Client-IP abgeleitet, keine Ports/Interfaces raten):
//   LAN      = lokales Netz am Geraet (WLAN-AP/-STA-Subnetz) -- immer erlaubt
//   VPN      = Gegenstelle im IPsec-Tunnel (Client-IP im gerouteten ipsec0-Netz)
//   INTERNET = alles andere ueber den Mobilfunk-Uplink (oeffentlich)
// Je Dienst zwei Freigaben: "im VPN" und "im Internet". Internet-Freigabe setzt den vorhandenen
// Schutz voraus (Web: PIN-Session; Stream: Stream-Schluessel). Persistenz NVS "access"/<dienst>.
// Das alte Flag wanweb (Weboberflaeche ueber WAN) bleibt als Spiegel der Web-Internet-Freigabe
// erhalten, weil die PIN-Logik es liest.
#pragma once
#include <Arduino.h>

enum AccessZone : uint8_t { ZONE_LAN = 0, ZONE_VPN = 1, ZONE_INTERNET = 2 };
#define ACCESS_VPN      1u
#define ACCESS_INTERNET 2u

struct AccessService {
    const char* id;        // "web" | "stream" | "nas"
    const char* label;     // UI
    const char* protection;// was im Internet schuetzt (UI-Hinweis)
    uint8_t     defaults;  // ACCESS_* Bitmaske
};

const AccessService* accessServices(int& count);
const char*  accessZoneName(AccessZone z);

// LAN-Erkennung liefert die .ino (kennt AP/STA-Subnetze); VPN-Erkennung fragt die IPsec-Runtime.
void        accessSetLanDetector(bool (*isLanIp)(const String& clientIp));
AccessZone  accessZoneOf(const String& clientIp);

uint8_t     accessMask(const char* svc);                    // gespeichert oder Default
void        accessSet(const char* svc, uint8_t mask);       // persistiert (+ wanweb-Spiegel fuer "web")
bool        accessAllowed(const char* svc, const String& clientIp);   // LAN immer, sonst je Maske
String      accessJson();                                   // {"web":{"vpn":true,"internet":true},...}
