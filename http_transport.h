// ============================================================================
// http_transport.h -- Generische HTTP-Transport-Abstraktion (Stufe 7.2c-1).
//
// Bewusst OHNE lwIP/mbedTLS/ESP-IDF-Typen in der Schnittstelle. Ein Transport
// bekommt EIN bereits aufgeloestes konkretes NetIface (egress) und bindet
// den Daten-Socket an dessen lokale IPv4 -> die Quell-IP haengt nicht mehr an
// netif_default (Kern von Issue #6). Der Transport macht KEINEN Policy-Fallback -
// das entscheidet der Consumer (EgressPolicy), nicht der Socket-Code.
// ============================================================================
#ifndef HTTP_TRANSPORT_H
#define HTTP_TRANSPORT_H

#include <Arduino.h>
#include "network_registry.h"   // NetIface (nur id/kind/up/ip - plattformneutral)

struct HttpRequest {
    String url;                       // vollstaendige https-URL
    const NetIface* egress;   // aufgeloestes Interface; Bind-Adresse = egress->ip
    // ---- Phase 3 (ACME): Methode/Body/Header + echte TLS-Pruefung ----
    String method      = "GET";       // "GET" | "POST" | "HEAD"
    String body;                      // Request-Body (POST)
    String contentType;               // z.B. "application/jose+json" (nur mit body)
    String accept;                    // optionaler Accept-Header
    bool   verifyTls   = false;       // true: Server-Zertifikat gegen das IDF-Root-Bundle pruefen
                                      // (braucht gueltige Systemzeit; ACME MUSS pruefen, DynDNS bisher nicht)
    size_t maxBody     = 16384;       // Antwortgroesse-Deckel (Cert-Kette ~3 KB, Directory ~1 KB)
};

struct HttpResponse {
    int    status = 0;   // HTTP-Status (>0) oder 0 bei Verbindungs-/TLS-Fehler
    String body;         // Antwortkoerper (getrimmt; chunked-Transfer aufgeloest)
    String error;        // "" wenn erfolgreich
    // Ausgewaehlte Antwort-Header (ACME braucht Replay-Nonce und Location):
    String replayNonce;  // Replay-Nonce
    String location;     // Location
    String contentType;  // Content-Type
    String retryAfter;   // Retry-After
};

class HttpTransport {
public:
    virtual ~HttpTransport() = default;
    virtual HttpResponse get(const HttpRequest& req) = 0;
    // Allgemeine Anfrage (Methode/Body/Header aus req). Default: nur GET-faehige Transporte.
    virtual HttpResponse request(const HttpRequest& req) { return get(req); }
};

// ESP32-Plattformimplementierung (eigener Socket, an egress->ip gebunden, mbedTLS).
HttpTransport& esp32BoundHttpTransport();

// Persistenten Worker-Task erstellen (EINMAL frueh in setup() aufrufen, damit sein
// Stack aus frischem Boot-Heap kommt und nicht spaeter mbedTLS den Block wegnimmt).
void esp32BoundHttpTransportBegin();

// 7.9.14: mbedTLS-Speicher-Policy (Plattform-Schalter). usePsram=true -> ALLE mbedTLS-
// Allocations (TLS-Record-/IO-Puffer, SSL-Kontext, Entropy/DRBG - auch die des WireGuard-RNG)
// gehen in den PSRAM; der knappe interne RAM (lwIP/USB/WireGuard-Hotpath) bleibt frei. false ->
// Standard (intern). Der Hook ist GLOBAL fuer mbedTLS und muss EINMAL SEHR FRUEH im Boot gesetzt
// werden, BEVOR irgendein mbedTLS/TLS/DRBG lief (kein Umschalten zur Laufzeit - Race). Ohne
// PSRAM (psramFound()==false, z.B. spaeter P4-INTERNAL) ist es ein sicherer No-op (bleibt intern).
void esp32ApplyCryptoMemoryPolicy(bool usePsram);

// Bequemer, stack-sicherer Aufruf: fuehrt get() in einem eigenen Task mit grossem
// Stack aus (mbedTLS-Handshake braucht ihn) und blockiert bis zum Ergebnis. Fuer
// Aufrufer aus kleinen Stacks (WebServer/loop-Task).
HttpResponse esp32BoundHttpGet(const HttpRequest& req);

#endif // HTTP_TRANSPORT_H
