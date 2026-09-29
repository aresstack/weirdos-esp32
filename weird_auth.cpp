// ============================================================================
// weird_auth.cpp  --  siehe weird_auth.h
// ============================================================================
#include "weird_auth.h"
#include "web_ui.h"          // devicePin (PIN-Policy), webWanEnabled (WAN-Policy)
#include "esp_random.h"

static String   s_token        = "";  // aktives Session-Token (RAM; leer = keine Session)
static uint32_t s_expiryMs     = 0;   // serverseitiger Ablauf (millis); 0 = keine Session
static bool     s_issuedSecure = false; // Session ueber HTTPS ausgegeben?
static WeirdAuthScope s_scope  = WeirdAuthScope::MANAGEMENT;  // Scope der aktiven Session

// ---- PIN-Rate-Limiting -----------------------------------------------------
static uint32_t s_pinFails      = 0;  // Fehlversuche in Folge
static uint32_t s_pinLockUntil  = 0;  // gesperrt bis (millis); nur gueltig wenn s_pinFails hoch
static const uint32_t PIN_FREE_TRIES = 5;      // erste Versuche ohne Sperre
static const uint32_t PIN_LOCK_STEP_MS = 15000UL; // Sperre pro Fehlversuch ueber dem Freibetrag

// Serverseitiges TTL passend zum Cookie Max-Age (24h). Ein kopiertes Token darf
// NICHT laenger gelten als das Browser-Cookie -> Ablauf wird serverseitig gefuehrt,
// nicht nur dem Browser ueberlassen.
static const uint32_t SESSION_TTL_MS = 86400000UL;   // 24h

static String genToken() {
    char b[33];
    for (int i = 0; i < 4; i++) snprintf(b + i * 8, 9, "%08x", (unsigned)esp_random());
    return String(b);   // 128 Bit als Hex
}

// Wraparound-sicher (millis() laeuft nach ~49 Tagen ueber; 24h-TTL ist unkritisch).
static bool sessionExpired() {
    if (s_token.length() == 0) return true;
    return (int32_t)(millis() - s_expiryMs) >= 0;
}

namespace WeirdAuth {

// Deckt der Session-Scope den geforderten ab? MANAGEMENT ist Obermenge; VIDEO_READ
// deckt nur VIDEO_READ. Ein gestohlenes Video-Token kann so NIE Management freischalten.
static bool scopeCovers(WeirdAuthScope have, WeirdAuthScope required) {
    if (have == WeirdAuthScope::MANAGEMENT) return true;          // voller Zugriff
    return have == required;                                      // sonst exakter Scope
}

bool authorized(const String& cookieToken, bool isWan, WeirdAuthScope required) {
    if (isWan && !webWanEnabled) return false;    // Web ueber WAN deaktiviert
    // PIN deaktiviert -> nur der volle Management-Zugriff ist "frei"; ein VIDEO_READ-
    // Check haengt weiterhin am echten Video-Grant (kommt mit der VideoServer-Migration).
    if (devicePin.length() == 0 && required == WeirdAuthScope::MANAGEMENT) return true;
    if (sessionExpired())        return false;    // keine/abgelaufene Session (serverseitig)
    if (cookieToken != s_token)  return false;    // Session-Token, nicht die PIN
    return scopeCovers(s_scope, required);        // Scope muss den geforderten abdecken
}

String newSession(bool issuedSecure, WeirdAuthScope scope) {
    s_token        = genToken();
    s_expiryMs     = millis() + SESSION_TTL_MS;
    s_issuedSecure = issuedSecure;
    s_scope        = scope;
    return s_token;
}
void   invalidate() { s_token = ""; s_expiryMs = 0; }
bool   hasSession() { return !sessionExpired(); }
const String& token() { return s_token; }
WeirdAuthScope scope() { return s_scope; }

void invalidateOnTransportChange(bool nowSecure) {
    if (s_token.length() > 0 && s_issuedSecure != nowSecure) invalidate();
}

// Cookie-Name je Transport (hardware-bewiesen 03.09.2026, Chrome): ein ueber HTTPS gesetztes
// Secure-Cookie darf ein HTTP-Ursprung weder ueberschreiben noch loeschen ("Leave Secure Cookies
// Alone"). Nach dem Rueckschalten auf HTTP blieb in Chrome das alte, serverseitig ungueltige
// Secure-Cookie "xcauth" stehen, das neue Set-Cookie der HTTP-Anmeldung wurde still verworfen ->
// Login "akzeptiert", aber jede Folgeanfrage ohne gueltiges Token = wieder die PIN-Maske. Firefox
// ohne HTTPS-Vorgeschichte war nicht betroffen. Loesung: getrennte Namen -- "__Secure-xcauth" fuer
// HTTPS (Prefix erzwingt Secure+HTTPS im Browser), "xcauth" fuer HTTP. Ein veraltetes Cookie des
// jeweils anderen Transports wird schlicht nicht gelesen.
static bool s_transportSecure = false;
void setTransportSecure(bool secure) { s_transportSecure = secure; }
const char* cookieName() { return s_transportSecure ? "__Secure-xcauth" : "xcauth"; }

String setCookieHeader() {
    // Secure NUR bei HTTPS -> ein Secure-Cookie verlaesst den Browser nie ueber Klartext-HTTP
    // (sonst wuerde das hochwertige Token bei HTTP-Zugriff leaken).
    String c = String(cookieName()) + "=" + s_token + "; Path=/; Max-Age=86400; HttpOnly; SameSite=Strict";
    if (s_transportSecure || s_issuedSecure) c += "; Secure";
    return c;
}
String clearCookieHeader() {
    String c = String(cookieName()) + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict";
    if (s_transportSecure) c += "; Secure";
    return c;
}

// ---- PIN-Rate-Limiting -----------------------------------------------------
bool pinRateLimited() {
    if (s_pinFails <= PIN_FREE_TRIES) return false;
    return (int32_t)(millis() - s_pinLockUntil) < 0;   // wraparound-sicher
}
uint32_t pinLockRemainingMs() {
    if (!pinRateLimited()) return 0;
    return s_pinLockUntil - millis();
}
void registerPinResult(bool ok) {
    if (ok) { s_pinFails = 0; s_pinLockUntil = 0; return; }
    s_pinFails++;
    if (s_pinFails > PIN_FREE_TRIES) {
        // Sperre waechst mit jeder weiteren Fehleingabe (linear, gedeckelt bei ~5 min).
        uint32_t steps = s_pinFails - PIN_FREE_TRIES;
        uint32_t lock  = steps * PIN_LOCK_STEP_MS;
        if (lock > 300000UL) lock = 300000UL;
        s_pinLockUntil = millis() + lock;
    }
}

} // namespace WeirdAuth
