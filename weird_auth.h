// ============================================================================
// weird_auth.h  --  WeirdOS backend-unabhaengiger Session-/Zugriffsdienst.
//
// Kennt Session-Token, PIN-Status und WAN-Policy - UNABHAENGIG davon, ob der
// Request ueber WeirdHttp (Arduino/Esp) oder den nativen VideoServer kommt.
// Damit ist Authentisierung orthogonal zur Transportverschluesselung:
// "Video-TLS aus" bedeutet NICHT "Video ohne Zugriffsschutz" - beide Server
// koennen denselben WeirdAuth::authorized()-Check nutzen.
//
// requireSession() (WeirdHttp-Middleware) ist nur EIN Adapter hierauf; der
// CameraServer kann WeirdAuth::authorized() direkt mit Token+isWan aufrufen.
//
// DESIGN-INTENT (fuer die VideoServer-Absicherung, spaeterer Batch):
// Ein Secure-Management-Cookie kann KEINEN bewusst auf HTTP geschalteten Video-
// stream authentisieren (Browser sendet Secure-Cookies nicht ueber HTTP; und
// Secure weglassen wuerde das hochwertige Token ueber Klartext leaken). Daher
// zwei getrennte Credentials mit Capabilities:
//   Management-Token: ui, dev.read, dev.write, ota, security   (Secure-Cookie)
//   Video-Token:      video.read                                (eigener, eingeschraenkt)
// Ein gestohlener Video-Token darf NIE /dev, OTA, Modem, VPN freischalten. Die
// hiesige API ist bewusst auf die Management-Session beschraenkt; der Video-Grant
// kommt mit der VideoServer-Migration dazu (authorizeVideo(...) o.ae.).
// ============================================================================
#ifndef WEIRD_AUTH_H
#define WEIRD_AUTH_H

#include <Arduino.h>

// Bewusst KLEIN gehalten (kein allgemeines RBAC): zwei Session-Typen genuegen.
// Spaeter koennen daraus Bit-Capabilities werden - jetzt nicht noetig, alles
// haengt an derselben PIN-Managementsession.
enum class WeirdAuthScope { MANAGEMENT, VIDEO_READ };

namespace WeirdAuth {

// Darf dieser Request auf eine Ressource des geforderten Scopes?
//   cookieToken = Wert des xcauth-Cookies (bereits geparst)
//   isWan       = Request kam uebers WAN (Aufrufer bestimmt aus clientIp)
//   required    = benoetigter Scope (Default MANAGEMENT)
// Regeln:
//   WAN + Web-ueber-WAN deaktiviert -> nie berechtigt
//   PIN deaktiviert (devicePin leer) -> frei (nur fuer MANAGEMENT; VIDEO_READ wird
//     spaeter separat granted, siehe VideoServer-Migration)
//   sonst: aktive Session muss existieren, Token matchen UND ihr Scope den geforderten
//     abdecken. MANAGEMENT deckt alles ab; VIDEO_READ deckt nur VIDEO_READ ab.
bool authorized(const String& cookieToken, bool isWan, WeirdAuthScope required = WeirdAuthScope::MANAGEMENT);

// issuedSecure = wurde die Session ueber HTTPS ausgegeben? Ein ueber HTTP (Klartext)
// ausgegebenes Token darf nach Umschalten auf HTTPS NICHT weitergelten (koennte
// abgehoert worden sein) - daher wird der Transport mitgefuehrt. scope defaultet auf
// MANAGEMENT (voller Zugriff); ein eingeschraenktes VIDEO_READ-Grant kommt mit der
// VideoServer-Migration.
String        newSession(bool issuedSecure = false, WeirdAuthScope scope = WeirdAuthScope::MANAGEMENT);
void          invalidate();       // Session loeschen (Logout/Factory-Reset/PIN-Wechsel)
bool          hasSession();
const String& token();
WeirdAuthScope scope();           // Scope der aktiven Session
// Fertiger Set-Cookie-Wert (HttpOnly/SameSite=Strict; zusaetzlich Secure, wenn die
// Session ueber HTTPS ausgegeben wurde -> ein Secure-Cookie geht nie ueber Klartext raus).
String        setCookieHeader();
// Cookie-Name je Transport: "__Secure-xcauth" (HTTPS) | "xcauth" (HTTP). Chrome laesst ein ueber
// HTTPS gesetztes Secure-Cookie von einem HTTP-Ursprung weder ueberschreiben noch loeschen -> nach
// dem Rueckschalten auf HTTP blieb das alte Cookie stehen und die HTTP-Anmeldung griff nie.
void          setTransportSecure(bool secure);   // einmal nach dem Start des Management-Servers
const char*   cookieName();
String        clearCookieHeader();               // Logout: Cookie des aktuellen Transports loeschen

// Beim Wechsel des Management-Transportmodus (HTTP<->HTTPS) aufrufen: invalidiert
// eine Session, die unter dem anderen Transport ausgegeben wurde. Verhindert, dass
// ein evtl. ueber Klartext ausgespaehtes Token nach dem TLS-Wechsel weiterlebt.
void          invalidateOnTransportChange(bool nowSecure);

// ---- PIN-Rate-Limiting (Brute-Force-Schutz) --------------------------------
// Vor dem PIN-Vergleich pruefen; nach dem Vergleich das Ergebnis melden. Nach
// zu vielen Fehlversuchen wird der Login kurz gesperrt (Zeitfenster waechst mit
// der Fehlerzahl). Erfolg setzt den Zaehler zurueck.
bool          pinRateLimited();          // true = gerade gesperrt (nicht vergleichen)
uint32_t      pinLockRemainingMs();      // verbleibende Sperrzeit (0 = frei)
void          registerPinResult(bool ok);// Fehlversuch zaehlen / bei Erfolg zuruecksetzen

} // namespace WeirdAuth

#endif // WEIRD_AUTH_H
