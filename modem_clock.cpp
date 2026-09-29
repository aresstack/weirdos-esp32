// ============================================================================
// modem_clock.cpp -- siehe modem_clock.h
//
// Baustein MODEM (weirdos_features.h): NUR modemClockSync() braucht den AT-Kanal des Modems.
// Die reinen Uhr-Helfer (systemClockValid/Iso/IsoOf, modemClockLastSyncMs) sind KEIN Modem-Wissen
// -- acme_client, die Zertifikatsanzeige, die serielle Konsole und die .ino nutzen sie auch ohne
// Modem -- und sind deshalb in BEIDEN Zweigen ein und dieselbe Definition (kein Stub-Duplikat,
// das auseinanderlaufen koennte). Bei WEIRDOS_FEATURE_MODEM=0 liefert modemClockSync() false und
// die Uhr bleibt ungesetzt (1970), bis eine andere Quelle sie setzt; systemClockValid() meldet
// das ehrlich.
// ============================================================================
#include "weirdos_features.h"   // WEIRDOS_FEATURE_MODEM -- der Schalter dieses Bausteins
#include "modem_clock.h"        // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#include <sys/time.h>

static uint32_t s_lastSyncMs = 0;

// ---- Reine Uhr-Helfer: in beiden Zweigen identisch und funktional --------------------------
bool systemClockValid() {
    time_t now = time(nullptr);
    return now > (time_t)1704067200;   // 2024-01-01 -- alles davor ist die ungesetzte Uhr (1970)
}

uint32_t modemClockLastSyncMs() { return s_lastSyncMs; }

String systemClockIsoOf(time_t tt) {
    if (tt <= 0) return "-";
    struct tm t; gmtime_r(&tt, &t);
    char b[32];
    snprintf(b, sizeof(b), "%04d-%02d-%02dT%02d:%02d:%02dZ",
             t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
    return String(b);
}

String systemClockIso() {
    if (!systemClockValid()) return "-";
    return systemClockIsoOf(time(nullptr));
}

#if WEIRDOS_FEATURE_MODEM
// ============================================================================
// Echte Netzzeit-Synchronisation (WEIRDOS_FEATURE_MODEM=1) -- unveraendert
// ============================================================================
#include "ec200a_modem.h"   // modemAtTest

// Tage seit 1970-01-01 fuer ein Kalenderdatum (proleptisch gregorianisch, ohne libc-Zeitzone).
static long daysFromCivil(int y, int m, int d) {
    y -= m <= 2;
    long era = (y >= 0 ? y : y - 399) / 400;
    long yoe = y - era * 400;
    long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

bool modemClockSync(uint8_t ifNum, uint8_t epOut, uint8_t epIn) {
    // Automatische Zeitzonen-/Uhr-Nachfuehrung aus dem Netz (NITZ) einschalten; harmlos, wenn
    // schon aktiv. Die Uhr des Modems ist danach Netzzeit, nicht die Modem-Boot-Zeit.
    modemAtTest(ifNum, epOut, epIn, "AT+CTZU=1");
    String r = modemAtTest(ifNum, epOut, epIn, "AT+CCLK?");
    int p = r.indexOf("+CCLK: \"");
    if (p < 0) { Serial.println("[clock] AT+CCLK? ohne Antwort"); return false; }
    // "yy/MM/dd,hh:mm:ss+zz"  (zz = Viertelstunden, Vorzeichen + oder -)
    const char* s = r.c_str() + p + 8;
    int yy, MM, dd, hh, mm, ss, tz; char sign;
    if (sscanf(s, "%2d/%2d/%2d,%2d:%2d:%2d%c%2d", &yy, &MM, &dd, &hh, &mm, &ss, &sign, &tz) != 8) {
        Serial.printf("[clock] CCLK unlesbar: %s\n", s);
        return false;
    }
    int year = 2000 + yy;
    if (year < 2024 || MM < 1 || MM > 12 || dd < 1 || dd > 31) {
        // Modem ohne Netzzeit meldet z.B. 80/01/06 -> nicht uebernehmen.
        Serial.printf("[clock] Netzzeit unplausibel (%04d-%02d-%02d) -> Uhr bleibt\n", year, MM, dd);
        return false;
    }
    long days = daysFromCivil(year, MM, dd);
    long long local = (long long)days * 86400 + hh * 3600 + mm * 60 + ss;
    long long offset = (long long)tz * 15 * 60 * (sign == '-' ? -1 : 1);
    long long utc = local - offset;   // CCLK ist Ortszeit inkl. Zone -> auf UTC zurueckrechnen

    struct timeval tv; tv.tv_sec = (time_t)utc; tv.tv_usec = 0;
    if (settimeofday(&tv, nullptr) != 0) { Serial.println("[clock] settimeofday fehlgeschlagen"); return false; }
    s_lastSyncMs = millis();
    Serial.printf("[clock] Systemzeit aus dem Mobilfunknetz gesetzt: %s (Zone %c%d:%02d)\n",
                  systemClockIso().c_str(), sign == '-' ? '-' : '+', (tz * 15) / 60, (tz * 15) % 60);
    return true;
}

#else  // !WEIRDOS_FEATURE_MODEM
// ============================================================================
// Stub: ohne Modem keine Netzzeit (WEIRDOS_FEATURE_MODEM=0). Kein AT-Kanal, kein settimeofday;
// s_lastSyncMs bleibt 0 ("nie"). Die Helfer oben bleiben voll funktional.
// ============================================================================
bool modemClockSync(uint8_t ifNum, uint8_t epOut, uint8_t epIn) {
    (void)ifNum; (void)epOut; (void)epIn;
    return false;
}

#endif // WEIRDOS_FEATURE_MODEM
