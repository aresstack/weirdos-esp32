// ============================================================================
// weird_http.cpp  --  geteilte Helfer fuer beide WeirdHttp-Adapter.
// Zentral, damit Arduino- und Esp-Adapter GARANTIERT dieselbe Semantik haben.
// ============================================================================
#include "weird_http.h"

// Semikolon-getrennter Cookie-Header, exakter Namensvergleich.
//   "a=1; xcauth=abc123; b=2"  ,  name="xcauth"  ->  "abc123"
// Kein Substring-Treffer: "xxcauth=.." matcht NICHT auf "xcauth".
String weirdHttpParseCookie(const String& cookieHeader, const char* name) {
    const int n = cookieHeader.length();
    int i = 0;
    while (i < n) {
        // Fuehrende Trenner/Leerzeichen ueberspringen.
        while (i < n && (cookieHeader[i] == ' ' || cookieHeader[i] == ';')) i++;
        if (i >= n) break;

        int eq = cookieHeader.indexOf('=', i);
        if (eq < 0) break;

        int semi = cookieHeader.indexOf(';', eq);
        if (semi < 0) semi = n;

        String key = cookieHeader.substring(i, eq);
        key.trim();
        if (key == name) {
            String val = cookieHeader.substring(eq + 1, semi);
            val.trim();
            return val;
        }
        i = semi + 1;
    }
    return String();
}

static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

String weirdHttpUrlDecode(const String& s) {
    String out;
    out.reserve(s.length());
    const int n = s.length();
    for (int i = 0; i < n; ++i) {
        char c = s[i];
        if (c == '+') {
            out += ' ';
        } else if (c == '%' && i + 2 < n) {
            int hi = hexVal(s[i + 1]);
            int lo = hexVal(s[i + 2]);
            if (hi >= 0 && lo >= 0) { out += (char)((hi << 4) | lo); i += 2; }
            else out += c;   // ungueltiges %XX -> literal
        } else {
            out += c;
        }
    }
    return out;
}

const char* weirdHttpStatusText(int code) {
    switch (code) {
        case 200: return "200 OK";
        case 204: return "204 No Content";
        case 301: return "301 Moved Permanently";
        case 302: return "302 Found";
        case 303: return "303 See Other";
        case 304: return "304 Not Modified";
        case 400: return "400 Bad Request";
        case 401: return "401 Unauthorized";
        case 403: return "403 Forbidden";
        case 404: return "404 Not Found";
        case 405: return "405 Method Not Allowed";
        case 413: return "413 Payload Too Large";
        case 500: return "500 Internal Server Error";
        case 501: return "501 Not Implemented";
        case 503: return "503 Service Unavailable";
        // Unbekannter Code darf NIEMALS still zu Erfolg werden (sonst wuerde z.B. die
        // P4-Quality-Ablehnung 501 auf dem Esp-Backend zu HTTP 200) -> auf 500 fallen.
        default:  return "500 Internal Server Error";
    }
}
