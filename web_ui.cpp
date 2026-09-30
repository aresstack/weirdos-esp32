// ============================================================================
// web_ui.cpp  --  View-Schicht: Skin / Seitengeruest der Weboberflaeche
//
// Haelt nur noch das Geruest (sendAppPage: Kopf -> Style -> Menue -> Content-
// Aufrufe -> Script -> Abschluss), das PIN-Gate und die Format-Helfer
// (escapeHtml/escapeJson/WeirdUiWriter/createStatusBlock). Ausgelagert:
//   web_ui_assets.cpp  - statische Assets (PAGE_STYLE/APP_STYLE/APP_SCRIPT)
//   web_ui_menu.cpp    - Menueaufbau (renderMenu)
//   ui_*.cpp           - Content je Menue-Oberpunkt (renderOverview/... )
// ============================================================================
#include "web_ui.h"
#include "weird_http.h"   // WeirdHttpResponse-Definition fuer die WeirdUiWriter-Methoden
// Baustein WIFI (WEIRDOS_FEATURE_WIFI aus weirdos_features.h, via web_ui.h): WLAN-Funk nur damit im Bild.
#if WEIRDOS_FEATURE_WIFI
#include <WiFi.h>        // WiFi.SSID()/localIP() in createStatusBlock
#endif

// ---- WeirdUiWriter: duenne Bruecke Renderer -> WeirdHttpResponse::write() ----
// write(const char*) haelt Literale/PROGMEM ohne String-Kopie (Flash ist auf dem
// ESP32 direkt lesbar); leere Writes verwirft der Adapter (kein Chunk-Terminator,
// das macht bewusst nur res.end()).
void WeirdUiWriter::write(const char* s)        { if (s) res_.write(s, strlen(s)); }
void WeirdUiWriter::write(const String& s)      { res_.write(s.c_str(), s.length()); }
void WeirdUiWriter::writeProgmem(const char* s) { if (s) res_.write(s, strlen(s)); }

// No-Cache-Header fuer die HTML-Seiten (backend-neutral, VOR beginChunked()).
static void uiNoCache(WeirdHttpResponse& res) {
    res.header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    res.header("Pragma", "no-cache");
    res.header("Expires", "0");
}

// RENDERT nur die PIN-Gate. Die Auth-/WAN-Entscheidung faellt VORHER im Handler
// (Root/Captive/Probe) -- hier keinerlei Cookie-/Auth-Pruefung. Reihenfolge streng:
// Header -> beginChunked (Status+Content-Type) -> Body-Chunks -> end().
void sendPinGate(WeirdHttpResponse& res, bool wrongPin) {
    uiNoCache(res);
    if (!res.beginChunked(200, "text/html; charset=utf-8")) return;
    WeirdUiWriter w(res);

    w.write(
        "<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Anmelden</title>"
    );
    w.writeProgmem(PAGE_STYLE);

    w.write(
        "</head><body><main>"
        "<h1>WeirdOS - Anmelden</h1>"
    );

    if (wrongPin) {
        w.write(
            "<p class='cam-hint' style='color:#c8362b'>Falsche PIN.</p>"
        );
    }

    bool stillDefault = (devicePin == PIN_DEFAULT);

    w.write(
        "<form method='POST' action='/pin-login'>"
        "<label for='pin'>PIN</label>"
        "<div class='field-wrap'>"
        "<input id='pin' class='has-inset' name='pin' type='password' "
        "inputmode='numeric' autocomplete='off' value='"
    );

    if (stillDefault) {
        w.write(PIN_DEFAULT);
    }

    w.write(
        "'>"
        "<button id='eye-button' class='inset-button' type='button' "
        "aria-pressed='false' title='PIN anzeigen' "
        "aria-label='PIN anzeigen'>&#128065;</button>"
        "</div>"
    );

    if (stillDefault) {
        w.write(
            "<p class='cam-hint'>Werks-PIN <strong>0000</strong> (vorausgefuellt). Nach der Anmeldung "
            "musst du zuerst eine eigene PIN setzen -- erst dann ist die Oberflaeche nutzbar. "
            "Grund: das Geraet ist ueber Mobilfunk mit oeffentlicher IPv4 erreichbar.</p>"
        );
    }

    w.write(
        "<button class='connect-button' type='submit'>Anmelden</button>"
        "</form>"
        "<script>(function(){"
        "var p=document.getElementById('pin');"
        "var e=document.getElementById('eye-button');"
        "e.addEventListener('click',function(){"
        "var sh=p.type==='password';p.type=sh?'text':'password';"
        "e.classList.toggle('active',sh);p.focus();});"
        "})();</script>"
        "</main></body></html>"
    );
    res.end();
}



// Erst-Einrichtung: Werks-PIN aktiv -> nur PIN setzen. Kein Menue, keine App (requireSession blockt
// bis zur Aenderung alles ausser /pin-change und /logout). Leere PIN (= Schutz aus) ist hier
// NICHT erlaubt, solange die Oberflaeche ueber WAN erreichbar ist -- entscheidet handlePinChange.
void sendPinSetupGate(WeirdHttpResponse& res, const String& error) {
    uiNoCache(res);
    if (!res.beginChunked(200, "text/html; charset=utf-8")) return;
    WeirdUiWriter w(res);
    w.write(
        "<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>PIN festlegen</title>"
    );
    w.writeProgmem(PAGE_STYLE);
    w.write(
        "</head><body><main>"
        "<h1>WeirdOS - Eigene PIN festlegen</h1>"
        "<p class='cam-hint'>Die Werks-PIN <strong>0000</strong> ist noch aktiv. Dieses Geraet ist ueber "
        "Mobilfunk mit <strong>oeffentlicher IPv4</strong> erreichbar -- mit bekannter PIN koennte es jeder "
        "aus dem Internet verwalten. Deshalb geht es erst weiter, wenn eine eigene PIN gesetzt ist "
        "(mindestens 4 Zeichen, nicht 0000).</p>"
    );
    if (error.length()) {
        w.write("<p class='cam-hint' style='color:#c8362b'>");
        w.write(escapeHtml(error));
        w.write("</p>");
    }
    w.write(
        "<form method='POST' action='/pin-change' onsubmit='return chk()'>"
        "<label for='newpin'>Neue PIN</label>"
        "<input id='newpin' name='newpin' type='password' inputmode='numeric' autocomplete='new-password'>"
        "<label for='newpin2'>Neue PIN wiederholen</label>"
        "<input id='newpin2' type='password' inputmode='numeric' autocomplete='new-password'>"
        "<p id='pinmsg' class='cam-hint' style='color:#c8362b'></p>"
        "<button class='connect-button' type='submit'>PIN setzen und weiter</button>"
        "</form>"
        "<form method='POST' action='/logout' style='margin-top:12px'>"
        "<button class='cam-button' type='submit'>Abmelden</button>"
        "</form>"
        "<script>function chk(){var a=document.getElementById('newpin').value,b=document.getElementById('newpin2').value,"
        "m=document.getElementById('pinmsg');if(a.length<4){m.textContent='Mindestens 4 Zeichen.';return false;}"
        "if(a==='0000'){m.textContent='0000 ist die Werks-PIN.';return false;}"
        "if(a!==b){m.textContent='Die beiden Eingaben stimmen nicht ueberein.';return false;}return true;}</script>"
        "</main></body></html>"
    );
    res.end();
}

#if WEIRDOS_FEATURE_WEBUI   // Seitengeruest + Assets (Seitentabelle referenziert alle Renderer)
String createStatusBlock() {
    String html;
    html.reserve(512);

    html += "<div class='info'>";

    html += "<div><span>Verbindung</span><span>";
    html += wifiStatusText();   // ohne Baustein WIFI: "nicht im Build enthalten"
    html += "</span></div>";

#if WEIRDOS_FEATURE_WIFI
    if (wifiPortalConnected()) {
        html += "<div><span>Netzwerk</span><span>";
        html += escapeHtml(WiFi.SSID());
        html += "</span></div>";

        html += "<div><span>Adresse im Netzwerk</span><span>http://";
        html += WiFi.localIP().toString();
        html += "</span></div>";

        html += "<div><span>oder</span><span>http://";
        html += deviceHostname;
        html += ".local</span></div>";
    }
#endif   // ohne WLAN-Baustein nie verbunden -> kein SSID/IP-Block

    html += "<div><span>Setup-AP</span><span>";
    html += setupApActive ? "aktiv" : "aus";
    html += "</span></div>";

    html += "</div>";
    return html;
}


// Die Tab-Oberflaeche: Video, Netzwerk, Kamera, Sicherheit, System.


// ----------------------------------------------------------------------------
// Skin: baut das Seitengeruest und rendert NUR die angeforderte Seite (?p=tab[/psub]).
// Frueher wurden ALLE Sektionen in einem Request gerendert (25 Sektionen + 110 KB Script inline):
// Peak-Heap im Render und Sockets/Traffic ueber LTE -> Haenger nach dem Login. Jetzt: Shell +
// Menue + eine Seite; CSS/JS liegen als gecachte Dateien /app.css und /app.js (URL mit Asset-Hash).
// Ein Renderer kann mehrere Menue-Tabs liefern (z.B. renderSystem: general/update/energy/...);
// das Menue schaltet dann im DOM um, sonst laedt es die Seite vom Server.
// ----------------------------------------------------------------------------
struct UiPage { const char* tab; void (*render)(WeirdUiWriter&); uint8_t stage; };
static const UiPage kUiPages[] = {
    {"overview",   renderOverview,    3},
    {"portal",     renderSetupPortal, 4},
    {"platform",   renderPlatform,    19},
    {"netmode",    renderNetmode,     5},
    {"mobilfunk",  renderInternet,    7},
    {"freigaben",  renderInternet,    7},
    {"dienste",    renderDienste,     8},
    {"vpn-srv",    renderVpnServer,   9},
    {"vpn-cli",    renderVpnClient,   10},
    {"lanallg",    renderLanGeneral,  11},
    {"wlan",       renderWlan,        12},
    {"zones",      renderZones,       20},
    {"bluetooth",  renderBluetooth,   13},
    {"video",      renderVideoServer, 14},
    {"peripherie", renderPeripherie,  15},
    {"diagsys",    renderDiag,        16},
    {"diagusb",    renderDiag,        16},
    {"diagnet",    renderDiag,        16},
    {"diagvideo",  renderDiag,        16},
    {"general",    renderSystem,      17},
    {"update",     renderSystem,      17},
    {"energy",     renderSystem,      17},
    {"syssec",     renderSystem,      17},
    {"backup",     renderSystem,      17},
};

static const UiPage* uiPageFor(const String& page) {
    int s = page.indexOf('/');
    String tab = s >= 0 ? page.substring(0, s) : page;
    // Alte Menuepunkte (Lesezeichen) -- identisch zur Alias-Tabelle im Script.
    struct { const char* from; const char* to; } alias[] = {
        {"zugang", "mobilfunk"}, {"wanport", "mobilfunk"}, {"diagfunc", "diagsys"}, {"events", "diagsys"},
        {"diagheap", "diagsys"}, {"diagspeed", "diagusb"}, {"diagwlan", "diagnet"} };
    for (auto& a : alias) if (tab == a.from) { tab = a.to; break; }
    for (auto& p : kUiPages) if (tab == p.tab) return &p;
    return &kUiPages[0];
}

// Asset-Version = FNV-1a ueber CSS+JS (einmal je Boot). Aendert sich mit jedem Build, in dem sich
// die Assets aendern -> Browser holt sie neu; sonst kommen sie aus dem Cache (kein LTE-Traffic).
const char* uiAssetVersion() {
    static char v[9] = {0};
    if (!v[0]) {
        uint32_t h = 2166136261u;
        const char* parts[] = { PAGE_STYLE, APP_STYLE, APP_SCRIPT };
        for (const char* s : parts) for (; *s; s++) { h ^= (uint8_t)*s; h *= 16777619u; }
        snprintf(v, sizeof v, "%08x", (unsigned)h);
    }
    return v;
}

// Die Literale tragen fuer die Inline-Nutzung (PIN-Gate, Setup-Seiten) ihre <style>/<script>-Tags;
// als Datei werden genau diese Huellen abgestreift.
static void writeAssetBody(WeirdHttpResponse& res, const char* s, const char* open, const char* close) {
    size_t n = strlen(s), no = strlen(open), nc = strlen(close);
    if (n > no + nc && !strncmp(s, open, no) && !strcmp(s + n - nc, close)) res.write(s + no, n - no - nc);
    else res.write(s, n);
}
void sendAppCss(WeirdHttpResponse& res) {
    res.header("Cache-Control", "public, max-age=31536000, immutable");   // URL traegt ?v=<Hash>
    if (!res.beginChunked(200, "text/css; charset=utf-8")) return;
    writeAssetBody(res, PAGE_STYLE, "<style>", "</style>");
    res.write("\n", 1);
    writeAssetBody(res, APP_STYLE, "<style>", "</style>");
    res.end();
}
void sendAppJs(WeirdHttpResponse& res) {
    res.header("Cache-Control", "public, max-age=31536000, immutable");
    if (!res.beginChunked(200, "application/javascript; charset=utf-8")) return;
    writeAssetBody(res, APP_SCRIPT, "<script>", "</script>");
    res.end();
}

void sendAppPage(WeirdHttpResponse& res, const String& page) {
    const UiPage* pg = uiPageFor(page);
    uiNoCache(res);
    if (!res.beginChunked(200, "text/html; charset=utf-8")) return;
    WeirdUiWriter w(res);

    w.write(
        "<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>WeirdOS</title>"
        "<link rel='stylesheet' href='/app.css?v=");
    w.write(uiAssetVersion());
    w.write("'>");

    // In-Band-Crash-Diagnose: vor jedem Renderer die Stufe merken (RTC_NOINIT). Bricht der
    // Render mit Panic ab, zeigt /sysinfo.json (httpstage) nach dem Reboot exakt den Renderer.
    w.write("</head><body><div class='shell'>");
    g_httpRenderStage = 2;  renderMenu(w);
    w.write(
        "<main class='content'>"
        "<div id='ctxbar' class='page-context'></div>"
    );
    // Gelbe Box "Neustart erforderlich" (Einstellungen, die erst beim Boot wirken) -- auf JEDER Seite, mit Knopf.
    // Serverseitig im Ist-Zustand gerendert; danach pollt ein kleines Script /restart-required.json (auch nach
    // fetch-basierten Speichern ohne Seitenneuladen sichtbar). Knopf -> POST /restart (Rueckfrage im Browser).
    w.write("<div id='restart-banner' class='restart-banner'");
    if (!g_restartReasons.length()) w.write(" style='display:none'");
    w.write("><div><b>Neustart erforderlich.</b> Geaendert: <span id='restart-why'>");
    w.write(escapeHtml(g_restartReasons));
    w.write("</span> &ndash; die Einstellung wirkt erst nach dem Neustart.</div>"
            "<button type='button' id='restart-now' class='cam-button'>Jetzt neu starten</button></div>"
            "<script>(function(){var b=document.getElementById('restart-banner'),w=document.getElementById('restart-why'),k=document.getElementById('restart-now');if(!b)return;"
            "function poll(){fetch('/restart-required.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();}).then(function(d){if(!d)return;b.style.display=d.required?'':'none';if(w)w.textContent=d.reasons||'';}).catch(function(){});}"
            "if(k)k.addEventListener('click',function(){if(!confirm('Geraet jetzt neu starten?'))return;k.disabled=true;k.textContent='Neustart ...';"
            "fetch('/restart',{method:'POST',cache:'no-store'}).then(function(){setTimeout(function(){location.href='/';},12000);}).catch(function(){k.disabled=false;k.textContent='Jetzt neu starten';});});"
            "setInterval(poll,15000);})();</script>");

    // Genau EINE Seite (der Renderer des angeforderten Tabs).
    g_httpRenderStage = pg->stage;  pg->render(w);

    g_httpRenderStage = 18;
    // Fallback ohne/vor app.js: die gelieferte Section sofort sichtbar machen (sonst leere Seite bei Ladefehler).
    w.write("</main></div><script>(function(){var s=document.querySelector('.tab-panel');if(s)s.classList.add('active');})();</script>"
            "<script src='/app.js?v=");
    w.write(uiAssetVersion());
    w.write("'></script></body></html>");
    res.end();
    g_httpRenderStage = 99;   // 99 = App-Seite komplett gesendet (kein Crash im Render)
}
#else
// Weboberflaeche nicht im Build (WEIRDOS_FEATURE_WEBUI=0): keine Seitentabelle, keine Renderer-Aufrufe,
// keine App-Assets. PIN-Gate, Setup-Gate und die Format-Helfer bleiben (JSON-API + Anmeldung laufen
// weiter); die Startseite nennt den Grund.
String createStatusBlock() { return String(); }
const char* uiAssetVersion() { return "0"; }
void sendAppCss(WeirdHttpResponse& res) { if (res.beginChunked(200, "text/css; charset=utf-8")) res.end(); }
void sendAppJs(WeirdHttpResponse& res)  { if (res.beginChunked(200, "application/javascript; charset=utf-8")) res.end(); }
void sendAppPage(WeirdHttpResponse& res, const String& page) {
    (void)page;
    uiNoCache(res);
    if (!res.beginChunked(200, "text/html; charset=utf-8")) return;
    WeirdUiWriter w(res);
    w.write("<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'><title>WeirdOS</title>");
    w.writeProgmem(PAGE_STYLE);
    w.write("</head><body><div class='shell'><main class='content'>"
            "<h2 class='section-title'>WeirdOS</h2>"
            "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0'>"
            "<p><strong>Die Weboberflaeche ist in diesem Build nicht enthalten (WEIRDOS_FEATURE_WEBUI=0).</strong> "
            "Der HTTP-Server laeuft mit PIN-Anmeldung und JSON-Schnittstelle (z. B. <code>/status.json</code>, "
            "<code>/sysinfo.json</code>, <code>/capture</code>); eingerichtet wird ueber die serielle Konsole oder "
            "mit einem Build, der den Baustein WEBUI enthaelt.</p></div>"
            "</main></div></body></html>");
    res.end();
}
#endif // WEIRDOS_FEATURE_WEBUI

void writeSecretField(WeirdUiWriter& w, const char* id, const char* name, const String& label,
                      const char* tip, bool isSet, size_t len, const char* unsetHint) {
    String ph;
    if (isSet) { size_t n = len > 48 ? 48 : len; for (size_t i = 0; i < n; i++) ph += "\xE2\x80\xA2"; }   // U+2022 je Zeichen
    else ph = (unsetHint && unsetHint[0]) ? unsetHint : "nicht gesetzt";
    String h = String("<label for='") + id + "'";
    if (tip && tip[0]) h += String(" title='") + tip + "'";
    h += String(">") + label + "</label>"
         "<div class='field-wrap secret-wrap'>"
         "<input id='" + id + "' class='has-inset secret-input' name='" + name + "' type='password' autocomplete='off' "
         "autocapitalize='none' autocorrect='off' spellcheck='false' value='' placeholder='" + escapeHtml(ph) + "' "
         "data-set='" + (isSet ? "1" : "0") + "' data-len='" + String((unsigned)len) + "'>"
         "<button class='inset-button secret-eye' type='button' data-for='" + id + "' aria-pressed='false' "
         "title='Eingabe anzeigen (der gespeicherte Wert wird nie uebertragen)' aria-label='Eingabe anzeigen'>&#128065;</button>"
         "</div>"
         "<div class='hint secret-hint' data-for='" + id + "'>";
    h += isSet ? (String("gesetzt (") + String((unsigned)len) + " Zeichen) &ndash; leer lassen zum Behalten, neue Eingabe ersetzt")
               : String("nicht gesetzt");
    h += "</div>";
    w.write(h);
}

String escapeHtml(const String& value) {
    String escaped = value;

    escaped.replace("&", "&amp;");
    escaped.replace("\"", "&quot;");
    escaped.replace("'", "&#39;");
    escaped.replace("<", "&lt;");
    escaped.replace(">", "&gt;");

    return escaped;
}

// Einheitlicher "Baustein fehlt"-Hinweis (siehe web_ui.h): dieselbe gelbe Box auf jeder Seite,
// deren Baustein nicht im Build ist -- statt schwarzer Player/leerer Tabellen ohne Erklaerung.
String uiBausteinFehlt(const char* was, const char* makro, const char* weiter) {
    String h;
    h.reserve(260);
    h += "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;"
         "border-radius:6px;margin:8px 0'><p><strong>";
    h += was;
    h += " ist in diesem Build nicht enthalten (";
    h += makro;
    h += ").</strong>";
    if (weiter && weiter[0]) { h += ' '; h += weiter; }
    h += "</p></div>";
    return h;
}

// Einheitliches Muster fuer "Titel + Aktions-Icon rechts" (siehe web_ui.h). Der Button hat eine
// zusaetzlich mitgegebene id/Klasse, damit das bestehende JS (getElementById/querySelectorAll)
// unveraendert bindet. CSS: .section-title.has-action / .icon-action in web_ui_assets.cpp.
String uiTitleWithAction(const char* title, const char* id, const char* extraCls, const char* icon, const char* tooltip) {
    String h;
    h.reserve(220);
    h += "<h2 class='section-title has-action'><span>";
    h += title;
    h += "</span><button type='button' class='icon-action";
    if (extraCls && extraCls[0]) { h += ' '; h += extraCls; }
    h += "'";
    if (id && id[0]) { h += " id='"; h += id; h += "'"; }
    h += " title='";
    h += tooltip;
    h += "' aria-label='";
    h += tooltip;
    h += "'>";
    h += icon;
    h += "</button></h2>";
    return h;
}


String escapeJson(const String& value) {
    String escaped = value;

    escaped.replace("\\", "\\\\");
    escaped.replace("\"", "\\\"");
    escaped.replace("\n", "\\n");
    escaped.replace("\r", "\\r");
    escaped.replace("\t", "\\t");

    return escaped;
}


