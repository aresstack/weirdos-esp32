// ui_diag.cpp -- Content: Oberpunkt "Diagnose": System (Ereignisse/Heap-Map), Modem, Netzwerk, Video
#include "weirdos_features.h"   // WEIRDOS_FEATURE_WEBUI -- Seiten nur mit Weboberflaeche
#if WEIRDOS_FEATURE_WEBUI
#include "web_ui.h"
#include "wifi_caps.h"   // wifiStackShouldInit()/wifiPresent(): der Netzwerk-Scan braucht den WLAN-Stack

void renderDiag(WeirdUiWriter& w) {
    // ===== Diagnose > System: Ereignisse | Heap-Map (eine Seite, zwei Tabs). Der fruehere Tab
    //       "Funktion" (Laufzeit/Heap/PSRAM/CPU) ist Status und liegt jetzt in der Uebersicht. =====
    w.write(
        "<section id='tab-diagsys' class='tab-panel'>"
        "<h2 class='section-title'>System (Diagnose)</h2>"
        "<div class='tabs'>"
        "<button class='tab active' data-psub='ds-events'>Ereignisse</button>"
        "<button class='tab' data-psub='ds-heap'>Heap-Map</button>"
        "</div>"
        "<div class='page-sub active' id='psub-ds-events'>"
    );
    // --- Ereignisse (Ringpuffer via /events.json) ---
    w.write(uiTitleWithAction("Ereignisse", "ev-refresh", "", UI_ICON_REFRESH, "Ereignisliste aktualisieren"));
    w.write(
        "<p class='cam-hint'>Letzte Ereignisse (PPP, Modem, System) seit dem Start. Neueste zuletzt.</p>"
        "<pre id='ev-out' style='background:#1c1f23;color:#e6e6e6;padding:10px;border-radius:6px;"
        "overflow:auto;max-height:300px;font-size:13px;white-space:pre-wrap;margin-top:10px'></pre>"
        "</div>"   // /psub-ds-events
        "<div class='page-sub' id='psub-ds-heap'>"
    );
    // --- Heap-Map: harte Aggregatzahlen + Boot-Zeitleiste + bekannte grosse Verbraucher.
    //     Kein echtes Heap-Tracing (braeuchte einen Allocator-Hook) -- Ziel ist zu zeigen, WARUM
    //     hohe H.264-Aufloesungen am internen (nicht PSRAM-)Speicher haengen und WO er beim Boot
    //     hingeht (z.B. WLAN/esp_hosted-Aufbau auf dem P4, siehe LAN > WLAN).
    w.write(uiTitleWithAction("Heap-Map", "hm-refresh", "", UI_ICON_REFRESH, "Heap-Werte aktualisieren"));
    w.write(
        "<p class='cam-hint'>Der H.264-HW-Encoder braucht seinen Referenzpuffer aus ZUSAMMENHAENGENDEM "
        "internem Speicher (~1152 Byte je 16 Pixel Breite, FHD ~135 KB) -- PSRAM zaehlt dafuer nicht. "
        "Diese Seite zeigt, wie viel davon frei ist und wo es beim Boot hingeht.</p>"
        "<div class='info'>"
        "<div><span>Intern frei</span><span id='hm-intfree'>-</span></div>"
        "<div><span>Intern groesster Block</span><span id='hm-intlargest'>-</span></div>"
        "<div><span>PSRAM frei</span><span id='hm-psramfree'>-</span></div>"
        "<div><span>PSRAM groesster Block</span><span id='hm-psramlargest'>-</span></div>"
        "<div><span>H.264 aktuell reserviert</span><span id='hm-h264ref'>-</span></div>"
        "<div><span>H.264-Boot-Reserve (Guard)</span><span id='hm-guard'>-</span></div>"
        "</div>"
        "<p class='cam-hint'>Die Boot-Reserve (Guard) stellst du unter Server &rarr; Video &rarr; Stream ein "
        "(Einstellung des H.264-Encoders, keine Diagnose) -- hier nur die Anzeige.</p>"
        "<h2 class='section-title' style='margin-top:16px'>Boot-Zeitleiste (interner Heap)</h2>"
        "<p class='cam-hint'>In welcher Boot-Phase der zusammenhaengende interne Speicher schrumpft "
        "(je Zeile: frei / groesster Block direkt nach dieser Phase).</p>"
        "<div id='hm-milestones' class='info'><div><span>-</span><span>-</span></div></div>"
        "<h2 class='section-title' style='margin-top:16px'>Bekannte grosse Verbraucher</h2>"
        "<p class='cam-hint'>Keine lueckenlose Verfolgung -- nur die bekannten, benannten Posten mit "
        "ihrer Groessenordnung/Formel, als Orientierung.</p>"
        "<div class='info'>"
        "<div><span>Kamera-Framebuffer</span><span>PSRAM: S3 fbCount&times;JPEG-Schaetzung, P4 V4L2-Puffer lt. Sensor</span></div>"
        "<div><span>H.264-NAL-Ausgabepuffer</span><span>PSRAM+DMA, ~Breite&times;Hoehe&times;2 (min. 64 KB)</span></div>"
        "<div><span>H.264-Referenzpuffer (Encoder)</span><span>INTERN, zusammenhaengend, ~1152&times;ceil(Breite/16) - FHD ~135 KB</span></div>"
        "<div><span>H.264-Boot-Reserve (Guard)</span><span>INTERN, zusammenhaengend, konfigurierte Groesse -- gehalten ausser waehrend eines H.264-Streams</span></div>"
        "<div><span>PPA-Ausgabepuffer</span><span>PSRAM+DMA, YUV420 = Breite&times;Hoehe&times;1,5</span></div>"
        "<div><span>Management-HTTP-Task-Stack</span><span>INTERN (Flash/NVS/OTA-sicher), 16 KB (+20 KB TLS)</span></div>"
        "<div><span>Video-HTTP-Task-Stack</span><span>PSRAM, 8 KB</span></div>"
        "<div><span>MJPEG-/H.264-Client-Task</span><span>INTERN, 8 KB bzw. 16 KB je Client</span></div>"
        "<div><span>WLAN-/esp_hosted-Aufbau (P4)</span><span>INTERN, gemessen bis zu ~150 KB beim Netz-Init -- "
        "auf dem P4 ungenutzt, abschaltbar unter LAN &gt; WLAN</span></div>"
        "</div>"
        "</div>"       // /psub-ds-heap
        "</section>"   // /tab-diagsys
    );
    // --- Modem (Diagnose): ALLE Modem-Diagnosen auf einer Seite (Tabs). Mobilfunk/Netzliste/
    //     SIM-Karte kamen von WAN > Modem (dort bleiben nur Einstellungen); Pipeline = die Live-
    //     Durchsatz-/TX-Pipeline-Zeilen der frueheren Modem-Uebersicht; Entwickler = die bisherige
    //     Seite "USB / Modem" (AT-Konsole, USB-Info, Log, Live-AT-Dump). Tab-ID 'diagusb' bleibt
    //     (JS-Hooks/Hash-Links), nur das Menue-Label heisst jetzt "Modem".
    w.write(
        "<section id='tab-diagusb' class='tab-panel'>"
#if !WEIRDOS_FEATURE_MODEM
        // Mobilfunk nicht im Build: die mj-*-Felder bleiben leer (/modem-json, /modem-info, /modem-at sind
        // in der .ino unter WEIRDOS_FEATURE_MODEM); der USB-/IDF-Log (/modem-log) bleibt nutzbar.
        "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0'>"
        "<p><strong>Mobilfunk ist in diesem Build nicht enthalten (WEIRDOS_FEATURE_MODEM=0).</strong> Funkwerte, "
        "Netzliste, SIM und AT-Befehle gehoeren zum Baustein MODEM und bleiben hier leer; der USB-/System-Log "
        "unten funktioniert weiterhin.</p></div>"
#endif
        "<h2 class='section-title'>Modem (Diagnose)</h2>"
        "<div class='tabs'>"
        "<button class='tab active' data-psub='dm-funk'>Mobilfunk</button>"
        "<button class='tab' data-psub='dm-netz'>Netzliste</button>"
        "<button class='tab' data-psub='dm-sim'>SIM-Karte</button>"
        "<button class='tab' data-psub='dm-pipe'>Pipeline</button>"
        "<button class='tab' data-psub='dm-speed'>Durchsatz</button>"
        "<button class='tab' data-psub='dm-dev'>Entwickler</button>"
        "</div>"
        // Mobilfunk: Funkwerte der aktuellen Zelle. Gleicher Abruf wie in der Uebersicht
        // (/modem-json fuellt alle mj-* Felder auf allen Seiten in einem Rutsch).
        "<div class='page-sub active' id='psub-dm-funk'>"
    );
    w.write(uiTitleWithAction("Funkwerte (aktuelle Zelle)", "", "js-mj-refresh", UI_ICON_REFRESH,
                              "Mobilfunkdaten vom Modem abrufen (AT-Abfrage, dauert einige Sekunden)"));
    w.write(
        "<div class='info'>"
        "<div><span>Band</span><span id='mj-band'>-</span></div>"
        "<div><span>Frequenz</span><span id='mj-freq'>-</span></div>"
        "<div><span>EARFCN</span><span id='mj-earfcn'>-</span></div>"
        "<div><span>PCI</span><span id='mj-pci'>-</span></div>"
        "<div><span>Cell-ID</span><span id='mj-cellid'>-</span></div>"
        "<div><span>TAC</span><span id='mj-tac'>-</span></div>"
        "<div><span>MCC / MNC</span><span id='mj-plmn'>-</span></div>"
        "<div><span>RSRP</span><span id='mj-rsrp'>-</span></div>"
        "<div><span>RSRQ</span><span id='mj-rsrq'>-</span></div>"
        "<div><span>RSSI</span><span id='mj-rssi'>-</span></div>"
        "<div><span>SINR</span><span id='mj-sinr'>-</span></div>"
        "</div>"
        "<p class='scan-status js-mj-msg'></p>"
        "<p class='cam-hint'>Funkwerte bei aktiver Verbindung = Snapshot vom Verbindungsaufbau; "
        "Live-Abfrage nur bei getrennter Verbindung (das Modem beantwortet die Zellabfrage nicht im "
        "Datenmodus).</p>"
        "</div>"
        "<div class='page-sub' id='psub-dm-netz'>"
    );
    w.write(uiTitleWithAction("Nachbarzellen", "nb-refresh", "", UI_ICON_REFRESH,
                              "Nachbarzellen vom Modem abfragen (nur bei getrennter Verbindung)"));
    w.write(
        "<p class='cam-hint'>Nachbarzellen (LTE): EARFCN/PCI/RSRP/RSRQ/SINR. Nur bei getrennter "
        "Verbindung abfragbar. Zeigt, welche Baender/Zellen in Reichweite sind - Basis fuer Bandwahl "
        "(WAN &rarr; Modem &rarr; Frequenzen) bzw. den SINR-Scan.</p>"
        "<pre id='nb-out' style='background:#1c1f23;color:#e6e6e6;padding:10px;border-radius:6px;"
        "overflow:auto;max-height:260px;font-size:13px;white-space:pre-wrap;margin-top:10px'></pre>"
        "</div>"
        "<div class='page-sub' id='psub-dm-sim'>"
        "<div class='info'>"
        "<div><span>SIM (CPIN)</span><span id='mj-cpin'>-</span></div>"
        "<div><span>ICCID</span><span id='mj-iccid'>-</span></div>"
        "<div><span>IMSI</span><span id='mj-imsi'>-</span></div>"
        "<div><span>IMEI</span><span id='mj-imei'>-</span></div>"
        "</div>"
        "<p class='cam-hint'>Aktualisieren ueber \"Mobilfunkdaten abrufen\" (Tab Mobilfunk oder "
        "Uebersicht). Die SIM-PIN selbst stellst du unter WAN &rarr; Modem &rarr; Zugangsdaten ein.</p>"
        "</div>"
        // Pipeline: Live-Werte des USB-/PPP-Datenpfads (alle 2 s, solange diese Seite offen ist).
        "<div class='page-sub' id='psub-dm-pipe'>"
        "<p class='cam-hint'>Live-Zustand des Datenpfads ESP &harr; Modem (USB-Transfer-Pool). "
        "Aktueller Durchsatz und Spitzenwerte stehen auch in der Uebersicht (Online-Monitor); hier "
        "zusaetzlich die TX-Pipeline: in-flight-Maximum, Pool-Waits, Timeouts, Submit-Fehler.</p>"
        "<div class='info'>"
        "<div><span>Durchsatz</span><span id='ppp-rate'>-</span></div>"
        "<div><span>TX-Pipeline</span><span id='ppp-diag'>-</span></div>"
        "</div>"
        "</div>"
        // Entwickler: die bisherige Seite "USB / Modem" unveraendert.
        "<div class='page-sub' id='psub-dm-dev'>"
        "<p class='cam-hint'>Technische Entwicklungsdiagnose. USB-Schnittstellenkarte: "
        "<code>/modem-usbinfo</code>, ESP-IDF-USB-Log: <code>/modem-log</code>.</p>"
        "<label class='check-row'><input id='diag-en' type='checkbox' name='diagen' value='1'"
    );
    if (diagEnabled) w.write(" checked");
    w.write(
        ">"
        "<span><strong>Entwickler-Diagnose aktiv.</strong> AT-Konsole, USB-Info und Log. "
        "Ohne Haken sind <code>/modem-at</code>, <code>/modem-usbinfo</code> und "
        "<code>/modem-log</code> gesperrt (auch fuer Fernzugriff - der Rest der UI bleibt).</span></label>"
        "<button id='diag-save' class='cam-button' type='button' style='margin-bottom:10px'>Speichern</button>"
        "<p id='diag-msg' class='scan-status'></p>"
        "<h2 class='section-title'>AT-Konsole (USB)</h2>"
        "<p class='cam-hint'>Sendet AT-Kommandos direkt an das Modem (IF3 = AT-Port). "
        "Ideal fuer die SIM-/Netz-/APN-Sequenz: AT+CPIN?, AT+CSQ, AT+CEREG?, "
        "AT+CGDCONT?, AT+CGACT?, AT+CGPADDR.</p>"
        "<div class='ssid-row'>"
        "<select id='at-if' class='cam-select'>"
        "<option value='3'>IF3 (AT)</option>"
        "<option value='4'>IF4 (Modem)</option>"
        "<option value='2'>IF2 (DIAG)</option>"
        "</select>"
        "<div class='field-wrap'>"
        "<input id='at-cmd' type='text' autocomplete='off' autocapitalize='characters' "
        "autocorrect='off' spellcheck='false' placeholder='AT+CPIN?' value='AT'>"
        "</div>"
        "<button id='at-send' class='icon-button' type='button' title='Senden' "
        "aria-label='Senden'>&#10148;</button>"
        "</div>"
        "<pre id='at-out' style='background:#1c1f23;color:#e6e6e6;padding:10px;"
        "border-radius:6px;overflow:auto;max-height:220px;font-size:13px;"
        "white-space:pre-wrap;margin-top:10px'></pre>"
    );
    // --- Modem-Status (frueher Mobilfunk > Diagnose-Tab; Entwickler-Live-AT-Dump) ---
    w.write(uiTitleWithAction("Modem-Status (Live-Abfrage)", "mi-refresh", "", UI_ICON_REFRESH,
                              "Status ueber den AT-Port abfragen"));
    w.write(
        "<p class='cam-hint'>Live-Abfrage ueber den AT-Port (Modul, SIM, Registrierung, Zelle, Signal, IP).</p>"
        "<pre id='mi-out' style='background:#1c1f23;color:#e6e6e6;padding:10px;"
        "border-radius:6px;overflow:auto;max-height:260px;font-size:13px;"
        "white-space:pre-wrap;margin-top:10px'></pre>"
        "</div>"       // /psub-dm-dev
        // --- Durchsatz: LTE-Speedtest ueber das Modem (frueher eigener Diagnose-Punkt) fuer alle;
        //     der Einzelstream-Fenstertest (conn=1) ist reine Entwicklerdiagnose -> nur bei diagEnabled.
        "<div class='page-sub' id='psub-dm-speed'>"
        "<h2 class='section-title'>Speedtest (LTE)</h2>"
        "<p class='cam-hint'>Misst Down-/Upload ueber das Modem (Tele2, ~20-25 s), "
        "entkoppelt von Kamera/TCP. Fuer ein sauberes Ergebnis den Kamera-Stream "
        "vorher pausieren. Waehrenddessen zeigt der Tab Pipeline bzw. der "
        "Online-Monitor in der Uebersicht live mit.</p>"
        "<p class='cam-hint'>Ein einzelner TCP-Stream ist durchs kleine Sende-Fenster "
        "gedeckelt; mehrere parallele Worker saettigen den Uplink in Summe. Mehr Worker "
        "helfen Bulk-Transfers und mehreren gleichzeitigen Zuschauern - nicht einem "
        "einzelnen Stream.</p>"
        "<div class='info' style='margin-top:8px'>"
        "<div><span>Parallele Worker</span><span>"
        "<input id='st-conn' type='number' min='1' max='16' value='6' "
        "style='width:64px;text-align:right'></span></div>"
        "</div>"
        "<label class='check-row'>"
        "<input id='st-auto' type='checkbox'>"
        "<span>Auto: optimale Worker-Zahl selbst ermitteln (Ramp 1..16, ~60-90 s)</span>"
        "</label>"
        "<button id='st-run' class='cam-button' type='button'>Speedtest starten</button>"
        "<div class='info' style='margin-top:8px'>"
        "<div><span>Download</span><span id='st-down'>-</span></div>"
        "<div><span>Upload</span><span id='st-up'>-</span></div>"
        "<div><span>Aktive Worker</span><span id='st-active'>-</span></div>"
        "</div>"
        "<p id='st-msg' class='scan-status'></p>"
    );
    if (diagEnabled) w.write(
        "<h2 class='section-title'>Fenster-Test (Entwickler)</h2>"
        "<p class='cam-hint'>Beweis fuers TCP-Fenster: der <b>Einzelstream</b> (genau 1 Verbindung). "
        "Stock-liblwip.a deckelt ihn bei ~0,6 Mbit/s; mit dem 32-KB-Fenster steigt er deutlich, "
        "sofern der LTE-Uplink es hergibt. Kamera-Stream vorher pausieren.</p>"
        "<button id='sp1-run' class='cam-button' type='button'>Einzelstream messen (1 Verbindung)</button>"
        "<div class='info' style='margin-top:8px'>"
        "<div><span>Download</span><span id='sp1-down'>-</span></div>"
        "<div><span>Upload</span><span id='sp1-up'>-</span></div>"
        "</div>"
        "<p id='sp1-msg' class='scan-status'></p>"
    );
    w.write(
        "</div>"       // /psub-dm-speed
        "</section>"   // /tab-diagusb
    );
    // --- Netzwerk: Netzwerk-Scan (Tabs Rechner/Funk: Ping-Sweep/Port-Scan bzw. Passiv-Monitor/Kanal-Scans), Body in
    //     ui_netscan.cpp. Alle Werkzeuge brauchen den WLAN-Stack (Subnetz der STA, Promiscuous-
    //     Modus, Kanalwechsel). Ist er aus (P4 in Auto, oder LAN > WLAN = "Aus"), wird ehrlich
    //     ausgegraut + der Grund genannt -- statisch (Stand dieses Boots), keine Live-Vorschau.
    {
        bool wifiOn = wifiStackShouldInit();
        // Tabs VOR dem Ausgrau-Wrapper, damit sie auch bei WLAN=aus klickbar bleiben (die Inhalte
        // selbst sind dann ausgegraut).
        w.write(
            "<section id='tab-diagnet' class='tab-panel'>"
            "<h2 class='section-title'>Netzwerk (Diagnose)</h2>"
            // Netzzonen 0.1: Registry-Sicht (Interface / Attachment / erreichbare Prefixe getrennt), read-only.
            // Automatisch vergebene Werte MIT Herkunft -- nichts davon wird hier konfiguriert.
            "<details class='wg-adv' id='zn-details'><summary>Netzanbindungen und erreichbare Netze (Registry, automatisch)</summary>"
            "<p class='hint'>Drei Ebenen: Interface (netif), Anbindung (stabile Adresse des Geraets, Herkunft) und darueber erreichbare "
            "Netze (on-link, ausgehandelter IPsec-Selektor TSr, WireGuard-AllowedIPs, Standardroute). Die Tunnel-Adresse eines "
            "IPsec-Clients ist NICHT das Zielnetz. Nur Anzeige -- Zonen und Verbindungen folgen (Netzzonen Phase 1).</p>"
            "<table class='info' id='zn-att'><thead><tr><th>Anbindung</th><th>Interface</th><th>Art</th><th>Status</th><th>Adresse</th>"
            "<th>Herkunft</th><th>MTU</th><th>akzeptiert Absender</th><th>Rueckweg zu</th></tr></thead><tbody></tbody></table>"
            "<table class='info' id='zn-pfx'><thead><tr><th>Anbindung</th><th>erreichbares Netz</th><th>Herkunft</th></tr></thead><tbody></tbody></table>"
            "<p class='hint' id='zn-hooks'></p>"
            "<table class='info' id='zn-rt'><thead><tr><th>Zielroute</th><th>Interface</th><th>Herkunft</th></tr></thead><tbody></tbody></table>"
            "<table class='info' id='zn-cnt'><thead><tr><th>Eingang</th><th>Ausgang</th><th>weitergeleitet</th><th>verworfen (Filter)</th></tr></thead><tbody></tbody></table>"
            "<script>(function(){function esc(s){return String(s==null?'':s).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}"
            "function load(){fetch('/net-interfaces.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();}).then(function(d){"
            "var a=document.querySelector('#zn-att tbody'),p=document.querySelector('#zn-pfx tbody');if(!a||!p)return;var h='';"
            "(d.attachments||[]).forEach(function(x){h+='<tr><td>'+esc(x.id)+'</td><td>'+esc(x.iface)+'</td><td>'+esc(x.kind)+'</td><td>'+(x.up?'aktiv':'aus')+'</td><td>'+"
            "(x.local?esc(x.local)+'/'+x.prefix:'-')+'</td><td>'+esc(x.addrSource)+'</td><td>'+(x.mtu||'-')+'</td><td>'+(x.acceptSrcKnown?esc(x.acceptSrc):'unbekannt')+'</td><td>'+"
            "(x.returnToKnown?esc(x.returnTo):'unbekannt')+'</td></tr>';});a.innerHTML=h;h='';"
            "(d.prefixes||[]).forEach(function(x){h+='<tr><td>'+esc(x.attachment)+'</td><td>'+esc(x.net)+'/'+x.prefix+'</td><td>'+esc(x.source)+(x.routingEligible===false?' &ndash; <b>keine Zonenroute:</b> '+esc(x.reason):'')+'</td></tr>';});p.innerHTML=h;"
            "var z=d.zones||{},hk=document.getElementById('zn-hooks'),rt=document.querySelector('#zn-rt tbody'),cn=document.querySelector('#zn-cnt tbody');"
            "if(hk){var hh=z.hooks||{};hk.innerHTML='lwIP-Hooks (eigenes liblwip.a): Route-Hook '+(hh.route?'vorhanden':'<b>fehlt</b> (Stock, Routen wirkungslos)')+', Forward-Hook '+(hh.forward?'vorhanden':'<b>fehlt</b> (Stock, Filter/Z&auml;hler wirkungslos)')+' &middot; Routentreffer '+(hh.routeHits||0)+', kein Treffer '+(hh.routeMiss||0);}"
            "if(rt){h='';(z.routes||[]).forEach(function(x){h+='<tr><td>'+esc(x.net)+'</td><td>'+esc(x.iface)+' ('+esc(x.netif)+')</td><td>'+esc(x.source)+'</td></tr>';});rt.innerHTML=h||'<tr><td colspan=3>keine Zielrouten</td></tr>';}"
            "if(cn){h='';(z.counters||[]).forEach(function(x){h+='<tr><td>'+esc(x.in)+'</td><td>'+esc(x.out)+'</td><td>'+x.fwd+'</td><td>'+x.dropFilter+'</td></tr>';});cn.innerHTML=h||'<tr><td colspan=4>noch kein weitergeleitetes Paket</td></tr>';}"
            "}).catch(function(){});}"
            "var el=document.getElementById('zn-details');if(el){el.addEventListener('toggle',function(){if(el.open)load();});}setInterval(function(){if(el&&el.open)load();},10000);})();</script>"
            "</details>"
            "<div class='tabs'>"
            "<button class='tab active' data-psub='nx-hosts'>Netz</button>"
            "<button class='tab' data-psub='nx-funk'>Funk (WLAN)</button>"
            "</div>");
        // D3: die allgemeinen L3/L4-Werkzeuge (Sweep, Ping, Portscan, Resolve) brauchen keinen WLAN-Stack
        // und bleiben bedienbar; nur der Funk-Tab wird bei WLAN=aus ausgegraut (in ui_netscan.cpp).
        renderNetScanBody(w, wifiOn, wifiPresent());
        w.write("</section>");   // (Interface-Registry liegt als Status in der Uebersicht)
    }
    // --- Video: Livebild zur Funktionskontrolle (frueher Tab "Diagnose" unter Server > Video).
    //     Block in ui_video.cpp (renderVideoLive); der Stream laeuft nur bei sichtbarer Seite.
    w.write(
        "<section id='tab-diagvideo' class='tab-panel'>"
        "<h2 class='section-title'>Video (Diagnose)</h2>");
    renderVideoLive(w);
    w.write("</section>");
}
#else
// Weboberflaeche nicht im Build (WEIRDOS_FEATURE_WEBUI=0): kein Seiteninhalt, nur die Renderer-Signaturen,
// damit web_ui.cpp (Seitentabelle) und Nachbarseiten unveraendert linken. Der HTTP-Server (Baustein HTTP)
// beantwortet dann PIN-Gate + JSON-API; sendAppPage() nennt den Grund.
#include "web_ui.h"
void renderDiag(WeirdUiWriter& w) { (void)w; }
#endif // WEIRDOS_FEATURE_WEBUI
