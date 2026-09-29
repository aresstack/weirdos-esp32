// ui_video.cpp -- Content: Server > "Video-Server" (frueher "Kamera") + Diagnose > Video (Livebild).
//   Server > Video: Tabs Stream (zuerst) | Bild -- nur EINSTELLUNGEN. Stream-Typ (HTTP-MJPEG | RTSP)
//   schaltet dynamisch die passenden Einstellungen (wie eine Radiogruppe). RTSP-Server-Runtime
//   folgt -> hier ehrlicher Config-Stub, KEIN stiller JPEG-Fallback. Bildsensor-Parameter bleiben
//   geraetespezifisch (camcfg).
//   Diagnose > Video: das Livebild (MJPEG/Einzelbilder/H.264 mit Codec-/Aufloesungswahl) --
//   renderVideoLive(), eingehaengt in ui_diag.cpp. Der Stream laeuft nur, solange diese Seite
//   sichtbar ist (videoVisible() in web_ui_assets.cpp).
#include "web_ui.h"
#include "h264_guard.h"   // Boot-Reserve (Guard): konfigurierte/gehaltene Groesse fuer den Stream-Tab
#include "camera_manager.h" // cameraManager.currentMode(): aktueller Sensor-Modus (PPA skaliert nur herunter)

// Livebild-Block (Diagnose > Video). Bleibt hier, damit alles Video-Wissen (streamPort/-Path/-Key,
// Stream-Modi, Codec-/Groessen-Dropdowns) in EINER Datei liegt; ui_diag.cpp setzt nur die Section.
void renderVideoLive(WeirdUiWriter& w) {
    w.write(
        "<div id='live-wrap' class='live-wrap' title='Klick: Vollbild'>"
        "<img id='live' class='live-frame' alt='Livebild' data-streamport='"
    );
    w.write(String(streamPort));
    w.write("' data-streampath='");
    w.write(escapeHtml(streamPath));
    w.write("' data-streamkey='");
    w.write(escapeHtml(streamKey));
    w.write(
        "'>"
        // H.264 wird NICHT als <img> abgespielt, sondern per Media Source Extensions in ein
        // <video> (fMP4 von /video.mp4). Standardmaessig versteckt; die Codec-Auswahl schaltet um.
        "<video id='live-video' class='live-frame' style='display:none' autoplay muted playsinline></video>"
        "</div>"
        "<div class='cam-bar'>"
        // Reihenfolge: Format (Codec) links, dann Modus (Stream/Einzelbilder), dann Aufloesung.
        // Codecs kommen dynamisch aus GET /dev/camera0 (codecs[]): nur HW-unterstuetzte sind
        // waehlbar, nicht verfuegbare erscheinen ausgegraut (disabled). Fuellt die JS.
        "<select id='codec-select' class='cam-select' aria-label='Codec' title='Video-Codec'></select>"
        "<select id='mode-select' class='cam-select' aria-label='Modus'>"
    );
    // HTTP-Stream aus -> nicht die kaputte MJPEG-URL laden, sondern Einzelbilder als Default.
    if (streamEnabled) {
        w.write(
            "<option value='stream' selected>Stream (MJPEG)</option>"
            "<option value='snap'>Einzelbilder</option>");
    } else {
        w.write(
            "<option value='stream' disabled>Stream (MJPEG) - HTTP-Stream aus</option>"
            "<option value='snap' selected>Einzelbilder</option>");
    }
    w.write(
        "</select>"
        // Aufloesungen kommen dynamisch aus GET /dev/camera0 (Backend-Capabilities,
        // nach w×h dedupliziert) -- KEINE feste FRAME_SIZE_OPTIONS-Tabelle, kein Boardwissen.
        "<select id='size-select' class='cam-select' aria-label='Aufloesung'></select>"
        "<span id='cam-status' class='cam-status'>Verbinde ...</span>"
        "<button id='pause-button' class='cam-button' type='button'>Pause</button>"
        "</div>"
        "<p class='cam-hint'>Live-Vorschau zur Funktionskontrolle. Ist der HTTP-Stream deaktiviert, "
        "nutze <strong>Einzelbilder</strong> -- der MJPEG-Modus braucht den aktiven HTTP-Stream. "
        "Einstellungen (Stream-Typ, FPS, Qualitaet, Sensor) unter Server &rarr; Video.</p>"
    );
}

void renderVideoServer(WeirdUiWriter& w) {
    w.write(
        "<section id='tab-video' class='tab-panel'>"
        "<h2 class='section-title'>Video-Server</h2>"
        "<div class='tabs'>"
        "<button class='tab active' data-psub='video-stream'>Stream</button>"
        "<button class='tab' data-psub='video-bild'>Bild</button>"
        "</div>"

        "<form class='camcfg' method='POST' action='/video-config'>"

        // ===== Stream (erster Tab): Transport-Auswahl + dynamische Einstellungen =====
        "<div class='page-sub active' id='psub-video-stream'>"
        "<label for='stream-type'>Stream-Transport</label>"
        "<select id='stream-type' name='streamtype' class='cam-select cfg-select'>"
        "<option value='off'"
    );
    if (streamType == "off") w.write(" selected");
    w.write(">Aus (kein Videoserver)</option><option value='http'");
    if (streamType == "http") w.write(" selected");
    w.write(">HTTP (MJPEG + H.264-fMP4 fuer den Browser, Port 81)</option><option value='rtsp'");
    if (streamType == "rtsp") w.write(" selected");
    w.write(
        ">RTSP (MJPEG + H.264 fuer VLC/ffmpeg/NVR, Port 554)</option></select>"
        "<p class='cam-hint'>Genau EIN Transport laeuft (Socket-Budget). Einzelbilder gibt es unabhaengig davon immer ueber <code>/capture</code> auf der Weboberflaeche. Wirkt nach Neustart.</p>"

        // ---- HTTP-MJPEG-Einstellungen ----
        "<div data-streamtype='http'>"
        "<label class='check-row'><input type='checkbox' name='multi' value='1'"
    );
    if (multiStreamEnabled) w.write(" checked");
    w.write(
        "><span>Mehrere gleichzeitige Zuschauer erlauben (bis zu 3)</span></label>"
        "<p class='cam-hint'>Roh-MJPEG auf eigenem Port. Ein Schluessel schuetzt den Stream "
        "(<code>?key=...</code>). Port/Pfad wirken nach Neustart.</p>"
        "<label for='streamport'>Stream-Port</label>"
        "<input id='streamport' name='streamport' type='number' min='1' max='65535' autocomplete='off' "
        "placeholder='81' value='"
    );
    w.write(String(streamPort));
    w.write(
        "'>"
        "<p class='cam-hint'>Default 81. Port 80 ist gesperrt (Weboberflaeche).</p>"
        "<label for='streampath'>Stream-Pfad</label>"
        "<input id='streampath' name='streampath' type='text' autocomplete='off' autocapitalize='none' "
        "autocorrect='off' spellcheck='false' placeholder='/stream' value='"
    );
    w.write(escapeHtml(streamPath));
    w.write(
        "'>"
        "<label for='streamkey'>Stream-Schluessel (leer = OHNE Schutz -- der Stream ist dann ueber die oeffentliche IPv4 fuer jeden abrufbar; ab Werk zufaellig gesetzt)</label>"
        "<input id='streamkey' name='streamkey' type='text' autocomplete='off' placeholder='(leer)' value='"
    );
    w.write(escapeHtml(streamKey));
    w.write(
        "'>"
        "</div>"   // /http-Block

        // ---- RTSP-Einstellungen (rtsp_server.*: RFC 2326/2435/6184, ersetzt den HTTP-Stream-Server) ----
        "<div data-streamtype='rtsp'>"
        "<div class='info' style='margin:8px 0'>"
        "<div><span>MJPEG (RTP/JPEG, RFC 2435)</span><span><code>rtsp://&lt;ip&gt;:<span class='rtsp-port'>554</span>/mjpeg</code></span></div>"
        "<div><span>H.264 (HW-Encoder, RFC 6184)</span><span><code>rtsp://&lt;ip&gt;:<span class='rtsp-port'>554</span>/h264</code> &nbsp;<small>optional <code>?w=1280&amp;h=720</code></small></span></div>"
        "<div><span>Zugriff</span><span>Stream-Schluessel (Tab HTTP) als Basic-Auth: <code>rtsp://user:&lt;schluessel&gt;@&lt;ip&gt;/...</code>; leer = ohne</span></div>"
        "</div>"
        "<p class='cam-hint'>Standardkonform fuer VLC, ffmpeg/ffplay, NVRs. RTP und RTCP laufen als Vorgabe im RTSP-TCP-Kanal "
        "(interleaved) -- ein Socket je Client. UDP kostet je Client zwei weitere Sockets; nur freigeben, wenn ein "
        "Client es zwingend braucht (der Server antwortet sonst 461, Clients fallen auf TCP zurueck). Keine "
        "Verschluesselung (Betrieb im VPN). Max. 2 Clients (1 ohne &quot;mehrere Zuschauer&quot;).</p>"
        "<label for='rtspport'>RTSP-Port</label>"
        "<input id='rtspport' name='rtspport' type='number' min='1' max='65535' autocomplete='off' "
        "placeholder='554' value='"
    );
    w.write(String(rtspPort));
    w.write(
        "'>"
        "<label for='rtsptransport'>Transport</label>"
        "<select id='rtsptransport' name='rtsptransport' class='cam-select cfg-select'>"
        "<option value='tcp'"
    );
    if (rtspTransport != "udp") w.write(" selected");
    w.write(">nur TCP interleaved (empfohlen, 1 Socket je Client)</option><option value='udp'");
    if (rtspTransport == "udp") w.write(" selected");
    w.write(
        ">TCP und UDP (RTP/AVP ueber UDP zusaetzlich erlauben)</option></select>"
        "</div>"   // /rtsp-Block

        // --- H.264 (HW-Encoder, fMP4 auf dem Stream-Port): Bitrate + adaptive Bildrate. Gilt fuer
        //     beide Transporte. Wirkt beim naechsten Streamstart.
        "<h2 class='section-title'>H.264</h2>"
        "<label for='h264kbit'>Ziel-Bitrate (kbit/s)</label>"
        "<input id='h264kbit' name='h264kbit' type='number' min='200' max='20000' step='100' value='"
    );
    w.write(String(h264Kbit));
    w.write(
        "'>"
        "<p class='cam-hint'>Den Mobilfunk-Uplink ausnutzen: Richtwert ~80 % des gemessenen Uploads "
        "(Diagnose &rarr; Modem &rarr; Durchsatz; Cat-4 typisch 6-8 Mbit/s). Die Bitrate bestimmt die "
        "Bildqualitaet je Frame; ist der Link schwaecher, greift darunter die adaptive Bildrate.</p>"
        "<p class='cam-hint'>Bildrate und Frame-Politik (veraltete Frames verwerfen = Bildrate folgt der "
        "Bandbreite) gelten fuer ALLE Streams und stehen im Tab <strong>Bild</strong>. Erreichte Bildrate/Bitrate "
        "und ausgelassene Frames zeigt Diagnose &rarr; Video waehrend eines H.264-Streams an.</p>"

        // --- H.264-Boot-Reserve (Guard): EINSTELLUNG des HW-Encoders (nicht Diagnose). Frueh nach der
        //     Kamera reserviert, beim Streamstart an den Encoder abgegeben, danach zurueckgeholt
        //     (h264_guard.h). NVS, wirkt ab Neustart. Eigener JS-Button (type=button) -- der Block liegt
        //     im atomaren camcfg-Formular und darf dessen POST nicht ausloesen. Messwerte: Diagnose > Heap-Map.
        "<h2 class='section-title'>H.264-Boot-Reserve (Guard)</h2>"
        "<p class='cam-hint'>Der H.264-HW-Encoder braucht seinen Referenzpuffer aus ZUSAMMENHAENGENDEM "
        "internem Speicher (~1152 Byte je 16 Pixel Breite). Direkt nach der Kamera ist der groesste Block "
        "noch gross; USB-Host, Netz, Webserver, PPP-Link, DynDNS-TLS und HTTP-Sitzungen zerstueckeln ihn "
        "danach. Die Reserve wird deshalb FRUEH reserviert und als <strong>eigene Heap-Region</strong> "
        "registriert: nur grosse Anfragen (der Encoder-Block) weichen dorthin aus, Kleinkram bleibt im "
        "Haupt-Heap -- die Region bleibt ueber beliebig viele Streams am Stueck. <strong>Automatisch</strong> "
        "(Default) = Referenzpuffer des groessten Kamera-Modus plus 12 KB Heap-Verwaltung -- keine Handzahl, "
        "folgt der Kamera-Bibliothek (FHD ~162 KB, 1280 breit ~112 KB, 800 breit ~75 KB; enthaelt Referenz-Zeilenpuffer, "
        "Deblocking-Zwischenpuffer und DMA-Deskriptoren -- alle internen Encoder-Puffer). <strong>Trade-off:</strong> "
        "was die Reserve haelt, fehlt dauerhaft allen anderen Diensten (Messung: Diagnose &rarr; System "
        "&rarr; Heap-Map). Melden PPP/DynDNS/Webserver Speicherfehler, hier manuell kleiner stellen oder "
        "ausschalten. Wirkt ab dem naechsten Neustart.</p>"
        "<p class='cam-hint'><strong>Kamera-Modus:</strong> die PPA skaliert nur herunter, der Sensor muss die "
        "Zielgroesse also liefern. Beim Start eines H.264-Streams schaltet die Firmware die Kamera selbst auf "
        "den kleinsten passenden Sensor-Modus (z.B. 1920&times;1080 fuer FHD) -- kein Umstellen von Hand. "
        "Aktueller Sensor-Modus: <strong>"
    );
    {
        uint16_t sw = 0, sh = 0;
        cameraManager.currentMode(sw, sh);
        w.write(sw ? (String(sw) + "&times;" + String(sh)) : String("unbekannt"));
    }
    w.write(
        "</strong>. Nur H.264-Groessen, die KEIN Sensor-Modus abdeckt, erscheinen im Livebild als "
        "&quot;(Sensor ...)&quot;.</p>"
        "<div class='info'>"
        "<div><span>Reserve beim Boot</span><span>"
        "<select id='vg-guardmode' class='cam-select' style='width:auto'>"
    );
    {
        int kb = h264GuardConfiguredKb();
        w.write(String("<option value='auto'") + (kb == H264_GUARD_AUTO ? " selected" : "") + ">Automatisch (groesster Kamera-Modus)</option>");
        w.write(String("<option value='off'")  + (kb == 0 ? " selected" : "") + ">Aus</option>");
        w.write(String("<option value='manual'") + (kb > 0 ? " selected" : "") + ">Manuell</option>");
        w.write("</select> <input id='vg-guardkb' type='number' min='4' max='400' step='4' "
                "style='width:80px;text-align:right'");
        if (kb <= 0) w.write(" disabled");
        w.write(" value='");
        w.write(String(kb > 0 ? kb : (int)(h264GuardBootBytes() / 1024)));
        w.write("'> KB</span></div>");
    }
    w.write(
        "<div><span>Aktuell (dieser Boot)</span><span>"
    );
    {
        size_t held = h264GuardBytes(), boot = h264GuardBootBytes();
        if (h264GuardSkippedServerOff())
                            w.write("aus -- HTTP-Stream war beim Start deaktiviert (Reserve nur mit aktivem Video-Server; wirkt ab Neustart)");
        else if (boot == 0) w.write("aus");
        else if (held)      w.write(String(held / 1024) + " KB exklusiv fuer Video reserviert (frei "
                                    + String(h264GuardRegionLargest() / 1024) + " KB)");
        else                w.write(String(boot / 1024) + " KB angefordert, Registrierung als Heap-Region fehlgeschlagen (siehe serielles Log)");
    }
    w.write(
        "</span></div>"
        "</div>"
        "<div class='cam-bar'>"
        "<button id='vg-guardsave' class='cam-button' type='button'>Reserve speichern (ab Neustart)</button>"
        "</div>"
        "<p class='cam-hint'>Die Reserve wird nur angelegt, wenn der HTTP-Stream (oben) aktiv ist -- ohne "
        "Video-Server gibt es keinen H.264-Endpunkt. Wie beim WLAN-Stack wirkt Ein-/Ausschalten ab dem "
        "naechsten Neustart. Die Reserve ist exklusiv: kein anderer Dienst kann daraus allozieren, nur "
        "der jeweils laufende Video-Encoder. MJPEG braucht keinen internen Speicher (Bildpuffer im PSRAM, "
        "gemeinsam ueber den Verteiler) -- es gibt also EINE Video-Reserve, keine zwei.</p>"
        "<p id='vg-guardmsg' class='scan-status'></p>"
        "</div>"   // /psub-video-stream

        // ===== Bild: geraetespezifische Sensor-/Bildparameter =====
        "<div class='page-sub' id='psub-video-bild'>"
        "<label id='quality-row' class='slider-row' for='quality-slider'>"
        "<span>JPEG-Qualitaet</span><span id='quality-value' class='slider-value'></span>"
        "</label>"
        "<input id='quality-slider' class='slider' type='range' min='0' max='63' step='1' value='"
    );
    w.write(String(cameraCurrentQuality));
    w.write(
        "'>"
        "<p class='cam-hint'>0 = beste Qualitaet (groesste Datei), 63 = kleinste. Wirkt sofort.</p>"
        "<label class='slider-row' for='fps-slider'>"
        "<span>Bildrate</span><span id='fps-value' class='slider-value'></span>"
        "</label>"
        "<input id='fps-slider' class='slider' type='range' min='1' max='30' step='1' value='"
    );
    w.write(String(cameraTargetFps));
    w.write(
        "'>"
        "<p class='cam-hint'>Bildrate wirkt sofort und gilt fuer alle Streams (MJPEG wie H.264): der Verteiler "
        "holt Frames in diesem Takt.</p>"
        // Globale Frame-Politik des Verteilers (gilt fuer MJPEG UND H.264): Live per PATCH /dev/camera0.
        "<label class='check-row'><input id='drop-stale' type='checkbox' value='1'"
    );
    if (streamDropStale) w.write(" checked");
    w.write(
        "><span><strong>Veraltete Frames verwerfen (Bildrate folgt der Bandbreite).</strong> Kommt ein "
        "Zuschauer nicht hinterher (Uplink voll), bekommt er nach jedem Send den <em>neuesten</em> Frame; "
        "was er verpasst hat, wird verworfen -- Latenz bleibt bei einem Frame. Ohne Haken geht kein Frame "
        "verloren: der naechste wird erst geholt, wenn alle Zuschauer den aktuellen haben (Rueckstau bis "
        "zum Sensor), die Verzoegerung darf wachsen. Wirkt sofort. <strong>H.264:</strong> dauert der Send "
        "eines Frames laenger als ein Frame-Intervall, werden die naechsten Frames proportional ausgelassen "
        "(vor dem Encoder, ausgeliehen und sofort zurueckgegeben). Nie am Kamera-Ring: das fruehere "
        "Verwerfen dort erzeugte hardware-bewiesen rosa driftende P-Frames (03.09.2026).</span></label>"
        "<p class='cam-hint'>Die folgenden Struktur-Werte wirken nach Neustart.</p>"
        "<label for='cfg-max'>Maximale Aufloesung</label>"
        // Capture-Eigenschaft des Geraets -> PATCH /dev/camera0 (kein Form-Submit, kein name=).
        "<select id='cfg-max' class='cam-select cfg-select'>"
    );
    w.write(createSizeOptionsHtml(FRAME_SIZE_OPTION_COUNT - 1, cameraConfiguredMaxIndex));
    w.write(
        "</select>"
        "<label class='slider-row' for='cfg-bufq'>"
        "<span>Max. Bildpuffer / beste Qualitaet</span><span id='cfgb-value' class='slider-value'></span>"
        "</label>"
        "<input id='cfg-bufq' class='slider' type='range' min='0' max='63' step='1' value='"
    );
    w.write(String(cameraBufferQuality));
    w.write(
        "'>"
        "<p class='cam-hint'>PSRAM je Bild. <strong>0</strong> = groesster Puffer (Live-Slider ueber "
        "den ganzen Bereich sicher).</p>"
        // Rueckmeldung der SOFORT wirkenden Einstellungen (Qualitaet/Bildrate/Frame-Politik/Puffer).
        // Die Statuszeile des Livebilds (#cam-status) steht seit dem Einzelseiten-Rendering auf einer
        // ANDEREN Seite (Diagnose > Video) -- ohne diese Zeile bliebe jede Meldung unsichtbar.
        "<p id='cam-cfg-msg' class='cam-hint'></p>"
        "<h2 class='section-title'>Sensor-Parameter</h2>"
        "<p class='cam-hint'>Alle Parameter, die das aktive Kamera-Geraet meldet (OV3660/DVP am S3 "
        "bzw. MIPI-CSI am P4). Wirken sofort. Bei anderer Quelle (z.B. USB-Webcam) koennen andere "
        "Parameter erscheinen.</p>"
        "<div id='cam-params'>lade ...</div>"
        "</div>"   // /psub-video-bild

        "<button class='connect-button' type='submit'>Speichern und neu starten</button>"
        "</form>"
        "</section>"

        // Stream-Typ -> passenden Einstellungsblock zeigen (dynamisch, wie die Radiogruppen).
        "<script>(function(){"
        "var s=document.getElementById('stream-type');if(!s)return;"
        "function tog(){var t=s.value;"
        "document.querySelectorAll('#psub-video-stream [data-streamtype]').forEach(function(el){"
        "el.style.display=(el.getAttribute('data-streamtype')===t)?'':'none';});}"
        "s.addEventListener('change',tog);tog();"
        "})();</script>"
    );
}
