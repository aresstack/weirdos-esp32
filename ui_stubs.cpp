// ============================================================================
// ui_stubs.cpp -- Platzhalter-Panels der neuen Informationsarchitektur.
// Reine View-Stubs ohne Runtime-Logik: hier liegen Oberpunkte, deren Ziel-
// Funktion noch nicht implementiert ist (Bluetooth/BLE, Peripherie). Sie dienen
// dazu, die IA fruehzeitig sichtbar zu machen, ohne Hardware-/Geraetelogik zu
// erfinden. Spaeter bekommt jeder Bereich seine eigene ui_*.cpp.
// ============================================================================
#include "weirdos_features.h"   // WEIRDOS_FEATURE_WEBUI -- Seiten nur mit Weboberflaeche
#if WEIRDOS_FEATURE_WEBUI
#include "web_ui.h"
#include "peripheral_registry.h"
#include "usb_device_service.h"   // "Bereitstellen an USB": Port-Wahl + Export je Geraet (UVC heute, UAC/NCM vorgesehen)
#include "usb_ports.h"            // USB-Anschluesse des Boards (Nutzer-Mapping: Anzahl, Name, Pins)

// Bluetooth: Panel jetzt in ui_bluetooth.cpp (renderBluetooth) + Logik in bt_scan.*.

// Peripherie: read-only LIVE-SNAPSHOT der Hardware-Registry (Stufe 5) nach dem
// Modell Port/Bus -> Geraet -> Capability. Konsumiert peripheral_registry, rendert
// aber nur - kein Runtime-Zustand wird veraendert (noch keine Source of Truth).
void renderPeripherie(WeirdUiWriter& w) {
    PeriphModel m;
    periphBuildModel(m);

    w.write(
        "<section id='tab-peripherie' class='tab-panel'>"
        "<h2 class='section-title'>Ger&auml;te</h2>"
        "<p class='cam-hint'>Angeschlossene Hardware nach dem Modell <strong>Port/Bus &rarr; "
        "Geraet &rarr; Capability</strong>. <strong>Zugeordnet</strong> = gewuenschte "
        "Zuordnung (persistente Registry), <strong>erkannt</strong> = aktuell am Bus gefunden. "
        "Die USB-Port-Zuordnung des Modems stellst du unter WAN &rarr; Modem ein. Aktuell angeschlossene "
        "Geraete stehen normal, nur <em>zugeordnete, aber nicht erkannte</em> (historische) werden "
        "<span style='opacity:.55'>blass</span> dargestellt.</p>"
        "<div class='cam-bar'>"
        "<button id='periph-rescan' class='cam-button' type='button'>Neue Geraete suchen</button>"
        "<span id='periph-rescan-msg' class='scan-status'></span>"
        "</div>"
        "<p class='cam-hint'>Sucht angeschlossene Geraete ohne Neustart (HotPlug auf Abruf) -- startet dazu "
        "bei Bedarf den USB-Host. Funktioniert nur, wenn am USB-Port kein PC/Netzteil haengt (ein Port). "
        "Die Erkennung ist live -- <strong>Seite bei Bedarf manuell neu laden</strong> (kein Auto-Reload, "
        "der wuerde bei knappem Speicher die Verbindung reissen).</p>"
        // WICHTIG: KEIN location.reload() -- ein automatischer Full-Render riss auf dem
        // internen Heap (heapmin ~244) die Verbindung ab. Nur Statustext, optionaler manueller Reload.
        "<script>(function(){var b=document.getElementById('periph-rescan'),m=document.getElementById('periph-rescan-msg');"
        "if(!b)return;b.addEventListener('click',function(){if(m)m.textContent='Suche ...';b.disabled=true;"
        "fetch('/periph-rescan',{method:'POST',cache:'no-store'}).then(function(r){return r.json();})"
        ".then(function(d){b.disabled=false;if(m)m.innerHTML=((d&&d.msg)||'')+"
        "\" <a href='#' onclick='location.reload();return false'>Seite neu laden</a>\";})"
        ".catch(function(){b.disabled=false;if(m)m.textContent='Netzwerkfehler.';});});})();</script>"
    );

    // Port-Wahl je Board + Export je Geraet der Registry. Klassen ohne Runtime (UAC, NCM) sind ausgegraut
    // und ehrlich als "nicht implementiert" markiert. Deskriptoren entstehen beim Boot -> Neustart noetig.
    // USB-Anschluesse des Boards (Mapping, Pinout) liegen unter Einrichtung > Plattform (ui_platform.cpp).
    w.write("<p class='cam-hint'>USB-Anschluesse und Pinout des Boards: <a href='#/platform'>Einrichtung &rarr; Plattform</a>.</p>");
    // ---- Bereitstellen an USB (PC = Host, WeirdOS = Geraet) ----
    {
        const UsbDeviceConfig& uc = usbDeviceService.config();
        w.write(
            "<h2 class='section-title'>Bereitstellen an USB (PC)</h2>");
        if (!UsbDeviceService::builtIn()) w.write(
            "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0'>"
            "<p><strong>In diesem Build nicht enthalten.</strong> Der USB-Geraete-Stack (TinyUSB des Arduino-Cores) belegt "
            "rund 48 KB internen RAM als feste Puffer, sobald er gelinkt ist &ndash; auch wenn das Feature aus ist. Auf einem "
            "Geraet mit Modem fehlt dieser RAM dem USB-Host. Deshalb wird der Stack nur mit dem Build-Flag "
            "<code>WEIRDOS_USB_DEVICE=1</code> eingebunden. Die Einstellungen hier bleiben gespeichert und wirken, sobald ein "
            "Build mit dem Flag laeuft.</p></div>");
        w.write(
            "<p class='cam-hint'>WeirdOS kann sich an einem PC als USB-Geraet melden: heute als <strong>Webcam (UVC)</strong>, "
            "ohne Treiber. Der PC ist Host, WeirdOS ist Geraet. Der Anschluss kommt aus dem Board-Mapping (Einrichtung &rarr; Plattform); ist es derselbe Port "
            "wie der des Modems, bleibt der Modem-Host beim Boot aus (ein Controller). Aenderungen wirken nach <strong>Neustart</strong>.</p>"
            "<form action='/usbdev-save' method='POST'>"
            "<label for='usb-port'>USB-Anschluss zum PC</label>"
            "<select id='usb-port' name='usbport' class='cam-select cfg-select'>");
        for (int i = 0; i < usbPortsCount(); i++) {
            const UsbPortEntry& e = usbPort(i);
            if (!usbPortUsable(e.id)) continue;
            w.write(String("<option value='") + e.id + "'" + (uc.port == e.id ? " selected" : "") + ">" + escapeHtml(usbPortDescribe(e.id)) + (e.id == periphModemPort ? " [= Modem-Port]" : "") + "</option>");
        }
        w.write(
            "</select>"
            "<p class='cam-hint'>Verkabelung zum PC: D+, D&minus; und GND; VBUS des PCs nicht anschliessen (WeirdOS ist extern versorgt). "
            "Eine VBUS-Erkennung gibt es nicht: der Pull-up liegt ab Boot an, Hotplug wird ueber Bus-Reset erkannt.</p>"
            "<div class='info'>"
            "<div><span>camera0 <small>(Kamera)</small></span><span><select name='cam_camera0' class='cam-select cfg-select usb-exp'>"
            "<option value='off'>aus</option><option value='uvc'");
        if (uc.cam == "camera0") w.write(" selected");
        w.write(">Webcam (UVC) &ndash; MJPEG im aktiven Kamera-Modus</option></select></span></div>"
            "<div><span>testpattern0 <small>(virtuell: Farbbalken 640x480)</small></span><span><select name='cam_testpattern0' class='cam-select cfg-select usb-exp'>"
            "<option value='off'>aus</option><option value='uvc'");
        if (uc.cam == "testpattern0") w.write(" selected");
        w.write(">Webcam (UVC) &ndash; Testbild ohne Kamera</option></select></span></div>"
            "<div><span>microphone0 <small>(Mikrofon)</small></span><span><select class='cam-select cfg-select' disabled title='USB Audio Class ist noch nicht implementiert'>"
            "<option>USB-Mikrofon (UAC) &ndash; nicht implementiert</option></select></span></div>"
            "<div><span>usb-network <small>(virtuell: Netzwerkkarte)</small></span><span><select class='cam-select cfg-select' disabled title='CDC-NCM ist noch nicht implementiert'>"
            "<option>USB-Netzwerk (NCM) &ndash; nicht implementiert</option></select></span></div>"
            "</div>"
            "<label for='usb-fps'>Angebotene Bildrate (fps)</label>"
            "<input id='usb-fps' name='uvcfps' type='number' min='1' max='30' value='");
        w.write(String((unsigned)uc.fps));
        w.write(
            "'>"
            "<p class='cam-hint'>Es kann genau EIN Geraet als Webcam bereitgestellt werden; wird ein zweites gewaehlt, "
            "wird das erste abgewaehlt. Full-Speed = 12 Mbit/s brutto: Aufloesung/Bildrate ergeben sich aus dem Kamera-Modus "
            "und werden nur hardwaregemessen erweitert.</p>"
            "<button class='connect-button' type='submit'>USB-Bereitstellung speichern</button>"
            "</form>"
            "<div id='usbdev-status' class='info' style='margin-top:8px'><div><span>USB-Geraet</span><span>wird geladen ...</span></div></div>"
            "<script>(function(){var sel=document.querySelectorAll('.usb-exp');sel.forEach(function(s){s.addEventListener('change',function(){if(s.value==='uvc')sel.forEach(function(o){if(o!==s)o.value='off';});});});"
            "var el=document.getElementById('usbdev-status');if(!el)return;function row(k,v){return '<div><span>'+k+'</span><span>'+v+'</span></div>';}"
            "function load(){fetch('/usbdev.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();}).then(function(d){"
            "var h=row('Stack',d.active?'laeuft ('+(d.highSpeed?'High-Speed':'Full-Speed')+')':(d.fail?'NICHT gestartet: '+d.fail:'nicht gestartet'))+row('PC',d.mounted?'verbunden (konfiguriert)':'nicht verbunden')"
            "+row('Stream',d.streaming?('AN, '+d.intervalMs+' ms/Bild'):'aus')+row('Format','MJPEG '+d.width+'x'+d.height)+row('Frames / Bytes',d.frames+' / '+d.bytes)+row('JPEG letzte / max',d.lastLen+' / '+d.maxLen+' B')+row('uebersprungen',d.skips);"
            "el.innerHTML=h;}).catch(function(){});}"
            // Socket-Budget (lwIP 16, Web 5): KEIN Abruf beim Laden der App-Seite -- nur solange der Tab offen ist.
            "var tick=function(){var s=document.getElementById('tab-peripherie');if(s&&s.classList.contains('active'))load();};setTimeout(tick,300);setInterval(tick,3000);})();</script>"
            "<h2 class='section-title'>Angeschlossene Hardware</h2>");
    }

    for (int pi = 0; pi < m.portCount; pi++) {
        const PeriphPort& p = m.ports[pi];
        w.write("<div class='info'>");
        // Port-Zeile
        w.write("<div><span><strong>");
        w.write(escapeHtml(p.id));
        w.write("</strong></span><span>");
        w.write(escapeHtml(p.kind));
        w.write("</span></div>");

        if (p.devCount == 0) {
            w.write("<div><span>&nbsp;&nbsp;&#9492;&nbsp;<em>kein Geraet zugeordnet</em>"
                               "</span><span>-</span></div>");
        }
        for (int di = 0; di < p.devCount; di++) {
            const PeriphDev& d = p.devs[di];
            // Historisch (zugeordnet, aber nicht erkannt) -> blass wie im Geraetemanager.
            const char* dim = d.detected ? "" : " style='opacity:.55'";
            // Geraet: Name (+ logischer Name) | Status
            w.write(String("<div") + dim + "><span>&nbsp;&nbsp;&#9492;&nbsp;");
            w.write(escapeHtml(d.logical.length() ? (d.name + " (" + d.logical + ")") : d.name));
            w.write("</span><span>");
            w.write(d.detected ? "angeschlossen" : (d.assigned ? "nicht angeschlossen" : "erkannt"));
            w.write("</span></div>");
            // Discovery getrennt ausweisen: erkannt ja/nein
            w.write(String("<div") + dim + "><span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;erkannt</span><span>");
            w.write(d.detected ? "ja" : "nein");
            w.write("</span></div>");

            for (int ci = 0; ci < d.capCount; ci++) {
                const PeriphCap& c = d.caps[ci];
                w.write(String("<div") + dim + "><span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&#9492;&nbsp;");
                w.write(escapeHtml(c.kind + " " + c.name));
                w.write("</span><span>");
                w.write(escapeHtml(c.status));
                w.write("</span></div>");
            }
        }
        w.write("</div>");
    }

    w.write("</section>");
}
#else
// Weboberflaeche nicht im Build (WEIRDOS_FEATURE_WEBUI=0): kein Seiteninhalt, nur die Renderer-Signaturen,
// damit web_ui.cpp (Seitentabelle) und Nachbarseiten unveraendert linken. Der HTTP-Server (Baustein HTTP)
// beantwortet dann PIN-Gate + JSON-API; sendAppPage() nennt den Grund.
#include "web_ui.h"
void renderPeripherie(WeirdUiWriter& w) { (void)w; }
#endif // WEIRDOS_FEATURE_WEBUI
