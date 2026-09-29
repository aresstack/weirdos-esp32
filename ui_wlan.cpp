// ui_wlan.cpp -- Content: LAN > WLAN (Tabs: Funknetz, Sicherheit). Der Netzwerk-Scan liegt
// jetzt unter Diagnose > Netzwerk (ui_netscan.cpp) -- reine Diagnose, keine LAN-Einstellung.
// Baustein WIFI (WEIRDOS_FEATURE_WIFI): ohne ihn bleibt die Seite (Menuepunkt sichtbar) und nennt nur
// den Grund -- keine Formulare, keine Bedien-IDs, kein /scan-/status.json-Polling (Muster ui_bluetooth.cpp).
#include "weirdos_features.h"
#include "web_ui.h"
#include "network_mode.h"   // AP-Kanal-Policy (apChannelPol/apChannel) fuer das Kanal-Dropdown
#include "wifi_caps.h"      // WLAN-Stack Auto/An/Aus + Hardware-/USB-Adapter-Erkennung

void renderWlan(WeirdUiWriter& w) {
#if WEIRDOS_FEATURE_WIFI
    const NetworkModeConfig& nm = networkMode.config();
    bool apAuto = (nm.apChannelPol != "fixed");   // "Automatisch (folgt Uplink)" vs. fester Kanal

    WifiStackMode stackMode = wifiStackMode();
    bool wifiHw   = wifiPresent();
    bool wifiEffOn = wifiStackShouldInit();   // was der NAECHSTE Boot mit dem aktuell gespeicherten Modus macht
    uint16_t usbVid = 0, usbPid = 0;
    const char* usbChip = usbWifiAdapterDetected(&usbVid, &usbPid);

    // --- WLAN-Seite: eine Seite, zwei Tabs (frueher drei Untermenues; Netzwerk-Scan -> Diagnose) ---
    w.write(
        "<section id='tab-wlan' class='tab-panel'>"
        "<div class='tabs'>"
        "<button class='tab active' data-psub='wl-funk'>Funknetz</button>"
        "<button class='tab' data-psub='wl-sec'>Sicherheit</button>"
        "</div>"
        "<div class='page-sub active' id='psub-wl-funk'>"
        "<h2 class='section-title'>WLAN-Funktion</h2>"
        "<form method='POST' action='/save'>"
        // Erster Eintrag entscheidet: laeuft der WLAN-Stack ueberhaupt? Analog zu VPN/Bluetooth
        // (nichts darunter laedt, wenn hier aus). Auto = nur bei erkannter Onboard-Funk-Hardware.
        "<label for='wifistack'>WLAN-Stack</label>"
        "<select id='wifistack' name='wifistack' class='cam-select cfg-select' data-hw-present='"
    );
    w.write(wifiHw ? "1" : "0");
    w.write("'>");
    w.write(String("<option value='auto'") + (stackMode == WifiStackMode::Auto ? " selected" : "") +
            ">Automatisch (nur bei erkannter Funk-Hardware)</option>");
    w.write(String("<option value='on'") + (stackMode == WifiStackMode::On ? " selected" : "") +
            ">Immer an (erzwingen)</option>");
    w.write(String("<option value='off'") + (stackMode == WifiStackMode::Off ? " selected" : "") +
            ">Immer aus</option>");
    w.write("</select>");
    w.write("<p class='cam-hint' id='wifistack-hint'>");
    w.write(wifiHw ? "Onboard-WLAN-Funk erkannt."
                   : "Keine WLAN-Funk-Hardware erkannt (dieses Board hat kein Onboard-WLAN).");
    if (usbChip) {
        w.write(" Zusaetzlich per USB gefunden: <strong>");
        w.write(escapeHtml(String(usbChip)));
        w.write("</strong> - in dieser Firmware gibt es dafuer KEINEN Treiber (ESP-IDF/Arduino-WLAN "
                "spricht nur mit Onboard-Funk oder einem SPI/SDIO-Companion-Chip, nie mit USB), daher "
                "nur Anzeige, nicht nutzbar.");
    }
    w.write("</p>");
    w.write(String("<div class='wifi-gated-fields") + (wifiEffOn ? "" : " fields-inactive") + "'>");
    if (!wifiEffOn) w.write(
        "<p class='cam-hint'><strong>Kein WLAN verfuegbar/aktiv.</strong> Ohne Funk-Hardware (oder bei "
        "'Immer aus') laufen weder Client- noch Accesspoint-Modus -- die Felder unten wirken erst nach "
        "Speichern, wenn oben 'Immer an' gewaehlt ist und echte Funk-Hardware vorhanden ist.</p>");
    w.write(
        "<h2 class='section-title'>Funknetz (Zielnetz)</h2>"
        "<p class='cam-hint'>Optional: dieses Geraet als Client in ein vorhandenes WLAN einhaengen "
        "(Zielnetz). Ohne Aktivierung bleibt es ein reiner Accesspoint, mit dem du dich direkt per "
        "Smartphone verbindest.</p>"
        "<label class='check-row'>"
        "<input type='checkbox' name='enable' value='1'"
    );
    if (targetNetworkEnabled) w.write(" checked");
    w.write(
        ">"
        "<span><strong>Mit vorhandenem WLAN verbinden (Client-Modus)</strong> - dieses Geraet als Station "
        "in ein bestehendes Netz einhaengen (statt eigenem Accesspoint).</span>"
        "</label>"
        "<label for='ssid'>Netzwerkname</label>"
        "<div class='ssid-wrap'>"
        "<div class='ssid-row'>"
        "<div class='field-wrap'>"
        "<input id='ssid' class='has-inset' name='ssid' type='text' "
        "autocomplete='username' autocapitalize='none' autocorrect='off' "
        "spellcheck='false' placeholder='SSID' value='"
    );
    w.write(escapeHtml(configuredSsid));
    w.write(
        "'>"
        "<button id='toggle-button' class='inset-button' type='button' "
        "aria-expanded='false' aria-controls='ssid-list' "
        "title='Netzwerke' aria-label='Netzwerke'>&#9662;</button>"
        "</div>"
        "<button id='rescan-button' class='icon-button' type='button' "
        "title='Erneut suchen' aria-label='Erneut suchen'>&#10227;</button>"
        "</div>"
        "<ul id='ssid-list' class='ssid-list hidden'></ul>"
        "</div>"
        "<div id='scan-status' class='scan-status'></div>"
        "<label for='password'>Passwort</label>"
        "<div class='field-wrap'>"
        "<input id='password' class='has-inset' name='password' "
        "type='password' autocomplete='current-password'>"
        "<button id='pw-eye' class='inset-button' type='button' "
        "aria-pressed='false' title='Passwort anzeigen' "
        "aria-label='Passwort anzeigen'>&#128065;</button>"
        "</div>"
        "<label class='check-row'>"
        "<input type='checkbox' name='persist' value='1' checked>"
        "<span>Zugangsdaten dauerhaft speichern</span>"
        "</label>"
        "<h2 class='section-title'>Accesspoint</h2>"
        "<label class='check-row'>"
        "<input type='checkbox' name='keepap' value='1'"
    );
    if (keepApAlways) w.write(" checked");
    w.write(
        ">"
        "<span><strong>Setup-Accesspoint dauerhaft eingeschaltet lassen.</strong> Mit Haken laeuft der "
        "AP immer. Ohne Haken ist er nur ein <strong>Sicherheitsnetz</strong>: er laeuft, solange "
        "<strong>kein WAN</strong> erreichbar ist (kein WLAN-Zielnetz verbunden UND kein Modem online). "
        "Ist das Captive-Portal unter <strong>Einrichtung &rarr; Setup &rarr; WLAN-Portal</strong> deaktiviert, bleibt "
        "der AP auch dann aus - bei fehlendem WAN kommst du dann nur noch ueber den Werksreset-Taster rein.</span>"
        "</label>"
        "</div>"   // /wifi-gated-fields (1/2, im /save-Formular)
        "<button class='connect-button' type='submit'>"
        "Speichern und neu starten"
        "</button>"
        "</form>"

        // --- AP-Kanal: EIN Dropdown. Auf einem Funkchip kann der AP-Kanal nicht vom STA-Kanal
        //     abweichen -> "Automatisch (folgt Uplink)" statt getrennter Policy+Nummer. Wirkungslos
        //     ohne laufenden WLAN-Stack -> Teil der gleichen wifi-gated-fields-Gruppe (2/2). ---
    );
    w.write(String("<div class='wifi-gated-fields") + (wifiEffOn ? "" : " fields-inactive") + "'>");
    w.write(
        "<h2 class='section-title'>AP-Kanal</h2>"
        "<form action='/wlan-apchannel-save' method='POST'>"
        "<label for='wl-apch'>Kanal des Setup-/AccessPoints</label>"
        "<select id='wl-apch' name='apchan' class='cam-select cfg-select'>"
    );
    w.write(apAuto ? "<option value='auto' selected>Automatisch (folgt WLAN-Uplink)</option>"
                              : "<option value='auto'>Automatisch (folgt WLAN-Uplink)</option>");
    for (int ch = 1; ch <= 13; ch++) {
        w.write("<option value='");
        w.write(String(ch));
        w.write((!apAuto && nm.apChannel == ch) ? "' selected>" : "'>");
        w.write(String(ch));
        w.write("</option>");
    }
    w.write(
        "</select>"
        "<p class='cam-hint'>AP und WLAN nutzen auf einem Funkchip zwangsweise <strong>denselben</strong> "
        "Kanal. Bei aktiver WLAN-Verbindung uebernimmt der AP deren Kanal; ohne WLAN gilt der hier "
        "gewaehlte Kanal. <strong>Automatisch</strong> ueberlaesst die Wahl dem System. Nur 2,4 GHz (1-13).</p>"
        "<button class='connect-button' type='submit'>AP-Kanal speichern</button>"
        "</form>"
        "</div>"   // /wifi-gated-fields (2/2)
        "</div>"   // /psub-wl-funk

        // --- WLAN-Sicherheit: eigenes WPA2-Passwort fuer den Setup-AP ---
        "<div class='page-sub' id='psub-wl-sec'>"
        "<h2 class='section-title'>Setup-Accesspoint</h2>"
        "<div class='info'>"
        "<div><span>SSID</span><span>XIAO-Setup</span></div>"
        "<div><span>Verschluesselung</span><span id='apsec-state'>lade ...</span></div>"
        "</div>"
        "<form id='apsec-form'>"
        "<label for='apsec-password'>Neues WPA2-Passwort</label>"
        "<div class='field-wrap'>"
        "<input id='apsec-password' class='has-inset' name='password' type='password' "
        "autocomplete='new-password' minlength='8' maxlength='63' "
        "placeholder='leer = gespeichertes Passwort beibehalten'>"
        "<button id='apsec-eye' class='inset-button' type='button' aria-pressed='false' "
        "title='Passwort anzeigen' aria-label='Passwort anzeigen'>&#128065;</button>"
        "</div>"
        "<p class='cam-hint'>Das gespeicherte Passwort wird nie an den Browser zurueckgegeben. "
        "Ein neues WPA2-Passwort muss 8 bis 63 Zeichen lang sein.</p>"
        "<label class='check-row'>"
        "<input id='apsec-open' type='checkbox' name='open' value='1'>"
        "<span>Setup-Accesspoint bewusst offen betreiben (WPA2 deaktivieren)</span>"
        "</label>"
        "<button class='connect-button' type='submit'>WLAN-Sicherheit uebernehmen</button>"
        "</form>"
        "<p id='apsec-msg' class='scan-status'></p>"
        "<p class='cam-hint'>Nach einer Aenderung startet das Geraet neu. Wenn du gerade ueber "
        "den Setup-AP verbunden bist, musst du dich danach mit dem neuen Passwort erneut verbinden.</p>"
        "<script>"
        "(function(){"
        "var f=document.getElementById('apsec-form'),p=document.getElementById('apsec-password'),"
        "o=document.getElementById('apsec-open'),m=document.getElementById('apsec-msg'),"
        "s=document.getElementById('apsec-state'),e=document.getElementById('apsec-eye');"
        "if(e&&p)e.addEventListener('click',function(){var show=p.type==='password';"
        "p.type=show?'text':'password';e.classList.toggle('active',show);});"
        "if(o&&p)o.addEventListener('change',function(){p.disabled=o.checked;if(o.checked)p.value='';});"
        "fetch('/status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})"
        ".then(function(d){if(s)s.textContent=d.apProtected?'WPA2-PSK':'offen';}).catch(function(){if(s)s.textContent='-';});"
        "if(f)f.addEventListener('submit',function(ev){ev.preventDefault();if(m)m.textContent='Speichere ...';"
        "var q=[];if(o&&o.checked)q.push('open=1');else if(p&&p.value)q.push('password='+encodeURIComponent(p.value));"
        "fetch('/ap-security-save',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:q.join('&')})"
        ".then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error((d&&d.msg)||('HTTP '+r.status));return d;});})"
        ".then(function(d){if(m)m.textContent=(d&&d.msg)||'Gespeichert.';if(d&&d.restart){if(f)f.querySelector('button[type=submit]').disabled=true;}})"
        ".catch(function(err){if(m)m.textContent='Fehler: '+err.message;});"
        "});"
        "})();"
        "</script>"
        "</div>"        // /psub-wl-sec
        "</section>"    // /tab-wlan
    );
#else
    // WLAN nicht im Build (WEIRDOS_FEATURE_WIFI=0): entweder hat der Chip keinen Funk (ESP32-P4 --
    // der Schalterkasten zieht den Baustein dort hart auf 0) oder er wurde beim Bauen abgewaehlt.
    // Panel bleibt sichtbar und nennt den Grund -- Menuepunkt nicht verstecken (Konsistenz mit
    // IoT > Bluetooth). Bewusst OHNE die Bedien-IDs (wifistack/ssid/toggle-button/apsec-form): das
    // WLAN-JS in web_ui_assets.cpp prueft darauf und wuerde sonst /scan bzw. /status.json rufen;
    // die Routen /save, /scan, /ap-security-save sind in der .ino ebenfalls unter WEIRDOS_FEATURE_WIFI.
    w.write(
        "<section id='tab-wlan' class='tab-panel'>"
        "<h2 class='section-title'>WLAN</h2>"
        "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;"
        "border-radius:6px;margin:8px 0'><p><strong>WLAN ist in dieser Firmware nicht enthalten</strong> "
        "(Baustein WIFI, <code>WEIRDOS_FEATURE_WIFI=0</code>). Entweder hat dieser Chip keinen WLAN-Funk "
        "(ESP32-P4: nur ueber ESP-Hosted mit einem Companion-Chip, der auf diesem Board nicht bestueckt ist) "
        "oder der Baustein wurde beim Bauen abgewaehlt. Es laeuft nur der Netz-Unterbau (lwIP) fuer "
        "Mobilfunk, VPN und die Weboberflaeche -- kein Setup-Accesspoint, kein Captive-Portal, kein "
        "WLAN-Client, kein mDNS. Ein USB-WLAN-Adapter hilft nicht: dafuer gibt es in ESP-IDF/Arduino "
        "keinen Treiber.</p></div>"
        "<div class='fields-inactive'>"
        "<p class='cam-hint'>Mit WLAN-Baustein bietet diese Seite: WLAN-Stack (Automatisch/Immer an/Immer aus), "
        "Client-Modus in ein vorhandenes Funknetz (Netzsuche, Zugangsdaten), Setup-Accesspoint "
        "(dauerhaft oder als Sicherheitsnetz ohne WAN), AP-Kanal und das WPA2-Passwort des Setup-AP.</p>"
        "<div class='info'>"
        "<div><span>WLAN-Stack</span><span>nicht im Build</span></div>"
        "<div><span>Client-Modus (Zielnetz)</span><span>nicht im Build</span></div>"
        "<div><span>Setup-Accesspoint / Captive-Portal</span><span>nicht im Build</span></div>"
        "<div><span>AP-Kanal / WLAN-Sicherheit</span><span>nicht im Build</span></div>"
        "</div>"
        "</div>"
        "</section>"    // /tab-wlan
    );
#endif
}
