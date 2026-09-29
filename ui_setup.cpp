// ui_setup.cpp -- Content: Einrichtung > "Setup" (Tabs: WLAN-Portal, UART).
//   WLAN-Portal: zwei Sicherheitsfunktionen fuer ein Geraet ohne Werksreset-Schalter:
//   (1) Captive-Portal als Lockout-Schutz (erzwungen, solange kein WAN da ist),
//       per Checkbox unter Warnhinweis ganz abschaltbar.
//   (2) Werksreset ueber die BOOT-Taste (GPIO0): N s halten -> Netzwerk/Zugang zuruecksetzen.
//   Persistenz ueber setup_guard (NVS "setup"); die Laufzeit-Wirkung liegt im Sketch.
//   UART: die serielle Bedien-Konsole (serial_console.*) -- der Weg, das Geraet OHNE WLAN
//   (P4) zu konfigurieren: Befehlsliste + Baudrate (NVS, ab Neustart).
#include "web_ui.h"
#include "setup_guard.h"
#include "serial_console.h"   // Befehlsliste + Baudrate + Schnittstellenname (eine Quelle)

void renderSetupPortal(WeirdUiWriter& w) {
    const SetupGuardConfig& sg = setupGuardGet();
    bool off = (sg.captiveMode == "off");
    uint32_t holdS = sg.resetHoldMs / 1000UL;
    uint32_t fullS = sg.fullHoldMs / 1000UL;

    w.write(
        "<section id='tab-portal' class='tab-panel'>"
        "<h2 class='section-title'>Setup</h2>"
        "<div class='tabs'>"
        "<button class='tab active' data-psub='set-portal'>WLAN-Portal</button>"
        "<button class='tab' data-psub='set-uart'>UART (USB)</button>"
        "</div>"
        "<div class='page-sub active' id='psub-set-portal'>"
        "<p class='cam-hint'>Sicherheitsfunktionen fuer ein Geraet <strong>ohne</strong> Werksreset-Schalter. "
        "Das Setup-Portal (Adresse 4.3.2.1 mit DNS-Umleitung) ist die Rueckfallebene, um wieder Zugriff "
        "zu bekommen, wenn kein Internet-Uplink (WAN) mehr besteht.</p>"

        "<form action='/setup-portal-save' method='POST'>"

        // ---- Captive-Portal ----
        "<h2 class='section-title'>Captive-Portal (Lockout-Schutz)</h2>"
        "<div class='info' style='margin-bottom:10px'>"
        "<div><span>Verhalten (Automatik)</span><span>Portal AN, solange kein WAN erreichbar</span></div>"
        "<div><span>WAN = erreichbar, wenn</span><span>WLAN-Zielnetz verbunden ODER Modem online</span></div>"
        "</div>"
        "<label class='check-row'>"
        "<input id='sp-captiveoff' name='captiveoff' type='checkbox' value='1'");
    if (off) w.write(" checked");
    w.write(
        ">"
        "<span><strong>Captive-Portal komplett deaktivieren.</strong> "
        "<span style='color:#b02a37'>Achtung:</span> Ohne Portal UND ohne WAN (kein WLAN-Zielnetz, kein "
        "Modem) bleibt fuer die Konfiguration die <strong>serielle UART-Konsole</strong> (USB) und der "
        "<strong>Werksreset-Taster</strong>. Solange die UART-Konsole aktiv ist (Tab UART), kommst du "
        "ueber USB immer ans Geraet; hast du auch die abgeschaltet, geht nur noch der Werksreset-Taster. "
        "Unabhaengig davon kannst du den Setup-AP unter <strong>LAN &rarr; WLAN &rarr; Funknetz</strong> "
        "auch <em>dauerhaft</em> anschalten - dann ist er immer erreichbar, egal ob WAN besteht.</span>"
        "</label>"

        // ---- Werksreset-Taster ----
        "<h2 class='section-title'>Werksreset-Taster</h2>"
        "<p class='cam-hint'>Die <strong>BOOT-Taste</strong> (GPIO0) im laufenden Betrieb lange gedrueckt "
        "halten setzt <strong>nur Netzwerk/Zugang</strong> zurueck (WLAN, WAN-/LAN-Policy, Captive) und "
        "startet neu -- das Geraet kommt als Setup-AP hoch. Kamera, PIN und VPN bleiben erhalten. "
        "(BOOT ist ein Strapping-Pin: nur im Betrieb halten, nicht schon beim Einschalten.)</p>"
        "<label class='check-row'>"
        "<input id='sp-rsten' name='rsten' type='checkbox' value='1'");
    if (sg.resetEnabled) w.write(" checked");
    w.write(
        ">"
        "<span>Werksreset ueber die BOOT-Taste erlauben</span>"
        "</label>"
        "<label for='sp-rsthold'>Stufe 1 - Haltezeit fuer <strong>Netzwerk/Zugang</strong> (Sekunden)</label>"
        "<input id='sp-rsthold' name='rsthold' type='number' min='3' max='120' value='");
    w.write(String(holdS));
    w.write(
        "'>"

        // ---- Stufe 2: kompletter Wipe (laenger halten) ----
        "<label class='check-row'>"
        "<input id='sp-fullen' name='fullen' type='checkbox' value='1'");
    if (sg.fullEnabled) w.write(" checked");
    w.write(
        ">"
        "<span><strong>Stufe 2: ALLES loeschen bei noch laengerem Halten.</strong> Setzt zusaetzlich "
        "<strong>PIN, Kamera, VPN und alle Einstellungen</strong> auf Werk zurueck (kompletter NVS-Wipe). "
        "<span style='color:#b02a37'>Sicherheitsschalter:</span> abschalten, damit niemand mit physischem "
        "Zugang per Tastendruck die PIN entfernen und ins Geraet gelangen kann.</span>"
        "</label>"
        "<label for='sp-fullhold'>Stufe 2 - Haltezeit fuer <strong>Komplett-Reset</strong> (Sekunden)</label>"
        "<input id='sp-fullhold' name='fullhold' type='number' min='5' max='300' value='");
    w.write(String(fullS));
    w.write(
        "'>"
        "<p class='cam-hint'>Kurz halten (Stufe 1) = nur Netzwerk zuruecksetzen, Geraet kommt als Setup-AP "
        "hoch. Laenger halten (Stufe 2) = komplett auf Werk. Die Haltezeit fuer Stufe 2 muss groesser sein "
        "als fuer Stufe 1 (wird sonst automatisch angehoben).</p>"

        "<button class='connect-button' type='submit'>Einrichtung speichern</button>"
        "</form>"
        "</div>"   // /psub-set-portal

        // ---- UART: serielle Bedien-Konsole ----
        "<div class='page-sub' id='psub-set-uart'>"
        "<p class='cam-hint'>Bedienung <strong>ohne WLAN</strong> ueber den USB-Anschluss: Terminal "
        "(z.B. Arduino-Serial-Monitor, PuTTY, screen) oeffnen, Zeilenende <em>Neue Zeile</em>, dann "
        "Befehle eintippen. Damit lassen sich APN, Bandprofil, Datenschicht und DynDNS setzen und der "
        "Modem-Status pruefen -- der Weg fuer den ESP32-P4, der kein eigenes WLAN hat.</p>"
        "<div class='info'>"
        "<div><span>Schnittstelle</span><span>");
    w.write(serialConsoleInterfaceName());
    w.write(
        "</span></div>"
        "<div><span>Baudrate (aktiv)</span><span>");
    w.write(String(serialConsoleBaud()));
    w.write(
        "</span></div>"
        "</div>"
        "<form action='/uart-save' method='POST'>"
        "<label for='uart-baud'>Baudrate (ab dem naechsten Neustart)</label>"
        "<select id='uart-baud' name='baud' class='cam-select cfg-select'>");
    {
        static const uint32_t rates[] = {9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600};
        uint32_t cur = serialConsoleBaud();
        for (size_t i = 0; i < sizeof(rates) / sizeof(rates[0]); i++) {
            w.write(String("<option value='") + String(rates[i]) + "'" + (rates[i] == cur ? " selected" : "") +
                    ">" + String(rates[i]) + "</option>");
        }
    }
    w.write("</select>");
    if (!serialConsoleBaudMatters()) {
        w.write("<p class='cam-hint'>Hinweis: Auf diesem Build haengt die Konsole am nativen USB-Serial/JTAG-"
                "Port (virtueller COM-Port). Die Baudrate ist dort nur ein Nominalwert -- die Verbindung "
                "laeuft unabhaengig davon mit USB-Geschwindigkeit; das Terminal darf jede Rate einstellen.</p>");
    } else {
        w.write("<p class='cam-hint'>Die Baudrate muss im Terminal identisch eingestellt sein.</p>");
    }
    // ---- UART-Zugriffsschutz: Konsole ganz abschaltbar (Produktivsystem) ----
    w.write(
        "<h2 class='section-title'>Zugriffsschutz</h2>"
        "<label class='check-row'><input id='uart-en' type='checkbox' name='uarten' value='1'");
    if (setupUartEnabled()) w.write(" checked");
    w.write(
        "><span><strong>UART-Konsole aktiv</strong> (nimmt Befehle an). "
        "<span style='color:#b02a37'>Nur fuer das Produktivsystem</span> zum Zugriffsschutz abschalten: "
        "dann nimmt die serielle Schnittstelle <strong>keine Befehle</strong> mehr an und zeigt auch keine "
        "Befehlsliste. Wieder einschalten geht dann <strong>nur ueber diese Web-UI</strong> -- ohne WLAN/WAN "
        "bleibt sonst nur der Werksreset-Taster.</span></label>"
        "<button class='connect-button' type='submit'>Baudrate speichern</button>"
        "</form>"
        // Doppelte, eindringliche Rueckfrage NUR beim Abschalten der Konsole.
        "<script>(function(){var f=document.getElementById('uart-en');if(!f)return;var form=f.form;var was=f.checked;"
        "form.addEventListener('submit',function(e){if(was&&!f.checked){"
        "if(!confirm('UART-Konsole wirklich DEAKTIVIEREN? Danach nimmt die serielle Schnittstelle keine Befehle mehr an. Nur fuers Produktivsystem empfohlen.')){e.preventDefault();return;}"
        "if(!confirm('Sicher? Wieder einschalten geht NUR ueber diese Web-UI. Besteht dann kein WLAN/WAN, kommst du nur noch ueber den Werksreset-Taster ans Geraet.')){e.preventDefault();return;}}});})();</script>"
        "<h2 class='section-title'>Befehle</h2>"
        "<pre style='background:#1c1f23;color:#e6e6e6;padding:10px;border-radius:6px;overflow:auto;"
        "font-size:13px;white-space:pre-wrap'>");
    w.write(escapeHtml(String(serialConsoleHelpText())));
    w.write(
        "</pre>"
        "</div>"   // /psub-set-uart

        "</section>");
}
