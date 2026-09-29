// ui_system.cpp -- Content: Oberpunkt "System"
//   Seiten: Allgemein, Update, Energiemonitor, Sicherheit (PIN+WAN), Sicherung
//   (Ereignisse: Diagnose, ui_diag.cpp)
#include "web_ui.h"
#include "acme_client.h"   // Zertifikat-Abschnitt (System > Sicherheit): Let's-Encrypt-Config
#include "cert_store.h"    // Zertifikatsherkunft (self-signed / eigenes / Let's Encrypt)
#include "access_policy.h" // Zugriff je Dienst (LAN / VPN / Internet)

void renderSystem(WeirdUiWriter& w) {
    // --- Allgemein (Router-Name / URL) ---
    w.write(
        "<section id='tab-general' class='tab-panel'>"
        "<h2 class='section-title'>Allgemein</h2>"
        "<p class='cam-hint'>Name, unter dem die Oberflaeche im Netzwerk erreichbar ist "
        "(per mDNS als <em>&lt;name&gt;.local</em>). Nur Buchstaben, Ziffern und Bindestrich. "
        "Die Aenderung wird nach einem Neustart aktiv.</p>"
        "<label for='gen-host'>Router-Name</label>"
        "<input id='gen-host' name='host' type='text' autocomplete='off' autocapitalize='none' "
        "spellcheck='false' maxlength='31' value='"
    );
    w.write(escapeHtml(deviceHostname));
    w.write(
        "'>"
        "<div class='info'><div><span>Adresse im Netzwerk</span><span id='gen-url'>http://"
    );
    w.write(escapeHtml(deviceHostname));
    w.write(
        ".local</span></div></div>"
        "<button id='gen-save' class='connect-button' type='button'>Speichern</button>"
        "<p id='gen-msg' class='scan-status'></p>"
        "<p class='cam-hint'>Im Setup-WLAN (Captive Portal) ist die Box zusaetzlich unter einem "
        "einpraegsamen Namen erreichbar; im Heim-/Firmennetz gilt die <em>.local</em>-Adresse "
        "oder die IP.</p>"
    );
    // --- 7.9.14: mbedTLS-Speicher-Schalter (PSRAM vs intern), wirkt nach Neustart ---
    w.write(
        "<h3 class='section-title' style='margin-top:20px'>TLS-Speicher (mbedTLS)</h3>"
        "<p class='cam-hint'>Woher TLS (DynDNS/HTTPS) seine Puffer nimmt. <strong>PSRAM</strong> "
        "entlastet den knappen internen RAM (empfohlen am ESP32-S3) und behebt das DynDNS-"
        "Fehlschlagen bei fragmentiertem Heap; grosse TLS-Recordpuffer (2&times;16&nbsp;KB) landen "
        "dann im PSRAM statt intern mit WLAN/USB/WireGuard zu konkurrieren. <strong>Intern</strong> "
        "ist der Standard (z.&nbsp;B. andere Boards wie ESP32-P4). Die Aenderung wird erst nach einem "
        "<strong>Neustart</strong> aktiv.</p>"
        "<label class='cam-hint' style='display:flex;gap:8px;align-items:center;cursor:pointer'>"
        "<input id='crypto-psram' type='checkbox'"
    );
    w.write(g_cryptoMemPsram ? " checked" : "");
    w.write(
        "> mbedTLS-Puffer in den PSRAM legen</label>"
        "<div class='info'><div><span>Aktiv (dieser Boot)</span><span id='crypto-now'>"
    );
    w.write((g_cryptoMemPsram && psramFound()) ? "PSRAM" : "intern");
    w.write(
        "</span></div></div>"
        "<button id='crypto-save' class='connect-button' type='button'>Uebernehmen &amp; Neustart</button>"
        "<p id='crypto-msg' class='scan-status'></p>"
        "</section>"
    );
    // (Ereignisse liegen jetzt unter Diagnose -> ui_diag.cpp.)
    // --- Update (Platzhalter) ---
    w.write(
        "<section id='tab-update' class='tab-panel'>"
        "<h2 class='section-title'>Update</h2>"
        "<div class='info'><div><span>Firmware-Build</span><span id='fw-build'>"
        __DATE__ " " __TIME__
        "</span></div></div>"
        "<p class='cam-hint'>Firmware (.bin) ueber WLAN einspielen. <strong>Waehrend des Uploads "
        "NICHT trennen oder neu laden.</strong> Benoetigt ein OTA-faehiges Partitionsschema "
        "(Arduino IDE: Tools -&gt; Partition Scheme mit OTA). Bei 'Huge App' ist kein OTA moeglich - "
        "dann weiter per USB flashen. Einstellungen/PIN bleiben erhalten.</p>"
#if WEIRDOS_FEATURE_OTA
        "<form method='POST' action='/ota-update' enctype='multipart/form-data'>"
        "<input id='ota-file' name='firmware' type='file' accept='.bin'>"
        "<button class='connect-button' type='submit' style='margin-top:8px'>Firmware hochladen und flashen</button>"
        "</form>"
#else
        "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0'>"
        "<p><strong>Firmware-Update ueber die Weboberflaeche ist in diesem Build nicht enthalten "
        "(WEIRDOS_FEATURE_OTA=0).</strong> Der Baustein OTA wurde beim Bauen abgewaehlt -- Updates laufen ueber "
        "USB (Kamera-Tool / arduino-cli).</p></div>"
#endif // WEIRDOS_FEATURE_OTA
        "</section>"
    );
    // --- Energiemonitor ---
    w.write(
        "<section id='tab-energy' class='tab-panel'>"
        "<h2 class='section-title'>Energiemonitor</h2>"
        "<div class='tabs'>"
        "<button class='tab active' data-psub='en-verbrauch'>Energieverbrauch</button>"
        "<button class='tab' data-psub='en-einst'>Einstellungen</button>"
        "</div>"
        "<div class='page-sub active' id='psub-en-verbrauch'>"
        "<div class='info'>"
        "<div><span>CPU-Takt</span><span>"
    );
    w.write(String(getCpuFrequencyMhz()) + " MHz");
    w.write("</span></div><div><span>WLAN</span><span>");
    w.write(setupApActive ? "AP aktiv" : "AP aus");
    w.write("</span></div><div><span>USB-Host / Modem</span><span>");
    w.write(escapeHtml(modemStatusText()));
    w.write("</span></div><div><span>Kamera</span><span>");
    w.write(cameraReady ? "aktiv" : "aus");
    w.write(
        "</span></div>"
        "</div>"
        "<p class='cam-hint'>Nur real ablesbare Zustaende/Werte (kein Stromsensor - "
        "daher keine Watt-Angaben).</p>"
        "</div>"
        "<div class='page-sub' id='psub-en-einst'>"
        "<label for='en-cpu'>CPU-Leistungsprofil</label>"
        "<select id='en-cpu' class='cam-select cfg-select'>"
        "<option value='power'"
    );
    if (cpuProfile == "power") w.write(" selected");
    w.write(">Maximale Leistung (240 MHz)</option><option value='balanced'");
    if (cpuProfile == "balanced") w.write(" selected");
    w.write(">Ausgeglichen (160 MHz)</option><option value='eco'");
    if (cpuProfile == "eco") w.write(" selected");
    w.write(
        ">Energiesparen (80 MHz)</option>"
        "</select>"
        "<div class='info'><div><span>Aktueller CPU-Takt</span><span id='en-freq'>"
    );
    w.write(String(getCpuFrequencyMhz()) + " MHz");
    w.write(
        "</span></div></div>"
        "<label class='check-row'>"
        "<input id='en-wifioff' type='checkbox' name='wifioff' value='1'"
    );
    if (wifiOffOnMobile) w.write(" checked");
    w.write(
        ">"
        "<span>WLAN nach erfolgreicher Mobilfunkverbindung deaktivieren. Greift, sobald der "
        "ESP32 ueber das Modem online ist (PPP); bei fehlender SIM / ohne Mobilfunk bleibt "
        "WLAN als Fallback an (kein Aussperren).</span>"
        "</label>"
        "<button id='en-save' class='connect-button' type='button'>Uebernehmen</button>"
        "<p id='en-msg' class='scan-status'></p>"
        "<p class='cam-hint'>CPU-Takt wirkt sofort (kein Neustart). Automatisches DFS / "
        "Light-Sleep braucht einen IDF-Build und ist in diesem Arduino-Build nicht verfuegbar.</p>"
        "</div>"
        "</section>"
    );
    // --- Sicherheit (Geraete-PIN + Fernzugriff WAN) ---
    w.write(
        "<section id='tab-syssec' class='tab-panel'>"
        "<h2 class='section-title'>PIN</h2>"
        "<p class='cam-hint'>Die PIN schuetzt die Konfiguration und den "
        "Zugang zur Oberflaeche. Leer lassen deaktiviert die PIN "
        "vollstaendig (dann keine Abfrage mehr).</p>"
        "<form method='POST' action='/pin-change'>"
        "<label for='newpin'>Neue PIN</label>"
        "<div class='field-wrap'>"
        "<input id='newpin' class='has-inset' name='newpin' type='password' "
        "inputmode='numeric' autocomplete='off' placeholder='(leer = aus)'>"
        "<button id='np-eye' class='inset-button' type='button' "
        "aria-pressed='false' title='PIN anzeigen' "
        "aria-label='PIN anzeigen'>&#128065;</button>"
        "</div>"
        "<button class='connect-button' type='submit'>PIN speichern</button>"
        "</form>"

        "<h2 class='section-title'>Zugriff je Dienst</h2>"
        "<p class='cam-hint'>Aus dem LAN (WLAN/AP) sind alle Dienste immer erreichbar. Fuer VPN (IPsec-Tunnel) "
        "und Internet (Mobilfunk) gilt die Freigabe je Dienst; im Internet greift zusaetzlich der Schutz des "
        "Dienstes. Achtung: Wer die Weboberflaeche fuer seine eigene Zone sperrt, kommt nur noch ueber die "
        "serielle Konsole an das Geraet.</p>"
        "<form id='access-form'>"
    );
    {
        int n; const AccessService* s = accessServices(n);
        w.write("<table class='access-table'><tr><th>Dienst</th><th>im VPN</th><th>im Internet</th></tr>");
        for (int i = 0; i < n; i++) {
            uint8_t m = accessMask(s[i].id);
            w.write(String("<tr><td>") + s[i].label + "<br><small>Internet-Schutz: " + s[i].protection + "</small></td>"
                    "<td><input type='checkbox' name='" + s[i].id + "_vpn' value='1'" + ((m & ACCESS_VPN) ? " checked" : "") + "></td>"
                    "<td><input type='checkbox' name='" + s[i].id + "_inet' value='1'" + ((m & ACCESS_INTERNET) ? " checked" : "") + "></td></tr>");
        }
        w.write("</table>");
    }
    w.write(
        "<button class='connect-button' type='submit'>Uebernehmen</button>"
        "</form>"
        "<p id='access-msg' class='scan-status'></p>"

        // --- Transportverschluesselung (HTTP vs HTTPS) ---
        "<h2 class='section-title'>Transportverschluesselung</h2>"
        "<form id='webhttps-form'>"
        "<label class='check-row'>"
        "<input id='webhttps' type='checkbox' name='https' value='1'"
    );
    if (webHttpsEnabled) w.write(" checked");
    w.write(
        ">"
        "<span><strong>HTTPS</strong> fuer die Weboberflaeche (empfohlen). Ohne Haken laeuft "
        "die Verwaltung ueber <strong>HTTP</strong> &ndash; Anmeldung, Einstellungen und "
        "Sitzungsdaten gehen dann <strong>unverschluesselt</strong> ueber die Leitung. Nur in "
        "vertrauenswuerdigen Netzen oder innerhalb eines VPN verwenden.</span>"
        "</label>"
        "<p class='cam-hint'>Wirkt nach Neustart (der Server bindet Port 443 bzw. 80 beim Start). "
        "Aktuell wird ein <strong>self-signed</strong>-Zertifikat genutzt &ndash; der Browser zeigt "
        "einmalig eine Warnung, die du bestaetigst (automatische Zertifikate / ACME folgen). "
        "Startet HTTPS nicht, faellt das Geraet zur Sicherheit auf HTTP zurueck (nur ueber Mobilfunk "
        "erreichbar).</p>"
        "<button class='connect-button' type='submit'>Uebernehmen &amp; neu starten</button>"
        "</form>"
        "<p id='webhttps-msg' class='scan-status'></p>"
    );

    // --- Zertifikat (HTTPS): Herkunft waehlen -- self-signed / eigenes / Let's Encrypt ---
    // Horizontale Radios wie im Assistenten (radio-row/wiz-opt). Erste Ebene: eigenes vs. Let's
    // Encrypt; bei "eigenes" zweite Ebene: selbst erstellen vs. hochladen/eintragen. Das mappt
    // 1:1 auf CertSource {SelfSigned, Upload, Acme} im cert_store.
#if WEIRDOS_FEATURE_TLS_SERVER
    {
        CertSource src = certSource();
#if WEIRDOS_FEATURE_ACME
        const AcmeConfig& ac = acmeConfig();
        bool own = (src != CertSource::Acme);
#else
        bool own = true;   // ohne Let's-Encrypt-Client gibt es nur "eigenes Zertifikat" (self-signed / Upload)
#endif
        w.write(
            "<h2 class='section-title'>Zertifikat (HTTPS)</h2>"
#if WEIRDOS_FEATURE_ACME
            "<div class='info' id='acme-status'>"
            "<div><span>Aktiv</span><span id='ac-active'>-</span></div>"
            "<div><span>Let's-Encrypt-Zertifikat</span><span id='ac-cert'>-</span></div>"
            "<div><span>Systemzeit</span><span id='ac-clock'>-</span></div>"
            "<div><span>Port 80 (Challenge/Redirect)</span><span id='ac-port80'>-</span></div>"
            "<div><span>Letzter Lauf</span><span id='ac-last'>-</span></div>"
            "</div>"
#endif

            "<p class='cam-hint'>Woher kommt das Zertifikat fuer die verschluesselte Weboberflaeche?</p>"
            "<div class='radio-row'>"
            "<label class='wiz-opt' title='Selbst erstelltes ODER hochgeladenes Zertifikat -- ohne Internet-Abhaengigkeit.'>"
            "<input type='radio' name='certsrc' value='own'"
        );
        if (own) w.write(" checked");
        w.write(
            "><span>Eigenes Zertifikat</span></label>"
#if WEIRDOS_FEATURE_ACME
            "<label class='wiz-opt' title='Let&#39;s Encrypt: oeffentlich gueltig, keine Browserwarnung, automatische Erneuerung. Braucht Internet + Domain + Port 80.'>"
            "<input type='radio' name='certsrc' value='acme'"
        );
        if (!own) w.write(" checked");
        w.write(
            "><span>Let's Encrypt (automatisch)</span></label>"
#endif
            "</div>"

            // ===== Panel: Eigenes Zertifikat =====
            "<div id='cert-own'>"
            "<div class='radio-row'>"
            "<label class='wiz-opt'><input type='radio' name='certown' value='self'"
        );
        if (src == CertSource::SelfSigned) w.write(" checked");
        w.write(
            "><span>Selbst erstellen lassen</span></label>"
            "<label class='wiz-opt'><input type='radio' name='certown' value='upload'"
        );
        if (src == CertSource::Upload) w.write(" checked");
        w.write(
            "><span>Hochladen / eintragen</span></label>"
            "</div>"

            // --- self-signed ---
            "<div id='cert-self'>"
            "<div class='info'>"
            "<div><span>Zertifikat</span><span id='ss-sub'>-</span></div>"
            "<div><span>Gueltig bis</span><span id='ss-exp'>-</span></div>"
            "</div>"
            "<label class='check-row'><input id='ss-renew' type='checkbox'"
        );
        if (certSelfSignedRenew()) w.write(" checked");
        w.write(
            "><span>Automatisch erneuern, bevor es ablaeuft (das Geraet erzeugt bei &lt; 30 Tagen "
            "Restlaufzeit ein neues; wirkt nach dem naechsten Neustart).</span></label>"
            "<button id='ss-regen' class='cam-button' type='button'>Jetzt neu erzeugen</button>"
            "<p class='cam-hint'>Das Geraet erstellt sein eigenes Zertifikat. Die Verbindung ist verschluesselt, "
            "aber der Browser zeigt einmalig eine Warnung (keine oeffentliche CA). Ohne Internet nutzbar.</p>"
            "</div>"

            // --- Upload/Eintragen ---
            "<div id='cert-upload'>"
            "<label for='up-cert'>Zertifikat (PEM &ndash; Leaf zuerst, dann Zwischenzertifikate)</label>"
            "<textarea id='up-cert' rows='6' autocomplete='off' spellcheck='false' "
            "placeholder='-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----'></textarea>"
            "<label for='up-key'>Privater Schluessel (PEM)</label>"
            "<textarea id='up-key' rows='6' autocomplete='off' spellcheck='false' "
            "placeholder='-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----'></textarea>"
            "<div class='info'><div><span>Hinterlegt</span><span id='up-state'>-</span></div></div>"
            "<button id='up-save' class='connect-button' type='button'>Zertifikat pruefen &amp; speichern</button>"
            "<p class='cam-hint'>Zertifikat und Schluessel werden geprueft (Format + Zusammenpassen) und im Geraet "
            "gespeichert. Der Schluessel wird aus Sicherheitsgruenden nie wieder angezeigt. Erneuerung liegt bei dir "
            "(neu einspielen, bevor es ablaeuft).</p>"
            "</div>"
            "</div>"  // /cert-own

            // ===== Panel: Let's Encrypt =====
#if WEIRDOS_FEATURE_ACME
            "<div id='cert-acme'>"
            "<form id='acme-form'>"
            "<label for='acme-domain'>Domain</label>"
            "<input id='acme-domain' name='domain' type='text' autocomplete='off' autocapitalize='none' spellcheck='false' placeholder='"
        );
        w.write(escapeHtml(dyndnsDomain));
        w.write("' value='");
        w.write(escapeHtml(ac.domain));
        w.write(
            "'>"
            "<p class='cam-hint'>Leer = DynDNS-Domain (Dienste). Muss von aussen auf dieses Geraet zeigen; Let's Encrypt "
            "prueft <code>http://&lt;Domain&gt;/.well-known/acme-challenge/...</code> auf <strong>Port 80</strong> "
            "(oeffentliche IPv4 noetig, Telekom internet.t-d1.de).</p>"
            "<label for='acme-email'>Kontakt-E-Mail (Ablaufwarnungen von Let's Encrypt)</label>"
            "<input id='acme-email' name='email' type='email' autocomplete='off' value='"
        );
        w.write(escapeHtml(ac.email));
        w.write(
            "'>"
            "<label class='check-row'><input id='acme-staging' type='checkbox' name='staging' value='1'"
        );
        if (ac.staging) w.write(" checked");
        w.write(
            "><span>Staging-CA zum Testen (hohe Rate-Limits; Zertifikat ist im Browser NICHT gueltig). "
            "Erst mit Staging pruefen, dann abschalten -- Produktion erlaubt nur 5 Fehlversuche/Stunde.</span></label>"
            "<label class='check-row'><input id='acme-tos' type='checkbox' name='tos' value='1'"
        );
        if (ac.tos) w.write(" checked");
        w.write(
            "><span>Ich akzeptiere die <a href='https://letsencrypt.org/repository/' target='_blank' rel='noopener'>"
            "Nutzungsbedingungen von Let's Encrypt</a> (Pflicht fuer den Account).</span></label>"
            "<div class='cam-bar'>"
            "<button class='cam-button' type='submit'>Einstellungen speichern</button>"
            "<button id='acme-run' class='cam-button' type='button'>Zertifikat jetzt anfordern</button>"
            "<button id='acme-clear' class='cam-button' type='button'>Zertifikat loeschen</button>"
            "</div>"
            "</form>"
            "<p class='cam-hint'>Voraussetzungen: HTTPS oben aktiv, Systemzeit aus dem Mobilfunknetz "
            "(Uebersicht &rarr; System), DynDNS aktuell. Erneuerung laeuft danach automatisch, solange Internet "
            "besteht (taegliche Pruefung, &lt; 30 Tage Restlaufzeit).</p>"
            "</div>"  // /cert-acme
#endif // WEIRDOS_FEATURE_ACME (Let's-Encrypt-Panel)

            // ===== Uebernehmen (Herkunft aktiv schalten) =====
            "<button id='cert-apply' class='connect-button' type='button'>Auswahl uebernehmen</button>"
            "<p id='acme-msg' class='scan-status'></p>"
            "<p class='cam-hint'>Die gewaehlte Herkunft wird nach dem naechsten Neustart aktiv; das Geraet startet "
            "dafuer selbst neu, sobald kein Video-Zuschauer mehr verbunden ist.</p>"
            "</section>"
        );
    }
#else
    // HTTPS-Server nicht im Build (WEIRDOS_FEATURE_TLS_SERVER=0): kein Zertifikatsspeicher, keine
    // Herkunftswahl -- der Abschnitt bleibt sichtbar und nennt den Grund (keine ac-*/cert-*-IDs, kein
    // Poll; die Zertifikats-/ACME-Routen sind in der .ino ebenfalls abgeschaltet).
    w.write(
        "<h2 class='section-title'>Zertifikat (HTTPS)</h2>"
        "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0'>"
        "<p><strong>Der HTTPS-Server ist in diesem Build nicht enthalten (WEIRDOS_FEATURE_TLS_SERVER=0).</strong> "
        "Die Weboberflaeche laeuft ueber HTTP; der Baustein TLS_SERVER (HTTPS, self-signed-Zertifikat, eigenes "
        "Zertifikat, Let's Encrypt) wurde beim Bauen abgewaehlt. Fuer verschluesselten Fernzugriff bleibt der "
        "VPN-Tunnel (WireGuard/IPsec), sofern enthalten.</p></div>"
        "</section>"
    );
#endif // WEIRDOS_FEATURE_TLS_SERVER
    // --- Sicherung (Werksreset) ---
    w.write(
        "<section id='tab-backup' class='tab-panel'>"
        "<h2 class='section-title'>Sicherung</h2>"
#if WEIRDOS_FEATURE_BACKUP
        "<button id='cfg-export' class='cam-button' type='button'>Sicherung exportieren</button>"
        "<p class='cam-hint'>Vollstaendige Konfiguration (alle Bereiche, zentral aus dem NVS) als "
        "Datei <code>weirdos-backup.cfg</code> - <strong>OHNE</strong> Passwoerter/PIN/Keys (die nach "
        "einem Restore neu setzen).</p>"
        "<h2 class='section-title'>Wiederherstellen</h2>"
        "<label for='cfg-import-file'>Sicherungsdatei einspielen</label>"
        "<input id='cfg-import-file' type='file' accept='.cfg,text/plain'>"
        "<button id='cfg-import' class='cam-button' type='button' style='margin-top:8px'>"
        "Importieren &amp; neu starten</button>"
        "<p class='cam-hint'>Spielt die Werte zurueck in den Speicher und startet neu (noetig, damit "
        "alle Bereiche die Config frisch laden). Secrets bleiben leer -- danach neu setzen.</p>"
        "<p id='cfg-import-msg' class='scan-status'></p>"
#else
        // Sicherung nicht im Build (WEIRDOS_FEATURE_BACKUP=0): keine cfg-*-IDs (das Export/Import-JS
        // bleibt inaktiv), /settings-export|import sind in der .ino ebenfalls abgeschaltet.
        "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0'>"
        "<p><strong>Sicherung/Wiederherstellung ist in diesem Build nicht enthalten (WEIRDOS_FEATURE_BACKUP=0).</strong> "
        "Der Baustein BACKUP (Export/Import aller Einstellungen aus dem NVS, auch ueber die Konsole mit "
        "<code>backup</code>/<code>restore</code>) wurde beim Bauen abgewaehlt.</p></div>"
#endif // WEIRDOS_FEATURE_BACKUP
        "<h2 class='section-title'>Werksreset</h2>"
        "<form method='POST' action='/forget' "
        "onsubmit=\"return confirm('Alles auf Werkseinstellungen "
        "zuruecksetzen (WLAN, Kamera, Modem/APN, DynDNS, PIN)?');\">"
        "<button class='danger-button' type='submit'>"
        "Werksreset (WLAN, Kamera, Modem, DynDNS, PIN)"
        "</button>"
        "</form>"
        "</section>"
    );
}
