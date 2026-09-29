// ui_internet.cpp -- Content: Oberpunkt "WAN" (Modem-Einstellungen, Firewall & NAT) + Dienste/VPN.
//   WAN > Modem = EINE Seite mit allen Modem-Einstellungen (Tabs: Anschluss, Zugangsdaten, IPv6,
//   DNS-Server, Frequenzen). Modem-STATUS liegt in der Uebersicht (ui_overview.cpp),
//   Modem-DIAGNOSE (Funkwerte, Netzliste, SIM, Pipeline, AT-Konsole) unter Diagnose > Modem
//   (ui_diag.cpp). Online-Monitor ebenfalls in der Uebersicht.
#include "weirdos_features.h"   // WEIRDOS_FEATURE_WEBUI -- Seiten nur mit Weboberflaeche
#if WEIRDOS_FEATURE_WEBUI
#include "web_ui.h"
#include "peripheral_registry.h"   // periphModemPort + periphAvailablePorts (Anschluss-Dropdown)
#include "wireguard_service.h"     // WireGuard-Backend-Status (Stufe 7.3)
#include "ipsec_service.h"
#include "ipsec_runtime.h"   // peerPfsRejected(): Laufzeit-Befund der Gegenstelle (PFS-Hinweis)
#include "ipsec_crypto_caps.h"     // IKEv2-Richtlinie: Faehigkeitstabelle (ausgegraut = nicht implementiert)
#include "network_mode.h"          // Forwarding/NAPT-Wahl (unter Firewall & NAT verortet)

#if WEIRDOS_FEATURE_MODEM
// Datenschicht (PPP<->ECM) + Frequenzen sind HARDWARE-Steuerung des Modems (nicht die
// Einwahl) -> gehoeren auf die Modem-Seite. Datenschicht ist Body-only und Teil des Tabs
// "Anschluss" (renderMfAnschluss), Frequenzen ein eigener Tab (psub-mf-band).
static void renderMfDatalink(WeirdUiWriter& w) {
    w.write(
        "<p class='cam-hint'><strong>Datenschicht.</strong> <em>CDC-ECM</em> ist der Standard "
        "(Produktion): rohe Ethernet-Frames ueber USB statt PPP/HDLC -- weniger Overhead, IPv6-faehig, "
        "und im NIC-Modus bekommt der ESP die oeffentliche Mobilfunk-IP direkt. <em>PPP</em> bleibt "
        "als Kompatibilitaets-/Rueckfallpfad (kein IPv6). Der Wechsel schaltet das <strong>Modem</strong> "
        "per usbnet um und startet es neu (~15-30 s) - der ESP bleibt an. Aktuelle Verbindung "
        "wird dabei getrennt. Steht das Modem beim Start noch auf RNDIS (Auslieferung), stellt die "
        "Firmware es fuer ECM einmalig selbst um.</p>"
        "<p class='cam-hint'><strong>Erreichbarkeit von aussen (wichtig):</strong> der einfachste Weg "
        "ist ein APN mit <strong>oeffentlicher IPv4</strong> (o2 <code>netpublic</code>, Telekom "
        "<code>internet.t-d1.de</code>) - dann PPP + DynDNS-A, von jedem Client erreichbar. "
        "<strong>Telekom-Standard</strong> (<code>internet.telekom</code>) gibt nur CGNAT-IPv4 und "
        "ein IPv6, das <strong>eingehend netzseitig gefiltert</strong> wird (hardware-verifiziert) - "
        "damit KEIN Zugriff von aussen. IPv6-Inbound lohnt daher bei Telekom nicht; nimm den "
        "public-IPv4-APN. (IPv6 selbst geht nur ueber ECM, da PPP-IPv6 im Stack deaktiviert ist.)</p>"
        "<form id='datalink-form'>"
        "<label for='m-datamode'>Datenschicht</label>"
        "<select id='m-datamode' name='datamode' class='cam-select cfg-select'>"
        "<option value='ecm'");
    if (modemDataMode == "ecm") w.write(" selected");
    w.write(">CDC-ECM (Standard)</option><option value='ppp'");
    if (modemDataMode != "ecm") w.write(" selected");
    w.write(
        ">PPP (Kompatibilitaet)</option>"
        "</select>"
        // NIC-/Routing-Modus des Modem-NIC (AT+QCFG="nat"): nur fuer ECM relevant. NIC = die
        // oeffentliche WAN-IP liegt direkt am ESP (Erreichbarkeit von aussen, DynDNS sinnvoll);
        // Routing = Modem NATet, ESP bekommt 192.168.43.x per DHCP, KEIN Inbound.
        "<label for='m-natmode'>ECM-Betriebsart des Modem-NIC</label>"
        "<select id='m-natmode' name='natmode' class='cam-select cfg-select' data-orig='");
    w.write(modemNatMode == "routing" ? "routing" : "nic");
    w.write(
        "'>"
        "<option value='nic'");
    if (modemNatMode != "routing") w.write(" selected");
    w.write(">NIC - oeffentliche IP direkt am ESP (Standard, von aussen erreichbar)</option><option value='routing'");
    if (modemNatMode == "routing") w.write(" selected");
    w.write(
        ">Routing - Modem-NAT, ESP privat (192.168.43.x), kein Zugriff von aussen</option>"
        "</select>"
        "<p class='cam-hint'>Wirkt nur bei CDC-ECM; wird beim Umschalten mit dem Modem-Neustart "
        "uebernommen (persistent im Modem).</p>"
        "<button id='dl-save' class='connect-button' type='submit'>Datenschicht umschalten</button>"
        "</form>"
        "<p id='dl-msg' class='scan-status'></p>");
}

// Anschluss (ERSTER Tab): das physische Modem -- Freigabe des USB-Hosts (Enable-first-Prinzip:
// erster Eintrag entscheidet, ob das Modem ueberhaupt laeuft), USB-Port-Zuordnung (cellular0) und
// Datenschicht PPP/ECM. Frueher standen USB-Modem/Port mitten in den Zugangsdaten (Einwahl) --
// dort unpassend. Speichern laeuft ueber denselben /modem-save wie die Zugangsdaten (JS mBody()
// sammelt per ID, unabhaengig vom Tab); die Datenschicht hat ihren eigenen Umschalter
// (Modem-Neustart, datalink-form).
static void renderMfAnschluss(WeirdUiWriter& w) {
    w.write(
        "<div class='page-sub active' id='psub-mf-port'>"
        "<label class='check-row'>"
        "<input id='m-usben' type='checkbox' name='usben' value='1'"
    );
    if (modemUsbEnabled) w.write(" checked");
    w.write(
        ">"
        "<span><strong>USB-Modem aktiv.</strong> Mit Haken uebernimmt der ESP beim "
        "Boot den USB als Host - aber NUR, wenn kein PC am USB haengt. Ist ein PC "
        "angeschlossen, bleibt der Programmierport erhalten (normales Flashen ohne "
        "BOOT-Taste). Ohne Haken bleibt USB immer frei. Wirkt nach Neustart.</span>"
        "</label>"
        "<p id='m-usbhost' class='scan-status'></p>"
        "<label for='m-port'>USB-Port</label>"
        "<select id='m-port' name='port' class='cam-select cfg-select'>"
    );
    {
        String ports[4]; int n = periphAvailablePorts(ports, 4);
        for (int i = 0; i < n; i++) {
            w.write("<option value='");
            w.write(escapeHtml(ports[i]));
            w.write(ports[i] == periphModemPort ? "' selected>" : "'>");
            w.write(escapeHtml(ports[i]));
            w.write("</option>");
        }
    }
    w.write(
        "</select>"
        "<p class='cam-hint'>USB-Port, dem das Modem (<code>cellular0</code>) zugeordnet ist. "
        "Heute nur USB0; die Zuordnung wird in der Peripherie-Registry gespeichert.</p>"
        "<button id='m-save-port' class='connect-button' type='button'>Anschluss speichern</button>"
        "<p id='m-port-msg' class='scan-status'></p>"
        "<h2 class='section-title'>Datenschicht</h2>"
    );
    renderMfDatalink(w);
    w.write("</div>");   // /psub-mf-port
}

static void renderMfBand(WeirdUiWriter& w) {
    w.write(
        "<div class='page-sub' id='psub-mf-band'>"
        "<h2 class='section-title'>Mobilfunk-Frequenzen</h2>"
        "<form id='band-form'>"
        "<label for='b-netmode'>Netzmodus</label>"
        "<select id='b-netmode' name='netmode' class='cam-select cfg-select'>"
        "<option value='auto'");
    if (modemNetMode == "auto") w.write(" selected");
    w.write(">Automatisch</option><option value='lte'");
    if (modemNetMode == "lte") w.write(" selected");
    w.write(">Nur LTE (4G)</option><option value='gsm'");
    if (modemNetMode == "gsm") w.write(" selected");
    w.write(
        ">Nur 2G (GSM)</option>"
        "</select>"
        "<label for='b-profile'>Bandprofil</label>"
        "<select id='b-profile' name='profile' class='cam-select cfg-select'>"
        "<option value='auto'");
    if (modemBandProfile == "auto") w.write(" selected");
    w.write(">Automatisch (alle Baender)</option><option value='mid'");
    if (modemBandProfile == "mid") w.write(" selected");
    w.write(">1-2 GHz (niedrige Latenz)</option><option value='low'");
    if (modemBandProfile == "low") w.write(" selected");
    w.write(">unter 1 GHz (max. Reichweite)</option><option value='custom'");
    if (modemBandProfile == "custom") w.write(" selected");
    w.write(
        ">Benutzerdefiniert</option>"
        "</select>"
        "<p class='cam-hint'>Baender nur bei <em>Benutzerdefiniert</em> waehlbar. Band-Lock kann "
        "an Orten ohne dieses Band den Empfang verhindern. Anwenden trennt eine aktive Verbindung.</p>"
    );
    // Ehrlich zur Bandliste: das EC200A meldet seine Bandfaehigkeit nicht per AT (QCFG="band" liefert nur
    // die aktuelle Maske) -> keine dynamische Ausgrauung moeglich. Die Tabelle ist der komplette
    // LTE-Bandsatz der EU-Variante; bei einer anderen Variante (CN/AU) warnen.
    {
        String ati = modemRfAti; ati.toUpperCase();
        bool isEc200a = ati.indexOf("EC200A") >= 0;
        bool isEu     = ati.indexOf("EC200AEU") >= 0;
        w.write("<p class='cam-hint'>Bandliste = kompletter LTE-Bandsatz der <strong>EC200A-EU</strong>-Variante "
                "(FDD B1/B3/B5/B7/B8/B20/B28, TDD B38/B40/B41; 2G 900/1800). Das Modem meldet seine "
                "Bandfaehigkeit nicht per AT, daher keine dynamische Ausgrauung. ");
        if (isEc200a && !isEu)
            w.write("<strong style='color:#b02a37'>Achtung: erkannte Variante ist nicht EU -- der Bandsatz weicht ab, "
                    "unbekannte Baender lehnt das Modem beim Anwenden ab.</strong>");
        else if (!isEc200a)
            w.write("Variante noch nicht erkannt (Uebersicht &rarr; Mobilfunkdaten abrufen).");
        else
            w.write("Erkannte Variante: EC200A-EU - Liste passt.");
        w.write("</p>");
    }
    w.write(
        "<div id='band-list' style='display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin:8px 0'>");
    {
        uint64_t bm = modemProfileLteMask();
        for (int i = 0; i < LTE_BAND_N; i++) {
            w.write(
                "<label style='display:flex;align-items:center;gap:5px;font-size:13px;"
                "border:1px solid #dfe3e8;border-radius:6px;padding:6px'>"
                "<input type='checkbox' class='b-band' value='");
            w.write(String(LTE_BANDS[i].bit));
            w.write("'");
            if (bm & (1ULL << LTE_BANDS[i].bit)) w.write(" checked");
            w.write("><span>B");
            w.write(String(LTE_BANDS[i].num));
            w.write("<br><small style='color:#6b7280'>");
            w.write(String(LTE_BANDS[i].mhz));
            w.write(LTE_BANDS[i].tdd ? " MHz TDD" : " MHz");
            w.write("</small></span></label>");
        }
    }
    w.write(
        "</div>"
        "<button id='b-save' class='connect-button' type='submit'>Bandwahl uebernehmen</button>"
        "</form>"
        "<p id='b-msg' class='scan-status'></p>"
        "<button id='b-scan' class='cam-button' type='button' style='margin-top:4px'>"
        "Beste Signalqualitaet ermitteln (SINR-Scan)</button>"
        "<p class='cam-hint'>Sperrt nacheinander jedes gewaehlte Band, misst SINR (Median) und lockt "
        "das beste. Dauert ~1-2 min und trennt eine aktive Verbindung. Behebt, dass das Modem auf "
        "einem Band mit gutem Pegel aber schlechtem SINR campt (z.B. B8/SINR 1 statt B20/SINR 9).</p>"
        "<div id='scan-out' class='info' style='margin-top:6px'></div>"
        "<p id='scan-msg' class='scan-status'></p>"
        "</div>");
}
#endif // WEIRDOS_FEATURE_MODEM (Modem-Tabs)

void renderInternet(WeirdUiWriter& w) {
    // Online-Monitor lebt jetzt in der Uebersicht (renderOverview); die om-* IDs
    // und der /modem-status.json-Poll sind unveraendert dorthin gewandert.
    // --- WAN > Modem: ALLE Modem-EINSTELLUNGEN auf einer Seite (Tabs): Zugangsdaten (frueher
    //     "Einstellungen" auf einer eigenen Seite "Zugangsdaten"), IPv6, DNS, Datenschicht,
    //     Frequenzen. Status/Infos liegen bewusst NICHT hier: Modell/Betreiber/IPs in der
    //     Uebersicht, Funkwerte/Netzliste/SIM/Pipeline unter Diagnose > Modem.
    w.write(
        "<section id='tab-mobilfunk' class='tab-panel'>"
        "<h2 class='section-title'>Netzzugang</h2>"
        // Generalisiertes WAN + Internet-Check (Klassen werden vom Uebersichts-Poll-Script aktualisiert).
        "<div class='info' style='margin-bottom:10px'>"
        "<div><span>Internet (WAN)</span><span class='js-wan-inet'>pruefe...</span></div>"
        "<div><span>WAN-Interface</span><span class='js-wan-if'>-</span></div>"
        "</div>"
    );
    // 1) Zugang waehlen (WanPolicy, Radiogruppe wie im Assistenten) + aktueller Zustand.
    renderWanAccessChoice(w);
    // 2) Einstellungen des gewaehlten Zugangs. Mobilfunk = die Modem-Tabs; WLAN-Client = Verweis auf
    //    LAN > WLAN (dort liegen SSID/Schluessel); Ethernet ist nicht waehlbar (kein PHY).
    //    JS blendet per data-wanview den passenden Block ein (Vorschau beim Umschalten der Radios).
    w.write(
        "<div data-wanview='wifi' style='display:none'>"
        "<h2 class='section-title'>WLAN-Client</h2>"
        "<div class='info'>"
        "<div><span>Zugangsdaten</span><span>LAN &rarr; WLAN &rarr; Funknetz</span></div>"
        "<div><span>Technisches Interface</span><span>wifi-sta</span></div>"
        "</div>"
        "<p class='cam-hint'>Das Geraet haengt sich als Client in ein vorhandenes WLAN. SSID und Schluessel "
        "pflegst du unter <strong>LAN &rarr; WLAN</strong> (Client-Modus einschalten). Die Modem-Einstellungen "
        "bleiben erhalten, das Modem dient dann als Rueckfall.</p>"
        "</div>"
    );
#if WEIRDOS_FEATURE_MODEM
    w.write(
        "<div data-wanview='cellular'>"
        "<h2 class='section-title'>Mobilfunk (Modem)</h2>"
        "<div class='tabs'>"
        "<button class='tab active' data-psub='mf-port'>Anschluss</button>"
        "<button class='tab' data-psub='zug-einst'>Zugangsdaten</button>"
        "<button class='tab' data-psub='zug-ipv6'>IPv6</button>"
        "<button class='tab' data-psub='zug-dns'>DNS-Server</button>"
        "<button class='tab' data-psub='mf-band'>Frequenzen</button>"
        "</div>"
    );
    renderMfAnschluss(w);   // erster Tab: USB-Modem aktiv, USB-Port, Datenschicht
    w.write(
        "<div class='page-sub' id='psub-zug-einst'>"
        "<form id='modem-form'>"
        // (Die fruehere "Zugangsart konfigurieren"-Radiogruppe ist entfallen: die Wahl des Netzzugangs
        //  steht jetzt EINMAL oben auf der Seite = WanPolicy. Hier nur noch die Mobilfunk-Einwahl.)
        "<label for='m-provider'>Anbieter-Profil</label>"
        "<select id='m-provider' class='cam-select cfg-select'>"
        "<option value=''>Benutzerdefiniert (Felder frei)</option>"
        "<option value='o2'>o2 / Telefonica (internet)</option>"
        "<option value='o2netpublic'>o2 netpublic - oeffentl. IPv4 (kostenpflichtig)</option>"
        "<option value='telekom'>Telekom (internet.telekom)</option>"
        "<option value='vodafone'>Vodafone (web.vodafone.de)</option>"
        "</select>"
        "<p id='m-provider-hint' class='cam-hint'></p>"
        "<label for='m-simpin'>SIM-PIN (nur falls SIM gesperrt)</label>"
        "<input id='m-simpin' name='simpin' type='password' autocomplete='off' inputmode='numeric' placeholder='");
    w.write(modemSimPin.length() ? "gesetzt - leer lassen zum Behalten" : "keine / leer lassen");
    w.write(
        "' value=''>"
        "<p class='cam-hint'>Nur noetig, wenn die SIM eine PIN verlangt. Wird beim Verbindungsaufbau (PPP wie ECM) "
        "nur bei gesperrter SIM angewandt (AT+CPIN) und hoechstens <strong>einmal je Start</strong> gesendet -- "
        "ein abgelehnter Versuch wird nicht wiederholt (drei Fehlversuche wuerden die SIM sperren, PUK). "
        "PIN-lose SIMs bleiben unberuehrt. Leer = unveraendert.</p>"
        "<label class='check-row'><input type='checkbox' name='simpinclear' value='1'>"
        "<span>Gespeicherte SIM-PIN loeschen (wenn die Karte keine PIN mehr verlangt)</span></label>"
        "<label for='m-apn'>APN</label>"
        "<input id='m-apn' name='apn' type='text' autocomplete='off' "
        "autocapitalize='none' autocorrect='off' spellcheck='false' "
        "placeholder='internet' value='"
    );
    w.write(escapeHtml(modemApn));
    w.write(
        "'>"
        "<label for='m-dialnum'>Einwahlnummer</label>"
        "<input id='m-dialnum' name='dialnum' type='text' autocomplete='off' autocapitalize='none' "
        "autocorrect='off' spellcheck='false' placeholder='*99***1#' value='");
    w.write(escapeHtml(modemDialNumber));
    w.write(
        "'>"
        "<p class='cam-hint'><strong>Nur PPP.</strong> Einwahl (<code>ATD&lt;nummer&gt;</code>); bei CDC-ECM gibt es "
        "keine Einwahl (Datenkanal per QNETDEVCTL). Standard <code>*99***1#</code> "
        "passt fuer praktisch alle LTE/GPRS-Modems; nur in Sonderfaellen aendern.</p>"
        "<label for='m-user'>Benutzer (optional)</label>"
        "<input id='m-user' name='user' type='text' autocomplete='off' "
        "autocapitalize='none' autocorrect='off' spellcheck='false' value='"
    );
    w.write(escapeHtml(modemUser));
    w.write(
        "'>"
        "<label for='m-pass'>Passwort (optional)</label>"
        "<div class='field-wrap'>"
        "<input id='m-pass' class='has-inset' name='pass' type='password' "
        "autocomplete='off' value='"
    );
    w.write(escapeHtml(modemPass));
    w.write(
        "'>"
        "<button id='m-pass-eye' class='inset-button' type='button' "
        "aria-pressed='false' title='Passwort anzeigen' "
        "aria-label='Passwort anzeigen'>&#128065;</button>"
        "</div>"
        "<label for='m-pdp'>PDP-Typ</label>"
        "<select id='m-pdp' name='pdp' class='cam-select cfg-select'>"
        "<option value='IP'"
    );
    if (modemPdpType != "IPV4V6") w.write(" selected");
    w.write(
        ">IPv4 (IP)</option>"
        "<option value='IPV4V6'"
    );
    if (modemPdpType == "IPV4V6") w.write(" selected");
    w.write(
        ">IPv4+IPv6 (IPV4V6)</option>"
        "</select>"
        "<label for='m-auth'>Authentifizierung</label>"
        "<select id='m-auth' name='auth' class='cam-select cfg-select'>"
        "<option value='0'"
    );
    if (modemAuth == "0") w.write(" selected");
    w.write(">Keine</option><option value='1'");
    if (modemAuth == "1") w.write(" selected");
    w.write(">PAP</option><option value='2'");
    if (modemAuth == "2") w.write(" selected");
    w.write(
        ">CHAP</option>"
        "</select>"
        "<p class='cam-hint'>Benutzer, Passwort und Authentifizierung (PAP/CHAP) werden jetzt tatsaechlich "
        "auf die PPP-Verbindung angewandt. Die meisten Mobilfunk-APNs brauchen <em>keine</em> Auth (Keine).</p>"
        "<label class='check-row'>"
        "<input id='m-autostart' type='checkbox' name='autostart' value='1'"
    );
    if (modemAutoStart) w.write(" checked");
    w.write(
        ">"
        "<span><strong>Automatisch verbinden.</strong> WeirdOS baut den ausgewaehlten "
        "Datenpfad (PPP oder ECM) beim Boot selbst auf und haelt ihn per Auto-Retry "
        "hoch - rein controllerseitig, es wird nichts ins Modem geschrieben.</span>"
        "</label>"
        "<label class='check-row'>"
        "<input id='m-auto' type='checkbox' name='autoconnect' value='1'"
    );
    if (modemAutoconnect) w.write(" checked");
    w.write(
        ">"
        "<span><strong>Autoconnect im Modem speichern (nur PPP; derzeit nur vorgemerkt, noch nicht ins "
        "Modem geschrieben).</strong> Bei CDC-ECM ist der Datenkanal ohnehin persistent (QNETDEVCTL=3). Persistente Auto-Dial-"
        "Einstellung im <strong>Modem-Flash</strong> (sofern Modem/Verfahren das "
        "unterstuetzen) - unabhaengig von 'Automatisch verbinden'. Ohne Haken wird sie "
        "im Modem wieder deaktiviert.</span>"
        "</label>"
        // (USB-Modem aktiv + USB-Port: Tab "Anschluss", renderMfAnschluss)
        "<button id='m-save' class='connect-button' type='submit'>"
        "Einstellungen speichern"
        "</button>"
        "</form>"

        "<h2 class='section-title'>Verbindung</h2>"
        "<div class='cam-bar'>"
        "<button id='m-connect' class='cam-button' type='button'>Verbinden</button>"
        "<button id='m-disconnect' class='cam-button' type='button'>Trennen</button>"
        "<button id='m-test' class='cam-button' type='button'>Internet testen</button>"
        "<button id='m-reset' class='cam-button' type='button'>Modem neu starten</button>"
        "</div>"
        "<p id='modem-msg' class='scan-status'></p>"

        // --- SIM-PIN-Sperre auf der KARTE (AT+CLCK/CPWD; modem_sim.*). Nur bei getrennter Verbindung.
        "<h2 class='section-title'>SIM-PIN-Sperre (auf der Karte)</h2>"
        "<p class='cam-hint'>Aendert die PIN-Sperre der SIM selbst: aktivieren (Karte verlangt kuenftig eine PIN), "
        "deaktivieren (Karte ohne PIN nutzbar) oder PIN aendern. Nur bei <strong>getrennter</strong> Verbindung. "
        "Nach Aktivieren/Aendern speichert WeirdOS die PIN automatisch fuer den Verbindungsaufbau; beim "
        "Deaktivieren wird die gespeicherte PIN geloescht. Drei falsche Versuche sperren die SIM (dann nur noch "
        "mit PUK am Telefon/PC entsperrbar).</p>"
        "<div class='info'>"
        "<div><span>Status</span><span id='sp-status'>- (Status abfragen)</span></div>"
        "<div><span>Verbleibende Versuche (PIN / PUK)</span><span id='sp-left'>-</span></div>"
        "</div>"
        "<div class='cam-bar'>"
        "<select id='sp-action' class='cam-select' aria-label='Aktion'>"
        "<option value='enable'>Sperre aktivieren</option>"
        "<option value='disable'>Sperre deaktivieren</option>"
        "<option value='change'>PIN aendern</option>"
        "</select>"
        "<input id='sp-pin' type='password' inputmode='numeric' autocomplete='off' placeholder='PIN' style='max-width:110px'>"
        "<input id='sp-newpin' type='password' inputmode='numeric' autocomplete='off' placeholder='neue PIN' style='max-width:110px;display:none'>"
        "<button id='sp-run' class='cam-button' type='button'>Ausfuehren</button>"
        "<button id='sp-refresh' class='cam-button' type='button'>Status abfragen</button>"
        "</div>"
        "<p id='sp-msg' class='scan-status'></p>"
        "</div>"   // /psub-zug-einst
        "<div class='page-sub' id='psub-zug-ipv6'>"
        "<p class='cam-hint'>IPv6 wird nur aktiv, wenn im Tab Zugangsdaten der PDP-Typ auf "
        "<strong>IPv4+IPv6 (IPV4V6)</strong> steht. Die zugewiesene WAN-IPv6 erscheint dann in der "
        "Uebersicht (Mobilfunk: IPv6). Das Netz vergibt die IPv6-Parameter - "
        "eigene Einstellungen sind beim Mobilfunk-Pfad in der Regel nicht noetig.</p>"
        "<p class='cam-hint'><strong>Wichtig:</strong> IPv6 funktioniert technisch nur mit Datenschicht "
        "<strong>CDC-ECM</strong> (ueber PPP ist IPv6 im Stack deaktiviert). ABER bei <strong>Telekom "
        "wird eingehendes IPv6 netzseitig gefiltert</strong> (hardware-verifiziert) - eine globale "
        "IPv6 macht die Kamera dort NICHT von aussen erreichbar. Fuer Erreichbarkeit bei Telekom "
        "stattdessen den public-IPv4-APN <code>internet.t-d1.de</code> nehmen (Tab Zugangsdaten), "
        "nicht IPv6.</p>"
        "</div>"
        "<div class='page-sub' id='psub-zug-dns'>"
        "<p class='cam-hint'>Die DNS-Server werden vom Mobilfunknetz per PPP automatisch zugewiesen "
        "(usepeerdns) - deshalb funktioniert die Namensaufloesung ueber das Modem sofort. Eigene "
        "DNS-Server (z.B. 1.1.1.1 / 8.8.8.8) sind hier bewusst nicht ueberschrieben.</p>"
        "</div>"   // /psub-zug-dns
    );
    // Frequenzen: eigener Tab. (Datenschicht liegt im Tab "Anschluss" -- renderMfAnschluss --, NICHT
    // hier noch einmal: als Body-only-Block wuerde sie sonst tab-unabhaengig unten doppelt erscheinen.
    // Die frueheren Info-Tabs Uebersicht/Mobilfunk/Netzliste/SIM-Karte liegen in der Uebersicht bzw.
    // unter Diagnose > Modem.)
    renderMfBand(w);
    w.write(
        "</div>"       // /data-wanview=cellular
    );
#else
    // Mobilfunk nicht im Build (WEIRDOS_FEATURE_MODEM=0): der Block bleibt (das JS blendet ihn per
    // data-wanview ein), nennt aber nur den Grund -- keine mf-*-IDs, keine Modem-Formulare, kein Poll
    // der Modem-Routen (die sind in der .ino ebenfalls unter WEIRDOS_FEATURE_MODEM).
    w.write(
        "<div data-wanview='cellular'>"
        "<h2 class='section-title'>Mobilfunk (Modem)</h2>"
        "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0'>"
        "<p><strong>Mobilfunk ist in diesem Build nicht enthalten (WEIRDOS_FEATURE_MODEM=0).</strong> Der Baustein MODEM "
        "(EC200A am USB-Host: Zugangsdaten, Datenschicht PPP/ECM, Frequenzen, SIM) wurde beim Bauen abgewaehlt. "
        "Als Internetzugang bleibt der WLAN-Client (LAN &rarr; WLAN), sofern der Baustein WIFI enthalten ist.</p></div>"
        "</div>"
    );
#endif // WEIRDOS_FEATURE_MODEM
    w.write("</section>");   // /tab-mobilfunk
    // --- Firewall & NAT (frueher 'Freigaben'; DynDNS lebt jetzt unter Dienste) ---
    w.write(
        "<section id='tab-freigaben' class='tab-panel'>"
        "<h2 class='section-title'>Firewall &amp; NAT</h2>"
        "<p class='cam-hint'>Dieses Geraet ist ein <strong>Endpunkt</strong>, kein Router mit "
        "LAN-Clients - klassische Portfreigaben (NAT-Forwarding) entfallen daher. Bei oeffentlicher "
        "WAN-IP ist die Kamera direkt erreichbar (Web-Port 80, Stream-Port konfigurierbar/Default 81, "
        "PIN-geschuetzt); dynamische "
        "IPs deckt DynDNS (unter Dienste) ab. Die WAN-Sichtbarkeit schaltest du unter System -&gt; Sicherheit.</p>"

        // --- Forwarding/NAPT: WAN<->LAN-Weiterleitung (frueher in der Betriebsart) ---
        "<h2 class='section-title'>Forwarding (NAPT)</h2>"
        "<p class='cam-hint'>Legt fest, ob LAN-/AP-Clients ueber den WAN-Uplink ins Internet geroutet "
        "werden. <strong>NAPT</strong> ersetzt dabei ihre privaten Absenderadressen durch die WAN-IP "
        "(Masquerading) - noetig fuer den Router-/Repeater-Betrieb. Heute rein gespeichert; die "
        "Laufzeit-Umschaltung schaltet der Betriebsart-Assistent scharf.</p>"
        "<form action='/wan-forwarding-save' method='POST'>"
        "<label for='fw-fwd'>Forwarding</label>"
        "<select id='fw-fwd' name='fwd' class='cam-select cfg-select'>");
    {
        const NetworkModeConfig& c = networkMode.config();
        w.write(c.forwarding != "napt"
            ? "<option value='none' selected>Kein Forwarding (kein Internet am AP)</option>"
            : "<option value='none'>Kein Forwarding (kein Internet am AP)</option>");
        w.write(c.forwarding == "napt"
            ? "<option value='napt' selected>NAPT (Router: AP-Clients ins WAN)</option>"
            : "<option value='napt'>NAPT (Router: AP-Clients ins WAN)</option>");
    }
    w.write(
        "</select>"
        "<button class='connect-button' type='submit'>Forwarding speichern</button>"
        "</form>"
        "</section>"
    );
}

// Content: Oberpunkt "Dienste" - nur noch DynDNS (funktional). WireGuard + IPsec sind
// nach 7.7 in die eigene VPN-Seite (renderVpn, Tabs) gewandert.
// DynDNS-Endpoints (/dyndns-save, /dyndns-status.json, /dyndns-update), IDs (dyn-*)
// und NVS unveraendert. Domain/User/Pass bleiben Teil der generischen Provider-Config.
void renderDienste(WeirdUiWriter& w) {
    w.write(
        "<section id='tab-dienste' class='tab-panel'>"
        "<div class='page-sub active' id='psub-svc-dyndns'>"
        "<h2 class='section-title'>DynDNS</h2>"
#if !WEIRDOS_FEATURE_DYNDNS
        // DynDNS nicht im Build: die /dyndns-*-Routen fehlen (in der .ino unter WEIRDOS_FEATURE_DYNDNS); das
        // Formular bleibt sichtbar, weil dieselben Felder (Domain) auch fuer Zertifikate/ACME gelten.
        "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0'>"
        "<p><strong>Der DynDNS-Updater ist in diesem Build nicht enthalten (WEIRDOS_FEATURE_DYNDNS=0).</strong> "
        "Die Felder unten werden nicht an einen Anbieter gemeldet; Speichern und &quot;Jetzt aktualisieren&quot; "
        "sind ohne Funktion.</p></div>"
#endif
        "<form id='dyn-form'>"
        "<label class='check-row'>"
        "<input id='dyn-enabled' type='checkbox' name='enabled' value='1'"
    );
    if (dyndnsEnabled) w.write(" checked");
    w.write(
        ">"
        "<span>DynDNS aktiv</span>"
        "</label>"
        "<label for='dyn-egress'>Ausgehendes Netz</label>"
        "<select id='dyn-egress' name='egress' class='cam-select cfg-select'>"
        "<option value='auto'"
    );
    if (dyndnsEgress != "modem" && dyndnsEgress != "wifi") w.write(" selected");
    w.write(">Automatisch (Mobilfunk bevorzugt)</option><option value='modem'");
    if (dyndnsEgress == "modem") w.write(" selected");
    w.write(">Mobilfunk-WAN (ECM/PPP)</option><option value='wifi'");
    if (dyndnsEgress == "wifi") w.write(" selected");
    w.write(
        ">WLAN-STA</option>"
        "</select>"
        "<p class='cam-hint'>Bestimmt, ueber welches Netzwerk der Update-Request rausgeht - der "
        "Anbieter sieht dessen Quell-IP. <strong>Mobilfunk-WAN</strong> veroeffentlicht die "
        "Mobilfunk-IP (fuer Erreichbarkeit von aussen); <strong>WLAN-STA</strong> die Heim-/Router-IP.</p>"
        "<label for='dyn-provider'>DynDNS-Anbieter</label>"
        "<select id='dyn-provider' name='provider' class='cam-select cfg-select'>"
        "<option value='custom'"
    );
    if (dyndnsProvider == "custom") w.write(" selected");
    w.write(
        ">Benutzerdefiniert</option>"
        "</select>"
        "<p class='cam-hint'>Geben Sie die Anmeldedaten fuer Ihren DynDNS-Anbieter an.</p>"
        "<label for='dyn-url'>Update-URL</label>"
        "<input id='dyn-url' name='url' type='text' autocomplete='off' autocapitalize='none' "
        "autocorrect='off' spellcheck='false' "
        "placeholder='https://...&myip=<ipaddr>&myipv6=<ip6addr>' value='"
    );
    w.write(escapeHtml(dyndnsUrl));
    w.write(
        "'>"
        "<label for='dyn-domain'>Domainnamen</label>"
        "<input id='dyn-domain' name='domain' type='text' autocomplete='off' autocapitalize='none' "
        "autocorrect='off' spellcheck='false' placeholder='meinname.example.de' value='"
    );
    w.write(escapeHtml(dyndnsDomain));
    w.write(
        "'>"
        "<label for='dyn-user'>Benutzername</label>"
        "<input id='dyn-user' name='user' type='text' autocomplete='off' autocapitalize='none' "
        "autocorrect='off' spellcheck='false' value='"
    );
    w.write(escapeHtml(dyndnsUser));
    w.write(
        "'>"
        "<label for='dyn-pass'>Kennwort</label>"
        "<div class='field-wrap'>"
        // Kennwort NICHT vorbelegen (nie im Klartext an den Browser). Leeres
        // Feld = unveraendert lassen (siehe handleDyndnsSave).
        "<input id='dyn-pass' class='has-inset' name='pass' type='password' autocomplete='off' "
        "value=''>"
        "<button id='dyn-eye' class='inset-button' type='button' aria-pressed='false' "
        "title='Kennwort anzeigen' aria-label='Kennwort anzeigen'>&#128065;</button>"
        "</div>"
    );
    if (dyndnsPass.length() > 0) {
        w.write("<p class='cam-hint'>Kennwort gespeichert.</p>");
    }
    w.write(
        "<button class='connect-button' type='submit'>Uebernehmen</button>"
        "</form>"
        "<div class='info' style='margin-top:12px'>"
        "<div><span>Status</span><span id='dyn-status'>-</span></div>"
        "<div><span>Gemeldete IP</span><span id='dyn-ip'>-</span></div>"
        "</div>"
        "<button id='dyn-now' class='cam-button' type='button' style='margin-top:8px'>"
        "Jetzt aktualisieren</button>"
        "<p id='dyn-msg' class='scan-status'></p>"
        "</div>"   // /psub-svc-dyndns
        "</section>"
    );
}

// 7.9: VPN-SERVER-Seite (Menue: Server > VPN). Die MCU stellt ein WireGuard-VPN bereit.
// "VPN-Server aktivieren" klappt den Konfig-Bereich auf/zu (FritzBox-Stil, JS). Client-Rolle
// ist eine eigene Seite (renderVpnClient, Menue: Dienste > VPN); beide teilen sich das Backend.
void renderVpnServer(WeirdUiWriter& w) {
    w.write(
        "<section id='tab-vpn-srv' class='tab-panel'>"
        "<div class='tabs'>"
        "<button class='tab active' data-psub='vpnsrv-wg'>WireGuard</button>"
        "<button class='tab' data-psub='vpnsrv-ipsec'>IPsec</button>"
        "</div>"

        // --- WireGuard-Server: Status + Konfiguration + Lifecycle ---
        "<div class='page-sub active' id='psub-vpnsrv-wg'>"
        "<h2 class='section-title'>WireGuard-Server</h2>"
        "<div class='info'>"
        "<div><span>Backend</span><span>"
    );
    w.write(wireguardService.backendAvailable() ? "eingebunden" : "nicht im Build");
    // Status (verbunden/wartet/Fehler, Underlay, Tunnel-IP, Peer) steht NUR noch auf der Uebersicht
    // (VPN-Tabelle, /vpn-status.json) -- hier nur Konfiguration + Werkzeuge.
    w.write("</span></div></div>");

    {
        const WireGuardConfig& wg = wireguardService.config();
        bool srvActive = wg.active && wg.mode != "client";
        bool cliBlocks = wg.active && wg.mode == "client";   // WireGuard laeuft als Client -> Server gesperrt
        // Das vendored WireGuard-Backend ist EINE Instanz: es kann nur Server ODER Client gleichzeitig.
        if (cliBlocks) w.write(
            "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0'>"
            "<p><strong>WireGuard laeuft derzeit als Client.</strong> Server und Client koennen nicht gleichzeitig "
            "laufen (ein Funk-/Krypto-Backend). Um den Server zu nutzen, zuerst unter <strong>Dienste &rarr; VPN</strong> "
            "den WireGuard-Client deaktivieren.</p></div>");
        // --- Aktivieren-Schalter (klappt #wg-srv-cfg auf/zu, JS) ---
        w.write(cliBlocks ? "<div class='fields-inactive'><form id='wg-form'>" : "<form id='wg-form'>");
        w.write(
            "<input type='hidden' name='mode' value='server'>"
            "<label class='check-row big-toggle'>"
            "<input id='wg-active' type='checkbox' name='active' value='1'"
        );
        if (srvActive) w.write(" checked");
        if (cliBlocks) w.write(" disabled");
        w.write(
            "><span><strong>VPN-Server aktivieren</strong> - die MCU stellt ein WireGuard-VPN "
            "bereit, in das sich Handy/PC von aussen einwaehlen.</span></label>"

            // Konfig-Bereich, per JS ein-/ausgeblendet je nach Schalter
            "<div id='wg-srv-cfg'"
        );
        if (!srvActive) w.write(" style='display:none'");
        w.write(
            ">"
            // --- Zugriff der Clients auf andere Netze: seit Netzzonen Phase 1 ausschliesslich ueber die
            //     Zonen-Policies (LAN > Netzzonen). Die alte Option "LAN-Gateway" wurde beim ersten Start
            //     automatisch in die Policy "WireGuard-Clients -> Heimnetz" migriert (zone_runtime.cpp).
            "<p class='cam-hint'><strong>Zugriff der Clients auf Heimnetz / IPsec-VPN / andere Netze:</strong> "
            "unter <a href='#/zones'>LAN &rarr; Netzzonen</a> je Verbindung erlauben oder trennen. Das Geraet richtet "
            "Route und NAT selbst ein und nimmt die Ziel-Netze automatisch in die AllowedIPs neu erzeugter "
            "Client-Konfigurationen auf. (Die fruehere Option &quot;LAN-Gateway&quot; ist dorthin migriert.)</p>"

            // --- Erweitert: aufklappbar, normal nicht noetig. Tunnel-IP/Schluessel werden
            //     automatisch vergeben; Endpoint nur fuer Client-Modus. ---
            "<details class='wg-adv'>"
            "<summary>Erweitert (Schluessel, Port, Routing - normal nicht noetig)</summary>"
            "<p class='cam-hint'>MCU-Schluessel wird automatisch erzeugt, Tunnel-IP ist vorbelegt - "
            "normal hier nichts noetig, einfach unten &quot;Geraet hinzufuegen&quot;.</p>"
            "<label for='wg-underlay'>Underlay</label>"
            "<select id='wg-underlay' name='underlay' class='cam-select cfg-select'>"
            "<option value='auto'"
        );
        if (wg.underlay != "modem" && wg.underlay != "wifi") w.write(" selected");
        w.write(">Automatisch (Mobilfunk bevorzugt)</option><option value='modem'");
        if (wg.underlay == "modem") w.write(" selected");
        w.write(">Mobilfunk-WAN (ECM/PPP)</option><option value='wifi'");
        if (wg.underlay == "wifi") w.write(" selected");
        w.write(
            ">WLAN-STA</option></select>"
            "<label for='wg-localip'>Tunnel-IP (lokal, Default 10.9.0.1)</label>"
            "<input id='wg-localip' name='localip' type='text' autocomplete='off' autocapitalize='none' "
            "autocorrect='off' spellcheck='false' placeholder='10.9.0.1' value='"
        );
        w.write(escapeHtml(wg.localIp));
        w.write(
            "'>"
        );
        writeSecretField(w, "wg-privkey", "privkey", "Private Key (leer = automatisch)", "",
                         wireguardService.privateKeySet(), wireguardService.privateKeyLength(), "wird beim Verbinden automatisch erzeugt");
        w.write(
            "<label for='wg-peerpub'>Zugelassenes Client-Geraet (Public Key) - via 'Geraet hinzufuegen'</label>"
            "<input id='wg-peerpub' name='peerpub' type='text' autocomplete='off' autocapitalize='none' "
            "autocorrect='off' spellcheck='false' value='"
        );
        w.write(escapeHtml(wg.peerPublicKey));
        w.write(
            "'>"
        );
        writeSecretField(w, "wg-psk", "psk", "Preshared Key (optional)", "", wireguardService.pskSet(), wireguardService.pskLength(), "nicht gesetzt");
        w.write(
            "<label for='wg-epport'>Listen-Port</label>"
            "<input id='wg-epport' name='epport' type='number' min='1' max='65535' value='"
        );
        w.write(String(wg.endpointPort));
        w.write(
            "'>"
            "<label for='wg-allowed'>Allowed IPs</label>"
            "<input id='wg-allowed' name='allowed' type='text' autocomplete='off' autocapitalize='none' "
            "autocorrect='off' spellcheck='false' placeholder='0.0.0.0/0' value='"
        );
        w.write(escapeHtml(wg.allowedIps));
        w.write(
            "'>"
            "<label for='wg-keepalive'>Persistent Keepalive (s, 0=aus)</label>"
            "<input id='wg-keepalive' name='keepalive' type='number' min='0' max='65535' value='"
        );
        w.write(String(wg.keepalive));
        w.write(
            "'>"
            "<label for='wg-routing'>Routing</label>"
            "<select id='wg-routing' name='routing' class='cam-select cfg-select'>"
            "<option value='split'"
        );
        if (!wg.fullTunnel) w.write(" selected");
        w.write(">Split Tunnel</option><option value='full'");
        if (wg.fullTunnel) w.write(" selected");
        w.write(
            ">Full Tunnel</option></select>"
            "<p class='cam-hint'>Private Key + PSK werden gespeichert, aber NIE zurueck an den Browser "
            "gegeben (leer lassen = behalten).</p>"
            "</details>"   // /Erweitert
            "</div>"       // /wg-srv-cfg (Aufklapp-Wrapper)
            "<button class='connect-button' type='submit'>Speichern</button>"
            "</form>"
            "<p id='wg-msg' class='scan-status'></p>"

            "<div class='info'>"
            "<div><span>MCU Public Key</span><span id='wg-mcupub' style='word-break:break-all;font-size:11px'>-</span></div>"
            "</div>"
            "<p class='cam-hint'>Der Server laeuft automatisch, sobald &quot;VPN-Server aktivieren&quot; "
            "gesetzt und gespeichert ist - und startet sich bei Bedarf selbst neu. Fuege ein Geraet hinzu, "
            "damit sich jemand verbinden kann. Den Verbindungsstatus zeigt die <strong>Uebersicht</strong> (VPN).</p>"

            // --- 7.9.2: Liste der zugelassenen Geraete (mit Handshake-Status + Loeschen) ---
            "<h2 class='section-title'>Verbundene Geraete</h2>"
            "<div id='wg-clients' class='info'><div><span>-</span><span></span></div></div>"

            "<h2 class='section-title'>Geraet hinzufuegen</h2>"
            "<p class='cam-hint'>Erzeugt ein Client-Schluesselpaar AUF dem Geraet, haengt es an die Liste an "
            "und zeigt die fertige Client-Config als QR (bzw. .conf zum Herunterladen). Der Client-Private-Key "
            "wird NICHT gespeichert, nur hier einmalig angezeigt. Endpoint = DynDNS-Domain (unter Dienste).</p>"
            "<label for='wg-cname'>Name (optional)</label>"
            "<input id='wg-cname' type='text' autocomplete='off' placeholder='z.B. Handy, Laptop' value=''>"
            "<div class='cam-bar'>"
            "<button id='wg-clientgen' class='cam-button' type='button'>Geraet erzeugen (QR + .conf)</button>"
            "</div>"
            "<p id='wg-qr-msg' class='scan-status'></p>"
            "<div id='wg-qr-wrap' style='display:none'>"
            "<div id='wg-qr' style='background:#fff;display:inline-block;padding:6px;border-radius:6px'></div>"
            "<pre id='wg-qr-conf' style='white-space:pre-wrap;word-break:break-all;font-size:12px;"
            "background:#111;color:#eee;padding:8px;border-radius:6px;overflow:auto'></pre>"
            "<div class='cam-bar'>"
            "<button id='wg-dl-conf' class='cam-button' type='button'>.conf herunterladen</button>"
            "<button id='wg-mail-conf' class='cam-button' type='button'>Per Mail teilen</button>"
            "</div>"
            "<p class='cam-hint'>Tipp: Die <b>.conf</b> als Mail-<b>Anhang</b> verschicken - der Empfaenger "
            "tippt sie am Handy an und importiert sie mit einem Tipp in die WireGuard-App. &quot;Per Mail "
            "teilen&quot; legt den Config-Text in den Mail-Body (ohne Anhang). Achtung: die Datei enthaelt "
            "den Client-Private-Key - nur ueber vertrauenswuerdige Kanaele teilen.</p>"
            "</div>"
        );
        if (cliBlocks) w.write("</div>");   // /fields-inactive (Server gesperrt, WireGuard laeuft als Client)
        w.write("</div>");   // /psub-vpnsrv-wg
    }

    // --- IPsec-Server (8.1) --- Config/Benutzer funktionsfaehig; IKE/ESP-Runtime folgt.
    {
        const IpsecConfig& is = ipsecService.config();
        bool act = is.active && is.mode == "server";
        w.write(
            "<div class='page-sub' id='psub-vpnsrv-ipsec'>"
            "<h2 class='section-title'>IPsec-VPN bereitstellen</h2>"
            "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0'>"
            "<p><strong>Noch nicht verfuegbar.</strong> Die IPsec-Server-Runtime (IKEv2/ESP-Responder) ist noch "
            "nicht implementiert -- die MCU kann heute nur IPsec-<em>Client</em> (WAN &gt; ... bzw. Dienste &gt; VPN). "
            "Die Felder sind deshalb ausgegraut. Sobald der Responder steht, wird der Server hier aktivierbar und "
            "erscheint unter LAN &gt; Netzzonen als eigener Endpunkt.</p></div>"
            "<div class='fields-inactive'>"
            "<form id='ipss-form'>"
            "<input type='hidden' name='mode' value='server'>"
            "<label class='check-row big-toggle'><input id='ipss-active' type='checkbox' name='active' value='1' disabled"
        );
        if (act) w.write(" checked");
        w.write(
            "><span><strong>IPsec-Server aktivieren</strong> <small>(noch nicht verfuegbar)</small></span></label>"
            "<div id='ipss-cfg'"
        );
        if (!act) w.write(" style='display:none'");
        w.write(
            ">"
            "<label for='ipss-listen'>Listen-Port (IKE)</label>"
            "<input id='ipss-listen' name='listenport' type='number' min='1' max='65535' value='"
        );
        w.write(String(is.listenPort));
        w.write(
            "'>"
            "<label for='ipss-pool'>IP-Pool fuer Clients (Subnetz)</label>"
            "<input id='ipss-pool' name='poolsub' type='text' autocomplete='off' autocapitalize='none' "
            "autocorrect='off' spellcheck='false' placeholder='10.10.0.0/24' value='"
        );
        w.write(escapeHtml(is.poolSubnet));
        w.write(
            "'>"
        );
        writeSecretField(w, "ipss-psk", "psk", "Pre-Shared Key (PSK)", "", ipsecService.pskSet(), ipsecService.pskLength(), "nicht gesetzt");
        w.write(
            "<details class='wg-adv'><summary>Erweitert (Identity)</summary>"
            "<label for='ipss-ident'>Server-Identity</label>"
            "<input id='ipss-ident' name='srvident' type='text' autocomplete='off' autocapitalize='none' "
            "autocorrect='off' spellcheck='false' value='"
        );
        w.write(escapeHtml(is.serverIdent));
        w.write(
            "'>"
            "</details>"
            "</div>"   // /ipss-cfg
            "<button class='connect-button' type='submit'>Speichern</button>"
            "</form>"
            "<p id='ipss-msg' class='scan-status'></p>"

            "<h2 class='section-title'>Benutzer (EAP)</h2>"
            "<p class='cam-hint'>Zugelassene Benutzer/Identities fuer den EAP-Login. Passwoerter werden "
            "geraeteseitig vergeben, sobald die Runtime steht.</p>"
            "<div id='ipss-users'></div>"
            "<div style='display:flex;gap:8px;margin-top:8px'>"
            "<input id='ipss-uname' type='text' placeholder='Benutzername' autocomplete='off' "
            "autocapitalize='none' spellcheck='false' style='flex:1'>"
            "<button id='ipss-uadd' class='cam-button' type='button'>Hinzufuegen</button>"
            "</div>"

            "<p class='cam-hint'>Den Status des IPsec-Servers zeigt die <strong>Uebersicht</strong> (VPN).</p>"
            "</div>"   // /fields-inactive
            "</div>"   // /psub-vpnsrv-ipsec
            "</section>"   // /tab-vpn-srv
        );
    }
}

// 7.9: VPN-CLIENT-Seite (Menue: Dienste > VPN). Die MCU waehlt sich als Client in ein fremdes
// WireGuard-Netz ein. Eigene IDs (wgc-*), damit sie nicht mit der Server-Seite (wg-*) kollidieren.
// IKEv2-Richtlinie im Raster des LANCOM Advanced VPN Client: DH-Gruppen, PFS, IKE-SA-Verschluesselung/
// -Hash, Child-SA-Verschluesselung/-Hash. Quelle der Wahrheit = ipsec_crypto_caps.h: Nicht-
// Implementiertes wird ausgegraut (disabled + "noch nicht implementiert") und serverseitig abgelehnt.
static void writeAlgoChecks(WeirdUiWriter& w, const char* cls, IpsecAlgoGroup g, const String& sel) {
    int n = 0; const IpsecAlgo* t = ipsecAlgoTable(g, n);
    w.write("<div class='ipsc-algos'>");
    for (int i = 0; i < n; i++) {
        const IpsecAlgo& a = t[i];
        // AP1.4: Ein Haken bedeutet IMMER "wird tatsaechlich angeboten/verwendet". Nicht
        // Implementiertes wird nie angeboten -> also NIE angehakt (auch keine LANCOM-Vorgabe).
        // Der Zusatz "(LANCOM-Vorgabe, noch nicht implementiert)" bleibt als ehrlicher Hinweis,
        // widerspricht dem Auswahlzustand aber nicht mehr.
        bool on = a.supported && ipsecAlgoListHas(sel, a.id);
        // Einheitlich mit WLAN/Bluetooth/Diagnose: .fields-inactive graut aus und blockiert die Maus,
        // ohne `disabled` -- der Wert bleibt im Formular. Serverseitig lehnt IpsecService alles
        // Nicht-Implementierte ohnehin ab ("Nicht gespeichert: ...").
        w.write(String("<label class='check-row") + (a.supported ? "" : " fields-inactive") + "'>"
                "<input type='checkbox' class='" + cls + "' value='" + a.id + "'" + (on ? " checked" : "")
                + (a.supported ? "" : " data-unsupported='1'") + "><span>" + a.label
                + (a.supported ? (a.lancomDefault ? " <em>(LANCOM-Vorgabe)</em>" : "")
                               : (a.lancomDefault ? " <em>(LANCOM-Vorgabe, noch nicht implementiert)</em>" : " <em>(noch nicht implementiert)</em>"))
                + "</span></label>");
    }
    w.write("</div>");
}

// IKE-Identitaeten -- Pflichtwissen fuer PSK gegen eine FRITZ!Box: die eigene Identity ist der
// VPN-Benutzername der Box mit ID-Typ keyid (ID_KEY_ID); sonst antwortet sie AUTHENTICATION_FAILED.
// Deshalb NICHT im eingeklappten "Erweitert", sondern direkt unter dem PSK.
// Identitaeten: je EINE Zeile [Typ][Dropdown] [Wert][Eingabe]. Keine Erklaertexte im Formular --
// alles Weitere steht im Tooltip (title). Vorgaben: eigene = aktuelle Uplink-IP, Server = keine feste
// Identitaet; das Wertfeld ist dann ausgegraut. Nur aendern, wenn der Administrator es vorgibt.
struct IdOpt { const char* value; const char* label; bool needsValue; const char* placeholder; };
static const IdOpt kLocalIdOpts[] = {
    {"sourceip", "IPv4 - aktuelle Uplink-IP",                 false, ""},
    {"eapuser",  "EAP-Benutzername verwenden (Vorgabe bei Benutzer + Passwort)", false, ""},
    {"keyid",    "KEY_ID - Schluessel-ID / VPN-Benutzername", true,  "fritz9352"},
    {"fqdn",     "FQDN - Domain/Hostname",                    true,  "client.example.com"},
    {"rfc822",   "RFC822 - E-Mail-Adresse",                   true,  "user@example.com"},
    {"ipv4",     "IPv4 - feste IP-Adresse",                   true,  "192.0.2.10"},
};
static const IdOpt kRemoteIdOpts[] = {
    {"none",     "keine feste Server-Identitaet",             false, ""},
    {"keyid",    "KEY_ID - Schluessel-ID",                    true,  "vpnserver"},
    {"fqdn",     "FQDN - Domain/Hostname",                    true,  "vpn.example.com"},
    {"rfc822",   "RFC822 - E-Mail-Adresse",                   true,  "vpn@example.com"},
    {"ipv4",     "IPv4 - IP-Adresse",                         true,  "203.0.113.5"},
};
// AP1.3: EINE Zeile "<Verb>: [Dropdown] [Wert]". Kein separates sichtbares "Typ"/"Wert" -- nur
// das fuehrende Verb ("Senden als" / "Erwarten als"); der Rest steht im Tooltip.
static void writeIdRow(WeirdUiWriter& w, const char* verb, const char* selId, const char* selName,
                       const char* inpId, const char* inpName,
                       const IdOpt* opts, int n, const String& curType, const String& curVal, const char* tip) {
    bool known = false;
    for (int i = 0; i < n; i++) if (curType == opts[i].value) known = true;
    w.write(String("<div class='combo-row' title='") + tip + "'>"
            "<span class='id-verb'>" + verb + "</span>"
            "<select id='" + selId + "' name='" + selName + "' class='cam-select cfg-select id-type'>");
    if (!known) w.write("<option value='' selected disabled>Bitte waehlen</option>");
    for (int i = 0; i < n; i++)
        w.write(String("<option value='") + opts[i].value + "'" + (curType == opts[i].value ? " selected" : "")
                + " data-needs='" + (opts[i].needsValue ? "1" : "0") + "' data-ph='" + opts[i].placeholder + "'>" + opts[i].label + "</option>");
    w.write(String("</select>"
            "<input id='") + inpId + "' name='" + inpName + "' type='text' class='id-value' autocomplete='off' "
            "autocapitalize='none' autocorrect='off' spellcheck='false' value='" + escapeHtml(curVal) + "'></div>");
}
// Trust-Modell fuer das Server-Zertifikat bei Benutzer + Passwort (EAP): vier Optionen wie im Assistenten,
// der Inhalt darunter wechselt. Datenmodell = GENAU zwei PEM-Bloecke (capem = Vertrauensanker,
// extrapem = Kettenmaterial). Datei-Upload und Textfeld fuellen dieselben Bloecke; der Haken je
// Zertifikat verschiebt es nur zwischen den Bloecken (kein drittes Feld, keine Flags im Core).
// Die erwartete Server-Identitaet bleibt AUSSERHALB dieser Auswahl (writeIpsecIdentity).
static void writeIpsecTrust(WeirdUiWriter& w, const IpsecConfig& ic) {
    struct Opt { const char* val; const char* label; const char* title; bool warn; };
    static const Opt opts[] = {
        { "public", "Oeffentliche CAs",
          "Kette gegen die eingebauten oeffentlichen Root-CAs (Mozilla-Root-Store der ESP-IDF, offline im Geraet, kein Nachladen). "
          "Die Server-Identitaet wird zusaetzlich gegen SAN/CN des Zertifikats geprueft. Empfohlen fuer Server mit oeffentlichem Zertifikat (z.B. Let&#39;s Encrypt).", false },
        { "public-plus", "Oeffentliche CAs + Zusatz",
          "Oeffentliche Root-CAs plus zusaetzliche Zertifikate fuer diese Verbindung: fehlende Zwischenzertifikate (Kettenmaterial) "
          "oder ausdruecklich zusaetzlich vertraute private/Test-Anker (Haken).", false },
        { "own", "Eigener Vertrauensanker",
          "Nur die hier hinterlegten Vertrauensanker gelten: CA-Zertifikat, Zwischen-CA als expliziter Anker oder das exakte/"
          "selbstsignierte Serverzertifikat. Der oeffentliche Store wird NICHT benutzt.", false },
        { "none", "Keine Vertrauenspruefung &#9888;",
          "Zertifikatskette und Server-Identitaet werden NICHT geprueft. Die kryptographische IKE-AUTH-Signatur des Servers wird "
          "weiterhin geprueft. Nicht empfohlen.", true },
    };
    String cur = ic.trustMode; if (cur != "public" && cur != "public-plus" && cur != "own" && cur != "none") cur = "own";
    w.write("<label title='Wem vertraut das Geraet, wenn sich der VPN-Server mit seinem Zertifikat ausweist? Nur bei Benutzer + Passwort relevant.'>"
            "Vertrauensmodell fuer das Server-Zertifikat</label>"
            "<div class='opt-bar' id='ipsc-trustbar'>");
    for (const Opt& o : opts) {
        w.write(String("<button type='button' class='opt-btn") + (o.warn ? " opt-warn" : "") + (cur == o.val ? " active" : "")
                + "' data-val='" + o.val + "' title='" + o.title + "'>" + o.label + "</button>");
    }
    w.write("</div><input type='hidden' id='ipsc-trust' name='trust' value='"); w.write(cur); w.write("'>");
    // Erklaerungstexte je Modus (die Buttons haben denselben Text als Tooltip)
    w.write("<div class='trust-pane' data-pane='public'><p class='hint'>Die Zertifikatskette des Servers muss in einer der eingebauten "
            "oeffentlichen Root-CAs enden (Mozilla-Root-Store, offline im Geraet). Keine Eingabe noetig. Die erwartete Server-Identitaet "
            "(unten, &#39;Erwarten als&#39;) wird gegen SAN/CN des Zertifikats geprueft.</p></div>");
    w.write("<div class='trust-pane' data-pane='public-plus'><p class='hint'>Oeffentliche Root-CAs wie oben, zusaetzlich die hier hinterlegten "
            "Zertifikate: ohne Haken = Kettenmaterial (fehlendes Zwischenzertifikat, beendet nie eine Kette), mit Haken = zusaetzlicher "
            "Vertrauensanker (private/Test-CA).</p></div>");
    w.write("<div class='trust-pane' data-pane='own'><p class='hint'>Nur die hier hinterlegten Zertifikate mit Haken sind Vertrauensanker "
            "(CA-Zertifikat, Zwischen-CA als expliziter Anker oder das exakte/selbstsignierte Serverzertifikat). Ohne Haken = Kettenmaterial. "
            "Der oeffentliche Store wird nicht benutzt.</p></div>");
    w.write("<div class='trust-pane' data-pane='none'><p class='hint warn'>&#9888; Nicht empfohlen: Zertifikatskette und Server-Identitaet werden "
            "nicht geprueft. Jeder, der die Verbindung umleiten kann, kann sich als VPN-Server ausgeben und die Anmeldung "
            "(EAP-MSCHAPv2) abgreifen. Geprueft wird nur noch die kryptographische IKE-AUTH-Signatur des vorgelegten Zertifikats. "
            "Nur fuer Tests ohne verfuegbares CA-Zertifikat.</p></div>");
    // Zertifikat-Editor (fuer public-plus und own): Liste + Haken, Datei-Upload, Textfeld -> zwei versteckte PEM-Bloecke
    w.write("<div id='ipsc-certeditor'>"
            "<label>Zertifikate fuer diese Verbindung (PEM)</label>"
            "<div id='ipsc-certlist' class='cert-list'></div>"
            "<textarea id='ipsc-certadd' rows='4' autocomplete='off' spellcheck='false' "
            "placeholder='PEM hier einfuegen (-----BEGIN CERTIFICATE----- ...) und Hinzufuegen druecken'></textarea>"
            "<div class='cert-add-row'><input type='file' id='ipsc-certfile' accept='.pem,.crt,.cer,.txt' multiple>"
            "<button type='button' id='ipsc-certadd-btn' class='opt-btn'>Hinzufuegen</button></div>"
            "<textarea id='ipsc-capem' name='capem' hidden>"); w.write(escapeHtml(ic.caPem));
    w.write("</textarea><textarea id='ipsc-extrapem' name='extrapem' hidden>"); w.write(escapeHtml(ic.extraPem));
    w.write("</textarea></div>");
}

static void writeIpsecIdentity(WeirdUiWriter& w, const IpsecConfig& ic) {
    static const char* tipLocal =
        "Vorgabe (aktuelle Uplink-IP) nur aendern und einen Wert eintragen, wenn der VPN-Administrator oder "
        "Anbieter eine Identitaet ausdruecklich vorgibt. FRITZ!Box: VPN-Benutzername als KEY_ID. "
        "Gesendet wird genau Typ(Wert), z.B. KEY_ID(\"fritz9352\").";
    static const char* tipRemote =
        "Vorgabe (keine feste Server-Identitaet) nur aendern, wenn der Administrator ausdruecklich vorgibt, "
        "mit welcher Identitaet sich der VPN-Server ausweist. FRITZ!Box: nicht noetig.";
    w.write(String("<label title='") + tipLocal + "'>Eigene VPN-Identitaet (IDi)</label>");
    writeIdRow(w, "Senden als", "ipsc-localidt", "localidt", "ipsc-localid", "localid",
               kLocalIdOpts, sizeof(kLocalIdOpts) / sizeof(kLocalIdOpts[0]), ic.localIdType, ic.localId, tipLocal);
    String rt = ic.remoteIdType;
    if (ic.remoteId.length() == 0) rt = "none";
    w.write(String("<label title='") + tipRemote + "'>Server-Identitaet (IDr)</label>");
    writeIdRow(w, "Erwarten als", "ipsc-remoteidt", "remoteidt", "ipsc-remoteid", "remoteid",
               kRemoteIdOpts, sizeof(kRemoteIdOpts) / sizeof(kRemoteIdOpts[0]), rt, ic.remoteId, tipRemote);
}

static void writeIpsecPolicy(WeirdUiWriter& w, const IpsecConfig& ic) {
    w.write(
        "<details class='wg-adv' open><summary>IKEv2-Richtlinie (Krypto, wie im LANCOM Advanced VPN Client)</summary>"
        "<p class='cam-hint'>Angehakt = wird angeboten (mehrere Haken = Alternativen, das Gateway waehlt eine). "
        "Vorgaben wie im LANCOM-Profil DEFAULT, soweit implementiert: DH14, AES-CBC-256, SHA-256 und SHA-1; PFS ist verfuegbar und wird unten gewaehlt. "
        "Ausgegraut = noch nicht implementiert und wird nicht angeboten; der Zusatz &bdquo;LANCOM-Vorgabe&ldquo; "
        "markiert nur, was als naechstes implementiert wird.</p>"
        "<label>DH-Gruppen (IKE_SA_INIT)</label>"
    );
    // Hinweis oben korrigiert (AP1.4): ausgegraut = nicht angeboten; kein angehakt-ausgegraut mehr.
    writeAlgoChecks(w, "ipsc-ikedh", IpsecAlgoGroup::Dh, ic.ikeDh);
    w.write(
        "<label for='ipsc-pfs' title='PFS wird beim Child-SA-Rekey verwendet: ein neuer Diffie-Hellman-Schluessel (Gruppe wie oben), "
        "ein spaeter kompromittierter IKE-Schluessel verraet dann keine frueheren ESP-Schluessel. "
        "Nicht jede Gegenstelle uebernimmt den angeforderten DH-Austausch. Wird PFS vom Peer ignoriert, lehnt WeirdOS den "
        "Rekey ab (kein stilles Downgrade) und baut den Tunnel neu auf -- fuer solche Gegenstellen PFS auf Nein stellen.'>"
        "PFS (Perfect Forward Secrecy beim Child-Rekey)</label>"
        "<select id='ipsc-pfs' name='pfs' class='cam-select cfg-select'>"
    );
    bool pfsOn = ipsecPfsSupported() && ic.pfs;
    w.write(String("<option value='0'") + (pfsOn ? "" : " selected") + ">Nein</option>");
    w.write(String("<option value='1'") + (ipsecPfsSupported() ? (pfsOn ? " selected" : "") : " disabled")
            + ">Ja" + (ipsecPfsSupported() ? " (LANCOM-Vorgabe)" : " - LANCOM-Vorgabe, noch nicht implementiert") + "</option></select>");
    if (ipsecRuntime.peerPfsRejected())   // Laufzeit-Befund der KONKRETEN Gegenstelle (kein Hardcode auf einen Hersteller)
        w.write("<div class='cfg-hint' style='color:#c60'>Die Gegenstelle hat PFS beim Child-SA-Rekey nicht akzeptiert "
                "(Child-SA ohne D-H/KE ausgewaehlt). Der Tunnel wurde aus Sicherheitsgruenden neu aufgebaut. "
                "Fuer diese Gegenstelle sollte PFS deaktiviert werden.</div>");
    w.write("<label>IKE-SA-Verschluesselung</label>");
    writeAlgoChecks(w, "ipsc-ikeenc", IpsecAlgoGroup::IkeEnc, ic.ikeEnc);
    w.write("<label>IKE-SA-Hash (PRF + Integritaet)</label>");
    writeAlgoChecks(w, "ipsc-ikehash", IpsecAlgoGroup::IkeHash, ic.ikeHash);
    w.write("<label>Child-SA-Verschluesselung (ESP)</label>");
    writeAlgoChecks(w, "ipsc-espenc", IpsecAlgoGroup::EspEnc, ic.espEnc);
    w.write("<label>Child-SA-Hash (ESP-Integritaet)</label>");
    writeAlgoChecks(w, "ipsc-esphash", IpsecAlgoGroup::EspHash, ic.espHash);
    w.write("</details>");
    // C1/C2/D: Lebensdauern, DPD und NAT-T-Keepalive -- dieselben Felder wie 'ipsec set ike-lifetime ...'
    w.write("<details class='wg-adv'><summary>Lebensdauer, Dead Peer Detection, NAT-T (wie im LANCOM-Client)</summary>"
            "<p class='cam-hint'>Rekey = neue Schluessel ohne Tunnelabbruch. Zeit- und Datenmengen-Limit gelten zusammen "
            "(was zuerst eintritt). 0 = WeirdIKE-Vorgabe bzw. kein Limit.</p>"
            "<label for='ipsc-ikelt' title='IKE-SA-Rekey durch dieses Geraet nach n Sekunden (LANCOM-Profil: 28800 = 8 h). 0 = nur auf Anforderung oder durch die Gegenstelle.'>IKE-SA-Lebensdauer (Sekunden)</label>"
            "<input id='ipsc-ikelt' name='ikelt' type='number' min='0' max='65535' value='" + String(ic.ikeLifetimeS) + "'>"
            "<label for='ipsc-childlt' title='Child-SA-Rekey (ESP-Schluessel) nach n Sekunden; 0 = WeirdIKE-Vorgabe 3300.'>Child-SA-Lebensdauer nach Zeit (Sekunden)</label>"
            "<input id='ipsc-childlt' name='childlt' type='number' min='0' max='65535' value='" + String(ic.childLifetimeS) + "'>"
            "<label for='ipsc-childmb' title='Child-SA-Rekey nach n MiB ESP-Verkehr (Senden + Empfangen); 0 = kein Byte-Limit.'>Child-SA-Lebensdauer nach Datenmenge (MiB)</label>"
            "<input id='ipsc-childmb' name='childmb' type='number' min='0' max='65535' value='" + String(ic.childLifetimeMb) + "'>"
            "<label class='check-row'><input id='ipsc-dpd' type='checkbox' name='dpd' value='1'" + String(ic.dpd ? " checked" : "") + ">"
            "<span>Dead Peer Detection: eigene Proben senden (aus = Ausfall der Gegenstelle wird nur ueber ihre Proben oder Rekeys erkannt)</span></label>"
            "<label for='ipsc-dpdint' title='Sekunden ohne Eingang von der Gegenstelle, bevor eine INFORMATIONAL-Probe gesendet wird (LANCOM: 20).'>DPD-Intervall (Sekunden)</label>"
            "<input id='ipsc-dpdint' name='dpdint' type='number' min='5' max='3600' value='" + String(ic.dpdIntervalS) + "'>"
            "<label for='ipsc-dpdretry' title='Wiederholungen einer unbeantworteten Probe (exponentiell 1,2,4,... s), danach gilt die Gegenstelle als tot und der Tunnel wird neu aufgebaut (LANCOM: 8).'>DPD-Wiederholungen</label>"
            "<input id='ipsc-dpdretry' name='dpdretry' type='number' min='1' max='20' value='" + String(ic.dpdRetries) + "'>"
            "<label for='ipsc-natka' title='Leeres UDP/4500-Paket, das die NAT-Zuordnung offen haelt; nur wirksam, wenn NAT erkannt wurde.'>NAT-T-Keepalive (Sekunden)</label>"
            "<input id='ipsc-natka' name='natka' type='number' min='5' max='600' value='" + String(ic.nattKeepaliveS) + "'>"
            "</details>");
}

void renderVpnClient(WeirdUiWriter& w) {
    const WireGuardConfig& wg = wireguardService.config();
    bool cliActive = wg.active && wg.mode == "client";
    w.write(
        "<section id='tab-vpn-cli' class='tab-panel'>"
        "<div class='tabs'>"
        "<button class='tab active' data-psub='vpncli-wg'>WireGuard</button>"
        "<button class='tab' data-psub='vpncli-ipsec'>IPsec</button>"
        "</div>"
        "<div class='page-sub active' id='psub-vpncli-wg'>"
        "<h2 class='section-title'>Mit anderem Netz verbinden</h2>"
        "<div class='info'>"
        "<div><span>MCU Public Key</span><span id='wgc-mcupub' style='word-break:break-all;font-size:11px'>-</span></div>"
        "</div>"
        "<p class='cam-hint'>Die MCU verbindet sich als Client in ein fremdes WireGuard-Netz. Den oben "
        "gezeigten <strong>MCU Public Key</strong> traegst du am Ziel-Server als erlaubten Peer ein.</p>");
    // Ein Backend, eine Rolle: laeuft der WireGuard-Server, ist der Client gesperrt (und umgekehrt).
    bool srvBlocks = wg.active && wg.mode != "client";
    if (srvBlocks) w.write(
        "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0'>"
        "<p><strong>WireGuard laeuft derzeit als Server.</strong> Server und Client koennen nicht gleichzeitig "
        "laufen (ein Backend). Um dich als Client zu verbinden, zuerst unter <strong>Server &rarr; VPN</strong> "
        "den WireGuard-Server deaktivieren.</p></div>");
    w.write(srvBlocks ? "<div class='fields-inactive'><form id='wgc-form'>" : "<form id='wgc-form'>");
    w.write(
        "<input type='hidden' name='mode' value='client'>"
        "<label class='check-row big-toggle'>"
        "<input id='wgc-active' type='checkbox' name='active' value='1'"
    );
    if (cliActive) w.write(" checked");
    if (srvBlocks) w.write(" disabled");
    w.write(
        "><span><strong>Mit einem anderen WireGuard-Netz verbinden</strong></span></label>"
        "<div id='wg-cli-cfg'"
    );
    if (!cliActive) w.write(" style='display:none'");
    w.write(
        ">"
        "<label for='wgc-ephost'>Ziel-Server (Adresse/Host)</label>"
        "<input id='wgc-ephost' name='ephost' type='text' autocomplete='off' autocapitalize='none' "
        "autocorrect='off' spellcheck='false' placeholder='vpn.example.com' value='"
    );
    w.write(escapeHtml(wg.clientEndpoint));
    w.write(
        "'>"
        "<label for='wgc-epport'>Ziel-Server Port</label>"
        "<input id='wgc-epport' name='epport' type='number' min='1' max='65535' value='"
    );
    w.write(String(wg.clientPort));
    w.write(
        "'>"
        "<label for='wgc-peerpub'>Public Key der Gegenstelle</label>"
        "<input id='wgc-peerpub' name='peerpub' type='text' autocomplete='off' autocapitalize='none' "
        "autocorrect='off' spellcheck='false' value='"
    );
    w.write(escapeHtml(wg.clientPeerPub));
    w.write(
        "'>"
        "<label for='wgc-allowed'>Was durch den Tunnel geroutet wird (AllowedIPs)</label>"
        "<input id='wgc-allowed' name='allowed' type='text' autocomplete='off' autocapitalize='none' "
        "autocorrect='off' spellcheck='false' placeholder='0.0.0.0/0 (alles) oder z.B. 10.0.0.0/24' value='"
    );
    w.write(escapeHtml(wg.clientAllowedIps));
    w.write(
        "'>"
        "<details class='wg-adv'><summary>Erweitert (PSK, Tunnel-IP, Underlay)</summary>"
    );
    writeSecretField(w, "wgc-psk", "psk", "Preshared Key (optional)", "", wireguardService.pskSet(), wireguardService.pskLength(), "nicht gesetzt");
    w.write(
        "<label for='wgc-localip'>Eigene Tunnel-IP</label>"
        "<input id='wgc-localip' name='localip' type='text' autocomplete='off' autocapitalize='none' "
        "autocorrect='off' spellcheck='false' placeholder='10.9.0.1' value='"
    );
    w.write(escapeHtml(wg.localIp));
    w.write(
        "'>"
        "<label for='wgc-underlay'>Underlay</label>"
        "<select id='wgc-underlay' name='underlay' class='cam-select cfg-select'>"
        "<option value='auto'"
    );
    if (wg.underlay != "modem" && wg.underlay != "wifi") w.write(" selected");
    w.write(">Automatisch (Mobilfunk bevorzugt)</option><option value='modem'");
    if (wg.underlay == "modem") w.write(" selected");
    w.write(">Mobilfunk-WAN (ECM/PPP)</option><option value='wifi'");
    if (wg.underlay == "wifi") w.write(" selected");
    w.write(
        ">WLAN-STA</option></select>"
        "</details>"
        "</div>"   // /wg-cli-cfg
        "<button class='connect-button' type='submit'>Speichern</button>"
        "</form>"
        "<p id='wgc-msg' class='scan-status'></p>"

        "<p class='cam-hint'>Verbindet automatisch, sobald &quot;Mit einem anderen WireGuard-Netz "
        "verbinden&quot; gesetzt und gespeichert ist - und stellt die Verbindung bei Bedarf selbst wieder her. "
        "Den Verbindungsstatus zeigt die <strong>Uebersicht</strong> (VPN).</p>");
    if (srvBlocks) w.write("</div>");   // /fields-inactive (Client gesperrt, WireGuard laeuft als Server)
    w.write(
        "</div>"   // /psub-vpncli-wg
    );

    // --- IPsec-Client (8.1) --- echtes Formular; IKE/ESP-Runtime folgt (ehrlich im Status).
    {
        const IpsecConfig& ic = ipsecService.config();
        bool act = ic.active && ic.mode == "client";
        w.write(
            "<div class='page-sub' id='psub-vpncli-ipsec'>"
            "<h2 class='section-title'>Mit einem IPsec-VPN verbinden</h2>"
            "<p class='cam-hint'>Die MCU verbindet sich als <strong>Client</strong> in ein fremdes "
            "IPsec-VPN (WeirdIKE-Runtime). Auf der Leitung: <strong>IKEv2</strong> mit PSK oder Benutzer+Passwort "
            "(EAP-MSCHAPv2), AES-CBC-128/192/256, SHA-1/256/384/512, DH14/15/16, ECP-256/384/521, Brainpool, Curve25519, "
            "PFS, NAT-T, IKE Config Mode. Ausgegraut ist nur, was diese Firmware nicht auf der Leitung kann (AES-GCM, "
            "ChaCha20, 3DES/MD5, DH2/5/17/18/32, Zertifikat-Auth, L2TP) -- das wird beim Speichern abgelehnt. "
            "Hinweis Routing: durch den Tunnel wird nur das erste Zielnetz geroutet; eine Standardroute (Full Tunnel) "
            "wird nicht installiert. Der Test-Ping unten prueft echten ESP-Datenverkehr am normalen Routing vorbei.</p>"
            "<form id='ipsc-form'>"
            "<input type='hidden' name='mode' value='client'>"
            "<label class='check-row big-toggle'><input id='ipsc-active' type='checkbox' name='active' value='1'"
        );
        if (act) w.write(" checked");
        w.write(
            "><span><strong>IPsec-Verbindung aktivieren</strong></span></label>"
            "<div id='ipsc-cfg'"
        );
        if (!act) w.write(" style='display:none'");
        w.write(">");
        // Autostart + automatisches Neuverbinden nach Aenderungen (Observer auf die gespeicherte
        // Konfiguration). Aus = Verbindung ausschliesslich ueber 'Neu verbinden'.
        w.write(String("<label class='check-row'><input id='ipsc-autoconn' type='checkbox' name='autoconn' value='1'")
                + (ic.autoConnect ? " checked" : "")
                + "><span>Automatisch verbinden: beim Start und wenn keine Verbindung steht "
                  "(aus = nur ueber 'Neu verbinden')</span></label>");
        w.write(
            "<label for='ipsc-proto'>Protokoll</label>"
            "<select id='ipsc-proto' name='proto' class='cam-select cfg-select'>"
            "<option value='ikev2'"
        );
        w.write(" selected>IKEv2 / IPsec</option><option value='l2tp' disabled");   // L2TP: noch nicht implementiert
        w.write(
            ">L2TP / IPsec (noch nicht implementiert)</option></select>"
            "<label for='ipsc-srvhost'>Server (Adresse/Host)</label>"
            "<input id='ipsc-srvhost' name='srvhost' type='text' autocomplete='off' autocapitalize='none' "
            "autocorrect='off' spellcheck='false' placeholder='vpn.example.com' value='"
        );
        w.write(escapeHtml(ic.serverHost));
        w.write(
            "'>"
            "<label for='ipsc-srvport'>Server-Port (IKE)</label>"
            "<input id='ipsc-srvport' name='srvport' type='number' min='1' max='65535' value='"
        );
        w.write(String(ic.serverPort));
        w.write(
            "'>"
            "<label for='ipsc-auth'>Authentifizierung</label>"
            "<select id='ipsc-auth' name='auth' class='cam-select cfg-select'>"
            // Nur PSK ist implementiert (ipsec_crypto_caps.h) -> immer vorgewaehlt; EAP-MSCHAPv2 und
            // Zertifikat ausgegraut, bis die WeirdIKE-Slices da sind. Benutzer/Passwort dazu ebenfalls
            // ausgegraut (nicht korrekt implementiert -> nicht bedienbar, Werte bleiben erhalten).
            "<option value='psk'"
        );
        if (ic.auth != "eap" || !ipsecAuthSupported("eap")) w.write(" selected");
        // EAP-MSCHAPv2 (Benutzer + Passwort): waehlbar, sobald ipsec_crypto_caps es freigibt (WeirdIKE
        // AP7/AP8 + strongSwan-Interop). Der Server weist sich dabei mit einem Zertifikat aus; WEM
        // vertraut wird, entscheidet das Trust-Modell am Ende des Formulars (Vorgabe: oeffentliche
        // CAs, kein manuelles CA-PEM noetig). Sichtbarkeit der Bloecke schaltet das JS je nach auth um,
        // gespeicherte Werte bleiben erhalten (nur display:none, nichts wird geloescht).
        w.write(">Pre-Shared Key (PSK)</option><option value='eap'");
        if (!ipsecAuthSupported("eap")) w.write(" disabled"); else if (ic.auth == "eap") w.write(" selected");
        w.write(ipsecAuthSupported("eap") ? ">Benutzer + Passwort (EAP-MSCHAPv2, Server per Zertifikat)</option>"
                                          : ">Benutzer + Passwort (EAP-MSCHAPv2) - noch nicht implementiert</option>");
        w.write(
            "<option value='cert' disabled>Zertifikat - noch nicht implementiert</option>"
            "</select>"
        );
        // .fields-inactive statt disabled: ausgegraut, Werte bleiben erhalten und werden mitgesendet
        w.write(ipsecAuthSupported("eap") ? "<div id='ipsc-eapfields'>" : "<div class='fields-inactive'>");
        w.write(String("<label for='ipsc-eapuser'>Benutzer (EAP-MSCHAPv2)") + (ipsecAuthSupported("eap") ? "" : " - noch nicht implementiert") + "</label>"
            "<input id='ipsc-eapuser' name='eapuser' type='text' autocomplete='off' autocapitalize='none' "
            "autocorrect='off' spellcheck='false' value='");
        w.write(escapeHtml(ic.eapUser));
        w.write("'>");
        writeSecretField(w, "ipsc-eappass", "eappass",
                         String("Passwort (EAP-MSCHAPv2)") + (ipsecAuthSupported("eap") ? "" : " - noch nicht implementiert"),
                         "Das gespeicherte Passwort verlaesst das Geraet nie; die Punkte zeigen nur seine Laenge. Leer lassen = behalten.",
                         ipsecService.eapPassSet(), ipsecService.eapPassLength(), "nicht gesetzt");
        w.write(
            "</div>"   // ipsc-eapfields
            "<div id='ipsc-pskfields'>"
        );
        writeSecretField(w, "ipsc-psk", "psk", "Pre-Shared Key (PSK)",
                         "Der gespeicherte Schluessel verlaesst das Geraet nie; die Punkte zeigen nur seine Laenge. Leer lassen = behalten.",
                         ipsecService.pskSet(), ipsecService.pskLength(), "nicht gesetzt");
        w.write("</div>");
        writeIpsecIdentity(w, ic);   // IDi/IDr -- bei PSK UND EAP relevant, deshalb immer sichtbar
        // Server-Zertifikat / Vertrauenspruefung ganz am Ende der Client-Konfiguration, direkt nach der
        // erwarteten Server-Identitaet (IDr); nur bei Benutzer + Passwort sichtbar.
        w.write("<div id='ipsc-trustblock'>");
        writeIpsecTrust(w, ic);   // Trust-Modell (vier Modi); Datenmodell = capem (Anker) + extrapem (Kettenmaterial)
        w.write("</div>");
        w.write(
            "<label for='ipsc-rsubnets' title='Leer = das VPN-Gateway bestimmt, welche Netze durch den Tunnel gehen (TSr 0.0.0.0/0, das Gateway schraenkt ein). Nur eintragen, wenn der Administrator bestimmte Netze vorgibt oder du sie einschraenken willst.'>Netze hinter dem VPN-Gateway (Remote-Subnetze)</label>"
            "<input id='ipsc-rsubnets' name='rsubnets' type='text' autocomplete='off' autocapitalize='none' "
            "autocorrect='off' spellcheck='false' placeholder='leer = automatisch vom VPN-Gateway' value='"
        );
        w.write(escapeHtml(ic.remoteSubnets));
        w.write(
            "'>"
            "<label class='check-row'><input id='ipsc-natt' type='checkbox' name='natt' value='1'"
        );
        if (ic.natT) w.write(" checked");
        w.write(
            "><span>NAT-Traversal (UDP-4500) - fuer Verbindungen ueber das Internet/hinter NAT</span></label>"
            "<label for='ipsc-localtip' title='Leer = die Tunnel-Adresse kommt vom VPN-Gateway (es schraenkt TSi auf die zugewiesene Adresse ein; FRITZ!Box vergibt sie pro VPN-Benutzer). Nur eintragen, wenn der Administrator eine feste Adresse vorgibt.'>Eigene Tunnel-IP</label>"
            "<input id='ipsc-localtip' name='localtip' type='text' autocomplete='off' autocapitalize='none' "
            "autocorrect='off' spellcheck='false' placeholder='leer = automatisch vom VPN-Gateway' value='"
        );
        w.write(escapeHtml(ic.localTunnelIp));
        w.write("'>");
        writeIpsecPolicy(w, ic);   // IKEv2-Richtlinie (LANCOM-Raster), Nicht-Implementiertes ausgegraut
        // "Erweitert" ganz unten (nach der Richtlinie): Server-Identitaet (optional) + Underlay.
        w.write("<details class='wg-adv'><summary>Erweitert (Underlay)</summary>");
        w.write(
            "<label for='ipsc-underlay'>Underlay</label>"
            "<select id='ipsc-underlay' name='underlay' class='cam-select cfg-select'>"
            "<option value='auto'"
        );
        if (ic.underlay != "modem" && ic.underlay != "wifi") w.write(" selected");
        w.write(">Automatisch (Mobilfunk bevorzugt)</option><option value='modem'");
        if (ic.underlay == "modem") w.write(" selected");
        w.write(">Mobilfunk-WAN (ECM/PPP)</option><option value='wifi'");
        if (ic.underlay == "wifi") w.write(" selected");
        w.write(
            ">WLAN-STA</option></select>"
            "</details>"
        );
        w.write(
            "</div>"   // /ipsc-cfg
            // Speichern reisst eine laufende Verbindung NICHT ab (sie laeuft mit der vorherigen
            // Konfiguration weiter); "Speichern & neu verbinden" = zwei Kommandos hintereinander.
            "<div class='combo-row'>"
            "<button class='connect-button' type='submit'>Speichern</button>"
            "<button id='ipsc-save-connect' class='connect-button' type='button' "
            "title='Konfiguration speichern und die Verbindung damit neu aufbauen'>Speichern &amp; neu verbinden</button>"
            "</div>"
            "</form>"
            "<p id='ipsc-msg' class='scan-status'></p>"
            // Verbindung erzwingen/trennen -- unabhaengig vom Speichern (Start/Stop laufen im loop-Task).
            "<div class='combo-row'>"
            "<button id='ipsc-connect-btn' type='button' class='cam-button' "
            "title='Verbindungsaufbau jetzt anstossen (bestehende Verbindung wird neu aufgebaut)'>Neu verbinden</button>"
            "<button id='ipsc-disconnect-btn' type='button' class='cam-button' title='IPsec-Verbindung trennen'>Trennen</button>"
            "</div>"
            "<p id='ipsc-conn-msg' class='scan-status'></p>"
            "<p class='cam-hint'>Den Verbindungsstatus (IKE-Zustand, ausgehandelte Suite, NAT-T, ESP-Zaehler, Fehler) "
            "zeigt die <strong>Uebersicht</strong> (VPN). Hier bleiben nur die Werkzeuge: Test-Ping und IKE-Protokoll.</p>"
            "<h2 class='section-title'>IPsec Test-Ping</h2>"
            "<p class='cam-hint'>Sendet ein echtes inneres ICMP durch den Tunnel (Fallback vor generischem Routing). "
            "Ziel z.B. die FRITZ!Box-LAN-IP.</p>"
            // Combobox: Eingabe + Dropdown der zuletzt gepingten Ziele (Historie im NVS des Geraets,
            // /ipsec-ping-history.json). Pfeiltasten waehlen, Enter uebernimmt, SHIFT+ENTF entfernt den
            // markierten Eintrag. Rechts daneben der Test-Ping als Icon-Button (wie die Titel-Icons).
            "<div class='combo-row'>"
            "<div class='combo' id='ipsc-ping-combo'>"
            "<input id='ipsc-ping-target' type='text' autocomplete='off' autocapitalize='none' autocorrect='off' "
            "spellcheck='false' placeholder='192.168.178.1'>"
            "<button id='ipsc-ping-toggle' type='button' class='combo-toggle' title='Zuletzt gepingte Ziele anzeigen' "
            "aria-label='Zuletzt gepingte Ziele anzeigen'>&#x25BE;</button>"
            "<div id='ipsc-ping-list' class='combo-list' hidden></div>"
            "</div>"
            "<button id='ipsc-ping-btn' type='button' class='icon-action' "
            "title='Test-Ping senden: echtes inneres ICMP durch den IPsec-Tunnel an das Ziel' "
            "aria-label='Test-Ping senden'>&#x27A4;</button>"
            "</div>"
            "<p id='ipsc-ping-res' class='scan-status'></p>"
            "<p class='cam-hint'>Das Dropdown merkt sich die letzten Ziele auf dem Geraet (NVS), nicht im Browser. "
            "Eintrag mit den Pfeiltasten markieren und mit <strong>SHIFT+ENTF</strong> entfernen.</p>"
            "<h2 class='section-title'>IKE-Log</h2>"
            "<pre id='ipsc-log' style='white-space:pre-wrap;font-size:12px;line-height:1.4;max-height:180px;overflow:auto;background:#111;color:#ddd;padding:8px;border-radius:6px'>-</pre>"
            "</div>"   // /psub-vpncli-ipsec
        );
    }
    w.write("</section>");   // /tab-vpn-cli
}
#else
// Weboberflaeche nicht im Build (WEIRDOS_FEATURE_WEBUI=0): kein Seiteninhalt, nur die Renderer-Signaturen,
// damit web_ui.cpp (Seitentabelle) und Nachbarseiten unveraendert linken. Der HTTP-Server (Baustein HTTP)
// beantwortet dann PIN-Gate + JSON-API; sendAppPage() nennt den Grund.
#include "web_ui.h"
void renderInternet(WeirdUiWriter& w) { (void)w; }
void renderDienste(WeirdUiWriter& w) { (void)w; }
void renderVpnServer(WeirdUiWriter& w) { (void)w; }
void renderVpnClient(WeirdUiWriter& w) { (void)w; }
#endif // WEIRDOS_FEATURE_WEBUI
