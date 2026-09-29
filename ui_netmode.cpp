// ui_netmode.cpp -- Content: Einrichtung > "Assistent" (kaskadierende Radiogruppen).
//   Gruppe 1 (Endpunkt/AP) -> Gruppe 2 (Internet durchreichen?) -> Gruppe 3 (Modell).
//   Je nach Wahl erscheinen Zusatzfelder + Hinweistexte (JS, in-page). Repeater ist
//   capability-gegatet (wifi_caps: WDS/4-Address) -> auf dieser Hardware ausgegraut.
//   Auswahl wird gespeichert (-> NetworkModeConfig) + ableitet mode/forwarding; die Laufzeit-
//   Umschaltung (Service-AP/NAPT) folgt hardware-getestet -- KEIN Laufzeiteingriff bis dahin.
#include "web_ui.h"
#include "network_mode.h"
#include "wifi_caps.h"
#include "wan_policy.h"   // Assistent-WAN-Wahl = dieselbe WanPolicy (keine zweite Wahrheit)

static void wradio(WeirdUiWriter& w, const char* group, const char* val, const char* label,
                   const String& cur, bool disabled, const char* title) {
    w.write("<label class='wiz-opt");
    if (disabled) w.write(" is-disabled");
    w.write("'");
    if (title && title[0]) { w.write(" title='"); w.write(title); w.write("'"); }
    w.write("><input type='radio' name='");
    w.write(group);
    w.write("' value='");
    w.write(val);
    w.write("'");
    if (cur == val) w.write(" checked");
    if (disabled) w.write(" disabled");
    w.write("><span>");
    w.write(label);
    w.write("</span></label>");
}

void renderNetmode(WeirdUiWriter& w) {
    const NetworkModeConfig& c = networkMode.config();
    bool repCap = repeaterCapable();
    bool wifiHw = wifiPresent();
    // Massgeblich fuer "AP moeglich?" ist die EFFEKTIVE Entscheidung (Hardware UND nicht per
    // LAN > WLAN auf "Aus" gestellt) -- nicht nur die reine Hardware-Tatsache. Sonst koennte man
    // hier "AccessPoint" waehlen, waehrend der WLAN-Stack beim naechsten Boot gar nicht laeuft.
    bool wifiUsable = wifiStackShouldInit();

    // Ohne nutzbares WLAN ist AccessPoint unmoeglich -> auf Endpunkt zwingen (die ausgegraute
    // Option nie aktiv lassen, analog zu Repeater/repCap unten).
    String uc  = c.usecase;
    if (uc == "ap" && !wifiUsable) uc = "endpoint";
    bool isAp  = (uc == "ap");
    bool apNet = c.apInternet;
    String am  = c.accessModel;
    if (am == "repeater" && !repCap) am = "gateway";   // ausgegraute Option nie aktiv lassen

    w.write(
        "<section id='tab-netmode' class='tab-panel'>"
        "<h2 class='section-title'>Assistent</h2>"
        "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0'>"
        "<p><strong>Auswahl wird gespeichert.</strong> Die echte Laufzeit-Umschaltung (Service-AP, "
        "Routing/NAPT) wird hardware-getestet schrittweise scharf geschaltet -- bis dahin bleibt das "
        "heutige Verhalten aktiv (kein Laufzeiteingriff). Der Default (Endpunkt) ist unveraendert.</p>"
        "</div>"

        "<form action='/wizard-save' method='POST' id='wiz-form'>"

        // ---- Gruppe 1 ----
        "<h3 class='section-title' style='font-size:15px'>1) Wozu dient das Geraet?</h3>"
        "<div class='radio-row'>");
    wradio(w, "usecase", "endpoint", "Nur dieses Geraet online (Endpunkt)", uc, false, "");
    wradio(w, "usecase", "ap",       "AccessPoint fuer andere Geraete",     uc, !wifiUsable,
           wifiUsable ? "" :
           !wifiHw ? "Kein lokales WLAN erkannt (der ESP32-P4 hat keinen WLAN-Funk -- nur ueber "
                     "ESP-Hosted + Companion-C6). Ohne WLAN-Hardware ist kein AccessPoint moeglich; "
                     "der Zugang laeuft ueber Mobilfunk (LTE/DynDNS) + serielle Konsole."
                   : "WLAN-Hardware vorhanden, aber der WLAN-Stack ist unter LAN > WLAN auf 'Aus' "
                     "gestellt -- dort auf 'Automatisch' oder 'Immer an' umstellen, um AccessPoint "
                     "waehlen zu koennen.");
    w.write("</div>");

    // ---- Gruppe 2 (nur bei usecase=ap) ----
    w.write("<div id='wiz-g2'");
    if (!isAp) w.write(" style='display:none'");
    w.write(
        ">"
        "<h3 class='section-title' style='font-size:15px'>2) Internet fuer die AP-Clients?</h3>"
        "<div class='radio-row'>");
    wradio(w, "apinet", "0", "Nein - lokaler AP / nur Einrichtung", apNet ? "1" : "0", false, "");
    wradio(w, "apinet", "1", "Ja - Internet durchreichen",          apNet ? "1" : "0", false, "");
    w.write("</div></div>");

    // ---- Gruppe 3 (nur bei ap + apinet=1) ----
    w.write("<div id='wiz-g3'");
    if (!(isAp && apNet)) w.write(" style='display:none'");
    w.write(
        ">"
        "<h3 class='section-title' style='font-size:15px'>3) Zugangs- / Verwaltungsmodell</h3>"
        "<div class='radio-row'>");
    wradio(w, "accmodel", "repeater", "Repeater", am, !repCap,
           "Repeater braucht transparentes L2-Bridging (WDS/4-Address-Mode). Aktuell ist keine "
           "WLAN-Hardware mit WDS-Treiber erkannt (Onboard-WLAN kann es nicht) - ein AccessPoint ist "
           "hier immer ein eigenes WLAN mit NAT. Moeglich mit einem USB-WLAN-Adapter mit WDS-Treiber. "
           "Sonst Gateway nutzen.");
    wradio(w, "accmodel", "gateway", "Gateway",        am, false, "");
    wradio(w, "accmodel", "guest",   "Gaeste-Hotspot", am, false, "");
    w.write("</div></div>");

    // ---- Upstream (WAN) -- relevant bei Endpunkt ODER AP+Internet ----
    w.write("<div id='wiz-wan'");
    if (!((!isAp) || (isAp && apNet))) w.write(" style='display:none'");
    w.write(
        ">"
        "<label for='wiz-wansel'>Bevorzugter Internetzugang</label>"
        "<select id='wiz-wansel' name='wan' class='cam-select cfg-select'>"
        "<option value='auto'");
    {
        String wanPref = wanPreference();   // dieselbe WanPolicy wie WAN -> Netzzugang (eine Wahrheit)
        if (wanPref != "cellular" && wanPref != "wifi") w.write(" selected");
        w.write(">Automatisch (Mobilfunk, sonst WLAN)</option><option value='modem'");
        if (wanPref == "cellular") w.write(" selected");
        w.write(">Mobilfunk bevorzugen</option><option value='wifi'");
        if (wanPref == "wifi") w.write(" selected");
    }
    w.write(
        ">WLAN bevorzugen</option></select>"
        "<p class='cam-hint'>Dieselbe systemweite WAN-Wahl wie unter <strong>WAN &rarr; Netzzugang</strong> -- "
        "wirkt <strong>sofort</strong> (anders als die Betriebsart unten, die noch gestaged ist).</p>"
        "</div>");

    // ---- dynamischer Hinweistext ----
    w.write(
        "<div id='wiz-hint' class='cam-hint' style='margin-top:10px'></div>"
        "<button class='connect-button' type='submit'>Assistent speichern</button>"
        "</form>");

    // ---- Cascading + Hinweislogik (in-page) ----
    w.write(
        "<script>(function(){"
        "var f=document.getElementById('wiz-form');if(!f)return;"
        "function val(n){var e=f.querySelector('[name=\"'+n+'\"]:checked');return e?e.value:'';}"
        "function show(id,on){var e=document.getElementById(id);if(e)e.style.display=on?'':'none';}"
        "function upd(){"
        "var uc=val('usecase'),ai=val('apinet'),am=val('accmodel');"
        "var isAp=(uc==='ap'),apNet=isAp&&(ai==='1');"
        "show('wiz-g2',isAp);show('wiz-g3',apNet);show('wiz-wan',(!isAp)||apNet);"
        "var h='';"
        "if(!isAp){h='Das Geraet ist nur selbst online (Endpunkt). Der AccessPoint dient nur als "
        "Setup/Recovery (kein Internet fuer Clients).';}"
        "else if(!apNet){h='Lokaler AccessPoint ohne Internet fuer die Clients - nur Einrichtung / lokales Netz.';}"
        "else if(am==='repeater'){h='Repeater: Upstream WLAN, transparentes L2-Bridging. Umkonfiguration nur "
        "ueber den Werksreset-Taster oder die WAN-Seite (falls nicht deaktiviert).';}"
        "else if(am==='guest'){h='Gaeste-Hotspot: Internet erst nach Captive-Login (Benutzerliste/Passwort); "
        "Admin jederzeit ueber die Router-PIN. <em>Runtime folgt (Stub).</em>';}"
        "else{h='Gateway (NAT-Router): Upstream Modem oder WLAN. AP-Passwort unter <strong>LAN &rarr; WLAN "
        "&rarr; Sicherheit</strong> setzen - ohne Passwort ist das Internet-Gateway <strong>OFFEN</strong>. "
        "Verwaltung kuenftig ueber <strong>http://weirdos.local/</strong> oder die WAN-Seite.';}"
        "var he=document.getElementById('wiz-hint');if(he)he.innerHTML=h;"
        "}"
        "f.addEventListener('change',upd);upd();"
        "})();</script>");

    // ---- Status/Gates ----
    w.write(
        "<h2 class='section-title'>Status</h2>"
        "<div class='cam-bar' style='flex-direction:column;align-items:flex-start;gap:4px'>");
    w.write(String("<div><span>Abgeleiteter Modus:</span> <strong>") + NetworkModeService::modeLabel(c.mode) + "</strong></div>");
    w.write(String("<div><span>Laufzeit-Umschaltung:</span> ") + (networkMode.runtimeActive() ? "aktiv" : "gespeichert, noch kein Laufzeiteingriff") + "</div>");
    w.write(String("<div><span>Internet durchreichen (NAPT):</span> ") + (c.apInternet ? "gewaehlt -- <strong>noch nicht scharf</strong> (folgt hardware-getestet)" : "nein") + "</div>");
    w.write(String("<div><span>lwIP-NAPT (Gateway-Gate):</span> ") + (networkMode.naptCapable() ? "verfuegbar" : "nicht einkompiliert -- Gateway braucht lwIP-NAPT") + "</div>");
    w.write(String("<div><span>Lokales WLAN:</span> ") + (wifiHw ? "Funk vorhanden" : "keine WLAN-Hardware (P4) -- AccessPoint deaktiviert") + "</div>");
    w.write(String("<div><span>Repeater (WDS/L2-Bridging):</span> ") + (repCap ? "Hardware erkannt" : "keine WDS-faehige WLAN-Hardware erkannt") + "</div>");
    w.write("</div></section>");
}
