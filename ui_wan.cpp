// ui_wan.cpp -- Bausteine fuer WAN > "Netzzugang" (ui_internet.cpp) und Diagnose > Netzwerk.
//
// renderWanAccessChoice(): die EINZIGE System-WAN-Wahl als Radiogruppe (wie im Assistenten):
//   Automatisch / Mobilfunk / WLAN-Client / Ethernet -- capability-gegated (WLAN nur mit laufendem
//   WLAN-Stack, Ethernet nur mit erkanntem PHY -> heute keiner). Der Nutzer waehlt einen LOGISCHEN
//   Zugang, NICHT ein internes Interface; die Wahl ist die systemweite WanPolicy (WanService
//   konsumiert sie). "Mobilfunk" loest intern ueber die Datenschicht (Anschluss-Tab: PPP|ECM) auf.
//   Dazu der aktuelle Zustand (Status, klar getrennt von der Wahl).
// renderWanInterfaces(): technische Interface-Registry -- Status (Uebersicht), keine Nutzerwahl
//   (Uebersicht > Interfaces).
#include "web_ui.h"
#include "network_registry.h"
#include "wan_policy.h"
#include "wan_service.h"
#include "wifi_caps.h"      // wifiStackShouldInit(): WLAN-Client nur mit laufendem WLAN-Stack waehlbar
#include "ec200a_modem.h"   // modemDataMode
#include "modem_datalink.h" // modemLinkModeName(): Datenschicht-Anzeige inkl. PPP-Rueckfall

static void statusRow(WeirdUiWriter& w, const char* k, const String& v) {
    w.write("<div><span>");
    w.write(k);
    w.write("</span><span>");
    w.write(escapeHtml(v.length() ? v : String("-")));
    w.write("</span></div>");
}

// Radio-Option im Assistenten-Stil (wiz-opt); ausgegraut mit ehrlichem Tooltip, wenn die
// Hardware/der Stack sie nicht tragen kann.
static void prefRadio(WeirdUiWriter& w, const char* val, const char* label, const String& cur,
                      bool disabled, const char* title) {
    w.write("<label class='wiz-opt");
    if (disabled) w.write(" is-disabled");
    w.write("'");
    if (title && title[0]) { w.write(" title='"); w.write(title); w.write("'"); }
    w.write("><input type='radio' name='pref' value='");
    w.write(val);
    w.write("'");
    if (cur == val) w.write(" checked");
    if (disabled) w.write(" disabled");
    w.write("><span>");
    w.write(label);
    w.write("</span></label>");
}

void renderWanAccessChoice(WeirdUiWriter& w) {
    String pref = wanPreference();
    NetIface act; bool haveActive = wanResolve(act);
    bool activeCell = haveActive && act.id != "wifi-sta";
    String dataMode = modemLinkModeName();   // "CDC-ECM" | "PPP" | "PPP (Rueckfall, ...)"
    bool wifiOk = wifiStackShouldInit();
    // Ausgegraute Option nie aktiv lassen (WLAN-Praeferenz ohne WLAN-Stack -> Automatisch).
    if (pref == "wifi" && !wifiOk) pref = "auto";

    w.write(
        "<h2 class='section-title'>Zugang waehlen</h2>"
        "<p class='cam-hint'>Ueber welchen Weg das Geraet ins Netz geht -- die <strong>systemweite WAN-Wahl</strong>. "
        "Darunter erscheinen die Einstellungen des gewaehlten Zugangs. Eine reine Standleitung ohne Internet "
        "ist genauso ein Netzzugang; der Internet-Check ist nur eine Anzeige.</p>"
        "<form action='/wan-policy-save' method='POST'>"
        "<div class='radio-row'>");
    prefRadio(w, "auto",     "Automatisch (Mobilfunk, sonst WLAN)", pref, false, "");
    prefRadio(w, "cellular", "Mobilfunk (Modem)",                   pref, false, "");
    prefRadio(w, "wifi",     "WLAN-Client",                         pref, !wifiOk,
              wifiOk ? "" : "Kein laufender WLAN-Stack: entweder hat dieses Board keinen WLAN-Funk (ESP32-P4 ohne "
                            "ESP-Hosted-Companion) oder der Stack ist unter LAN > WLAN auf 'Aus' gestellt. "
                            "Ohne WLAN-Stack kann das Geraet kein Client in einem fremden WLAN sein.");
    prefRadio(w, "ethernet", "Ethernet (PHY)",                       pref, true,
              "Kein Ethernet-PHY erkannt. Der ESP32-P4 hat zwar einen EMAC, aber auf diesem Board ist kein "
              "PHY-Baustein bestueckt und in dieser Firmware kein Ethernet-Treiber eingebunden. Wird waehlbar, "
              "sobald ein PHY erkannt wird.");
    w.write(
        "</div>"
        "<p class='cam-hint'>Automatisch = Mobilfunk bevorzugt, WLAN als Rueckfall. Wirkt sofort nach dem "
        "Speichern. Per-Dienst-Ausnahmen (IPsec/WireGuard/DynDNS) bleiben unberuehrt.</p>"
        "<button class='connect-button' type='submit'>Zugang speichern</button>"
        "</form>"

        // ---- Aktueller Zustand (Status, klar getrennt von der Wahl) ----
        "<h2 class='section-title'>Aktueller Zustand</h2>"
        "<div class='info'>");
    statusRow(w, "Gewaehlter Zugang", pref == "wifi" ? "WLAN-Client" : (pref == "cellular" ? "Mobilfunk" : "Automatisch (Mobilfunk, sonst WLAN)"));
    statusRow(w, "Aktiver Zugang",    haveActive ? (act.id == "wifi-sta" ? "WLAN-Client" : "Mobilfunk") : String("-"));
    statusRow(w, "Geraet",            haveActive ? act.device : String("-"));
    statusRow(w, "Datenschicht",      activeCell ? dataMode : String("-"));
    statusRow(w, "Technisches Interface", haveActive ? act.id : String("-"));
    statusRow(w, "IP-Adresse",        haveActive ? act.ip : String("-"));
    statusRow(w, "Internet",          wanService.everChecked() ? (wanService.internetOk() ? "erreichbar" : "nicht erreichbar (Standleitung/Intranet?)") : String("pruefe ..."));
    w.write("</div>");
}

void renderWanInterfaces(WeirdUiWriter& w) {
    NetIface ifs[8]; int n = 0;
    netRegistryBuild(ifs, 8, n);
    w.write(
        "<h2 class='section-title'>Interfaces</h2>"
        "<p class='cam-hint'>Die konkreten Netzwerk-Interfaces hinter den logischen Zugaengen (Wahl unter "
        "WAN &rarr; Netzzugang): Rolle, Geraet und Zustand/IP.</p>"
        "<table class='info' style='width:100%;border-collapse:collapse'>"
        "<tr><th style='text-align:left'>Interface</th><th style='text-align:left'>Rolle</th>"
        "<th style='text-align:left'>Geraet</th><th style='text-align:left'>Status</th></tr>");
    for (int i = 0; i < n; i++) {
        String role = ((ifs[i].roles & NETROLE_WAN) ? String("WAN") : String("")) +
                      ((ifs[i].roles & NETROLE_LAN) ? String((ifs[i].roles & NETROLE_WAN) ? "/LAN" : "LAN") : String(""));
        String dev = ifs[i].device + (ifs[i].port.length() ? " @ " + ifs[i].port : String(""));
        String st  = ifs[i].up ? (ifs[i].ip.length() ? ifs[i].ip : String("aktiv")) : String("aus");
        w.write("<tr><td>");
        w.write(escapeHtml(ifs[i].id));
        w.write("</td><td>");
        w.write(escapeHtml(role.length() ? role : String("-")));
        w.write("</td><td>");
        w.write(escapeHtml(dev.length() ? dev : String("-")));
        w.write("</td><td>");
        w.write(escapeHtml(st));
        w.write("</td></tr>");
    }
    w.write("</table>");
}
