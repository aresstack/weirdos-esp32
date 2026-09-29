// ui_overview.cpp -- Content: Oberpunkt "Uebersicht"
#include "web_ui.h"

void renderOverview(WeirdUiWriter& w) {
    w.write(
        "<section id='tab-overview' class='tab-panel active'>"
        "<h2 class='section-title'>Uebersicht</h2>"
    );
    w.write(createStatusBlock());
    // --- System: Laufzeit/Heap/PSRAM/CPU (ex Diagnose > System > Funktion; /sysinfo.json, Refresh-
    //     Icon + beim Oeffnen der Uebersicht) + Modem-/Kamera-Zustand. CPU/Kamera serverseitig
    //     vorbelegt, Modem-Status live (Uebersichts-Poll schreibt d.status nach #modem-status).
    w.write(uiTitleWithAction("System", "si-refresh", "", UI_ICON_REFRESH, "Systemwerte aktualisieren"));
    w.write(
        "<div class='info'>"
        "<div><span>Laufzeit</span><span id='si-uptime'>-</span></div>"
        "<div><span>Systemzeit (UTC, aus dem Mobilfunknetz)</span><span id='si-time'>-</span></div>"
        "<div><span>Freier Heap</span><span id='si-heap'>-</span></div>"
        "<div><span>Heap-Minimum</span><span id='si-heapmin'>-</span></div>"
        "<div><span>PSRAM frei</span><span id='si-psram'>-</span></div>"
        "<div><span>CPU-Takt</span><span id='si-cpu'>");
    w.write(String(getCpuFrequencyMhz()) + " MHz");
    w.write("</span></div><div><span>Mobilfunk-Modem</span><span id='modem-status'>");
    w.write(escapeHtml(modemStatusText()));
    w.write("</span></div><div><span>Kamera</span><span id='si-cam'>");
    w.write(cameraReady ? "aktiv" : "aus");
    w.write(
        "</span></div></div>"
        // --- Mobilfunk (Modem-Identitaet + Netz + IPs; frueher WAN > Modem > Uebersicht). Die Werte
        //     kommen aus /modem-json: EINMAL beim Seitenaufruf und danach auf Knopfdruck -- kein
        //     Dauer-Poll. Bei bestehender Verbindung antwortet der Endpunkt aus dem Snapshot vom
        //     Verbindungsaufbau (kein Live-AT); nur getrennt dauert die Abfrage einige Sekunden.
        //     Funkwerte/SIM-Details: Diagnose > Modem (gleicher Abruf).
    );
    w.write(uiTitleWithAction("Mobilfunk", "", "js-mj-refresh", UI_ICON_REFRESH,
                              "Mobilfunkdaten vom Modem abrufen (AT-Abfrage, dauert einige Sekunden)"));
    w.write(
        "<div class='info'>"
        "<div><span>Modell</span><span id='mj-model'>-</span></div>"
        "<div><span>Firmware</span><span id='mj-firmware'>-</span></div>"
        "<div><span>Betreiber</span><span id='mj-operator'>-</span></div>"
        "<div><span>Registrierung</span><span id='mj-reg'>-</span></div>"
        "<div><span>Funkstandard</span><span id='mj-rat'>-</span></div>"
        "<div><span>IPv4</span><span id='mj-ipv4'>-</span></div>"
        "<div><span>IPv6</span><span id='mj-ipv6'>-</span></div>"
        "</div>"
        "<p class='scan-status js-mj-msg'></p>"
        // --- Generalisiertes WAN + Internet-Check (wan_service, Hintergrund-Task) ---
        "<h2 class='section-title'>WAN / Internet</h2>"
        "<div class='info'>"
        "<div><span>Internet (WAN)</span><span class='js-wan-inet'>pruefe...</span></div>"
        "<div><span>WAN-Interface</span><span class='js-wan-if'>-</span></div>"
        "</div>"
        // Ein isoliertes Poll-Script (updated auch die gleichnamigen Klassen auf der WAN-Seite).
        "<script>(function(){function u(){fetch('/wan-status.json',{cache:'no-store'})"
        ".then(function(r){return r.json();}).then(function(d){"
        "var t=d.everChecked?(d.internetOk?'OK':'kein Internet'):'pruefe...';"
        "var s=(d.iface||'-')+(d.ip&&d.ip!=='-'?' ('+d.ip+')':'');"
        "document.querySelectorAll('.js-wan-inet').forEach(function(x){x.textContent=t;});"
        "document.querySelectorAll('.js-wan-if').forEach(function(x){x.textContent=s;});"
        "}).catch(function(){});}u();setInterval(u,10000);})();</script>"
    );
    // Interface-Registry (technische Interfaces hinter den logischen Zugaengen) -- Status, daher
    // hier und nicht unter Diagnose. Block in ui_wan.cpp.
    renderWanInterfaces(w);
    // --- VPN: EIN Statusmodell fuer alle Tunnel (vpn_status.h, /vpn-status.json). Die Dienst-Seiten
    //     (Dienste/Server > VPN) zeigen keinen Status mehr -- nur hier. Zeilen baut die JS je Dienst.
    w.write(uiTitleWithAction("VPN", "vpn-refresh", "", UI_ICON_REFRESH, "VPN-Status aktualisieren"));
    w.write(
        "<div class='info' id='vpn-table'>"
        "<div><span>WireGuard</span><span id='vpn-wg'>-</span></div>"
        "<div><span>IPsec/IKEv2</span><span id='vpn-ipsec'>-</span></div>"
        "</div>"
        "<p id='vpn-detail' class='cam-hint'></p>"
    );
    // --- Online-Monitor (aus WAN hierher gezogen). Reset-Icon in der Titelzeile; Download/Upload
    //     als "aktuell / max" in EINER Zeile mit fester Breite je Seite (Tooltip erklaert die Werte).
    w.write(uiTitleWithAction("Online-Monitor", "om-reset", "", UI_ICON_RESET,
                              "Spitzenwerte (max) von Download/Upload zuruecksetzen"));
    w.write(
        "<p class='cam-hint'>Live-Datenverkehr ueber die Mobilfunkverbindung (PPP oder ECM).</p>"
        "<div class='info'>"
        "<div><span>Status</span><span id='om-ppp'>-</span></div>"
        "<div><span>WAN-IP</span><span id='om-ip'>-</span></div>"
        "<div><span>Download</span><span class='om-pair' title='links: aktuell (Download) / rechts: "
        "Spitzenwert (max) seit dem letzten Zuruecksetzen'><span id='om-rx' class='om-num'>-</span> / "
        "<span id='om-rxmax' class='om-num'>-</span> Mbit/s</span></div>"
        "<div><span>Upload</span><span class='om-pair' title='links: aktuell (Upload) / rechts: "
        "Spitzenwert (max) seit dem letzten Zuruecksetzen'><span id='om-tx' class='om-num'>-</span> / "
        "<span id='om-txmax' class='om-num'>-</span> Mbit/s</span></div>"
        "<div><span>Empfangen gesamt</span><span id='om-rxtot'>-</span></div>"
        "<div><span>Gesendet gesamt</span><span id='om-txtot'>-</span></div>"
        "</div>"
        "<p class='cam-hint'>Je Zeile: aktuell / Spitzenwert (max). Max wird im Hintergrund gemessen -- "
        "auch wenn ein anderes Menue offen ist. Details unter Diagnose -> Modem (Pipeline) bzw. "
        "Server -> Video.</p>"
        "</section>"
    );
}
