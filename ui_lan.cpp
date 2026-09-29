// ui_lan.cpp -- Content: LAN > "Allgemein".
//   LAN-seitige Grundeinstellung: Router-LAN-Subnetz (frueher in der Betriebsart).
//   Die Captive-DNS-Umleitung ist als Sicherheitsfunktion nach Einrichtung > Setup-Portal
//   gewandert. Persistenz ueber NetworkModeConfig; Plain-POST -> /lan-general-save.
#include "weirdos_features.h"   // WEIRDOS_FEATURE_WEBUI -- Seiten nur mit Weboberflaeche
#if WEIRDOS_FEATURE_WEBUI
#include "web_ui.h"
#include "network_mode.h"

void renderLanGeneral(WeirdUiWriter& w) {
    const NetworkModeConfig& c = networkMode.config();

    w.write(
        "<section id='tab-lanallg' class='tab-panel'>"
        "<h2 class='section-title'>LAN - Allgemein</h2>"
        "<form action='/lan-general-save' method='POST'>"

        "<label for='lan-sub'>Router-LAN-Subnetz</label>"
        "<input id='lan-sub' name='lansub' type='text' autocomplete='off' value='");
    w.write(escapeHtml(c.lanSubnet));
    w.write(
        "'>"
        "<p class='cam-hint'>Eigenes LAN fuer den Router-/Repeater-Betrieb (NICHT 4.3.2.1 -- das "
        "Setup-Portal bleibt separat). Standard 192.168.4.0/24. Wirkt erst mit der Laufzeit-Umschaltung "
        "(Assistent), heute rein gespeichert.</p>"
        "<p class='cam-hint'>Die <strong>Captive-DNS-Umleitung</strong> liegt jetzt unter "
        "<strong>Einrichtung &rarr; Setup-Portal</strong> (Sicherheits-/Lockout-Schutz).</p>"

        "<button class='connect-button' type='submit'>Speichern</button>"
        "</form>"
        "</section>");
}
#else
// Weboberflaeche nicht im Build (WEIRDOS_FEATURE_WEBUI=0): kein Seiteninhalt, nur die Renderer-Signaturen,
// damit web_ui.cpp (Seitentabelle) und Nachbarseiten unveraendert linken. Der HTTP-Server (Baustein HTTP)
// beantwortet dann PIN-Gate + JSON-API; sendAppPage() nennt den Grund.
#include "web_ui.h"
void renderLanGeneral(WeirdUiWriter& w) { (void)w; }
#endif // WEIRDOS_FEATURE_WEBUI
