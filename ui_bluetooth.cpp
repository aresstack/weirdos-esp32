// ============================================================================
// ui_bluetooth.cpp -- View: Bluetooth (LE) - Geraetesuche + best-effort-Kopplung.
// Analog zum WLAN-Netzwerk-Scan. Logik/Endpoints: bt_scan.* + esp32-modem-host.ino.
// Hardware-Grenze steht ehrlich im Panel: S3 = nur BLE, kein Classic/Audio; P4 = gar kein Funk.
// Das Panel wird IMMER gerendert (Menuepunkt IoT > Bluetooth bleibt sichtbar).
// ============================================================================
#include "web_ui.h"

void renderBluetooth(WeirdUiWriter& w) {
#if WEIRDOS_HAS_BT
    w.write(
        "<section id='tab-bluetooth' class='tab-panel'>"
        "<h2 class='section-title'>Bluetooth (LE)</h2>"
        "<p class='cam-hint'>Sucht nach Bluetooth-LE-Geraeten in der Umgebung (Name, Adresse, "
        "Signalstaerke, beworbene Dienste) - analog zum WLAN-Scan. "
        "<strong>Hinweis zur Hardware:</strong> Der ESP32-S3 beherrscht <em>nur</em> Bluetooth&nbsp;LE, "
        "<em>kein</em> Bluetooth&nbsp;Classic. Klassisches BT-Audio/Mikrofon (A2DP/HFP - z.&nbsp;B. "
        "Kopfhoerer, Freisprecher) ist auf diesem Chip technisch nicht moeglich; das ist eine "
        "Hardware-Grenze, keine fehlende Software.</p>"
        "<p class='cam-hint'>Der Bluetooth-Stack wird erst beim Start einer Suche geladen (er belegt "
        "internen Speicher, der hier knapp ist) und kann danach wieder freigegeben werden. "
        "Solange eine BLE-Suche laeuft, ist der WLAN-Funk-Scan gesperrt (und umgekehrt) - beide "
        "teilen sich das 2,4-GHz-Funkteil.</p>"
        "<div class='info'>"
        "<div><span>Geraete suchen</span><span>verfuegbar</span></div>"
        "<div><span>BLE verbinden (Test)</span><span>verfuegbar</span></div>"
        "<div><span>Pairing / Bonding</span><span>noch nicht implementiert</span></div>"
        "<div><span>Audio / Mikrofon</span><span>Hardware-Grenze (S3 = kein Classic)</span></div>"
        "</div>"

        "<div class='info'>"
        "<div><span>Status</span><span id='bt-state'>-</span></div>"
        "<div><span>Interner Heap frei</span><span id='bt-heap'>-</span></div>"
        "</div>"

        "<label for='bt-secs'>Suchdauer (Sekunden)</label>"
        "<input id='bt-secs' type='number' min='2' max='30' value='6' style='max-width:120px'>"
        "<div style='display:flex;gap:8px;flex-wrap:wrap;margin-top:8px'>"
        "<button id='bt-scan' class='connect-button' type='button'>Geraete suchen</button>"
        "<button id='bt-release' class='cam-button' type='button'>BT-Stack freigeben</button>"
        "</div>"
        "<p id='bt-msg' class='scan-status'></p>"

        "<div id='bt-list' style='margin-top:12px'></div>"

        "<p class='cam-hint' style='margin-top:12px'><strong>Verbinden</strong> ist ein reiner "
        "BLE-<em>Verbindungstest</em> (GATT-Services zaehlen, dann trennen) - <strong>noch kein "
        "Pairing/Bonding</strong> (kein Passkey/Security-Flow). Echtes Bonding ist der naechste "
        "Slice und braucht ein konkretes Zielgeraet.</p>"
        "</section>"
    );
#else
    // Kein BT-Funk auf dieser Hardware (SOC_BT_SUPPORTED=0, z.B. ESP32-P4 ohne ESP-Hosted-Companion).
    // Panel bleibt sichtbar und nennt den Grund -- Menuepunkt nicht verstecken (Konsistenz mit
    // LAN > WLAN). Bewusst OHNE die Bedien-IDs (bt-scan/bt-status): das Bluetooth-JS in
    // web_ui_assets.cpp prueft auf #bt-scan und wuerde sonst /bt-status.json pollen, das hier gar
    // nicht registriert ist (Routen in der .ino ebenfalls unter WEIRDOS_HAS_BT).
    w.write(
        "<section id='tab-bluetooth' class='tab-panel'>"
        "<h2 class='section-title'>Bluetooth (LE)</h2>"
        "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;"
        "border-radius:6px;margin:8px 0'><p><strong>Kein Bluetooth-Funk auf dieser Hardware.</strong> "
        "Der ESP32-P4 hat keinen eigenen WLAN-/Bluetooth-Funk; Bluetooth ginge nur ueber ESP-Hosted "
        "mit einem Companion-Chip (ESP32-C6), der auf diesem Board nicht bestueckt ist. Ein USB-"
        "Bluetooth-Adapter hilft nicht: dafuer gibt es in ESP-IDF/Arduino keinen Treiber.</p></div>"
        "<div class='fields-inactive'>"
        "<p class='cam-hint'>Auf Hardware mit BLE (z.B. ESP32-S3) bietet diese Seite: Geraetesuche "
        "(Name, Adresse, Signalstaerke, Dienste), BLE-Verbindungstest und Freigabe des BT-Stacks. "
        "Der Stack wird erst bei der ersten Suche geladen (belegt internen Speicher).</p>"
        "<div class='info'>"
        "<div><span>Geraete suchen</span><span>kein Funk</span></div>"
        "<div><span>BLE verbinden (Test)</span><span>kein Funk</span></div>"
        "<div><span>Pairing / Bonding</span><span>noch nicht implementiert</span></div>"
        "<div><span>Audio / Mikrofon</span><span>Hardware-Grenze (BLE-only-Chips: kein Classic)</span></div>"
        "</div>"
        "</div>"
        "</section>"
    );
#endif
}
