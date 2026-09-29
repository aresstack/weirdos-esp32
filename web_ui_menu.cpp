// ============================================================================
// web_ui_menu.cpp  --  Menueaufbau: die komplette Sidebar-Navigation.
// Ein Ort fuer alle Oberpunkte/Untermenues (FRITZ!Box-artig). Die Panels
// dazu liefern die ui_*.cpp; die Zuordnung erfolgt per data-tab / id.
// ============================================================================
#include "web_ui.h"

void renderMenu(WeirdUiWriter& w) {
    // Brand-Banner ueber die eigene Route /banner.png (separat vom Browser gecacht) --
    // NICHT mehr als 39-KB-Data-URI in JEDER Seite. Das inline-Banner drueckte den
    // fragmentierten internen Heap und riss den Seiten-Stream ab (kaputtes Banner-Bild).
    w.write(
        "<aside class='sidebar'>"
        // Klick aufs Logo = harter Neuladen der Wurzel: ist die Sitzung abgelaufen, kommt sofort die
        // Login-Seite (statt erst F5 zu druecken); ist sie gueltig, landet man auf der Uebersicht.
        "<div class='brand'><a href='/' title='Neu laden / zum Login' style='display:block'><img class='brand-logo' alt='WeirdOS' src='/banner.png'></a></div>"
        "<nav class='side-nav'>"
        "<button class='nav-item nav-top active' data-tab='overview'>Uebersicht</button>"
        "<button class='nav-l1 has-sub' data-group='g-setup'>"
        "Einrichtung<span class='caret'></span></button>"
        "<ul class='nav-sub' id='g-setup'>"
        "<li><button class='nav-item' data-tab='portal'>Setup</button></li>"   // Tabs: WLAN-Portal, UART
        "<li><button class='nav-item' data-tab='platform'>Plattform</button></li>"   // Board-Profil, Pinout, USB-Anschluesse (Mapping)
        "<li><button class='nav-item' data-tab='netmode'>Assistent</button></li>"
        "</ul>"
        "<button class='nav-l1 has-sub' data-group='g-wan'>"
        "WAN<span class='caret'></span></button>"
        "<ul class='nav-sub' id='g-wan'>"
        // Netzzugang = EINE Seite: oben die Wahl des Zugangs (Automatisch/Mobilfunk/WLAN-Client/Ethernet,
        // capability-gegated) = WanPolicy (frueher eigener Punkt "Uplink"), darunter die Einstellungen des
        // gewaehlten Zugangs (Mobilfunk: Anschluss/Zugangsdaten/IPv6/DNS/Frequenzen; WLAN-Client -> LAN > WLAN).
        // Bewusst nicht "Internet": auch eine Standleitung ohne Internet ist ein Netzzugang. Tab-ID
        // 'mobilfunk' beibehalten (JS-Hooks); alte Links #/wanport und #/zugang werden umgeleitet.
        "<li><button class='nav-item' data-tab='mobilfunk'>Netzzugang</button></li>"
        "<li><button class='nav-item' data-tab='freigaben'>Firewall &amp; NAT</button></li>"
        "</ul>"
        "<button class='nav-l1 has-sub' data-group='g-lan'>"
        "LAN<span class='caret'></span></button>"
        "<ul class='nav-sub' id='g-lan'>"
        "<li><button class='nav-item' data-tab='lanallg'>Allgemein</button></li>"
        "<li><button class='nav-item' data-tab='wlan'>WLAN</button></li>"
        "<li><button class='nav-item' data-tab='zones'>Netzzonen</button></li>"   // Phase 1: Verbindungen zwischen Netzen/VPNs
        "</ul>"
    );
    // IoT: externe Geraete, die sich per Funk oder Netz an dieses Geraet KOPPELN (BLE; spaeter
    // MQTT/HTTP-Geraete, Zigbee/Thread, andere MCU-Knoten). Abgrenzung: fest verbaute/verdrahtete
    // Hardware (Kamera, Audio, I2C/SPI, USB) steht unter System > Geraete. Bewusst nicht "Smarthome"
    // (Consumer-Begriff, das hier ist kein Consumer-Geraet) und nicht "M2M" (im Mobilfunk fest fuer
    // Modul/SIM/Tarif belegt -- waere neben WAN > Modem missverstaendlich).
    // IMMER im Menue: frueher per WEIRDOS_HAS_BT komplett wegkompiliert -> auf dem P4 (kein BT-Funk)
    // war der ganze Oberpunkt "verschwunden". Ohne Funk nennt das Panel ehrlich den Grund.
    w.write(
        "<button class='nav-l1 has-sub' data-group='g-iot'>"
        "IoT<span class='caret'></span></button>"
        "<ul class='nav-sub' id='g-iot'>"
        "<li><button class='nav-item' data-tab='bluetooth'>Bluetooth</button></li>"
        "</ul>");
    w.write(
        "<button class='nav-l1 has-sub' data-group='g-dienste'>"
        "Dienste<span class='caret'></span></button>"
        "<ul class='nav-sub' id='g-dienste'>"
        "<li><button class='nav-item' data-tab='dienste' data-psub='svc-dyndns'>DynDNS</button></li>"
        "<li><button class='nav-item' data-tab='vpn-cli'>VPN</button></li>"
        "</ul>"
        "<button class='nav-l1 has-sub' data-group='g-server'>"
        "Server<span class='caret'></span></button>"
        "<ul class='nav-sub' id='g-server'>"
        "<li><button class='nav-item' data-tab='vpn-srv'>VPN</button></li>"
        "<li><button class='nav-item' data-tab='video'>Video</button></li>"
        "</ul>"
        // --- System VOR Diagnose: Verwaltung ist der haeufigere Weg, Diagnose der letzte Punkt ---
        "<button class='nav-l1 has-sub' data-group='g-system'>"
        "System<span class='caret'></span></button>"
        "<ul class='nav-sub' id='g-system'>"
        "<li><button class='nav-item' data-tab='general'>Allgemein</button></li>"
        "<li><button class='nav-item' data-tab='peripherie'>Ger&auml;te</button></li>"
        "<li><button class='nav-item' data-tab='energy'>Energiemonitor</button></li>"
        "<li><button class='nav-item' data-tab='syssec'>Sicherheit</button></li>"
        "<li><button class='nav-item' data-tab='backup'>Sicherung</button></li>"
        "<li><button class='nav-item' data-tab='update'>Update</button></li>"
        "</ul>"
        // --- Diagnose: eigenes Hauptmenue, buendelt alle Standalone-Diagnosen (letzter Punkt) ---
        "<button class='nav-l1 has-sub' data-group='g-diag'>"
        "Diagnose<span class='caret'></span></button>"
        // Vier Seiten, je mit Tabs (kein Wildwuchs an Einzelpunkten):
        //   System   = Ereignisse | Heap-Map  (Laufzeit/Heap/CPU = Status -> Uebersicht)
        //   Modem    = Mobilfunk | Netzliste | SIM-Karte | Pipeline | Durchsatz | Entwickler (Tab-ID 'diagusb' beibehalten)
        //   Netzwerk = Rechner (Ping/Port-Scan) | Funk (Passiv-Monitor/Kanal-Scans) -- braucht WLAN-Stack
        //   Video    = Livebild (ex Server > Video > Diagnose)
        "<ul class='nav-sub' id='g-diag'>"
        "<li><button class='nav-item' data-tab='diagsys'>System</button></li>"
        "<li><button class='nav-item' data-tab='diagusb'>Modem</button></li>"
        "<li><button class='nav-item' data-tab='diagnet'>Netzwerk</button></li>"
        "<li><button class='nav-item' data-tab='diagvideo'>Video</button></li>"
        "</ul>"
        "</nav>"
    );
    // Abmelden: nur sinnvoll, wenn eine PIN aktiv ist (ohne PIN ist die Root ohnehin frei -> ein
    // Logout wuerde sofort wieder die App zeigen). Echtes POST-Formular, kein JS: /logout loescht
    // die Session serverseitig + das Cookie, Root rendert danach das PIN-Gate.
    if (devicePin.length() > 0) w.write(
        "<form class='nav-logout' method='POST' action='/logout'>"
        "<button class='nav-l1' type='submit' title='Sitzung beenden -- danach ist wieder die PIN noetig'>"
        "Abmelden</button></form>");
    w.write("</aside>");
}
