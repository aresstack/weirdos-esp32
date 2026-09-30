// USB-Netzwerkadapter (CDC-NCM): das Board meldet sich am PC zusaetzlich als
// Netzwerkkarte. Zwei Zwecke (siehe MODULES.md, Baustein USB_NCM):
//   * Konfiguration/OTA der Webcam ueber das USB-Kabel, ohne WLAN im Image
//     (HTTP/WEBUI horchen auf dem USB-netif).
//   * USB-Tethering auf dem P4: Internet vom LTE-Modem an den PC (der P4 kann
//     gleichzeitig USB-Host fuers Modem und USB-Geraet fuer den PC).
//
// Der ESP ist die GERAETESEITE mit fester Adresse und einem DHCP-Server, der dem
// PC eine Adresse gibt. TinyUSB-NCM-Frames <-> ein rohes lwIP-netif (dasselbe
// Muster wie ec200a_ecm, nur andersherum: hier vergeben WIR die Adresse).
//
// Alles hinter WEIRDOS_FEATURE_USB_NCM: ohne den Baustein kein Byte davon; die
// Deskriptor-Erweiterung in usb_device_service ist ebenso gated.
#pragma once

#include <stdint.h>

struct netif;   // lwIP-Typ: global forward-deklariert (im Namespace entstuende ein NEUER Typ)

namespace cam { namespace usbnet {

// Bringt netif + DHCP-Server hoch (idempotent). Rueckgabe false, wenn kein
// Speicher/lwIP-Fehler -> der Aufrufer laeuft ohne USB-Netz weiter.
bool begin();
void end();
bool active();

// Feste Geraeteadresse (der PC bekommt .2 per DHCP). Fuer Status/Anzeige.
const char* deviceIpText();

// Natives lwIP-Interface fuer Registry/Zonen (network_platform: "usb-ncm").
// nullptr solange begin() nicht lief -- der Zonen-Planner zeigt dann "nicht aktiv".
struct netif* nativeNetif();

// Sendewarteschlange abarbeiten: lwIP legt ausgehende Frames im tcpip-Thread ab,
// tud_network_xmit() laeuft NUR hier -- im USB-Task neben tud_task() (die NCM-Klasse
// ist nicht thread-sicher). Aus UsbDeviceService::taskLoop() aufrufen.
void pump();

}} // namespace cam::usbnet
