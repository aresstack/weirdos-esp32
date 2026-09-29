// ============================================================================
// ec200a_ecm.h  --  CDC-ECM-Host-Pfad (Alternative zu PPPoS)
//
// PERFORMANT + plattformneutral: rohe Ethernet-Frames ueber USB-Bulk, KEIN
// RNDIS-/HDLC-Overhead (RNDIS = Microsoft, hier bewusst NICHT verwendet).
// Additiv: PPP (ec200a_modem.*) bleibt unveraendert und Default; ECM ist die
// per Web-UI umschaltbare Alternative hinter demselben Datenschicht-Gedanken.
//
// Voraussetzung am Modem (einmalig, ueber IF3-AT, dann Modem-Reboot):
//   AT+QCFG="usbnet",1     -> CDC-ECM (statt 3=RNDIS)         [persistent]
//   AT+QNETDEVCTL=1,1,1    -> Datenkanal an
// Danach exponiert das Modem: CDC-ECM Communication-IF (Class 0x02/Sub 0x06,
// Interrupt-IN) + Data-IF (Class 0x0A, Altsetting 1 = Bulk IN/OUT). Die
// konkreten Interface-Nummern/Endpoints werden zur Laufzeit aus dem
// Config-Descriptor entdeckt (ecmDiscover) - nichts hartkodiert.
// Plan/Stufen: doc/ecm-host-plan.md.
// ============================================================================
#ifndef EC200A_ECM_H
#define EC200A_ECM_H

#include <Arduino.h>
#include <cstdint>
#include <cstddef>

// ---- USB-CDC-ECM Klassen/Subklassen (ECM_-Praefix: USB_CLASS_* sind bereits
//      Makros in IDFs usb_types_ch9.h -> Namenskollision vermeiden) ----
static const uint8_t ECM_IF_CLASS_COMM  = 0x02;  // Communication-IF
static const uint8_t ECM_IF_SUBCLASS    = 0x06;  // Ethernet Networking Control Model
static const uint8_t ECM_IF_CLASS_DATA  = 0x0A;  // Data-IF (Bulk IN/OUT, Altsetting 1)

// ---- Class-specific Requests (bmRequestType 0x21, Communication-IF) ----
static const uint8_t CDC_SET_ETHERNET_PACKET_FILTER = 0x43;

// ---- SetEthernetPacketFilter-Bitmap (CDC-ECM-Spec) ----
static const uint16_t ECM_PF_PROMISCUOUS    = 0x0001;
static const uint16_t ECM_PF_ALL_MULTICAST  = 0x0002;
static const uint16_t ECM_PF_DIRECTED       = 0x0004;
static const uint16_t ECM_PF_BROADCAST      = 0x0008;
static const uint16_t ECM_PF_MULTICAST      = 0x0010;

// ---- Notification-Codes (Interrupt-IN der Communication-IF) ----
static const uint8_t CDC_NOTIFY_NETWORK_CONNECTION    = 0x00;
static const uint8_t CDC_NOTIFY_CONNECTION_SPEED_CHG  = 0x2A;

// Ethernet-Rahmen: Standard-MTU 1500 -> Frame bis 1514 B (ohne FCS ueber USB).
static const size_t ECM_MAX_ETH_FRAME = 1514;

class Ec200aEcm {
public:
    bool   begin();                 // Discovery + Interfaces + PacketFilter + Bulk-Pools + netif/DHCP
    void   stop();                  // netif abbauen, Interfaces freigeben (Device lebt)
    void   onGone();                // Modem weg (Reboot/Unplug): NUR lwIP+Flags, keine USB-Ops
    bool   isUp() const;
    String statusText() const;      // "ECM up, IP x.x.x.x" | "ECM aus" | Fehlergrund
    String rateJson() const;        // "ecmtx":..,"ecmrx":.. Fragment fuer sendModemJson

private:
    bool up_ = false;
};

extern Ec200aEcm ec200aEcm;

// Byte-Zaehler des ECM-Datenpfads (der Speedtest nutzt sie im ECM-Modus).
extern volatile uint32_t g_ecmRxBytes, g_ecmTxBytes;

// Oeffentliche WAN-IPv4 im ECM-Modus (aus CGPADDR, beim begin gecacht; "" wenn aus).
// Fuer DynDNS: im ECM-Modus hat der ESP-netif nur die private Modem-Subnetz-IP.
String ecmWanIp();   // reale ECM-WAN-IPv4 (aus dem netif; "" wenn aus). Read-only.
String ecmWanIp6();  // globale ECM-WAN-IPv6 (SLAAC/RA; "" wenn keine). Nur ECM kann IPv6.
void   ecmSetDefaultRoute();   // ECM als Default-Route (ESP-Outbound ueber Mobilfunk, fuer DynDNS)
String ecmDefaultRouteIp();    // IP des aktuellen Default-netif (Diagnose)

struct netif;                  // Vorwaertsdeklaration (kein lwIP-Include im Header)
struct netif* ecmNetifHandle();   // rohes lwIP-netif des ECM-Pfads (nullptr wenn aus) - fuer Underlay-Bindung

// Supervisor: wartet auf ein enumeriertes Modem und ruft begin() (Retry).
// Wird in setup() gestartet, wenn modemDataMode == "ecm".
void ecmStartSupervisor();
void ecmStopSupervisor();
// PPP-Rueckfall (3x ECM-Start fehlgeschlagen bei anwesendem Modem, kein SIM-Problem): aktiv?
// Reset bei manuellem Verbinden / Datenschicht-Wechsel -> ECM wird erneut versucht.
bool ecmFallbackActive();
void ecmFallbackReset();

// Vom USB-DEV_GONE-Handler (Modem-Reboot/Unplug): ECM lwIP-seitig abbauen, damit
// die Interface-Freigabe + device_close sauber laufen und das Re-Enum klappt.
void ecmOnDeviceGone();

// Bequemer Einmal-Schalter am Modem (aktueller Modus, ueber IF3-AT):
// AT+QCFG="usbnet",<mode> (1=ECM,3=RNDIS) + AT+QNETDEVCTL=1,1,1. Reboot noetig.
String ecmSwitchModemUsbnet(int mode);
// NIC-Betriebsart des Modem-NIC: AT+QCFG="nat",<0=Routing|1=NIC>. Persistent im Modem, wirkt nach Reboot.
String ecmSwitchModemNat(int nat);

#endif // EC200A_ECM_H
