// ============================================================================
// modem_datalink.h  --  Neutrale Modem-Datenlink-Schicht (PPP | ECM)
//
// GENAU EINE Stelle entscheidet den Datenpfad anhand von modemDataMode. Der
// Rest von WeirdOS (Web-UI, serielle Konsole, Autostart, WAN, DynDNS) ruft NUR
// diese API und kennt weder pppStart()/pppStop() noch ec200aEcm.begin()/.stop().
//
// PPP (ec200a_modem.*) und ECM (ec200a_ecm.*) bleiben die konkreten Backends;
// hier wird nur dispatcht. Damit verschwindet die bisherige PPP-Zentrik: neue
// Startpfade koennen nicht mehr versehentlich "modemConnect()" == PPP erwischen.
// ============================================================================
#ifndef MODEM_DATALINK_H
#define MODEM_DATALINK_H

#include <Arduino.h>

String modemLinkConnect();       // ausgewaehlten Datenpfad aufbauen (Rueckgabe = Meldung fuer UI/Konsole)
String modemLinkDisconnect();    // ausgewaehlten Datenpfad trennen
bool   modemLinkIsUp();          // Datenlink aktiv?
String modemLinkWanIp();         // oeffentliche WAN-IP des aktiven Pfads ("" wenn keine)

void   startModemDataSupervisor();  // Autostart/Auto-Retry des ausgewaehlten Pfads (Boot/Wechsel)
void   stopModemDataSupervisor();   // ausgewaehlten Pfad + dessen Supervisor stoppen

const char* modemLinkModeName();    // "PPP" | "CDC-ECM" (Anzeige)

#endif // MODEM_DATALINK_H
