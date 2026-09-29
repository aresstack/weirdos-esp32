// ============================================================================
// settings_backup.h -- Zentraler, vollstaendiger Sicherungs-Manager.
//
// Statt hand-gepflegter Feldliste (unvollstaendig, veraltet schnell) iteriert der
// Manager generisch die NVS-Partition -> ALLE Einstellungen aller Namespaces sind
// automatisch enthalten (WLAN/Kamera/Modem/DynDNS/WAN-Policy/Assistent/Setup-Guard...).
// Secrets (PIN/Passwoerter/PSK/Keys) werden per Denylist AUSGESCHLOSSEN -> die
// Sicherungsdatei enthaelt keine Geheimnisse (nach Restore neu zu setzen).
//
// Format (zeilenbasiert, robust; String-Werte base64-kodiert -> verlustfrei):
//   WEIRDOS-BACKUP v1
//   <namespace>|<key>|<typ s|i|u|8>|<wert>
// ============================================================================
#pragma once
#include <Arduino.h>

// Komplette Sicherung als Text erzeugen (ohne Secrets).
String settingsBackupExport();

// Sicherung einspielen: schreibt jede Zeile in den NVS zurueck. Gibt die Zahl der
// uebernommenen Eintraege zurueck. Der Aufrufer startet danach neu (Reboot noetig,
// damit alle Subsysteme ihre Config frisch laden).
int settingsBackupImport(const String& body);
