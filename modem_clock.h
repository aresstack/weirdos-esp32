// ============================================================================
// modem_clock.h -- Systemzeit aus dem Mobilfunknetz (EC200A: AT+CCLK? nach CTZU).
//
// Der P4 hat weder NTP (kein SNTP ueber den gebundenen Egress) noch eine Batterie-RTC.
// Fuer TLS-Zertifikatspruefung (ACME/Let's Encrypt: Server-Cert-Gueltigkeit, eigenes
// Cert-Ablaufdatum, Erneuerung) braucht das Geraet aber eine Wanduhr. Das Modem bekommt
// die Netzzeit vom Betreiber (NITZ); AT+CTZU=1 laesst es die Uhr automatisch nachfuehren,
// AT+CCLK? liefert "yy/MM/dd,hh:mm:ss+zz" (zz = Zeitzone in Viertelstunden).
//
// Aufruf NUR ueber den AT-Port (IF3), solange er frei ist -- also im Verbindungsaufbau
// VOR dem PPP-Dial bzw. im ECM-Setup (bei aktivem PPP ist IF3 nicht mehr erreichbar).
// ============================================================================
#ifndef MODEM_CLOCK_H
#define MODEM_CLOCK_H
#include <Arduino.h>
#include <time.h>

// Netzzeit per AT holen und als Systemzeit (UTC) setzen. true = Uhr gesetzt.
bool modemClockSync(uint8_t ifNum, uint8_t epOut, uint8_t epIn);

// Ist die Systemzeit plausibel (>= 2024)? Vor jeder Zertifikats-/Ablaufpruefung abfragen.
bool systemClockValid();

// Zeitpunkt (millis) der letzten erfolgreichen Synchronisation, 0 = nie.
uint32_t modemClockLastSyncMs();

// ISO-8601-UTC-Text der aktuellen Systemzeit ("-" wenn ungueltig), fuer UI/Konsole.
String systemClockIso();
// ISO-8601-UTC-Text eines Zeitpunkts ("-" wenn 0).
String systemClockIsoOf(time_t t);

#endif // MODEM_CLOCK_H
