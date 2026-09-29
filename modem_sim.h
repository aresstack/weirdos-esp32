// ============================================================================
// modem_sim.h -- SIM-Bereitschaft (PIN beim Verbinden) + PIN-Verwaltung auf der Karte.
//
// EIN gemeinsamer Pfad fuer PPP und CDC-ECM: vor Kontext/Datenkanal wird die SIM
// entsperrt, falls sie eine PIN verlangt. Frueher tat das nur der PPP-Pfad, ECM
// (jetzt Produktions-Default) gar nicht -- eine Karte mit PIN haette ueber ECM nie
// funktioniert. Ausserdem: die konfigurierte PIN wird je Boot GENAU EINMAL gesendet.
// Ein abgelehnter Versuch wird nicht wiederholt (drei falsche Versuche sperren die
// SIM -> PUK), auch nicht durch Supervisor-Retries.
// ============================================================================
#ifndef MODEM_SIM_H
#define MODEM_SIM_H

#include <Arduino.h>

// Liest AT+CPIN? auf dem angegebenen AT-Interface (IF3 = 3/0x0F/0x86, PPP-Dial = IF4).
// "SIM PIN" + konfigurierte PIN -> AT+CPIN=<pin> (einmalig je Boot), dann bis ~6 s auf READY warten.
// Rueckgabe beginnt mit "READY", wenn die SIM nutzbar ist; sonst ein Klartext-Grund.
String modemEnsureSimReady(uint8_t ifNum, uint8_t epOut, uint8_t epIn);

// Letzter Status-Text (fuer UI/Diagnose), "" solange nie geprueft.
const String& modemSimLastStatus();

// PIN-Verwaltung auf der Karte, nur bei GETRENNTER Verbindung (IF3-AT):
//   action = "status" | "enable" | "disable" | "change"
//   enable/disable brauchen pin; change braucht pin (alt) + newPin. Bei Erfolg wird die PIN in
//   WeirdOS mitgefuehrt (enable/change -> gespeichert, disable -> geloescht), damit der naechste
//   Verbindungsaufbau ohne weitere Nutzeraktion klappt.
// Rueckgabe: JSON {"ok":bool,"msg":"..","locked":-1|0|1,"cpin":"..","pinLeft":n|null,"pukLeft":n|null}
String modemSimPinManage(const String& action, const String& pin, const String& newPin);

#endif // MODEM_SIM_H
