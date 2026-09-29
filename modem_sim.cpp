// ============================================================================
// modem_sim.cpp -- siehe modem_sim.h.
// ============================================================================
#include "modem_sim.h"
#include "ec200a_modem.h"   // modemAtTest, modemSimPin, saveModemPrefs
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static String s_lastStatus = "";
static bool   s_pinTried   = false;   // je Boot genau EIN Versuch mit der konfigurierten PIN
static String s_pinTriedFor = "";

const String& modemSimLastStatus() { return s_lastStatus; }

static String setStatus(const String& s) {
    s_lastStatus = s;
    s_lastStatus.trim();
    return s_lastStatus;
}

String modemEnsureSimReady(uint8_t ifNum, uint8_t epOut, uint8_t epIn) {
    String cpin = modemAtTest(ifNum, epOut, epIn, "AT+CPIN?");
    if (cpin.indexOf("READY") >= 0) return setStatus("READY");
    if (cpin.indexOf("SIM PUK") >= 0)
        return setStatus("SIM gesperrt (PUK noetig) - PIN-Versuche aufgebraucht; nur mit PUK am PC/Telefon entsperrbar");
    if (cpin.indexOf("SIM PIN") < 0) {
        if (cpin.indexOf("CME ERROR") >= 0) return setStatus("keine SIM / SIM nicht bereit (" + cpin + ")");
        return setStatus("SIM-Status unklar: " + cpin);
    }
    // SIM verlangt eine PIN.
    if (!modemSimPin.length())
        return setStatus("SIM PIN noetig, aber keine PIN konfiguriert (WAN > Netzzugang > Zugangsdaten)");
    if (s_pinTried && s_pinTriedFor == modemSimPin)
        return setStatus("PIN-Versuch bereits fehlgeschlagen - kein weiterer Versuch (PUK-Schutz); PIN pruefen, dann Neustart");
    s_pinTried = true; s_pinTriedFor = modemSimPin;
    Serial.println("[SIM] SIM PIN verlangt -> konfigurierte PIN senden (einmalig je Boot)");
    String r = modemAtTest(ifNum, epOut, epIn, "AT+CPIN=\"" + modemSimPin + "\"");
    if (r.indexOf("OK") < 0) return setStatus("PIN abgelehnt (" + r + ")");
    for (int i = 0; i < 12; i++) {   // Entsperren + Re-Attach: bis ~6 s auf READY warten
        vTaskDelay(pdMS_TO_TICKS(500));
        cpin = modemAtTest(ifNum, epOut, epIn, "AT+CPIN?");
        if (cpin.indexOf("READY") >= 0) { s_pinTried = false; return setStatus("READY (PIN entsperrt)"); }
    }
    return setStatus("PIN gesendet, SIM meldet kein READY: " + cpin);
}

// ---- PIN-Verwaltung ----------------------------------------------------------------------
static String jsonStr(const String& s) {
    String e = s;
    e.replace("\\", "\\\\"); e.replace("\"", "\\\"");
    e.replace("\r", " ");    e.replace("\n", " ");
    e.trim();
    return e;
}

// "+CLCK: 1" -> 1, "+CLCK: 0" -> 0, sonst -1.
static int parseClck(const String& r) {
    int p = r.indexOf("+CLCK:");
    if (p < 0) return -1;
    p += 6;
    while (p < (int)r.length() && r[p] == ' ') p++;
    if (p >= (int)r.length()) return -1;
    if (r[p] == '1') return 1;
    if (r[p] == '0') return 0;
    return -1;
}

// Quectel: +QPINC: "SC",<pin_remaining>,<puk_remaining>
static bool parseQpinc(const String& r, int& pinLeft, int& pukLeft) {
    int p = r.indexOf("\"SC\",");
    if (p < 0) return false;
    p += 5;
    pinLeft = r.substring(p).toInt();
    int c = r.indexOf(',', p);
    if (c < 0) return false;
    pukLeft = r.substring(c + 1).toInt();
    return true;
}

String modemSimPinManage(const String& action, const String& pin, const String& newPin) {
    const uint8_t IF = 3, EO = 0x0F, EI = 0x86;
    bool ok = false;
    String msg;

    if (action == "enable" || action == "disable") {
        if (pin.length() < 4 || pin.length() > 8) msg = "PIN fehlt (4-8 Ziffern).";
        else {
            String r = modemAtTest(IF, EO, EI, String("AT+CLCK=\"SC\",") + (action == "enable" ? "1" : "0") + ",\"" + pin + "\"");
            ok = (r.indexOf("OK") >= 0);
            if (ok) {
                modemSimPin = (action == "enable") ? pin : String("");
                saveModemPrefs();
                s_pinTried = false;
                msg = (action == "enable")
                    ? "PIN-Sperre aktiviert. PIN in WeirdOS gespeichert (wird beim Verbinden gesendet)."
                    : "PIN-Sperre deaktiviert. Gespeicherte PIN in WeirdOS geloescht.";
            } else {
                msg = "Modem lehnt ab: " + r;
            }
        }
    } else if (action == "change") {
        if (pin.length() < 4 || newPin.length() < 4 || newPin.length() > 8) msg = "Alte und neue PIN noetig (4-8 Ziffern).";
        else {
            String r = modemAtTest(IF, EO, EI, "AT+CPWD=\"SC\",\"" + pin + "\",\"" + newPin + "\"");
            ok = (r.indexOf("OK") >= 0);
            if (ok) {
                modemSimPin = newPin;
                saveModemPrefs();
                s_pinTried = false;
                msg = "PIN geaendert. Neue PIN in WeirdOS gespeichert.";
            } else {
                msg = "Modem lehnt ab: " + r + " (Sperre muss dafuer aktiv sein, alte PIN korrekt)";
            }
        }
    } else {
        ok = true;   // reiner Status
    }

    // Status immer mitliefern (Sperre an/aus, CPIN-Zustand, Restversuche falls das Modem sie meldet).
    int locked = parseClck(modemAtTest(IF, EO, EI, "AT+CLCK=\"SC\",2"));
    String cpinRaw = modemAtTest(IF, EO, EI, "AT+CPIN?");
    String cpin = "";
    { int p = cpinRaw.indexOf("+CPIN:"); if (p >= 0) { int e = cpinRaw.indexOf('\r', p); if (e < 0) e = cpinRaw.length(); cpin = cpinRaw.substring(p + 6, e); cpin.trim(); } }
    int pinLeft = -1, pukLeft = -1;
    bool haveLeft = parseQpinc(modemAtTest(IF, EO, EI, "AT+QPINC=\"SC\""), pinLeft, pukLeft);

    String j = "{\"ok\":"; j += ok ? "true" : "false";
    j += ",\"msg\":\"";   j += jsonStr(msg); j += "\"";
    j += ",\"locked\":";  j += locked;
    j += ",\"cpin\":\"";  j += jsonStr(cpin); j += "\"";
    j += ",\"pinLeft\":"; j += haveLeft ? String(pinLeft) : String("null");
    j += ",\"pukLeft\":"; j += haveLeft ? String(pukLeft) : String("null");
    j += "}";
    return j;
}
