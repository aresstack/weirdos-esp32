// ============================================================================
// ipsec_config_fields.h -- EIN typisierter Feld-Layer fuer die IPsec-Konfiguration.
//
// Grundsatz: Jede Einstellung, die die Web-UI liest oder schreibt, ist hier GENAU EINMAL beschrieben
// (Schluessel, Typ, erlaubte Werte, Getter/Setter, Web-Formularname). Web-POST-Handler UND serielle
// Konsole gehen ueber dieselben Funktionen; Parsen/Bereichs-/Enum-/Algorithmen-Pruefung passiert hier,
// die semantische Pruefung + NVS-Persistenz in IpsecService::saveConfig(). So koennen die beiden
// Oberflaechen nicht auseinanderlaufen ("UI kann X, Serial nicht" / verschiedene Validierung).
//
// Secrets (PSK, EAP-Passwort) sind KEINE IpsecConfig-Felder: sie werden nur gesetzt, nie ausgegeben
// (Anzeige = gesetzt/nicht gesetzt + Laenge) und wandern getrennt an saveConfig().
// ============================================================================
#ifndef IPSEC_CONFIG_FIELDS_H
#define IPSEC_CONFIG_FIELDS_H

#include <Arduino.h>
#include "ipsec_service.h"       // IpsecConfig
#include "ipsec_crypto_caps.h"   // IpsecAlgoGroup (Allowlist-Felder)

enum class IpsecFieldType : uint8_t { Bool, Int, Text, Enum, AlgoList, Secret };
enum class IpsecFieldRole : uint8_t { Both, Client, Server };

struct IpsecFieldDef {
    const char*    key;        // Konsolen-Schluessel, leitungsnah ("ike-hash", "dh", "local-id-type")
    const char*    webArg;     // Formularname des POST /ipsec-save (bestehende Web-Keys, nullptr = kein Web-Feld)
    IpsecFieldType type;
    IpsecFieldRole role;       // fuer welche Rolle das Feld gilt (Web: nach gepostetem mode)
    const char*    webMarker;  // Web: nur uebernehmen, wenn dieses Formular-Marker-Feld vorhanden ist (fv2/fv3/fv4), sonst nullptr
    bool           webCheckbox;// Web: Checkbox-Semantik (fehlendes Feld = aus) statt "fehlt = unveraendert"
    const char*    enumValues; // Enum: "a|b|c"
    IpsecAlgoGroup algoGroup;  // AlgoList: Gruppe der Faehigkeitstabelle
    int            minInt, maxInt;   // Int
    const char*    help;       // Kurzbeschreibung fuer 'ipsec fields'
};

// Tabelle aller Felder (Reihenfolge = Anzeige-Reihenfolge).
const IpsecFieldDef* ipsecFieldTable(int& count);
const IpsecFieldDef* ipsecFieldFind(const String& key);

// Wert lesen (als Text; Bool = "1"/"0"). found=false, wenn der Schluessel unbekannt ist.
String ipsecFieldGet(const IpsecConfig& c, const IpsecFieldDef& f);
// Wert setzen: parst + prueft Typ/Bereich/Enum/Algorithmen-Kennungen. "" = ok, sonst Fehlertext.
// Secrets werden hier NICHT gesetzt (Typ Secret -> Fehler "ueber Secret-Pfad"), siehe Konsole/Handler.
String ipsecFieldSet(IpsecConfig& c, const IpsecFieldDef& f, const String& value);

// Erlaubte Werte als Text (Enum-Liste, Algo-Kennungen mit "unterstuetzt"-Markierung, Int-Bereich).
String ipsecFieldAllowed(const IpsecFieldDef& f);

// Komplette Konfiguration als Text (eine Zeile je Feld), Secrets maskiert.
String ipsecConfigDump(const IpsecConfig& c, bool pskSet, size_t pskLen, bool eapPassSet);

#endif // IPSEC_CONFIG_FIELDS_H
