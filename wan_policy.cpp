// ============================================================================
// wan_policy.cpp -- Logische System-WAN-Praeferenz + Aufloesung. Reiner Lookup.
// ============================================================================
#include "wan_policy.h"
#include "ec200a_modem.h"   // modemDataMode (Datenschicht ppp|ecm) -> Mobilfunk-Interface
#include <Preferences.h>

static WanPolicy g_wan;
static bool      g_loaded = false;

static String canonPref(const String& p) {
    if (p == "wifi" || p == "cellular") return p;
    return "auto";
}

void wanLoadConfig() {
    Preferences prefs;
    prefs.begin("wanpol", true);
    g_wan.preference = canonPref(prefs.getString("pref", "auto"));
    prefs.end();
    g_loaded = true;
}

String wanSaveConfig(const WanPolicy& p) {
    g_wan.preference = canonPref(p.preference);
    Preferences prefs;
    prefs.begin("wanpol", false);
    prefs.putString("pref", g_wan.preference);
    prefs.end();
    g_loaded = true;
    return "";
}

const WanPolicy& wanPolicyGet() {
    if (!g_loaded) wanLoadConfig();
    return g_wan;
}

String wanPreference() { return wanPolicyGet().preference; }

// "Mobilfunk" -> konkrete Datenschicht. Wer ECM waehlt, bekommt modem-ecm (kein PPP-Fallback).
String wanCellularIfaceId() {
    return (modemDataMode == "ecm") ? String("modem-ecm") : String("modem-ppp");
}

bool wanResolve(NetIface& out) {
    String cell = wanCellularIfaceId();
    // Logische Kandidatenreihenfolge; Fallback ist immer Mobilfunk<->WLAN (nicht ecm->ppp).
    const char* seq0; const char* seq1;
    if (wanPreference() == "wifi") { seq0 = "wifi";     seq1 = "cellular"; }
    else                           { seq0 = "cellular"; seq1 = "wifi";     }

    NetIface ni;
    const char* order[2] = { seq0, seq1 };
    for (int i = 0; i < 2; i++) {
        String id = (String(order[i]) == "cellular") ? cell : String("wifi-sta");
        if (netInterfaceById(id, ni) && ni.up && ni.ip.length() > 0) { out = ni; return true; }
    }
    return false;
}

String wanStatusJson() {
    String pref = wanPreference();
    NetIface ni;
    bool ok = wanResolve(ni);
    String j = "{";
    j += "\"preference\":\""; j += pref; j += "\",";
    j += "\"dataMode\":\"";   j += (modemDataMode == "ecm") ? "ecm" : "ppp"; j += "\",";
    j += "\"resolved\":";
    if (ok) {
        String logical = (ni.id == "wifi-sta") ? "wifi" : "cellular";
        j += "{\"logical\":\""; j += logical;
        j += "\",\"iface\":\"";  j += ni.id;
        j += "\",\"device\":\""; j += ni.device;
        j += "\",\"ip\":\"";     j += ni.ip;
        j += "\"}";
    } else {
        j += "null";
    }
    j += "}";
    return j;
}
