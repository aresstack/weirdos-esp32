// ============================================================================
// egress_policy.cpp -- Aufloesung geordneter Egress-Policies auf ein Interface.
// Reiner Lookup ueber die NetworkRegistry; keine Routing-/Transport-Aktion.
// ============================================================================
#include "egress_policy.h"

// "Mobilfunk-WAN" = aktueller Mobilfunk-Datenpfad: ECM bevorzugt, sonst PPP.
static bool resolveMobileWan(NetIface& out) {
    NetIface ni;
    if (netInterfaceById("modem-ecm", ni) && ni.up) { out = ni; return true; }
    if (netInterfaceById("modem-ppp", ni) && ni.up) { out = ni; return true; }
    return false;
}

bool egressResolve(const String& policy, NetIface& out) {
    NetIface ni;

    if (policy == "wifi") {
        if (netInterfaceById("wifi-sta", ni) && ni.up) { out = ni; return true; }
        return false;
    }

    // "modem" und "auto" (Default): Mobilfunk zuerst.
    if (resolveMobileWan(out)) return true;

    // "auto": WLAN-Fallback, wenn Mobilfunk nicht verfuegbar. "modem": kein Fallback.
    if (policy != "modem") {
        if (netInterfaceById("wifi-sta", ni) && ni.up) { out = ni; return true; }
    }
    return false;
}

String egressResolvedId(const String& policy) {
    NetIface ni;
    return egressResolve(policy, ni) ? ni.id : String("");
}
