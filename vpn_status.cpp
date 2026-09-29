// ============================================================================
// vpn_status.cpp -- siehe vpn_status.h
// ============================================================================
#include "vpn_status.h"
#include "wireguard_service.h"
#include "ipsec_service.h"

static String jesc(const String& s) {
    String o; o.reserve(s.length() + 8);
    for (unsigned i = 0; i < s.length(); i++) {
        char c = s[i];
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n') o += "\\n";
        else if (c == '\r') continue;
        else if ((uint8_t)c < 0x20) o += ' ';
        else o += c;
    }
    return o;
}

const char* vpnStateName(VpnState s) {
    switch (s) {
        case VpnState::Inactive:     return "inaktiv";
        case VpnState::Disconnected: return "getrennt";
        case VpnState::Connecting:   return "verbindet";
        case VpnState::Listening:    return "wartet auf Clients";
        case VpnState::Connected:    return "verbunden";
        case VpnState::Error:        return "Fehler";
    }
    return "?";
}

String VpnStatus::toJson() const {
    String j = "{";
    j += "\"service\":\"";   j += jesc(service);   j += "\",";
    j += "\"role\":\"";      j += jesc(role);      j += "\",";
    j += "\"active\":";      j += active ? "true" : "false"; j += ",";
    j += "\"state\":\"";     j += vpnStateName(state); j += "\",";
    j += "\"stateText\":\""; j += jesc(stateText); j += "\",";
    j += "\"endpoint\":\"";  j += jesc(endpoint);  j += "\",";
    j += "\"underlay\":\"";  j += jesc(underlay);  j += "\",";
    j += "\"tunnelIp\":\"";  j += jesc(tunnelIp);  j += "\",";
    j += "\"peer\":\"";      j += jesc(peer);      j += "\",";
    j += "\"detail\":\"";    j += jesc(detail);    j += "\",";
    j += "\"hasTraffic\":";  j += hasTraffic ? "true" : "false"; j += ",";
    j += "\"txPackets\":";   j += txPackets; j += ",";
    j += "\"rxPackets\":";   j += rxPackets; j += ",";
    j += "\"txBytes\":";     j += txBytes;   j += ",";
    j += "\"rxBytes\":";     j += rxBytes;   j += ",";
    j += "\"error\":\"";     j += jesc(error);     j += "\"";
    j += "}";
    return j;
}

String vpnStatusJsonAll() {
    String j = "{\"ok\":true,\"vpn\":[";
    j += wireguardService.vpnStatus().toJson();
    j += ",";
    j += ipsecService.vpnStatus().toJson();
    j += "]}";
    return j;
}
