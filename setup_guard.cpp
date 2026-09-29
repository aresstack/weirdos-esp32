// ============================================================================
// setup_guard.cpp -- Persistenz fuer die "Einrichtung" (Captive + Werksreset).
// Reine Config/NVS; die Laufzeit-Wirkung liegt im Sketch (applyApPolicy/loop).
// ============================================================================
#include "setup_guard.h"
#include <Preferences.h>

static SetupGuardConfig g_cfg;
static bool             g_loaded = false;

// Haltezeiten kanonisieren: Stufe 1 in [3s,120s]; Stufe 2 in [Stufe1+5s, 300s].
static void clampHolds(SetupGuardConfig& c) {
    if (c.resetHoldMs < 3000UL)   c.resetHoldMs = 3000UL;
    if (c.resetHoldMs > 120000UL) c.resetHoldMs = 120000UL;
    if (c.fullHoldMs < c.resetHoldMs + 5000UL) c.fullHoldMs = c.resetHoldMs + 5000UL;
    if (c.fullHoldMs > 300000UL)  c.fullHoldMs = 300000UL;
}

void setupGuardLoadConfig() {
    Preferences p;
    p.begin("setup", true);
    g_cfg.captiveMode  = p.getString("captive", CAPTIVE_MODE_DEFAULT);
    g_cfg.resetEnabled = p.getBool("rstEn", RESET_ENABLED_DEFAULT);
    g_cfg.resetHoldMs  = p.getULong("rstHold", RESET_HOLD_MS_DEFAULT);
    g_cfg.fullEnabled  = p.getBool("fullEn", FULLRESET_ENABLED_DEFAULT);
    g_cfg.fullHoldMs   = p.getULong("fullHold", FULLRESET_HOLD_MS_DEFAULT);
    g_cfg.uartEnabled  = p.getBool("uartEn", UART_ENABLED_DEFAULT);
    p.end();
    if (g_cfg.captiveMode != "off") g_cfg.captiveMode = "auto";   // kanonisieren
    clampHolds(g_cfg);
    g_loaded = true;
}

String setupGuardSave(const SetupGuardConfig& c) {
    SetupGuardConfig nc = c;
    nc.captiveMode = (c.captiveMode == "off") ? "off" : "auto";
    clampHolds(nc);

    Preferences p;
    p.begin("setup", false);
    p.putString("captive", nc.captiveMode);
    p.putBool("rstEn", nc.resetEnabled);
    p.putULong("rstHold", nc.resetHoldMs);
    p.putBool("fullEn", nc.fullEnabled);
    p.putULong("fullHold", nc.fullHoldMs);
    p.putBool("uartEn", nc.uartEnabled);
    p.end();

    g_cfg = nc;
    g_loaded = true;
    return "";
}

const SetupGuardConfig& setupGuardGet() {
    if (!g_loaded) setupGuardLoadConfig();
    return g_cfg;
}
