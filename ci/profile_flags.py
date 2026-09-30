#!/usr/bin/env python3
"""profile_flags.py -- Profil aus modules.json -> Compiler-Flags, oder alle Profile pruefen.

  python3 ci/profile_flags.py <profil-id>   gibt "-DWEIRDOS_FEATURE_<KEY>=0/1 ..." fuer JEDEN Baustein aus
                                               (wie das Cam-Tool: aktiv = 1, alles andere = 0, nichts weggelassen).
                                               Geplante Bausteine (status "planned") bleiben 0, es gibt keinen Code.
  python3 ci/profile_flags.py --check       prueft jedes Profil gegen die harten Regeln aus
                                               weirdos_module_rules.h (#error) und gegen unbekannte Schluessel.

Dieselbe Quelle wie Firmware und Tool (modules.json) -- die CI baut damit Profile wortwoertlich.
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "..", "modules.json")

# Harte Pflichten, 1:1 aus weirdos_module_rules.h (Abschnitt 2). PSRAM ist eine Board-Option, nicht pruefbar.
RULES = [
    (["MODEM"], ["USB_HOST"], "MODEM braucht USB_HOST"),
    (["UVC"], ["USB_DEVICE"], "UVC braucht USB_DEVICE"),
    (["USB_NCM"], ["USB_DEVICE"], "USB_NCM braucht USB_DEVICE"),
    (["UVC", "VIDEO_HTTP", "RTSP", "H264", "DETECTION"], ["CAMERA"], "Video-Ausgang braucht CAMERA"),
    (["MODEM", "WIFI", "USB_NCM", "ROUTER", "WIREGUARD", "IPSEC", "DYNDNS", "NETSCAN", "RTSP", "HTTP", "OTA", "ACME", "TLS_CLIENT"],
     ["NET"], "Netzwerk-Baustein braucht NET"),
    (["WEBUI", "VIDEO_HTTP", "OTA", "TLS_SERVER"], ["HTTP"], "WEBUI/VIDEO_HTTP/OTA/TLS_SERVER brauchen HTTP"),
    (["ACME"], ["TLS_SERVER", "TLS_CLIENT"], "ACME braucht TLS_SERVER und TLS_CLIENT"),
    (["DYNDNS"], ["TLS_CLIENT"], "DYNDNS braucht TLS_CLIENT"),
    (["IPSEC"], ["CRYPTO_AES"], "IPSEC braucht CRYPTO_AES"),
]


def load():
    with open(MANIFEST, encoding="utf-8") as f:
        m = json.load(f)
    mods = {x["key"]: x for x in m["modules"]}
    profs = {p["id"]: p for p in m["profiles"]}
    return mods, profs


def profile_set(p, mods):
    ms = p.get("modules", [])
    if ms == "*" or ms == ["*"] or p.get("all"):
        return None  # Vollausbau = Firmware-Vorgaben, keine Flags
    return set(ms)


def flags(pid):
    mods, profs = load()
    p = profs.get(pid)
    if p is None:
        sys.exit(f"unbekanntes Profil '{pid}' (bekannt: {', '.join(sorted(profs))})")
    s = profile_set(p, mods)
    if s is None:
        return ""
    out = []
    for key, m in mods.items():
        on = key in s and m.get("status") != "planned"
        out.append(f"-DWEIRDOS_FEATURE_{key}={1 if on else 0}")
    return " ".join(out)


def check():
    mods, profs = load()
    bad = 0
    for pid, p in profs.items():
        s = profile_set(p, mods)
        if s is None or pid == "custom":
            continue
        for k in sorted(s):
            if k not in mods:
                print(f"{pid}: unbekannter Baustein {k}"); bad += 1
        active = {k for k in s if k in mods and mods[k].get("status") != "planned"}
        for trig, need, text in RULES:
            if active & set(trig) and not set(need) <= active:
                print(f"{pid}: {text} (aktiv: {', '.join(sorted(active & set(trig)))}, fehlt: {', '.join(sorted(set(need) - active))})")
                bad += 1
    print(f"{len(profs)} Profile, {len(mods)} Bausteine, {bad} Verstoesse")
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    if sys.argv[1] == "--check":
        sys.exit(check())
    print(flags(sys.argv[1]))
