# CycloneIPSEC-Vendoring — noch NICHT im Build

Dieser Ordner (`ipsec-port/`) liegt bewusst NICHT unter `src/`, damit der Arduino-Build ihn
NICHT kompiliert. Er ist die Werkbank für den IKEv2-Port (Stufe 8.2). Plan: `../../IPSEC-PORT.md`.

## Was hier rein muss, bevor der erste Compile-Loop starten kann

Ausgecheckt ist bisher nur **CycloneIPSEC** (`C:\Projects\CycloneIPSEC`). Zusätzlich nötig
(beide github.com/Oryx-Embedded, GPL-2.0-or-later):

1. **CycloneCRYPTO** — die gesamte Krypto (cipher/hash/mac/aead/pkc/pkix/encoding/rng).
   CycloneIPSEC-IKE ruft diese API direkt. Ohne sie kompiliert nichts.
2. **Oryx Common** — `os_port*.{h,c}` (FreeRTOS-Port für ESP32!), `error.h`, `debug.h`,
   `cpu_endian.h`, `date_time.h`. Liefert `OsEvent`, `OsTaskParameters`, `systime_t`,
   `osGetSystemTime`, `osAllocMem`.

NICHT übernehmen: **CycloneTCP** (wäre ein zweiter TCP/IP-Stack neben lwIP). Stattdessen der
lwIP-Net-Shim (`core/net.h`/`core/socket.h`/`core/ip.h` selbst, Sockets auf lwIP-BSD; s. Plan §2).

## VENDOR-Regeln (wie bei src/WireGuard)
- Pro Lib die Quelle notieren: Repo-URL + Commit-Hash + Lizenzdatei mitkopieren.
- Nach dem Vendoren nach `src/CycloneIPSEC/` (dann kompiliert Arduino es). Includes per
  Anführungszeichen-Pfad, damit immer die vendored Fassung greift.
- Patches (falls nötig für IDF/ESP) HIER dokumentieren, nicht still im Code.

## Reihenfolge
Erst `ipsec_config.h`/`crypto_config.h`/`os_port_config.h` (Minimalprofil, s. ipsec_config.h hier),
dann Net-Shim, dann os_port_freertos, dann Verschieben nach src/ + Compile-Loop mit dem User.
Ziel Slice 1: **kompiliert & linkt**. Noch kein Tunnel.
