# Provenance

WeirdIKE is an **independent implementation written to RFC 7296**; **CycloneIPSEC is used only as a
reference**, its code is not copied (see "Current classification" below). This file pins the exact
upstream reference commit so it is always unambiguous which reference state was consulted.

## Upstream

```
Project:    CycloneIPSEC (IPsec/IKEv2 Library)
Author:     Oryx Embedded SARL  (https://www.oryx-embedded.com)
Upstream:   https://github.com/Oryx-Embedded/CycloneIPSEC
License:    GPL-2.0-or-later
Pinned at:  v2.6.4
Commit:     e549c03f5c72bed8c278578f7129bccd157b1f08
Date:       2026-05-28
Local ref:  C:\Projects\CycloneIPSEC  (fork: github.com/Miguel0888/CycloneIPSEC @ e549c03)
```

## Current classification (important)

As of now, **no source file in WeirdIKE is a verbatim derivative of CycloneIPSEC.** The core
(`src/core/ike_wire.c`, the parser, the FSM, crypto adapter) is an **independent implementation
written to the normative RFCs** (RFC 7296 for IKEv2 wire format/state, RFC 4231 etc. for crypto
vectors). CycloneIPSEC was studied as a *reference* to understand the protocol; its code was not
copied. Files therefore carry only the WeirdIKE GPL header.

The project license is **GPL-2.0-or-later by choice** (it keeps the door open to importing Cyclone
code later, and is a fine license for this library regardless). **IF** Cyclone code is ever imported
verbatim, those specific files MUST retain the original Oryx Embedded copyright + GPL headers and be
listed explicitly below. Until then the list below is a *plan/reference*, not a claim of derivation.

## Files that WOULD be derived IF Cyclone code is imported verbatim (extraction plan, ANALYSIS.md §4)

As each Cyclone-derived source is added under `src/core/`, it MUST:
  * retain the original Oryx Embedded copyright + GPL header, and
  * add a short WeirdIKE derivation note (what changed: platform layer removed, poll-driven, etc.).

Planned derivations (upstream -> WeirdIKE):
```
ike/ike_message_format.c + ike_message_parse.c  -> src/core/ike_message.c
ike/ike_payload_format.c  + ike_payload_parse.c  -> src/core/ike_payload.c
ike/ike_fsm.c                                    -> src/core/ike_fsm.c   (OsTask/OsEvent removed)
ike/ike_key_material.c                           -> src/core/ike_keymat.c
ike/ike_algorithms.c                             -> src/core/ike_algorithms.c (trimmed)
ike/ike_auth.c                                   -> src/core/ike_auth.c   (PSK branch first)
esp/esp*.c                                       -> src/esp/esp_engine.c   (+ tunnel-mode ext.)
```

Not derived (replaced by adapters / not on the PSK path): CycloneTCP, CycloneCRYPTO, Oryx os_port,
CyclonePKIX/X.509, RSA/ECDSA/EdDSA/DSA, AH. See docs/ANALYSIS.md.
