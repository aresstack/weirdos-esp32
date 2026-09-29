# Vendored: WireGuard-ESP32

**Upstream:** WireGuard-ESP32 by Kenta Ida (fuga@fugafuga.org), version **0.1.5**
(Arduino Library Manager). Basis: wireguard-lwip. Lizenz: **BSD-3-Clause**
(siehe Datei-Header und `UPSTREAM_LICENSE`).

Diese Kopie liegt bewusst im Repo (`esp32-modem-host/src/WireGuard/`), damit der
Build **allein aus dem Repo** (Arduino Core 3.3.11 / IDF 5.5.5) durchlaeuft, ohne
eine extern installierte, manuell gepatchte Arduino-Library. Der Sketch inkludiert
`"src/WireGuard/WireGuard-ESP32.h"` (relativ, Anfuehrungszeichen) - dadurch triggert
Arduinos Library-Discovery NICHT die installierte `WireGuard-ESP32`-Library. Die
installierte Fassung sollte entfernt/umbenannt werden, damit es keine Verwirrung gibt.

## WeirdOS-Patches (IDF 5.5.5 / GCC 12) - Marker `WeirdOS/IDF-5`

1. `wireguardif.c`: `#include "tcpip_adapter.h"` -> `#include "esp_netif.h"` +
   `#include "esp_netif_net_stack.h"` (tcpip_adapter in IDF 5 entfernt).
2. `wireguardif.c`: `tcpip_adapter_get_netif(TCPIP_ADAPTER_IF_STA, ...)` ->
   `esp_netif_get_handle_from_ifkey("WIFI_STA_DEF")` + `esp_netif_get_netif_impl(...)`.
   (Underlay noch hardcoded WIFI_STA - wird in Stufe 7.4b auf die NetworkRegistry-
   Auswahl abstrahiert.)
3. `wireguard.h`: fehlender Prototyp `handshake_destroy(...)` ergaenzt (unter GCC 12
   ist implicit-function-declaration ein Fehler, frueher Warnung).
4. `wireguard-platform.c`: `#include "esp_random.h"` (esp_fill_random() ist in IDF 5
   von esp_system.h nach esp_random.h gewandert).

Alle Patches sind im Code mit `WeirdOS/IDF-5` markiert.
