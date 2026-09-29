// logo_banner.h -- WeirdOS-Banner (rohe PNG-Bytes in logo_banner.cpp, PROGMEM).
// Wird ueber die Route /banner.png ausgeliefert (separat gecacht), NICHT mehr als
// Data-URI in jede Seite eingebettet -> kleinere Seiten-HTML, weniger Heap-Druck.
#pragma once
#include <Arduino.h>
extern const uint8_t  LOGO_BANNER_PNG[];
extern const uint32_t LOGO_BANNER_PNG_LEN;
