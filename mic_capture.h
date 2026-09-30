// Duenner Mikrofon-Layer fuer das USB-Audio (UAC2). Ein Build zielt immer auf
// EINE Plattform (FQBN), also waehlt der Compiler das passende Backend:
//   * ESP32-S3 (XIAO Sense u.a.): PDM-Mikro ueber I2S-PDM-RX.
//   * ESP32-P4 (Waveshare Pico):  ES8311-Codec ueber I2S-Std + I2C-Steuerung.
// So deckt EIN AUDIO-Baustein beide Boards ab, ohne Tool-Auswahl und ohne den
// jeweils anderen Treiber mitzuschleppen (das andere Target wird nicht kompiliert).
//
// Auto-Erkennung mit sanftem Scheitern (Option 3): begin() versucht die
// Hardware zu initialisieren; ist sie nicht da (S3 ohne Sense-Mikro, P4 ohne
// bestueckten Codec), liefert begin() false -> es gibt halt kein Audio, das
// Video laeuft unberuehrt weiter.
#pragma once

#include <stdint.h>
#include <stddef.h>

namespace cam { namespace mic {

// 16 kHz mono, signed 16-bit -- die Vorgabe fuer ein Sprach-Mikro. begin()
// liefert die tatsaechlich gesetzte Rate zurueck (kann abweichen).
bool     begin(uint32_t sampleRate, uint32_t* actualRate);
void     end();
bool     active();

// Bis maxSamples PCM-Samples (int16, mono) abholen. Rueckgabe: gelesene Anzahl.
// 0 = gerade nichts da (nicht blockierend). Ruft der USB-Audio-Feed periodisch.
size_t   read(int16_t* dst, size_t maxSamples);

// Kurzer, menschenlesbarer Zustand fuer den Status/Log ("PDM GPIO42/41" etc.).
const char* backendName();

}} // namespace cam::mic
