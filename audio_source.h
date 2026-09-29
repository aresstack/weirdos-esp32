// ============================================================================
// audio_source.h  --  Neutrale Audio-Abstraktion (analog zu FrameSource/Kamera).
//
// Eine spaetere Transkriptions-/Voice-Assistant-Pipeline haengt an AudioSource
// (Capture) bzw. AudioSink (Playback) und ist damit UNABHAENGIG davon, ob das
// Audio vom Onboard-Mikro (ES8311/I2S am P4-Pico), USB-Audio oder irgendwann
// einem anderen Codec kommt. Das KI-Menue waehlt dann `microphone0` als Quelle
// (Transkription/Geraeuscherkennung) und `speaker0` als Ausgabe (TTS).
//
// HEUTE bewusst nur die Schnittstelle + Geraete-Registrierung/Descriptor
// (peripheral_registry, /dev). Noch KEINE ES8311/I2S-Runtime, keine Pipeline.
// Die logischen Geraete sind microphone0 (audio.capture) / speaker0
// (audio.playback); ES8311/I2S bleiben P4-Backenddetail (kein /dev/es8311).
// ============================================================================
#ifndef AUDIO_SOURCE_H
#define AUDIO_SOURCE_H

#include <cstdint>
#include <cstddef>

// Ein Block PCM-Audio (signed 16-bit). Groessere Ring-/PCM-Puffer gehoeren in den
// spaeteren Backends bevorzugt in PSRAM; nur die tatsaechlich DMA-pflichtigen
// Bereiche in den knappen internen Heap.
struct AudioFrame {
    const int16_t* samples;     // interleaved PCM
    size_t         count;       // Anzahl Samples (ueber alle Kanaele)
    uint32_t       sampleRate;  // z.B. 16000, 48000
    uint8_t        channels;    // 1 = mono
    uint32_t       sequence;
};

// audio.capture (z.B. microphone0). Analog zu FrameSource::acquireFrame/releaseFrame.
class AudioSource {
public:
    virtual ~AudioSource() {}
    virtual bool        beginCapture(uint32_t sampleRate, uint8_t channels) = 0;
    virtual AudioFrame* acquireFrame() = 0;             // nullptr = noch kein Block
    virtual void        releaseFrame(AudioFrame* frame) = 0;
    virtual void        endCapture() = 0;
};

// audio.playback (z.B. speaker0).
class AudioSink {
public:
    virtual ~AudioSink() {}
    virtual bool beginPlayback(uint32_t sampleRate, uint8_t channels) = 0;
    virtual bool write(const AudioFrame& frame) = 0;
    virtual void endPlayback() = 0;
};

#endif // AUDIO_SOURCE_H
