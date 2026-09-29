// ============================================================================
// h264_fmp4.h  --  Minimaler fragmentierter-MP4-Muxer fuer H.264 (Browser/MSE)
//
// Der HW-Encoder liefert H.264 als Annex-B-Access-Unit (Start-Code 00 00 00 01 getrennt,
// IDR mit vorangestelltem SPS+PPS). Der Browser spielt H.264 NICHT als rohen ES; er braucht
// fragmentiertes MP4 (fMP4) ueber Media Source Extensions:
//   - EIN Init-Segment (ftyp+moov, enthaelt SPS/PPS als avcC) am Stream-Anfang
//   - je Frame ein Media-Segment (moof+mdat, NAL als AVCC laengen-praefixiert)
//
// Diese Klasse ist zustandsbehaftet und rein rechnend (keine HW): AU reinfuettern, dann
// Init- (einmal, sobald SPS/PPS bekannt) und Media-Segment (pro AU) rausholen. Beide Puffer
// liegen intern (PSRAM) und sind bis zum naechsten Aufruf gueltig.
// ============================================================================
#ifndef H264_FMP4_H
#define H264_FMP4_H

#include <cstdint>
#include <cstddef>

class Fmp4Muxer {
public:
    Fmp4Muxer();
    ~Fmp4Muxer();

    // timescale/fps bestimmen die Sample-Dauer (timescale/fps pro Frame). 90000/30 ist ueblich.
    bool begin(uint16_t width, uint16_t height, uint32_t timescale, uint32_t fps);
    void end();

    // Eine Annex-B-Access-Unit einspeisen. Zerlegt in NAL-Einheiten: SPS/PPS werden gemerkt
    // (fuer das Init-Segment), VCL-NALs werden AVCC-laengen-praefixiert fuer das Media-Segment
    // gesammelt. isKey = Keyframe (IDR). Rueckgabe false bei Parse-/Alloc-Fehler.
    bool feed(const uint8_t* annexB, size_t len, bool isKey);

    // Init-Segment verfuegbar (SPS+PPS gesehen)? Erst dann darf initSegment() gesendet werden.
    bool hasInit() const { return haveSps_ && havePps_; }

    // Init-Segment (ftyp+moov). Gueltig nach hasInit(). *out bis zum naechsten begin()/end().
    bool initSegment(const uint8_t** out, size_t* len);

    // Media-Segment (moof+mdat) fuer die zuletzt eingespeiste AU. *out bis zum naechsten feed().
    // durationTicks = echte Frame-Dauer in timescale-Ticks (0 -> Nominal timescale/fps). Echte Dauer
    // haelt die Medienzeit an der Wanduhr -> kein aufsummierter Delay, wenn Encode/Send langsamer ist.
    bool mediaSegment(const uint8_t** out, size_t* len, uint32_t durationTicks = 0);

    // avc1.PPCCLL-Codec-String fuer MSE (aus SPS). Leer bis SPS bekannt.
    const char* codecString() const { return codec_; }

private:
    // wachsende Byte-Puffer (PSRAM)
    // err: persistenter Schreibfehler (PSRAM-Wachstum gescheitert). Ab dann schreibt KEIN Helfer
    // mehr (kein Zugriff auf p == nullptr, kein halb gebauter Box-Baum), und feed()/initSegment()/
    // mediaSegment() melden false. reset() hebt ihn fuer den naechsten Frame wieder auf.
    struct Buf { uint8_t* p; size_t len; size_t cap; bool err = false; };
    static bool ensure(Buf& b, size_t need);
    static void reset(Buf& b) { b.len = 0; b.err = false; }
    static void u8(Buf& b, uint8_t v);
    static void u16(Buf& b, uint16_t v);
    static void u32(Buf& b, uint32_t v);
    static void u64(Buf& b, uint64_t v);
    static void raw(Buf& b, const void* d, size_t n);
    static size_t boxStart(Buf& b, const char* type);     // schreibt Platzhalter-Groesse+Typ, gibt Offset
    static void   boxEnd(Buf& b, size_t startOff);        // patcht Groesse

    uint16_t w_, h_;
    uint32_t timescale_, sampleDur_;
    uint32_t seq_;            // moof-Sequenznummer
    uint64_t baseDecodeTime_; // kumulierte Decode-Zeit
    bool     haveSps_, havePps_;
    uint8_t* sps_; size_t spsLen_;
    uint8_t* pps_; size_t ppsLen_;
    char     codec_[16];
    Buf      avcc_;   // AVCC-Sample-Daten (laengen-praefixierte VCL-NALs) der aktuellen AU
    bool     avccKey_;
    Buf      init_;   // Init-Segment
    Buf      media_;  // Media-Segment
};

#endif // H264_FMP4_H
