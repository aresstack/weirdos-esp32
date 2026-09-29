// ============================================================================
// h264_fmp4.cpp  --  siehe h264_fmp4.h
// ============================================================================
#include "h264_fmp4.h"
#include "esp_heap_caps.h"
#include <cstring>
#include <cstdio>

// ---- wachsende PSRAM-Puffer -------------------------------------------------
bool Fmp4Muxer::ensure(Buf& b, size_t need) {
    if (b.err) return false;
    if (b.cap >= need) return true;
    size_t nc = b.cap ? b.cap * 2 : 2048;
    if (nc < need) nc = need;
    uint8_t* np = (uint8_t*)heap_caps_realloc(b.p, nc, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!np) np = (uint8_t*)heap_caps_realloc(b.p, nc, MALLOC_CAP_DEFAULT);
    if (!np) { b.err = true; return false; }   // persistent: kein Weiterschreiben, kein Teil-MP4 als Erfolg
    b.p = np; b.cap = nc; return true;
}
void Fmp4Muxer::u8 (Buf& b, uint8_t v)  { if (ensure(b, b.len + 1)) b.p[b.len++] = v; }
void Fmp4Muxer::u16(Buf& b, uint16_t v) { u8(b, v >> 8); u8(b, v & 0xff); }
void Fmp4Muxer::u32(Buf& b, uint32_t v) { u8(b, v >> 24); u8(b, v >> 16); u8(b, v >> 8); u8(b, v); }
void Fmp4Muxer::u64(Buf& b, uint64_t v) { u32(b, (uint32_t)(v >> 32)); u32(b, (uint32_t)v); }
void Fmp4Muxer::raw(Buf& b, const void* d, size_t n) { if (ensure(b, b.len + n)) { memcpy(b.p + b.len, d, n); b.len += n; } }

// Box mit Platzhalter-Groesse oeffnen; boxEnd() patcht sie. Gibt Offset des Groessenfelds.
size_t Fmp4Muxer::boxStart(Buf& b, const char* type) {
    size_t off = b.len;
    u32(b, 0);                       // Platzhalter
    raw(b, type, 4);
    return off;
}
void Fmp4Muxer::boxEnd(Buf& b, size_t startOff) {
    if (b.err || !b.p || startOff + 4 > b.len) return;   // nach Schreibfehler nichts patchen (p kann nullptr sein)
    uint32_t sz = (uint32_t)(b.len - startOff);
    b.p[startOff]     = sz >> 24;    b.p[startOff + 1] = sz >> 16;
    b.p[startOff + 2] = sz >> 8;     b.p[startOff + 3] = sz;
}

static const uint8_t kMatrix[36] = {
    0x00,0x01,0x00,0x00, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0x00,0x01,0x00,0x00, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0x40,0x00,0x00,0x00
};

Fmp4Muxer::Fmp4Muxer()
    : w_(0), h_(0), timescale_(90000), sampleDur_(3000), seq_(1), baseDecodeTime_(0),
      haveSps_(false), havePps_(false), sps_(nullptr), spsLen_(0), pps_(nullptr), ppsLen_(0),
      avccKey_(false) {
    codec_[0] = 0;
    avcc_ = {nullptr,0,0}; init_ = {nullptr,0,0}; media_ = {nullptr,0,0};
}
Fmp4Muxer::~Fmp4Muxer() { end(); }

bool Fmp4Muxer::begin(uint16_t width, uint16_t height, uint32_t timescale, uint32_t fps) {
    end();
    w_ = width; h_ = height;
    timescale_ = timescale ? timescale : 90000;
    sampleDur_ = fps ? (timescale_ / fps) : (timescale_ / 30);
    seq_ = 1; baseDecodeTime_ = 0;
    haveSps_ = havePps_ = false; codec_[0] = 0;
    return true;
}

void Fmp4Muxer::end() {
    if (sps_)  { heap_caps_free(sps_);  sps_  = nullptr; } spsLen_ = 0;
    if (pps_)  { heap_caps_free(pps_);  pps_  = nullptr; } ppsLen_ = 0;
    if (avcc_.p)  { heap_caps_free(avcc_.p);  avcc_  = {nullptr,0,0}; }
    if (init_.p)  { heap_caps_free(init_.p);  init_  = {nullptr,0,0}; }
    if (media_.p) { heap_caps_free(media_.p); media_ = {nullptr,0,0}; }
    haveSps_ = havePps_ = false;
}

// naechsten Annex-B-Start-Code ab 'from' finden; setzt scLen (3 oder 4). Rueckgabe len = keiner.
static size_t nextStartCode(const uint8_t* d, size_t len, size_t from, int& scLen) {
    for (size_t k = from; k + 3 <= len; k++) {
        if (d[k] == 0 && d[k + 1] == 0) {
            if (k + 4 <= len && d[k + 2] == 0 && d[k + 3] == 1) { scLen = 4; return k; }
            if (d[k + 2] == 1) { scLen = 3; return k; }
        }
    }
    scLen = 0; return len;
}

bool Fmp4Muxer::feed(const uint8_t* d, size_t len, bool isKey) {
    if (!d || len < 4) return false;
    reset(avcc_); avccKey_ = isKey;

    int scLen = 0;
    size_t sc = nextStartCode(d, len, 0, scLen);
    if (sc == len) return false;
    size_t nalStart = sc + scLen;

    while (nalStart < len) {
        int scLen2 = 0;
        size_t nalEnd = nextStartCode(d, len, nalStart, scLen2);   // = naechster SC oder len
        size_t nalLen = nalEnd - nalStart;
        if (nalLen > 0) {
            uint8_t t = d[nalStart] & 0x1F;
            if (t == 7) {                       // SPS
                if (!haveSps_) {
                    sps_ = (uint8_t*)heap_caps_malloc(nalLen, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
                    if (!sps_) sps_ = (uint8_t*)heap_caps_malloc(nalLen, MALLOC_CAP_DEFAULT);
                    if (sps_) { memcpy(sps_, d + nalStart, nalLen); spsLen_ = nalLen; haveSps_ = true;
                                if (nalLen >= 4) snprintf(codec_, sizeof(codec_), "avc1.%02X%02X%02X",
                                                          d[nalStart+1], d[nalStart+2], d[nalStart+3]); }
                }
            } else if (t == 8) {                // PPS
                if (!havePps_) {
                    pps_ = (uint8_t*)heap_caps_malloc(nalLen, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
                    if (!pps_) pps_ = (uint8_t*)heap_caps_malloc(nalLen, MALLOC_CAP_DEFAULT);
                    if (pps_) { memcpy(pps_, d + nalStart, nalLen); ppsLen_ = nalLen; havePps_ = true; }
                }
            } else if (t == 1 || t == 5) {      // VCL (non-IDR / IDR) -> AVCC (4-Byte-Laenge + NAL)
                u32(avcc_, (uint32_t)nalLen);
                raw(avcc_, d + nalStart, nalLen);
            }
            // andere (SEI=6, AUD=9) werden ausgelassen -> haelt das Media-Segment schlank
        }
        if (nalEnd == len) break;
        nalStart = nalEnd + scLen2;
    }
    if (avcc_.err) return false;   // AVCC-Puffer konnte nicht wachsen -> Frame verwerfen, nicht halb senden
    return avcc_.len > 0 || (isKey && hasInit());
}

bool Fmp4Muxer::initSegment(const uint8_t** out, size_t* len) {
    if (!hasInit() || !out || !len) return false;
    Buf& b = init_; reset(b);

    // ---- ftyp ----
    size_t ftyp = boxStart(b, "ftyp");
    raw(b, "iso5", 4); u32(b, 0); raw(b, "iso5", 4); raw(b, "iso6", 4); raw(b, "mp41", 4);
    boxEnd(b, ftyp);

    // ---- moov ----
    size_t moov = boxStart(b, "moov");
    {   // mvhd
        size_t mvhd = boxStart(b, "mvhd");
        u32(b, 0); u32(b, 0); u32(b, 0); u32(b, timescale_); u32(b, 0);
        u32(b, 0x00010000); u16(b, 0x0100); u16(b, 0); u32(b, 0); u32(b, 0);
        raw(b, kMatrix, 36); for (int i = 0; i < 6; i++) u32(b, 0); u32(b, 2);
        boxEnd(b, mvhd);
    }
    {   // trak
        size_t trak = boxStart(b, "trak");
        {   // tkhd (enabled|in_movie|in_preview)
            size_t tkhd = boxStart(b, "tkhd");
            u32(b, 0x00000007); u32(b, 0); u32(b, 0); u32(b, 1); u32(b, 0); u32(b, 0);
            u32(b, 0); u32(b, 0); u16(b, 0); u16(b, 0); u16(b, 0); u16(b, 0);
            raw(b, kMatrix, 36); u32(b, (uint32_t)w_ << 16); u32(b, (uint32_t)h_ << 16);
            boxEnd(b, tkhd);
        }
        {   // mdia
            size_t mdia = boxStart(b, "mdia");
            {   // mdhd
                size_t mdhd = boxStart(b, "mdhd");
                u32(b, 0); u32(b, 0); u32(b, 0); u32(b, timescale_); u32(b, 0);
                u16(b, 0x55C4); u16(b, 0);
                boxEnd(b, mdhd);
            }
            {   // hdlr
                size_t hdlr = boxStart(b, "hdlr");
                u32(b, 0); u32(b, 0); raw(b, "vide", 4); u32(b, 0); u32(b, 0); u32(b, 0);
                raw(b, "VideoHandler", 12); u8(b, 0);
                boxEnd(b, hdlr);
            }
            {   // minf
                size_t minf = boxStart(b, "minf");
                { size_t vmhd = boxStart(b, "vmhd"); u32(b, 0x00000001); u16(b,0); u16(b,0); u16(b,0); u16(b,0); boxEnd(b, vmhd); }
                {   size_t dinf = boxStart(b, "dinf");
                    size_t dref = boxStart(b, "dref"); u32(b, 0); u32(b, 1);
                    size_t url = boxStart(b, "url "); u32(b, 0x00000001); boxEnd(b, url);
                    boxEnd(b, dref); boxEnd(b, dinf);
                }
                {   size_t stbl = boxStart(b, "stbl");
                    {   // stsd -> avc1 -> avcC
                        size_t stsd = boxStart(b, "stsd"); u32(b, 0); u32(b, 1);
                        size_t avc1 = boxStart(b, "avc1");
                        for (int i = 0; i < 6; i++) u8(b, 0); u16(b, 1);          // reserved + data_ref_index
                        u16(b, 0); u16(b, 0); u32(b, 0); u32(b, 0); u32(b, 0);    // pre_defined/reserved
                        u16(b, w_); u16(b, h_);
                        u32(b, 0x00480000); u32(b, 0x00480000); u32(b, 0); u16(b, 1);
                        for (int i = 0; i < 32; i++) u8(b, 0);                    // compressorname
                        u16(b, 0x0018); u16(b, 0xFFFF);
                        {   size_t avcC = boxStart(b, "avcC");
                            u8(b, 1); u8(b, sps_[1]); u8(b, sps_[2]); u8(b, sps_[3]); u8(b, 0xFF);
                            u8(b, 0xE1); u16(b, (uint16_t)spsLen_); raw(b, sps_, spsLen_);
                            u8(b, 1);   u16(b, (uint16_t)ppsLen_); raw(b, pps_, ppsLen_);
                            boxEnd(b, avcC);
                        }
                        boxEnd(b, avc1); boxEnd(b, stsd);
                    }
                    { size_t x = boxStart(b, "stts"); u32(b,0); u32(b,0); boxEnd(b,x); }
                    { size_t x = boxStart(b, "stsc"); u32(b,0); u32(b,0); boxEnd(b,x); }
                    { size_t x = boxStart(b, "stsz"); u32(b,0); u32(b,0); u32(b,0); boxEnd(b,x); }
                    { size_t x = boxStart(b, "stco"); u32(b,0); u32(b,0); boxEnd(b,x); }
                    boxEnd(b, stbl);
                }
                boxEnd(b, minf);
            }
            boxEnd(b, mdia);
        }
        boxEnd(b, trak);
    }
    {   // mvex -> trex
        size_t mvex = boxStart(b, "mvex");
        size_t trex = boxStart(b, "trex");
        u32(b, 0); u32(b, 1); u32(b, 1); u32(b, 0); u32(b, 0); u32(b, 0);
        boxEnd(b, trex); boxEnd(b, mvex);
    }
    boxEnd(b, moov);

    if (b.err) return false;   // unvollstaendiges Init-Segment nie als Erfolg melden
    *out = b.p; *len = b.len;
    return b.len > 0;
}

bool Fmp4Muxer::mediaSegment(const uint8_t** out, size_t* len, uint32_t durationTicks) {
    if (!out || !len || avcc_.len == 0) return false;
    uint32_t dur = durationTicks ? durationTicks : sampleDur_;
    Buf& b = media_; reset(b);
    size_t dataOffsetField = 0;

    // ---- moof ----
    size_t moof = boxStart(b, "moof");
    { size_t mfhd = boxStart(b, "mfhd"); u32(b, 0); u32(b, seq_); boxEnd(b, mfhd); }
    {   size_t traf = boxStart(b, "traf");
        { size_t tfhd = boxStart(b, "tfhd"); u32(b, 0x00020000); u32(b, 1); boxEnd(b, tfhd); } // default-base-is-moof
        { size_t tfdt = boxStart(b, "tfdt"); u32(b, 0x01000000); u64(b, baseDecodeTime_); boxEnd(b, tfdt); }
        {   size_t trun = boxStart(b, "trun");
            u32(b, 0x00000701);              // flags: data-offset | sample-duration | sample-size | sample-flags
            u32(b, 1);                       // sample_count
            dataOffsetField = b.len; u32(b, 0);   // data_offset (patch spaeter)
            u32(b, dur);                     // sample_duration (echte Frame-Dauer)
            u32(b, (uint32_t)avcc_.len);     // sample_size
            u32(b, avccKey_ ? 0x02000000 : 0x01010000);  // sample_flags (sync vs. non-sync)
            boxEnd(b, trun);
        }
        boxEnd(b, traf);
    }
    boxEnd(b, moof);

    // data_offset = Start moof (=0) .. Start mdat-Daten = moofLen + 8 (mdat-Header)
    uint32_t dataOffset = (uint32_t)(b.len + 8);
    b.p[dataOffsetField]     = dataOffset >> 24; b.p[dataOffsetField + 1] = dataOffset >> 16;
    b.p[dataOffsetField + 2] = dataOffset >> 8;  b.p[dataOffsetField + 3] = dataOffset;

    // ---- mdat ----
    size_t mdat = boxStart(b, "mdat");
    raw(b, avcc_.p, avcc_.len);
    boxEnd(b, mdat);

    if (b.err || avcc_.err) return false;   // Segment unvollstaendig -> nicht senden, Zeitbasis nicht fortschreiben
    seq_++; baseDecodeTime_ += dur;
    *out = b.p; *len = b.len;
    return b.len > 0;
}
