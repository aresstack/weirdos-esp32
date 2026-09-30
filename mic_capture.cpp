#include "mic_capture.h"

#include "weirdos_features.h"

#if WEIRDOS_FEATURE_AUDIO

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include "soc/soc_caps.h"   // SOC_I2S_SUPPORTS_PDM_RX fuer die Backend-Weiche
#include <string.h>

namespace cam { namespace mic {
namespace {

constexpr char TAG[] = "mic";

// --- Gemeinsamer Ring (ein Lese-Task fuellt, USB-Feed leert) -----------------
// PCM 16 kHz mono: 1 s = 32 KB. 250 ms Ring reicht als Puffer zwischen dem I2S-
// DMA und dem USB-Feed. Wenn PSRAM da ist, dorthin (der DMA-Puffer selbst muss
// intern sein, das erledigt der I2S-Treiber).
constexpr size_t kRingSamples = 16000 / 4;   // ~250 ms
int16_t*          s_ring = nullptr;
volatile size_t   s_head = 0, s_tail = 0;     // head=Schreiber, tail=Leser
SemaphoreHandle_t s_lock = nullptr;
TaskHandle_t      s_task = nullptr;
volatile bool     s_run = false;
bool              s_active = false;
uint32_t          s_rate = 16000;
const char*       s_name = "aus";

inline size_t ringCount() { return (s_head + kRingSamples - s_tail) % kRingSamples; }

void ringPush(const int16_t* src, size_t n) {
    if (!s_ring || !s_lock) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (size_t i = 0; i < n; i++) {
        size_t next = (s_head + 1) % kRingSamples;
        if (next == s_tail) s_tail = (s_tail + 1) % kRingSamples;   // voll -> aeltestes fallen lassen
        s_ring[s_head] = src[i];
        s_head = next;
    }
    xSemaphoreGive(s_lock);
}

// ============================================================================
// Backend: ESP32-P4 -> ES8311-Codec (I2S-Std-RX + I2C-Steuerung)
// ============================================================================
#if defined(CONFIG_IDF_TARGET_ESP32P4)
#include "driver/i2s_std.h"
#include "driver/i2c_master.h"

// Waveshare P4-Pico: ES8311 am geteilten I2C (SDA=7, SCL=8), I2S-Daten GPIO9-13
// (DSDIN=9 Codec->ESP, LRCK=10, ASDOUT=11 ESP->Codec, SCLK=12, MCLK=13).
constexpr gpio_num_t P4_I2C_SDA = GPIO_NUM_7, P4_I2C_SCL = GPIO_NUM_8;
constexpr gpio_num_t P4_MCLK = GPIO_NUM_13, P4_SCLK = GPIO_NUM_12, P4_WS = GPIO_NUM_10, P4_DIN = GPIO_NUM_9;
constexpr uint8_t    ES8311_ADDR = 0x18;

i2s_chan_handle_t     s_rx = nullptr;
i2c_master_bus_handle_t s_i2cBus = nullptr;
i2c_master_dev_handle_t s_i2cDev = nullptr;

bool es8311Write(uint8_t reg, uint8_t val) {
    uint8_t buf[2] = { reg, val };
    return s_i2cDev && i2c_master_transmit(s_i2cDev, buf, 2, 100) == ESP_OK;
}

// Minimaler Aufnahmepfad des ES8311 (interner MCLK aus SCLK, ADC an, 16 kHz).
// Best-effort: schlaegt ein Schritt fehl, meldet begin() false -> kein Audio.
bool es8311RecordInit(uint32_t rate) {
    i2c_master_bus_config_t bc = {};
    bc.i2c_port = -1;                 // beliebiger freier Port
    bc.sda_io_num = P4_I2C_SDA; bc.scl_io_num = P4_I2C_SCL;
    bc.clk_source = I2C_CLK_SRC_DEFAULT; bc.glitch_ignore_cnt = 7;
    bc.flags.enable_internal_pullup = true;
    if (i2c_new_master_bus(&bc, &s_i2cBus) != ESP_OK) return false;
    i2c_device_config_t dc = {};
    dc.dev_addr_length = I2C_ADDR_BIT_LEN_7; dc.device_address = ES8311_ADDR; dc.scl_speed_hz = 100000;
    if (i2c_master_bus_add_device(s_i2cBus, &dc, &s_i2cDev) != ESP_OK) return false;

    // Reset + Takt aus SCLK (kein externer MCLK noetig), Aufnahmekette an.
    const uint8_t seq[][2] = {
        {0x00,0x1F},{0x00,0x00},{0x01,0x30},{0x02,0x10},{0x03,0x10},
        {0x16,0x24},{0x04,0x10},{0x05,0x00},{0x0B,0x00},{0x0C,0x00},
        {0x10,0x1F},{0x11,0x7F},{0x00,0x80},          // Slave, an
        {0x14,0x1A},                                  // ADC: 1 Kanal, Mic-Gain
        {0x17,0xBF},{0x18,0x00},{0x19,0x00},{0x1B,0x0A},{0x1C,0x6A},
        {0x09,0x00},{0x0A,0x00},                      // Serial: 16 bit, I2S
    };
    for (auto& s : seq) if (!es8311Write(s[0], s[1])) return false;
    (void)rate;   // feste 16 kHz ueber die I2S-Clk unten
    return true;
}

bool backendStart(uint32_t rate) {
    if (!es8311RecordInit(rate)) return false;
    i2s_chan_config_t cc = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_AUTO, I2S_ROLE_MASTER);
    if (i2s_new_channel(&cc, nullptr, &s_rx) != ESP_OK) return false;
    i2s_std_config_t sc = {};
    sc.clk_cfg  = I2S_STD_CLK_DEFAULT_CONFIG(rate);
    sc.slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO);
    sc.gpio_cfg.mclk = P4_MCLK; sc.gpio_cfg.bclk = P4_SCLK; sc.gpio_cfg.ws = P4_WS;
    sc.gpio_cfg.dout = I2S_GPIO_UNUSED; sc.gpio_cfg.din = P4_DIN;
    if (i2s_channel_init_std_mode(s_rx, &sc) != ESP_OK) return false;
    if (i2s_channel_enable(s_rx) != ESP_OK) return false;
    s_name = "ES8311 (P4, I2S GPIO9-13)";
    return true;
}
void backendStop() {
    if (s_rx) { i2s_channel_disable(s_rx); i2s_del_channel(s_rx); s_rx = nullptr; }
    if (s_i2cDev) { i2c_master_bus_rm_device(s_i2cDev); s_i2cDev = nullptr; }
    if (s_i2cBus) { i2c_del_master_bus(s_i2cBus); s_i2cBus = nullptr; }
}
size_t backendRead(int16_t* dst, size_t maxSamples) {
    if (!s_rx) return 0;
    size_t got = 0;
    if (i2s_channel_read(s_rx, dst, maxSamples * sizeof(int16_t), &got, 20) != ESP_OK) return 0;
    return got / sizeof(int16_t);
}

// ============================================================================
// Backend: ESP32-S3 (u.a. XIAO Sense) -> PDM-Mikro ueber I2S-PDM-RX
// ============================================================================
#elif defined(SOC_I2S_SUPPORTS_PDM_RX) || defined(CONFIG_IDF_TARGET_ESP32S3)
#include "driver/i2s_pdm.h"

// XIAO ESP32-S3 Sense: PDM-Takt GPIO42, PDM-Daten GPIO41 (Seeed-Belegung).
constexpr gpio_num_t S3_PDM_CLK = GPIO_NUM_42, S3_PDM_DIN = GPIO_NUM_41;
i2s_chan_handle_t s_rx = nullptr;

bool backendStart(uint32_t rate) {
    i2s_chan_config_t cc = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_AUTO, I2S_ROLE_MASTER);
    if (i2s_new_channel(&cc, nullptr, &s_rx) != ESP_OK) return false;
    i2s_pdm_rx_config_t pc = {};
    pc.clk_cfg  = I2S_PDM_RX_CLK_DEFAULT_CONFIG(rate);
    pc.slot_cfg = I2S_PDM_RX_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO);
    pc.gpio_cfg.clk = S3_PDM_CLK;
    pc.gpio_cfg.din = S3_PDM_DIN;
    pc.gpio_cfg.invert_flags.clk_inv = 0;
    if (i2s_channel_init_pdm_rx_mode(s_rx, &pc) != ESP_OK) { i2s_del_channel(s_rx); s_rx = nullptr; return false; }
    if (i2s_channel_enable(s_rx) != ESP_OK) { i2s_del_channel(s_rx); s_rx = nullptr; return false; }
    s_name = "PDM (S3, CLK42/DATA41)";
    return true;
}
void backendStop() {
    if (s_rx) { i2s_channel_disable(s_rx); i2s_del_channel(s_rx); s_rx = nullptr; }
}
size_t backendRead(int16_t* dst, size_t maxSamples) {
    if (!s_rx) return 0;
    size_t got = 0;
    if (i2s_channel_read(s_rx, dst, maxSamples * sizeof(int16_t), &got, 20) != ESP_OK) return 0;
    return got / sizeof(int16_t);
}

// ============================================================================
// Backend: keins (Plattform ohne unterstuetztes Mikro)
// ============================================================================
#else
bool   backendStart(uint32_t) { return false; }
void   backendStop() {}
size_t backendRead(int16_t*, size_t) { return 0; }
#endif

// --- Lese-Task: I2S blockierend lesen, in den Ring schieben ------------------
void readerTask(void*) {
    int16_t buf[256];
    while (s_run) {
        size_t n = backendRead(buf, 256);
        if (n) ringPush(buf, n);
        else vTaskDelay(1);
    }
    vTaskDelete(nullptr);
}

} // namespace

bool begin(uint32_t sampleRate, uint32_t* actualRate) {
    if (s_active) { if (actualRate) *actualRate = s_rate; return true; }
    s_rate = sampleRate ? sampleRate : 16000;
    if (!s_lock) s_lock = xSemaphoreCreateMutex();
    if (!s_ring) {
        s_ring = (int16_t*)heap_caps_malloc(kRingSamples * sizeof(int16_t),
                                            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_ring) s_ring = (int16_t*)malloc(kRingSamples * sizeof(int16_t));
    }
    if (!s_lock || !s_ring) { ESP_LOGE(TAG, "kein Speicher"); return false; }
    s_head = s_tail = 0;
    if (!backendStart(s_rate)) { ESP_LOGW(TAG, "kein Mikro erkannt -> kein Audio"); return false; }
    s_run = true;
    if (xTaskCreatePinnedToCore(readerTask, "mic", 3072, nullptr, 5, &s_task, 0) != pdPASS) {
        s_run = false; backendStop(); return false;
    }
    s_active = true;
    if (actualRate) *actualRate = s_rate;
    ESP_LOGI(TAG, "Mikro aktiv: %s @ %u Hz", s_name, (unsigned)s_rate);
    return true;
}

void end() {
    if (!s_active) return;
    s_run = false;
    if (s_task) { vTaskDelay(pdMS_TO_TICKS(30)); s_task = nullptr; }
    backendStop();
    s_active = false;
    s_name = "aus";
}

bool active() { return s_active; }

size_t read(int16_t* dst, size_t maxSamples) {
    if (!s_active || !s_ring || !s_lock || !dst || !maxSamples) return 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    size_t avail = ringCount();
    size_t n = avail < maxSamples ? avail : maxSamples;
    for (size_t i = 0; i < n; i++) { dst[i] = s_ring[s_tail]; s_tail = (s_tail + 1) % kRingSamples; }
    xSemaphoreGive(s_lock);
    return n;
}

const char* backendName() { return s_name; }

}} // namespace cam::mic

#else  // !WEIRDOS_FEATURE_AUDIO -- kein Audio-Code im Build

namespace cam { namespace mic {
bool begin(uint32_t, uint32_t*) { return false; }
void end() {}
bool active() { return false; }
size_t read(int16_t*, size_t) { return 0; }
const char* backendName() { return "aus"; }
}}

#endif
