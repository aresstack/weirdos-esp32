// ============================================================================
// tinyusb_class_stubs.c -- No-op-Einsprungpunkte fuer die TinyUSB-Geraeteklassen, die WeirdOS NICHT benutzt.
//
// Warum: usbd.c der Core-Bibliothek (libarduino_tinyusb.a) haelt eine feste Treibertabelle mit ALLEN
// Klassen (CDC, HID, MIDI, MSC, Audio, DFU, Vendor, NCM/ECM, ...). Sobald usbd gelinkt wird, zieht der
// Linker jede Klasse samt ihrer statischen Puffer (~46 KB internes RAM) mit -- auch ungenutzt. Sketch-
// Objekte werden VOR den Archiven aufgeloest: definieren wir die Einsprungpunkte hier, werden die Klassen-
// Objekte nie aus dem Archiv geholt, ihre Puffer verschwinden. Uebrig bleiben usbd + dcd_dwc2 + video
// (~2 KB). Dasselbe gilt fuer den TinyUSB-Host-Stack (tuh_*/usbh_*/hcd_*), den tusb.c referenziert --
// WeirdOS nutzt fuer das Modem den IDF-Host, nicht TinyUSB-Host.
//
// Semantik der Stubs: init/reset = nichts; deinit = true; open = 0 (Interface nicht uebernommen -> usbd
// probiert den naechsten Treiber, z. B. video); control/xfer = false. Nur die Video-Klasse bleibt echt --
// und auch die kommt nicht aus dem Archiv, sondern aus uvc_video_device.c (derselbe Mechanismus: alle
// videod_*/tud_video_*-Symbole im Sketch -> video_device.o der Bibliothek wird nie gezogen).
// Kompiliert immer mit; ohne WEIRDOS_USB_DEVICE wird usbd nicht gelinkt und die Stubs bleiben unbenutzt.
// ============================================================================
#include "soc/soc_caps.h"
#if SOC_USB_OTG_SUPPORTED && defined(CONFIG_TINYUSB_ENABLED)
#include "tusb.h"

#define STUB_CLASS(P) \
    void     P##_init(void) {} \
    bool     P##_deinit(void) { return true; } \
    void     P##_reset(uint8_t rhport) { (void)rhport; } \
    uint16_t P##_open(uint8_t rhport, tusb_desc_interface_t const* itf_desc, uint16_t max_len) { (void)rhport; (void)itf_desc; (void)max_len; return 0; } \
    bool     P##_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const* request) { (void)rhport; (void)stage; (void)request; return false; } \
    bool     P##_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes) { (void)rhport; (void)ep_addr; (void)result; (void)xferred_bytes; return false; }

STUB_CLASS(cdcd)
STUB_CLASS(hidd)
STUB_CLASS(midid)
STUB_CLASS(vendord)
STUB_CLASS(netd)
STUB_CLASS(audiod)
bool audiod_xfer_isr(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes) { (void)rhport; (void)ep_addr; (void)result; (void)xferred_bytes; return false; }
void audiod_sof_isr(uint8_t rhport, uint32_t frame_count) { (void)rhport; (void)frame_count; }
// MSC hat kein deinit in der Tabelle
void     mscd_init(void) {}
void     mscd_reset(uint8_t rhport) { (void)rhport; }
uint16_t mscd_open(uint8_t rhport, tusb_desc_interface_t const* itf_desc, uint16_t max_len) { (void)rhport; (void)itf_desc; (void)max_len; return 0; }
bool     mscd_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const* request) { (void)rhport; (void)stage; (void)request; return false; }
bool     mscd_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes) { (void)rhport; (void)ep_addr; (void)result; (void)xferred_bytes; return false; }
// DFU (Runtime + Mode) hat kein xfer_cb in der Tabelle
#define STUB_DFU(P) \
    void     P##_init(void) {} \
    bool     P##_deinit(void) { return true; } \
    void     P##_reset(uint8_t rhport) { (void)rhport; } \
    uint16_t P##_open(uint8_t rhport, tusb_desc_interface_t const* itf_desc, uint16_t max_len) { (void)rhport; (void)itf_desc; (void)max_len; return 0; } \
    bool     P##_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const* request) { (void)rhport; (void)stage; (void)request; return false; }
STUB_DFU(dfu_rtd)
STUB_DFU(dfu_moded)

// TinyUSB-Host-Stack: von tusb.c/dcd_dwc2.c referenziert, in WeirdOS nie benutzt (Modem-Host = IDF usb_host).
bool tuh_rhport_init(uint8_t rhport, const tusb_rhport_init_t* rh_init) { (void)rhport; (void)rh_init; return false; }
bool tuh_deinit(uint8_t rhport) { (void)rhport; return false; }
bool tuh_inited(void) { return false; }
bool usbh_edpt_claim(uint8_t dev_addr, uint8_t ep_addr) { (void)dev_addr; (void)ep_addr; return false; }
bool usbh_edpt_release(uint8_t dev_addr, uint8_t ep_addr) { (void)dev_addr; (void)ep_addr; return false; }
bool usbh_edpt_xfer_with_callback(uint8_t dev_addr, uint8_t ep_addr, uint8_t* buffer, uint16_t total_bytes, tuh_xfer_cb_t complete_cb, uintptr_t user_data) {
    (void)dev_addr; (void)ep_addr; (void)buffer; (void)total_bytes; (void)complete_cb; (void)user_data; return false;
}
void hcd_int_handler(uint8_t rhport, bool in_isr) { (void)rhport; (void)in_isr; }
#endif
