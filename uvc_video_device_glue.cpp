// ============================================================================
// uvc_video_device_glue.cpp -- Weiche fuer usbd_edpt_xfer(): TinyUSB 0.19/0.20 hat vier Argumente,
// master (0.21) fuenf (bool is_isr). uvc_video_device.c ist C und kann die Signatur des gelinkten
// Headers nicht selbst erkennen; hier entscheidet die Ueberladungsaufloesung ueber den Funktionszeiger-
// Typ zur Uebersetzungszeit. Passt keine der beiden Formen, bricht der Build sichtbar ab (gewollt).
// ============================================================================
#include "soc/soc_caps.h"
#include "weirdos_features.h"
#if SOC_USB_OTG_SUPPORTED && defined(CONFIG_TINYUSB_ENABLED) && WEIRDOS_FEATURE_USB_DEVICE && WEIRDOS_FEATURE_UVC
#include "tusb.h"
#include "device/usbd_pvt.h"

namespace {
using Xfer4 = bool (*)(uint8_t, uint8_t, uint8_t*, uint16_t);
using Xfer5 = bool (*)(uint8_t, uint8_t, uint8_t*, uint16_t, bool);
inline bool callXfer(Xfer4 f, uint8_t rhport, uint8_t ep, uint8_t* buf, uint16_t len) { return f(rhport, ep, buf, len); }
inline bool callXfer(Xfer5 f, uint8_t rhport, uint8_t ep, uint8_t* buf, uint16_t len) { return f(rhport, ep, buf, len, false); }
}

extern "C" bool weirdos_usbd_edpt_xfer(uint8_t rhport, uint8_t ep_addr, uint8_t* buffer, uint16_t total_bytes) {
    return callXfer(&usbd_edpt_xfer, rhport, ep_addr, buffer, total_bytes);
}
#endif
