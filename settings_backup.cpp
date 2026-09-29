// ============================================================================
// settings_backup.cpp -- siehe settings_backup.h. Generische NVS-Iteration.
// ============================================================================
#include "settings_backup.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "mbedtls/base64.h"

// Secret-Denylist: Keys, deren Name (case-insensitive) eines dieser Fragmente
// enthaelt, werden NICHT exportiert (PIN/Passwoerter/PSK/private Keys/Stream-Key).
static bool isSecretKey(const char* key) {
    String k = key; k.toLowerCase();
    return k.indexOf("pass") >= 0 || k.indexOf("pin") >= 0 || k.indexOf("psk") >= 0
        || k.indexOf("key")  >= 0 || k.indexOf("priv") >= 0 || k.indexOf("secret") >= 0;
}

static String b64enc(const String& s) {
    size_t need = 4 * ((s.length() + 2) / 3) + 1;
    unsigned char* buf = (unsigned char*)malloc(need + 4);
    if (!buf) return "";
    size_t olen = 0;
    String out;
    if (mbedtls_base64_encode(buf, need + 4, &olen, (const unsigned char*)s.c_str(), s.length()) == 0) {
        buf[olen] = 0;
        out = String((char*)buf);
    }
    free(buf);
    return out;
}

static String b64dec(const String& s) {
    size_t need = (s.length() / 4) * 3 + 4;
    unsigned char* buf = (unsigned char*)malloc(need + 4);
    if (!buf) return "";
    size_t olen = 0;
    String out;
    if (mbedtls_base64_decode(buf, need + 4, &olen, (const unsigned char*)s.c_str(), s.length()) == 0) {
        out.reserve(olen);
        for (size_t i = 0; i < olen; i++) out += (char)buf[i];
    }
    free(buf);
    return out;
}

String settingsBackupExport() {
    String out = "WEIRDOS-BACKUP v1\n";
    nvs_iterator_t it = NULL;
    esp_err_t err = nvs_entry_find("nvs", NULL, NVS_TYPE_ANY, &it);
    while (err == ESP_OK && it != NULL) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        if (!isSecretKey(info.key)) {
            nvs_handle_t h;
            if (nvs_open(info.namespace_name, NVS_READONLY, &h) == ESP_OK) {
                String head = String(info.namespace_name) + "|" + info.key + "|";
                if (info.type == NVS_TYPE_STR) {
                    size_t len = 0;
                    if (nvs_get_str(h, info.key, NULL, &len) == ESP_OK && len > 0) {
                        char* v = (char*)malloc(len);
                        if (v && nvs_get_str(h, info.key, v, &len) == ESP_OK) {
                            out += head + "s|" + b64enc(String(v)) + "\n";
                        }
                        free(v);
                    }
                } else if (info.type == NVS_TYPE_I32) {
                    int32_t v; if (nvs_get_i32(h, info.key, &v) == ESP_OK) out += head + "i|" + String(v) + "\n";
                } else if (info.type == NVS_TYPE_U32) {
                    uint32_t v; if (nvs_get_u32(h, info.key, &v) == ESP_OK) out += head + "u|" + String(v) + "\n";
                } else if (info.type == NVS_TYPE_U8) {
                    uint8_t v; if (nvs_get_u8(h, info.key, &v) == ESP_OK) out += head + "8|" + String(v) + "\n";
                }
                // Andere Typen (I8/U16/I64/BLOB) nutzt Preferences hier nicht -> uebersprungen.
                nvs_close(h);
            }
        }
        err = nvs_entry_next(&it);
    }
    if (it != NULL) nvs_release_iterator(it);
    return out;
}

int settingsBackupImport(const String& body) {
    int n = 0;
    int start = 0;
    while (start < (int)body.length()) {
        int nl = body.indexOf('\n', start);
        String line = (nl < 0) ? body.substring(start) : body.substring(start, nl);
        start = (nl < 0) ? body.length() : nl + 1;
        line.trim();
        if (line.length() == 0 || line.startsWith("WEIRDOS-BACKUP")) continue;

        int p1 = line.indexOf('|');
        int p2 = line.indexOf('|', p1 + 1);
        int p3 = line.indexOf('|', p2 + 1);
        if (p1 < 0 || p2 < 0 || p3 < 0) continue;
        String ns  = line.substring(0, p1);
        String key = line.substring(p1 + 1, p2);
        String typ = line.substring(p2 + 1, p3);
        String val = line.substring(p3 + 1);
        if (ns.length() == 0 || key.length() == 0 || key.length() > 15) continue;

        nvs_handle_t h;
        if (nvs_open(ns.c_str(), NVS_READWRITE, &h) != ESP_OK) continue;
        esp_err_t e = ESP_FAIL;
        if (typ == "s")      { String d = b64dec(val); e = nvs_set_str(h, key.c_str(), d.c_str()); }
        else if (typ == "i") { e = nvs_set_i32(h, key.c_str(), (int32_t)val.toInt()); }
        else if (typ == "u") { e = nvs_set_u32(h, key.c_str(), (uint32_t)strtoul(val.c_str(), NULL, 10)); }
        else if (typ == "8") { e = nvs_set_u8(h, key.c_str(), (uint8_t)val.toInt()); }
        if (e == ESP_OK) { nvs_commit(h); n++; }
        nvs_close(h);
    }
    return n;
}
