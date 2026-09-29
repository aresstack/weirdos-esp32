// ============================================================================
// ipsec_config.h -- WeirdOS-Minimalprofil fuer CycloneIPSEC (Stufe 8.2, ENTWURF).
//
// STAND: Entwurf/Startpunkt. NICHT im Build (Ordner liegt nicht unter src/). Wird beim ersten
// Compile-Loop gegen CycloneCRYPTO/Common verifiziert und praezisiert. Ziel: SCHMAL halten
// (Flash/RAM auf dem ESP32-S3 knapp) - nur was ein typischer Remote-Access-IKEv2-Server braucht.
//
// Makronamen aus dem CycloneIPSEC-Checkout (ike/*.c) uebernommen. ENABLED/DISABLED kommen aus
// Oryx os_port.h. Krypto-Gegenstuecke (SHA256_SUPPORT etc.) gehoeren in crypto_config.h.
// ============================================================================
#ifndef IPSEC_CONFIG_H
#define IPSEC_CONFIG_H

// --- Rollen/Grundfunktionen ---
#define IKE_SUPPORT                     ENABLED
#define IKE_CLIENT_SUPPORT              ENABLED    // Client-Rolle zuerst (Initiator)
// Server/Responder erst spaeter:
// #define IKE_SERVER_SUPPORT           DISABLED

// --- Authentisierung: PSK zuerst, Cert/EAP spaeter ---
#define IKE_PSK_AUTH_SUPPORT            ENABLED
#define IKE_CERT_AUTH_SUPPORT           DISABLED
#define IKE_EAP_AUTH_SUPPORT            DISABLED

// --- NAT-Traversal + Liveness (Mobilfunk: Pflicht) ---
#define IKE_COOKIE_SUPPORT              ENABLED
#define IKE_DPD_SUPPORT                 ENABLED
#define IKE_CREATE_CHILD_SA_SUPPORT     ENABLED

// --- Verschluesselung (schmal): AES-256, AEAD (GCM) UND CBC+HMAC als breite Kompatibilitaet ---
#define IKE_AES_128_SUPPORT             ENABLED
#define IKE_AES_192_SUPPORT             DISABLED
#define IKE_AES_256_SUPPORT             ENABLED
#define IKE_3DES_SUPPORT                DISABLED
#define IKE_DES_SUPPORT                 DISABLED
#define IKE_CAMELLIA_128_SUPPORT        DISABLED
#define IKE_CAMELLIA_192_SUPPORT        DISABLED
#define IKE_CAMELLIA_256_SUPPORT        DISABLED
#define IKE_CHACHA20_POLY1305_SUPPORT   DISABLED

#define IKE_CBC_SUPPORT                 ENABLED
#define IKE_CTR_SUPPORT                 DISABLED
#define IKE_GCM_8_SUPPORT               DISABLED
#define IKE_GCM_12_SUPPORT              DISABLED
#define IKE_GCM_16_SUPPORT              ENABLED
#define IKE_CCM_8_SUPPORT               DISABLED
#define IKE_CCM_12_SUPPORT              DISABLED
#define IKE_CCM_16_SUPPORT              DISABLED

// --- Integritaet/PRF: HMAC-SHA2 ---
#define IKE_HMAC_AUTH_SUPPORT           ENABLED
#define IKE_HMAC_PRF_SUPPORT            ENABLED
#define IKE_CMAC_AUTH_SUPPORT           DISABLED
#define IKE_CMAC_PRF_SUPPORT            DISABLED
#define IKE_SHA1_SUPPORT                ENABLED    // viele Server verlangen es noch (Interop)
#define IKE_SHA256_SUPPORT              ENABLED
#define IKE_SHA384_SUPPORT              ENABLED
#define IKE_SHA512_SUPPORT              DISABLED

// --- Schluesselaustausch: ECP-256 (Group 19) + modp2048 (Group 14, Fritz!Box & Co.) + X25519 ---
#define IKE_DH_KE_SUPPORT               ENABLED    // klassische modp-Gruppen
#define IKE_ECDH_KE_SUPPORT             ENABLED
#define IKE_ECP_192_SUPPORT             DISABLED
#define IKE_ECP_224_SUPPORT             DISABLED
#define IKE_ECP_256_SUPPORT             ENABLED    // Group 19
#define IKE_ECP_384_SUPPORT             DISABLED
#define IKE_ECP_521_SUPPORT             DISABLED
#define IKE_CURVE25519_SUPPORT          ENABLED    // Group 31
#define IKE_CURVE448_SUPPORT            DISABLED
#define IKE_BRAINPOOLP224R1_SUPPORT     DISABLED
#define IKE_BRAINPOOLP256R1_SUPPORT     DISABLED
#define IKE_BRAINPOOLP384R1_SUPPORT     DISABLED
#define IKE_BRAINPOOLP512R1_SUPPORT     DISABLED

// --- Signatur-Auth (nur wenn Cert/EAP spaeter an) ---
#define IKE_RSA_SIGN_SUPPORT            DISABLED
#define IKE_ECDSA_SIGN_SUPPORT          DISABLED
#define IKE_DSA_SIGN_SUPPORT            DISABLED
#define IKE_ED25519_SIGN_SUPPORT        DISABLED
#define IKE_ED448_SIGN_SUPPORT          DISABLED

// --- Groessen (klein halten; beim Test hochziehen falls noetig) ---
#define IKE_MAX_SA_ENTRIES              2
#define IKE_MAX_CHILD_SA_ENTRIES        2
// Weitere IKE_MAX_* (Nonce/DH/Proposal-Puffer) beim Compile-Loop aus ike_*.c ergaenzen.

// HINWEIS: Genaue Makro-Liste + Defaults liefert CycloneCRYPTO/CycloneIPSEC's mitgelieferte
// *_config.h-Vorlage. Diese Datei ist der WeirdOS-Startpunkt, kein vollstaendiger Satz.

#endif // IPSEC_CONFIG_H
