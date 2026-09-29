/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "WireGuard-ESP32.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#include "lwip/netdb.h"
#include "lwip/tcpip.h"   // WeirdOS: LOCK_TCPIP_CORE (CONFIG_LWIP_TCPIP_CORE_LOCKING=1)

#include <cstdio>    // WeirdOS 7.4d.1: sscanf (CIDR-Parse)
#include <cstring>

#include "esp32-hal-log.h"

extern "C" {
#include "wireguardif.h"
#include "wireguard-platform.h"
#include "wireguard.h"          // WeirdOS 7.4d: wireguard_base64_decode + WIREGUARD_SESSION_KEY_LEN (PSK)
}

// Wireguard instance
static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static struct netif *previous_default_netif = NULL;
static uint8_t wgPeerIndex = WIREGUARDIF_INVALID_INDEX;

#define TAG "[WireGuard] "

// 7.4d.3: Crash-Lokalisierung. Definition/JSON im .ino (RTC_NOINIT, ueberlebt Panic-Reboot).
extern volatile uint32_t g_wgCrashStage;

// WeirdOS 7.4b: 5-arg-Fassung bleibt (Underlay = NULL -> Fallback in wireguardif_init).
bool WireGuard::begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort) {
	return this->begin(localIP, privateKey, remotePeerAddress, remotePeerPublicKey, remotePeerPort, nullptr);
}

bool WireGuard::begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort, void* underlayNetif) {
	g_wgCrashStage = 20;   // 7.4d.3: begin() betreten
	// WeirdOS 7.4d.3 CRASH-FIX: Platform/RNG (mbedtls_ctr_drbg) MUSS vor netif_add stehen.
	// netif_add -> wireguardif_init -> wireguard_device_init -> generate_cookie_secret ->
	// wireguard_random_bytes -> mbedtls_ctr_drbg_random(&random_context). Ohne vorheriges
	// wireguard_platform_init() ist random_context ungeseedet -> Bad-Access -> PANIC (stage 21).
	// Kein lwIP -> ausserhalb des Locks, ganz am Anfang. (Idempotent: is_platform_initialized.)
	wireguard_platform_init();
	struct wireguardif_init_data wg;
	struct wireguardif_peer peer;
	ip_addr_t ipaddr = IPADDR4_INIT(static_cast<uint32_t>(localIP));
	// WeirdOS 7.6: /24 statt /32. Bei /32 hat lwIP keine Subnetz-Route zu den Peer-Tunnel-IPs
	// (z.B. 10.9.0.2) -> Rueckpakete/geforwardete Antworten wuerden an die Default-Route statt
	// ueber wg0 gehen. /24 deckt die (server+1) Client-IPs ab. Fuer Full-Tunnel egal (wg = default).
	ip_addr_t netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0);
	ip_addr_t gateway = IPADDR4_INIT_BYTES(0, 0, 0, 0);

	assert(privateKey != NULL);
	assert(remotePeerPublicKey != NULL);
	assert(remotePeerPort != 0);
	// WeirdOS 7.4d.2: remotePeerAddress darf LEER sein -> Server/Responder-Modus
	// (wir lauschen auf listen_port, der Peer initiiert den Handshake zu uns).
	bool have_endpoint = (remotePeerAddress != NULL && remotePeerAddress[0] != 0);

	// Setup the WireGuard device structure
	wg.private_key = privateKey;
    wg.listen_port = remotePeerPort;

	// WeirdOS 7.4b: Underlay explizit binden (rohes lwIP-netif, z.B. ECM) statt
	// hardcoded WIFI_STA. NULL -> Fallback WIFI_STA_DEF in wireguardif_init.
	wg.bind_netif = (struct netif*)underlayNetif;

	// Initialise the first WireGuard peer structure
	wireguardif_peer_init(&peer);
	// Endpoint aufloesen - NUR im Client-Modus (have_endpoint). Server-Modus: peer.endpoint_ip
	// bleibt 0, wireguardif_connect wird unten nicht gerufen -> wir warten auf den Peer.
	bool success_get_endpoint_ip = !have_endpoint;
	if (have_endpoint) {
	    for(int retry = 0; retry < 5; retry++) {
	        ip_addr_t endpoint_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
	        struct addrinfo *res = NULL;
	        struct addrinfo hint;
	        memset(&hint, 0, sizeof(hint));
	        memset(&endpoint_ip, 0, sizeof(endpoint_ip));
	        if( lwip_getaddrinfo(remotePeerAddress, NULL, &hint, &res) != 0 ) {
				vTaskDelay(pdMS_TO_TICKS(2000));
				continue;
			}
			success_get_endpoint_ip = true;
	        struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
	        inet_addr_to_ip4addr(ip_2_ip4(&endpoint_ip), &addr4);
	        lwip_freeaddrinfo(res);

	        peer.endpoint_ip = endpoint_ip;
	        log_i(TAG "%s is %3d.%3d.%3d.%3d"
				, remotePeerAddress
	            , (endpoint_ip.u_addr.ip4.addr >>  0) & 0xff
	            , (endpoint_ip.u_addr.ip4.addr >>  8) & 0xff
	            , (endpoint_ip.u_addr.ip4.addr >> 16) & 0xff
	            , (endpoint_ip.u_addr.ip4.addr >> 24) & 0xff
	            );
			break;
	    }
		if( !success_get_endpoint_ip  ) {
			log_e(TAG "failed to get endpoint ip.");
			return false;
		}
	}
	// Register the new WireGuard network interface with lwIP.
	// WeirdOS-fix: unter LOCK_TCPIP_CORE (CONFIG_LWIP_TCPIP_CORE_LOCKING=1) - wir laufen im
	// wg_conn-Task, nicht im tcpip-Thread; ohne Lock crasht netif_add/udp_bind (ECM verwaltet
	// parallel ein rohes netif). netif_add triggert wireguardif_init (udp_bind + Crypto).
	g_wgCrashStage = 21;   // vor netif_add (triggert wireguardif_init: udp_bind + device_init-Crypto)
	LOCK_TCPIP_CORE();
	wg_netif = netif_add(&wg_netif_struct, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gateway), &wg, &wireguardif_init, &ip_input);
	g_wgCrashStage = 22;   // netif_add zurueck
	// WeirdOS 7.9.5: Link FEST auf "up". ip4_route() ueberspringt netifs mit Link-down -> sonst
	// wird der Rueckverkehr zum Tunnel-Client (10.9.0.2) faelschlich ueber WLAN/Default geroutet
	// statt ueber wg0. Die Lib setzt den Link sonst nur bei RX kurz up (fragil). Ohne Peer
	// verwirft wireguardif_output ohnehin - Link-up ist also gefahrlos.
	if (wg_netif != nullptr) { netif_set_up(wg_netif); netif_set_link_up(wg_netif); }
	UNLOCK_TCPIP_CORE();
	g_wgCrashStage = 23;   // netif_set_up + UNLOCK zurueck
	if( wg_netif == nullptr ) {
		log_e(TAG "failed to initialize WG netif.");
		return false;
	}

	peer.public_key = remotePeerPublicKey;
	// WeirdOS 7.4d: preshared_key ist ein ROHER 32-Byte-Key (const uint8_t*), kein
	// Base64-String wie public_key. Base64 -> 32 Byte dekodieren. wireguard_peer_init
	// kopiert die Bytes (memcpy) waehrend wireguardif_add_peer -> lokaler Puffer reicht.
	uint8_t psk_bin[WIREGUARD_SESSION_KEY_LEN];
	bool have_psk = false;
	if (_psk && _psk[0]) {
		size_t psk_len = sizeof(psk_bin);
		if (wireguard_base64_decode(_psk, psk_bin, &psk_len) && psk_len == WIREGUARD_SESSION_KEY_LEN) have_psk = true;
	}
	peer.preshared_key = have_psk ? psk_bin : nullptr;
	// WeirdOS 7.4d.1: AllowedIPs aus Config (erste CIDR). Default 0.0.0.0/0 (= alles,
	// mask 0). Bei Split-Tunnel z.B. 10.0.0.0/24 -> nur dieses Subnetz durch den Tunnel.
	{
		ip_addr_t allowed_ip   = IPADDR4_INIT_BYTES(0, 0, 0, 0);
		ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
		if (_allowedCidr && _allowedCidr[0]) {
			char buf[64];
			strncpy(buf, _allowedCidr, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
			char* comma = strchr(buf, ','); if (comma) *comma = 0;   // nur die erste CIDR
			int o0 = 0, o1 = 0, o2 = 0, o3 = 0, prefix = 32;
			if (sscanf(buf, "%d.%d.%d.%d/%d", &o0, &o1, &o2, &o3, &prefix) >= 4) {
				IP_ADDR4(&allowed_ip, o0, o1, o2, o3);
				uint32_t m = (prefix <= 0) ? 0u : (prefix >= 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - prefix)));
				IP_ADDR4(&allowed_mask, (m >> 24) & 0xFF, (m >> 16) & 0xFF, (m >> 8) & 0xFF, m & 0xFF);
			}
		}
		peer.allowed_ip   = allowed_ip;
		peer.allowed_mask = allowed_mask;
	}

	peer.endport_port = remotePeerPort;
	peer.keep_alive   = _keepalive;   // WeirdOS 7.4d.1: Persistent Keepalive (0 = aus)

    // (7.4d.3: wireguard_platform_init() ist nach ganz oben gewandert - vor netif_add,
    //  weil device_init dort schon den DRBG braucht. Siehe Kommentar am Funktionsanfang.)

	// WeirdOS 7.4d.1: Returncodes pruefen und bei Fehler sauber rueckbauen (statt
	// _is_initialized trotzdem true -> UI haengt sonst ewig auf "verbindet").
	// WeirdOS-fix: netif/peer-Ops unter LOCK_TCPIP_CORE.
	g_wgCrashStage = 24;   // vor add_peer (curve25519 DH-Precompute)
	LOCK_TCPIP_CORE();
	err_t aerr = wireguardif_add_peer(wg_netif, &peer, &wgPeerIndex);
	g_wgCrashStage = 25;   // add_peer zurueck
	if (aerr != ERR_OK || wgPeerIndex == WIREGUARDIF_INVALID_INDEX) {
		wireguardif_shutdown(wg_netif);
		netif_remove(wg_netif);
		UNLOCK_TCPIP_CORE();
		log_e(TAG "wireguardif_add_peer failed (%d)", (int)aerr);
		wg_netif = nullptr;
		wgPeerIndex = WIREGUARDIF_INVALID_INDEX;
		return false;
	}

	if (!ip_addr_isany(&peer.endpoint_ip)) {
		// Start outbound connection to peer
		log_i(TAG "connecting wireguard...");
		err_t cerr = wireguardif_connect(wg_netif, wgPeerIndex);
		if (cerr != ERR_OK) {
			wireguardif_remove_peer(wg_netif, wgPeerIndex);
			wireguardif_shutdown(wg_netif);
			netif_remove(wg_netif);
			UNLOCK_TCPIP_CORE();
			log_e(TAG "wireguardif_connect failed (%d)", (int)cerr);
			wgPeerIndex = WIREGUARDIF_INVALID_INDEX;
			wg_netif = nullptr;
			return false;
		}
		// WeirdOS 7.4d: nur bei Full-Tunnel wg als Default-Route setzen. Sonst kommt der
		// Tunnel hoch + Handshake, aber das restliche Routing bleibt unberuehrt (kein
		// Aussperren des Geraets, falls der Tunnel fehlschlaegt).
		if (_routeDefault) {
			previous_default_netif = netif_default;
			netif_set_default(wg_netif);
		}
	}
	UNLOCK_TCPIP_CORE();

	g_wgCrashStage = 26;   // begin() komplett durchgelaufen (Handshake/Timer laufen ab jetzt)
	this->_is_initialized = true;
	return true;
}

bool WireGuard::isPeerUp() {
	if (!this->_is_initialized || wg_netif == nullptr || wgPeerIndex == WIREGUARDIF_INVALID_INDEX) return false;
	LOCK_TCPIP_CORE();
	bool up = (wireguardif_peer_is_up(wg_netif, wgPeerIndex, NULL, NULL) == ERR_OK);
	UNLOCK_TCPIP_CORE();
	return up;
}

// WeirdOS 7.9.8: netif als opaker Handle (fuer NAPT auf dem WG-Input-netif).
void* WireGuard::netifHandle() const {
	return (void*)wg_netif;
}

// WeirdOS 7.9.2 Multi-Client.
int WireGuard::firstPeerIndex() const {
	return (wgPeerIndex == WIREGUARDIF_INVALID_INDEX) ? -1 : (int)wgPeerIndex;
}

int WireGuard::addServerPeer(const char* publicKeyB64, const IPAddress& allowedIp) {
	if (wg_netif == nullptr || publicKeyB64 == nullptr) return -1;
	struct wireguardif_peer peer;
	wireguardif_peer_init(&peer);
	peer.public_key = publicKeyB64;
	peer.preshared_key = nullptr;
	ip_addr_t aip   = IPADDR4_INIT(static_cast<uint32_t>(allowedIp));
	ip_addr_t amask = IPADDR4_INIT_BYTES(255, 255, 255, 255);
	peer.allowed_ip   = aip;
	peer.allowed_mask = amask;
	peer.endport_port = 0;        // Server-Peer: kein Endpoint (wir lauschen)
	peer.keep_alive   = _keepalive;
	uint8_t idx = WIREGUARDIF_INVALID_INDEX;
	LOCK_TCPIP_CORE();
	err_t e = wireguardif_add_peer(wg_netif, &peer, &idx);
	UNLOCK_TCPIP_CORE();
	if (e != ERR_OK || idx == WIREGUARDIF_INVALID_INDEX) return -1;
	return (int)idx;
}

bool WireGuard::isPeerUpIndex(int index) {
	if (!this->_is_initialized || wg_netif == nullptr || index < 0) return false;
	LOCK_TCPIP_CORE();
	bool up = (wireguardif_peer_is_up(wg_netif, (uint8_t)index, NULL, NULL) == ERR_OK);
	UNLOCK_TCPIP_CORE();
	return up;
}

bool WireGuard::peerStats(int index, uint32_t& rxAgeMs, uint32_t& txAgeMs) {
	if (wg_netif == nullptr || index < 0) return false;
	uint32_t lrx = 0, ltx = 0, now = 0;
	LOCK_TCPIP_CORE();
	err_t e = wireguardif_peer_stats(wg_netif, (uint8_t)index, &lrx, &ltx, &now);
	UNLOCK_TCPIP_CORE();
	if (e != ERR_OK) return false;
	rxAgeMs = lrx ? (now - lrx) : 0xFFFFFFFFu;
	txAgeMs = ltx ? (now - ltx) : 0xFFFFFFFFu;
	return true;
}

void WireGuard::end() {
	if( !this->_is_initialized ) return;

	// WeirdOS-fix: lwIP-Ops unter LOCK_TCPIP_CORE (wie begin()).
	LOCK_TCPIP_CORE();
	// WeirdOS 7.4d: nur zuruecksetzen, wenn wir die Default-Route ueberhaupt uebernommen
	// hatten (Full-Tunnel). Sonst wuerde netif_set_default(NULL) die Route killen.
	if (previous_default_netif != nullptr) {
		netif_set_default(previous_default_netif);
		previous_default_netif = nullptr;
	}
	wireguardif_disconnect(wg_netif, wgPeerIndex);
	wireguardif_remove_peer(wg_netif, wgPeerIndex);
	wgPeerIndex = WIREGUARDIF_INVALID_INDEX;
	wireguardif_shutdown(wg_netif);
	netif_remove(wg_netif);
	wg_netif = nullptr;
	UNLOCK_TCPIP_CORE();

	this->_is_initialized = false;
}