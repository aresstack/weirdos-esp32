// ============================================================================
// serial_console.h  --  Serielle Kommando-Konsole (Bedien-Alternative zur Web-UI)
//
// Vor allem fuer den ESP32-P4 (kein natives WLAN -> keine lokale Web-UI): ueber
// den USB-CDC-Port (AS-Serial-Monitor) laesst sich das Geraet wie ein Terminal
// bedienen. serialConsoleTick() gehoert in loop(); es liest zeilenweise von
// Serial und ruft die vorhandene Kern-Logik (Modem/DynDNS/Status) auf.
// Board-neutral (auch am S3 zum Debuggen nutzbar).
// ============================================================================
#ifndef SERIAL_CONSOLE_H
#define SERIAL_CONSOLE_H

#include <stdint.h>

void serialConsoleTick();   // aus loop() aufrufen (nicht blockierend beim Lesen)

// Befehlsliste (dieselbe wie 'help' auf der Konsole) -- fuer die Web-UI (Einrichtung > Setup > UART).
const char* serialConsoleHelpText();

// Baudrate: NVS "cfg"/"uartbaud" (Default 115200), wird in setup() fuer Serial.begin() gelesen.
// Aenderung wirkt ab dem naechsten Neustart. Nur bekannte Standardraten werden akzeptiert.
uint32_t serialConsoleBaud();
bool     serialConsoleSetBaud(uint32_t baud);

// Woran Serial haengt (compile-time): USB-Serial/JTAG (Baudrate ohne Wirkung) oder UART0.
const char* serialConsoleInterfaceName();
bool        serialConsoleBaudMatters();

#endif // SERIAL_CONSOLE_H
