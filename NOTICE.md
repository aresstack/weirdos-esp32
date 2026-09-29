# NOTICE — Herkunft & Lizenzen

## Herkunft
WeirdOS ist eine Kopie des Arbeits-Sketches aus
`Miguel0888/quectel-ec200a-eu`, Unterordner `esp32-modem-host/`,
Stand Commit `2d4c4f28e4f3b00fd8ebbe943afa97fd61357038`.

Beim Herauslösen geändert:
- `esp32-modem-host.ino` → `weirdos-esp32.ino` (auf die Repo-Wurzel gelegt).
- Neue Dokumente: `README.md`, `DECOMPOSITION.md`, `docs/flash-and-heap.md`.
- Bisheriges `README.md` → `README.sketch.md` (Inhalt unverändert).

Der Quellcode selbst (`.ino`, `.cpp`, `.h`) ist bit-identisch übernommen.

## Vendored-Bibliotheken (unverändert, eigene Lizenzen)
- `src/WireGuard/` — WireGuard-ESP32 (siehe `src/WireGuard/UPSTREAM_LICENSE`,
  `VENDOR.md`); enthält Referenz-Krypto (BLAKE2s, ChaCha20-Poly1305, X25519).
- `src/weirdike/` — eigene IKEv2/IPsec-Implementierung ("WeirdIKE").
- `src/qrcode/` — QR-Encoder (ricmoo, MIT).

## Bewusst NICHT übernommen
Aus dem Quell-Repo wurde ausschließlich `esp32-modem-host/` übernommen. Die
übrigen Verzeichnisse (Reverse-Engineering, Treiber, Bootrom-Werkzeuge, Logs)
gehören nicht zu WeirdOS und bleiben im Quell-Repo.
