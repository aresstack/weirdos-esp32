<#
.SYNOPSIS
  Netzzonen Phase 0.3-0.5: liblwip.a mit Zielrouten-Hook, Forward-Hook, NAT-Entscheidung je Paar und
  DNAT-Antwort-Markierung bauen (P4, optional S3) -
  lokal auf Windows in Sekunden, ohne IDF-Fullbuild. Gleiches Prinzip wie build-lwip.ps1
  (Objekt-Tausch im Stock-Archiv), aber andere Objekte und KEIN Fenster-Patch.

.DESCRIPTION
  1. holt die exakten IDF-5.5.5-lwIP-Quellen (sparse Checkout, Cache in %LOCALAPPDATA%\Temp),
  2. patcht eine Kopie von ip4.c (NUR dieses Objekt wird getauscht):
       - ip4_route_src() + ip4_route(): rufen ZUERST weirdos_ip4_route_lookup(src, dest, &out) (schwach),
         Tri-State: NO_MATCH = weiter wie Stock, ROUTE = Tabellentreffer gewinnt vor on-link/ESP-Hook/Standardroute,
         BLOCK = sofort NULL ohne Rueckfall (fail-closed, z. B. Zonenroute auf einen Tunnel, der down ist),
       - ip4_forward(): ruft nach der Routingentscheidung (echtes inp + outp), VOR TTL/NAPT,
         weirdos_ip4_forward_allow(p, iphdr, inp, outp) (schwach); 0 = verwerfen,
       - ip4_forward() NAPT-Aufrufstelle: weirdos_ip4_nat_wanted(p, iphdr, inp, outp) (schwach) entscheidet je
         Paar, ob ip_napt_forward() laeuft (0.4: NAT = Eigenschaft der Policy, NAT-Domain = Eingangsinterface),
       - ip4_input(): nach ip_napt_recv() wird ein zurueckuebersetztes Ziel im pbuf markiert (0x80), damit
         der Forward-Hook NAT-Antworten zur Gegenrichtung der NAT-Policy durchlaesst (0.5),
       - Marker weirdos_lwip_route_hook_present / weirdos_lwip_forward_hook_present, damit der
         Sketch erkennen kann, ob das gepatchte Archiv gelinkt ist,
  3. kompiliert NUR diese eine .c mit dem installierten Arduino-Core-Compiler + dessen Flags/Includes,
  4. tauscht ip4.c.obj per 'ar r' in eine KOPIE des Stock-Archivs,
  5. gibt tools\liblwip-<target>-zones.a aus; -Install spielt es ein (Stock-Backup), -Revert rollt zurueck.
  Alle uebrigen Stock-.o bleiben unveraendert. Ohne Sketch-Symbole verhalten sich die Hooks wie Stock.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\build-lwip-zones.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\build-lwip-zones.ps1 -Install
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\build-lwip-zones.ps1 -Revert
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\build-lwip-zones.ps1 -Target s3 -Variant opi_opi
#>
[CmdletBinding()]
param(
  [ValidateSet('p4','s3')]
  [string] $Target      = 'p4',
  [string] $CoreVersion = '3.3.11',
  # WELCHES Libs-Paket der Linker wirklich nimmt, entscheidet boards.txt ueber build.chip_variant:
  #   esp32p4 (auch ChipVariant=prev3) -> chip_variant=esp32p4_es -> Paket esp32p4_es-libs  (NICHT esp32p4-libs!)
  # Beweis: Map-Datei des Builds (esp32-modem-host.ino.map) nennt den absoluten liblwip.a-Pfad.
  [string] $LibDir      = '',                          # leer = Vorgabe je Target (p4: esp32p4_es-libs, s3: esp32s3-libs)
  [string] $Variant     = '',                          # leer = Vorgabe je Target (p4: qio_qspi, s3: opi_opi)
  [string] $IdfCommit   = 'b774170ff46c393eeb5e495ea37936038d3f4f4f',   # ESP-IDF v5.5.5
  [string] $LwipSrc     = '',                          # vorhandener esp-idf-Sparse-Checkout; leer = Cache/Clone
  [string] $Opt         = '-Os',
  [string] $Out         = '',
  [string] $VerifyElf   = '',                          # nur pruefen: enthaelt diese Firmware-ELF die Marker? (kein Build)
  [switch] $Install,
  [switch] $Revert
)
$ErrorActionPreference = 'Stop'

$tools = Join-Path $env:LOCALAPPDATA 'Arduino15\packages\esp32\tools'
switch ($Target) {
  'p4' { if (-not $LibDir) { $LibDir = 'esp32p4_es-libs' }; $gccName = 'riscv32-esp-elf-gcc.exe';    $arName = 'riscv32-esp-elf-gcc-ar.exe';    $nmName = 'riscv32-esp-elf-nm.exe';    if (-not $Variant) { $Variant = 'qio_qspi' } }
  's3' { if (-not $LibDir) { $LibDir = 'esp32s3-libs' };    $gccName = 'xtensa-esp32s3-elf-gcc.exe'; $arName = 'xtensa-esp32s3-elf-gcc-ar.exe'; $nmName = 'xtensa-esp32s3-elf-nm.exe'; if (-not $Variant) { $Variant = 'opi_opi' } }
}
$LIB    = Join-Path $tools "$LibDir\$CoreVersion"
$stock  = Join-Path $LIB 'lib\liblwip.a'
$backup = "$stock.stock-bak"

$gccExe = Get-ChildItem -Path $tools -Recurse -Filter $gccName -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $gccExe) { throw "$gccName nicht gefunden unter $tools" }
$GCC = $gccExe.FullName
$AR  = Join-Path (Split-Path $GCC) $arName
$NM  = Join-Path (Split-Path $GCC) $nmName

# Marker-Pruefung: beide Praesenz-Symbole muessen DEFINIERT sein (Typ R/D/T), nicht nur referenziert.
function Test-Markers([string]$file, [string]$what) {
  $syms = & $NM $file 2>$null | Select-String 'weirdos_lwip_(route|forward)_hook_present'
  $defined = @($syms | Where-Object { $_.Line -match '\s[RDTrdt]\s+weirdos_lwip_' } | ForEach-Object { ($_.Line -split '\s+')[-1] } | Sort-Object -Unique)
  $ok = ($defined -contains 'weirdos_lwip_route_hook_present') -and ($defined -contains 'weirdos_lwip_forward_hook_present')
  if ($ok) { Write-Host "OK: $what enthaelt beide Marker (weirdos_lwip_route_hook_present, weirdos_lwip_forward_hook_present)." -ForegroundColor Green }
  else     { Write-Host "FEHLT: $what enthaelt die Marker NICHT (gefunden: $($defined -join ', '))." -ForegroundColor Red }
  return $ok
}

if ($VerifyElf) {
  if (-not (Test-Path $VerifyElf)) { throw "ELF fehlt: $VerifyElf" }
  $ok = Test-Markers $VerifyElf "Firmware-ELF $VerifyElf"
  $map = [IO.Path]::ChangeExtension($VerifyElf, '.map')
  if (Test-Path $map) {
    $libs = Select-String -Path $map -Pattern '[A-Za-z]:[^\s]*liblwip\.a' -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique
    Write-Host ("Gelinkte liblwip.a laut Map: " + ($libs -join '; '))
  }
  if (-not $ok) { exit 1 }
  return
}

if ($Revert) {
  if (-not (Test-Path $backup)) { throw "Kein Backup: $backup" }
  Copy-Item -Force $backup $stock
  Write-Host "OK: Stock-liblwip.a wiederhergestellt ($stock)." -ForegroundColor Green
  return
}
foreach ($p in @($GCC,$AR,$stock,"$LIB\flags\c_flags","$LIB\flags\defines","$LIB\flags\includes","$LIB\$Variant\include\sdkconfig.h")) {
  if (-not (Test-Path $p)) { throw "fehlt: $p" }
}
Write-Host "Target: $Target  GCC: $GCC"
Write-Host "Stock:  $stock"

# ---- 1) lwIP-Quellen (Cache) ----
if (-not $LwipSrc) {
  $LwipSrc = Join-Path $env:LOCALAPPDATA 'Temp\lwip-idf-5.5.5'
  if (-not (Test-Path (Join-Path $LwipSrc 'components\lwip\lwip\src\core\ipv4\ip4.c'))) {
    Write-Host "Hole IDF-5.5.5-lwIP-Quellen (sparse) nach $LwipSrc ..."
    & git clone --quiet --filter=blob:none --sparse https://github.com/espressif/esp-idf.git $LwipSrc
    Push-Location $LwipSrc
    & git sparse-checkout set components/lwip | Out-Null
    & git checkout --quiet $IdfCommit
    & git submodule update --init --depth 1 components/lwip/lwip
    Pop-Location
  }
}
$comp = Join-Path $LwipSrc 'components\lwip'
$ip4Src   = Join-Path $comp 'lwip\src\core\ipv4\ip4.c'
foreach ($p in @($ip4Src)) { if (-not (Test-Path $p)) { throw "lwIP-Quelle fehlt: $p" } }

$work = Join-Path $env:TEMP ("lwipzones-" + [Guid]::NewGuid().ToString('N'))
$srcDir = Join-Path $work 'src'; New-Item -ItemType Directory -Path $srcDir | Out-Null
$objDir = Join-Path $work 'obj'; New-Item -ItemType Directory -Path $objDir | Out-Null

function Patch-Once([string]$text, [string]$pattern, [string]$replacement, [string]$what) {
  $m = [regex]::Matches($text, $pattern)
  if ($m.Count -ne 1) { throw "Patch-Anker '$what' nicht eindeutig (Treffer: $($m.Count)) - Quelle passt nicht zu IDF $IdfCommit" }
  return [regex]::Replace($text, $pattern, $replacement, 1)
}

# ---- 2) ip4.c: Tri-State-Zielrouten-Lookup (fail-closed) in ip4_route_src() + ip4_route(),
#            Forward-Hook nach der Routingentscheidung, vor TTL/NAPT. NUR ip4.c wird getauscht;
#            Espressifs ip4_route_src_hook() (lwip_default_hooks.c) bleibt Stock.
$ip4 = [IO.File]::ReadAllText($ip4Src)
$decls = @"
#include <string.h>

/* WeirdOS Netzzonen 0.3 (schwache Symbole; fehlt das Sketch-Symbol, Stock-Verhalten):
 *   weirdos_ip4_route_lookup: 0 = NO_MATCH (weiter wie Stock), 1 = ROUTE (*out), 2 = BLOCK (sofort
 *   NULL, KEIN Rueckfall auf on-link/ESP-Hook/Standardroute -- fail-closed bei unbenutzbarem Ausgang).
 *   weirdos_ip4_forward_allow: 0 = verwerfen (nach Routingentscheidung, vor TTL/NAPT). */
extern int weirdos_ip4_route_lookup(const ip4_addr_t *src, const ip4_addr_t *dest, struct netif **out) __attribute__((weak));
extern int weirdos_ip4_forward_allow(struct pbuf *p, const struct ip_hdr *iphdr, struct netif *inp, struct netif *outp) __attribute__((weak));
/* 0.4/0.5: policy-bezogenes NAT -- entscheidet je (inp, outp), ob ip_napt_forward() gerufen wird
 * (1 = NAT wie Stock, 0 = reines Routing ohne Uebersetzung). ip_napt_forward() selbst uebersetzt nur,
 * wenn inp->napt gesetzt ist (NAT-Domain = natives Eingangsinterface). */
extern int weirdos_ip4_nat_wanted(struct pbuf *p, const struct ip_hdr *iphdr, struct netif *inp, struct netif *outp) __attribute__((weak));
/* 0.5: wird NUR gerufen, wenn ip_napt_forward() die Quelladresse wirklich geaendert hat (Zaehler natTranslated). */
extern void weirdos_ip4_nat_done(struct netif *inp, struct netif *outp) __attribute__((weak));
/* 0.5: ip4_input markiert Pakete, deren Ziel ip_napt_recv() zurueckuebersetzt hat (Antwort eines
 * NAT-Flusses); der Forward-Hook laesst sie zur Gegenrichtung der NAT-Policy durch. Freies pbuf-Flag-Bit. */
#define WEIRDOS_PBUF_FLAG_DNAT 0x80U
const int weirdos_lwip_route_hook_present = 1;
const int weirdos_lwip_forward_hook_present = 1;
#define WEIRDOS_ZONE_ROUTE_LOOKUP(src, dest)                                   \
  if (weirdos_ip4_route_lookup != NULL) {                                       \
    struct netif *weirdos_zn = NULL;                                            \
    int weirdos_rc = weirdos_ip4_route_lookup((src), (dest), &weirdos_zn);      \
    if (weirdos_rc == 2) { return NULL; }                                       \
    if (weirdos_rc == 1 && weirdos_zn != NULL) { return weirdos_zn; }           \
  }
"@
$ip4 = Patch-Once $ip4 '#include <string\.h>' ($decls -replace "`r?`n", "`r`n").TrimEnd() 'string.h-Include'
$routeSrc = @"
ip4_route_src(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  /* WeirdOS Netzzonen 0.3: Zielrouten-Tabelle zuerst, BLOCK ohne Rueckfall. */
  WEIRDOS_ZONE_ROUTE_LOOKUP(src, dest)
  if (src != NULL) {
"@
$ip4 = Patch-Once $ip4 'ip4_route_src\(const ip4_addr_t \*src, const ip4_addr_t \*dest\)\r?\n\{\r?\n  if \(src != NULL\) \{' ($routeSrc -replace "`r?`n", "`r`n").TrimEnd() 'ip4_route_src-Kopf'
$routeDst = @"
  /* WeirdOS Netzzonen 0.3: Zielrouten-Tabelle vor on-link/ESP-Hook/Standardroute, BLOCK ohne Rueckfall. */
  WEIRDOS_ZONE_ROUTE_LOOKUP(NULL, dest)

#if LWIP_MULTICAST_TX_OPTIONS
  /* Use administratively selected interface for multicast by default */
"@
$ip4 = Patch-Once $ip4 '#if LWIP_MULTICAST_TX_OPTIONS\r?\n  /\* Use administratively selected interface for multicast by default \*/' ($routeDst -replace "`r?`n", "`r`n").TrimEnd() 'ip4_route-Kopf'
$callFwd = @"
#endif /* IP_FORWARD_ALLOW_TX_ON_RX_NETIF */

  /* WeirdOS Netzzonen 0.3: Zonen-Filter mit echtem Eingangs- UND Ausgangsinterface, vor TTL/NAPT. */
  if (weirdos_ip4_forward_allow != NULL && !weirdos_ip4_forward_allow(p, iphdr, inp, netif)) {
    goto return_noroute;
  }
"@
$ip4 = Patch-Once $ip4 '#endif /\* IP_FORWARD_ALLOW_TX_ON_RX_NETIF \*/' ($callFwd -replace "`r?`n", "`r`n").TrimEnd() 'Forward-Hook-Einfuegestelle'
$natSite = @"
  if (!netif->napt && (weirdos_ip4_nat_wanted == NULL || weirdos_ip4_nat_wanted(p, iphdr, inp, netif))) {
    u32_t weirdos_src_before = iphdr->src.addr;   /* 0.5: nur eine TATSAECHLICHE Uebersetzung zaehlt */
    if (ip_napt_forward(p, iphdr, inp, netif) != ERR_OK)
      return;
    if (weirdos_ip4_nat_done != NULL && iphdr->src.addr != weirdos_src_before)
      weirdos_ip4_nat_done(inp, netif);
"@
$ip4 = Patch-Once $ip4 '  if \(!netif->napt\) \{\r?\n    if \(ip_napt_forward\(p, iphdr, inp, netif\) != ERR_OK\)\r?\n      return;' ($natSite -replace "`r?`n", "`r`n").TrimEnd() 'NAPT-Aufruf in ip4_forward'
$dnatSite = @"
  if (!inp->napt && ip4_addr_cmp(&iphdr->dest, netif_ip4_addr(inp))) {
    u32_t weirdos_dest_before = iphdr->dest.addr;   /* ip4_addr_p_t (gepackt) */
    ip_napt_recv(p, iphdr);
    if (iphdr->dest.addr != weirdos_dest_before) {
      p->flags |= WEIRDOS_PBUF_FLAG_DNAT;   /* Antwort eines NAT-Flusses: Ziel zurueckuebersetzt */
    }
  }
"@
$ip4 = Patch-Once $ip4 '  if \(!inp->napt && ip4_addr_cmp\(&iphdr->dest, netif_ip4_addr\(inp\)\)\)\r?\n    ip_napt_recv\(p, iphdr\);' ($dnatSite -replace "`r?`n", "`r`n").TrimEnd() 'ip_napt_recv-Aufruf in ip4_input'
[IO.File]::WriteAllText((Join-Path $srcDir 'ip4.c'), $ip4)
Write-Host "ip4.c gepatcht (Tri-State-Route-Lookup in ip4_route_src/ip4_route, Forward-Hook in ip4_forward)."

# ---- 3) kompilieren wie der Stock-Build (Core-Snapshot-Header, Komponenten-Defines) ----
$members = & $AR t $(if (Test-Path $backup) { $backup } else { $stock })
foreach ($m in @('ip4.c.obj')) { if ($members -notcontains $m) { throw "Member fehlt im Stock-Archiv: $m" } }
$incs = @("-I$LIB\$Variant\include", "-iprefix", "$LIB\include\", "@$LIB\flags\includes")
$lwipDefs = @('-DESP_LWIP_COMPONENT_BUILD', '-Wno-address')
$objs = @()
foreach ($c in @('ip4.c')) {
  $obj = Join-Path $objDir ($c + '.obj')
  Write-Host "  cc $c"
  & $GCC "@$LIB\flags\c_flags" "@$LIB\flags\defines" $Opt @incs @lwipDefs -c (Join-Path $srcDir $c) -o $obj
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $obj)) { throw "Compile fehlgeschlagen: $c" }
  $objs += $obj
}

# ---- 4) Objekte in eine Kopie des Stock-Archivs tauschen ----
if (-not $Out) { $Out = Join-Path (Split-Path $PSCommandPath) ("liblwip-" + $Target + "-zones.a") }
# Basis ist IMMER das unveraenderte Stock-Archiv: liegt schon ein Backup (fruehere -Install), ist
# lib\liblwip.a bereits gepatcht -> vom Backup ausgehen, sonst haetten alte Patch-Objekte Bestand.
$base = $stock
if (Test-Path $backup) { $base = $backup; Write-Host "Basis: Stock-Backup ($backup)" }
Copy-Item -Force $base $Out
& $AR r $Out @objs
if ($LASTEXITCODE -ne 0) { throw "ar r fehlgeschlagen" }
Write-Host "Fertig: $Out ($((Get-Item $Out).Length) B)" -ForegroundColor Green
if (-not (Test-Markers $Out "Patch-Archiv")) { throw "Objekttausch fehlgeschlagen: Marker fehlen im erzeugten Archiv" }

# ---- 5) optional einspielen (Erfolg erst nach Nachweis im installierten Archiv) ----
if ($Install) {
  if (-not (Test-Path $backup)) { Copy-Item -Force $stock $backup; Write-Host "Stock gesichert -> $backup" }
  Copy-Item -Force $Out $stock
  if (-not (Test-Markers $stock "installierte liblwip.a ($stock)")) { throw "Installation fehlgeschlagen: Marker fehlen nach dem Kopieren" }
  Write-Host "Eingespielt -> $stock" -ForegroundColor Green
  Write-Host "Der Linker nimmt dieses Paket nur, wenn boards.txt build.chip_variant darauf zeigt ($LibDir). Nachweis nach dem Build:"
  Write-Host "  build-lwip-zones.ps1 -VerifyElf <Build-Ordner>\esp32-modem-host.ino.elf   (prueft Marker + nennt die gelinkte liblwip.a aus der Map)"
  Write-Host "Auf dem Geraet: 'zones routes' -> 'Route-Hook vorhanden, Forward-Hook vorhanden'. Zurueck: -Revert"
} else {
  Write-Host "Zum Einspielen: build-lwip-zones.ps1 -Install   (sichert Stock, ersetzt liblwip.a, prueft Marker)"
}
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
