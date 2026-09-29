// ============================================================================
// web_ui_assets.cpp  --  Statische View-Daten (kein Code, nur PROGMEM-Assets)
//
// PAGE_STYLE (Basis-CSS, auch vom PIN-Gate/Handlern genutzt), APP_STYLE (CSS
// der App-Oberflaeche) und APP_SCRIPT (deren JavaScript). Bewusst als eigene
// "Daten-CPP" ausgelagert: laesst sich unabhaengig vom Code pflegen/flashen.
// Alle drei mit externer Bindung. WICHTIG: web_ui.h (mit den extern-Deklara-
// tionen) MUSS hier inkludiert sein - sonst haben die const-Arrays interne
// Bindung (C++-Default fuer const) und andere .cpp finden sie nicht (Linker:
// "undefined reference"). 'static' weglassen allein genuegt dafuer NICHT.
// ============================================================================
#include "web_ui.h"

const char PAGE_STYLE[] PROGMEM = R"CSS(<style>
*{box-sizing:border-box}
body{
  font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
  margin:0;padding:20px;background:#eceef1;color:#1c1f23;
}
main{
  max-width:480px;margin:0 auto;background:#fff;
  padding:22px;border-radius:10px;
  box-shadow:0 1px 3px rgba(0,0,0,.12);
}
h1{font-size:20px;margin:0 0 16px}
.info{
  margin-bottom:20px;line-height:1.7;font-size:14px;
  padding:12px;background:#f5f6f8;border-radius:6px;
}
.info div{display:flex;justify-content:space-between;gap:12px}
.info span:last-child{font-weight:600;text-align:right;word-break:break-all}
label{display:block;margin-top:16px;margin-bottom:6px;font-weight:600;font-size:14px}
input{
  width:100%;height:44px;padding:8px 10px;font-size:16px;
  border:1px solid #b9bfc7;border-radius:6px;background:#fff;
}
input:focus{outline:2px solid #2f6fd0;outline-offset:1px;border-color:#2f6fd0}
.ssid-wrap{position:relative}
.ssid-row{display:flex;width:100%;gap:6px;align-items:stretch}
.ssid-row input{flex:1;min-width:0}
.icon-button{
  flex:0 0 44px;width:44px;height:44px;margin:0;padding:0;
  border:1px solid #b9bfc7;border-radius:6px;background:#f5f6f8;
  font-size:17px;line-height:1;text-align:center;cursor:pointer;color:#1c1f23;
}
.icon-button:active{background:#e4e7ea}
.icon-button:disabled{opacity:.45;cursor:default}
.icon-button:focus-visible{outline:2px solid #2f6fd0;outline-offset:1px}
.ssid-list{
  position:absolute;z-index:10;left:0;right:0;top:calc(100% + 4px);
  margin:0;padding:0;list-style:none;max-height:260px;overflow-y:auto;
  background:#fff;border:1px solid #b9bfc7;border-radius:6px;
  box-shadow:0 6px 18px rgba(0,0,0,.16);
}
.ssid-list.hidden{display:none}
.ssid-list li{
  display:flex;justify-content:space-between;align-items:center;gap:10px;
  padding:11px 12px;border-bottom:1px solid #eceef1;cursor:pointer;font-size:15px;
}
.ssid-list li:last-child{border-bottom:none}
.ssid-list li:hover,.ssid-list li:focus{background:#eef4fd;outline:none}
.ssid-list li.empty{cursor:default;color:#6b7280;justify-content:center}
.ssid-list li.empty:hover{background:#fff}
.ssid-name{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ssid-meta{flex:0 0 auto;font-size:12px;color:#6b7280;font-variant-numeric:tabular-nums}
.field-wrap{position:relative;flex:1;min-width:0}
.field-wrap input{width:100%}
.has-inset{padding-right:44px}
.inset-button{
  position:absolute;right:4px;top:50%;transform:translateY(-50%);
  width:36px;height:36px;margin:0;padding:0;border:none;border-radius:6px;
  background:transparent;font-size:18px;line-height:1;text-align:center;
  cursor:pointer;color:#6b7280;
}
.inset-button:hover{background:#eef0f3}
.inset-button:focus-visible{outline:2px solid #2f6fd0;outline-offset:1px}
.inset-button.active{color:#2f6fd0}
.check-row{
  display:flex;gap:10px;align-items:flex-start;margin-top:16px;
  font-size:14px;font-weight:400;line-height:1.5;
}
.check-row input{width:18px;height:18px;margin:2px 0 0;flex:0 0 auto}
.danger-button{
  width:100%;margin-top:14px;padding:11px;font-size:14px;font-weight:600;
  border:1px solid #c8362b;border-radius:6px;background:#fff;color:#c8362b;
  cursor:pointer;
}
.danger-button:active{background:#fbeae8}
.connect-button{
  width:100%;margin-top:22px;padding:13px;font-size:16px;font-weight:600;
  border:none;border-radius:6px;background:#2f6fd0;color:#fff;cursor:pointer;
}
.connect-button:active{background:#255ab0}
.scan-status{min-height:18px;margin-top:6px;font-size:12px;color:#6b7280}
.status-link{margin:18px 0 0;font-size:13px}
.status-link a{color:#2f6fd0}
</style>)CSS";

const char APP_STYLE[] PROGMEM = R"CSS(<style>
.tabs{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:16px;
  border-bottom:1px solid #d7dbe0}
.tab{appearance:none;border:none;background:transparent;padding:10px 14px;
  font-size:14px;font-weight:600;color:#6b7280;cursor:pointer;
  border-bottom:2px solid transparent;margin-bottom:-1px}
.tab.active{color:#2f6fd0;border-bottom-color:#2f6fd0}
.tab-panel{display:none}
.tab-panel.active{display:block}
/* Seiten-Tabs (Level 3): obere Tabs pro Menuepunkt. Leiste nutzt .tabs/.tab. */
.page-sub{display:none}
.page-sub.active{display:block}
/* WireGuard: "Erweitert"-Aufklapper (native details/summary) */
.wg-adv{margin:10px 0;border:1px solid #d7dbe0;border-radius:6px;padding:6px 12px}
.wg-adv summary{cursor:pointer;font-weight:600;color:#6b7280;padding:4px 0}
/* VPN: prominenter Aktivieren-Schalter (FritzBox-Stil) */
.big-toggle{background:#eef4fd;border:1px solid #cfe0f7;border-radius:6px;padding:10px 12px;margin:8px 0}
/* FRITZ!OS-Kontextkopf (Bereichszeile ueber dem Seitentitel) */
.page-context{font-size:12px;font-weight:600;color:#6b7280;margin:0 0 4px;min-height:14px}
.page-context:empty{margin:0}
/* FRITZ!Box-artiges Layout: linke Sidebar + Inhaltsbereich rechts */
main.content{max-width:none;margin:0;flex:1;min-width:0}
.shell{display:flex;gap:16px;max-width:940px;margin:0 auto;align-items:flex-start}
.sidebar{flex:0 0 210px;background:#fff;border-radius:10px;
  box-shadow:0 1px 3px rgba(0,0,0,.12);padding:12px}
.brand{font-size:15px;font-weight:700;padding:6px 8px 12px;color:#1c1f23}
.brand-logo{display:block;width:100%;height:auto;max-width:240px}
.radio-row{display:flex;gap:16px;flex-wrap:wrap;margin:6px 0 10px}
.wiz-opt{display:flex;align-items:center;gap:6px;font-weight:500;margin:0;cursor:pointer}
.wiz-opt input{width:auto;height:auto;margin:0}
.wiz-opt.is-disabled{color:#9aa0a6;cursor:not-allowed}
/* Horizontale Optionsbuttons (IPsec-Trust-Modell) + Zertifikatsliste */
.opt-bar{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 10px}
.opt-btn{appearance:none;border:1px solid #d7dbe0;border-radius:6px;background:#fff;padding:8px 12px;
  font-size:13px;font-weight:600;color:#3b4046;cursor:pointer}
.opt-btn.active{border-color:#2f6fd0;background:#eef4fd;color:#2f6fd0}
.opt-btn.opt-warn.active{border-color:#c8362b;background:#fbeae8;color:#c8362b}
.hint{font-size:12px;color:#6b7280;margin:4px 0 8px;line-height:1.45}
.hint.warn,.cert-row .warn{color:#c8362b;font-weight:600}
.cert-list{display:flex;flex-direction:column;gap:6px;margin:6px 0}
.cert-row{display:flex;gap:8px;align-items:flex-start;border:1px solid #d7dbe0;border-radius:6px;padding:8px 10px;font-size:13px}
.cert-main{flex:1;min-width:0;word-break:break-word}
.cert-row .cert-anchor{margin-top:6px}
.cert-del{appearance:none;border:none;background:transparent;font-size:18px;color:#6b7280;cursor:pointer;padding:0 4px}
.cert-add-row{display:flex;gap:8px;align-items:center;margin:6px 0 10px;flex-wrap:wrap}
/* Formularbereich visuell "ausgegraut" (z.B. WLAN-Felder ohne Funk-Hardware/im Aus-Modus).
   BEWUSST kein HTML disabled=""-Attribut: disabled-Felder werden beim Submit NICHT mitgesendet
   -> ein Speichern wuerde SSID/Zielnetz-Haken sonst stillschweigend zuruecksetzen. */
.fields-inactive{opacity:.5;pointer-events:none}
.restart-banner{border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;border-radius:6px;margin:8px 0 14px;display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.side-nav{display:flex;flex-direction:column;gap:2px}
.nav-l1{appearance:none;border:none;background:transparent;text-align:left;
  padding:10px;font-size:14px;font-weight:600;color:#1c1f23;cursor:pointer;
  border-radius:6px;display:flex;justify-content:space-between;align-items:center}
.nav-l1:hover{background:#f2f4f7}
.caret{width:0;height:0;border:4px solid transparent;border-left-color:#9aa1a9;
  display:inline-block;transition:transform .15s;flex:0 0 auto}
.nav-l1.open .caret{transform:rotate(90deg)}
.nav-sub{list-style:none;margin:0 0 2px;padding:0;max-height:0;overflow:hidden;
  transition:max-height .18s ease}
.nav-sub.open{max-height:320px}
.nav-item{appearance:none;border:none;background:transparent;text-align:left;width:100%;
  padding:9px 10px 9px 22px;font-size:14px;color:#3a4048;cursor:pointer;border-radius:6px}
.nav-top{padding-left:10px;font-weight:600;color:#1c1f23}
/* Abmelden: eigenes Formular (POST /logout) unter dem Menue, optisch wie ein Hauptpunkt */
.nav-logout{margin-top:10px;border-top:1px solid #eceef1;padding-top:8px}
.nav-logout .nav-l1{width:100%;padding-left:10px;color:#b02a37}
.nav-item:hover{background:#f2f4f7}
.nav-item.active{background:#eef4fd;color:#2f6fd0;font-weight:600}
@media(max-width:640px){
  .shell{flex-direction:column}
  .sidebar{flex-basis:auto;width:100%}
  .nav-sub.open{max-height:none}
}
.live-wrap{cursor:zoom-in}
/* Echte Fullscreen-API (Desktop) - Bonus, falls verfuegbar. */
.live-wrap:fullscreen{background:#000;display:flex;align-items:center;
  justify-content:center;cursor:zoom-out}
.live-wrap:fullscreen img{width:100%;height:100%;object-fit:contain;border-radius:0}
/* CSS-Overlay-Vollbild: funktioniert ueberall (auch Portal-Browser/Mobil).
   object-fit:contain passt sich automatisch an Quer-/Hochformat an -
   drehst du das Handy quer, fuellt das Bild den Screen entsprechend. */
body.fs{overflow:hidden}
body.fs .live-wrap{position:fixed;inset:0;z-index:9999;background:#000;
  display:flex;align-items:center;justify-content:center;cursor:zoom-out;
  margin:0;border-radius:0}
body.fs .live-frame{width:100vw;height:100vh;max-width:100vw;max-height:100vh;
  object-fit:contain;border-radius:0;min-height:0}
.live-frame{width:100%;display:block;border-radius:6px;background:#1c1f23;min-height:180px}
.cam-bar{display:flex;justify-content:space-between;align-items:center;
  margin-top:10px;gap:10px;flex-wrap:wrap}
.cam-select{height:36px;padding:0 8px;font-size:14px;border:1px solid #b9bfc7;
  border-radius:6px;background:#fff}
.cfg-select{width:100%;height:44px}
.cam-status{font-size:13px;color:#6b7280;font-variant-numeric:tabular-nums}
.cam-button{padding:9px 16px;font-size:14px;font-weight:600;border:1px solid #b9bfc7;
  border-radius:6px;background:#f5f6f8;cursor:pointer}
.cam-hint{margin:8px 0 0;font-size:12px;color:#6b7280}
.section-title{font-size:16px;margin:24px 0 8px;padding-top:14px;
  border-top:1px solid #eceef1}
/* Titel + Aktions-Icon rechts in derselben Zeile (uiTitleWithAction) */
.section-title.has-action{display:flex;align-items:center;justify-content:space-between;gap:8px}
.icon-action{flex:0 0 30px;width:30px;height:30px;margin:0;padding:0;
  border:1px solid #b9bfc7;border-radius:6px;background:#f5f6f8;
  font-size:16px;line-height:1;text-align:center;cursor:pointer;color:#1c1f23}
.access-table{width:100%;border-collapse:collapse;margin:6px 0}
.access-table th,.access-table td{text-align:left;padding:6px 8px;border-bottom:1px solid #e5e7eb;font-size:14px}
.access-table th:not(:first-child),.access-table td:not(:first-child){text-align:center;width:90px}
.access-table small{color:#6b7280}
.combo-row{display:flex;align-items:center;gap:6px;margin:6px 0}
.combo-row .connect-button{flex:1 1 0;margin:0}
.id-verb{flex:0 0 auto;color:#6b7280;font-size:13px;white-space:nowrap}
.id-type{flex:0 0 46%;min-width:0}
.id-value{flex:1 1 0;min-width:0;margin:0}
.id-value:disabled{opacity:.5}
.combo{position:relative;flex:1 1 auto;display:flex;min-width:0}
.combo input{flex:1 1 auto;min-width:0;padding-right:32px;margin:0}
.combo-toggle{position:absolute;right:0;top:0;bottom:0;width:30px;border:0;background:transparent;cursor:pointer;color:#6b7280;font-size:14px}
.combo-toggle:hover{color:#1c1f23}
.combo-list{position:absolute;left:0;right:0;top:100%;z-index:30;background:#fff;border:1px solid #d7dbe0;border-radius:6px;
  max-height:180px;overflow:auto;box-shadow:0 4px 12px rgba(0,0,0,.12);margin-top:2px}
.combo-item{padding:8px 10px;cursor:pointer;font-size:14px}
.combo-item.sel,.combo-item:hover{background:#e9ecef}
.combo-empty{padding:8px 10px;color:#6b7280;font-size:13px}
.icon-action:hover{background:#e9ecef}
.icon-action:active{background:#e4e7ea}
.icon-action:disabled{opacity:.45;cursor:default}
.icon-action.busy{animation:ui-spin 1s linear infinite}
@keyframes ui-spin{to{transform:rotate(360deg)}}
/* Wertepaar "aktuell / max": gleiche Schrift wie der Rest, Ziffern in Tabellenbreite (jede Ziffer
   gleich breit) + feste Mindestbreite je Zahl -> Komma und "/" bleiben an Ort und Stelle */
.om-pair{font-variant-numeric:tabular-nums;white-space:nowrap}
.om-pair .om-num{display:inline-block;min-width:6ch;text-align:right}
.slider-row{display:flex;justify-content:space-between;align-items:center;
  margin-top:16px;margin-bottom:4px;font-weight:600;font-size:14px}
.slider-value{font-weight:700;color:#2f6fd0;font-variant-numeric:tabular-nums}
.slider{width:100%;height:32px}
</style>)CSS";

const char APP_SCRIPT[] PROGMEM = R"JS(<script>
(function(){
// ---- Sidebar-Navigation (FRITZ!Box-artig) ----
var navItems=document.querySelectorAll('.nav-item');
var panels=document.querySelectorAll('.tab-panel');
// Section rein VISUELL aktivieren (kein Hash-Schreiben) -- von Klick UND Hash-Restore genutzt.
function activateNav(t){
  navItems.forEach(function(x){x.classList.remove('active');});
  panels.forEach(function(x){x.classList.remove('active');});
  t.classList.add('active');
  var p=document.getElementById('tab-'+t.dataset.tab);
  if(p){p.classList.add('active');
    // Unterpunkt mit data-psub (z.B. Kamera->Livebild/Bild/Stream): das
    // passende page-sub im Panel aktivieren, so wie es frueher die In-Panel-Tabs taten.
    if(t.dataset.psub){
      p.querySelectorAll('.page-sub').forEach(function(x){x.classList.remove('active');});
      var ps=p.querySelector('#psub-'+t.dataset.psub);
      if(ps)ps.classList.add('active');
      // Falls die Seite eine In-Page-Tab-Leiste hat (z.B. VPN: WireGuard/IPsec), den
      // passenden Tab mit-highlighten, damit Sidebar-Auswahl und Tab-Bar synchron sind.
      p.querySelectorAll('.tab').forEach(function(x){x.classList.toggle('active',x.dataset.psub===t.dataset.psub);});
    }
  }
  // FRITZ!OS-Kontextzeile aus der Sidebar-Gruppe (leer bei Top-Level)
  var ctxEl=document.getElementById('ctxbar');
  if(ctxEl){var sub=t.closest('.nav-sub');var l1=sub?sub.previousElementSibling:null;
    ctxEl.textContent=l1?l1.textContent.trim():'';}
  // Beim Restore aus dem Hash die evtl. eingeklappte Elterngruppe aufklappen.
  var grp=t.closest('.nav-sub');
  if(grp){grp.classList.add('open');var l1o=grp.previousElementSibling;if(l1o)l1o.classList.add('open');}
  firePageShown();
}
// URL-State: Schluessel eines Menuepunkts ("tab" bzw. "tab/psub") -> /?p=<key>
function navKey(t){return t.dataset.tab+(t.dataset.psub?'/'+t.dataset.psub:'');}
navItems.forEach(function(t){
  t.addEventListener('click',function(){
    // Seiten-Navigation: der Server rendert je Aufruf NUR die angeforderte Seite (Heap/Sockets, LTE).
    // Liegt die Section schon im DOM (gleicher Renderer, anderer Unterpunkt), nur umschalten.
    if(document.getElementById('tab-'+t.dataset.tab)){
      activateNav(t);
      try{history.replaceState(null,'','/?p='+navKey(t));}catch(e){}
    } else location.href='/?p='+navKey(t);
  });
});
// Aufklappbare Untermenues (Level 2)
var groups=document.querySelectorAll('.nav-l1.has-sub');
groups.forEach(function(l1){
  l1.addEventListener('click',function(){
    var sub=document.getElementById(l1.dataset.group);
    l1.classList.toggle('open');
    if(sub)sub.classList.toggle('open');
  });
});
// Seiten-Tabs (Level 3): obere Tabs, pro Seite (.tab-panel) gescoped
document.querySelectorAll('.tabs').forEach(function(bar){
  var ptabs=bar.querySelectorAll('.tab');
  var page=bar.closest('.tab-panel');
  ptabs.forEach(function(pt){
    pt.addEventListener('click',function(){
      ptabs.forEach(function(x){x.classList.remove('active');});
      if(page)page.querySelectorAll('.page-sub').forEach(function(x){x.classList.remove('active');});
      pt.classList.add('active');
      var sub=page?page.querySelector('#psub-'+pt.dataset.psub):null;
      if(sub)sub.classList.add('active');
      firePageShown();
    });
  });
});

// ---- Seiten-Routing (?p=tab[/psub]) ----
// Der Server liefert pro Aufruf genau die Seite aus ?p=; hier wird der passende Menuepunkt
// aktiviert (Section sichtbar, Elterngruppe auf, Kontextzeile). Alte Hash-Lesezeichen (#/video/live)
// werden auf die neue URL umgeleitet. Alias-Tabelle identisch zu uiPageFor() im Server.
function navByKey(h){
  if(!h) return null;
  var parts=h.split('/'), tab=parts[0], psub=parts[1];
  var alias={zugang:'mobilfunk',wanport:'mobilfunk',diagfunc:'diagsys',events:'diagsys',diagheap:'diagsys',diagspeed:'diagusb',diagwlan:'diagnet'};
  if(alias[tab])tab=alias[tab];
  var list=document.querySelectorAll('.nav-item[data-tab="'+tab+'"]');
  if(psub){for(var i=0;i<list.length;i++){if(list[i].dataset.psub===psub)return list[i];}}
  return list[0]||null;   // Section-Fallback (erster Menuepunkt dieser Section)
}
function routeFromUrl(){
  var h=(location.hash||'').replace(/^#\/?/,'');
  if(h){location.replace('/?p='+h);return;}
  var m=/[?&]p=([^&#]*)/.exec(location.search||'');
  var t=null;
  try{t=navByKey(m?decodeURIComponent(m[1]):'');}catch(e){t=null;}
  if(!t||!document.getElementById('tab-'+t.dataset.tab)){
    // unbekannt/leer: den Menuepunkt der Section nehmen, die der Server tatsaechlich geliefert hat
    var sec=document.querySelector('.tab-panel');
    t=sec?document.querySelector('.nav-item[data-tab="'+sec.id.replace(/^tab-/,'')+'"]'):null;
  }
  if(!t)t=navItems[0];
  if(t)activateNav(t);
}
// Links innerhalb der Seiten (href='#/tab') -> Seitenwechsel ueber den Server
document.addEventListener('click',function(e){
  var a=(e.target&&e.target.closest)?e.target.closest('a[href^="#/"]'):null;
  if(a){e.preventDefault();location.href='/?p='+a.getAttribute('href').slice(2);}
});
// Initial-Restore ANS ENDE (via setTimeout 0): erst NACH der restlichen Init dieses Scripts
// (v.a. der Video-/Stream-Setup weiter unten). try/catch: eine kaputte URL bricht die Seite nie.
setTimeout(function(){try{routeFromUrl();}catch(e){}},0);

// ---- Passwort/PIN Augen ----
function eye(btnId,inpId){
  var b=document.getElementById(btnId),i=document.getElementById(inpId);
  if(!b||!i)return;
  b.addEventListener('click',function(){
    var sh=i.type==='password';i.type=sh?'text':'password';
    b.classList.toggle('active',sh);i.focus();
  });
}
eye('pw-eye','password');
eye('np-eye','newpin');
// ---- Geheimnis-Felder (writeSecretField, ein Element fuer PSK/Passwoerter/Schluessel) ----
// Das Auge zeigt nur die EIGENE Eingabe; der gespeicherte Wert kommt nie vom Geraet. Nach erfolgreichem
// Speichern setzt secretSaved() die Punkte/Laenge auf den neuen Wert und leert das Feld.
document.querySelectorAll('button.secret-eye').forEach(function(b){
  var i=document.getElementById(b.getAttribute('data-for'));if(!i)return;
  b.addEventListener('click',function(){var sh=i.type==='password';i.type=sh?'text':'password';
    b.classList.toggle('active',sh);b.setAttribute('aria-pressed',sh?'true':'false');i.focus();});
});
function secretSaved(id){
  var i=document.getElementById(id);if(!i)return;var n=i.value.length;
  if(n>0){var d='';for(var k=0;k<Math.min(n,48);k++)d+='•';i.placeholder=d;i.setAttribute('data-set','1');i.setAttribute('data-len',n);
    var h=document.querySelector('.secret-hint[data-for="'+id+'"]');if(h)h.textContent='gesetzt ('+n+' Zeichen) – leer lassen zum Behalten, neue Eingabe ersetzt';}
  i.value='';i.type='password';
  var b=document.querySelector('button.secret-eye[data-for="'+id+'"]');if(b){b.classList.remove('active');b.setAttribute('aria-pressed','false');}
}

// ================== Gemeinsame Basis (gilt auf JEDER Seite) ==================
// Der Server rendert seit dem Einzelseiten-Umbau je Aufruf NUR EINE Seite; die Elemente ALLER
// anderen Seiten fehlen dann im DOM. Alles ab hier ist deshalb in Seiten-Module aufgeteilt, die
// mit einem Wurzel-Guard beginnen und zurueckkehren, wenn "ihre" Seite nicht geliefert wurde.
// NUR was in diesem Abschnitt steht, laeuft seitenuebergreifend und muss ohne jedes Seiten-
// Element auskommen (sonst bricht das ganze Script und KEIN Modul darunter wird mehr init'd).

// Seitenwechsel INNERHALB des DOMs (gleicher Renderer, anderer Unterpunkt -- z.B. Diagnose
// System/USB/Netz/Video). Module, die darauf reagieren muessen, melden sich mit onPageShown() an;
// ein Fehler in einem Modul darf die uebrigen nicht mitreissen.
var pageHooks=[];
function onPageShown(fn){pageHooks.push(fn);}
function firePageShown(){pageHooks.forEach(function(f){try{f();}catch(e){}});}

// Abgelaufene Session (z.B. nach Reboot: Session-Token liegt im RAM, altes Cookie matcht nicht
// mehr) -> authentifizierte Endpunkte liefern 401 (/dev-Guard) oder 403 (Modem-/Status-Handler).
// Statt still/irrefuehrend zu scheitern ("Abfrage fehlgeschlagen") neu laden: GET / rendert die PIN-Gate.
function on401(r){if(r.status===401||r.status===403){location.reload();throw new Error('auth');}return r;}
// Datenraten einheitlich formatieren (Modem-Status, Speedtest, Einzelstream-Test).
function fmtKbit(k){if(k==null)return '-';if(k>=1000)return (k/1000).toFixed(1)+' Mbit/s';return k+' kbit/s';}
// Kamera-Rueckmeldung. Die Statuszeile des Livebilds (#cam-status) steht auf Diagnose > Video, die
// sofort wirkenden Einstellungen (Qualitaet/Bildrate/Puffer) auf Server > Video -- seit dem
// Einzelseiten-Rendering nie zusammen im DOM. Deshalb erst die Statuszeile, sonst die Meldungszeile
// der Einstellungsseite; ist keine da, geht die Meldung verloren statt das Script zu brechen.
function camStatus(t){var e=document.getElementById('cam-status')||document.getElementById('cam-cfg-msg');if(e)e.textContent=t;}

// ================== Seiten-Module ==================

// ---- Livebild (Diagnose > Video): MJPEG-Stream / Einzelbilder / H.264 ----
// Wurzel-Guard: das Livebild steht NUR auf Diagnose > Video (renderVideoLive). Auf jeder anderen
// Seite fehlen <img id='live'> & Co. komplett -- ohne diesen Guard griff das Modul frueher ins
// Leere (pauseButton.addEventListener auf null) und riss das GESAMTE Script mit sich.
(function(){
var img=document.getElementById('live');
if(!img)return;
var wrap=document.getElementById('live-wrap');
var statusEl=document.getElementById('cam-status');
var pauseButton=document.getElementById('pause-button');
var sizeSelect=document.getElementById('size-select');
var codecSelect=document.getElementById('codec-select');
var modeSelect=document.getElementById('mode-select');
var _sp=img?img.getAttribute('data-streamport'):'';
var _spath=img?img.getAttribute('data-streampath'):'';
var streamUrl='http://'+location.hostname+':'+(_sp||'81')+(_spath||'/stream');
var _sk=img?img.getAttribute('data-streamkey'):'';
if(_sk)streamUrl+='?key='+encodeURIComponent(_sk);   // sonst 403 bei gesetztem Stream-Schluessel
var mode='stream',paused=false,frames=0,windowStart=Date.now(),snapTimer=null,streamRetries=0;

function stopSnapshots(){if(snapTimer){clearTimeout(snapTimer);snapTimer=null;}}
function schedule(ms){snapTimer=setTimeout(refresh,ms);}
function refresh(){
  if(mode!=='snap'){return;}
  if(paused){schedule(300);return;}
  var n=new Image();
  n.onload=function(){
    img.src=n.src;frames++;
    var el=Date.now()-windowStart;
    if(el>=2000){statusEl.textContent=(frames*1000/el).toFixed(1)+' fps';frames=0;windowStart=Date.now();}
    schedule(120);
  };
  n.onerror=function(){statusEl.textContent='Kein Bild von der Kamera.';schedule(2000);};
  n.src='/capture?t='+Date.now();
}
var streamRetryTimer=null;
function stopStreamRetry(){if(streamRetryTimer){clearTimeout(streamRetryTimer);streamRetryTimer=null;}}
function startStream(){
  stopSnapshots();stopStreamRetry();
  // KEIN Fallback auf Einzelbilder (das ueberschrieb frueher auf dem Handy die Auswahl).
  // Stattdessen AUTO-RECONNECT: bricht der Stream ab (z.B. ESP-Reboot/Flash, mobiler
  // Reconnect), nach kurzer Pause neu verbinden. Nach einem Reboot ist der alte 1-Client-
  // Slot ohnehin weg -> kein Doppelbelegungs-503; und img.src neu zu setzen schliesst den
  // alten Request DIESES <img>. Solange "Stream" gewaehlt und nicht pausiert.
  img.onerror=function(){
    if(mode!=='stream'||paused)return;
    statusEl.textContent='Verbindung verloren - neuer Versuch ...';
    stopStreamRetry();
    streamRetryTimer=setTimeout(function(){if(mode==='stream'&&!paused)startStream();},4000);
  };
  img.src=streamUrl+(streamUrl.indexOf('?')>=0?'&':'?')+'t='+Date.now();
  statusEl.textContent='MJPEG-Stream aktiv';
}
function stopStream(){stopStreamRetry();img.onerror=null;img.src='';}
function applyMode(){
  mode=modeSelect.value;paused=false;pauseButton.textContent='Pause';
  if(mode==='stream'){streamRetries=0;startStream();}
  else{stopStream();frames=0;windowStart=Date.now();statusEl.textContent='Lade ...';refresh();}
}
if(pauseButton)pauseButton.addEventListener('click',function(){
  paused=!paused;pauseButton.textContent=paused?'Fortsetzen':'Pause';
  if(mode==='stream'){if(paused){stopStream();statusEl.textContent='Pausiert';}else{startStream();}return;}
  if(paused)statusEl.textContent='Pausiert';
});
if(wrap)wrap.addEventListener('click',function(){
  // Umschalten eines CSS-Overlays statt der Fullscreen-API: Letztere ist
  // in vielen mobilen Browsern und im Captive-Portal-Browser des AP
  // gesperrt (kein sicherer Kontext / kein HTTPS). Das Overlay legt das
  // Bild formatfuellend ueber die ganze Seite und funktioniert ueberall.
  var on=document.body.classList.toggle('fs');
  // Wo verfuegbar, zusaetzlich die echte Fullscreen-API nutzen (Desktop) -
  // Fehler werden ignoriert, das Overlay traegt den Effekt ohnehin.
  try{
    if(on){
      if(wrap.requestFullscreen)wrap.requestFullscreen();
      else if(wrap.webkitRequestFullscreen)wrap.webkitRequestFullscreen();
    }else{
      if(document.fullscreenElement&&document.exitFullscreen)document.exitFullscreen();
      else if(document.webkitFullscreenElement&&document.webkitExitFullscreen)document.webkitExitFullscreen();
    }
  }catch(e){}
});
document.addEventListener('fullscreenchange',function(){
  if(!document.fullscreenElement)document.body.classList.remove('fs');
});
// Aufloesungen dynamisch aus den Backend-Capabilities (/dev/camera0). Kein festes
// Table, kein Boardwissen im JS. Dedup nach w×h -- Pixelformate/fps gehoeren NICHT in die
// Aufloesungswahl; fps=0 = unbekannt -> nie anzeigen (kein "@0 fps").
var camModes=[],camCur='',h264Res=[],codecInit=true;
// EIN Aufloesungs-Dropdown fuer beide Codecs. MJPEG: die Kamera-Aufnahme-Modi. H.264: die
// Ausgabe-Groessen -- ALLE gelistet, die nicht in den internen Heap passenden ausgegraut (disabled).
function fillSizeForCodec(){
  if(!sizeSelect)return;
  var opts='';
  if(codecSelect&&codecSelect.value==='h264'){
    var firstAvail='';
    h264Res.forEach(function(r){
      var key=r.w+'x'+r.h;
      if(r.available&&!firstAvail)firstAvail=key;
      // Grund fuers Ausgrauen ehrlich benennen: Sensor (KEIN Kamera-Modus deckt die Groesse ab; den
      // passenden Modus schaltet der Stream-Start sonst selbst) vs. Heap (Referenzpuffer passt nicht).
      var why=r.available?'':(r.reason==='sensor'?' (Sensor zu klein)':' (Heap)');
      opts+='<option value="'+key+'"'+(r.available?'':' disabled')+'>'+r.w+'×'+r.h+why+'</option>';
    });
    sizeSelect.innerHTML=opts; sizeSelect.disabled=false;
    if(firstAvail)sizeSelect.value=firstAvail;   // erste passende vorwaehlen (hoechste, die geht)
  }else{
    camModes.forEach(function(m){var key=m.w+'x'+m.h;
      opts+='<option value="'+key+'"'+(key===camCur?' selected':'')+'>'+m.w+'×'+m.h+'</option>';});
    sizeSelect.innerHTML=opts; sizeSelect.disabled=(sizeSelect.options.length<=1);
  }
}
function loadSizes(){
  if(!sizeSelect)return;
  // Generisch aus dem Geraete-Namespace: /dev/camera0 -> Capability-Descriptor (Modi, current).
  fetch('/dev/camera0',{cache:'no-store'}).then(on401).then(function(r){return r.json();})
    .then(function(d){
      if(!d)return;
      camModes=d.modes||[]; camCur=d.current?(d.current.w+'x'+d.current.h):''; h264Res=d.h264res||[];
      // Codec-Dropdown aus d.codecs[]: nur HW-unterstuetzte waehlbar, Rest ausgegraut (disabled).
      // "active" markiert den Codec, der aktuell den Stream liefert. So sieht man ehrlich, was die
      // Hardware kann (H.264 am P4 verfuegbar, H.265/AV1 nicht) -- ohne zu behaupten, es liefe schon.
      var codecChanged=false;
      if(codecSelect&&d.codecs&&d.codecs.length){
        // Server liefert die Codecs in RANGFOLGE (bester zuerst). Default = der gerade aktive Stream,
        // sonst der erste verfuegbare -> "beste verfuegbare Version" ohne Nutzeraktion. Nur beim
        // ersten Laden umschalten, nicht bei spaeteren Refreshes (Nutzerwahl respektieren).
        var cop='',best='',active='',prev=codecSelect.value;
        d.codecs.forEach(function(c){
          if(c.available&&!best)best=c.id;
          if(c.available&&c.active)active=c.id;
          cop+='<option value="'+c.id+'"'+(c.available?'':' disabled')+'>'+c.label+(c.available?'':' - keine HW')+'</option>';
        });
        codecSelect.innerHTML=cop;
        var want=active||(prev&&!codecInit?prev:best)||best;
        if(want){codecSelect.value=want;codecChanged=(want!==prev);}
        codecInit=false;
      } else if(codecSelect){ codecSelect.style.display='none'; }
      fillSizeForCodec();   // das eine Aufloesungs-Dropdown passend zum (Start-)Codec befuellen
      if(codecChanged)applyCodec();   // Default-Codec (z.B. H.264) wirklich starten
      // Quality nur anbieten, wo das Backend sie wirklich setzt (S3). Am P4 (qualitySettable=false)
      // die ganze Quality-Zeile ausblenden -> kein Schein-Regler.
      if(d.qualitySettable===false){
        var qr=document.getElementById('quality-row'); if(qr)qr.style.display='none';
        var qsl=document.getElementById('quality-slider'); if(qsl)qsl.disabled=true;
      }
    }).catch(function(){});
}
loadSizes();
if(sizeSelect)sizeSelect.addEventListener('change',function(){
  // H.264: Aufloesungswahl -> Stream mit neuer Groesse neu starten (ausgegraute sind nicht waehlbar).
  if(codecSelect&&codecSelect.value==='h264'){ stopH264(); startH264(); return; }
  if(sizeSelect.options.length<=1)return;
  var v=sizeSelect.value.split('x');
  statusEl.textContent='Stelle Aufloesung um ...';frames=0;windowStart=Date.now();
  // Eine Kamera-Resource: PATCH /dev/camera0 {mode:{width,height}} (kein /dev/camera0/mode mehr).
  fetch('/dev/camera0',{method:'PATCH',cache:'no-store',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({mode:{width:parseInt(v[0],10),height:parseInt(v[1],10)}})})
    .then(on401).then(function(r){return r.json();})
    .then(function(d){if(!d.ok){statusEl.textContent=d.error||'Fehler.';return;}
      // KEIN startStream(): der laufende MJPEG-Stream liefert die neue Aufloesung nahtlos
      // weiter (jeder Multipart-Part hat sein eigenes Content-Length). Ein Reconnect wuerde
      // den 1-Client-Slot doppelt belegen -> 503 "bereits belegt" -> schwarzer Screen.
      statusEl.textContent=(mode==='stream')?'MJPEG-Stream aktiv':'Aufloesung gesetzt';
      loadSizes();   // Descriptor neu: aktueller Kamera-Modus + H.264-Verfuegbarkeit (sonst veraltete Ausgrauung)
    })
    .catch(function(){statusEl.textContent='Fehler.';});
});
if(modeSelect)modeSelect.addEventListener('change',applyMode);

// ---- H.264-Wiedergabe im Browser: fMP4 (/video.mp4) via Media Source Extensions ----
// H.264 laeuft NICHT als <img>. MSE ist nativ in Firefox/Edge/Chrome (kein Plugin). Wir lesen den
// fMP4-Stream (Init-Segment + Media-Segmente) haeppchenweise und schieben sie in ein SourceBuffer.
var vid=document.getElementById('live-video');
var h264Base='http://'+location.hostname+':'+(_sp||'81')+'/video.mp4';
var ms264=null,sb264=null,reader264=null,segQ=[],h264On=false,h264StatTimer=null;
function h264ResValue(){ return (codecSelect&&codecSelect.value==='h264'&&sizeSelect)?sizeSelect.value:''; }
function h264StreamUrl(){
  var u=h264Base, sep='?';
  if(_sk){ u+='?key='+encodeURIComponent(_sk); sep='&'; }
  var rv=h264ResValue();
  if(rv){ var p=rv.split('x'); if(p.length===2) u+=sep+'w='+p[0]+'&h='+p[1]; }
  return u;
}
function sbFlush(){ if(!sb264||sb264.updating||!segQ.length)return; try{sb264.appendBuffer(segQ.shift());}catch(e){} }
// Live-Edge: NICHT hart seeken (ein Sprung landet mitten in der GOP auf einem P-Frame -> der Decoder
// hat keine gueltige Referenz -> wandernde lila Artefakte bis zum naechsten Keyframe). Stattdessen
// SANFT aufholen: bei Rueckstand kurz schneller abspielen (alle Frames der Reihe nach -> keine
// Referenz-Korruption). Nur ein harter Seek, wenn wir GROB (>4 s) hinterherhaengen (echter Stall).
function liveEdge(){
  try{ if(!vid.buffered.length)return;
    var end=vid.buffered.end(vid.buffered.length-1);
    var behind=end-vid.currentTime;
    // Ziel: <=0,3 s hinter dem Live-Ende. KEIN harter Seek mehr: ein Sprung mitten in die GOP laesst den
    // Decoder P-Frames ohne gueltige Referenz dekodieren -> rosa/lila Drift bis zum naechsten Keyframe,
    // sporadisch bei jedem Stall (LTE-Hickser). Stattdessen nur schneller abspielen; erst ein ECHTER
    // Stall (>6 s Rueckstand) startet den Stream neu (frisches Init-Segment + IDR, sauberer Einstieg).
    if(behind>6){ stopH264(); startH264(); return; }
    else if(behind>1.5) vid.playbackRate=2.0;                          // weit hinten -> schnell aufholen
    else if(behind>0.6) vid.playbackRate=1.5;                          // deutlich hinten -> zuegig aufholen
    else if(behind>0.3) vid.playbackRate=1.2;                          // leicht hinten -> sanft aufholen
    else if(behind<0.2) vid.playbackRate=1.0;                          // am Live-Ende -> normal
    var start=vid.buffered.start(0);
    if(sb264&&!sb264.updating&&vid.currentTime-start>4) sb264.remove(start,vid.currentTime-2);
  }catch(e){}
}
function startH264(){
  if(!('MediaSource'in window)){statusEl.textContent='Dieser Browser kann kein MSE -> H.264 nicht abspielbar.';return;}
  stopStream();stopSnapshots();
  h264On=true; img.style.display='none'; vid.style.display='';
  try{ vid.playbackRate=1.0; }catch(e){}   // Rate der vorigen Sitzung (1,2/1,5/2,0) nicht mitnehmen
  var resTxt=h264ResValue()?(' '+h264ResValue()):'';
  statusEl.textContent='H.264'+resTxt+' verbindet ...';
  ms264=new MediaSource();
  vid.src=URL.createObjectURL(ms264);
  ms264.addEventListener('sourceopen',function(){
    try{ sb264=ms264.addSourceBuffer('video/mp4; codecs="avc1.42E01E"'); }   // Constrained Baseline 3.0
    catch(e){ statusEl.textContent='H.264-Codec vom Browser abgelehnt.'; return; }
    sb264.addEventListener('updateend',function(){ sbFlush(); liveEdge(); });
    fetch(h264StreamUrl(),{cache:'no-store'}).then(function(resp){
      if(!resp.ok){ resp.text().then(function(t){ statusEl.textContent='H.264 '+resp.status+': '+(t||''); }).catch(function(){ statusEl.textContent='H.264-Stream '+resp.status; }); return; }
      statusEl.textContent='H.264'+resTxt+'-Stream aktiv';
      // Live-Statistik (fps / kbit/s / ausgelassene Frames) aus /dev/camera0 alle 2 s in die Statuszeile.
      if(h264StatTimer)clearInterval(h264StatTimer);
      h264StatTimer=setInterval(function(){
        if(!h264On)return;
        fetch('/dev/camera0?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();}).then(function(d){
          var s=d&&d.h264stat; if(!s||!h264On)return;
          statusEl.textContent='H.264'+resTxt+' aktiv - '+s.fps+' fps, '+(s.kbit/1000).toFixed(1)+' Mbit/s'
            +(s.dropstale?(s.skips?(' ('+s.skips+' Frames/s wegen Bandbreite ausgelassen)'):''):' (keine Bandbreiten-Anpassung)');
        }).catch(function(){});
      },2000);
      reader264=resp.body.getReader();
      (function pump(){
        if(!h264On)return;
        reader264.read().then(function(r){
          if(r.done||!h264On)return;
          segQ.push(r.value); sbFlush(); pump();
        }).catch(function(){});
      })();
    }).catch(function(){ statusEl.textContent='H.264-Verbindung fehlgeschlagen.'; });
  });
  vid.play().catch(function(){});
}
function stopH264(){
  h264On=false;
  if(h264StatTimer){clearInterval(h264StatTimer);h264StatTimer=null;}
  if(reader264){try{reader264.cancel();}catch(e){} reader264=null;}
  segQ=[]; sb264=null;
  if(ms264){try{if(ms264.readyState==='open')ms264.endOfStream();}catch(e){}} ms264=null;
  try{vid.pause();vid.removeAttribute('src');vid.load();}catch(e){}
  vid.style.display='none'; img.style.display='';
}
// Codec anwenden: EIN Pfad fuer Nutzerwahl, Default-Wahl beim Laden und Sichtbarkeitswechsel.
// H.264: MSE-Player (Modus-Dropdown gesperrt); MJPEG/Einzelbilder: <img>-Pfad (mode-select gilt).
// Laeuft nur, wenn die Seite sichtbar ist -- sonst alles stoppen (spart Kamera/CPU/Uplink).
function applyCodec(){
  var h=(codecSelect&&codecSelect.value==='h264');
  if(modeSelect)modeSelect.disabled=h;
  if(!videoVisible()){stopStream();stopSnapshots();stopH264();if(statusEl)statusEl.textContent='Pausiert';return;}
  if(h){ if(!h264On){stopStream();stopSnapshots();startH264();} }
  else { stopH264(); applyMode(); }
}
// Codec-Auswahl schaltet die Wiedergabe wirklich um (kein Zurueckspringen mehr). Ausgegraute
// Codecs (keine HW) sind ohnehin nicht waehlbar.
if(codecSelect){codecSelect.addEventListener('change',function(){
  fillSizeForCodec();   // dasselbe Aufloesungs-Dropdown neu befuellen (Kamera-Modi vs. H.264-Groessen)
  if(codecSelect.value==='h264')stopH264();   // Neustart mit ggf. neuer Groesse
  applyCodec();
});}

// Kamera-Stream/Einzelbilder nur laufen lassen, wenn Diagnose -> Video (Livebild) tatsaechlich
// sichtbar ist (spart WLAN/CPU/Kamera). Innerhalb der Diagnose-Seite wechselt der Unterpunkt im
// DOM -- darum ueber onPageShown() am Seitenwechsel haengen statt einmalig beim Laden.
function videoVisible(){
  var kp=document.getElementById('tab-diagvideo');
  return !!(kp&&kp.classList.contains('active'));
}
function updateVideo(){ applyCodec(); }   // applyCodec() stoppt alles bei unsichtbarer Seite
onPageShown(updateVideo);
updateVideo();
})();

// ---- Qualitaets-Slider (Server > Video, live; persistiert bei change) ----
(function(){
var qs=document.getElementById('quality-slider');
var qv=document.getElementById('quality-value');
if(!qs||!qv)return;
function showQ(){qv.textContent=qs.value+(qs.value==='0'?' (beste)':'');}
showQ();
qs.addEventListener('input',showQ);
qs.addEventListener('change',function(){
  // Device-Resource-API: PATCH /dev/camera0 (statt Legacy /cam-set). Ein Endpunkt fuer
  // mode/fps/quality/params, keine wachsende /cam-*-Sammlung.
  fetch('/dev/camera0',{method:'PATCH',cache:'no-store',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({quality:parseInt(qs.value,10)})})
    .then(on401).then(function(r){return r.json();})
    .then(function(d){if(!d||!d.ok)camStatus((d&&d.error)||'Fehler.');})
    .catch(function(){});
});
})();

// ---- Bildrate-Slider (Server > Video, live; persistiert bei change) ----
(function(){
var fps=document.getElementById('fps-slider');
var fv=document.getElementById('fps-value');
if(!fps||!fv)return;
function showF(){fv.textContent=fps.value+' fps';}
showF();
fps.addEventListener('input',showF);
fps.addEventListener('change',function(){
  fetch('/dev/camera0',{method:'PATCH',cache:'no-store',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({fps:parseInt(fps.value,10)})})
    .then(on401).then(function(r){return r.json();})
    .then(function(d){if(!d||!d.ok)camStatus((d&&d.error)||'Fehler.');})
    .catch(function(){});
});
})();

// ---- Globale Frame-Politik (veraltete Frames verwerfen) -- gilt fuer alle Streams, wirkt sofort ----
(function(){
var dsChk=document.getElementById('drop-stale');
if(!dsChk)return;
dsChk.addEventListener('change',function(){
  fetch('/dev/camera0',{method:'PATCH',cache:'no-store',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({dropstale:dsChk.checked?1:0})})
    .then(on401).then(function(r){return r.json();})
    .then(function(d){if(!d||!d.ok)camStatus((d&&d.error)||'Fehler.');})
    .catch(function(){});
});
})();

// ---- Slider-Wert im Kamera-Tab (Bildpuffer) ----
(function(){
  function bindVal(sid,vid,suffix){
    var sl=document.getElementById(sid),va=document.getElementById(vid);
    if(!sl||!va)return;
    function u(){va.textContent=sl.value+(suffix||'')+(sl.value==='0'?' (max)':'');}
    u();sl.addEventListener('input',u);
  }
  bindVal('cfg-bufq','cfgb-value','');
})();

// ---- Capture-Config (max Aufloesung + Bildpuffer) -> PATCH /dev/camera0 (Kamera-Geraet,
//      NICHT der VideoServer-Form). Beide wirken nach Neustart (Framebuffer-Dimensionierung). ----
(function(){
  var mx=document.getElementById('cfg-max'),bq=document.getElementById('cfg-bufq');
  if(!mx&&!bq)return;
  function patchCap(payload){
    fetch('/dev/camera0',{method:'PATCH',cache:'no-store',
      headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
      .then(on401).then(function(r){return r.json();})
      .then(function(d){
        if(d&&d.ok)camStatus(d.restartRequired?'Gespeichert - wirkt nach Neustart.':'Gespeichert.');
        else if(d&&!d.ok)camStatus((d&&d.error)||'Fehler.');
      }).catch(function(){});
  }
  if(mx)mx.addEventListener('change',function(){patchCap({maxMode:mx.value});});
  if(bq)bq.addEventListener('change',function(){patchCap({bufferQuality:parseInt(bq.value,10)});});
})();

// ---- Kamera Sensor-Parameter (generisch, geraeteunabhaengig: S3-DVP / P4-MIPI) ----
(function(){
  var box=document.getElementById('cam-params');
  if(!box)return;
  function setParam(key,val){
    // Device-Resource-API: PATCH /dev/camera0 {params:{<key>:<val>}} (statt Legacy /cam-param).
    var pp={}; pp[key]=val;
    fetch('/dev/camera0',{method:'PATCH',cache:'no-store',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({params:pp})})
      .then(on401).catch(function(){});
  }
  // Param-Liste + aktuelle Werte kommen aus GET /dev/camera0 (d.params), nicht mehr /cam-params.json.
  fetch('/dev/camera0',{cache:'no-store'}).then(on401).then(function(r){return r.json();}).then(function(d){
    if(!d||!d.params){box.textContent='-';return;}
    if(!d.params.length){box.textContent=d.present?'Keine einstellbaren Parameter.':'Kamera nicht aktiv.';return;}
    box.innerHTML='';
    // Kein Schein-Regler: wo das Backend die Params nicht setzt (P4/V4L2), NUR die aktuellen
    // Werte read-only zeigen (ehrlich), statt Slider, die beim Aendern 501 quittieren wuerden.
    if(d.paramsSettable===false){
      var note=document.createElement('p');note.className='cam-hint';
      note.textContent='Sensor-Parameter sind auf diesem Geraet fest (Backend erlaubt keine Aenderung).';
      box.appendChild(note);
      d.params.forEach(function(p){
        var r=document.createElement('div');r.className='slider-row';
        var a=document.createElement('span');a.textContent=p.label;
        var b=document.createElement('span');b.className='slider-value';b.textContent=p.value;
        r.appendChild(a);r.appendChild(b);box.appendChild(r);
      });
      return;
    }
    d.params.forEach(function(p){
      if(p.kind===1){ // BOOL -> Schalter
        var lab=document.createElement('label');lab.className='check-row';
        var cb=document.createElement('input');cb.type='checkbox';cb.checked=(p.value!=0);
        cb.addEventListener('change',function(){setParam(p.key,cb.checked?1:0);});
        var sp=document.createElement('span');sp.textContent=p.label;
        lab.appendChild(cb);lab.appendChild(sp);box.appendChild(lab);
      }else{ // INT -> Slider
        var row=document.createElement('label');row.className='slider-row';
        var nm=document.createElement('span');nm.textContent=p.label;
        var vv=document.createElement('span');vv.className='slider-value';vv.textContent=p.value;
        row.appendChild(nm);row.appendChild(vv);box.appendChild(row);
        var sl=document.createElement('input');sl.className='slider';sl.type='range';
        sl.min=p.min;sl.max=p.max;sl.step=1;sl.value=p.value;
        sl.addEventListener('input',function(){vv.textContent=sl.value;});
        sl.addEventListener('change',function(){setParam(p.key,sl.value);});
        box.appendChild(sl);
      }
    });
  }).catch(function(){box.textContent='Fehler beim Laden.';});
})();

// ---- WLAN-Stack Auto/An/Aus: Live-Vorschau, welche Felder wirken wuerden (kein Fetch, reine
// DOM-Logik) -- analog zum VPN-big-toggle-Muster (show/hide je Enable-Haken). Serverseitig ist
// der Initialzustand schon per wifiEffOn vorgerendert; hier nur der sofortige visuelle Wechsel
// bei Auswahl, BEVOR gespeichert wird (die echte Wirkung kommt erst nach Speichern+Neustart).
(function(){
  var sel=document.getElementById('wifistack');
  if(!sel)return;
  var hwPresent=sel.getAttribute('data-hw-present')==='1';
  function sync(){
    var effOn=(sel.value==='on')||(sel.value==='auto'&&hwPresent);
    document.querySelectorAll('.wifi-gated-fields').forEach(function(el){
      el.classList.toggle('fields-inactive',!effOn);
    });
  }
  sel.addEventListener('change',sync);
})();

// ---- SSID-Scan (WLAN-Seite) ----
(function(){
var ssidInput=document.getElementById('ssid');
var ssidList=document.getElementById('ssid-list');
var toggleButton=document.getElementById('toggle-button');
if(!toggleButton||!ssidList||!ssidInput)return;   // Wurzel-Guard: nur auf der WLAN-Seite
var rescanButton=document.getElementById('rescan-button');
var scanStatus=document.getElementById('scan-status');
var pw=document.getElementById('password');
var networks=[];
function bars(r){if(r>=-55)return'||||';if(r>=-67)return'|||.';if(r>=-78)return'||..';return'|...';}
function hideL(){ssidList.classList.add('hidden');toggleButton.setAttribute('aria-expanded','false');}
function showL(){ssidList.classList.remove('hidden');toggleButton.setAttribute('aria-expanded','true');}
function pick(s){ssidInput.value=s;hideL();pw.focus();}
function render(){
  ssidList.innerHTML='';
  if(!networks.length){var e=document.createElement('li');e.className='empty';e.textContent='Keine Netzwerke';ssidList.appendChild(e);return;}
  networks.forEach(function(nw){
    var li=document.createElement('li');li.tabIndex=0;
    var nm=document.createElement('span');nm.className='ssid-name';nm.textContent=nw.ssid;
    var me=document.createElement('span');me.className='ssid-meta';
    me.textContent=bars(nw.rssi)+'  '+nw.rssi+' dBm  '+(nw.secure?'gesichert':'offen');
    li.appendChild(nm);li.appendChild(me);
    li.addEventListener('click',function(){pick(nw.ssid);});
    li.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();pick(nw.ssid);}});
    ssidList.appendChild(li);
  });
}
function scan(force){
  rescanButton.disabled=true;scanStatus.textContent='Suche ...';
  fetch('/scan?'+(force?'refresh=1&':'')+'t='+Date.now(),{cache:'no-store'})
    .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})
    .then(function(d){
      if(d.scanning){scanStatus.textContent='Suche laeuft ...';setTimeout(function(){scan(false);},1200);return;}
      networks=d.networks||[];render();scanStatus.textContent=networks.length+' Netzwerk(e)';rescanButton.disabled=false;})
    .catch(function(e){scanStatus.textContent='Suche fehlgeschlagen: '+e.message;rescanButton.disabled=false;});
}
toggleButton.addEventListener('click',function(){
  if(ssidList.classList.contains('hidden')){render();showL();if(!networks.length)scan(false);}else{hideL();}});
if(rescanButton)rescanButton.addEventListener('click',function(){render();showL();scan(true);});
document.addEventListener('click',function(e){if(!e.target.closest('.ssid-wrap'))hideL();});
document.addEventListener('keydown',function(e){if(e.key==='Escape')hideL();});
})();

// ---- Internet / Modem (Mobilfunk ueber USB + PPP) ----
// Wurzel-Guard: die Modem-Bedienung steht auf WAN > Mobilfunk und Diagnose > Modem. Auf jeder
// anderen Seite wuerden nur Klick-Hooks und ein 2-s-Poll ins Leere laufen (Sockets/LTE).
// Der Modem-Status der UEBERSICHT hat einen eigenen Poll (Online-Monitor) und braucht das hier nicht.
(function(){
if(!document.getElementById('tab-mobilfunk')&&!document.getElementById('tab-diagusb'))return;
eye('m-pass-eye','m-pass');
var mStatus=document.getElementById('modem-status');
var mMsg=document.getElementById('modem-msg');
var mForm=document.getElementById('modem-form');
var mDataModeLoaded=null;   // zuletzt gespeicherte Datenschicht (fuer Wechsel-Erkennung)
function mRate(d){var el=document.getElementById('ppp-rate');if(!el||d.txkbit==null)return;
  el.textContent='TX '+fmtKbit(d.txkbit)+' / RX '+fmtKbit(d.rxkbit);
  var dg=document.getElementById('ppp-diag');
  if(dg&&d.txwait!=null){var avg=d.txwait>0?Math.round(d.txwaitus/d.txwait):0;
    dg.textContent='in-flight max '+d.txmaxinflight+' | Pool-Waits '+d.txwait+(avg?(' (~'+avg+' us)'):'')+' | Timeouts '+d.txtimeout+(d.txsubmitfail?(' | SubmitFail '+d.txsubmitfail):'');}}
function mApply(d){
  if(!d)return;
  if(d.datamode!=null)mDataModeLoaded=d.datamode;
  if(mStatus&&d.status!=null)mStatus.textContent=d.status;
  if(mMsg&&d.msg!=null)mMsg.textContent=d.msg;
  var uh=document.getElementById('m-usbhost');
  if(uh&&d.usbhost!=null)uh.textContent=d.usbhost?'USB-Host: aktiv (Modem laeuft).':('USB-Host: nicht gestartet'+(d.usbhostreason?(' - '+d.usbhostreason):'')+'.');
  mRate(d);
}
function mFail(){if(mMsg)mMsg.textContent='Netzwerkfehler.';}
function mPost(url,body){
  return fetch(url,{method:'POST',cache:'no-store',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body||''})
    .then(function(r){return r.json();}).then(mApply).catch(mFail);
}
function mGet(url){
  return fetch(url+(url.indexOf('?')<0?'?':'&')+'t='+Date.now(),{cache:'no-store'})
    .then(function(r){return r.json();}).then(mApply).catch(mFail);
}
function mBody(){
  var q=[];
  function add(id,name){var el=document.getElementById(id);if(el)q.push(name+'='+encodeURIComponent(el.value));}
  add('m-apn','apn');add('m-user','user');add('m-pass','pass');add('m-pdp','pdp');add('m-auth','auth');
  add('m-port','port');add('m-dialnum','dialnum');add('m-simpin','simpin');
  var spc=document.querySelector('input[name="simpinclear"]');if(spc&&spc.checked)q.push('simpinclear=1');
  var a=document.getElementById('m-auto');if(a&&a.checked)q.push('autoconnect=1');
  var as=document.getElementById('m-autostart');if(as&&as.checked)q.push('autostart=1');
  var ue=document.getElementById('m-usben');if(ue&&ue.checked)q.push('usben=1');
  return q.join('&');
}
// EIN Speichern fuer beide Tabs (Anschluss + Zugangsdaten): mBody() sammelt alle Felder per ID,
// unabhaengig davon, in welchem Tab sie stehen. Die Rueckmeldung landet in #modem-msg (Zugangsdaten)
// und wird fuer den Anschluss-Tab nach #m-port-msg gespiegelt.
function mSave(){
  if(mMsg)mMsg.textContent='Speichere ...';
  var pm=document.getElementById('m-port-msg');if(pm)pm.textContent='Speichere ...';
  return mPost('/modem-save',mBody()).then(function(){if(pm&&mMsg)pm.textContent=mMsg.textContent;});
}
if(mForm){mForm.addEventListener('submit',function(e){e.preventDefault();mSave();});}
var mSavePort=document.getElementById('m-save-port');
if(mSavePort)mSavePort.addEventListener('click',function(){mSave();});
// ---- Datenschicht PPP<->ECM (eigener Tab, braucht Modem-Reboot) ----
var dlForm=document.getElementById('datalink-form');
if(dlForm){
  dlForm.addEventListener('submit',function(e){
    e.preventDefault();
    var sel=document.getElementById('m-datamode');
    var newMode=sel?sel.value:'ppp';
    var dlMsg=document.getElementById('dl-msg');
    var body='datamode='+encodeURIComponent(newMode);
    // NIC-/Routing-Betriebsart (nur ECM): Aenderung braucht ebenfalls einen Modem-Neustart.
    var nat=document.getElementById('m-natmode');
    var natChanged=false;
    if(nat){body+='&natmode='+encodeURIComponent(nat.value);natChanged=(nat.dataset.orig&&nat.dataset.orig!==nat.value&&newMode==='ecm');}
    var modeChanged=(mDataModeLoaded!=null&&newMode!==mDataModeLoaded);
    if(modeChanged||natChanged){
      var what=modeChanged?('Datenschicht auf '+(newMode==='ecm'?'CDC-ECM':'PPP')+' umstellen?'):
        ('ECM-Betriebsart auf '+(nat.value==='routing'?'Routing (Modem-NAT)':'NIC (oeffentliche IP am ESP)')+' umstellen?');
      if(!confirm(what+'\n\n'
        +'Dafuer wird das MODEM neu gestartet (~15-30 s) und die aktuelle '
        +'Verbindung getrennt. Der ESP bleibt an (kein ESP-Neustart).\n\nFortfahren?'))return;
      body+='&switchnow=1';
    }
    if(dlMsg)dlMsg.textContent='Schalte um ...';
    fetch('/modem-datalink',{method:'POST',cache:'no-store',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
      .then(function(r){return r.json();})
      .then(function(d){if(dlMsg&&d&&d.msg)dlMsg.textContent=d.msg;mDataModeLoaded=newMode;if(nat)nat.dataset.orig=nat.value;})
      .catch(function(){if(dlMsg)dlMsg.textContent='Netzwerkfehler.';});
  });
}
// ---- SIM-PIN-Sperre auf der Karte (WAN > Netzzugang > Zugangsdaten): Status / an / aus / aendern ----
(function(){
  var run=document.getElementById('sp-run'),rf=document.getElementById('sp-refresh');
  if(!run)return;
  var act=document.getElementById('sp-action'),pin=document.getElementById('sp-pin'),np=document.getElementById('sp-newpin'),msg=document.getElementById('sp-msg');
  function show(d){
    if(!d)return;
    var st=document.getElementById('sp-status'),lf=document.getElementById('sp-left');
    if(st&&d.locked!=null)st.textContent=(d.locked===1?'Sperre aktiv':(d.locked===0?'Sperre inaktiv':'unbekannt'))+(d.cpin?(' - SIM: '+d.cpin):'');
    if(lf)lf.textContent=(d.pinLeft!=null?d.pinLeft:'?')+' / '+(d.pukLeft!=null?d.pukLeft:'?');
    if(msg&&d.msg!=null)msg.textContent=d.msg;
  }
  function call(body){
    if(msg)msg.textContent='Frage Modem ...';
    fetch('/sim-pin',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
      .then(function(r){return r.json();}).then(show).catch(function(){if(msg)msg.textContent='Netzwerkfehler.';});
  }
  if(act)act.addEventListener('change',function(){if(np)np.style.display=(act.value==='change')?'':'none';});
  if(rf)rf.addEventListener('click',function(){call('action=status');});
  run.addEventListener('click',function(){
    var a=act?act.value:'enable';
    if(a==='disable'&&!confirm('PIN-Sperre auf der SIM deaktivieren? Die Karte ist dann ohne PIN in jedem Geraet nutzbar.'))return;
    call('action='+a+'&pin='+encodeURIComponent(pin?pin.value:'')+'&newpin='+encodeURIComponent(np?np.value:''));
    if(pin)pin.value='';if(np)np.value='';
  });
})();

// ---- Mobilfunk-Frequenzen (Band/RAT) ----
var bandForm=document.getElementById('band-form');
var bMsg=document.getElementById('b-msg');
var bProfile=document.getElementById('b-profile');
function bandBoxes(){return document.querySelectorAll('#band-list .b-band');}
function bandToggle(){
  var custom=(bProfile&&bProfile.value==='custom');
  bandBoxes().forEach(function(cb){cb.disabled=!custom;});
}
if(bProfile){bProfile.addEventListener('change',bandToggle);bandToggle();}
if(bandForm)bandForm.addEventListener('submit',function(e){
  e.preventDefault();
  if(bMsg)bMsg.textContent='Wende an ...';
  var q=[];
  var nm=document.getElementById('b-netmode');if(nm)q.push('netmode='+encodeURIComponent(nm.value));
  q.push('profile='+encodeURIComponent(bProfile?bProfile.value:'auto'));
  if(bProfile&&bProfile.value==='custom'){
    var mask=0n;
    bandBoxes().forEach(function(cb){if(cb.checked)mask|=(1n<<BigInt(cb.value));});
    q.push('bandc='+mask.toString(16));
  }
  fetch('/modem-band-save',{method:'POST',cache:'no-store',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},body:q.join('&')})
    .then(function(r){return r.json();})
    .then(function(d){if(bMsg)bMsg.textContent=(d&&d.msg)||'Uebernommen.';})
    .catch(function(){if(bMsg)bMsg.textContent='Netzwerkfehler.';});
});
function pppPoll(n){
  if(n<=0)return;
  fetch('/modem-status.json?t='+Date.now(),{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){
      if(!d)return;
      if(mStatus&&d.status!=null)mStatus.textContent=d.status;
      mRate(d);
      var ecm=(d.datamode=='ecm');
      var s=ecm?(d.ecmstatus||'-'):(d.ppp||'-');
      if(mMsg)mMsg.textContent=(ecm?'ECM: ':'PPP: ')+s;
      if(s.indexOf('verbunden')>=0||s.indexOf('fehlgeschlagen')>=0||s.indexOf(' up')>=0||s.indexOf('aus')>=0)return;
      setTimeout(function(){pppPoll(n-1);},1500);
    }).catch(function(){});
}
var mConnect=document.getElementById('m-connect');
if(mConnect)mConnect.addEventListener('click',function(){
  if(mMsg)mMsg.textContent='Datenpfad-Aufbau ...';
  mPost('/modem-connect').then(function(){pppPoll(12);});
});
var mDisc=document.getElementById('m-disconnect');
if(mDisc)mDisc.addEventListener('click',function(){if(mMsg)mMsg.textContent='Trenne ...';mPost('/modem-disconnect');});
var mTest=document.getElementById('m-test');
if(mTest)mTest.addEventListener('click',function(){if(mMsg)mMsg.textContent='Teste ...';mGet('/modem-test');});
var mReset=document.getElementById('m-reset');
if(mReset)mReset.addEventListener('click',function(){
  if(!confirm('Modem neu starten (AT+CFUN=1,1)? Es ist danach ~15-20 s nicht erreichbar.'))return;
  if(mMsg)mMsg.textContent='Starte Modem neu ...';mPost('/modem-reset');});
// Einmal-Abruf beim Oeffnen von WAN > Modem (USB-Host-Zeile) und Diagnose > Modem (Pipeline).
['mobilfunk','diagusb'].forEach(function(tb){
  var t=document.querySelector('.nav-item[data-tab="'+tb+'"]');
  if(t)t.addEventListener('click',function(){mGet('/modem-status.json');});
});
// Solange Diagnose > Modem sichtbar ist, alle 2 s aktualisieren (Durchsatz/TX-Pipeline live).
// Bewusst NICHT auf WAN > Modem: dort wuerde der Poll die Rueckmeldung der Verbindungs-Buttons
// (#modem-msg) alle 2 s ueberschreiben. Der USB-Status lebt in der Uebersicht (eigener Poll).
setInterval(function(){
  var p=document.getElementById('tab-diagusb');
  if(p&&p.classList.contains('active'))mGet('/modem-status.json');
},2000);
})();

// ---- Speedtest (LTE, Download+Upload ueber PPP) ----
(function(){
  var stRun=document.getElementById('st-run');
  var stDown=document.getElementById('st-down'),stUp=document.getElementById('st-up'),stMsg=document.getElementById('st-msg');
  var stConn=document.getElementById('st-conn'),stAuto=document.getElementById('st-auto'),stActive=document.getElementById('st-active');
  var stInit=false;   // Eingabefelder nur einmal aus dem Geraet vorbelegen
  function stShow(d){
    if(!d)return;
    if(stDown)stDown.textContent=d.stdown?fmtKbit(d.stdown):(d.ststate=='down'?'messe...':'-');
    if(stUp)stUp.textContent=d.stup?fmtKbit(d.stup):(d.ststate=='up'?'messe...':'-');
    if(stActive)stActive.textContent=(d.stactive>0)?(''+d.stactive):'-';
    if(!stInit){stInit=true;                     // gespeicherte Vorgabe vorbelegen (nicht beim Tippen ueberschreiben)
      if(stConn&&d.stconn)stConn.value=d.stconn;
      if(stAuto)stAuto.checked=!!d.stauto;
    }
    if(stMsg){
      var w=(d.stauto&&d.stactive)?(' ('+d.stactive+' Worker)'):'';
      if(d.ststate=='down')stMsg.textContent='Download laeuft ...'+w;
      else if(d.ststate=='up')stMsg.textContent='Upload laeuft ...'+w;
      else if(d.ststate=='done')stMsg.textContent='Fertig.'+(d.stmsg?(' '+d.stmsg):'');
      else if(d.ststate=='error')stMsg.textContent='Fehler: '+(d.stmsg||'unbekannt');
    }
  }
  function stPoll(){
    fetch('/modem-status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d)return;stShow(d);
        if(d.ststate=='done'||d.ststate=='error'||d.ststate=='idle'){if(stRun)stRun.disabled=false;return;}
        setTimeout(stPoll,1500);
      }).catch(function(){setTimeout(stPoll,2000);});
  }
  if(stRun)stRun.addEventListener('click',function(){
    stRun.disabled=true;
    if(stDown)stDown.textContent='-';if(stUp)stUp.textContent='-';
    if(stMsg)stMsg.textContent='Starte ...';
    var conn=stConn?Math.max(1,Math.min(16,parseInt(stConn.value,10)||6)):6;
    var auto=(stAuto&&stAuto.checked)?1:0;
    fetch('/speedtest-start',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'conn='+conn+'&auto='+auto})
      .then(function(r){return r.json();})
      .then(function(d){if(stMsg&&d&&d.msg)stMsg.textContent=d.msg;setTimeout(stPoll,800);})
      .catch(function(){if(stMsg)stMsg.textContent='Netzwerkfehler.';if(stRun)stRun.disabled=false;});
  });
  // Vorgabe beim Laden einmal holen (auch ohne laufenden Poll)
  fetch('/modem-status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();}).then(stShow).catch(function(){});
})();

// ---- Einzelstream-Fenstertest (Diagnose > Durchsatz), feste conn=1 ----
(function(){
  var run=document.getElementById('sp1-run');
  if(!run)return;
  var down=document.getElementById('sp1-down'),up=document.getElementById('sp1-up'),msg=document.getElementById('sp1-msg');
  function show(d){
    if(!d)return;
    if(down)down.textContent=d.stdown?fmtKbit(d.stdown):(d.ststate=='down'?'messe...':'-');
    if(up)up.textContent=d.stup?fmtKbit(d.stup):(d.ststate=='up'?'messe...':'-');
    if(msg){
      if(d.ststate=='down')msg.textContent='Download laeuft ...';
      else if(d.ststate=='up')msg.textContent='Upload laeuft ...';
      else if(d.ststate=='done')msg.textContent='Fertig.'+(d.stmsg?(' '+d.stmsg):'');
      else if(d.ststate=='error')msg.textContent='Fehler: '+(d.stmsg||'unbekannt');
    }
  }
  function poll(){
    fetch('/modem-status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d)return;show(d);
        if(d.ststate=='done'||d.ststate=='error'||d.ststate=='idle'){run.disabled=false;return;}
        setTimeout(poll,1500);
      }).catch(function(){setTimeout(poll,2000);});
  }
  run.addEventListener('click',function(){
    run.disabled=true;
    if(down)down.textContent='-';if(up)up.textContent='-';
    if(msg)msg.textContent='Starte Einzelstream (1 Verbindung) ...';
    fetch('/speedtest-start',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'conn=1&auto=0'})
      .then(function(r){return r.json();})
      .then(function(d){if(msg&&d&&d.msg)msg.textContent=d.msg;setTimeout(poll,800);})
      .catch(function(){if(msg)msg.textContent='Netzwerkfehler.';run.disabled=false;});
  });
})();

// ---- AT-Konsole (Diagnose > Modem) ----
(function(){
var atIf=document.getElementById('at-if');
var atCmd=document.getElementById('at-cmd');
if(!atCmd||!atIf)return;
var atSend=document.getElementById('at-send');
var atOut=document.getElementById('at-out');
function atRun(){
  var c=atCmd.value||'AT';
  if(atOut)atOut.textContent='> '+c+'\n...';
  fetch('/modem-at?if='+atIf.value+'&cmd='+encodeURIComponent(c),{cache:'no-store'})
    .then(function(r){return r.text();})
    .then(function(t){if(atOut)atOut.textContent='> '+c+'\n'+t;})
    .catch(function(){if(atOut)atOut.textContent='Netzwerkfehler.';});
}
if(atSend)atSend.addEventListener('click',atRun);
atCmd.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();atRun();}});
})();

// ---- Entwickler-Diagnose an/aus (Diagnose > USB/Modem) ----
(function(){
var diagSaveBtn=document.getElementById('diag-save');
if(!diagSaveBtn)return;
diagSaveBtn.addEventListener('click',function(){
  var cb=document.getElementById('diag-en');
  var m=document.getElementById('diag-msg');
  var body=(cb&&cb.checked)?'diagen=1':'';
  if(m)m.textContent='Speichere ...';
  fetch('/diag-save',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
    .then(function(r){return r.json();})
    .then(function(d){if(m)m.textContent=(d&&d.diagen)?'Diagnose aktiv.':'Diagnose deaktiviert - AT-Konsole/USB-Info/Log gesperrt.';})
    .catch(function(){if(m)m.textContent='Netzwerkfehler.';});
});
})();

// ---- Anbieter-Profile (fuellen nur die Felder; Speichern bleibt separat) ----
// Deutsche Default-APNs wie in der FritzBox. netpublic ist bewusst NICHT der
// o2-Default, sondern eine separate, kostenpflichtig zu beantragende IPv4-Variante.
(function(){
var mProv=document.getElementById('m-provider');
if(!mProv)return;
var providers={
  o2:{apn:'internet',pdp:'IPV4V6',auth:'0',user:'',pass:'',
      hint:'o2/Telefonica Standard (Vertrag & Prepaid): APN internet, keine Zugangsdaten.'},
  o2netpublic:{apn:'netpublic',pdp:'IP',auth:'0',user:'',pass:'',
      hint:'o2 netpublic = oeffentliche dynamische IPv4 (PDP-Typ IP / IPv4-only - mit IPV4V6 scheitert '
          +'die Einwahl!). Setzt den kostenpflichtigen o2-Antrag voraus (Kontaktformular, ~49 EUR).'},
  telekom:{apn:'internet.telekom',pdp:'IPV4V6',auth:'1',user:'t-mobile',pass:'tm',
      hint:'Telekom Standard: APN internet.telekom, Benutzer t-mobile / Passwort tm (PAP). Auf vielen '
          +'Tarifen auch ohne Zugangsdaten. ABER: nur CGNAT-IPv4 -> NICHT von aussen erreichbar '
          +'(IPv6 wird netzseitig eingehend gefiltert). Fuer Erreichbarkeit -> telekompublic waehlen.'},
  telekompublic:{apn:'internet.t-d1.de',pdp:'IP',auth:'0',user:'',pass:'',
      hint:'Telekom OEFFENTLICHE dynamische IPv4 (Pendant zu o2 netpublic): APN internet.t-d1.de, '
          +'PDP-Typ IP, keine Zugangsdaten. HARDWARE-VERIFIZIERT 2026-08-28: gibt eine public IPv4 '
          +'(z.B. 37.81.x) OHNE CGNAT, eingehendes TCP kommt von aussen durch -> mit DynDNS-A von '
          +'ueberall erreichbar. Genau das fuer Kamera/VPN nehmen, NICHT internet.telekom.'},
  vodafone:{apn:'web.vodafone.de',pdp:'IPV4V6',auth:'0',user:'',pass:'',
      hint:'Vodafone: APN web.vodafone.de, keine Zugangsdaten.'}
};
function setVal(id,v){var e=document.getElementById(id);if(e)e.value=v;}
var mProvHint=document.getElementById('m-provider-hint');
mProv.addEventListener('change',function(){
  var p=providers[mProv.value];
  if(!p){if(mProvHint)mProvHint.textContent='Alle Felder unten frei einstellbar.';return;}
  setVal('m-apn',p.apn);setVal('m-user',p.user);setVal('m-pass',p.pass);
  setVal('m-pdp',p.pdp);setVal('m-auth',p.auth);
  if(mProvHint)mProvHint.textContent=p.hint;
});
})();
// Netzzugang: die Wahl oben (Automatisch/Mobilfunk/WLAN-Client) blendet die passenden Einstellungen
// darunter ein -- Vorschau; die Wahl selbst wirkt erst nach "Speichern" (WanPolicy).
(function(){
  function sel(){var r=document.querySelector('input[name="pref"]:checked');return r?r.value:'auto';}
  function tog(){var view=(sel()==='wifi')?'wifi':'cellular';
    document.querySelectorAll('[data-wanview]').forEach(function(el){
      el.style.display=(el.getAttribute('data-wanview')===view)?'':'none';});}
  document.querySelectorAll('input[name="pref"]').forEach(function(r){r.addEventListener('change',tog);});
  tog();
})();

// ---- Mobilfunk-Status ----
(function(){
var miBtn=document.getElementById('mi-refresh');
if(!miBtn)return;
var miOut=document.getElementById('mi-out');
miBtn.addEventListener('click',function(){
  if(miOut)miOut.textContent='Frage Modem ab ...';
  fetch('/modem-info?t='+Date.now(),{cache:'no-store'})
    .then(on401)
    .then(function(r){return r.text();})
    .then(function(t){if(miOut)miOut.textContent=t;})
    .catch(function(){if(miOut)miOut.textContent='Netzwerkfehler.';});
});
})();

// ---- Mobilfunkdaten (strukturiert, /modem-json) ----
// Der Abruf-Button steht auf MEHREREN Seiten (Uebersicht + Diagnose > Modem); EIN Abruf fuellt
// alle mj-* Felder ueberall. Deshalb Klassen statt IDs: .js-mj-refresh (Buttons), .js-mj-msg (Status).
(function(){
var mjBtns=document.querySelectorAll('.js-mj-refresh');
if(!mjBtns.length)return;
var mjMsg={set textContent(v){document.querySelectorAll('.js-mj-msg').forEach(function(e){e.textContent=v;});}};
function mjSet(id,v){var e=document.getElementById(id);if(e)e.textContent=(v==null||v==='')?'-':v;}
function mjU(v,u){return (v==null||v==='')?'-':(v+u);}
function mjBusy(on){mjBtns.forEach(function(b){b.classList.toggle('busy',on);b.disabled=on;});}
function mjLoad(){
  if(mjMsg)mjMsg.textContent='Frage Modem ab (dauert einige Sekunden) ...';
  mjBusy(true);
  fetch('/modem-json?t='+Date.now(),{cache:'no-store'})
    .then(on401)
    .then(function(r){return r.json();})
    .then(function(d){mjBusy(false);
      if(!d||!d.ok){if(mjMsg)mjMsg.textContent='Abfrage fehlgeschlagen.';return;}
      mjSet('mj-model',d.model);mjSet('mj-firmware',d.firmware);
      mjSet('mj-reg',d.reg==='1'?'Heimnetz':(d.reg==='5'?'Roaming':d.reg));
      mjSet('mj-operator',d.operator);mjSet('mj-rat',d.rat);
      mjSet('mj-ipv4',d.ipv4);mjSet('mj-ipv6',d.ipv6);
      mjSet('mj-band',d.band?('B'+d.band):'');mjSet('mj-freq',d.freq);
      mjSet('mj-earfcn',d.earfcn);mjSet('mj-pci',d.pci);
      mjSet('mj-cellid',d.cellid?('0x'+d.cellid):'');
      mjSet('mj-tac',d.tac?('0x'+d.tac):'');
      mjSet('mj-plmn',(d.mcc&&d.mnc)?(d.mcc+' / '+d.mnc):'');
      mjSet('mj-rsrp',mjU(d.rsrp,' dBm'));mjSet('mj-rsrq',mjU(d.rsrq,' dB'));
      mjSet('mj-rssi',mjU(d.rssi,' dBm'));mjSet('mj-sinr',mjU(d.sinr,' dB'));
      mjSet('mj-cpin',d.cpin);mjSet('mj-iccid',d.iccid);
      mjSet('mj-imsi',d.imsi);mjSet('mj-imei',d.imei);
      if(mjMsg)mjMsg.textContent=d.rfsnap?'Aktualisiert (Funkwerte = Snapshot vom Verbindungsaufbau; Live-Abfrage nur bei getrennter Verbindung).':'Aktualisiert.';
    })
    .catch(function(){mjBusy(false);if(mjMsg)mjMsg.textContent='Netzwerkfehler.';});
}
mjBtns.forEach(function(mjBtn){mjBtn.addEventListener('click',mjLoad);});
// Einmal beim Seitenaufruf (kein Dauer-Poll). Bei bestehender Verbindung liefert /modem-json alle
// Felder aus dem Snapshot vom Verbindungsaufbau, also OHNE Live-AT -- nur getrennt ist der Abruf
// wirklich langsam. Die kurze Verzoegerung haelt ihn aus dem Sofort-Schub der Seite heraus
// (Web hat 5 Sockets; /sysinfo.json, /vpn-status.json und /wan-status.json laufen schon).
setTimeout(mjLoad,400);
})();

// ---- DynDNS (Internet -> Freigaben) ----
(function(){
var dynForm=document.getElementById('dyn-form');
if(!dynForm)return;
eye('dyn-eye','dyn-pass');
var dynMsg=document.getElementById('dyn-msg');
dynForm.addEventListener('submit',function(e){
  e.preventDefault();
  if(dynMsg)dynMsg.textContent='Speichere ...';
  var q=[];
  var en=document.getElementById('dyn-enabled');if(en&&en.checked)q.push('enabled=1');
  function addD(id,name){var el=document.getElementById(id);if(el)q.push(name+'='+encodeURIComponent(el.value));}
  addD('dyn-egress','egress');
  addD('dyn-provider','provider');addD('dyn-url','url');addD('dyn-domain','domain');
  addD('dyn-user','user');addD('dyn-pass','pass');
  fetch('/dyndns-save',{method:'POST',cache:'no-store',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},body:q.join('&')})
    .then(function(r){return r.json();})
    .then(function(d){if(dynMsg)dynMsg.textContent=(d&&d.msg)||'Gespeichert.';})
    .catch(function(){if(dynMsg)dynMsg.textContent='Netzwerkfehler.';});
});
function dynStat(){
  fetch('/dyndns-status.json?t='+Date.now(),{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){if(!d)return;
      var s=document.getElementById('dyn-status');if(s)s.textContent=d.status||'-';
      var ip=document.getElementById('dyn-ip');if(ip)ip.textContent=(d.last||d.ip||'-');
    }).catch(function(){});
}
var dynNow=document.getElementById('dyn-now');
if(dynNow)dynNow.addEventListener('click',function(){
  if(dynMsg)dynMsg.textContent='Update angestossen ...';
  fetch('/dyndns-update',{method:'POST',cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){if(dynMsg)dynMsg.textContent=(d&&d.msg)||'';
      setTimeout(dynStat,1500);setTimeout(dynStat,4000);setTimeout(dynStat,8000);})
    .catch(function(){if(dynMsg)dynMsg.textContent='Netzwerkfehler.';});
});
// Solange die DynDNS-Unteransicht sichtbar ist, Status alle 5 s aktualisieren.
setInterval(function(){var p=document.getElementById('psub-svc-dyndns');
  if(p&&p.classList.contains('active'))dynStat();},5000);
})();

// ---- WireGuard-Config (7.4c) ----
(function(){
var wgForm=document.getElementById('wg-form');
if(!wgForm)return;
var wgMsg=document.getElementById('wg-msg');
wgForm.addEventListener('submit',function(e){
  e.preventDefault();
  if(wgMsg)wgMsg.textContent='Speichere ...';
  var q=['mode=server'];
  var ac=document.getElementById('wg-active');if(ac&&ac.checked)q.push('active=1');
  var lg=document.getElementById('wg-langw');if(lg&&lg.checked)q.push('langw=1');
  function adWG(id,name){var el=document.getElementById(id);if(el)q.push(name+'='+encodeURIComponent(el.value));}
  adWG('wg-underlay','underlay');adWG('wg-localip','localip');adWG('wg-privkey','privkey');
  adWG('wg-peerpub','peerpub');adWG('wg-psk','psk');adWG('wg-epport','epport');
  adWG('wg-allowed','allowed');adWG('wg-keepalive','keepalive');adWG('wg-routing','routing');
  adWG('wg-lantgt','lantgt');
  fetch('/wg-save',{method:'POST',cache:'no-store',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},body:q.join('&')})
    .then(function(r){return r.json();})
    .then(function(d){if(wgMsg)wgMsg.textContent=(d&&d.msg)||'Gespeichert.';
      secretSaved('wg-privkey');
      secretSaved('wg-psk');})
    .catch(function(){if(wgMsg)wgMsg.textContent='Netzwerkfehler.';});
});
})();

// ---- WireGuard-Verbindung (7.4d) ----
(function(){
  if(!document.getElementById('tab-vpn-srv'))return;   // Wurzel-Guard: nur Server > VPN (3-s-Poll)
  function setW(id,v){var e=document.getElementById(id);if(e)e.textContent=v;}
  var cm=document.getElementById('wg-conn-msg');
  var cn=document.getElementById('wg-connect');
  var dc=document.getElementById('wg-disconnect');
  // FritzBox-Stil: der Aktivieren-Schalter klappt den Konfig-Bereich auf/zu.
  var sa=document.getElementById('wg-active');
  var scfg=document.getElementById('wg-srv-cfg');
  function syncSrv(){if(scfg&&sa)scfg.style.display=sa.checked?'':'none';}
  if(sa)sa.addEventListener('change',syncSrv);
  // LAN-Gateway-Ziel nur zeigen, wenn LAN-Gateway aktiv ist.
  var lg=document.getElementById('wg-langw');
  var ltr=document.getElementById('wg-lantgt-row');
  function syncLan(){if(ltr&&lg)ltr.style.display=lg.checked?'':'none';}
  if(lg)lg.addEventListener('change',syncLan);
  if(cn)cn.addEventListener('click',function(){
    if(cm)cm.textContent='Server startet ...';
    fetch('/wg-connect',{method:'POST',cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(cm)cm.textContent=(d&&d.msg)||'';}).catch(function(){if(cm)cm.textContent='Netzwerkfehler.';});
  });
  if(dc)dc.addEventListener('click',function(){
    if(cm)cm.textContent='Server stoppt ...';
    fetch('/wg-disconnect',{method:'POST',cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(cm)cm.textContent=(d&&d.msg)||'';}).catch(function(){if(cm)cm.textContent='Netzwerkfehler.';});
  });
  var cg=document.getElementById('wg-clientgen');
  var qm=document.getElementById('wg-qr-msg');
  var lastConf='';
  if(cg)cg.addEventListener('click',function(){
    if(qm)qm.textContent='Erzeuge Geraet ...';
    cg.disabled=true;
    var nm=document.getElementById('wg-cname');
    var body=(nm&&nm.value)?('name='+encodeURIComponent(nm.value)):'';
    fetch('/wg-client-gen',{method:'POST',cache:'no-store',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body}).then(function(r){return r.json();})
      .then(function(d){
        cg.disabled=false;
        if(!d||!d.ok){if(qm)qm.textContent=(d&&d.msg)||'Fehler.';return;}
        lastConf=d.conf||'';
        if(qm)qm.textContent='Fertig - in der WireGuard-App per QR scannen bzw. .conf importieren.';
        var q=document.getElementById('wg-qr');if(q)q.innerHTML=d.svg||'';
        var c=document.getElementById('wg-qr-conf');if(c)c.textContent=lastConf;
        var w=document.getElementById('wg-qr-wrap');if(w)w.style.display='';
        if(nm)nm.value='';
        loadClients();
      }).catch(function(){cg.disabled=false;if(qm)qm.textContent='Netzwerkfehler.';});
  });
  // 7.9.2: Client-Liste laden/rendern (Name, IP, Handshake-Status, Entfernen).
  function escH(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  function loadClients(){
    var box=document.getElementById('wg-clients');if(!box)return;
    fetch('/wg-clients.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(list){
        if(!list||!list.length){box.innerHTML='<div><span>Noch keine Geraete</span><span></span></div>';return;}
        var h='';
        for(var i=0;i<list.length;i++){var c=list[i];
          var rx=(c.rxAgo!=null&&c.rxAgo>=0)?('RX vor '+c.rxAgo+'s'):'RX nie';
          var tx=(c.txAgo!=null&&c.txAgo>=0)?('TX vor '+c.txAgo+'s'):'TX nie';
          h+='<div><span>'+escH(c.name)+' <small>('+c.ip+')</small></span><span>'
            +(c.up?'<b style="color:#2e9e5b">verbunden</b>':'wartet')
            +' <small>'+rx+' / '+tx+'</small>'
            +' <button class="cam-button wg-del" type="button" data-i="'+c.i+'">Entfernen</button></span></div>';
        }
        box.innerHTML=h;
      }).catch(function(){});
  }
  var cbox=document.getElementById('wg-clients');
  if(cbox)cbox.addEventListener('click',function(e){
    var b=e.target&&e.target.classList&&e.target.classList.contains('wg-del')?e.target:null;
    if(!b)return;
    if(!window.confirm('Geraet entfernen?'))return;
    fetch('/wg-client-del',{method:'POST',cache:'no-store',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'i='+encodeURIComponent(b.dataset.i)})
      .then(function(r){return r.json();}).then(function(){loadClients();}).catch(function(){});
  });
  var dl=document.getElementById('wg-dl-conf');
  if(dl)dl.addEventListener('click',function(){
    if(!lastConf)return;
    var b=new Blob([lastConf],{type:'application/octet-stream'});
    var u=URL.createObjectURL(b);
    var a=document.createElement('a');a.href=u;a.download='mcu-wireguard.conf';
    document.body.appendChild(a);a.click();document.body.removeChild(a);
    setTimeout(function(){URL.revokeObjectURL(u);},1000);
  });
  var ml=document.getElementById('wg-mail-conf');
  if(ml)ml.addEventListener('click',function(){
    if(!lastConf)return;
    window.location.href='mailto:?subject='+encodeURIComponent('WireGuard-Zugang')
      +'&body='+encodeURIComponent(lastConf);
  });
  function pollW(){
    var p=document.getElementById('psub-vpnsrv-wg');
    if(!p||!p.classList.contains('active'))return;
    fetch('/wg-status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d)return;
        // Diese Seite ist der Server. Laeuft gerade der Client-Modus, ist der Server gestoppt.
        // Status steht nur noch auf der Uebersicht (/vpn-status.json); hier nur Public Key + Clients.
        setW('wg-mcupub',d.mcuPub||'-');
        loadClients();
      }).catch(function(){});
  }
  setInterval(pollW,3000);
})();

// ---- VPN-Client (7.9): Dienste > VPN ----
(function(){
  var f=document.getElementById('wgc-form');
  if(!f)return;                                        // Wurzel-Guard: nur Dienste > VPN (3-s-Poll)
  function setC(id,v){var e=document.getElementById(id);if(e)e.textContent=v;}
  var msg=document.getElementById('wgc-msg');
  var ca=document.getElementById('wgc-active');
  var ccfg=document.getElementById('wg-cli-cfg');
  function syncCli(){if(ccfg&&ca)ccfg.style.display=ca.checked?'':'none';}
  if(ca)ca.addEventListener('change',syncCli);
  f.addEventListener('submit',function(e){
    e.preventDefault();
    if(msg)msg.textContent='Speichere ...';
    var q=['mode=client'];
    if(ca&&ca.checked)q.push('active=1');
    function ad(id,name){var el=document.getElementById(id);if(el)q.push(name+'='+encodeURIComponent(el.value));}
    ad('wgc-ephost','ephost');ad('wgc-epport','epport');ad('wgc-peerpub','peerpub');
    ad('wgc-allowed','allowed');ad('wgc-psk','psk');ad('wgc-localip','localip');ad('wgc-underlay','underlay');
    fetch('/wg-save',{method:'POST',cache:'no-store',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},body:q.join('&')})
      .then(function(r){return r.json();})
      .then(function(d){if(msg)msg.textContent=(d&&d.msg)||'Gespeichert.';
        secretSaved('wgc-psk');})
      .catch(function(){if(msg)msg.textContent='Netzwerkfehler.';});
  });
  var cm=document.getElementById('wgc-conn-msg');
  var cn=document.getElementById('wgc-connect');
  var dc=document.getElementById('wgc-disconnect');
  if(cn)cn.addEventListener('click',function(){
    if(cm)cm.textContent='Verbinde ...';
    fetch('/wg-connect',{method:'POST',cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(cm)cm.textContent=(d&&d.msg)||'';}).catch(function(){if(cm)cm.textContent='Netzwerkfehler.';});
  });
  if(dc)dc.addEventListener('click',function(){
    if(cm)cm.textContent='Trenne ...';
    fetch('/wg-disconnect',{method:'POST',cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(cm)cm.textContent=(d&&d.msg)||'';}).catch(function(){if(cm)cm.textContent='Netzwerkfehler.';});
  });
  function pollC(){
    var p=document.getElementById('psub-vpncli-wg');
    if(!p||!p.classList.contains('active'))return;
    fetch('/wg-status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d)return;
        // Status steht nur noch auf der Uebersicht (/vpn-status.json); hier nur der Public Key.
        setC('wgc-mcupub',d.mcuPub||'-');
      }).catch(function(){});
  }
  setInterval(pollC,3000);
})();

// ---- IPsec-Client (8.1): Dienste > VPN > IPsec ----
(function(){
  function setC(id,v){var e=document.getElementById(id);if(e)e.textContent=v;}
  var f=document.getElementById('ipsc-form');
  if(!f)return;
  var msg=document.getElementById('ipsc-msg');
  var ca=document.getElementById('ipsc-active');
  var cfg=document.getElementById('ipsc-cfg');
  function sync(){if(cfg&&ca)cfg.style.display=ca.checked?'':'none';}
  if(ca)ca.addEventListener('change',sync);
  f.addEventListener('submit',function(e){
    e.preventDefault();
    if(msg)msg.textContent='Speichere ...';
    var q=['mode=client','fv2=1'];
    if(ca&&ca.checked)q.push('active=1');
    function ad(id,name){var el=document.getElementById(id);if(el)q.push(name+'='+encodeURIComponent(el.value));}
    ad('ipsc-proto','proto');ad('ipsc-srvhost','srvhost');ad('ipsc-srvport','srvport');ad('ipsc-auth','auth');
    ad('ipsc-eapuser','eapuser');ad('ipsc-eappass','eappass');ad('ipsc-capem','capem');ad('ipsc-psk','psk');ad('ipsc-rsubnets','rsubnets');
    q.push('fv5=1');storeCerts();ad('ipsc-trust','trust');ad('ipsc-extrapem','extrapem');   // Trust-Modell + zweiter PEM-Block
    ad('ipsc-localid','localid');ad('ipsc-remoteid','remoteid');
    ad('ipsc-underlay','underlay');ad('ipsc-localtip','localtip');ad('ipsc-localidt','localidt');ad('ipsc-remoteidt','remoteidt');
    var nt=document.getElementById('ipsc-natt');if(nt&&nt.checked)q.push('natt=1');
    q.push('fv4=1');var ac=document.getElementById('ipsc-autoconn');if(ac&&ac.checked)q.push('autoconn=1');
    // IKEv2-Richtlinie (LANCOM-Raster): CSV der angehakten Algorithmen je Gruppe (ausgegraute sind disabled).
    q.push('fv3=1');
    function csv(cls){var a=[];document.querySelectorAll('input.'+cls+':checked:not([data-unsupported])').forEach(function(x){a.push(x.value);});return a.join(',');}
    q.push('ikedh='+csv('ipsc-ikedh'));q.push('ikeenc='+csv('ipsc-ikeenc'));q.push('ikehash='+csv('ipsc-ikehash'));
    q.push('espenc='+csv('ipsc-espenc'));q.push('esphash='+csv('ipsc-esphash'));ad('ipsc-pfs','pfs');
    // Lebensdauern / DPD / NAT-T (fv6 = Marker fuer alte Formulare; dpd ist eine Checkbox: fehlt = aus)
    q.push('fv6=1');ad('ipsc-ikelt','ikelt');ad('ipsc-childlt','childlt');ad('ipsc-childmb','childmb');
    ad('ipsc-dpdint','dpdint');ad('ipsc-dpdretry','dpdretry');ad('ipsc-natka','natka');
    var dp=document.getElementById('ipsc-dpd');if(dp&&dp.checked)q.push('dpd=1');
    fetch('/ipsec-save',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:q.join('&')})
      .then(function(r){return r.json();}).then(function(d){if(msg)msg.textContent=(d&&d.msg)||'Gespeichert.';
        if(d&&d.ok){secretSaved('ipsc-psk');secretSaved('ipsc-eappass');}
        if(d&&d.ok&&saveThenConnect){saveThenConnect=false;connAction('/ipsec-connect',null);}
        saveThenConnect=false;})
      .catch(function(){saveThenConnect=false;if(msg)msg.textContent='Netzwerkfehler.';});
  });
  // "Speichern & neu verbinden": erst speichern, bei Erfolg /ipsec-connect (zwei getrennte Kommandos).
  var saveThenConnect=false;
  var sc=document.getElementById('ipsc-save-connect');
  if(sc)sc.addEventListener('click',function(){saveThenConnect=true;if(f.requestSubmit)f.requestSubmit();else f.dispatchEvent(new Event('submit',{cancelable:true}));});
  // Identitaetszeilen: Typ bestimmt, ob ein Wert einzugeben ist (Uplink-IP / keine Server-ID -> Feld aus).
  function idRow(selId,inpId){
    var s=document.getElementById(selId),i=document.getElementById(inpId);if(!s||!i)return;
    function upd(){var o=s.options[s.selectedIndex];var needs=!o||o.getAttribute('data-needs')!=='0';
      i.disabled=!needs;i.placeholder=o?(o.getAttribute('data-ph')||''):'';if(!needs)i.value='';}
    s.addEventListener('change',upd);upd();
  }
  idRow('ipsc-localidt','ipsc-localid');idRow('ipsc-remoteidt','ipsc-remoteid');
  // Authentifizierung bestimmt die SICHTBARKEIT: PSK -> nur PSK-Feld; EAP -> Benutzer/Passwort + Trust-Modell.
  // Nur display:none -- Werte bleiben erhalten und werden weiter mitgesendet (nichts wird geloescht).
  // IDi-Typ 'EAP-Benutzername verwenden' gibt es nur bei EAP; 'aktuelle Uplink-IP' nicht bei EAP.
  var au=document.getElementById('ipsc-auth');
  function authSync(){var v=au?au.value:'psk';function sh(id,on){var e=document.getElementById(id);if(e)e.style.display=on?'':'none';}
    sh('ipsc-eapfields',v==='eap');sh('ipsc-trustblock',v==='eap');sh('ipsc-pskfields',v!=='eap');
    var s=document.getElementById('ipsc-localidt');if(s){for(var i=0;i<s.options.length;i++){var o=s.options[i];
      if(o.value==='eapuser')o.disabled=(v!=='eap');if(o.value==='sourceip')o.disabled=(v==='eap');}}}
  if(au){au.addEventListener('change',authSync);authSync();}
  // Trust-Modell: vier Buttons -> verstecktes Feld + Panes. Zertifikat-Editor arbeitet auf GENAU zwei
  // PEM-Bloecken (capem = Anker, extrapem = Kettenmaterial); der Haken verschiebt nur zwischen beiden.
  var tb=document.getElementById('ipsc-trustbar'),th=document.getElementById('ipsc-trust');
  var capem=document.getElementById('ipsc-capem'),expem=document.getElementById('ipsc-extrapem');
  function esc(s){return String(s).replace(/[&<>"']/g,function(ch){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];});}
  function pemBlocks(t){var a=[],re=/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,m;while((m=re.exec(t||'')))a.push(m[0]);return a;}
  var certs=[];
  function loadCerts(){certs=[];pemBlocks(capem&&capem.value).forEach(function(p){certs.push({pem:p,anchor:true});});
    pemBlocks(expem&&expem.value).forEach(function(p){certs.push({pem:p,anchor:false});});}
  function storeCerts(){if(!capem||!expem)return;
    capem.value=certs.filter(function(c){return c.anchor;}).map(function(c){return c.pem;}).join('\n');
    expem.value=certs.filter(function(c){return !c.anchor;}).map(function(c){return c.pem;}).join('\n');}
  function certType(i){if(!i)return '';if(i.error)return 'nicht lesbar';
    return i.selfSigned?(i.ca?'selbstsignierte CA (Root)':'selbstsigniertes Serverzertifikat'):(i.ca?'CA-/Zwischenzertifikat':'Serverzertifikat (exakt)');}
  function renderCerts(){var l=document.getElementById('ipsc-certlist');if(!l)return;l.innerHTML='';
    if(!certs.length){l.innerHTML="<div class='hint'>Keine Zertifikate hinterlegt.</div>";return;}
    certs.forEach(function(c,i){var d=document.createElement('div');d.className='cert-row';var inf=c.info||{};
      d.innerHTML="<div class='cert-main'><strong>"+esc(inf.subject||(inf.error?'Zertifikat':'(wird gelesen ...)'))+"</strong>"+
        "<div class='hint'>"+esc(certType(inf))+(inf.issuer&&!inf.selfSigned?' &middot; Aussteller: '+esc(inf.issuer):'')+
        (inf.validTo?' &middot; gueltig bis '+esc(inf.validTo):'')+(inf.error?" &middot; <span class='warn'>"+esc(inf.error)+"</span>":'')+"</div>"+
        "<label class='check-row cert-anchor'><input type='checkbox'"+(c.anchor?' checked':'')+"><span>Diesem Zertifikat als Vertrauensanker vertrauen (die Kette darf hier enden)</span></label></div>"+
        "<button type='button' class='cert-del' title='Entfernen'>&times;</button>";
      d.querySelector('input').addEventListener('change',function(e){c.anchor=e.target.checked;storeCerts();});
      d.querySelector('.cert-del').addEventListener('click',function(){certs.splice(i,1);storeCerts();renderCerts();});
      l.appendChild(d);});}
  function infoCerts(list,cb){var need=list.filter(function(c){return !c.info;});if(!need.length){cb();return;}
    fetch('/ipsec-certinfo',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'pem='+encodeURIComponent(need.map(function(c){return c.pem;}).join('\n'))})
      .then(function(r){return r.json();}).then(function(d){var arr=(d&&d.certs)||[];need.forEach(function(c,i){c.info=arr[i]||{error:'nicht lesbar'};});cb();})
      .catch(function(){need.forEach(function(c){c.info={error:'keine Antwort vom Geraet'};});cb();});}
  function addPem(text){var nb=pemBlocks(text),added=[];
    nb.forEach(function(p){if(certs.some(function(c){return c.pem===p;}))return;var c={pem:p,anchor:false};certs.push(c);added.push(c);});
    renderCerts();
    // Vorauswahl: selbstsigniertes Zertifikat (Root-CA oder selbstsigniertes Serverzertifikat) = Anker; alles andere = Kettenmaterial
    infoCerts(added,function(){added.forEach(function(c){if(c.info&&c.info.selfSigned&&!c.info.error)c.anchor=true;});storeCerts();renderCerts();});
    return nb.length;}
  function setTrust(v){if(th)th.value=v;
    if(tb)tb.querySelectorAll('.opt-btn').forEach(function(b){b.classList.toggle('active',b.getAttribute('data-val')===v);});
    document.querySelectorAll('.trust-pane').forEach(function(p){p.style.display=p.getAttribute('data-pane')===v?'':'none';});
    var ed=document.getElementById('ipsc-certeditor');if(ed)ed.style.display=(v==='public-plus'||v==='own')?'':'none';}
  if(tb){tb.querySelectorAll('.opt-btn').forEach(function(b){b.addEventListener('click',function(){setTrust(b.getAttribute('data-val'));});});setTrust(th?th.value:'public');}
  loadCerts();renderCerts();infoCerts(certs,function(){renderCerts();});
  var ab=document.getElementById('ipsc-certadd-btn'),at=document.getElementById('ipsc-certadd');
  if(ab&&at)ab.addEventListener('click',function(){if(!addPem(at.value)){if(msg)msg.textContent='Kein PEM-Zertifikat erkannt (-----BEGIN CERTIFICATE-----).';return;}at.value='';if(msg)msg.textContent='';});
  var cf=document.getElementById('ipsc-certfile');
  if(cf)cf.addEventListener('change',function(){Array.prototype.forEach.call(cf.files,function(f){var rd=new FileReader();
    rd.onload=function(){if(!addPem(rd.result)&&msg)msg.textContent='Datei '+f.name+': kein PEM-Zertifikat erkannt (DER/PKCS#12 werden nicht gelesen).';};rd.readAsText(f);});cf.value='';});
  function poll(){
    var p=document.getElementById('psub-vpncli-ipsec');
    if(!p||!p.classList.contains('active'))return;
    fetch('/ipsec-status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d)return;
        // Status steht nur noch auf der Uebersicht (/vpn-status.json); hier nur das IKE-Protokoll (Werkzeug).
        var rt=d.rt||{};
        var lg=document.getElementById('ipsc-log');if(lg)lg.textContent=(rt.log&&rt.log.length)?rt.log.join('\n'):'-';
      }).catch(function(){});
  }
  setInterval(poll,3000);
  // ---- Neu verbinden / Trennen (POST /ipsec-connect, /ipsec-disconnect; Ausfuehrung im loop-Task) ----
  function connAction(url,btn){
    var m=document.getElementById('ipsc-conn-msg');if(m)m.textContent='...';
    if(btn)btn.disabled=true;
    fetch(url,{method:'POST',cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(btn)btn.disabled=false;if(m)m.textContent=(d&&d.msg)||(d&&d.ok?'OK':'Fehler');})
      .catch(function(){if(btn)btn.disabled=false;if(m)m.textContent='Netzwerkfehler.';});
  }
  var cb=document.getElementById('ipsc-connect-btn');if(cb)cb.addEventListener('click',function(){connAction('/ipsec-connect',cb);});
  var db=document.getElementById('ipsc-disconnect-btn');if(db)db.addEventListener('click',function(){connAction('/ipsec-disconnect',db);});
  // ---- Test-Ping: Combobox mit Ziel-Historie (auf dem Geraet, /ipsec-ping-history.json) ----
  var cin=document.getElementById('ipsc-ping-target'),clist=document.getElementById('ipsc-ping-list'),ctg=document.getElementById('ipsc-ping-toggle');
  var items=[],sel=-1;
  function crender(){
    if(!clist)return;clist.innerHTML='';
    if(!items.length){var e=document.createElement('div');e.className='combo-empty';e.textContent='keine gespeicherten Ziele';clist.appendChild(e);return;}
    items.forEach(function(v,i){
      var d=document.createElement('div');d.className='combo-item'+(i===sel?' sel':'');d.textContent=v;
      d.addEventListener('mousedown',function(ev){ev.preventDefault();if(cin)cin.value=v;cclose();});
      d.addEventListener('mouseenter',function(){sel=i;var ch=clist.children;for(var k=0;k<ch.length;k++)ch[k].classList.toggle('sel',k===i);});
      clist.appendChild(d);
    });
  }
  function copen(){if(!clist)return;clist.hidden=false;sel=-1;crender();}
  function cclose(){if(clist)clist.hidden=true;sel=-1;}
  function cload(cb){
    fetch('/ipsec-ping-history.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){items=(d&&d.targets)||[];if(cb)cb();else crender();}).catch(function(){});
  }
  function cdel(){
    if(sel<0||sel>=items.length)return;var v=items[sel];
    fetch('/ipsec-ping-history',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'del='+encodeURIComponent(v)})
      .then(function(r){return r.json();}).then(function(d){items=(d&&d.targets)||[];if(sel>=items.length)sel=items.length-1;crender();}).catch(function(){});
  }
  if(ctg)ctg.addEventListener('mousedown',function(e){e.preventDefault();if(!clist)return;if(clist.hidden){cload(copen);if(cin)cin.focus();}else cclose();});
  if(cin){
    cin.addEventListener('keydown',function(e){
      var open=clist&&!clist.hidden;
      if(e.key==='ArrowDown'){e.preventDefault();if(!open){cload(function(){copen();sel=items.length?0:-1;crender();});}else if(items.length){sel=Math.min(sel+1,items.length-1);crender();}}
      else if(e.key==='ArrowUp'){if(!open)return;e.preventDefault();if(items.length){sel=Math.max(sel-1,0);crender();}}
      else if(e.key==='Enter'){if(open&&sel>=0&&sel<items.length){e.preventDefault();cin.value=items[sel];cclose();}}
      else if(e.key==='Escape'){if(open){e.preventDefault();cclose();}}
      else if(e.key==='Delete'&&e.shiftKey){if(open&&sel>=0){e.preventDefault();cdel();}}
    });
    cin.addEventListener('blur',function(){setTimeout(cclose,150);});
  }
  var pb=document.getElementById('ipsc-ping-btn');
  if(pb)pb.addEventListener('click',function(){
    var t=cin;var res=document.getElementById('ipsc-ping-res');
    var tv=t?t.value.trim():'';if(!tv){if(res)res.textContent='Ziel-IP eingeben.';return;}
    if(res)res.textContent='Ping laeuft ...';
    pb.disabled=true;pb.classList.add('busy');
    fetch('/ipsec-ping',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'target='+encodeURIComponent(tv)})
      .then(function(r){return r.json();}).then(function(d){
        pb.disabled=false;pb.classList.remove('busy');
        cload();   // Ziel ist jetzt in der Geraete-Historie
        if(!res)return;
        if(d&&d.ok)res.textContent='OK - RTT '+d.rttMs+' ms (ESP TX-Seq '+d.txSeq+', RX-Seq '+d.rxSeq+')';
        else res.textContent='Fehlgeschlagen: '+((d&&d.detail)||'?')+((d&&d.stage)?(' ['+d.stage+']'):'');
      }).catch(function(){pb.disabled=false;pb.classList.remove('busy');if(res)res.textContent='Netzwerkfehler.';});
  });
})();

// ---- IPsec-Server (8.1): Server > VPN > IPsec ----
(function(){
  function setC(id,v){var e=document.getElementById(id);if(e)e.textContent=v;}
  var f=document.getElementById('ipss-form');
  if(!f)return;
  var msg=document.getElementById('ipss-msg');
  var ca=document.getElementById('ipss-active');
  var cfg=document.getElementById('ipss-cfg');
  function sync(){if(cfg&&ca)cfg.style.display=ca.checked?'':'none';}
  if(ca)ca.addEventListener('change',sync);
  f.addEventListener('submit',function(e){
    e.preventDefault();
    if(msg)msg.textContent='Speichere ...';
    var q=['mode=server'];
    if(ca&&ca.checked)q.push('active=1');
    function ad(id,name){var el=document.getElementById(id);if(el)q.push(name+'='+encodeURIComponent(el.value));}
    ad('ipss-listen','listenport');ad('ipss-pool','poolsub');ad('ipss-psk','psk');ad('ipss-ident','srvident');
    fetch('/ipsec-save',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:q.join('&')})
      .then(function(r){return r.json();}).then(function(d){if(msg)msg.textContent=(d&&d.msg)||'Gespeichert.';
        secretSaved('ipss-psk');})
      .catch(function(){if(msg)msg.textContent='Netzwerkfehler.';});
  });
  function renderUsers(us){
    var box=document.getElementById('ipss-users');if(!box)return;
    if(!us||!us.length){box.innerHTML='<p class="cam-hint">Noch keine Benutzer.</p>';return;}
    var h='<div class="info">';
    us.forEach(function(u,i){h+='<div><span>'+((u.name||'').replace(/[<>&]/g,''))+'</span><span><button class="cam-button ipss-udel" data-i="'+i+'" type="button">Entfernen</button></span></div>';});
    h+='</div>';box.innerHTML=h;
    Array.prototype.forEach.call(document.querySelectorAll('.ipss-udel'),function(b){
      b.addEventListener('click',function(){
        fetch('/ipsec-user-del',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'i='+b.getAttribute('data-i')})
          .then(function(r){return r.json();}).then(function(d){if(d&&d.users)renderUsers(d.users);}).catch(function(){});
      });
    });
  }
  var add=document.getElementById('ipss-uadd');
  if(add)add.addEventListener('click',function(){
    var el=document.getElementById('ipss-uname');var n=el?el.value:'';
    if(!n)return;
    fetch('/ipsec-user-add',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'name='+encodeURIComponent(n)})
      .then(function(r){return r.json();}).then(function(d){if(el)el.value='';if(d&&d.users)renderUsers(d.users);if(d&&!d.ok&&msg)msg.textContent=(d.msg||'Fehler');}).catch(function(){});
  });
  var seeded=false;
  function poll(){
    var p=document.getElementById('psub-vpnsrv-ipsec');
    if(!p||!p.classList.contains('active'))return;
    fetch('/ipsec-status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d)return;
        // Status steht nur noch auf der Uebersicht (/vpn-status.json); hier nur die Benutzerliste.
        if(d.users){renderUsers(d.users);}
      }).catch(function(){});
  }
  setInterval(poll,3000);
})();

// ---- Zugriff je Dienst (System -> Sicherheit): <svc>_vpn / <svc>_inet ----
(function(){
var accForm=document.getElementById('access-form');
if(!accForm)return;
var accMsg=document.getElementById('access-msg');
accForm.addEventListener('submit',function(e){
  e.preventDefault();
  if(accMsg)accMsg.textContent='Speichere ...';
  var q=[];accForm.querySelectorAll('input[type=checkbox]:checked').forEach(function(x){q.push(encodeURIComponent(x.name)+'=1');});
  fetch('/access-save',{method:'POST',cache:'no-store',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},body:q.join('&')})
    .then(function(r){return r.json();})
    .then(function(d){if(accMsg)accMsg.textContent=(d&&d.msg)||'Gespeichert.';})
    .catch(function(){if(accMsg)accMsg.textContent='Netzwerkfehler.';});
});
})();

// ---- Zertifikat (System -> Sicherheit): Herkunft self-signed / eigenes / Let's Encrypt ----
(function(){
  var applyBtn=document.getElementById('cert-apply'); if(!applyBtn)return;
  var msg=document.getElementById('acme-msg');
  function set(id,v){var e=document.getElementById(id);if(e)e.textContent=v;}
  function show(id,on){var e=document.getElementById(id);if(e)e.style.display=on?'':'none';}
  function radioVal(name){var r=document.querySelector('input[name="'+name+'"]:checked');return r?r.value:'';}
  function fmtTs(ts){ if(!ts||ts<100000)return '-'; var d=new Date(ts*1000); return d.toISOString().slice(0,10); }
  function post(url,body,cb){
    fetch(url,{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body||''})
      .then(function(r){return r.json();}).then(function(d){ if(msg)msg.textContent=(d&&(d.msg||d.error))||'Fertig.'; if(cb)cb(d); })
      .catch(function(){ if(msg)msg.textContent='Fehler.'; });
  }
  // Panels nach Radiowahl ein-/ausblenden.
  function refreshPanels(){
    var top=radioVal('certsrc');       // own | acme
    var own=radioVal('certown');       // self | upload
    show('cert-own', top==='own');
    show('cert-acme', top==='acme');
    show('cert-self', top==='own' && own==='self');
    show('cert-upload', top==='own' && own==='upload');
  }
  document.querySelectorAll('input[name="certsrc"],input[name="certown"]').forEach(function(r){ r.addEventListener('change',refreshPanels); });
  refreshPanels();

  // Info-Felder (Subjects/Ablaeufe) laden.
  function info(){
    fetch('/cert-info.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();}).then(function(d){
      if(!d||!d.ok)return;
      set('ss-sub', d.ssSubject||'noch keins (wird beim Aktivieren erzeugt)');
      set('ss-exp', fmtTs(d.ssNotAfter));
      set('up-state', d.upPresent?((d.upSubject||'')+', gueltig bis '+fmtTs(d.upNotAfter)):'keins');
    }).catch(function(){});
  }
  // ACME-Statuszeilen (aktiv/cert/clock/port80/letzter Lauf).
  function status(){
    fetch('/acme-status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();}).then(function(d){
      if(!d||!d.ok)return;
      set('ac-active', d.activeCert==='letsencrypt'?'HTTPS mit Let\'s-Encrypt-Zertifikat':(d.activeCert==='selfsigned'?'HTTPS mit eigenem/self-signed Zertifikat':'HTTP (unverschluesselt) -- HTTPS oben aktivieren'));
      set('ac-cert', d.hasCert?((d.subject||'')+', gueltig bis '+d.notAfter+(d.daysLeft>=0?(' ('+d.daysLeft+' Tage)'):'')+(d.usable?'':' -- NICHT nutzbar (Domain/abgelaufen)')):'keins');
      set('ac-clock', d.clockValid?d.clock:'unbekannt -- kommt vom Modem beim Verbinden');
      set('ac-port80', d.httpsActive?(d.port80?'laeuft (Hilfsserver)':(d.enabled?'NICHT aktiv -- nach Neustart (Hilfsserver startet nur mit Let\'s Encrypt)':'aus (startet nach Neustart, sobald Let\'s Encrypt aktiviert ist)')):'= Verwaltung (HTTP-Betrieb)');
      var last=d.running?('laeuft: '+d.state):(d.lastRunAgo>=0?((d.lastOk?'ok':'Fehler')+' vor '+Math.round(d.lastRunAgo/60)+' min -- '+(d.lastOk?d.state:d.lastError)):'noch keiner');
      if(d.restartPending)last+=' | Neustart folgt (neues Zertifikat)';
      set('ac-last', last);
      if(d.running)setTimeout(status,2000);
    }).catch(function(){});
  }

  // ACME-Formular: nur Domain/E-Mail/Staging/TOS speichern (Aktiv-Schalter = Herkunftswahl).
  var f=document.getElementById('acme-form');
  if(f)f.addEventListener('submit',function(e){e.preventDefault(); if(msg)msg.textContent='Speichere ...';
    var q=[];
    q.push('domain='+encodeURIComponent(document.getElementById('acme-domain').value));
    q.push('email='+encodeURIComponent(document.getElementById('acme-email').value));
    if(document.getElementById('acme-staging').checked)q.push('staging=1');
    if(document.getElementById('acme-tos').checked)q.push('tos=1');
    post('/acme-save',q.join('&'),status);
  });
  var run=document.getElementById('acme-run'); if(run)run.addEventListener('click',function(){ if(msg)msg.textContent='Starte ...'; post('/acme-run','',function(){setTimeout(status,1500);}); });
  var clr=document.getElementById('acme-clear'); if(clr)clr.addEventListener('click',function(){ if(!confirm('Let\'s-Encrypt-Zertifikat loeschen? Ab dem naechsten Neustart wieder self-signed.'))return; post('/acme-clear','',status); });

  // Eigenes Zertifikat hochladen/eintragen.
  var upSave=document.getElementById('up-save');
  if(upSave)upSave.addEventListener('click',function(){
    var c=document.getElementById('up-cert').value, k=document.getElementById('up-key').value;
    if(!c||!k){ if(msg)msg.textContent='Zertifikat und Schluessel eintragen.'; return; }
    if(msg)msg.textContent='Pruefe ...';
    post('/cert-upload','cert='+encodeURIComponent(c)+'&key='+encodeURIComponent(k),function(d){ if(d&&d.ok){document.getElementById('up-key').value=''; info();} });
  });
  // self-signed jetzt neu erzeugen.
  var regen=document.getElementById('ss-regen');
  if(regen)regen.addEventListener('click',function(){ if(msg)msg.textContent='Erzeuge ...'; post('/cert-selfsign','',function(){ info(); }); });

  // Herkunft uebernehmen (aktiv nach Neustart).
  applyBtn.addEventListener('click',function(){
    var top=radioVal('certsrc');
    var src=(top==='acme')?'acme':(radioVal('certown')==='upload'?'upload':'self');
    var body='src='+encodeURIComponent(src);
    if(document.getElementById('ss-renew') && document.getElementById('ss-renew').checked)body+='&ssrenew=1';
    if(msg)msg.textContent='Uebernehme ...';
    post('/cert-save',body,function(d){ if(d&&d.restart){ if(msg)msg.textContent=(d.msg||'')+' (Seite laedt nach dem Neustart neu)'; setTimeout(function(){location.reload();},5000);} });
  });

  info(); status();
})();
// ---- Transportverschluesselung (System -> Sicherheit): HTTP <-> HTTPS ----
(function(){
var tpForm=document.getElementById('webhttps-form');
if(!tpForm)return;
var tpMsg=document.getElementById('webhttps-msg');
tpForm.addEventListener('submit',function(e){
  e.preventDefault();
  if(tpMsg)tpMsg.textContent='Speichere ...';
  var cb=document.getElementById('webhttps');
  var body=(cb&&cb.checked)?'https=1':'';
  fetch('/web-transport-save',{method:'POST',cache:'no-store',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
    .then(function(r){return r.json();})
    .then(function(d){
      if(tpMsg)tpMsg.textContent=(d&&d.msg)||'Gespeichert.';
      // Nach dem Neustart wechselt der Port/Transport -> Reload lohnt erst nach ~4 s.
      if(d&&d.restart)setTimeout(function(){location.reload();},4000);
    })
    .catch(function(){if(tpMsg)tpMsg.textContent='Netzwerkfehler.';});
});
})();

// ---- Energie (System -> Energiemonitor -> Einstellungen) ----
(function(){
var enSave=document.getElementById('en-save');
if(!enSave)return;
var enMsg=document.getElementById('en-msg');
enSave.addEventListener('click',function(){
  if(enMsg)enMsg.textContent='Speichere ...';
  var q=[];
  var cpu=document.getElementById('en-cpu');if(cpu)q.push('cpu='+encodeURIComponent(cpu.value));
  var wo=document.getElementById('en-wifioff');if(wo&&wo.checked)q.push('wifioff=1');
  fetch('/energy-save',{method:'POST',cache:'no-store',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},body:q.join('&')})
    .then(function(r){return r.json();})
    .then(function(d){
      if(d&&d.ok){var f=document.getElementById('en-freq');if(f)f.textContent=d.freq+' MHz';
        if(enMsg)enMsg.textContent='Uebernommen ('+d.freq+' MHz).';}
      else if(enMsg)enMsg.textContent='Fehler.';
    })
    .catch(function(){if(enMsg)enMsg.textContent='Netzwerkfehler.';});
});
})();

// ---- Allgemein (System -> Allgemein -> Router-URL) ----
(function(){
var genSave=document.getElementById('gen-save');
if(!genSave)return;
var genMsg=document.getElementById('gen-msg');
genSave.addEventListener('click',function(){
  if(genMsg)genMsg.textContent='Speichere ...';
  var h=document.getElementById('gen-host');
  fetch('/general-save',{method:'POST',cache:'no-store',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'host='+encodeURIComponent(h?h.value:'')})
    .then(function(r){return r.json();})
    .then(function(d){
      if(d&&d.ok){var u=document.getElementById('gen-url');if(u)u.textContent='http://'+d.host+'.local';
        if(genMsg)genMsg.textContent='Gespeichert: '+d.host+'.local (nach Neustart aktiv).';}
      else if(genMsg)genMsg.textContent=(d&&d.msg)||'Fehler.';
    })
    .catch(function(){if(genMsg)genMsg.textContent='Netzwerkfehler.';});
});
})();

// ---- 7.9.14: TLS-Speicher-Schalter (PSRAM/intern), wirkt nach Neustart ----
(function(){
  var cryptoSave=document.getElementById('crypto-save');
  var cryptoMsg=document.getElementById('crypto-msg');
  if(!cryptoSave)return;
  cryptoSave.addEventListener('click',function(){
    var cb=document.getElementById('crypto-psram');
    var h=document.getElementById('gen-host');
    if(cryptoMsg)cryptoMsg.textContent='Speichere ...';
    fetch('/general-save',{method:'POST',cache:'no-store',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'host='+encodeURIComponent(h?h.value:'')+'&cryptomem='+((cb&&cb.checked)?'1':'0')})
      .then(function(r){return r.json();})
      .then(function(d){
        if(d&&d.ok){
          var n=document.getElementById('crypto-now');if(n)n.textContent=(d.cryptomem==='psram')?'PSRAM':'intern';
          if(cryptoMsg)cryptoMsg.textContent=d.reboot
            ?('Gespeichert ('+d.cryptomem+'). Neustart laeuft - Seite in ~15 s neu laden.')
            :('Gespeichert ('+d.cryptomem+'). Keine Aenderung, kein Neustart.');
        } else if(cryptoMsg)cryptoMsg.textContent=(d&&d.msg)||'Fehler.';
      })
      .catch(function(){if(cryptoMsg)cryptoMsg.textContent='Netzwerkfehler.';});
  });
})();

// ---- 8.0: Bluetooth (LE) - Geraetesuche + best-effort-Verbindung ----
(function(){
  var scanBtn=document.getElementById('bt-scan');
  if(!scanBtn)return;
  var relBtn=document.getElementById('bt-release');
  var msg=document.getElementById('bt-msg');
  var list=document.getElementById('bt-list');
  var stateEl=document.getElementById('bt-state');
  var heapEl=document.getElementById('bt-heap');
  var poll=null;
  function fmtHeap(b){return b?((b/1024).toFixed(0)+' KB'):'-';}
  function esc(s){return (s||'').replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function status(){
    fetch('/bt-status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d)return;
        if(stateEl)stateEl.textContent=(d.initialized?'Stack aktiv':'Stack aus')+(d.busy?' - laeuft ...':'')+(d.connResult?(' | '+d.connResult):'');
        if(heapEl)heapEl.textContent=fmtHeap(d.heap);
      }).catch(function(){});
  }
  function render(devs){
    if(!list)return;
    if(!devs||!devs.length){list.innerHTML='<p class="cam-hint">Keine Geraete gefunden.</p>';return;}
    devs.sort(function(a,b){return (b.rssi||-999)-(a.rssi||-999);});
    var AT={0:'oeffentlich',1:'random',2:'oeffentl.-ID',3:'random-ID'};
    var h='';
    devs.forEach(function(d){
      var nm=d.name?esc(d.name):'<em>(kein Name)</em>';
      var at=AT[d.atype]||(d.rnd?'random':'');
      h+='<div class="info"><div><span><strong>'+nm+'</strong>'+(at?(' <small>('+at+')</small>'):'')+'</span><span>'+(d.rssi||0)+' dBm</span></div>';
      h+='<div><span>'+esc(d.addr)+'</span><span>'+(d.svc||0)+' Svc'+(d.mfg?(' | '+esc(d.mfg)):'')+'</span></div>';
      if(d.svc0)h+='<div><span>Service</span><span>'+esc(d.svc0)+'</span></div>';
      h+='<div><span></span><span><button class="cam-button bt-conn" data-addr="'+esc(d.addr)+'" type="button">Verbindungstest</button></span></div></div>';
    });
    list.innerHTML=h;
    Array.prototype.forEach.call(document.querySelectorAll('.bt-conn'),function(b){
      b.addEventListener('click',function(){
        var a=b.getAttribute('data-addr');
        if(msg)msg.textContent='Verbindungsversuch zu '+a+' ...';
        fetch('/bt-connect',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'addr='+encodeURIComponent(a)})
          .then(function(r){return r.json();}).then(function(){setTimeout(status,1500);setTimeout(status,4000);}).catch(function(){});
      });
    });
  }
  function pollScan(){
    fetch('/bt-scan.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d)return;
        if(heapEl)heapEl.textContent=fmtHeap(d.heap);
        render(d.devices||[]);
        if(d.running){if(msg)msg.textContent='Suche laeuft ('+(d.count||0)+' bisher) ...';}
        else{if(msg)msg.textContent='Fertig: '+(d.count||0)+' Geraet(e).';if(poll){clearInterval(poll);poll=null;}status();}
      }).catch(function(){});
  }
  scanBtn.addEventListener('click',function(){
    var el=document.getElementById('bt-secs');
    var secs=parseInt(el&&el.value||'6',10)||6;
    if(msg)msg.textContent='Starte Suche (Stack laedt, WLAN kann kurz zucken) ...';
    fetch('/bt-scan-start',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'secs='+secs})
      .then(function(r){return r.json();}).then(function(){if(poll)clearInterval(poll);poll=setInterval(pollScan,1500);setTimeout(pollScan,800);}).catch(function(){if(msg)msg.textContent='Netzwerkfehler.';});
  });
  if(relBtn)relBtn.addEventListener('click',function(){
    if(msg)msg.textContent='Gebe BT-Stack frei ...';
    fetch('/bt-release',{method:'POST',cache:'no-store'}).then(function(r){return r.json();})
      .then(function(){if(list)list.innerHTML='';if(msg)msg.textContent='BT-Stack freigegeben.';status();}).catch(function(){});
  });
  var nav=document.querySelector('.nav-item[data-tab="bluetooth"]');
  if(nav)nav.addEventListener('click',status);
})();

// ---- Sicherung: Konfig-Export (backup) ----
(function(){var ce=document.getElementById('cfg-export');if(ce)ce.addEventListener('click',function(){window.location='/settings-export';});})();
(function(){var b=document.getElementById('cfg-import'),f=document.getElementById('cfg-import-file'),m=document.getElementById('cfg-import-msg');
if(!b)return;b.addEventListener('click',function(){
if(!f||!f.files||!f.files[0]){if(m)m.textContent='Bitte zuerst eine Sicherungsdatei waehlen.';return;}
if(!confirm('Sicherung einspielen und neu starten? Bestehende Einstellungen werden ueberschrieben.'))return;
var fd=new FormData();fd.append('file',f.files[0]);if(m)m.textContent='Spiele ein ...';
fetch('/settings-import',{method:'POST',cache:'no-store',body:fd}).then(function(r){return r.text();})
.then(function(t){if(m)m.textContent=t;}).catch(function(){if(m)m.textContent='Netzwerkfehler (evtl. schon am Neustarten).';});
});})();

// ---- Ereignisse (events) ----
(function(){
  if(!document.getElementById('tab-diagsys'))return;   // Wurzel-Guard: nur Diagnose > System
  var b=document.getElementById('ev-refresh'),o=document.getElementById('ev-out');
  function fmtT(s){var m=Math.floor(s/60),h=Math.floor(m/60);return (h>0?(h+':'):'')+('0'+(m%60)).slice(-2)+':'+('0'+(s%60)).slice(-2);}
  function load(){
    fetch('/events.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d||!d.ok||!o)return;
        o.textContent=(d.events||[]).map(function(e){return '['+fmtT(e.t)+'] '+e.m;}).join('\n')||'(keine Ereignisse)';
      }).catch(function(){});
  }
  if(b)b.addEventListener('click',load);
  // Diagnose > System: laden beim Seitenaufruf UND beim Klick auf den Tab "Ereignisse".
  var t=document.querySelector('.nav-item[data-tab="diagsys"]');
  if(t)t.addEventListener('click',load);
  var tb=document.querySelector('#tab-diagsys .tab[data-psub="ds-events"]');
  if(tb)tb.addEventListener('click',load);
})();

// ---- Online-Monitor (onlinemon) ----
(function(){
  if(!document.getElementById('tab-overview'))return;   // Wurzel-Guard: nur die Uebersicht (2-s-Poll)
  function set(id,v){var e=document.getElementById(id);if(e)e.textContent=v;}
  function fmtB(n){if(n==null)return '-';if(n>=1048576)return (n/1048576).toFixed(1)+' MB';if(n>=1024)return (n/1024).toFixed(1)+' KB';return n+' B';}
  function fmtFix(k){return (k==null)?'-':(k/1000).toFixed(2);}   // nur die Zahl (Mbit/s); Einheit steht einmal hinter dem Paar
  function load(){
    var p=document.getElementById('tab-overview');
    if(!p||!p.classList.contains('active'))return;
    fetch('/modem-status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d)return;
        if(d.status!=null)set('modem-status',d.status);   // USB-/Modem-Status (Uebersicht, live)
        set('om-ppp',d.wanstatus||d.ppp||'-');set('om-ip',d.wanip||d.pppip||'-');
        // "aktuell / max" in EINER Zeile: immer Mbit/s mit 2 Nachkommastellen; feste Mindestbreite +
        // tabular-nums per CSS (.om-num) -> Komma und "/" wandern nicht. Einheit einmal am Ende.
        set('om-rx',fmtFix(d.rxkbit));set('om-tx',fmtFix(d.txkbit));
        set('om-rxmax',fmtFix(d.maxrxkbit));set('om-txmax',fmtFix(d.maxtxkbit));
        set('om-rxtot',fmtB(d.rxbytes));set('om-txtot',fmtB(d.txbytes));
      }).catch(function(){});
  }
  setInterval(load,2000);
  var t=document.querySelector('.nav-item[data-tab="overview"]');
  if(t)t.addEventListener('click',load);
  var rb=document.getElementById('om-reset');
  if(rb)rb.addEventListener('click',function(){
    fetch('/modem-rate-reset',{method:'POST',cache:'no-store'}).then(function(){load();}).catch(function(){});
  });
})();

// ---- VPN-Status (Uebersicht, EIN Modell fuer alle Tunnel: /vpn-status.json) ----
(function(){
  if(!document.getElementById('tab-overview'))return;   // Wurzel-Guard: nur die Uebersicht (3-s-Poll)
  function set(id,v){var e=document.getElementById(id);if(e)e.textContent=v;}
  function fmtB(n){if(n==null)return '-';if(n>=1048576)return (n/1048576).toFixed(1)+' MB';if(n>=1024)return (n/1024).toFixed(1)+' KB';return n+' B';}
  function line(v){
    if(!v)return '-';
    var s=(v.role==='server'?'Server: ':'Client: ')+(v.stateText||v.state||'-');
    if(!v.active)return s;
    if(v.endpoint)s+=' · '+v.endpoint;
    if(v.underlay)s+=' · via '+v.underlay;
    if(v.tunnelIp)s+=' · Tunnel-IP '+v.tunnelIp;
    if(v.peer)s+=' · Peer '+v.peer;
    if(v.hasTraffic)s+=' · '+v.txPackets+'/'+v.rxPackets+' Pk ('+fmtB(v.txBytes)+' / '+fmtB(v.rxBytes)+')';
    return s;
  }
  function load(){
    var p=document.getElementById('tab-overview');
    if(!p||!p.classList.contains('active'))return;
    fetch('/vpn-status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d||!d.ok||!d.vpn)return;
        var det=[];
        d.vpn.forEach(function(v){
          var id=(v.service==='WireGuard')?'vpn-wg':'vpn-ipsec';
          set(id,line(v));
          if(v.detail)det.push(v.service+': '+v.detail);
          if(v.error)det.push(v.service+' Fehler: '+v.error);
        });
        set('vpn-detail',det.join(' — '));
      }).catch(function(){});
  }
  setInterval(load,3000);
  var t=document.querySelector('.nav-item[data-tab="overview"]');
  if(t)t.addEventListener('click',load);
  var b=document.getElementById('vpn-refresh');
  if(b)b.addEventListener('click',load);
  load();
})();

// ---- Systemstatus (Uebersicht > System, /sysinfo.json) ----
(function(){
  if(!document.getElementById('tab-overview'))return;   // Wurzel-Guard: nur die Uebersicht
  var b=document.getElementById('si-refresh');
  function set(id,v){var e=document.getElementById(id);if(e)e.textContent=v;}
  function load(){
    fetch('/sysinfo.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d||!d.ok)return;
        var m=Math.floor(d.uptime/60),h=Math.floor(m/60);
        set('si-uptime',(h>0?(h+' h '):'')+(m%60)+' min');
        set('si-time',d.time||'-');
        set('si-heap',Math.round(d.heap/1024)+' KB');
        set('si-heapmin',Math.round(d.heapmin/1024)+' KB');
        set('si-psram',Math.round(d.psram/1024)+' / '+Math.round(d.psramtot/1024)+' KB');
        set('si-cpu',d.cpu+' MHz');
        set('si-rssi',d.wifirssi+' dBm');set('si-ip',d.wifiip);set('si-apip',d.apip);
        set('si-usb',d.usb);set('si-cam',d.camera?'aktiv':'aus');
      }).catch(function(){});
  }
  if(b)b.addEventListener('click',load);
  // Uebersicht > System: beim Oeffnen der Uebersicht laden + einmal beim Seitenstart (Startseite).
  var t=document.querySelector('.nav-item[data-tab="overview"]');
  if(t)t.addEventListener('click',load);
  load();
})();

// ---- Heap-Map (diagheap) ----
(function(){
  if(!document.getElementById('tab-diagsys'))return;   // Wurzel-Guard: nur Diagnose > System
  var b=document.getElementById('hm-refresh');
  function set(id,v){var e=document.getElementById(id);if(e)e.textContent=v;}
  function fmtKb(bytes){return Math.round(bytes/1024)+' KB';}
  function load(){
    fetch('/heapmap?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d||!d.ok)return;
        set('hm-intfree',fmtKb(d.intFree));set('hm-intlargest',fmtKb(d.intLargest));
        set('hm-psramfree',fmtKb(d.psramFree));set('hm-psramlargest',fmtKb(d.psramLargest));
        set('hm-h264ref',d.h264ActiveRefKb?(d.h264ActiveRefKb+' KB'):'keiner aktiv');
        if(d.guardBootKb!=null){
          var pref=(d.guardPrefKb<0)?'Automatisch':(d.guardPrefKb===0?'Aus':d.guardPrefKb+' KB');
          set('hm-guard',d.guardBootKb?(d.guardHeldKb+' KB exklusiv fuer Video, davon frei '+(d.guardFreeKb||0)+' KB, Encoder-Puffer daraus: '+(d.guardHits||0)+' (Boot: '+d.guardBootKb+' KB, Einstellung: '+pref+')'):('aus (Einstellung: '+pref+')'));
        }
        var m=document.getElementById('hm-milestones');
        if(m&&d.milestones&&d.milestones.length){
          var rows='';
          d.milestones.forEach(function(x){
            rows+='<div><span>'+x.tag+'</span><span>'+x.freeKb+'k frei / '+x.largestKb+'k groesster Block</span></div>';
          });
          m.innerHTML=rows;
        }
      }).catch(function(){});
  }
  if(b)b.addEventListener('click',load);
  // Diagnose > System: laden beim Seitenaufruf UND beim Klick auf den Tab "Heap-Map".
  var t=document.querySelector('.nav-item[data-tab="diagsys"]');
  if(t)t.addEventListener('click',load);
  var tb=document.querySelector('#tab-diagsys .tab[data-psub="ds-heap"]');
  if(tb)tb.addEventListener('click',load);
})();

// ---- H.264-Boot-Reserve (Guard): Server > Video > Stream. Wert kommt serverseitig (value=), Speichern
//      per /h264guard?bootkb=N (NVS, wirkt ab Neustart). Eigener Button (type=button), weil der Block im
//      atomaren camcfg-Formular liegt und dessen POST nicht mitbenutzen soll. ----
(function(){
  var gi=document.getElementById('vg-guardkb'),gs=document.getElementById('vg-guardsave'),gm=document.getElementById('vg-guardmsg');
  var gmode=document.getElementById('vg-guardmode');
  if(!gs)return;
  if(gmode)gmode.addEventListener('change',function(){if(gi)gi.disabled=(gmode.value!=='manual');});
  gs.addEventListener('click',function(){
    // -1 = Automatisch (Default), 0 = aus, >0 = manuell KB
    var mode=gmode?gmode.value:'manual';
    var kb=mode==='auto'?-1:(mode==='off'?0:Math.max(4,Math.min(400,parseInt(gi&&gi.value,10)||0)));
    if(gm)gm.textContent='Speichere ...';
    fetch('/h264guard?bootkb='+kb+'&t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(gm)gm.textContent=(d&&d.ok)?('Gespeichert: '+(d.bootKbPref<0?'Automatisch':(d.bootKbPref===0?'Aus':d.bootKbPref+' KB'))+' -- wirkt ab dem naechsten Neustart.'):'Speichern fehlgeschlagen.';})
      .catch(function(){if(gm)gm.textContent='Netzwerkfehler.';});
  });
})();

// ---- Nachbarzellen (mf-netz) ----
(function(){
  var nb=document.getElementById('nb-refresh'),nbo=document.getElementById('nb-out');
  if(nb)nb.addEventListener('click',function(){
    if(nbo)nbo.textContent='Frage ab ...';
    fetch('/modem-neighbours?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.text();})
      .then(function(t){if(nbo)nbo.textContent=t||'(keine Antwort)';})
      .catch(function(){if(nbo)nbo.textContent='Netzwerkfehler.';});
  });
})();

// ---- Best-SINR-Bandscan ----
(function(){
  var scanBtn=document.getElementById('b-scan');
  var scanOut=document.getElementById('scan-out'),scanMsg=document.getElementById('scan-msg');
  function scanShow(d){
    if(scanOut&&d.scanbands){
      var h='';
      (d.scanbands||[]).forEach(function(b){
        h+='<div><span>B'+b.band+'</span><span>'+(b.ok?('SINR '+b.sinr+' dB, RSRP '+b.rsrp+', RSRQ '+b.rsrq):'-')+(b.band===d.scanbest?' ← gewaehlt':'')+'</span></div>';
      });
      scanOut.innerHTML=h;
    }
    if(scanMsg){
      if(d.scanstate==='running')scanMsg.textContent='Scan laeuft ... aktuell B'+d.scancur;
      else if(d.scanstate==='done')scanMsg.textContent=d.scanmsg||'Fertig.';
      else if(d.scanstate==='error')scanMsg.textContent='Fehler: '+(d.scanmsg||'unbekannt');
    }
  }
  function scanPoll(){
    fetch('/modem-status.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(!d)return;scanShow(d);
        if(d.scanstate==='done'||d.scanstate==='error'||d.scanstate==='idle'){if(scanBtn)scanBtn.disabled=false;return;}
        setTimeout(scanPoll,2500);
      }).catch(function(){setTimeout(scanPoll,3000);});
  }
  if(scanBtn)scanBtn.addEventListener('click',function(){
    if(!confirm('SINR-Scan starten? Dauert ~1-2 min und trennt eine aktive Verbindung.'))return;
    scanBtn.disabled=true;
    if(scanMsg)scanMsg.textContent='Starte Scan ...';
    fetch('/modem-bandscan-start',{method:'POST',cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){if(scanMsg&&d&&d.msg)scanMsg.textContent=d.msg;setTimeout(scanPoll,1500);})
      .catch(function(){if(scanMsg)scanMsg.textContent='Netzwerkfehler.';if(scanBtn)scanBtn.disabled=false;});
  });
})();
})();
</script>)JS";
