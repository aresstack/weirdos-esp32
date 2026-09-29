// ============================================================================
// ui_zones.cpp -- Content: LAN > Netzzonen (Phase 1, reduzierte Oberflaeche ueber dem vollen Modell).
//
// Einzige Konfigurationsquelle sind die persistenten Zonen-Intents der Runtime (zone_runtime.*,
// identisch mit 'zones policy' auf der Konsole) -- keine zweite UI-Konfiguration. Der Schalter je
// Verbindung bildet ALLOW_AUTO <-> DENY ab (ROUTE_ONLY/NAT_ONLY bleiben Expert-/Konsolen-Semantik).
// Verbindungen sind GERICHTET (Quelle -> Ziel). Neben jedem Schalter steht read-only der effektive
// Zustand (ROUTE/NAT/IMPOSSIBLE), der Grund, die Routen und bei NAT die SNAT-Adresse -- alles aus
// /zones.json; die Netzsicht (Anbindungen, Adressen mit Herkunft) aus /net-interfaces.json.
// Endpunkte: GET /zones.json, GET /net-interfaces.json, POST /zones-policy (src, dst, intent).
// Baustein ROUTER (WEIRDOS_FEATURE_ROUTER): ohne ihn bleibt die Seite (Menuepunkt sichtbar) und nennt nur
// den Grund -- keine Bedienelemente, kein Polling (Muster ui_bluetooth.cpp).
// ============================================================================
#include "weirdos_features.h"
#include "web_ui.h"

void renderZones(WeirdUiWriter& w) {
#if WEIRDOS_FEATURE_ROUTER
    w.write(
        "<section id='tab-zones' class='tab-panel'>"
        "<h2 class='section-title'>Netzzonen</h2>"
        "<p class='cam-hint'>Verbindungen zwischen den Netzen und VPNs dieses Geraets. Eine Verbindung ist "
        "<b>gerichtet</b> (Quelle darf Verbindungen zum Ziel beginnen). Das Geraet waehlt selbst, ob es routet "
        "oder mit NAT uebersetzt, und zeigt das Ergebnis mit Grund an. Nichts davon ist eine Bruecke: alle Netze "
        "sind IP-Netze, es wird geroutet. Dieselben Regeln sind auf der Konsole als <code>zones policy</code> sichtbar.</p>"

        "<h2 class='section-title'>Netze (automatisch erkannt)</h2>"
        "<div id='zo-nets' class='info'><div><span>wird geladen ...</span><span></span></div></div>"

        "<h2 class='section-title'>Verbindungen</h2>"
        "<p class='cam-hint'>Schalter an = erlauben (das Geraet richtet Route und, wenn noetig, NAT ein); aus = getrennt. "
        "Ein neuer Client-Zugang (WireGuard-QR) bekommt die Ziel-Netze der erlaubten Verbindungen automatisch in seine "
        "AllowedIPs.</p>"
        "<div id='zo-conns'></div>"
        "<details class='wg-adv' id='zo-more'><summary>Weitere Verbindungen (Netze derzeit nicht aktiv)</summary><div id='zo-conns-more'></div></details>"
        "<p id='zo-msg' class='scan-status'></p>"

        "<h2 class='section-title'>Technische Details (automatisch)</h2>"
        "<div id='zo-tech' class='info'></div>"

        "<script>(function(){"
        "function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/\"/g,'&quot;');}"
        "var NAMES={'wlan-ap':'Eigenes WLAN (AccessPoint)','wlan-sta-lan':'Heimnetz (WLAN-Client)','wlan-sta-uplink':'Internet ueber WLAN','modem-uplink':'Internet ueber Mobilfunk','wg-server':'WireGuard-Server (Clients haengen an uns)','wg-client':'WireGuard-Client (fremder Server)','ipsec-client':'IPsec-Client (fremdes Gateway)','ipsec-server':'IPsec-Server (Clients haengen an uns)'};"
        "function nm(id){return NAMES[id]||id;}"
        "var A=[],P={},Z={};"
        "function pol(s,d){var l=Z.policies||[];for(var i=0;i<l.length;i++)if(l[i].src===s&&l[i].dst===d)return l[i];return null;}"
        "function rowNet(a,pf){var pfx=(pf||[]).filter(function(p){return p.attachment===a.id;});var r='';"
          "r+='<div><span><b>'+esc(nm(a.id))+'</b> <small>'+esc(a.id)+' / '+esc(a.iface)+'</small></span><span>'+(a.up?'aktiv':(a.runtimeSupported===false?'<b>nicht verfuegbar</b>':'aus'))+"
            "(a.local?(' &middot; '+esc(a.local)+'/'+a.prefix+' <small>('+esc(a.addrSource)+')</small>'):'')+(!a.up&&a.stateNote?(' <small>&ndash; '+esc(a.stateNote)+'</small>'):'')+'</span></div>';"
          "pfx.forEach(function(p){r+='<div><span style=\"padding-left:18px\">erreichbar '+esc(p.net)+'/'+p.prefix+'</span><span><small>'+esc(p.source)+(p.routingEligible===false?' &ndash; keine Zonenroute: '+esc(p.reason):'')+'</small></span></div>';});"
          "return r;}"
        "function badge(p){if(!p)return '<span class=\"scan-status\">getrennt (keine Regel)</span>';"
          "var m=p.mode||'?';var col=m==='NAT'?'#2e9e5b':m==='ROUTE'?'#2f6fd0':m==='DENY'?'#777':'#c0392b';"
          "var t='<span style=\"display:inline-block;padding:2px 8px;border-radius:10px;background:'+col+';color:#fff;font-size:12px\">'+esc(m==='NAT'?'geroutet mit NAT':m==='ROUTE'?'geroutet':m==='DENY'?'getrennt':'nicht realisierbar')+'</span>';"
          "if(p.mode==='NAT'&&p.natSource)t+=' <small>Uebersetzung &rarr; '+esc(p.natSource)+'</small>';"
          "if(p.routes&&p.routes.length)t+=' <small>Ziele: '+esc(p.routes.join(', '))+'</small>';"
          "if(p.reason)t+='<br><small>'+esc(p.reason)+'</small>';return t;}"
        "function card(s,d){var p=pol(s.id,d.id);var on=p&&p.intent!=='DENY';"
          "var noRt=(s.runtimeSupported===false)?s:((d.runtimeSupported===false)?d:null);"   // Rolle ohne Runtime: Schalter aus, Grund zeigen, nicht verstecken
          "var st=noRt?('<span class=\"scan-status\">nicht verfuegbar &ndash; '+esc(noRt.stateNote||('Runtime fuer '+noRt.id+' noch nicht implementiert'))+'</span>'):badge(p);"
          "return '<div class=\"cam-bar\" style=\"align-items:flex-start;margin:6px 0;padding:8px;border:1px solid #d7dbe0;border-radius:6px'+(noRt?';opacity:.7':'')+'\">'+"
            "'<label class=\"check-row\" style=\"min-width:320px\"><input type=\"checkbox\" class=\"zo-sw\" data-src=\"'+esc(s.id)+'\" data-dst=\"'+esc(d.id)+'\"'+(on?' checked':'')+(noRt?' disabled':'')+'><span><b>'+esc(nm(s.id))+'</b> &rarr; <b>'+esc(nm(d.id))+'</b><br><small>'+esc(s.id)+' &rarr; '+esc(d.id)+'</small></span></label>'+"
            "'<div style=\"flex:1\">'+st+'</div></div>';}"
        "function render(){var nets=document.getElementById('zo-nets');if(nets){var h='';A.forEach(function(a){h+=rowNet(a,P);});nets.innerHTML=h||'<div><span>keine Netze</span><span></span></div>';}"
          "var main='',more='';var srcs=A.filter(function(a){return a.kind!=='uplink';});"
          "srcs.forEach(function(s){A.forEach(function(d){if(d.id===s.id)return;if(d.kind==='uplink')return;"   // Internet-Ziele: Phase 2 (NetworkMode-Migration)
            "var p=pol(s.id,d.id);var rt=(s.runtimeSupported!==false&&d.runtimeSupported!==false);var live=rt&&(s.up||d.up||(p&&p.intent!=='DENY'));if(live){main+=card(s,d);}else{more+=card(s,d);}});});"
          "var c=document.getElementById('zo-conns');if(c)c.innerHTML=main||'<p class=\"cam-hint\">Keine aktiven Netze -- Verbindungen erscheinen, sobald ein VPN oder WLAN aktiv ist.</p>';"
          "var m=document.getElementById('zo-conns-more');if(m)m.innerHTML=more||'<p class=\"cam-hint\">keine</p>';"
          "var t=document.getElementById('zo-tech');if(t){var x='';var lw=Z.lwip||{},hk=lw.hooks||{};"
            "x+='<div><span>lwIP-Hooks</span><span>'+(hk.route&&hk.forward?'vorhanden':'<b>fehlen</b> (Stock-liblwip.a: Routen/Filter wirkungslos)')+'</span></div>';"
            "x+='<div><span>Forward-Policy</span><span>'+(hk.policyMode?'aktiv (nur erlaubte Verbindungen + NAT-Antworten, Rest verworfen)':'inaktiv (keine Regeln, Stock)')+'</span></div>';"
            "if(Z.commitError)x+='<div><span>Commit</span><span><b>'+esc(Z.commitError)+'</b></span></div>';"
            "if(Z.clientRoutesWg)x+='<div><span>AllowedIPs neuer WireGuard-Clients</span><span>'+esc(Z.clientRoutesWg)+'</span></div>';"
            "(lw.routes||[]).forEach(function(r){x+='<div><span>Route '+esc(r.net)+'</span><span>'+(r.block?'BLOCK ('+esc(r.note)+')':('&rarr; '+esc(r.iface)+(r.usable?'':' (down)')))+' <small>Treffer '+r.hits+'</small></span></div>';});"
            "(lw.pairs||[]).forEach(function(p){x+='<div><span>'+esc(p.src)+' &rarr; '+esc(p.dst)+' ('+esc(p.mode)+')</span><span>weitergeleitet '+p.fwd+(p.mode==='NAT'?(', NAT uebersetzt '+p.natTranslated+', Antworten '+p.replies+(p.inNapt?'':', <b>napt-Flag fehlt</b>')):'')+'</span></div>';});"
            "x+='<div><span>Verworfen (Policy)</span><span>'+(hk.dropPolicy||0)+'</span></div>';t.innerHTML=x;}}"
        "function load(){fetch('/net-interfaces.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json();}).then(function(d){A=d.attachments||[];P=d.prefixes||[];"
          "return fetch('/zones.json?t='+Date.now(),{cache:'no-store'});}).then(function(r){return r.json();}).then(function(z){Z=z||{};render();}).catch(function(){});}"
        "document.addEventListener('change',function(e){var t=e.target;if(!t||!t.classList||!t.classList.contains('zo-sw'))return;"
          "var msg=document.getElementById('zo-msg');if(msg)msg.textContent='speichere ...';"
          "fetch('/zones-policy',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
            "body:'src='+encodeURIComponent(t.getAttribute('data-src'))+'&dst='+encodeURIComponent(t.getAttribute('data-dst'))+'&intent='+(t.checked?'allow':'deny')})"
          ".then(function(r){return r.json();}).then(function(d){if(msg)msg.textContent=d.ok?(d.msg||'gespeichert'):('Fehler: '+d.msg);load();}).catch(function(){if(msg)msg.textContent='Fehler';});});"
        // Socket-Budget (lwIP 16, Web 5): KEIN Abruf beim Laden der App-Seite -- nur solange der Tab offen ist.
        "var tick=function(){var s=document.getElementById('tab-zones');if(s&&s.classList.contains('active'))load();};setTimeout(tick,300);setInterval(tick,5000);"
        "})();</script>"
        "</section>");
#else
    // Netzzonen nicht im Build (WEIRDOS_FEATURE_ROUTER=0: Profil ohne Router oder Board ohne PSRAM). Panel
    // bleibt sichtbar und nennt den Grund -- Menuepunkt nicht verstecken (Konsistenz mit IoT > Bluetooth).
    // Bewusst OHNE die Bedien-IDs (zo-nets/zo-conns/zo-sw) und OHNE das Poll-Script: /zones.json und
    // /zones-policy sind in diesem Build nicht registriert (Routen in der .ino ebenfalls unter
    // WEIRDOS_FEATURE_ROUTER).
    w.write(
        "<section id='tab-zones' class='tab-panel'>"
        "<h2 class='section-title'>Netzzonen</h2>"
        "<div style='border-left:4px solid #e0a800;background:#fff8e6;padding:10px 12px;"
        "border-radius:6px;margin:8px 0'><p><strong>Netzzonen sind in diesem Build nicht enthalten "
        "(WEIRDOS_FEATURE_ROUTER=0).</strong> Der Baustein ROUTER (Weiterleitung, NAT und Verbindungsregeln "
        "zwischen den Netzen und VPNs dieses Geraets) wurde beim Bauen abgewaehlt oder ist auf dieser Hardware "
        "nicht moeglich (er braucht PSRAM). Ohne ihn gibt es keine konfigurierbaren Verbindungen (Zonen-Regeln) "
        "zwischen den Netzen; die WireGuard-Option LAN-Gateway bleibt davon unberuehrt.</p></div>"
        "<div class='fields-inactive'>"
        "<p class='cam-hint'>Mit dem Baustein ROUTER bietet diese Seite: automatisch erkannte Netze, gerichtete "
        "Verbindungen (Quelle &rarr; Ziel) als Schalter, den effektiven Zustand (geroutet / mit NAT / getrennt) "
        "mit Grund sowie die AllowedIPs neuer WireGuard-Clients. Dieselben Regeln sind dann auf der Konsole als "
        "<code>zones policy</code> sichtbar.</p>"
        "</div>"
        "</section>"
    );
#endif
}
