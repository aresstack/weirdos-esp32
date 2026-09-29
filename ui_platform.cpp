// ============================================================================
// ui_platform.cpp -- Einrichtung > Plattform: Board-Profil (welcher ESP / welches Board), Chip-Faehigkeiten,
// Pinout-Bild (SVG: erzeugt oder -- Profil custom -- hochgeladen/eingefuegt) und das USB-Port-Mapping.
// EIN Formular "Plattform speichern" fuer Profil + USB-Anschluesse; Profilwechsel zeigt sofort die Pinout-
// Vorschau (/pinout.svg?profile=). Export/Import der ganzen Plattform-Konfiguration als JSON.
// Alles wirkt nach Neustart (gelbe Box).
// ============================================================================
#include "web_ui.h"
#include "platform.h"
#include "usb_ports.h"
#include "peripheral_registry.h"   // periphModemPort: welcher feste Port traegt cellular0
#include "wifi_caps.h"

void renderPlatform(WeirdUiWriter& w) {
    const PlatformProfile& p = platformCurrent();
    bool custom = platformIsCustom();
    w.write(
        "<section id='tab-platform' class='tab-panel'>"
        "<h2 class='section-title'>Plattform</h2>"
        "<p class='cam-hint'>Zentrale Angabe, <strong>welches Board</strong> unter dieser Firmware liegt. Der Chip ist durch den Build fest "
        "(hier: <strong>");
    w.write(platformChipName());
    w.write("</strong>, WLAN-Funk: ");
    w.write(wifiPresent() ? "vorhanden" : "keiner");
    w.write(
        "); das Profil beschreibt die Verdrahtung des Boards (Buchsen, Stiftleiste, USB) und belegt das USB-Mapping vor. "
        "Alle Module fragen ihre Faehigkeiten hier ab &ndash; so laeuft dieselbe Firmware auf dem P4-Pico mit Modem, auf einem "
        "XIAO-S3 als VPN-Zugangspunkt oder als reine Webcam.</p>"
        "<form id='pf-form' action='/platform-save' method='POST'>"
        // Zweistufig: erst die MCU-Familie (Chip-Wahrheit), dann das Board dieser Familie. Fremde
        // Familien bleiben WAEHLBAR -- man soll sehen, was es gibt; nur das Speichern ist gesperrt.
        "<label for='pf-mcu'>MCU-Familie</label>"
        "<select id='pf-mcu' class='cam-select cfg-select'>");
    for (int i = 0; i < platformMcuCount(); i++) {
        const PlatformMcu& m = platformMcuAt(i);
        bool self = !strcmp(m.id, platformChipName());
        bool cur  = !strcmp(m.id, p.chip);
        w.write(String("<option value='") + m.id + "'" + (cur ? " selected" : "") + ">" + escapeHtml(m.name)
                + (self ? " &mdash; dieser Build" : "") + "</option>");
    }
    w.write("</select><p class='cam-hint' id='pf-mcu-info'></p>"
            "<label for='pf-id'>Board</label>"
            "<select id='pf-id' name='id' class='cam-select cfg-select'>");
    // Serverseitig nur die Boards der aktuellen Familie -- der Katalog hat ueber 110 Eintraege.
    // Beim Wechsel der Familie fuellt das Script die Liste aus einer kompakten Tabelle neu.
    for (int i = 0; i < platformCount(); i++) {
        const PlatformProfile& q = platformAt(i);
        if (strcmp(q.chip, p.chip) && q.chip[0] != '*') continue;
        w.write(String("<option value='") + q.id + "'" + (platformId() == q.id ? " selected" : "") + ">"
                + escapeHtml(q.name) + (q.level >= PDL_FULL ? "" : String(" &ndash; ") + platformLevelText(q)) + "</option>");
    }
    w.write("</select><p class='cam-hint' id='pf-notes'>");
    w.write(escapeHtml(p.notes));
    w.write("</p><p class='scan-status' id='pf-preview-note'></p>");
    w.write(escapeHtml(p.notes));
    w.write("</p><p class='scan-status' id='pf-preview-note'></p>");
    if (custom) w.write(
        "<div style='border-left:4px solid #c0392b;background:#fdecea;padding:10px 12px;border-radius:6px;margin:10px 0'>"
        "<p><strong>Custom-Profil &ndash; auf eigene Gefahr.</strong> Du traegst die USB-Pins selbst ein, ohne Pruefung gegen die "
        "bekannten Paare des Chips. WeirdOS kann nur die festen USB-Pads des Chips ansteuern; Ports mit fremden Pins werden "
        "gespeichert und angezeigt, aber von keinem Treiber initialisiert (kein Modem-Host, kein PC-Geraet darauf). Bekannte Paare "
        "dieses Chips siehst du in der Tabelle unten.</p></div>");

    // ---- Pinout: drei Ansichten; der XML-/Bearbeiten-Schalter liegt als Overlay in der Bildecke,
    //      damit er zur ANGEZEIGTEN Ansicht gehoert -- jede der drei ist einzeln ersetzbar. ----
    w.write("<h2 class='section-title'>Pinout</h2>"
            "<div id='pf-img-box' style='position:relative;text-align:center;background:#fff;border:1px solid #d7dbe0;border-radius:6px;padding:6px'>"
            // Socket-Budget: das Bild wird ERST geladen, wenn der Plattform-Tab offen ist (kein src beim Seitenaufbau).
            // Das SVG wird INLINE eingehaengt (nicht als <img>): nur so lassen sich Pins anklicken und
            // ansichtsuebergreifend markieren. Socket-Budget bleibt gewahrt -- es wird weiter erst
            // geladen, wenn der Plattform-Tab offen ist, und immer nur EINE Ansicht.
            "<div id='pinout-svg' style='overflow:auto'></div>"
            // Ist fuer die gezeigte Ansicht nichts hinterlegt (SVG traegt data-empty), tritt dieser
            // Kasten AN DIE STELLE des leeren Bildes -- mit dem Weg, ein eigenes SVG zu hinterlegen.
            "<div id='pf-upload' style='display:none;padding:26px 12px;color:#555'>"
            "<p><strong>Fuer diese Ansicht ist kein Bild hinterlegt.</strong></p>"
            "<p class='cam-hint' id='pf-upload-why'></p>"
            "<p><button type='button' class='cam-button' id='pf-upload-btn'>SVG-Bild hochladen</button></p>"
            "</div>"
            "<button type='button' id='pf-xml-toggle' title='Diese Ansicht als SVG-XML bearbeiten' "
            "style='position:absolute;top:8px;right:8px;padding:3px 9px;font-size:11px;line-height:1.6;"
            "background:rgba(255,255,255,.9);border:1px solid #c4cad0;border-radius:5px;cursor:pointer'>XML</button>"
            "</div>"
            "<div id='pf-xml-box' style='display:none'>"
            "<p class='cam-hint' id='pf-xml-which'></p>"
            "<textarea id='pf-svg' rows='14' style='width:100%;font-family:monospace;font-size:12px;box-sizing:border-box'");
    if (!custom) w.write(" readonly");
    w.write(" placeholder='SVG-XML hier einfuegen ...'></textarea>");
    // Das Dateifeld wird IMMER gerendert (der Upload-Kasten oben loest es aus); wirksam gespeichert
    // wird ein eigenes Bild aber nur im Profil Custom -- deshalb der ehrliche Hinweis daneben.
    w.write("<p>SVG-Datei laden: <input type='file' id='pf-svg-file' accept='.svg,image/svg+xml'></p>");
    if (custom) w.write("<p class='cam-hint'>Eigenes SVG fuer <strong>diese</strong> Ansicht (max. 96 KB). Leerer Text loescht es, "
                        "danach wird wieder das erzeugte Bild gezeigt. Gespeichert wird mit <em>Plattform speichern</em>.</p>");
    else        w.write("<p class='cam-hint'>Erzeugtes SVG (nur lesen) &ndash; als Vorlage fuer ein eigenes Board kopierbar (Profil Custom).</p>");
    w.write("<p><button type='button' class='cam-button' id='pf-xml-back'>Zurueck zum Bild</button></p>"
            "</div>"
            "<div style='margin:6px 0 0 0'>"
            "<button type='button' class='tab active' id='pf-view-board'>Platine</button> "
            "<button type='button' class='tab' id='pf-view-chip'>Chip</button> "
            "<button type='button' class='tab' id='pf-view-aux'>Zusatzchips</button>"
            "</div>"
            "<p class='scan-status' id='pf-sel'></p>"
            "<p class='cam-hint' id='pf-view-hint'></p>"
            "<p class='cam-hint'>Drei Ansichten aus denselben Daten &ndash; auf dem Handy auch durch Wischen. Es wird immer "
            "nur EIN Bild geladen. Der <em>XML</em>-Knopf in der Bildecke oeffnet die gerade gezeigte Ansicht zum "
            "Bearbeiten; im Profil Custom laesst sich jede der drei einzeln durch ein eigenes SVG ersetzen.</p>");

    // ---- USB-Anschluesse ----
    // Feste Anschluesse (HS-OTG mit dedizierten UTMI-Pads, keine GPIOs) sind NICHT einstellbar und werden nur
    // genannt; einstellbar sind allein die GPIO-Paare der Full-Speed-PHYs. Die festen Eintraege stehen vorn im
    // Mapping (USB0 ...) und werden beim Speichern ueber versteckte Felder unveraendert mitgefuehrt.
    int fixedN = 0;
    for (int i = 0; i < usbPortsCount(); i++) { if (usbPort(i).dm < 0 && usbPortIsHighSpeed(usbPort(i).id)) fixedN++; else break; }
    w.write("<h2 class='section-title'>USB-Anschluesse</h2>");
    if (fixedN) {
        w.write("<p class='cam-hint'><strong>Feste Anschluesse</strong> &ndash; USB 2.0 High-Speed ueber dedizierte UTMI-Pads des Chips. "
                "Sie haben keine GPIO-Nummern, sind von den Einstellungen unten unabhaengig und immer vorhanden:</p><div class='info'>");
        for (int i = 0; i < fixedN; i++) {
            const UsbPortEntry& e = usbPort(i);
            w.write(String("<div><span><strong>") + e.id + "</strong> " + escapeHtml(e.label) + "</span><span>OTG 2.0 High-Speed, dedizierte Pads"
                    + (e.id == periphModemPort ? " &middot; traegt <strong>cellular0</strong> (Modem)" : "") + "</span></div>");
        }
        w.write("</div>");
    }
    w.write(
        "<p class='cam-hint' style='margin-top:8px'><strong>Einstellbare Anschluesse</strong> &ndash; Full-Speed-Ports auf GPIO-Paaren: Anzahl, je Port ein Name, "
        "die Pins D&minus;/D+ und ob der Port benutzt wird. Rollen (Modem unter WAN &rarr; Modem, PC-Geraet unter System &rarr; Geraete) "
        "verweisen auf diese Ports. Moegliche GPIO-Paare dieses Chips:</p>"
        "<div class='info'>");
    int pairN = 0;
    for (int k = 0; k < usbHwPairCount(); k++) {
        const UsbHwPair& hp = usbHwPair(k);
        if (hp.dm < 0) continue;   // feste HS-Pads: oben genannt, hier nicht einstellbar
        pairN++;
        w.write(String("<div><span>") + hp.name + " &ndash; GPIO" + hp.dm + " (D&minus;) / GPIO" + hp.dp + " (D+)</span><span>" + escapeHtml(hp.note) + "</span></div>");
    }
    if (!pairN) w.write("<div><span>keine GPIO-USB-Paare auf diesem Chip</span><span></span></div>");
    w.write("</div>");
    // Versteckte Felder der festen Eintraege (unveraendert mitfuehren)
    for (int i = 0; i < fixedN; i++) {
        const UsbPortEntry& e = usbPort(i); String k = String(i);
        w.write(String("<input type='hidden' name='label") + k + "' value='" + escapeHtml(e.label) + "'><input type='hidden' name='dm" + k + "' value='-1'>"
                "<input type='hidden' name='dp" + k + "' value='-1'>" + (e.enabled ? "<input type='hidden' name='en" + k + "' value='1'>" : ""));
    }
    // Anzahl der EINSTELLBAREN Ports; der Formularwert 'count' ist die Gesamtzahl (fest + einstellbar)
    int minExtra = fixedN ? 0 : 1;
    w.write("<label for='usbp-count'>Anzahl einstellbarer USB-Ports</label>"
            "<select id='usbp-count' name='count' class='cam-select cfg-select'>");
    for (int n = minExtra; n <= USB_PORTS_MAX - fixedN; n++)
        w.write(String("<option value='") + (fixedN + n) + "'" + (usbPortsCount() == fixedN + n ? " selected" : "") + ">" + n + "</option>");
    w.write("</select><div class='info'>");
    for (int i = fixedN; i < USB_PORTS_MAX; i++) {
        bool have = i < usbPortsCount();
        const UsbPortEntry* e = have ? &usbPort(i) : nullptr;
        String k = String(i);
        bool cpins = e && usbPortHasCustomPins(e->id);
        w.write(String("<div class='usbp-row' data-idx='") + i + "'" + (have ? "" : " style='display:none'") + "><span><strong>USB" + i + "</strong> "
                "<input name='label" + k + "' type='text' maxlength='24' placeholder='Name (Buchse/Stiftleiste)' value='" + (e ? escapeHtml(e->label) : String("")) + "' style='width:170px'></span>"
                "<span>D&minus; <input name='dm" + k + "' type='number' min='0' max='54' value='" + (e ? String((int)e->dm) : String("")) + "' style='width:64px'> "
                "D+ <input name='dp" + k + "' type='number' min='0' max='54' value='" + (e ? String((int)e->dp) : String("")) + "' style='width:64px'> "
                "<label style='display:inline'><input name='en" + k + "' type='checkbox' value='1'" + ((e && e->enabled) ? " checked" : "") + "> aktiv</label>"
                + (e ? (String(" <small") + (cpins ? " style='color:#c0392b'" : "") + ">" + escapeHtml(usbPortDescribe(e->id)) + "</small>") : String("")) + "</span></div>");
    }
    w.write(
        "</div>"
        "<p class='cam-hint'>Ein Profilwechsel setzt die USB-Anschluesse auf die Vorgaben des Profils. Alles wirkt nach <strong>Neustart</strong> "
        "(Modem-Host und PC-Geraet werden beim Boot auf ihre Ports gelegt). In mitgelieferten Profilen werden nur Chip-Paare angenommen; "
        "im Custom-Profil auch fremde Pins (rot markiert, inert).</p>"
        "<button class='connect-button' type='submit' id='pf-save'>Plattform speichern</button>"
        "<p class='scan-status' id='pf-save-note'></p>"
        "</form>");

    // ---- Export / Import (die ganze Plattform-Konfiguration als JSON) ----
    w.write(
        "<h2 class='section-title'>Plattform sichern / uebertragen</h2>"
        "<p class='cam-hint'>Die komplette Plattform-Konfiguration (Profil, USB-Anschluesse, Modem-Port, eigenes Pinout) als JSON-Datei. "
        "Dieselbe Datei laesst sich hier oder ueber die Konsole (<code>platform import</code>) zurueckspielen.</p>"
        "<p><a class='connect-button' style='display:inline-block;text-decoration:none' href='/platform-config.json?download=1'>Exportieren (JSON herunterladen)</a></p>"
        "<label for='pf-imp-file'>Importieren</label>"
        "<p><input type='file' id='pf-imp-file' accept='.json,application/json'></p>"
        "<textarea id='pf-imp' rows='5' style='width:100%;font-family:monospace;font-size:12px;box-sizing:border-box' placeholder='... oder JSON hier einfuegen'></textarea>"
        "<p><button type='button' class='cam-button' id='pf-imp-btn'>Importieren</button> <span id='pf-imp-msg' class='scan-status'></span></p>");

    // ---- Script: Vorschau bei Profilwechsel, Bild|XML, SVG-Upload/-Speichern, Import ----
    // ---- Board-Tabelle fuers Script: nur id, Name und "hat Pinout", gruppiert nach MCU-Familie.
    //      So kann die zweite Auswahlliste ohne Serveranfrage umgebaut werden (Socket-Budget), und
    //      es geht nur EINE kompakte Tabelle ueber die Leitung statt 110 <option>-Elemente.
    w.write("<script>/*GENERATED*/var PF_BOARDS={");   // in einer Schleife gebaut -- siehe check-embedded-js.pl
    for (int i = 0; i < platformMcuCount(); i++) {
        const PlatformMcu& m = platformMcuAt(i);
        if (i) w.write(",");
        w.write(String("\"") + m.id + "\":[");
        bool first = true;
        for (int k = 0; k < platformCount(); k++) {
            const PlatformProfile& q = platformAt(k);
            if (strcmp(q.chip, m.id)) continue;
            if (!first) w.write(",");
            first = false;
            w.write(String("[\"") + q.id + "\",\"" + escapeHtml(q.name) + "\"," + q.level + "]");
        }
        w.write("]");
    }
    w.write("};var PF_MCU={");
    for (int i = 0; i < platformMcuCount(); i++) {
        const PlatformMcu& m = platformMcuAt(i);
        if (i) w.write(",");
        w.write(String("\"") + m.id + "\":\"USB: " + escapeHtml(m.usb) + " &middot; Funk: " + escapeHtml(m.radio)
                + " &middot; I/O: " + escapeHtml(m.io) + "\"");
    }
    w.write(String("};var PF_CHIP=\"") + platformChipName() + "\";</script>");
    // Profile ohne eigene Familie (z.B. Custom mit chip \"*\") haengen wir an jede Liste an.
    w.write("<script>/*GENERATED*/(function(){var uni=[];");
    for (int k = 0; k < platformCount(); k++) {
        const PlatformProfile& q = platformAt(k);
        if (q.chip[0] != '*') continue;
        w.write(String("uni.push([\"") + q.id + "\",\"" + escapeHtml(q.name) + "\"," + q.level + "]);");
    }
    w.write("for(var k in PF_BOARDS)PF_BOARDS[k]=PF_BOARDS[k].concat(uni);})();</script>");
    w.write(
        "<script>(function(){"
        "var sel=document.getElementById('pf-id'),holder=document.getElementById('pinout-svg'),ta=document.getElementById('pf-svg'),"
        "selNote=document.getElementById('pf-sel'),selPins=[],selPrim='',selLabel='',svgLoaded=false,"
        "bB=document.getElementById('pf-view-board'),bC=document.getElementById('pf-view-chip'),"
        "bA=document.getElementById('pf-view-aux'),bX=document.getElementById('pf-xml-toggle'),"
        "bXb=document.getElementById('pf-xml-back'),xw=document.getElementById('pf-xml-which'),dirtyView='',"
        "hint=document.getElementById('pf-view-hint'),ib=document.getElementById('pf-img-box'),"
        "views=['','chip','aux'],view='',"
        "hints={'':'Platine: was an der Stiftleiste herausgefuehrt ist.',"
        "'chip':'Chip: welche Pins und Pads der SoC hat und was davon dieses Board belegt.',"
        "'aux':'Zusatzchips: welcher Onboard-Baustein an welchen Pins haengt.'},"
        "xb=document.getElementById('pf-xml-box'),up=document.getElementById('pf-svg-file'),note=document.getElementById('pf-preview-note'),"
        "form=document.getElementById('pf-form'),cur=sel?sel.value:'',dirty=false,loaded=false;"
        "function isCustom(){return sel&&sel.value==='custom';}"
        "var mcu=document.getElementById('pf-mcu'),mi=document.getElementById('pf-mcu-info'),"
        "sv=document.getElementById('pf-save'),sn=document.getElementById('pf-save-note');"
        // Zweite Liste aus der kompakten Tabelle neu aufbauen -- ohne Serveranfrage.
        "function fillBoards(keep){if(!mcu||!sel)return;var l=PF_BOARDS[mcu.value]||[],h='';"
        "var lvl=['nicht verifiziert','Verdrahtung belegt, Stiftleiste fehlt',''];"
        "for(var i=0;i<l.length;i++)h+='<option value=\"'+l[i][0]+'\"'+(l[i][0]===keep?' selected':'')"
        "+'>'+l[i][1]+(lvl[l[i][2]]?(' – '+lvl[l[i][2]]):'')+'</option>';sel.innerHTML=h;}"
        // Fremde Familien bleiben WAEHLBAR (man soll den Bestand sehen); gesperrt ist nur das Speichern.
        "function gate(){var ok=!!(mcu&&mcu.value===PF_CHIP)||(sel&&sel.value==='custom');"
        "if(mi&&mcu)mi.innerHTML=PF_MCU[mcu.value]||'';"
        "if(sv){sv.disabled=!ok;sv.style.opacity=ok?'':'0.5';sv.style.cursor=ok?'':'not-allowed';"
        "sv.textContent=ok?'Plattform speichern':'Nicht unterstuetzt';}"
        "if(sn)sn.textContent=ok?'':('Diese Firmware ist fuer '+PF_CHIP+' gebaut. Das gewaehlte Board braucht einen '"
        "+(mcu?mcu.value:'anderen')+'-Build -- ansehen geht, speichern nicht.');}"
        "function srcFor(v){return '/pinout.svg?profile='+encodeURIComponent(sel?sel.value:'')+(v?'&view='+v:'')+'&t='+Date.now();}"
        "function src(){return srcFor(view);}"
        // XML gehoert zur GERADE GEZEIGTEN Ansicht -- jede der drei ist einzeln ersetzbar.
        "var vname={'':'Platine','chip':'Chip','aux':'Zusatzchips'};"
        "function loadXml(){if(loaded||dirty||!ta)return;fetch(srcFor(view),{cache:'no-store'})"
        ".then(function(r){return r.text();}).then(function(t){ta.value=t;loaded=true;}).catch(function(){});}"
        "function marks(x){"
        "[bB,bC,bA].forEach(function(b,i){if(b)b.classList.toggle('active',views[i]===view);});"
        "if(bX)bX.textContent=x?'Bild':'XML';if(xw)xw.textContent='Ansicht: '+vname[view];}"
        "function show(x){if(ib)ib.style.display=x?'none':'';if(xb)xb.style.display=x?'':'none';marks(x);if(x)loadXml();}"
        // ---- Inline-SVG laden und Markierung ansichtsuebergreifend halten ----------------------------
        // Ein Klick auf einen Pin markiert ihn; ein Klick auf einen Baustein markiert alle seine Pins.
        // Die Auswahl ueberlebt den Ansichtswechsel, weil sie als GPIO-Nummern gefuehrt wird -- die sind
        // in Platinen-, Chip- und Zusatzchip-Ansicht dieselben.
        // Klasse in EINEM Zug setzen (Grundklasse + Zustand) statt zwei Flags nacheinander zu
        // schalten -- das war fehleranfaellig. Ohne Regex: '\s'/'\b' waeren in einem C++-Literal
        // C-Escapes (\b = Backspace), nicht Regex-Escapes; das JS waere still kaputt.
        "function mark(n,base,st){n.setAttribute('class',st?(base+' '+st):base);}"
        "function hasCls(n,c){return (' '+(n.getAttribute('class')||'')+' ').indexOf(' '+c+' ')>=0;}"
        // Zwei Stufen: 'sel' = angeklickt, 'rel' = teilt sich diese Pins. Ohne die Trennung sah ein
        // Klick auf EINE Buchse so aus, als waeren drei Bausteine gleichzeitig gewaehlt.
        "function shares(g){var l=(g.getAttribute('data-gpios')||'').split(',');"
        "for(var j=0;j<l.length;j++)if(l[j]&&selPins.indexOf(l[j])>=0)return true;return false;}"
        "function applySel(){if(!holder)return;"
        "var ps=holder.querySelectorAll('.pin');"
        "for(var i=0;i<ps.length;i++){var pv=ps[i].getAttribute('data-pin');"
        "mark(ps[i],'pin',selPrim==='pin:'+pv?'sel':(selPins.indexOf(pv)>=0?'rel':''));}"
        "var as=holder.querySelectorAll('.aux');"
        "for(var k=0;k<as.length;k++){var av=as[k].getAttribute('data-aux');"
        "mark(as[k],'aux',selPrim==='aux:'+av?'sel':(selPins.length&&shares(as[k])?'rel':''));}"
        "if(selNote){var pl=(selPins.length===1&&selPins[0]==='-')"
        "?' (keine GPIO-Nummern -- dedizierte Pads)':(' (GPIO '+selPins.join(', ')+')');"
        "selNote.textContent=selPrim?(selLabel+' ausgewaehlt'+pl+' -- durchgezogen: die Auswahl,"
        " gestrichelt: teilt sich diese Pins. Gilt auch in den anderen Ansichten;"
        " Klick daneben hebt auf.'):'';}}"
        "function grpOf(n){while(n&&n!==holder){if(n.getAttribute&&(hasCls(n,'pin')||hasCls(n,'aux')))return n;n=n.parentNode;}return null;}"
        // Name des Bausteins = der erste Textknoten seiner Ueberschrift (ohne den Typ im tspan).
        "function grpLabel(g){if(hasCls(g,'pin'))return 'GPIO '+g.getAttribute('data-pin');"
        "var t=g.querySelector('text');"
        "return (t&&t.firstChild&&t.firstChild.nodeValue)?t.firstChild.nodeValue:'Baustein';}"
        // Veraltete Antworten duerfen die Anzeige NICHT mehr ueberschreiben: jede Anfrage bekommt
        // eine Nummer, nur die neueste wird eingehaengt. Ohne das blieb beim schnellen Umschalten
        // (oder wenn das Geraet langsam antwortet) die vorherige Ansicht stehen.
        "var svgSeq=0;"
        "function loadSvg(){if(!holder)return;svgLoaded=true;var my=++svgSeq;"
        "if(selNote)selNote.textContent='lade ...';"
        "fetch(src(),{cache:'no-store'}).then(function(r){return r.text();}).then(function(t){"
        "if(my!==svgSeq)return;holder.innerHTML=t;applySel();emptyBox();}).catch(function(){"
        "if(my!==svgSeq)return;holder.textContent='Pinout nicht ladbar.';if(selNote)selNote.textContent='';});}"
        // Leere Ansicht -> Upload-Kasten statt Bild.
        "function emptyBox(){var box=document.getElementById('pf-upload'),"
        "why=document.getElementById('pf-upload-why');if(!holder||!box)return;"
        "var e=holder.querySelector('svg[data-empty]');"
        "box.style.display=e?'':'none';holder.style.display=e?'none':'';"
        "if(!e)return;"
        "var btn=document.getElementById('pf-upload-btn');"
        "if(why)why.textContent=isCustom()"
        "?('Ansicht '+vname[view]+': ein eigenes SVG tritt an ihre Stelle. Gespeichert wird mit Plattform speichern.')"
        ":('Ansicht '+vname[view]+': fuer dieses Profil sind keine Daten hinterlegt. Ein eigenes Bild laesst sich nur im Profil Eigenes Board (Custom) speichern.');"
        "if(btn)btn.style.display=isCustom()?'':'none';}"
        "var upBtn=document.getElementById('pf-upload-btn');"
        "if(upBtn)upBtn.addEventListener('click',function(){var f=document.getElementById('pf-svg-file');if(f)f.click();});"
        "function clearSel(){selPins=[];selPrim='';selLabel='';}"
        "if(holder)holder.addEventListener('click',function(e){var g=grpOf(e.target);"
        "if(!g){clearSel();applySel();return;}"
        "var key=(hasCls(g,'pin')?'pin:':'aux:')+g.getAttribute(hasCls(g,'pin')?'data-pin':'data-aux');"
        "if(key===selPrim){clearSel();applySel();return;}"          // nochmal draufklicken hebt auf
        "selPrim=key;selLabel=grpLabel(g);selPins=[];"
        "if(hasCls(g,'pin'))selPins=[g.getAttribute('data-pin')];"
        "else{var l=(g.getAttribute('data-gpios')||'').split(',');"
        "for(var j=0;j<l.length;j++)if(l[j])selPins.push(l[j]);}"
        // Baustein ohne GPIO-Nummern (dedizierte Pads): trotzdem markieren, aber ohne Pin-Bezug.
        "if(!selPins.length)selPins=['-'];"
        "applySel();});"
        // Ansicht wechseln: es ist immer nur EIN Bild geladen, das alte wird ersetzt (Heap/Sockets).
        "function setView(v){view=v;if(!dirty)loaded=false;loadSvg();"
        "if(hint)hint.textContent=hints[v]||'';show(false);}"
        // Der XML-Knopf gehoert zur gezeigten Ansicht. Liegt eine ungespeicherte Aenderung an einer
        // ANDEREN Ansicht, wird nachgefragt, statt sie stillschweigend zu ueberschreiben.
        "function openXml(){if(dirty&&dirtyView!==view){"
        "if(!confirm('Ungespeicherte Aenderung an der Ansicht '+vname[dirtyView]+' verwerfen?'))return;dirty=false;}"
        "if(!dirty)loaded=false;show(true);}"
        "if(bB)bB.addEventListener('click',function(){setView('');});"
        "if(bC)bC.addEventListener('click',function(){setView('chip');});"
        "if(bA)bA.addEventListener('click',function(){setView('aux');});"
        "if(bX)bX.addEventListener('click',openXml);"
        "if(bXb)bXb.addEventListener('click',function(){show(false);});"
        "if(hint)hint.textContent=hints[''];"
        // Handy: waagerecht wischen blaettert durch die Ansichten (wie eine Bildergalerie).
        "var tx=0,ty=0;"
        "if(ib){ib.addEventListener('touchstart',function(e){tx=e.changedTouches[0].clientX;"
        "ty=e.changedTouches[0].clientY;},{passive:true});"
        "ib.addEventListener('touchend',function(e){var dx=e.changedTouches[0].clientX-tx,"
        "dy=e.changedTouches[0].clientY-ty;"
        "if(Math.abs(dx)<45||Math.abs(dx)<Math.abs(dy))return;"
        "setView(views[(views.indexOf(view)+(dx<0?1:2))%3]);},{passive:true});}"
        // Socket-Budget: Bild erst laden, wenn der Tab offen ist
        "var t=function(){var s=document.getElementById('tab-platform');"
        "if(s&&holder&&s.classList.contains('active')&&!svgLoaded){svgLoaded=true;loadSvg();}};setTimeout(t,300);setInterval(t,1000);"
        // Profilwechsel: sofort Vorschau (nichts gespeichert)
        // Boardwechsel: sofort Vorschau (nichts gespeichert) und Speichern-Sperre neu bewerten.
        "function onBoard(){loaded=false;dirty=false;selPins=[];loadSvg();"
        "if(note)note.textContent=(sel&&sel.value===cur)?'':'Vorschau -- noch nicht gespeichert. Speichern setzt die USB-Anschluesse auf die Vorgaben dieses Profils.';"
        "if(ta){ta.readOnly=!isCustom();if(xb&&xb.style.display!=='none')loadXml();}gate();}"
        "if(sel)sel.addEventListener('change',onBoard);"
        "if(mcu)mcu.addEventListener('change',function(){fillBoards(null);onBoard();});"
        "gate();"
        "if(ta)ta.addEventListener('input',function(){dirty=true;loaded=true;dirtyView=view;});"
        // SVG-Datei -> Textfeld (gespeichert wird mit dem Formular)
        "if(up)up.addEventListener('change',function(){var f=up.files&&up.files[0];if(!f||!ta)return;var r=new FileReader();"
        "r.onload=function(){ta.value=String(r.result||'');dirty=true;loaded=true;dirtyView=view;show(true);};r.readAsText(f);});"
        // Plattform speichern: zuerst ein geaendertes SVG (roher Body an /platform-svg), dann das Formular
        "if(form)form.addEventListener('submit',function(e){if(!dirty||!isCustom()||!ta)return;e.preventDefault();"
        "fetch('/platform-svg?view='+encodeURIComponent(dirtyView),{method:'POST',cache:'no-store',"
        "headers:{'Content-Type':'image/svg+xml'},body:ta.value})"
        ".then(function(r){return r.json();}).then(function(d){if(d&&d.ok){dirty=false;form.submit();}else{alert('Pinout-SVG nicht gespeichert: '+((d&&d.msg)||'Fehler'));}})"
        ".catch(function(){alert('Pinout-SVG nicht gespeichert (Netzwerkfehler).');});});"
        // Import: Datei -> Textfeld -> POST /platform-import
        "var impF=document.getElementById('pf-imp-file'),imp=document.getElementById('pf-imp'),impB=document.getElementById('pf-imp-btn'),impM=document.getElementById('pf-imp-msg');"
        "if(impF)impF.addEventListener('change',function(){var f=impF.files&&impF.files[0];if(!f||!imp)return;var r=new FileReader();r.onload=function(){imp.value=String(r.result||'');};r.readAsText(f);});"
        "if(impB)impB.addEventListener('click',function(){if(!imp||!imp.value.trim()){if(impM)impM.textContent='keine Daten';return;}if(impM)impM.textContent='importiere ...';"
        "fetch('/platform-import',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json'},body:imp.value})"
        ".then(function(r){return r.json();}).then(function(d){if(impM)impM.textContent=(d&&d.msg)||(d&&d.ok?'ok':'Fehler');if(d&&d.ok)setTimeout(function(){location.href='/?p=platform';},1200);})"
        ".catch(function(){if(impM)impM.textContent='Netzwerkfehler';});});"
        // Einstellbare Ports: Zeilen nach Anzahl ein-/ausblenden
        "var c=document.getElementById('usbp-count');if(c){var sync=function(){var n=parseInt(c.value,10);"
        "document.querySelectorAll('.usbp-row').forEach(function(r){r.style.display=(parseInt(r.getAttribute('data-idx'),10)<n)?'':'none';});};"
        "c.addEventListener('change',sync);sync();}"
        "})();</script>"
        "</section>");
}
