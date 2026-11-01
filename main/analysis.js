// Device analysis rules, shared by the dashboard's Devices tab (main/index.html)
// and the device page (main/device.html): one copy, served at GET /analysis.js
// (main/admin/api_devlog.c). Fork addition (alert-web), Robert Mech.
//
// Plain-language notes on one device, worked out in the browser from the
// /api/devices fields: no firmware change, no device RAM. Descriptive only.
// The device keeps its last 4 distinct queries, so older behaviour may not show.
//
// ssAnalysis(device, foot) returns a <div class="an"> (Identity, Behaviour,
// Risk notes, Suggestion, Rates; foot, if given, as the last line) whose _ai
// holds the same text for an AI prompt: {id, beh, risk, rate, sug, qs}.
// Every value goes in with textContent. Everything else stays inside this
// function, so the pages' own names (el, dur, ...) never clash.
window.ssAnalysis=(function(){
  'use strict';
  function el(tag,cls,text){const x=document.createElement(tag);if(cls)x.className=cls;if(text!==undefined&&text!==null)x.textContent=String(text);return x;}
  const dur=s=>{s=s|0;const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return(d?d+'d ':'')+h+'h '+m+'m';};
  // Brand of a label, hostname or MAC vendor, for "other makers' gear".
  const DV_BRAND=[[/webOS|\bLG\b|LG Electronics/i,'LG'],[/PlayStation|Sony|BDP|Bravia/i,'Sony'],[/HDHomeRun|SiliconDust/i,'SiliconDust'],
    [/Roku/i,'Roku'],[/Sonos/i,'Sonos'],[/Chromecast|CrKey|Google|Nest/i,'Google'],[/Samsung|Tizen|SEC_HHP/i,'Samsung'],
    [/Philips|\bHue\b|IpBridge|Signify/i,'Philips'],[/Xbox|Windows|Microsoft|MSFT/i,'Microsoft'],[/Amazon|Fire TV|Echo/i,'Amazon'],
    [/Apple|iPhone|iPad/i,'Apple'],[/Belkin|WeMo/i,'Belkin'],[/TP-?Link|Kasa/i,'TP-Link'],[/LIFX/i,'LIFX']];
  // What it searches for. q: tested on each M-SEARCH query; p: a protocol it sent;
  // brand: whose gear that is; w: risk weight of the note (2 isolate, 1 watch).
  const DV_LOOK=[
    {q:/urn:Belkin:/i,brand:'Belkin',t:'Searching for Belkin WeMo smart plugs (LG Home Dashboard style device discovery)'},
    {p:'kasa',brand:'TP-Link',t:'Probing for TP-Link Kasa plugs',google:'Probing for TP-Link Kasa plugs; on a Google or Nest device this is usually a leftover smart-home integration'},
    {p:'lifx',brand:'LIFX',t:'Looking for LIFX bulbs'},
    {p:'playstation',brand:'Sony',t:'Looking for a PlayStation (Remote Play or the PlayStation App)'},
    {q:/roku:ecp/i,brand:'Roku',t:'Looking for Roku players'},
    {q:/ZonePlayer|Sonos/i,brand:'Sonos',t:'Looking for Sonos speakers'},
    {q:/IpBridge|\bhue\b/i,brand:'Philips',t:'Looking for Philips Hue bridges'},
    {q:/samsung\.com/i,brand:'Samsung',t:'Looking for Samsung devices'},
    {q:/dial-multiscreen|:dial:/i,t:'Looking for cast targets (DIAL)'},
    {q:/MediaServer|ContentDirectory/i,t:'Looking for DLNA media servers'},
    {q:/MediaRenderer|AVTransport|RenderingControl/i,t:'Looking for DLNA media renderers (screens and speakers to play to)'},
    {q:/InternetGatewayDevice|WANIPConnection|WANPPPConnection/i,t:'Looking for the router\'s UPnP port-mapping service',
      risk:'Opens router ports by UPnP if the router allows it: check whether UPnP is on',w:1},
    {q:/ssdp:all|upnp:rootdevice/i,t:'Looking for every UPnP device'},
  ];
  // What it announces itself as, from NOTIFY queries.
  const DV_SAY=[[/MediaRenderer/i,'a DLNA media renderer'],[/MediaServer/i,'a DLNA media server'],[/dial/i,'a DIAL cast target'],
    [/InternetGatewayDevice/i,'a UPnP router'],[/ZonePlayer/i,'a Sonos speaker'],[/HDHomeRun|SiliconDust/i,'an HDHomeRun tuner']];
  const DV_SRC={server:'its SSDP SERVER header','user-agent':'its USER-AGENT header','dhcp-class':'its DHCP vendor class',
    dhcp:'its DHCP hostname',netbios:'its NetBIOS name',host:'its hostname',pihole:'Pi-hole\'s name for it'};
  const DV_CHATTY=360;      // packets an hour, all protocols: more than one every 10 s
  const DV_MIN_SPAN=600;    // seconds seen before a rate means anything
  function dvRate(n,span){const r=n*3600/span;return r<10?r.toFixed(1):String(Math.round(r));}
  function analyse(x,foot){
    const id=[],beh=[],risk=[],rate=[];let w=0;
    const qs=(x.queries||[]).map(String),pr=x.protos||{},vendor=String(x.vendor||''),label=String(x.label||''),host=String(x.host||'');
    const own=(DV_BRAND.find(([re])=>re.test(label+' '+host+' '+vendor))||[])[1]||'';
    const span=(+x.first_ago_s||0)-(+x.last_ago_s||0),total=+x.total||0;
    const flag=(t,weight)=>{risk.push(t);w=Math.max(w,weight);};
    // Identity
    id.push(vendor?'MAC vendor: '+vendor:'MAC vendor unknown');
    if(label&&x.label_src!=='mac-vendor')id.push('Model hint: "'+label+'", from '+(DV_SRC[x.label_src]||String(x.label_src||'?')));
    if(host&&host!==label)id.push('Hostname: '+host);
    const vc=(qs.join(' ').match(/class=(\S+)/)||[])[1]||'';
    const av=vc.match(/android-dhcp-(\d+)/i);
    if(vc)id.push('DHCP vendor class: '+vc+(av?' (Android '+av[1]+')':/MSFT/i.test(vc)?' (Windows)':''));
    if(x.random_mac)id.push('Randomised MAC: a phone, or privacy mode on');
    // Behaviour
    const looked=new Set();
    for(const r of DV_LOOK){
      const hit=r.p?pr[r.p]:qs.some(q=>/^M-SEARCH/i.test(q)&&r.q.test(q));
      if(!hit)continue;
      beh.push(r.google&&own==='Google'?r.google:r.t);
      if(r.brand&&r.brand!==own)looked.add(r.brand==='Belkin'?'Belkin WeMo':r.brand==='TP-Link'?'TP-Link Kasa':r.brand);
      if(r.risk)flag(r.risk,r.w);
    }
    if(pr['ssdp-search']&&!qs.some(q=>/^M-SEARCH/i.test(q)&&DV_LOOK.some(r=>r.q&&r.q.test(q))))beh.push('Searching for UPnP devices');
    if(pr['ssdp-notify']){
      const as=DV_SAY.filter(([re])=>qs.some(q=>/^NOTIFY/i.test(q)&&re.test(q))).map(s=>s[1]);
      beh.push('Announcing itself'+(as.length?' as '+as.join(', '):'')+(span>=DV_MIN_SPAN?', '+dvRate(pr['ssdp-notify'],span)+' times an hour':''));
    }
    if(qs.some(q=>/^(Probe|Resolve)\b/.test(q)))beh.push('Looking for WS-Discovery devices (printers, scanners, PCs)');
    if(qs.some(q=>/^Hello\b/.test(q)))beh.push('Announcing itself over WS-Discovery');
    const wpad=qs.some(q=>/\bwpad\b/i.test(q));
    if(wpad)beh.push('Proxy auto-discovery lookup (WPAD)');
    const names=qs.filter(q=>/^(A|AAAA|ANY|PTR) /.test(q)||/^query /.test(q)).filter(q=>!/\bwpad\b/i.test(q));
    if(names.length)beh.push('Broadcast name lookups that DNS did not answer: '+names.join('; '));
    if(qs.some(q=>/^(register|refresh) /.test(q)))beh.push('Registers its NetBIOS name on the LAN');
    if(pr.dhcp)beh.push('Asked for an address by DHCP');
    if(!beh.length)beh.push('Nothing beyond the packets counted below');
    // Risk notes
    if(av&&+av[1]<=8)flag('Android '+av[1]+'.x, no security updates for years',2);
    if(wpad)flag('WPAD can be answered by a hostile host to intercept web traffic (the honeypot never answers)',1);
    if(looked.size)flag('Scans for other makers\' IoT gear: '+[...looked].join(', '),2);
    if(span>=DV_MIN_SPAN&&total*3600/span>DV_CHATTY)flag('Very chatty multicast: '+dvRate(total,span)+' packets an hour in all',1);
    if(!vendor&&x.random_mac)flag('Can\'t identify; check your router\'s client list',1);
    // Rates
    if(span>=DV_MIN_SPAN){
      for(const [k,v] of Object.entries(pr))rate.push(k+': '+dvRate(+v||0,span)+' an hour ('+v+' in '+dur(span)+')');
    }else rate.push('Seen over '+span+' s only, too short for a rate: '+Object.entries(pr).map(([k,v])=>k+' '+v).join(', '));
    // Suggestion
    const known=own||vendor||(label&&x.label_src!=='mac-vendor');
    const sug=w>=2?['Isolate (guest or IoT network)','sg-iso']:w===1||!known?['Watch','sg-watch']:['Known and benign: name it','sg-ok'];
    const box=el('div','an'),sec=(h,items)=>{const s=el('div'),u=el('ul');s.append(el('h5','',h));items.forEach(t=>u.append(el('li','',t)));s.append(u);box.append(s);};
    sec('Identity',id);sec('Behaviour',beh);sec('Risk notes',risk.length?risk:['None from these rules']);
    const s=el('div');s.append(el('h5','','Suggestion'),el('div','sg '+sug[1],sug[0]),el('h5','','Rates'));
    const u=el('ul');rate.forEach(t=>u.append(el('li','',t)));s.append(u);box.append(s);
    if(foot)box.append(el('div','an-foot',foot));
    box._ai={id,beh,risk,rate,sug:sug[0],qs};
    return box;
  }
  return analyse;
})();
