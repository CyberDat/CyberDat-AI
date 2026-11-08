/* Local SVG atlas + bounded, same-origin read-only events. No tiles or telemetry generation. */
(() => {
 'use strict';
 const project = (lat, lon) => [(lon + 180) * 1000 / 360, (90 - lat) * 500 / 180];
 const clampCamera = (scale, x, y) => ({scale: Math.max(1, Math.min(6, scale)), x: Math.max(1000 - 1000 * Math.max(1, Math.min(6, scale)), Math.min(0, x)), y: Math.max(500 - 500 * Math.max(1, Math.min(6, scale)), Math.min(0, y))});
 if (typeof module !== 'undefined' && module.exports) module.exports = {project, clampCamera};
 if (typeof document === 'undefined') return;
 const map = document.querySelector('[data-threat-map]'); if (!map) return;
 const svg=map.querySelector('svg'), viewport=map.querySelector('.tg-viewport'), camera=map.querySelector('[data-geo-camera]'), markers=map.querySelector('[data-geo-markers]'), empty=map.querySelector('[data-geo-empty]'), status=map.querySelector('[data-geo-status]'), more=map.querySelector('[data-geo-more]'), form=map.querySelector('[data-geo-filters]'), popup=map.querySelector('[data-geo-popup]');
 let view=clampCamera(1,0,0), page=1, controller=null, dragging=false, start=null, generation=0;
 const say = text => { status.textContent=text; };
 const element = (name,text) => { const n=document.createElement(name);n.textContent=text;return n; };
 const describe = event => {
  const box=map.querySelector('[data-geo-details]');box.replaceChildren(element('h3',`${event.event_type} · ${event.country}`));
  for (const [label,value] of [['Source',event.source_name],['Observed',event.observed_at],['Approximate location type',event.geo_type],['Geolocation confidence',event.confidence],['Verification',event.verification_status]]) box.append(element('p',`${label}: ${value}`));
  box.append(element('p','Location does not establish attacker origin.'));
  try { const url=new URL(event.evidence_url); if(url.protocol==='https:'&&!url.username&&!url.password){const a=element('a','View evidence ↗');a.href=url.href;a.rel='noopener noreferrer';box.append(a);} } catch (_) { /* No untrusted URL fallback. */ }
  popup.hidden=false;popup.querySelector('button').focus();
 };
 const renderItems = (items,append) => {
  if(!append)markers.replaceChildren();
  for (const cluster of items) {
   if(!Number.isFinite(cluster.latitude)||!Number.isFinite(cluster.longitude)||!Number.isInteger(cluster.count)||cluster.count<1)continue;
   const [x,y]=project(cluster.latitude,cluster.longitude),g=document.createElementNS('http://www.w3.org/2000/svg','g');g.setAttribute('transform',`translate(${x},${y})`);g.setAttribute('tabindex','0');g.setAttribute('role','button');g.setAttribute('aria-label',`${cluster.count} verified observations; open evidence`);
   const circle=document.createElementNS(g.namespaceURI,'circle');circle.setAttribute('r',String((cluster.count>1?12:6)/view.scale));circle.setAttribute('class','tg-marker');g.append(circle);
   if(cluster.count>1){const label=document.createElementNS(g.namespaceURI,'text');label.setAttribute('text-anchor','middle');label.setAttribute('dy','.35em');label.setAttribute('font-size',String(11/view.scale));label.textContent=String(cluster.count);g.append(label);}
   const open=()=>{if(cluster.events?.length===1){describe(cluster.events[0]);}else{const box=map.querySelector('[data-geo-details]');box.replaceChildren(element('h3',`${cluster.count} verified observations in this cluster`),element('p','Zoom in for smaller clusters. Evidence below is a bounded sample, not the full cluster.'));for(const event of cluster.events||[]){const button=element('button',`${event.source_name} · ${event.observed_at}`);button.type='button';button.addEventListener('click',()=>describe(event));box.append(button);}popup.hidden=false;popup.querySelector('button').focus();}};
   g.addEventListener('click',open);g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();open();}});markers.append(g);
  }
 };
 const load = async (append=false) => {
  if(controller)controller.abort();controller=new AbortController();const request=++generation;if(!append){markers.replaceChildren();map.dataset.state='loading';say('Loading verified observations from the local store…');}
  try {
   const endpoint=new URL(map.dataset.endpoint,location.origin);if(endpoint.origin!==location.origin||!endpoint.pathname.endsWith('/cyberdat-geo/v1/events'))throw new Error('Unsafe map endpoint');
   const query=new URLSearchParams(new FormData(form));query.set('zoom',String(Math.round(view.scale)));query.set('page',String(page));query.set('per_page','100');query.set('format','clusters');endpoint.search=query;
   const timer=setTimeout(()=>controller.abort(),10000);let response;
   try{response=await fetch(endpoint,{credentials:'same-origin',cache:'no-store',redirect:'error',signal:controller.signal,headers:{Accept:'application/json'}});}finally{clearTimeout(timer);}
   if(!response.ok)throw new Error('Map unavailable');const text=await response.text();if(text.length>2097152)throw new Error('Response budget');const data=JSON.parse(text);if(data.schema!==1||data.mode!=='observed_events'||data.live_available!==false||!Array.isArray(data.items)||data.items.length>100)throw new Error('Invalid map data');if(request!==generation)return;
   renderItems(data.items,append);empty.querySelector('strong').textContent=data.empty_message;empty.querySelector('span').textContent=Object.keys(data.sources).length?'No verified observations match these filters.':'No telemetry sources connected. No simulated events are shown.';empty.hidden=data.matched_events!==0;more.hidden=!data.has_more||page>=10;map.dataset.state=data.matched_events?'observations':'empty';
   say(`${data.matched_events} verified observations in the selected local window. Observed Events mode; no live telemetry. ${data.coverage_limited?'Coverage limited to 1,000 recent verified records. ':''}${data.has_more?'More clusters are available. ':''}Cache generated ${data.generated_at}.`);
  }catch(error){if(error.name==='AbortError')return;map.dataset.state='error';if(!append){empty.hidden=false;empty.querySelector('strong').textContent='Verified geographic events unavailable.';empty.querySelector('span').textContent='No simulated data is substituted.';}say('Verified geo events unavailable. No simulated data is substituted.');}
 };
 const transform = () => {camera.setAttribute('transform',`translate(${view.x} ${view.y}) scale(${view.scale})`);map.dataset.zoom=String(view.scale);};
 const zoom = delta => {const scale=Math.max(1,Math.min(6,view.scale+delta)),ratio=scale/view.scale;view=clampCamera(scale,500-(500-view.x)*ratio,250-(250-view.y)*ratio);transform();page=1;load();};
 map.querySelectorAll('[data-geo-action]').forEach(button=>button.addEventListener('click',()=>{const action=button.dataset.geoAction;if(action==='in')zoom(1);if(action==='out')zoom(-1);if(action==='reset'){view=clampCamera(1,0,0);transform();page=1;load();}if(action==='pan'){dragging=!dragging;button.setAttribute('aria-pressed',String(dragging));viewport.classList.toggle('is-dragging-enabled',dragging);}}));
 viewport.addEventListener('keydown',e=>{if(e.target!==viewport)return;const directions={ArrowLeft:[60,0],ArrowRight:[-60,0],ArrowUp:[0,40],ArrowDown:[0,-40]};if(directions[e.key]){e.preventDefault();const [x,y]=directions[e.key];view=clampCamera(view.scale,view.x+x,view.y+y);transform();}else if(e.key==='+'||e.key==='='){e.preventDefault();zoom(1);}else if(e.key==='-'){e.preventDefault();zoom(-1);}});
 viewport.addEventListener('pointerdown',e=>{if(!dragging||e.target.closest('[role=button]'))return;start={id:e.pointerId,x:e.clientX,y:e.clientY,vx:view.x,vy:view.y};viewport.setPointerCapture(e.pointerId);});
 viewport.addEventListener('pointermove',e=>{if(!start||start.id!==e.pointerId)return;const matrix=svg.getScreenCTM();if(!matrix)return;view=clampCamera(view.scale,start.vx+(e.clientX-start.x)/matrix.a,start.vy+(e.clientY-start.y)/matrix.d);transform();});
 ['pointerup','pointercancel','lostpointercapture'].forEach(name=>viewport.addEventListener(name,()=>{start=null;}));
 form.addEventListener('submit',e=>{e.preventDefault();page=1;load();});more.addEventListener('click',()=>{page++;load(true);});map.querySelector('[data-geo-close]').addEventListener('click',()=>{popup.hidden=true;viewport.focus();});
 map.addEventListener('keydown',e=>{if(e.key==='Escape'&&!popup.hidden){popup.hidden=true;viewport.focus();}});
 transform();load();
})();
