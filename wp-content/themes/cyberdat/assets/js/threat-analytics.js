/* Read-only same-origin paginated records. No external API requests or untrusted HTML insertion. */
(() => {
 'use strict';
 const root=document.querySelector('[data-analytics-endpoint]'), dialog=document.querySelector('[data-analytics-dialog]');
 if(!root||!dialog||!dialog.showModal)return;
 const endpoint=new URL(root.dataset.analyticsEndpoint,location.href);if(endpoint.origin!==location.origin)return;
 const form=dialog.querySelector('form'), list=dialog.querySelector('[data-ta-results]'), status=dialog.querySelector('[data-ta-status]'), refresh=dialog.querySelector('[data-ta-refresh]');
 let selected=null,page=1,pages=0,revision='',trigger=null,controller=null,serial=0;
 const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
 const pagesUI=busy=>{dialog.querySelector('[data-ta-page=previous]').disabled=busy||page<=1;dialog.querySelector('[data-ta-page=next]').disabled=busy||page>=pages;};
 const load=async()=>{
  if(!selected)return;const id=++serial;if(controller)controller.abort();const abort=new AbortController();controller=abort;
  const url=new URL(endpoint);const params={...selected,page,per_page:20,q:form.elements.q.value.trim(),sort:form.elements.sort.value,revision};Object.entries(params).forEach(([k,v])=>{if(v!=='')url.searchParams.set(k,String(v));});
  status.textContent='Loading verified source records…';list.replaceChildren();pagesUI(true);refresh.hidden=true;
  const timeout=setTimeout(()=>abort.abort(),15000);
  try{
   const response=await fetch(url,{method:'GET',credentials:'same-origin',headers:{Accept:'application/json'},signal:abort.signal});
   if(id!==serial)return;
   if(response.status===409){revision='';status.textContent='Data changed since this selection. Refresh to see current records; counts may differ from the earlier chart.';refresh.hidden=false;return;}
   if(!response.ok){status.textContent=response.status===503?'Research data is updating. Retry shortly.':'Records could not be loaded.';refresh.hidden=false;return;}
   const data=await response.json();if(id!==serial||!dialog.open)return;
   if(!Array.isArray(data.items)||data.items.length>50||!Number.isInteger(data.total)||!Number.isInteger(data.pages))throw Error('Invalid response');
   revision=data.revision;pages=data.pages;page=data.page;
   status.textContent=data.total+' matching records · '+(data.filter.date||data.filter.days==='all'?'':data.filter.days+' UTC days · ')+'projection '+new Date(data.generated_at*1000).toISOString()+'.';
   if(Number(root.dataset.analyticsGenerated)!==data.generated_at)status.textContent+=' Source data has refreshed since the chart; this list uses the current verified projection.';
   if(!data.items.length)list.append(el('p','No verified records match this filter.'));
   for(const record of data.items){
    const card=el('article',undefined,'ta-record'), heading=el('h3');const link=el('a',record.title||record.id);let target;try{target=new URL(record.url);}catch(_){continue;}if(target.protocol!=='https:')continue;
    link.href=target.href;link.rel='noopener noreferrer';heading.append(link);card.append(heading);
    if(record.id?.startsWith('CVE-'))card.append(el('p',record.id,'ta-cve'));
    const metric=record.score===null?'Unrated':record.severity+' · CVSS '+record.cvss_version+' · '+record.score;
    card.append(el('p',metric+' · '+record.source_name,'ta-meta'));
    card.append(el('p',record.date_added?'CISA dateAdded: '+record.date_added+' UTC':'Published: '+record.published+' UTC','ta-meta'));
    if(record.description)card.append(el('p',record.description));list.append(card);
   }
   dialog.querySelector('[data-ta-page-label]').textContent='Page '+(pages?page:0)+' / '+pages;pagesUI(false);
  }catch(error){if(id===serial){status.textContent=error.name==='AbortError'?'Request timed out or was cancelled. Retry shortly.':'Verified records are temporarily unavailable.';refresh.hidden=false;}}
  finally{clearTimeout(timeout);}
 };
 const open=(query,label,source)=>{
  trigger=source;selected=query;page=1;pages=0;revision=root.dataset.analyticsRevision||'';form.reset();dialog.querySelector('[data-ta-title]').textContent=label;dialog.showModal();dialog.querySelector('[data-ta-close]').focus();load();
 };
 const actionable=(node,group,value)=>{node.dataset.drillGroup=group;node.dataset.drillValue=value;node.setAttribute('role','button');node.setAttribute('aria-haspopup','dialog');node.setAttribute('tabindex','0');};
 root.querySelectorAll('[data-chart-id=cvss-severity] .td-ring-segment').forEach(n=>actionable(n,'severity',n.dataset.tooltip.split(' · ')[0]));
 root.querySelectorAll('[data-chart-id=ransomware] .td-ring-segment').forEach(n=>actionable(n,'ransomware',n.dataset.tooltip.startsWith('Known ransomware use')?'known':'not_known'));
 const sources=['cisa-advisories','cert-eu','msrc'];root.querySelectorAll('[data-chart-id=advisory-sources] .td-advisory-column rect').forEach((n,i)=>actionable(n,'advisory',sources[i]));
 root.querySelectorAll('.td-overlap-row').forEach((row,i)=>{const rects=row.querySelectorAll('rect');if(rects[0])actionable(rects[0],'overlap',i===0?'kev_only':'nvd_only');if(rects[1])actionable(rects[1],'overlap','shared');});
 // Text alternatives keep zero-count/tiny segments reachable on touch and keyboard.
 const browse=(selector,group,values)=>{
  const card=root.querySelector(selector);if(!card)return;const details=el('details',undefined,'ta-browse'),summary=el('summary','Browse source records'),controls=el('div',undefined,'ta-set-controls');details.append(summary,controls);
  values.forEach(([value,label])=>{const button=el('button',label);button.type='button';button.dataset.drillGroup=group;button.dataset.drillValue=value;button.setAttribute('aria-haspopup','dialog');controls.append(button);});card.append(details);
 };
 browse('[data-chart-id=cvss-severity]','severity',['Critical','High','Medium','Low','None','Unrated'].map(v=>[v,v]));
 browse('[data-chart-id=ransomware]','ransomware',[['known','Known ransomware use'],['not_known','Not marked Known / unreported']]);
 browse('[data-chart-id=advisory-sources]','advisory',[['cisa-advisories','CISA Cybersecurity Advisories'],['cert-eu','CERT-EU'],['msrc','Microsoft Security Response Center']]);
 root.querySelectorAll('.ta-set-controls[hidden]').forEach(n=>{n.hidden=false;});
 const activate=event=>{
  const point=event.target.closest('.td-chart-point'), mark=event.target.closest('[data-drill-group]');
  if(point){const chart=point.closest('[data-chart-line]'), date=(point.dataset.tooltip||'').match(/^\d{4}-\d{2}-\d{2}/)?.[0];if(!date)return;const days=chart.dataset.activePeriod||'30',value=chart.dataset.chartLine.includes('kev')?'kev':'nvd';open({group:'day',value,date,days},value.toUpperCase()+' · '+date+' UTC · '+days+'D',point);}
  else if(mark){open({group:mark.dataset.drillGroup,value:mark.dataset.drillValue},mark.getAttribute('aria-label')||mark.textContent||mark.dataset.drillValue,mark);}
 };
 root.addEventListener('click',activate);
 root.addEventListener('keydown',event=>{if(['Enter',' '].includes(event.key)&&event.target.matches('.td-chart-point,[data-drill-group]')){event.preventDefault();activate(event);}});
 // Dynamic SVG line points remain keyboard-operable after period redraws.
 const decorate=()=>root.querySelectorAll('.td-chart-point').forEach(n=>{n.setAttribute('role','button');n.setAttribute('aria-haspopup','dialog');});decorate();new MutationObserver(decorate).observe(root,{childList:true,subtree:true});
 form.addEventListener('submit',event=>{event.preventDefault();page=1;load();});
 dialog.querySelectorAll('[data-ta-page]').forEach(button=>button.addEventListener('click',()=>{page+=button.dataset.taPage==='next'?1:-1;load();}));
 refresh.addEventListener('click',()=>{page=1;revision='';load();});
 dialog.querySelector('[data-ta-close]').addEventListener('click',()=>dialog.close());
 dialog.addEventListener('close',()=>{serial++;controller?.abort();trigger?.focus();});
})();
