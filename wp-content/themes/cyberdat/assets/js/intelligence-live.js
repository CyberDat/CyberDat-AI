/* Same-origin projection refresh. No source fetch, ingestion or article publication. */
(() => {
 'use strict';
 const interval = 60000;
 const filterKeys = ['ti_source','ti_kind','ti_severity'];
 const readFilters = root => Object.fromEntries(filterKeys.map(key=>[key,root.querySelector('[name="'+key+'"]')?.value || 'all']));
 const capture = root => ({
  pulse: root.querySelector('[data-pulse-period][aria-pressed=true]')?.dataset.pulsePeriod,
  filters: ['ti_source','ti_kind','ti_severity'].map(key=>[key,root.querySelector('[name="'+key+'"]')?.value]),
  charts: [...root.querySelectorAll('[data-chart-line]')].map(n => [n.dataset.chartLine, n.dataset.activePeriod || '30']),
  focus: root.contains(document.activeElement) ? document.activeElement.id : ''
 });
 const restore = (root, state) => {
  for(const [key,value] of state.filters){const field=root.querySelector('[name="'+key+'"]');if(field&&value!==undefined)field.value=value;}
  if (state.pulse) [...root.querySelectorAll('[data-pulse-period]')].find(n => n.dataset.pulsePeriod === state.pulse)?.click();
  for (const [id, days] of state.charts) {
   const chart = [...root.querySelectorAll('[data-chart-line]')].find(n => n.dataset.chartLine === id);
   if (chart) [...chart.querySelectorAll('[data-period]')].find(n => n.dataset.period === days)?.click();
  }
  if (state.focus) [...root.querySelectorAll('[id]')].find(n => n.id === state.focus)?.focus({preventScroll:true});
 };
 for (const initial of document.querySelectorAll('[data-intelligence-live]')) {
  let root=initial, busy=false, pending=false, controller=null, generation=0, userAction=null, activeFilter=false;
  let appliedFilters=readFilters(root),feedFeedback=root.querySelector('[data-feed-status]')?.textContent || '';
  let endpoint;try{endpoint=new URL(root.dataset.liveEndpoint,location.href);}catch(_){continue;}
  if(endpoint.origin!==location.origin||!['overview','pulse'].includes(root.dataset.intelligenceLive))continue;
  const modalOpen=()=>!!root.querySelector('dialog[open]');
  const status=text=>{const target=root.querySelector('[data-live-status]');if(target)target.textContent=text;};
  const feedStatus=text=>{feedFeedback=text;const target=root.querySelector('[data-feed-status]');if(target)target.textContent=text;};
  const showResults=()=>{
   const results=root.querySelector('.td-feed');if(!results)return;
   let edge=0;
   const bars=[...document.querySelectorAll('#wpadminbar,.site-header')].filter(node=>['fixed','sticky'].includes(getComputedStyle(node).position)).map(node=>node.getBoundingClientRect()).sort((a,b)=>a.top-b.top);
   for(const box of bars){if(box.top<=edge+1&&box.bottom>edge)edge=box.bottom;}
   results.focus({preventScroll:true});
   window.scrollTo({top:Math.max(0,window.scrollY+results.getBoundingClientRect().top-edge-16),behavior:'instant'});
  };
  const commitURL=filters=>{
   const url=new URL(location.href);
   for(const key of filterKeys){if(filters[key]==='all')url.searchParams.delete(key);else url.searchParams.set(key,filters[key]);}
   url.hash='intelligence-feed';
   if(url.href!==location.href)history.pushState(history.state,'',url);
  };
  const filter= (filters,historyMode='push')=>{
   for(const key of filterKeys){const field=root.querySelector('[name="'+key+'"]');if(field)field.value=filters[key];}
   generation++;userAction={filters,historyMode};pending=true;controller?.abort();refresh();
  };
  const refresh=async()=>{
   if(document.hidden||modalOpen()){pending=true;return;}
   if(busy){pending=true;return;}
   busy=true;pending=false;controller=new AbortController();
   const action=userAction;userAction=null;activeFilter=!!action;const serial=generation;
   const filters=action?.filters || appliedFilters;
   if(action){feedStatus('Applying filters…');root.querySelector('.td-filters')?.setAttribute('aria-busy','true');}
   const timeout=setTimeout(()=>controller.abort(),20000);
   try{
    let data;
    if(action){
     // The ordinary cached page stays readable while ingestion holds the live-REST guard.
     // Fetch its HTML, never navigate or execute its document scripts.
     const url=new URL(root.querySelector('.td-filters').action,location.href);
     if(url.origin!==location.origin)throw Error('Unexpected filter destination');
     for(const key of filterKeys)url.searchParams.set(key,filters[key]);url.hash='';
     const response=await fetch(url,{credentials:'same-origin',cache:'no-store',headers:{Accept:'text/html'},signal:controller.signal});
     if(!response.ok)throw Error('Filtered data temporarily unavailable');
     const html=await response.text();if(html.length>4194304)throw Error('Invalid filter document');
     const doc=new DOMParser().parseFromString(html,'text/html'),sections=doc.querySelectorAll('[data-intelligence-live="overview"]');
     if(sections.length!==1)throw Error('Missing filter section');const section=sections[0];
     data={revision:section.dataset.liveRevision,generated_at:Number(section.dataset.displayGenerated),changed:true,html:section.outerHTML};
    }else{
     const url=new URL(endpoint);url.searchParams.set('view',root.dataset.intelligenceLive);url.searchParams.set('revision',root.dataset.liveRevision||'');
     if(root.dataset.intelligenceLive==='overview')for(const key of filterKeys)url.searchParams.set(key,appliedFilters[key]);
     const response=await fetch(url,{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'},signal:controller.signal});
     if(!response.ok)throw Error('Projection temporarily unavailable');data=await response.json();
    }
    if(serial!==generation)return;
    if(!/^[a-f0-9]{64}$/.test(data.revision)||!Number.isSafeInteger(data.generated_at)||typeof data.changed!=='boolean')throw Error('Invalid projection');
    if(data.changed){
     if((!action&&data.revision===root.dataset.liveRevision)||typeof data.html!=='string'||data.html.length>2097152)throw Error('Invalid changed projection');
     if(document.hidden||modalOpen()){if(action)userAction=action;pending=true;return;}
     const doc=new DOMParser().parseFromString(data.html,'text/html'), next=doc.body.firstElementChild;
     if(doc.body.children.length!==1||!next||next.dataset.intelligenceLive!==root.dataset.intelligenceLive||next.dataset.liveRevision!==data.revision||Number(next.dataset.displayGenerated)!==data.generated_at||doc.querySelector('script,iframe,object,embed,base'))throw Error('Invalid projection fragment');
     if([...next.querySelectorAll('*'),next].some(n=>[...n.attributes].some(a=>/^on/i.test(a.name))))throw Error('Unexpected fragment handler');
     if(!action&&feedFeedback){const feedback=next.querySelector('[data-feed-status]');if(feedback){feedFeedback=feedFeedback.startsWith('Filters applied.')?'Filters applied. '+(next.querySelector('.td-feed')?.dataset.feedCount || '0')+' results.':feedFeedback;feedback.textContent=feedFeedback;}}
     const liveStatus=next.querySelector('[data-live-status]');if(liveStatus)liveStatus.textContent='Checked '+new Date().toISOString().slice(11,19)+' UTC. Displayed data updated '+new Date(data.generated_at*1000).toISOString().replace('T',' ').slice(0,19)+' UTC.';
     const state=capture(root);document.dispatchEvent(new CustomEvent('cyberdat:intelligence-before-update',{detail:{root}}));
     root.replaceWith(next);root=next;document.dispatchEvent(new CustomEvent('cyberdat:intelligence-updated',{detail:{root}}));restore(root,state);
    }else if(data.revision!==root.dataset.liveRevision){throw Error('Revision mismatch');}
    if(action){
     if(!data.changed)throw Error('Missing filtered fragment');
     appliedFilters={...filters};if(action.historyMode==='push')commitURL(filters);
     feedStatus('Filters applied. '+(root.querySelector('.td-feed')?.dataset.feedCount || '0')+' results.');showResults();
    }
    root.dataset.liveChecked=String(Math.floor(Date.now()/1000));
    status('Checked '+new Date().toISOString().slice(11,19)+' UTC. Displayed data updated '+new Date(data.generated_at*1000).toISOString().replace('T',' ').slice(0,19)+' UTC.');
   }catch(error){if(serial===generation){if(action)feedStatus('Filters could not be applied. The previous results are retained. Try again.');else status('Update check unavailable; retaining the displayed data. Retrying on the next check.');}}
   finally{clearTimeout(timeout);root.querySelector('.td-filters')?.removeAttribute('aria-busy');busy=false;activeFilter=false;controller=null;if(pending&&!document.hidden&&!modalOpen()){pending=false;Promise.resolve().then(refresh);}}
  };
  document.addEventListener('submit',event=>{if(root.contains(event.target)&&event.target.matches('.td-filters')){event.preventDefault();filter(readFilters(root));}});
  document.addEventListener('click',event=>{const reset=event.target.closest('[data-feed-reset]');if(reset&&root.contains(reset)&&!event.ctrlKey&&!event.metaKey&&!event.shiftKey&&!event.altKey&&event.button===0){event.preventDefault();filter(Object.fromEntries(filterKeys.map(key=>[key,'all'])));}});
  if(root.dataset.intelligenceLive==='overview')window.addEventListener('popstate',()=>{
   const url=new URL(location.href),filters={};
   for(const key of filterKeys){const value=url.searchParams.get(key)||'all',field=root.querySelector('[name="'+key+'"]');filters[key]=field&&[...field.options].some(n=>n.value===value)?value:'all';}
   if(!userAction&&!activeFilter&&filterKeys.every(key=>filters[key]===appliedFilters[key]))return;
   filter(filters,'none');
  });
  setInterval(refresh,interval);
  document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
  window.addEventListener('pageshow',event=>{if(event.persisted)refresh();});
  document.addEventListener('close',()=>{if(pending&&!modalOpen())refresh();},true);
  window.addEventListener('pagehide',()=>controller?.abort());
 }
})();
