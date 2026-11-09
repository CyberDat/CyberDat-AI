/* Execute actual theme JS with a queued native close event and abortable fetches. No DOM library or network. */
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require('node:path').join(__dirname,'../wp-content/themes/cyberdat/assets/js/threat-analytics.js'),'utf8');
async function exercise(code){
 const handlers=new Map(),queued=[],pending=[];
 class Element{
  constructor(kind='div'){this.kind=kind;this.dataset={};this.hidden=false;this.open=false;this.textContent='';this.children=[];this.className='';}
  addEventListener(name,fn){const key=this.kind+':'+name;handlers.set(key,fn);}
  append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;}setAttribute(){}focus(){context.active=this;}
  showModal(){this.open=true;}close(){this.open=false;queued.push(()=>handlers.get('dialog:close')());}
  querySelector(selector){return nodes[selector]||null;}querySelectorAll(){return [];}
 }
 const dialog=new Element('dialog'),root=new Element('root');root.dataset={analyticsEndpoint:'https://staging.cyberdat.eu/wp-json/cyberdat-analytics/v1/records',analyticsRevision:'revision',analyticsGenerated:'1'};
 const form=new Element('form');form.elements={q:{value:''},sort:{value:'date_desc'}};form.reset=()=>{form.elements.q.value='';form.elements.sort.value='date_desc';};
 const nodes={'form':form,'[data-ta-results]':new Element(),'[data-ta-status]':new Element(),'[data-ta-refresh]':new Element('refresh'),'[data-ta-title]':new Element(),'[data-ta-close]':new Element('close-button'),'[data-ta-page-label]':new Element(),'[data-ta-page=previous]':new Element(),'[data-ta-page=next]':new Element()};
 const context={URL,AbortController,DOMException,setTimeout,clearTimeout,console,location:{origin:'https://staging.cyberdat.eu',href:'https://staging.cyberdat.eu/threat-intelligence/'},MutationObserver:class{observe(){}},document:{querySelector:s=>s==='[data-analytics-endpoint]'?root:s==='[data-analytics-dialog]'?dialog:null,createElement:kind=>new Element(kind)}};
 context.fetch=(url,options)=>new Promise((resolve,reject)=>{const request={filter:new URL(url).searchParams.get('value'),signal:options.signal,resolve:()=>resolve({ok:true,status:200,json:async()=>({items:[],total:0,pages:0,page:1,revision:'revision',generated_at:1,filter:{date:'',days:'all'}})})};pending.push(request);options.signal.addEventListener('abort',()=>reject(new DOMException('cancelled','AbortError')),{once:true});});
 vm.runInNewContext(code,context);
 function choose(value){const mark=new Element('mark');mark.dataset={drillGroup:'severity',drillValue:value};mark.closest=selector=>selector==='.td-chart-point'?null:mark;handlers.get('root:click')({target:mark});return mark;}
 const critical=choose('Critical');pending[0].resolve();await new Promise(setImmediate);assert(nodes['[data-ta-status]'].textContent.includes('matching records'));
 handlers.get('close-button:click')();assert(!dialog.open);const high=choose('High');assert(dialog.open);assert(pending[1].filter==='High');
 // Deliver Critical's queued close AFTER High has opened, exactly the hazardous ordering.
 queued.shift()();await new Promise(setImmediate);const aborted=pending[1].signal.aborted;
 if(!aborted){pending[1].resolve();await new Promise(setImmediate);}
 const loaded=nodes['[data-ta-status]'].textContent.includes('matching records');
 // A genuine close must still cancel an outstanding request and restore focus.
 choose('Medium');const medium=pending[2];handlers.get('close-button:click')();queued.shift()();await new Promise(setImmediate);
 assert(medium.signal.aborted,'Actual closed dialog must cancel its request');assert(context.active.dataset.drillValue==='Medium','Actual close restores the current trigger');
 return {aborted,loaded};
}
(async()=>{
 const result=await exercise(source);
 assert(!result.aborted&&result.loaded,'Delayed previous close must not cancel the reopened dialog');
 const old=source.replace('if(dialog.open)return;','');assert.notEqual(old,source);const broken=await exercise(old);assert(broken.aborted&&!broken.loaded,'Fixture must reproduce the old stuck-loading bug');
 console.log('PASS: reproduced old cancelled-High/loading bug; fixed reopened dialog completes; true close still cancels and restores focus');
})().catch(error=>{console.error(error);process.exitCode=1;});
