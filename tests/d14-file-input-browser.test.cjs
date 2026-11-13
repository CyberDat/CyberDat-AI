/* Loopback-only file provenance/line-ending regressions. No sensitive fixture text. */
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const pw=require('playwright');
const origin=process.argv[2],browserName=process.argv[3],output=process.argv[4];
if(origin!=='http://127.0.0.1:18092'||!['chromium','firefox','webkit'].includes(browserName)||!output)throw Error('Explicit isolated fixture/browser/private output required');
if(fs.existsSync(output))throw Error('Evidence already exists');fs.mkdirSync(output,{recursive:true,mode:0o700});
(async()=>{const opts={headless:true};if(browserName==='webkit')opts.executablePath=process.env.CYBERDAT_WEBKIT_EXECUTABLE;const browser=await pw[browserName].launch(opts);const rows=[];try{
 for(const scenario of ['CRLF','LF','mixed','CR','inline-boundary','large-file','edit','read-race']){
  const context=await browser.newContext({acceptDownloads:true});const page=await context.newPage();let phase='load';const unexpected=[],errors=[];
  context.on('request',r=>{const u=new URL(r.url());if(u.origin!==origin||r.method()!=='GET'||r.postData()||(phase!=='load'&&!u.pathname.startsWith('/wp-content/themes/cyberdat/assets/')))unexpected.push({phase,type:r.resourceType()});});
  await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());page.on('pageerror',()=>errors.push('runtime'));
  await page.goto(origin+'/tools/log-anonymizer/');phase='input';
  let text=scenario==='CRLF'?'first public line\r\nsecond public line\r\n':scenario==='CR'?'first public line\rsecond public line\r':scenario==='mixed'?'one\r\ntwo\nthree\rfour\r\n':'one public line\ntwo public lines\n';
  if(scenario==='inline-boundary')text='x'.repeat(1048574)+'\r\n';if(scenario==='large-file')text='x'.repeat(1048575)+'\r\n';
  if(scenario==='read-race')await page.evaluate(()=>{const original=File.prototype.text;File.prototype.text=function(){const f=this;return this.name==='delayed.txt'?new Promise(resolve=>setTimeout(()=>resolve(original.call(f)),250)):original.call(this);};});
  await page.setInputFiles('[data-la-file]',{name:scenario==='read-race'?'delayed.txt':'public.txt',mimeType:'text/plain',buffer:Buffer.from(text)});
  if(scenario==='read-race'){text='latest public input\r\n';await page.setInputFiles('[data-la-file]',{name:'latest.txt',mimeType:'text/plain',buffer:Buffer.from(text)});await page.waitForTimeout(350);}
  if(text.length<=1048576)await page.waitForFunction(()=>document.querySelector('[data-la-input]').value.length>0);
  if(scenario==='edit'){text='edited public text\n';await page.fill('[data-la-input]',text);}
  await page.click('[data-la-run]');await page.waitForFunction(()=>!document.querySelector('[data-la-run]').disabled&&!document.querySelector('[data-la-results]').hidden);
  const [download]=await Promise.all([page.waitForEvent('download'),page.click('[data-la-download]')]);const file=path.join(output,scenario+'.txt');await download.saveAs(file);assert.deepEqual(fs.readFileSync(file),Buffer.from(text),scenario+' exact bytes');assert.equal(unexpected.length,0);assert.equal(errors.length,0);rows.push({scenario,pass:true,input_bytes:Buffer.byteLength(text),unexpected_network:0,runtime_errors:0});await context.close();
 }
}finally{await browser.close();}fs.writeFileSync(path.join(output,'summary.json'),JSON.stringify({browser:browserName,checks:rows.length,rows},null,2));console.log(JSON.stringify({browser:browserName,checks:rows.length,pass:true}));})().catch(e=>{console.error(e.name+': file-input regression failed');process.exit(1);});
