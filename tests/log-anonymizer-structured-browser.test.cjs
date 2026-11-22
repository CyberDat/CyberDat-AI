/* Local fixture UI/Worker regressions. Evidence contains counts/hashes, never raw inputs. */
'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const pw=require('playwright');
const origin=process.argv[2],name=process.argv[3],output=process.argv[4];
if(!origin||!['chromium','firefox','webkit'].includes(name)||!output)throw Error('Provide loopback origin, browser and fresh evidence directory');
if(!/^http:\/\/127\.0\.0\.1:\d+$/.test(origin))throw Error('This regression runner is loopback-only');
if(fs.existsSync(output))throw Error('Fresh evidence required');fs.mkdirSync(output,{recursive:true,mode:0o700});
const rows=[],markers=[],logs=[],runtime=[];let stage='load',phase='load',unexpected=0,afterInput=0;
const value=()=>{const s=['ci','browser','field',markers.length+1].join('-');markers.push(s);return s;};
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const record=(id,extra={})=>rows.push({id,pass:true,...extra});
(async()=>{
 const options={headless:true};if(name==='webkit')options.executablePath=process.env.CYBERDAT_WEBKIT_EXECUTABLE;
 const browser=await pw[name].launch(options);
 try{
  const context=await browser.newContext({acceptDownloads:true}),page=await context.newPage();
  context.on('request',r=>{if(r.url().startsWith('blob:'))return;const u=new URL(r.url());if(u.origin!==origin||r.method()!=='GET'||r.postData())unexpected++;if(phase!=='load')afterInput++;});
  await context.route('**/*',r=>new URL(r.request().url()).origin===origin?r.continue():r.abort('blockedbyclient'));
  page.on('console',m=>{logs.push(m.text());if(m.type()==='error')runtime.push('console');});page.on('pageerror',e=>{logs.push(e.message);runtime.push('runtime');});
  await page.goto(origin+'/tools/log-anonymizer/',{waitUntil:'networkidle'});
  await page.locator('[data-la-app]:not([hidden])').waitFor();phase='input';
  async function clear(){await page.click('[data-la-clear]');}
  async function run(){await page.click('[data-la-run]');await page.waitForFunction(()=>!document.querySelector('[data-la-run]').disabled&&(!document.querySelector('[data-la-results]').hidden||!document.querySelector('[data-la-error]').hidden));}
  async function downloaded(selector){const [download]=await Promise.all([page.waitForEvent('download'),page.click(selector)]);assert.ok(download.url().startsWith('blob:'));const stream=await download.createReadStream(),parts=[];for await(const chunk of stream)parts.push(chunk);const text=Buffer.concat(parts).toString('utf8');await download.delete();return text;}
  async function goodResult(){assert.ok(await page.locator('[data-la-error]').evaluate(e=>e.hidden));return downloaded('[data-la-download]');}
  stage='BOM CSV upload and export';
  const user=value(),password=value(),account=['123456','789012'].join('');
  const input='\uFEFFUser name,Password,Console sign-in URL\r\n'+[user,password,'https://'+account+'.signin.aws.amazon.com/console'].join(',')+'\r\n';
  await page.setInputFiles('[data-la-file]',{name:'credential-fixture.csv',mimeType:'text/csv',buffer:Buffer.from(input)});await run();
  const text=await goodResult();assert.ok(text==='\uFEFFUser name,Password,Console sign-in URL\r\nUSER_1,SECRET_1,https://HOST_1/console\r\n');
  record('CSV_BOM_UPLOAD_EXPORT',{output_sha256:sha(text),crlf_preserved:true});
  stage='statistics and acknowledged replacement map';
  assert.ok((await page.locator('[data-la-summary]').innerText()).includes('3 values replaced'));
  const notes=await page.locator('[data-la-notes]').innerText();assert.ok(notes.includes('Password fields: 1'));
  assert.ok(await page.locator('[data-la-map]').isDisabled());await page.check('[data-la-map-ack]');
  const map=JSON.parse(await downloaded('[data-la-map]'));assert.ok(map.warning.includes('ORIGINAL SENSITIVE VALUES'));
  assert.ok(map.entries.some(e=>e.label==='USER_1'&&e.original===user)&&map.entries.some(e=>e.label==='SECRET_1'&&e.original===password));
  record('STATS_AND_OPT_IN_MAP',{entries:map.entries.length});
  stage='quoted multiline file';await clear();
  const a=value(),b=value(),csv='Username;Password;Notes ✓\r\n"'+user+'";"'+a+',""'+b+'\r\n'+a+'";"keep;context"\r\n';
  await page.setInputFiles('[data-la-file]',{name:'quoted-fixture.csv',mimeType:'text/csv',buffer:Buffer.from(csv)});await run();
  const multi=await goodResult();assert.ok(multi==='Username;Password;Notes ✓\r\n"USER_1";"SECRET_1\r\nSECRET_1";"keep;context"\r\n');record('QUOTED_MULTILINE_EXPORT',{output_sha256:sha(multi)});
  stage='JSON and log fields';await clear();
  await page.fill('[data-la-input]',JSON.stringify({'User ID':1729,'API Key':password,'Auth Token':a,Password:'',Credentials:null}));await run();
  const json=JSON.parse(await goodResult());assert.ok(json['User ID']==='USER_1'&&json['API Key']==='SECRET_1'&&json['Auth Token']==='SECRET_2'&&json.Password===''&&json.Credentials===null);record('JSON_FIELDS');
  stage='ordinary log fields';await clear();await page.fill('[data-la-input]','username='+user+' password="'+password+'" token:'+a+' ip=203.0.113.42');await run();
  assert.ok((await goodResult())==='username=USER_1 password="SECRET_1" token:SECRET_2 ip=IPV4_1');record('LOG_FIELDS_AND_LEGACY_IP');
  stage='empty fields';await clear();const empty='Username,Password,Status\r\n,"",keep\r\n';
  await page.setInputFiles('[data-la-file]',{name:'empty-fields.csv',mimeType:'text/csv',buffer:Buffer.from(empty)});await run();
  assert.ok((await goodResult())===empty);record('EMPTY_FIELDS');
  stage='metadata false positives';await clear();const benign='Password length,Token count,Notes ✓\n12,3,keep\n';await page.fill('[data-la-input]',benign);await run();
  assert.ok((await goodResult())===benign);record('METADATA_FALSE_POSITIVES');
  stage='CSV boundary';await clear();await page.fill('[data-la-input]','User name,Password\n'+user+','+password+'\nuser='+user);await run();const boundary=await goodResult();assert.ok(boundary==='User name,Password\nUSER_1,SECRET_1\nuser=USER_1');record('CSV_BOUNDARY_CONTINUES_TEXT');
  stage='invalid custom pattern error';await clear();const pattern=value()+'(';await page.click('[data-la-add-rule]');await page.fill('[data-la-rule-pattern]',pattern);await page.fill('[data-la-rule-label]','LOCAL');await page.fill('[data-la-input]','safe');await page.click('[data-la-run]');
  assert.ok((await page.locator('[data-la-error]').innerText()).includes('highlighted'));const ruleError=await page.locator('[data-la-rule-error="pattern"]').innerText();assert.ok(!ruleError.includes(pattern));record('REGEX_ERROR_NO_VALUE_LEAK');
  stage='privacy and diagnostics';assert.ok(afterInput===0&&unexpected===0&&runtime.length===0);assert.ok(markers.every(m=>logs.every(l=>!l.includes(m))));
  const storage=await page.evaluate(async()=>({ls:localStorage.length,ss:sessionStorage.length,cookie:document.cookie,idb:(await indexedDB.databases()).length}));assert.ok(storage.ls===0&&storage.ss===0&&storage.cookie===''&&storage.idb===0);
  record('NO_INPUT_NETWORK_STORAGE_OR_DIAGNOSTIC_LEAK',{after_input_requests:afterInput,unexpected_requests:unexpected,errors:runtime.length});
  const result={pass:true,browser:name,version:browser.version(),checks:rows.length,rows};fs.writeFileSync(path.join(output,'results.json'),JSON.stringify(result,null,2));console.log(JSON.stringify({browser:name,pass:true,checks:rows.length}));await context.close();
 }finally{await browser.close();}
})().catch(e=>{fs.writeFileSync(path.join(output,'results.json'),JSON.stringify({pass:false,browser:name,stage,type:e.name,completed_checks:rows.length,rows},null,2));console.error('FAIL: '+name+' structured browser '+stage);process.exitCode=1;});
