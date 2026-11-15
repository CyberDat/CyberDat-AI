/* Synthetic structured-field regressions. Never print values, maps or caught errors. */
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),assets=path.join(root,'wp-content/themes/cyberdat/assets/js/log-anonymizer');
const engine=require(process.env.CYBERDAT_ENGINE_UNDER_TEST||path.join(assets,'engine.js'));
const workerSource=fs.readFileSync(process.env.CYBERDAT_WORKER_UNDER_TEST||path.join(assets,'worker.js'),'utf8');
let passed=0,failed=0,sequence=0;
const value=()=>['ci','field','fixture',++sequence].join('-');
function check(name,fn){try{fn();passed++;console.log('PASS: '+name);}catch{failed++;console.error('FAIL: '+name);}}
function absent(text,values){assert.ok(values.every(v=>!text.includes(v)),'a required value remains');}
function breaks(s){return s.match(/\r\n|\r|\n/g)||[];}
function parse(text,delimiter=','){
 const p=spawnSync('python3',['-c',
  'import csv,io,json,sys;csv.field_size_limit(2147483647);print(json.dumps(list(csv.reader(io.StringIO(sys.stdin.read(),newline=""),delimiter=sys.argv[1],strict=True))))',delimiter],
  {input:text,encoding:'utf8',maxBuffer:32*1024*1024});
 assert.ok(p.status===0,'independent CSV parser rejected output');return JSON.parse(p.stdout);
}
function workerRun(input,options={},api=engine){
 const messages=[],diagnostics=[];
 const self={location:{search:''},navigator:{},postMessage:m=>messages.push(m)};
 const sandbox={self,URLSearchParams,TextDecoder,Uint8Array,console:Object.fromEntries(['log','warn','error','info','debug'].map(k=>[k,()=>diagnostics.push(k)])),
  importScripts:()=>{self.CyberDatLogAnonymizer=api;}};
 vm.runInNewContext(workerSource,sandbox);
 self.onmessage({data:{type:'run',jobId:1,source:{kind:'text',text:input},options}});
 return {message:messages.at(-1),diagnostics};
}

const user=['test','user'].join('_'),password=['Example','Pass',123,'!'].join(''),account=['123456','789012'].join('');
const header='User name,Password,Console sign-in URL';
const sample=header+'\r\n'+[user,password,'https://'+account+'.signin.aws.amazon.com/console'].join(',')+'\r\n';
for(const [name,input] of [['plain',sample],['BOM','\uFEFF'+sample],['Unicode unknown heading',sample.replace('Console sign-in URL','Console sign-in URL ✓')]]){
 check('acceptance CSV privacy: '+name,()=>{const r=engine.anonymize(input);absent(r.output,[user,password,account]);assert.ok(r.stats.username.replacements===1&&r.stats.secret.replacements===1&&r.stats.host.replacements===1);});
 check('acceptance CSV framing and labels: '+name,()=>{const r=engine.anonymize(input);const rows=parse(r.output.replace(/^\uFEFF/,''));assert.deepEqual(rows[1],['USER_1','SECRET_1','https://HOST_1/console']);assert.deepEqual(breaks(r.output),breaks(input));assert.ok(r.output.startsWith(input.slice(0,input.indexOf('\r\n')+2)));});
}
const aliases=[['Username','USER'],['User name','USER'],['Login','USER'],['User ID','USER'],['user_id','USER'],['USER-NAME','USER'],
 ['Password','SECRET'],['Passwd','SECRET'],['Pwd','SECRET'],['API Key','SECRET'],['api_key','SECRET'],['Access Token','SECRET'],['Auth Token','SECRET'],['auth-token','SECRET'],
 ['Secret','SECRET'],['Client Secret','SECRET'],['Private Key','SECRET'],['Credentials','SECRET']];
for(const [heading,prefix] of aliases)check('CSV supported heading: '+heading,()=>{
 const sensitive=value(),input=heading+',Unrelated heading ✓\n'+sensitive+',keep-context\n';const r=engine.anonymize(input);
 absent(r.output,[sensitive]);assert.deepEqual(parse(r.output)[1],[prefix+'_1','keep-context']);assert.ok(r.map.some(x=>x.original===sensitive&&x.label===prefix+'_1'));
});
for(const delimiter of [',',';','\t'])for(const eol of ['\n','\r\n','\r'])check('dialect and line endings '+JSON.stringify(delimiter)+' '+JSON.stringify(eol),()=>{
 const sensitive=value(),input=['"User name"','"Password"','"Notes ✓"'].join(delimiter)+eol+['"'+user+'"','"'+sensitive+'"','"keep'+delimiter+'context"'].join(delimiter)+eol;
 const r=engine.anonymize(input);const rows=parse(r.output,delimiter);assert.deepEqual(rows[1],['USER_1','SECRET_1','keep'+delimiter+'context']);assert.deepEqual(breaks(r.output),breaks(input));
});
check('empty and whitespace framing preserved',()=>{
 const input='Username,Password,Notes\r\n,"",keep\r\n  ""  ,  ,stay\r\n';assert.ok(engine.anonymize(input).output===input);
});
check('quoted escaped values are entirely replaced',()=>{
 const sensitive='"'+value()+',"'+value(),raw='"'+sensitive.replace(/"/g,'""')+'"';
 const r=engine.anonymize('Username,Password,Notes\n'+user+','+raw+',keep\n');assert.deepEqual(parse(r.output)[1],['USER_1','SECRET_1','keep']);assert.ok(r.map.some(x=>x.original===sensitive));
});
check('padding, duplicate headers, and trailing empty columns retained',()=>{
 const sensitive=value(),input=' "Username" , "Password" ,Password,\r\n "'+user+'" , "'+sensitive+'" ,'+sensitive+',\r\n';
 const r=engine.anonymize(input);absent(r.output,[user,sensitive]);assert.ok(r.output.includes(' "USER_1" , "SECRET_1" ,SECRET_1,\r\n'));
});
check('multiline quoted cells keep records, breaks and stable labels across chunks',()=>{
 const a=value(),b=value(),secret=a+'\r\n'+b,input='Username,Password,Notes\r\n'+user+',"'+secret+'",keep\r\n'+user+',"'+secret+'",stay\r\n';
 const small=engine.anonymize(input,{}, {chunkChars:1}),large=engine.anonymize(input,{}, {chunkChars:1<<20});
 assert.ok(small.output===large.output);absent(small.output,[user,a,b]);assert.deepEqual(breaks(small.output),breaks(input));
 const rows=parse(small.output);assert.ok(rows.length===3&&rows.every(r=>r.length===3));assert.ok(rows[1][1]===rows[2][1]);
});
check('long quoted cell crossing normal chunk boundary is fully protected',()=>{
 const sensitive=value()+'x'.repeat((1<<20)+11)+'\n'+value(),input='Username,Password\n'+user+',"'+sensitive+'"\n';
 const r=engine.anonymize(input);assert.ok(r.output.length<200);assert.ok(parse(r.output).length===2);assert.deepEqual(breaks(r.output),breaks(input));
});
check('complete contextual fields beat embedded host/IP/custom matches',()=>{
 const sensitive=value()+'@db.example.test:203.0.113.42!'+value();
 const csv=engine.anonymize('Username,Password\n'+user+',"'+sensitive+'"\n',{customRules:[{pattern:'db\\.example\\.test',label:'PART'}]});
 assert.deepEqual(parse(csv.output)[1],['USER_1','SECRET_1']);
 const log=engine.anonymize('password="'+sensitive+'"',{customRules:[{pattern:'db\\.example\\.test',label:'PART'}]});assert.ok(log.output==='password="SECRET_1"');
});
check('ordinary IP, host and email detectors remain active in unrelated CSV fields',()=>{
 const r=engine.anonymize('Username,IP,Email,Host\n'+user+',203.0.113.42,mail@example.test,node.example.test\n');
 assert.deepEqual(parse(r.output)[1],['USER_1','IPV4_1','EMAIL_1','HOST_1']);
});
check('generic matches cannot consume CSV separators or framing quotes',()=>{
 const input='Username,Notes,Status\n'+user+',"Authorization: Custom '+value()+'",keep\n';
 const rows=parse(engine.anonymize(input).output);assert.ok(rows.length===2&&rows[1].length===3&&rows[1][2]==='keep');
});
check('metadata fields and ordinary prose are not inferred as credentials',()=>{
 const input='Password length,Token count,Secret name,User agent,Notes ✓\n12,3,configuration,desktop,keep\n';assert.ok(engine.anonymize(input).output===input);
 const text='A user name is a label. Password policy is strict. token_count=4 password_policy=strict secret_name=configuration';assert.ok(engine.anonymize(text).output===text);
});
check('legacy user/host CSV and ordinary-log labels remain compatible',()=>{
 assert.ok(engine.anonymize('user,host,status\nalice,web01,ok\n').output==='user,host,status\nUSER_1,HOST_1,ok\n');
 assert.ok(engine.anonymize('username='+value()+' password='+value()+' token:'+value()).output==='username=USER_1 password=SECRET_1 token:SECRET_2');
});
check('explicit numeric JSON User ID produces valid JSON',()=>{
 const input=JSON.stringify({'User ID':78923,'User name':user,'Client Secret':password,status:'keep'});const out=JSON.parse(engine.anonymize(input).output);
 assert.deepEqual(out,{'User ID':'USER_1','User name':'USER_2','Client Secret':'SECRET_1',status:'keep'});
});
check('spaced keys, escaped JSON values, null and empty fields',()=>{
 const secret=value()+'"\\'+value(),input=JSON.stringify({'API Key':secret,'Access Token':value(),Password:'',Credentials:null,notes:'keep'});
 const out=JSON.parse(engine.anonymize(input).output);assert.ok(out['API Key']==='SECRET_1'&&out['Access Token']==='SECRET_2'&&out.Password===''&&out.Credentials===null&&out.notes==='keep');
});
check('empty log fields do not consume the following spaced key name',()=>{
 const out=engine.anonymize('username= API Key='+value()+' status=ok').output;assert.ok(out==='username= API Key=SECRET_1 status=ok');
});
check('single-quoted escaped log values and very long scalar secrets are complete',()=>{
 const secret=value()+"\\'"+value();assert.ok(engine.anonymize("password='"+secret+"'").output==="password='SECRET_1'");
 assert.ok(engine.anonymize('password='+value()+'x'.repeat(10000)).output==='password=SECRET_1');
});
check('CSV aliases use consistent labels, group statistics, subtype statistics and map counts',()=>{
 const a=value(),b=value(),c=value(),input='Username,Password,Access Token\n'+[a,b,c].join(',')+'\n'+[a,b,c].join(',')+'\n';const r=engine.anonymize(input);
 assert.ok(r.stats.username.replacements===2&&r.stats.username.unique===1&&r.stats.secret.replacements===4&&r.stats.secret.unique===2);
 for(const type of ['password','token']){assert.ok(r.fieldStats[type].replacements===2&&r.fieldStats[type].unique===1);}assert.ok(r.map.every(x=>x.occurrences===2));
 assert.ok(r.map.length===3);
});
check('existing category switches and generic-label mode apply to structured fields',()=>{
 const categories=Object.fromEntries(engine.CATEGORIES.map(x=>[x.id,false]));categories.username=true;
 const sensitive=value(),input='Username,Password\n'+user+','+sensitive+'\n';const r=engine.anonymize(input,{categories,labelMode:'generic'});
 assert.ok(r.output==='Username,Password\nREDACTED_USER,'+sensitive+'\n');assert.ok(r.stats.secret.replacements===0);
});
check('CSV rows with different shape end the table, ordinary rules continue',()=>{
 const secret=value(),input='Username,Password\n'+user+','+secret+'\nuser='+user+'\n';const r=engine.anonymize(input);absent(r.output,[user,secret]);assert.ok(r.output.endsWith('user=USER_1\n'));
});
check('invalid custom pattern diagnostics never echo entered pattern',()=>{
 const marker=value();let error;try{engine.anonymize('safe',{customRules:[{pattern:'('+marker,label:'LOCAL'}]});}catch(e){error=e;}
 assert.ok(error&&error.code==='CUSTOM_RULE');absent(JSON.stringify({message:error.message,details:error.details}),[marker]);
});
check('worker forwards new totals and emits no diagnostic values',()=>{
 const secret=value(),r=workerRun('Username,Password\n'+user+','+secret+'\n');assert.ok(r.message.type==='result');
 assert.ok(r.message.fieldStats.password.replacements===1&&r.diagnostics.length===0);
});
check('unexpected worker exceptions suppress input and internal details',()=>{
 const marker=value(),r=workerRun('safe',{}, {anonymize(){const e=new Error(marker);e.details={input:marker};throw e;}});
 assert.ok(r.message.type==='error'&&r.message.code==='FAILED'&&r.diagnostics.length===0);absent(JSON.stringify(r.message),[marker]);
});
check('known worker error codes never trust raw messages or details',()=>{
 const marker=value();for(const code of ['CSV_FORMAT','CUSTOM_RULE']){
  const r=workerRun('safe',{}, {anonymize(){const e=new Error(marker);e.code=code;e.details=[{index:0,field:'pattern',message:marker}];throw e;}});
  assert.ok(r.message.type==='error'&&r.message.code===code);absent(JSON.stringify(r.message),[marker]);
 }
});
console.log(JSON.stringify({suite:'structured-fields',pass:passed,fail:failed}));if(failed)process.exitCode=1;
