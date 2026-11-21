/* Review regression: synthetic factories only; no private fixtures or literal credentials. */
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=process.env.EXPORT_REGRESSION_ROOT||path.resolve(__dirname,'../wp-content/themes/cyberdat');
const bom=require(root+'/assets/js/ai-model-bom/engine.js'),atlas=require(root+'/assets/js/atlas-mapper/engine.js');
const {SYNTH:S}=require('./lib/synthetic-secrets.cjs');
const rows=[],tests=[];const test=(id,fn)=>tests.push([id,fn]);
const unmd=s=>String(s).replace(/\\([\\`*_{}\[\]<>()#+!|~])/gu,'$1');
function absent(text,values){for(const v of values)assert.ok(!unmd(text).includes(v),'synthetic probe remains in output')}
function inv(){const r=JSON.parse(JSON.stringify(bom.EXAMPLE));r.weights=[{file:'audit.safetensors',format:'safetensors',hashAlg:'SHA-256',hash:crypto.createHash('sha256').update('reviewed synthetic public digest').digest('hex'),source:'https://artifacts.example.invalid/models/audit'}];return r}
for(const [kind,secret]of [['known',S.OPENAI_PROJECT_KEY],['opaque',S.OPAQUE_LONG]]){
 test('HASH-'+kind+'-build-findings',()=>{const r=inv();r.weights[0].hash=secret;const f=bom.build(r).findings.find(x=>x.rule==='AIBOM-WGT-001');assert.ok(f);absent(JSON.stringify(f),[secret.slice(0,24)])});
 test('HASH-'+kind+'-markdown',()=>{const r=inv();r.weights[0].hash=secret;absent(bom.build(r).markdown,[secret.slice(0,24)])});
 test('HASH-'+kind+'-review-findings',()=>{const raw=JSON.parse(bom.build(inv()).bomText);raw.components.find(x=>x.type==='file').hashes[0].content=secret;const r=bom.review(JSON.stringify(raw));assert.ok(r.findings.some(x=>x.rule==='AIBOM-WGT-001'));absent(JSON.stringify(r.findings),[secret.slice(0,24)])});
}
for(const prefix of ['ключ','clé','cle\u0301'])for(const [kind,secret]of [['known',S.OPENAI_PROJECT_KEY],['opaque',S.OPAQUE_LONG]]){
 test('BOM-Unicode-'+prefix+'-'+kind,()=>{const r=inv();r.purpose=prefix+secret;const b=bom.build(r);absent(b.bomText+b.markdown,[secret]);absent(bom.maskSecrets(prefix+secret),[secret])});
 test('ATLAS-Unicode-'+prefix+'-'+kind,()=>{absent(atlas.maskSecrets(prefix+secret),[secret]);const r=atlas.exportSelection([{id:'AML.T0051',note:prefix+secret}]);absent(r.json+r.markdown,[secret])});
}
for(const [kind,secret]of [['known',S.OPENAI_PROJECT_KEY],['opaque',S.OPAQUE_LONG]]){
 test('BOM-URL-path-'+kind,()=>{const r=inv();r.weights[0].source='https://artifacts.example.invalid/v1/'+secret+'/run';const b=bom.build(r);absent(b.bomText+b.markdown,[secret]);const component=b.bom.components.find(x=>x.type==='file');const f=component.externalReferences?.find(x=>x.type==='distribution')?.url||component.properties?.find(x=>x.name==='cyberdat:aibom:source')?.value||'';assert.ok(f.startsWith('https://artifacts.example.invalid/v1/')&&f.endsWith('/run'))});
}
test('BOM-URL-path-with-query-credential',()=>{const r=inv();r.weights[0].source='https://artifacts.example.invalid/v1/'+S.OPAQUE_LONG+'/run?token='+S.ASSIGNED_SECRET;const b=bom.build(r);absent(b.bomText+b.markdown,[S.OPAQUE_LONG,S.ASSIGNED_SECRET])});
test('BOM-URL-path-with-userinfo',()=>{const r=inv();r.weights[0].source='https://audit:'+S.ASSIGNED_SECRET+'@artifacts.example.invalid/v1/'+S.OPAQUE_LONG+'/run';const b=bom.build(r);absent(b.bomText+b.markdown,[S.OPAQUE_LONG,S.ASSIGNED_SECRET])});
for(const key of ['token','access_token','api_key'])test('ATLAS-URL-query-'+key,()=>{const url='https://api.example.invalid/v1/run?'+key+'='+S.ASSIGNED_SECRET+'&mode=audit';absent(atlas.maskSecrets(url),[S.ASSIGNED_SECRET]);const r=atlas.exportSelection([{id:'AML.T0051',note:url}]);absent(r.json+r.markdown,[S.ASSIGNED_SECRET]);assert.ok(atlas.maskSecrets(url).startsWith('https://api.example.invalid/'))});
test('ATLAS-URL-userinfo',()=>{const url='https://audit:'+S.ASSIGNED_SECRET+'@api.example.invalid/v1/run';absent(atlas.maskSecrets(url),[S.ASSIGNED_SECRET]);const r=atlas.exportSelection([{id:'AML.T0051',note:url}]);absent(r.json+r.markdown,[S.ASSIGNED_SECRET]);assert.ok(atlas.maskSecrets(url).startsWith('https://'))});
test('ATLAS-URL-userinfo-and-query',()=>{const r=atlas.exportSelection([{id:'AML.T0051',note:'https://audit:'+S.ASSIGNED_PLAIN+'@api.example.invalid/run?token='+S.ASSIGNED_SECRET+'#review'}]);absent(r.json+r.markdown,[S.ASSIGNED_PLAIN,S.ASSIGNED_SECRET])});
test('ATLAS-query-fragment-retained',()=>{const s=atlas.maskSecrets('https://api.example.invalid/run?token='+S.ASSIGNED_SECRET+'#review');absent(s,[S.ASSIGNED_SECRET]);assert.ok(s.endsWith('#review'))});
test('ATLAS-harmless-https-preserved',()=>{const s='https://api.example.invalid/v1/run?mode=audit';assert.equal(atlas.maskSecrets(s),s)});
test('ATLAS-assignment-key-boundary',()=>{const s='notatoken='+S.ASSIGNED_PLAIN;assert.equal(atlas.maskSecrets(s),s)});
test('BOM-public-digest-and-safe-path-preserved',()=>{const r=inv(),b=bom.build(r),f=b.bom.components.find(x=>x.type==='file');assert.equal(f.hashes[0].content,r.weights[0].hash);assert.equal(f.externalReferences.find(x=>x.type==='distribution').url,r.weights[0].source)});
test('Unicode-contract-no-lookbehind',()=>{for(const n of ['ai-model-bom','atlas-mapper']){const s=fs.readFileSync(root+'/assets/js/'+n+'/engine.js','utf8');assert.ok(!s.includes('(?<=')&&!s.includes('(?<!'))}});
for(const[id,fn]of tests){try{fn();rows.push({id,pass:true})}catch(e){rows.push({id,pass:false,error:e.name})}}
const out={tests:rows.length,pass:rows.filter(x=>x.pass).length,fail:rows.filter(x=>!x.pass).length,rows};console.log(JSON.stringify(out,null,2));if(process.env.EXPORT_REVIEW_RESULT)fs.writeFileSync(process.env.EXPORT_REVIEW_RESULT,JSON.stringify(out,null,2)+'\n');process.exitCode=out.fail?1:0;
