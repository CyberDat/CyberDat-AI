/* Regression after independent acceptance; synthetic values only, never private fixtures. */
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../wp-content/themes/cyberdat');
const bom=require(root+'/assets/js/ai-model-bom/engine.js'),atlas=require(root+'/assets/js/atlas-mapper/engine.js');
const {SYNTH}=require('./lib/synthetic-secrets.cjs');
const password=SYNTH.ASSIGNED_SECRET,token=SYNTH.OPENAI_PROJECT_KEY,opaque=SYNTH.OPAQUE_LONG;
const hex=require('node:crypto').createHash('sha256').update('not-a-weights-hash-secret-regression').digest('hex');
const text='password: '+password+'; api_key: '+token+'; unclassified '+opaque;
const unmd=s=>s.replace(/\\([\\`*_{}\[\]<>()#+!|~])/g,'$1');
const safe=(s,values)=>{for(const v of values)assert.ok(!unmd(String(s)).includes(v),'complete synthetic secret remains')};
function inventory(purpose){return {model:{name:'Synthetic model',version:'1.0',vendor:'Example team',license:'Apache-2.0',type:'own'},purpose,limitations:'Exercise only',owner:{name:'Example team',contact:'maintainer@example.invalid'},weights:[{file:'model.safetensors',format:'safetensors',hashAlg:'SHA-256',hash:hex,source:'https://artifacts.example.invalid/model'}]}}
const cases=[];function test(id,fn){cases.push([id,fn])}
test('BOM-01 build JSON masks assigned and known secrets',()=>safe(bom.build(inventory(text)).bomText,[password,token]));
test('BOM-02 build Markdown masks before escaping',()=>safe(bom.build(inventory(text)).markdown,[password,token]));
test('BOM-03 direct CycloneDX helper masks user text',()=>safe(JSON.stringify(bom.toCycloneDX(inventory(text))),[password,token]));
test('BOM-04 direct Markdown helper masks user text',()=>safe(bom.toMarkdown(inventory(text),[]),[password,token]));
test('BOM-05 unknown long value masked in both formats',()=>{const r=bom.build(inventory('Unclassified '+opaque));safe(r.bomText+r.markdown,[opaque])});
test('BOM-06 unknown long hex outside digest field masked',()=>safe(bom.build(inventory('Unclassified '+hex)).bomText,[hex]));
test('BOM-07 validated weights digest preserved',()=>{const r=bom.build(inventory('A harmless classifier.'));assert.equal(r.bom.components.find(c=>c.type==='file').hashes[0].content,hex)});
test('BOM-08 nested JSON assignment masked before serialization',()=>safe(bom.build(inventory(JSON.stringify({password}))).bomText,[password]));
test('BOM-09 quoted punctuation and Unicode remain valid JSON',()=>{const r=bom.build(inventory('Ähre \"quoted\" 密码; password="'+password+'"'));JSON.parse(r.bomText);safe(r.bomText+r.markdown,[password]);assert.ok(r.bomText.includes('Ähre'))});
test('BOM-10 source inventory is not mutated',()=>{const inv=inventory(text),before=JSON.stringify(inv);bom.build(inv);assert.equal(JSON.stringify(inv),before)});
test('BOM-11 safe preview aliases equal actual exports',()=>{const r=bom.build(inventory(text));assert.equal(r.bomTextMasked,r.bomText);assert.equal(r.markdownMasked,r.markdown)});
test('BOM-12 open-export acknowledgement removed',()=>{const template=fs.readFileSync(root+'/template-parts/tools/ai-model-bom.php','utf8'),app=fs.readFileSync(root+'/assets/js/ai-model-bom/app.js','utf8');assert.ok(!template.includes('data-bom-secret-ack'));assert.ok(!app.includes('secretAck'));assert.ok(!/export (?:the document )?anyway|unmasked/i.test(template+app))});
test('ATLAS-01 JSON note masks assigned password',()=>safe(atlas.exportSelection([{id:'AML.T0051',note:text}]).json,[password,token,opaque]));
test('ATLAS-02 Markdown note masks before escaping',()=>safe(atlas.exportSelection([{id:'AML.T0051',note:text}]).markdown,[password,token,opaque]));
test('ATLAS-03 every user-controlled source field is masked',()=>{const r=atlas.exportSelection([{id:'AML.T0051',note:'safe',source:'password='+password}]);safe(r.json+r.markdown,[password])});
test('ATLAS-04 user timestamp is masked',()=>{const r=atlas.exportSelection([{id:'AML.T0051'}],{timestamp:'password='+password});safe(r.json+r.markdown,[password])});
test('ATLAS-05 findings use the same assignment masking',()=>safe(JSON.stringify(atlas.mapFinding('A password: '+password+' was found in agent configuration.')),[password]));
test('ATLAS-06 quoted JSON assignment is masked',()=>safe(atlas.exportSelection([{id:'AML.T0051',note:JSON.stringify({password})}]).json,[password]));
test('ATLAS-07 mask before note truncation',()=>{const note='x '.repeat(1988)+'password: '+password;safe(atlas.exportSelection([{id:'AML.T0051',note}]).json,[password])});
test('ATLAS-08 harmless notes preserved',()=>{const r=JSON.parse(atlas.exportSelection([{id:'AML.T0051',note:'Reviewed by the example team.'}]).json);assert.equal(r.techniques[0].note,'Reviewed by the example team.')});
let failed=0;const rows=[];for(const [id,fn]of cases){try{fn();rows.push({id,pass:true})}catch(e){failed++;rows.push({id,pass:false,error:e.name});}}
const result={tests:rows.length,pass:rows.length-failed,fail:failed,rows};console.log(JSON.stringify(result,null,2));if(process.env.EXPORT_REGRESSION_RESULT)fs.writeFileSync(process.env.EXPORT_REGRESSION_RESULT,JSON.stringify(result,null,2)+'\n');process.exitCode=failed?1:0;
