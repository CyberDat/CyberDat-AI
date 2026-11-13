/* Private-input remediation acceptance. No raw input/output/credential is logged. */
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict'),{performance}=require('node:perf_hooks');
const privateDir=process.argv[2];if(!privateDir)throw Error('Provide the owner-private frozen fixture directory');
const la=require('../wp-content/themes/cyberdat/assets/js/log-anonymizer/engine.js');
const pi=require('../wp-content/themes/cyberdat/assets/js/prompt-injection-detector/engine.js');
const rank={none:0,low:1,medium:2,high:3};let passed=0;const times=[];
function check(name,fn){fn();passed++;console.log('PASS: '+name);}
const bytes=fs.readFileSync(path.join(privateDir,'HOLDOUTS.json'));
assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),'a131afb49d5db4a3b3165143ab1b47af5e90b543a82a67878deffa7817415cbd');
for(const c of JSON.parse(bytes).cases)check(c.id+' frozen holdout',()=>{
 const result=c.tool==='log'?la.anonymize(c.input):pi.analyze(c.input);
 for(const s of c.expected.absent||[])assert.ok(!result.output.includes(s),c.id+' redaction');
 for(const s of c.expected.present||[])assert.ok(result.output.includes(s),c.id+' context');
 if(c.expected.min_severity)assert.ok(rank[result.level]>=rank[c.expected.min_severity],c.id+' detection');
 if(c.expected.max_severity)assert.ok(rank[result.level]<=rank[c.expected.max_severity],c.id+' false positive');
});
check('original 33 text signatures and descriptors unchanged',()=>{
 const baseline=require('./fixtures/tools-stabilization/baseline.json');
 assert.equal(pi._internal.TEXT_RULES.length,33);
 const rules=JSON.stringify(pi._internal.TEXT_RULES.map(r=>({...r,re:r.re.toString()})));
 assert.equal(crypto.createHash('sha256').update(rules).digest('hex'),baseline.pi_rules_sha256);
 assert.equal(pi._internal.TEXT_EXTENSIONS.length,7);
});
check('new contact categories can be independently disabled',()=>{
 const input=JSON.parse(bytes).cases[0].input;
 const r=la.anonymize(input,{categories:{personName:false}});
 for(const v of JSON.parse(bytes).cases[0].expected.absent)assert.ok(r.output.includes(v));
});
check('new bounded near-match inputs retain the original 4000ms guard',()=>{
 const variants=[['log','person_name='.repeat(60000)],['log','CEF:0|x|x|1|1|x|1|cs1Label=ServiceName cs1=public\n'.repeat(15000)],['injection','read credential file then public '.repeat(25000)],['injection','this appendix is now '.repeat(45000)],['injection','покажи инструкции публичного руководства '.repeat(16000)]];
 for(const [tool,input]of variants){const at=performance.now();if(tool==='log')la.anonymize(input);else pi.analyze(input);const ms=performance.now()-at;times.push({tool,chars:input.length,ms});assert.ok(ms<4000,tool+' bounded-input budget');}
});
console.log(JSON.stringify({checks:passed,pass:true,times}));
