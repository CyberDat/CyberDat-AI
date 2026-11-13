/* Preservation/performance regressions for the authorized stabilization stage. */
'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),path=require('node:path'),fs=require('node:fs'),{performance}=require('node:perf_hooks');
const {vectors}=require('./lib/tools-stabilization-vectors.cjs');
const frozen=require('./fixtures/tools-stabilization/baseline.json');
const root=path.resolve(__dirname,'../wp-content/themes/cyberdat/assets/js');
const la=require(root+'/log-anonymizer/engine.js'),pi=require(root+'/prompt-injection-detector/engine.js');
let passed=0;const times=[];
function check(name,fn){fn();passed++;console.log('PASS: '+name);}
function digestResults(engine,method,items){const h=crypto.createHash('sha256');for(const s of items){const r=engine[method](s);delete r.engine;
// Preserve the original frozen behavior hashes. Only new zero-valued category
// schema fields and the declared ruleset release label are projected away;
// output/findings/offsets/maps/counts/preview/sanitization remain byte-compared.
if(method==='anonymize')for(const k of ['personName','phone']){assert.deepEqual(r.stats[k],{replacements:0,unique:0});delete r.stats[k];}
if(method==='analyze'){assert.equal(r.ruleset,'2026-11-14.1');r.ruleset='2026-11-11.1';}
h.update(JSON.stringify(r)+'\n');}return h.digest('hex');}
const v=vectors();
check('4006 log cases preserve the frozen pre-stabilization output, map, counts, warnings and preview',()=>{assert.equal(v.la.length,frozen.contracts.la.cases);assert.equal(digestResults(la,'anonymize',v.la),frozen.contracts.la.sha256);});
check('245 Unicode/injection cases preserve findings, severity, offsets, counts, normalization and sanitized text',()=>{assert.equal(v.pi.length,frozen.contracts.pi.cases);assert.equal(digestResults(pi,'analyze',v.pi),frozen.contracts.pi.sha256);});
check('every Injection text signature/flag and rule descriptor remains identical',()=>{const rules=JSON.stringify(pi._internal.TEXT_RULES.map(r=>({...r,re:r.re.toString()})));assert.equal(crypto.createHash('sha256').update(rules).digest('hex'),frozen.pi_rules_sha256);});
check('cached invisible metadata retains per-run emoji/word context and fresh per-call offsets',()=>{const runs=pi._internal.scanInvisible('a\u200db 👩\u200d👩');assert.equal(runs.length,2);assert.equal(runs[0].legit,false);assert.equal(runs[1].legit,true);assert.notEqual(runs[0].start,runs[1].start);assert.equal(pi._internal.scanInvisible('👩\u200d👩')[0].legit,true);assert.equal(pi._internal.scanInvisible('a\u200db')[0].legit,false);});
check('pathological repeated log keys stay below the existing4000ms budget; sensitive tails still redacted',()=>{
 for(const prefix of ['ab:'.repeat(1<<18),'"ab":'.repeat(1<<17),'other=ab:'.repeat(1<<17)]){
  const input=prefix+'\npassword=fictionalTail\nusername=syntheticTail\n';const start=performance.now(),r=la.anonymize(input),ms=performance.now()-start;times.push({tool:'log',chars:input.length,ms});assert.ok(ms<4000,'log pathological input exceeded4000ms: '+ms);assert.ok(!r.output.includes('fictionalTail')&&!r.output.includes('syntheticTail'));assert.equal(r.output.split('\n').length,input.split('\n').length);
 }
});
check('one million alternating visible/invisible characters stays below4000ms without dropping500000 detections',()=>{
 const start=performance.now(),r=pi.analyze('a\u200b'.repeat(500000)),ms=performance.now()-start;times.push({tool:'injection',chars:1000000,ms});assert.ok(ms<4000,'injection pathological input exceeded4000ms: '+ms);assert.equal(r.counts.total,500000);assert.equal(r.counts.byRule['PI-HID-001'],500000);assert.equal(r.counts.bySeverity.medium,499999);assert.equal(r.counts.bySeverity.low,1);assert.equal(r.sanitized.text,'a'.repeat(500000));
});
console.log(JSON.stringify({checks:passed,pass:true,times}));
