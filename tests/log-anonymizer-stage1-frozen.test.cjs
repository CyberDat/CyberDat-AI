/* Differential acceptance; frozen files are read, never regenerated. No source values in evidence. */
'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const basePath=process.argv[2],evidence=process.argv[3];if(!basePath||!evidence)throw Error('Private baseline and fresh report path required');
const base=require(basePath),candidate=require('../wp-content/themes/cyberdat/assets/js/log-anonymizer/engine.js'),{vectors}=require('./lib/tools-stabilization-vectors.cjs');const frozen=require('./fixtures/tools-stabilization/baseline.json');
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');const baselineHash=crypto.createHash('sha256'),changed=[],unexpected=[],counts={};
function stripped(r){r=JSON.parse(JSON.stringify(r));delete r.engine;for(const k of ['personName','phone','identifier'])if(r.stats[k]&&r.stats[k].replacements===0&&r.stats[k].unique===0)delete r.stats[k];return r;}
function shape(r){r=stripped(r);delete r.fieldStats;for(const m of r.map)delete m.fieldTypes;return r;}
for(const [index,input]of vectors().la.entries()){
 const old=base.anonymize(input),now=candidate.anonymize(input);baselineHash.update(JSON.stringify(stripped(old))+'\n');
 if(JSON.stringify(stripped(old))===JSON.stringify(stripped(now)))continue;
 const reasons=[];
 // 1.1 permits additional type metadata only; all pre-existing output/map/count/preview bytes must match.
 if(JSON.stringify(shape(old))===JSON.stringify(shape(now))){reasons.push('1.1 field-type metadata');}
 else{
  // No blanket permission based on the presence of a secret. Any behavioral delta must be reviewed.
  unexpected.push({case:index,before_sha256:sha(JSON.stringify(shape(old))),after_sha256:sha(JSON.stringify(shape(now))),output_changed:old.output!==now.output});
 }
 for(const reason of reasons)counts[reason]=(counts[reason]||0)+1;
 changed.push({case:index,rules:reasons,before_sha256:sha(JSON.stringify(stripped(old))),after_sha256:sha(JSON.stringify(stripped(now))),output_changed:old.output!==now.output});
}
assert.equal(baselineHash.digest('hex'),frozen.contracts.la.sha256,'Baseline is not the frozen accepted behavior');
const report={total:4006,changed:changed.length,unchanged:4006-changed.length,counts,examples:Object.fromEntries(Object.keys(counts).map(k=>[k,changed.filter(x=>x.rules.includes(k)).slice(0,5)])),unexpected,all_changed_case_ids:changed.map(x=>x.case),baseline_verified:true};fs.writeFileSync(evidence,JSON.stringify(report,null,2));console.log(JSON.stringify({total:report.total,changed:report.changed,counts,unexpected:unexpected.length}));if(unexpected.length)process.exitCode=1;
