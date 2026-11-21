/* Diagnostic inventory: known synthetic values only. It does not redefine legacy export contracts. */
'use strict';
const path=require('node:path'),fs=require('node:fs'),R=path.resolve(__dirname,'../wp-content/themes/cyberdat/assets/js'),{SYNTH:S}=require('./lib/synthetic-secrets.cjs');
const password=S.ASSIGNED_SECRET,token=S.OPENAI_PROJECT_KEY,opaque=S.OPAQUE_LONG,probe='password: '+password+'; api_key: '+token+'; '+opaque;
const visibleTypes=v=>[['assigned_password',password],['known_provider_key',token],['unknown_long_value',opaque]].filter(([,x])=>JSON.stringify(v).includes(x)).map(([k])=>k);
const exposed=v=>visibleTypes(v).length>0;
const rows=[];
(async()=>{
 const la=await require(process.env.LA_AUDIT_ENGINE||R+'/log-anonymizer/engine.js').anonymize(probe);rows.push({tool:'Log Anonymizer',channel:'anonymized text',tested:process.env.LA_AUDIT_ENGINE?'accepted Stage1 source (offline)':'integration branch source (older than installed Stage1)',secret_visible:exposed(la.output),exposed_classes:visibleTypes(la.output)});rows.push({tool:'Log Anonymizer',channel:'replacement map',tested:'engine map included by downloadMap',secret_visible:exposed(la.map),exposed_classes:visibleTypes(la.map),intentional:true});
 const pi=require(R+'/prompt-injection-detector/engine.js').analyze('Harmless metadata: '+probe);rows.push({tool:'Prompt Injection Detector',channel:'sanitized text',secret_visible:exposed(pi.sanitized),intentional:'injection sanitization is not secret redaction'});
 const lotl=require(R+'/lotl-analyzer/engine.js').analyze('cmdkey /add:example.invalid /user:demo /pass:'+password);rows.push({tool:'LotL Analyzer',channel:'analysis JSON with command lines',secret_visible:exposed(lotl),intentional:true});
 const mcp=require(R+'/mcp-checker/engine.js').analyze(JSON.stringify({mcpServers:{example:{command:'node',args:['server.js'],env:{API_KEY:token}}}}));rows.push({tool:'MCP Checker',channel:'security findings report',secret_visible:exposed(mcp)});rows.push({tool:'MCP Checker',channel:'policy download',source_confirmed:fs.readFileSync(R+'/mcp-checker/app.js','utf8').includes("el.policy.value.replace(/\\s*$/, '')"),secret_visible:'verbatim by implementation; no redaction',intentional:true});
 const lki=require(R+'/leak-inspector/engine.js').audit(probe);rows.push({tool:'Leak Inspector',channel:'findings report',secret_visible:exposed(lki)});
 const bom=require(R+'/ai-model-bom/engine.js').build({model:{name:'Audit model'},purpose:probe});rows.push({tool:'AI BOM',channel:'CycloneDX/Markdown export',secret_visible:exposed(bom.bomText+bom.markdown)});
 const atlas=require(R+'/atlas-mapper/engine.js').exportSelection([{id:'AML.T0051',note:probe,source:probe}]);rows.push({tool:'ATLAS Mapper',channel:'selection JSON/Markdown',secret_visible:exposed(atlas.json+atlas.markdown)});
 console.log(JSON.stringify({scope:'Source/engine audit, not a browser certification of legacy modes; no private values printed',rows},null,2));
})().catch(e=>{console.error(e.name);process.exitCode=1});
