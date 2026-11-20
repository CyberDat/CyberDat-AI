/*
 * AI Model Bill of Materials engine: static contracts, export structure, Review round trip, Unicode, key normalization,
 * secret masking, parser errors and large inputs. Examples here are DEPENDENT (written with the rules).
 *   node tests/ai-bom-engine.test.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const { bigBom } = require('./lib/ai-bom-inputs.cjs');
const corpus = require('./ai-bom-corpus.test.cjs');
const DIR = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/ai-model-bom');
const e = require(path.join(DIR, 'engine.js'));
let n = 0;
const ok = label => { n++; console.log('PASS: ' + label); };
const ids = r => [...new Set(r.findings.map(f => f.rule))].sort();

// ---------------------------------------------------------------- static contracts
const SRC = Object.fromEntries(['engine.js', 'worker.js', 'app.js'].map(f => [f, fs.readFileSync(path.join(DIR, f), 'utf8')]));
for (const [f, src] of Object.entries(SRC)) {
	assert.ok(!/\(\?<[=!]/.test(src), f + ': look-behind');
	assert.ok(!/\\[bBwW]/.test(src), f + ': \\b, \\B, \\w or \\W');
	assert.ok(!/\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML|document\.write|\beval\(|new Function\(/.test(src), f + ': HTML sinks or eval');
	assert.ok(!/localStorage|sessionStorage|indexedDB|document\.cookie|history\.(?:push|replace)State|location\.hash\s*=/.test(src), f + ': storage or URL APIs');
	if (f !== 'worker.js') { assert.ok(!/\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource/.test(src), f + ': network APIs'); }
}
ok('engine, worker and app: no look-behind, no \\b/\\w, no HTML sinks, no storage or network APIs');
const rules = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/ai-bom/rules.json'), 'utf8')).rules;
assert.deepEqual(Object.keys(e.RULES).sort(), rules.map(r => r.id).sort());
for (const r of rules) { assert.equal(e.RULES[r.id][0], r.group, r.id); assert.equal(e.RULES[r.id][1], r.severity, r.id); assert.ok(e.RULES[r.id][3].length > 20 && e.RULES[r.id][4].length > 20, r.id + ' explanation and fix'); }
ok('engine rule ids, groups and severities equal the frozen catalogue (' + rules.length + ' rules), each with explanation and recommendation');
const app = SRC['app.js'];
assert.ok(app.includes("'No known gaps matched. This does not mean the model or its supply chain is safe.'"));
ok('result without findings uses the agreed sentence');

// ---------------------------------------------------------------- export structure and round trip on every Build case
let cases = 0;
for (const f of ['corpus.json', 'holdout.json']) {
	for (const c of corpus.load(f)) {
		if (c.mode !== 'build') { continue; }
		cases++;
		const b = e.build(corpus.expandDeep(c.inventory), { timestamp: '2026-11-14T00:00:00Z' });
		assert.deepEqual(b.structure, [], c.id + ' export structure');
		assert.equal(b.bom.specVersion, '1.7');
		const r = e.review(b.bomText);
		assert.deepEqual(r.structure, [], c.id + ' review structure');
		if (!b.secrets) { assert.deepEqual(e.normalizeInventory(r.inventory), b.inventory, c.id + ' clean round trip'); }
		else {
			// Export now deliberately removes secrets; the in-memory input is kept only for editing.
			for (const v of Object.values(S)) { if (JSON.stringify(b.inventory).includes(v)) { assert.ok(!b.bomText.includes(v), c.id + ' safe export'); } }
		}
		assert.deepEqual(ids(r).filter(id => !id.startsWith('AIBOM-SEC-')), ids(b).filter(id => !id.startsWith('AIBOM-SEC-')), c.id + ' non-secret rules in Review');
	}
}
ok('all ' + cases + ' Build cases: valid safe export; clean data round-trips, secret values are removed and non-secret rule ids survive');
const ex = e.build(e.EXAMPLE, { timestamp: '2026-11-14T00:00:00Z' });
assert.equal(ex.bom.components[0].type, 'machine-learning-model');
assert.ok(ex.bom.components[0].modelCard && ex.bom.components[0].modelCard.modelParameters.datasets[0].ref === 'data-1');
assert.match(ex.bom.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
assert.ok(ex.bom.dependencies[0].dependsOn.length === 5);
ok('export: machine-learning-model with model card, dataset refs, random v4 serial number, dependency graph');

// ---------------------------------------------------------------- Unicode in every text field
const NAMES = ['Jörg Müller', 'Пётр Йосифович', 'Ölçer Şahin', 'Größenklasse', 'О́льга'];
for (const name of NAMES) {
	const inv = JSON.parse(JSON.stringify(e.EXAMPLE));
	inv.model.name = name; inv.model.vendor = name; inv.owner.name = name; inv.datasets[0].name = name + ' 2025'; inv.dependencies[0].name = name; inv.purpose = name + ': ' + inv.purpose; inv.limitations = name;
	const b = e.build(inv);
	const extra = ids(b).filter(x => !ex.findings.some(f => f.rule === x));
	assert.deepEqual(extra, ['AIBOM-DOC-002'].filter(() => false), name + ': extra findings ' + extra.join(' '));
	assert.ok(b.bomText.includes(name.normalize('NFC')) && !b.bomText.includes(name.normalize('NFD').replace(name.normalize('NFC'), '\u0000')));
	assert.deepEqual(e.normalizeInventory(e.review(b.bomText).inventory), b.inventory);
}
assert.ok(e.isMissing('Неизвестно') && e.isMissing('UNBEKANNT') && e.isMissing(' n/a ') && !e.isMissing('Unbekannte Lizenz 2.0'));
assert.ok(e.isFloating('последняя') && e.isFloating('Neueste') && e.isFloating('2.x') && !e.isFloating('2026-05-01') && !e.isFloating('v1.2'));
ok('names in NFC and NFD (Cyrillic, umlauts, Turkish, combining accents) cause no extra findings, are exported in NFC and survive the round trip');

// ---------------------------------------------------------------- key normalization in Review
const keyVariants = JSON.stringify({ BOM_FORMAT: 'CycloneDX', 'spec-version': '1.7', version: 1, Components: [{ TYPE: 'machine-learning-model', name: 'M', version: '1', supplier: { name: 'V' }, licenses: [{ license: { id: 'MIT' } }], Properties: [{ name: 'CYBERDAT:AIBOM:MODEL_TYPE', value: 'Fine_Tuned' }], ModelCard: { Considerations: { 'use-cases': ['u'], TechnicalLimitations: ['l'] }, quantitative_analysis: { PerformanceMetrics: [{ type: 'f1', value: '1' }] } }, Pedigree: { ancestors: [{ type: 'machine-learning-model', name: 'base', version: '1' }] } }], metadata: { authors: [{ name: 'A', email: 'a@example.com' }] } });
const kv = e.review(keyVariants);
assert.equal(kv.inventory.model.type, 'fine-tuned');
assert.equal(kv.inventory.purpose, 'u');
assert.equal(kv.inventory.model.baseModel.name, 'base');
assert.deepEqual(ids(kv), ['AIBOM-DAT-003', 'AIBOM-FMT-002', 'AIBOM-WGT-005']);
assert.ok(kv.structure.some(p => /not the standard spelling “modelCard”/.test(p.message)) && kv.structure.some(p => /“specVersion”/.test(p.message)));
ok('Review reads keys after normalization (case, _, -, camelCase) and reports non-standard spellings');

// ---------------------------------------------------------------- secrets: only type and masked fragment
const secretValues = [S.HF_TOKEN, S.AWS_ACCESS_KEY_ID, S.GITHUB_PAT, S.ANTHROPIC_API_KEY, S.OPENAI_PROJECT_KEY, S.JWT, S.SLACK_BOT_TOKEN, S.GITLAB_PAT, S.GOOGLE_API_KEY, S.OPAQUE_LONG];
for (const v of secretValues) {
	const inv = JSON.parse(JSON.stringify(e.EXAMPLE));
	inv.evaluation.safety = 'Checked with credential ' + v + ' in place.';
	inv.model.version = '1.2.0 ' + v;
	const b = e.build(inv);
	const shown = JSON.stringify(b.findings) + b.bomTextMasked + b.markdownMasked;
	assert.ok(!shown.includes(v), 'secret visible: ' + v.slice(0, 4));
	assert.ok(b.secrets >= 1 && b.findings.some(f => f.group === 'secrets' && /…|••••/.test(f.evidence)), 'masked evidence: ' + v.slice(0, 4));
	assert.ok(!b.bomText.includes(v) && !b.markdown.includes(v), 'exports mask the entry');
	const r = e.review(b.bomText);
	assert.ok(!JSON.stringify(r.findings).includes(v) && !JSON.stringify(r.structure).includes(v) && !JSON.stringify(r.inventoryView).includes(v), 'review shows ' + v.slice(0, 4));
}
const urlSecrets = e.build(Object.assign(JSON.parse(JSON.stringify(e.EXAMPLE)), { deployment: { environment: '', apis: [{ name: 'a', url: S.URL_WITH_PASSWORD }, { name: 'b', url: S.URL_WITH_QUERY_KEY }] } }));
assert.ok(!JSON.stringify(urlSecrets.findings).includes('Pa55') && !JSON.stringify(urlSecrets.findings).includes('abc123def'));
assert.equal(urlSecrets.findings.filter(f => f.rule === 'AIBOM-SEC-001').length, 2);
ok('secrets (' + secretValues.length + ' formats incl. an unrecognized long value, and URL credentials) appear only as type and masked fragment in findings, previews and Review');
assert.deepEqual(e.scanText('sha256 ' + 'a'.repeat(64) + ' uuid 3e671687-395b-41f5-a30f-a58921a69b79 Datenschutzfolgenabschätzungsverfahren distilbert-base-multilingual-cased-v2.0.1').filter(x => /SEC/.test(x.rule)), []);
ok('hex digests, UUIDs, long words and model names are not reported as secrets');

// ---------------------------------------------------------------- parser errors and limits
assert.throws(() => e.review('{"bomFormat": "CycloneDX", /* c */ "specVersion": "1.7"}'), err => err.code === 'PARSE' && err.line === 1 && err.column === 28);
assert.throws(() => e.review('{\n "a": 1,\n}'), err => err.code === 'PARSE' && err.line === 3);
assert.throws(() => e.review('['.repeat(200) + ']'.repeat(200)), err => err.code === 'PARSE' && /deeper/.test(err.message));
assert.throws(() => e.review('x'.repeat(e.MAX_INPUT_CHARS + 1)), err => err.code === 'TOO_LARGE');
assert.throws(() => e.review('   '), err => err.code === 'EMPTY');
assert.throws(() => e.review('{"specVersion":"1.7"}'), err => err.code === 'NOT_CYCLONEDX');
const dup = e.review('{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"version":2,"components":[]}');
assert.ok(dup.structure.some(p => /duplicate key “version”/.test(p.message)));
ok('strict JSON: comments, trailing commas, deep nesting, size, empty input, non-CycloneDX and duplicate keys are reported with line numbers');

// ---------------------------------------------------------------- large inputs
const big = bigBom(4.9 * 1024 * 1024);
let t = performance.now();
const rb = e.review(big.text);
const reviewMs = performance.now() - t;
assert.equal(rb.counts.datasets, big.datasets);
assert.ok(reviewMs < 10000, 'review took ' + reviewMs);
const wide = JSON.parse(JSON.stringify(e.EXAMPLE));
wide.datasets = Array.from({ length: 200 }, (x, k) => ({ name: 'Набор ' + k, role: 'training', source: 'https://data.example.com/' + k, license: k % 3 ? 'CC-BY-4.0' : '', personalData: k % 2 ? 'no' : 'unknown' }));
wide.limitations = 'Lange Beschreibung ohne Geheimnisse. '.repeat(500);
t = performance.now();
const wb = e.build(wide);
const buildMs = performance.now() - t;
assert.deepEqual(wb.structure, []);
assert.ok(buildMs < 5000, 'build took ' + buildMs);
const pathological = e.review(JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.7', components: [{ type: 'machine-learning-model', name: 'm', description: ('a1B2' + '='.repeat(30)).repeat(20000) + ' latest '.repeat(10000) }] }));
assert.ok(pathological.counts.models === 1);
ok('large inputs: ' + (big.text.length / 1048576).toFixed(1) + ' MB Review in ' + Math.round(reviewMs) + ' ms; Build with 200 datasets in ' + Math.round(buildMs) + ' ms; pathological text finishes');

console.log('\n' + n + ' AI BOM engine checks passed (examples DEPENDENT).');
