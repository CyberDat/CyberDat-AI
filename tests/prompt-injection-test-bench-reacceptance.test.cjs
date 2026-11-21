/*
 * Test Bench — Codex re-acceptance of release 1.3 (4ee0ada), 2026-11-21: one synthetic test per open defect.
 *   1. short secrets in the preview and in the re-exported CSV/JSONL of an imported set;
 *   2. short secrets beside the canary in the result fragment and in JSON/Markdown (values separated by spaces or
 *      punctuation: this is not the known "glued without a separator" limitation);
 *   3. the canary written with an underscore (B-P14) is the whole code; the bare core stays "possible leak (core only)".
 * Rule: the whole text is masked before the fragment is cut and before the preview is shown (u flag, no look-behind).
 * Values come from tests/lib/synthetic-secrets.cjs. Codex's frozen expectations are not reproduced or changed here.
 * Run: node tests/prompt-injection-test-bench-reacceptance.test.cjs
 */
'use strict';
const path = require('node:path');
const { SYNTH } = require('./lib/synthetic-secrets.cjs');
const PITB = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/prompt-injection-test-bench/engine.js'));
let failed = 0, n = 0;
const check = (ok, msg) => { n++; console.log((ok ? 'PASS: ' : 'FAIL: ') + msg); if (!ok) { failed++; } };
const leaks = (blob, values) => values.filter(v => blob.includes(v));

// short values (12–19 characters, no known format, below the 24-character long-value rule) after common key names
const PAIRS = [
	['api_key=', SYNTH.GENERIC_API_KEY], ['X-Api-Key: ', SYNTH.X_API_KEY_2], ['Authorization: Bearer ', SYNTH.ACCESS_TOKEN_QUERY],
	['Bearer ', SYNTH.CSRF_TOKEN], ['csrf=', SYNTH.CSRF_TOKEN], ['pwd=', SYNTH.ASSIGNED_PLAIN], ['passwd: ', SYNTH.ASSIGNED_PLAIN_2],
	['access_key: ', SYNTH.X_API_KEY_2], ['session_id=', SYNTH.CSRF_TOKEN], ['API key: ', SYNTH.GENERIC_API_KEY],
	['password => ', SYNTH.ASSIGNED_SECRET], ['client_secret: "', SYNTH.ASSIGNED_PLAIN]
];
const VALUES = [...new Set(PAIRS.map(p => p[1]))];
const SEPS = [' ', ', ', '; ', ' | ', '\n'];
const block = sep => PAIRS.map(([k, v]) => k + v + (k.endsWith('"') ? '"' : '')).join(sep);

for (const [k, v] of PAIRS) {
	check(!PITB.maskSecrets('Config: ' + k + v + (k.endsWith('"') ? '"' : '') + '.', []).includes(v), 'masked: ' + k.trim() + ' <short value>');
}

const set = PITB.buildSet({ appTypes: ['chat'], langs: ['en'], seed: 3 });
const t0 = set.tests[0];

// defect 1: imported set — preview data (what the page shows) and re-export
{
	const lines = PITB.exportSet(set).jsonl.trim().split('\n');
	const h0 = JSON.parse(lines[0]); h0.labelInstruction += ' ' + block(', ');
	const l1 = JSON.parse(lines[1]); l1.input += '\n' + block('\n'); l1.ask += ' ' + block('; '); l1.template += ' ' + block(' | ');
	const imp = PITB.importSet([JSON.stringify(h0), JSON.stringify(l1)].concat(lines.slice(2)).join('\n'));
	const preview = imp.labelInstruction + imp.tests.map(t => t.id + t.template + t.how + t.ask + t.input).join('');
	check(!leaks(preview, VALUES).length, 'defect 1: preview data of an imported set has no short secret (' + VALUES.length + ' values, ' + PAIRS.length + ' key forms)');
	const re = PITB.exportSet(imp);
	check(!leaks(re.jsonl, VALUES).length && !leaks(re.csv, VALUES).length, 'defect 1: re-exported JSONL and CSV of the imported set have no short secret');
	check(imp.tests[0].canary === t0.canary && imp.tests[0].input.includes('[value of a secret field'), 'defect 1: the canary is kept, the values are replaced by their masked form');
}

// defect 2: short secrets beside the canary, separated by spaces or punctuation
for (const sep of SEPS) {
	const resp = 'Sure. ' + t0.canary + sep + block(sep);
	const r = PITB.check(set, { [t0.id]: resp });
	const rep = PITB.exportReport(set, r, { timestamp: '2026-11-21T00:00:00Z' });
	check(r.rows[0].status === 'triggered' && r.rows[0].fragment.includes(t0.canary) && !leaks(r.rows[0].fragment + rep.json + rep.markdown, VALUES).length,
		'defect 2: separator ' + JSON.stringify(sep) + ': fragment, JSON and Markdown keep the canary and mask every short secret');
}
{
	// a short secret right at the edge of the 60-character window is masked as a whole, not cut into an unrecognised piece
	const resp = 'x'.repeat(80) + ' ' + t0.canary + ' ' + 'y'.repeat(44) + ' api_key=' + SYNTH.GENERIC_API_KEY + ' done';
	const r = PITB.check(set, { [t0.id]: resp });
	check(!r.rows[0].fragment.includes(SYNTH.GENERIC_API_KEY.slice(0, 6)) && !r.rows[0].fragment.includes(SYNTH.GENERIC_API_KEY.slice(-6)), 'defect 2: a short secret at the window edge is masked before the window is cut');
}

// defect 3: B-P14 underscore and other separators between prefix and core
{
	const core = t0.canary.slice(t0.canary.indexOf('-') + 1);
	for (const v of ['CANARY_' + core, 'canary_' + core.toLowerCase(), 'CANARY ' + core, 'CANARY–' + core, 'CANARY__' + core]) {
		const r = PITB.check(set, { [t0.id]: 'Answer: ' + v + '.' });
		check(r.rows[0].status === 'triggered' && r.counts.triggered === 1 && r.counts.possibleLeak === 0, 'defect 3: ' + JSON.stringify(v.replace(core, '<core>')) + ' is the whole code (triggered, method ' + r.rows[0].method + ')');
	}
	const bare = PITB.check(set, { [t0.id]: 'Answer: ' + core + '.' });
	check(bare.rows[0].status === 'possible-leak' && bare.counts.triggered === 0, 'defect 3: the bare core still gives possible leak (core only), unchanged');
	const near = PITB.check(set, { [t0.id]: 'Answer: CANARY_' + core + 'A.' });
	check(near.rows[0].status === 'not-triggered', 'defect 3: CANARY_<core> followed by another character is a different code, not a match');
	const other = PITB.check(set, { [t0.id]: 'Answer: TOKEN_' + core + '.' });
	check(other.rows[0].status !== 'triggered', 'defect 3: another prefix with an underscore is not the whole code');
}

// linear on hostile input (many short keyed values)
{
	let t = Date.now();
	PITB.maskSecrets('token=a '.repeat(130000) + 'Bearer abcdef '.repeat(5000), []);
	const ms1 = Date.now() - t;
	t = Date.now();
	PITB.findSecrets('api key'.repeat(150000) + 'pwd:'.repeat(100000), []);
	const ms2 = Date.now() - t;
	check(ms1 < 2000 && ms2 < 2000, 'masking stays linear on 1 MB with many short keyed values (' + ms1 + ' ms, ' + ms2 + ' ms)');
}

// own generated sets stay byte for byte
{
	const all = PITB.buildSet({ appTypes: Object.keys(PITB.APP_TYPES), langs: ['en', 'de', 'ru'], seed: 9 });
	const mk = PITB.maskedSet(all);
	check(all.tests.every((t, i) => t.input === mk.tests[i].input && t.ask === mk.tests[i].ask && t.template === mk.tests[i].template) && all.labelInstruction === mk.labelInstruction, 'own generated set unchanged by the wider key list (' + all.tests.length + ' tests)');
}

console.log(failed ? '\nFAIL: ' + failed + ' of ' + n + ' checks' : '\nPASS: test bench re-acceptance (' + n + ' checks)');
process.exit(failed ? 1 : 0);
