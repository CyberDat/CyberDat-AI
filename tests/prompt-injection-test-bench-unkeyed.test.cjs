/*
 * Test Bench — values without a key (Codex B02, B-H3, B-H4 on c1cf7e6, 2026-11-22).
 * Two short values stand as separate words, without "password=" or another key, in the probe
 *   [known] [opaque] [named] [password] [XSS-marker]
 * written into the set header (labelInstruction, shown as the preview), into a test input (JSONL and the quoted CSV
 * cell) and into the response after the canary. Rule: a separate word of 16+ characters from [A-Za-z0-9_-] with lower
 * case, upper case and digits is masked without a key; the canary, hex hashes, GUIDs and words without digits are not.
 * The values have the shape of the Codex fixtures (23 = 14 lower, 4 upper, 3 digits, 2 "_"; 21 = 12/4/3/2) but are new
 * synthetic values from tests/lib/synthetic-secrets.cjs. Codex's frozen inputs and expectations are not reproduced here.
 * Run: node tests/prompt-injection-test-bench-unkeyed.test.cjs
 */
'use strict';
const crypto = require('node:crypto');
const path = require('node:path');
const { SYNTH } = require('./lib/synthetic-secrets.cjs');
const PITB = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/prompt-injection-test-bench/engine.js'));
let failed = 0, n = 0;
const check = (ok, msg) => { n++; console.log((ok ? 'PASS: ' : 'FAIL: ') + msg); if (!ok) { failed++; } };
const leaks = (blob, values) => values.filter(v => blob.includes(v));
const shape = s => [s.length, (s.match(/[a-z]/g) || []).length, (s.match(/[A-Z]/g) || []).length, (s.match(/[0-9]/g) || []).length, (s.match(/_/g) || []).length].join('/');

const NAMED = SYNTH.UNKEYED_NAMED, PASSWORD = SYNTH.UNKEYED_PASSWORD;
check(shape(NAMED) === '23/14/4/3/2' && shape(PASSWORD) === '21/12/4/3/2', 'synthetic values have the shape of the B02 fixtures (23: 14/4/3/2, 21: 12/4/3/2)');
const XSS = '<img src=x onerror="alert(1)">';
const SHORT = [NAMED, PASSWORD];
const ALL = [SYNTH.GITHUB_PAT, SYNTH.OPAQUE_LONG, NAMED, PASSWORD];
const probe = ' ' + [SYNTH.GITHUB_PAT, SYNTH.OPAQUE_LONG, NAMED, PASSWORD, XSS].join(' ') + ' ';

for (const v of SHORT) { check(!PITB.maskSecrets(probe, []).includes(v), 'maskSecrets: ' + v.length + '-character value without a key is masked in the probe'); }
for (const [label, text] of [['line start', NAMED + ' rest'], ['line end', 'rest ' + PASSWORD], ['in quotes', 'value "' + NAMED + '" here'], ['in brackets', 'value (' + PASSWORD + ') here'], ['before a full stop', 'value ' + NAMED + '. Next'], ['after a newline', 'a\n' + PASSWORD + '\nb']]) {
	check(!leaks(PITB.maskSecrets(text, []), SHORT).length, 'masked as a separate word: ' + label);
}

const set = PITB.buildSet({ appTypes: ['chat'], langs: ['en'], seed: 5 });
const t0 = set.tests[0];
const core = t0.canary.slice(t0.canary.indexOf('-') + 1);

// B02: imported set — preview data, JSONL and CSV (masking before the preview and before the export)
{
	const lines = PITB.exportSet(set).jsonl.trim().split('\n');
	const h0 = JSON.parse(lines[0]); h0.labelInstruction += probe;
	const l1 = JSON.parse(lines[1]); l1.input += probe;
	const imp = PITB.importSet([JSON.stringify(h0), JSON.stringify(l1)].concat(lines.slice(2)).join('\n'));
	check(!leaks(imp.labelInstruction, ALL).length && !leaks(imp.tests[0].input, ALL).length, 'B02: preview data of the imported set (labelInstruction, input) has none of the four values');
	check(imp.labelInstruction.includes(XSS) && imp.tests[0].input.includes(XSS), 'B02: the XSS marker is text and stays (escaped by the page, not masked)');
	const re = PITB.exportSet(imp);
	check(!leaks(re.jsonl, ALL).length, 'B02: exported JSONL (header and test line) has none of the four values');
	const csvRow = re.csv.split('\r\n')[1];
	check(/"$/u.test(csvRow) && !leaks(re.csv, ALL).length, 'B02: exported CSV (quoted input cell) has none of the four values');
	check(imp.tests[0].canary === t0.canary && (imp.tests[0].input.match(/\[value that looks like a secret: /gu) || []).length === 2, 'B02: the canary is kept; both short values are replaced by their masked form');
	// masking happens on import, before the page builds the preview: the imported set already carries masked strings
	check(PITB.maskedSet(imp).tests[0].input === imp.tests[0].input, 'B02: the imported set is already masked (masking again changes nothing)');
}

// B-H3 / B-H4: the value right after the canary — fragment, JSON and Markdown; status unchanged
for (const [id, v] of [['B-H3', NAMED], ['B-H4', PASSWORD]]) {
	const resp = 'Done: ' + t0.canary + probe + 'end';
	const r = PITB.check(set, { [t0.id]: resp });
	const rep = PITB.exportReport(set, r, { timestamp: '2026-11-22T00:00:00Z' });
	check(r.rows[0].status === 'triggered' && r.rows[0].fragment.includes(t0.canary) && !leaks(r.rows[0].fragment + rep.json + rep.markdown, [v]).length,
		id + ': ' + v.length + '-character value next to the canary is masked in the fragment, JSON and Markdown; full match kept');
	const near = PITB.check(set, { [t0.id]: 'Done: ' + t0.canary + ' ' + v });
	check(near.rows[0].status === 'triggered' && !near.rows[0].fragment.includes(v), id + ': directly after the canary (one space) the value is masked');
	const onlyCore = PITB.check(set, { [t0.id]: 'Done: ' + core + probe });
	check(onlyCore.rows[0].status === 'possible-leak' && !leaks(onlyCore.rows[0].fragment, [v]).length, id + ': with only the core: possible leak (core only) as before, value masked');
}
{
	// at the edge of the 60-character window: masked as a whole before the window is cut
	const resp = 'x'.repeat(80) + ' ' + t0.canary + ' ' + 'y'.repeat(50) + ' ' + NAMED + ' done';
	const f = PITB.check(set, { [t0.id]: resp }).rows[0].fragment;
	check(!f.includes(NAMED.slice(0, 6)) && !f.includes(NAMED.slice(-6)), 'a value at the window edge is masked before the window is cut');
}

// not masked: the canary in every accepted form, its core, hex hashes, GUIDs, words without digits, whole paths and URLs
const keep = [core.toUpperCase()];
const NEG = [
	['CANARY-<core>', t0.canary], ['CANARY_<core>', 'CANARY_' + core], ['canary_<core> (lower case)', 'canary_' + core.toLowerCase()], ['Canary_<core> (mixed case)', 'Canary_' + core],
	['bare core', core], ['SHA-256 hex', crypto.createHash('sha256').update('cyberdat').digest('hex')], ['mixed-case hex', 'DeadBeef0123CafeBabe4567'],
	['GUID', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'], ['GUID upper case', '3F2504E0-4F89-11D3-9A0C-0305E82C3301'], ['CamelCase word without digits', 'ConfigurationManagerFactory'],
	['identifier without digits', 'get_user_profile_settings'], ['path', 'C:\\Users\\Public\\Report2026_Final\\notes.txt'], ['URL', 'https://example.org/docs/Release2026_Notes'],
	['assignment-free version string', 'v1.2.3-build'], ['label of the set', set.label]
];
for (const [label, v] of NEG) {
	const text = 'Seen: ' + v + ' here.';
	const k = keep.concat([String(set.label).slice(String(set.label).indexOf('-') + 1).toUpperCase()]);
	// paths and URLs: the new rule never takes them (their parts are left to the earlier rules, e.g. the long-value rule)
	check(label === 'path' || label === 'URL' ? !PITB.findSecrets(text, k).some(x => x.kind === 'value that looks like a secret') : PITB.maskSecrets(text, k) === text, 'not masked: ' + label);
}
// the canary search is not affected: a response with the canary in each separator form stays triggered
for (const form of ['CANARY_' + core, 'canary_' + core.toLowerCase(), t0.canary]) {
	check(PITB.check(set, { [t0.id]: 'Answer ' + form + ' ' + NAMED }).rows[0].status === 'triggered', 'canary still found: ' + form.replace(core, '<core>').replace(core.toLowerCase(), '<core>') + ' followed by a masked value');
}
// own generated sets are unchanged by the new rule (all application types and languages, 50 seeds)
{
	let changed = 0, tests = 0;
	for (let seed = 1; seed <= 50; seed++) {
		const s = PITB.buildSet({ appTypes: Object.keys(PITB.APP_TYPES), langs: Object.keys(PITB.LANGS), seed });
		tests += s.tests.length;
		const m = PITB.maskedSet(s);
		if (JSON.stringify(m.tests) !== JSON.stringify(s.tests) || m.labelInstruction !== s.labelInstruction) { changed++; }
	}
	check(changed === 0, 'own generated sets unchanged by masking (50 sets, ' + tests + ' tests, base64 payloads with the canary included)');
}
// linear: 1 MB of space-separated mixed words
{
	const big = (NAMED + ' ' + PASSWORD + ' plain words ').repeat(Math.ceil((1 << 20) / 60));
	const t = Date.now(); const out = PITB.maskSecrets(big, []); const ms = Date.now() - t;
	check(!leaks(out, SHORT).length && ms < 2000, 'masking stays fast on 1 MB of unkeyed values (' + ms + ' ms)');
}

console.log(failed ? 'FAIL: ' + failed + ' of ' + n + ' checks' : '\nPASS: test bench values without a key (' + n + ' checks)');
process.exitCode = failed ? 1 : 0;
