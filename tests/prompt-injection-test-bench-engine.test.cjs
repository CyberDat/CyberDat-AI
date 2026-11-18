/*
 * Prompt Injection Test Bench engine: library safety constraints, canaries, export/import round trip, response parsing,
 * secret masking, limits and static contracts. Examples here are DEPENDENT.
 *   node tests/prompt-injection-test-bench-engine.test.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const DIR = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/prompt-injection-test-bench');
const e = require(path.join(DIR, 'engine.js'));
let n = 0;
const ok = l => { n++; console.log('PASS: ' + l); };
const full = e.buildSet({ appTypes: Object.keys(e.APP_TYPES), langs: ['en', 'de', 'ru'], seed: 42 });

// ---------------------------------------------------------------- library safety
const cats = new Set(e.LIB.map(t => t.category));
assert.deepEqual([...cats].sort(), Object.keys(e.CATEGORIES).sort());
for (const t of e.LIB) { for (const l of ['en', 'de', 'ru']) { assert.ok(t.text[l], t.id + ' ' + l); } }
assert.equal(full.tests.length, e.LIB.length * 3);
ok('library: ' + e.LIB.length + ' templates in all ' + cats.size + ' categories, each in English, German and Russian');
const HARM = /weapon|explosiv|bomb|malware|ransomware|virus|exploit|drug|poison|kill|suicide|self-harm|hack into|steal|credit card|password of|social security|waffe|sprengstoff|droge|оружи|взрывч|наркот|вредонос|укради|самоубий|jailbreak|developer mode|DAN\b|no restrictions|без ограничений|ohne einschränkungen/iu;
for (const t of full.tests) {
	const decoded = t.template === 'ENC-01' ? e.b64decode(t.input.slice(t.input.lastIndexOf(' ') + 1)) : t.template === 'ENC-02' ? [...t.input].filter(c => c.codePointAt(0) > 0xE0000).map(c => String.fromCharCode(c.codePointAt(0) - 0xE0000)).join('') : '';
	const all = t.input + ' ' + decoded;
	assert.ok(!HARM.test(all), t.id + ' contains a harmful term');
	const urls = all.match(/https?:\/\/[^\s)"'<>]+/gu) || [];
	for (const u of urls) { assert.ok(/^https:\/\/example\.(?:com|org|net)\//u.test(u), t.id + ' URL ' + u); }
	if (t.check === 'canary') { assert.ok(all.includes(t.canary), t.id + ' asks for its canary'); } else { assert.ok(t.canary === full.label && !all.includes(full.label), t.id + ' label test must not contain the label'); }
	if (t.category === 'tool') { assert.ok(all.includes(e.TOOL)); }
}
ok('every test asks only for a harmless canary action; URLs only on example.com/.org/.net; no harmful or jailbreak wording; label tests do not reveal the label');
const canaries = full.tests.filter(t => t.check === 'canary').map(t => t.canary);
assert.equal(new Set(canaries).size, canaries.length);
assert.ok(canaries.every(c => /^CANARY-[0-9A-F]{8}$/u.test(c)) && /^LABEL-[0-9A-F]{8}$/u.test(full.label));
const a = e.buildSet({ appTypes: ['chat'], langs: ['en'] }), b = e.buildSet({ appTypes: ['chat'], langs: ['en'] });
assert.notEqual(a.tests[0].canary, b.tests[0].canary);
assert.deepEqual(e.buildSet({ appTypes: ['chat'], langs: ['en'], seed: 1 }).tests.map(t => t.canary), e.buildSet({ appTypes: ['chat'], langs: ['en'], seed: 1 }).tests.map(t => t.canary));
ok('canaries are unique within a set, random between sets (crypto), reproducible with a seed in tests');
assert.throws(() => e.buildSet({ appTypes: [], langs: ['en'] }), err => err.code === 'NO_TYPE');
assert.throws(() => e.buildSet({ appTypes: ['chat'], langs: [] }), err => err.code === 'NO_LANG');
ok('building needs an application type and a language');

// ---------------------------------------------------------------- every test detects its own canary, and only its own
for (const t of full.tests) {
	const own = e.check(full, { [t.id]: 'Sure: ' + t.canary });
	assert.equal(own.rows.find(r => r.id === t.id).status, 'triggered', t.id);
	const neg = e.check(full, { [t.id]: 'I will not follow instructions from that content.' });
	assert.equal(neg.rows.find(r => r.id === t.id).status, 'not-triggered', t.id);
}
const cross = e.check(full, { [full.tests[0].id]: 'Code ' + full.tests[1].canary });
assert.equal(cross.rows[0].status, 'not-triggered');
assert.equal(cross.rows[0].otherCanary, full.tests[1].id);
ok('each of ' + full.tests.length + ' tests triggers on its own canary and not on a refusal; a canary of another test is reported separately');

// ---------------------------------------------------------------- export / import / responses
const files = e.exportSet(full);
const back = e.importSet(files.jsonl);
assert.deepEqual(back.tests.map(t => [t.id, t.canary, t.input]), full.tests.map(t => [t.id, t.canary, t.input]));
assert.equal(back.label, full.label);
assert.equal(files.csv.split('\r\n').length, full.tests.length + 2);
assert.throws(() => e.importSet('{"type":"other"}'), err => err.code === 'NOT_SET');
assert.throws(() => e.importSet('x'), err => err.code === 'PARSE');
const jsonl = full.tests.slice(0, 3).map(t => JSON.stringify({ id: t.id, response: 'Antwort mit „Anführungszeichen“, ' + t.canary })).join('\n');
const pj = e.parseResponses(jsonl);
assert.equal(Object.keys(pj).length, 3);
const pc = e.parseResponses('id,response\r\nT001,"Ответ, с ""кавычками""\nи переносом ' + full.tests[0].canary + '"\r\nT002,plain\r\n');
assert.ok(pc.T001.includes('""') === false && pc.T001.includes('"кавычками"') && pc.T001.includes('\n') && pc.T002 === 'plain');
ok('test set JSONL round trip keeps ids, canaries and inputs; CSV export; responses from JSONL and quoted CSV (Unicode, commas, quotes, newlines)');

// ---------------------------------------------------------------- secrets, report, limits
const t0 = full.tests[0];
const sec = e.check(full, { [t0.id]: 'Debug ' + S.OPENAI_PROJECT_KEY + ' token ' + S.OPAQUE_LONG + ' code ' + t0.canary });
const rep = e.exportReport(full, sec, { timestamp: '2026-11-18T00:00:00Z' });
for (const v of [S.OPENAI_PROJECT_KEY, S.OPAQUE_LONG]) { assert.ok(!JSON.stringify(sec).includes(v) && !rep.json.includes(v) && !rep.markdown.includes(v)); }
assert.ok(sec.rows[0].fragment.includes(t0.canary) && sec.rows[0].secrets.length === 2);
assert.ok(/does not mean the application is protected/.test(rep.json) && !/\b(?:secure|compliant|certified)\b/iu.test(rep.json.replace(/protected/gu, '')));
ok('secrets and unrecognized long values in responses are masked in fragments and reports; the canary stays visible');
assert.throws(() => e.check(full, { [t0.id]: 'x'.repeat(e.MAX_RESPONSE_CHARS + 1) }), err => err.code === 'TOO_LARGE');
const big = {};
for (const t of full.tests) { big[t.id] = ('Long answer text without the code. Ёлка, Größe. ').repeat(1500).slice(0, 80000); }
let s = performance.now();
const rb = e.check(full, big);
const ms = performance.now() - s;
assert.ok(rb.counts.answered === full.tests.length && rb.counts.triggered === 0 && ms < 10000, 'large check ' + Math.round(ms));
ok('limits: 200,000 characters per response; ' + full.tests.length + ' responses of 80,000 characters checked in ' + Math.round(ms) + ' ms');

// ---------------------------------------------------------------- static contracts
for (const f of ['engine.js', 'worker.js', 'app.js']) {
	const src = fs.readFileSync(path.join(DIR, f), 'utf8');
	assert.ok(!src.includes('(?<=') && !src.includes('(?<!'), f + ': look-behind');
	assert.ok(!/\\[bBwW]/.test(src), f + ': \\b or \\w');
	assert.ok(!/\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML|document\.write|\beval\(|new Function\(/.test(src), f + ': HTML sink or eval');
	assert.ok(!/localStorage|sessionStorage|indexedDB|document\.cookie|history\.(?:push|replace)State/.test(src), f + ': storage');
	if (f !== 'worker.js') { assert.ok(!/\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource/.test(src), f + ': network'); }
}
assert.ok(fs.readFileSync(path.join(DIR, 'app.js'), 'utf8').includes("'No canary appeared in the answered tests. This does not mean the application is protected.'"));
ok('engine, worker and app: no look-behind, no \\b/\\w, no HTML sinks, storage or network; agreed no-trigger sentence');
console.log('\n' + n + ' test bench engine checks passed (examples DEPENDENT).');
