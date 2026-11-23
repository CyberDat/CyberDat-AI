/*
 * MITRE ATLAS Attack Vector Mapper engine: data integrity against the frozen mapping spec and the snapshot provenance,
 * static contracts, Unicode, secret masking, export and large inputs. Examples here are DEPENDENT.
 *   node tests/atlas-mapper-engine.test.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const DIR = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/atlas-mapper');
const e = require(path.join(DIR, 'engine.js'));
const D = e.DATA;
let n = 0;
const ok = l => { n++; console.log('PASS: ' + l); };
const ids = r => r.techniques.map(t => t.id).sort();

// ---------------------------------------------------------------- snapshot provenance and integrity
const snap = JSON.parse(fs.readFileSync(path.join(__dirname, '../deploy/tools-atlas-mapper/atlas-snapshot.json'), 'utf8'));
const lf = f => fs.readFileSync(path.join(DIR, f)).toString('utf8').replace(/\r\n/g, '\n');
for (const f of ['atlas-data.js', 'LICENSE-ATLAS.txt', 'LICENSE-APACHE-2.0.txt']) {
	assert.equal(crypto.createHash('sha256').update(lf(f), 'utf8').digest('hex'), snap.outputSha256[f], f + ' differs from the generated snapshot');
}
assert.ok(/Licensed under the Apache License, Version 2\.0/.test(lf('LICENSE-ATLAS.txt')) && /Apache License\s+Version 2\.0, January 2004/.test(lf('LICENSE-APACHE-2.0.txt')));
assert.equal(D.meta.release, snap.release);
assert.equal(D.meta.commit, snap.commit);
assert.deepEqual(D.meta.counts, snap.counts);
ok('snapshot files equal the generated output (' + snap.release + ', commit ' + snap.commit.slice(0, 7) + '); upstream Apache-2.0 notice and full license text present');
const TECH = new Map(D.techniques.map(t => [t.id, t]));
const all = new Set(D.techniques.map(t => t.id).concat(D.tactics.map(t => t.id), D.mitigations.map(m => m.id)));
for (const t of D.techniques) { for (const x of t.tactics.concat(t.parent ? [t.parent] : [])) { assert.ok(all.has(x), t.id + ' -> ' + x); } assert.ok(t.tactics.length > 0, t.id + ' has a tactic'); }
for (const [m, t] of D.mitigates) { assert.ok(all.has(m) && all.has(t), m + ' -> ' + t); }
ok('every tactic, parent and mitigation link in the snapshot points to an existing id');
const spec = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/atlas-mapper/mapping-spec.json'), 'utf8'));
const used = new Set();
for (const [k, p] of Object.entries(spec.properties)) {
	assert.ok(e.PROPERTIES[k], k);
	assert.equal(e.PROPERTIES[k][0], p.label);
	assert.deepEqual(e.PROPERTIES[k][1].map(x => x[0]), p.techniques.map(x => x.technique), k);
	for (const x of p.techniques) { used.add(x.technique); }
}
assert.deepEqual(Object.keys(e.PROPERTIES), Object.keys(spec.properties));
// round 11: rules added after the frozen spec are listed in mapping-spec-r11.json (the frozen file is unchanged)
const specR11 = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/atlas-mapper/mapping-spec-r11.json'), 'utf8'));
assert.deepEqual(e.RULES.map(r => [r.id, r.technique]), spec.findingRules.concat(specR11.findingRules).map(r => [r.id, r.technique]));
for (const r of e.RULES) { used.add(r.technique); for (const u of r.unless || []) { assert.ok(e.RULES.some(x => x.id === u), r.id + ' unless ' + u); } }
const missing = [...used].filter(id => !TECH.has(id));
assert.deepEqual(missing, [], 'mapping refers to techniques that are not in the snapshot (removed or renamed upstream?)');
ok('the engine equals the frozen mapping spec; all ' + used.size + ' technique ids used by the CyberDat mapping exist in ATLAS ' + D.meta.release);

// ---------------------------------------------------------------- static contracts
const SRC = Object.fromEntries(['engine.js', 'worker.js', 'app.js'].map(f => [f, fs.readFileSync(path.join(DIR, f), 'utf8')]));
for (const [f, src] of Object.entries(SRC)) {
	assert.ok(!src.includes('(?<=') && !src.includes('(?<!'), f + ': look-behind');
	assert.ok(!/\\[bBwW]/.test(src), f + ': \\b or \\w');
	assert.ok(!/\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML|document\.write|\beval\(|new Function\(/.test(src), f + ': HTML sink or eval');
	assert.ok(!/localStorage|sessionStorage|indexedDB|document\.cookie|history\.(?:push|replace)State/.test(src), f + ': storage');
	if (f !== 'worker.js') { assert.ok(!/\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource/.test(src), f + ': network'); }
	assert.ok(!/createElement\(['"]a['"]\)[^;]*\.href\s*=\s*(?!url)/.test(src), f + ': links');
}
assert.ok(SRC['app.js'].includes("'No matching techniques found. This does not mean the system is not exposed.'"));
ok('engine, worker and app: no look-behind, no \\b/\\w, no HTML sinks, storage or network; agreed no-match sentence');

// ---------------------------------------------------------------- behaviour (dependent examples)
const p = e.profile(['rag', 'agent-tools']);
assert.ok(p.groups.length >= 3 && p.techniques.every(t => t.reasons.length && t.tactics.length));
const t51 = p.techniques.find(t => t.id === 'AML.T0051.001');
assert.ok(t51.parent.id === 'AML.T0051' && t51.mitigations.length > 0);
assert.ok(t51.mitigations.some(m => m.via === 'AML.T0051') || t51.mitigations.every(m => !m.via));
ok('profile: techniques grouped by ATLAS tactic with CyberDat reasons and ATLAS mitigations (parent links marked)');
const phrase = e.mapFinding('Бот раскрыл системный промпт по просьбе пользователя.');
assert.deepEqual(ids(phrase), ['AML.T0069.002']);
assert.ok(e.termRe('системн промпт').test('системный промпт') && !e.termRe('rag$').test('ragged'));
ok('every word of a phrase is a stem (fix after the first run); "$" fixes the last word');
for (const [t, want] of [
	['Indirekte Prompt-Injection über eine hochgeladene Datei.', 'AML.T0051.001'],
	['Indirekte Prompt-Injection über eine hochgeladene Datei.'.normalize('NFD'), 'AML.T0051.001'],
	['Через ДЖЕЙЛБРЕЙК обошли ограничения модели.', 'AML.T0054'],
	['Ёмкий бэкдор в модели срабатывал на триггер.'.normalize('NFD'), 'AML.T0043.004']
]) { assert.ok(ids(e.mapFinding(t)).includes(want), t + ' -> ' + want); }
for (const t of ['Ragged edges on the dashboard were fixed.', 'Der Agent für Immobilien zeigte drei Wohnungen.', 'Мы обсудили ограничения бюджета.']) { assert.deepEqual(ids(e.mapFinding(t)), [], t); }
ok('Unicode: German and Russian, NFC and NFD, upper case; words inside other words do not match');

// ---------------------------------------------------------------- secrets: masked, not used for matching, not exported
const values = [S.OPENAI_PROJECT_KEY, S.GITHUB_PAT, S.HF_TOKEN, S.AWS_ACCESS_KEY_ID, S.JWT, S.OPAQUE_LONG];
const r = e.mapFinding('The API key was committed to a public repository: ' + values.join(' and '));
const shown = JSON.stringify(r);
for (const v of values) { assert.ok(!shown.includes(v), 'result shows ' + v.slice(0, 4)); }
assert.ok(r.secrets.length === values.length && ids(r).includes('AML.T0055'));
const ex = e.exportSelection([{ id: 'AML.T0055', note: 'rotate ' + S.OPENAI_PROJECT_KEY, source: 'Finding mapper' }, { id: 'AML.T9999', note: 'x' }], { timestamp: '2026-11-15T00:00:00Z' });
for (const v of [S.OPENAI_PROJECT_KEY]) { assert.ok(!ex.json.includes(v) && !ex.markdown.includes(v)); }
assert.equal(ex.count, 1);
const j = JSON.parse(ex.json);
assert.ok(j.data.release === D.meta.release && j.data.commit === D.meta.commit && /Apache License 2\.0/.test(j.data.attribution) && /not a security assessment/.test(j.note));
assert.ok(!/compliant|certified|complete coverage/i.test(ex.json + ex.markdown));
ok('secrets in pasted text and notes appear only masked; exports carry ids, notes, data version and attribution, unknown ids dropped');

// ---------------------------------------------------------------- browse and limits
assert.ok(e.search('prompt injection').techniques.some(t => t.id === 'AML.T0051') && e.search('aml.t0051').techniques.length >= 4 && e.search('').tactics.length === 16);
assert.equal(e.lookup('aml.m0020').kind, 'mitigation');
assert.ok(e.lookup('AML.TA0005').item.techniques.length > 3 && e.lookup('nope') === null);
assert.throws(() => e.mapFinding('x'.repeat(e.MAX_INPUT_CHARS + 1)), err => err.code === 'TOO_LARGE');
assert.throws(() => e.mapFinding('  '), err => err.code === 'EMPTY');
const big = ('The agent deleted files after reading a document with hidden instructions. Ein Deepfake-Anruf. Отравление обучающих данных. ').repeat(800).slice(0, e.MAX_INPUT_CHARS);
let t0 = performance.now();
const rb = e.mapFinding(big);
const ms = performance.now() - t0;
assert.ok(rb.count >= 3 && ms < 3000, 'large input ' + Math.round(ms) + ' ms');
const patho = ('a'.repeat(5000) + ' ').repeat(19);
t0 = performance.now(); e.mapFinding(patho); const ms2 = performance.now() - t0;
assert.ok(ms2 < 3000);
ok('browse by id or name; size limit; 100,000-character finding mapped in ' + Math.round(ms) + ' ms, long words in ' + Math.round(ms2) + ' ms');
console.log('\n' + n + ' ATLAS mapper engine checks passed (examples DEPENDENT).');
