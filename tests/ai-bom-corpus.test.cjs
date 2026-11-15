/*
 * AI Model Bill of Materials: metrics on the frozen corpus and the held-out set.
 * NOT INDEPENDENT: the corpus, the held-out set and the rules were written by the same author.
 *   node tests/ai-bom-corpus.test.cjs [--verbose] [--no-guard]
 */
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { fill } = require('./lib/synthetic-secrets.cjs');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/ai-model-bom/engine.js'));
const FIX = path.join(__dirname, 'fixtures/ai-bom');
const ALG = { SHA256: 'sha256', SHA384: 'sha384', SHA512: 'sha512', SHA1: 'sha1', MD5: 'md5' };

/** Test-side placeholders: synthetic secrets and hex digests of a seed (so no digest literals are committed). */
function expand(s) {
	return fill(String(s)).replace(/\{\{(SHA256|SHA384|SHA512|SHA1|MD5):([^}]*)\}\}/g, (m, a, seed) => crypto.createHash(ALG[a]).update(seed).digest('hex'));
}
const expandDeep = v => (typeof v === 'string' ? expand(v) : Array.isArray(v) ? v.map(expandDeep) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expandDeep(x)])) : v);
const load = f => JSON.parse(fs.readFileSync(path.join(FIX, f), 'utf8')).cases;

function run(c) {
	try {
		const r = c.mode === 'build' ? engine.build(expandDeep(c.inventory), { timestamp: '2026-11-14T00:00:00Z' }) : engine.review(expand(c.text));
		return { ids: [...new Set(r.findings.map(f => f.rule))].sort(), result: r };
	} catch (e) {
		return { error: e.code || 'THROW', message: e.message, ids: [] };
	}
}

function evaluate(cases) {
	const m = { cases: cases.length, exact: 0, errorsExpected: 0, errorsOk: 0, perRule: {}, mismatches: [], tp: 0, fp: 0, fn: 0, cleanCases: 0, cleanOk: 0 };
	const pr = id => (m.perRule[id] = m.perRule[id] || { tp: 0, fp: 0, fn: 0 });
	for (const c of cases) {
		const r = run(c);
		if (c.expectError) {
			m.errorsExpected++;
			if (r.error === c.expectError) { m.errorsOk++; m.exact++; } else { m.mismatches.push(c.id + ': expected error ' + c.expectError + ', got ' + (r.error || 'findings ' + r.ids.join(' '))); }
			continue;
		}
		if (r.error) { m.mismatches.push(c.id + ': unexpected error ' + r.error + ': ' + r.message); for (const id of c.expect) { pr(id).fn++; m.fn++; } continue; }
		const exp = new Set(c.expect), got = new Set(r.ids);
		for (const id of got) { if (exp.has(id)) { pr(id).tp++; m.tp++; } else { pr(id).fp++; m.fp++; } }
		for (const id of exp) { if (!got.has(id)) { pr(id).fn++; m.fn++; } }
		if (!c.expect.length) { m.cleanCases++; if (!got.size) { m.cleanOk++; } }
		if (exp.size === got.size && [...exp].every(x => got.has(x))) { m.exact++; } else { m.mismatches.push(c.id + ' [' + c.lang + ']: expected ' + (c.expect.join(' ') || 'nothing') + ' | got ' + (r.ids.join(' ') || 'nothing')); }
	}
	return m;
}
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) : '—') + '%';
function report(name, m) {
	console.log(name + ' (NOT INDEPENDENT):');
	console.log('  cases fully correct ' + m.exact + '/' + m.cases + ' (' + pct(m.exact, m.cases) + '); rule hits: recall ' + pct(m.tp, m.tp + m.fn) + ' (' + m.tp + '/' + (m.tp + m.fn) + '), precision ' + pct(m.tp, m.tp + m.fp) + ' (false ' + m.fp + '); clean cases without findings ' + m.cleanOk + '/' + m.cleanCases + '; expected errors ' + m.errorsOk + '/' + m.errorsExpected);
	if (process.argv.includes('--verbose')) {
		for (const x of m.mismatches) { console.log('    MISMATCH ' + x); }
		for (const [id, v] of Object.entries(m.perRule).sort()) { if (v.fp || v.fn) { console.log('    ' + id + ' tp ' + v.tp + ' fp ' + v.fp + ' fn ' + v.fn); } }
	}
}
const main = evaluate(load('corpus.json'));
const hold = evaluate(load('holdout.json'));
report('main corpus', main);
report('held-out set', hold);
module.exports = { expand, expandDeep, load, run, evaluate };

if (require.main === module && !process.argv.includes('--no-guard')) {
	const assert = require('node:assert/strict');
	assert.equal(main.exact, main.cases, 'every main-corpus case matches its expected rule set');
	assert.ok(hold.tp / (hold.tp + hold.fn) >= 0.8, 'held-out recall >= 80%');
	assert.ok(hold.fp <= 2, 'held-out false rule hits <= 2');
	console.log('PASS: corpus regression guards (NOT INDEPENDENT)');
}
