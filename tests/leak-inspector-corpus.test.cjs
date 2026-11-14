/*
 * System Prompt & Agent Leak Inspector: metrics on the synthetic corpus and the held-out set.
 * NOT INDEPENDENT: the corpus and the rules were written by the same author.
 *   node tests/leak-inspector-corpus.test.cjs [--verbose] [--no-guard]
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { fill } = require('./lib/synthetic-secrets.cjs');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/leak-inspector/engine.js'));
const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };
const FIX = path.join(__dirname, 'fixtures/leak-inspector');

/** Test-side encoding markers: the engine only ever sees the encoded text. */
function expand(s) {
	return String(s)
		.replace(/\{\{B64:([\s\S]*?)\}\}/g, (m, x) => Buffer.from(x, 'utf8').toString('base64'))
		.replace(/\{\{HEX:([\s\S]*?)\}\}/g, (m, x) => Buffer.from(x, 'utf8').toString('hex'))
		.replace(/\{\{URL:([\s\S]*?)\}\}/g, (m, x) => encodeURIComponent(x));
}
const load = f => JSON.parse(fill(fs.readFileSync(path.join(FIX, f), 'utf8')));

function evaluate(set) {
	const m = { auditRisky: set.audit.risky.length, auditDetected: 0, auditRule: 0, auditBenign: set.audit.benign.length, auditFpMedium: 0, auditFpLow: 0, leakPos: 0, leakDetected: 0, leakRule: 0, leakNeg: 0, leakFpMedium: 0, leakFpLow: 0, misses: [], fps: [] };
	for (const c of set.audit.risky) {
		const r = engine.audit(c.text);
		const ok = r.findings.some(f => f.group === c.expect.group && RANK[f.severity] >= RANK[c.expect.min]);
		if (ok) { m.auditDetected++; } else { m.misses.push(c.id + ' expected ' + c.expect.group + '>=' + c.expect.min + ' got ' + (r.findings.map(f => f.rule + ':' + f.severity).join(' ') || 'nothing')); }
		if (r.findings.some(f => f.rule === c.expect.rule && RANK[f.severity] >= RANK[c.expect.min])) { m.auditRule++; }
	}
	for (const c of set.audit.benign) {
		const r = engine.audit(c.text);
		const med = r.findings.filter(f => RANK[f.severity] >= RANK.medium), low = r.findings.filter(f => RANK[f.severity] >= RANK.low);
		if (med.length) { m.auditFpMedium++; }
		if (low.length) { m.auditFpLow++; m.fps.push(c.id + ': ' + low.map(f => f.rule + ':' + f.severity).join(' ')); }
	}
	for (const p of set.leak.pairs) {
		const r = engine.leakCheck(set.leak[p.prompt], expand(p.response));
		if (p.expect) {
			m.leakPos++;
			const ok = r.findings.some(f => f.group === 'leak' && RANK[f.severity] >= RANK[p.expect.min]);
			if (ok) { m.leakDetected++; } else { m.misses.push(p.id + ' expected leak>=' + p.expect.min + ' got ' + (r.findings.map(f => f.rule + ':' + f.severity).join(' ') || 'nothing') + ' overlap ' + (r.overlap ? r.overlap.share : 0) + '%'); }
			if (r.findings.some(f => f.rule === p.expect.rule && RANK[f.severity] >= RANK[p.expect.min])) { m.leakRule++; }
		} else {
			m.leakNeg++;
			const med = r.findings.filter(f => RANK[f.severity] >= RANK.medium), low = r.findings.filter(f => RANK[f.severity] >= RANK.low);
			if (med.length) { m.leakFpMedium++; }
			if (low.length) { m.leakFpLow++; m.fps.push(p.id + ': ' + low.map(f => f.rule + ':' + f.severity).join(' ') + ' overlap ' + r.overlap.share + '%'); }
		}
	}
	return m;
}
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) : '0.0') + '%';
function report(name, m) {
	console.log(name + ' (NOT INDEPENDENT):');
	console.log('  audit: detected ' + m.auditDetected + '/' + m.auditRisky + ' (' + pct(m.auditDetected, m.auditRisky) + '), specific rule ' + m.auditRule + '/' + m.auditRisky + '; benign with medium+ ' + m.auditFpMedium + '/' + m.auditBenign + ' (' + pct(m.auditFpMedium, m.auditBenign) + '), low+ ' + m.auditFpLow + '/' + m.auditBenign);
	console.log('  leak check: detected ' + m.leakDetected + '/' + m.leakPos + ' (' + pct(m.leakDetected, m.leakPos) + '), specific rule ' + m.leakRule + '/' + m.leakPos + '; negatives with medium+ ' + m.leakFpMedium + '/' + m.leakNeg + ', low+ ' + m.leakFpLow + '/' + m.leakNeg);
	if (process.argv.includes('--verbose')) { for (const x of m.misses) { console.log('    MISS ' + x); } for (const x of m.fps) { console.log('    FP   ' + x); } }
}
const main = evaluate(load('corpus.json'));
const hold = evaluate(load('holdout.json'));
report('main corpus', main);
report('held-out set', hold);
module.exports = { expand, evaluate, load };

if (require.main === module && !process.argv.includes('--no-guard')) {
	const assert = require('node:assert/strict');
	assert.ok(main.auditDetected / main.auditRisky >= 0.85, 'audit detection >= 85%');
	assert.ok(main.auditFpMedium / main.auditBenign <= 0.08, 'audit medium+ false positives <= 8%');
	assert.ok(main.leakDetected / main.leakPos >= 0.85, 'leak detection >= 85%');
	assert.equal(main.leakFpMedium, 0, 'no medium+ on leak negatives');
	console.log('PASS: corpus regression guards (NOT INDEPENDENT)');
}
