/*
 * MCP Security & Policy Checker: detection and false-positive metrics on the synthetic corpus and the held-out set.
 *   node tests/mcp-checker-corpus.test.cjs            (prints metrics, enforces regression guards)
 *   node tests/mcp-checker-corpus.test.cjs --verbose  (lists misses and false positives)
 * The corpus was written by the tool author, so the numbers are optimistic.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { fill } = require('./lib/synthetic-secrets.cjs');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/mcp-checker/engine.js'));

const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };
const FIX = path.join(__dirname, 'fixtures/mcp-checker');
const load = f => JSON.parse(fill(fs.readFileSync(path.join(FIX, f), 'utf8')));
const textOf = c => (c.text !== undefined ? c.text : JSON.stringify(c.config, null, 2));

function evaluate(set) {
	const out = { risky: set.risky.length, detected: 0, rule: 0, legit: set.legit.length, fpMedium: 0, fpLow: 0, misses: [], fps: [] };
	for (const c of set.risky) {
		let r;
		try { r = engine.analyze(textOf(c)); } catch (e) { out.misses.push(c.id + ' ERROR ' + e.message); continue; }
		const inGroup = r.findings.filter(f => f.group === c.expect.group && RANK[f.severity] >= RANK[c.expect.min]);
		if (inGroup.length) { out.detected++; } else { out.misses.push(c.id + ' expected ' + c.expect.group + '>=' + c.expect.min + ', got ' + (r.findings.map(f => f.rule + ':' + f.severity).join(' ') || 'nothing')); }
		if (r.findings.some(f => f.rule === c.expect.rule && RANK[f.severity] >= RANK[c.expect.min])) { out.rule++; }
	}
	for (const c of set.legit) {
		let r;
		try { r = engine.analyze(textOf(c)); } catch (e) { out.fpMedium++; out.fps.push(c.id + ' ERROR ' + e.message); continue; }
		const med = r.findings.filter(f => RANK[f.severity] >= RANK.medium);
		const low = r.findings.filter(f => RANK[f.severity] >= RANK.low);
		if (med.length) { out.fpMedium++; }
		if (low.length) { out.fpLow++; }
		if (low.length) { out.fps.push(c.id + ': ' + low.map(f => f.rule + ':' + f.severity + ' [' + f.evidence.slice(0, 70) + ']').join(' | ')); }
	}
	return out;
}
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) : '0.0') + '%';
function report(name, m) {
	console.log(`${name}: detected ${m.detected}/${m.risky} (${pct(m.detected, m.risky)}), most specific rule ${m.rule}/${m.risky} (${pct(m.rule, m.risky)}); legit with medium+ ${m.fpMedium}/${m.legit} (${pct(m.fpMedium, m.legit)}), with low+ ${m.fpLow}/${m.legit} (${pct(m.fpLow, m.legit)})`);
	if (process.argv.includes('--verbose')) { for (const x of m.misses) { console.log('  MISS ' + x); } for (const x of m.fps) { console.log('  FP   ' + x); } }
}

const main = evaluate(load('corpus.json'));
const hold = evaluate(load('holdout.json'));
report('main corpus', main);
report('held-out set', hold);
module.exports = { evaluate, textOf };

if (require.main === module && !process.argv.includes('--no-guard')) {
	const assert = require('node:assert/strict');
	assert.ok(main.detected / main.risky >= 0.9, 'main corpus detection >= 90%');
	assert.ok(main.fpMedium / main.legit <= 0.05, 'main corpus medium+ false positives <= 5%');
	console.log('PASS: corpus regression guards (main corpus detection >= 90%, medium+ false positives <= 5%)');
}
