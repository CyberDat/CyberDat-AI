/*
 * Prompt Injection Test Bench: canary detection on the frozen response corpus and the held-out set.
 * NOT INDEPENDENT: responses and detection were written by the same author.
 *   node tests/prompt-injection-test-bench-corpus.test.cjs [--verbose] [--no-guard]
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { fill } = require('./lib/synthetic-secrets.cjs');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/prompt-injection-test-bench/engine.js'));
const FIX = path.join(__dirname, 'fixtures/prompt-injection-test-bench');

/** Test-side markers: the engine only ever sees the encoded text. */
function expand(s) {
	return fill(String(s))
		.replace(/\{\{B64:([\s\S]*?)\}\}/g, (m, x) => Buffer.from(x, 'utf8').toString('base64'))
		.replace(/\{\{HEX:([\s\S]*?)\}\}/g, (m, x) => Buffer.from(x, 'utf8').toString('hex'))
		.replace(/\{\{URL:([\s\S]*?)\}\}/g, (m, x) => encodeURIComponent(x))
		.replace(/\{\{ZW:([\s\S]*?)\}\}/g, (m, x) => [...x].join('​'))
		.replace(/\{\{TAG:([\s\S]*?)\}\}/g, (m, x) => [...x].map(c => String.fromCodePoint(0xE0000 + c.charCodeAt(0))).join(''));
}
const load = f => JSON.parse(fs.readFileSync(path.join(FIX, f), 'utf8'));
function evaluate(set) {
	const m = { pos: 0, hit: 0, methodOk: 0, neg: 0, fp: 0, misses: [] };
	for (const c of set.cases) {
		const r = engine.detect(expand(c.response), c.canary);
		if (c.expect.triggered) {
			m.pos++;
			if (r) { m.hit++; if (r.method === c.expect.method) { m.methodOk++; } else { m.misses.push(c.id + ': method ' + r.method + ' instead of ' + c.expect.method); } } else { m.misses.push(c.id + ': not found'); }
		} else {
			m.neg++;
			if (r) { m.fp++; m.misses.push(c.id + ': false hit (' + r.method + ')'); }
		}
	}
	return m;
}
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) : '—') + '%';
const report = (name, m) => { console.log(name + ' (NOT INDEPENDENT): canary found ' + m.hit + '/' + m.pos + ' (' + pct(m.hit, m.pos) + '), method as expected ' + m.methodOk + '/' + m.pos + '; negatives with a false hit ' + m.fp + '/' + m.neg); if (process.argv.includes('--verbose')) { for (const x of m.misses) { console.log('    ' + x); } } };
const main = evaluate(load('corpus.json'));
const hold = evaluate(load('holdout.json'));
report('main corpus', main);
report('held-out set', hold);
module.exports = { expand };
if (require.main === module && !process.argv.includes('--no-guard')) {
	const assert = require('node:assert/strict');
	assert.equal(main.hit, main.pos);
	assert.equal(main.fp, 0);
	assert.equal(hold.fp, 0);
	console.log('PASS: corpus regression guards (NOT INDEPENDENT)');
}
