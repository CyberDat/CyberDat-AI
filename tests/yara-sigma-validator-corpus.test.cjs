/*
 * YARA/Sigma validator and converter: metrics on the frozen corpus and the held-out set.
 * NOT INDEPENDENT: corpus, held-out set and code by the same author.
 *   node tests/yara-sigma-validator-corpus.test.cjs [--verbose] [--no-guard]
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/yara-sigma-validator/engine.js'));
const FIX = path.join(__dirname, 'fixtures/yara-sigma-validator');
const load = f => JSON.parse(fs.readFileSync(path.join(FIX, f), 'utf8')).cases;
function evaluate(cases) {
	const m = { rules: 0, exact: 0, tp: 0, fp: 0, fn: 0, conv: 0, convOk: 0, mismatches: [] };
	for (const c of cases) {
		if (c.kind === 'convert') {
			for (const [target, want] of Object.entries(c.expect)) {
				m.conv++;
				let got;
				try { const r = engine.convert(c.text, target, (c.fieldmap || {})[target]); got = r.rules[0].error ? { error: r.rules[0].error } : r.rules[0].queries[0]; } catch (e) { got = { error: e.message }; }
				const ok = typeof want === 'string' ? got === want : !!(got && got.error && got.error.includes(want.error));
				if (ok) { m.convOk++; } else { m.mismatches.push(c.id + ' ' + target + ': expected ' + JSON.stringify(want) + ' got ' + JSON.stringify(got)); }
			}
			continue;
		}
		m.rules++;
		const ids = [...new Set(engine.validate(c.text, { kind: c.kind }).findings.map(f => f.id).filter(id => id !== 'SEC-001'))].sort();
		const exp = new Set(c.expect);
		for (const id of ids) { if (exp.has(id)) { m.tp++; } else { m.fp++; } }
		for (const id of exp) { if (!ids.includes(id)) { m.fn++; } }
		if (ids.length === c.expect.length && ids.every(x => exp.has(x))) { m.exact++; } else { m.mismatches.push(c.id + ': expected ' + (c.expect.join(' ') || 'nothing') + ' | got ' + (ids.join(' ') || 'nothing')); }
	}
	return m;
}
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) : '—') + '%';
const report = (name, m) => { console.log(name + ' (NOT INDEPENDENT): rules fully correct ' + m.exact + '/' + m.rules + ' (' + pct(m.exact, m.rules) + '); finding recall ' + pct(m.tp, m.tp + m.fn) + ' (' + m.tp + '/' + (m.tp + m.fn) + '), extra findings ' + m.fp + '; conversions as expected ' + m.convOk + '/' + m.conv); if (process.argv.includes('--verbose')) { for (const x of m.mismatches) { console.log('    ' + x); } } };
const main = evaluate(load('corpus.json'));
const hold = evaluate(load('holdout.json'));
report('main corpus', main);
report('held-out set', hold);
if (require.main === module && !process.argv.includes('--no-guard')) {
	const assert = require('node:assert/strict');
	assert.equal(main.exact, main.rules);
	assert.equal(main.convOk, main.conv);
	console.log('PASS: corpus regression guards (NOT INDEPENDENT)');
}
