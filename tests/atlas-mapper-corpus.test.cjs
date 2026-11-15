/*
 * MITRE ATLAS Attack Vector Mapper: metrics on the frozen corpus and the held-out set.
 * NOT INDEPENDENT: the corpus, the held-out set and the CyberDat mapping were written by the same author.
 *   node tests/atlas-mapper-corpus.test.cjs [--verbose] [--no-guard]
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { fill } = require('./lib/synthetic-secrets.cjs');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/atlas-mapper/engine.js'));
const FIX = path.join(__dirname, 'fixtures/atlas-mapper');
const load = f => JSON.parse(fs.readFileSync(path.join(FIX, f), 'utf8')).cases;

function run(c) {
	const r = c.mode === 'profile' ? engine.profile(c.properties) : engine.mapFinding(fill(c.text));
	return r.techniques.map(t => t.id).sort();
}
function evaluate(cases) {
	const m = { profiles: 0, profilesExact: 0, findings: 0, findingsHit: 0, findingsExact: 0, tp: 0, fn: 0, fp: 0, benign: 0, benignClean: 0, mismatches: [] };
	for (const c of cases) {
		const got = run(c);
		if (c.mode === 'profile') {
			m.profiles++;
			if (JSON.stringify(got) === JSON.stringify(c.expect)) { m.profilesExact++; } else { m.mismatches.push(c.id + ': expected ' + c.expect.join(' ') + ' | got ' + got.join(' ')); }
			continue;
		}
		const exp = new Set(c.expect), allow = new Set(c.allow || []);
		const fp = got.filter(x => !exp.has(x) && !allow.has(x));
		const fn = c.expect.filter(x => !got.includes(x));
		m.tp += c.expect.length - fn.length; m.fn += fn.length; m.fp += fp.length;
		if (!c.expect.length) { m.benign++; if (!got.length) { m.benignClean++; } } else { m.findings++; if (!fn.length) { m.findingsHit++; } if (!fn.length && !fp.length) { m.findingsExact++; } }
		if (fn.length || fp.length) { m.mismatches.push(c.id + ' [' + c.lang + ']: missed ' + (fn.join(' ') || '-') + ' | extra ' + (fp.join(' ') || '-')); }
	}
	return m;
}
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) : '—') + '%';
function report(name, m) {
	console.log(name + ' (NOT INDEPENDENT):');
	console.log('  profiles exact ' + m.profilesExact + '/' + m.profiles + '; findings with all expected techniques ' + m.findingsHit + '/' + m.findings + ' (' + pct(m.findingsHit, m.findings) + '), exact ' + m.findingsExact + '/' + m.findings + '; technique recall ' + pct(m.tp, m.tp + m.fn) + ' (' + m.tp + '/' + (m.tp + m.fn) + '), extra techniques ' + m.fp + '; benign texts without candidates ' + m.benignClean + '/' + m.benign);
	if (process.argv.includes('--verbose')) { for (const x of m.mismatches) { console.log('    ' + x); } }
}
const main = evaluate(load('corpus.json'));
const hold = evaluate(load('holdout.json'));
report('main corpus', main);
report('held-out set', hold);
module.exports = { load, run, evaluate };
if (require.main === module && !process.argv.includes('--no-guard')) {
	const assert = require('node:assert/strict');
	assert.equal(main.profilesExact, main.profiles, 'profiles follow the frozen spec');
	assert.equal(main.findingsHit, main.findings, 'every main-corpus finding gets its expected techniques');
	assert.equal(main.benignClean, main.benign, 'benign main-corpus texts give no candidates');
	assert.ok(main.fp <= 2, 'main-corpus extra techniques <= 2');
	console.log('PASS: corpus regression guards (NOT INDEPENDENT)');
}
