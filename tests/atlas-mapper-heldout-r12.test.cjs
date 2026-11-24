/*
 * MITRE ATLAS Attack Vector Mapper — round 11 held-out set (tests/fixtures/atlas-mapper/heldout-r11.json), written before
 * the rule changes for the classes of the Codex 1.2 acceptance misses and frozen after it. NOT INDEPENDENT.
 * Positive: one technique of expectAny proposed and none of absent. Negative: none of absent; negation negatives: none at all.
 *   node tests/atlas-mapper-heldout-r11.test.cjs [--details] [--no-guard]
 */
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/atlas-mapper/engine.js'));
const FILE = path.join(__dirname, 'fixtures/atlas-mapper/heldout-r12.json');
const raw = fs.readFileSync(FILE);
const set = JSON.parse(raw.toString('utf8'));
const known = new Set(engine.DATA.techniques.map(t => t.id));
const per = {};
const rows = [];
let unknown = 0;
for (const c of set.cases) {
	for (const id of [].concat(c.expectAny || [], c.absent || [])) { if (!known.has(id)) { unknown++; } }
	const p = per[c.class] || (per[c.class] = { pos: 0, tp: 0, neg: 0, fp: 0 });
	const got = engine.mapFinding(c.text).techniques.map(t => t.id);
	const bad = got.filter(x => (c.absent || []).includes(x));
	if (c.expectAny) {
		p.pos++;
		const ok = c.expectAny.some(x => got.includes(x)) && !bad.length;
		if (ok) { p.tp++; } else { rows.push('MISS ' + c.id + ' got [' + got.join(' ') + ']'); }
	} else {
		p.neg++;
		const fp = c.expectNone ? got.length > 0 : bad.length > 0;
		if (fp) { p.fp++; rows.push('FP   ' + c.id + ' got [' + got.join(' ') + ']'); }
	}
}
const sum = k => Object.values(per).reduce((a, p) => a + p[k], 0);
console.log('round 12 held-out set (NOT INDEPENDENT) — sha256 ' + crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16) + '… — mapping ' + engine.RULESET + ', ATLAS ' + engine.DATA.meta.release + (unknown ? ' — UNKNOWN ids ' + unknown : ''));
for (const [k, p] of Object.entries(per)) { console.log('  ' + k.padEnd(20) + ' positives ' + p.tp + '/' + p.pos + ', false positives ' + p.fp + '/' + p.neg); }
console.log('  total: positives ' + sum('tp') + '/' + sum('pos') + ', false positives ' + sum('fp') + '/' + sum('neg'));
if (process.argv.includes('--details')) { for (const r of rows) { console.log('    ' + r); } }
module.exports = { per };
if (require.main === module && !process.argv.includes('--no-guard')) {
	const ok = !unknown && Object.values(per).every(p => p.tp / p.pos >= 0.8 && p.fp <= 1);
	console.log(ok ? 'PASS: every class finds >= 80% of its positives with at most one false positive' : 'FAIL: a class below 80% or with more than one false positive');
	process.exitCode = ok ? 0 : 1;
}
