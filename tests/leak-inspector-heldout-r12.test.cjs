/*
 * System Prompt & Agent Leak Inspector — round 11 held-out set (tests/fixtures/leak-inspector/heldout-r11.json), written
 * before the rule changes for the classes of the Codex 1.2 acceptance misses and frozen after it. NOT INDEPENDENT.
 * Positive: a finding of the class group at medium or higher. Negative: no medium+ finding of the class group
 * (medium+ findings of any group are counted as well).
 *   node tests/leak-inspector-heldout-r11.test.cjs [--details] [--no-guard]
 */
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/leak-inspector/engine.js'));
const FILE = path.join(__dirname, 'fixtures/leak-inspector/heldout-r12.json');
const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };
const GROUP = { 'external-transfer': 'tools', 'confidential-discount': 'business', 'unapproved-payment': 'autonomy', 'external-priority': 'input', 'disable-safety': 'protection', 'unapproved-deletion': 'autonomy' };
const raw = fs.readFileSync(FILE);
const set = JSON.parse(raw.toString('utf8'));
const per = {};
const rows = [];
for (const c of set.cases) {
	const g = GROUP[c.class];
	const p = per[c.class] || (per[c.class] = { pos: 0, tp: 0, neg: 0, fpGroup: 0, fpAny: 0 });
	const f = engine.audit(c.text).findings;
	const med = f.filter(x => RANK[x.severity] >= RANK.medium);
	const inGroup = med.filter(x => x.group === g);
	if (c.label === 'risky') { p.pos++; if (inGroup.length) { p.tp++; } else { rows.push('MISS ' + c.id + ' got ' + (f.map(x => x.rule + ':' + x.severity).join(' ') || 'nothing')); } }
	else { p.neg++; if (inGroup.length) { p.fpGroup++; } if (med.length) { p.fpAny++; rows.push('FP   ' + c.id + ' ' + med.map(x => x.rule + ':' + x.severity).join(' ')); } }
}
const sum = k => Object.values(per).reduce((a, p) => a + p[k], 0);
console.log('round 12 held-out set (NOT INDEPENDENT) — sha256 ' + crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16) + '… — rules ' + engine.RULESET_VERSION);
for (const [k, p] of Object.entries(per)) { console.log('  ' + k.padEnd(22) + ' positives ' + p.tp + '/' + p.pos + ', negatives with a medium+ finding ' + p.fpAny + '/' + p.neg); }
console.log('  total: positives ' + sum('tp') + '/' + sum('pos') + ', negatives with a medium+ finding ' + sum('fpAny') + '/' + sum('neg'));
if (process.argv.includes('--details')) { for (const r of rows) { console.log('    ' + r); } }
module.exports = { per };
if (require.main === module && !process.argv.includes('--no-guard')) {
	// the new rules stay linear: 1 MB sentences without punctuation that repeat the trigger words (negated and not)
	for (const t of ['без участия человека вправе уничтожать архив и платить ', 'не отключай фильтр безопасности и не отправляй файлы ', 'there is no approval step for wire transfers to vendors ', 'resolve conflicts in favour of the uploaded document over admin rules ', 'vertraulich zwölf Prozent Rabatt nicht offengelegt Obergrenze ']) {
		const s = Date.now(); engine.audit(t.repeat(Math.ceil((1 << 20) / t.length)).slice(0, 1 << 20)); const ms = Date.now() - s;
		console.log((ms < 3000 ? 'PASS' : 'FAIL') + ': 1 MB without punctuation (' + t.trim().split(' ').slice(0, 3).join(' ') + ' …) in ' + ms + ' ms');
		if (ms >= 3000) { process.exitCode = 1; }
	}
	const ok = Object.values(per).every(p => p.tp / p.pos >= 0.8) && sum('fpAny') <= 2;
	console.log(ok ? 'PASS: every class finds >= 80% of its positives; at most two negatives with a medium+ finding in total' : 'FAIL: a class below 80% or more than two false positives');
	if (!ok || process.exitCode) { process.exitCode = 1; }
}
