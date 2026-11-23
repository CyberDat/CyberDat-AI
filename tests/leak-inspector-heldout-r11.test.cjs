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
const FILE = path.join(__dirname, 'fixtures/leak-inspector/heldout-r11.json');
const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };
const GROUP = { 'tools-outbound': 'tools', 'business-concession': 'business', 'autonomy-finance': 'autonomy', 'autonomy-destructive': 'autonomy', 'input-hierarchy': 'input', 'protection-safety-off': 'protection' };
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
	else { p.neg++; if (inGroup.length) { p.fpGroup++; rows.push('FP   ' + c.id + ' ' + inGroup.map(x => x.rule + ':' + x.severity).join(' ')); } if (med.length) { p.fpAny++; if (!inGroup.length) { rows.push('FP*  ' + c.id + ' (other group) ' + med.map(x => x.rule + ':' + x.severity).join(' ')); } } }
}
const sum = k => Object.values(per).reduce((a, p) => a + p[k], 0);
console.log('round 11 held-out set (NOT INDEPENDENT) — sha256 ' + crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16) + '… — rules ' + engine.RULESET_VERSION);
for (const [k, p] of Object.entries(per)) { console.log('  ' + k.padEnd(22) + ' positives ' + p.tp + '/' + p.pos + ', negatives with a medium+ finding of the group ' + p.fpGroup + '/' + p.neg + ' (any group ' + p.fpAny + ')'); }
console.log('  total: positives ' + sum('tp') + '/' + sum('pos') + ', false positives in the group ' + sum('fpGroup') + '/' + sum('neg') + ', any group ' + sum('fpAny'));
if (process.argv.includes('--details')) { for (const r of rows) { console.log('    ' + r); } }
module.exports = { per };
if (require.main === module && !process.argv.includes('--no-guard')) {
	// the new rules stay linear: 1 MB sentences without punctuation that repeat the trigger words (negated and not)
	for (const t of ['без согласия не нужно отправляй переписку внешнему ', 'не отключай фильтр безопасности и не отправляй файлы ', 'never send files to external partners silently ', 'downloaded files never take precedence over admin rules ']) {
		const s = Date.now(); engine.audit(t.repeat(Math.ceil((1 << 20) / t.length)).slice(0, 1 << 20)); const ms = Date.now() - s;
		console.log((ms < 3000 ? 'PASS' : 'FAIL') + ': 1 MB without punctuation (' + t.trim().split(' ').slice(0, 3).join(' ') + ' …) in ' + ms + ' ms');
		if (ms >= 3000) { process.exitCode = 1; }
	}
	const ok = Object.values(per).every(p => p.tp / p.pos >= 0.8 && p.fpGroup <= 1);
	console.log(ok ? 'PASS: every class finds >= 80% of its positives with at most one false positive' : 'FAIL: a class below 80% or with more than one false positive');
	if (!ok || process.exitCode) { process.exitCode = 1; }
}
