/*
 * Detection / false-positive measurement for the LotL / LOLBAS Command Analyzer. Pure Node.js, offline.
 *   node tests/lotl-analyzer-corpus.test.cjs [metrics.json]     (LOTL_METRICS_ONLY=1 skips the regression guards)
 *
 * Suspicious case "flagged": verdict medium or high. "Function correct": the expected LOLBAS binary is
 * reported with a documented usage of the expected category (any match quality), or, for heuristic-only
 * cases, a CyberDat heuristic of medium+ severity is reported.
 * Benign false positive: verdict medium or high ("medium+"); "any" also counts low.
 * The corpus is written by the tool author, so these numbers are optimistic.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/lotl-analyzer/engine.js'));

const psenc = s => Buffer.from(s, 'utf16le').toString('base64');
const expand = t => t.replace(/\{\{psenc:((?:(?!\}\})[\s\S])*)\}\}/g, (m, s) => psenc(s));
module.exports = { expand, psenc };
if (require.main !== module) { return; }

const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };
function evaluate(set) {
	const r = { suspicious: set.suspicious.length, flagged: 0, functionCorrect: 0, missed: [], wrongFunction: [], benign: set.benign.length, fpAny: 0, fpMedium: 0, flaggedBenign: [] };
	for (const c of set.suspicious) {
		const res = engine.analyze(expand(c.cmd)).commands[0];
		const all = [res].concat(res.decoded.map(d => d.analysis).filter(Boolean));
		if (RANK[res.severity] >= RANK.medium) { r.flagged++; } else { r.missed.push(c.id + ' (' + res.severity + ')'); }
		let ok;
		if (c.expect.binary) {
			ok = all.some(a => a.binaries.some(b => b.name.toLowerCase() === c.expect.binary && b.matches.some(m => m.category === c.expect.category)));
		} else {
			ok = all.some(a => a.heuristics.some(h => RANK[h.severity] >= RANK.medium));
		}
		if (ok) { r.functionCorrect++; } else { r.wrongFunction.push(c.id); }
	}
	for (const c of set.benign) {
		const res = engine.analyze(c.cmd).commands[0];
		if (RANK[res.severity] >= RANK.low) { r.fpAny++; r.flaggedBenign.push(c.id + ': ' + res.severity + ' ' + res.binaries.flatMap(b => b.matches.map(m => b.name + '/' + m.category + '/' + m.quality)).concat(res.heuristics.map(h => h.id + ':' + h.severity)).join(', ')); }
		if (RANK[res.severity] >= RANK.medium) { r.fpMedium++; }
	}
	return r;
}
const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : 0) + '%';
const main = evaluate(JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/lotl-analyzer/corpus.json'), 'utf8')));
const hold = evaluate(JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/lotl-analyzer/holdout.json'), 'utf8')));
for (const [name, r] of [['Main corpus', main], ['Held-out set (not used for tuning)', hold]]) {
	console.log(`\n${name}:`);
	console.log(`  suspicious flagged (medium+): ${r.flagged}/${r.suspicious} = ${pct(r.flagged, r.suspicious)}; function/heuristic correct: ${r.functionCorrect}/${r.suspicious} = ${pct(r.functionCorrect, r.suspicious)}`);
	console.log(`  missed: ${r.missed.join(', ') || '-'}; wrong or missing function: ${r.wrongFunction.join(', ') || '-'}`);
	console.log(`  benign false positives: medium+ ${r.fpMedium}/${r.benign} = ${pct(r.fpMedium, r.benign)}; any (low+) ${r.fpAny}/${r.benign} = ${pct(r.fpAny, r.benign)}`);
	for (const f of r.flaggedBenign) { console.log('    ' + f); }
}
if (process.argv[2]) { fs.writeFileSync(process.argv[2], JSON.stringify({ engine: engine.VERSION, ruleset: engine.RULESET_VERSION, data: engine.DATA_META.commit, at: new Date().toISOString(), main, holdout: hold }, null, 2) + '\n'); }
if (process.env.LOTL_METRICS_ONLY) { process.exit(0); }
assert.ok(main.flagged / main.suspicious >= 0.85, 'main corpus detection regression');
assert.ok(main.fpMedium / main.benign <= 0.10, 'main corpus false-positive regression');
console.log('\nPASS: corpus regression guards (main corpus detection >= 85%, medium+ false positives <= 10%)');
