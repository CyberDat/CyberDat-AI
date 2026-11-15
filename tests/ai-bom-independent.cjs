/*
 * Independent acceptance runner for the AI Model Bill of Materials (local, offline).
 *   node tests/ai-bom-independent.cjs <private-set.json> [--details]
 * Format: deploy/tools-ai-bom/independent/template.json. Keep real sets OUTSIDE the repository.
 * Results are labelled INDEPENDENT only when "provenance" is "independent" or "owner" and "authoredByToolAuthor" is false.
 * Output contains ids, rule ids and counts only, never sample text or values. Nothing is sent anywhere.
 */
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { fill } = require('./lib/synthetic-secrets.cjs');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/ai-model-bom/engine.js'));
const ALG = { SHA256: 'sha256', SHA384: 'sha384', SHA512: 'sha512', SHA1: 'sha1', MD5: 'md5' };
const expand = s => fill(String(s)).replace(/\{\{(SHA256|SHA384|SHA512|SHA1|MD5):([^}]*)\}\}/g, (m, a, seed) => crypto.createHash(ALG[a]).update(seed).digest('hex'));
const expandDeep = v => (typeof v === 'string' ? expand(v) : Array.isArray(v) ? v.map(expandDeep) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expandDeep(x)])) : v);
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + '%' : 'n/a');

function evaluate(file, details) {
	const raw = fs.readFileSync(file);
	const set = JSON.parse(raw.toString('utf8'));
	if (set.tool !== 'ai-model-bom') { throw new Error('"tool" must be "ai-model-bom"'); }
	const independent = ['independent', 'owner'].includes(set.provenance) && set.authoredByToolAuthor === false;
	const m = { cases: 0, exact: 0, tp: 0, fp: 0, fn: 0, clean: 0, cleanOk: 0, errorsExpected: 0, errorsOk: 0, unexpectedErrors: 0 };
	const perRule = {};
	const pr = id => (perRule[id] = perRule[id] || { tp: 0, fp: 0, fn: 0 });
	const rows = [];
	for (const c of set.cases || []) {
		m.cases++;
		let got = [], err = '';
		try {
			const r = c.mode === 'review' ? engine.review(expand(c.text)) : engine.build(expandDeep(c.inventory), { timestamp: '2026-01-01T00:00:00Z' });
			got = [...new Set(r.findings.map(f => f.rule))].sort();
		} catch (e) { err = e.code || 'THROW'; }
		if (c.expectError) {
			m.errorsExpected++;
			if (err === c.expectError) { m.errorsOk++; m.exact++; rows.push('ok    ' + c.id + ' error ' + err); } else { rows.push('MISS  ' + c.id + ' expected error ' + c.expectError + ', got ' + (err || got.join(' ') || 'nothing')); }
			continue;
		}
		if (err) { m.unexpectedErrors++; for (const id of c.expect || []) { pr(id).fn++; m.fn++; } rows.push('ERROR ' + c.id + ' ' + err); continue; }
		const exp = new Set(c.expect || []);
		for (const id of got) { if (exp.has(id)) { pr(id).tp++; m.tp++; } else { pr(id).fp++; m.fp++; } }
		for (const id of exp) { if (!got.includes(id)) { pr(id).fn++; m.fn++; } }
		if (!exp.size) { m.clean++; if (!got.length) { m.cleanOk++; } }
		const same = exp.size === got.length && got.every(x => exp.has(x));
		if (same) { m.exact++; }
		rows.push((same ? 'ok    ' : 'DIFF  ') + c.id + ' expected [' + [...exp].sort().join(' ') + '] got [' + got.join(' ') + ']');
	}
	console.log((independent ? 'INDEPENDENT' : 'NOT INDEPENDENT (' + (set.provenance || 'no provenance') + ')') + ' — ' + path.basename(file) + ' — sha256 ' + crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16) + '… — engine ' + engine.ENGINE + ', rules ' + engine.RULESET);
	console.log('  cases fully correct ' + m.exact + '/' + m.cases + ' (' + pct(m.exact, m.cases) + '); rule recall ' + pct(m.tp, m.tp + m.fn) + ' (' + m.tp + '/' + (m.tp + m.fn) + '); false rule hits ' + m.fp + '; clean cases without findings ' + m.cleanOk + '/' + m.clean + '; expected errors ' + m.errorsOk + '/' + m.errorsExpected + (m.unexpectedErrors ? '; unexpected errors ' + m.unexpectedErrors : ''));
	if (details) {
		for (const r of rows) { console.log('    ' + r); }
		for (const [id, v] of Object.entries(perRule).sort()) { console.log('    ' + id + ' tp ' + v.tp + ' fp ' + v.fp + ' fn ' + v.fn); }
	}
	return Object.assign({ independent, perRule }, m);
}
if (require.main === module) {
	const file = process.argv.slice(2).find(a => !a.startsWith('--'));
	if (!file) { console.error('Usage: node tests/ai-bom-independent.cjs <set.json> [--details]'); process.exit(64); }
	evaluate(file, process.argv.includes('--details'));
}
module.exports = { evaluate };
