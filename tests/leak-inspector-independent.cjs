/*
 * Independent acceptance runner for the System Prompt & Agent Leak Inspector (local, offline).
 *   node tests/leak-inspector-independent.cjs <private-set.json> [--details]
 * Format: deploy/tools-leak-inspector/independent/template.json. Keep real sets OUTSIDE the repository.
 * Results are labelled INDEPENDENT only when "provenance" is "independent" or "owner" and "authoredByToolAuthor" is false.
 * Output contains ids, labels, rule ids and counts only, never sample text. Nothing is sent anywhere.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/leak-inspector/engine.js'));
const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };
const expand = s => String(s)
	.replace(/\{\{B64:([\s\S]*?)\}\}/g, (m, x) => Buffer.from(x, 'utf8').toString('base64'))
	.replace(/\{\{HEX:([\s\S]*?)\}\}/g, (m, x) => Buffer.from(x, 'utf8').toString('hex'))
	.replace(/\{\{URL:([\s\S]*?)\}\}/g, (m, x) => encodeURIComponent(x));
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + '%' : 'n/a');

function evaluate(file, details) {
	const set = JSON.parse(fs.readFileSync(file, 'utf8'));
	if (set.tool !== 'agent-leak-inspector') { throw new Error('"tool" must be "agent-leak-inspector"'); }
	const independent = ['independent', 'owner'].includes(set.provenance) && set.authoredByToolAuthor === false;
	const threshold = set.threshold || 'medium';
	const rows = [];
	const m = { auditPos: 0, auditHit: 0, auditNeg: 0, auditFp: 0, leakPos: 0, leakHit: 0, leakNeg: 0, leakFp: 0, errors: 0 };
	for (const c of set.audit || []) {
		let r;
		try { r = engine.audit(c.text); } catch (e) { m.errors++; rows.push('ERROR ' + c.id + ' ' + e.code); continue; }
		const hits = r.findings.filter(f => RANK[f.severity] >= RANK[threshold]);
		if (c.label === 'risky') {
			m.auditPos++;
			const ok = hits.length > 0 && (c.expectGroups || []).every(g => hits.some(f => f.group === g));
			if (ok) { m.auditHit++; }
			rows.push((ok ? 'hit  ' : 'MISS ') + 'audit ' + c.id + ' [' + hits.map(f => f.rule).join(' ') + ']');
		} else {
			m.auditNeg++;
			if (hits.length) { m.auditFp++; }
			rows.push((hits.length ? 'FP   ' : 'ok   ') + 'audit ' + c.id + ' [' + hits.map(f => f.rule).join(' ') + ']');
		}
	}
	for (const c of set.leak || []) {
		let r;
		try { r = engine.leakCheck(expand(c.prompt), expand(c.response), { minWords: set.minWords }); } catch (e) { m.errors++; rows.push('ERROR ' + c.id + ' ' + e.code); continue; }
		const hits = r.findings.filter(f => f.group === 'leak' && RANK[f.severity] >= RANK[threshold]);
		const overlap = r.overlap ? r.overlap.share + '%' : '-';
		if (c.label === 'leak') {
			m.leakPos++;
			if (hits.length) { m.leakHit++; }
			rows.push((hits.length ? 'hit  ' : 'MISS ') + 'leak ' + c.id + (c.kind ? ' (' + c.kind + ')' : '') + ' [' + hits.map(f => f.rule).join(' ') + '] overlap ' + overlap);
		} else {
			m.leakNeg++;
			if (hits.length) { m.leakFp++; }
			rows.push((hits.length ? 'FP   ' : 'ok   ') + 'leak ' + c.id + ' [' + hits.map(f => f.rule).join(' ') + '] overlap ' + overlap);
		}
	}
	console.log((independent ? 'INDEPENDENT' : 'NOT INDEPENDENT (' + (set.provenance || 'no provenance') + ')') + ' — ' + path.basename(file) + ' — threshold ' + threshold);
	console.log('  prompt audit: detected ' + m.auditHit + '/' + m.auditPos + ' (' + pct(m.auditHit, m.auditPos) + '); false positives ' + m.auditFp + '/' + m.auditNeg + ' (' + pct(m.auditFp, m.auditNeg) + ')');
	console.log('  leak check:   detected ' + m.leakHit + '/' + m.leakPos + ' (' + pct(m.leakHit, m.leakPos) + '); false positives ' + m.leakFp + '/' + m.leakNeg + ' (' + pct(m.leakFp, m.leakNeg) + ')' + (m.errors ? '; errors ' + m.errors : ''));
	if (details) { for (const r of rows) { console.log('    ' + r); } }
	return Object.assign({ independent, threshold }, m);
}
if (require.main === module) {
	const file = process.argv.slice(2).find(a => !a.startsWith('--'));
	if (!file) { console.error('Usage: node tests/leak-inspector-independent.cjs <set.json> [--details]'); process.exit(64); }
	evaluate(file, process.argv.includes('--details'));
}
module.exports = { evaluate };
