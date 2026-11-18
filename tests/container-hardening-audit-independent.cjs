/*
 * Independent acceptance runner for the Docker & Kubernetes Hardening Audit Generator (local, offline).
 *   node tests/container-hardening-audit-independent.cjs <private-set.json> [--details]
 * Format: deploy/tools-release-1.3/container-hardening-audit/independent/template.json. Keep real sets OUTSIDE the repository.
 * cases[]: id, name (file name, e.g. Dockerfile or deploy.yaml), text, expect (exact list of finding ids from rules.json),
 * or error (expected input error code such as INPUT-HELM). Optional mustNotShow: strings that must not appear in findings or reports.
 * Results are labelled INDEPENDENT only when "provenance" is "independent" or "owner" and "authoredByToolAuthor" is false.
 * Output contains case ids, finding ids and counts only, never file text. Nothing is sent anywhere.
 */
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/container-hardening-audit/engine.js'));
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + '%' : 'n/a');
function evaluate(file, details) {
	const raw = fs.readFileSync(file);
	const set = JSON.parse(raw.toString('utf8'));
	if (set.tool !== 'container-hardening-audit') { throw new Error('"tool" must be "container-hardening-audit"'); }
	const independent = ['independent', 'owner'].includes(set.provenance) && set.authoredByToolAuthor === false;
	const m = { files: 0, exact: 0, tp: 0, fp: 0, fn: 0, inputErrors: 0, inputErrorsOk: 0, masked: 0, maskedOk: 0, errors: 0 };
	const rows = [];
	for (const c of set.cases || []) {
		if (typeof c.text !== 'string') { m.errors++; rows.push('ERROR ' + c.id + ' text'); continue; }
		let r;
		try { r = engine.audit(c.text, { name: c.name }); } catch (e) { m.errors++; rows.push('ERROR ' + c.id + ' ' + (e.code || 'exception')); continue; }
		if (c.error) { m.inputErrors++; const ok = !!(r.error && r.error.code === c.error); if (ok) { m.inputErrorsOk++; } rows.push((ok ? 'ok    ' : 'DIFF  ') + c.id + ' error ' + (r.error ? r.error.code : 'none')); continue; }
		m.files++;
		const ids = r.error ? [] : [...new Set(r.findings.map(f => f.id))].sort();
		const exp = new Set(c.expect || []);
		const extra = ids.filter(x => !exp.has(x));
		const missed = [...exp].filter(x => !ids.includes(x));
		m.tp += ids.length - extra.length; m.fp += extra.length; m.fn += missed.length;
		if (!extra.length && !missed.length && !r.error) { m.exact++; }
		rows.push((extra.length || missed.length || r.error ? 'DIFF  ' : 'ok    ') + c.id + (r.error ? ' input error ' + r.error.code : '') + (missed.length ? ' missed ' + missed.join(',') : '') + (extra.length ? ' extra ' + extra.join(',') : ''));
		if (Array.isArray(c.mustNotShow) && c.mustNotShow.length) {
			const rep = engine.exportReport(engine.auditFiles([{ name: c.name, text: c.text }]), {});
			for (const s of c.mustNotShow) { m.masked++; if (!JSON.stringify(r.findings).includes(s) && !rep.json.includes(s) && !rep.markdown.includes(s)) { m.maskedOk++; } else { rows.push('LEAK  ' + c.id + ' a mustNotShow value appears in the output'); } }
		}
	}
	console.log((independent ? 'INDEPENDENT' : 'NOT INDEPENDENT (' + (set.provenance || 'no provenance') + ')') + ' — ' + path.basename(file) + ' — sha256 ' + crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16) + '… — engine ' + engine.ENGINE + ', rules ' + engine.RULESET);
	console.log('  files fully correct ' + m.exact + '/' + m.files + ' (' + pct(m.exact, m.files) + '); finding recall ' + pct(m.tp, m.tp + m.fn) + ', extra findings ' + m.fp + '; input errors ' + m.inputErrorsOk + '/' + m.inputErrors + '; masked ' + m.maskedOk + '/' + m.masked + (m.errors ? '; errors ' + m.errors : ''));
	if (details) { for (const x of rows) { console.log('    ' + x); } }
	return Object.assign({ independent }, m);
}
if (require.main === module) {
	const file = process.argv.slice(2).find(a => !a.startsWith('--'));
	if (!file) { console.error('Usage: node tests/container-hardening-audit-independent.cjs <set.json> [--details]'); process.exit(64); }
	evaluate(file, process.argv.includes('--details'));
}
module.exports = { evaluate };
