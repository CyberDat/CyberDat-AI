/*
 * Docker & Kubernetes Hardening Audit Generator: metrics on the frozen corpus and the held-out set.
 * Exact finding sets per file, plus line, document and container checks, input errors and secret masking.
 * NOT INDEPENDENT: corpus, held-out set and rules are written by the same author.
 *   node tests/container-hardening-audit-corpus.test.cjs [--verbose] [--no-guard]
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { SYNTH } = require('./lib/synthetic-secrets.cjs');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/container-hardening-audit/engine.js'));
const FIX = path.join(__dirname, 'fixtures/container-hardening-audit');
const synth = s => String(s).replace(/@@SYNTH:([A-Z0-9_]+)@@/gu, (m, k) => { if (!SYNTH[k]) { throw new Error('unknown synthetic value ' + k); } return SYNTH[k]; });
const load = f => JSON.parse(fs.readFileSync(path.join(FIX, f), 'utf8')).cases;
function evaluate(cases) {
	const m = { files: 0, exact: 0, tp: 0, fp: 0, fn: 0, errorsOk: 0, errors: 0, details: 0, detailsOk: 0, masked: 0, maskedOk: 0, mismatches: [] };
	for (const c of cases) {
		const text = synth(c.text);
		const r = engine.audit(text, { name: c.name });
		const rep = engine.exportReport(engine.auditFiles([{ name: c.name, text }]), { timestamp: '2026-11-18T00:00:00Z' });
		if (c.error) {
			m.errors++;
			const ok = r.error && r.error.code === c.error && (!c.errorLine || r.error.line === c.errorLine);
			if (ok) { m.errorsOk++; } else { m.mismatches.push(c.id + ': expected error ' + c.error + (c.errorLine ? ' line ' + c.errorLine : '') + ' got ' + JSON.stringify(r.error)); }
			continue;
		}
		m.files++;
		if (r.error) { m.fn += c.expect.length; m.mismatches.push(c.id + ': unexpected error ' + JSON.stringify(r.error)); continue; }
		const ids = [...new Set(r.findings.map(f => f.id))].sort();
		const exp = new Set(c.expect);
		for (const id of ids) { if (exp.has(id)) { m.tp++; } else { m.fp++; } }
		for (const id of exp) { if (!ids.includes(id)) { m.fn++; } }
		if (ids.length === c.expect.length && ids.every(x => exp.has(x))) { m.exact++; } else { m.mismatches.push(c.id + ': expected ' + (c.expect.join(' ') || 'nothing') + ' | got ' + (ids.join(' ') || 'nothing')); }
		for (const [field, key] of [['lines', 'line'], ['documents', 'document'], ['containers', 'container']]) {
			for (const [id, want] of Object.entries(c[field] || {})) {
				m.details++;
				const got = r.findings.filter(f => f.id === id).map(f => f[key]);
				if (got.includes(want)) { m.detailsOk++; } else { m.mismatches.push(c.id + ': ' + id + ' ' + key + ' expected ' + want + ' got ' + JSON.stringify(got)); }
			}
		}
		for (const s of c.mustNotShow || []) {
			m.masked++;
			const v = synth(s);
			if (!JSON.stringify(r.findings).includes(v) && !rep.json.includes(v) && !rep.markdown.includes(v)) { m.maskedOk++; } else { m.mismatches.push(c.id + ': value shown unmasked'); }
		}
	}
	return m;
}
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) : '—') + '%';
const report = (name, m) => { console.log(name + ' (NOT INDEPENDENT): files fully correct ' + m.exact + '/' + m.files + ' (' + pct(m.exact, m.files) + '); finding recall ' + pct(m.tp, m.tp + m.fn) + ' (' + m.tp + '/' + (m.tp + m.fn) + '), extra findings ' + m.fp + '; line/document/container ' + m.detailsOk + '/' + m.details + '; input errors ' + m.errorsOk + '/' + m.errors + '; secrets masked ' + m.maskedOk + '/' + m.masked); if (process.argv.includes('--verbose')) { for (const x of m.mismatches) { console.log('    ' + x); } } };
const main = evaluate(load('corpus.json'));
const hold = evaluate(load('holdout.json'));
report('main corpus', main);
report('held-out set', hold);
if (require.main === module && !process.argv.includes('--no-guard')) {
	const bad = [main, hold].filter(m => m.mismatches.length);
	if (bad.length) { console.error('FAIL: ' + bad.reduce((n, m) => n + m.mismatches.length, 0) + ' mismatches (run with --verbose)'); process.exit(1); }
	console.log('PASS: corpus and held-out set match exactly');
}
module.exports = { evaluate };
