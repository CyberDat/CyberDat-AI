/*
 * Email Header Analyzer: metrics on the frozen corpus and the held-out set.
 * Exact finding sets per message, plus path (Received count, unparsed lines, first external server), trusted DMARC,
 * decoded names and subjects, and that the message body never appears in results or exports.
 * NOT INDEPENDENT: corpus, held-out set and rules are written by the same author.
 *   node tests/email-header-analyzer-corpus.test.cjs [--verbose] [--no-guard]
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/email-header-analyzer/engine.js'));
const FIX = path.join(__dirname, 'fixtures/email-header-analyzer');
const load = f => JSON.parse(fs.readFileSync(path.join(FIX, f), 'utf8')).cases;
function evaluate(cases) {
	const m = { msgs: 0, exact: 0, tp: 0, fp: 0, fn: 0, details: 0, detailsOk: 0, body: 0, bodyOk: 0, mismatches: [] };
	const detail = (c, label, ok, got) => { m.details++; if (ok) { m.detailsOk++; } else { m.mismatches.push(c.id + ': ' + label + ' got ' + JSON.stringify(got)); } };
	for (const c of cases) {
		m.msgs++;
		let r;
		try { r = engine.analyze(c.text, Object.assign({ now: c.now }, c.opts || {})); } catch (e) { m.fn += c.expect.length; m.mismatches.push(c.id + ': error ' + e.message); continue; }
		const ids = [...new Set(r.findings.map(f => f.id))].sort();
		const exp = new Set(c.expect);
		for (const id of ids) { if (exp.has(id)) { m.tp++; } else { m.fp++; } }
		for (const id of exp) { if (!ids.includes(id)) { m.fn++; } }
		if (ids.length === c.expect.length && ids.every(x => exp.has(x))) { m.exact++; } else { m.mismatches.push(c.id + ': expected ' + (c.expect.join(' ') || 'nothing') + ' | got ' + (ids.join(' ') || 'nothing')); }
		if (c.hops !== undefined) { detail(c, 'hops ' + c.hops, r.path.hops.length === c.hops, r.path.hops.length); }
		if (c.unparsed !== undefined) { const u = r.path.hops.filter(h => !h.parsed).length; detail(c, 'unparsed ' + c.unparsed, u === c.unparsed, u); }
		if (c.external !== undefined) { const x = r.path.external && r.path.external.label; detail(c, 'external ' + c.external, x === c.external, x); }
		if (c.auth) { const d = r.auth.effective.dmarc; detail(c, 'dmarc ' + JSON.stringify(c.auth), !!d && d.result === c.auth.dmarc && d.trusted === c.auth.trusted, d && { result: d.result, trusted: d.trusted }); }
		if (c.fromName !== undefined) { const n = r.summary.from && r.summary.from.name; detail(c, 'fromName ' + c.fromName, n === c.fromName, n); }
		if (c.subject !== undefined) { detail(c, 'subject ' + c.subject, r.summary.subject === c.subject, r.summary.subject); }
		const rep = engine.exportReport(r, { timestamp: '2026-11-19T00:00:00Z' });
		const blob = JSON.stringify(r) + rep.json + rep.markdown;
		for (const s of (c.mustNotShow || []).concat(['BODY-MARKER-7Q'])) {
			if (!c.text.includes(s)) { continue; }
			m.body++;
			if (!blob.includes(s)) { m.bodyOk++; } else { m.mismatches.push(c.id + ': body text “' + s + '” appears in the output'); }
		}
	}
	return m;
}
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) : '—') + '%';
const report = (name, m) => { console.log(name + ' (NOT INDEPENDENT): messages fully correct ' + m.exact + '/' + m.msgs + ' (' + pct(m.exact, m.msgs) + '); finding recall ' + pct(m.tp, m.tp + m.fn) + ' (' + m.tp + '/' + (m.tp + m.fn) + '), extra findings ' + m.fp + '; path/auth/decoding details ' + m.detailsOk + '/' + m.details + '; body never shown ' + m.bodyOk + '/' + m.body); if (process.argv.includes('--verbose')) { for (const x of m.mismatches) { console.log('    ' + x); } } };
const main = evaluate(load('corpus.json'));
const hold = evaluate(load('holdout.json'));
report('main corpus', main);
report('held-out set', hold);
if (require.main === module && !process.argv.includes('--no-guard')) {
	const bad = [main, hold].filter(x => x.mismatches.length);
	if (bad.length) { console.error('FAIL: ' + bad.reduce((n, x) => n + x.mismatches.length, 0) + ' mismatches (run with --verbose)'); process.exit(1); }
	console.log('PASS: corpus and held-out set match exactly');
}
module.exports = { evaluate };
