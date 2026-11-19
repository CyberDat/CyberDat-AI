/*
 * Independent acceptance runner for the Email Header Analyzer (local, offline).
 *   node tests/email-header-analyzer-independent.cjs <private-set.json> [--details]
 * Format and instructions: deploy/tools-utilities-1/independent/email-header-analyzer/. Keep real sets OUTSIDE the repository.
 * cases[]: id, source (gmail, outlook, spam, ...), text (headers with addresses replaced), optional own (your domains),
 * optional now (ISO time of the analysis, default: the time of the last Received line plus one hour), and either
 * expect (exact list of finding ids) or include/exclude (ids that must / must not appear); ignoreInfo: true compares
 * only findings above info. Optional dmarc (expected trusted DMARC result) and external (first external server).
 * Results are labelled INDEPENDENT only when "provenance" is "independent" or "owner" and "authoredByToolAuthor" is false.
 * Output contains case ids, finding ids and counts only, never header text. Nothing is sent anywhere.
 */
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/email-header-analyzer/engine.js'));
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + '%' : 'n/a');
function evaluate(file, details) {
	const raw = fs.readFileSync(file);
	const set = JSON.parse(raw.toString('utf8'));
	if (set.tool !== 'email-header-analyzer') { throw new Error('"tool" must be "email-header-analyzer"'); }
	const independent = ['independent', 'owner'].includes(set.provenance) && set.authoredByToolAuthor === false;
	const m = { msgs: 0, ok: 0, tp: 0, fp: 0, fn: 0, checks: 0, checksOk: 0, errors: 0, highOnBenign: 0, benign: 0 };
	const rows = [];
	for (const c of set.cases || []) {
		if (typeof c.text !== 'string') { m.errors++; rows.push('ERROR ' + c.id + ' text'); continue; }
		let r;
		try {
			let now = c.now;
			if (!now) { const first = engine.analyze(c.text, { own: c.own || '' }); const t = first.path.hops.map(h => h.time).filter(x => x !== null); now = new Date((t.length ? Math.max(...t) : Date.now()) + 3600000).toISOString(); }
			r = engine.analyze(c.text, { own: c.own || '', now });
		} catch (e) { m.errors++; rows.push('ERROR ' + c.id + ' ' + (e.code || 'exception')); continue; }
		m.msgs++;
		const all = [...new Set(r.findings.filter(f => !c.ignoreInfo || f.severity !== 'info').map(f => f.id))].sort();
		const out = [];
		if (Array.isArray(c.expect)) {
			const exp = new Set(c.expect.filter(x => !c.ignoreInfo || !engine.DEF[x] || engine.DEF[x][0] !== 'info'));
			const extra = all.filter(x => !exp.has(x)), missed = [...exp].filter(x => !all.includes(x));
			m.tp += all.length - extra.length; m.fp += extra.length; m.fn += missed.length;
			if (missed.length) { out.push('missed ' + missed.join(',')); }
			if (extra.length) { out.push('extra ' + extra.join(',')); }
		} else {
			for (const x of c.include || []) { if (all.includes(x)) { m.tp++; } else { m.fn++; out.push('missed ' + x); } }
			for (const x of c.exclude || []) { if (all.includes(x)) { m.fp++; out.push('unwanted ' + x); } }
		}
		if (c.dmarc !== undefined) { m.checks++; const d = r.auth.effective.dmarc; if (d && d.result === c.dmarc) { m.checksOk++; } else { out.push('dmarc ' + (d ? d.result : 'none')); } }
		if (c.external !== undefined) { m.checks++; const x = r.path.external && r.path.external.label; if (x === c.external) { m.checksOk++; } else { out.push('external differs'); } }
		if (c.benign) { m.benign++; if (r.counts.high) { m.highOnBenign++; out.push('high finding on a benign message'); } }
		if (!out.length) { m.ok++; }
		rows.push((out.length ? 'DIFF  ' : 'ok    ') + c.id + (c.source ? ' [' + c.source + ']' : '') + ' — ' + r.path.hops.length + ' Received, ' + r.path.hops.filter(h => !h.parsed).length + ' unparsed' + (out.length ? ' — ' + out.join('; ') : ''));
	}
	console.log((independent ? 'INDEPENDENT' : 'NOT INDEPENDENT (' + (set.provenance || 'no provenance') + ')') + ' — ' + path.basename(file) + ' — sha256 ' + crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16) + '… — engine ' + engine.ENGINE + ', rules ' + engine.RULESET);
	console.log('  messages as expected ' + m.ok + '/' + m.msgs + ' (' + pct(m.ok, m.msgs) + '); expected findings found ' + pct(m.tp, m.tp + m.fn) + ' (' + m.tp + '/' + (m.tp + m.fn) + '), extra or unwanted ' + m.fp + '; DMARC/boundary checks ' + m.checksOk + '/' + m.checks + '; benign messages with a high finding ' + m.highOnBenign + '/' + m.benign + (m.errors ? '; errors ' + m.errors : ''));
	if (details) { for (const x of rows) { console.log('    ' + x); } }
	return Object.assign({ independent }, m);
}
if (require.main === module) {
	const file = process.argv.slice(2).find(a => !a.startsWith('--'));
	if (!file) { console.error('Usage: node tests/email-header-analyzer-independent.cjs <set.json> [--details]'); process.exit(64); }
	evaluate(file, process.argv.includes('--details'));
}
module.exports = { evaluate };
