/*
 * Independent acceptance runner for the YARA/Sigma Rule Validator & Converter (local, offline).
 *   node tests/yara-sigma-validator-independent.cjs <private-set.json> [--details]
 * Format: deploy/tools-release-1.3/yara-sigma-validator/independent/template.json. Keep real sets OUTSIDE the repository.
 * Case kinds: "sigma" / "yara" with expect = exact list of finding ids (see the rules catalogue),
 * or "convert" with expect = {spl|kql|lucene: expected query string, or {error: text the error must mention}} and an optional fieldmap per target.
 * Results are labelled INDEPENDENT only when "provenance" is "independent" or "owner" and "authoredByToolAuthor" is false.
 * Output contains case ids, finding ids and counts only, never rule text or queries. Nothing is sent anywhere.
 */
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/yara-sigma-validator/engine.js'));
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + '%' : 'n/a');
function evaluate(file, details) {
	const raw = fs.readFileSync(file);
	const set = JSON.parse(raw.toString('utf8'));
	if (set.tool !== 'yara-sigma-validator') { throw new Error('"tool" must be "yara-sigma-validator"'); }
	const independent = ['independent', 'owner'].includes(set.provenance) && set.authoredByToolAuthor === false;
	const m = { rules: 0, exact: 0, tp: 0, fp: 0, fn: 0, conv: 0, convOk: 0, errors: 0 };
	const rows = [];
	for (const c of set.cases || []) {
		if (typeof c.text !== 'string' || !['sigma', 'yara', 'convert'].includes(c.kind)) { m.errors++; rows.push('ERROR ' + c.id + ' kind or text'); continue; }
		if (c.kind === 'convert') {
			for (const [target, want] of Object.entries(c.expect || {})) {
				m.conv++;
				let got;
				try { const r = engine.convert(c.text, target, (c.fieldmap || {})[target]); got = r.rules[0].error ? { error: r.rules[0].error } : r.rules[0].queries[0]; } catch (e) { got = { error: e.message }; }
				const ok = typeof want === 'string' ? got === want : !!(got && got.error && want && got.error.includes(want.error));
				if (ok) { m.convOk++; }
				rows.push((ok ? 'ok    ' : 'DIFF  ') + c.id + ' ' + target + (ok ? '' : (got && got.error ? ' (error returned)' : ' (different query)')));
			}
			continue;
		}
		m.rules++;
		let ids;
		try { ids = [...new Set(engine.validate(c.text, { kind: c.kind }).findings.map(f => f.id).filter(id => id !== 'SEC-001'))].sort(); } catch (e) { m.errors++; rows.push('ERROR ' + c.id + ' ' + (e.code || 'exception')); continue; }
		const exp = new Set(c.expect || []);
		const extra = ids.filter(x => !exp.has(x));
		const missed = [...exp].filter(x => !ids.includes(x));
		m.tp += ids.length - extra.length; m.fp += extra.length; m.fn += missed.length;
		if (!extra.length && !missed.length) { m.exact++; }
		rows.push((extra.length || missed.length ? 'DIFF  ' : 'ok    ') + c.id + (missed.length ? ' missed ' + missed.join(',') : '') + (extra.length ? ' extra ' + extra.join(',') : ''));
	}
	console.log((independent ? 'INDEPENDENT' : 'NOT INDEPENDENT (' + (set.provenance || 'no provenance') + ')') + ' — ' + path.basename(file) + ' — sha256 ' + crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16) + '… — engine ' + engine.ENGINE + ', rules ' + engine.RULESET);
	console.log('  rules fully correct ' + m.exact + '/' + m.rules + ' (' + pct(m.exact, m.rules) + '); finding recall ' + pct(m.tp, m.tp + m.fn) + ', extra findings ' + m.fp + '; conversions as expected ' + m.convOk + '/' + m.conv + (m.errors ? '; errors ' + m.errors : ''));
	if (details) { for (const r of rows) { console.log('    ' + r); } }
	return Object.assign({ independent }, m);
}
if (require.main === module) {
	const file = process.argv.slice(2).find(a => !a.startsWith('--'));
	if (!file) { console.error('Usage: node tests/yara-sigma-validator-independent.cjs <set.json> [--details]'); process.exit(64); }
	evaluate(file, process.argv.includes('--details'));
}
module.exports = { evaluate };
