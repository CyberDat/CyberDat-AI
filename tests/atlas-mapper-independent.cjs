/*
 * Independent acceptance runner for the MITRE ATLAS Attack Vector Mapper (local, offline).
 *   node tests/atlas-mapper-independent.cjs <private-set.json> [--details]
 * Format: deploy/tools-release-1.2/independent/mitre-atlas-mapper/template.json. Keep real sets OUTSIDE the repository.
 * Results are labelled INDEPENDENT only when "provenance" is "independent" or "owner" and "authoredByToolAuthor" is false.
 * Output contains case ids, technique ids and counts only, never sample text. Nothing is sent anywhere.
 */
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { fill } = require('./lib/synthetic-secrets.cjs');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/atlas-mapper/engine.js'));
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + '%' : 'n/a');

function evaluate(file, details) {
	const raw = fs.readFileSync(file);
	const set = JSON.parse(raw.toString('utf8'));
	if (set.tool !== 'mitre-atlas-mapper') { throw new Error('"tool" must be "mitre-atlas-mapper"'); }
	const independent = ['independent', 'owner'].includes(set.provenance) && set.authoredByToolAuthor === false;
	const known = new Set(engine.DATA.techniques.map(t => t.id));
	const m = { findings: 0, hit: 0, exact: 0, tp: 0, fn: 0, fp: 0, benign: 0, benignClean: 0, profiles: 0, profileTp: 0, profileFn: 0, unknownIds: 0, errors: 0 };
	const rows = [];
	for (const c of set.cases || []) {
		const ids = [].concat(c.expect || [], c.allow || []);
		m.unknownIds += ids.filter(id => !known.has(id)).length;
		let got;
		try { got = (c.mode === 'profile' ? engine.profile(c.properties || []) : engine.mapFinding(fill(c.text))).techniques.map(t => t.id); } catch (e) { m.errors++; rows.push('ERROR ' + c.id + ' ' + (e.code || '')); continue; }
		const exp = c.expect || [], allow = new Set(c.allow || []);
		const fn = exp.filter(x => !got.includes(x));
		const fp = got.filter(x => !exp.includes(x) && !allow.has(x));
		if (c.mode === 'profile') { m.profiles++; m.profileTp += exp.length - fn.length; m.profileFn += fn.length; rows.push((fn.length ? 'MISS  ' : 'ok    ') + c.id + ' missing [' + fn.join(' ') + ']'); continue; }
		m.tp += exp.length - fn.length; m.fn += fn.length; m.fp += fp.length;
		if (!exp.length) { m.benign++; if (!got.length) { m.benignClean++; } } else { m.findings++; if (!fn.length) { m.hit++; } if (!fn.length && !fp.length) { m.exact++; } }
		rows.push((fn.length || fp.length ? 'DIFF  ' : 'ok    ') + c.id + ' missed [' + fn.join(' ') + '] extra [' + fp.join(' ') + ']');
	}
	console.log((independent ? 'INDEPENDENT' : 'NOT INDEPENDENT (' + (set.provenance || 'no provenance') + ')') + ' — ' + path.basename(file) + ' — sha256 ' + crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16) + '… — mapping ' + engine.RULESET + ', ATLAS ' + engine.DATA.meta.release);
	console.log('  findings with all expected techniques ' + m.hit + '/' + m.findings + ' (' + pct(m.hit, m.findings) + '), exact ' + m.exact + '; technique recall ' + pct(m.tp, m.tp + m.fn) + '; extra techniques ' + m.fp + '; benign without candidates ' + m.benignClean + '/' + m.benign + '; profile recall ' + pct(m.profileTp, m.profileTp + m.profileFn) + (m.unknownIds ? '; ids not in ATLAS ' + m.unknownIds : '') + (m.errors ? '; errors ' + m.errors : ''));
	if (details) { for (const r of rows) { console.log('    ' + r); } }
	return Object.assign({ independent }, m);
}
if (require.main === module) {
	const file = process.argv.slice(2).find(a => !a.startsWith('--'));
	if (!file) { console.error('Usage: node tests/atlas-mapper-independent.cjs <set.json> [--details]'); process.exit(64); }
	evaluate(file, process.argv.includes('--details'));
}
module.exports = { evaluate };
