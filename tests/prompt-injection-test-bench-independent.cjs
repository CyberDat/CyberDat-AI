/*
 * Independent acceptance runner for the LLM Prompt Injection Test Bench canary check (local, offline).
 *   node tests/prompt-injection-test-bench-independent.cjs <private-set.json> [--details]
 * Format: deploy/tools-release-1.3/prompt-injection-test-bench/independent/template.json. Keep real sets OUTSIDE the repository.
 * Results are labelled INDEPENDENT only when "provenance" is "independent" or "owner" and "authoredByToolAuthor" is false.
 * Output contains case ids and counts only, never response text. Nothing is sent anywhere.
 */
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/prompt-injection-test-bench/engine.js'));
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + '%' : 'n/a');
function evaluate(file, details) {
	const raw = fs.readFileSync(file);
	const set = JSON.parse(raw.toString('utf8'));
	if (set.tool !== 'prompt-injection-test-bench') { throw new Error('"tool" must be "prompt-injection-test-bench"'); }
	const independent = ['independent', 'owner'].includes(set.provenance) && set.authoredByToolAuthor === false;
	const m = { pos: 0, hit: 0, neg: 0, fp: 0, errors: 0 };
	const rows = [];
	for (const c of set.cases || []) {
		if (!/^(?:CANARY|LABEL)-[0-9A-F]{8}$/u.test(String(c.canary))) { m.errors++; rows.push('ERROR ' + c.id + ' canary format'); continue; }
		const r = engine.detect(String(c.response || ''), c.canary);
		if (c.triggered) { m.pos++; if (r) { m.hit++; } rows.push((r ? 'hit   ' : 'MISS  ') + c.id + (r ? ' ' + r.method : '')); }
		else { m.neg++; if (r) { m.fp++; } rows.push((r ? 'FP    ' : 'ok    ') + c.id + (r ? ' ' + r.method : '')); }
	}
	console.log((independent ? 'INDEPENDENT' : 'NOT INDEPENDENT (' + (set.provenance || 'no provenance') + ')') + ' — ' + path.basename(file) + ' — sha256 ' + crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16) + '… — engine ' + engine.ENGINE);
	console.log('  canaries found ' + m.hit + '/' + m.pos + ' (' + pct(m.hit, m.pos) + '); false hits ' + m.fp + '/' + m.neg + (m.errors ? '; errors ' + m.errors : ''));
	if (details) { for (const r of rows) { console.log('    ' + r); } }
	return Object.assign({ independent }, m);
}
if (require.main === module) {
	const file = process.argv.slice(2).find(a => !a.startsWith('--'));
	if (!file) { console.error('Usage: node tests/prompt-injection-test-bench-independent.cjs <set.json> [--details]'); process.exit(64); }
	evaluate(file, process.argv.includes('--details'));
}
module.exports = { evaluate };
