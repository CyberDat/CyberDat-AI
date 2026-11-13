/*
 * Independent evaluation runner for the four CyberDat tools (local, offline).
 *
 *   node tests/independent-eval/evaluate.cjs <set.json> [<set.json> ...] [--details]
 *
 * A set is a labelled JSON file (formats: tests/independent-eval/templates/*.json). Results are labelled
 * INDEPENDENT only when the file says "provenance": "owner" and "authoredByToolAuthor": false; everything else is
 * printed as NOT INDEPENDENT. Output never prints sample text, only ids, labels and counts, so real data stays
 * on the owner's machine. Nothing is sent anywhere.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const THEME = path.join(__dirname, '../../wp-content/themes/cyberdat/assets/js');
const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };
const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + '%' : 'n/a');

const TOOLS = {
	'log-anonymizer': {
		engine: () => require(path.join(THEME, 'log-anonymizer/engine.js')),
		// Detection: every mustMask value is gone from the output. False positive: a mustKeep value changed.
		run(engine, s) {
			const out = engine.anonymize(String(s.text), {}).output;
			const leaked = (s.mustMask || []).filter(v => out.includes(v));
			const lost = (s.mustKeep || []).filter(v => !out.includes(v));
			return { positive: (s.mustMask || []).length > 0, detected: leaked.length === 0, falsePositive: lost.length > 0, detail: 'leaked ' + leaked.length + '/' + (s.mustMask || []).length + ', changed context ' + lost.length + '/' + (s.mustKeep || []).length };
		}
	},
	'prompt-injection-detector': {
		engine: () => require(path.join(THEME, 'prompt-injection-detector/engine.js')),
		run(engine, s, threshold) {
			const level = engine.analyze(String(s.text), {}).level;
			const hit = RANK[level] >= RANK[threshold];
			return { positive: s.label === 'attack', detected: s.label === 'attack' && hit, falsePositive: s.label === 'benign' && hit, detail: 'level ' + level };
		}
	},
	'lotl-command-analyzer': {
		engine: () => require(path.join(THEME, 'lotl-analyzer/engine.js')),
		run(engine, s, threshold) {
			const r = engine.analyze(String(s.cmd));
			const level = r.commands.reduce((m, c) => (RANK[c.severity] > RANK[m] ? c.severity : m), 'none');
			const hit = RANK[level] >= RANK[threshold];
			return { positive: s.label === 'malicious', detected: s.label === 'malicious' && hit, falsePositive: s.label === 'benign' && hit, detail: 'level ' + level };
		}
	},
	'mcp-security-checker': {
		engine: () => require(path.join(THEME, 'mcp-checker/engine.js')),
		run(engine, s, threshold) {
			const text = typeof s.config === 'string' ? s.config : JSON.stringify(s.config);
			const r = engine.analyze(text);
			const hits = r.findings.filter(f => RANK[f.severity] >= RANK[threshold]);
			const groupsOk = !(s.expectGroups || []).length || s.expectGroups.every(g => hits.some(f => f.group === g));
			return { positive: s.label === 'risky', detected: s.label === 'risky' && hits.length > 0 && groupsOk, falsePositive: s.label === 'benign' && hits.length > 0, detail: 'level ' + r.level + (hits.length ? ', ' + [...new Set(hits.map(f => f.rule))].join(' ') : '') };
		}
	}
};

function evaluateFile(file, details) {
	const set = JSON.parse(fs.readFileSync(file, 'utf8'));
	const tool = TOOLS[set.tool];
	if (!tool) { throw new Error(file + ': unknown "tool" (expected one of ' + Object.keys(TOOLS).join(', ') + ')'); }
	if (!Array.isArray(set.samples) || !set.samples.length) { throw new Error(file + ': "samples" must be a non-empty list'); }
	const independent = set.provenance === 'owner' && set.authoredByToolAuthor === false;
	const threshold = set.threshold || 'medium';
	const engine = tool.engine();
	let pos = 0, neg = 0, det = 0, fp = 0;
	const rows = [];
	for (const s of set.samples) {
		if (!s.id) { throw new Error(file + ': every sample needs an "id"'); }
		let r;
		try { r = tool.run(engine, s, threshold); } catch (e) { r = { positive: true, detected: false, falsePositive: false, detail: 'ERROR ' + (e.code || '') + ' ' + String(e.message).slice(0, 80) }; }
		if (r.positive) { pos++; if (r.detected) { det++; } }
		const isNegative = set.tool === 'log-anonymizer' ? (s.mustKeep || []).length > 0 : !r.positive;
		if (isNegative) { neg++; if (r.falsePositive) { fp++; } }
		rows.push((r.positive ? (r.detected ? 'hit ' : 'MISS') : (r.falsePositive ? 'FP  ' : 'ok  ')) + ' ' + s.id + ' — ' + r.detail);
	}
	console.log('\n' + (independent ? 'INDEPENDENT (owner data)' : 'NOT INDEPENDENT (' + (set.provenance || 'no provenance') + ')') + ' — ' + set.tool + ' — ' + path.basename(file));
	console.log('  threshold: ' + threshold + '; samples: ' + set.samples.length);
	console.log('  detection: ' + det + '/' + pos + ' (' + pct(det, pos) + ')');
	console.log('  false positives: ' + fp + '/' + neg + ' (' + pct(fp, neg) + ')');
	if (details) { for (const r of rows) { console.log('    ' + r); } }
	return { file: path.basename(file), tool: set.tool, independent, threshold, samples: set.samples.length, positives: pos, detected: det, negatives: neg, falsePositives: fp };
}

if (require.main === module) {
	const files = process.argv.slice(2).filter(a => !a.startsWith('--'));
	if (!files.length) { console.error('Usage: node tests/independent-eval/evaluate.cjs <set.json> [...] [--details]'); process.exit(64); }
	const out = files.map(f => evaluateFile(f, process.argv.includes('--details')));
	if (!out.every(o => o.independent)) { console.log('\nNote: at least one set is NOT INDEPENDENT; do not report its numbers as an independent evaluation.'); }
}
module.exports = { evaluateFile };
