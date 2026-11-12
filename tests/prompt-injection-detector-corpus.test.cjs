/*
 * Detection and false-positive measurement on the synthetic corpus.
 * Pure Node.js, no network. Run: node tests/prompt-injection-detector-corpus.test.cjs [metrics.json]
 *
 * Detection: a case counts as detected when at least one finding of its own group is reported
 * (any severity); "detected at medium+" requires severity medium or high in that group.
 * False positive: a benign sample with at least one finding (any group, any severity);
 * "medium+" counts only medium/high findings. Numbers are printed as they are; the
 * assertions below only guard against regressions.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/prompt-injection-detector/engine.js'));
const { fill } = require('./lib/synthetic-secrets.cjs');

const FIX = path.join(__dirname, 'fixtures/prompt-injection-detector');

// ---------------------------------------------------------------- transforms
const bytes = s => Buffer.from(s, 'utf8');
const HOMO = { a: 'а', e: 'е', o: 'о', p: 'р', c: 'с', i: 'і', x: 'х', y: 'у', s: 'ѕ' };
const LEET = { o: '0', i: '1', e: '3', a: '4', s: '5', t: '7' };
const T = {
	b64: s => bytes(s).toString('base64'),
	b64url: s => bytes(s).toString('base64url'),
	hex: s => bytes(s).toString('hex'),
	hexesc: s => Array.from(bytes(s), b => '\\x' + b.toString(16).padStart(2, '0')).join(''),
	url: s => Array.from(bytes(s), b => '%' + b.toString(16).toUpperCase().padStart(2, '0')).join(''),
	entities: s => Array.from(s, c => '&#' + c.codePointAt(0) + ';').join(''),
	uesc: s => Array.from(s, c => '\\u' + c.codePointAt(0).toString(16).padStart(4, '0')).join(''),
	tags: s => Array.from(s, c => String.fromCodePoint(0xE0000 + c.charCodeAt(0))).join(''),
	vs: s => Array.from(bytes(s), b => String.fromCodePoint(b < 16 ? 0xFE00 + b : 0xE0100 + b - 16)).join(''),
	zw: s => Array.from(s).join('​'),
	zwbits: s => Array.from(bytes(s), b => b.toString(2).padStart(8, '0').replace(/0/g, '​').replace(/1/g, '‌')).join(''),
	fullwidth: s => Array.from(s, c => c === ' ' ? '　' : (c >= '!' && c <= '~' ? String.fromCharCode(c.charCodeAt(0) + 0xFEE0) : c)).join(''),
	mathbold: s => Array.from(s, c => /[a-z]/.test(c) ? String.fromCodePoint(0x1D41A + c.charCodeAt(0) - 97) : /[A-Z]/.test(c) ? String.fromCodePoint(0x1D400 + c.charCodeAt(0) - 65) : c).join(''),
	homoglyph: s => Array.from(s, c => HOMO[c] || c).join(''),
	leet: s => Array.from(s, c => LEET[c] || c).join(''),
	spaced: s => s.split(' ').map(w => Array.from(w).join(' ')).join('   ')
};
function expand(text) {
	const re = /\{\{(\w+):((?:(?!\{\{|\}\})[\s\S])*)\}\}/;
	let m;
	while ((m = re.exec(text)) !== null) {
		if (!T[m[1]]) { throw new Error('unknown transform ' + m[1]); }
		text = text.slice(0, m.index) + T[m[1]](m[2]) + text.slice(m.index + m[0].length);
	}
	return text;
}
module.exports = { expand, T };
if (require.main !== module) { return; }

let passed = 0;
function check(label, fn) {
	try { fn(); } catch (e) { console.error('FAIL: ' + label); throw e; }
	passed++;
	console.log('PASS: ' + label);
}

// ---------------------------------------------------------------- attacks
const attacks = JSON.parse(fill(fs.readFileSync(path.join(FIX, 'attacks.json'), 'utf8'))).cases;
const byGroup = {};
for (const g of engine.GROUPS) { byGroup[g.id] = { cases: 0, detected: 0, detectedMedium: 0, anyGroup: 0, missed: [], paraphrase: { cases: 0, detected: 0 } }; }
for (const c of attacks) {
	const text = expand(c.text);
	const r = engine.analyze(text, {});
	const own = r.findings.filter(f => f.group === c.group);
	const g = byGroup[c.group];
	g.cases++;
	if (own.length) { g.detected++; } else { g.missed.push(c.id); }
	if (own.some(f => f.severity !== 'low')) { g.detectedMedium++; }
	if (r.findings.length) { g.anyGroup++; }
	if (c.paraphrase) { g.paraphrase.cases++; if (own.length) { g.paraphrase.detected++; } }
}

// ---------------------------------------------------------------- RAG documents
const rag = JSON.parse(fill(fs.readFileSync(path.join(FIX, 'rag/expected.json'), 'utf8'))).files;
const ragResults = {};
for (const [file, exp] of Object.entries(rag)) {
	const r = engine.analyze(fill(fs.readFileSync(path.join(FIX, 'rag', file), 'utf8')), {});
	const groups = Array.from(new Set(r.findings.map(f => f.group)));
	ragResults[file] = { benign: exp.benign, expected: exp.groups || [], found: groups, findings: r.findings.map(f => f.ruleId + ':' + f.severity) };
}

// ---------------------------------------------------------------- benign
const benign = JSON.parse(fill(fs.readFileSync(path.join(FIX, 'benign.json'), 'utf8'))).samples;
for (const [file, exp] of Object.entries(rag)) {
	if (exp.benign) { benign.push({ id: 'rag:' + file, category: 'rag', text: fill(fs.readFileSync(path.join(FIX, 'rag', file), 'utf8')) }); }
}
const fp = { samples: benign.length, any: 0, medium: 0, findings: 0, byCategory: {}, flagged: [] };
for (const s of benign) {
	const r = engine.analyze(s.text, {});
	const cat = fp.byCategory[s.category] || (fp.byCategory[s.category] = { samples: 0, any: 0, medium: 0 });
	cat.samples++;
	if (r.findings.length) {
		fp.any++; cat.any++;
		fp.findings += r.findings.length;
		fp.flagged.push({ id: s.id, findings: r.findings.map(f => f.ruleId + ':' + f.severity) });
	}
	if (r.findings.some(f => f.severity !== 'low')) { fp.medium++; cat.medium++; }
}

// ---------------------------------------------------------------- held-out set (not used for tuning; no thresholds)
const holdout = JSON.parse(fill(fs.readFileSync(path.join(FIX, 'holdout.json'), 'utf8')));
const ho = { byGroup: {}, detected: 0, cases: 0, missed: [], benign: { samples: 0, any: 0, medium: 0, flagged: [] } };
for (const c of holdout.attacks) {
	const r = engine.analyze(expand(c.text), {});
	const g = ho.byGroup[c.group] || (ho.byGroup[c.group] = { cases: 0, detected: 0 });
	g.cases++; ho.cases++;
	if (r.findings.some(f => f.group === c.group)) { g.detected++; ho.detected++; } else { ho.missed.push(c.id + (r.findings.length ? ' (other groups: ' + Array.from(new Set(r.findings.map(f => f.group))).join('/') + ')' : '')); }
}
for (const b of holdout.benign) {
	const r = engine.analyze(b.text, {});
	ho.benign.samples++;
	if (r.findings.length) { ho.benign.any++; ho.benign.flagged.push(b.id + ': ' + r.findings.map(f => f.ruleId + ':' + f.severity).join(', ')); }
	if (r.findings.some(f => f.severity !== 'low')) { ho.benign.medium++; }
}

// ---------------------------------------------------------------- report
const pct = (a, b) => b ? Math.round((a / b) * 1000) / 10 : 0;
const totals = Object.values(byGroup).reduce((t, g) => ({ cases: t.cases + g.cases, detected: t.detected + g.detected, detectedMedium: t.detectedMedium + g.detectedMedium }), { cases: 0, detected: 0, detectedMedium: 0 });
console.log('\nDetection by group (own group reported; any severity / medium+):');
for (const [id, g] of Object.entries(byGroup)) {
	console.log(`  ${id.padEnd(13)} ${String(g.detected).padStart(2)}/${g.cases} = ${pct(g.detected, g.cases)}%   medium+ ${g.detectedMedium}/${g.cases} = ${pct(g.detectedMedium, g.cases)}%   paraphrases ${g.paraphrase.detected}/${g.paraphrase.cases}   missed: ${g.missed.join(', ') || '-'}`);
}
console.log(`  ${'TOTAL'.padEnd(13)} ${totals.detected}/${totals.cases} = ${pct(totals.detected, totals.cases)}%   medium+ ${totals.detectedMedium}/${totals.cases} = ${pct(totals.detectedMedium, totals.cases)}%`);
console.log(`\nFalse positives on ${fp.samples} benign samples: any severity ${fp.any} (${pct(fp.any, fp.samples)}%), medium+ ${fp.medium} (${pct(fp.medium, fp.samples)}%)`);
for (const [cat, c] of Object.entries(fp.byCategory)) { console.log(`  ${cat.padEnd(14)} ${c.any}/${c.samples} any, ${c.medium}/${c.samples} medium+`); }
for (const f of fp.flagged) { console.log('  flagged ' + f.id + ': ' + f.findings.join(', ')); }
console.log('\nRAG documents:');
for (const [file, r] of Object.entries(ragResults)) { console.log(`  ${file.padEnd(26)} expected [${r.expected}] found [${r.found}]`); }

console.log('\nHeld-out set (written after tuning, not tuned on):');
for (const [id, g] of Object.entries(ho.byGroup)) { console.log(`  ${id.padEnd(13)} ${g.detected}/${g.cases}`); }
console.log(`  TOTAL detected ${ho.detected}/${ho.cases} = ${pct(ho.detected, ho.cases)}%; missed: ${ho.missed.join('; ') || '-'}`);
console.log(`  benign ${ho.benign.samples}: any severity ${ho.benign.any} (${pct(ho.benign.any, ho.benign.samples)}%), medium+ ${ho.benign.medium} (${pct(ho.benign.medium, ho.benign.samples)}%)`);
for (const f of ho.benign.flagged) { console.log('  flagged ' + f); }

if (process.argv[2]) {
	fs.writeFileSync(process.argv[2], JSON.stringify({ engine: engine.VERSION, ruleset: engine.RULESET_VERSION, at: new Date().toISOString(), detection: byGroup, totals, falsePositives: fp, rag: ragResults, holdout: ho }, null, 2) + '\n');
	console.log('\nMetrics written to ' + process.argv[2]);
}

if (process.env.PI_METRICS_ONLY) { process.exit(0); }

// ---------------------------------------------------------------- regression guards
check('every attack case belongs to a known group and every group has at least 10 cases', () => {
	for (const g of Object.values(byGroup)) { assert.ok(g.cases >= 10); }
});
check('non-paraphrase attacks: every group detects at least 90% (regression guard)', () => {
	for (const [id, g] of Object.entries(byGroup)) {
		const strict = g.cases - g.paraphrase.cases;
		const hit = g.detected - g.paraphrase.detected;
		assert.ok(hit / strict >= 0.9, `${id}: ${hit}/${strict}`);
	}
});
check('false positives at medium+ on the benign corpus stay at or below 10%', () => {
	assert.ok(fp.medium / fp.samples <= 0.10, `${fp.medium}/${fp.samples}`);
});
check('RAG attack documents: every expected group is found; benign RAG documents have no medium+ finding', () => {
	for (const [file, r] of Object.entries(ragResults)) {
		if (r.benign) { assert.ok(!r.findings.some(f => !/:low$/.test(f)), file + ': ' + r.findings); }
		else { for (const g of r.expected) { assert.ok(r.found.includes(g), file + ' missing ' + g); } }
	}
});
console.log(`\n${passed} corpus checks passed.`);
