/*
 * Measurement only: how many Test Bench library inputs the Prompt Injection Detector (tool 2) flags. The detector is not
 * changed. NOT INDEPENDENT: both tools are by the same author.
 *   node tests/prompt-injection-test-bench-detector.test.cjs [--verbose]
 */
'use strict';
const path = require('node:path');
const bench = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/prompt-injection-test-bench/engine.js'));
const detector = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/prompt-injection-detector/engine.js'));
const set = bench.buildSet({ appTypes: Object.keys(bench.APP_TYPES), langs: ['en', 'de', 'ru'], seed: 1 });
const RANK = { low: 1, medium: 2, high: 3 };
const by = {};
let any = 0, medium = 0;
const missed = [];
for (const t of set.tests) {
	const r = detector.analyze(t.input);
	const top = r.findings.reduce((m, f) => Math.max(m, RANK[f.severity] || 0), 0);
	const k = t.category + ' ' + t.lang;
	const g = by[t.category] = by[t.category] || { total: 0, any: 0, medium: 0 };
	g.total++;
	if (top >= 1) { any++; g.any++; }
	if (top >= 2) { medium++; g.medium++; } else { missed.push(t.template + '/' + t.lang + (top ? ' (low only)' : '')); }
	void k;
}
const pct = (a, b) => (100 * a / b).toFixed(1) + '%';
console.log('Prompt Injection Detector ' + detector.VERSION + ' on ' + set.tests.length + ' Test Bench inputs (library ' + bench.LIBRARY_VERSION + ', NOT INDEPENDENT):');
console.log('  any finding ' + any + '/' + set.tests.length + ' (' + pct(any, set.tests.length) + '); medium or high ' + medium + '/' + set.tests.length + ' (' + pct(medium, set.tests.length) + ')');
for (const [c, g] of Object.entries(by)) { console.log('  ' + c.padEnd(18) + ' medium+ ' + g.medium + '/' + g.total + ', any ' + g.any + '/' + g.total); }
if (process.argv.includes('--verbose')) { console.log('  not flagged at medium+: ' + missed.join(', ')); }
console.log('PASS: measurement recorded (no threshold; the detector is not changed)');
