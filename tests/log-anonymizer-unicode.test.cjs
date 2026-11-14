/*
 * Log Anonymizer: user names with Cyrillic and umlauts (DEPENDENT examples, see the fixture note).
 *   node tests/log-anonymizer-unicode.test.cjs [--report]   (--report prints all results without asserting)
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/log-anonymizer/engine.js'));
const set = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/log-anonymizer/unicode-names.json'), 'utf8'));
const results = { fixed: [0, 0], control: [0, 0], added: [0, 0], negative: [0, 0] };
const failures = [];

function masked(text, name) {
	const out = engine.anonymize(text, {}).output;
	if (out.split('\n').length !== text.split('\n').length) { return 'line count changed'; }
	if (out.includes(name)) { return 'not masked'; }
	// A partial match such as "USER_1örg" leaves the tail of the name behind.
	if (name.length >= 3 && (out.includes(name.slice(1)) || out.includes(name.slice(0, -1)))) { return 'partly masked'; }
	// Even a single leftover letter next to the label means the name was cut (e.g. "USER_1ë").
	if (/(?:USER|REDACTED_USERNAME)(?:_\d+)?[\p{L}\p{N}]|[\p{L}\p{N}](?:USER_\d+)/u.test(out)) { return 'partly masked (letters next to the label)'; }
	return '';
}
for (const group of ['fixed', 'control', 'added']) {
	for (const c of set[group]) {
		for (const name of c.names) {
			const problem = masked(c.text.replace('NAME', name), name);
			results[group][problem ? 1 : 0]++;
			const line = group.padEnd(8) + c.id.padEnd(18) + name.padEnd(10) + (problem || 'masked');
			if (problem) { failures.push(line); }
			if (process.argv.includes('--report')) { console.log((problem ? 'FAIL ' : 'ok   ') + line); }
		}
	}
}
for (const c of set.negative) {
	const out = engine.anonymize(c.text, {}).output;
	const lost = c.keep.filter(k => !out.includes(k));
	results.negative[lost.length ? 1 : 0]++;
	const line = 'negative' + c.id.padEnd(18) + (lost.length ? 'changed: ' + lost.join(', ') : 'kept');
	if (lost.length) { failures.push(line); }
	if (process.argv.includes('--report')) { console.log((lost.length ? 'FAIL ' : 'ok   ') + line); }
}
for (const [g, [ok, bad]] of Object.entries(results)) { console.log(g.padEnd(9) + ok + '/' + (ok + bad) + ' as expected'); }
console.log('NOT INDEPENDENT: examples written after the defect was known.');
if (!process.argv.includes('--report')) {
	assert.deepEqual(failures, []);
	console.log('PASS: Log Anonymizer Unicode user names');
}
