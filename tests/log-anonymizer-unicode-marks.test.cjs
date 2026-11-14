/*
 * Log Anonymizer: user names with combining marks (NFD) in the five user-name forms (DEPENDENT examples, see the fixture note).
 *   node tests/log-anonymizer-unicode-marks.test.cjs [--report]   (--report prints all results without asserting)
 * Groups:
 *   nfd       five forms, names decomposed (o + U+0308 ...) and names with marks that have no precomposed form  -> must be masked
 *   control   five forms, the same names in NFC and ASCII names                                                    -> must be masked
 *   negative  prose with combining marks next to the trigger words                                                 -> must be kept
 *   other     other user rules with NFD names: REPORTED ONLY (these rules are out of scope and unchanged)
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/log-anonymizer/engine.js'));
const set = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/log-anonymizer/unicode-marks.json'), 'utf8'));
const report = process.argv.includes('--report');
const results = { nfd: [0, 0], control: [0, 0], negative: [0, 0], other: [0, 0] };
const failures = [];
const hex = s => [...s].map(c => c.codePointAt(0) > 127 ? 'U+' + c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0') : c).join(' ');

function problem(text, name) {
	const template = text.split(name).join('');
	const out = engine.anonymize(text, {}).output;
	if (out.split('\n').length !== text.split('\n').length) { return 'line count changed'; }
	for (const form of [name, name.normalize('NFC'), name.normalize('NFD')]) {
		if (out.includes(form)) { return 'not masked'; }
	}
	// Any tail or head of two or more code points left behind (e.g. "̈rg" after "jo" was replaced),
	// ignoring fragments that also occur in the rest of the line ("pe" in "opened").
	const cps = [...name];
	for (let k = 1; k + 2 <= cps.length; k++) {
		for (const part of [cps.slice(k).join(''), cps.slice(0, cps.length - k).join('')]) {
			if (out.includes(part) && !template.includes(part)) { return 'partly masked'; }
		}
	}
	// Templates contain no combining marks, so any mark in the output is a remainder of the name.
	if (/\p{M}/u.test(name) && /\p{M}/u.test(out)) { return 'partly masked (combining mark left: ' + hex(out.match(/\p{M}+/u)[0]) + ')'; }
	if (/(?:USER|REDACTED_USERNAME)(?:_\d+)?[\p{L}\p{N}\p{M}]|[\p{L}\p{N}\p{M}](?:USER_\d+)/u.test(out)) { return 'partly masked (characters next to the label)'; }
	return '';
}
function record(group, id, name, issue) {
	results[group][issue ? 1 : 0]++;
	const line = group.padEnd(9) + id.padEnd(16) + (name.padEnd(9) + ' [' + hex(name) + ']').padEnd(44) + (issue || 'masked');
	if (issue && group !== 'other') { failures.push(line); }
	if (report || (issue && group === 'other')) { console.log((issue ? 'FAIL ' : 'ok   ') + line); }
}
for (const c of set.forms) {
	for (const name of c.names) {
		const nfd = name.normalize('NFD');
		assert.notEqual(nfd, name.normalize('NFC'), 'fixture name must decompose: ' + name);
		record('nfd', c.id, nfd, problem(c.text.replace('NAME', nfd), nfd));
		record('control', c.id, name.normalize('NFC'), problem(c.text.replace('NAME', name.normalize('NFC')), name));
	}
	for (const name of set.marked) { record('nfd', c.id, name, problem(c.text.replace('NAME', name), name)); }
	for (const name of set.ascii) { record('control', c.id, name, problem(c.text.replace('NAME', name), name)); }
}
for (const c of set.otherRules) {
	for (const name of c.names) { const nfd = name.normalize('NFD'); record('other', c.id, nfd, problem(c.text.replace('NAME', nfd), nfd)); }
}
for (const c of set.negative) {
	const out = engine.anonymize(c.text, {}).output;
	const lost = c.keep.filter(k => !out.includes(k));
	results.negative[lost.length ? 1 : 0]++;
	const line = 'negative ' + c.id.padEnd(22) + (lost.length ? 'changed: ' + lost.join(', ') + ' -> ' + out : 'kept');
	if (lost.length) { failures.push(line); }
	if (report) { console.log((lost.length ? 'FAIL ' : 'ok   ') + line); }
}
for (const [g, [ok, bad]] of Object.entries(results)) { console.log(g.padEnd(9) + ok + '/' + (ok + bad) + ' as expected' + (g === 'other' ? ' (reported only, rules unchanged)' : '')); }
console.log('NOT INDEPENDENT: examples written after the defect was known.');
if (!report) {
	assert.deepEqual(failures, []);
	console.log('PASS: Log Anonymizer user names with combining marks');
}
