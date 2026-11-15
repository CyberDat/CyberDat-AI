/*
 * Leak Inspector: e-mail addresses with Unicode local parts (DEPENDENT examples, written 2026-11-15 after the defect was
 * reproduced: the e-mail pattern used ASCII classes and \b, so "jürgen@example.com" became "rgen@example.com" and
 * Cyrillic local parts were not found). Invented addresses, example.* domains only.
 *   node tests/leak-inspector-email-unicode.test.cjs [--report]
 */
'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const e = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/leak-inspector/engine.js'));
const report = process.argv.includes('--report');
const NFD = s => s.normalize('NFD');

// Personal addresses: the finding must show the whole address (compared in NFC).
const personal = ['jürgen@example.com', NFD('jürgen@example.com'), 'Ölaf.berg@example.de', 'zoë.lind@example.com', NFD('zoë.lind@example.com'), 'иван.петров@example.ru', NFD('пётр.сидоров@example.ru'), 'björn.müller@example.de'];
const controls = ['joerg.mueller@example.de', 'anna.k+news@example.org'];
// Role mailboxes are not personal addresses; a Unicode prefix must not hide the role word or create a partial address.
const role = ['support@example.com', 'info@example.de'];
const notEmail = ['Größe@Maßstab ist kein Adresse.', 'Обращение @ 10:00 в отделе.'];
const results = { personal: [0, 0], control: [0, 0], role: [0, 0], notEmail: [0, 0] };
const fails = [];
const staffEvidence = t => e.audit(t).findings.filter(f => f.rule === 'LKI-INT-002').map(f => String(f.evidence).normalize('NFC'));
function check(group, addr, ok, got) {
	results[group][ok ? 0 : 1]++;
	const line = group.padEnd(9) + addr.padEnd(30) + ' -> ' + (got.join(', ') || 'nothing');
	if (!ok) { fails.push(line); }
	if (report) { console.log((ok ? 'ok   ' : 'FAIL ') + line); }
}
for (const a of personal.concat(controls)) {
	const got = staffEvidence('Escalate billing questions to ' + a + ' if needed.');
	check(controls.includes(a) ? 'control' : 'personal', a, got.length === 1 && got[0] === a.normalize('NFC'), got);
}
for (const a of role) { const got = staffEvidence('Escalate billing questions to ' + a + ' if needed.'); check('role', a, got.length === 0, got); }
for (const t of notEmail) { const got = staffEvidence(t); check('notEmail', t, got.length === 0, got); }
for (const [g, [ok, bad]] of Object.entries(results)) { console.log(g.padEnd(9) + ok + '/' + (ok + bad) + ' as expected'); }
console.log('NOT INDEPENDENT: examples written after the defect was known.');
if (!report) {
	assert.deepEqual(fails, []);
	console.log('PASS: Leak Inspector e-mail addresses with Unicode local parts');
}
