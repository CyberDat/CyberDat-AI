/*
 * Quick utilities (utilities 1): no regular-expression look-behind in app.js, worker.js and engine.js, and every regular
 * expression with Unicode property classes is created with the u flag (checked at run time over EN/DE/RU headers, NFC and
 * NFD, including patterns built at run time).
 *   node tests/tools-utilities-1-unicode.test.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const JS = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js');
const TOOLS = ['email-header-analyzer'].filter(t => fs.existsSync(path.join(JS, t, 'engine.js')));
let n = 0;
const ok = l => { n++; console.log('PASS: ' + l); };
for (const t of TOOLS) {
	for (const f of ['app.js', 'worker.js', 'engine.js']) {
		const src = fs.readFileSync(path.join(JS, t, f), 'utf8');
		assert.ok(!src.includes('(?<=') && !src.includes('(?<!'), t + '/' + f + ': look-behind');
		assert.ok(!/\\[bBwW]/.test(src), t + '/' + f + ': \\b or \\w');
	}
}
let literals = 0;
for (const t of TOOLS) {
	for (const f of ['app.js', 'worker.js', 'engine.js']) {
		const lines = fs.readFileSync(path.join(JS, t, f), 'utf8').split('\n');
		lines.forEach((line, k) => {
			if (!line.includes('\\p{') || line.includes('new RegExp(')) { return; }
			literals++;
			const tail = line.slice(line.lastIndexOf('\\p{'));
			assert.ok(/\/[dgimsy]*u[dgimsy]*(?:[,;).:\s\]]|$)/.test(tail), t + '/' + f + ':' + (k + 1) + ': Unicode class in a regular expression without the u flag');
		});
	}
}
assert.ok(literals > 0, 'no Unicode regular-expression literals found');
ok('all ' + literals + ' source lines with Unicode property classes in regular-expression literals carry the u flag');
ok('no look-behind and no \\b/\\w in app.js, worker.js and engine.js of ' + TOOLS.join(', '));

const engines = Object.fromEntries(TOOLS.map(t => [t, require(path.join(JS, t, 'engine.js'))]));
const NativeRegExp = RegExp;
const noU = new Set();
let built = 0;
global.RegExp = function (p, f) {
	const src = p && p.source !== undefined ? p.source : String(p);
	const flags = f !== undefined ? f : (p && p.flags) || '';
	built++;
	if (/\\p\{/.test(src) && !flags.includes('u')) { noU.add(src.slice(0, 50) + '… flags=' + flags); }
	return new NativeRegExp(p, f);
};
global.RegExp.prototype = NativeRegExp.prototype;
const b64 = s => '=?UTF-8?B?' + Buffer.from(s, 'utf8').toString('base64') + '?=';
const texts = [
	'From: ' + b64('Jörg Größe') + ' <joerg@münchen.example>\nTo: Пётр <petr@пример.example>\nSubject: Prüfung für Größe\nDate: Tue, 17 Nov 2026 10:00:00 +0100\n',
	('From: "Сбербанк Онлайн" <info@sb.example>\nReply-To: Ёлка <elka@example.net>\nSubject: Ёлка и Пётр\n').normalize('NFD'),
	'Received: from mail.example.org (mail.example.org [198.51.100.10])\n\tby mx.example.com; Tue, 17 Nov 2026 10:00:03 +0100\nFrom: PayPal <service@xn--pypal-4ve.example>\nSubject: Plain English text\n'
];
const inputs = { 'email-header-analyzer': e => { for (const t of texts) { const r = e.analyze(t, { now: '2026-11-18T12:00:00Z', own: 'example.com' }); e.exportReport(r, { maskRecipients: true, maskInternal: true }); } } };
for (const t of TOOLS) { inputs[t](engines[t]); }
global.RegExp = NativeRegExp;
assert.equal(noU.size, 0, [...noU].join(' | '));
ok('every regular expression with \\p{...} created while processing EN/DE/RU headers (NFC and NFD) has the u flag (' + built + ' constructed at run time)');
console.log('\n' + n + ' utilities 1 Unicode contract checks passed.');
