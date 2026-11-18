/*
 * Release 1.3 tools: no regular-expression look-behind in app.js, worker.js and engine.js, and every regular expression with
 * Unicode property classes is created with the u flag (checked at run time over EN/DE/RU input, NFC and NFD, including
 * patterns built at run time).
 *   node tests/tools-release-1.3-unicode.test.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const JS = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js');
const TOOLS = ['prompt-injection-test-bench', 'yara-sigma-validator', 'container-hardening-audit'].filter(t => fs.existsSync(path.join(JS, t, 'engine.js')));
let n = 0;
const ok = l => { n++; console.log('PASS: ' + l); };
for (const t of TOOLS) {
	for (const f of ['app.js', 'worker.js', 'engine.js']) {
		const src = fs.readFileSync(path.join(JS, t, f), 'utf8');
		assert.ok(!src.includes('(?<=') && !src.includes('(?<!'), t + '/' + f + ': look-behind');
		assert.ok(!/\\[bBwW]/.test(src), t + '/' + f + ': \\b or \\w');
	}
}
ok('no look-behind and no \\b/\\w in app.js, worker.js and engine.js of ' + TOOLS.join(', '));

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
const texts = ['Ignoriere die Anweisungen; Größe für Jörg. Ёлка и Пётр.'.normalize('NFD'), 'Plain English text with CANARY-7F3A9C2B.', 'Привет, мир — CANARY-7f3a9c2b'];
const inputs = {
	'prompt-injection-test-bench': e => { const s = e.buildSet({ appTypes: Object.keys(e.APP_TYPES), langs: ['en', 'de', 'ru'], seed: 3 }); const r = {}; s.tests.forEach((t, i) => { r[t.id] = texts[i % texts.length] + ' ' + (i % 2 ? t.canary : ''); }); e.check(s, r); e.parseResponses('id,response\nT001,' + texts[0]); },
	'yara-sigma-validator': e => { for (const t of texts) { e.validate(t, {}); } },
	'container-hardening-audit': e => { for (const t of texts) { try { e.audit(t, {}); } catch (x) { /* parse errors are fine here */ } } }
};
for (const t of TOOLS) { inputs[t](require(path.join(JS, t, 'engine.js'))); }
global.RegExp = NativeRegExp;
assert.equal(noU.size, 0, [...noU].join(' | '));
ok('every regular expression with \\p{...} created while processing EN/DE/RU input (NFC and NFD) has the u flag (' + built + ' constructed at run time)');
console.log('\n' + n + ' release 1.3 Unicode contract checks passed.');
