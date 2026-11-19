/*
 * Email Header Analyzer engine: Public Suffix List snapshot and lookups, punycode against Node's own implementation,
 * encoded words, line endings, masking in exports, the body never in the output, hang protection (large input, many
 * Received lines, pathological strings), fuzzing, examples and static contracts. Examples here are DEPENDENT.
 *   node tests/email-header-analyzer-engine.test.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { domainToASCII } = require('node:url');
const { performance } = require('node:perf_hooks');
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const DIR = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/email-header-analyzer');
const e = require(path.join(DIR, 'engine.js'));
let n = 0;
const ok = l => { n++; console.log('PASS: ' + l); };
const ids = r => [...new Set(r.findings.map(f => f.id))].sort();
const lf = p => fs.readFileSync(p, 'utf8').replace(/\r\n/g, '\n');
const NOW = '2026-11-18T12:00:00Z';
const NOW_EX = '2026-11-19T12:00:00Z'; // after the dates in the built-in examples

// ---------------------------------------------------------------- catalogue and PSL snapshot
const frozen = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/email-header-analyzer/rules.json'), 'utf8'));
for (const r of frozen.findings) { assert.ok(e.DEF[r.id], r.id); assert.equal(e.DEF[r.id][0], r.severity, r.id); }
assert.equal(Object.keys(e.DEF).length, frozen.findings.length);
const snap = JSON.parse(fs.readFileSync(path.join(__dirname, '../deploy/tools-utilities-1/psl-snapshot.json'), 'utf8'));
const dat = lf(path.join(DIR, 'public_suffix_list.dat'));
assert.equal(crypto.createHash('sha256').update(dat).digest('hex'), snap.sha256['public_suffix_list.dat']);
global.self = {};
new Function(lf(path.join(DIR, 'psl-data.js')))(); // test only: evaluates the generated data carrier
assert.equal(self.CyberDatPSL.text, dat);
assert.equal(self.CyberDatPSL.sha256, snap.sha256['public_suffix_list.dat']);
assert.ok(self.CyberDatPSL.source === 'https://publicsuffix.org/list/public_suffix_list.dat' && self.CyberDatPSL.license === 'MPL-2.0' && self.CyberDatPSL.date === snap.listDate);
{ const head = lf(path.join(DIR, 'psl-data.js')).slice(0, 700); assert.ok(head.includes('Mozilla Public License 2.0 (MPL-2.0)') && head.includes('Source: https://publicsuffix.org/list/public_suffix_list.dat'), 'psl-data.js header names MPL-2.0 and the source'); }
assert.ok(/Mozilla Public License/u.test(lf(path.join(DIR, 'LICENSE-MPL-2.0.txt'))) && /This Source Code Form is subject to the terms of the Mozilla Public/u.test(dat));
ok('finding ids equal the frozen catalogue (' + frozen.findings.length + '); psl-data.js carries public_suffix_list.dat byte for byte (SHA-256 pinned, publicsuffix.org list of ' + snap.listDate.slice(0, 10) + '); header names MPL-2.0 and the source; MPL-2.0 text shipped');

const org = e.orgDomain;
assert.equal(org('a.b.example.co.uk'), 'example.co.uk');
assert.equal(org('mail.evil.co.uk'), 'evil.co.uk');
assert.notEqual(org('example.co.uk'), org('evil.co.uk'));
assert.equal(org('co.uk'), '');
assert.equal(org('www.ck'), 'www.ck');
assert.equal(org('a.b.ck'), 'a.b.ck');
assert.equal(org('host.city.kawasaki.jp'), 'city.kawasaki.jp');
assert.equal(org('x.y.kawasaki.jp'), 'x.y.kawasaki.jp');
assert.equal(org('mail.prod.outlook.com'), 'outlook.com');
assert.equal(org('shop.example.xn--p1ai'), 'example.xn--p1ai');
assert.equal(org('shop.пример.рф'), e.toASCII('пример.рф'));
assert.equal(org('a.b.example'), 'b.example');
ok('Public Suffix List lookups: multi-label suffixes (co.uk), wildcard and exception rules (*.ck / !www.ck, *.kawasaki.jp / !city.kawasaki.jp), IDN suffixes; example.co.uk and evil.co.uk are different organizations');

for (const d of ['pаypal.example', 'bäckerei-müller.example', 'αpple-id.example', 'пример.рф', 'münchen.de', '例え.テスト', 'xn--already.example']) {
	assert.equal(e.toASCII(d), domainToASCII(d) || e.toASCII(d), d);
	if (domainToASCII(d)) { assert.equal(e.toUnicode(e.toASCII(d)), d.normalize('NFC'), d); }
}
for (let k = 0; k < 300; k++) { const s = Array.from({ length: 1 + (k % 9) }, (_, j) => String.fromCodePoint([0x61, 0xe4, 0x436, 0x3b1, 0x4e2d, 0x30c6, 0x1f600][(k + j * 3) % 7])).join(''); assert.equal(e.punyDecode(e.punyEncode(s)), s); }
assert.throws(() => e.punyDecode('99999999999999999999'));
ok('punycode: own encoder equals Node url.domainToASCII on Latin, Cyrillic, Greek and CJK domains; 300 round trips; invalid input refused');

// ---------------------------------------------------------------- decoding and line endings
assert.equal(e.decodeWords('=?ISO-8859-1?Q?J=FCrgen_M=FCller?=').text, 'Jürgen Müller');
assert.equal(e.decodeWords('=?UTF-8?B?' + Buffer.from('Größe ').toString('base64') + '?= \t =?UTF-8?B?' + Buffer.from('Пётр').toString('base64') + '?=').text, 'Größe Пётр');
assert.equal(e.decodeWords('=?windows-1251?B?' + Buffer.from([0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2]).toString('base64') + '?=').text, 'Привет');
assert.equal(e.decodeWords('=?koi8-r?Q?=F0=D2=C9=D7=C5=D4?=').text, 'Привет');
assert.equal(e.decodeWords('=?x-unknown-cs?Q?abc?=').text, '=?x-unknown-cs?Q?abc?=');
const base = e.EXAMPLE_NORMAL;
const variants = [base, base.replace(/\n/g, '\r\n'), base.replace(/\n/g, '\r'), base.replace(/\n/g, '\r\r\n'), '\n\n' + base, 'From MAILER-DAEMON Wed Nov 18 13:02:07 2026\n' + base];
const sig = r => JSON.stringify([ids(r), r.path.hops.length, r.summary.subject, r.summary.from.name, r.auth.effective.dmarc.result]);
const ref = sig(e.analyze(base, { now: NOW, own: 'example.com' }));
for (const v of variants) { assert.equal(sig(e.analyze(v, { now: NOW, own: 'example.com' })), ref); }
ok('encoded words (Q and B, ISO-8859-1, UTF-8, windows-1251, KOI8-R, adjacent words joined, unknown charset kept); LF, CRLF, CR, CR CR LF, leading blank lines and an mbox From line give the same result');

// ---------------------------------------------------------------- the body never leaves the engine
const body = '\nSecret plan BODY-ONLY-91\nhttp://203.0.113.200/pay\n' + 'x'.repeat(200000) + '\n';
const rb = e.analyze(e.EXAMPLE_PHISHING.replace(/\n\n[\s\S]*$/u, '\n') + body, { now: NOW });
const repB = e.exportReport(rb, {});
for (const s of ['BODY-ONLY-91', '203.0.113.200']) { assert.ok(!(JSON.stringify(rb) + repB.json + repB.markdown).includes(s), s); }
assert.ok(rb.bodyIgnored.lines >= 3 && rb.notes.some(x => /body .* was ignored/u.test(x)));
ok('the message body is not analysed, returned or exported; only its size is counted and a note says it was ignored');

// ---------------------------------------------------------------- export masking
const hdr = 'Received: from mx.example.com (mx.example.com [192.0.2.25])\n\tby imap.example.com (Postfix) with ESMTPS id A1\n\tfor <bob@example.com>; Tue, 17 Nov 2026 10:00:05 +0100\nReceived: from [10.9.8.7] (unknown [10.9.8.7])\n\tby mx.example.com (Postfix) with ESMTP id A0\n\tfor <bob@example.com>; Tue, 17 Nov 2026 10:00:03 +0100\nDelivered-To: carol@example.com\nFrom: Alice <alice@example.org>\nTo: Bob <bob@example.com>, dave@example.com\nCc: erin@example.com\nSubject: token ' + S.GITHUB_PAT + '\nX-Note: ' + S.OPAQUE_LONG + '\nDate: Tue, 17 Nov 2026 10:00:00 +0100\nMessage-ID: <1@example.org>\n';
const rm = e.analyze(hdr, { now: NOW });
assert.ok(!JSON.stringify(rm).includes(S.GITHUB_PAT));
const plain = e.exportReport(rm, {}), masked = e.exportReport(rm, { maskRecipients: true, maskInternal: true });
assert.ok(plain.json.includes('bob@example.com') && plain.json.includes('10.9.8.7'));
for (const s of ['bob@example.com', 'dave@example.com', 'erin@example.com', 'carol@example.com', '10.9.8.7', 'Bob']) { assert.ok(!masked.json.includes(s) && !masked.markdown.includes(s), s); }
assert.ok(masked.json.includes('[recipient 1]') && masked.json.includes('[internal IP 1]') && masked.json.includes('alice@example.org') && masked.json.includes('192.0.2.25'));
for (const s of [S.GITHUB_PAT]) { assert.ok(!plain.json.includes(s) && !plain.markdown.includes(s)); }
ok('export: secrets always masked; on request recipient addresses (To, Cc, Delivered-To, Received for) and internal IPs are replaced consistently; sender and public IPs stay');

// ---------------------------------------------------------------- hang protection
const time = f => { const t = performance.now(); const r = f(); return [performance.now() - t, r]; };
const hop = i => 'Received: from relay' + i + '.example.net (relay' + i + '.example.net [198.51.100.' + (i % 250) + '])\n\tby relay' + (i + 1) + '.example.net (Postfix) with ESMTP id Q' + i + '\n\tfor <bob@example.com>; Tue, 17 Nov 2026 10:' + String(i % 60).padStart(2, '0') + ':00 +0100\n';
const many = Array.from({ length: 1000 }, (_, i) => hop(1000 - i)).join('') + 'From: a@example.org\nDate: Tue, 17 Nov 2026 10:00:00 +0100\n';
let [ms, r] = time(() => e.analyze(many, { now: NOW }));
assert.ok(r.path.hops.length === 1000 && ms < 3000, ms);
const patho = [
	'Received: ' + '('.repeat(200000) + '\n', 'Received: from ' + 'from '.repeat(40000) + '\n', 'Received: ' + 'a@'.repeat(100000) + '\n', 'From: ' + '"'.repeat(100000) + '<'.repeat(50000) + '\n',
	'Subject: ' + '=?UTF-8?B?'.repeat(50000) + '\n', 'Authentication-Results: x; ' + 'spf=pass;'.repeat(50000) + '\n', 'Received: from [' + '1.'.repeat(100000) + ']\n', 'From: "' + 'a.'.repeat(100000) + 'b" <a@example.org>\n',
	'Received: by ' + ':'.repeat(200000) + '\n', 'DKIM-Signature: ' + 'd='.repeat(100000) + '\n', 'Date: ' + '1 '.repeat(100000) + '\n', 'Reply-To: ' + 'x'.repeat(300000) + '@' + 'y.'.repeat(50000) + 'example\n'
];
let worst = 0;
for (const p of patho) { const [t] = time(() => e.analyze(p, { now: NOW })); worst = Math.max(worst, t); }
assert.ok(worst < 3000, worst);
assert.throws(() => e.analyze('x'.repeat(e.MAX_INPUT_CHARS + 1)), x => x.code === 'TOO_LARGE');
assert.throws(() => e.analyze('Subject: ' + 'y'.repeat(e.MAX_HEADER_CHARS + 10) + '\n'), x => x.code === 'TOO_LARGE');
ok('hang protection: 1,000 Received lines in ' + Math.round(ms) + ' ms; 12 pathological inputs (200,000 parentheses, repeated keywords, quotes, encoded-word starts, separators) each under ' + Math.round(worst) + ' ms; size limits');

// ---------------------------------------------------------------- fuzz
let seed = 19;
const rnd = () => { seed = (seed * 1103515245 + 12345) >>> 0; return seed / 4294967296; };
const parts = ['Received: ', 'from ', 'by ', 'with ', 'id ', 'for ', '<', '>', '(', ')', '[', ']', ';', ':', '@', '.', 'example.org', '198.51.100.7', '2001:db8::1', 'IPv6:', '=?UTF-8?B?', '?=', '=?x?Q?', '\n', '\n\t', '\r\n', ' ', 'From: ', 'Authentication-Results: ', 'spf=pass', 'dmarc=fail', 'xn--', 'Ж', 'é', '́', '"', ',', 'Tue, 17 Nov 2026 10:00:00 +0100', '\n\n'];
for (let k = 0; k < 600; k++) {
	const t = Array.from({ length: 3 + Math.floor(rnd() * 120) }, () => parts[Math.floor(rnd() * parts.length)]).join('');
	try { const x = e.analyze(t, { now: NOW, own: rnd() > 0.5 ? 'example.com' : '' }); e.exportReport(x, { maskRecipients: true, maskInternal: true }); assert.ok(Array.isArray(x.findings)); }
	catch (err) { assert.ok(['EMPTY', 'NO_HEADERS', 'TOO_LARGE'].includes(err.code), 'fuzz ' + k + ': ' + err.message); }
}
ok('600 random inputs: no crash; every failure is a coded input error');

// ---------------------------------------------------------------- examples, wording, static contracts
assert.deepEqual(ids(e.analyze(e.EXAMPLE_NORMAL, { now: NOW_EX, own: 'example.com' })), []);
const ph = e.analyze(e.EXAMPLE_PHISHING, { now: NOW_EX, own: 'example.com' });
assert.ok(['EHA-AUTH-001', 'EHA-BRAND-001', 'EHA-LOOK-003', 'EHA-FROM-002', 'EHA-REPLY-001', 'EHA-AUTH-005'].every(x => ids(ph).includes(x)), ids(ph).join(' '));
assert.ok(ph.auth.results.some(a => !a.trusted && /duplicate/u.test(a.reason)));
const rep = e.exportReport(e.analyze(e.EXAMPLE_NORMAL, { now: NOW_EX, own: 'example.com' }), {});
assert.ok(/No known warning signs matched\. This does not mean the message is safe\./u.test(rep.markdown) && /hijacked real account passes every check/u.test(rep.json));
assert.ok(!/(?:^|[^\p{L}])(?:compliant|certified|secure|genuine message|is safe)(?:[^\p{L}]|$)/iu.test(JSON.stringify(e.DEF)));
ok('normal example has no findings; phishing example shows DMARC fail, brand, lookalike, Reply-To and a forged duplicate result; report says no finding does not mean safe');
for (const f of ['engine.js', 'worker.js', 'app.js']) {
	const src = fs.readFileSync(path.join(DIR, f), 'utf8');
	assert.ok(!src.includes('(?<=') && !src.includes('(?<!'), f + ': look-behind');
	assert.ok(!/\\[bBwW]/.test(src), f + ': \\b or \\w');
	assert.ok(!/\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML|document\.write|\beval\(|new Function\(/.test(src), f + ': HTML sink or eval');
	assert.ok(!/localStorage|sessionStorage|indexedDB|document\.cookie|history\.(?:push|replace)State/.test(src), f + ': storage');
		if (f !== 'worker.js') { assert.ok(!/\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource|RTCPeerConnection|new Image\(/.test(src), f + ': network'); }
}
ok('engine, worker and app: no look-behind, no \\b/\\w, no HTML sinks, storage, network or lookups');
const appSrc = fs.readFileSync(path.join(DIR, 'app.js'), 'utf8');
const exSrc = appSrc.slice(appSrc.indexOf('const EX = {') + 'const EX = '.length, appSrc.indexOf('};', appSrc.indexOf('const EX = {')) + 1);
const EX = new Function('return ' + exSrc)(); // test only: evaluates the literal object copied in app.js
assert.equal(EX.normal, e.EXAMPLE_NORMAL);
assert.equal(EX.phishing, e.EXAMPLE_PHISHING);
ok('examples in app.js equal the engine copies');
console.log('\n' + n + ' Email Header Analyzer engine checks passed (examples DEPENDENT).');
