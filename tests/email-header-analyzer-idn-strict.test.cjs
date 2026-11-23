/*
 * Email Header Analyzer, ruleset 2026-11-23.1 — strict punycode (found while setting up CI: on Node 24.22 the engine's
 * toUnicode turned the invalid label xn--already into control characters; Node 24.14.1 hid it in the engine test).
 * A label that is not valid punycode is never turned into Unicode: it stays in ASCII and EHA-LOOK-001 names it as
 * invalid; EHA-LOOK-002 neither fails nor passes such a label silently. Valid IDN domains decode as before.
 * The engine has its own decoder (no URL / domainToUnicode of the runtime); the browser regression runs the same checks
 * in Edge, Firefox and WebKit. Synthetic headers only: example.* domains, documentation addresses.
 * Run: node tests/email-header-analyzer-idn-strict.test.cjs
 */
'use strict';
const path = require('path');
const fs = require('fs');
const { domainToUnicode } = require('url');
const DIR = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/email-header-analyzer');
const E = require(path.join(DIR, 'engine.js'));
E.loadPSL(fs.readFileSync(path.join(DIR, 'public_suffix_list.dat'), 'utf8').split(String.fromCharCode(13)).join(''), { source: 'test', license: 'MPL-2.0' });
const NOW = '2026-11-23T12:00:00Z';
let failed = 0, n = 0;
const check = (ok, msg) => { n++; console.log((ok ? 'PASS: ' : 'FAIL: ') + msg); if (!ok) { failed++; } };
// control, format (zero-width, bidi), private use, surrogates, separators other than the plain space
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}\u00a0\u2000-\u200f\u2028-\u202f\u205f\u3000\ufeff]/u;
const strings = (v, out) => { if (typeof v === 'string') { out.push(v); } else if (v && typeof v === 'object') { for (const k of Object.keys(v)) { strings(v[k], out); } } return out; };
const clean = r => !strings(r, []).some(s => INVISIBLE.test(s.replace(/[\r\n\t]/gu, '')));
const msg = (from, extra) => ['Return-Path: <' + ((extra && extra.rp) || 'bounce@mail.example.org') + '>', 'From: Sender <' + from + '>'].concat(extra && extra.reply ? ['Reply-To: <' + extra.reply + '>'] : [], ['To: user1@example.com', 'Subject: Notice', 'Date: Mon, 23 Nov 2026 10:00:00 +0000', 'Message-ID: <1@mail.example.org>']).join('\r\n') + '\r\n\r\nbody\r\n';
const look = r => r.findings.filter(f => /^EHA-LOOK-00[12]$/u.test(f.id));

// invalid labels: decoding gives code points U+0080..U+009F (xn--already), truncated labels, invalid code points
const INVALID = [
	['xn--already (decodes to C1 controls)', 'xn--already'],
	['truncated: xn--mnchen-3y', 'xn--mnchen-3y'],
	['truncated: xn--bcher-kv', 'xn--bcher-kv'],
	['lone surrogate code point', 'xn--' + E.punyEncode('a\ud800b')],
	['C1 control U+0085', 'xn--' + E.punyEncode('a\u0085b')],
	['zero-width joiner U+200D', 'xn--' + E.punyEncode('a\u200db')],
	['right-to-left override U+202E', 'xn--' + E.punyEncode('pay\u202epal')],
	['noncharacter U+FFFF', 'xn--' + E.punyEncode('a\uffffb')],
	['upper-case letter (no round trip)', 'xn--' + E.punyEncode('Äx')],
	['all-ASCII result', 'xn--abc-'],
	['empty', 'xn--'],
	['digit outside the alphabet', 'xn--99999999999999999999'],
];
for (const [label, l] of INVALID) {
	const d = l + '.example';
	const x = E.idnInfo(d);
	check(x.unicode === d && x.invalid.length === 1 && x.invalid[0] === l && E.toUnicode(d) === d && !INVISIBLE.test(x.unicode), 'invalid label stays in ASCII and is listed: ' + label);
	let r = null, err = null;
	try { r = E.analyze(msg('alerts@' + d), { now: NOW }); } catch (e) { err = e; }
	check(!err && r && clean(r), 'analysis does not fail and has no control or invisible characters: ' + label);
	const lk = r ? look(r) : [];
	const l1 = lk.find(f => f.id === 'EHA-LOOK-001');
	check(!!l1 && l1.evidence.includes('invalid punycode label ' + l) && l1.evidence.includes('not decoded, shown in ASCII') && !lk.some(f => f.id === 'EHA-LOOK-002'),
		'EHA-LOOK-001 names the invalid label, no false alphabet mix: ' + label);
}
// the same labels in Reply-To and Return-Path
{
	const r = E.analyze(msg('a@xn--mnchen-3ya.example', { reply: 'b@xn--already.example', rp: 'c@xn--bcher-kv.example' }), { now: NOW });
	const l1 = r.findings.find(f => f.id === 'EHA-LOOK-001');
	check(clean(r) && l1 && l1.evidence.includes('xn--mnchen-3ya.example = münchen.example') && l1.evidence.includes('invalid punycode label xn--already') && l1.evidence.includes('invalid punycode label xn--bcher-kv'),
		'From valid, Reply-To and Return-Path invalid: every punycode domain listed, the invalid ones named');
	check(r.summary === undefined || clean(r.summary), 'summary has no control characters');
}
// a mixed-alphabet label is still found when another label of the domain is invalid
{
	const mixed = E.toASCII('pаypal');
	const r = E.analyze(msg('a@' + mixed + '.xn--already.example'), { now: NOW });
	check(clean(r) && r.findings.some(f => f.id === 'EHA-LOOK-002') && r.findings.find(f => f.id === 'EHA-LOOK-001').evidence.includes('invalid punycode label xn--already'), 'mixed alphabets in a valid label still give EHA-LOOK-002 next to an invalid label');
}

// valid IDN domains decode as before (Cyrillic, umlauts, Greek, CJK) and equal the runtime's domainToUnicode
const VALID = ['пример.рф', 'münchen.de', 'bäckerei-müller.example', 'bücher.example', 'αpple-id.example', '例え.テスト', 'pаypal.example'];
for (const u of VALID) {
	const a = E.toASCII(u);
	const x = E.idnInfo(a);
	check(x.unicode === u.normalize('NFC') && !x.invalid.length && x.unicode === domainToUnicode(a), 'valid IDN decodes as before: ' + u + ' (' + a + ')');
}
{
	const r = E.analyze(msg('a@' + E.toASCII('münchen.de')), { now: NOW });
	const l1 = r.findings.find(f => f.id === 'EHA-LOOK-001');
	check(l1 && l1.evidence === 'xn--mnchen-3ya.de = münchen.de' && !r.findings.some(f => f.id === 'EHA-LOOK-002'), 'valid IDN sender: EHA-LOOK-001 evidence unchanged ("xn--… = münchen.de")');
	const r2 = E.analyze(msg('a@' + E.toASCII('pаypal.example')), { now: NOW });
	check(r2.findings.some(f => f.id === 'EHA-LOOK-002'), 'valid mixed-alphabet domain: EHA-LOOK-002 as before');
}
// round trip of random valid labels; ruleset raised
for (let k = 0; k < 300; k++) {
	const s = Array.from({ length: 1 + (k % 9) }, (_, j) => String.fromCodePoint([0x61, 0xe4, 0x436, 0x3b1, 0x4e2d, 0x30c6, 0x1f600][(k + j * 3) % 7])).join('');
	if (/^[a-z]+$/u.test(s)) { continue; }
	const a = 'xn--' + E.punyEncode(s);
	if (E.toUnicode(a) !== s) { check(false, 'round trip ' + a); break; }
}
check(true, 'round trip of 300 generated labels unchanged');
check(E.RULESET === '2026-11-23.1', 'ruleset 2026-11-23.1');

console.log(failed ? 'FAIL: ' + failed + ' of ' + n + ' checks' : '\nPASS: Email Header Analyzer strict punycode (' + n + ' checks, Node ' + process.version + ')');
process.exitCode = failed ? 1 : 0;
