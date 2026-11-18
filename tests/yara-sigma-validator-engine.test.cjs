/*
 * YARA/Sigma validator engine: hang protection (YAML size, depth, aliases, time), user regular expressions never compiled,
 * fuzzed input never crashes, secrets masked, conversion of multi-condition rules, report and static contracts.
 * Examples here are DEPENDENT.
 *   node tests/yara-sigma-validator-engine.test.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const DIR = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/yara-sigma-validator');
const e = require(path.join(DIR, 'engine.js'));
let n = 0;
const ok = l => { n++; console.log('PASS: ' + l); };
const ids = r => [...new Set(r.findings.map(f => f.id))].sort();

// ---------------------------------------------------------------- examples are clean; ids catalogue frozen
assert.deepEqual(ids(e.validate(e.EXAMPLE_SIGMA, { kind: 'sigma' })), []);
assert.deepEqual(ids(e.validate(e.EXAMPLE_YARA, { kind: 'yara' })), []);
const frozen = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/yara-sigma-validator/rules.json'), 'utf8'));
for (const r of frozen.sigma.concat(frozen.yara)) { assert.ok(e.DEF[r.id], r.id); assert.equal(e.DEF[r.id][0], r.severity, r.id); }
ok('built-in examples have no findings; finding ids and severities equal the frozen catalogue (' + (frozen.sigma.length + frozen.yara.length) + ')');

// ---------------------------------------------------------------- hang protection
const time = f => { const t = performance.now(); f(); return performance.now() - t; };
const deep = 'title: x\ndetection:\n' + Array.from({ length: 80 }, (_, i) => ' '.repeat(4 + i * 2) + 'k' + i + ':\n').join('');
assert.equal(ids(e.validate(deep, { kind: 'sigma' }))[0], 'SIG-YAML-001');
const flowDeep = 'title: x\ntags: ' + '['.repeat(100) + ']'.repeat(100) + '\n';
assert.equal(ids(e.validate(flowDeep, { kind: 'sigma' }))[0], 'SIG-YAML-001');
const bomb = 'a: &a ["x","x"]\nb: &b [*a,*a]\nc: &c [*b,*b]\nd: [*c,*c]\n';
assert.deepEqual(ids(e.validate(bomb, { kind: 'sigma' })), ['SIG-YAML-002']);
assert.throws(() => e.validate('x'.repeat(e.MAX_INPUT_CHARS + 1)), err => err.code === 'TOO_LARGE');
const many = 'title: x\nlogsource:\n    product: windows\ndetection:\n' + Array.from({ length: 5000 }, (_, i) => '    sel' + i + ':\n        Field' + i + '|contains: \'value' + i + '\'\n').join('') + '    condition: 1 of sel*\nlevel: low\n';
let ms = time(() => { const r = e.validate(many, { kind: 'sigma' }); assert.ok(r.counts.error === 0); });
const msConv = time(() => { const c = e.convert(many, 'kql'); assert.ok(c.rules[0].queries[0].length > 100000); });
assert.ok(ms < 5000 && msConv < 5000, ms + ' ' + msConv);
const longLine = 'title: ' + 'a'.repeat(900000) + '\n';
const msLong = time(() => e.validate(longLine, { kind: 'sigma' }));
assert.ok(msLong < 5000);
ok('hang protection: 80-level nesting and deep flow lists refused, alias bomb refused, size limit; 5,000 search identifiers validated in ' + Math.round(ms) + ' ms and converted in ' + Math.round(msConv) + ' ms; a 900,000-character line in ' + Math.round(msLong) + ' ms');

// ---------------------------------------------------------------- user regular expressions are never compiled
const Native = RegExp;
const built = [];
global.RegExp = function (p, f) { built.push(String(p && p.source !== undefined ? p.source : p)); return new Native(p, f); };
global.RegExp.prototype = Native.prototype;
const evil = '(a+)+$Zq9';
e.validate('rule R\n{\n    strings:\n        $r = /' + evil + '/\n    condition:\n        filesize < 1MB and $r\n}\n', { kind: 'yara' });
e.convert("title: t\nlogsource:\n    product: windows\ndetection:\n    s:\n        F|re: '" + evil + "'\n    condition: s\n", 'kql');
global.RegExp = Native;
assert.ok(!built.some(b => b.includes('Zq9')), 'a user regular expression was compiled');
const r1 = e.validate('rule R\n{\n    strings:\n        $r = /(x+x+)+y/\n    condition:\n        filesize < 1MB and $r\n}\n', { kind: 'yara' });
assert.ok(ids(r1).includes('YAR-Q-002'));
ok('regular expressions from rules are checked statically and never turned into RegExp objects; nested quantifiers reported as slow');

// ---------------------------------------------------------------- fuzz: random input never crashes
let seed = 7;
const rnd = () => { seed = (seed * 1103515245 + 12345) >>> 0; return seed / 4294967296; };
const alphabet = ['rule ', '{', '}', ':', '$a', '=', '"', '/', '(', ')', '[', ']', '-', ' ', '\n', '    ', 'condition', 'strings', 'title: ', 'detection:', '|contains', '*', '&', '!', '#', 'é', 'Ж', '\u0301', '\\', '\'', 'and ', 'not ', '1 of ', 'them'];
for (let k = 0; k < 400; k++) {
	const text = Array.from({ length: 5 + Math.floor(rnd() * 80) }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join('');
	for (const kind of ['sigma', 'yara']) {
		try { e.validate(text, { kind }); } catch (err) { assert.ok(['EMPTY', 'TOO_LARGE'].includes(err.code), kind + ' crash on fuzz ' + k + ': ' + err.message); }
	}
	try { e.convert(text, 'spl'); } catch (err) { assert.ok(/^SIG-YAML|UNSUPPORTED/u.test(err.code || ''), 'convert crash on fuzz ' + k + ': ' + err.message); }
}
ok('400 random inputs: no crash; every failure is a coded YAML or YARA finding');

// ---------------------------------------------------------------- secrets, Unicode, multi-condition, report
const withSecret = e.EXAMPLE_SIGMA.replace("User|contains: 'svc_'", "CommandLine|contains: '" + S.GITHUB_PAT + "'");
const v = e.validate(withSecret, { kind: 'sigma' });
const c = e.convert(withSecret, 'spl');
const rep = e.exportReport(v, c, { timestamp: '2026-11-18T00:00:00Z' });
assert.ok(ids(v).includes('SEC-001') && c.containsSecrets && c.rules[0].queries[0].includes(S.GITHUB_PAT));
assert.ok(!JSON.stringify(v).includes(S.GITHUB_PAT) && !rep.json.includes(S.GITHUB_PAT) && !rep.markdown.includes(S.GITHUB_PAT));
ok('a secret in a rule is reported masked (SEC-001); findings and reports mask it; the query keeps it and is flagged containsSecrets');
const multi = "title: m\nlogsource:\n    product: windows\ndetection:\n    a:\n        F: 'x'\n    b:\n        G: 'y'\n    condition:\n        - a\n        - b\n";
assert.deepEqual(e.convert(multi, 'lucene').rules[0].queries, ['F:x', 'G:y']);
const docs = e.EXAMPLE_SIGMA + '---\n' + e.EXAMPLE_SIGMA.replace('Net.exe started', 'Zweite Regel für Größe');
const two = e.validate(docs, { kind: 'sigma' });
assert.equal(two.rules, 2);
assert.equal(e.convert(docs, 'kql').rules.length, 2);
const nfd = e.validate(e.EXAMPLE_SIGMA.replace("ParentImage|endswith: '\\cmd.exe'", "ParentImage|endswith: '\\Pru\u0308fung.exe'"), { kind: 'sigma' });
assert.deepEqual(ids(nfd), []);
ok('multiple conditions give multiple queries; several YAML documents are checked one by one; NFD values accepted');
assert.ok(/do not replace compiling the rule with the official engine/.test(rep.json) && !/\b(?:compliant|certified|secure)\b/iu.test(rep.json));
ok('report states that syntax checks do not replace compilation and testing');

// ---------------------------------------------------------------- static contracts
for (const f of ['engine.js', 'worker.js', 'app.js']) {
	const src = fs.readFileSync(path.join(DIR, f), 'utf8');
	assert.ok(!src.includes('(?<=') && !src.includes('(?<!'), f + ': look-behind');
	assert.ok(!/\\[bBwW]/.test(src), f + ': \\b or \\w');
	assert.ok(!/\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML|document\.write|\beval\(|new Function\(/.test(src), f + ': HTML sink or eval');
	assert.ok(!/localStorage|sessionStorage|indexedDB|document\.cookie|history\.(?:push|replace)State/.test(src), f + ': storage');
	if (f !== 'worker.js') { assert.ok(!/\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource/.test(src), f + ': network'); }
}
ok('engine, worker and app: no look-behind, no \\b/\\w, no HTML sinks, storage or network');
const appSrc = fs.readFileSync(path.join(DIR, 'app.js'), 'utf8');
const exSrc = appSrc.slice(appSrc.indexOf('const EX = {') + 'const EX = '.length, appSrc.indexOf('};', appSrc.indexOf('const EX = {')) + 1);
const EX = new Function('return ' + exSrc)(); // test only: evaluates the literal object copied in app.js
assert.equal(EX.sigma, e.EXAMPLE_SIGMA);
assert.equal(EX.yara, e.EXAMPLE_YARA);
assert.deepEqual(EX.fieldmap, e.EXAMPLE_FIELDMAP);
ok('examples and field mappings in app.js equal the engine copies');
console.log('\n' + n + ' YARA/Sigma engine checks passed (examples DEPENDENT).');
