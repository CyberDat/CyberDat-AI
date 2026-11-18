/*
 * Container hardening audit engine: hang protection (YAML size, depth, anchors, time), Helm refusal, fuzzed input never
 * crashes, secrets masked (including unrecognised long values), several files, examples, report wording and static contracts.
 * Examples here are DEPENDENT.
 *   node tests/container-hardening-audit-engine.test.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const DIR = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/container-hardening-audit');
const e = require(path.join(DIR, 'engine.js'));
let n = 0;
const ok = l => { n++; console.log('PASS: ' + l); };
const ids = r => [...new Set(r.findings.map(f => f.id))].sort();

// ---------------------------------------------------------------- catalogue frozen; examples give the documented findings
const frozen = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/container-hardening-audit/rules.json'), 'utf8'));
const all = frozen.dockerfile.concat(frozen.compose, frozen.kubernetes);
for (const r of all) { assert.ok(e.DEF[r.id], r.id); assert.equal(e.DEF[r.id][0], r.severity, r.id); }
assert.equal(Object.keys(e.DEF).length, all.length);
assert.deepEqual(ids(e.audit(e.EXAMPLE_DOCKERFILE, { name: 'Dockerfile' })), ['DF-HYG-002', 'DF-HYG-003', 'DF-PIPE-001', 'DF-TAG-001', 'DF-USER-001']);
assert.deepEqual(ids(e.audit(e.EXAMPLE_COMPOSE, {})), ['DC-CAP-002', 'DC-ESC-001', 'DC-HYG-002', 'DC-PRIV-001', 'DC-RES-001', 'DC-RO-001', 'DC-SEC-001', 'DC-SOCK-001', 'DC-TAG-002', 'DC-USER-002']);
assert.ok(e.audit(e.EXAMPLE_COMPOSE, {}).findings.every(f => f.container === 'agent'), 'the hardened web service in the example has no findings');
assert.deepEqual(ids(e.audit(e.EXAMPLE_KUBERNETES, {})), ['K8S-APPARMOR-001', 'K8S-CAP-002', 'K8S-ESC-001', 'K8S-PROBE-001', 'K8S-PROBE-002', 'K8S-RBAC-002', 'K8S-RES-001', 'K8S-RO-001', 'K8S-SA-001', 'K8S-SA-002', 'K8S-SECCOMP-001', 'K8S-USER-002']);
for (const f of e.audit(e.EXAMPLE_KUBERNETES, {}).findings) { assert.ok(f.file && f.document >= 1 && f.line > 0 && f.severity && f.explanation && f.fix, f.id + ' fields'); }
ok('finding ids and severities equal the frozen catalogue (' + all.length + '); examples give the documented findings, each with file, document, line, severity, explanation and fix');

// ---------------------------------------------------------------- hang protection and input errors
const time = f => { const t = performance.now(); f(); return performance.now() - t; };
const deep = 'apiVersion: v1\nkind: Pod\nmetadata:\n' + Array.from({ length: 80 }, (_, i) => ' '.repeat(2 + i * 2) + 'k' + i + ':\n').join('');
assert.equal(e.audit(deep, {}).error.code, 'INPUT-YAML');
assert.equal(e.audit('apiVersion: v1\nkind: Pod\nmetadata: ' + '['.repeat(100) + ']'.repeat(100) + '\n', {}).error.code, 'INPUT-YAML');
assert.equal(e.audit('a: &a ["x","x"]\nb: &b [*a,*a]\nc: [*b,*b]\nservices: {}\n', {}).error.code, 'INPUT-ANCHOR');
assert.throws(() => e.audit('x'.repeat(e.MAX_INPUT_CHARS + 1)), err => err.code === 'TOO_LARGE');
assert.throws(() => e.auditFiles(Array.from({ length: 21 }, () => ({ text: 'FROM a:1' }))), err => err.code === 'TOO_MANY');
const helm = e.audit('apiVersion: v1\nkind: Service\nmetadata:\n  name: {{ .Release.Name }}\n', { kind: 'kubernetes' });
assert.ok(helm.error.code === 'INPUT-HELM' && helm.error.line === 4 && /Helm template/u.test(helm.error.message));
const many = Array.from({ length: 300 }, (_, i) => 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app' + i + '\nspec:\n  template:\n    spec:\n      containers:\n        - name: c' + i + '\n          image: nginx:latest\n          env:\n            - name: GREETING\n              value: "Größe ' + i + '"\n').join('---\n');
let r;
const ms = time(() => { r = e.audit(many, { name: 'many.yaml' }); });
assert.ok(r.objects === 300 && r.documents === 300 && ms < 5000, ms);
const msLong = time(() => e.audit('FROM a:1\nRUN echo ' + 'a'.repeat(900000) + '\n', {}));
assert.ok(msLong < 5000, msLong);
ok('hang protection: 80-level nesting and deep flow lists refused, anchors refused, size and file limits, Helm refused with line; 300 documents in ' + Math.round(ms) + ' ms; a 900,000-character RUN in ' + Math.round(msLong) + ' ms');

// ---------------------------------------------------------------- fuzz
let seed = 11;
const rnd = () => { seed = (seed * 1103515245 + 12345) >>> 0; return seed / 4294967296; };
const alphabet = ['FROM ', 'RUN ', 'USER ', 'ENV ', 'curl ', '| sh', 'services:', '  web:', '    image: ', 'apiVersion: v1', 'kind: Pod', 'spec:', '  containers:', '  - name: x', '\n', '  ', '- ', ': ', '"', '\'', '[', ']', '{', '}', '&a', '*a', '#', '\\', '---', 'é', 'Ж', '\u0301', 'privileged: true', 'hostPath:', 'path: /', '{{', '}}', '\t'];
for (let k = 0; k < 500; k++) {
	const text = Array.from({ length: 3 + Math.floor(rnd() * 90) }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join('');
	for (const kind of ['auto', 'dockerfile', 'compose', 'kubernetes']) {
		try { const x = e.audit(text, { kind }); assert.ok(Array.isArray(x.findings) && (x.error === null || /^INPUT-/u.test(x.error.code)), 'fuzz ' + k); } catch (err) { assert.ok(['EMPTY', 'TOO_LARGE'].includes(err.code), kind + ' crash on fuzz ' + k + ': ' + err.message); }
	}
}
ok('500 random inputs x 4 types: no crash; every problem is a coded input error');

// ---------------------------------------------------------------- secrets, several files, report
const tok = S.GITHUB_PAT, opaque = S.OPAQUE_LONG;
const files = [
	{ name: 'Dockerfile', text: 'FROM python:3.12\nARG DEPLOY_KEY=' + tok + '\nRUN curl -H "Authorization: Bearer ' + opaque + '" https://api.example.com/x -o /tmp/x\nUSER 1000\nHEALTHCHECK NONE\n' },
	{ name: 'compose.yaml', text: 'services:\n  a:\n    image: a:1\n    environment:\n      - NOTE=' + opaque + '\n' },
	{ name: 'k8s.yaml', text: 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  token: ' + Buffer.from(tok).toString('base64') + '\n' }
];
const res = e.auditFiles(files);
const rep = e.exportReport(res, { timestamp: '2026-11-18T00:00:00Z' });
const blob = JSON.stringify(res) + rep.json + rep.markdown;
for (const v of [tok, opaque, Buffer.from(tok).toString('base64')]) { assert.ok(!blob.includes(v), 'secret shown'); }
assert.deepEqual(res.files.map(ids), [['DF-SEC-001'], ['DC-CAP-002', 'DC-ESC-001', 'DC-HYG-002', 'DC-RES-001', 'DC-RO-001', 'DC-SEC-001', 'DC-USER-002'], ['K8S-SEC-002']]);
ok('three files at once; a token in ARG, an unrecognised long value in RUN and environment, and Secret data are reported masked; never in findings or reports');
assert.ok(/not a complete audit/u.test(rep.markdown) && /no findings does not mean a configuration is safe/u.test(rep.markdown) && /Nothing was changed/u.test(rep.json));
assert.ok(!/(?:^|[^\p{L}])(?:compliant|certified|secure)(?:[^\p{L}]|$)/iu.test(rep.json + rep.markdown + JSON.stringify(e.DEF)));
assert.ok(!/CIS[ -]?[0-9]|[0-9]+\.[0-9]+\.[0-9]+ Ensure/u.test(fs.readFileSync(path.join(DIR, 'engine.js'), 'utf8')));
assert.ok(/- \[ \] \*\*HIGH\*\* DF-SEC-001/u.test(rep.markdown) && /### Hygiene \(info\)/u.test(rep.markdown));
ok('checklist states that it is not a complete audit and changes nothing; no "compliant", "certified" or "secure"; no CIS numbering; Markdown checkboxes; hygiene grouped');

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
assert.equal(EX.dockerfile, e.EXAMPLE_DOCKERFILE);
assert.equal(EX.compose, e.EXAMPLE_COMPOSE);
assert.equal(EX.kubernetes, e.EXAMPLE_KUBERNETES);
ok('examples in app.js equal the engine copies');
console.log('\n' + n + ' container audit engine checks passed (examples DEPENDENT).');
