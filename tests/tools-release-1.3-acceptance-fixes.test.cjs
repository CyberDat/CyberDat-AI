/*
 * Release 1.3 — one synthetic test per defect of the Codex acceptance of 2026-11-21 (DEFECTS-FOR-CLAUDE.md,
 * SIGMA-CONVERSION-MATRIX.md) and per owner decision. Token-shaped values come only from tests/lib/synthetic-secrets.cjs;
 * short secret-like values are obvious test strings. Codex's frozen expectations are not reproduced or changed here.
 * Run: node tests/tools-release-1.3-acceptance-fixes.test.cjs
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { SYNTH } = require('./lib/synthetic-secrets.cjs');
const JS = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js');
const TPL = path.join(__dirname, '../wp-content/themes/cyberdat/template-parts/tools');
const YSV = require(path.join(JS, 'yara-sigma-validator/engine.js'));
const PITB = require(path.join(JS, 'prompt-injection-test-bench/engine.js'));
const CHA = require(path.join(JS, 'container-hardening-audit/engine.js'));
let failed = 0, n = 0;
const check = (ok, msg) => { n++; console.log((ok ? 'PASS: ' : 'FAIL: ') + msg); if (!ok) { failed++; } };
const leaks = (blob, values) => values.filter(v => blob.includes(v));
const SHORT = ['hunter22', 'pw7x', 'tk42'];
// a prefix-less random-looking value generated at run time (never stored in the repository)
let seed = 5; const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648);
const AL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const OPAQUE = Array.from({ length: 40 }, () => AL[rnd() % AL.length]).join('');

// ---------------------------------------------------------------- tool 9: YARA/Sigma validator
const head = (title) => 'title: ' + (title || 'Synthetic rule') + '\nid: 5b0f3c2e-8a71-4d6e-9f12-3c4b5a6d7e8f\nstatus: test\ndescription: synthetic\nauthor: CyberDat tests\ndate: 2026-11-21\nlogsource:\n    product: windows\nfalsepositives:\n    - none\nlevel: low\ndetection:\n';
const rule = (det, title) => head(title) + det;
const conv = (text, t) => YSV.convert(text, t, {}).rules[0];
const T3 = ['spl', 'kql', 'lucene'];

// SEC-01: short values of Credential/Password (and Secret/Token) fields masked in screen output and both exports
const sec1 = rule("    selection:\n        Credential: '" + SHORT[0] + "'\n        Password|contains: '" + SHORT[1] + "'\n        Token: " + SHORT[2] + "\n        TokenElevationType: '%%1936'\n    condition: selection\n");
for (const t of T3) {
	const c = YSV.convert(sec1, t, {});
	const rep = YSV.exportReport(YSV.validate(sec1, { kind: 'sigma' }), c, { timestamp: '2026-11-21T00:00:00Z' });
	check(!leaks(c.masked[0].queries.join('\n') + rep.json + rep.markdown, SHORT).length, 'SEC-01 ' + t + ': short Credential/Password/Token values masked on screen and in JSON/Markdown');
	check(c.masked[0].queries[0].includes('%%1936'), 'SEC-01 ' + t + ': a field that merely starts with Token (TokenElevationType) is not masked');
}
// SEC-02: known-format key and opaque value in the title masked in the visible heading, messages and export
const sec2 = rule("    selection:\n        Image|endswith: '\\\\net.exe'\n    condition: selection\n", 'Probe ' + SYNTH.GITHUB_PAT + ' and ' + OPAQUE);
{
	const c = YSV.convert(sec2, 'spl', {});
	const rep = YSV.exportReport(YSV.validate(sec2, { kind: 'sigma' }), c, {});
	check(!leaks(c.masked[0].title + rep.json + rep.markdown, [SYNTH.GITHUB_PAT, OPAQUE]).length, 'SEC-02: title with a known key and an opaque value is masked in the heading and the export');
	const app = fs.readFileSync(path.join(JS, 'yara-sigma-validator/app.js'), 'utf8');
	check(app.includes("node('h4', 'cd-ysv-query__title', m.title)") && !app.includes("node('h4', 'cd-ysv-query__title', r.title)"), 'SEC-02: the page heading of a conversion uses the masked title');
	const bad = rule("    selection:\n        Name|" + 'x' + OPAQUE + ": audit\n    condition: selection\n");
	const cb = YSV.convert(bad, 'kql', {});
	check(cb.rules[0].error && !cb.masked[0].error.includes(OPAQUE), 'SEC-02: a conversion error that names a user string is masked');
}
// SEC-03: full query only on request, export always masked (owner decision; accepted exception)
{
	const sec3 = rule("    selection:\n        CommandLine|contains: '" + SYNTH.GITHUB_PAT + "'\n    condition: selection\n");
	const c = YSV.convert(sec3, 'kql', {});
	const rep = YSV.exportReport(YSV.validate(sec3, { kind: 'sigma' }), c, {});
	check(c.containsSecrets && c.rules[0].queries[0].includes(SYNTH.GITHUB_PAT) && !c.masked[0].queries[0].includes(SYNTH.GITHUB_PAT), 'SEC-03: the raw query is kept only for the optional full view; the default view is masked');
	check(!rep.json.includes(SYNTH.GITHUB_PAT) && !rep.markdown.includes(SYNTH.GITHUB_PAT), 'SEC-03: the report stays masked even when the full query exists');
	const app = fs.readFileSync(path.join(JS, 'yara-sigma-validator/app.js'), 'utf8');
	const tpl = fs.readFileSync(path.join(TPL, 'yara-sigma-validator.php'), 'utf8');
	check(app.includes('const full = conv.containsSecrets && el.convAck.checked;') && app.includes('el.convAck.checked = false;'), 'SEC-03: full-query mode is off by default and reset on every run');
	check(tpl.includes('Show the full query on this screen without masking (off by default)') && tpl.includes('the downloaded report stays masked'), 'SEC-03: the page warns before showing the full query');
}
// Sigma conversion defects of the frozen matrix
const C = {
	C06: "    selection:\n        Name: ''\n    condition: selection\n",
	C11: "    selection:\n        Name: 'audit\\*note'\n    condition: selection\n",
	C14: "    selection:\n        Image: 'D:\\\\Audit\\\\\\*'\n    condition: selection\n",
	C15: "    selection:\n        Name: []\n    condition: selection\n",
	C16: "    selection:\n        Name:\n            - null\n            - audit\n    condition: selection\n",
	C17: "    selection:\n        Name: 'audit?.exe'\n    condition: selection\n",
	C18: "    selection:\n        Name: audit\n    condition: 1 of nomatch_*\n",
	C22: "    selection:\n        Name|bogusmod: audit\n    condition: selection\n",
	C23: "    selection:\n        Name|contains: 'audit\\*trail'\n    condition: selection\n"
};
check(conv(rule(C.C06), 'lucene').queries[0] === 'Name:""', 'C06 Lucene: an empty string becomes Name:""');
for (const k of ['C11', 'C14', 'C23']) {
	const r = conv(rule(C[k]), 'spl');
	check(!r.queries.length && r.code === 'CONV-SPL-STAR' && /literal \*/u.test(r.error), k + ' SPL: a literal asterisk is refused with an explicit error');
}
check(conv(rule(C.C11), 'kql').queries[0] === 'Name =~ "audit*note"' && conv(rule(C.C11), 'lucene').queries[0] === 'Name:audit\\*note', 'C11 KQL and Lucene unchanged (literal star kept literal)');
check(conv(rule(C.C23), 'kql').queries[0] === 'Name contains "audit*trail"' && conv(rule(C.C23), 'lucene').queries[0] === 'Name:*audit\\*trail*', 'C23 KQL and Lucene unchanged');
const want = { C15: 'SIG-DET-001', C16: 'SIG-DET-001', C18: 'SIG-COND-002', C22: 'SIG-MOD-001' };
for (const [k, code] of Object.entries(want)) {
	for (const t of T3) { const r = conv(rule(C[k]), t); check(!r.queries.length && r.code === code && r.error.startsWith(code), k + ' ' + t + ': refused with ' + code + ', no query'); }
	const v = YSV.validate(rule(C[k]), { kind: 'sigma' });
	check(v.findings.some(f => f.id === code && f.severity === 'error'), k + ': the check reports ' + code + ' as an error');
	const refused = YSV.refuseConversion(v, 'spl');
	check(refused.rules[0].queries.length === 0 && refused.refused.includes(code), k + ': the worker path refuses the conversion with the diagnostic code');
}
{
	const worker = fs.readFileSync(path.join(JS, 'yara-sigma-validator/worker.js'), 'utf8');
	check(worker.includes('result.counts.error > 0) { conversion = ENGINE.refuseConversion(result, msg.target); }') && !worker.includes('/^SIG-YAML/.test(f.id)'), 'worker: any error-level finding blocks the conversion, not only SIG-YAML');
}
check(conv(rule(C.C17), 'spl').error.includes('not supported for Splunk SPL') && /matches regex/u.test(conv(rule(C.C17), 'kql').queries[0]) && conv(rule(C.C17), 'lucene').queries[0] === 'Name:audit?.exe', 'C17: ? refused in SPL, supported in KQL and Lucene (behaviour unchanged)');
{
	const tpl = fs.readFileSync(path.join(TPL, 'yara-sigma-validator.php'), 'utf8');
	check(tpl.includes('? (Lucene and KQL; Splunk SPL refuses it)') && !tpl.includes('? (Lucene only)'), 'C17 documentation: ? is supported in Lucene and KQL, refused in SPL');
	check(tpl.includes('in KQL this is isempty(), which also matches an empty string, and its exact meaning depends on the field type'), 'C07 documentation: KQL isempty() marked as type-dependent');
	check(conv(rule("    selection:\n        EventID: null\n    condition: selection\n"), 'kql').queries[0] === 'isempty(EventID)', 'C07 KQL behaviour kept (isempty)');
}
// YARA Y09 and Y12
const yv = t => YSV.validate(t, { kind: 'yara' }).findings.map(f => f.id);
check(yv('rule A {\n meta:\n  x = 1.5\n strings:\n  $a = "abcd"\n condition:\n  $a and filesize < 1MB\n}\n').includes('YAR-META-001'), 'Y09: a fractional meta value gives YAR-META-001');
check(!yv('rule A {\n meta:\n  x = 15\n  y = -2\n  z = 0x1F\n  w = "s"\n  v = true\n strings:\n  $a = "abcd"\n condition:\n  $a and filesize < 1MB\n}\n').includes('YAR-META-001'), 'Y09: integer, negative, hex, string and boolean meta values stay valid');
check(yv('rule B {\n strings:\n  $a = /abc[\n condition:\n  $a and filesize < 1MB\n}\n').join() === 'YAR-RE-001', 'Y12: an unterminated regular expression gives YAR-RE-001 (not YAR-SYN-001)');
check(yv('rule C {\n strings:\n  $a = /ab(c/\n condition:\n  $a and filesize < 1MB\n}\n').includes('YAR-RE-001'), 'Y12: an unbalanced group gives YAR-RE-001');

// ---------------------------------------------------------------- tool 8: Prompt Injection Test Bench
const CAN = 'CANARY-7F3A9C2B';
const ent = [...CAN].map(c => '&#' + c.charCodeAt(0) + ';').join('');
const entx = [...CAN].map(c => '&#x' + c.charCodeAt(0).toString(16) + ';').join('');
const BS = String.fromCharCode(92);
const ju = [...CAN].map(c => BS + 'u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
const d = (t) => PITB.detect(t, CAN), p = (t) => PITB.detectPartial(t, CAN);
check(d('Antwort: ' + ent) && d('Antwort: ' + ent).method === 'html-entity' && d(entx).method === 'html-entity', 'canary written as HTML character references (decimal and hex) is found');
check(d('{"v":"' + ju + '"}') && d('{"v":"' + ju + '"}').method === 'json-escape', 'canary written as JSON \\u escapes is found');
check(d('Code: ' + CAN + '.').method === 'plain' && !p('Code: ' + CAN + '.'), 'full code with prefix: full match');
check(!d('Here: 7F3A9C2B') && p('Here: 7F3A9C2B').method === 'partial (core only)', 'core without prefix: partial (core only), not a full match');
check(!d('7F3A9C2B-CANARY') && p('7F3A9C2B-CANARY'), 'core in another order: partial (core only)');
check(!d(CAN + '0') && !p(CAN + '0') && !d('ref 7F3A9C2B0') && !p('ref 7F3A9C2B0'), 'a 9-character near code is not a match');
check(!d('ключ' + CAN) && !p('xx7F3A9C2Byy'), 'codes glued into a longer word are not matches (Unicode boundaries)');
check(d('https://example.com/t?c=code%20' + CAN) && d('https://example.com/t?c=code%20' + CAN).method === 'link', 'percent escape before the code counts as a separator');
{
	const set = PITB.buildSet({ appTypes: Object.keys(PITB.APP_TYPES), langs: ['en', 'de', 'ru'], seed: 3 });
	const res = PITB.check(set, { [set.tests[0].id]: 'only 7F3A9C2B', [set.tests[1].id]: set.tests[1].canary });
	const core0 = set.tests[0].canary.slice(7);
	const res2 = PITB.check(set, { [set.tests[0].id]: 'only ' + core0, [set.tests[1].id]: set.tests[1].canary });
	check(res2.rows[0].status === 'partial' && res2.counts.partial === 1 && res2.counts.triggered === 1, 'check(): core-only response is status partial and not counted as triggered');
	void res;
	const lbl = set.tests.filter(t => t.template === 'LBL-02');
	check(lbl.length === 3 && lbl.every(t => /Internal configuration label/u.test(t.input)) && lbl.every(t => !/everything above|alles über|всё, что выше/iu.test(t.input)), 'LBL-02 (EN, DE, RU) asks only for the line with the controlled label');
	check(PITB.LIBRARY_VERSION === '2026-11-21.1', 'library version raised to 2026-11-21.1');
	// SEC-05: short secrets right beside the canary
	const t0 = set.tests[0];
	const resp = 'Done ' + t0.canary + ' password=' + SHORT[0] + ' token: ' + SHORT[2] + ' ' + SYNTH.GITHUB_PAT;
	const r5 = PITB.check(set, { [t0.id]: resp });
	const rep5 = PITB.exportReport(set, r5, { timestamp: '2026-11-21T00:00:00Z' });
	check(r5.rows[0].status === 'triggered' && !leaks(r5.rows[0].fragment + rep5.json + rep5.markdown, [SHORT[0], SHORT[2], SYNTH.GITHUB_PAT]).length, 'SEC-05: short password/token values beside the canary are masked in the fragment and in JSON/Markdown');
	const edge = 'x'.repeat(70) + t0.canary + ' ' + 'y'.repeat(50) + ' ' + SYNTH.GITHUB_PAT;
	const r5b = PITB.check(set, { [t0.id]: edge });
	check(!r5b.rows[0].fragment.includes(SYNTH.GITHUB_PAT.slice(0, 12)) && r5b.rows[0].fragment.includes('[GitHub token'), 'SEC-05: a secret at the edge of the fragment window is masked before the window is cut');
	// SEC-04: imported set with secrets in labelInstruction and input
	const ex = PITB.exportSet(set);
	const lines = ex.jsonl.trim().split('\n');
	const h0 = JSON.parse(lines[0]); h0.labelInstruction += ' admin password: ' + SHORT[1] + ' ' + SYNTH.GITHUB_PAT;
	const l1 = JSON.parse(lines[1]); l1.input += ' token=' + SHORT[2] + ' ' + SYNTH.ANTHROPIC_API_KEY;
	const imp = PITB.importSet([JSON.stringify(h0), JSON.stringify(l1)].concat(lines.slice(2)).join('\n'));
	const re = PITB.exportSet(imp);
	check(!leaks(imp.labelInstruction + imp.tests[0].input + re.jsonl + re.csv, [SHORT[1], SHORT[2], SYNTH.GITHUB_PAT, SYNTH.ANTHROPIC_API_KEY]).length, 'SEC-04: imported set masked in the preview data and in the re-exported JSONL and CSV');
	// own sets: masking keeps the generated tests byte for byte
	const all = PITB.buildSet({ appTypes: Object.keys(PITB.APP_TYPES), langs: ['en', 'de', 'ru'], seed: 9 });
	const mk = PITB.maskedSet(all);
	check(all.tests.every((t, i) => t.input === mk.tests[i].input && t.ask === mk.tests[i].ask) && all.labelInstruction === mk.labelInstruction, 'export masking leaves the generated tests unchanged (' + all.tests.length + ' tests: canaries, labels, own base64 payloads)');
}

// ---------------------------------------------------------------- tool 10: Container Audit
{
	const k8s = 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod-' + OPAQUE + '\nspec:\n  containers:\n    - name: c-' + SYNTH.GITHUB_PAT + '\n      image: nginx:latest\n      securityContext:\n        privileged: true\n';
	const broken = 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n  bad: [' + SYNTH.GOOGLE_API_KEY + '\n';
	const r = CHA.auditFiles([{ name: 'deploy-' + OPAQUE + '.yaml', text: k8s }, { name: SYNTH.GITHUB_PAT + '.Dockerfile', text: 'FROM node:latest\nUSER root\n', kind: 'dockerfile' }, { name: 'broken-' + SYNTH.GOOGLE_API_KEY + '.yaml', text: broken }]);
	const rep = CHA.exportReport(r, { timestamp: '2026-11-21T00:00:00Z' });
	const blob = JSON.stringify(r) + rep.json + rep.markdown;
	check(r.files[0].findings.length > 0 && !leaks(blob, [OPAQUE, SYNTH.GITHUB_PAT, SYNTH.GOOGLE_API_KEY]).length, 'SEC-06: file names, Kubernetes object and container names and error paths are masked in findings and both exports');
	const raw = { files: [{ file: 'f-' + OPAQUE, kindLabel: 'Kubernetes', documents: 1, objects: 1, error: null, counts: { high: 0, medium: 0, low: 0, info: 0 }, findings: [{ id: 'K8S-PRIV-001', severity: 'high', group: 'security', title: 't', explanation: 'e', fix: 'f', file: 'f-' + OPAQUE, document: 1, object: 'Pod ' + OPAQUE, container: SYNTH.GITHUB_PAT, line: 1, evidence: '' }] }], counts: { high: 1, medium: 0, low: 0, info: 0 } };
	const rep2 = CHA.exportReport(raw, {});
	check(!leaks(rep2.json + rep2.markdown, [OPAQUE, SYNTH.GITHUB_PAT]).length, 'SEC-06: exportReport masks names again even for an unmasked result object');
}

// ---------------------------------------------------------------- page texts: no promise to find every secret
for (const slug of ['prompt-injection-test-bench', 'yara-sigma-validator', 'container-hardening-audit']) {
	const t = fs.readFileSync(path.join(TPL, slug + '.php'), 'utf8');
	check(!/finds? (?:all|every) secrets?|detects? (?:all|every) secrets?/iu.test(t.split('does not find every secret').join('')) && /does not find every secret/u.test(t), slug + ': the page does not promise to find every secret');
}

// ---------------------------------------------------------------- no ReDoS in the new patterns
{
	const big = ['password|a'.repeat(100000), 'token:'.repeat(160000), ('secret:"' + BS).repeat(60000)];
	for (const [name, E] of [['validator', YSV], ['test bench', PITB]]) { const t0 = Date.now(); for (const s of big) { E.findSecrets(s); } check(Date.now() - t0 < 5000, name + ': keyed-secret masking stays fast on 1 MB hostile input (' + (Date.now() - t0) + ' ms)'); }
	const t1 = Date.now();
	for (const s of ['&#'.repeat(99990), (BS + 'u').repeat(66000), CAN + '0'.repeat(1)].concat([(CAN + '0').repeat(12000)])) { PITB.detect(s, CAN); PITB.detectPartial(s, CAN); }
	check(Date.now() - t1 < 5000, 'test bench: detection stays fast on hostile responses (' + (Date.now() - t1) + ' ms)');
}
console.log(failed ? failed + ' of ' + n + ' checks failed' : 'PASS: release 1.3 acceptance fixes (' + n + ' checks)');
process.exit(failed ? 1 : 0);
