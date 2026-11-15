/*
 * Browser acceptance for the AI Model Bill of Materials (Chromium/Edge over the DevTools protocol, no deps).
 *   node tests/ai-bom-browser.test.cjs [url] [evidence-dir]
 *   default url: http://127.0.0.1:18091/tools/ai-model-bom/  (tests/tools-sandbox-server.py --port 18091)
 * Optional: CYBERDAT_BROWSER (browser executable), CYBERDAT_BASIC_AUTH_FILE (protected staging, see tests/lib/basic-auth.cjs).
 * Only for local or authorized staging pages. Nothing is sent anywhere except page loads to <url>.
 */
'use strict';
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/ai-model-bom/engine.js'));
const { bigBom } = require('./lib/ai-bom-inputs.cjs');

const URL_UNDER_TEST = process.argv[2] || 'http://127.0.0.1:18091/tools/ai-model-bom/';
const ORIGIN = new URL(URL_UNDER_TEST).origin;
const EVIDENCE = process.argv[3] || path.join(os.tmpdir(), 'cyberdat-ai-bom-' + Date.now());
fs.mkdirSync(EVIDENCE, { recursive: true });
const BROWSERS = [process.env.CYBERDAT_BROWSER, 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/google-chrome', '/usr/bin/chromium'].filter(Boolean);
const results = [];
const pass = (label, detail) => { results.push({ label, detail }); console.log('PASS: ' + label + (detail ? ' — ' + detail : '')); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const EXAMPLE_IDS = ['AIBOM-DAT-002', 'AIBOM-DEP-001', 'AIBOM-DOC-002', 'AIBOM-LIC-002', 'AIBOM-NET-001', 'AIBOM-VER-003', 'AIBOM-WGT-001', 'AIBOM-WGT-002'];

class CDP {
	constructor(ws) { this.ws = ws; this.id = 0; this.pending = new Map(); this.handlers = []; ws.addEventListener('message', e => this.onMessage(JSON.parse(e.data))); }
	static async connect(url) { const ws = new WebSocket(url); await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); }); return new CDP(ws); }
	onMessage(msg) {
		if (msg.id && this.pending.has(msg.id)) { const { resolve, reject } = this.pending.get(msg.id); this.pending.delete(msg.id); msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result); return; }
		for (const h of this.handlers) { h(msg); }
	}
	send(method, params = {}, sessionId) { const id = ++this.id; const payload = { id, method, params }; if (sessionId) { payload.sessionId = sessionId; } this.ws.send(JSON.stringify(payload)); return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject })); }
	on(fn) { this.handlers.push(fn); }
}
async function launch() {
	const exe = BROWSERS.find(p => fs.existsSync(p));
	if (!exe) { throw new Error('No Edge/Chrome found; set CYBERDAT_BROWSER.'); }
	const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cd-bom-browser-'));
	const proc = spawn(exe, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-extensions', '--disable-features=Translate,OptimizationHints,MediaRouter', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'], { stdio: 'ignore' });
	const portFile = path.join(profile, 'DevToolsActivePort');
	for (let i = 0; i < 100 && !fs.existsSync(portFile); i++) { await sleep(100); }
	const [port, wsPath] = fs.readFileSync(portFile, 'utf8').split('\n');
	return { cdp: await CDP.connect(`ws://127.0.0.1:${port}${wsPath.trim()}`), proc, profile };
}

(async () => {
	const { cdp, proc, profile } = await launch();
	const requests = [], consoleErrors = [], dialogs = [], workers = [];
	let phase = 'load';
	const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
	const { sessionId: s } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
	const send = (m, p) => cdp.send(m, p, s);
	cdp.on(msg => {
		if (msg.method === 'Network.requestWillBeSent') { requests.push({ phase, url: msg.params.request.url }); }
		if (msg.method === 'Runtime.exceptionThrown') { consoleErrors.push({ phase, text: msg.params.exceptionDetails.text + ' ' + JSON.stringify(msg.params.exceptionDetails.exception && msg.params.exceptionDetails.exception.description || '').slice(0, 300) }); }
		if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') { consoleErrors.push({ phase, text: msg.params.entry.source + ': ' + msg.params.entry.text }); }
		if (msg.method === 'Page.javascriptDialogOpening') { dialogs.push(msg.params.message); send('Page.handleJavaScriptDialog', { accept: false }); }
		if (msg.method === 'Target.attachedToTarget' && /worker/.test(msg.params.targetInfo.type)) { workers.push(msg.params.sessionId); cdp.send('Network.enable', {}, msg.params.sessionId).catch(() => {}); cdp.send('Runtime.runIfWaitingForDebugger', {}, msg.params.sessionId).catch(() => {}); }
	});
	for (const d of ['Page', 'Runtime', 'Network', 'Log', 'DOM']) { await send(d + '.enable'); }
	if (await require('./lib/basic-auth.cjs').enableCdp(cdp, s)) { console.log('Basic Auth: credentials from CYBERDAT_BASIC_AUTH_FILE'); }
	await send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
	await cdp.send('Browser.setDownloadBehavior', { behavior: 'deny' }).catch(() => {});
	const evaluate = async expression => { const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) { throw new Error('evaluate: ' + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text)); } return r.result.value; };
	const waitFor = async (expression, timeout = 15000, label = expression) => { const end = Date.now() + timeout; while (Date.now() < end) { if (await evaluate(expression).catch(() => false)) { return; } await sleep(100); } throw new Error('Timed out waiting for ' + label); };
	const shot = async name => { const { data } = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false }); fs.writeFileSync(path.join(EVIDENCE, name + '.png'), Buffer.from(data, 'base64')); };
	const viewport = (w, h, mobile) => send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: mobile ? 2 : 1, mobile });
	const navigate = async () => {
		await send('Page.navigate', { url: URL_UNDER_TEST });
		await waitFor("document.readyState === 'complete' && !!document.querySelector('[data-bom-app]') && !document.querySelector('[data-bom-app]').hidden", 20000, 'tool ready');
		await sleep(300);
		await evaluate("(() => { const orig = URL.createObjectURL; window.__blobs = []; URL.createObjectURL = b => { window.__blobs.push(b); return orig.call(URL, b); }; return true; })()");
	};
	const click = sel => evaluate(`(() => { document.querySelector(${JSON.stringify(sel)}).click(); return true; })()`);
	const setValue = (sel, t) => evaluate(`(() => { const i = document.querySelector(${JSON.stringify(sel)}); i.value = ${JSON.stringify(t)}; i.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);
	const setMode = m => evaluate(`(() => { const r = document.querySelector('[data-bom-mode][value="${m}"]'); r.checked = true; r.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
	const runAndWait = async (timeout = 30000, allowError = false) => {
		await evaluate("window.__done = false; new MutationObserver((m, o) => { if (!document.querySelector('[data-bom-run]').disabled && (!document.querySelector('[data-bom-results]').hidden || !document.querySelector('[data-bom-error]').hidden)) { window.__done = true; o.disconnect(); } }).observe(document.querySelector('[data-bom]'), { subtree: true, attributes: true, childList: true, characterData: true }); true");
		await click('[data-bom-run]');
		await waitFor('window.__done === true', timeout, 'result');
		const err = await evaluate("document.querySelector('[data-bom-error]').hidden ? '' : document.querySelector('[data-bom-error]').textContent");
		if (err && !allowError) { throw new Error('Tool error: ' + err); }
		return err;
	};
	const ids = () => evaluate("[...new Set([...document.querySelectorAll('[data-bom-list] .cd-bom-finding__head code')].map(c => c.textContent))].sort()");
	const lastBlob = () => evaluate("window.__blobs.length ? window.__blobs[window.__blobs.length - 1].text() : ''");
	const blobCount = () => evaluate('window.__blobs.length');
	const key = async (k, mods = 0) => { const codes = { Tab: 9, Enter: 13, Escape: 27, ' ': 32 }; const base = { key: k, code: k === ' ' ? 'Space' : k, windowsVirtualKeyCode: codes[k], nativeVirtualKeyCode: codes[k], modifiers: mods }; await send('Input.dispatchKeyEvent', Object.assign({ type: 'rawKeyDown' }, base)); if (k === 'Enter' || k === ' ') { await send('Input.dispatchKeyEvent', Object.assign({ type: 'char', text: k === 'Enter' ? '\r' : ' ' }, base)); } await send('Input.dispatchKeyEvent', Object.assign({ type: 'keyUp' }, base)); };
	const active = () => evaluate("(() => { const a = document.activeElement; return { id: a.id, tag: a.tagName, add: a.getAttribute('data-bom-add'), col: a.getAttribute('data-bom-col'), outline: getComputedStyle(a).outlineStyle + ' ' + getComputedStyle(a).outlineWidth, text: (a.textContent || '').trim().slice(0, 40) }; })()");

	try {
		await viewport(1440, 1000, false);
		await navigate();
		const load = requests.filter(r => /^(https?|wss?):/.test(r.url));
		assert.deepEqual(load.filter(r => new URL(r.url).origin !== ORIGIN), []);
		assert.ok(['worker', 'engine', 'app'].every(n => load.some(r => new RegExp('ai-model-bom/' + n + '\\.js').test(r.url))));
		pass('page load: first-party only; app, worker and engine load from this site', load.length + ' requests');
		phase = 'csp-probe';
		const probe = await evaluate("fetch('https://registry.example.com/v1', {mode: 'no-cors'}).then(() => 'unblocked', e => 'blocked: ' + e.message)").catch(e => 'blocked: ' + e.message);
		assert.match(probe, /^blocked/);
		pass('CSP connect-src blocks page scripts from contacting a model registry or any other service', probe.slice(0, 50));
		assert.deepEqual(consoleErrors.filter(e => e.phase === 'load'), []);
		const wr = await cdp.send('Runtime.evaluate', { expression: "(() => ['fetch','XMLHttpRequest','WebSocket','importScripts'].map(n => { try { n === 'fetch' ? self.fetch('/') : new self[n]('/'); return n + ':allowed'; } catch (e) { return n + ':blocked'; } }).join(','))()", returnByValue: true }, workers[0]);
		assert.ok(!/allowed/.test(wr.result.value));
		pass('network APIs are disabled inside the worker; no console errors on load', wr.result.value);
		const storage = () => evaluate("JSON.stringify({ ls: localStorage.length, ss: sessionStorage.length, cookie: document.cookie, href: location.href })");
		const storageBefore = await storage();

		phase = 'translate';
		for (const k of ['weights', 'datasets', 'dependencies', 'apis', 'metrics']) { await click(`[data-bom-add="${k}"]`); }
		const tr = await evaluate("(() => { const sel = 'input:not([type=radio]):not([type=checkbox]), textarea, select, pre, [data-bom-results], [data-bom-error], [data-bom-source]'; const all = [...document.querySelectorAll('[data-bom] ' + sel.split(', ').join(', [data-bom] '))]; const bad = all.filter(e => !(e.getAttribute('translate') === 'no' && e.classList.contains('notranslate'))).map(e => e.outerHTML.slice(0, 80)); const sp = [...document.querySelectorAll('[data-bom] input[type=text], [data-bom] textarea')].filter(e => e.getAttribute('spellcheck') !== 'false').length; return { n: all.length, bad, sp }; })()");
		assert.deepEqual(tr.bad, []);
		assert.equal(tr.sp, 0);
		assert.ok(tr.n >= 35, 'controls counted: ' + tr.n);
		pass('every input, select, preview and result element (also in added rows) has translate="no" and class notranslate; spellcheck off', tr.n + ' elements');
		await click('[data-bom-clear]');

		phase = 'build';
		await click('[data-bom-sample]');
		await waitFor("document.querySelector('#cd-bom-model-name').value === 'Ticket Router'", 5000, 'example');
		await runAndWait();
		const b = await evaluate("({ verdict: document.querySelector('[data-bom-verdict]').textContent, focus: document.activeElement.id, links: document.querySelectorAll('[data-bom] a').length, export: !document.querySelector('[data-bom-export-wrap]').hidden, json: document.querySelector('[data-bom-preview-json]').textContent, md: document.querySelector('[data-bom-preview-md]').textContent })");
		assert.deepEqual(await ids(), EXAMPLE_IDS);
		assert.match(b.verdict, /^Gaps worth fixing found\./);
		assert.equal(b.focus, 'cd-bom-step-results');
		assert.equal(b.links, 0);
		assert.ok(b.export && /"specVersion": "1.7"/.test(b.json) && /^# AI Bill of Materials: Ticket Router/.test(b.md));
		pass('Build of the example: eight expected gaps, focus moves to the results, no links, previews of JSON and Markdown', EXAMPLE_IDS.length + ' rules');
		await shot('01-build-1440');
		await click('[data-bom-download-json]');
		await sleep(300);
		const exported = await lastBlob();
		const bom = JSON.parse(exported);
		assert.equal(bom.components[0].type, 'machine-learning-model');
		assert.deepEqual(engine.validateCycloneDX(bom), []);
		await click('[data-bom-download-md]');
		await sleep(300);
		assert.match(await lastBlob(), /## Gaps found by the check/);
		pass('exports: CycloneDX JSON passes the structure check (0 problems), Markdown contains the gaps; created as blob: in the tab');

		phase = 'roundtrip';
		await setMode('review');
		await setValue('[data-bom-input]', exported);
		await runAndWait();
		assert.deepEqual(await ids(), EXAMPLE_IDS);
		const inv = await evaluate("document.querySelector('[data-bom-inventory]').textContent");
		assert.ok(/Ticket Router 1\.2\.0/.test(inv) && /ticket-router\.pt/.test(inv) && /Support ML team/.test(inv));
		pass('re-import of the exported JSON in Review gives the same gaps and the same contents');
		await click('[data-bom-edit]');
		await sleep(200);
		const formBack = await evaluate("({ name: document.querySelector('#cd-bom-model-name').value, type: document.querySelector('#cd-bom-model-type').value, rows: document.querySelectorAll('[data-bom-rows] > li').length, pd: document.querySelector('[data-bom-rows=datasets] [data-bom-col=personalData]').value, mode: document.querySelector('[data-bom-mode]:checked').value })");
		assert.deepEqual(formBack, { name: 'Ticket Router', type: 'fine-tuned', rows: 6, pd: 'unknown', mode: 'build' });
		await runAndWait();
		assert.deepEqual(await ids(), EXAMPLE_IDS);
		pass('“Open in the Build form” restores the form from the BOM; building again gives the same gaps');

		phase = 'secrets';
		await setValue('#cd-bom-owner-contact', 'support-ml@example.com, token ' + S.HF_TOKEN);
		await setValue('[data-bom-rows=apis] [data-bom-col=url]', S.URL_WITH_PASSWORD);
		await runAndWait();
		const sec = await evaluate("({ ui: document.querySelector('[data-bom-results]').textContent, dj: document.querySelector('[data-bom-download-json]').disabled, dm: document.querySelector('[data-bom-download-md]').disabled, warn: !document.querySelector('[data-bom-secret-warning]').hidden, preview: document.querySelector('[data-bom-preview-json]').textContent + document.querySelector('[data-bom-preview-md]').textContent })");
		const pwd = S.URL_WITH_PASSWORD.split(':')[2].split('@')[0];
		assert.ok((await ids()).includes('AIBOM-SEC-001') && (await ids()).includes('AIBOM-SEC-002'));
		for (const v of [S.HF_TOKEN, pwd]) { assert.ok(!sec.ui.includes(v), 'UI shows a secret'); assert.ok(!sec.preview.includes(v), 'preview shows a secret before confirmation'); }
		assert.ok(/hf_A… \(37 characters\)/.test(sec.ui));
		assert.ok(sec.dj && sec.dm && sec.warn);
		const nBlobs = await blobCount();
		await evaluate("document.querySelector('[data-bom-download-json]').disabled = false; document.querySelector('[data-bom-download-json]').click(); true");
		assert.equal(await blobCount(), nBlobs, 'export without confirmation must not create a file');
		await evaluate("document.querySelector('[data-bom-download-json]').disabled = true; true");
		await click('[data-bom-secret-ack]');
		const after = await evaluate("({ dj: document.querySelector('[data-bom-download-json]').disabled, preview: document.querySelector('[data-bom-preview-json]').textContent })");
		assert.ok(!after.dj && after.preview.includes(S.HF_TOKEN));
		await click('[data-bom-download-json]');
		await sleep(300);
		assert.ok((await lastBlob()).includes(S.HF_TOKEN));
		pass('secrets: findings and previews show only type and masked fragment; export is blocked until the user confirms, then contains the entries as typed');

		phase = 'unicode';
		await click('[data-bom-clear]');
		await setValue('#cd-bom-model-name', 'Jo\u0308rg-Modell fu\u0308r Pru\u0308fung');
		await setValue('#cd-bom-owner-name', 'Пе\u0308тр И\u0306осифович');
		await setValue('#cd-bom-purpose', 'Классификация обращений; Größenklassen prüfen.');
		await runAndWait();
		const u = await ids();
		assert.ok(!u.some(x => /SEC|NET/.test(x)), 'no secret findings for Unicode names: ' + u.join(' '));
		const uj = await evaluate("document.querySelector('[data-bom-preview-json]').textContent");
		assert.ok(uj.includes('Jörg-Modell für Prüfung') && uj.includes('Пётр Йосифович'));
		pass('names in NFD (umlauts, ё, й) are kept, exported in NFC and cause no false secret findings');

		phase = 'xss';
		await click('[data-bom-clear]');
		const payload = '<img src=x onerror=alert(1)><script>alert(2)</script><svg onload=alert(3)>';
		await setValue('#cd-bom-model-name', payload);
		await setValue('#cd-bom-limitations', payload);
		await runAndWait();
		await sleep(300);
		const x = await evaluate("({ img: document.querySelectorAll('[data-bom] img, [data-bom] svg, [data-bom] script').length, text: document.querySelector('[data-bom-preview-md]').textContent })");
		assert.equal(x.img, 0);
		assert.deepEqual(dialogs, []);
		assert.ok(x.text.includes('\\<img src=x onerror=alert\\(1\\)\\>'));
		pass('markup in entries is shown as text, never executed; Markdown export escapes it');

		phase = 'errors';
		await setMode('review');
		await setValue('[data-bom-input]', '{\n  "bomFormat": "CycloneDX",\n  "specVersion": "1.7",,\n}');
		assert.match(await runAndWait(10000, true), /line 3, column 24/);
		await setValue('[data-bom-input]', JSON.stringify({ spdxVersion: 'SPDX-2.3', SPDXID: 'SPDXRef-DOCUMENT' }));
		assert.match(await runAndWait(10000, true), /SPDX document/);
		await setValue('[data-bom-input]', 'x'.repeat(5 * 1024 * 1024 + 10));
		await click('[data-bom-run]');
		assert.match(await evaluate("document.querySelector('[data-bom-error]').textContent"), /larger than 5 MB/);
		pass('Review errors: broken JSON reports line and column; SPDX and over-size input are refused with a clear message');

		phase = 'large';
		const big = bigBom(4.6 * 1024 * 1024);
		await setValue('[data-bom-input]', big.text);
		await evaluate("window.__gap = 0; window.__last = performance.now(); window.__probe = setInterval(() => { const n = performance.now(); window.__gap = Math.max(window.__gap, n - window.__last); window.__last = n; }, 50); true");
		const t0 = Date.now();
		await runAndWait(120000);
		const elapsed = Date.now() - t0;
		const gap = await evaluate('(() => { clearInterval(window.__probe); return Math.round(window.__gap); })()');
		const sum = await evaluate("document.querySelector('[data-bom-summary]').textContent");
		assert.ok(new RegExp(big.datasets.toLocaleString('en-US') + ' datasets').test(sum), sum);
		assert.ok(gap < 1000, 'main thread blocked ' + gap + ' ms');
		pass('large input: ' + (big.text.length / 1048576).toFixed(1) + ' MB BOM with ' + big.components.toLocaleString('en-US') + ' components checked in the worker; page stays responsive', (elapsed / 1000).toFixed(1) + ' s, longest main-thread gap ' + gap + ' ms');
		await evaluate("document.querySelector('[data-bom-run]').click(); true");
		await sleep(150);
		await click('[data-bom-cancel]');
		await sleep(200);
		assert.match(await evaluate("document.querySelector('[data-bom-status]').textContent"), /^Cancelled/);
		pass('Cancel stops a running check and restarts the worker');
		assert.deepEqual(requests.filter(r => r.phase !== 'load' && /^(https?|wss?):/.test(r.url) && !/ai-model-bom\/(worker|engine)\.js/.test(r.url)), []);
		pass('no network requests after load except the worker restart after Cancel (static scripts)');

		phase = 'keyboard';
		await navigate();
		await evaluate("document.querySelector('[data-bom-add=datasets]').focus(); true");
		await key('Enter');
		await sleep(100);
		let a = await active();
		assert.equal(a.col, 'name');
		await key('Tab');
		a = await active();
		assert.equal(a.col, 'role');
		await evaluate("document.querySelector('#cd-bom-model-name').focus(); true");
		await key('Enter', 2);
		await waitFor("!document.querySelector('[data-bom-results]').hidden", 10000, 'Ctrl+Enter result');
		a = await active();
		assert.equal(a.id, 'cd-bom-step-results');
		await evaluate("document.querySelector('[data-bom-run]').focus(); true");
		a = await active();
		assert.ok(!/^none/.test(a.outline), 'focus outline on the run button: ' + a.outline);
		const order = [];
		await evaluate("document.querySelector('[data-bom-mode]').focus(); true");
		for (let i = 0; i < 6; i++) { await key('Tab'); const x2 = await active(); order.push(x2.id || x2.tag); }
		assert.ok(order.includes('cd-bom-model-name'), order.join(' > '));
		pass('keyboard: Enter on “Add dataset” focuses the new row, Tab moves through fields, Ctrl+Enter runs, focus is visible', order.slice(0, 4).join(' > '));

		phase = 'contrast';
		await click('[data-bom-sample]');
		await waitFor("document.querySelector('#cd-bom-model-name').value === 'Ticket Router'", 5000, 'example');
		await setValue('#cd-bom-owner-contact', 'support-ml@example.com ' + S.HF_TOKEN);
		await runAndWait();
		const c = await evaluate(`(() => {
			const parse = s => { const m = s.match(/rgba?\\(([^)]+)\\)/); if (!m) { return null; } const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
			const lum = c => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
			const bg = e => { for (let n = e; n; n = n.parentElement) { const c = parse(getComputedStyle(n).backgroundColor); if (c && c.a > 0.5) { return c; } } return parse(getComputedStyle(document.body).backgroundColor) || { r: 0, g: 0, b: 0 }; };
			const sels = ['.cd-la-label', '.cd-la-help', '.cd-bom-row__title', '.cd-la-button--primary', '.cd-la-button--secondary', '.cd-la-button--ghost', '.cd-bom-verdict strong', '.cd-bom-sev--high', '.cd-bom-sev--medium', '.cd-bom-sev--low', '.cd-bom-muted', '.cd-bom-code', '.cd-bom-finding p', '.cd-la-callout--warning strong', '.cd-la-info li', '.cd-la-text', '.cd-la-step'];
			const out = [];
			for (const s of sels) { const e = [...document.querySelectorAll('[data-bom] ' + s)].find(x => x.offsetParent); if (!e) { out.push({ s, missing: true }); continue; } const f = parse(getComputedStyle(e).color), b = bg(e); const L1 = lum(f), L2 = lum(b); out.push({ s, ratio: Math.round(((Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05)) * 100) / 100 }); }
			return out; })()`);
		const low = c.filter(x => x.missing || x.ratio < 4.5);
		assert.deepEqual(low, []);
		pass('text contrast at least 4.5:1 for labels, help, buttons, verdict, severity badges, findings and info text', 'lowest ' + Math.min(...c.map(x => x.ratio)) + ':1');

		phase = 'mobile';
		await viewport(360, 780, true);
		await navigate();
		await click('[data-bom-sample]');
		await waitFor("document.querySelector('#cd-bom-model-name').value === 'Ticket Router'", 5000, 'example');
		await runAndWait();
		const m = await evaluate("({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, small: [...document.querySelectorAll('[data-bom] button, [data-bom] input[type=text], [data-bom] select')].filter(e => e.offsetParent && e.getBoundingClientRect().height < 44).map(e => e.outerHTML.slice(0, 60)) })");
		assert.ok(m.sw <= m.cw + 1, 'horizontal overflow at 360px: ' + m.sw + ' > ' + m.cw);
		assert.deepEqual(m.small, []);
		const stepH = await evaluate("[...document.querySelectorAll('[data-bom] .cd-la-step')].filter(e => e.offsetParent).map(e => Math.round(e.getBoundingClientRect().height))");
		assert.ok(stepH.length >= 2 && stepH.every(h => h <= 64), 'step headings wrap badly at 360px: ' + stepH.join(','));
		await shot('02-build-360');
		await setMode('review');
		await click('[data-bom-review-sample]');
		await waitFor("document.querySelector('[data-bom-input]').value.length > 100", 5000, 'review example');
		await runAndWait();
		const m2 = await evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1');
		assert.ok(m2);
		await shot('03-review-360');
		pass('360 px: no horizontal scrolling in Build and Review; buttons and fields are at least 44 px high');

		assert.equal(await storage(), storageBefore.replace(/"href":"[^"]*"/, '"href":"' + URL_UNDER_TEST + '"'));
		pass('nothing stored in localStorage, sessionStorage, cookies or the URL');
		assert.deepEqual(consoleErrors.filter(e => e.phase !== 'csp-probe'), []);
		assert.deepEqual(dialogs, []);
		pass('no console errors and no dialogs during the whole run');
		fs.writeFileSync(path.join(EVIDENCE, 'browser-results.json'), JSON.stringify({ url: URL_UNDER_TEST, results }, null, 2));
		console.log('\n' + results.length + ' browser checks passed. Evidence: ' + EVIDENCE);
	} catch (e) {
		await shot('failure').catch(() => {});
		console.error('FAIL (' + phase + '): ' + e.message);
		console.error('console errors: ' + JSON.stringify(consoleErrors).slice(0, 2000));
		process.exitCode = 1;
	} finally {
		cdp.ws.close();
		proc.kill();
		await sleep(400);
		try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) { /* locked on Windows */ }
	}
})();
