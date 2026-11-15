/*
 * Browser acceptance for the MITRE ATLAS Attack Vector Mapper (Chromium/Edge over the DevTools protocol, no deps).
 *   node tests/atlas-mapper-browser.test.cjs [url] [evidence-dir]
 *   default url: http://127.0.0.1:18091/tools/mitre-atlas-mapper/  (tests/tools-sandbox-server.py --port 18091)
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

const URL_UNDER_TEST = process.argv[2] || 'http://127.0.0.1:18091/tools/mitre-atlas-mapper/';
const ORIGIN = new URL(URL_UNDER_TEST).origin;
const EVIDENCE = process.argv[3] || path.join(os.tmpdir(), 'cyberdat-atlas-mapper-' + Date.now());
fs.mkdirSync(EVIDENCE, { recursive: true });
const BROWSERS = [process.env.CYBERDAT_BROWSER, 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/google-chrome', '/usr/bin/chromium'].filter(Boolean);
const results = [];
const pass = (label, detail) => { results.push({ label, detail }); console.log('PASS: ' + label + (detail ? ' — ' + detail : '')); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

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
	const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cd-atl-browser-'));
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
		await waitFor("document.readyState === 'complete' && !!document.querySelector('[data-atl-app]') && !document.querySelector('[data-atl-app]').hidden", 20000, 'tool ready');
		await sleep(300);
		await evaluate("(() => { const orig = URL.createObjectURL; window.__blobs = []; URL.createObjectURL = b => { window.__blobs.push(b); return orig.call(URL, b); }; return true; })()");
	};
	const click = sel => evaluate(`(() => { document.querySelector(${JSON.stringify(sel)}).click(); return true; })()`);
	const setValue = (sel, t) => evaluate(`(() => { const i = document.querySelector(${JSON.stringify(sel)}); i.value = ${JSON.stringify(t)}; i.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);
	const setMode = m => evaluate(`(() => { const r = document.querySelector('[data-atl-mode][value="${m}"]'); r.checked = true; r.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
	const runAndWait = async (timeout = 30000, allowError = false) => {
		await evaluate("window.__done = false; new MutationObserver((m, o) => { if (!document.querySelector('[data-atl-run]').disabled && (!document.querySelector('[data-atl-results]').hidden || !document.querySelector('[data-atl-error]').hidden)) { window.__done = true; o.disconnect(); } }).observe(document.querySelector('[data-atl]'), { subtree: true, attributes: true, childList: true, characterData: true }); true");
		await click('[data-atl-run]');
		await waitFor('window.__done === true', timeout, 'result');
		const err = await evaluate("document.querySelector('[data-atl-error]').hidden ? '' : document.querySelector('[data-atl-error]').textContent");
		if (err && !allowError) { throw new Error('Tool error: ' + err); }
		return err;
	};
	const ids = () => evaluate("[...new Set([...document.querySelectorAll('[data-atl-groups] .cd-atl-tech__head code')].map(c => c.textContent))].sort()");
	const lastBlob = () => evaluate("window.__blobs.length ? window.__blobs[window.__blobs.length - 1].text() : ''");
	const key = async (k, mods = 0) => { const codes = { Tab: 9, Enter: 13, Escape: 27, ' ': 32 }; const base = { key: k, code: k === ' ' ? 'Space' : k, windowsVirtualKeyCode: codes[k], nativeVirtualKeyCode: codes[k], modifiers: mods }; await send('Input.dispatchKeyEvent', Object.assign({ type: 'rawKeyDown' }, base)); if (k === 'Enter' || k === ' ') { await send('Input.dispatchKeyEvent', Object.assign({ type: 'char', text: k === 'Enter' ? '\r' : ' ' }, base)); } await send('Input.dispatchKeyEvent', Object.assign({ type: 'keyUp' }, base)); };
	const active = () => evaluate("(() => { const a = document.activeElement; return { id: a.id, tag: a.tagName, add: a.getAttribute('data-atl-add'), outline: getComputedStyle(a).outlineStyle, text: (a.textContent || '').trim().slice(0, 40) }; })()");
	const checkProps = list => evaluate(`(() => { for (const c of document.querySelectorAll('[data-atl-property]')) { c.checked = ${JSON.stringify(list)}.includes(c.value); c.dispatchEvent(new Event('change', { bubbles: true })); } return true; })()`);

	try {
		await viewport(1440, 1000, false);
		await navigate();
		const load = requests.filter(r => /^(https?|wss?):/.test(r.url));
		assert.deepEqual(load.filter(r => new URL(r.url).origin !== ORIGIN), []);
		assert.ok(['worker', 'engine', 'app', 'atlas-data'].every(n => load.some(r => new RegExp('atlas-mapper/' + n + '\\.js').test(r.url))));
		pass('page load: first-party only; app, worker, engine and the ATLAS data file load from this site', load.length + ' requests');
		phase = 'csp-probe';
		const probe = await evaluate("fetch('https://atlas.mitre.org/', {mode: 'no-cors'}).then(() => 'unblocked', e => 'blocked: ' + e.message)").catch(e => 'blocked: ' + e.message);
		assert.match(probe, /^blocked/);
		pass('CSP connect-src blocks page scripts from contacting the MITRE site or any other host', probe.slice(0, 50));
		assert.deepEqual(consoleErrors.filter(e => e.phase === 'load'), []);
		const wr = await cdp.send('Runtime.evaluate', { expression: "(() => ['fetch','XMLHttpRequest','WebSocket','importScripts'].map(n => { try { n === 'fetch' ? self.fetch('/') : new self[n]('/'); return n + ':allowed'; } catch (e) { return n + ':blocked'; } }).join(','))()", returnByValue: true }, workers[0]);
		assert.ok(!/allowed/.test(wr.result.value));
		pass('network APIs are disabled inside the worker; no console errors on load', wr.result.value);
		const storage = () => evaluate("JSON.stringify({ ls: localStorage.length, ss: sessionStorage.length, cookie: document.cookie })");
		const storageBefore = await storage();

		phase = 'profile';
		await checkProps(['rag', 'agent-tools']);
		await runAndWait();
		const pr = await evaluate("({ verdict: document.querySelector('[data-atl-verdict]').textContent, tactics: document.querySelectorAll('[data-atl-groups] .cd-atl-group').length, why: document.querySelector('.cd-atl-why').textContent, focus: document.activeElement.id, links: document.querySelectorAll('[data-atl] a').length })");
		const profIds = await ids();
		assert.ok(profIds.includes('AML.T0051.001') && profIds.includes('AML.T0053') && profIds.length === 13, profIds.join(' '));
		assert.match(pr.verdict, /^13 candidate techniques in \d+ tactics\./);
		assert.ok(pr.tactics >= 3 && /CyberDat mapping/.test(pr.why) && pr.focus === 'cd-atl-step-results' && pr.links === 0);
		pass('System profile (RAG + agent with tools): 13 techniques grouped by ATLAS tactic, reasons marked as CyberDat mapping, focus on results, no links', pr.tactics + ' tactics');
		await shot('01-profile-1440');

		phase = 'finding';
		await setMode('finding');
		await click('[data-atl-sample]');
		await setValue('[data-atl-text]', (await evaluate("document.querySelector('[data-atl-text]').value")) + ' Key used: ' + S.OPENAI_PROJECT_KEY + ' and token ' + S.OPAQUE_LONG);
		await runAndWait();
		const f = await evaluate("({ ui: document.querySelector('[data-atl-results]').textContent, words: [...document.querySelectorAll('.cd-atl-word')].map(m => m.textContent), notes: document.querySelector('[data-atl-notes]').textContent })");
		const fIds = await ids();
		for (const t of ['AML.T0051.001', 'AML.T0086', 'AML.T0083', 'AML.T0055']) { assert.ok(fIds.includes(t), t + ' in ' + fIds.join(' ')); }
		assert.ok(f.words.includes('hidden instructions'));
		for (const v of [S.OPENAI_PROJECT_KEY, S.OPAQUE_LONG]) { assert.ok(!f.ui.includes(v), 'result shows a secret'); }
		assert.ok(/OpenAI-style API key sk-p… \(\d+ characters\)/.test(f.notes) && /unrecognized long value/.test(f.notes));
		assert.ok(!f.ui.includes('customer email that contained hidden instructions for the model'), 'pasted text echoed');
		pass('Finding mapper: candidates with the words that led to them; secrets and an unrecognized long value only masked; pasted text not echoed', fIds.join(' '));
		await shot('02-finding-1440');
		await setValue('[data-atl-text]', 'The quarterly report was approved by the board and sent to the auditors.');
		await runAndWait();
		assert.equal(await evaluate("document.querySelector('[data-atl-verdict]').textContent"), 'No matching techniques found. This does not mean the system is not exposed.');
		pass('no match: the agreed sentence is shown');

		phase = 'selection';
		await setMode('profile');
		await checkProps(['open-registry']);
		await runAndWait();
		await click('[data-atl-add="AML.T0011.000"]');
		await click('[data-atl-add="AML.T0010.003"]');
		await setValue('.cd-atl-note', 'Check model loading; old key ' + S.HF_TOKEN + ' — Jörg prüft das.');
		await evaluate("document.querySelector('.cd-atl-note').dispatchEvent(new Event('input', { bubbles: true })); true");
		await click('[data-atl-export="json"]');
		await sleep(400);
		const jx = JSON.parse(await lastBlob());
		await click('[data-atl-export="markdown"]');
		await sleep(400);
		const mx = await lastBlob();
		assert.deepEqual(jx.techniques.map(t => t.id), ['AML.T0011.000', 'AML.T0010.003']);
		assert.ok(jx.data.release === '2026.10' && /Apache License 2\.0/.test(jx.data.attribution) && jx.techniques[0].mitigations.length > 0);
		assert.ok(!JSON.stringify(jx).includes(S.HF_TOKEN) && !mx.includes(S.HF_TOKEN) && /hf_A…/.test(jx.techniques[0].note));
		assert.ok(/^# MITRE ATLAS techniques selected for review/.test(mx) && /Data source: MITRE ATLAS 2026\.10/.test(mx));
		pass('selection export: JSON and Markdown with ids, tactics, mitigations, notes (secret masked) and the ATLAS version and attribution');

		phase = 'browse';
		await setMode('browse');
		await setValue('[data-atl-search]', 'aml.t0051');
		await waitFor("[...document.querySelectorAll('[data-atl-browse] .cd-atl-idbtn')].some(b => b.textContent.startsWith('AML.T0051 '))", 5000, 'search results');
		await evaluate("[...document.querySelectorAll('[data-atl-browse] .cd-atl-idbtn')].find(b => b.textContent.startsWith('AML.T0051 ')).click(); true");
		await waitFor("!!document.querySelector('.cd-atl-item__head') && document.querySelector('.cd-atl-item__head').textContent.startsWith('AML.T0051')", 5000, 'technique view');
		const b = await evaluate("({ text: document.querySelector('[data-atl-browse]').textContent, focus: document.activeElement.className })");
		assert.ok(/LLM Prompt Injection/.test(b.text) && /Sub-techniques/.test(b.text) && /AML\.M0020/.test(b.text) && /cd-atl-item__head/.test(b.focus));
		await evaluate("[...document.querySelectorAll('[data-atl-browse] .cd-atl-idbtn')].find(x => x.textContent.startsWith('AML.M0020')).click(); true");
		await waitFor("document.querySelector('.cd-atl-item__head').textContent.startsWith('AML.M0020')", 5000, 'mitigation view');
		pass('Browse: search by id, open a technique (tactics, sub-techniques, mitigations) and follow a mitigation; focus moves to the opened item');

		phase = 'translate';
		const tr = await evaluate("(() => { const all = [...document.querySelectorAll('[data-atl] textarea, [data-atl] input[type=search], [data-atl-results], [data-atl-error], [data-atl-selection], [data-atl-browse]')]; return { n: all.length, bad: all.filter(e => !(e.getAttribute('translate') === 'no' && e.classList.contains('notranslate'))).map(e => e.outerHTML.slice(0, 80)) }; })()");
		assert.deepEqual(tr.bad, []);
		pass('finding text, search, notes (also added ones), browse view, results, selection and error box carry translate="no" and notranslate', tr.n + ' elements');

		phase = 'large';
		await setMode('finding');
		await setValue('[data-atl-text]', ('The agent deleted files after reading a document with hidden instructions. Ein Deepfake-Anruf. Отравление обучающих данных. ').repeat(900).slice(0, 100000));
		await evaluate("window.__gap = 0; window.__last = performance.now(); window.__probe = setInterval(() => { const n = performance.now(); window.__gap = Math.max(window.__gap, n - window.__last); window.__last = n; }, 50); true");
		const t0 = Date.now();
		await runAndWait();
		const elapsed = Date.now() - t0;
		const gap = await evaluate('(() => { clearInterval(window.__probe); return Math.round(window.__gap); })()');
		assert.ok(gap < 1000);
		await setValue('[data-atl-text]', 'x'.repeat(100001));
		await click('[data-atl-run]');
		assert.match(await evaluate("document.querySelector('[data-atl-error]').textContent"), /longer than 100,000/);
		pass('100,000-character finding mapped in the worker; page responsive; longer text refused', (elapsed / 1000).toFixed(1) + ' s, longest gap ' + gap + ' ms');
		await setValue('[data-atl-text]', 'Prompt injection in a PDF.');
		await evaluate("document.querySelector('[data-atl-run]').click(); document.querySelector('[data-atl-cancel]').click(); true");
		await sleep(200);
		assert.match(await evaluate("document.querySelector('[data-atl-status]').textContent"), /^Cancelled|^Done/);
		pass('Cancel is available while a mapping runs');
		assert.deepEqual(requests.filter(r => r.phase !== 'load' && r.phase !== 'csp-probe' && /^(https?|wss?):/.test(r.url) && !/atlas-mapper\/(worker|engine|atlas-data)\.js/.test(r.url)), []);
		pass('no network requests after load except the worker restart after Cancel (static scripts of this site)');

		phase = 'keyboard';
		await navigate();
		await evaluate("document.querySelector('[data-atl-property]').focus(); true");
		await key(' ');
		assert.equal(await evaluate("document.querySelector('[data-atl-property]').checked"), true);
		await evaluate("document.querySelector('[data-atl-run]').focus(); true");
		await key('Enter');
		await waitFor("!document.querySelector('[data-atl-results]').hidden && document.activeElement.id === 'cd-atl-step-results'", 10000, 'keyboard run');
		await evaluate("document.querySelector('[data-atl-add]').focus(); true");
		const a = await active();
		assert.ok(a.add && a.outline !== 'none', JSON.stringify(a));
		await key('Enter');
		assert.equal(await evaluate("document.querySelectorAll('[data-atl-selected] > li').length"), 1);
		await setMode('finding');
		await evaluate("const t = document.querySelector('[data-atl-text]'); t.value = 'Indirect prompt injection through an uploaded PDF.'; t.focus(); true");
		await key('Enter', 2);
		await waitFor("!document.querySelector('[data-atl-results]').hidden && document.activeElement.id === 'cd-atl-step-results'", 10000, 'Ctrl+Enter');
		pass('keyboard: Space selects a property, Enter runs, focus moves to the results, Enter adds to the selection, Ctrl+Enter maps a finding; focus visible');

		phase = 'contrast';
		await evaluate("(() => { const b = [...document.querySelectorAll('[data-atl-results] [data-atl-add]')].find(x => x.getAttribute('aria-pressed') !== 'true'); if (b) { b.click(); } return true; })()");
		const c = await evaluate(`(() => {
			const parse = s => { const m = s.match(/rgba?\\(([^)]+)\\)/); if (!m) { return null; } const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
			const lum = c => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
			const bg = e => { for (let n = e; n; n = n.parentElement) { const c = parse(getComputedStyle(n).backgroundColor); if (c && c.a > 0.5) { return c; } } return parse(getComputedStyle(document.body).backgroundColor) || { r: 0, g: 0, b: 0 }; };
			const sels = ['.cd-la-label', '.cd-la-help', '.cd-la-button--primary', '.cd-la-button--secondary', '.cd-la-button--ghost', '.cd-atl-verdict strong', '.cd-atl-id', '.cd-atl-muted', '.cd-atl-word', '.cd-atl-label', '.cd-atl-tech__head', '.cd-la-callout--warning strong', '.cd-la-info li', '.cd-la-step', '.cd-atl-add[aria-pressed="true"]'];
			const out = [];
			for (const s of sels) { const e = [...document.querySelectorAll('[data-atl] ' + s)].find(x => x.offsetParent); if (!e) { out.push({ s, missing: true }); continue; } const f = parse(getComputedStyle(e).color), b = bg(e); const L1 = lum(f), L2 = lum(b); out.push({ s, ratio: Math.round(((Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05)) * 100) / 100 }); }
			return out; })()`);
		assert.deepEqual(c.filter(x => x.missing || x.ratio < 4.5), []);
		pass('text contrast at least 4.5:1 for labels, help, buttons, verdict, ids, matched words, cards and info text', 'lowest ' + Math.min(...c.map(x => x.ratio)) + ':1');

		phase = 'mobile';
		await viewport(360, 780, true);
		await navigate();
		await checkProps(['external-api', 'rag', 'public']);
		await runAndWait();
		const m = await evaluate("({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, small: [...document.querySelectorAll('[data-atl] button, [data-atl] input[type=search]')].filter(e => e.offsetParent && e.getBoundingClientRect().height < 44).map(e => e.outerHTML.slice(0, 60)), steps: [...document.querySelectorAll('[data-atl] .cd-la-step')].filter(e => e.offsetParent).map(e => Math.round(e.getBoundingClientRect().height)) })");
		assert.ok(m.sw <= m.cw + 1, 'overflow ' + m.sw);
		assert.deepEqual(m.small, []);
		assert.ok(m.steps.every(h => h <= 64), m.steps.join(','));
		await shot('03-profile-360');
		await setMode('browse');
		await setValue('[data-atl-search]', 'agent');
		await waitFor("document.querySelector('[data-atl-browse]').textContent.includes('Techniques (')", 5000, 'search');
		assert.ok(await evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1'));
		await shot('04-browse-360');
		pass('360 px: no horizontal scrolling in profile results and Browse; buttons at least 44 px; headings fit');

		assert.equal(await storage(), storageBefore);
		pass('nothing stored in localStorage, sessionStorage or cookies');
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
