/*
 * Shared Chromium/Edge (DevTools protocol, no dependencies) harness for the release 1.3 tool browser tests.
 * runEdge({ name, url, root, evidence, body: async h => {...} }) launches a headless browser, opens the page, checks the
 * common contracts (first-party load, CSP, worker network lock, data-worker-state="ready") and calls body with helpers.
 * Only for local or authorized staging pages. Optional: CYBERDAT_BROWSER, CYBERDAT_BASIC_AUTH_FILE.
 */
'use strict';
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const BROWSERS = [process.env.CYBERDAT_BROWSER, 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/google-chrome', '/usr/bin/chromium'].filter(Boolean);

class CDP {
	constructor(ws) { this.ws = ws; this.id = 0; this.pending = new Map(); this.handlers = []; ws.addEventListener('message', e => this.onMessage(JSON.parse(e.data))); }
	static async connect(url) { const ws = new WebSocket(url); await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); }); return new CDP(ws); }
	onMessage(msg) { if (msg.id && this.pending.has(msg.id)) { const { resolve, reject } = this.pending.get(msg.id); this.pending.delete(msg.id); msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result); return; } for (const h of this.handlers) { h(msg); } }
	send(method, params = {}, sessionId) { const id = ++this.id; const payload = { id, method, params }; if (sessionId) { payload.sessionId = sessionId; } this.ws.send(JSON.stringify(payload)); return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject })); }
	on(fn) { this.handlers.push(fn); }
}

const CONTRAST_JS = `(sels) => {
	const parse = s => { const m = s.match(/rgba?\\(([^)]+)\\)/); if (!m) { return null; } const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
	const lum = c => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
	const bg = e => { for (let n = e; n; n = n.parentElement) { const c = parse(getComputedStyle(n).backgroundColor); if (c && c.a > 0.5) { return c; } } return parse(getComputedStyle(document.body).backgroundColor) || { r: 0, g: 0, b: 0 }; };
	return sels.map(s => { const e = [...document.querySelectorAll(s)].find(x => x.offsetParent); if (!e) { return { s, missing: true }; } const f = parse(getComputedStyle(e).color), b = bg(e); const L1 = lum(f), L2 = lum(b); return { s, ratio: Math.round(((Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05)) * 100) / 100 }; });
}`;

async function runEdge(opt) {
	const exe = BROWSERS.find(p => fs.existsSync(p));
	if (!exe) { throw new Error('No Edge/Chrome found; set CYBERDAT_BROWSER.'); }
	const EVIDENCE = opt.evidence || path.join(os.tmpdir(), 'cyberdat-' + opt.name + '-' + Date.now());
	fs.mkdirSync(EVIDENCE, { recursive: true });
	const ORIGIN = new URL(opt.url).origin;
	const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cd-' + opt.name + '-'));
	const proc = spawn(exe, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-extensions', '--disable-features=Translate,OptimizationHints,MediaRouter', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'], { stdio: 'ignore' });
	const portFile = path.join(profile, 'DevToolsActivePort');
	for (let i = 0; i < 100 && !fs.existsSync(portFile); i++) { await sleep(100); }
	const [port, wsPath] = fs.readFileSync(portFile, 'utf8').split('\n');
	const cdp = await CDP.connect(`ws://127.0.0.1:${port}${wsPath.trim()}`);
	const results = [], requests = [], consoleErrors = [], dialogs = [], workers = [];
	const h = { phase: 'load', EVIDENCE, ORIGIN, results, requests, consoleErrors, dialogs, workers, sleep, assert };
	h.pass = (label, detail) => { results.push({ label, detail }); console.log('PASS: ' + label + (detail ? ' — ' + detail : '')); };
	const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
	const { sessionId: s } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
	const send = (m, p) => cdp.send(m, p, s);
	cdp.on(msg => {
		if (msg.method === 'Network.requestWillBeSent') { requests.push({ phase: h.phase, url: msg.params.request.url }); }
		if (msg.method === 'Runtime.exceptionThrown') { consoleErrors.push({ phase: h.phase, text: msg.params.exceptionDetails.text }); }
		if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') { consoleErrors.push({ phase: h.phase, text: msg.params.entry.source + ': ' + msg.params.entry.text }); }
		if (msg.method === 'Page.javascriptDialogOpening') { dialogs.push(msg.params.message); send('Page.handleJavaScriptDialog', { accept: false }); }
		if (msg.method === 'Target.attachedToTarget' && /worker/.test(msg.params.targetInfo.type)) { workers.push(msg.params.sessionId); cdp.send('Network.enable', {}, msg.params.sessionId).catch(() => {}); cdp.send('Runtime.runIfWaitingForDebugger', {}, msg.params.sessionId).catch(() => {}); }
	});
	for (const d of ['Page', 'Runtime', 'Network', 'Log', 'DOM']) { await send(d + '.enable'); }
	if (await require('./basic-auth.cjs').enableCdp(cdp, s)) { console.log('Basic Auth: credentials from CYBERDAT_BASIC_AUTH_FILE'); }
	await send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
	await cdp.send('Browser.setDownloadBehavior', { behavior: 'deny' }).catch(() => {});
	h.evaluate = async expression => { const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) { throw new Error('evaluate: ' + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text)); } return r.result.value; };
	h.waitFor = async (expression, timeout = 15000, label = expression) => { const end = Date.now() + timeout; while (Date.now() < end) { if (await h.evaluate(expression).catch(() => false)) { return; } await sleep(100); } throw new Error('Timed out waiting for ' + label); };
	h.shot = async name => { const { data } = await send('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(path.join(EVIDENCE, name + '.png'), Buffer.from(data, 'base64')); };
	h.viewport = (w, ht, mobile) => send('Emulation.setDeviceMetricsOverride', { width: w, height: ht, deviceScaleFactor: mobile ? 2 : 1, mobile });
	h.navigate = async () => {
		const prev = h.phase;
		h.phase = 'reload';
		await send('Page.navigate', { url: opt.url });
		await h.waitFor(`document.readyState === 'complete' && document.querySelector('${opt.root}') && document.querySelector('${opt.root}').getAttribute('data-worker-state') === 'ready'`, 20000, 'data-worker-state="ready"');
		await sleep(200);
		await h.evaluate("(() => { const orig = URL.createObjectURL; window.__blobs = []; URL.createObjectURL = b => { window.__blobs.push(b); return orig.call(URL, b); }; return true; })()");
		h.phase = prev === 'load' ? 'load' : prev;
	};
	h.click = sel => h.evaluate(`(() => { document.querySelector(${JSON.stringify(sel)}).click(); return true; })()`);
	h.setValue = (sel, t) => h.evaluate(`(() => { const i = document.querySelector(${JSON.stringify(sel)}); i.value = ${JSON.stringify(t)}; i.dispatchEvent(new Event('input', { bubbles: true })); i.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
	h.lastBlob = () => h.evaluate("window.__blobs.length ? window.__blobs[window.__blobs.length - 1].text() : ''");
	h.blobCount = () => h.evaluate('window.__blobs.length');
	h.key = async (k, mods = 0) => { const codes = { Tab: 9, Enter: 13, Escape: 27, ' ': 32 }; const base = { key: k, code: k === ' ' ? 'Space' : k, windowsVirtualKeyCode: codes[k], nativeVirtualKeyCode: codes[k], modifiers: mods }; await send('Input.dispatchKeyEvent', Object.assign({ type: 'rawKeyDown' }, base)); if (k === 'Enter' || k === ' ') { await send('Input.dispatchKeyEvent', Object.assign({ type: 'char', text: k === 'Enter' ? '\r' : ' ' }, base)); } await send('Input.dispatchKeyEvent', Object.assign({ type: 'keyUp' }, base)); };
	h.contrast = async sels => { const c = await h.evaluate('(' + CONTRAST_JS + ')(' + JSON.stringify(sels) + ')'); assert.deepEqual(c.filter(x => x.missing || x.ratio < 4.5), []); return Math.min(...c.map(x => x.ratio)); };
	h.mobileCheck = async () => { const m = await h.evaluate(`({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, small: [...document.querySelectorAll('${opt.root} button, ${opt.root} input[type=search], ${opt.root} input[type=text], ${opt.root} select')].filter(e => e.offsetParent && e.getBoundingClientRect().height < 44).map(e => e.outerHTML.slice(0, 60)), steps: [...document.querySelectorAll('${opt.root} .cd-la-step')].filter(e => e.offsetParent).map(e => Math.round(e.getBoundingClientRect().height)) })`); assert.ok(m.sw <= m.cw + 1, 'horizontal overflow ' + m.sw + ' > ' + m.cw); assert.deepEqual(m.small, []); assert.ok(m.steps.every(x => x <= 64), 'headings ' + m.steps.join(',')); };
	h.translateCheck = async selector => { const r = await h.evaluate(`(() => { const all = [...document.querySelectorAll(${JSON.stringify(selector)})]; return { n: all.length, bad: all.filter(e => !(e.getAttribute('translate') === 'no' && e.classList.contains('notranslate'))).map(e => e.outerHTML.slice(0, 80)) }; })()`); assert.deepEqual(r.bad, []); return r.n; };
	const storage = () => h.evaluate("JSON.stringify({ ls: localStorage.length, ss: sessionStorage.length, cookie: document.cookie })");
	let code = 0;
	try {
		await h.viewport(1440, 1000, false);
		await h.navigate();
		const load = requests.filter(r => /^(https?|wss?):/.test(r.url));
		assert.deepEqual(load.filter(r => new URL(r.url).origin !== ORIGIN), []);
		h.pass('page load: first-party only; the page reports data-worker-state="ready" when the local engine runs', load.length + ' requests');
		h.phase = 'csp-probe';
		const probe = await h.evaluate("fetch('https://example.com/', {mode: 'no-cors'}).then(() => 'unblocked', e => 'blocked: ' + e.message)").catch(e => 'blocked: ' + e.message);
		assert.match(probe, /^blocked/);
		const wr = await cdp.send('Runtime.evaluate', { expression: "(() => ['fetch','XMLHttpRequest','WebSocket','importScripts'].map(n => { try { n === 'fetch' ? self.fetch('/') : new self[n]('/'); return n + ':allowed'; } catch (e) { return n + ':blocked'; } }).join(','))()", returnByValue: true }, workers[0]);
		assert.ok(!/allowed/.test(wr.result.value));
		assert.deepEqual(consoleErrors.filter(e => e.phase === 'load'), []);
		h.pass('CSP blocks page scripts from any network connection; network APIs disabled in the worker; no console errors on load', wr.result.value);
		const before = await storage();
		h.phase = 'body';
		await opt.body(h);
		assert.equal(await storage(), before);
		assert.deepEqual(requests.filter(r => r.phase !== 'load' && r.phase !== 'csp-probe' && r.phase !== 'reload' && /^(https?|wss?):/.test(r.url) && !/\/assets\/js\/[^/]+\/(?:worker|engine)\.js/.test(r.url)), []);
		h.pass('nothing stored in localStorage, sessionStorage or cookies; no network requests after load except worker restarts (static scripts of this site)');
		assert.deepEqual(consoleErrors.filter(e => e.phase !== 'csp-probe'), []);
		assert.deepEqual(dialogs, []);
		h.pass('no console errors and no dialogs during the whole run');
		fs.writeFileSync(path.join(EVIDENCE, 'browser-results.json'), JSON.stringify({ url: opt.url, results }, null, 2));
		console.log('\n' + results.length + ' browser checks passed. Evidence: ' + EVIDENCE);
	} catch (e) {
		await h.shot('failure').catch(() => {});
		console.error('FAIL (' + h.phase + '): ' + e.message);
		console.error('console errors: ' + JSON.stringify(consoleErrors.filter(x => x.phase !== 'csp-probe')).slice(0, 1500));
		code = 1;
	} finally {
		cdp.ws.close();
		proc.kill();
		await sleep(400);
		try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) { /* locked on Windows */ }
	}
	process.exitCode = code;
}

module.exports = { runEdge, sleep };
