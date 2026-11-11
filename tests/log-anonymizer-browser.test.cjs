/*
 * Browser acceptance for the Log Anonymizer against a running WordPress page.
 * Dependency-free: drives a headless Edge/Chrome over the DevTools protocol (Node >= 22 WebSocket).
 *
 *   node tests/log-anonymizer-browser.test.cjs [url] [evidence-dir]
 *   default url: http://127.0.0.1:8090/tools/log-anonymizer/  (tests/local-wp/up.sh)
 *
 * Only for local or authorized staging pages. Nothing is sent anywhere except page loads to <url>.
 */
'use strict';
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const URL_UNDER_TEST = process.argv[2] || 'http://127.0.0.1:8090/tools/log-anonymizer/';
const ORIGIN = new URL(URL_UNDER_TEST).origin;
const EVIDENCE = process.argv[3] || path.join(os.homedir(), 'CyberDat-tools-log-anonymizer-' + new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, 'Z'));
fs.mkdirSync(EVIDENCE, { recursive: true });
const BROWSERS = [process.env.CYBERDAT_BROWSER, 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/google-chrome', '/usr/bin/chromium'].filter(Boolean);

const results = [];
function pass(label, detail) { results.push({ status: 'PASS', label, detail }); console.log('PASS: ' + label + (detail ? ' — ' + detail : '')); }
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ------------------------------------------------------------------ CDP client
class CDP {
	constructor(ws) { this.ws = ws; this.id = 0; this.pending = new Map(); this.handlers = []; ws.addEventListener('message', e => this.onMessage(JSON.parse(e.data))); }
	static async connect(url) {
		const ws = new WebSocket(url);
		await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
		return new CDP(ws);
	}
	onMessage(msg) {
		if (msg.id && this.pending.has(msg.id)) {
			const { resolve, reject } = this.pending.get(msg.id);
			this.pending.delete(msg.id);
			msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
			return;
		}
		for (const h of this.handlers) { h(msg); }
	}
	send(method, params = {}, sessionId) {
		const id = ++this.id;
		const payload = { id, method, params };
		if (sessionId) { payload.sessionId = sessionId; }
		this.ws.send(JSON.stringify(payload));
		return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
	}
	on(fn) { this.handlers.push(fn); }
}

async function launch() {
	const exe = BROWSERS.find(p => fs.existsSync(p));
	if (!exe) { throw new Error('No Edge/Chrome found; set CYBERDAT_BROWSER.'); }
	const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cd-la-browser-'));
	const args = ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-extensions', '--disable-features=Translate,OptimizationHints,MediaRouter', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'];
	const proc = spawn(exe, args, { stdio: 'ignore' });
	const portFile = path.join(profile, 'DevToolsActivePort');
	for (let i = 0; i < 100 && !fs.existsSync(portFile); i++) { await sleep(100); }
	const [port, wsPath] = fs.readFileSync(portFile, 'utf8').split('\n');
	if (!/^\d+$/.test(port) || !wsPath.startsWith('/devtools/browser/')) { throw new Error('Unexpected DevToolsActivePort'); }
	const cdp = await CDP.connect(`ws://127.0.0.1:${port}${wsPath.trim()}`);
	return { cdp, proc, profile, exe };
}

// ------------------------------------------------------------------ main
(async () => {
	const { cdp, proc, profile, exe } = await launch();
	const requests = [];
	const consoleErrors = [];
	const dialogs = [];
	const workers = [];
	let phase = 'load';
	const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
	const { sessionId: s } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
	const send = (m, p) => cdp.send(m, p, s);
	cdp.on(msg => {
		if (msg.method === 'Network.requestWillBeSent') {
			const u = msg.params.request.url;
			requests.push({ phase, url: u, type: msg.params.type || '', session: msg.sessionId === s ? 'page' : 'worker' });
		}
		if (msg.method === 'Runtime.exceptionThrown') { consoleErrors.push({ phase, text: msg.params.exceptionDetails.text + ' ' + (msg.params.exceptionDetails.exception && msg.params.exceptionDetails.exception.description || '') }); }
		if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') { consoleErrors.push({ phase, text: msg.params.entry.source + ': ' + msg.params.entry.text }); }
		if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') { consoleErrors.push({ phase, text: 'console.error' }); }
		if (msg.method === 'Page.javascriptDialogOpening') { dialogs.push(msg.params.message); send('Page.handleJavaScriptDialog', { accept: false }); }
		if (msg.method === 'Target.attachedToTarget' && /worker/.test(msg.params.targetInfo.type)) {
			workers.push(msg.params.sessionId);
			cdp.send('Network.enable', {}, msg.params.sessionId).catch(() => {});
			cdp.send('Runtime.runIfWaitingForDebugger', {}, msg.params.sessionId).catch(() => {});
		}
	});
	for (const d of ['Page', 'Runtime', 'Network', 'Log', 'DOM']) { await send(d + '.enable'); }
	await send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
	await cdp.send('Browser.setDownloadBehavior', { behavior: 'deny' }).catch(() => {});

	const evaluate = async (expression, awaitPromise = true) => {
		const r = await send('Runtime.evaluate', { expression, awaitPromise, returnByValue: true });
		if (r.exceptionDetails) { throw new Error('evaluate: ' + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text)); }
		return r.result.value;
	};
	const waitFor = async (expression, timeout = 15000, label = expression) => {
		const end = Date.now() + timeout;
		while (Date.now() < end) { if (await evaluate(expression).catch(() => false)) { return; } await sleep(100); }
		throw new Error('Timed out waiting for ' + label);
	};
	const shot = async name => {
		const { data } = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
		fs.writeFileSync(path.join(EVIDENCE, name + '.png'), Buffer.from(data, 'base64'));
	};
	const viewport = (width, height, mobile) => send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: mobile ? 2 : 1, mobile });
	const navigate = async () => {
		await send('Page.navigate', { url: URL_UNDER_TEST });
		await waitFor("document.readyState === 'complete' && !!document.querySelector('[data-la-app]') && !document.querySelector('[data-la-app]').hidden", 20000, 'tool ready');
		await sleep(300);
	};
	const click = sel => evaluate(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); e.click(); return true; })()`);
	const runAndWait = async (timeout = 30000) => {
		await evaluate("window.__laDone = false; new MutationObserver((m, o) => { if (!document.querySelector('[data-la-results]').hidden && document.querySelector('[data-la-run]').disabled === false) { window.__laDone = true; o.disconnect(); } }).observe(document.querySelector('[data-log-anonymizer]'), { subtree: true, attributes: true, childList: true }); true");
		await click('[data-la-run]');
		await waitFor("window.__laDone === true || !document.querySelector('[data-la-error]').hidden", timeout, 'result');
		const err = await evaluate("document.querySelector('[data-la-error]').hidden ? '' : document.querySelector('[data-la-error]').textContent");
		if (err) { throw new Error('Tool error: ' + err); }
	};
	const httpAfter = p => requests.filter(r => r.phase !== 'load' && (p ? r.phase === p : true) && /^(https?|wss?):/.test(r.url));

	try {
		await viewport(1440, 1000, false);
		await navigate();
		const pageLoad = requests.filter(r => /^(https?|wss?):/.test(r.url));
		assert.ok(pageLoad.length > 0);
		const foreign = pageLoad.filter(r => new URL(r.url).origin !== ORIGIN);
		assert.deepEqual(foreign, [], 'page load requested third-party resources');
		assert.ok(pageLoad.some(r => /log-anonymizer\/worker\.js/.test(r.url)) && pageLoad.some(r => /log-anonymizer\/engine\.js/.test(r.url)), 'worker and engine preloaded');
		pass('page load uses first-party resources only', pageLoad.length + ' requests, all ' + ORIGIN + ', worker and engine loaded before any input');

		const head = await evaluate("fetch(location.href, {method: 'HEAD', cache: 'no-store'}).then(() => 'unblocked', e => 'blocked: ' + e.message)").catch(e => 'blocked: ' + e.message);
		phase = 'csp-probe';
		assert.match(head, /^blocked/, 'CSP connect-src must block fetch');
		pass('CSP connect-src blocks scripts on the page from making requests', head.slice(0, 80));
		const probeErrors = consoleErrors.filter(e => e.phase === 'load');
		consoleErrors.length = 0;
		assert.deepEqual(probeErrors.filter(e => !/Content Security Policy|connect-src|Refused to connect/i.test(e.text)), [], 'console errors during load');
		pass('no console errors or CSP violations during page load');

		if (workers.length) {
			const r = await cdp.send('Runtime.evaluate', { expression: "(() => { const out = []; for (const n of ['fetch','XMLHttpRequest','WebSocket','importScripts']) { try { typeof self[n] === 'function' && n === 'fetch' ? self.fetch('/') : new self[n]('/'); out.push(n + ':allowed'); } catch (e) { out.push(n + ':blocked'); } } return out.join(','); })()", returnByValue: true }, workers[0]);
			assert.ok(!/allowed/.test(r.result.value), 'worker network APIs: ' + r.result.value);
			pass('network APIs are disabled inside the worker', r.result.value);
		}

		const before = await evaluate("JSON.stringify({ ls: localStorage.length, ss: sessionStorage.length, cookie: document.cookie, href: location.href })");
		const { cookies: cookiesBefore } = await send('Network.getCookies', { urls: [ORIGIN] });

		// ---- sample log, stable labels
		phase = 'process';
		await click('[data-la-sample]');
		await runAndWait();
		const preview = await evaluate("document.querySelector('[data-la-preview]').textContent");
		for (const leaked of ['alice', '203.0.113.42', 'bob.smith@example.com', 'Winter2026!', 'Pa55w0rd', 'AKIAIOSFODNN7EXAMPLE', '4111 1111 1111 1111', '123-45-6789', 'eyJhbGci', '00:1A:2B:3C:4D:5E', 'billing.internal.example.com', '7f3c9a1b2d4e6f80', 'ghp_aBcD', '2001:db8:4::17']) {
			assert.ok(!preview.includes(leaked), 'leaked ' + leaked);
		}
		for (const kept of ['version 1.2.3.4', 'build=10.0.19045.1', 'order_id=9988776655', 'trace=4bf92f3577b34da6a3ce929d0e0e4736', '10:20:30', 'Nov 11 09:14:02']) {
			assert.ok(preview.includes(kept), 'kept ' + kept);
		}
		const lines = await evaluate("[document.querySelector('[data-la-input]').value.split('\\n').length, document.querySelector('[data-la-preview]').textContent.split('\\n').length]");
		assert.equal(lines[0], lines[1]);
		const marks = await evaluate("document.querySelectorAll('[data-la-preview] mark').length");
		assert.ok(marks >= 20);
		const focusAfter = await evaluate("document.activeElement && document.activeElement.id");
		assert.equal(focusAfter, 'cd-la-step-results');
		pass('sample log anonymized in the browser', `${marks} highlighted replacements, ${lines[0]} lines in = out, versions/IDs/timestamps kept, focus moved to results`);
		await shot('01-desktop-1440-result');

		// ---- generic mode + keep private + custom rule + category toggle
		await evaluate("document.querySelector('[data-la-mode][value=generic]').click(); document.querySelector('[data-la-keep-private]').click(); true");
		await click('[data-la-add-rule]');
		await evaluate("const r = document.querySelector('.cd-la-rule'); r.querySelector('[data-la-rule-pattern]').value = 'order_id=\\\\d+'; r.querySelector('[data-la-rule-label]').value = 'ORDER'; true");
		await runAndWait();
		const p2 = await evaluate("document.querySelector('[data-la-preview]').textContent");
		assert.ok(p2.includes('REDACTED_IPV4') && p2.includes('10.20.30.40') && p2.includes('192.168.1.10') && p2.includes('REDACTED_ORDER') && !p2.includes('order_id=9988776655') && !/IPV4_\d/.test(p2), 'options applied');
		pass('generic labels, keep-private IPv4 and a custom rule applied');
		await evaluate("document.querySelector('.cd-la-rule [data-la-rule-pattern]').value = '('; true");
		await click('[data-la-run]');
		await sleep(200);
		const ruleErr = await evaluate("[document.querySelector('.cd-la-rule [data-la-rule-pattern]').getAttribute('aria-invalid'), document.querySelector('[data-la-rule-error=pattern]').textContent, document.activeElement.matches('[data-la-rule-pattern]')]");
		assert.equal(ruleErr[0], 'true'); assert.match(ruleErr[1], /not a valid regular expression/); assert.equal(ruleErr[2], true);
		pass('invalid custom regex: inline error, aria-invalid and focus on the field', ruleErr[1].slice(0, 70));
		await click('[data-la-remove-rule]');
		await evaluate("document.querySelector('[data-la-mode][value=stable]').click(); document.querySelector('[data-la-keep-private]').click(); true");

		// ---- XSS: input is text, never markup
		await evaluate("document.querySelector('[data-la-input]').value = '<img src=x onerror=alert(1)> <script>alert(2)<\\/script> user=<b>bob</b> \"><svg onload=alert(3)>'; document.querySelector('[data-la-input]').dispatchEvent(new Event('input', {bubbles: true})); true");
		await runAndWait();
		const xss = await evaluate("({ el: document.querySelectorAll('[data-la-preview] img, [data-la-preview] script, [data-la-preview] svg, [data-la-preview] b').length, text: document.querySelector('[data-la-preview]').textContent })");
		await sleep(300);
		assert.equal(xss.el, 0); assert.deepEqual(dialogs, []); assert.ok(xss.text.includes('<img src=x onerror=alert(1)>'));
		pass('HTML/script in input is rendered as text only (no elements, no dialogs)');

		// ---- copy & downloads
		await cdp.send('Browser.grantPermissions', { permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'], origin: ORIGIN }).catch(() => {});
		await click('[data-la-sample]');
		await runAndWait();
		await click('[data-la-copy]');
		await waitFor("/copied|blocked/.test(document.querySelector('[data-la-status]').textContent)", 5000, 'copy status');
		const copyStatus = await evaluate("document.querySelector('[data-la-status]').textContent");
		await click('[data-la-download]');
		const mapDisabled = await evaluate("document.querySelector('[data-la-map]').disabled");
		assert.equal(mapDisabled, true);
		await click('[data-la-map-ack]');
		assert.equal(await evaluate("document.querySelector('[data-la-map]').disabled"), false);
		await click('[data-la-map]');
		await sleep(500);
		pass('copy, result download and acknowledged map download work without requests', copyStatus);

		// ---- storage / URL
		const after = await evaluate("JSON.stringify({ ls: localStorage.length, ss: sessionStorage.length, cookie: document.cookie, href: location.href })");
		const idb = await evaluate("indexedDB.databases ? indexedDB.databases().then(d => d.length) : 0");
		const { cookies: cookiesAfter } = await send('Network.getCookies', { urls: [ORIGIN] });
		assert.equal(after, before); assert.equal(idb, 0); assert.deepEqual(cookiesAfter, cookiesBefore);
		pass('nothing written to localStorage, sessionStorage, IndexedDB, cookies or the URL', after);

		// ---- large input via file
		phase = 'large';
		const big = path.join(profile, 'large.log');
		const base = fs.readFileSync(path.join(__dirname, 'fixtures/log-anonymizer/mixed.log'), 'utf8');
		const fd = fs.openSync(big, 'w');
		let size = 0;
		for (let i = 0; size < 30 * 1024 * 1024; i++) { const chunk = base.replace(/203\.0\.113\.\d+/g, () => '198.51.' + ((i >> 8) & 255) + '.' + (i & 255)); fs.writeSync(fd, chunk); size += Buffer.byteLength(chunk); }
		fs.closeSync(fd);
		const { root } = await send('DOM.getDocument', { depth: 1 });
		const { nodeId } = await send('DOM.querySelector', { nodeId: root.nodeId, selector: '[data-la-file]' });
		await send('DOM.setFileInputFiles', { nodeId, files: [big] });
		await waitFor("/Large files are not displayed/.test(document.querySelector('[data-la-source]').textContent)", 5000, 'file loaded');
		await evaluate("window.__gap = 0; window.__last = performance.now(); window.__probe = setInterval(() => { const n = performance.now(); window.__gap = Math.max(window.__gap, n - window.__last); window.__last = n; }, 50); window.__progressSeen = 0; window.__po = setInterval(() => { const p = document.querySelector('[data-la-progress]'); if (!p.hidden && p.value > 0) window.__progressSeen++; }, 100); true");
		const t0 = Date.now();
		await runAndWait(180000);
		const elapsed = Date.now() - t0;
		const perf = await evaluate("clearInterval(window.__probe); clearInterval(window.__po); ({ gap: Math.round(window.__gap), progress: window.__progressSeen, summary: document.querySelector('[data-la-summary]').textContent, truncated: document.querySelector('[data-la-truncated]').textContent })");
		assert.ok(perf.gap < 1000, 'main thread blocked for ' + perf.gap + ' ms');
		assert.ok(/lines processed/.test(perf.summary));
		assert.deepEqual(httpAfter('large'), [], 'requests during large processing');
		pass('30 MB file processed in the worker without freezing the page', `${(size / 1048576).toFixed(1)} MB in ${(elapsed / 1000).toFixed(1)} s; longest main-thread gap ${perf.gap} ms; progress updates seen ${perf.progress}; ${perf.summary.split('.')[0]}`);
		await shot('02-desktop-large-file');
		await click('[data-la-clear]');

		// ---- zero network requests across every interaction
		phase = 'final';
		const during = httpAfter();
		assert.deepEqual(during.filter(r => r.phase !== 'csp-probe'), [], 'HTTP requests after page load');
		pass('zero network requests while processing, toggling, copying, exporting and clearing', 'only blob: downloads; ' + requests.filter(r => r.phase !== 'load').length + ' non-HTTP or probe entries');
		assert.deepEqual(consoleErrors.filter(e => e.phase !== 'csp-probe'), [], 'console errors during interaction');
		pass('no console errors during interaction');

		// ---- cancel: the only case that restarts the worker (re-requests its static script, never data)
		phase = 'cancel';
		await send('DOM.setFileInputFiles', { nodeId: (await send('DOM.querySelector', { nodeId: (await send('DOM.getDocument', { depth: 1 })).root.nodeId, selector: '[data-la-file]' })).nodeId, files: [big] });
		await waitFor("/Large files are not displayed/.test(document.querySelector('[data-la-source]').textContent)", 5000, 'file loaded');
		await click('[data-la-run]');
		await click('[data-la-cancel]');
		await waitFor("/Cancelled/.test(document.querySelector('[data-la-status]').textContent) && !document.querySelector('[data-la-run]').disabled", 5000, 'cancelled');
		await sleep(500);
		const cancelReqs = httpAfter('cancel');
		assert.ok(cancelReqs.every(r => /\/assets\/js\/log-anonymizer\/(?:worker|engine)\.js\?(?:ver=\d+(?:&ev=\d+)?)$/.test(r.url) && new URL(r.url).origin === ORIGIN), JSON.stringify(cancelReqs));
		pass('cancel restarts the worker; only its static same-origin scripts are re-requested, no input data', cancelReqs.length + ' asset requests');
		await click('[data-la-clear]');

		// ---- keyboard
		await navigate();
		await evaluate("document.activeElement && document.activeElement.blur(); window.scrollTo(0, 0); document.querySelector('.cd-la').scrollIntoView(); true");
		await evaluate("(() => { const r = document.createRange(); r.selectNodeContents(document.querySelector('.cd-la')); r.collapse(true); const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); document.querySelector('[data-la-app]').setAttribute('tabindex','-1'); document.querySelector('[data-la-app]').focus(); document.querySelector('[data-la-app]').removeAttribute('tabindex'); return true; })()");
		const order = [];
		for (let i = 0; i < 40; i++) {
			await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
			await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
			const d = await evaluate("(() => { const e = document.activeElement; const cs = getComputedStyle(e); const vis = cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0 || getComputedStyle(e.closest('.cd-la-file') || e).outlineStyle !== 'none' || !!e.closest('.cd-la-file'); return { d: e.matches('[data-la-run]') ? 'RUN' : (e.getAttribute('data-la-sample') !== null ? 'SAMPLE' : e.tagName + (e.type ? ':' + e.type : '') + (e.value && e.type === 'checkbox' ? ':' + e.value : '')), vis }; })()");
			order.push(d);
			if (d.d === 'RUN') { break; }
		}
		const names = order.map(o => o.d);
		assert.ok(names.some(n => n.startsWith('TEXTAREA')) && names.includes('INPUT:file') && names.includes('SAMPLE') && names.filter(n => n.startsWith('INPUT:checkbox')).length >= 14 && names.includes('INPUT:radio') && names.at(-1) === 'RUN', names.join(' > '));
		assert.ok(order.every(o => o.vis), 'focus indicator visible on every stop');
		pass('keyboard: Tab reaches textarea, file picker, buttons, all categories, label mode and Anonymize with a visible focus ring', order.length + ' tab stops');
		await evaluate("document.querySelector('[data-la-input]').value = ''; document.querySelector('[data-la-sample]').focus(); true");
		await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: String.fromCharCode(13) });
		await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
		assert.ok(await evaluate("document.querySelector('[data-la-input]').value.length > 100"), 'Enter on the sample button loaded the sample');
		await evaluate("document.querySelector('[data-la-input]').focus(); true");
		await evaluate("window.__laDone = false; new MutationObserver((m, o) => { if (!document.querySelector('[data-la-results]').hidden) { window.__laDone = true; o.disconnect(); } }).observe(document.querySelector('[data-la-results]'), { attributes: true }); true");
		await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, modifiers: 2 });
		await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, modifiers: 2 });
		await waitFor('window.__laDone === true', 15000, 'keyboard run');
		pass('keyboard: Enter on "Load sample log", Ctrl+Enter in the text box runs the tool');

		// ---- accessible names & contrast
		const a11y = await evaluate(`(() => {
			const lum = c => { const m = c.match(/[\\d.]+/g).map(Number); const [r, g, b] = m.slice(0, 3).map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
			const bg = e => { for (let n = e; n; n = n.parentElement) { const c = getComputedStyle(n).backgroundColor; const m = c.match(/[\\d.]+/g); if (m && (m.length < 4 || Number(m[3]) > 0.9)) { return c; } } return 'rgb(8, 13, 19)'; };
			const ratio = e => { const a = lum(getComputedStyle(e).color), b = lum(bg(e)); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); };
			const missing = [];
			for (const c of document.querySelectorAll('.cd-la input, .cd-la textarea, .cd-la button, .cd-la [tabindex="0"]')) {
				if (c.closest('[hidden], template')) { continue; }
				const name = (c.getAttribute('aria-label') || (c.getAttribute('aria-labelledby') || '').split(' ').map(id => (document.getElementById(id) || {}).textContent || '').join(' ') || (c.labels && [...c.labels].map(l => l.textContent).join(' ')) || (c.tagName === 'BUTTON' ? c.textContent : '')).trim();
				if (!name) { missing.push(c.outerHTML.slice(0, 80)); }
			}
			const samples = ['.cd-la-help', '.cd-la-label', '.cd-la-check span', '.cd-la-example', '.cd-la-button--primary', '.cd-la-button--secondary', '.cd-la-button--ghost', '.cd-la-callout--warning strong', '.cd-la-callout--privacy', '.cd-la-table caption', '.cd-la-table td', '.cd-la-status', '.cd-la-summary', '.cd-la-info li', '.cd-la-meta', 'mark.cd-la-mark--ipv4', 'mark.cd-la-mark--secret', 'mark.cd-la-mark--username', 'mark.cd-la-mark--privateKey', '.cd-la-step span', '.cd-la-preview'];
			const contrast = {};
			for (const s of samples) { const e = document.querySelector(s); if (e) { contrast[s] = Math.round(ratio(e) * 100) / 100; } }
			return { missing, contrast };
		})()`);
		assert.deepEqual(a11y.missing, [], 'controls without accessible names');
		const low = Object.entries(a11y.contrast).filter(([, r]) => r < 4.5);
		assert.deepEqual(low, [], 'contrast below 4.5:1');
		pass('every visible control has an accessible name; text contrast ≥ 4.5:1 (WCAG AA)', 'min ' + Math.min(...Object.values(a11y.contrast)).toFixed(2) + ':1 over ' + Object.keys(a11y.contrast).length + ' styles');
		fs.writeFileSync(path.join(EVIDENCE, 'contrast.json'), JSON.stringify(a11y.contrast, null, 2));

		// ---- responsive
		for (const [w, h, mobile, name] of [[360, 780, true, '03-mobile-360'], [390, 844, true, '04-mobile-390'], [768, 1024, true, '05-tablet-768']]) {
			await viewport(w, h, mobile);
			await navigate();
			await click('[data-la-sample]');
			await runAndWait();
			const o = await evaluate("({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, smallTargets: [...document.querySelectorAll('.cd-la button:not([hidden]), .cd-la-check')].filter(e => e.offsetParent && e.getBoundingClientRect().height < 44).length })");
			assert.ok(o.sw <= o.cw, `horizontal overflow at ${w}px: ${o.sw} > ${o.cw}`);
			assert.equal(o.smallTargets, 0, 'touch targets under 44px');
			await shot(name);
			pass(`${w}px viewport: no horizontal page overflow, touch targets ≥ 44px`, `scrollWidth ${o.sw} ≤ ${o.cw}`);
		}

		// ---- no JavaScript
		await viewport(1440, 1000, false);
		await send('Emulation.setScriptExecutionDisabled', { value: true });
		await send('Page.navigate', { url: URL_UNDER_TEST });
		await sleep(1500);
		const nojs = await evaluate("({ app: document.querySelector('[data-la-app]').hidden, info: !!document.querySelector('#cd-la-limits'), text: document.body.innerText.includes('This tool needs JavaScript') })");
		assert.equal(nojs.app, true); assert.equal(nojs.info, true); assert.equal(nojs.text, true);
		await shot('06-no-javascript');
		pass('without JavaScript: explanatory notice, How it works / Privacy / Limitations still visible, no dead controls');
		await send('Emulation.setScriptExecutionDisabled', { value: false });
	} finally {
		fs.writeFileSync(path.join(EVIDENCE, 'browser-results.json'), JSON.stringify({ url: URL_UNDER_TEST, browser: path.basename(exe), at: new Date().toISOString(), results, requestsAfterLoad: requests.filter(r => r.phase !== 'load'), consoleErrors }, null, 2));
		await cdp.send('Browser.close').catch(() => {});
		proc.kill();
		await sleep(500);
		try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) { /* locked by browser on Windows */ }
	}
	console.log(`\n${results.length} browser checks passed. Evidence: ${EVIDENCE}`);
	process.exit(0);
})().catch(e => { console.error('FAIL: ' + e.message); process.exit(1); });
