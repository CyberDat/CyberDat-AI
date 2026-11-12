/*
 * Browser acceptance for the LotL / LOLBAS Command Analyzer against a running WordPress page.
 * Dependency-free: drives a headless Edge/Chrome over the DevTools protocol (Node >= 22 WebSocket).
 *
 *   node tests/lotl-analyzer-browser.test.cjs [url] [evidence-dir]
 *   default url: http://127.0.0.1:8090/tools/lotl-command-analyzer/  (tests/local-wp/up.sh)
 *
 * Only for local or authorized staging pages. Nothing is sent anywhere except page loads to <url>.
 */
'use strict';
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { expand } = require('./lotl-analyzer-corpus.test.cjs');

const URL_UNDER_TEST = process.argv[2] || 'http://127.0.0.1:8090/tools/lotl-command-analyzer/';
const ORIGIN = new URL(URL_UNDER_TEST).origin;
const EVIDENCE = process.argv[3] || path.join(os.homedir(), 'CyberDat-tools-lotl-analyzer-' + new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, 'Z'));
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
	const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cd-lotl-browser-'));
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
		if (msg.method === 'Network.requestWillBeSent') { requests.push({ phase, url: msg.params.request.url, type: msg.params.type || '' }); }
		if (msg.method === 'Runtime.exceptionThrown') { consoleErrors.push({ phase, text: msg.params.exceptionDetails.text }); }
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
	const shot = async name => { const { data } = await send('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(path.join(EVIDENCE, name + '.png'), Buffer.from(data, 'base64')); };
	const viewport = (w, h, mobile) => send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: mobile ? 2 : 1, mobile });
	const navigate = async () => {
		await send('Page.navigate', { url: URL_UNDER_TEST });
		await waitFor("document.readyState === 'complete' && !!document.querySelector('[data-lotl-app]') && !document.querySelector('[data-lotl-app]').hidden", 20000, 'tool ready');
		await sleep(300);
	};
	const click = sel => evaluate(`(() => { document.querySelector(${JSON.stringify(sel)}).click(); return true; })()`);
	const setInput = t => evaluate(`(() => { const i = document.querySelector('[data-lotl-input]'); i.value = ${JSON.stringify(t)}; i.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);
	const runAndWait = async (timeout = 30000) => {
		await evaluate("window.__done = false; new MutationObserver((m, o) => { if (!document.querySelector('[data-lotl-results]').hidden && !document.querySelector('[data-lotl-run]').disabled) { window.__done = true; o.disconnect(); } }).observe(document.querySelector('[data-lotl-analyzer]'), { subtree: true, attributes: true, childList: true }); true");
		await click('[data-lotl-run]');
		await waitFor("window.__done === true || !document.querySelector('[data-lotl-error]').hidden", timeout, 'result');
		const err = await evaluate("document.querySelector('[data-lotl-error]').hidden ? '' : document.querySelector('[data-lotl-error]').textContent");
		if (err) { throw new Error('Tool error: ' + err); }
	};
	const httpAfter = p => requests.filter(r => r.phase !== 'load' && (p ? r.phase === p : true) && /^(https?|wss?):/.test(r.url));
	const ASSET_RE = /\/assets\/js\/lotl-analyzer\/(?:worker|engine|lolbas-data)\.js\?ver=\d+(?:&ev=\d+)?(?:&dv=\d+)?$/;

	try {
		await viewport(1440, 1000, false);
		await navigate();
		const load = requests.filter(r => /^(https?|wss?):/.test(r.url));
		assert.deepEqual(load.filter(r => new URL(r.url).origin !== ORIGIN), [], 'third-party requests on load');
		assert.ok(['worker', 'engine', 'lolbas-data'].every(n => load.some(r => new RegExp('lotl-analyzer/' + n + '\\.js').test(r.url))), 'worker, engine and LOLBAS data preloaded');
		assert.ok(!load.some(r => /github/i.test(r.url)));
		pass('page load: first-party only; worker, engine and the bundled LOLBAS data load from this site, nothing from GitHub', load.length + ' requests');

		phase = 'csp-probe';
		const head = await evaluate("fetch('https://raw.githubusercontent.com/', {mode: 'no-cors'}).then(() => 'unblocked', e => 'blocked: ' + e.message)").catch(e => 'blocked: ' + e.message);
		assert.match(head, /^blocked/);
		pass('CSP connect-src blocks scripts on the page from reaching GitHub or any host', head.slice(0, 60));
		assert.deepEqual(consoleErrors.filter(e => e.phase === 'load'), []);
		consoleErrors.length = 0;
		pass('no console errors during page load');
		const wr = await cdp.send('Runtime.evaluate', { expression: "(() => { const out = []; for (const n of ['fetch','XMLHttpRequest','WebSocket','importScripts']) { try { n === 'fetch' ? self.fetch('/') : new self[n]('/'); out.push(n + ':allowed'); } catch (e) { out.push(n + ':blocked'); } } return out.join(','); })()", returnByValue: true }, workers[0]);
		assert.ok(!/allowed/.test(wr.result.value));
		pass('network APIs are disabled inside the worker', wr.result.value);
		const storage = () => evaluate("JSON.stringify({ ls: localStorage.length, ss: sessionStorage.length, cookie: document.cookie, href: location.href })");
		const before = await storage();

		phase = 'process';
		await click('[data-lotl-sample]');
		await runAndWait();
		const st = await evaluate(`(() => ({
			verdict: document.querySelector('[data-lotl-verdict]').textContent,
			commands: [...document.querySelectorAll('[data-lotl-commands] > li')].map(li => li.className.replace(/.*--/, '')),
			cats: [...document.querySelectorAll('[data-lotl-categories] th')].map(t => t.textContent),
			text: document.querySelector('[data-lotl-commands]').textContent,
			links: [...document.querySelectorAll('.cd-lotl a')].map(a => a.getAttribute('href') + ' ' + a.rel),
			decoded: document.querySelectorAll('.cd-lotl-decoded').length
		}))()`);
		assert.match(st.verdict, /strongly resembling/);
		assert.equal(st.commands.length, 8);
		assert.ok(st.commands.filter(c => c === 'high').length >= 4, st.commands.join(','));
		assert.ok(st.cats.includes('Download') && st.cats.includes('AWL Bypass'));
		assert.ok(/T1105/.test(st.text) && /From LOLBAS/.test(st.text) && /CyberDat heuristic/.test(st.text) && st.decoded >= 1 && /DownloadString/.test(st.text));
		assert.ok(st.links.every(l => /^https:\/\/(?:lolbas-project\.github\.io|github\.com|www\.elastic\.co|research\.splunk\.com|[a-z0-9.-]+)\/\S* noopener noreferrer$/.test(l) || l.startsWith(ORIGIN)), st.links.slice(0, 3).join('; '));
		assert.equal(await evaluate("document.activeElement && document.activeElement.id"), 'cd-lotl-step-results');
		pass('examples analyzed: 8 commands, documented LOLBAS functions with ATT&CK ids from LOLBAS, heuristics labeled separately, encoded PowerShell decoded; data links are plain https links', `${st.commands.join(', ')}; ${st.links.length} links`);
		await shot('01-desktop-1440-results');

		// XSS: commands are text only
		await setInput('mshta "javascript:document.write(\'<img src=x onerror=alert(1)>\')" <script>alert(2)</script>\n<svg onload=alert(3)> certutil -urlcache -f http://example.com/"><img src=x onerror=alert(4)> a\nrundll32 javascript:"\\..\\mshtml,RunHTMLApplication ";alert(5)\n{"CommandLine":"<b onmouseover=alert(6)>x</b>"}');
		await runAndWait();
		await sleep(300);
		const xss = await evaluate("({ el: document.querySelectorAll('.cd-la-results img, .cd-la-results script, .cd-la-results svg, .cd-la-results b, .cd-la-results iframe').length, bad: [...document.querySelectorAll('.cd-la-results a')].filter(a => !/^https:\\/\\//.test(a.getAttribute('href'))).length, text: document.querySelector('[data-lotl-commands]').textContent })");
		assert.equal(xss.el, 0); assert.equal(xss.bad, 0); assert.deepEqual(dialogs, []);
		assert.ok(xss.text.includes('<img src=x onerror=alert(4)>'));
		pass('HTML, scripts and javascript: URLs in commands are shown as text only: no elements, no non-https links, no dialogs');

		await click('[data-lotl-sample]');
		await runAndWait();
		await click('[data-lotl-report]');
		await sleep(400);
		assert.equal(await storage(), before);
		const { cookies } = await send('Network.getCookies', { urls: [ORIGIN] });
		assert.deepEqual(cookies, []);
		pass('JSON report generated locally; nothing written to storage, cookies or the URL');

		phase = 'large';
		const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/lotl-analyzer/corpus.json'), 'utf8'));
		const lines = corpus.suspicious.concat(corpus.benign).map(c => expand(c.cmd)).join('\n') + '\n';
		const big = path.join(profile, 'commands.txt');
		let text = '';
		while (text.length + lines.length < 4.9 * 1024 * 1024) { text += lines; }
		fs.writeFileSync(big, text);
		const fileNode = async () => (await send('DOM.querySelector', { nodeId: (await send('DOM.getDocument', { depth: 1 })).root.nodeId, selector: '[data-lotl-file]' })).nodeId;
		await send('DOM.setFileInputFiles', { nodeId: await fileNode(), files: [big] });
		await waitFor("/Large files are not displayed/.test(document.querySelector('[data-lotl-source]').textContent)", 5000, 'file loaded');
		await evaluate("window.__gap = 0; window.__last = performance.now(); window.__probe = setInterval(() => { const n = performance.now(); window.__gap = Math.max(window.__gap, n - window.__last); window.__last = n; }, 50); true");
		const t0 = Date.now();
		await runAndWait(120000);
		const ms = Date.now() - t0;
		const perf = await evaluate("clearInterval(window.__probe); ({ gap: Math.round(window.__gap), summary: document.querySelector('[data-lotl-summary]').textContent })");
		assert.deepEqual(httpAfter('large'), []);
		pass('4.9 MB file analyzed in the worker without network requests', `${(ms / 1000).toFixed(1)} s, longest main-thread gap ${perf.gap} ms (incl. rendering 300 cards); ${perf.summary.slice(0, 120)}`);
		fs.writeFileSync(path.join(EVIDENCE, 'large-input.json'), JSON.stringify({ bytes: text.length, elapsedMs: ms, longestMainThreadGapMs: perf.gap, summary: perf.summary }, null, 2));
		await click('[data-lotl-clear]');

		phase = 'final';
		assert.deepEqual(httpAfter().filter(r => r.phase !== 'csp-probe'), []);
		assert.deepEqual(consoleErrors.filter(e => e.phase !== 'csp-probe'), []);
		pass('input text is never sent: no HTTP requests after page load while analyzing, exporting and clearing; no console errors');

		phase = 'cancel';
		await send('DOM.setFileInputFiles', { nodeId: await fileNode(), files: [big] });
		await waitFor("/Large files are not displayed/.test(document.querySelector('[data-lotl-source]').textContent)", 5000, 'file loaded');
		await click('[data-lotl-run]');
		await click('[data-lotl-cancel]');
		await waitFor("/Cancelled/.test(document.querySelector('[data-lotl-status]').textContent)", 5000, 'cancelled');
		await sleep(600);
		const cr = httpAfter('cancel');
		assert.ok(cr.every(r => ASSET_RE.test(r.url) && new URL(r.url).origin === ORIGIN), JSON.stringify(cr));
		pass('Cancel restarts the worker; only its static same-origin scripts are re-requested', cr.map(r => new URL(r.url).pathname.split('/').pop()).join(', ') || 'served from cache');
		await click('[data-lotl-clear]');

		await navigate();
		await evaluate("(() => { const a = document.querySelector('[data-lotl-app]'); a.setAttribute('tabindex', '-1'); a.focus(); a.removeAttribute('tabindex'); return true; })()");
		const order = [];
		for (let i = 0; i < 12; i++) {
			await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
			await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
			const d = await evaluate("(() => { const e = document.activeElement; const cs = getComputedStyle(e); return { d: e.matches('[data-lotl-run]') ? 'RUN' : e.tagName + (e.type ? ':' + e.type : ''), vis: (cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0) || !!e.closest('.cd-la-file') || cs.boxShadow !== 'none' }; })()");
			order.push(d);
			if (d.d === 'RUN') { break; }
		}
		assert.ok(order.map(o => o.d).join('>').match(/TEXTAREA.*INPUT:file.*BUTTON.*BUTTON.*RUN/), order.map(o => o.d).join('>'));
		assert.ok(order.every(o => o.vis));
		await setInput('certutil -urlcache -f http://example.com/a a');
		await evaluate("document.querySelector('[data-lotl-input]').focus(); true");
		await evaluate("window.__done = false; new MutationObserver((m, o) => { if (!document.querySelector('[data-lotl-results]').hidden) { window.__done = true; o.disconnect(); } }).observe(document.querySelector('[data-lotl-results]'), { attributes: true }); true");
		await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, modifiers: 2 });
		await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, modifiers: 2 });
		await waitFor('window.__done === true', 15000, 'keyboard run');
		pass('keyboard: Tab order text box → file → buttons → Analyze with visible focus; Ctrl+Enter runs', order.map(o => o.d).join(' > '));

		await click('[data-lotl-sample]');
		await runAndWait();
		await evaluate("document.querySelectorAll('.cd-lotl-hints').forEach(d => d.open = true); true");
		const a11y = await evaluate(`(() => {
			const lum = c => { const m = c.match(/[\\d.]+/g).map(Number); const [r, g, b] = m.slice(0, 3).map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
			const bg = e => { for (let n = e; n; n = n.parentElement) { const c = getComputedStyle(n).backgroundColor; const m = c.match(/[\\d.]+/g); if (m && (m.length < 4 || Number(m[3]) > 0.9)) { return c; } } return 'rgb(8, 13, 19)'; };
			const ratio = e => { const a = lum(getComputedStyle(e).color), b = lum(bg(e)); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); };
			const missing = [];
			for (const c of document.querySelectorAll('.cd-lotl input, .cd-lotl textarea, .cd-lotl button, .cd-lotl a, .cd-lotl summary')) {
				if (c.closest('[hidden]')) { continue; }
				const name = (c.getAttribute('aria-label') || (c.labels && [...c.labels].map(l => l.textContent).join(' ')) || c.textContent || '').trim();
				if (!name) { missing.push(c.outerHTML.slice(0, 80)); }
			}
			const samples = ['.cd-la-help', '.cd-la-label', '.cd-la-button--primary', '.cd-la-button--secondary', '.cd-la-button--ghost', '.cd-la-callout--warning strong', '.cd-la-callout--privacy', '.cd-lotl-verdict strong', '.cd-la-summary', '.cd-lotl-sev--high', '.cd-lotl-sev--medium', '.cd-lotl-sev--low', '.cd-lotl-sev--info', '.cd-lotl-tag--lolbas', '.cd-lotl-tag--heuristic', '.cd-lotl-muted', '.cd-lotl-command__text', '.cd-lotl-desc', '.cd-lotl-fn', '.cd-lotl-detail', '.cd-lotl-match p', '.cd-lotl-match strong', '.cd-lotl-hints summary', '.cd-lotl-hints li', '.cd-lotl-refs a', '.cd-lotl-entry a', '.cd-lotl-pre', '.cd-la-info li', '.cd-la-info a', '.cd-la-meta', '.cd-la-step span'];
			const contrast = {};
			for (const s of samples) { const e = document.querySelector(s); if (e) { contrast[s] = Math.round(ratio(e) * 100) / 100; } }
			return { missing, contrast };
		})()`);
		assert.deepEqual(a11y.missing, []);
		assert.deepEqual(Object.entries(a11y.contrast).filter(([, r]) => r < 4.5), [], JSON.stringify(a11y.contrast));
		assert.ok(Object.keys(a11y.contrast).length >= 26, Object.keys(a11y.contrast).length + ' styles sampled');
		fs.writeFileSync(path.join(EVIDENCE, 'contrast.json'), JSON.stringify(a11y.contrast, null, 2));
		pass('every control and link has an accessible name; text contrast ≥ 4.5:1', 'min ' + Math.min(...Object.values(a11y.contrast)).toFixed(2) + ':1 over ' + Object.keys(a11y.contrast).length + ' styles');

		for (const [w, h, name] of [[360, 780, '02-mobile-360'], [390, 844, '03-mobile-390'], [768, 1024, '04-tablet-768']]) {
			await viewport(w, h, true);
			await navigate();
			await click('[data-lotl-sample]');
			await runAndWait();
			const o = await evaluate("({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, small: [...document.querySelectorAll('.cd-lotl button:not([hidden]), .cd-lotl summary')].filter(e => e.offsetParent && e.getBoundingClientRect().height < 44).map(e => e.textContent.trim().slice(0, 30)) })");
			assert.ok(o.sw <= o.cw, `overflow at ${w}: ${o.sw} > ${o.cw}`);
			assert.deepEqual(o.small, []);
			await evaluate("window.scrollTo(0, 0); true");
			await shot(name);
			await evaluate("document.querySelector('[data-lotl-commands]').scrollIntoView(); true");
			await shot(name + '-results');
			pass(`${w}px viewport: no horizontal page overflow, touch targets ≥ 44px`, `scrollWidth ${o.sw}`);
		}

		await viewport(1440, 1000, false);
		await send('Emulation.setScriptExecutionDisabled', { value: true });
		await send('Page.navigate', { url: URL_UNDER_TEST });
		await sleep(1500);
		const nojs = await evaluate("({ app: document.querySelector('[data-lotl-app]').hidden, info: ['#cd-lotl-how', '#cd-lotl-source-title', '#cd-lotl-privacy', '#cd-lotl-limits'].every(s => !!document.querySelector(s)), text: document.body.innerText.includes('This tool needs JavaScript') })");
		assert.deepEqual(nojs, { app: true, info: true, text: true });
		await shot('05-no-javascript');
		pass('without JavaScript: notice shown; How it works, Data source and license, Privacy, Limitations still visible');
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
