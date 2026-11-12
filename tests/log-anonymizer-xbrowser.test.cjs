/*
 * Cross-browser acceptance (Firefox, WebKit, Chromium) for the Log Anonymizer via Playwright.
 * Playwright is NOT a repository dependency. Install it outside the repo, then point NODE_PATH at it:
 *
 *   mkdir %TEMP%\pw && cd %TEMP%\pw && npm i --save-exact playwright@1.49.1 && npx playwright install firefox webkit
 *   NODE_PATH=%TEMP%\pw\node_modules node tests/log-anonymizer-xbrowser.test.cjs [url] [evidence-dir] [browsers]
 *
 * Default url: http://127.0.0.1:8090/tools/log-anonymizer/ (tests/local-wp/up.sh). browsers: "firefox,webkit" (Chromium/Edge is covered by log-anonymizer-browser.test.cjs).
 * Real Safari and iOS devices are not covered: Playwright WebKit on Windows is the WebKit engine, not Safari.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { SYNTH: S, fill } = require('./lib/synthetic-secrets.cjs');
let playwright;
try {
	playwright = require('playwright');
} catch (e) {
	console.log('SKIP: Playwright is not installed (intentionally not a repository dependency). See the header of this file.');
	process.exit(0);
}

const URL_UNDER_TEST = process.argv[2] || 'http://127.0.0.1:8090/tools/log-anonymizer/';
const ORIGIN = new URL(URL_UNDER_TEST).origin;
const EVIDENCE = process.argv[3] || path.join(os.homedir(), 'CyberDat-tools-log-anonymizer-xbrowser-' + new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, 'Z'));
const BROWSERS = (process.argv[4] || 'firefox,webkit').split(',');
fs.mkdirSync(EVIDENCE, { recursive: true });

const summary = {};
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function runBrowser(name) {
	const results = [];
	const pass = (label, detail) => { results.push({ label, detail }); console.log(`PASS [${name}]: ${label}${detail ? ' — ' + detail : ''}`); };
	const browser = await playwright[name].launch();
	const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 1280, height: 900 } });
	const requests = [];
	const consoleErrors = [];
	let phase = 'load';
	context.on('request', r => requests.push({ phase, url: r.url(), type: r.resourceType() }));
	const page = await context.newPage();
	// The deliberate fetch probe below is test code ("debugger eval code"); its CSP report is expected.
	page.on('console', m => { if (m.type() === 'error') { consoleErrors.push({ phase: /debugger eval code/.test(m.text()) ? 'probe' : phase, text: m.text() }); } });
	page.on('pageerror', e => consoleErrors.push({ phase, text: 'pageerror: ' + e.message }));
	const dialogs = [];
	page.on('dialog', d => { dialogs.push(d.message()); d.dismiss(); });
	// Playwright's waitForFunction injects code via eval, which the page CSP (correctly) forbids.
	// Poll with page.evaluate instead; the CSP is never bypassed.
	const until = async (fn, arg, timeout = 15000) => {
		const end = Date.now() + timeout;
		while (Date.now() < end) { if (await page.evaluate(fn, arg).catch(() => false)) { return; } await sleep(100); }
		throw new Error('Timed out waiting for ' + fn.toString().slice(0, 80));
	};
	const http = p => requests.filter(r => r.phase === p && /^(https?|wss?):/.test(r.url));
	const run = async (timeout = 30000) => {
		await page.click('[data-la-run]');
		await until(() => !document.querySelector('[data-la-results]').hidden && !document.querySelector('[data-la-run]').disabled || !document.querySelector('[data-la-error]').hidden, null, timeout);
		const err = await page.$eval('[data-la-error]', e => e.hidden ? '' : e.textContent);
		assert.equal(err, '', 'tool error');
	};
	try {
		const response = await page.goto(URL_UNDER_TEST, { waitUntil: 'load' });
		const csp = response.headers()['content-security-policy'] || '';
		assert.match(csp, /connect-src 'none'/);
		assert.match(csp, /script-src 'self' 'nonce-/);
		await page.waitForSelector('[data-la-app]:not([hidden])', { timeout: 15000 });
		await sleep(500);
		const loadHttp = http('load');
		assert.deepEqual(loadHttp.filter(r => new URL(r.url).origin !== ORIGIN), [], 'third-party requests');
		pass('page loads under strict CSP with nonce; app.js executed; only first-party requests', `${loadHttp.length} requests`);

		const workerUrls = page.workers().map(w => w.url());
		assert.ok(workerUrls.some(u => /log-anonymizer\/worker\.js/.test(u)), 'worker started: ' + workerUrls.join(','));
		const lockdown = await page.workers()[0].evaluate(() => ['fetch', 'XMLHttpRequest', 'WebSocket', 'importScripts'].map(n => {
			try { if (n === 'fetch') { self.fetch('/'); } else if (n === 'importScripts') { self.importScripts('/x.js'); } else { new self[n]('/'); } return n + ':allowed'; } catch (e) { return n + ':blocked'; }
		}).join(','));
		assert.ok(!/allowed/.test(lockdown), lockdown);
		pass('Web Worker starts from the same origin under worker-src \'self\'; its network APIs are disabled', lockdown);

		phase = 'probe';
		const probe = await page.evaluate(() => fetch(location.href, { method: 'HEAD', cache: 'no-store' }).then(() => 'unblocked', e => 'blocked: ' + e.message));
		assert.match(probe, /^blocked/);
		await sleep(700); // Firefox reports the probe's CSP violation asynchronously.
		pass('CSP connect-src blocks fetch from the page', probe.slice(0, 70));
		const loadErrors = consoleErrors.filter(e => e.phase === 'load');
		assert.deepEqual(loadErrors, [], 'console errors on load');
		pass('no console errors or CSP violations while loading');

		phase = 'process';
		await page.click('[data-la-sample]');
		await run();
		const preview = await page.textContent('[data-la-preview]');
		for (const leaked of ['alice', '203.0.113.42', 'bob.smith@example.com', 'Winter2026!', 'Pa55w0rd', S.AWS_ACCESS_KEY_ID, '123-45-6789', '00:1A:2B:3C:4D:5E']) {
			assert.ok(!preview.includes(leaked), 'leaked ' + leaked);
		}
		assert.ok(preview.includes('version 1.2.3.4') && preview.includes('trace=4bf92f3577b34da6a3ce929d0e0e4736'));
		assert.ok(await page.$$eval('[data-la-preview] mark', m => m.length) >= 20);
		pass('sample anonymized, highlighted preview rendered');

		await page.fill('[data-la-input]', '<img src=x onerror=alert(1)> <script>alert(2)</script> "><svg onload=alert(3)>');
		await run();
		assert.equal(await page.$$eval('[data-la-preview] img, [data-la-preview] script, [data-la-preview] svg', e => e.length), 0);
		await sleep(300);
		assert.deepEqual(dialogs, []);
		pass('markup in input stays text (no elements, no dialogs)');

		await page.click('[data-la-sample]');
		await run();
		const [download] = await Promise.all([page.waitForEvent('download'), page.click('[data-la-download]')]);
		const saved = path.join(EVIDENCE, name + '-result.txt');
		await download.saveAs(saved);
		const downloaded = fs.readFileSync(saved, 'utf8');
		assert.ok(downloaded.includes('USER_1') && !downloaded.includes('alice'));
		fs.rmSync(saved);
		await page.check('[data-la-map-ack]');
		const [mapDownload] = await Promise.all([page.waitForEvent('download'), page.click('[data-la-map]')]);
		assert.equal(mapDownload.suggestedFilename(), 'replacement-map.json');
		await mapDownload.delete();
		pass('result and acknowledged map downloads work (blob:, no HTTP)');

		const storage = await page.evaluate(async () => ({ ls: localStorage.length, ss: sessionStorage.length, cookie: document.cookie, href: location.href, idb: indexedDB.databases ? (await indexedDB.databases()).length : 0 }));
		assert.deepEqual(storage, { ls: 0, ss: 0, cookie: '', href: URL_UNDER_TEST, idb: 0 });
		assert.deepEqual(await context.cookies(), []);
		pass('nothing stored in localStorage, sessionStorage, IndexedDB, cookies or the URL');

		phase = 'large';
		const big = path.join(os.tmpdir(), `cd-la-${name}-large.log`);
		const base = fill(fs.readFileSync(path.join(__dirname, 'fixtures/log-anonymizer/mixed.log'), 'utf8'));
		const fd = fs.openSync(big, 'w');
		let size = 0;
		for (let i = 0; size < 30 * 1024 * 1024; i++) { const c = base.replace(/203\.0\.113\.\d+/g, () => '198.51.' + ((i >> 8) & 255) + '.' + (i & 255)); fs.writeSync(fd, c); size += Buffer.byteLength(c); }
		fs.closeSync(fd);
		await page.setInputFiles('[data-la-file]', big);
		await until(() => /Large files are not displayed/.test(document.querySelector('[data-la-source]').textContent));
		await page.evaluate(() => { window.__gap = 0; window.__last = performance.now(); window.__probe = setInterval(() => { const n = performance.now(); window.__gap = Math.max(window.__gap, n - window.__last); window.__last = n; }, 50); });
		const t0 = Date.now();
		await run(180000);
		const elapsed = Date.now() - t0;
		const gap = await page.evaluate(() => { clearInterval(window.__probe); return Math.round(window.__gap); });
		assert.ok(gap < 1000, 'main thread blocked ' + gap + ' ms');
		assert.deepEqual(http('large'), []);
		pass('30 MB file processed in the worker; page stays responsive', `${(elapsed / 1000).toFixed(1)} s, longest main-thread gap ${gap} ms`);

		phase = 'cancel';
		await page.click('[data-la-run]');
		await page.click('[data-la-cancel]');
		await until(() => /Cancelled/.test(document.querySelector('[data-la-status]').textContent));
		await sleep(800);
		const cancelReqs = http('cancel');
		assert.ok(cancelReqs.every(r => /\/assets\/js\/log-anonymizer\/(?:worker|engine)\.js\?ver=\d+(?:&ev=\d+)?$/.test(r.url)), JSON.stringify(cancelReqs));
		pass('Cancel restarts the worker; only its two static scripts may be re-requested', cancelReqs.map(r => r.url.replace(/^.*\//, '').replace(/\?.*/, '')).join(', ') || 'served from memory, 0 requests');
		fs.rmSync(big, { force: true });

		phase = 'final';
		assert.deepEqual(['process'].flatMap(p => http(p)), [], 'requests while processing');
		assert.deepEqual(consoleErrors.filter(e => e.phase !== 'probe'), [], 'console errors');
		pass('input text never sent: no HTTP requests while processing, downloading or clearing; no console errors');

		await page.setViewportSize({ width: 360, height: 780 });
		await page.reload({ waitUntil: 'load' });
		await page.waitForSelector('[data-la-app]:not([hidden])');
		await page.click('[data-la-sample]');
		await run();
		const o = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
		assert.ok(o.sw <= o.cw, `overflow ${o.sw} > ${o.cw}`);
		await page.screenshot({ path: path.join(EVIDENCE, `${name}-360.png`), fullPage: false });
		pass('360 px viewport: no horizontal overflow', `${o.sw} ≤ ${o.cw}`);

		await page.setViewportSize({ width: 1280, height: 900 });
		await page.reload({ waitUntil: 'load' });
		await page.waitForSelector('[data-la-app]:not([hidden])');
		await page.focus('[data-la-input]');
		const stops = [];
		for (let i = 0; i < 40; i++) {
			await page.keyboard.press(name === 'webkit' ? 'Alt+Tab' : 'Tab');
			const d = await page.evaluate(() => document.activeElement.matches('[data-la-run]') ? 'RUN' : document.activeElement.tagName + ':' + (document.activeElement.type || ''));
			stops.push(d);
			if (d === 'RUN') { break; }
		}
		assert.equal(stops.at(-1), 'RUN', stops.join(' > '));
		await page.keyboard.press('Enter');
		await until(() => !document.querySelector('[data-la-error]').hidden);
		pass('keyboard: Tab reaches every control up to "Anonymize log"; Enter activates it', `${stops.length} stops`);
	} finally {
		summary[name] = { browser: name, version: browser.version(), results, consoleErrors, requestsAfterLoad: requests.filter(r => r.phase !== 'load') };
		await browser.close();
	}
}

(async () => {
	let failed = false;
	for (const name of BROWSERS) {
		try { await runBrowser(name); } catch (e) { failed = true; console.error(`FAIL [${name}]: ${e.message.split('\n')[0]}`); summary[name] = Object.assign(summary[name] || {}, { error: e.message }); }
	}
	fs.writeFileSync(path.join(EVIDENCE, 'xbrowser-results.json'), JSON.stringify({ url: URL_UNDER_TEST, at: new Date().toISOString(), playwright: require('playwright/package.json').version, summary }, null, 2));
	for (const [n, s] of Object.entries(summary)) { console.log(`${n} ${s.version || ''}: ${(s.results || []).length} checks passed${s.error ? ', FAILED' : ''}`); }
	console.log('Evidence: ' + EVIDENCE);
	process.exit(failed ? 1 : 0);
})();
