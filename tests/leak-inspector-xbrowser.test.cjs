/*
 * Cross-browser acceptance (Firefox, WebKit) for the System Prompt & Agent Leak Inspector via Playwright.
 * Playwright is NOT a repository dependency:
 *   NODE_PATH=<pw>/node_modules node tests/leak-inspector-xbrowser.test.cjs [url] [evidence-dir] [browsers]
 * Optional: CYBERDAT_WEBKIT_EXECUTABLE (task-local WebKit loader), CYBERDAT_BASIC_AUTH_FILE.
 * Real Safari and iOS devices are not covered: Playwright WebKit is the WebKit engine, not Safari.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
let playwright;
try { playwright = require('playwright'); } catch (e) { console.log('SKIP: Playwright is not installed (intentionally not a repository dependency).'); process.exit(0); }

const URL_UNDER_TEST = process.argv[2] || 'http://127.0.0.1:18091/tools/agent-leak-inspector/';
const ORIGIN = new URL(URL_UNDER_TEST).origin;
const EVIDENCE = process.argv[3] || path.join(os.tmpdir(), 'cyberdat-lki-xbrowser-' + Date.now());
const BROWSERS = (process.argv[4] || 'firefox,webkit').split(',');
fs.mkdirSync(EVIDENCE, { recursive: true });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const summary = {};
const BIG = path.join(os.tmpdir(), 'cd-lki-xbrowser.txt');
{ const unit = 'User: Where is my parcel? Assistant: Please share the order number and I will check the delivery status for you.\n'; fs.writeFileSync(BIG, unit.repeat(Math.ceil(4.8 * 1024 * 1024 / unit.length))); }
const UNKNOWN_LONG = 'Zq7' + 'Lm2Vx9Kp4Wd8Nf3Rt6Yh1';

async function runBrowser(name) {
	const results = [];
	const pass = (label, detail) => { results.push({ label, detail }); console.log(`PASS [${name}]: ${label}${detail ? ' — ' + detail : ''}`); };
	const launchOptions = name === 'webkit' && process.env.CYBERDAT_WEBKIT_EXECUTABLE ? { executablePath: process.env.CYBERDAT_WEBKIT_EXECUTABLE } : {};
	const browser = await playwright[name].launch(launchOptions);
	const context = await browser.newContext(Object.assign({ acceptDownloads: true, viewport: { width: 1280, height: 900 } }, require('./lib/basic-auth.cjs').playwrightOptions()));
	const requests = [], consoleErrors = [], dialogs = [];
	let phase = 'load';
	context.on('request', r => requests.push({ phase, url: r.url() }));
	const page = await context.newPage();
	// The CSP probe's violation report can arrive after the phase changed (Firefox); classify it by its text.
	page.on('console', m => { if (m.type() === 'error') { consoleErrors.push({ phase: phase === 'csp-probe' || /debugger eval code|api\.example\.com\/v1/.test(m.text()) ? 'probe' : phase, text: m.text() }); } });
	page.on('pageerror', e => consoleErrors.push({ phase, text: 'pageerror: ' + e.message }));
	page.on('dialog', d => { dialogs.push(d.message()); d.dismiss(); });
	const until = async (fn, arg, timeout = 20000) => { const end = Date.now() + timeout; while (Date.now() < end) { if (await page.evaluate(fn, arg).catch(() => false)) { return; } await sleep(100); } throw new Error('Timed out: ' + fn.toString().slice(0, 80)); };
	const http = p => requests.filter(r => r.phase === p && /^(https?|wss?):/.test(r.url));
	const run = async (timeout = 60000) => {
		await page.click('[data-lki-run]');
		await until(() => !document.querySelector('[data-lki-run]').disabled && (!document.querySelector('[data-lki-results]').hidden || !document.querySelector('[data-lki-error]').hidden), null, timeout);
		assert.equal(await page.$eval('[data-lki-error]', e => (e.hidden ? '' : e.textContent)), '');
	};
	const ready = () => until(() => document.readyState === 'complete' && !!document.querySelector('[data-lki-app]') && !document.querySelector('[data-lki-app]').hidden);
	try {
		await page.goto(URL_UNDER_TEST);
		await ready();
		await sleep(500);
		assert.deepEqual(requests.filter(r => /^https?:/.test(r.url) && new URL(r.url).origin !== ORIGIN), []);
		const w = page.workers();
		assert.ok(w.some(x => /leak-inspector\/worker\.js/.test(x.url())));
		const lock = await w[0].evaluate(() => ['fetch', 'XMLHttpRequest', 'WebSocket', 'importScripts'].map(n => { try { if (n === 'fetch') { self.fetch('/'); } else { new self[n]('/'); } return n + ':allowed'; } catch (e) { return n + ':blocked'; } }).join(','));
		assert.ok(!/allowed/.test(lock));
		pass('first-party page load; same-origin worker with network APIs disabled', lock);
		phase = 'csp-probe';
		assert.match(await page.evaluate(() => fetch('https://api.example.com/v1', { mode: 'no-cors' }).then(() => 'unblocked', e => 'blocked: ' + e.message)), /^blocked/);
		pass('CSP blocks page scripts from contacting any service');

		phase = 'process';
		await page.click('[data-lki-sample]');
		await run();
		const a = await page.evaluate(() => ({ verdict: document.querySelector('[data-lki-verdict]').textContent, text: document.querySelector('[data-lki-list]').textContent }));
		assert.match(a.verdict, /^High-risk weaknesses found\./);
		assert.ok(/LKI-SEC-001/.test(a.text) && /LKI-AUT-001/.test(a.text) && !/EXAMPLE0123456789/.test(a.text));
		await page.check('[data-lki-mode][value=leak]');
		await run();
		assert.ok(/LKC-001/.test(await page.$eval('[data-lki-list]', e => e.textContent)) && /LKC-003/.test(await page.$eval('[data-lki-list]', e => e.textContent)));
		pass('example: audit finds weaknesses, leak check finds verbatim and Base64 fragments');
		await page.screenshot({ path: path.join(EVIDENCE, name + '-01-leak.png') });

		await page.fill('[data-lki-prompt]', 'Backend key ' + S.OPENAI_PROJECT_KEY + ' and token ' + UNKNOWN_LONG + '. Keep all answers short and friendly for every customer you help today.');
		await page.fill('[data-lki-response]', 'Here: ' + S.OPENAI_PROJECT_KEY + ' / ' + UNKNOWN_LONG + '. Keep all answers short and friendly for every customer you help today.');
		await run();
		const dl = await Promise.all([page.waitForEvent('download'), page.click('[data-lki-report]')]);
		const out = path.join(EVIDENCE, name + '-report.json');
		await dl[0].saveAs(out);
		const exported = fs.readFileSync(out, 'utf8');
		const ui = await page.$eval('[data-lki-results]', e => e.textContent);
		for (const v of [S.OPENAI_PROJECT_KEY, UNKNOWN_LONG]) { assert.ok(!exported.includes(v) && !ui.includes(v), 'leaked ' + v.slice(0, 4)); }
		assert.ok(/LKC-005/.test(ui));
		pass('secrets and unrecognized long values are masked in results and the downloaded report');

		await page.fill('[data-lki-response]', '<img src=x onerror=alert(1)><script>alert(2)</script><svg onload=alert(3)>');
		await run();
		await sleep(300);
		assert.equal(await page.evaluate(() => document.querySelectorAll('.cd-la-results img, .cd-la-results script, .cd-la-results svg, .cd-la-results a').length), 0);
		assert.deepEqual(dialogs, []);
		assert.equal(await page.evaluate(() => JSON.stringify([localStorage.length, sessionStorage.length, document.cookie])), JSON.stringify([0, 0, '']));
		pass('markup and scripts are shown as text only; no dialogs; nothing stored');

		phase = 'large';
		await page.fill('[data-lki-prompt]', 'You are a delivery assistant. Ask for the order number and check the delivery status. ' + 'Be friendly and brief. '.repeat(100));
		await page.setInputFiles('[data-lki-response-file]', BIG);
		await until(() => /Large files are not displayed/.test(document.querySelector('[data-lki-response-source]').textContent));
		const t0 = Date.now();
		await run(180000);
		const ms = Date.now() - t0;
		assert.deepEqual(http('large'), []);
		summary[name + 'LargeMs'] = ms;
		pass('4.8 MB transcript compared without network requests', (ms / 1000).toFixed(1) + ' s');
		phase = 'cancel';
		await page.click('[data-lki-run]');
		await page.click('[data-lki-cancel]');
		await until(() => /Cancelled/.test(document.querySelector('[data-lki-status]').textContent));
		await sleep(800);
		assert.ok(http('cancel').every(r => /\/assets\/js\/leak-inspector\/(?:worker|engine)\.js\?ver=\d+/.test(r.url) && new URL(r.url).origin === ORIGIN));
		pass('Cancel re-requests only static same-origin worker scripts', http('cancel').length + ' requests');
		await page.click('[data-lki-clear]');
		phase = 'final';
		assert.deepEqual(requests.filter(r => !['load', 'csp-probe', 'cancel'].includes(r.phase) && /^(https?|wss?):/.test(r.url)), []);
		assert.deepEqual(consoleErrors.filter(e => e.phase !== 'probe'), []);
		pass('input text is never sent: no HTTP requests during checks, exports and clearing; no console errors');

		await page.setViewportSize({ width: 360, height: 780 });
		await page.goto(URL_UNDER_TEST);
		await ready();
		await page.click('[data-lki-sample]');
		await page.check('[data-lki-mode][value=leak]');
		await run();
		const o = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, small: [...document.querySelectorAll('.cd-lki button:not([hidden]), .cd-lki-mode, .cd-lki-number input')].filter(e => e.offsetParent && e.getBoundingClientRect().height < 44).length }));
		assert.ok(o.sw <= o.cw);
		assert.equal(o.small, 0);
		await page.screenshot({ path: path.join(EVIDENCE, name + '-02-mobile-360.png') });
		pass('360px: no horizontal overflow, touch targets >= 44px', 'scrollWidth ' + o.sw);

		await page.check('[data-lki-mode][value=audit]');
		await page.fill('[data-lki-prompt]', 'Use ' + S.GITHUB_PAT + ' for every call.');
		await page.focus('[data-lki-run]');
		const walk = [];
		for (let i = 0; i < 20; i++) {
			await page.keyboard.press('Shift+Tab');
			const f = await page.evaluate(() => ({ id: document.activeElement.id, ok: document.hasFocus() && document.activeElement === document.querySelector('[data-lki-prompt]') }));
			walk.push(f.id || '?');
			if (f.ok) { break; }
		}
		assert.equal(await page.evaluate(() => document.activeElement === document.querySelector('[data-lki-prompt]')), true, 'Tab navigation must reach the prompt');
		await page.keyboard.press('Control+Enter');
		await until(() => !document.querySelector('[data-lki-results]').hidden && /LKI-SEC-001/.test(document.querySelector('[data-lki-list]').textContent));
		pass('keyboard: Shift+Tab reaches the prompt and Ctrl+Enter runs the audit', walk.join(' < '));
	} finally {
		summary[name] = results.length;
		fs.writeFileSync(path.join(EVIDENCE, name + '-results.json'), JSON.stringify({ browser: name, version: browser.version(), results, consoleErrors }, null, 2));
		await browser.close();
	}
}

(async () => {
	for (const n of BROWSERS) { await runBrowser(n); }
	fs.writeFileSync(path.join(EVIDENCE, 'xbrowser-results.json'), JSON.stringify(summary, null, 2));
	console.log('\nAll cross-browser checks passed: ' + JSON.stringify(summary));
	try { fs.unlinkSync(BIG); } catch (e) { /* ignore */ }
})().catch(e => { console.error('FAIL: ' + e.message); try { fs.unlinkSync(BIG); } catch (x) { /* ignore */ } process.exit(1); });
