/*
 * Cross-browser acceptance (Firefox, WebKit) for the AI Model Bill of Materials via Playwright.
 * Playwright is NOT a repository dependency (see tests/log-anonymizer-xbrowser.test.cjs for installation):
 *   NODE_PATH=<pw>/node_modules node tests/ai-bom-xbrowser.test.cjs [url] [evidence-dir] [browsers]
 * Real Safari and iOS devices are not covered: Playwright WebKit on Windows is the WebKit engine, not Safari.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const { bigBom } = require('./lib/ai-bom-inputs.cjs');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/ai-model-bom/engine.js'));
let playwright;
try { playwright = require('playwright'); } catch (e) { console.log('SKIP: Playwright is not installed (intentionally not a repository dependency).'); process.exit(0); }

const URL_UNDER_TEST = process.argv[2] || 'http://127.0.0.1:18091/tools/ai-model-bom/';
const ORIGIN = new URL(URL_UNDER_TEST).origin;
const EVIDENCE = process.argv[3] || path.join(os.tmpdir(), 'cyberdat-ai-bom-xbrowser-' + Date.now());
const BROWSERS = (process.argv[4] || 'firefox,webkit').split(',');
fs.mkdirSync(EVIDENCE, { recursive: true });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const EXAMPLE_IDS = ['AIBOM-DAT-002', 'AIBOM-DEP-001', 'AIBOM-DOC-002', 'AIBOM-LIC-002', 'AIBOM-NET-001', 'AIBOM-VER-003', 'AIBOM-WGT-001', 'AIBOM-WGT-002'];
const BIG = path.join(os.tmpdir(), 'cd-ai-bom-xbrowser.cdx.json');
const big = bigBom(4.6 * 1024 * 1024);
fs.writeFileSync(BIG, big.text);
const summary = {};

async function runBrowser(name) {
	const results = [];
	const pass = (label, detail) => { results.push({ label, detail }); console.log(`PASS [${name}]: ${label}${detail ? ' — ' + detail : ''}`); };
	const launchOptions = name === 'webkit' && process.env.CYBERDAT_WEBKIT_EXECUTABLE ? { executablePath: process.env.CYBERDAT_WEBKIT_EXECUTABLE } : {};
	const browser = await playwright[name].launch(launchOptions);
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
	const run = async (timeout = 60000, allowError = false) => {
		await page.click('[data-bom-run]');
		await until(() => !document.querySelector('[data-bom-run]').disabled && (!document.querySelector('[data-bom-results]').hidden || !document.querySelector('[data-bom-error]').hidden), null, timeout);
		const err = await page.$eval('[data-bom-error]', e => (e.hidden ? '' : e.textContent));
		if (!allowError) { assert.equal(err, ''); }
		return err;
	};
	const ids = () => page.evaluate(() => [...new Set([...document.querySelectorAll('[data-bom-list] .cd-bom-finding__head code')].map(c => c.textContent))].sort());
	const ready = () => until(() => document.readyState === 'complete' && !!document.querySelector('[data-bom-app]') && !document.querySelector('[data-bom-app]').hidden);
	const loadExample = async () => { await page.click('[data-bom-sample]'); await until(() => document.querySelector('#cd-bom-model-name').value === 'Ticket Router'); };
	const setMode = m => page.check('[data-bom-mode][value="' + m + '"]');
	try {
		await page.goto(URL_UNDER_TEST);
		await ready();
		await sleep(500);
		const load = requests.filter(r => /^https?:/.test(r.url));
		assert.deepEqual(load.filter(r => new URL(r.url).origin !== ORIGIN), []);
		const w = page.workers();
		assert.ok(w.some(x => /ai-model-bom\/worker\.js/.test(x.url())));
		const lock = await w[0].evaluate(() => ['fetch', 'XMLHttpRequest', 'WebSocket', 'importScripts'].map(n => { try { if (n === 'fetch') { self.fetch('/'); } else { new self[n]('/'); } return n + ':allowed'; } catch (e) { return n + ':blocked'; } }).join(','));
		assert.ok(!/allowed/.test(lock));
		pass('first-party page load; same-origin worker with network APIs disabled', lock);
		phase = 'csp-probe';
		const probe = await page.evaluate(() => fetch('https://registry.example.com/', { mode: 'no-cors' }).then(() => 'unblocked', e => 'blocked: ' + e.message));
		assert.match(probe, /^blocked/);
		pass('CSP blocks page scripts from contacting a model registry or any host', probe.slice(0, 50));

		phase = 'translate';
		for (const k of ['weights', 'datasets', 'dependencies', 'apis', 'metrics']) { await page.click(`[data-bom-add="${k}"]`); }
		const bad = await page.evaluate(() => [...document.querySelectorAll('[data-bom] input:not([type=radio]):not([type=checkbox]), [data-bom] textarea, [data-bom] select, [data-bom] pre, [data-bom-results], [data-bom-error]')].filter(e => !(e.getAttribute('translate') === 'no' && e.classList.contains('notranslate'))).length);
		assert.equal(bad, 0);
		pass('inputs, previews and results carry translate="no" and notranslate (also in added rows)');
		await page.click('[data-bom-clear]');

		phase = 'build';
		await loadExample();
		await run();
		assert.deepEqual(await ids(), EXAMPLE_IDS);
		const [dl] = await Promise.all([page.waitForEvent('download'), page.click('[data-bom-download-json]')]);
		assert.equal(dl.suggestedFilename(), 'ai-bom.cdx.json');
		const exported = fs.readFileSync(await dl.path(), 'utf8');
		assert.deepEqual(engine.validateCycloneDX(JSON.parse(exported)), []);
		const [dm] = await Promise.all([page.waitForEvent('download'), page.click('[data-bom-download-md]')]);
		assert.equal(dm.suggestedFilename(), 'ai-bom.md');
		pass('Build of the example: expected gaps; JSON export passes the structure check; Markdown download', EXAMPLE_IDS.length + ' rules');
		await page.screenshot({ path: path.join(EVIDENCE, name + '-build.png') });

		phase = 'roundtrip';
		await setMode('review');
		await page.fill('[data-bom-input]', exported);
		await run();
		assert.deepEqual(await ids(), EXAMPLE_IDS);
		await page.click('[data-bom-edit]');
		assert.equal(await page.inputValue('#cd-bom-model-name'), 'Ticket Router');
		await run();
		assert.deepEqual(await ids(), EXAMPLE_IDS);
		pass('re-import in Review and back into the form give the same gaps');

		phase = 'secrets';
		await page.fill('#cd-bom-owner-contact', 'ml@example.com ' + S.HF_TOKEN + ' ' + S.OPAQUE_LONG);
		await run();
		const sec = await page.evaluate(() => ({ ui: document.querySelector('[data-bom-results]').textContent, disabled: document.querySelector('[data-bom-download-json]').disabled }));
		for (const v of [S.HF_TOKEN, S.OPAQUE_LONG]) { assert.ok(!sec.ui.includes(v)); }
		assert.ok(!sec.disabled && (await ids()).includes('AIBOM-SEC-002') && (await ids()).includes('AIBOM-SEC-003'));
		assert.equal(await page.locator('[data-bom-secret-ack]').count(), 0);
		const [ds] = await Promise.all([page.waitForEvent('download'), page.click('[data-bom-download-json]')]);
		for (const v of [S.HF_TOKEN, S.OPAQUE_LONG]) { assert.ok(!fs.readFileSync(await ds.path(), 'utf8').includes(v)); }
		pass('secrets and an unrecognized long value are masked in the output and export; no raw-export override');

		phase = 'unicode';
		await page.click('[data-bom-clear]');
		await page.fill('#cd-bom-model-name', 'Jörg für Пётр');
		await run();
		assert.ok((await page.$eval('[data-bom-preview-json]', e => e.textContent)).includes('Jörg für Пётр'));
		pass('NFD names are exported in NFC');

		phase = 'large';
		await setMode('review');
		await page.setInputFiles('[data-bom-file]', BIG);
		await until(() => /Large files are not displayed/.test(document.querySelector('[data-bom-source]').textContent));
		await page.evaluate(() => { window.__gap = 0; window.__last = performance.now(); window.__probe = setInterval(() => { const n = performance.now(); window.__gap = Math.max(window.__gap, n - window.__last); window.__last = n; }, 50); });
		const t0 = Date.now();
		await run(120000);
		const elapsed = Date.now() - t0;
		const gap = await page.evaluate(() => { clearInterval(window.__probe); return Math.round(window.__gap); });
		assert.ok(gap < 1000, 'main thread blocked ' + gap + ' ms');
		assert.match(await page.$eval('[data-bom-summary]', e => e.textContent), new RegExp(big.datasets.toLocaleString('en-US') + ' datasets'));
		pass('4.6 MB file checked in the worker; page stays responsive', `${(elapsed / 1000).toFixed(1)} s, longest main-thread gap ${gap} ms`);
		summary[name + '-large-seconds'] = Number((elapsed / 1000).toFixed(1));

		phase = 'keyboard';
		await setMode('build');
		await page.focus('[data-bom-add=datasets]');
		await page.keyboard.press('Enter');
		assert.equal(await page.evaluate(() => document.activeElement.getAttribute('data-bom-col')), 'name');
		await page.focus('#cd-bom-model-name');
		await page.keyboard.press('Control+Enter');
		await until(() => !document.querySelector('[data-bom-results]').hidden && document.activeElement.id === 'cd-bom-step-results');
		pass('keyboard: Enter adds a row and focuses it; Ctrl+Enter runs and moves focus to the results');

		const afterLoad = requests.filter(r => !['load', 'csp-probe'].includes(r.phase) && /^(https?|wss?):/.test(r.url));
		assert.deepEqual(afterLoad, [], 'requests after load: ' + afterLoad.map(r => r.phase + ' ' + r.url).join(', '));
		pass('no network requests at all after page load (Build, export, Review, secrets, 4.6 MB file, keyboard)', requests.filter(r => r.phase === 'load').length + ' requests during load only');

		phase = 'mobile';
		await page.setViewportSize({ width: 360, height: 780 });
		await page.goto(URL_UNDER_TEST);
		await ready();
		await loadExample();
		await run();
		const m = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, steps: [...document.querySelectorAll('[data-bom] .cd-la-step')].filter(e => e.offsetParent).map(e => Math.round(e.getBoundingClientRect().height)) }));
		assert.ok(m.sw <= m.cw + 1 && m.steps.every(h => h <= 64), JSON.stringify(m));
		await page.screenshot({ path: path.join(EVIDENCE, name + '-360.png') });
		pass('360 px: no horizontal scrolling, headings fit');

		const storage = await page.evaluate(async () => ({ ls: localStorage.length, ss: sessionStorage.length, cookie: document.cookie, href: location.href }));
		assert.deepEqual(storage, { ls: 0, ss: 0, cookie: '', href: URL_UNDER_TEST });
		assert.deepEqual(await context.cookies(), []);
		const external = requests.filter(r => /^(https?|wss?):/.test(r.url) && new URL(r.url).origin !== ORIGIN);
		assert.deepEqual(external.filter(r => r.phase !== 'csp-probe'), []);
		assert.deepEqual(consoleErrors.filter(e => e.phase !== 'probe'), []);
		assert.deepEqual(dialogs, []);
		pass('no storage, cookies, external requests, console errors or dialogs');
	} finally {
		await browser.close();
	}
	return results.length;
}

(async () => {
	let total = 0;
	for (const b of BROWSERS) { total += await runBrowser(b); }
	fs.writeFileSync(path.join(EVIDENCE, 'xbrowser-summary.json'), JSON.stringify(summary, null, 2));
	console.log('\n' + total + ' cross-browser checks passed (' + BROWSERS.join(', ') + '). Evidence: ' + EVIDENCE);
})().catch(e => { console.error('FAIL: ' + e.message); process.exit(1); });
