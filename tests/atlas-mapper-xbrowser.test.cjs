/*
 * Cross-browser acceptance (Firefox, WebKit) for the MITRE ATLAS Attack Vector Mapper via Playwright.
 * Playwright is NOT a repository dependency (see tests/log-anonymizer-xbrowser.test.cjs for installation):
 *   NODE_PATH=<pw>/node_modules node tests/atlas-mapper-xbrowser.test.cjs [url] [evidence-dir] [browsers]
 * Real Safari and iOS devices are not covered: Playwright WebKit on Windows is the WebKit engine, not Safari.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
let playwright;
try { playwright = require('playwright'); } catch (e) { console.log('SKIP: Playwright is not installed (intentionally not a repository dependency).'); process.exit(0); }

const URL_UNDER_TEST = process.argv[2] || 'http://127.0.0.1:18091/tools/mitre-atlas-mapper/';
const ORIGIN = new URL(URL_UNDER_TEST).origin;
const EVIDENCE = process.argv[3] || path.join(os.tmpdir(), 'cyberdat-atlas-xbrowser-' + Date.now());
const BROWSERS = (process.argv[4] || 'firefox,webkit').split(',');
fs.mkdirSync(EVIDENCE, { recursive: true });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const BIG = ('The agent deleted files after reading a document with hidden instructions. Ein Deepfake-Anruf. Отравление обучающих данных. ').repeat(900).slice(0, 100000);

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
	const run = async (timeout = 60000) => {
		await page.click('[data-atl-run]');
		await until(() => !document.querySelector('[data-atl-run]').disabled && (!document.querySelector('[data-atl-results]').hidden || !document.querySelector('[data-atl-error]').hidden), null, timeout);
		assert.equal(await page.$eval('[data-atl-error]', e => (e.hidden ? '' : e.textContent)), '');
	};
	const ids = () => page.evaluate(() => [...new Set([...document.querySelectorAll('[data-atl-groups] .cd-atl-tech__head code')].map(c => c.textContent))].sort());
	const ready = () => until(() => document.readyState === 'complete' && !!document.querySelector('[data-atl-app]') && !document.querySelector('[data-atl-app]').hidden);
	const setProps = list => page.evaluate(l => { for (const c of document.querySelectorAll('[data-atl-property]')) { c.checked = l.includes(c.value); } }, list);
	try {
		await page.goto(URL_UNDER_TEST);
		await ready();
		await sleep(500);
		const load = requests.filter(r => /^https?:/.test(r.url));
		assert.deepEqual(load.filter(r => new URL(r.url).origin !== ORIGIN), []);
		const w = page.workers();
		assert.ok(w.some(x => /atlas-mapper\/worker\.js/.test(x.url())));
		const lock = await w[0].evaluate(() => ['fetch', 'XMLHttpRequest', 'WebSocket', 'importScripts'].map(n => { try { if (n === 'fetch') { self.fetch('/'); } else { new self[n]('/'); } return n + ':allowed'; } catch (e) { return n + ':blocked'; } }).join(','));
		assert.ok(!/allowed/.test(lock));
		pass('first-party page load (data file included); same-origin worker with network APIs disabled', lock);
		phase = 'csp-probe';
		const probe = await page.evaluate(() => fetch('https://atlas.mitre.org/', { mode: 'no-cors' }).then(() => 'unblocked', e => 'blocked: ' + e.message));
		assert.match(probe, /^blocked/);
		pass('CSP blocks page scripts from contacting the MITRE site or any host', probe.slice(0, 50));

		phase = 'profile';
		await setProps(['rag', 'agent-tools']);
		await run();
		const p = await ids();
		assert.equal(p.length, 13);
		pass('System profile: 13 techniques for RAG + agent with tools, grouped by tactic');
		await page.screenshot({ path: path.join(EVIDENCE, name + '-profile.png') });

		phase = 'finding';
		await page.check('[data-atl-mode][value="finding"]');
		await page.click('[data-atl-sample]');
		await page.fill('[data-atl-text]', (await page.inputValue('[data-atl-text]')) + ' Key ' + S.OPENAI_PROJECT_KEY + ' token ' + S.OPAQUE_LONG);
		await run();
		const f = await ids();
		for (const t of ['AML.T0051.001', 'AML.T0055', 'AML.T0083', 'AML.T0086']) { assert.ok(f.includes(t), t); }
		const ui = await page.$eval('[data-atl-results]', e => e.textContent);
		assert.ok(!ui.includes(S.OPENAI_PROJECT_KEY) && !ui.includes(S.OPAQUE_LONG) && /sk-p…/.test(ui));
		pass('Finding mapper: expected candidates; secrets and an unrecognized long value only masked', f.join(' '));
		await page.fill('[data-atl-text]', 'The quarterly report was approved and sent to the auditors.');
		await run();
		assert.equal(await page.$eval('[data-atl-verdict]', e => e.textContent), 'No matching techniques found. This does not mean the system is not exposed.');
		pass('no match: the agreed sentence');

		phase = 'export';
		await page.check('[data-atl-mode][value="profile"]');
		await setProps(['open-registry']);
		await run();
		await page.click('[data-atl-add="AML.T0011.000"]');
		await page.fill('.cd-atl-note', 'old key ' + S.HF_TOKEN);
		const [dj] = await Promise.all([page.waitForEvent('download'), page.click('[data-atl-export="json"]')]);
		const j = JSON.parse(fs.readFileSync(await dj.path(), 'utf8'));
		const [dm] = await Promise.all([page.waitForEvent('download'), page.click('[data-atl-export="markdown"]')]);
		const md = fs.readFileSync(await dm.path(), 'utf8');
		assert.ok(j.techniques[0].id === 'AML.T0011.000' && j.data.release === '2026.10' && !JSON.stringify(j).includes(S.HF_TOKEN) && !md.includes(S.HF_TOKEN) && /Apache License 2\.0/.test(md));
		pass('exports (JSON, Markdown): ids, note with the secret masked, ATLAS version and attribution');

		phase = 'browse';
		await page.check('[data-atl-mode][value="browse"]');
		await page.fill('[data-atl-search]', 'AML.T0051');
		await until(() => [...document.querySelectorAll('[data-atl-browse] .cd-atl-idbtn')].some(b => b.textContent.startsWith('AML.T0051 ')));
		await page.evaluate(() => [...document.querySelectorAll('[data-atl-browse] .cd-atl-idbtn')].find(b => b.textContent.startsWith('AML.T0051 ')).click());
		await until(() => !!document.querySelector('.cd-atl-item__head') && document.querySelector('.cd-atl-item__head').textContent.startsWith('AML.T0051'));
		pass('Browse: search by id and open a technique');
		const bad = await page.evaluate(() => [...document.querySelectorAll('[data-atl] textarea, [data-atl] input[type=search], [data-atl-results], [data-atl-error], [data-atl-selection], [data-atl-browse]')].filter(e => !(e.getAttribute('translate') === 'no' && e.classList.contains('notranslate'))).length);
		assert.equal(bad, 0);
		pass('inputs, notes, browse view and results carry translate="no" and notranslate');

		phase = 'large';
		await page.check('[data-atl-mode][value="finding"]');
		await page.fill('[data-atl-text]', BIG);
		await page.evaluate(() => { window.__gap = 0; window.__last = performance.now(); window.__probe = setInterval(() => { const n = performance.now(); window.__gap = Math.max(window.__gap, n - window.__last); window.__last = n; }, 50); });
		const t0 = Date.now();
		await run();
		const elapsed = Date.now() - t0;
		const gap = await page.evaluate(() => { clearInterval(window.__probe); return Math.round(window.__gap); });
		assert.ok(gap < 1000);
		pass('100,000-character finding mapped in the worker; page responsive', `${(elapsed / 1000).toFixed(1)} s, longest gap ${gap} ms`);

		phase = 'keyboard';
		await page.focus('[data-atl-text]');
		await page.fill('[data-atl-text]', 'Indirect prompt injection through an uploaded PDF.');
		await page.keyboard.press('Control+Enter');
		await until(() => !document.querySelector('[data-atl-results]').hidden && document.activeElement.id === 'cd-atl-step-results');
		await page.focus('[data-atl-results] [data-atl-add]');
		await page.keyboard.press('Enter');
		assert.ok(await page.evaluate(() => document.querySelector('[data-atl-results] [data-atl-add]').getAttribute('aria-pressed') === 'true'));
		pass('keyboard: Ctrl+Enter maps, focus moves to the results, Enter adds to the selection');
		const afterLoad = requests.filter(r => !['load', 'csp-probe'].includes(r.phase) && /^(https?|wss?):/.test(r.url));
		assert.deepEqual(afterLoad, [], afterLoad.map(r => r.phase + ' ' + r.url).join(', '));
		pass('no network requests at all after page load (profile, finding, export, browse, 100,000 characters, keyboard)', requests.filter(r => r.phase === 'load').length + ' requests during load only');

		phase = 'mobile';
		await page.setViewportSize({ width: 360, height: 780 });
		await page.goto(URL_UNDER_TEST);
		await ready();
		await setProps(['external-api', 'rag', 'public']);
		await run();
		const m = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, steps: [...document.querySelectorAll('[data-atl] .cd-la-step')].filter(e => e.offsetParent).map(e => Math.round(e.getBoundingClientRect().height)) }));
		assert.ok(m.sw <= m.cw + 1 && m.steps.every(h => h <= 64), JSON.stringify(m));
		await page.screenshot({ path: path.join(EVIDENCE, name + '-360.png') });
		pass('360 px: no horizontal scrolling, headings fit');

		assert.deepEqual(await page.evaluate(() => ({ ls: localStorage.length, ss: sessionStorage.length, cookie: document.cookie })), { ls: 0, ss: 0, cookie: '' });
		assert.deepEqual(await context.cookies(), []);
		assert.deepEqual(requests.filter(r => /^(https?|wss?):/.test(r.url) && new URL(r.url).origin !== ORIGIN && r.phase !== 'csp-probe'), []);
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
	console.log('\n' + total + ' cross-browser checks passed (' + BROWSERS.join(', ') + '). Evidence: ' + EVIDENCE);
})().catch(e => { console.error('FAIL: ' + e.message); process.exit(1); });
