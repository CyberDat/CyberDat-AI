/*
 * Shared Playwright (Firefox, WebKit) harness for the release 1.3 tool cross-browser tests.
 * Playwright is NOT a repository dependency: NODE_PATH=<pw>/node_modules. Real Safari/iOS are not covered.
 * runX({ name, url, root, browsers, body: async h => {...} }) checks the common contracts and calls body per browser.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function runX(opt) {
	let playwright;
	try { playwright = require('playwright'); } catch (e) { console.log('SKIP: Playwright is not installed (intentionally not a repository dependency).'); return; }
	const ORIGIN = new URL(opt.url).origin;
	const EVIDENCE = opt.evidence || path.join(os.tmpdir(), 'cyberdat-' + opt.name + '-xbrowser-' + Date.now());
	fs.mkdirSync(EVIDENCE, { recursive: true });
	let total = 0;
	for (const name of opt.browsers) {
		const launchOptions = name === 'webkit' && process.env.CYBERDAT_WEBKIT_EXECUTABLE ? { executablePath: process.env.CYBERDAT_WEBKIT_EXECUTABLE } : {};
		const browser = await playwright[name].launch(launchOptions);
		const context = await browser.newContext(Object.assign({ acceptDownloads: true, viewport: { width: 1280, height: 900 } }, require('./basic-auth.cjs').playwrightOptions()));
		const requests = [], consoleErrors = [], dialogs = [];
		const h = { name, phase: 'load', ORIGIN, EVIDENCE, sleep, assert };
		context.on('request', r => requests.push({ phase: h.phase, url: r.url() }));
		const page = await context.newPage();
		h.page = page;
		page.on('console', m => { if (m.type() === 'error') { consoleErrors.push({ phase: h.phase === 'csp-probe' || /debugger eval code/.test(m.text()) ? 'probe' : h.phase, text: m.text() }); } });
		page.on('pageerror', e => consoleErrors.push({ phase: h.phase, text: 'pageerror: ' + e.message }));
		page.on('dialog', d => { dialogs.push(d.message()); d.dismiss(); });
		let n = 0;
		h.pass = (label, detail) => { n++; console.log(`PASS [${name}]: ${label}${detail ? ' — ' + detail : ''}`); };
		h.until = async (fn, arg, timeout = 20000) => { const end = Date.now() + timeout; while (Date.now() < end) { if (await page.evaluate(fn, arg).catch(() => false)) { return; } await sleep(100); } throw new Error('Timed out: ' + fn.toString().slice(0, 80)); };
		h.ready = async () => { await page.goto(opt.url); await h.until(r => document.readyState === 'complete' && document.querySelector(r) && document.querySelector(r).getAttribute('data-worker-state') === 'ready', opt.root); };
		h.download = async (sel) => { const [d] = await Promise.all([page.waitForEvent('download'), page.click(sel)]); return { name: d.suggestedFilename(), text: fs.readFileSync(await d.path(), 'utf8') }; };
		try {
			await h.ready();
			const load = requests.filter(r => /^https?:/.test(r.url));
			assert.deepEqual(load.filter(r => new URL(r.url).origin !== ORIGIN), []);
			const w = page.workers();
			assert.ok(w.length >= 1);
			const lock = await w[0].evaluate(() => ['fetch', 'XMLHttpRequest', 'WebSocket', 'importScripts'].map(k => { try { if (k === 'fetch') { self.fetch('/'); } else { new self[k]('/'); } return k + ':allowed'; } catch (e) { return k + ':blocked'; } }).join(','));
			assert.ok(!/allowed/.test(lock));
			h.pass('first-party load; data-worker-state="ready"; worker network APIs disabled', lock);
			h.phase = 'csp-probe';
			const probe = await page.evaluate(() => fetch('https://example.com/', { mode: 'no-cors' }).then(() => 'unblocked', e => 'blocked: ' + e.message));
			assert.match(probe, /^blocked/);
			h.pass('CSP blocks page scripts from any network connection', probe.slice(0, 40));
			h.phase = 'body';
			await opt.body(h);
			const after = requests.filter(r => !['load', 'csp-probe', 'reload'].includes(r.phase) && /^(https?|wss?):/.test(r.url));
			assert.deepEqual(after, [], after.map(r => r.phase + ' ' + r.url).join(', '));
			h.pass('no network requests at all after page load', requests.filter(r => r.phase === 'load').length + ' requests during load only');
			h.phase = 'reload';
			await page.setViewportSize({ width: 360, height: 780 });
			await h.ready();
			if (opt.mobile) { await opt.mobile(h); }
			const m = await page.evaluate(r => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, steps: [...document.querySelectorAll(r + ' .cd-la-step')].filter(e => e.offsetParent).map(e => Math.round(e.getBoundingClientRect().height)) }), opt.root);
			assert.ok(m.sw <= m.cw + 1 && m.steps.every(x => x <= 64), JSON.stringify(m));
			await page.screenshot({ path: path.join(EVIDENCE, name + '-360.png') });
			h.pass('360 px: no horizontal scrolling, headings fit');
			assert.deepEqual(await page.evaluate(() => ({ ls: localStorage.length, ss: sessionStorage.length, cookie: document.cookie })), { ls: 0, ss: 0, cookie: '' });
			assert.deepEqual(await context.cookies(), []);
			assert.deepEqual(requests.filter(r => /^(https?|wss?):/.test(r.url) && new URL(r.url).origin !== ORIGIN && r.phase !== 'csp-probe'), []);
			assert.deepEqual(consoleErrors.filter(e => e.phase !== 'probe'), []);
			assert.deepEqual(dialogs, []);
			h.pass('no storage, cookies, external requests, console errors or dialogs');
		} finally {
			await browser.close();
		}
		total += n;
	}
	console.log('\n' + total + ' cross-browser checks passed (' + opt.browsers.join(', ') + '). Evidence: ' + EVIDENCE);
}
module.exports = { runX };
