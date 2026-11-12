/*
 * Cross-browser acceptance (Firefox, WebKit) for the MCP Security & Policy Checker via Playwright.
 * Playwright is NOT a repository dependency (see tests/log-anonymizer-xbrowser.test.cjs for installation):
 *   NODE_PATH=<pw>/node_modules node tests/mcp-checker-xbrowser.test.cjs [url] [evidence-dir] [browsers]
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

const URL_UNDER_TEST = process.argv[2] || 'http://127.0.0.1:8090/tools/mcp-security-checker/';
const ORIGIN = new URL(URL_UNDER_TEST).origin;
const EVIDENCE = process.argv[3] || path.join(os.homedir(), 'CyberDat-tools-mcp-xbrowser-' + Date.now());
const BROWSERS = (process.argv[4] || 'firefox,webkit').split(',');
fs.mkdirSync(EVIDENCE, { recursive: true });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const summary = {};
const BIG = path.join(os.tmpdir(), 'cd-mcp-xbrowser.json');
{
	const tools = [];
	let size = 0;
	for (let i = 0; size < 4.8 * 1024 * 1024; i++) { const t = { name: 'tool_' + i, description: 'Return item ' + i + ' from the catalogue. '.repeat(20), inputSchema: { type: 'object', properties: { id: { type: 'string', maxLength: 64 } } } }; size += JSON.stringify(t).length + 1; tools.push(t); }
	fs.writeFileSync(BIG, JSON.stringify({ tools }));
}
const SECRET_CFG = JSON.stringify({ mcpServers: { gh: { command: 'npx', args: ['-y', 'example-gh@1.0.0', '--token', S.GITHUB_PAT_FINE], env: { GITHUB_TOKEN: S.GITHUB_PAT, OPENAI_API_KEY: S.OPENAI_PROJECT_KEY } }, api: { url: 'https://api.example.com/mcp', headers: { Authorization: 'Bearer ' + S.JWT } } } });
const SECRETS = [S.GITHUB_PAT_FINE, S.GITHUB_PAT, S.OPENAI_PROJECT_KEY, S.JWT];

async function runBrowser(name) {
	const results = [];
	const pass = (label, detail) => { results.push({ label, detail }); console.log(`PASS [${name}]: ${label}${detail ? ' — ' + detail : ''}`); };
	const browser = await playwright[name].launch();
	const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 1280, height: 900 } });
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
	const run = async (timeout = 60000, allowError = false) => {
		await page.click('[data-mcp-run]');
		await until(() => !document.querySelector('[data-mcp-run]').disabled && (!document.querySelector('[data-mcp-results]').hidden || !document.querySelector('[data-mcp-error]').hidden), null, timeout);
		const err = await page.$eval('[data-mcp-error]', e => (e.hidden ? '' : e.textContent));
		if (!allowError) { assert.equal(err, ''); }
		return err;
	};
	const ready = () => until(() => document.readyState === 'complete' && !!document.querySelector('[data-mcp-app]') && !document.querySelector('[data-mcp-app]').hidden);
	try {
		await page.goto(URL_UNDER_TEST);
		await ready();
		await sleep(500);
		const load = requests.filter(r => /^https?:/.test(r.url));
		assert.deepEqual(load.filter(r => new URL(r.url).origin !== ORIGIN), []);
		const w = page.workers();
		assert.ok(w.some(x => /mcp-checker\/worker\.js/.test(x.url())));
		const lock = await w[0].evaluate(() => ['fetch', 'XMLHttpRequest', 'WebSocket', 'importScripts'].map(n => { try { if (n === 'fetch') { self.fetch('/'); } else { new self[n]('/'); } return n + ':allowed'; } catch (e) { return n + ':blocked'; } }).join(','));
		assert.ok(!/allowed/.test(lock));
		pass('first-party page load; same-origin worker with network APIs disabled', lock);

		phase = 'csp-probe';
		const probe = await page.evaluate(() => fetch('https://registry.npmjs.org/', { mode: 'no-cors' }).then(() => 'unblocked', e => 'blocked: ' + e.message));
		assert.match(probe, /^blocked/);
		pass('CSP blocks page scripts from contacting registries or any host', probe.slice(0, 50));

		phase = 'process';
		await page.click('[data-mcp-sample]');
		await run();
		const st = await page.evaluate(() => ({ verdict: document.querySelector('[data-mcp-verdict]').textContent, cards: document.querySelectorAll('[data-mcp-list] > li').length, text: document.querySelector('[data-mcp-list]').textContent }));
		assert.match(st.verdict, /^High-risk issues found\./);
		assert.ok(st.cards >= 6 && /MCP-CMD-001/.test(st.text) && /MCP-TP-004/.test(st.text) && /ghp_…•••• \(40 characters\)/.test(st.text));
		pass('example checked: high verdict, findings per server, fake token masked', st.cards + ' cards');
		await page.screenshot({ path: path.join(EVIDENCE, name + '-01-results.png') });

		await page.fill('[data-mcp-input]', SECRET_CFG);
		await run();
		const dl = await Promise.all([page.waitForEvent('download'), page.click('[data-mcp-report]')]);
		const out = path.join(EVIDENCE, name + '-report.json');
		await dl[0].saveAs(out);
		const exported = fs.readFileSync(out, 'utf8');
		const ui = await page.$eval('[data-mcp-results]', e => e.textContent);
		for (const v of SECRETS) { assert.ok(!exported.includes(v) && !ui.includes(v), 'secret leaked: ' + v.slice(0, 4)); }
		assert.ok(JSON.parse(exported).findings.filter(f => f.group === 'secrets').length >= 4);
		pass('secrets never appear in full in the results or the downloaded report');

		await page.fill('[data-mcp-input]', JSON.stringify({ mcpServers: { '<img src=x onerror=alert(1)>': { url: 'javascript:alert(2)', tools: [{ name: '<svg onload=alert(3)>', description: '<script>alert(4)</script><IMPORTANT>x</IMPORTANT>' }] } } }));
		await run();
		await sleep(300);
		const x = await page.evaluate(() => document.querySelectorAll('.cd-la-results img, .cd-la-results script, .cd-la-results svg, .cd-la-results a').length);
		assert.equal(x, 0);
		assert.deepEqual(dialogs, []);
		pass('markup and scripts in configurations are shown as text only; no dialogs');

		await page.check('[data-mcp-mode][value=policy]');
		await page.click('[data-mcp-sample]');
		await page.fill('[data-mcp-policy]', '{"deniedComands": ["sudo"]}');
		const perr = await run(30000, true);
		assert.match(perr, /Did you mean "deniedCommands"\?/);
		await page.click('[data-mcp-policy-example]');
		await run();
		assert.match(await page.$eval('[data-mcp-verdict]', e => e.textContent), /policy violations? found/);
		const pd = await Promise.all([page.waitForEvent('download'), page.click('[data-mcp-policy-download]')]);
		const pout = path.join(EVIDENCE, name + '-policy.json');
		await pd[0].saveAs(pout);
		assert.deepEqual(JSON.parse(fs.readFileSync(pout, 'utf8')).deniedPaths, ['~/.ssh', '~/.aws', '~/.config']);
		assert.equal(await page.evaluate(() => JSON.stringify([localStorage.length, sessionStorage.length, document.cookie])), JSON.stringify([0, 0, '']));
		pass('policy check: schema error explained, example policy violations listed, policy downloaded; nothing stored');
		await page.check('[data-mcp-mode][value=security]');

		phase = 'large';
		await page.setInputFiles('[data-mcp-file]', BIG);
		await until(() => /Large files are not displayed/.test(document.querySelector('[data-mcp-source]').textContent));
		const t0 = Date.now();
		await run(180000);
		const ms = Date.now() - t0;
		assert.deepEqual(http('large'), []);
		summary[name + 'LargeMs'] = ms;
		pass('4.8 MB tool list checked without network requests', (ms / 1000).toFixed(1) + ' s');

		phase = 'cancel';
		await page.click('[data-mcp-run]');
		await page.click('[data-mcp-cancel]');
		await until(() => /Cancelled/.test(document.querySelector('[data-mcp-status]').textContent));
		await sleep(800);
		const cr = http('cancel');
		assert.ok(cr.every(r => /\/assets\/js\/mcp-checker\/(?:worker|engine)\.js\?ver=\d+/.test(r.url) && new URL(r.url).origin === ORIGIN), JSON.stringify(cr));
		pass('Cancel re-requests only static same-origin worker scripts', cr.length + ' requests');
		await page.click('[data-mcp-clear]');
		phase = 'final';
		assert.deepEqual(requests.filter(r => !['load', 'csp-probe', 'cancel'].includes(r.phase) && /^(https?|wss?):/.test(r.url)), []);
		assert.deepEqual(consoleErrors.filter(e => e.phase !== 'probe'), []);
		pass('input text is never sent: no HTTP requests during checks, exports and clearing; no console errors');

		await page.setViewportSize({ width: 360, height: 780 });
		await page.goto(URL_UNDER_TEST);
		await ready();
		await page.click('[data-mcp-sample]');
		await page.check('[data-mcp-mode][value=policy]');
		await page.click('[data-mcp-policy-example]');
		await page.check('[data-mcp-mode][value=security]');
		await run();
		const o = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, small: [...document.querySelectorAll('.cd-mcp button:not([hidden]), .cd-mcp summary, .cd-mcp-mode')].filter(e => e.offsetParent && e.getBoundingClientRect().height < 44).length }));
		assert.ok(o.sw <= o.cw);
		assert.equal(o.small, 0);
		await page.screenshot({ path: path.join(EVIDENCE, name + '-02-mobile-360.png') });
		pass('360px: no horizontal overflow, touch targets ≥ 44px', 'scrollWidth ' + o.sw);

		await page.fill('[data-mcp-input]', '{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]}}}');
		await page.focus('[data-mcp-input]');
		await page.keyboard.press('Shift+Tab');
		await page.keyboard.press('Tab');
		await page.keyboard.press('Control+Enter');
		await until(() => !document.querySelector('[data-mcp-results]').hidden && /MCP-FS-001/.test(document.querySelector('[data-mcp-list]').textContent));
		pass('keyboard: Ctrl+Enter in the text box runs the check');
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
