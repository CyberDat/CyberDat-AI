/*
 * Browser check (Chromium/Edge over CDP): when regular-expression look-behind is unavailable, Log Anonymizer, Prompt
 * Injection Detector and LotL show "Browser not supported" instead of failing silently. Old Safari is simulated by
 * replacing the RegExp constructor before the page loads so that look-behind patterns throw a SyntaxError.
 *   node tests/tools-lookbehind-support-browser.test.cjs [base-url]   (default http://127.0.0.1:18091, tools-sandbox-server.py)
 */
'use strict';
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const BASE = (process.argv[2] || 'http://127.0.0.1:18091').replace(/\/$/, '');
const BROWSERS = [process.env.CYBERDAT_BROWSER, 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/google-chrome', '/usr/bin/chromium'].filter(Boolean);
const TOOLS = [['log-anonymizer', 'la'], ['prompt-injection-detector', 'pi'], ['lotl-command-analyzer', 'lotl']];
const SIMULATE = "(() => { const R = RegExp; const P = function (p, f) { const src = p && p.source !== undefined ? p.source : String(p); if (/\\(\\?<[=!]/.test(src)) { throw new SyntaxError('Invalid regular expression: look-behind is not supported (simulated)'); } return new R(p, f); }; P.prototype = R.prototype; Object.setPrototypeOf(P, R); window.RegExp = P; })();";
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
	const exe = BROWSERS.find(p => fs.existsSync(p));
	if (!exe) { throw new Error('No Edge/Chrome found; set CYBERDAT_BROWSER.'); }
	const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cd-lookbehind-'));
	const proc = spawn(exe, ['--headless=new', '--disable-gpu', '--no-first-run', '--disable-extensions', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'], { stdio: 'ignore' });
	const portFile = path.join(profile, 'DevToolsActivePort');
	for (let i = 0; i < 100 && !fs.existsSync(portFile); i++) { await sleep(100); }
	const [port, wsPath] = fs.readFileSync(portFile, 'utf8').split('\n');
	const ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath.trim()}`);
	await new Promise(r => ws.addEventListener('open', r, { once: true }));
	let id = 0;
	const pending = new Map();
	ws.addEventListener('message', e => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } });
	const send = (method, params = {}, sessionId) => new Promise(r => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify(Object.assign({ id: i, method, params }, sessionId ? { sessionId } : {}))); });
	let passed = 0;
	try {
		for (const simulate of [false, true]) {
			for (const [slug, p] of TOOLS) {
				const { result: { targetId } } = await send('Target.createTarget', { url: 'about:blank' });
				const { result: { sessionId: s } } = await send('Target.attachToTarget', { targetId, flatten: true });
				await send('Page.enable', {}, s);
				if (simulate) { await send('Page.addScriptToEvaluateOnNewDocument', { source: SIMULATE }, s); }
				await send('Page.navigate', { url: BASE + '/tools/' + slug + '/' }, s);
				let st = null;
				for (let i = 0; i < 80; i++) {
					await sleep(100);
					const r = await send('Runtime.evaluate', { expression: `(() => { if (document.readyState !== 'complete') return null; const u = document.querySelector('[data-${p}-unsupported]'), a = document.querySelector('[data-${p}-app]'); return { unsupported: !u.hidden, text: u.textContent, app: !a.hidden }; })()`, returnByValue: true }, s);
					st = r.result && r.result.result && r.result.result.value;
					if (st && (st.app || st.unsupported)) { break; }
				}
				if (simulate) {
					assert.ok(st && st.unsupported && !st.app && /^Browser not supported: .*look-behind/.test(st.text), slug + ': ' + JSON.stringify(st));
					console.log('PASS: ' + slug + ' without look-behind: "Browser not supported" shown, workspace hidden');
				} else {
					assert.ok(st && st.app && !st.unsupported, slug + ': ' + JSON.stringify(st));
					console.log('PASS: ' + slug + ' in a current browser: workspace shown, no warning');
				}
				passed++;
				await send('Target.closeTarget', { targetId });
			}
		}
	} finally {
		ws.close();
		proc.kill();
		await sleep(400);
		try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) { /* locked on Windows */ }
	}
	console.log('\n' + passed + ' look-behind support checks passed.');
	process.exit(0);
})().catch(e => { console.error('FAIL: ' + e.message); process.exit(1); });
