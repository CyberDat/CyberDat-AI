/*
 * Visual regression snapshot for tool pages (used to prove that moving shared styles to
 * assets/css/tools-common.css changed nothing). Dependency-free: headless Edge/Chrome over CDP.
 *
 *   node tests/tools-visual-snapshot.cjs capture <out-dir> [origin]
 *   node tests/tools-visual-snapshot.cjs compare <before-dir> <after-dir>
 *
 * capture: for each tool page × viewport (1440, 360) × state (initial, result), records the full
 * computed style of every element inside the tool root plus a viewport screenshot of the tool.
 * Dynamic texts (timings, clipboard status) are replaced by fixed strings before capture.
 * compare: every computed property and every screenshot byte must be identical.
 */
'use strict';
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const sleep = ms => new Promise(r => setTimeout(r, ms));
const BROWSERS = [process.env.CYBERDAT_BROWSER, 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/google-chrome', '/usr/bin/chromium'].filter(Boolean);
const PAGES = [
	{ name: 'log-anonymizer', path: '/tools/log-anonymizer/', root: '[data-log-anonymizer]', app: '[data-la-app]', sample: '[data-la-sample]', run: '[data-la-run]', results: '[data-la-results]', dynamic: ['[data-la-summary]', '[data-la-status]'] },
	{ name: 'prompt-injection-detector', path: '/tools/prompt-injection-detector/', root: '[data-prompt-detector]', app: '[data-pi-app]', sample: '[data-pi-sample]', run: '[data-pi-run]', results: '[data-pi-results]', dynamic: ['[data-pi-summary]', '[data-pi-status]'] }
];
const VIEWPORTS = [[1440, 1000, false], [360, 780, true]];

async function capture(outDir, origin) {
	fs.mkdirSync(outDir, { recursive: true });
	const exe = BROWSERS.find(p => fs.existsSync(p));
	const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cd-vis-'));
	const proc = spawn(exe, ['--headless=new', '--disable-gpu', '--hide-scrollbars', '--font-render-hinting=none', '--no-first-run', '--disable-extensions', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'], { stdio: 'ignore' });
	const portFile = path.join(profile, 'DevToolsActivePort');
	for (let i = 0; i < 100 && !fs.existsSync(portFile); i++) { await sleep(100); }
	const [port, wsPath] = fs.readFileSync(portFile, 'utf8').split('\n');
	const ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath.trim()}`);
	await new Promise(r => ws.addEventListener('open', r, { once: true }));
	let id = 0;
	const pending = new Map();
	ws.addEventListener('message', e => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.reject(new Error(m.error.message)) : p.resolve(m.result); } });
	const call = (method, params = {}, sessionId) => { const msg = { id: ++id, method, params }; if (sessionId) { msg.sessionId = sessionId; } ws.send(JSON.stringify(msg)); return new Promise((resolve, reject) => pending.set(msg.id, { resolve, reject })); };
	const { targetId } = await call('Target.createTarget', { url: 'about:blank' });
	const { sessionId } = await call('Target.attachToTarget', { targetId, flatten: true });
	const send = (m, p) => call(m, p, sessionId);
	await send('Page.enable');
	const evaluate = async expr => { if (process.env.VDEBUG) { console.log('eval', expr.slice(0, 70).replace(/s+/g, ' ')); } const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) { throw new Error(r.exceptionDetails.text); } return r.result.value; };
	const waitFor = async (expr, timeout = 20000) => { const end = Date.now() + timeout; while (Date.now() < end) { if (await evaluate(expr).catch(() => false)) { return; } await sleep(100); } throw new Error('timeout ' + expr); };
	const summary = {};
	try {
		for (const page of PAGES) {
			for (const [w, h, mobile] of VIEWPORTS) {
				await send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile });
				await send('Page.navigate', { url: origin + page.path });
				await waitFor(`document.readyState === 'complete' && !document.querySelector('${page.app}').hidden`);
				await evaluate("document.fonts ? document.fonts.ready.then(() => true) : true");
				for (const state of ['initial', 'result']) {
					if (state === 'result') {
						await evaluate(`document.querySelector('${page.sample}').click(); document.querySelector('${page.run}').click(); true`);
						await waitFor(`!document.querySelector('${page.results}').hidden && !document.querySelector('${page.run}').disabled`);
					}
					await evaluate(`(() => { for (const s of ${JSON.stringify(page.dynamic)}) { const e = document.querySelector(s); if (e) { e.textContent = 'FIXED'; } } document.activeElement && document.activeElement.blur(); window.scrollTo(0, 0); return true; })()`);
					await sleep(300);
					const styles = await evaluate(`(() => {
						const root = document.querySelector('${page.root}');
						const all = [root, ...root.querySelectorAll('*')];
						const out = [];
						for (const el of all) {
							const cs = getComputedStyle(el);
							// All computed properties, hashed in the page (FNV-1a) to keep the CDP message small.
							// Sorted: custom properties are enumerated in a nondeterministic order.
							const list = [];
							for (let i = 0; i < cs.length; i++) { list.push(cs[i] + ':' + cs.getPropertyValue(cs[i])); }
							const str = list.sort().join(';');
							let hv = 0x811c9dc5;
							for (let i = 0; i < str.length; i++) { hv = Math.imul(hv ^ str.charCodeAt(i), 0x01000193) >>> 0; }
							const props = { count: cs.length, fnv: hv.toString(16), sample: [cs.color, cs.backgroundColor, cs.fontSize, cs.fontFamily, cs.padding, cs.margin, cs.border, cs.display].join(' | ') };
							const r = el.getBoundingClientRect();
							out.push({ tag: el.tagName, cls: el.getAttribute('class') || '', box: [r.x, r.y, r.width, r.height].map(v => Math.round(v * 100) / 100).join(','), props });
						}
						const rr = root.getBoundingClientRect();
						return { elements: out, root: { x: rr.x + scrollX, y: rr.y + scrollY, width: rr.width, height: rr.height } };
					})()`);
					const key = `${page.name}-${w}-${state}`;
					// Viewport screenshots while scrolling through the tool (full-page capture stalls headless Edge).
					const hash = crypto.createHash('sha256');
					const screens = Math.min(6, Math.ceil(styles.root.height / h));
					for (let i = 0; i < screens; i++) {
						await evaluate(`window.scrollTo(0, ${Math.round(styles.root.y + i * h)}); true`);
						await sleep(150);
						const shot = await send('Page.captureScreenshot', { format: 'png' });
						const buf = Buffer.from(shot.data, 'base64');
						hash.update(buf);
						fs.writeFileSync(path.join(outDir, `${key}-${i}.png`), buf);
					}
					const data = hash.digest('base64');
					fs.writeFileSync(path.join(outDir, key + '.styles.json'), JSON.stringify(styles.elements));
					summary[key] = { elements: styles.elements.length, stylesSha256: crypto.createHash('sha256').update(JSON.stringify(styles.elements)).digest('hex'), screenshotSha256: Buffer.from(data, 'base64').toString('hex'), screenshots: screens };
					console.log(`captured ${key}: ${styles.elements.length} elements`);
				}
			}
		}
	} finally {
		ws.close();
		proc.kill();
		await sleep(500);
		try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) { /* locked */ }
	}
	fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
}

function compare(a, b) {
	const sa = JSON.parse(fs.readFileSync(path.join(a, 'summary.json'), 'utf8'));
	const sb = JSON.parse(fs.readFileSync(path.join(b, 'summary.json'), 'utf8'));
	let failures = 0;
	let props = 0;
	for (const key of Object.keys(sa)) {
		const ea = JSON.parse(fs.readFileSync(path.join(a, key + '.styles.json'), 'utf8'));
		const eb = JSON.parse(fs.readFileSync(path.join(b, key + '.styles.json'), 'utf8'));
		const diffs = [];
		if (ea.length !== eb.length) { diffs.push(`element count ${ea.length} → ${eb.length}`); }
		for (let i = 0; i < Math.min(ea.length, eb.length); i++) {
			if (ea[i].box !== eb[i].box) { diffs.push(`${ea[i].tag}.${ea[i].cls} box ${ea[i].box} → ${eb[i].box}`); }
			props += ea[i].props.count || 0;
			for (const p of new Set([...Object.keys(ea[i].props), ...Object.keys(eb[i].props)])) {
				if (ea[i].props[p] !== eb[i].props[p]) { diffs.push(`${ea[i].tag}.${ea[i].cls} ${p}: ${ea[i].props[p]} → ${eb[i].props[p]}`); }
			}
		}
		const sameShot = sa[key].screenshotSha256 === (sb[key] || {}).screenshotSha256;
		if (diffs.length || !sameShot) { failures++; }
		console.log(`${diffs.length || !sameShot ? 'FAIL' : 'PASS'}: ${key} — ${ea.length} elements, ${diffs.length} computed-style/box differences, screenshot ${sameShot ? 'byte-identical' : 'DIFFERENT'}`);
		for (const d of diffs.slice(0, 10)) { console.log('    ' + d); }
	}
	console.log(`${props.toLocaleString('en-US')} computed property values compared (hashed per element, sorted; plus layout boxes and screenshots).`);
	process.exit(failures ? 1 : 0);
}

const [mode, x, y] = process.argv.slice(2);
if (mode === 'capture') { capture(x, y || 'http://127.0.0.1:8090').catch(e => { console.error('FAIL: ' + e.message); process.exit(1); }); }
else if (mode === 'compare') { compare(x, y); }
else { console.error('usage: capture <dir> [origin] | compare <before> <after>'); process.exit(64); }
