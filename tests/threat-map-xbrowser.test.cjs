/*
 * Global Cyber Threat Map in Chromium (Edge channel), Firefox and WebKit, desktop and mobile, on the local stand
 * (tests/threat-map-sandbox.php + tests/threat-map-sandbox-server.cjs; synthetic data). Playwright is not a
 * repository dependency:
 *   NODE_PATH=<pw>/node_modules node tests/threat-map-xbrowser.test.cjs [base-url] [evidence-dir] [browsers]
 * Real Safari and iOS devices are not covered: Playwright WebKit on Windows is the WebKit engine, not Safari.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
let playwright;
try { playwright = require('playwright'); } catch (e) { console.log('SKIP: Playwright is not installed (intentionally not a repository dependency).'); process.exit(0); }

const BASE = (process.argv[2] || 'http://127.0.0.1:18093').replace(/\/$/, '');
const ORIGIN = new URL(BASE).origin;
const EVIDENCE = process.argv[3] || path.join(os.tmpdir(), 'cyberdat-threat-map-' + Date.now());
const BROWSERS = (process.argv[4] || 'chromium,firefox,webkit').split(',');
fs.mkdirSync(EVIDENCE, { recursive: true });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const VIEWPORTS = { desktop: { width: 1280, height: 900 }, mobile: { width: 390, height: 844 } };

/** WCAG contrast of an element's text against the first opaque background up the tree. */
const CONTRAST = () => {
	const rgb = s => (s.match(/[\d.]+/g) || []).map(Number);
	const lum = ([r, g, b]) => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
	const bg = el => { for (let n = el; n; n = n.parentElement) { const c = rgb(getComputedStyle(n).backgroundColor); if (c.length >= 3 && (c.length < 4 || c[3] > 0.9)) return c; } return [8, 13, 19]; };
	const out = [];
	for (const sel of ['.cdtm-intro', '.cdtm-note', '.cdtm-status', '.cdtm-tab-source', '.cdtm-legend span', '.cdtm-rank', '.cdtm-unit', '.cdtm-source', '.cdtm-periods button', '.cdtm-tabs [aria-selected=true] .cdtm-chip', '.cdtm-mapnote', '.cdtm-disclaimer', '.cdtm-top-n', '.cdtm-kicker']) {
		const el = [...document.querySelectorAll(sel)].find(e => e.offsetParent && e.textContent.trim());
		if (!el) continue;
		const a = lum(rgb(getComputedStyle(el).color)), b = lum(bg(el));
		out.push({ sel, ratio: Math.round((Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) * 100) / 100 });
	}
	return out;
};

async function run(name) {
	const launch = name === 'chromium' ? { channel: 'msedge' } : name === 'webkit' && process.env.CYBERDAT_WEBKIT_EXECUTABLE ? { executablePath: process.env.CYBERDAT_WEBKIT_EXECUTABLE } : {};
	const browser = await playwright[name].launch(launch);
	const results = [];
	const pass = (label, detail) => { results.push({ label, detail }); console.log(`PASS [${name}]: ${label}${detail ? ' — ' + detail : ''}`); };
	try {
		for (const [vpName, viewport] of Object.entries(VIEWPORTS)) {
			const context = await browser.newContext({ viewport });
			const requests = [], errors = [];
			context.on('request', r => requests.push(r.url()));
			const page = await context.newPage();
			page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
			page.on('pageerror', e => errors.push('pageerror: ' + e.message));
			if (name === 'chromium') await page.addInitScript(() => { window.__cls = 0; new PerformanceObserver(l => { for (const e of l.getEntries()) if (!e.hadRecentInput) window.__cls += e.value; }).observe({ type: 'layout-shift', buffered: true }); });
			await page.goto(BASE + '/stand/data/');
			await page.waitForLoadState('load');
			await sleep(vpName === 'desktop' ? 1200 : 600);
			const tag = `${name}-${vpName}`;

			assert.deepEqual(requests.filter(u => /^https?:/.test(u) && new URL(u).origin !== ORIGIN), []);
			const geometry = requests.filter(u => u.includes('threat-map-countries.json')).length;
			assert.equal(geometry, vpName === 'desktop' ? 1 : 0);
			assert.deepEqual(errors, []);
			pass(`${vpName}: ${requests.length} requests, all to the CyberDat origin; geometry ${vpName === 'desktop' ? 'loaded once' : 'not loaded (list mode)'}; no console errors`);

			const layout = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, inner: innerWidth, map: getComputedStyle(document.querySelector('.cdtm-mapbox')).display, search: getComputedStyle(document.querySelector('.cdtm-search')).display, paths: document.querySelectorAll('.cdtm-map path').length }));
			assert.ok(layout.scroll <= layout.inner, `no horizontal scroll (${layout.scroll} > ${layout.inner})`);
			if (vpName === 'desktop') { assert.equal(layout.map, 'block'); assert.equal(layout.search, 'none'); assert.ok(layout.paths >= 170); }
			else { assert.equal(layout.map, 'none'); assert.equal(layout.search, 'block'); }
			pass(`${vpName}: ${vpName === 'desktop' ? layout.paths + ' country shapes, no search box' : 'map replaced by the top 10 and a country search'}; no horizontal scroll (${layout.scroll}/${layout.inner})`);

			// v1.1: default tab from the data, flags only for what is on the page, fixed size, empty alt
			await page.evaluate(() => document.querySelector('[data-cdtm-top]').scrollIntoView({ block: 'center' }));
			await sleep(600);
			// loaded = decode() succeeds (Firefox reports naturalWidth 0 for SVGs that have only a viewBox)
			const decoded = await page.evaluate(() => Promise.all([...document.querySelectorAll('[data-cdtm-top] img.cdtm-flag')].map(i => i.decode().then(() => true, () => false))));
			assert.ok(decoded.length === 10 && decoded.every(Boolean), 'flags decoded: ' + decoded.join(','));
			const fl = await page.evaluate(() => ({
				tabs: [...document.querySelectorAll('[data-cdtm-tab]')].map(t => t.dataset.cdtmTab + (t.getAttribute('aria-selected') === 'true' ? '*' : '')),
				imgs: [...document.querySelectorAll('[data-cdtm-top] img.cdtm-flag')].map(i => ({ w: i.getAttribute('width'), h: i.getAttribute('height'), alt: i.getAttribute('alt'), lazy: i.loading, ok: i.complete, box: Math.round(i.getBoundingClientRect().width) + 'x' + Math.round(i.getBoundingClientRect().height) })),
				low: document.querySelector('[data-cdtm-low]').hidden,
			}));
			const flagRequests = requests.filter(u => u.includes('/assets/flags/4x3/'));
			assert.deepEqual(fl.tabs, ['radar*', 'ransomware', 'feodo']);
			assert.equal(fl.imgs.length, 10);
			assert.ok(fl.imgs.every(i => i.w === '20' && i.h === '15' && i.alt === '' && i.lazy === 'lazy' && i.ok && i.box === '20x15'), JSON.stringify(fl.imgs[0]));
			assert.ok(flagRequests.length >= 1 && flagRequests.length <= 10, 'flag requests ' + flagRequests.length);
			assert.ok(flagRequests.every(u => new URL(u).origin === ORIGIN));
			assert.equal(fl.low, true);
			pass(`${vpName}: default tab from the data (${fl.tabs.join(', ')}); 10 flags 20x15, lazy, alt="" — ${flagRequests.length} flag files requested (not 250), all from the CyberDat origin`);

			if (name === 'chromium') {
				const cls = await page.evaluate(() => window.__cls);
				assert.ok(cls < 0.02, 'CLS ' + cls);
				pass(`${vpName}: layout shift on load ${cls.toFixed(4)} (< 0.02)`);
			}

			const small = await page.evaluate(() => [...document.querySelectorAll('.cdtm-tabs button, .cdtm-periods button, .cdtm-top button, .cdtm-search input')].filter(e => e.offsetParent).map(e => { const r = e.getBoundingClientRect(); return { t: e.textContent.trim().slice(0, 20) || e.tagName, w: r.width, h: r.height }; }).filter(r => r.h < 44 || r.w < 44));
			assert.deepEqual(small, []);
			const contrast = await page.evaluate(CONTRAST);
			assert.ok(contrast.length >= 10 && contrast.every(c => c.ratio >= 4.5), JSON.stringify(contrast.filter(c => c.ratio < 4.5)));
			pass(`${vpName}: targets ≥ 44 px; text contrast ≥ 4.5 (min ${Math.min(...contrast.map(c => c.ratio))} over ${contrast.length} styles)`);

			// keyboard: Tab through layer tabs, periods and the top 10 (WebKit moves focus to buttons only with Alt+Tab)
			const TAB = name === 'webkit' ? 'Alt+Tab' : 'Tab';
			await page.focus('.cdtm-disclaimer').catch(() => {});
			await page.evaluate(() => { const d = document.querySelector('.cdtm-disclaimer'); d.tabIndex = -1; d.focus(); });
			const order = [];
			for (let i = 0; i < 10; i++) { await page.keyboard.press(TAB); order.push(await page.evaluate(() => { const a = document.activeElement; return a.dataset.cdtmTab || a.dataset.cdtmPeriod || (a.dataset.cdtmCc ? 'top:' + a.dataset.cdtmCc : a.tagName); })); }
			assert.deepEqual(order.slice(0, 6), ['radar', 'ransomware', 'feodo', '24h', '7d', '30d']);
			assert.ok(order.slice(6).every(x => x.startsWith('top:')), order.join(','));
			await page.focus('[data-cdtm-tab="radar"]');
			await page.keyboard.press('ArrowRight');
			assert.equal(await page.evaluate(() => document.activeElement.dataset.cdtmTab + '|' + document.querySelector('[data-cdtm-tab=ransomware]').getAttribute('aria-selected') + '|' + document.querySelector('#cdtm-panel-radar').hidden), 'ransomware|true|true');
			await page.focus('[data-cdtm-period="30d"]');
			await page.keyboard.press('Enter');
			assert.equal(await page.getAttribute('[data-cdtm-period="30d"]', 'aria-pressed'), 'true');
			assert.match(await page.textContent('[data-cdtm-top-title]'), /30 days/);
			await page.focus('[data-cdtm-top] li:first-child button');
			await page.keyboard.press('Enter');
			const panel = await page.evaluate(() => { const b = document.querySelector('[data-cdtm-country]'); return { h: b.querySelector('h4')?.textContent, strong: [...b.querySelectorAll('strong')].map(s => s.textContent), link: b.querySelector('a')?.href, related: !!b.querySelector('[data-cdtm-related]'), close: b.querySelector('.cdtm-close')?.getBoundingClientRect().height }; });
			assert.equal(panel.h, 'United States');
			assert.match(panel.strong[1], /^[+-]?\d+%$|^new$|^0$/);
			assert.equal(panel.link, 'https://www.ransomware.live/country/US');
			assert.ok(panel.related && panel.close >= 44);
			await page.keyboard.press('Escape');
			assert.equal(await page.evaluate(() => !!document.querySelector('[data-cdtm-country] h4')), false);
			pass(`${vpName}: keyboard — ${TAB} order tabs → periods → top 10; arrows switch layers; Enter opens the country panel (total, ${panel.strong[1]} vs previous, sectors, source link, related-articles slot); Escape closes`);

			if (vpName === 'desktop') {
				await page.evaluate(() => document.querySelector('.cdtm-mapbox').scrollIntoView({ block: 'center' }));
				await sleep(100);
				const usa = await page.$('.cdtm-map path[data-cc="US"]');
				const box = await usa.boundingBox();
				// a real pointer moves in steps (WebKit ignores a single jump from outside the page)
				await page.mouse.move(box.x + box.width * 0.5, box.y + box.height * 0.55);
				await page.mouse.move(box.x + box.width * 0.55, box.y + box.height * 0.6, { steps: 3 });
				await sleep(150);
				const tip = await page.evaluate(() => { const t = document.querySelector('[data-cdtm-tip]'); return t.hidden ? '' : t.textContent; });
				assert.match(tip, /United States\d[\d,]* reported victims/);
				assert.equal(await page.evaluate(() => document.querySelectorAll('[data-cdtm-tip] img.cdtm-flag').length), 1);
				await page.mouse.click(box.x + box.width * 0.55, box.y + box.height * 0.6);
				assert.equal(await page.evaluate(() => document.querySelector('[data-cdtm-country] h4')?.textContent), 'United States');
				assert.equal(await page.getAttribute('.cdtm-map path[data-cc="US"]', 'class'), 'cdtm-c s5 is-selected');
				const legend = await page.textContent('[data-cdtm-legend]');
				assert.match(legend, /^Reported victims:none1/);
				pass(`desktop: hover tooltip "${tip}", click selects the country, legend "${legend.slice(0, 60)}…"`);
				await page.locator('.cdtm').screenshot({ path: path.join(EVIDENCE, tag + '-ransomware-30d-US.png') });
				// Cloudflare Radar: percentages, change in percentage points against the source's comparison window
				await page.click('[data-cdtm-tab="radar"]');
				await page.click('[data-cdtm-period="7d"]');
				await page.click('[data-cdtm-top] li:first-child button');
				await sleep(150);
				const rd = await page.evaluate(() => ({
					legend: document.querySelector('[data-cdtm-legend]').textContent,
					values: [...document.querySelectorAll('[data-cdtm-top] .cdtm-top-n')].map(x => x.textContent),
					change: [...document.querySelectorAll('[data-cdtm-country] .cdtm-figures div:nth-child(2) > *')].map(x => x.textContent),
					low: document.querySelector('[data-cdtm-low]').hidden,
				}));
				assert.match(rd.legend, /^% of observed attacks:none0\.01–/);
				assert.ok(rd.values.length === 10 && rd.values.every(v => /^\d+\.\d{2}%$/.test(v)), rd.values.join(' '));
				assert.equal(rd.change[0], 'vs comparison window');
				assert.match(rd.change[1], /^[+−]?\d+\.\d{2} pp$/);
				assert.match(rd.change[2], /^then: \d+\.\d{2}% \(2026-11-10 – 2026-11-17, as provided by the source\)$/);
				assert.equal(rd.low, true);
				pass(`desktop: Radar in percent (top ${rd.values[0]}, legend "${rd.legend.slice(0, 40)}…"), change ${rd.change[1]} vs the source's comparison window; no low-activity note`);
				await page.locator('.cdtm').screenshot({ path: path.join(EVIDENCE, tag + '-radar-7d-US.png') });
				await page.click('[data-cdtm-tab="feodo"]');
				await sleep(150);
				assert.equal(await page.evaluate(() => document.querySelector('[data-cdtm-low]').hidden), false);
				pass('desktop: Feodo (3 countries) shows "Low activity in the source right now"');
				await page.locator('.cdtm').screenshot({ path: path.join(EVIDENCE, tag + '-feodo-7d-low.png') });
			} else {
				await page.fill('[data-cdtm-search]', 'ger');
				const hits = await page.$$eval('[data-cdtm-results] button', b => b.map(x => x.dataset.cdtmCc));
				assert.deepEqual(hits, ['DE', 'NG']);
				await page.click('[data-cdtm-results] button[data-cdtm-cc="DE"]');
				assert.equal(await page.evaluate(() => document.querySelector('[data-cdtm-country] h4')?.textContent), 'Germany');
				pass('mobile: country search "ger" → Germany, Nigeria; a result opens the country panel');
				await page.screenshot({ path: path.join(EVIDENCE, tag + '-search-DE.png'), fullPage: true });
			}
			await context.close();
		}

		// statuses from the server HTML (and kept by the script)
		const ctx = await browser.newContext({ viewport: VIEWPORTS.desktop });
		const page = await ctx.newPage();
		const statuses = {};
		for (const s of ['stale', 'unavailable', 'empty', 'notconfigured']) {
			await page.goto(BASE + '/stand/' + s + '/');
			await sleep(700);
			statuses[s] = await page.evaluate(() => ({
				chips: [...document.querySelectorAll('.cdtm-chip')].map(c => c.textContent),
				status: [...document.querySelectorAll('[data-cdtm-status]')].map(p => p.textContent),
				stage: document.querySelector('[data-cdtm-stage]').dataset.state,
				top: document.querySelectorAll('[data-cdtm-top] li').length,
			}));
			if (name === 'chromium') await page.locator('.cdtm').screenshot({ path: path.join(EVIDENCE, `${name}-status-${s}.png`) });
		}
		assert.deepEqual(statuses.stale.chips, ['Stale', 'Stale', 'Stale']);
		assert.match(statuses.stale.status[0], /^Stale: last successful update 4 h 0 min ago \(2026-11-24 19:27 UTC\)/);
		assert.ok(statuses.stale.top > 0 && statuses.stale.stage === 'data');
		assert.deepEqual(statuses.unavailable.chips, ['Unavailable', 'Unavailable', 'Unavailable']);
		assert.match(statuses.unavailable.status[0], /^Data unavailable since 2026-11-24 19:27 UTC/);
		assert.ok(statuses.unavailable.top === 0 && statuses.unavailable.stage === 'nodata');
		assert.ok(statuses.empty.status.every(t => t.startsWith('Data unavailable: waiting for the first successful collection')) && statuses.empty.stage === 'nodata');
		assert.deepEqual(statuses.notconfigured.chips, ['Updated', 'Not configured', 'Not configured']);
		assert.match(statuses.notconfigured.status[1], /^Not configured: this layer needs a source API key/);
		pass('statuses: stale after 3 h (numbers with time), unavailable after 48 h (grey map, no numbers), empty store, "not configured" without keys (Feodo, the only ok layer, opens first)');
		await ctx.close();

		// without JavaScript: server top-10 tables for every layer, no controls that need the script
		const nojs = await browser.newContext({ viewport: VIEWPORTS.desktop, javaScriptEnabled: false });
		const p2 = await nojs.newPage();
		await p2.goto(BASE + '/stand/data/');
		const nj = await p2.evaluate(() => ({
			tables: [...document.querySelectorAll('.cdtm-table table')].filter(t => t.offsetParent).map(t => t.querySelector('caption').textContent + ':' + t.querySelectorAll('tbody tr').length),
			tabs: getComputedStyle(document.querySelector('.cdtm-tabs')).display,
			stage: getComputedStyle(document.querySelector('.cdtm-stage')).display,
			panels: [...document.querySelectorAll('.cdtm-panel')].filter(p => p.offsetParent).length,
		}));
		assert.equal(nj.tables.length, 3);
		assert.ok(nj.tables.every(t => /:([1-9]|10)$/.test(t)), nj.tables.join(' | '));
		assert.equal(nj.tabs, 'none');
		assert.equal(nj.stage, 'none');
		assert.equal(nj.panels, 3);
		if (name === 'chromium') await p2.locator('.cdtm').screenshot({ path: path.join(EVIDENCE, `${name}-no-javascript.png`) });
		pass('no JavaScript: all three layers with status and a server top-10 table; tabs and map hidden — ' + nj.tables.join(' | '));
		await nojs.close();
	} finally {
		await browser.close();
	}
	return results;
}

(async () => {
	const all = {};
	for (const b of BROWSERS) all[b] = await run(b);
	fs.writeFileSync(path.join(EVIDENCE, 'results.json'), JSON.stringify(all, null, 2));
	console.log(`PASS: threat map cross-browser — ${Object.values(all).reduce((n, r) => n + r.length, 0)} checks in ${BROWSERS.join(', ')}; evidence ${EVIDENCE}`);
})().catch(e => { console.error('FAIL:', e && e.stack || e); process.exit(1); });
