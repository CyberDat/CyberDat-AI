/*
 * Cross-browser acceptance (Firefox, WebKit) for the YARA/Sigma Rule Validator & Converter via Playwright.
 *   NODE_PATH=<pw>/node_modules node tests/yara-sigma-validator-xbrowser.test.cjs [url] [evidence-dir] [browsers]
 */
'use strict';
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const { runX } = require('./lib/tool-xbrowser.cjs');

runX({
	name: 'ysv', root: '[data-ysv]', url: process.argv[2] || 'http://127.0.0.1:18091/tools/yara-sigma-validator/', evidence: process.argv[3], browsers: (process.argv[4] || 'firefox,webkit').split(','),
	body: async h => {
		const { page, assert } = h;
		const run = async () => { await page.click('[data-ysv-run]'); await h.until(() => !document.querySelector('[data-ysv-run]').disabled && !document.querySelector('[data-ysv-results]').hidden && document.activeElement.id === 'cd-ysv-step-results', null, 30000); };
		const ids = () => page.evaluate(() => [...new Set([...document.querySelectorAll('[data-ysv-list] .cd-ysv-finding__head code')].map(c => c.textContent))].sort());
		await page.click('[data-ysv-sample-sigma]');
		await page.evaluate(() => { document.querySelector('.cd-ysv-convert').open = true; });
		await page.selectOption('[data-ysv-target]', 'spl');
		await run();
		assert.deepEqual(await ids(), []);
		assert.equal(await page.$eval('[data-ysv-conv-out] pre', e => e.textContent), 'Image="*\\\\net.exe" AND ParentImage="*\\\\cmd.exe" AND NOT User="*svc_*"');
		h.pass('Sigma example: no findings; SPL conversion');
		await page.fill('[data-ysv-input]', 'rule Bad\n{\n    strings:\n        $a = "ab"\n    condition:\n        $a and $b\n}\n');
		await run();
		assert.deepEqual(await ids(), ['YAR-Q-001', 'YAR-Q-003', 'YAR-STR-002']);
		h.pass('YARA: undeclared string, short string, no file size limit');
		await page.fill('[data-ysv-input]', "title: S\nlogsource:\n    product: windows\ndetection:\n    s:\n        CommandLine|contains: '" + S.HF_TOKEN + "'\n    condition: s\n");
		await run();
		const ui = await page.$eval('[data-ysv-results]', e => e.textContent);
		assert.ok(!ui.includes(S.HF_TOKEN));
		const rep = await h.download('[data-ysv-report="markdown"]');
		assert.ok(!rep.text.includes(S.HF_TOKEN) && /do not replace compiling/.test(rep.text));
		h.pass('secret in a rule masked in results and Markdown report; query hidden until confirmed');
		const bad = await page.evaluate(() => [...document.querySelectorAll('[data-ysv] textarea, [data-ysv] select, [data-ysv] pre, [data-ysv-results], [data-ysv-error]')].filter(e => !(e.getAttribute('translate') === 'no' && e.classList.contains('notranslate'))).length);
		assert.equal(bad, 0);
		h.pass('translate="no" and notranslate on inputs, queries and results');
		const big = 'title: Many\nlogsource:\n    product: windows\ndetection:\n' + Array.from({ length: 6000 }, (_, i) => '    sel' + i + ":\n        F" + i + "|contains: 'Пётр" + i + "'\n").join('') + '    condition: 1 of sel*\n';
		await page.$eval('[data-ysv-input]', (el, v) => { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); }, big); // page.fill types 300 KB too slowly in WebKit
		await page.selectOption('[data-ysv-target]', 'kql');
		const t0 = Date.now();
		await run();
		h.pass('6,000 search identifiers checked and converted in the worker', ((Date.now() - t0) / 1000).toFixed(1) + ' s');
		await page.focus('[data-ysv-input]');
		await page.keyboard.press('Control+Enter');
		await h.until(() => document.activeElement.id === 'cd-ysv-step-results');
		h.pass('keyboard: Ctrl+Enter checks and moves focus to the results');
	},
	mobile: async h => { await h.page.click('[data-ysv-sample-yara]'); await h.page.click('[data-ysv-run]'); await h.until(() => !document.querySelector('[data-ysv-results]').hidden); }
});
