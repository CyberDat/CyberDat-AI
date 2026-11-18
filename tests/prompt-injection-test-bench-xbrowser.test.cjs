/*
 * Cross-browser acceptance (Firefox, WebKit) for the LLM Prompt Injection Test Bench via Playwright.
 *   NODE_PATH=<pw>/node_modules node tests/prompt-injection-test-bench-xbrowser.test.cjs [url] [evidence-dir] [browsers]
 */
'use strict';
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const { runX } = require('./lib/tool-xbrowser.cjs');

runX({
	name: 'pitb', root: '[data-pitb]', url: process.argv[2] || 'http://127.0.0.1:18091/tools/prompt-injection-test-bench/', evidence: process.argv[3], browsers: (process.argv[4] || 'firefox,webkit').split(','),
	body: async h => {
		const { page, assert } = h;
		await page.evaluate(() => { document.querySelectorAll('[data-pitb-lang]').forEach(c => { c.checked = true; }); });
		await page.click('[data-pitb-build]');
		await h.until(() => !document.querySelector('[data-pitb-set]').hidden);
		assert.equal(await page.locator('[data-pitb-tests] > li').count(), 30);
		const set = await h.download('[data-pitb-download="jsonl"]');
		assert.equal(set.name, 'prompt-injection-tests.jsonl');
		const lines = set.text.trim().split('\n').slice(1).map(JSON.parse);
		h.pass('build (chat, three languages): 30 tests; JSONL download with canaries');
		await page.fill('[data-pitb-response="' + lines[0].id + '"]', 'ok ' + lines[0].canary + ' ' + S.HF_TOKEN);
		await page.fill('[data-pitb-response="' + lines[1].id + '"]', [...lines[1].canary].reverse().join(''));
		await page.fill('[data-pitb-response="' + lines[2].id + '"]', 'Nein, das mache ich nicht.');
		await page.click('[data-pitb-check]');
		await h.until(() => !document.querySelector('[data-pitb-results]').hidden && document.activeElement.id === 'cd-pitb-step-results');
		const ui = await page.$eval('[data-pitb-results]', e => e.textContent);
		assert.ok(/^2 tests of 3 answered triggered/.test(await page.$eval('[data-pitb-verdict]', e => e.textContent)) && !ui.includes(S.HF_TOKEN) && /reversed/.test(ui));
		const rep = await h.download('[data-pitb-report="markdown"]');
		assert.ok(!rep.text.includes(S.HF_TOKEN) && /\*\*Triggered\*\*/.test(rep.text));
		h.pass('check: plain and reversed canaries found, refusal not; secret masked in results and Markdown report');
		const bad = await page.evaluate(() => [...document.querySelectorAll('[data-pitb] textarea, [data-pitb] pre, [data-pitb-set], [data-pitb-results], [data-pitb-error]')].filter(e => !(e.getAttribute('translate') === 'no' && e.classList.contains('notranslate'))).length);
		assert.equal(bad, 0);
		h.pass('translate="no" and notranslate on inputs, test texts, responses and results');
		await page.evaluate(() => { const big = ('Long answer without the code. Größe. ').repeat(5000).slice(0, 150000); document.querySelectorAll('[data-pitb-response]').forEach(t => { t.value = big; }); });
		const t0 = Date.now();
		await page.click('[data-pitb-check]');
		await h.until(() => !document.querySelector('[data-pitb-check]').disabled && /^No canary/.test(document.querySelector('[data-pitb-verdict]').textContent), null, 60000);
		h.pass('30 responses of 150,000 characters checked in the worker', ((Date.now() - t0) / 1000).toFixed(1) + ' s');
		await page.focus('[data-pitb-response]');
		await page.keyboard.press('Control+Enter');
		await h.until(() => document.activeElement.id === 'cd-pitb-step-results');
		h.pass('keyboard: Ctrl+Enter in a response checks and moves focus to the results');
	},
	mobile: async h => { await h.page.click('[data-pitb-build]'); await h.until(() => !document.querySelector('[data-pitb-set]').hidden); }
});
