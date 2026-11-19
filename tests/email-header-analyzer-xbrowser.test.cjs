/*
 * Cross-browser acceptance (Firefox, WebKit) for the Email Header Analyzer via Playwright.
 *   NODE_PATH=<pw>/node_modules node tests/email-header-analyzer-xbrowser.test.cjs [url] [evidence-dir] [browsers]
 */
'use strict';
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const { runX } = require('./lib/tool-xbrowser.cjs');

runX({
	name: 'eha', root: '[data-eha]', url: process.argv[2] || 'http://127.0.0.1:18091/tools/email-header-analyzer/', evidence: process.argv[3], browsers: (process.argv[4] || 'firefox,webkit').split(','),
	body: async h => {
		const { page, assert } = h;
		const run = async () => { await page.evaluate(() => document.activeElement && document.activeElement.blur()); await page.click('[data-eha-run]'); await h.until(() => !document.querySelector('[data-eha-run]').disabled && !document.querySelector('[data-eha-results]').hidden && document.activeElement.id === 'cd-eha-step-results', null, 30000); };
		const ids = () => page.evaluate(() => [...new Set([...document.querySelectorAll('[data-eha-results] .cd-eha-finding code.cd-eha-muted')].map(c => c.textContent))].sort());
		await page.click('[data-eha-sample="phishing"]');
		await run();
		const got = await ids();
		assert.ok(['EHA-AUTH-001', 'EHA-BRAND-001', 'EHA-LOOK-003'].every(x => got.includes(x)), got.join(' '));
		h.pass('phishing example: DMARC fail, brand impersonation, lookalike domain');
		const eml = 'Received: from mx.example.com (mx.example.com [192.0.2.25])\r\n\tby imap.example.com (Postfix) with ESMTPS id E1\r\n\tfor <bob@example.com>; Tue, 17 Nov 2026 10:00:05 +0100\r\nFrom: =?UTF-8?B?' + Buffer.from('Пётр Größe').toString('base64') + '?= <petr@example.org>\r\nTo: bob@example.com\r\nSubject: <img src=x onerror=window.__xss=1> ' + S.HF_TOKEN + '\r\nDate: Tue, 17 Nov 2026 10:00:00 +0100\r\nMessage-ID: <x@example.org>\r\n\r\nBODY-ONLY-77\r\n';
		await page.fill('[data-eha-input]', '');
		await page.setInputFiles('[data-eha-file]', { name: 'message.eml', mimeType: 'message/rfc822', buffer: Buffer.from(eml) });
		await h.until(() => document.querySelector('[data-eha-input]').value.includes('BODY-ONLY-77'));
		await run();
		const r = await page.evaluate(() => ({ ui: document.querySelector('[data-eha-results]').textContent, imgs: document.querySelectorAll('[data-eha-results] img').length, xss: window.__xss || 0 }));
		assert.ok(!r.ui.includes('BODY-ONLY-77') && !r.ui.includes(S.HF_TOKEN) && r.imgs === 0 && r.xss === 0 && r.ui.includes('Пётр Größe'));
		await page.check('[data-eha-mask="recipients"]');
		const rep = await h.download('[data-eha-report="markdown"]');
		assert.ok(!rep.text.includes('BODY-ONLY-77') && !rep.text.includes(S.HF_TOKEN) && !rep.text.includes('bob@example.com') && /does not mean the message is safe|hijacked real account/u.test(rep.text));
		h.pass('.eml file: body ignored, encoded name decoded, HTML in the subject stays text, secret masked; Markdown report with recipients masked');
		const bad = await page.evaluate(() => [...document.querySelectorAll('[data-eha] textarea, [data-eha] input[type=file], [data-eha-own], [data-eha-results], [data-eha-error]')].filter(e => !(e.getAttribute('translate') === 'no' && e.classList.contains('notranslate'))).length);
		assert.equal(bad, 0);
		h.pass('translate="no" and notranslate on inputs and results');
		const hop = i => 'Received: from relay' + i + '.example.net (relay' + i + '.example.net [198.51.100.' + (i % 250) + '])\n\tby relay' + (i + 1) + '.example.net with ESMTP id Q' + i + '; Tue, 17 Nov 2026 10:' + String(i % 60).padStart(2, '0') + ':00 +0100\n';
		const big = Array.from({ length: 600 }, (_, i) => hop(600 - i)).join('') + 'From: a@example.org\n';
		await page.$eval('[data-eha-input]', (el, v) => { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); }, big);
		const t0 = Date.now();
		await run();
		assert.equal(await page.evaluate(() => document.querySelectorAll('.cd-eha-hop').length), 600);
		h.pass('600 Received lines analysed in the worker', ((Date.now() - t0) / 1000).toFixed(1) + ' s');
		await page.click('[data-eha-sample="normal"]');
		await page.focus('[data-eha-input]');
		await page.keyboard.press('Control+Enter');
		await h.until(() => document.activeElement.id === 'cd-eha-step-results' && /No known warning signs matched/u.test(document.querySelector('[data-eha-verdict]').textContent));
		h.pass('keyboard: Ctrl+Enter analyses the normal example; no-findings wording');
	},
	mobile: async h => { await h.page.click('[data-eha-sample="phishing"]'); await h.page.click('[data-eha-run]'); await h.until(() => !document.querySelector('[data-eha-results]').hidden); }
});
