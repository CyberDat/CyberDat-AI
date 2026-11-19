/*
 * Browser acceptance for the Email Header Analyzer (Chromium/Edge over the DevTools protocol, no deps).
 *   node tests/email-header-analyzer-browser.test.cjs [url] [evidence-dir]
 */
'use strict';
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const { runEdge } = require('./lib/tool-browser.cjs');

runEdge({
	name: 'eha', root: '[data-eha]', url: process.argv[2] || 'http://127.0.0.1:18091/tools/email-header-analyzer/', evidence: process.argv[3],
	body: async h => {
		const { assert } = h;
		const run = async () => { await h.evaluate("window.__done = false; new MutationObserver((m, o) => { if (!document.querySelector('[data-eha-run]').disabled && (document.activeElement.id === 'cd-eha-step-results' || !document.querySelector('[data-eha-error]').hidden)) { window.__done = true; o.disconnect(); } }).observe(document.querySelector('[data-eha]'), { subtree: true, attributes: true, childList: true, characterData: true }); document.activeElement.blur(); true"); await h.click('[data-eha-run]'); await h.waitFor('window.__done === true', 30000, 'result'); };
		const ids = () => h.evaluate("[...new Set([...document.querySelectorAll('[data-eha-results] .cd-eha-finding code.cd-eha-muted')].map(c => c.textContent))].sort()");

		h.phase = 'phishing';
		await h.click('[data-eha-sample="phishing"]');
		await run();
		const p = await h.evaluate("({ verdict: document.querySelector('[data-eha-verdict]').textContent, auth: document.querySelector('[data-eha-auth]').textContent, boundary: document.querySelector('[data-eha-boundary]').textContent, steps: document.querySelectorAll('.cd-eha-hop').length, bnd: document.querySelectorAll('.cd-eha-hop--boundary').length, unt: document.querySelectorAll('.cd-eha-hop--untrusted').length, links: document.querySelectorAll('[data-eha] a').length, focus: document.activeElement.id })");
		const got = await ids();
		for (const x of ['EHA-AUTH-001', 'EHA-AUTH-005', 'EHA-BRAND-001', 'EHA-FROM-002', 'EHA-LOOK-003', 'EHA-REPLY-001']) { assert.ok(got.includes(x), x + ' in ' + got.join(' ')); }
		assert.ok(/warning signs? found/u.test(p.verdict) && /NOT trusted \(duplicate/u.test(p.auth) && /First external server: 203\.0\.113\.44/u.test(p.boundary), JSON.stringify(p));
		assert.ok(p.steps === 3 && p.bnd === 1 && p.unt === 1 && p.links === 0 && p.focus === 'cd-eha-step-results', JSON.stringify(p));
		h.pass('phishing example: DMARC fail, brand and lookalike, Reply-To, forged duplicate result marked NOT trusted; path from sender with the trust boundary; focus on results; no links', got.length + ' findings');
		await h.shot('01-phishing-1440');

		h.phase = 'normal';
		await h.click('[data-eha-sample="normal"]');
		await run();
		assert.equal(await h.evaluate("document.querySelector('[data-eha-verdict] strong').textContent"), 'No known warning signs matched. This does not mean the message is safe.');
		assert.match(await h.evaluate("document.querySelector('[data-eha-summary]').textContent"), /Jürgen Beispiel/u);
		h.pass('normal example: “No known warning signs matched. This does not mean the message is safe.”; encoded sender name decoded');

		h.phase = 'eml';
		const eml = 'Received: from mx.example.com (mx.example.com [192.0.2.25])\r\n\tby imap.example.com (Postfix) with ESMTPS id E1\r\n\tfor <bob@example.com>; Tue, 17 Nov 2026 10:00:05 +0100\r\nReceived: from [10.4.4.4] (unknown [10.4.4.4])\r\n\tby mx.example.com (Postfix) with ESMTP id E0\r\n\tfor <bob@example.com>; Tue, 17 Nov 2026 10:00:03 +0100\r\nFrom: "<img src=x onerror=window.__xss=1>" <alice@example.org>\r\nTo: Bob <bob@example.com>\r\nSubject: <script>window.__xss=2</script> ' + S.GITHUB_PAT + '\r\nDate: Tue, 17 Nov 2026 10:00:00 +0100\r\nMessage-ID: <e1@example.org>\r\n\r\nBODY-ONLY-55 confidential plan\r\n';
		await h.setValue('[data-eha-input]', '');
		await h.evaluate('(() => { const dt = new DataTransfer(); dt.items.add(new File([' + JSON.stringify(eml) + '], "message.eml", { type: "message/rfc822" })); const i = document.querySelector("[data-eha-file]"); i.files = dt.files; i.dispatchEvent(new Event("change", { bubbles: true })); return true; })()');
		await h.waitFor("document.querySelector('[data-eha-input]').value.includes('BODY-ONLY-55')", 5000, 'file read');
		await run();
		const x = await h.evaluate("({ ui: document.querySelector('[data-eha-results]').textContent, imgs: document.querySelectorAll('[data-eha-results] img, [data-eha-results] script').length, xss: window.__xss || 0, notes: document.querySelector('[data-eha-notes]').textContent })");
		assert.ok(!x.ui.includes('BODY-ONLY-55') && /body .* was ignored/u.test(x.notes), 'body');
		assert.ok(x.imgs === 0 && x.xss === 0 && x.ui.includes('<img src=x onerror=window.__xss=1>') && x.ui.includes('<script>window.__xss=2</script>'), 'xss');
		assert.ok(!x.ui.includes(S.GITHUB_PAT));
		await h.click('[data-eha-report="json"]');
		await h.sleep(300);
		const j1 = await h.lastBlob();
		await h.evaluate("for (const m of document.querySelectorAll('[data-eha-mask]')) { m.checked = true; } true");
		await h.click('[data-eha-report="markdown"]');
		await h.sleep(300);
		const m2 = await h.lastBlob();
		await h.click('[data-eha-report="json"]');
		await h.sleep(300);
		const j2 = await h.lastBlob();
		assert.ok(!j1.includes('BODY-ONLY-55') && !m2.includes('BODY-ONLY-55') && !j1.includes(S.GITHUB_PAT) && j1.includes('bob@example.com') && j1.includes('10.4.4.4'));
		assert.ok(!j2.includes('bob@example.com') && !m2.includes('bob@example.com') && !j2.includes('10.4.4.4') && j2.includes('[recipient 1]') && j2.includes('[internal IP 1]'));
		h.pass('.eml file opened in the tab: body ignored and never shown or exported; names and subjects with HTML stay text (no element, no script run); secrets masked; export masks recipients and internal IPs on request');

		h.phase = 'translate';
		const n = await h.translateCheck('[data-eha] textarea, [data-eha] input[type=file], [data-eha-own], [data-eha-results], [data-eha-error]');
		h.pass('header input, file input, own-domain field, results and error box carry translate="no" and notranslate', n + ' elements');

		h.phase = 'large';
		const hop = i => 'Received: from relay' + i + '.example.net (relay' + i + '.example.net [198.51.100.' + (i % 250) + '])\n\tby relay' + (i + 1) + '.example.net (Postfix) with ESMTP id Q' + i + '\n\tfor <bob@example.com>; Tue, 17 Nov 2026 10:' + String(i % 60).padStart(2, '0') + ':00 +0100\n';
		const big = Array.from({ length: 800 }, (_, i) => hop(800 - i)).join('') + 'From: a@example.org\nSubject: Größe\n\n' + 'body line\n'.repeat(200000);
		await h.setValue('[data-eha-input]', big);
		const t0 = Date.now();
		await run();
		assert.equal(await h.evaluate("document.querySelectorAll('.cd-eha-hop').length"), 800);
		h.pass('800 Received lines with a ' + Math.round(big.length / 1048576 * 10) / 10 + ' MB body analysed in the worker', ((Date.now() - t0) / 1000).toFixed(1) + ' s');
		await h.setValue('[data-eha-input]', 'x'.repeat(5 * 1024 * 1024 + 5));
		await h.click('[data-eha-run]');
		assert.match(await h.evaluate("document.querySelector('[data-eha-error]').textContent"), /larger than 5 MB/u);
		h.pass('input over 5 MB refused with a message');

		h.phase = 'keyboard';
		await h.navigate();
		await h.evaluate("document.querySelector('[data-eha-sample=\"phishing\"]').focus(); true");
		await h.key('Enter');
		await h.evaluate("document.querySelector('[data-eha-input]').focus(); true");
		await h.key('Enter', 2);
		await h.waitFor("document.activeElement.id === 'cd-eha-step-results'", 10000, 'Ctrl+Enter');
		const outline = await h.evaluate("(() => { document.querySelector('[data-eha-run]').focus(); return getComputedStyle(document.activeElement).outlineStyle; })()");
		assert.ok(outline !== 'none');
		h.pass('keyboard: Enter loads the example, Ctrl+Enter analyses, focus moves to the results; focus visible');
		await h.evaluate("document.querySelector('[data-eha-info-wrap]').open = true; true");
		const low = await h.contrast(['[data-eha] .cd-la-label', '[data-eha] .cd-la-help', '[data-eha] .cd-la-button--primary', '[data-eha] .cd-la-button--secondary', '[data-eha] .cd-eha-sev--high', '[data-eha] .cd-eha-sev--medium', '[data-eha] .cd-eha-sev--info', '[data-eha] .cd-eha-muted', '[data-eha] .cd-eha-verdict strong', '[data-eha] .cd-eha-state', '[data-eha] .cd-eha-tag', '[data-eha] .cd-eha-summary dt', '[data-eha] .cd-la-info li']);
		h.pass('text contrast at least 4.5:1', 'lowest ' + low + ':1');

		h.phase = 'reload';
		await h.viewport(360, 780, true);
		await h.navigate();
		await h.click('[data-eha-sample="phishing"]');
		await run();
		await h.mobileCheck();
		await h.shot('02-phishing-360');
		h.pass('360 px: no horizontal scrolling; controls at least 44 px; headings fit');
	}
});
