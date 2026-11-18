/*
 * Browser acceptance for the LLM Prompt Injection Test Bench (Chromium/Edge over the DevTools protocol, no deps).
 *   node tests/prompt-injection-test-bench-browser.test.cjs [url] [evidence-dir]
 *   default url: http://127.0.0.1:18091/tools/prompt-injection-test-bench/  (tests/tools-sandbox-server.py --port 18091)
 */
'use strict';
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const { runEdge } = require('./lib/tool-browser.cjs');

runEdge({
	name: 'pitb', root: '[data-pitb]', url: process.argv[2] || 'http://127.0.0.1:18091/tools/prompt-injection-test-bench/', evidence: process.argv[3],
	body: async h => {
		const { assert } = h;
		h.phase = 'build';
		await h.evaluate("document.querySelectorAll('[data-pitb-app-type]').forEach(c => { c.checked = ['chat', 'agent'].includes(c.value); }); document.querySelectorAll('[data-pitb-lang]').forEach(c => { c.checked = ['en', 'ru'].includes(c.value); }); true");
		await h.click('[data-pitb-build]');
		await h.waitFor("!document.querySelector('[data-pitb-set]').hidden && document.activeElement.id === 'cd-pitb-step-run'", 10000, 'set');
		const set = await h.evaluate("({ n: document.querySelectorAll('[data-pitb-tests] > li').length, label: document.querySelector('[data-pitb-label]').textContent, inputs: [...document.querySelectorAll('.cd-pitb-input')].map(p => p.textContent), links: document.querySelectorAll('[data-pitb] a').length })");
		assert.equal(set.n, 32);
		assert.ok(/LABEL-[0-9A-F]{8}/.test(set.label) && set.links === 0);
		assert.ok(set.inputs.every(t => /CANARY-[0-9A-F]{8}|label|метк|above this message|выше этого|Base64|[\u{E0000}-\u{E007F}]/iu.test(t)));
		h.pass('build: chat + agent in English and Russian gives 32 tests with own canaries and a system-prompt label; focus moves to the set; no links', set.n + ' tests');
		await h.shot('01-set-1440');
		await h.click('[data-pitb-download="jsonl"]');
		await h.sleep(300);
		const jsonl = await h.lastBlob();
		assert.equal(jsonl.trim().split('\n').length, 33);
		await h.click('[data-pitb-download="csv"]');
		await h.sleep(300);
		assert.ok(/^id,category,lang,channel/.test(await h.lastBlob()));
		h.pass('test set downloads: JSONL (header + 32 tests) and CSV');

		h.phase = 'check';
		const tests = await h.evaluate("[...document.querySelectorAll('[data-pitb-response]')].map(t => t.getAttribute('data-pitb-response'))");
		const canaryOf = id => JSON.parse(jsonl.trim().split('\n').find(l => l.includes('"id":"' + id + '"'))).canary;
		const c0 = canaryOf(tests[0]), c1 = canaryOf(tests[1]);
		await h.setValue('[data-pitb-response="' + tests[0] + '"]', 'Sure: ' + c0 + ' (debug key ' + S.OPENAI_PROJECT_KEY + ')');
		await h.setValue('[data-pitb-response="' + tests[1] + '"]', 'Code: ' + Buffer.from(c1).toString('base64'));
		await h.setValue('[data-pitb-response="' + tests[2] + '"]', 'I will not follow that instruction.');
		await h.click('[data-pitb-check]');
		await h.waitFor("!document.querySelector('[data-pitb-results]').hidden && document.activeElement.id === 'cd-pitb-step-results'", 10000, 'results');
		const r = await h.evaluate("({ verdict: document.querySelector('[data-pitb-verdict]').textContent, rows: [...document.querySelectorAll('[data-pitb-rows] tr')].slice(0, 3).map(tr => [...tr.children].map(td => td.textContent)), ui: document.querySelector('[data-pitb-results]').textContent })");
		assert.match(r.verdict, /^2 tests of 3 answered triggered\./);
		assert.deepEqual(r.rows.map(x => [x[3], x[4].split(' ')[0]]), [['Triggered', 'plain'], ['Triggered', 'base64'], ['Not triggered', '']]);
		assert.ok(!r.ui.includes(S.OPENAI_PROJECT_KEY) && /sk-p…/.test(r.ui));
		h.pass('check: plain and Base64 canaries found, refusal not triggered; secret in a response masked; focus on results');
		await h.click('[data-pitb-report="json"]');
		await h.sleep(300);
		const rep = await h.lastBlob();
		assert.ok(!rep.includes(S.OPENAI_PROJECT_KEY) && /does not mean the application is protected/.test(rep));
		h.pass('report download (JSON) without the secret and with the no-protection note');
		await h.evaluate("document.querySelectorAll('[data-pitb-response]').forEach(t => { t.value = ''; }); true");
		await h.setValue('[data-pitb-response="' + tests[0] + '"]', 'No code here.');
		await h.click('[data-pitb-check]');
		await h.waitFor("document.querySelector('[data-pitb-verdict]').textContent.startsWith('No canary')", 10000, 'no trigger');
		assert.equal(await h.evaluate("document.querySelector('[data-pitb-verdict]').textContent"), 'No canary appeared in the answered tests. This does not mean the application is protected.');
		h.pass('no trigger: the agreed sentence');

		h.phase = 'bulk';
		const lines = tests.slice(0, 5).map((id, k) => JSON.stringify({ id, response: k % 2 ? 'Код: ' + canaryOf(id).split('').join(' ') : 'Nein.' })).join('\n');
		await h.evaluate("document.querySelector('.cd-pitb-bulk').open = true; true");
		await h.setValue('[data-pitb-bulk]', lines);
		await h.click('[data-pitb-bulk-apply]');
		await h.waitFor("/Filled in 5 responses/.test(document.querySelector('[data-pitb-status]').textContent)", 5000, 'bulk');
		await h.click('[data-pitb-check]');
		await h.waitFor("/^2 tests of 5 answered/.test(document.querySelector('[data-pitb-verdict]').textContent)", 10000, 'bulk result');
		h.pass('bulk JSONL responses fill the form; split canaries (with spaces) are found');

		h.phase = 'translate';
		const n = await h.translateCheck('[data-pitb] textarea, [data-pitb] input[type=file], [data-pitb] pre, [data-pitb-set], [data-pitb-results], [data-pitb-error]');
		h.pass('inputs, test texts, responses, results and error box carry translate="no" and notranslate', n + ' elements');

		h.phase = 'reload-set';
		const before = await h.evaluate('window.__blobs.length');
		void before;
		await h.navigate();
		await h.evaluate(`(() => { const f = new File([${JSON.stringify(jsonl)}], 'set.jsonl', { type: 'application/json' }); const dt = new DataTransfer(); dt.items.add(f); const i = document.querySelector('[data-pitb-set-file]'); i.files = dt.files; i.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
		await h.waitFor("document.querySelectorAll('[data-pitb-tests] > li').length === 32", 10000, 'loaded set');
		await h.setValue('[data-pitb-response="' + tests[3] + '"]', 'https://example.com/x?c=' + canaryOf(tests[3]));
		await h.click('[data-pitb-check]');
		await h.waitFor("/^1 test of 1 answered/.test(document.querySelector('[data-pitb-verdict]').textContent)", 10000, 'loaded check');
		h.pass('a saved test set (JSONL) can be loaded later and checked with the same canaries');

		h.phase = 'large';
		await h.evaluate(`(() => { const big = ('Long answer without the code. Ёлка. ').repeat(5000).slice(0, 150000); document.querySelectorAll('[data-pitb-response]').forEach(t => { t.value = big; }); return true; })()`);
		await h.evaluate("window.__gap = 0; window.__last = performance.now(); window.__probe = setInterval(() => { const n = performance.now(); window.__gap = Math.max(window.__gap, n - window.__last); window.__last = n; }, 50); true");
		const t0 = Date.now();
		await h.click('[data-pitb-check]');
		await h.waitFor("!document.querySelector('[data-pitb-check]').disabled && /^No canary/.test(document.querySelector('[data-pitb-verdict]').textContent)", 60000, 'large');
		const gap = await h.evaluate('(() => { clearInterval(window.__probe); return Math.round(window.__gap); })()');
		assert.ok(gap < 1000);
		h.pass('32 responses of 150,000 characters (4.8 MB) checked in the worker; page responsive', ((Date.now() - t0) / 1000).toFixed(1) + ' s, longest gap ' + gap + ' ms');
		await h.evaluate("document.querySelector('[data-pitb-check]').click(); document.querySelector('[data-pitb-cancel]').click(); true");
		await h.sleep(300);
		assert.match(await h.evaluate("document.querySelector('[data-pitb-status]').textContent"), /^Cancelled|^Done/);
		await h.waitFor("document.querySelector('[data-pitb]').getAttribute('data-worker-state') === 'ready'", 10000, 'worker ready after cancel');
		h.pass('Cancel restarts the worker; the page returns to data-worker-state="ready"');

		h.phase = 'keyboard';
		await h.navigate();
		await h.evaluate("document.querySelector('[data-pitb-build]').focus(); true");
		await h.key('Enter');
		await h.waitFor("document.activeElement.id === 'cd-pitb-step-run'", 10000, 'keyboard build');
		const firstId = await h.evaluate("document.querySelector('[data-pitb-response]').getAttribute('data-pitb-response')");
		await h.evaluate("const t = document.querySelector('[data-pitb-response]'); t.value = 'no'; t.focus(); true");
		await h.key('Enter', 2);
		await h.waitFor("document.activeElement.id === 'cd-pitb-step-results'", 10000, 'Ctrl+Enter');
		const outline = await h.evaluate("(() => { document.querySelector('[data-pitb-check]').focus(); return getComputedStyle(document.activeElement).outlineStyle; })()");
		assert.ok(outline !== 'none');
		h.pass('keyboard: Enter builds, focus moves to the set; Ctrl+Enter in a response checks; focus visible', firstId);
		const low = await h.contrast(['[data-pitb] .cd-la-label', '[data-pitb] .cd-la-help', '[data-pitb] .cd-la-button--primary', '[data-pitb] .cd-la-button--secondary', '[data-pitb] .cd-pitb-id', '[data-pitb] .cd-pitb-muted', '[data-pitb] .cd-pitb-verdict strong', '[data-pitb] .cd-pitb-state', '[data-pitb] .cd-la-info li', '[data-pitb] .cd-la-callout--warning strong', '[data-pitb] td']);
		h.pass('text contrast at least 4.5:1', 'lowest ' + low + ':1');

		h.phase = 'reload';
		await h.viewport(360, 780, true);
		await h.navigate();
		await h.click('[data-pitb-build]');
		await h.waitFor("!document.querySelector('[data-pitb-set]').hidden", 10000, 'set 360');
		await h.mobileCheck();
		await h.shot('02-set-360');
		h.pass('360 px: no horizontal scrolling; controls at least 44 px; headings fit');
	}
});
