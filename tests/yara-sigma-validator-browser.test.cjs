/*
 * Browser acceptance for the YARA/Sigma Rule Validator & Converter (Chromium/Edge over the DevTools protocol, no deps).
 *   node tests/yara-sigma-validator-browser.test.cjs [url] [evidence-dir]
 */
'use strict';
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const { runEdge } = require('./lib/tool-browser.cjs');

runEdge({
	name: 'ysv', root: '[data-ysv]', url: process.argv[2] || 'http://127.0.0.1:18091/tools/yara-sigma-validator/', evidence: process.argv[3],
	body: async h => {
		const { assert } = h;
		const run = async () => { await h.evaluate("window.__done = false; new MutationObserver((m, o) => { if (!document.querySelector('[data-ysv-run]').disabled && (!document.querySelector('[data-ysv-results]').hidden || !document.querySelector('[data-ysv-error]').hidden)) { window.__done = true; o.disconnect(); } }).observe(document.querySelector('[data-ysv]'), { subtree: true, attributes: true, childList: true, characterData: true }); true"); await h.click('[data-ysv-run]'); await h.waitFor('window.__done === true', 30000, 'result'); };
		const ids = () => h.evaluate("[...new Set([...document.querySelectorAll('[data-ysv-list] .cd-ysv-finding__head code')].map(c => c.textContent))].sort()");
		h.phase = 'sigma';
		await h.click('[data-ysv-sample-sigma]');
		await h.evaluate("document.querySelector('.cd-ysv-convert').open = true; document.querySelector('[data-ysv-target]').value = 'kql'; true");
		await h.click('[data-ysv-fieldmap-example]');
		await run();
		const a = await h.evaluate("({ verdict: document.querySelector('[data-ysv-verdict]').textContent, q: document.querySelector('[data-ysv-conv-out] pre').textContent, focus: document.activeElement.id, links: document.querySelectorAll('[data-ysv] a').length })");
		assert.equal(a.verdict, 'No problems found by these checks. This does not mean the rule is correct or effective.');
		assert.equal(a.q, 'FolderPath endswith @"\\net.exe" and InitiatingProcessFolderPath endswith @"\\cmd.exe" and not(AccountName contains "svc_")');
		assert.ok(a.focus === 'cd-ysv-step-results' && a.links === 0);
		h.pass('Sigma example: no findings; KQL with the example field mapping; focus on results; no links', a.q.slice(0, 60));
		await h.shot('01-sigma-1440');
		await h.setValue('[data-ysv-input]', "title: Broken rule\nlogsource:\n    product: windows\ndetection:\n    selection:\n        Image|endwith: '\\x.exe'\n    condition: selection and not filter\nlevel: severe\n");
		await run();
		assert.deepEqual(await ids(), ['SIG-COND-002', 'SIG-LVL-001', 'SIG-MOD-001', 'SIG-Q-001', 'SIG-Q-004', 'SIG-Q-006']);
		assert.match(await h.evaluate("document.querySelector('[data-ysv-conv-out]').textContent"), /Not converted: The modifier “endwith”|Not converted/);
		h.pass('broken Sigma rule: missing filter, invalid level, unknown modifier with lines; conversion refused with a message');

		h.phase = 'yara';
		await h.evaluate("document.querySelector('[data-ysv-target]').value = ''; true");
		await h.click('[data-ysv-sample-yara]');
		await run();
		assert.deepEqual(await ids(), []);
		await h.setValue('[data-ysv-input]', 'rule Bad\n{\n    strings:\n        $a = "ab"\n        $r = /.*token=.+/\n    condition:\n        $a and $b and pe.is_dll()\n}\n');
		await run();
		assert.deepEqual(await ids(), ['YAR-IMP-001', 'YAR-Q-001', 'YAR-Q-002', 'YAR-Q-003', 'YAR-STR-002', 'YAR-STR-003']);
		h.pass('YARA example: no findings; broken YARA rule: undeclared and unused strings, missing import, short string, slow regex, no file size limit');

		h.phase = 'secret';
		await h.setValue('[data-ysv-input]', "title: Secret in rule\nid: 1b2c3d4e-5f60-4718-8a9b-0c1d2e3f4a5b\nstatus: test\ndescription: d\nauthor: a\nlogsource:\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains: '" + S.GITHUB_PAT + "'\n    condition: selection\nfalsepositives:\n    - none\nlevel: low\n");
		await h.evaluate("document.querySelector('[data-ysv-target]').value = 'spl'; true");
		await run();
		const s = await h.evaluate("({ ui: document.querySelector('[data-ysv-results]').textContent, secretBox: !document.querySelector('[data-ysv-conv-secret]').hidden })");
		assert.ok(!s.ui.includes(S.GITHUB_PAT) && s.secretBox && /ghp_…/.test(s.ui));
		await h.click('[data-ysv-conv-ack]');
		assert.ok((await h.evaluate("document.querySelector('[data-ysv-conv-out] pre').textContent")).includes(S.GITHUB_PAT));
		await h.click('[data-ysv-report="json"]');
		await h.sleep(300);
		assert.ok(!(await h.lastBlob()).includes(S.GITHUB_PAT));
		h.pass('a secret in a rule is masked in findings and in the report; the converted query is shown only after confirmation');

		h.phase = 'translate';
		const n = await h.translateCheck('[data-ysv] textarea, [data-ysv] select, [data-ysv] pre, [data-ysv-results], [data-ysv-error]');
		h.pass('rule input, field mapping, target, queries, results and error box carry translate="no" and notranslate', n + ' elements');

		h.phase = 'large';
		const big = 'title: Many selections\nlogsource:\n    product: windows\ndetection:\n' + Array.from({ length: 6000 }, (_, i) => '    sel' + i + ":\n        Field" + i + "|contains: 'Größe" + i + "'\n").join('') + '    condition: 1 of sel*\nlevel: low\n';
		await h.setValue('[data-ysv-input]', big);
		await h.evaluate("document.querySelector('[data-ysv-target]').value = 'lucene'; true");
		const t0 = Date.now();
		await run();
		assert.match(await h.evaluate("document.querySelector('[data-ysv-summary]').textContent"), /Checked 1 Sigma rule/);
		assert.ok(await h.evaluate("document.querySelector('[data-ysv-conv-out] pre').textContent.includes('Field5999:*Größe5999*')"), 'large conversion output');
		h.pass('large rule with 6,000 search identifiers (' + Math.round(big.length / 1024) + ' KB) checked and converted in the worker', ((Date.now() - t0) / 1000).toFixed(1) + ' s');
		await h.setValue('[data-ysv-input]', 'x'.repeat(1024 * 1024 + 5));
		await h.click('[data-ysv-run]');
		assert.match(await h.evaluate("document.querySelector('[data-ysv-error]').textContent"), /larger than 1 MB/);
		h.pass('input over 1 MB refused with a message');

		h.phase = 'keyboard';
		await h.navigate();
		await h.evaluate("document.querySelector('[data-ysv-sample-yara]').focus(); true");
		await h.key('Enter');
		await h.evaluate("document.querySelector('[data-ysv-input]').focus(); true");
		await h.key('Enter', 2);
		await h.waitFor("document.activeElement.id === 'cd-ysv-step-results'", 10000, 'Ctrl+Enter');
		const outline = await h.evaluate("(() => { document.querySelector('[data-ysv-run]').focus(); return getComputedStyle(document.activeElement).outlineStyle; })()");
		assert.ok(outline !== 'none');
		h.pass('keyboard: Enter loads the example, Ctrl+Enter checks, focus moves to the results; focus visible');
		await h.setValue('[data-ysv-input]', 'rule X { strings: $a = "ab" condition: $a and $b }');
		await h.click('[data-ysv-run]');
		await h.waitFor("document.querySelectorAll('[data-ysv-list] li').length > 0", 10000, 'findings');
		const low = await h.contrast(['[data-ysv] .cd-la-label', '[data-ysv] .cd-la-help', '[data-ysv] .cd-la-button--primary', '[data-ysv] .cd-la-button--secondary', '[data-ysv] .cd-ysv-sev--error', '[data-ysv] .cd-ysv-sev--warning', '[data-ysv] .cd-ysv-sev--info', '[data-ysv] .cd-ysv-muted', '[data-ysv] .cd-ysv-verdict strong', '[data-ysv] .cd-ysv-state', '[data-ysv] .cd-la-info li']);
		h.pass('text contrast at least 4.5:1', 'lowest ' + low + ':1');

		h.phase = 'reload';
		await h.viewport(360, 780, true);
		await h.navigate();
		await h.click('[data-ysv-sample-sigma]');
		await h.evaluate("document.querySelector('.cd-ysv-convert').open = true; document.querySelector('[data-ysv-target]').value = 'spl'; true");
		await run();
		await h.mobileCheck();
		await h.shot('02-sigma-360');
		h.pass('360 px: no horizontal scrolling; controls at least 44 px; headings fit');
	}
});
