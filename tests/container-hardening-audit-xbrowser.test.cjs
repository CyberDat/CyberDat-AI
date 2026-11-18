/*
 * Cross-browser acceptance (Firefox, WebKit) for the Docker & Kubernetes Hardening Audit Generator via Playwright.
 *   NODE_PATH=<pw>/node_modules node tests/container-hardening-audit-xbrowser.test.cjs [url] [evidence-dir] [browsers]
 */
'use strict';
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const { runX } = require('./lib/tool-xbrowser.cjs');

runX({
	name: 'cha', root: '[data-cha]', url: process.argv[2] || 'http://127.0.0.1:18091/tools/container-hardening-audit/', evidence: process.argv[3], browsers: (process.argv[4] || 'firefox,webkit').split(','),
	body: async h => {
		const { page, assert } = h;
		const run = async () => { await page.evaluate(() => document.activeElement && document.activeElement.blur()); await page.click('[data-cha-run]'); await h.until(() => !document.querySelector('[data-cha-run]').disabled && !document.querySelector('[data-cha-results]').hidden && document.activeElement.id === 'cd-cha-step-results', null, 30000); };
		const ids = () => page.evaluate(() => [...new Set([...document.querySelectorAll('[data-cha-files-out] .cd-cha-finding__head code')].map(c => c.textContent))].sort());
		await page.click('[data-cha-sample="compose"]');
		await run();
		assert.deepEqual(await ids(), ['DC-CAP-002', 'DC-ESC-001', 'DC-HYG-002', 'DC-PRIV-001', 'DC-RES-001', 'DC-RO-001', 'DC-SEC-001', 'DC-SOCK-001', 'DC-TAG-002', 'DC-USER-002']);
		h.pass('Compose example: 10 findings for the agent service');
		await page.fill('[data-cha-input]', '');
		await page.setInputFiles('[data-cha-files]', [
			{ name: 'Containerfile', mimeType: 'text/plain', buffer: Buffer.from('FROM node:22\nENV API_TOKEN=' + S.HF_TOKEN + '\nUSER node\nHEALTHCHECK NONE\n') },
			{ name: 'rbac.yaml', mimeType: 'text/plain', buffer: Buffer.from('apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: all\nrules:\n  - apiGroups: ["*"]\n    resources: ["*"]\n    verbs: ["*"]\n') }
		]);
		await h.until(() => !document.querySelector('[data-cha-filelist]').hidden);
		await run();
		assert.deepEqual(await ids(), ['DF-SEC-001', 'K8S-RBAC-001']);
		const ui = await page.$eval('[data-cha-results]', e => e.textContent);
		assert.ok(!ui.includes(S.HF_TOKEN));
		const rep = await h.download('[data-cha-report="markdown"]');
		assert.ok(!rep.text.includes(S.HF_TOKEN) && /not a complete audit/u.test(rep.text));
		h.pass('two opened files: secret in ENV masked in results and Markdown checklist; wildcard RBAC rule');
		const bad = await page.evaluate(() => [...document.querySelectorAll('[data-cha] textarea, [data-cha] input[type=file], [data-cha-filelist], [data-cha-results], [data-cha-error]')].filter(e => !(e.getAttribute('translate') === 'no' && e.classList.contains('notranslate'))).length);
		assert.equal(bad, 0);
		h.pass('translate="no" and notranslate on inputs, file names and results');
		await page.click('[data-cha-clear]');
		const big = Array.from({ length: 400 }, (_, i) => 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: p' + i + '\nspec:\n  containers:\n    - name: c\n      image: nginx:1.27\n      env:\n        - name: NAME\n          value: "Пётр ' + i + '"\n').join('---\n');
		await page.$eval('[data-cha-input]', (el, v) => { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); }, big);
		const t0 = Date.now();
		await run();
		h.pass('400 Kubernetes documents checked in the worker', ((Date.now() - t0) / 1000).toFixed(1) + ' s');
		await page.fill('[data-cha-input]', 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Values.name }}\n');
		await page.focus('[data-cha-input]');
		await page.keyboard.press('Control+Enter');
		await h.until(() => document.activeElement.id === 'cd-cha-step-results' && /Helm template/u.test(document.querySelector('.cd-cha-file-error') ? document.querySelector('.cd-cha-file-error').textContent : ''));
		h.pass('keyboard: Ctrl+Enter checks; a Helm template is refused with a clear message');
	},
	mobile: async h => { await h.page.click('[data-cha-sample="dockerfile"]'); await h.page.click('[data-cha-run]'); await h.until(() => !document.querySelector('[data-cha-results]').hidden); }
});
