/*
 * Browser acceptance for the Docker & Kubernetes Hardening Audit Generator (Chromium/Edge over the DevTools protocol, no deps).
 *   node tests/container-hardening-audit-browser.test.cjs [url] [evidence-dir]
 */
'use strict';
const { SYNTH: S } = require('./lib/synthetic-secrets.cjs');
const { runEdge } = require('./lib/tool-browser.cjs');

runEdge({
	name: 'cha', root: '[data-cha]', url: process.argv[2] || 'http://127.0.0.1:18091/tools/container-hardening-audit/', evidence: process.argv[3],
	body: async h => {
		const { assert } = h;
		const run = async () => { await h.evaluate("window.__done = false; new MutationObserver((m, o) => { if (!document.querySelector('[data-cha-run]').disabled && (document.activeElement.id === 'cd-cha-step-results' || !document.querySelector('[data-cha-error]').hidden)) { window.__done = true; o.disconnect(); } }).observe(document.querySelector('[data-cha]'), { subtree: true, attributes: true, childList: true, characterData: true }); document.activeElement.blur(); true"); await h.click('[data-cha-run]'); await h.waitFor('window.__done === true', 30000, 'result'); };
		const ids = () => h.evaluate("[...new Set([...document.querySelectorAll('[data-cha-files-out] .cd-cha-finding__head code')].map(c => c.textContent))].sort()");
		const openFiles = list => h.evaluate('(() => { const dt = new DataTransfer(); for (const [n, t] of ' + JSON.stringify(list) + ') { dt.items.add(new File([t], n, { type: "text/plain" })); } const i = document.querySelector("[data-cha-files]"); i.files = dt.files; i.dispatchEvent(new Event("change", { bubbles: true })); return true; })()');

		h.phase = 'kubernetes';
		await h.click('[data-cha-sample="kubernetes"]');
		await run();
		const k = await h.evaluate("({ verdict: document.querySelector('[data-cha-verdict]').textContent, hyg: document.querySelectorAll('.cd-cha-hygiene .cd-cha-finding').length, hygOpen: document.querySelector('.cd-cha-hygiene').open, where: document.querySelector('.cd-cha-finding .cd-cha-muted + p, .cd-cha-finding p.cd-cha-muted').textContent, links: document.querySelectorAll('[data-cha] a').length, focus: document.activeElement.id })");
		assert.deepEqual(await ids(), ['K8S-APPARMOR-001', 'K8S-CAP-002', 'K8S-ESC-001', 'K8S-PROBE-001', 'K8S-PROBE-002', 'K8S-RBAC-002', 'K8S-RES-001', 'K8S-RO-001', 'K8S-SA-001', 'K8S-SA-002', 'K8S-SECCOMP-001', 'K8S-USER-002']);
		assert.ok(/10 security findings and 2 hygiene items/u.test(k.verdict) && k.hyg === 2 && k.hygOpen === false && k.links === 0 && k.focus === 'cd-cha-step-results', JSON.stringify(k));
		assert.match(k.where, /^Line [0-9]+ · document 2 · ClusterRoleBinding shop-admin$/u);
		h.pass('Kubernetes example: 12 findings with line, document and object; hygiene grouped and collapsed; focus on results; no links', k.where);
		await h.shot('01-k8s-1440');

		h.phase = 'files';
		await h.setValue('[data-cha-input]', '');
		await openFiles([['Dockerfile', 'FROM python:3.12\nARG DEPLOY_KEY=' + S.GITHUB_PAT + '\nUSER 1000\nHEALTHCHECK NONE\n'], ['compose.yaml', 'services:\n  agent:\n    image: agent:1\n    privileged: true\n    environment:\n      NOTE: ' + S.OPAQUE_LONG + '\n'], ['chart.yaml', 'apiVersion: v1\nkind: Service\nmetadata:\n  name: {{ .Release.Name }}\n']]);
		await h.waitFor("!document.querySelector('[data-cha-filelist]').hidden", 5000, 'file list');
		await run();
		const f = await h.evaluate("({ titles: [...document.querySelectorAll('.cd-cha-file-title')].map(x => x.textContent), err: document.querySelector('.cd-cha-file-error').textContent, ui: document.querySelector('[data-cha-results]').textContent })");
		assert.deepEqual(f.titles, ['Dockerfile (Dockerfile)', 'compose.yaml (Docker Compose)', 'chart.yaml']);
		assert.match(f.err, /Helm template/u);
		assert.ok(!f.ui.includes(S.GITHUB_PAT) && !f.ui.includes(S.OPAQUE_LONG) && f.ui.includes('ghp_…'));
		await h.click('[data-cha-report="markdown"]');
		await h.sleep(300);
		const md = await h.lastBlob();
		await h.click('[data-cha-report="json"]');
		await h.sleep(300);
		const js = await h.lastBlob();
		assert.ok(!md.includes(S.GITHUB_PAT) && !js.includes(S.GITHUB_PAT) && !md.includes(S.OPAQUE_LONG) && /- \[ \] \*\*HIGH\*\* DC-PRIV-001/u.test(md) && /not a complete audit/u.test(md) && JSON.parse(js).files.length === 3);
		h.pass('three opened files checked together: Dockerfile, Compose and a Helm template refused with a message; secrets masked in results and in both checklists');

		h.phase = 'translate';
		const n = await h.translateCheck('[data-cha] textarea, [data-cha] input[type=file], [data-cha-filelist], [data-cha-results], [data-cha-error]');
		h.pass('pasted text, file input, file names, results and error box carry translate="no" and notranslate', n + ' elements');

		h.phase = 'large';
		await h.click('[data-cha-clear]');
		const big = Array.from({ length: 400 }, (_, i) => 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app' + i + '\nspec:\n  template:\n    spec:\n      containers:\n        - name: c' + i + '\n          image: nginx:1.27\n          env:\n            - name: GREETING\n              value: "Größe ' + i + '"\n').join('---\n');
		await h.setValue('[data-cha-input]', big);
		const t0 = Date.now();
		await run();
		assert.match(await h.evaluate("document.querySelector('[data-cha-summary]').textContent"), /Checked 1 file/u);
		assert.ok(await h.evaluate("document.querySelector('.cd-cha-file-out .cd-cha-muted').textContent.startsWith('400 documents, 400 objects')"));
		h.pass('400 Kubernetes documents (' + Math.round(big.length / 1024) + ' KB) checked in the worker', ((Date.now() - t0) / 1000).toFixed(1) + ' s');
		await h.setValue('[data-cha-input]', 'x'.repeat(1024 * 1024 + 5));
		await h.click('[data-cha-run]');
		assert.match(await h.evaluate("document.querySelector('[data-cha-error]').textContent"), /larger than 1 MB/u);
		h.pass('pasted text over 1 MB refused with a message');

		h.phase = 'keyboard';
		await h.navigate();
		await h.evaluate("document.querySelector('[data-cha-sample=\"dockerfile\"]').focus(); true");
		await h.key('Enter');
		await h.evaluate("document.querySelector('[data-cha-input]').focus(); true");
		await h.key('Enter', 2);
		await h.waitFor("document.activeElement.id === 'cd-cha-step-results'", 10000, 'Ctrl+Enter');
		assert.deepEqual(await ids(), ['DF-HYG-002', 'DF-HYG-003', 'DF-PIPE-001', 'DF-TAG-001', 'DF-USER-001']);
		const outline = await h.evaluate("(() => { document.querySelector('[data-cha-run]').focus(); return getComputedStyle(document.activeElement).outlineStyle; })()");
		assert.ok(outline !== 'none');
		h.pass('keyboard: Enter loads the Dockerfile example, Ctrl+Enter checks, focus moves to the results; focus visible');
		await h.evaluate("document.querySelector('.cd-cha-hygiene').open = true; true");
		const low = await h.contrast(['[data-cha] .cd-la-label', '[data-cha] .cd-la-help', '[data-cha] .cd-la-button--primary', '[data-cha] .cd-la-button--secondary', '[data-cha] .cd-cha-sev--high', '[data-cha] .cd-cha-sev--medium', '[data-cha] .cd-cha-sev--info', '[data-cha] .cd-cha-muted', '[data-cha] .cd-cha-verdict strong', '[data-cha] .cd-cha-state', '[data-cha] .cd-la-info li']);
		h.pass('text contrast at least 4.5:1', 'lowest ' + low + ':1');

		h.phase = 'reload';
		await h.viewport(360, 780, true);
		await h.navigate();
		await h.click('[data-cha-sample="compose"]');
		await run();
		assert.equal(await h.evaluate("document.querySelectorAll('.cd-cha-finding').length"), 10);
		await h.mobileCheck();
		await h.shot('02-compose-360');
		h.pass('360 px: Compose example, no horizontal scrolling; controls at least 44 px; headings fit');
	}
});
