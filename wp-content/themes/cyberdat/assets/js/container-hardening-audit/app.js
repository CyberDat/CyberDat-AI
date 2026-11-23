/*!
 * CyberDat Docker & Kubernetes Hardening Audit Generator — user interface.
 *
 * Contract (enforced by tests):
 *  - file contents, file names and findings are written to the DOM only with textContent, never as HTML; no links;
 *  - no network, storage, cookie or URL-bar APIs; opened files are read in the tab; downloads are created in the tab;
 *  - inputs, file names and findings carry translate="no" and the notranslate class;
 *  - the page reports the worker state in data-worker-state (loading, ready, error);
 *  - no regular-expression look-behind here or in worker.js / engine.js.
 */
(function () {
	'use strict';

	const root = document.querySelector('[data-cha]');
	if (!root) { return; }

	const MAX_CHARS = 1024 * 1024;
	const MAX_FILES = 20;
	const MAX_TOTAL_CHARS = 4 * 1024 * 1024; // engine limit for all files together
	const JOB_TIMEOUT_MS = 30000;
	const NO_FINDINGS = 'No findings from these checks. This does not mean the configuration is safe.';
	const $ = s => root.querySelector(s);
	const el = {
		app: $('[data-cha-app]'), unsupported: $('[data-cha-unsupported]'), workerStatus: $('[data-cha-worker-status]'), input: $('[data-cha-input]'), kind: $('[data-cha-kind]'),
		files: $('[data-cha-files]'), fileList: $('[data-cha-filelist]'), samples: root.querySelectorAll('[data-cha-sample]'), clear: $('[data-cha-clear]'),
		run: $('[data-cha-run]'), cancel: $('[data-cha-cancel]'), progress: $('[data-cha-progress]'), status: $('[data-cha-status]'), error: $('[data-cha-error]'), size: $('[data-cha-size]'),
		results: $('[data-cha-results]'), heading: $('#cd-cha-step-results'), verdict: $('[data-cha-verdict]'), summary: $('[data-cha-summary]'), out: $('[data-cha-files-out]'), reports: root.querySelectorAll('[data-cha-report]')
	};
	const setWorkerState = (s, text) => { root.setAttribute('data-worker-state', s); el.workerStatus.textContent = text; };
	let unicodeOk = false;
	try { unicodeOk = new RegExp('^\\p{L}\\p{M}$', 'u').test('é'); } catch (e) { unicodeOk = false; }
	if (!unicodeOk || typeof Worker !== 'function' || typeof Blob !== 'function' || !window.URL || typeof URL.createObjectURL !== 'function') {
		el.unsupported.textContent = 'Browser not supported: this tool needs Web Workers and Unicode regular expressions. Use a current version of Edge, Chrome, Firefox or Safari. Nothing was sent anywhere.';
		el.unsupported.hidden = false;
		root.setAttribute('data-worker-state', 'unsupported');
		return;
	}
	// ---------------------------------------------------------------- warning before large inputs (shared block)
	// The same block is in every tool that accepts files (a test checks that all copies are equal). Before a file or pasted
	// text larger than 10 MB is processed, or larger than 5 MB in Safari and other WebKit-based browsers (all browsers on
	// iPhone and iPad), the page shows its size, a rough processing time and that Cancel stops the work. The warning never
	// blocks or changes processing and never weakens the tool's own size limit. Plain DOM text only.
	const LARGE_MB = 1024 * 1024;
	const LARGE_UA = (window.navigator && window.navigator.userAgent) || '';
	const LARGE_WEBKIT = (/AppleWebKit\//.test(LARGE_UA) && !/(?:Chrome|Chromium|Edg|OPR|Android)\//.test(LARGE_UA)) || /iPhone|iPad|iPod/.test(LARGE_UA) || (/Macintosh/.test(LARGE_UA) && window.navigator.maxTouchPoints > 1);
	const LARGE_THRESHOLD = LARGE_WEBKIT ? 5 * LARGE_MB : 10 * LARGE_MB;
	/** [low, high] seconds; rate in MB/s: fast = the faster of Edge/Chrome and Firefox, fastSlow = the slower one, webkit. */
	function largeEstimate(bytes, rate) {
		const r = rate || { fast: 4, fastSlow: 2, webkit: 1 };
		const mb = Number(bytes) / LARGE_MB;
		const low = Math.max(1, Math.round(mb / (LARGE_WEBKIT ? r.webkit : r.fast)));
		const high = LARGE_WEBKIT ? low * 5 : Math.round((mb / (r.fastSlow || r.fast)) * 2);
		return [low, Math.max(low + 1, high)];
	}
	function largeMessage(bytes, rate) {
		const [low, high] = largeEstimate(bytes, rate);
		const min = s => Math.max(1, Math.round(s / 60));
		const time = high < 90 ? 'about ' + low + '–' + high + ' seconds' : low >= 90 ? 'about ' + min(low) + '–' + Math.max(min(low) + 1, min(high)) + ' minutes' : 'about ' + low + ' seconds to ' + min(high) + ' minutes';
		const size = Number(bytes) >= LARGE_MB ? (Number(bytes) / LARGE_MB).toFixed(1) + ' MB' : Math.max(1, Math.round(Number(bytes) / 1024)) + ' KB';
		return 'Large input: ' + size + '. Processing in this browser can take ' + time + ' (rough estimate from a desktop computer; slower computers and phones take longer).' +
			(LARGE_WEBKIT ? ' Safari and other WebKit-based browsers, including every browser on iPhone and iPad, are several times slower with large inputs and phones may run out of memory.' : '') +
			' Progress is shown while it runs, and Cancel stops the processing at any time.';
	}
	/** Shows or hides the warning right after anchor; returns true when it is shown. */
	function largeUpdate(anchor, bytes, rate) {
		if (!anchor || !anchor.parentNode) { return false; }
		let box = anchor.nextElementSibling;
		if (!box || !box.hasAttribute('data-large-input-warning')) {
			box = document.createElement('p');
			box.className = 'cd-large-input-warning';
			box.setAttribute('data-large-input-warning', '');
			box.setAttribute('role', 'status');
			box.hidden = true;
			anchor.parentNode.insertBefore(box, anchor.nextSibling);
		}
		const show = Number(bytes) > LARGE_THRESHOLD;
		box.textContent = show ? largeMessage(Number(bytes), rate) : '';
		box.hidden = !show;
		return show;
	}
	// ---------------------------------------------------------------- end of warning before large inputs (shared block)
	const LARGE_INPUT_RATE = null;
	function largeInput(bytes) { return largeUpdate(el.progress, bytes, LARGE_INPUT_RATE); }
	const state = { worker: null, jobId: 0, running: false, timer: 0, report: null, files: [] };
	const number = n => Number(n).toLocaleString('en-US');
	const plural = (n, w, many) => number(n) + ' ' + (n === 1 ? w : many || w + 's');
	const setStatus = m => { el.status.textContent = m; };
	const showError = m => { el.error.textContent = m; el.error.hidden = !m; };
	function node(tag, className, text) { const e = document.createElement(tag); if (className) { e.className = className; } if (text !== undefined && text !== null) { e.textContent = String(text); } return e; }

	function workerUrl() { const url = new URL(root.getAttribute('data-worker-src') || '', document.baseURI); if (url.origin !== window.location.origin) { throw new Error('Worker must be same-origin.'); } return url.href; }
	function createWorker() {
		if (state.worker) { state.worker.terminate(); }
		setWorkerState('loading', 'Starting the local checker…');
		try { state.worker = new Worker(workerUrl()); } catch (e) { state.worker = null; setWorkerState('error', 'The local checker could not start.'); el.unsupported.hidden = false; el.app.hidden = true; return; }
		state.worker.onmessage = ev => {
			const msg = ev.data || {};
			if (msg.type === 'ready') { setWorkerState('ready', 'Ready. Files are checked locally in this tab.'); return; }
			if (msg.jobId !== state.jobId) { return; }
			if (msg.type === 'progress') { el.progress.value = Math.round(100 * msg.done / msg.total); return; }
			finish();
			if (msg.type === 'error') { setStatus(''); showError(msg.message || 'The files could not be checked.'); return; }
			render(msg);
		};
		state.worker.onerror = ev => { ev.preventDefault(); finish(); setWorkerState('error', 'The local checker stopped. Reload the page.'); showError('The background worker stopped unexpectedly. Nothing was sent anywhere. Reload the page and try again.'); };
	}
	function setRunning(r) { state.running = r; el.run.disabled = r; el.cancel.hidden = !r; el.progress.hidden = !r; el.app.setAttribute('aria-busy', r ? 'true' : 'false'); if (!r) { el.progress.value = 0; } }
	function finish() { window.clearTimeout(state.timer); setRunning(false); }
	function cancel(message) { if (!state.running) { return; } state.jobId++; finish(); createWorker(); if (message) { showError(message); } setStatus(message ? '' : 'Cancelled. Nothing was checked further.'); el.run.focus(); }

	function inputs() {
		const list = [];
		if (el.input.value.trim()) { list.push({ name: 'pasted input', text: el.input.value, kind: el.kind.value }); }
		for (const f of state.files) { list.push({ name: f.name, text: f.text, kind: 'auto' }); }
		return list;
	}
	function run() {
		showError('');
		if (state.running) { return; }
		const list = inputs();
		if (!list.length) { showError('Paste a Dockerfile, Compose file or Kubernetes manifest, or open files first.'); el.input.focus(); return; }
		if (el.input.value.length > MAX_CHARS) { showError('The pasted text is larger than 1 MB.'); return; }
		if (list.length > MAX_FILES) { showError('At most ' + MAX_FILES + ' files can be checked at once.'); return; }
		if (!state.worker) { createWorker(); }
		const jobId = ++state.jobId;
		setRunning(true);
		largeInput(Math.min(list.reduce((a, x) => a + String(x.text || '').length, 0), MAX_TOTAL_CHARS));
		setStatus('Checking ' + plural(list.length, 'file') + ' locally…');
		state.timer = window.setTimeout(() => { if (state.running && state.jobId === jobId) { cancel('Processing took longer than 30 seconds and was stopped.'); } }, JOB_TIMEOUT_MS);
		state.worker.postMessage({ jobId, files: list });
	}
	function where(f) { return [f.line ? 'Line ' + number(f.line) : 'Whole file', f.document ? 'document ' + f.document : '', f.object, f.container && !f.object.endsWith(' ' + f.container) ? 'container ' + f.container : ''].filter(Boolean).join(' · '); }
	function findingItem(f) {
		const li = node('li', 'cd-cha-finding cd-cha-finding--' + f.severity);
		const head = node('p', 'cd-cha-finding__head');
		head.append(node('span', 'cd-cha-sev cd-cha-sev--' + f.severity, f.severity.toUpperCase()), ' ', node('strong', '', f.title), ' ', node('code', 'cd-cha-muted', f.id));
		li.appendChild(head);
		li.appendChild(node('p', 'cd-cha-muted', where(f)));
		if (f.evidence) { const p = node('p'); p.append(node('span', 'cd-cha-muted', 'Found: '), node('code', 'cd-cha-code', f.evidence)); li.appendChild(p); }
		li.appendChild(node('p', '', f.explanation));
		const fix = node('p');
		fix.append(node('span', 'cd-cha-label', 'Suggested change: '), document.createTextNode(f.fix));
		li.appendChild(fix);
		return li;
	}
	function render(msg) {
		const r = msg.result;
		state.report = msg.report;
		const c = r.counts;
		const total = c.high + c.medium + c.low + c.info;
		const failed = r.files.filter(x => x.error).length;
		el.verdict.className = 'cd-cha-verdict cd-cha-verdict--' + (c.high ? 'high' : c.medium ? 'medium' : 'ok');
		if (!total) { el.verdict.replaceChildren(node('strong', '', failed === r.files.length ? 'Nothing could be checked.' : NO_FINDINGS)); }
		else { el.verdict.replaceChildren(node('strong', '', plural(total - c.info, 'security finding') + ' and ' + plural(c.info, 'hygiene item') + ' to review.'), document.createTextNode(' Each item names the place and a suggested change; nothing was changed.')); }
		el.summary.textContent = 'Checked ' + plural(r.files.length, 'file') + ' (' + plural(msg.chars, 'character') + ') in ' + (msg.elapsedMs < 1000 ? number(Math.max(1, msg.elapsedMs)) + ' ms' : (msg.elapsedMs / 1000).toFixed(1) + ' s') + ': ' + c.high + ' high, ' + c.medium + ' medium, ' + c.low + ' low, ' + c.info + ' hygiene' + (failed ? '; ' + plural(failed, 'file') + ' not checked' : '') + '.';
		el.out.replaceChildren(...r.files.map(fr => {
			const sec = node('section', 'cd-cha-file-out');
			sec.appendChild(node('h3', 'cd-cha-file-title', fr.file + (fr.kindLabel ? ' (' + fr.kindLabel + ')' : '')));
			if (fr.error) { sec.appendChild(node('p', 'cd-cha-file-error', 'Not checked: ' + fr.error.message)); return sec; }
			const s = fr.findings.filter(f => f.group === 'security'), h = fr.findings.filter(f => f.group === 'hygiene');
			sec.appendChild(node('p', 'cd-cha-muted', plural(fr.documents, 'document') + ', ' + plural(fr.objects, fr.kind === 'dockerfile' ? 'stage' : fr.kind === 'compose' ? 'service' : 'object') + ' · ' + fr.counts.high + ' high, ' + fr.counts.medium + ' medium, ' + fr.counts.low + ' low, ' + fr.counts.info + ' hygiene'));
			if (!fr.findings.length) { sec.appendChild(node('p', '', NO_FINDINGS)); return sec; }
			if (s.length) { const ol = node('ol', 'cd-cha-findings'); ol.setAttribute('aria-label', 'Security findings in ' + fr.file); ol.replaceChildren(...s.slice(0, 500).map(findingItem)); sec.appendChild(ol); }
			if (h.length) {
				const d = node('details', 'cd-cha-hygiene');
				d.appendChild(node('summary', '', 'Hygiene (info): ' + plural(h.length, 'item')));
				const ol = node('ol', 'cd-cha-findings');
				ol.replaceChildren(...h.slice(0, 500).map(findingItem));
				d.appendChild(ol);
				sec.appendChild(d);
			}
			return sec;
		}));
		el.results.hidden = false;
		setStatus('Done. ' + plural(total, 'item') + ' in the checklist.');
		el.heading.focus();
	}
	function download(name, text, type) { const blob = new Blob([text], { type }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name; a.hidden = true; document.body.appendChild(a); a.click(); a.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 30000); }
	function showFiles() { el.fileList.replaceChildren(...state.files.map(f => node('li', '', f.name + ' — ' + plural(f.text.length, 'character')))); el.fileList.hidden = !state.files.length; }
	async function openFiles() {
		showError('');
		const chosen = [...(el.files.files || [])];
		if (!chosen.length) { return; }
		if (chosen.length > MAX_FILES) { showError('At most ' + MAX_FILES + ' files can be opened at once.'); el.files.value = ''; return; }
		const big = chosen.filter(f => f.size > MAX_CHARS * 4);
		if (big.length) { showError('Too large (over 1 MB): ' + big.map(f => f.name).join(', ') + '.'); el.files.value = ''; return; }
		const read = await Promise.all(chosen.map(f => f.text().then(text => ({ name: f.name, text }))));
		const tooLong = read.filter(f => f.text.length > MAX_CHARS);
		if (tooLong.length) { showError('Too large (over 1 MB): ' + tooLong.map(f => f.name).join(', ') + '.'); el.files.value = ''; return; }
		state.files = read;
		// the engine accepts at most 4 MB in total, below every warning threshold: larger sets are refused, not slow
		largeInput(Math.min(chosen.reduce((x, f) => x + f.size, 0), MAX_TOTAL_CHARS));
		el.files.value = '';
		showFiles();
		setStatus(plural(read.length, 'file') + ' opened in this tab. Nothing was uploaded.');
	}

	el.run.addEventListener('click', run);
	el.cancel.addEventListener('click', () => cancel());
	el.input.addEventListener('input', () => { el.size.textContent = el.input.value.length > MAX_CHARS * 0.9 ? 'The text is ' + number(el.input.value.length) + ' characters; the limit is 1,048,576.' : ''; });
	el.files.addEventListener('change', () => { openFiles().catch(() => showError('The files could not be read.')); });
	for (const b of el.samples) { b.addEventListener('click', () => { const k = b.getAttribute('data-cha-sample'); el.input.value = EX[k]; el.kind.value = 'auto'; setStatus('Example ' + (k === 'dockerfile' ? 'Dockerfile' : k === 'compose' ? 'Compose file' : 'Kubernetes manifests') + ' loaded (written by CyberDat, with deliberate problems).'); el.input.focus(); }); }
	el.clear.addEventListener('click', () => { if (state.running) { cancel(); } el.input.value = ''; state.files = []; showFiles(); el.results.hidden = true; el.out.replaceChildren(); state.report = null; showError(''); setStatus('Cleared. The text, opened files and results were removed from this page.'); el.input.focus(); });
	for (const b of el.reports) { b.addEventListener('click', () => { if (!state.report) { return; } const k = b.getAttribute('data-cha-report'); download(k === 'json' ? 'hardening-checklist.json' : 'hardening-checklist.md', k === 'json' ? state.report.json : state.report.markdown, k === 'json' ? 'application/json' : 'text/markdown'); setStatus('Checklist downloaded. Secrets are masked in it.'); }); }
	root.addEventListener('keydown', e => { if (e.key === 'Escape' && state.running) { cancel(); } if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && e.target === el.input) { e.preventDefault(); run(); } });

	// Examples are copies of the engine examples (checked by tests), kept here so they load without a worker round trip.
	const EX = {
		dockerfile: '# Example Dockerfile written by CyberDat (contains deliberate problems)\nFROM node:latest\nWORKDIR /app\nRUN apt-get update && apt-get install -y curl\nRUN curl -fsSL https://get.example.com/setup.sh | bash\nCOPY package.json server.js ./\nRUN npm ci --omit=dev\nENV NODE_ENV=production\nEXPOSE 3000\nCMD ["node", "server.js"]\n',
		compose: '# Example Compose file written by CyberDat (contains deliberate problems)\nservices:\n  web:\n    image: nginx:1.27.2\n    read_only: true\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    user: "101:101"\n    mem_limit: 256m\n    cpus: 0.5\n    ports:\n      - "127.0.0.1:8080:8080"\n    healthcheck:\n      test: ["CMD", "wget", "-q", "-O-", "http://localhost:8080/"]\n  agent:\n    image: monitoring.example.com/agent\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n    environment:\n      AGENT_PASSWORD: example-only-change-me\n',
		kubernetes: '# Example manifests written by CyberDat (contain deliberate problems)\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: shop\nspec:\n  replicas: 2\n  selector:\n    matchLabels:\n      app: shop\n  template:\n    metadata:\n      labels:\n        app: shop\n    spec:\n      containers:\n        - name: shop\n          image: registry.example.com/shop:2.3.1\n          ports:\n            - containerPort: 8080\n          resources:\n            limits:\n              memory: 256Mi\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: shop-admin\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n  - kind: ServiceAccount\n    name: default\n    namespace: shop\n'
	};

	createWorker();
	el.app.hidden = false;
	el.app.setAttribute('aria-busy', 'false');
}());
