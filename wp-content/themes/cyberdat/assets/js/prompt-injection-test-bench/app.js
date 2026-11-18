/*!
 * CyberDat LLM Prompt Injection Test Bench — user interface.
 *
 * Contract (enforced by tests):
 *  - test texts, responses and results are written to the DOM only with textContent, never as HTML; no links;
 *  - no network, storage, cookie or URL-bar APIs; the tool never sends tests anywhere; downloads are created in the tab;
 *  - inputs, test texts, responses and results carry translate="no" and the notranslate class;
 *  - the page reports the worker state in data-worker-state (loading, ready, error) and in a status line;
 *  - no regular-expression look-behind here or in worker.js / engine.js.
 */
(function () {
	'use strict';

	const root = document.querySelector('[data-pitb]');
	if (!root) { return; }

	const MAX_RESPONSE = 200000;
	const MAX_TOTAL = 5 * 1024 * 1024;
	const JOB_TIMEOUT_MS = 60000;
	const NO_TRIGGER = 'No canary appeared in the answered tests. This does not mean the application is protected.';
	const $ = s => root.querySelector(s);
	const el = {
		app: $('[data-pitb-app]'), unsupported: $('[data-pitb-unsupported]'), workerStatus: $('[data-pitb-worker-status]'), appTypes: root.querySelectorAll('[data-pitb-app-type]'), langs: root.querySelectorAll('[data-pitb-lang]'),
		build: $('[data-pitb-build]'), setFile: $('[data-pitb-set-file]'), setPanel: $('[data-pitb-set]'), setHeading: $('#cd-pitb-step-run'), setSummary: $('[data-pitb-set-summary]'), label: $('[data-pitb-label]'),
		downloads: root.querySelectorAll('[data-pitb-download]'), tests: $('[data-pitb-tests]'), bulk: $('[data-pitb-bulk]'), bulkApply: $('[data-pitb-bulk-apply]'),
		check: $('[data-pitb-check]'), cancel: $('[data-pitb-cancel]'), progress: $('[data-pitb-progress]'), status: $('[data-pitb-status]'), error: $('[data-pitb-error]'),
		results: $('[data-pitb-results]'), heading: $('#cd-pitb-step-results'), verdict: $('[data-pitb-verdict]'), summary: $('[data-pitb-summary]'), rows: $('[data-pitb-rows]'), reports: root.querySelectorAll('[data-pitb-report]')
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

	const state = { worker: null, seq: 0, pending: new Map(), runJob: 0, running: false, timer: 0, set: null, files: null, report: null };
	const number = n => Number(n).toLocaleString('en-US');
	const plural = (n, w, many) => number(n) + ' ' + (n === 1 ? w : many || w + 's');
	const setStatus = m => { el.status.textContent = m; };
	const showError = m => { el.error.textContent = m; el.error.hidden = !m; };
	function node(tag, className, text) { const e = document.createElement(tag); if (className) { e.className = className; } if (text !== undefined && text !== null) { e.textContent = String(text); } return e; }
	function button(label, className, onClick) { const b = node('button', 'cd-la-button ' + (className || 'cd-la-button--secondary'), label); b.type = 'button'; b.addEventListener('click', onClick); return b; }

	// ---------------------------------------------------------------- worker
	function workerUrl() { const url = new URL(root.getAttribute('data-worker-src') || '', document.baseURI); if (url.origin !== window.location.origin) { throw new Error('Worker must be same-origin.'); } return url.href; }
	function createWorker() {
		if (state.worker) { state.worker.terminate(); }
		for (const p of state.pending.values()) { p.reject(Object.assign(new Error('cancelled'), { code: 'CANCELLED' })); }
		state.pending.clear();
		setWorkerState('loading', 'Starting the local test engine…');
		try { state.worker = new Worker(workerUrl()); } catch (e) { state.worker = null; setWorkerState('error', 'The local test engine could not start.'); el.unsupported.hidden = false; el.app.hidden = true; return; }
		state.worker.onmessage = ev => {
			const msg = ev.data || {};
			if (msg.type === 'ready') { setWorkerState('ready', 'Ready. The test engine runs locally in this tab.'); return; }
			const p = state.pending.get(msg.jobId);
			if (!p) { return; }
			if (msg.type === 'progress') { if (msg.jobId === state.runJob) { el.progress.value = msg.total ? Math.round(100 * msg.done / msg.total) : 100; } return; }
			state.pending.delete(msg.jobId);
			if (msg.type === 'error') { p.reject(Object.assign(new Error(msg.message), { code: msg.code })); } else { p.resolve(msg); }
		};
		state.worker.onerror = ev => { ev.preventDefault(); finish(); setWorkerState('error', 'The local test engine stopped. Reload the page.'); showError('The background worker stopped unexpectedly. Nothing was sent anywhere. Reload the page and try again.'); };
	}
	function request(msg) { if (!state.worker) { createWorker(); } const jobId = ++state.seq; return { jobId, promise: new Promise((resolve, reject) => { state.pending.set(jobId, { resolve, reject }); state.worker.postMessage(Object.assign({ jobId }, msg)); }) }; }
	function setRunning(r) { state.running = r; el.check.disabled = r; el.build.disabled = r; el.cancel.hidden = !r; el.progress.hidden = !r; el.app.setAttribute('aria-busy', r ? 'true' : 'false'); if (!r) { el.progress.value = 0; } }
	function finish() { window.clearTimeout(state.timer); setRunning(false); }
	function cancel(message) { if (!state.running) { return; } state.runJob = -1; finish(); createWorker(); if (message) { showError(message); } setStatus(message ? '' : 'Cancelled. Nothing was processed further.'); el.check.focus(); }

	// ---------------------------------------------------------------- build / load a set
	function showSet(res) {
		state.set = res.set;
		state.files = res.files;
		const s = res.set;
		el.setSummary.textContent = plural(s.tests.length, 'test') + ' in ' + plural(new Set(s.tests.map(t => t.category)).size, 'category', 'categories') + ', languages: ' + (s.langs.join(', ') || 'from file') + '. Library ' + (s.library || 'unknown') + '.';
		el.label.textContent = s.labelInstruction || 'This test set has no system-prompt label.';
		el.tests.replaceChildren(...s.tests.map(t => {
			const li = node('li', 'cd-pitb-test');
			const head = node('h3', 'cd-pitb-test__head');
			head.append(node('code', 'cd-pitb-id', t.id), ' ', node('span', '', t.categoryLabel), ' ', node('span', 'cd-pitb-muted', '· ' + t.lang.toUpperCase()));
			li.appendChild(head);
			li.appendChild(node('p', 'cd-pitb-muted', t.how + (t.ask ? ' Then ask: “' + t.ask + '”' : '')));
			const pre = node('pre', 'cd-la-preview cd-pitb-input notranslate', t.input);
			pre.setAttribute('translate', 'no');
			pre.tabIndex = 0;
			pre.setAttribute('aria-label', 'Test input ' + t.id);
			li.appendChild(pre);
			const copy = button('Copy test input', 'cd-la-button--ghost', () => {
				const done = () => setStatus('Copied the input of ' + t.id + ' to the clipboard.');
				if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(t.input).then(done, () => setStatus('Copying is not allowed here; select the text and copy it.')); } else { setStatus('Copying is not available; select the text and copy it.'); }
			});
			copy.setAttribute('aria-label', 'Copy the input of ' + t.id);
			li.appendChild(copy);
			const id = 'cd-pitb-resp-' + t.id;
			const label = node('label', 'cd-la-label', 'Response of your application to ' + t.id);
			label.htmlFor = id;
			const ta = node('textarea', 'cd-la-text cd-pitb-response notranslate');
			ta.id = id;
			ta.rows = 3;
			ta.maxLength = MAX_RESPONSE;
			for (const [k, v] of [['translate', 'no'], ['spellcheck', 'false'], ['autocomplete', 'off'], ['data-gramm', 'false'], ['data-lt-active', 'false'], ['data-pitb-response', t.id]]) { ta.setAttribute(k, v); }
			ta.addEventListener('input', () => { if (ta.value.length >= MAX_RESPONSE) { setStatus('The response of ' + t.id + ' reached the limit of 200,000 characters; the rest was cut.'); } });
			li.append(label, ta);
			return li;
		}));
		el.setPanel.hidden = false;
		el.results.hidden = true;
		setStatus(plural(s.tests.length, 'test') + ' ready. Run them in your application and paste the responses.');
		el.setHeading.focus();
	}
	function build() {
		showError('');
		const appTypes = [...el.appTypes].filter(x => x.checked).map(x => x.value);
		const langs = [...el.langs].filter(x => x.checked).map(x => x.value);
		if (!appTypes.length) { showError('Choose at least one application type.'); el.appTypes[0].focus(); return; }
		if (!langs.length) { showError('Choose at least one language.'); el.langs[0].focus(); return; }
		request({ type: 'build', appTypes, langs }).promise.then(showSet, err => showError(err.message));
	}
	function loadSetFile(file) {
		showError('');
		if (!file) { return; }
		if (file.size > MAX_TOTAL) { showError('The file is larger than 5 MB.'); el.setFile.value = ''; return; }
		file.text().then(text => request({ type: 'import-set', text }).promise.then(res => { showSet(res); setStatus('Loaded test set “' + file.name + '” with ' + plural(res.set.tests.length, 'test') + '.'); }, err => showError(err.message)), () => showError('The file could not be read.'));
	}
	function download(name, text, type) { const blob = new Blob([text], { type }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name; a.hidden = true; document.body.appendChild(a); a.click(); a.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 30000); }

	// ---------------------------------------------------------------- check
	function responses() { const out = {}; for (const ta of el.tests.querySelectorAll('[data-pitb-response]')) { if (ta.value.trim()) { out[ta.getAttribute('data-pitb-response')] = ta.value; } } return out; }
	function applyBulk() {
		showError('');
		if (el.bulk.value.length > MAX_TOTAL) { showError('The pasted responses are larger than 5 MB.'); return; }
		request({ type: 'parse-responses', text: el.bulk.value }).promise.then(res => {
			let n = 0;
			const unknown = [];
			for (const [id, text] of Object.entries(res.responses)) { const ta = el.tests.querySelector('[data-pitb-response="' + id.replace(/[^0-9A-Za-z_-]/gu, '') + '"]'); if (ta) { ta.value = text.slice(0, MAX_RESPONSE); n++; } else { unknown.push(id); } }
			setStatus('Filled in ' + plural(n, 'response') + '.' + (unknown.length ? ' Unknown test ids ignored: ' + unknown.slice(0, 10).join(', ') + (unknown.length > 10 ? '…' : '') + '.' : ''));
		}, err => showError(err.message));
	}
	function runCheck() {
		showError('');
		if (state.running || !state.set) { return; }
		const resp = responses();
		if (!Object.keys(resp).length) { showError('Paste at least one response first.'); const ta = el.tests.querySelector('[data-pitb-response]'); if (ta) { ta.focus(); } return; }
		const job = request({ type: 'check', set: state.set, responses: resp });
		state.runJob = job.jobId;
		setRunning(true);
		setStatus('Checking the responses locally…');
		state.timer = window.setTimeout(() => { if (state.running && state.runJob === job.jobId) { cancel('Processing took longer than 60 seconds and was stopped.'); } }, JOB_TIMEOUT_MS);
		job.promise.then(res => { if (job.jobId !== state.runJob) { return; } finish(); render(res); }, err => { if (err.code === 'CANCELLED' || job.jobId !== state.runJob) { return; } finish(); setStatus(''); showError(err.message); });
	}
	function render(res) {
		state.report = res.report;
		const c = res.counts;
		el.verdict.className = 'cd-pitb-verdict cd-pitb-verdict--' + (c.triggered ? 'hit' : 'none');
		if (c.triggered) { el.verdict.replaceChildren(node('strong', '', plural(c.triggered, 'test') + ' of ' + number(c.answered) + ' answered triggered.'), document.createTextNode(' The application followed injected instructions; review the categories below.')); }
		else { el.verdict.replaceChildren(node('strong', '', NO_TRIGGER)); }
		el.summary.textContent = 'Answered ' + number(c.answered) + ' of ' + plural(c.tests, 'test') + '; not triggered ' + number(c.notTriggered) + '; without response ' + number(c.noResponse) + '. By category: ' + Object.values(res.byCategory).map(x => x.label + ' ' + x.triggered + '/' + x.answered).join('; ') + '.';
		const labels = { triggered: 'Triggered', 'not-triggered': 'Not triggered', 'no-response': 'No response' };
		el.rows.replaceChildren(...res.rows.map(r => {
			const tr = node('tr', 'cd-pitb-row cd-pitb-row--' + r.status);
			const th = node('th', '', r.id);
			th.scope = 'row';
			const frag = r.fragment + (r.otherCanary ? ' (contains the canary of ' + r.otherCanary + ')' : '') + (r.secrets.length ? ' [secrets masked: ' + r.secrets.length + ']' : '');
			tr.append(th, node('td', '', r.categoryLabel), node('td', '', r.lang.toUpperCase()), node('td', 'cd-pitb-result', labels[r.status]), node('td', '', r.method + (r.link ? ' (link)' : '')), node('td', 'cd-pitb-frag', frag));
			return tr;
		}));
		el.results.hidden = false;
		setStatus('Done. ' + plural(c.triggered, 'test') + ' triggered.');
		el.heading.focus();
	}

	// ---------------------------------------------------------------- events
	el.build.addEventListener('click', build);
	el.setFile.addEventListener('change', () => loadSetFile(el.setFile.files && el.setFile.files[0]));
	for (const b of el.downloads) { b.addEventListener('click', () => { if (!state.files) { return; } const k = b.getAttribute('data-pitb-download'); download(k === 'csv' ? 'prompt-injection-tests.csv' : 'prompt-injection-tests.jsonl', k === 'csv' ? state.files.csv : state.files.jsonl, k === 'csv' ? 'text/csv' : 'application/x-ndjson'); setStatus('Test set downloaded. It contains the canary codes.'); }); }
	for (const b of el.reports) { b.addEventListener('click', () => { if (!state.report) { return; } const k = b.getAttribute('data-pitb-report'); download(k === 'json' ? 'prompt-injection-results.json' : 'prompt-injection-results.md', k === 'json' ? state.report.json : state.report.markdown, k === 'json' ? 'application/json' : 'text/markdown'); setStatus('Report downloaded. Secrets in fragments are masked.'); }); }
	el.bulk.addEventListener('input', () => { if (el.bulk.value.length > MAX_TOTAL) { setStatus('The pasted responses are larger than 5 MB and cannot be used.'); } });
	el.bulkApply.addEventListener('click', applyBulk);
	el.check.addEventListener('click', runCheck);
	el.cancel.addEventListener('click', () => cancel());
	root.addEventListener('keydown', e => { if (e.key === 'Escape' && state.running) { cancel(); } if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && e.target && e.target.hasAttribute && e.target.hasAttribute('data-pitb-response')) { e.preventDefault(); runCheck(); } });

	createWorker();
	el.app.hidden = false;
	el.app.setAttribute('aria-busy', 'false');
}());
