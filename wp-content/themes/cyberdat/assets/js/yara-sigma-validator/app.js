/*!
 * CyberDat YARA/Sigma Rule Validator & Converter — user interface.
 *
 * Contract (enforced by tests):
 *  - rules, findings and queries are written to the DOM only with textContent, never as HTML; no links;
 *  - no network, storage, cookie or URL-bar APIs; downloads are created in the tab;
 *  - inputs, findings and converted queries carry translate="no" and the notranslate class;
 *  - queries that contain values looking like secrets are shown only after explicit confirmation;
 *  - the page reports the worker state in data-worker-state (loading, ready, error);
 *  - no regular-expression look-behind here or in worker.js / engine.js.
 */
(function () {
	'use strict';

	const root = document.querySelector('[data-ysv]');
	if (!root) { return; }

	const MAX_CHARS = 1024 * 1024;
	const JOB_TIMEOUT_MS = 30000;
	const NO_FINDINGS = 'No problems found by these checks. This does not mean the rule is correct or effective.';
	const $ = s => root.querySelector(s);
	const el = {
		app: $('[data-ysv-app]'), unsupported: $('[data-ysv-unsupported]'), workerStatus: $('[data-ysv-worker-status]'), input: $('[data-ysv-input]'), kinds: root.querySelectorAll('[data-ysv-kind]'),
		sampleSigma: $('[data-ysv-sample-sigma]'), sampleYara: $('[data-ysv-sample-yara]'), clear: $('[data-ysv-clear]'), target: $('[data-ysv-target]'), fieldmap: $('[data-ysv-fieldmap]'), fieldmapExample: $('[data-ysv-fieldmap-example]'),
		run: $('[data-ysv-run]'), cancel: $('[data-ysv-cancel]'), progress: $('[data-ysv-progress]'), status: $('[data-ysv-status]'), error: $('[data-ysv-error]'), size: $('[data-ysv-size]'),
		results: $('[data-ysv-results]'), heading: $('#cd-ysv-step-results'), verdict: $('[data-ysv-verdict]'), summary: $('[data-ysv-summary]'), notes: $('[data-ysv-notes]'), list: $('[data-ysv-list]'),
		convWrap: $('[data-ysv-conv]'), convTitle: $('[data-ysv-conv-title]'), convSecret: $('[data-ysv-conv-secret]'), convAck: $('[data-ysv-conv-ack]'), convOut: $('[data-ysv-conv-out]'), reports: root.querySelectorAll('[data-ysv-report]')
	};
	const setWorkerState = (s, text) => { root.setAttribute('data-worker-state', s); el.workerStatus.textContent = text; };
	let unicodeOk = false;
	try { unicodeOk = new RegExp('^\\p{L}\\p{M}$', 'u').test('e\u0301'); } catch (e) { unicodeOk = false; }
	if (!unicodeOk || typeof Worker !== 'function' || typeof Blob !== 'function' || !window.URL || typeof URL.createObjectURL !== 'function') {
		el.unsupported.textContent = 'Browser not supported: this tool needs Web Workers and Unicode regular expressions. Use a current version of Edge, Chrome, Firefox or Safari. Nothing was sent anywhere.';
		el.unsupported.hidden = false;
		root.setAttribute('data-worker-state', 'unsupported');
		return;
	}
	const state = { worker: null, jobId: 0, running: false, timer: 0, examples: null, report: null, conversion: null };
	const number = n => Number(n).toLocaleString('en-US');
	const plural = (n, w, many) => number(n) + ' ' + (n === 1 ? w : many || w + 's');
	const setStatus = m => { el.status.textContent = m; };
	const showError = m => { el.error.textContent = m; el.error.hidden = !m; };
	function node(tag, className, text) { const e = document.createElement(tag); if (className) { e.className = className; } if (text !== undefined && text !== null) { e.textContent = String(text); } return e; }
	const kind = () => { const r = [...el.kinds].find(x => x.checked); return r ? r.value : 'auto'; };

	function workerUrl() { const url = new URL(root.getAttribute('data-worker-src') || '', document.baseURI); if (url.origin !== window.location.origin) { throw new Error('Worker must be same-origin.'); } return url.href; }
	function createWorker() {
		if (state.worker) { state.worker.terminate(); }
		setWorkerState('loading', 'Starting the local rule checker…');
		try { state.worker = new Worker(workerUrl()); } catch (e) { state.worker = null; setWorkerState('error', 'The local rule checker could not start.'); el.unsupported.hidden = false; el.app.hidden = true; return; }
		state.worker.onmessage = ev => {
			const msg = ev.data || {};
			if (msg.type === 'ready') { setWorkerState('ready', 'Ready. Rules are checked locally in this tab.'); return; }
			if (msg.jobId !== state.jobId) { return; }
			if (msg.type === 'progress') { el.progress.value = Math.round(100 * msg.done / msg.total); return; }
			finish();
			if (msg.type === 'error') { setStatus(''); showError(msg.message || 'The rule could not be checked.'); return; }
			render(msg);
		};
		state.worker.onerror = ev => { ev.preventDefault(); finish(); setWorkerState('error', 'The local rule checker stopped. Reload the page.'); showError('The background worker stopped unexpectedly. Nothing was sent anywhere. Reload the page and try again.'); };
	}
	function setRunning(r) { state.running = r; el.run.disabled = r; el.cancel.hidden = !r; el.progress.hidden = !r; el.app.setAttribute('aria-busy', r ? 'true' : 'false'); if (!r) { el.progress.value = 0; } }
	function finish() { window.clearTimeout(state.timer); setRunning(false); }
	function cancel(message) { if (!state.running) { return; } state.jobId++; finish(); createWorker(); if (message) { showError(message); } setStatus(message ? '' : 'Cancelled. Nothing was checked further.'); el.run.focus(); }

	function run() {
		showError('');
		if (state.running) { return; }
		if (!el.input.value.trim()) { showError('Paste a Sigma or YARA rule first.'); el.input.focus(); return; }
		if (el.input.value.length > MAX_CHARS) { showError('The text is larger than 1 MB.'); return; }
		if (!state.worker) { createWorker(); }
		const jobId = ++state.jobId;
		setRunning(true);
		setStatus('Checking the rule locally…');
		state.timer = window.setTimeout(() => { if (state.running && state.jobId === jobId) { cancel('Processing took longer than 30 seconds and was stopped.'); } }, JOB_TIMEOUT_MS);
		state.worker.postMessage({ jobId, text: el.input.value, kind: kind(), target: el.target.value, fieldmap: el.fieldmap.value });
	}
	function render(msg) {
		const r = msg.result;
		state.report = msg.report;
		state.conversion = msg.conversion;
		const c = r.counts;
		el.verdict.className = 'cd-ysv-verdict cd-ysv-verdict--' + (c.error ? 'error' : c.warning ? 'warning' : 'ok');
		if (!r.findings.length) { el.verdict.replaceChildren(node('strong', '', NO_FINDINGS)); }
		else { el.verdict.replaceChildren(node('strong', '', c.error ? plural(c.error, 'error') + ' found.' : 'No errors; ' + plural(c.warning + c.info, 'note') + ' to review.'), document.createTextNode(' Each finding shows the line and a suggested change.')); }
		el.summary.textContent = 'Checked ' + plural(r.rules, r.kind === 'yara' ? 'YARA rule' : 'Sigma rule') + ' (' + plural(msg.chars, 'character') + ') in ' + (msg.elapsedMs < 1000 ? number(Math.max(1, msg.elapsedMs)) + ' ms' : (msg.elapsedMs / 1000).toFixed(1) + ' s') + ': ' + c.error + ' errors, ' + c.warning + ' warnings, ' + c.info + ' info.';
		el.notes.replaceChildren(...r.notes.map(x => node('li', '', x)));
		el.notes.hidden = !r.notes.length;
		el.list.replaceChildren(...r.findings.slice(0, 500).map(f => {
			const li = node('li', 'cd-ysv-finding cd-ysv-finding--' + f.severity);
			const head = node('p', 'cd-ysv-finding__head');
			head.append(node('span', 'cd-ysv-sev cd-ysv-sev--' + f.severity, f.severity.toUpperCase()), ' ', node('strong', '', f.title), ' ', node('code', 'cd-ysv-muted', f.id));
			li.appendChild(head);
			li.appendChild(node('p', 'cd-ysv-muted', (f.line ? 'Line ' + number(f.line) : 'Whole rule') + (f.rule ? ' · rule ' + f.rule : '')));
			if (f.evidence) { const p = node('p'); p.append(node('span', 'cd-ysv-muted', 'Found: '), node('code', 'cd-ysv-code', f.evidence)); li.appendChild(p); }
			li.appendChild(node('p', '', f.explanation));
			const fix = node('p');
			fix.append(node('span', 'cd-ysv-label', 'Suggested change: '), document.createTextNode(f.fix));
			li.appendChild(fix);
			return li;
		}));
		const conv = msg.conversion;
		el.convWrap.hidden = !conv;
		if (conv) {
			el.convTitle.textContent = 'Conversion to ' + conv.targetLabel;
			el.convAck.checked = false;
			el.convSecret.hidden = !conv.containsSecrets;
			showConversion();
		}
		el.results.hidden = false;
		setStatus('Done. ' + plural(r.findings.length, 'finding') + (conv ? '; conversion to ' + conv.targetLabel + ' included.' : '.'));
		el.heading.focus();
	}
	function showConversion() {
		const conv = state.conversion;
		if (!conv) { return; }
		const hide = conv.containsSecrets && !el.convAck.checked;
		el.convOut.replaceChildren(...conv.rules.map(r => {
			const div = node('div', 'cd-ysv-query');
			div.appendChild(node('h4', 'cd-ysv-query__title', r.title));
			if (r.error) { div.appendChild(node('p', 'cd-ysv-conv-error', 'Not converted: ' + r.error)); return div; }
			r.queries.forEach((q, i) => {
				const pre = node('pre', 'cd-la-preview cd-ysv-pre notranslate', hide ? 'Hidden: the query contains values that look like secrets. Confirm above to show it.' : q);
				pre.setAttribute('translate', 'no');
				pre.tabIndex = 0;
				pre.setAttribute('aria-label', 'Query ' + (i + 1) + ' for ' + r.title);
				div.appendChild(pre);
			});
			return div;
		}));
	}
	function download(name, text, type) { const blob = new Blob([text], { type }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name; a.hidden = true; document.body.appendChild(a); a.click(); a.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 30000); }

	el.run.addEventListener('click', run);
	el.cancel.addEventListener('click', () => cancel());
	el.input.addEventListener('input', () => { el.size.textContent = el.input.value.length > MAX_CHARS * 0.9 ? 'The text is ' + number(el.input.value.length) + ' characters; the limit is 1,048,576.' : ''; });
	el.sampleSigma.addEventListener('click', () => { el.input.value = EX.sigma; for (const r of el.kinds) { r.checked = r.value === 'auto'; } setStatus('Example Sigma rule loaded (written by CyberDat).'); el.input.focus(); });
	el.sampleYara.addEventListener('click', () => { el.input.value = EX.yara; for (const r of el.kinds) { r.checked = r.value === 'auto'; } setStatus('Example YARA rule loaded (written by CyberDat).'); el.input.focus(); });
	el.clear.addEventListener('click', () => { if (state.running) { cancel(); } el.input.value = ''; el.results.hidden = true; showError(''); setStatus('Cleared. The rule and the results were removed from this page.'); el.input.focus(); });
	el.fieldmapExample.addEventListener('click', () => { el.fieldmap.value = JSON.stringify(EX.fieldmap[el.target.value] || {}, null, 2); setStatus('Example field mapping for ' + el.target.options[el.target.selectedIndex].text + ' loaded.'); });
	el.convAck.addEventListener('change', showConversion);
	for (const b of el.reports) { b.addEventListener('click', () => { if (!state.report) { return; } const k = b.getAttribute('data-ysv-report'); download(k === 'json' ? 'rule-check.json' : 'rule-check.md', k === 'json' ? state.report.json : state.report.markdown, k === 'json' ? 'application/json' : 'text/markdown'); setStatus('Report downloaded. Secrets are masked in it.'); }); }
	root.addEventListener('keydown', e => { if (e.key === 'Escape' && state.running) { cancel(); } if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && e.target === el.input) { e.preventDefault(); run(); } });

	// Examples are copies of the engine examples (checked by tests), kept here so they load without a worker round trip.
	const EX = {
		sigma: "title: Net.exe started from a command shell\nid: 5b0f3c2e-8a71-4d6e-9f12-3c4b5a6d7e8f\nstatus: test\ndescription: Detects net.exe started by cmd.exe (example rule written by CyberDat).\nauthor: CyberDat\ndate: 2026-11-18\ntags:\n    - attack.discovery\n    - attack.t1033\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\net.exe'\n        ParentImage|endswith: '\\cmd.exe'\n    filter_admin:\n        User|contains: 'svc_'\n    condition: selection and not filter_admin\nfalsepositives:\n    - Administrators checking their own account\nlevel: low\n",
		yara: 'import "pe"\n\nrule Example_Loader_Marker\n{\n    meta:\n        author = "CyberDat"\n        description = "Example rule written by CyberDat"\n    strings:\n        $marker = "ExampleLoaderMarker" wide ascii\n        $mz = { 4D 5A 90 00 }\n        $cfg = /cfg_[0-9]{2}\\.example/\n    condition:\n        $mz at 0 and filesize < 5MB and pe.number_of_sections > 2 and ($marker or $cfg)\n}\n',
		fieldmap: { spl: { Image: 'process_path', ParentImage: 'parent_process_path', User: 'user' }, kql: { Image: 'FolderPath', ParentImage: 'InitiatingProcessFolderPath', User: 'AccountName' }, lucene: { Image: 'process.executable', ParentImage: 'process.parent.executable', User: 'user.name' } }
	};

	createWorker();
	el.app.hidden = false;
	el.app.setAttribute('aria-busy', 'false');
}());
