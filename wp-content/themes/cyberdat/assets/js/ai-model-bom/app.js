/*!
 * CyberDat AI Model Bill of Materials — user interface.
 *
 * Contract (enforced by tests):
 *  - entries and pasted BOMs are text: written to the DOM only with textContent, never as HTML, never executed;
 *    addresses from the input are never opened, requested or turned into links;
 *  - no network, storage, cookie or URL-bar APIs; everything stays in this tab until the user downloads a file;
 *  - every input, preview and result element has translate="no" and the notranslate class;
 *  - findings show secrets masked; exporting a document with detected secrets needs explicit confirmation;
 *  - no regular-expression look-behind here or in worker.js / engine.js.
 */
(function () {
	'use strict';

	const root = document.querySelector('[data-bom]');
	if (!root) { return; }

	const MAX_BYTES = 5 * 1024 * 1024;
	const INLINE_FILE_BYTES = 1024 * 1024;
	const JOB_TIMEOUT_MS = 120000;
	const MAX_RENDERED = 500;
	const MAX_ROWS = 200;
	const NO_GAPS = 'No known gaps matched. This does not mean the model or its supply chain is safe.';
	const SEV_LABEL = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
	const GROUPS = { license: 'Licenses', version: 'Versions', weights: 'Weights files', provenance: 'Base model', data: 'Data', dependencies: 'Dependencies', endpoints: 'Addresses', secrets: 'Secrets', documentation: 'Documentation', format: 'Format' };

	const $ = s => root.querySelector(s);
	const el = {
		app: $('[data-bom-app]'), unsupported: $('[data-bom-unsupported]'), modes: root.querySelectorAll('[data-bom-mode]'),
		buildPanel: $('[data-bom-build-panel]'), reviewPanel: $('[data-bom-review-panel]'), sample: $('[data-bom-sample]'), clear: $('[data-bom-clear]'),
		input: $('[data-bom-input]'), file: $('[data-bom-file]'), source: $('[data-bom-source]'), reviewSample: $('[data-bom-review-sample]'), reviewClear: $('[data-bom-review-clear]'),
		run: $('[data-bom-run]'), cancel: $('[data-bom-cancel]'), progress: $('[data-bom-progress]'), status: $('[data-bom-status]'), error: $('[data-bom-error]'),
		results: $('[data-bom-results]'), heading: $('#cd-bom-step-results'), resultsTitle: $('[data-bom-results-title]'), verdict: $('[data-bom-verdict]'), summary: $('[data-bom-summary]'),
		notes: $('[data-bom-notes]'), groupsWrap: $('[data-bom-groups-wrap]'), groups: $('[data-bom-groups]'), list: $('[data-bom-list]'), more: $('[data-bom-more]'),
		structureWrap: $('[data-bom-structure-wrap]'), structure: $('[data-bom-structure]'), inventoryWrap: $('[data-bom-inventory-wrap]'), inventory: $('[data-bom-inventory]'),
		edit: $('[data-bom-edit]'), report: $('[data-bom-report]'), exportWrap: $('[data-bom-export-wrap]'), secretWarning: $('[data-bom-secret-warning]'), secretText: $('[data-bom-secret-text]'),
		secretAck: $('[data-bom-secret-ack]'), downloadJson: $('[data-bom-download-json]'), downloadMd: $('[data-bom-download-md]'), previewJson: $('[data-bom-preview-json]'), previewMd: $('[data-bom-preview-md]')
	};

	let unicodeOk = false;
	try { unicodeOk = new RegExp('^\\p{L}\\p{M}$', 'u').test('é'); } catch (e) { unicodeOk = false; }
	if (!unicodeOk || typeof Worker !== 'function' || typeof Blob !== 'function' || !window.URL || typeof URL.createObjectURL !== 'function' || typeof String.prototype.normalize !== 'function') {
		el.unsupported.textContent = 'Browser not supported: this tool needs Web Workers and Unicode regular expressions. Use a current version of Edge, Chrome, Firefox or Safari. Nothing was sent anywhere.';
		el.unsupported.hidden = false;
		return;
	}

	const state = { source: { kind: 'text' }, worker: null, jobId: 0, running: false, timer: 0, result: null, stale: false, rowSeq: 0, pendingExample: '' };
	const number = n => Number(n).toLocaleString('en-US');
	const plural = (n, w, many) => number(n) + ' ' + (n === 1 ? w : many || w + 's');
	const formatBytes = b => (b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB' : (b / 1048576).toFixed(1) + ' MB');
	const setStatus = m => { el.status.textContent = m; };
	const showError = m => { el.error.textContent = m; el.error.hidden = !m; };
	const mode = () => { const r = [...el.modes].find(x => x.checked); return r ? r.value : 'build'; };
	function node(tag, className, text) {
		const e = document.createElement(tag);
		if (className) { e.className = className; }
		if (text !== undefined && text !== null) { e.textContent = String(text); }
		return e;
	}

	// ---------------------------------------------------------------- worker
	function workerUrl() {
		const url = new URL(root.getAttribute('data-worker-src') || '', document.baseURI);
		if (url.origin !== window.location.origin) { throw new Error('Worker must be same-origin.'); }
		return url.href;
	}
	function createWorker() {
		if (state.worker) { state.worker.terminate(); }
		try { state.worker = new Worker(workerUrl()); } catch (e) { state.worker = null; el.unsupported.hidden = false; el.app.hidden = true; return; }
		state.worker.onmessage = onMessage;
		state.worker.onerror = ev => { ev.preventDefault(); finish(); showError('The background worker stopped unexpectedly. Nothing was sent anywhere. Reload the page and try again.'); createWorker(); };
	}
	function setRunning(r) {
		state.running = r;
		el.run.disabled = r;
		el.cancel.hidden = !r;
		el.progress.hidden = !r;
		el.app.setAttribute('aria-busy', r ? 'true' : 'false');
		if (!r) { el.progress.value = 0; }
	}
	function finish() { window.clearTimeout(state.timer); setRunning(false); }

	// ---------------------------------------------------------------- form rows
	const rowsOf = key => root.querySelector('[data-bom-rows="' + key + '"]');
	function renumber(key) {
		const list = rowsOf(key);
		const label = list.getAttribute('data-bom-row-label');
		[...list.children].forEach((li, k) => {
			li.querySelector('[data-bom-row-title]').textContent = label + ' ' + (k + 1);
			li.querySelector('[data-bom-remove]').setAttribute('aria-label', 'Remove ' + label.toLowerCase() + ' ' + (k + 1));
		});
	}
	function addRow(key, values, focus) {
		const list = rowsOf(key);
		if (list.children.length >= MAX_ROWS) { showError('At most ' + MAX_ROWS + ' rows per section.'); return null; }
		const tpl = root.querySelector('template[data-bom-template="' + key + '"]');
		const li = tpl.content.firstElementChild.cloneNode(true);
		const seq = ++state.rowSeq;
		for (const ctl of li.querySelectorAll('[data-bom-col]')) {
			const id = 'cd-bom-' + key + '-' + seq + '-' + ctl.getAttribute('data-bom-col');
			ctl.id = id;
			ctl.previousElementSibling.setAttribute('for', id);
			const v = values ? values[ctl.getAttribute('data-bom-col')] : undefined;
			if (v !== undefined && v !== null) { setControl(ctl, String(v)); }
		}
		li.querySelector('[data-bom-remove]').addEventListener('click', () => { li.remove(); renumber(key); markStale(); root.querySelector('[data-bom-add="' + key + '"]').focus(); });
		list.appendChild(li);
		renumber(key);
		if (focus) { li.querySelector('[data-bom-col]').focus(); }
		return li;
	}
	function setControl(ctl, v) {
		if (ctl.tagName === 'SELECT' && ![...ctl.options].some(o => o.value === v)) {
			const o = document.createElement('option');
			o.value = v;
			o.textContent = v;
			ctl.appendChild(o);
		}
		ctl.value = v;
	}
	function readRows(key) { return [...rowsOf(key).children].map(li => { const o = {}; for (const ctl of li.querySelectorAll('[data-bom-col]')) { o[ctl.getAttribute('data-bom-col')] = ctl.value; } return o; }); }
	const fieldPath = (obj, pathStr, value) => { const parts = pathStr.split('.'); let cur = obj; for (let k = 0; k < parts.length - 1; k++) { cur[parts[k]] = cur[parts[k]] || {}; cur = cur[parts[k]]; } if (value === undefined) { return cur[parts[parts.length - 1]]; } cur[parts[parts.length - 1]] = value; return value; };
	function readForm() {
		const inv = { model: { baseModel: {} }, deployment: {}, evaluation: {}, owner: {} };
		for (const ctl of el.buildPanel.querySelectorAll('[data-bom-field]')) { fieldPath(inv, ctl.getAttribute('data-bom-field'), ctl.value); }
		inv.weights = readRows('weights');
		inv.datasets = readRows('datasets');
		inv.dependencies = readRows('dependencies');
		inv.deployment.apis = readRows('apis');
		inv.evaluation.metrics = readRows('metrics');
		return inv;
	}
	function fillForm(inv) {
		clearForm();
		for (const ctl of el.buildPanel.querySelectorAll('[data-bom-field]')) { const v = fieldPath(inv, ctl.getAttribute('data-bom-field')); setControl(ctl, v === undefined || v === null ? '' : String(v)); }
		for (const w of inv.weights || []) { addRow('weights', w); }
		for (const d of inv.datasets || []) { addRow('datasets', d); }
		for (const d of inv.dependencies || []) { addRow('dependencies', d); }
		for (const a of (inv.deployment && inv.deployment.apis) || []) { addRow('apis', a); }
		for (const m of (inv.evaluation && inv.evaluation.metrics) || []) { addRow('metrics', m); }
	}
	function clearForm() {
		for (const ctl of el.buildPanel.querySelectorAll('[data-bom-field]')) { ctl.value = ''; }
		for (const key of ['weights', 'datasets', 'dependencies', 'apis', 'metrics']) { rowsOf(key).replaceChildren(); }
	}

	// ---------------------------------------------------------------- run
	function loadFile(file) {
		showError('');
		if (!file) { return; }
		if (file.size > MAX_BYTES) { showError('“' + file.name + '” is ' + formatBytes(file.size) + '. The maximum is 5 MB.'); el.file.value = ''; return; }
		markStale();
		if (file.size <= INLINE_FILE_BYTES) {
			file.text().then(t => { el.input.value = t; state.source = { kind: 'text' }; el.source.textContent = 'Loaded “' + file.name + '” (' + formatBytes(file.size) + ').'; }, () => showError('The file could not be read.'));
			return;
		}
		state.source = { kind: 'file', file };
		el.input.value = '';
		el.source.textContent = 'Loaded “' + file.name + '” (' + formatBytes(file.size) + '). Large files are not displayed; they are checked in the background. Type in the box to switch back to pasted text.';
	}
	function run() {
		showError('');
		if (state.running) { return; }
		const m = mode();
		let msg;
		if (m === 'review') {
			if (state.source.kind !== 'file' && !el.input.value.trim()) { showError('Paste a CycloneDX JSON document or load a file first.'); el.input.focus(); return; }
			if (state.source.kind !== 'file' && el.input.value.length > MAX_BYTES) { showError('The pasted text is larger than 5 MB.'); return; }
			msg = { type: 'review', source: state.source.kind === 'file' ? { kind: 'file', file: state.source.file } : { kind: 'text', text: el.input.value } };
		} else {
			msg = { type: 'build', inventory: readForm(), timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') };
		}
		if (!state.worker) { createWorker(); }
		const jobId = ++state.jobId;
		msg.jobId = jobId;
		setRunning(true);
		setStatus(m === 'review' ? 'Checking the BOM locally…' : 'Checking and building locally…');
		state.timer = window.setTimeout(() => { if (state.jobId === jobId && state.running) { cancel('Processing took longer than ' + (JOB_TIMEOUT_MS / 1000) + ' seconds and was stopped.'); } }, JOB_TIMEOUT_MS);
		state.worker.postMessage(msg);
	}
	function cancel(message) {
		if (!state.running) { return; }
		state.jobId++;
		finish();
		createWorker();
		if (message) { showError(message); }
		setStatus(message ? '' : 'Cancelled. Nothing was processed further.');
		el.run.focus();
	}
	function onMessage(event) {
		const msg = event.data || {};
		if (msg.type === 'example') {
			if (state.pendingExample === 'build') { fillForm(msg.inventory); setStatus('Example loaded: an invented model with typical gaps. Select “Check and build”.'); el.buildPanel.querySelector('[data-bom-field]').focus(); }
			if (state.pendingExample === 'review') { el.input.value = msg.bomText; state.source = { kind: 'text' }; el.file.value = ''; el.source.textContent = 'Example loaded: the same invented model as a CycloneDX document.'; el.input.focus(); }
			state.pendingExample = '';
			markStale();
			return;
		}
		if (msg.jobId !== state.jobId) { return; }
		if (msg.type === 'progress') { el.progress.value = msg.total ? Math.round((msg.done / msg.total) * 100) : 100; return; }
		finish();
		if (msg.type === 'error') { setStatus(''); showError(msg.code === 'PARSE' ? 'The JSON could not be read: ' + msg.message : msg.message || 'The input could not be processed.'); return; }
		if (msg.type === 'result') { render(msg); }
	}

	// ---------------------------------------------------------------- rendering
	function findingItem(f) {
		const li = node('li', 'cd-bom-finding cd-bom-finding--' + f.severity);
		const head = node('p', 'cd-bom-finding__head');
		head.append(node('span', 'cd-bom-sev cd-bom-sev--' + f.severity, SEV_LABEL[f.severity]), ' ', node('strong', '', f.title), ' ', node('code', 'cd-bom-muted', f.rule));
		li.appendChild(head);
		li.appendChild(node('p', 'cd-bom-muted', (GROUPS[f.group] || f.group) + ' · ' + (f.location || '') + (f.line ? ' (line ' + number(f.line) + ')' : '')));
		if (f.evidence) { const p = node('p', 'cd-bom-evidence'); p.append(node('span', 'cd-bom-muted', 'Found: '), node('code', 'cd-bom-code', f.evidence)); li.appendChild(p); }
		li.appendChild(node('p', '', f.explanation));
		const fix = node('p', 'cd-bom-fix');
		fix.append(node('span', 'cd-bom-label', 'Suggested change: '), document.createTextNode(f.fix));
		li.appendChild(fix);
		return li;
	}
	function render(msg) {
		state.result = msg;
		state.stale = false;
		const verdicts = {
			high: ['Secrets or high-risk gaps found.', 'Remove secrets before you share this document.'],
			medium: ['Gaps worth fixing found.', 'Each one is listed with a suggested change.'],
			low: ['Only minor gaps found.', 'This does not mean the model or its supply chain is safe.'],
			info: ['Only notes.', 'This does not mean the model or its supply chain is safe.']
		};
		el.verdict.className = 'cd-bom-verdict cd-bom-verdict--' + msg.level;
		if (msg.level === 'none') { el.verdict.replaceChildren(node('strong', '', NO_GAPS)); }
		else { const [h, t] = verdicts[msg.level]; el.verdict.replaceChildren(node('strong', '', h), document.createTextNode(' ' + t)); }
		const s = msg.counts.bySeverity;
		const took = msg.elapsedMs < 1000 ? number(Math.max(1, msg.elapsedMs)) + ' ms' : (msg.elapsedMs / 1000).toFixed(1) + ' s';
		const what = msg.mode === 'review' ? 'Checked ' + plural(msg.counts.models, 'model component') + ', ' + plural(msg.counts.weights, 'weights file') + ', ' + plural(msg.counts.datasets, 'dataset') + ' and ' + plural(msg.counts.dependencies, 'dependency', 'dependencies') : 'Checked the form';
		el.summary.textContent = what + ' in ' + took + ': ' + plural(msg.counts.findings, 'finding') + ' (' + number(s.high) + ' high, ' + number(s.medium) + ' medium, ' + number(s.low) + ' low).';
		el.notes.replaceChildren(...(msg.notes || []).map(n => node('li', '', n)));
		el.notes.hidden = !(msg.notes && msg.notes.length);
		const groups = Object.entries(msg.counts.byGroup).sort((a, b) => b[1] - a[1]);
		el.groups.replaceChildren(...groups.map(([g, n]) => { const tr = node('tr'); const th = node('th', '', GROUPS[g] || g); th.scope = 'row'; tr.append(th, node('td', '', number(n))); return tr; }));
		el.groupsWrap.hidden = groups.length === 0;
		el.list.replaceChildren(...msg.findings.slice(0, MAX_RENDERED).map(findingItem));
		el.more.hidden = msg.findings.length <= MAX_RENDERED;
		el.more.textContent = msg.findings.length > MAX_RENDERED ? plural(msg.findings.length - MAX_RENDERED, 'more finding') + ' are not shown here; they are included in the downloads.' : '';
		el.resultsTitle.textContent = msg.mode === 'review' ? 'Review the gaps' : 'Review the gaps and export';
		// Review: structure and contents
		el.structureWrap.hidden = msg.mode !== 'review' || !msg.structure.length;
		el.structure.replaceChildren(...(msg.mode === 'review' ? msg.structure.slice(0, MAX_RENDERED) : []).map(p => node('li', '', p.location + (p.line ? ' (line ' + number(p.line) + ')' : '') + ': ' + p.message)));
		el.inventoryWrap.hidden = msg.mode !== 'review';
		if (msg.mode === 'review') {
			const v = msg.inventoryView;
			const rows = [
				['Model', v.model.name ? v.model.name + (v.model.version ? ' ' + v.model.version : '') : '(none)'],
				['Model components', (msg.modelNames || []).join(', ') || '(none)'],
				['Weights files', v.weights.map(w => w.file).join(', ') || '(none)'],
				['Datasets', v.datasets.map(d => d.name).join(', ') || '(none)'],
				['Dependencies', v.dependencies.map(d => d.name + (d.version ? ' ' + d.version : '')).join(', ') || '(none)'],
				['External APIs', v.deployment.apis.map(a => a.name || a.url).join(', ') || '(none)'],
				['Responsible', [v.owner.name, v.owner.organization, v.owner.contact].filter(Boolean).join(' · ') || '(none)']
			];
			el.inventory.replaceChildren(...rows.flatMap(([k, x]) => [node('dt', '', k), node('dd', '', x)]));
		}
		// Build: export
		el.exportWrap.hidden = msg.mode !== 'build';
		if (msg.mode === 'build') {
			el.secretAck.checked = false;
			el.secretWarning.hidden = !msg.secrets;
			el.secretText.textContent = msg.secrets ? plural(msg.secrets, 'value') + ' that look like secrets or credentials ' + (msg.secrets === 1 ? 'was' : 'were') + ' found (see the findings). The preview below shows them masked. Remove them from the form, or confirm to export anyway.' : '';
			syncExport();
		}
		el.results.hidden = false;
		setStatus('Done. ' + plural(msg.counts.findings, 'finding') + '.');
		el.heading.focus();
	}
	function syncExport() {
		const r = state.result;
		if (!r || r.mode !== 'build') { return; }
		const blocked = r.secrets > 0 && !el.secretAck.checked;
		el.downloadJson.disabled = blocked;
		el.downloadMd.disabled = blocked;
		el.previewJson.textContent = blocked ? r.bomTextMasked : r.bomText;
		el.previewMd.textContent = blocked ? r.markdownMasked : r.markdown;
	}
	function markStale() {
		if (state.result && !state.stale) { state.stale = true; setStatus('Input changed. Run the check again to update the result.'); }
	}

	// ---------------------------------------------------------------- downloads
	function download(name, text, type) {
		const blob = new Blob([text], { type });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = name;
		a.hidden = true;
		document.body.appendChild(a);
		a.click();
		a.remove();
		window.setTimeout(() => URL.revokeObjectURL(url), 30000);
	}
	function exportFile(kind) {
		const r = state.result;
		if (!r || r.mode !== 'build') { return; }
		if (r.secrets > 0 && !el.secretAck.checked) { showError('Confirm the export first: the document contains values that look like secrets.'); el.secretAck.focus(); return; }
		if (kind === 'json') { download('ai-bom.cdx.json', r.bomText, 'application/vnd.cyclonedx+json'); setStatus('CycloneDX JSON downloaded.'); }
		else { download('ai-bom.md', r.markdown, 'text/markdown'); setStatus('Markdown downloaded.'); }
	}
	function downloadReport() {
		const r = state.result;
		if (!r || r.mode !== 'review') { return; }
		const body = { tool: 'CyberDat AI Model Bill of Materials', engine: r.engine, ruleset: r.ruleset, mode: 'review', note: 'Findings only; the BOM itself is not included. Recognized secrets are masked. The tool does not verify entries and does not assess the model. No finding does not mean the model or its supply chain is safe.', specVersion: r.specVersion, level: r.level, counts: r.counts, findings: r.findings, structure: r.structure, notes: r.notes, generatedAt: new Date().toISOString() };
		download('ai-bom-review.json', JSON.stringify(body, null, 2) + '\n', 'application/json');
		setStatus('Findings downloaded. The file contains findings with secrets masked, not the BOM.');
	}

	// ---------------------------------------------------------------- events
	function clearResults() {
		state.result = null;
		for (const c of [el.list, el.groups, el.verdict, el.notes, el.structure, el.inventory]) { c.replaceChildren(); }
		el.summary.textContent = '';
		el.previewJson.textContent = '';
		el.previewMd.textContent = '';
		el.results.hidden = true;
	}
	function syncMode() {
		const m = mode();
		el.buildPanel.hidden = m !== 'build';
		el.reviewPanel.hidden = m !== 'review';
		el.run.textContent = m === 'review' ? 'Check the BOM' : 'Check and build';
		if (state.result && state.result.mode !== m) { clearResults(); setStatus(''); }
	}
	function requestExample(kind) {
		if (!state.worker) { createWorker(); }
		state.pendingExample = kind;
		state.worker.postMessage({ type: 'example' });
	}
	for (const b of root.querySelectorAll('[data-bom-add]')) { b.addEventListener('click', () => { addRow(b.getAttribute('data-bom-add'), null, true); markStale(); }); }
	for (const r of el.modes) { r.addEventListener('change', syncMode); }
	el.buildPanel.addEventListener('input', markStale);
	el.buildPanel.addEventListener('change', markStale);
	el.input.addEventListener('input', () => { if (state.source.kind === 'file') { state.source = { kind: 'text' }; el.source.textContent = ''; } markStale(); });
	el.file.addEventListener('change', () => loadFile(el.file.files && el.file.files[0]));
	el.sample.addEventListener('click', () => requestExample('build'));
	el.reviewSample.addEventListener('click', () => requestExample('review'));
	el.clear.addEventListener('click', () => { if (state.running) { cancel(); } clearForm(); clearResults(); showError(''); setStatus('Cleared. The form and the results were removed from this page.'); el.buildPanel.querySelector('[data-bom-field]').focus(); });
	el.reviewClear.addEventListener('click', () => { if (state.running) { cancel(); } el.input.value = ''; el.file.value = ''; state.source = { kind: 'text' }; el.source.textContent = ''; clearResults(); showError(''); setStatus('Cleared. The pasted BOM and the results were removed from this page.'); el.input.focus(); });
	el.run.addEventListener('click', run);
	el.cancel.addEventListener('click', () => cancel());
	el.secretAck.addEventListener('change', syncExport);
	el.downloadJson.addEventListener('click', () => exportFile('json'));
	el.downloadMd.addEventListener('click', () => exportFile('md'));
	el.report.addEventListener('click', downloadReport);
	el.edit.addEventListener('click', () => {
		const r = state.result;
		if (!r || r.mode !== 'review') { return; }
		const inv = r.inventory;
		const modeBuild = [...el.modes].find(x => x.value === 'build');
		modeBuild.checked = true;
		syncMode();
		fillForm(inv);
		clearResults();
		setStatus('The BOM was copied into the Build form. Check it and select “Check and build”.');
		el.buildPanel.querySelector('[data-bom-field]').focus();
	});
	root.addEventListener('keydown', e => {
		if (e.key === 'Escape' && state.running) { cancel(); }
		if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && (el.buildPanel.contains(e.target) || e.target === el.input)) { e.preventDefault(); run(); }
	});

	createWorker();
	syncMode();
	el.app.hidden = false;
	el.app.setAttribute('aria-busy', 'false');
}());
