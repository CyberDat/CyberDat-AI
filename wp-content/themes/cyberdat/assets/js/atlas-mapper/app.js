/*!
 * CyberDat MITRE ATLAS Attack Vector Mapper — user interface.
 *
 * Contract (enforced by tests):
 *  - all text (pasted findings, notes, ATLAS data) is written to the DOM only with textContent, never as HTML; no links;
 *  - no network, storage, cookie or URL-bar APIs; everything stays in this tab until the user downloads a file;
 *  - inputs, notes and results carry translate="no" and the notranslate class;
 *  - pasted text is never shown back whole and never exported; secrets appear masked;
 *  - no regular-expression look-behind here or in worker.js / engine.js.
 */
(function () {
	'use strict';

	const root = document.querySelector('[data-atl]');
	if (!root) { return; }

	const MAX_CHARS = 100000;
	const JOB_TIMEOUT_MS = 60000;
	const NO_MATCH = 'No matching techniques found. This does not mean the system is not exposed.';
	const SAMPLE = 'During testing, the support assistant summarized a customer email that contained hidden instructions for the model. Afterwards the agent used its email tool to send the conversation to an external address. The agent configuration file also held a database password.';
	const $ = s => root.querySelector(s);
	const el = {
		app: $('[data-atl-app]'), unsupported: $('[data-atl-unsupported]'), modes: root.querySelectorAll('[data-atl-mode]'), panels: root.querySelectorAll('[data-atl-panel]'),
		props: root.querySelectorAll('[data-atl-property]'), text: $('[data-atl-text]'), sample: $('[data-atl-sample]'), clearText: $('[data-atl-clear-text]'),
		search: $('[data-atl-search]'), browse: $('[data-atl-browse]'), actions: $('[data-atl-actions]'), run: $('[data-atl-run]'), cancel: $('[data-atl-cancel]'),
		progress: $('[data-atl-progress]'), status: $('[data-atl-status]'), error: $('[data-atl-error]'), results: $('[data-atl-results]'), heading: $('#cd-atl-step-results'),
		verdict: $('[data-atl-verdict]'), summary: $('[data-atl-summary]'), notes: $('[data-atl-notes]'), groups: $('[data-atl-groups]'),
		selected: $('[data-atl-selected]'), selectionEmpty: $('[data-atl-selection-empty]'), exportBtns: root.querySelectorAll('[data-atl-export]'), clearSelection: $('[data-atl-clear-selection]')
	};

	let unicodeOk = false;
	try { unicodeOk = new RegExp('^\\p{L}\\p{M}$', 'u').test('é'); } catch (e) { unicodeOk = false; }
	if (!unicodeOk || typeof Worker !== 'function' || typeof Blob !== 'function' || !window.URL || typeof URL.createObjectURL !== 'function') {
		el.unsupported.textContent = 'Browser not supported: this tool needs Web Workers and Unicode regular expressions. Use a current version of Edge, Chrome, Firefox or Safari. Nothing was sent anywhere.';
		el.unsupported.hidden = false;
		return;
	}

	const state = { worker: null, seq: 0, pending: new Map(), runJob: 0, running: false, timer: 0, stale: false, result: null, selection: new Map(), searchTimer: 0 };
	const number = n => Number(n).toLocaleString('en-US');
	const plural = (n, w, many) => number(n) + ' ' + (n === 1 ? w : many || w + 's');
	const setStatus = m => { el.status.textContent = m; };
	const showError = m => { el.error.textContent = m; el.error.hidden = !m; };
	const mode = () => { const r = [...el.modes].find(x => x.checked); return r ? r.value : 'profile'; };
	function node(tag, className, text) {
		const e = document.createElement(tag);
		if (className) { e.className = className; }
		if (text !== undefined && text !== null) { e.textContent = String(text); }
		return e;
	}
	function button(label, className, onClick) { const b = node('button', 'cd-la-button ' + (className || 'cd-la-button--secondary'), label); b.type = 'button'; b.addEventListener('click', onClick); return b; }

	// ---------------------------------------------------------------- worker
	function workerUrl() {
		const url = new URL(root.getAttribute('data-worker-src') || '', document.baseURI);
		if (url.origin !== window.location.origin) { throw new Error('Worker must be same-origin.'); }
		return url.href;
	}
	function createWorker() {
		if (state.worker) { state.worker.terminate(); }
		for (const p of state.pending.values()) { p.reject(Object.assign(new Error('cancelled'), { code: 'CANCELLED' })); }
		state.pending.clear();
		try { state.worker = new Worker(workerUrl()); } catch (e) { state.worker = null; el.unsupported.hidden = false; el.app.hidden = true; return; }
		state.worker.onmessage = ev => {
			const msg = ev.data || {};
			const p = state.pending.get(msg.jobId);
			if (!p) { return; }
			if (msg.type === 'progress') { if (msg.jobId === state.runJob) { el.progress.value = msg.total ? Math.round(100 * msg.done / msg.total) : 100; } return; }
			state.pending.delete(msg.jobId);
			if (msg.type === 'error') { p.reject(Object.assign(new Error(msg.message), { code: msg.code })); } else { p.resolve(msg); }
		};
		state.worker.onerror = ev => { ev.preventDefault(); finish(); showError('The background worker stopped unexpectedly. Nothing was sent anywhere. Reload the page and try again.'); createWorker(); };
	}
	function request(msg) {
		if (!state.worker) { createWorker(); }
		const jobId = ++state.seq;
		return { jobId, promise: new Promise((resolve, reject) => { state.pending.set(jobId, { resolve, reject }); state.worker.postMessage(Object.assign({ jobId }, msg)); }) };
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

	// ---------------------------------------------------------------- run (profile, finding)
	function run() {
		showError('');
		if (state.running) { return; }
		const m = mode();
		let msg;
		if (m === 'profile') {
			const properties = [...el.props].filter(x => x.checked).map(x => x.value);
			if (!properties.length) { showError('Select at least one property of your system.'); el.props[0].focus(); return; }
			msg = { type: 'profile', properties };
		} else if (m === 'finding') {
			if (!el.text.value.trim()) { showError('Paste or type a description of the finding first.'); el.text.focus(); return; }
			if (el.text.value.length > MAX_CHARS) { showError('The text is longer than 100,000 characters.'); return; }
			msg = { type: 'finding', text: el.text.value };
		} else { return; }
		const job = request(msg);
		state.runJob = job.jobId;
		setRunning(true);
		setStatus('Matching locally…');
		state.timer = window.setTimeout(() => { if (state.running && state.runJob === job.jobId) { cancel('Processing took longer than ' + (JOB_TIMEOUT_MS / 1000) + ' seconds and was stopped.'); } }, JOB_TIMEOUT_MS);
		job.promise.then(res => { if (job.jobId !== state.runJob) { return; } finish(); render(res); }, err => { if (err.code === 'CANCELLED' || job.jobId !== state.runJob) { return; } finish(); setStatus(''); showError(err.message || 'The input could not be processed.'); });
	}
	function cancel(message) {
		if (!state.running) { return; }
		state.runJob = -1;
		finish();
		createWorker();
		if (message) { showError(message); }
		setStatus(message ? '' : 'Cancelled. Nothing was processed further.');
		el.run.focus();
	}

	// ---------------------------------------------------------------- rendering
	function paragraphs(text) {
		const wrap = node('div', 'cd-atl-desc');
		for (const part of String(text || '').split(/\n{2,}/u)) { if (part.trim()) { wrap.appendChild(node('p', '', part.trim())); } }
		return wrap;
	}
	function mitigationList(list, browse) {
		if (!list.length) { return node('p', 'cd-atl-muted', 'No mitigations are linked to this technique in ATLAS.'); }
		const ul = node('ul', 'cd-atl-mitigations');
		for (const m of list) {
			const li = node('li');
			if (browse) { li.appendChild(idButton(m.id, m.name)); } else { li.append(node('code', 'cd-atl-id', m.id), ' ', node('span', '', m.name)); }
			if (m.via) { li.append(' ', node('span', 'cd-atl-muted', '(linked to the parent technique ' + m.via + ')')); }
			if (m.how) { li.appendChild(node('span', 'cd-atl-how', m.how)); }
			ul.appendChild(li);
		}
		return ul;
	}
	function addButton(t, source) {
		const b = button('', 'cd-la-button--secondary cd-atl-add', () => {
			if (state.selection.has(t.id)) { removeSelected(t.id); } else { state.selection.set(t.id, { id: t.id, name: t.name, source, note: '' }); renderSelection(); }
			syncAddButtons();
		});
		b.setAttribute('data-atl-add', t.id);
		syncAddButton(b);
		return b;
	}
	function syncAddButton(b) {
		const id = b.getAttribute('data-atl-add');
		const on = state.selection.has(id);
		b.textContent = on ? 'Remove from selection' : 'Add to selection';
		b.setAttribute('aria-pressed', on ? 'true' : 'false');
		b.setAttribute('aria-label', (on ? 'Remove ' : 'Add ') + id + (on ? ' from selection' : ' to selection'));
	}
	function syncAddButtons() { for (const b of root.querySelectorAll('[data-atl-add]')) { syncAddButton(b); } }
	function techniqueCard(t, source) {
		const li = node('li', 'cd-atl-tech');
		const head = node('h4', 'cd-atl-tech__head');
		head.append(node('code', 'cd-atl-id', t.id), ' ', node('span', '', (t.parent ? t.parent.name + ': ' : '') + t.name));
		li.appendChild(head);
		const meta = [];
		if (t.parent) { meta.push('Sub-technique of ' + t.parent.id + ' ' + t.parent.name); }
		meta.push('Maturity (ATLAS): ' + (t.maturity || 'not stated'));
		li.appendChild(node('p', 'cd-atl-muted', meta.join(' · ')));
		if (t.reasons) {
			const why = node('div', 'cd-atl-why');
			why.appendChild(node('p', 'cd-atl-label', 'Why proposed — CyberDat mapping:'));
			const ul = node('ul');
			for (const r of t.reasons) { ul.appendChild(node('li', '', r.label + ': ' + r.reason)); }
			why.appendChild(ul);
			li.appendChild(why);
		}
		if (t.matched) {
			const why = node('p', 'cd-atl-why');
			why.append(node('span', 'cd-atl-label', 'Words in your text — CyberDat mapping ' + t.rule + ': '));
			t.matched.forEach((w, i) => { if (i) { why.append(', '); } why.append(node('mark', 'cd-atl-word', w)); });
			li.appendChild(why);
		}
		const d = node('details', 'cd-atl-details');
		d.appendChild(node('summary', '', 'Description and mitigations (MITRE ATLAS)'));
		d.appendChild(paragraphs(t.description));
		d.appendChild(node('p', 'cd-atl-label', 'Related mitigations (MITRE ATLAS):'));
		d.appendChild(mitigationList(t.mitigations));
		li.appendChild(d);
		li.appendChild(addButton(t, source));
		return li;
	}
	function render(res) {
		state.result = res;
		state.stale = false;
		const source = res.mode === 'profile' ? 'System profile (CyberDat mapping)' : 'Finding mapper (CyberDat mapping)';
		el.verdict.className = 'cd-atl-verdict' + (res.count ? '' : ' cd-atl-verdict--none');
		if (!res.count) { el.verdict.replaceChildren(node('strong', '', NO_MATCH)); }
		else { el.verdict.replaceChildren(node('strong', '', plural(res.count, 'candidate technique') + ' in ' + plural(res.groups.length, 'tactic') + '.'), document.createTextNode(' Review each one; they are candidates, not findings.')); }
		const took = res.elapsedMs < 1000 ? number(Math.max(1, res.elapsedMs)) + ' ms' : (res.elapsedMs / 1000).toFixed(1) + ' s';
		el.summary.textContent = (res.mode === 'profile' ? 'Properties: ' + res.properties.map(p => p.label).join('; ') + '.' : 'Checked ' + plural(res.chars, 'character') + ' with ' + plural(32, 'keyword rule') + '.') + ' Data: MITRE ATLAS ' + res.data.release + '. Took ' + took + '.';
		const notes = [];
		if (res.secrets && res.secrets.length) { notes.push('Values that look like secrets were found and masked; they were not used for matching: ' + res.secrets.map(s => s.kind + ' ' + s.shown).join('; ') + '.'); }
		el.notes.replaceChildren(...notes.map(n => node('li', '', n)));
		el.notes.hidden = !notes.length;
		const parts = [];
		for (const g of res.groups) {
			const sec = node('section', 'cd-atl-group');
			const h = node('h3', 'cd-atl-group__head');
			h.append(node('span', '', g.tactic.name), ' ', node('code', 'cd-atl-id', g.tactic.id));
			const ol = node('ol', 'cd-atl-techs');
			for (const t of g.techniques) { ol.appendChild(techniqueCard(t, source)); }
			sec.append(h, ol);
			parts.push(sec);
		}
		el.groups.replaceChildren(...parts);
		el.results.hidden = false;
		setStatus('Done. ' + (res.count ? plural(res.count, 'candidate technique') + '.' : NO_MATCH));
		el.heading.focus();
	}

	// ---------------------------------------------------------------- browse
	function idButton(id, name) {
		const b = button('', 'cd-la-button--ghost cd-atl-idbtn', () => openItem(id));
		b.append(node('code', 'cd-atl-id', id), ' ', node('span', '', name));
		return b;
	}
	function doSearch() {
		const job = request({ type: 'search', query: el.search.value.slice(0, 200) });
		job.promise.then(res => {
			const r = res.results;
			const wrap = node('div', 'cd-atl-search-results');
			const section = (title, list) => { if (!list.length) { return; } wrap.appendChild(node('h3', 'cd-atl-subhead', title + ' (' + list.length + ')')); const ul = node('ul', 'cd-atl-list'); for (const x of list) { const li = node('li'); li.appendChild(idButton(x.id, x.name + (x.parentName ? ' — sub-technique of ' + x.parent : ''))); ul.appendChild(li); } wrap.appendChild(ul); };
			section('Tactics', r.tactics);
			section('Techniques', r.techniques);
			section('Mitigations', r.mitigations);
			if (!r.tactics.length && !r.techniques.length && !r.mitigations.length) { wrap.appendChild(node('p', 'cd-atl-muted', 'No ATLAS entries match “' + r.query + '”.')); }
			el.browse.replaceChildren(wrap);
		}, () => {});
	}
	function openItem(id) {
		const job = request({ type: 'lookup', id });
		job.promise.then(res => {
			const f = res.found;
			if (!f) { return; }
			const it = f.item;
			const wrap = node('article', 'cd-atl-item');
			wrap.appendChild(button('Back to search results', 'cd-la-button--ghost', doSearch));
			const h = node('h3', 'cd-atl-item__head');
			h.tabIndex = -1;
			h.append(node('code', 'cd-atl-id', it.id), ' ', node('span', '', it.name));
			wrap.appendChild(h);
			wrap.appendChild(node('p', 'cd-atl-muted', { technique: 'Technique', mitigation: 'Mitigation', tactic: 'Tactic' }[f.kind] + ' · MITRE ATLAS data'));
			wrap.appendChild(paragraphs(it.description));
			const list = (title, items) => { wrap.appendChild(node('h4', 'cd-atl-subhead', title)); if (!items.length) { wrap.appendChild(node('p', 'cd-atl-muted', 'None.')); return; } const ul = node('ul', 'cd-atl-list'); for (const x of items) { const li = node('li'); li.appendChild(idButton(x.id, x.name)); ul.appendChild(li); } wrap.appendChild(ul); };
			if (f.kind === 'technique') {
				list('Tactics', it.tactics);
				if (it.parent) { list('Parent technique', [it.parent]); }
				list('Sub-techniques', it.subtechniques);
				wrap.appendChild(node('h4', 'cd-atl-subhead', 'Related mitigations'));
				wrap.appendChild(mitigationList(it.mitigations, true));
				wrap.appendChild(addButton(it, 'Browse'));
			} else if (f.kind === 'mitigation') {
				wrap.appendChild(node('p', 'cd-atl-muted', 'Categories: ' + (it.categories.join(', ') || 'not stated') + ' · Lifecycle: ' + (it.lifecyclePhases.join(', ') || 'not stated')));
				list('Techniques this mitigation is linked to', it.techniques);
			} else {
				list('Techniques', it.techniques.map(x => ({ id: x.id, name: x.name + (x.subtechniques ? ' (' + plural(x.subtechniques, 'sub-technique') + ')' : '') })));
			}
			el.browse.replaceChildren(wrap);
			h.focus();
		}, () => {});
	}

	// ---------------------------------------------------------------- selection and export
	function removeSelected(id) { state.selection.delete(id); renderSelection(); syncAddButtons(); }
	function renderSelection() {
		const items = [...state.selection.values()];
		el.selectionEmpty.hidden = items.length > 0;
		for (const b of el.exportBtns) { b.disabled = !items.length; }
		el.clearSelection.disabled = !items.length;
		el.selected.replaceChildren(...items.map((s, k) => {
			const li = node('li', 'cd-atl-sel');
			const head = node('p', 'cd-atl-sel__head');
			head.append(node('code', 'cd-atl-id', s.id), ' ', node('span', '', s.name), ' ', node('span', 'cd-atl-muted', '· ' + s.source));
			const id = 'cd-atl-note-' + k + '-' + s.id.replace(/[^0-9A-Za-z]/gu, '');
			const label = node('label', 'cd-la-label', 'Your note on ' + s.id);
			label.htmlFor = id;
			const ta = node('textarea', 'cd-la-text cd-atl-note notranslate');
			ta.id = id;
			ta.rows = 2;
			ta.maxLength = 4000;
			for (const [k2, v] of [['translate', 'no'], ['spellcheck', 'false'], ['autocomplete', 'off'], ['data-gramm', 'false'], ['data-lt-active', 'false']]) { ta.setAttribute(k2, v); }
			ta.value = s.note;
			ta.addEventListener('input', () => { s.note = ta.value; });
			const remove = button('Remove', 'cd-la-button--ghost', () => { removeSelected(s.id); (el.selected.querySelector('textarea') || $('#cd-atl-selection-title')).focus(); });
			remove.setAttribute('aria-label', 'Remove ' + s.id + ' from selection');
			li.append(head, label, ta, remove);
			return li;
		}));
	}
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
	function exportSelection(kind) {
		const selection = [...state.selection.values()].map(s => ({ id: s.id, note: s.note, source: s.source }));
		if (!selection.length) { return; }
		const job = request({ type: 'export', kind, selection, timestamp: new Date().toISOString() });
		job.promise.then(res => {
			if (kind === 'json') { download('atlas-selection.json', res.json, 'application/json'); } else { download('atlas-selection.md', res.markdown, 'text/markdown'); }
			setStatus('Downloaded ' + plural(res.count, 'technique') + ' as ' + (kind === 'json' ? 'JSON' : 'Markdown') + '. Secrets in notes are masked.');
		}, err => showError(err.message || 'The export failed.'));
	}

	// ---------------------------------------------------------------- events
	function markStale() { if (state.result && !state.stale) { state.stale = true; setStatus('Input changed. Run again to update the result.'); } }
	function syncMode() {
		const m = mode();
		for (const p of el.panels) { p.hidden = p.getAttribute('data-atl-panel') !== m; }
		el.actions.hidden = m === 'browse';
		el.run.textContent = m === 'finding' ? 'Map the finding' : 'Show techniques';
		if (m === 'browse') { if (state.running) { cancel(); } el.results.hidden = true; if (!el.browse.firstChild) { doSearch(); } }
		else if (state.result && state.result.mode !== m) { el.results.hidden = true; state.result = null; setStatus(''); }
		showError('');
	}
	for (const r of el.modes) { r.addEventListener('change', syncMode); }
	for (const p of el.props) { p.addEventListener('change', markStale); }
	el.text.addEventListener('input', markStale);
	el.sample.addEventListener('click', () => { el.text.value = SAMPLE; markStale(); el.text.focus(); setStatus('Example loaded: an invented incident description.'); });
	el.clearText.addEventListener('click', () => { el.text.value = ''; el.results.hidden = true; state.result = null; showError(''); setStatus('Cleared. The text and the results were removed from this page.'); el.text.focus(); });
	el.search.addEventListener('input', () => { window.clearTimeout(state.searchTimer); state.searchTimer = window.setTimeout(doSearch, 200); });
	el.search.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); window.clearTimeout(state.searchTimer); doSearch(); } });
	el.run.addEventListener('click', run);
	el.cancel.addEventListener('click', () => cancel());
	for (const b of el.exportBtns) { b.addEventListener('click', () => exportSelection(b.getAttribute('data-atl-export'))); }
	el.clearSelection.addEventListener('click', () => { state.selection.clear(); renderSelection(); syncAddButtons(); setStatus('Selection cleared.'); $('#cd-atl-selection-title').focus(); });
	root.addEventListener('keydown', e => {
		if (e.key === 'Escape' && state.running) { cancel(); }
		if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && e.target === el.text) { e.preventDefault(); run(); }
	});

	createWorker();
	syncMode();
	renderSelection();
	el.app.hidden = false;
	el.app.setAttribute('aria-busy', 'false');
}());
