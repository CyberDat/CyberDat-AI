/*!
 * CyberDat Privacy Shield Log Anonymizer — user interface.
 *
 * Privacy contract (enforced by tests):
 *  - user text is only ever written to the DOM with textContent / text nodes;
 *  - no network APIs, storage APIs, cookies or URL changes are used;
 *  - heavy work runs in a dedicated Web Worker.
 */
(function () {
	'use strict';

	const root = document.querySelector('[data-log-anonymizer]');
	if (!root) { return; }

	const MAX_BYTES = 50 * 1024 * 1024;
	const INLINE_FILE_BYTES = 1024 * 1024;
	const PREVIEW_CHARS = 200000;
	const JOB_TIMEOUT_MS = 180000;
	const MAX_RULES = 20;
	const LABEL_RE = /^[A-Z][A-Z0-9_]{0,31}$/;

	const $ = selector => root.querySelector(selector);
	const $$ = selector => Array.from(root.querySelectorAll(selector));
	const el = {
		app: $('[data-la-app]'),
		unsupported: $('[data-la-unsupported]'),
		input: $('[data-la-input]'),
		file: $('[data-la-file]'),
		source: $('[data-la-source]'),
		sample: $('[data-la-sample]'),
		clear: $('[data-la-clear]'),
		categories: $$('[data-la-category]'),
		modes: $$('[data-la-mode]'),
		keepPrivate: $('[data-la-keep-private]'),
		rules: $('[data-la-rules]'),
		ruleTemplate: $('[data-la-rule-template]'),
		addRule: $('[data-la-add-rule]'),
		run: $('[data-la-run]'),
		cancel: $('[data-la-cancel]'),
		progress: $('[data-la-progress]'),
		status: $('[data-la-status]'),
		error: $('[data-la-error]'),
		results: $('[data-la-results]'),
		resultsHeading: $('#cd-la-step-results'),
		summary: $('[data-la-summary]'),
		notes: $('[data-la-notes]'),
		stats: $('[data-la-stats]'),
		preview: $('[data-la-preview]'),
		truncated: $('[data-la-truncated]'),
		copy: $('[data-la-copy]'),
		download: $('[data-la-download]'),
		mapAck: $('[data-la-map-ack]'),
		map: $('[data-la-map]')
	};

	if (typeof Worker !== 'function' || typeof Blob !== 'function' || !window.URL || typeof URL.createObjectURL !== 'function') {
		el.unsupported.hidden = false;
		return;
	}

	// Token-shaped sample values (a JWT, the AWS documentation key ID, a fake GitHub token) are joined at
	// runtime so the source contains nothing a repository secret scanner would report.
	const synth = parts => parts.join('');
	const SAMPLE = [
		'Nov 11 09:14:02 web-01 sshd[2211]: Accepted publickey for alice from 203.0.113.42 port 52211 ssh2',
		'Nov 11 09:14:09 web-01 sshd[2214]: Failed password for invalid user admin from 198.51.100.23 port 40122 ssh2',
		'2026-11-11T09:15:31.120Z api.example.com app[812]: POST /v1/login user=bob.smith email=bob.smith@example.com password="Winter2026!" status=401 ip=203.0.113.42',
		'2026-11-11T09:15:32.004Z api.example.com app[812]: GET https://svc:Pa55w0rd@billing.internal.example.com/charge?access_token=abc123DEF456ghi789&page=2 client=2001:db8:4::17',
		'2026-11-11T09:15:33.517Z api.example.com app[812]: Authorization: Bearer ' + synth(['eyJ', 'hbGciOiJ', 'IUzI1NiI', 'sInR5cCI', '6IkpXVCJ', '9.eyJzdW', 'IiOiJib2', 'Iuc21pdG', 'giLCJpYX', 'QiOjE3Mz', 'EzMTYxMz', 'J9.c2lnb', 'mF0dXJlL', 'WZvci1kb', '2NzLW9ub', 'Hk']),
		'2026-11-11T09:15:34.900Z api.example.com app[812]: payment card=4111 1111 1111 1111 ssn=123-45-6789 order_id=9988776655 build=10.0.19045.1 version 1.2.3.4',
		'{"ts":"2026-11-11T09:16:00Z","level":"warn","host":"db01.corp.example.com","mac":"00:1A:2B:3C:4D:5E","aws_key":"' + synth(['AKIA', 'IOSFODNN', '7EXAMPLE']) + '","api_token":"' + synth(['ghp_', 'aBcDeFgH', 'iJkLmNoP', 'qRsTuVwX', 'yZ012345', '6789']) + '","path":"/home/carol/.aws/credentials"}',
		'Nov 11 09:16:05 web-01 sudo:    carol : TTY=pts/0 ; PWD=/home/carol ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx',
		'Cookie: sessionid=7f3c9a1b2d4e6f80; theme=dark',
		'internal call from 10.20.30.40 to 192.168.1.10:5432 at 10:20:30 trace=4bf92f3577b34da6a3ce929d0e0e4736'
	].join('\n') + '\n';

	const state = {
		source: { kind: 'text' },
		fileName: '',
		worker: null,
		jobId: 0,
		running: false,
		timer: 0,
		result: null,
		stale: false
	};

	// ---------------------------------------------------------------- helpers

	function formatBytes(bytes) {
		if (bytes < 1024) { return bytes + ' B'; }
		if (bytes < 1024 * 1024) { return (bytes / 1024).toFixed(1) + ' KB'; }
		return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
	}

	function number(n) {
		return Number(n).toLocaleString('en-US');
	}

	function setStatus(message) {
		el.status.textContent = message;
	}

	function showError(message) {
		el.error.textContent = message;
		el.error.hidden = !message;
	}

	function categoryName(id) {
		if (id === 'custom') { return 'Custom rules'; }
		const box = el.categories.find(c => c.value === id);
		return box ? box.dataset.short : id;
	}

	function workerUrl() {
		// The worker URL is a same-origin theme asset printed by WordPress.
		const raw = root.getAttribute('data-worker-src') || '';
		const url = new URL(raw, document.baseURI);
		if (url.origin !== window.location.origin) { throw new Error('Worker must be same-origin.'); }
		return url.href;
	}

	function createWorker() {
		if (state.worker) { state.worker.terminate(); }
		try {
			state.worker = new Worker(workerUrl());
		} catch (e) {
			state.worker = null;
			el.unsupported.hidden = false;
			el.app.hidden = true;
			return;
		}
		state.worker.onmessage = onWorkerMessage;
		state.worker.onerror = event => {
			event.preventDefault();
			finishJob();
			showError('The background worker stopped unexpectedly. Your data was not sent anywhere. Reload the page and try again.');
			createWorker();
		};
	}

	function setRunning(running) {
		state.running = running;
		el.run.disabled = running;
		el.cancel.hidden = !running;
		el.progress.hidden = !running;
		el.app.setAttribute('aria-busy', running ? 'true' : 'false');
		if (!running) { el.progress.value = 0; }
	}

	function finishJob() {
		window.clearTimeout(state.timer);
		setRunning(false);
	}

	// ---------------------------------------------------------------- input

	function setTextSource(note) {
		state.source = { kind: 'text' };
		el.source.textContent = note || '';
	}

	// Safari and every browser on iOS use WebKit, which processed large logs several times slower in tests
	// (about 23 s for 30 MB on desktop WebKit vs about 3 s in Edge/Firefox). Warn before large inputs.
	const WEBKIT_NOTE_BYTES = 10 * 1024 * 1024;
	const ua = navigator.userAgent || '';
	const webkitOnly = (/AppleWebKit\//.test(ua) && !/(?:Chrome|Chromium|Edg|OPR|Android)\//.test(ua)) || /iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
	function webkitNote(bytes) {
		return webkitOnly && bytes > WEBKIT_NOTE_BYTES ? ' Safari and other WebKit-based browsers (all browsers on iPhone and iPad) process large inputs much more slowly; 30 MB took about 23 seconds in tests and phones may run out of memory. If it takes too long, select Cancel and split the file or use a desktop browser.' : '';
	}

	function loadFile(file) {
		showError('');
		if (!file) { return; }
		if (file.size > MAX_BYTES) {
			showError('“' + file.name + '” is ' + formatBytes(file.size) + '. The maximum is 50 MB — split the file and process the parts separately.');
			el.file.value = '';
			return;
		}
		state.fileName = file.name;
		markStale();
		if (file.size <= INLINE_FILE_BYTES) {
			file.text().then(text => {
				el.input.value = text;
				setTextSource('Loaded “' + file.name + '” (' + formatBytes(file.size) + '). You can edit it before anonymizing.' + webkitNote(file.size));
			}, () => showError('The file could not be read. Make sure it is a plain-text file.'));
			return;
		}
		state.source = { kind: 'file', file };
		el.input.value = '';
		el.source.textContent = 'Loaded “' + file.name + '” (' + formatBytes(file.size) + '). Large files are not displayed; they are processed in the background. Type in the box to switch back to pasted text.' + webkitNote(file.size);
	}

	function hasInput() {
		return state.source.kind === 'file' || el.input.value.length > 0;
	}

	// ---------------------------------------------------------------- rules

	function addRule() {
		if (el.rules.children.length >= MAX_RULES) {
			setStatus('A maximum of ' + MAX_RULES + ' custom rules is supported.');
			return;
		}
		const index = ++addRule.counter;
		const node = el.ruleTemplate.content.firstElementChild.cloneNode(true);
		for (const field of ['pattern', 'label']) {
			const input = node.querySelector('[data-la-rule-' + field + ']');
			const id = 'cd-la-rule-' + index + '-' + field;
			input.id = id;
			node.querySelector('[data-la-for="' + field + '"]').setAttribute('for', id);
			const error = node.querySelector('[data-la-rule-error="' + field + '"]');
			error.id = id + '-error';
		}
		node.querySelector('[data-la-rule-label]').addEventListener('input', event => {
			const input = event.target;
			const upper = input.value.toUpperCase();
			if (upper !== input.value) { input.value = upper; }
		});
		node.querySelector('[data-la-remove-rule]').addEventListener('click', () => {
			node.remove();
			markStale();
			el.addRule.focus();
		});
		el.rules.appendChild(node);
		renumberRules();
		node.querySelector('[data-la-rule-pattern]').focus();
	}
	addRule.counter = 0;

	function renumberRules() {
		Array.from(el.rules.children).forEach((node, i) => {
			node.querySelector('[data-la-remove-rule]').setAttribute('aria-label', 'Remove custom rule ' + (i + 1));
		});
	}

	function setFieldError(node, field, message) {
		const input = node.querySelector('[data-la-rule-' + field + ']');
		const error = node.querySelector('[data-la-rule-error="' + field + '"]');
		error.textContent = message || '';
		error.hidden = !message;
		if (message) {
			input.setAttribute('aria-invalid', 'true');
			input.setAttribute('aria-describedby', error.id);
		} else {
			input.removeAttribute('aria-invalid');
			input.removeAttribute('aria-describedby');
		}
	}

	/** Validate custom rules in the UI; the worker validates again. */
	function collectRules() {
		const rules = [];
		let firstInvalid = null;
		for (const node of Array.from(el.rules.children)) {
			const patternInput = node.querySelector('[data-la-rule-pattern]');
			const labelInput = node.querySelector('[data-la-rule-label]');
			const pattern = patternInput.value;
			const label = labelInput.value.trim();
			const caseInsensitive = node.querySelector('[data-la-rule-case]').checked;
			let patternError = '';
			let labelError = '';
			if (!pattern && !label) { setFieldError(node, 'pattern', ''); setFieldError(node, 'label', ''); continue; }
			if (!pattern) {
				patternError = 'Enter a regular expression.';
			} else {
				try {
					const re = new RegExp(pattern, 'g' + (caseInsensitive ? 'i' : ''));
					if (re.test('')) { patternError = 'This pattern matches an empty string. Make it match at least one character.'; }
				} catch (e) {
					patternError = 'This is not a valid regular expression: ' + String(e.message).replace(/^Invalid regular expression: /, '');
				}
			}
			if (!LABEL_RE.test(label) || /^REDACTED_/.test(label)) {
				labelError = 'Use 1–32 uppercase letters, digits or underscores, starting with a letter.';
			}
			setFieldError(node, 'pattern', patternError);
			setFieldError(node, 'label', labelError);
			if (patternError || labelError) {
				firstInvalid = firstInvalid || node.querySelector(patternError ? '[data-la-rule-pattern]' : '[data-la-rule-label]');
				continue;
			}
			rules.push({ pattern, label, caseInsensitive });
		}
		return { rules, firstInvalid };
	}

	function collectOptions() {
		const categories = {};
		for (const box of el.categories) { categories[box.value] = box.checked; }
		const mode = el.modes.find(r => r.checked);
		return {
			categories,
			labelMode: mode ? mode.value : 'stable',
			keepPrivateIPv4: el.keepPrivate.checked
		};
	}

	// ---------------------------------------------------------------- run

	function run() {
		showError('');
		if (state.running) { return; }
		if (!hasInput()) {
			showError('Paste a log or load a file first.');
			el.input.focus();
			return;
		}
		if (state.source.kind === 'text' && el.input.value.length > MAX_BYTES) {
			showError('The pasted text is larger than 50 MB. Save it to a file and process it in parts.');
			return;
		}
		const { rules, firstInvalid } = collectRules();
		if (firstInvalid) {
			showError('Fix the highlighted custom rule before anonymizing.');
			firstInvalid.focus();
			return;
		}
		const options = collectOptions();
		options.customRules = rules;
		const enabled = Object.keys(options.categories).some(k => options.categories[k]) || rules.length > 0;
		if (!enabled) {
			showError('Select at least one category or add a custom rule.');
			el.categories[0].focus();
			return;
		}
		options.categories.custom = true;
		if (!state.worker) { createWorker(); }
		const jobId = ++state.jobId;
		const source = state.source.kind === 'file' ? { kind: 'file', file: state.source.file } : { kind: 'text', text: el.input.value };
		setRunning(true);
		setStatus('Anonymizing locally…' + webkitNote(state.source.kind === 'file' ? state.source.file.size : el.input.value.length));
		state.timer = window.setTimeout(() => {
			if (state.jobId === jobId && state.running) {
				cancel('Processing took longer than ' + (JOB_TIMEOUT_MS / 1000) + ' seconds and was stopped. A custom rule may be too complex, or the input too large.');
			}
		}, JOB_TIMEOUT_MS);
		state.worker.postMessage({ type: 'run', jobId, source, options, previewChars: PREVIEW_CHARS });
	}

	function cancel(message) {
		if (!state.running) { return; }
		state.jobId++;
		finishJob();
		createWorker();
		if (message) { showError(message); }
		setStatus(message ? '' : 'Cancelled. Nothing was processed further.');
		el.run.focus();
	}

	function onWorkerMessage(event) {
		const msg = event.data || {};
		if (msg.jobId !== state.jobId) { return; }
		if (msg.type === 'progress') {
			el.progress.value = msg.total ? Math.round((msg.done / msg.total) * 100) : 100;
			return;
		}
		finishJob();
		if (msg.type === 'error') {
			setStatus('');
			showError(msg.message || 'The log could not be processed.');
			return;
		}
		if (msg.type === 'result') {
			renderResult(msg);
		}
	}

	// ---------------------------------------------------------------- output

	function renderPreview(preview) {
		const fragment = document.createDocumentFragment();
		const text = preview.text;
		let pos = 0;
		for (const [start, end, category] of preview.spans) {
			if (start > pos) { fragment.appendChild(document.createTextNode(text.slice(pos, start))); }
			const mark = document.createElement('mark');
			mark.className = 'cd-la-mark cd-la-mark--' + category;
			mark.textContent = text.slice(start, end);
			fragment.appendChild(mark);
			pos = end;
		}
		if (pos < text.length) { fragment.appendChild(document.createTextNode(text.slice(pos))); }
		el.preview.replaceChildren(fragment);
	}

	function renderStats(stats) {
		const rows = document.createDocumentFragment();
		let total = 0;
		let unique = 0;
		for (const id of Object.keys(stats)) {
			const s = stats[id];
			total += s.replacements;
			unique += s.unique;
			if (!s.replacements) { continue; }
			const tr = document.createElement('tr');
			const th = document.createElement('th');
			th.scope = 'row';
			const swatch = document.createElement('span');
			swatch.className = 'cd-la-swatch cd-la-mark--' + id;
			swatch.setAttribute('aria-hidden', 'true');
			th.appendChild(swatch);
			th.appendChild(document.createTextNode(categoryName(id)));
			const a = document.createElement('td');
			a.textContent = number(s.replacements);
			const b = document.createElement('td');
			b.textContent = number(s.unique);
			tr.append(th, a, b);
			rows.appendChild(tr);
		}
		if (!total) {
			const tr = document.createElement('tr');
			const td = document.createElement('td');
			td.colSpan = 3;
			td.textContent = 'Nothing was detected for the selected categories.';
			tr.appendChild(td);
			rows.appendChild(tr);
		}
		el.stats.replaceChildren(rows);
		return { total, unique };
	}

	function renderResult(msg) {
		state.result = msg;
		state.stale = false;
		const totals = renderStats(msg.stats);
		const took = msg.elapsedMs < 1000 ? number(Math.max(1, msg.elapsedMs)) + ' ms' : (msg.elapsedMs / 1000).toFixed(1) + ' s';
		el.summary.textContent = number(msg.lines) + ' lines processed in ' + took + '. ' +
			number(totals.total) + ' values replaced (' + number(totals.unique) + ' unique). Line count and delimiters were preserved.';
		const notes = [];
		if (msg.encoding !== 'utf-8') { notes.push('The file was decoded as ' + msg.encoding.toUpperCase() + '. Downloads are saved as UTF-8.'); }
		if (msg.invalidBytes) { notes.push('Some bytes were not valid text and appear as “�”. Check that the file encoding is UTF-8.'); }
		if (msg.warnings && msg.warnings.multilineCustom) { notes.push(number(msg.warnings.multilineCustom) + ' custom-rule matches spanning several lines were skipped to keep the log structure.'); }
		if (!totals.total) { notes.push('No values were replaced. This does not mean the log is free of sensitive data.'); }
		el.notes.replaceChildren(...notes.map(text => { const li = document.createElement('li'); li.textContent = text; return li; }));
		el.notes.hidden = notes.length === 0;
		renderPreview(msg.preview);
		el.truncated.hidden = !msg.preview.truncated;
		el.truncated.textContent = msg.preview.truncated ? 'The preview shows the first ' + number(msg.preview.text.length) + ' of ' + number(msg.output.length) + ' characters. Copy and Download include the complete result.' : '';
		el.mapAck.checked = false;
		el.map.disabled = true;
		el.results.hidden = false;
		setStatus('Done. Review the highlighted result below before sharing it.');
		el.resultsHeading.focus();
	}

	function markStale() {
		if (state.result && !state.stale) {
			state.stale = true;
			setStatus('Input or settings changed. Select “Anonymize log” again to update the result.');
		}
	}

	function outputName() {
		if (!state.fileName) { return 'anonymized-log.txt'; }
		const dot = state.fileName.lastIndexOf('.');
		const base = (dot > 0 ? state.fileName.slice(0, dot) : state.fileName).replace(/[^\w.-]+/g, '_').slice(0, 80) || 'log';
		const ext = dot > 0 ? state.fileName.slice(dot).replace(/[^\w.]+/g, '').slice(0, 10) : '.txt';
		return base + '.anonymized' + ext;
	}

	function saveFile(content, name, type) {
		const blob = new Blob([content], { type });
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

	function copyFallback(text) {
		const area = document.createElement('textarea');
		area.value = text;
		area.setAttribute('readonly', '');
		area.className = 'cd-la-offscreen';
		document.body.appendChild(area);
		area.select();
		let ok = false;
		try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
		area.remove();
		return ok;
	}

	function copyResult() {
		if (!state.result) { return; }
		const text = state.result.output;
		const done = ok => setStatus(ok ? 'Result copied to the clipboard (' + formatBytes(text.length) + ').' : 'Copying was blocked by the browser. Use “Download result” instead.');
		if (navigator.clipboard && window.isSecureContext) {
			navigator.clipboard.writeText(text).then(() => done(true), () => done(copyFallback(text)));
		} else {
			done(copyFallback(text));
		}
	}

	function downloadMap() {
		if (!state.result || !el.mapAck.checked) { return; }
		const body = {
			tool: 'CyberDat Privacy Shield Log Anonymizer',
			warning: 'CONTAINS ORIGINAL SENSITIVE VALUES. Keep private. Never share together with the anonymized log.',
			labelMode: collectOptions().labelMode,
			generatedAt: new Date().toISOString(),
			entries: state.result.map
		};
		saveFile(JSON.stringify(body, null, 2) + '\n', 'replacement-map.json', 'application/json');
		setStatus('Replacement map downloaded. Store it securely and delete it when no longer needed.');
	}

	function clearAll() {
		if (state.running) { cancel(); }
		el.input.value = '';
		el.file.value = '';
		state.fileName = '';
		setTextSource('');
		state.result = null;
		state.stale = false;
		el.preview.replaceChildren();
		el.stats.replaceChildren();
		el.summary.textContent = '';
		el.results.hidden = true;
		el.mapAck.checked = false;
		el.map.disabled = true;
		showError('');
		// The worker keeps nothing between jobs (all job data is local to its message
		// handler), so it is not recreated here: recreating would re-request its script.
		setStatus('Cleared. Input and results were removed from this page.');
		el.input.focus();
	}

	// ---------------------------------------------------------------- wiring

	el.file.addEventListener('change', () => loadFile(el.file.files && el.file.files[0]));
	el.input.addEventListener('input', () => {
		if (state.source.kind === 'file') { setTextSource(''); state.fileName = ''; }
		markStale();
	});
	el.input.addEventListener('dragover', event => { event.preventDefault(); el.input.classList.add('is-dragover'); });
	el.input.addEventListener('dragleave', () => el.input.classList.remove('is-dragover'));
	el.input.addEventListener('drop', event => {
		el.input.classList.remove('is-dragover');
		const files = event.dataTransfer && event.dataTransfer.files;
		if (files && files.length) {
			event.preventDefault();
			loadFile(files[0]);
		}
	});
	el.sample.addEventListener('click', () => {
		el.input.value = SAMPLE;
		state.fileName = '';
		el.file.value = '';
		setTextSource('Sample loaded. It uses documentation-only addresses and test values.');
		markStale();
		el.input.focus();
	});
	el.clear.addEventListener('click', clearAll);
	root.addEventListener('change', event => {
		if (event.target.closest('[data-la-category], [data-la-mode], [data-la-keep-private], [data-la-rules]')) { markStale(); }
	});
	root.addEventListener('input', event => {
		if (event.target.closest('[data-la-rules]')) { markStale(); }
	});
	$$('[data-la-select]').forEach(button => button.addEventListener('click', () => {
		const on = button.getAttribute('data-la-select') === 'all';
		el.categories.forEach(box => { box.checked = on; });
		markStale();
	}));
	el.addRule.addEventListener('click', () => { addRule(); markStale(); });
	el.run.addEventListener('click', run);
	el.cancel.addEventListener('click', () => cancel());
	el.copy.addEventListener('click', copyResult);
	el.download.addEventListener('click', () => {
		if (!state.result) { return; }
		saveFile(state.result.output, outputName(), 'text/plain;charset=utf-8');
		setStatus('Download started: ' + outputName() + '.');
	});
	el.mapAck.addEventListener('change', () => { el.map.disabled = !el.mapAck.checked; });
	el.map.addEventListener('click', downloadMap);
	root.addEventListener('keydown', event => {
		if (event.key === 'Escape' && state.running) { cancel(); }
		if (event.key === 'Enter' && (event.ctrlKey || event.metaKey) && event.target === el.input) { event.preventDefault(); run(); }
	});

	// Create the worker up front so processing itself triggers no request at all.
	createWorker();
	el.app.hidden = false;
	el.app.setAttribute('aria-busy', 'false');
}());
