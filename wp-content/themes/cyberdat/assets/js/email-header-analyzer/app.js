/*!
 * CyberDat Email Header Analyzer — user interface.
 *
 * Contract (enforced by tests):
 *  - header values, names and findings are written to the DOM only with textContent, never as HTML; no links;
 *  - no network, storage, cookie or URL-bar APIs; an opened file is read in the tab; downloads are created in the tab;
 *  - the message body is never shown; inputs and results carry translate="no" and the notranslate class;
 *  - the page reports the worker state in data-worker-state (loading, ready, error);
 *  - no regular-expression look-behind here or in worker.js / engine.js.
 */
(function () {
	'use strict';

	const root = document.querySelector('[data-eha]');
	if (!root) { return; }

	const MAX_CHARS = 5 * 1024 * 1024;
	const JOB_TIMEOUT_MS = 30000;
	const NO_FINDINGS = 'No known warning signs matched. This does not mean the message is safe.';
	const $ = s => root.querySelector(s);
	const el = {
		app: $('[data-eha-app]'), unsupported: $('[data-eha-unsupported]'), workerStatus: $('[data-eha-worker-status]'), input: $('[data-eha-input]'), file: $('[data-eha-file]'), own: $('[data-eha-own]'),
		samples: root.querySelectorAll('[data-eha-sample]'), clear: $('[data-eha-clear]'), run: $('[data-eha-run]'), cancel: $('[data-eha-cancel]'), progress: $('[data-eha-progress]'),
		status: $('[data-eha-status]'), error: $('[data-eha-error]'), size: $('[data-eha-size]'), results: $('[data-eha-results]'), heading: $('#cd-eha-step-results'),
		verdict: $('[data-eha-verdict]'), notes: $('[data-eha-notes]'), summary: $('[data-eha-summary]'), findings: $('[data-eha-findings]'), infoWrap: $('[data-eha-info-wrap]'), infoTitle: $('[data-eha-info-title]'), info: $('[data-eha-info]'),
		boundary: $('[data-eha-boundary]'), path: $('[data-eha-path]'), auth: $('[data-eha-auth]'), align: $('[data-eha-align]'), masks: root.querySelectorAll('[data-eha-mask]'), reports: root.querySelectorAll('[data-eha-report]')
	};
	const setWorkerState = (s, text) => { root.setAttribute('data-worker-state', s); el.workerStatus.textContent = text; };
	let unicodeOk = false;
	try { unicodeOk = new RegExp('^\\p{L}\\p{M}$', 'u').test('e\u0301') && typeof TextDecoder === 'function'; } catch (e) { unicodeOk = false; }
	if (!unicodeOk || typeof Worker !== 'function' || typeof Blob !== 'function' || !window.URL || typeof URL.createObjectURL !== 'function') {
		el.unsupported.textContent = 'Browser not supported: this tool needs Web Workers, Unicode regular expressions and TextDecoder. Use a current version of Edge, Chrome, Firefox or Safari. Nothing was sent anywhere.';
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
	const state = { worker: null, jobId: 0, running: false, timer: 0, reports: null };
	const number = n => Number(n).toLocaleString('en-US');
	const plural = (n, w, many) => number(n) + ' ' + (n === 1 ? w : many || w + 's');
	const setStatus = m => { el.status.textContent = m; };
	const showError = m => { el.error.textContent = m; el.error.hidden = !m; };
	function node(tag, className, text) { const e = document.createElement(tag); if (className) { e.className = className; } if (text !== undefined && text !== null) { e.textContent = String(text); } return e; }

	function workerUrl() { const url = new URL(root.getAttribute('data-worker-src') || '', document.baseURI); if (url.origin !== window.location.origin) { throw new Error('Worker must be same-origin.'); } return url.href; }
	function createWorker() {
		if (state.worker) { state.worker.terminate(); }
		setWorkerState('loading', 'Starting the local analyzer…');
		try { state.worker = new Worker(workerUrl()); } catch (e) { state.worker = null; setWorkerState('error', 'The local analyzer could not start.'); el.unsupported.hidden = false; el.app.hidden = true; return; }
		state.worker.onmessage = ev => {
			const msg = ev.data || {};
			if (msg.type === 'ready') { setWorkerState('ready', 'Ready. Headers are analyzed locally in this tab.'); return; }
			if (msg.jobId !== state.jobId) { return; }
			if (msg.type === 'progress') { el.progress.value = Math.round(100 * msg.done / msg.total); return; }
			finish();
			if (msg.type === 'error') { setStatus(''); showError(msg.message || 'The headers could not be analyzed.'); return; }
			render(msg);
		};
		state.worker.onerror = ev => { ev.preventDefault(); finish(); setWorkerState('error', 'The local analyzer stopped. Reload the page.'); showError('The background worker stopped unexpectedly. Nothing was sent anywhere. Reload the page and try again.'); };
	}
	function setRunning(r) { state.running = r; el.run.disabled = r; el.cancel.hidden = !r; el.progress.hidden = !r; el.app.setAttribute('aria-busy', r ? 'true' : 'false'); if (!r) { el.progress.value = 0; } }
	function finish() { window.clearTimeout(state.timer); setRunning(false); }
	function cancel(message) { if (!state.running) { return; } state.jobId++; finish(); createWorker(); if (message) { showError(message); } setStatus(message ? '' : 'Cancelled. Nothing was analyzed further.'); el.run.focus(); }

	function run() {
		showError('');
		if (state.running) { return; }
		if (!el.input.value.trim()) { showError('Paste the message headers or open a saved message first.'); el.input.focus(); return; }
		if (el.input.value.length > MAX_CHARS) { showError('The text is larger than 5 MB.'); return; }
		if (!state.worker) { createWorker(); }
		const jobId = ++state.jobId;
		setRunning(true);
		largeInput(el.input.value.length);
		setStatus('Analyzing the headers locally…');
		state.timer = window.setTimeout(() => { if (state.running && state.jobId === jobId) { cancel('Processing took longer than 30 seconds and was stopped.'); } }, JOB_TIMEOUT_MS);
		state.worker.postMessage({ jobId, text: el.input.value, own: el.own.value });
	}
	const addr = a => (a ? (a.name ? a.name + ' <' + a.address + '>' : a.address) : '');
	function findingItem(f) {
		const li = node('li', 'cd-eha-finding cd-eha-finding--' + f.severity);
		const head = node('p', 'cd-eha-head');
		head.append(node('span', 'cd-eha-sev cd-eha-sev--' + f.severity, f.severity.toUpperCase()), ' ', node('strong', '', f.title), ' ', node('code', 'cd-eha-muted', f.id));
		li.appendChild(head);
		if (f.evidence) { const p = node('p'); p.append(node('span', 'cd-eha-muted', 'Found: '), node('code', 'cd-eha-code', f.evidence)); li.appendChild(p); }
		li.appendChild(node('p', '', f.explanation));
		const nx = node('p');
		nx.append(node('span', 'cd-eha-label', 'Check next: '), document.createTextNode(f.next));
		li.appendChild(nx);
		return li;
	}
	function hopItem(h, boundaryLabel) {
		const kind = h.boundary ? 'boundary' : h.trusted ? 'trusted' : 'untrusted';
		const li = node('li', 'cd-eha-hop cd-eha-hop--' + kind);
		const head = node('p', 'cd-eha-head');
		head.append(node('strong', '', 'Step ' + h.step), ' ', node('span', 'cd-eha-tag', h.boundary ? 'Trust boundary: your first server' : h.trusted ? 'Your servers' : 'Not verifiable (could be forged)'));
		li.appendChild(head);
		if (!h.parsed) { li.appendChild(node('p', 'cd-eha-muted', 'Not recognised, shown as written:')); li.appendChild(node('p', 'cd-eha-code', h.raw)); return li; }
		const from = h.from ? [h.from.rdns || h.from.host, h.from.helo && h.from.helo !== (h.from.rdns || h.from.host) ? '(HELO ' + h.from.helo + ')' : '', h.from.ip ? '[' + h.from.ip + (h.ipClass && h.ipClass !== 'public' ? ', ' + h.ipClass : '') + ']' : ''].filter(Boolean).join(' ') : '—';
		const by = h.by ? (h.by.host || h.by.ip || '—') : '—';
		const p1 = node('p'); p1.append(node('span', 'cd-eha-muted', 'From: '), node('span', 'cd-eha-code', from)); li.appendChild(p1);
		const p2 = node('p'); p2.append(node('span', 'cd-eha-muted', 'By: '), node('span', 'cd-eha-code', by + (h.with ? ' · with ' + h.with : '') + (h.id ? ' · id ' + h.id : '') + (h.for ? ' · for ' + h.for : ''))); li.appendChild(p2);
		li.appendChild(node('p', 'cd-eha-muted', (h.dateRaw || 'no date') + (h.delaySec !== null ? ' · ' + (h.delaySec < 0 ? 'minus ' : '+') + number(Math.abs(h.delaySec)) + ' s' : '')));
		if (h.boundary && boundaryLabel) { li.appendChild(node('p', '', boundaryLabel)); }
		return li;
	}
	function render(msg) {
		const r = msg.result;
		state.reports = msg.reports;
		const c = r.counts;
		const warn = r.findings.filter(f => f.group === 'warning'), info = r.findings.filter(f => f.group === 'info');
		el.verdict.className = 'cd-eha-verdict cd-eha-verdict--' + (c.high ? 'high' : c.medium ? 'medium' : 'ok');
		if (!warn.length) { el.verdict.replaceChildren(node('strong', '', NO_FINDINGS)); if (info.length) { el.verdict.append(document.createTextNode(' ' + plural(info.length, 'informational item') + ' below.')); } }
		else { el.verdict.replaceChildren(node('strong', '', plural(warn.length, 'warning sign') + ' found (' + c.high + ' high, ' + c.medium + ' medium, ' + c.low + ' low).'), document.createTextNode(' No finding proves a message is genuine; each one explains what to check next.')); }
		const notes = r.notes.slice();
		if (!r.bodyIgnored.lines) { notes.push('No message body was included; only headers were analyzed.'); }
		el.notes.replaceChildren(...notes.map(x => node('li', '', x)));
		el.notes.hidden = !notes.length;
		const S = r.summary;
		const rows = [['From', S.from ? addr(S.from) : 'missing'], ['Reply-To', addr(S.replyTo)], ['Return-Path', S.returnPath || ''], ['To', S.to.map(addr).join(', ')], ['Cc', S.cc.map(addr).join(', ')], ['Subject', S.subject === null ? 'missing' : S.subject], ['Date', S.date ? S.date.raw : 'missing'], ['Message-ID', S.messageId || 'missing'], ['Mail software', S.mailer], ['Originating IP', S.originatingIp]].filter(x => x[1]);
		el.summary.replaceChildren(...rows.flatMap(([k, v]) => [node('dt', '', k), node('dd', '', v)]));
		el.findings.replaceChildren(...(warn.length ? warn.map(findingItem) : [node('li', 'cd-eha-muted', NO_FINDINGS)]));
		el.info.replaceChildren(...info.map(findingItem));
		el.infoTitle.textContent = 'Minor and informational: ' + plural(info.length, 'item');
		el.infoWrap.hidden = !info.length;
		el.infoWrap.open = false;
		const P = r.path;
		const ext = P.external ? (P.external.label + (P.external.ip && P.external.ip !== P.external.label ? ' [' + P.external.ip + ']' : '')) : '';
		el.boundary.textContent = (P.providerBoundary ? 'Trust boundary: ' + P.providerBoundary.host + ' (mailbox provider for your domain). ' : '') + (!P.hops.length ? 'No Received lines were found.' : P.internal ? 'All steps are inside your organization (' + P.trustedOrgs.join(', ') + ').' : 'Your servers: ' + (P.trustedOrgs.join(', ') || 'unknown') + (P.ownDeclared ? ' (as you entered).' : ' (assumed from the top line; enter your domain to set it).') + (ext ? ' First external server: ' + ext + '.' : '') + (P.totalDelaySec !== null ? ' Total time: ' + number(P.totalDelaySec) + ' s.' : ''));
		el.path.replaceChildren(...P.hops.slice().reverse().map(h => hopItem(h, ext ? 'It received the message from ' + ext + '. Everything in earlier steps was written by servers you cannot verify.' : '')));
		const A = r.auth;
		const items = [];
		for (const a of A.results) { items.push(node('li', '', (a.trusted ? 'Trusted' : 'NOT trusted (' + a.reason + ')') + ' · Authentication-Results' + (a.authservId ? ' by ' + a.authservId : '') + ': ' + (a.methods.map(m => m.method + '=' + m.result + (m.props['header.from'] ? ' (From ' + m.props['header.from'] + ')' : m.props['header.d'] ? ' (d=' + m.props['header.d'] + ')' : m.props['smtp.mailfrom'] ? ' (' + m.props['smtp.mailfrom'] + ')' : '')).join(', ') || 'no results'))); }
		for (const s of A.receivedSpf) { items.push(node('li', '', (s.trusted ? 'Trusted' : 'NOT trusted (' + s.reason + ')') + ' · Received-SPF: ' + s.result + (s.domain ? ' for ' + s.domain : '') + (s.ip ? ' from ' + s.ip : ''))); }
		for (const a of A.arc) { items.push(node('li', '', 'ARC-Authentication-Results' + (a.authservId ? ' by ' + a.authservId : '') + ' (recorded by a forwarder; trusted only through arc= of your server): ' + a.methods.map(m => m.method + '=' + m.result).join(', '))); }
		for (const d of A.dkimSignatures) { items.push(node('li', '', 'DKIM-Signature (not verified here): d=' + d.d + ', s=' + d.s + ', a=' + d.a + (d.h.length ? ', signs ' + d.h.join(', ') : ''))); }
		if (!items.length) { items.push(node('li', '', 'No authentication headers were found.')); }
		el.auth.replaceChildren(...items);
		const al = A.alignment;
		el.align.textContent = 'Alignment' + (al.approximate ? ' (approximate: the Public Suffix List is not loaded)' : '') + ': From domain ' + (al.fromOrg || 'unknown') + '; SPF domain ' + (al.spf.domain ? al.spf.domain + (al.spf.aligned ? ' — aligned' : ' — not aligned') + ' (' + al.spf.source + ')' : 'unknown') + '; DKIM ' + (al.dkim.length ? al.dkim.map(x => x.domain + (x.aligned ? ' — aligned' : ' — not aligned') + (x.verified ? ' (' + x.result + ')' : ' (not verified)')).join('; ') : 'none') + '.';
		el.results.hidden = false;
		setStatus('Done. ' + plural(P.hops.length, 'Received line') + ', ' + plural(r.findings.length, 'finding') + ' in ' + (msg.elapsedMs < 1000 ? number(Math.max(1, msg.elapsedMs)) + ' ms' : (msg.elapsedMs / 1000).toFixed(1) + ' s') + '.');
		el.heading.focus();
	}
	function download(name, text, type) { const blob = new Blob([text], { type }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name; a.hidden = true; document.body.appendChild(a); a.click(); a.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 30000); }
	const maskKey = () => { const on = k => [...el.masks].some(m => m.getAttribute('data-eha-mask') === k && m.checked); return (on('recipients') ? 'r' : '') + (on('internal') ? 'i' : '') || 'none'; };

	el.run.addEventListener('click', run);
	el.cancel.addEventListener('click', () => cancel());
	el.input.addEventListener('input', () => { el.size.textContent = el.input.value.length > MAX_CHARS * 0.9 ? 'The text is ' + number(el.input.value.length) + ' characters; the limit is 5,242,880.' : ''; });
	el.file.addEventListener('change', () => {
		const f = el.file.files && el.file.files[0];
		if (!f) { return; }
		showError('');
		if (f.size > MAX_CHARS) { showError('The file is larger than 5 MB.'); el.file.value = ''; return; }
		largeInput(f.size);
		f.text().then(t => { el.input.value = t; el.file.value = ''; el.input.dispatchEvent(new Event('input')); setStatus('File opened in this tab (' + plural(t.length, 'character') + '). Only the headers will be analyzed; nothing was uploaded.'); }).catch(() => showError('The file could not be read.'));
	});
	for (const b of el.samples) { b.addEventListener('click', () => { const k = b.getAttribute('data-eha-sample'); el.input.value = EX[k]; el.own.value = 'example.com'; setStatus('Example ' + k + ' message headers loaded (written by CyberDat; your domain set to example.com).'); el.input.focus(); }); }
	el.clear.addEventListener('click', () => { if (state.running) { cancel(); } el.input.value = ''; el.own.value = ''; el.results.hidden = true; state.reports = null; for (const x of [el.summary, el.findings, el.info, el.path, el.auth]) { x.replaceChildren(); } showError(''); setStatus('Cleared. The headers and the results were removed from this page.'); el.input.focus(); });
	for (const b of el.reports) { b.addEventListener('click', () => { if (!state.reports) { return; } const k = b.getAttribute('data-eha-report'); const rep = state.reports[maskKey()]; download(k === 'json' ? 'email-header-analysis.json' : 'email-header-analysis.md', k === 'json' ? rep.json : rep.markdown, k === 'json' ? 'application/json' : 'text/markdown'); setStatus('Report downloaded' + (maskKey() === 'none' ? '' : ' with the chosen masking') + '. It does not contain the message body.'); }); }
	root.addEventListener('keydown', e => { if (e.key === 'Escape' && state.running) { cancel(); } if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && e.target === el.input) { e.preventDefault(); run(); } });

	// Examples are copies of the engine examples (checked by tests), kept here so they load without a worker round trip.
	const EX = {
		phishing: "Return-Path: <bounce@bulk.example.net>\nDelivered-To: bob@example.com\nReceived: from mx.example.com (mx.example.com [192.0.2.25])\n\tby imap.example.com (Postfix) with ESMTPS id 4Xm1Ab2\n\tfor <bob@example.com>; Wed, 18 Nov 2026 09:15:44 +0100 (CET)\nAuthentication-Results: mx.example.com;\n\tspf=softfail smtp.mailfrom=bulk.example.net;\n\tdkim=none;\n\tdmarc=fail header.from=paypa1-secure.example\nReceived: from unknown (unknown [203.0.113.44])\n\tby mx.example.com (Postfix) with ESMTP id 4Xm1Ab1\n\tfor <bob@example.com>; Wed, 18 Nov 2026 09:15:42 +0100 (CET)\nAuthentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\nReceived: from mail.paypal.example (mail.paypal.example [198.51.100.7])\n\tby relay.bulk.example.net with ESMTP id 77; Wed, 18 Nov 2026 07:10:00 +0000\nFrom: \"PayPal Service\" <service@paypa1-secure.example>\nReply-To: support@example.net\nTo: bob@example.com\nSubject: =?UTF-8?B?WW91ciBhY2NvdW50IGlzIGxpbWl0ZWQ=?=\nDate: Wed, 18 Nov 2026 09:15:40 +0100\nX-Mailer: PHPMailer 6.9.1\n\n(The message body would be here; it is ignored.)\n",
		normal: "Return-Path: <alice@example.org>\nDelivered-To: bob@example.com\nReceived: from mx.example.com (mx.example.com [192.0.2.25])\n\tby imap.example.com (Postfix) with ESMTPS id 4Xk9Ex1\n\tfor <bob@example.com>; Wed, 18 Nov 2026 14:02:07 +0100 (CET)\nAuthentication-Results: mx.example.com;\n\tspf=pass smtp.mailfrom=example.org;\n\tdkim=pass header.d=example.org header.s=s2026;\n\tdmarc=pass header.from=example.org\nReceived: from mail.example.org (mail.example.org [198.51.100.10])\n\tby mx.example.com (Postfix) with ESMTPS id 4Xk9Ex0\n\tfor <bob@example.com>; Wed, 18 Nov 2026 14:02:05 +0100 (CET)\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=s2026;\n\th=from:to:subject:date:message-id; bh=ZXhhbXBsZQ==; b=ZXhhbXBsZQ==\nFrom: =?UTF-8?Q?J=C3=BCrgen_Beispiel?= <juergen@example.org>\nTo: Bob <bob@example.com>\nSubject: Meeting notes\nDate: Wed, 18 Nov 2026 14:02:01 +0100\nMessage-ID: <20261118130201.4711@mail.example.org>\n\n(The message body would be here; it is ignored.)\n"
	};

	createWorker();
	el.app.hidden = false;
	el.app.setAttribute('aria-busy', 'false');
}());
