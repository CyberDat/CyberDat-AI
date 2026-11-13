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
 * CyberDat LotL / LOLBAS Command Analyzer: background worker.
 * Loads the bundled LOLBAS snapshot and the engine, then disables network-capable APIs
 * (defence in depth; the page Content Security Policy also sets connect-src 'none').
 * Commands are analyzed as text only and never executed.
 */
'use strict';

(function () {
	const params = new URLSearchParams(self.location.search);
	const clean = v => (v || '').replace(/[^0-9A-Za-z._-]/g, '');
	const ev = clean(params.get('ev'));
	const dv = clean(params.get('dv'));
	importScripts('lolbas-data.js' + (dv ? '?ver=' + encodeURIComponent(dv) : ''), 'engine.js' + (ev ? '?ver=' + encodeURIComponent(ev) : ''));

	const blocked = function () { throw new Error('Network access is disabled in the LotL Command Analyzer worker.'); };
	for (const name of ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'importScripts', 'WebTransport']) {
		try {
			Object.defineProperty(self, name, { value: blocked, writable: false, configurable: false });
		} catch (e) {
			// Property may be absent in this browser.
		}
	}
	try {
		Object.defineProperty(self.navigator, 'sendBeacon', { value: blocked });
	} catch (e) {
		// Not available in workers in most browsers.
	}
}());

const MAX_INPUT_CHARS = self.CyberDatLotlAnalyzer.MAX_INPUT_CHARS;

function decodeFile(file) {
	if (file.size > MAX_INPUT_CHARS) {
		const err = new Error('The file is larger than the 5 MB limit. Split it into smaller parts.');
		err.code = 'TOO_LARGE';
		throw err;
	}
	const bytes = new Uint8Array(new FileReaderSync().readAsArrayBuffer(file));
	let encoding = 'utf-8';
	if (bytes.length >= 2 && bytes[0] === 0xFF && bytes[1] === 0xFE) { encoding = 'utf-16le'; }
	else if (bytes.length >= 2 && bytes[0] === 0xFE && bytes[1] === 0xFF) { encoding = 'utf-16be'; }
	if (encoding === 'utf-8') {
		const probe = bytes.subarray(0, Math.min(bytes.length, 8192));
		for (let i = 0; i < probe.length; i++) {
			if (probe[i] === 0) {
				const err = new Error('This looks like a binary file. Only plain text (UTF-8 or UTF-16 with BOM) is supported. Export the events as text, CSV or JSON first.');
				err.code = 'BINARY';
				throw err;
			}
		}
	}
	const text = new TextDecoder(encoding).decode(bytes);
	return { text, encoding };
}

self.onmessage = function (event) {
	const msg = event.data || {};
	if (msg.type !== 'run') { return; }
	const jobId = msg.jobId;
	try {
		let text;
		let encoding = 'utf-8';
		if (msg.source && msg.source.kind === 'file') {
			const decoded = decodeFile(msg.source.file);
			text = decoded.text;
			encoding = decoded.encoding;
		} else {
			text = String((msg.source && msg.source.text) || '');
		}
		let lastReport = 0;
		const started = Date.now();
		const result = self.CyberDatLotlAnalyzer.analyze(text, {}, {
			onProgress(done, total) {
				const now = Date.now();
				if (now - lastReport > 100 || done === total) {
					lastReport = now;
					self.postMessage({ type: 'progress', jobId, done, total });
				}
			}
		});
		result.type = 'result';
		result.jobId = jobId;
		result.encoding = encoding;
		result.chars = text.length;
		result.elapsedMs = Date.now() - started;
		self.postMessage(result);
	} catch (error) {
		self.postMessage({ type: 'error', jobId, code: error.code || 'FAILED', message: String(error.message || error) });
	}
};
