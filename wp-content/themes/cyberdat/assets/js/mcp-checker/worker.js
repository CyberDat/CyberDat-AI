/*!
 * CyberDat MCP Security & Policy Checker: background worker.
 * Loads the engine, then disables network-capable APIs (defence in depth; the page Content Security
 * Policy also sets connect-src 'none'). Configurations are parsed as data only: no server is started,
 * no command is run and no URL from the input is requested.
 */
'use strict';

(function () {
	const params = new URLSearchParams(self.location.search);
	const ev = (params.get('ev') || '').replace(/[^0-9A-Za-z._-]/g, '');
	importScripts('engine.js' + (ev ? '?ver=' + encodeURIComponent(ev) : ''));

	const blocked = function () { throw new Error('Network access is disabled in the MCP checker worker.'); };
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

const MAX_INPUT_CHARS = self.CyberDatMcpChecker.MAX_INPUT_CHARS;

function decodeFile(file) {
	if (file.size > MAX_INPUT_CHARS) {
		const err = new Error('The file is larger than the 5 MB limit.');
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
				const err = new Error('This looks like a binary file. Only JSON text (UTF-8 or UTF-16 with BOM) is supported.');
				err.code = 'BINARY';
				throw err;
			}
		}
	}
	return { text: new TextDecoder(encoding).decode(bytes), encoding };
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
		const hooks = {
			onProgress(done, total) {
				const now = Date.now();
				if (now - lastReport > 100 || done === total) {
					lastReport = now;
					self.postMessage({ type: 'progress', jobId, done, total });
				}
			}
		};
		const engine = self.CyberDatMcpChecker;
		const result = msg.mode === 'policy' ? engine.checkPolicy(text, String(msg.policy || ''), hooks) : engine.analyze(text, {}, hooks);
		result.type = 'result';
		result.jobId = jobId;
		result.encoding = encoding;
		result.chars = text.length;
		result.elapsedMs = Date.now() - started;
		self.postMessage(result);
	} catch (error) {
		self.postMessage({ type: 'error', jobId, code: error.code || 'FAILED', message: String(error.message || error), errors: error.errors || null, warnings: error.warnings || null });
	}
};
