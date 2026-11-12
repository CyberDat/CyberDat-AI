/*!
 * CyberDat Indirect Prompt Injection Detector — background worker.
 * Reads the selected file or pasted text and runs the engine off the main thread.
 * Network-capable APIs are disabled after the engine is loaded (defence in depth;
 * the page Content Security Policy also sets connect-src 'none').
 */
'use strict';

(function () {
	const params = new URLSearchParams(self.location.search);
	const engineVersion = (params.get('ev') || '').replace(/[^0-9A-Za-z._-]/g, '');
	importScripts('engine.js' + (engineVersion ? '?ver=' + encodeURIComponent(engineVersion) : ''));

	const blocked = function () { throw new Error('Network access is disabled in the Prompt Injection Detector worker.'); };
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

const MAX_INPUT_CHARS = self.CyberDatPromptInjectionDetector.MAX_INPUT_CHARS;

function decodeFile(file) {
	if (file.size > MAX_INPUT_CHARS) {
		const err = new Error('The file is larger than the 20 MB limit. Split it into smaller parts.');
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
				const err = new Error('This looks like a binary file. Only plain text (UTF-8 or UTF-16 with BOM) is supported. For PDF or Word documents, copy the text and paste it here.');
				err.code = 'BINARY';
				throw err;
			}
		}
	}
	// The BOM is kept so that a leading U+FEFF is visible to the analysis like any other character.
	const text = new TextDecoder(encoding, { ignoreBOM: true }).decode(bytes);
	return { text, encoding, invalidBytes: text.indexOf('�') !== -1 };
}

self.onmessage = function (event) {
	const msg = event.data || {};
	if (msg.type !== 'run') { return; }
	const jobId = msg.jobId;
	try {
		let text;
		let encoding = 'utf-8';
		let invalidBytes = false;
		if (msg.source && msg.source.kind === 'file') {
			const decoded = decodeFile(msg.source.file);
			text = decoded.text;
			encoding = decoded.encoding;
			invalidBytes = decoded.invalidBytes;
		} else {
			text = String((msg.source && msg.source.text) || '');
		}
		if (text.length > MAX_INPUT_CHARS) {
			const err = new Error('The text is longer than the 20 MB limit (' + MAX_INPUT_CHARS.toLocaleString('en-US') + ' characters). Split it into smaller parts.');
			err.code = 'TOO_LARGE';
			throw err;
		}
		let lastReport = 0;
		const started = Date.now();
		const result = self.CyberDatPromptInjectionDetector.analyze(text, msg.options, {
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
		result.invalidBytes = invalidBytes;
		result.elapsedMs = Date.now() - started;
		self.postMessage(result);
	} catch (error) {
		self.postMessage({ type: 'error', jobId, code: error.code || 'FAILED', message: String(error.message || error) });
	}
};
