/*!
 * CyberDat LLM Prompt Injection Test Bench: background worker.
 * Loads the engine from this site, then disables network-capable APIs (defence in depth; the page Content Security Policy
 * also sets connect-src 'none'). This tool never sends test inputs to any application: the user runs them.
 */
'use strict';

(function () {
	const params = new URLSearchParams(self.location.search);
	const ev = (params.get('ev') || '').replace(/[^0-9A-Za-z._-]/g, '');
	importScripts('engine.js' + (ev ? '?ver=' + encodeURIComponent(ev) : ''));
	const blocked = function () { throw new Error('Network access is disabled in the test bench worker.'); };
	for (const name of ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'importScripts', 'WebTransport']) {
		try { Object.defineProperty(self, name, { value: blocked, writable: false, configurable: false }); } catch (e) { /* absent */ }
	}
	try { Object.defineProperty(self.navigator, 'sendBeacon', { value: blocked }); } catch (e) { /* absent */ }
}());

const ENGINE = self.CyberDatTestBench;
self.postMessage({ type: 'ready', engine: ENGINE.ENGINE, library: ENGINE.LIBRARY_VERSION });

self.onmessage = function (event) {
	const msg = event.data || {};
	const jobId = msg.jobId;
	let last = 0;
	const hooks = { onProgress(done, total) { const now = Date.now(); if (now - last > 100 || done === total) { last = now; self.postMessage({ type: 'progress', jobId, done, total }); } } };
	try {
		const started = Date.now();
		let result;
		if (msg.type === 'build') { result = { mode: 'build', set: ENGINE.buildSet({ appTypes: msg.appTypes, langs: msg.langs }) }; result.files = ENGINE.exportSet(result.set); }
		else if (msg.type === 'import-set') { result = { mode: 'build', set: ENGINE.importSet(String(msg.text || '')) }; result.files = ENGINE.exportSet(result.set); }
		else if (msg.type === 'parse-responses') { result = { mode: 'responses', responses: ENGINE.parseResponses(String(msg.text || '')) }; }
		else if (msg.type === 'check') { result = ENGINE.check(msg.set, msg.responses || {}, hooks); result.report = ENGINE.exportReport(msg.set, result, { timestamp: new Date().toISOString() }); }
		else { return; }
		result.type = 'result';
		result.jobId = jobId;
		result.elapsedMs = Date.now() - started;
		self.postMessage(result);
	} catch (error) {
		self.postMessage({ type: 'error', jobId, code: error.code || 'FAILED', message: String(error.message || error) });
	}
};
