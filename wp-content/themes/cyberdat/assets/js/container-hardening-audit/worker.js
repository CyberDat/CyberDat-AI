/*!
 * CyberDat Docker & Kubernetes Hardening Audit Generator: background worker.
 * Loads the engine from this site, then disables network-capable APIs (defence in depth; the page Content Security Policy
 * also sets connect-src 'none'). Files are analysed as text only: nothing is built, pulled, deployed or run.
 */
'use strict';

(function () {
	const params = new URLSearchParams(self.location.search);
	const ev = (params.get('ev') || '').replace(/[^0-9A-Za-z._-]/g, '');
	importScripts('engine.js' + (ev ? '?ver=' + encodeURIComponent(ev) : ''));
	const blocked = function () { throw new Error('Network access is disabled in the audit worker.'); };
	for (const name of ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'importScripts', 'WebTransport']) {
		try { Object.defineProperty(self, name, { value: blocked, writable: false, configurable: false }); } catch (e) { /* absent */ }
	}
	try { Object.defineProperty(self.navigator, 'sendBeacon', { value: blocked }); } catch (e) { /* absent */ }
}());

const ENGINE = self.CyberDatContainerAudit;
self.postMessage({ type: 'ready', engine: ENGINE.ENGINE });

self.onmessage = function (event) {
	const msg = event.data || {};
	const jobId = msg.jobId;
	try {
		const started = Date.now();
		const files = Array.isArray(msg.files) ? msg.files.map(f => ({ name: String(f.name || ''), text: String(f.text || ''), kind: String(f.kind || 'auto') })) : [];
		self.postMessage({ type: 'progress', jobId, done: 1, total: 3 });
		const result = ENGINE.auditFiles(files);
		self.postMessage({ type: 'progress', jobId, done: 2, total: 3 });
		const report = ENGINE.exportReport(result, { timestamp: new Date().toISOString() });
		self.postMessage({ type: 'result', jobId, result, report, elapsedMs: Date.now() - started, chars: files.reduce((n, f) => n + f.text.length, 0) });
	} catch (error) {
		self.postMessage({ type: 'error', jobId, code: error.code || 'FAILED', message: String(error.message || error) });
	}
};
