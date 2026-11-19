/*!
 * CyberDat Email Header Analyzer: background worker.
 * Loads the Public Suffix List data file and the engine from this site, then disables network-capable APIs (defence in
 * depth; the page Content Security Policy also sets connect-src 'none'). Headers are read as text only: no DNS, WHOIS,
 * reputation or signature lookups are made.
 */
'use strict';

(function () {
	const params = new URLSearchParams(self.location.search);
	const ev = (params.get('ev') || '').replace(/[^0-9A-Za-z._-]/g, '');
	const pv = (params.get('pv') || '').replace(/[^0-9A-Za-z._-]/g, '');
	importScripts('psl-data.js' + (pv ? '?ver=' + encodeURIComponent(pv) : ''), 'engine.js' + (ev ? '?ver=' + encodeURIComponent(ev) : ''));
	const blocked = function () { throw new Error('Network access is disabled in the header analyzer worker.'); };
	for (const name of ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'importScripts', 'WebTransport']) {
		try { Object.defineProperty(self, name, { value: blocked, writable: false, configurable: false }); } catch (e) { /* absent */ }
	}
	try { Object.defineProperty(self.navigator, 'sendBeacon', { value: blocked }); } catch (e) { /* absent */ }
}());

const ENGINE = self.CyberDatEmailHeaders;
self.postMessage({ type: 'ready', engine: ENGINE.ENGINE, psl: !!(self.CyberDatPSL && self.CyberDatPSL.commit) });

self.onmessage = function (event) {
	const msg = event.data || {};
	const jobId = msg.jobId;
	try {
		const started = Date.now();
		self.postMessage({ type: 'progress', jobId, done: 1, total: 3 });
		const result = ENGINE.analyze(String(msg.text || ''), { own: String(msg.own || '') });
		self.postMessage({ type: 'progress', jobId, done: 2, total: 3 });
		const ts = new Date().toISOString();
		const reports = {};
		for (const [k, o] of [['none', {}], ['r', { maskRecipients: true }], ['i', { maskInternal: true }], ['ri', { maskRecipients: true, maskInternal: true }]]) { reports[k] = ENGINE.exportReport(result, Object.assign({ timestamp: ts }, o)); }
		self.postMessage({ type: 'result', jobId, result, reports, elapsedMs: Date.now() - started, chars: String(msg.text || '').length });
	} catch (error) {
		self.postMessage({ type: 'error', jobId, code: error.code || 'FAILED', message: String(error.message || error) });
	}
};
