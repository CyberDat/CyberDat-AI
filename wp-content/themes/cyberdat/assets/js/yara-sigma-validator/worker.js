/*!
 * CyberDat YARA/Sigma Rule Validator & Converter: background worker.
 * Loads the engine from this site, then disables network-capable APIs (defence in depth; the page Content Security Policy
 * also sets connect-src 'none'). Rules are analysed as text only: never compiled by YARA, never run against files.
 */
'use strict';

(function () {
	const params = new URLSearchParams(self.location.search);
	const ev = (params.get('ev') || '').replace(/[^0-9A-Za-z._-]/g, '');
	importScripts('engine.js' + (ev ? '?ver=' + encodeURIComponent(ev) : ''));
	const blocked = function () { throw new Error('Network access is disabled in the rule validator worker.'); };
	for (const name of ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'importScripts', 'WebTransport']) {
		try { Object.defineProperty(self, name, { value: blocked, writable: false, configurable: false }); } catch (e) { /* absent */ }
	}
	try { Object.defineProperty(self.navigator, 'sendBeacon', { value: blocked }); } catch (e) { /* absent */ }
}());

const ENGINE = self.CyberDatRuleValidator;
self.postMessage({ type: 'ready', engine: ENGINE.ENGINE });

self.onmessage = function (event) {
	const msg = event.data || {};
	const jobId = msg.jobId;
	try {
		const started = Date.now();
		self.postMessage({ type: 'progress', jobId, done: 1, total: 3 });
		const result = ENGINE.validate(String(msg.text || ''), { kind: msg.kind });
		self.postMessage({ type: 'progress', jobId, done: 2, total: 3 });
		let conversion = null;
		// Any error-level finding blocks the conversion (owner decision 2026-11-21): a rule with errors gives a wrong or empty query.
		if (result.kind === 'sigma' && msg.target && result.counts.error > 0) { conversion = ENGINE.refuseConversion(result, msg.target); }
		else if (result.kind === 'sigma' && msg.target) {
			let fieldmap = {};
			if (msg.fieldmap && String(msg.fieldmap).trim()) {
				try { fieldmap = JSON.parse(String(msg.fieldmap)); } catch (e) { const err = new Error('The field mapping is not valid JSON: ' + e.message); err.code = 'FIELDMAP'; throw err; }
				if (!fieldmap || typeof fieldmap !== 'object' || Array.isArray(fieldmap) || Object.values(fieldmap).some(v => typeof v !== 'string')) { const err = new Error('The field mapping must be a JSON object such as {"Image": "process.executable"}.'); err.code = 'FIELDMAP'; throw err; }
			}
			conversion = ENGINE.convert(String(msg.text || ''), msg.target, fieldmap);
		}
		const report = ENGINE.exportReport(result, conversion, { timestamp: new Date().toISOString() });
		self.postMessage({ type: 'result', jobId, result, conversion, report, elapsedMs: Date.now() - started, chars: String(msg.text || '').length });
	} catch (error) {
		self.postMessage({ type: 'error', jobId, code: error.code || 'FAILED', message: String(error.message || error) });
	}
};
