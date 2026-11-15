/*!
 * CyberDat MITRE ATLAS Attack Vector Mapper: background worker.
 * Loads the MITRE ATLAS snapshot and the engine from this site, then disables network-capable APIs (defence in depth;
 * the page Content Security Policy also sets connect-src 'none'). No model, MITRE site or other service is contacted.
 */
'use strict';

(function () {
	const params = new URLSearchParams(self.location.search);
	const clean = v => (v || '').replace(/[^0-9A-Za-z._-]/g, '');
	const ev = clean(params.get('ev'));
	const dv = clean(params.get('dv'));
	importScripts('atlas-data.js' + (dv ? '?ver=' + encodeURIComponent(dv) : ''), 'engine.js' + (ev ? '?ver=' + encodeURIComponent(ev) : ''));

	const blocked = function () { throw new Error('Network access is disabled in the ATLAS mapper worker.'); };
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

const ENGINE = self.CyberDatAtlasMapper;

self.onmessage = function (event) {
	const msg = event.data || {};
	const jobId = msg.jobId;
	let lastReport = 0;
	const hooks = {
		onProgress(done, total) {
			const now = Date.now();
			if (now - lastReport > 100 || done === total) {
				lastReport = now;
				self.postMessage({ type: 'progress', jobId, done, total });
			}
		}
	};
	try {
		const started = Date.now();
		let result;
		if (msg.type === 'profile') { result = ENGINE.profile(msg.properties || [], hooks); }
		else if (msg.type === 'finding') { result = ENGINE.mapFinding(String(msg.text || ''), hooks); }
		else if (msg.type === 'search') { result = { mode: 'search', results: ENGINE.search(String(msg.query || '')) }; }
		else if (msg.type === 'lookup') { result = { mode: 'lookup', found: ENGINE.lookup(String(msg.id || '')) }; }
		else if (msg.type === 'export') { result = Object.assign({ mode: 'export', kind: msg.kind }, ENGINE.exportSelection(msg.selection || [], { timestamp: msg.timestamp })); }
		else { return; }
		result.type = 'result';
		result.jobId = jobId;
		result.elapsedMs = Date.now() - started;
		self.postMessage(result);
	} catch (error) {
		self.postMessage({ type: 'error', jobId, code: error.code || 'FAILED', message: String(error.message || error) });
	}
};
