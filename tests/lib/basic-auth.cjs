/*
 * Optional HTTP Basic Auth for browser tests against a protected staging site.
 * Set CYBERDAT_BASIC_AUTH_FILE to a file that contains one line "user:password" (mode 0600, outside the repository).
 * The value is never printed or written to evidence files. Without the variable the tests behave as before.
 */
'use strict';
const fs = require('node:fs');

function credentials() {
	const file = process.env.CYBERDAT_BASIC_AUTH_FILE;
	if (!file) { return null; }
	const line = fs.readFileSync(file, 'utf8').split(/\r?\n/)[0];
	const i = line.indexOf(':');
	if (i < 1) { throw new Error('CYBERDAT_BASIC_AUTH_FILE must contain "user:password" on the first line'); }
	return { username: line.slice(0, i), password: line.slice(i + 1) };
}

/** Chrome/Edge over CDP: answer Basic Auth challenges for the page session; the browser caches them for the origin. */
async function enableCdp(cdp, sessionId) {
	const c = credentials();
	if (!c) { return false; }
	cdp.on(msg => {
		if (msg.sessionId !== sessionId) { return; }
		if (msg.method === 'Fetch.requestPaused') { cdp.send('Fetch.continueRequest', { requestId: msg.params.requestId }, sessionId).catch(() => {}); }
		if (msg.method === 'Fetch.authRequired') { cdp.send('Fetch.continueWithAuth', { requestId: msg.params.requestId, authChallengeResponse: { response: 'ProvideCredentials', username: c.username, password: c.password } }, sessionId).catch(() => {}); }
	});
	await cdp.send('Fetch.enable', { handleAuthRequests: true, patterns: [{ urlPattern: '*' }] }, sessionId);
	return true;
}

/** Playwright context option. */
function playwrightOptions() {
	const c = credentials();
	return c ? { httpCredentials: c } : {};
}

module.exports = { credentials, enableCdp, playwrightOptions };
