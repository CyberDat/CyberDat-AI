#!/usr/bin/env node
/*
 * List the open GitHub Secret Scanning alerts of this repository with file, commit and a verdict "synthetic or not".
 * Read-only: it never closes or changes an alert (the owner does that). It never prints a secret value: the verdict
 * compares the alert value with tests/lib/synthetic-secrets.cjs in memory and prints only the type, the first four
 * characters and the length.
 *
 *   GITHUB_TOKEN=<token with security_events read (classic: repo/security_events; fine-grained: Secret scanning alerts: read)> \
 *     node tools/list-secret-scanning-alerts.cjs [owner/repo] [--state open|resolved|all]
 *
 * The token is read from the environment only and is sent only to api.github.com.
 */
'use strict';
const https = require('node:https');
const path = require('node:path');
const { SYNTH } = require(path.join(__dirname, '../tests/lib/synthetic-secrets.cjs'));

const repo = process.argv.slice(2).find(a => /^[\w.-]+\/[\w.-]+$/.test(a)) || 'CyberDat/CyberDat-AI';
const stateArg = process.argv.indexOf('--state');
const state = stateArg > 0 ? process.argv[stateArg + 1] : 'open';
const token = process.env.GITHUB_TOKEN;
if (!token) { console.error('Set GITHUB_TOKEN (read access to secret scanning alerts).'); process.exit(2); }

function get(p) {
	return new Promise((resolve, reject) => {
		https.get({ host: 'api.github.com', path: p, headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'User-Agent': 'secret-scan-alert-list', 'X-GitHub-Api-Version': '2022-11-28' } }, res => {
			let body = '';
			res.on('data', d => { body += d; });
			res.on('end', () => (res.statusCode === 200 ? resolve({ json: JSON.parse(body), link: res.headers.link || '' }) : reject(new Error(p + ': HTTP ' + res.statusCode + ' ' + body.slice(0, 200)))));
		}).on('error', reject);
	});
}
async function all(p) {
	let out = [], next = p;
	while (next) {
		const { json, link } = await get(next);
		out = out.concat(json);
		const m = link.match(/<https:\/\/api\.github\.com([^>]+)>;\s*rel="next"/);
		next = m ? m[1] : null;
	}
	return out;
}

const synthetic = Object.entries(SYNTH).map(([k, v]) => [k, String(v)]);
// the key header comes from the synthetic set, so this file holds no token-shaped literal
const PEM_BODY = new RegExp(SYNTH.PEM_BEGIN + ' [A-Z ]*PRIVATE KEY-----([\\s\\S]*?)-----END');
function verdict(secret, locations) {
	const s = String(secret || '');
	const hit = synthetic.find(([, v]) => v.length >= 8 && (s === v || s.includes(v) || (s.length >= 12 && v.includes(s))));
	if (hit) { return 'synthetic (tests/lib/synthetic-secrets.cjs ' + hit[0] + ')'; }
	const body = s.match(PEM_BODY);
	if (body) {
		let parsed = false;
		try { require('node:crypto').createPrivateKey(s); parsed = true; } catch (e) { parsed = false; }
		return parsed ? 'NOT SYNTHETIC: parses as a private key — check and rotate' : 'synthetic placeholder (private key block that does not parse as a key)';
	}
	if (locations.length && locations.every(l => /^tests\//.test(l.path || ''))) { return 'probably synthetic (test files only, value not in synthetic-secrets.cjs) — review'; }
	return 'NOT SHOWN TO BE SYNTHETIC — review';
}

(async () => {
	const alerts = await all('/repos/' + repo + '/secret-scanning/alerts?per_page=100' + (state === 'all' ? '' : '&state=' + encodeURIComponent(state)));
	console.log(alerts.length + ' ' + state + ' alert(s) in ' + repo);
	for (const a of alerts) {
		const locs = (await all('/repos/' + repo + '/secret-scanning/alerts/' + a.number + '/locations?per_page=100')).filter(l => l.type === 'commit').map(l => l.details);
		const s = String(a.secret || '');
		console.log('#' + a.number + ' ' + a.secret_type_display_name + ' (' + a.secret_type + '), ' + s.slice(0, 4) + '… (' + s.length + ' characters), state ' + a.state + (a.validity ? ', validity ' + a.validity : '') + ', created ' + a.created_at);
		for (const l of locs) { console.log('    ' + l.path + ':' + l.start_line + ' @ ' + String(l.commit_sha).slice(0, 7)); }
		console.log('    verdict: ' + verdict(a.secret, locs));
	}
})().catch(e => { console.error(String(e.message || e)); process.exit(1); });
