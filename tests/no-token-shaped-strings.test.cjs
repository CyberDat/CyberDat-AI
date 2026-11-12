/*
 * Guard: tracked files must not contain token-shaped strings that repository secret scanners report
 * (GitHub Secret Scanning, gitleaks, trufflehog). Synthetic test values live in tests/lib/synthetic-secrets.cjs,
 * assembled from short pieces, and fixtures use {{SYNTH:NAME}} placeholders filled in at test time.
 * A failure here means a new token-shaped string was committed: replace it the same way (do NOT add an exclusion
 * to secret scanning). If it might be a real credential, treat it as a leak: report it so it can be revoked.
 * Output shows file, line, rule, the first 4 characters and the length only: values are never printed.
 *   node tests/no-token-shaped-strings.test.cjs
 */
'use strict';
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const RULES = [
	['aws-access-key-id', /(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}/],
	['aws-unique-id', /(?<![A-Z0-9])(?:AIDA|AROA|AGPA|ANPA|ANVA|AIPA|APKA)[A-Z0-9]{16,}(?![A-Z0-9])/],
	['aws-secret-example', /[A-Za-z0-9/+]{20,40}EXAMPLEKEY/],
	['google-api-key', /AIza[0-9A-Za-z_-]{35}/],
	['github-token', /\bgh[pousr]_[0-9A-Za-z]{30,}/],
	['github-fine-grained-pat', /\bgithub_pat_[0-9A-Za-z_]{40,}/],
	['gitlab-pat', /\bglpat-[0-9A-Za-z_-]{20}/],
	['slack-token', /\bxox[abposr]-[0-9A-Za-z-]{10,}/],
	['slack-webhook', /hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9+/]{20,}/],
	['openai-key', /(?<![A-Za-z0-9])sk-(?:proj-|svcacct-|admin-)?(?=[A-Za-z_-]{0,40}[0-9])[A-Za-z0-9_-]{20,}/],
	['anthropic-key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
	['stripe-key', /\b[rs]k_(?:live|test)_[0-9A-Za-z]{10,}/],
	['azure-storage-key', /AccountKey=[A-Za-z0-9+/]{40,}={0,2}/],
	['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{5,}\./],
	['private-key', /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/],
	['npm-token', /\bnpm_[A-Za-z0-9]{36}\b/],
	['sendgrid-key', /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/],
	['google-oauth-token', /\bya29\.[0-9A-Za-z_-]{20,}/]
];

const files = execFileSync('git', ['ls-files', '-z'], { cwd: ROOT, maxBuffer: 1 << 28 }).toString().split('\0').filter(Boolean);
const findings = [];
let scanned = 0;
for (const f of files) {
	const full = path.join(ROOT, f);
	let buf;
	try { buf = fs.readFileSync(full); } catch (e) { continue; }
	if (buf.includes(0)) { continue; } // binary
	scanned++;
	const lines = buf.toString('utf8').split('\n');
	lines.forEach((line, i) => {
		for (const [rule, re] of RULES) {
			if (rule === 'aws-secret-example' && !line.includes('EXAMPLEKEY')) { continue; }
			const m = line.match(re);
			if (m) { findings.push(`${f}:${i + 1} ${rule} ${m[0].slice(0, 4)}… len=${m[0].length}`); }
		}
	});
}

// Self-test: every rule must still detect the synthetic values, so a broken regex cannot pass silently.
const { SYNTH } = require('./lib/synthetic-secrets.cjs');
const expectHit = {
	'aws-access-key-id': ['AWS_ACCESS_KEY_ID', 'AWS_TEMP_ACCESS_KEY_ID'], 'aws-unique-id': ['AWS_IAM_USER_ID', 'AWS_ROLE_ID'],
	'aws-secret-example': ['AWS_SECRET_ACCESS_KEY'], 'google-api-key': ['GOOGLE_API_KEY'], 'github-token': ['GITHUB_PAT'],
	'github-fine-grained-pat': ['GITHUB_PAT_FINE'], 'gitlab-pat': ['GITLAB_PAT'], 'slack-token': ['SLACK_BOT_TOKEN'],
	'slack-webhook': ['SLACK_WEBHOOK_URL'], 'openai-key': ['OPENAI_PROJECT_KEY'], 'anthropic-key': ['ANTHROPIC_API_KEY'],
	'azure-storage-key': [], 'jwt': ['JWT'], 'private-key': []
};
const selfFail = [];
for (const [rule, names] of Object.entries(expectHit)) {
	const re = RULES.find(r => r[0] === rule)[1];
	for (const n of names) { if (!re.test(SYNTH[n])) { selfFail.push(rule + ' misses ' + n); } }
}
if (!RULES.find(r => r[0] === 'azure-storage-key')[1].test('AccountKey=' + SYNTH.AZURE_STORAGE_KEY)) { selfFail.push('azure-storage-key misses AZURE_STORAGE_KEY'); }
if (!RULES.find(r => r[0] === 'private-key')[1].test(SYNTH.PEM_BEGIN + ' RSA PRIVATE KEY-----')) { selfFail.push('private-key misses PEM header'); }

if (selfFail.length) { console.error('FAIL: scanner self-test\n  ' + selfFail.join('\n  ')); process.exit(1); }
console.log(`PASS: scanner self-test: ${Object.keys(expectHit).length} rules detect the synthetic values`);
if (findings.length) {
	console.error(`FAIL: ${findings.length} token-shaped string(s) in ${scanned} tracked text files:\n  ` + findings.join('\n  '));
	process.exit(1);
}
console.log(`PASS: no token-shaped strings in ${scanned} tracked text files (${RULES.length} rules)`);
