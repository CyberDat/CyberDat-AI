/*
 * Synthetic, token-shaped test values for the Security Tools tests.
 *
 * None of these values is a real credential: they are documentation examples (AWS) or strings
 * written for the tests (sequential digits/letters, "EXAMPLE", "FAKE", obvious payloads).
 * They are assembled at runtime from short pieces so that the repository itself contains
 * nothing a secret scanner (GitHub Secret Scanning, gitleaks, trufflehog) would report, while
 * the detectors under test still see the full token shape.
 *
 * Fixtures refer to these values as {{SYNTH:NAME}}; tests pass fixture text through fill().
 * Do not add real values here. Do not "fix" alerts by excluding tests/ from secret scanning:
 * that would hide a future real leak.
 */
'use strict';

const SYNTH = Object.freeze({
	// JWT, header {"alg":"HS256","typ":"JWT"}, payload {"sub":"bob.smith","iat":1731316132}, signature synthetic
	JWT_6: ['eyJ', 'hbGciOiJ', 'IUzI1NiI', 'sInR5cCI', '6IkpXVCJ', '9.eyJzdW', 'IiOiJib2', 'Iuc21pdG', 'giLCJpYX', 'QiOjE3Mz', 'EzMTYxMz', 'J9.c2lnb', 'mF0dXJlL', 'WZvci1kb', '2NzLW9ub', 'Hk'].join(''),
	// JWT, header {"alg":"RS256","typ":"JWT"}, payload {"sub":"heidi","scope":"pay"}, signature synthetic
	JWT: ['eyJ', 'hbGciOiJ', 'SUzI1NiI', 'sInR5cCI', '6IkpXVCJ', '9.eyJzdW', 'IiOiJoZW', 'lkaSIsIn', 'Njb3BlIj', 'oicGF5In', '0.c2lnbm', 'F0dXJlLW', 'Zvci10ZX', 'N0cy1vbm', 'x5'].join(''),
	// JWT, header {"alg":"HS256"}, payload {"sub":"1234567890"}, signature synthetic
	JWT_3: ['eyJ', 'hbGciOiJ', 'IUzI1NiJ', '9.eyJzdW', 'IiOiIxMj', 'M0NTY3OD', 'kwIn0.do', 'zjgNryP4', 'J3jVmNHl', '0w5N_XgL', '0n3I9PlF', 'UP0THsR8', 'U'].join(''),
	// Azure storage account key: the publicly documented storage emulator (Azurite) key
	AZURE_STORAGE_KEY: ['Eby', '8vdM02xN', 'OcqFlqUw', 'JPLlmEtl', 'CDXJ1OUz', 'FT50uSRZ', '6IFsuFq2', 'UVErCz4I', '6tq/K1SZ', 'FPTOtr/K', 'BHBeksoG', 'MGw=='].join(''),
	// JWT, header {"alg":"HS256"}, payload {"sub":"mia"}, signature synthetic
	JWT_2: ['eyJ', 'hbGciOiJ', 'IUzI1NiJ', '9.eyJzdW', 'IiOiJtaW', 'EifQ.c2l', 'nbmF0dXJ', 'lLWZvci1', '0ZXN0cw'].join(''),
	// Slack incoming webhook URL shape, placeholder IDs
	SLACK_WEBHOOK_URL: ['http', 's://hook', 's.slack.', 'com/serv', 'ices/T00', '0/B000/X', 'XXXXXXXX', 'XXXXXXX'].join(''),
	// GitHub fine-grained PAT shape, synthetic
	GITHUB_PAT_FINE: ['gith', 'ub_pat_1', '1ABCDEFG', '01234567', '89_abcde', 'fghijklm', 'nopqrstu', 'v'].join(''),
	// JWT, header {"alg":"HS256"}, payload {"sub":"1"}, signature synthetic
	JWT_5: ['eyJ', 'hbGciOiJ', 'IUzI1NiJ', '9.eyJzdW', 'IiOiIxIn', '0.c2lnbm', 'F0dXJl'].join(''),
	// Anthropic API key shape, synthetic
	ANTHROPIC_API_KEY: ['sk-a', 'nt-api03', '-abcdefg', 'hijklmno', 'pqrstuvw', 'xyz01234', '5'].join(''),
	// OpenAI project key shape, synthetic
	OPENAI_PROJECT_KEY: ['sk-p', 'roj-abcd', 'efghij12', '34567890', 'ABCDEFGH', 'IJklmnop'].join(''),
	// GitHub classic PAT shape, synthetic
	GITHUB_PAT: ['ghp_', 'aBcDeFgH', 'iJkLmNoP', 'qRsTuVwX', 'yZ012345', '6789'].join(''),
	// Google API key shape: sequential digits and consecutive alphabet letters
	GOOGLE_API_KEY: ['AIza', 'SyA12345', '67890abc', 'defghijk', 'lmnopqrs', 'tuv'].join(''),
	// AWS secret access key: the AWS documentation example with its "/" removed (ends in EXAMPLEKEY)
	AWS_SECRET_ACCESS_KEY: ['wJa', 'lrXUtnFE', 'MIK7MDEN', 'GbPxRfiC', 'YEXAMPLE', 'KEY'].join(''),
	// JWT, header {"alg":"none"}, payload {"sub":"a"}, signature empty (alg none)
	JWT_4: ['eyJ', 'hbGciOiJ', 'ub25lIn0', '.eyJzdWI', 'iOiJhIn0', '.'].join(''),
	// generic X-Api-Key header value, synthetic
	X_API_KEY: ['0f1', 'e2d3c4b5', 'a6978879', '6a5b4c3d', '2e1f0'].join(''),
	// Slack bot token shape, synthetic
	SLACK_BOT_TOKEN: ['xoxb', '-1234567', '890-abcd', 'efghijkl'].join(''),
	// GitLab PAT shape, synthetic
	GITLAB_PAT: ['glpa', 't-abcdef', 'ghij0123', '456789'].join(''),
	// AWS IAM user unique ID shape, synthetic (not a credential: unique IDs are not secret)
	AWS_IAM_USER_ID: ['AIDA', 'J45Q7YFF', 'AREXAMPL', 'E'].join(''),
	// AWS IAM user unique ID shape, synthetic (not a credential: unique IDs are not secret)
	AWS_IAM_USER_ID_2: ['AIDA', 'J45Q7YFF', 'AREXAMPL', '2'].join(''),
	// AWS role unique ID shape, synthetic, contains EXAMPLE (not a credential)
	AWS_ROLE_ID: ['AROA', 'EXAMPLER', 'OLEID123', '4'].join(''),
	// AWS access key ID: the AWS documentation example (ends in EXAMPLE)
	AWS_ACCESS_KEY_ID: ['AKIA', 'IOSFODNN', '7EXAMPLE'].join(''),
	// AWS temporary (STS) access key ID: the AWS documentation example with the ASIA prefix
	AWS_TEMP_ACCESS_KEY_ID: ['ASIA', 'IOSFODNN', '7EXAMPLE'].join(''),
	// HTTP Basic credentials: base64 of a synthetic user:password
	BASIC_AUTH: ['dXN', 'lcjpwYXN', 'zd29yZA=', '='].join(''),
	// generic API key value, synthetic
	GENERIC_API_KEY: ['k_l', 'ive_abc1', '23def456'].join(''),
	// generic OAuth access token value, synthetic
	ACCESS_TOKEN_QUERY: ['tok', '_8f7e6d5', 'c4b3a'].join(''),
	// generic CSRF cookie value, synthetic
	CSRF_TOKEN: ['Zx9', 'Yw8Vu7Ts', '6'].join(''),
	// generic X-Api-Key header value, synthetic
	X_API_KEY_2: ['0f1', 'e2d3c4b5', 'a'].join(''),
	// PEM armour opener; key bodies in the tests are short fake base64
	PEM_BEGIN: ['----', '-BEGIN'].join(''),
	// JWT, header {"alg":"HS256","typ":"JWT"}, payload {"sub":"1234"}, signature synthetic
	PI_BENIGN_JWT: ['eyJ', 'hbGciOiJ', 'IUzI1NiI', 'sInR5cCI', '6IkpXVCJ', '9.eyJzdW', 'IiOiIxMj', 'M0In0.c2', 'lnbmF0dX', 'Jl'].join(''),
});

function fill(text) {
	return String(text).replace(/\{\{SYNTH:([A-Z0-9_]+)\}\}/g, (m, name) => {
		if (!Object.prototype.hasOwnProperty.call(SYNTH, name)) { throw new Error('Unknown synthetic placeholder ' + name); }
		return SYNTH[name];
	});
}

module.exports = { SYNTH, fill };
