/* Engine unit tests: pure Node.js, no browser, network or dependencies. Run: node tests/log-anonymizer-engine.test.cjs */
'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/log-anonymizer/engine.js'));

let passed = 0;
function check(label, fn) {
	try { fn(); } catch (e) { console.error('FAIL: ' + label); throw e; }
	passed++;
	console.log('PASS: ' + label);
}

function only(category, extra) {
	const categories = {};
	for (const c of engine.CATEGORIES) { categories[c.id] = c.id === category || c.id === 'custom'; }
	return Object.assign({ categories }, extra || {});
}
const run = (text, options) => engine.anonymize(text, options || {});
const out = (text, options) => run(text, options).output;

/** Assert each positive sample is fully replaced and each negative sample is untouched. */
function category(id, prefix, positives, negatives, extra) {
	check(`${id}: ${positives.length} positive samples detected`, () => {
		for (const [line, secret] of positives) {
			const r = run(line, only(id, extra));
			assert.ok(!r.output.includes(secret), `${id} leaked "${secret}" in: ${r.output}`);
			assert.match(r.output, new RegExp('(?<![A-Z_])' + prefix + '_\\d+(?![0-9])'), `${id} label missing in: ${r.output}`);
		}
	});
	check(`${id}: ${negatives.length} negative samples unchanged`, () => {
		for (const line of negatives) {
			assert.equal(out(line, only(id, extra)), line, `${id} false positive`);
		}
	});
}

// ---------------------------------------------------------------- categories

category('ipv4', 'IPV4', [
	['connect from 203.0.113.7 port 22', '203.0.113.7'],
	['src=198.51.100.255:443', '198.51.100.255'],
	['route 10.1.2.0/24 via 10.1.2.1.', '10.1.2.1'],
	['"ip":"192.0.2.10"', '192.0.2.10'],
	['X-Forwarded-For: 203.0.113.7, 198.51.100.9', '198.51.100.9'],
	['bare 1.2.3.4 without context is still an address', '1.2.3.4']
], [
	'version 1.2.3.4', 'v1.2.3.4', 'Version: 2.0.0.1', 'build=1.2.3.4', 'release 4.3.2.1', 'firmware 1.0.0.12',
	'1.2.3.4.5 five parts', '256.1.1.1 out of range', '01.02.03.04 leading zeros', 'Chrome/120.0.6099.109',
	'10.0.19045.1 windows build', 'pi 3.14159', 'Chrome/120.0.0.0', 'Edg/120.0.0.0', 'app_version=1.2.3.4', '{"version":"1.2.3.4"}',
	'listen 0.0.0.0:80', 'netmask 255.255.255.0', 'broadcast-all 255.255.255.255'
]);

category('ipv6', 'IPV6', [
	['client 2001:db8::1 connected', '2001:db8::1'],
	['fe80::1ff:fe23:4567:890a%eth0 link', 'fe80::1ff:fe23:4567:890a'],
	['full 2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'],
	['mapped ::ffff:192.0.2.128 here', '192.0.2.128'],
	['loopback ::1 only', '::1'],
	['url http://[2001:db8::7]:8080/', '2001:db8::7']
], [
	'time 10:20:30:40 elapsed', '12:30:45', 'std::vector<int>', 'Foo::Bar::baz', 'a::b',
	'mac 00:1A:2B:3C:4D:5E', 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'ratio 1:2:3'
]);

category('email', 'EMAIL', [
	['from alice@example.com', 'alice@example.com'],
	['<bob.smith+logs@mail.example.co.uk>', 'bob.smith+logs@mail.example.co.uk'],
	['"email":"Carol_99@Example.ORG"', 'Carol_99@Example.ORG'],
	['upn jdoe@corp.local', 'jdoe@corp.local']
], [
	'git@ without domain', 'user@localhost', 'decorator @property', 'npm i @types/node', 'price 5@3', 'a@b'
]);

category('mac', 'MAC', [
	['hw 00:1A:2B:3C:4D:5E', '00:1A:2B:3C:4D:5E'],
	['hw 00-1a-2b-3c-4d-5e', '00-1a-2b-3c-4d-5e'],
	['cisco 001a.2b3c.4d5e', '001a.2b3c.4d5e']
], [
	'time 10:20:30:40', '00:1A:2B:3C:4D', 'mixed 00:1A-2B:3C:4D:5E', '00:1A:2B:3C:4D:5E:6F', 'uuid 550e8400-e29b-41d4-a716-446655440000'
]);

category('jwt', 'JWT', [
	['token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0'],
	['alg none eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.', 'eyJzdWIiOiJhIn0']
], [
	'eyJ not a token', 'header.payload.signature', 'eyJabc.def.ghi'
]);

category('auth', '(?:BEARER_TOKEN|BASIC_AUTH|AUTH_TOKEN)', [
	['Authorization: Bearer abc123.def456-ghi789', 'abc123.def456-ghi789'],
	['curl -H "Authorization: Basic dXNlcjpwYXNzd29yZA==" https://x', 'dXNlcjpwYXNzd29yZA=='],
	['Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b', '9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b'],
	['{"authorization":"ApiKey s3cr3tvalue"}', 's3cr3tvalue'],
	['Proxy-Authorization: Digest username="bob", response="6629fae49393a05397450978507c4ef1"', '6629fae49393a05397450978507c4ef1']
], [
	'Basic authentication failed for request', 'Bearer token expired', 'Use Basic or Bearer schemes', 'Authorization: -'
]);

category('apiKey', 'API_KEY', [
	['aws AKIAIOSFODNN7EXAMPLE', 'AKIAIOSFODNN7EXAMPLE'],
	['gh ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789', 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'],
	['pat github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuv', 'github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuv'],
	['slack xoxb-1234567890-abcdefghijkl', 'xoxb-1234567890-abcdefghijkl'],
	// Assembled at runtime so repository secret scanners do not flag a fake key.
	['stripe ' + ['sk', 'live', 'FAKE0TEST0ONLY0abcdefgh'].join('_'), ['sk', 'live', 'FAKE0TEST0ONLY0abcdefgh'].join('_')],
	['google AIzaSyA1234567890abcdefghijklmnopqrstuv', 'AIzaSyA1234567890abcdefghijklmnopqrstuv'],
	['openai sk-proj-abcdefghij1234567890ABCDEFGHIJklmnop', 'sk-proj-abcdefghij1234567890ABCDEFGHIJklmnop'],
	['anthropic sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345', 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345'],
	['gitlab glpat-abcdefghij0123456789', 'glpat-abcdefghij0123456789'],
	['webhook https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX', 'XXXXXXXXXXXXXXXX'],
	['DefaultEndpointsProtocol=https;AccountName=x;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;', 'Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq']
], [
	'AKIA too short', 'sk-learn-pipeline-config-version', 'task-0123456789abcdefghij', 'ghp_short', 'risk-assessment-report-2026-final-v2'
]);

category('secret', '(?:SECRET|COOKIE)', [
	['password=hunter2', 'hunter2'],
	['db_password: "c0rrect horse"', 'c0rrect horse'],
	['{"client_secret":"abcXYZ123"}', 'abcXYZ123'],
	["api_key='k-123-456'", 'k-123-456'],
	['GET /cb?access_token=tok987&state=1', 'tok987'],
	['X-Api-Key: 0f1e2d3c4b5a', '0f1e2d3c4b5a'],
	['<password>Sup3r</password>', 'Sup3r'],
	['Cookie: sessionid=7f3c9a1b2d4e; csrftoken=Zx9', 'Zx9'],
	['Set-Cookie: SID=31d4d96e407aad42; Path=/; Secure', '31d4d96e407aad42'],
	['postgres://app:Pa55w0rd@db.example.com/prod', 'Pa55w0rd'],
	['secret => "rails-secret"', 'rails-secret'],
	['PASSWD=letmein', 'letmein']
], [
	'token_count=5', 'password_policy=strict', 'password_required: true', 'password=', 'password: ***', 'secret_type=aws',
	'token_expires_in=3600', 'password=null', 'password=REDACTED_SECRET', 'max_tokens=512', 'compass=north', 'bypass=1'
]);

category('privateKey', 'PRIVATE_KEY', [
	['-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAzYxExampleKeyBody0123456789\nabcdefghijklmnopqrstuvwxyz0123456789+/==\n-----END RSA PRIVATE KEY-----', 'MIIEowIBAAKCAQEAzYxExampleKeyBody0123456789'],
	['{"key":"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\n-----END PRIVATE KEY-----\\n"}', 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC'],
	['-----BEGIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\r\n-----END OPENSSH PRIVATE KEY-----', 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ'],
	['truncated:\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBexampleTruncatedBody0123\nnext log line', 'MHcCAQEEIBexampleTruncatedBody0123']
], [
	'-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkq\n-----END CERTIFICATE-----',
	'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----'
]);

category('username', 'USER', [
	['Accepted password for alice from 203.0.113.7 port 22 ssh2', 'alice'],
	['Failed password for invalid user oracle from 203.0.113.7', 'oracle'],
	['pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)', 'deploy'],
	['sudo:    carol : TTY=pts/0 ; PWD=/root', 'carol'],
	['user=bob.smith action=login', 'bob.smith'],
	['"username": "Dave Jones"', 'Dave Jones'],
	['open /home/erin/.bashrc', 'erin'],
	['C:\\Users\\frank\\AppData\\Local', 'frank'],
	['"path":"C:\\\\Users\\\\grace\\\\Desktop"', 'grace'],
	['logon CORP\\heidi succeeded', 'heidi'],
	['<Data Name="TargetUserName">ivan</Data>', 'ivan'],
	['Account Name:\t\tjudy', 'judy'],
	['suser=mallory', 'mallory']
], [
	'user_agent=Mozilla/5.0', 'userId=12345', 'user_count=7', 'C:\\Users\\Public\\Documents', '/home/', 'HKLM\\Software\\Vendor',
	'C:\\Program Files\\Common Files', 'username=-', 'NT AUTHORITY\\SYSTEM'
]);

category('host', 'HOST', [
	['GET https://api.example.com/v1/users', 'api.example.com'],
	['resolve db01.corp.example.com failed', 'db01.corp.example.com'],
	['Nov 11 10:00:01 web-01 sshd[2211]: msg', 'web-01'],
	['<34>1 2026-11-11T22:14:15.003Z mymachine.example.com su - ID47 - msg', 'mymachine.example.com'],
	['host=ws042 status=up', 'ws042'],
	['"hostname":"LAPTOP-7Q2R"', 'LAPTOP-7Q2R'],
	['Host: intranet.local', 'intranet.local'],
	['Visit cyberdat.eu.', 'cyberdat.eu'],
	['svc kube-dns.kube-system.svc.cluster.local', 'kube-dns.kube-system.svc.cluster.local'],
	['<Data Name="WorkstationName">WS-0042</Data>', 'WS-0042']
], [
	'config.json', 'app.py', 'index.html', 'java.lang.NullPointerException', 'System.out.println', 'user.id', 'user.name',
	'com.example.service.UserService', 'Thread.run', 'readme.md', 'model.ai', 'Safari.app', 'archive.zip', 'nginx.conf',
	'/var/log/nginx/access.log', 'v1.2.3', 'Server: nginx/1.18.0', 'host=localhost', 'machine: x86_64', 'node: v18.0.0'
]);

category('card', 'CARD', [
	['visa 4111111111111111', '4111111111111111'],
	['spaced 4111 1111 1111 1111', '4111 1111 1111 1111'],
	['dashed 5555-5555-5555-4444', '5555-5555-5555-4444'],
	['amex 378282246310005', '378282246310005'],
	['amex grouped 3782 822463 10005', '3782 822463 10005'],
	['discover 6011111111111117 end', '6011111111111117']
], [
	'luhn fail 4111111111111112', 'unix ms 1731340800123', 'order 1234567890123456', 'repeated 4444444444444444',
	'mixed seps 4111-1111 1111-1111', 'phone +1 555 123 4567', 'bank 0000111122223333', 'singles 4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1'
]);

category('ssn', 'SSN', [
	['ssn 123-45-6789', '123-45-6789'],
	['"ssn":"078-05-1120"', '078-05-1120']
], [
	'000-12-3456', '666-12-3456', '900-12-3456', '123-00-4567', '123-45-0000', '123456789', '2026-11-1234', '555-123-4567', '1123-45-6789'
]);

// ---------------------------------------------------------------- false-positive corpus

check('false-positive corpus: versions, timestamps, hashes and identifiers stay unchanged with every category enabled', () => {
	const corpus = fs.readFileSync(path.join(__dirname, 'fixtures/log-anonymizer/false-positives.txt'), 'utf8');
	const r = run(corpus);
	if (r.output !== corpus) {
		const a = corpus.split('\n');
		const b = r.output.split('\n');
		const diff = a.map((l, i) => l !== b[i] ? `  - ${l}\n  + ${b[i]}` : null).filter(Boolean).join('\n');
		assert.fail('False positives:\n' + diff);
	}
	assert.ok(corpus.split('\n').length > 40, 'corpus has meaningful size');
});

// ---------------------------------------------------------------- structure

// ":" is excluded on purpose: it is part of IPv6/MAC values that are replaced.
function skeleton(text) { return text.replace(/[^\n\r\t,;|"'{}\[\]=<>]/g, ''); }

check('structure: realistic multi-format log keeps line count, CRLF and every delimiter', () => {
	const log = fs.readFileSync(path.join(__dirname, 'fixtures/log-anonymizer/mixed.log'), 'utf8');
	const r = run(log);
	assert.notEqual(r.output, log, 'something was replaced');
	assert.equal(r.output.split('\n').length, log.split('\n').length);
	assert.equal((r.output.match(/\r/g) || []).length, (log.match(/\r/g) || []).length);
	// Private key body lines are values themselves (base64 "=" padding is not a delimiter).
	const inKey = [];
	let open = false;
	log.split('\n').forEach((l, i) => { if (/-----END /.test(l)) { open = false; } inKey[i] = open; if (/-----BEGIN /.test(l)) { open = true; } });
	const outside = s => s.split('\n').filter((_, i) => !inKey[i]).join('\n');
	assert.equal(skeleton(outside(r.output)), skeleton(outside(log)), 'delimiter skeleton identical');
	r.output.split('\n').forEach((l, i) => { if (inKey[i]) { assert.match(l, /^PRIVATE_KEY_1$/); } });
	assert.ok(r.output.includes('|cvv=SECRET_') && r.output.includes('|ssn=SSN_1'), 'pipe-delimited fields are separate values');
	for (const [i, line] of log.split('\n').entries()) {
		const o = r.output.split('\n')[i];
		const fields = s => s.split(/[,|\t]/).length;
		assert.equal(fields(o), fields(line), `field count line ${i + 1}`);
	}
});

check('structure: CRLF, BOM, empty lines, trailing newline and tabs survive', () => {
	const text = '\uFEFFa=1\r\n\r\nip\t203.0.113.1\r\npassword=x\r\n';
	const r = run(text);
	assert.equal(r.output, '\uFEFFa=1\r\n\r\nip\tIPV4_1\r\npassword=SECRET_1\r\n');
	assert.equal(r.lines, 4);
});

check('structure: fuzzed random input never changes line breaks', () => {
	let seed = 42;
	const rnd = n => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
	const pieces = ['203.0.113.', 'user=', 'password=', '@example.com', '\n', '\r\n', ' ', ':', '::', '-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----', 'eyJ', '.', '4111', 'Bearer ', '"', "'", '\\n', 'abc', '42', 'AKIA', '/home/', '\\'];
	for (let round = 0; round < 300; round++) {
		let text = '';
		const len = 20 + rnd(200);
		for (let i = 0; i < len; i++) { text += pieces[rnd(pieces.length)]; }
		const r = run(text);
		assert.equal(r.output.split('\n').length, text.split('\n').length, 'LF count');
		assert.equal(r.output.split('\r').length, text.split('\r').length, 'CR count');
	}
});

check('structure: chunk boundaries do not split private key blocks', () => {
	const key = '-----BEGIN PRIVATE KEY-----\n' + 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n'.repeat(40) + '-----END PRIVATE KEY-----\n';
	const text = 'line 203.0.113.9\n'.repeat(30) + key + 'tail password=zz\n';
	const small = engine.anonymize(text, {}, { chunkChars: 64 });
	const whole = engine.anonymize(text, {});
	assert.equal(small.output, whole.output);
	assert.ok(!small.output.includes('QUJDREVG'));
});

// ---------------------------------------------------------------- real-format corpus

const FORMATS = path.join(__dirname, 'fixtures/log-anonymizer/formats');
const formatSpec = JSON.parse(fs.readFileSync(path.join(FORMATS, 'expected.json'), 'utf8'));
// Shape of parsed JSON: keys and value types, values themselves ignored.
function shape(v) {
	if (Array.isArray(v)) { return v.map(shape); }
	if (v && typeof v === 'object') { return Object.fromEntries(Object.keys(v).map(k => [k, shape(v[k])])); }
	return typeof v;
}
function csvFields(line) {
	let n = 1, q = false;
	for (let i = 0; i < line.length; i++) {
		if (line[i] === '"') { q = !q; } else if (line[i] === ',' && !q) { n++; }
	}
	return n;
}
for (const [file, spec] of Object.entries(formatSpec)) {
	if (file.startsWith('_')) { continue; }
	check(`format ${file}: ${spec.mask.length} sensitive values masked, ${spec.keep.length} context values kept, structure preserved`, () => {
		const input = fs.readFileSync(path.join(FORMATS, file), 'utf8');
		const output = run(input).output;
		for (const m of spec.mask) { assert.ok(!output.includes(m), `${file} leaked "${m}"\n${output}`); }
		for (const k of spec.keep) { assert.ok(output.includes(k), `${file} lost "${k}"\n${output}`); }
		assert.equal(output.split('\n').length, input.split('\n').length, 'LF count');
		assert.equal(output.split('\r').length, input.split('\r').length, 'CR count');
		assert.equal(skeleton(output), skeleton(input), 'delimiter skeleton');
		if (spec.structure === 'json-lines') {
			input.split('\n').forEach((line, i) => { if (line.trim()) { assert.deepEqual(shape(JSON.parse(output.split('\n')[i])), shape(JSON.parse(line)), `JSON shape line ${i + 1}`); } });
		}
		if (spec.structure === 'json-document') {
			assert.deepEqual(shape(JSON.parse(output)), shape(JSON.parse(input)), 'JSON document shape');
		}
		if (spec.structure === 'csv') {
			input.split('\n').forEach((line, i) => assert.equal(csvFields(output.split('\n')[i]), csvFields(line), `CSV fields line ${i + 1}`));
		}
	});
}

check('format corpus: CSV header row is never masked; columns are only used with a consistent header', () => {
	const csv = 'user,host,status\nalice,web01,ok\n';
	assert.equal(out(csv), 'user,host,status\nUSER_1,HOST_1,ok\n');
	const notCsv = 'user,host,status\nfree text line without the same fields\n';
	assert.equal(out(notCsv), notCsv);
});

// ---------------------------------------------------------------- labels

check('stable labels: same value → same label, different values → different labels, numbering in order of appearance', () => {
	const r = run('a 203.0.113.1\nb 203.0.113.2\nc 203.0.113.1\nd ALICE@example.com alice@example.com\n');
	assert.equal(r.output, 'a IPV4_1\nb IPV4_2\nc IPV4_1\nd EMAIL_1 EMAIL_1\n');
	const entry = r.map.find(e => e.label === 'IPV4_1');
	assert.equal(entry.original, '203.0.113.1');
	assert.equal(entry.occurrences, 2);
	assert.equal(r.stats.ipv4.replacements, 3);
	assert.equal(r.stats.ipv4.unique, 2);
});

check('stable labels: consistent across chunk boundaries and across detectors (URL host vs bare FQDN)', () => {
	const text = 'x https://db.example.com/a\n'.repeat(50) + 'y db.example.com\n';
	const r = engine.anonymize(text, {}, { chunkChars: 100 });
	assert.ok(r.output.split('\n').slice(0, -1).every(l => l === 'x https://HOST_1/a' || l === 'y HOST_1'));
});

check('generic labels: REDACTED_<CATEGORY> everywhere', () => {
	assert.equal(out('203.0.113.1 203.0.113.2 bob@example.com', { labelMode: 'generic' }), 'REDACTED_IPV4 REDACTED_IPV4 REDACTED_EMAIL');
});

check('keep private IPv4 ranges option', () => {
	const line = '10.1.2.3 172.16.0.1 172.32.0.1 192.168.1.1 127.0.0.1 169.254.1.1 203.0.113.1';
	assert.equal(out(line, { keepPrivateIPv4: true }), '10.1.2.3 172.16.0.1 IPV4_1 192.168.1.1 127.0.0.1 169.254.1.1 IPV4_2');
	assert.equal(out(line), 'IPV4_1 IPV4_2 IPV4_3 IPV4_4 IPV4_5 IPV4_6 IPV4_7');
});

check('disabled categories are left untouched', () => {
	const line = 'ip=203.0.113.1 mail=a@example.com password=x';
	const categories = Object.fromEntries(engine.CATEGORIES.map(c => [c.id, false]));
	assert.equal(out(line, { categories }), line);
	categories.email = true;
	assert.equal(out(line, { categories }), 'ip=203.0.113.1 mail=EMAIL_1 password=x');
});

check('priority: JWT inside Bearer keeps JWT label; email inside user= keeps EMAIL label', () => {
	const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl';
	assert.equal(out(`Authorization: Bearer ${jwt}\nraw ${jwt}`), 'Authorization: Bearer JWT_1\nraw JWT_1');
	assert.equal(out('user=bob@example.com to=bob@example.com'), 'user=EMAIL_1 to=EMAIL_1');
});

check('replacement map lists originals once per unique value', () => {
	const r = run('password=a\npassword=a\npassword=b\n');
	assert.deepEqual(r.map.map(e => [e.label, e.original, e.occurrences]), [['SECRET_1', 'a', 2], ['SECRET_2', 'b', 1]]);
});

// ---------------------------------------------------------------- custom rules

check('custom rules: matches replaced with the custom label and run before built-ins', () => {
	const r = run('ticket EMP-12345 and emp-99999 at 203.0.113.1', { customRules: [{ pattern: 'EMP-\\d{5}', label: 'EMPLOYEE', caseInsensitive: true }] });
	assert.equal(r.output, 'ticket EMPLOYEE_1 and EMPLOYEE_2 at IPV4_1');
	assert.equal(r.stats.custom.replacements, 2);
});

check('custom rules: invalid regex, empty match, bad label and too many rules are rejected with messages', () => {
	const cases = [
		[{ pattern: '(', label: 'X' }, /Invalid regular expression/],
		[{ pattern: 'a*', label: 'X' }, /empty string/],
		[{ pattern: '', label: 'X' }, /Enter a regular expression/],
		[{ pattern: 'a', label: 'lower' }, /uppercase/],
		[{ pattern: 'a', label: 'REDACTED_X' }, /REDACTED_/],
		[{ pattern: 'a'.repeat(1001), label: 'X' }, /longer than/]
	];
	for (const [rule, message] of cases) {
		assert.throws(() => run('abc', { customRules: [rule] }), err => err.code === 'CUSTOM_RULE' && message.test(err.message));
	}
	const many = Array.from({ length: 21 }, () => ({ pattern: 'a', label: 'X' }));
	assert.throws(() => run('a', { customRules: many }), /maximum of 20/);
});

check('custom rules: multi-line matches are skipped and counted, structure preserved', () => {
	const r = run('a\nb\n', { customRules: [{ pattern: 'a\\nb', label: 'X' }] });
	assert.equal(r.output, 'a\nb\n');
	assert.equal(r.warnings.multilineCustom, 1);
});

// ---------------------------------------------------------------- robustness

check('malformed input: non-string rejected, empty string allowed', () => {
	assert.throws(() => engine.anonymize(null, {}), TypeError);
	assert.equal(run('').output, '');
});

check('ReDoS guard: 1 MB pathological inputs finish quickly for every detector', () => {
	const evil = ['a'.repeat(1 << 20), '.'.repeat(1 << 20), ':'.repeat(1 << 20), '1.'.repeat(1 << 19), 'a.'.repeat(1 << 19),
		'a@'.repeat(1 << 19), '-'.repeat(1 << 20), '1 '.repeat(1 << 19), 'password='.repeat(1 << 16), '"'.repeat(1 << 20),
		'-----BEGIN PRIVATE KEY-----'.repeat(1 << 15), 'ab:'.repeat(1 << 18), '\\'.repeat(1 << 20), 'eyJ'.repeat(1 << 18) + '.',
		'<a>'.repeat(1 << 18), 'Authorization: '.repeat(1 << 16), 'Cookie: a=b'.repeat(1 << 16), 'x://'.repeat(1 << 18)];
	for (const text of evil) {
		const t = Date.now();
		const r = run(text);
		const ms = Date.now() - t;
		assert.ok(ms < 4000, `pathological input "${text.slice(0, 12)}…" took ${ms} ms`);
		assert.equal(r.output.split('\n').length, text.split('\n').length);
	}
});

check('large input: ~30 MB realistic log processed with stable labels and preserved lines', () => {
	const base = fs.readFileSync(path.join(__dirname, 'fixtures/log-anonymizer/mixed.log'), 'utf8').replace(/\r/g, '');
	let text = '';
	let i = 0;
	while (text.length < 30 * 1024 * 1024) {
		text += base.replace(/203\.0\.113\.\d+/g, () => '198.51.' + ((i >> 8) & 255) + '.' + (i++ & 255));
	}
	const t = Date.now();
	let progressCalls = 0;
	const r = engine.anonymize(text, {}, { onProgress: () => { progressCalls++; } });
	const ms = Date.now() - t;
	assert.equal(r.output.split('\n').length, text.split('\n').length);
	assert.ok(progressCalls >= 25, 'progress reported per chunk');
	assert.ok(r.preview.truncated && r.preview.text.length === 200000);
	assert.ok(ms < 120000, `took ${ms} ms`);
	console.log(`      ${(text.length / 1048576).toFixed(1)} MB, ${r.lines} lines in ${(ms / 1000).toFixed(1)} s (Node ${process.version})`);
});

check('preview spans point at labels in the output', () => {
	const r = run('a 203.0.113.1 b password=x');
	for (const [s, e, c] of r.preview.spans) {
		assert.match(r.preview.text.slice(s, e), /^[A-Z][A-Z0-9_]*_\d+$/);
		assert.ok(['ipv4', 'secret'].includes(c));
	}
	assert.equal(r.preview.spans.length, 2);
});

check('engine source uses no network, storage, DOM or eval APIs', () => {
	const dir = path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/log-anonymizer');
	const banned = /\b(?:fetch|XMLHttpRequest|WebSocket|sendBeacon|EventSource|localStorage|sessionStorage|indexedDB|document\.cookie|innerHTML|outerHTML|insertAdjacentHTML|eval|Function\(|history\.(?:push|replace)State|location\.(?:hash|search)\s*=)\b/;
	const engineSrc = fs.readFileSync(path.join(dir, 'engine.js'), 'utf8');
	assert.ok(!banned.test(engineSrc.replace(/\/\*[\s\S]*?\*\//g, '')), 'engine.js');
	const appSrc = fs.readFileSync(path.join(dir, 'app.js'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
	assert.ok(!banned.test(appSrc), 'app.js');
	const workerSrc = fs.readFileSync(path.join(dir, 'worker.js'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
	assert.ok(!/localStorage|sessionStorage|indexedDB|innerHTML|\bfetch\(/.test(workerSrc), 'worker.js');
	// Only documentation-domain URLs inside the built-in sample log may appear.
	const hosts = [...(appSrc + workerSrc + engineSrc).matchAll(/https?:\/\/(?:[^\s@\/'"]+@)?([A-Za-z0-9.-]+)/g)].map(m => m[1]);
	assert.ok(hosts.every(h => /(?:^|\.)example\.(?:com|org|net)$/.test(h)), 'no non-documentation absolute URLs: ' + hosts.join(', '));
});

check('PHP category list matches engine categories and versions', () => {
	const php = fs.readFileSync(path.join(__dirname, '../wp-content/themes/cyberdat/inc/tool-log-anonymizer.php'), 'utf8');
	const ids = [...php.matchAll(/^\t\t'([A-Za-z0-9]+)'\s+=> array\( 'label'/gm)].map(m => m[1]);
	assert.deepEqual(ids, engine.CATEGORIES.map(c => c.id).filter(id => id !== 'custom'));
	assert.ok(php.includes(`CYBERDAT_LOG_ANONYMIZER_ENGINE = '${engine.VERSION}'`));
	assert.ok(php.includes(`CYBERDAT_LOG_ANONYMIZER_RULESET = '${engine.RULESET_VERSION}'`));
});

console.log(`\n${passed} checks passed.`);
