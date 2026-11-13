/*!
 * CyberDat MCP Security & Policy Checker — analysis engine.
 *
 * Static review of Model Context Protocol client configurations and server tool lists.
 * Contract (enforced by tests):
 *  - input is data: it is parsed by a small JSON/JSONC parser written for this tool, never evaluated,
 *    servers are never started, commands are never run and URLs are never requested;
 *  - no network, storage, DOM or eval APIs (runs in a Web Worker and in Node for tests);
 *  - secret values never leave the engine: findings, summaries and policy results carry only the
 *    kind of secret and a masked fragment (first characters and length);
 *  - every regular expression is linear or bounded, and every scanned text is length-capped.
 * Rules are CyberDat's own wording. Background reading (text references only): the Model Context
 * Protocol specification, sections "Security and Trust & Safety" and "Tools".
 */
(function (root, factory) {
	if (typeof module === 'object' && module.exports) { module.exports = factory(); } else { root.CyberDatMcpChecker = factory(); }
}(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const VERSION = '1.0.0';
	const RULESET_VERSION = '2026-11-13.1';
	const MAX_INPUT_CHARS = 5 * 1024 * 1024;
	const MAX_POLICY_CHARS = 256 * 1024;
	const MAX_DEPTH = 64;
	const MAX_SERVERS = 1000;
	const MAX_TOOLS = 10000;
	const MAX_SCAN = 20000;
	const MAX_FINDINGS = 5000;
	const SEVERITIES = ['high', 'medium', 'low', 'info'];
	const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };

	// ------------------------------------------------------------------ JSON / JSONC parser
	/**
	 * Parses one or more JSON documents (JSONC comments and trailing commas accepted).
	 * Records the line of every property and array item, and duplicate keys, without evaluating anything.
	 */
	function parseDocuments(text) {
		const src = String(text);
		const n = src.length;
		let i = 0;
		let jsonc = false;
		const lineStarts = [0];
		for (let k = 0; k < n; k++) { if (src.charCodeAt(k) === 10) { lineStarts.push(k + 1); } }
		const lineOf = pos => {
			let lo = 0, hi = lineStarts.length - 1;
			while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= pos) { lo = mid; } else { hi = mid - 1; } }
			return lo + 1;
		};
		const meta = new WeakMap();
		const duplicates = [];
		const path = [];
		const describe = c => (c === undefined ? 'end of input' : /[\x00-\x1f\x7f]/.test(c) ? 'a control character' : '"' + c + '"');
		function fail(msg, pos) {
			const p = Math.min(pos, n);
			const line = lineOf(p);
			const column = p - lineStarts[line - 1] + 1;
			const err = new Error('Invalid JSON at line ' + line + ', column ' + column + ': ' + msg);
			err.code = 'INVALID_JSON';
			err.line = line;
			err.column = column;
			throw err;
		}
		function ws() {
			while (i < n) {
				const c = src.charCodeAt(i);
				if (c === 32 || c === 9 || c === 10 || c === 13 || c === 0xFEFF) { i++; continue; }
				if (c === 47 && src.charCodeAt(i + 1) === 47) { jsonc = true; const e = src.indexOf('\n', i); i = e < 0 ? n : e + 1; continue; }
				if (c === 47 && src.charCodeAt(i + 1) === 42) { jsonc = true; const e = src.indexOf('*/', i + 2); if (e < 0) { fail('a /* comment is not closed', i); } i = e + 2; continue; }
				break;
			}
		}
		function str() {
			const start = i;
			i++;
			let out = '';
			let chunk = i;
			while (true) {
				if (i >= n) { fail('a string is not closed (missing ")', start); }
				const c = src.charCodeAt(i);
				if (c === 34) { out += src.slice(chunk, i); i++; return out; }
				if (c === 92) {
					out += src.slice(chunk, i);
					const e = src[i + 1];
					const map = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
					if (e === 'u') {
						const hex = src.slice(i + 2, i + 6);
						if (!/^[0-9A-Fa-f]{4}$/.test(hex)) { fail('invalid \\u escape (four hex digits expected)', i); }
						out += String.fromCharCode(parseInt(hex, 16));
						i += 6;
					} else if (e !== undefined && Object.prototype.hasOwnProperty.call(map, e)) {
						out += map[e];
						i += 2;
					} else {
						fail('invalid escape \\' + (e || '') + ' in a string', i);
					}
					chunk = i;
					continue;
				}
				if (c < 32) { fail(c === 10 ? 'line break inside a string (write it as \\n)' : 'control character inside a string', i); }
				i++;
			}
		}
		const NUM = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
		function num() {
			NUM.lastIndex = i;
			const m = NUM.exec(src);
			if (!m || !m[0] || m[0] === '-') { fail('invalid number', i); }
			i += m[0].length;
			return Number(m[0]);
		}
		function set(obj, key, value) { Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true }); }
		function value(depth) {
			if (depth > MAX_DEPTH) { fail('nesting is deeper than ' + MAX_DEPTH + ' levels', i); }
			ws();
			if (i >= n) { fail('unexpected end of input (a value was expected)', i); }
			const c = src[i];
			if (c === '{') { return object(depth); }
			if (c === '[') { return array(depth); }
			if (c === '"') { return str(); }
			if (c === '-' || (c >= '0' && c <= '9')) { return num(); }
			if (src.startsWith('true', i)) { i += 4; return true; }
			if (src.startsWith('false', i)) { i += 5; return false; }
			if (src.startsWith('null', i)) { i += 4; return null; }
			if (c === "'") { fail("strings must use double quotes (\"), not single quotes", i); }
			const word = (src.slice(i, i + 24).match(/^[A-Za-z_$][A-Za-z0-9_$]*/) || [''])[0];
			if (word) {
				const hint = { True: ' (use true)', False: ' (use false)', None: ' (use null)', undefined: ' (use null)', NaN: ' (not allowed in JSON)' }[word] || ' (text values must be in double quotes)';
				fail('unexpected word "' + word + '"' + hint, i);
			}
			fail('unexpected character ' + describe(c), i);
		}
		function object(depth) {
			i++;
			const obj = {};
			const keys = new Map();
			meta.set(obj, { keys });
			ws();
			if (src[i] === '}') { i++; return obj; }
			while (true) {
				ws();
				if (src[i] === '}' ) { jsonc = true; i++; return obj; }
				if (src[i] !== '"') {
					if (src[i] === "'") { fail("property names must use double quotes (\"), not single quotes", i); }
					if (/[A-Za-z_$]/.test(src[i] || '')) { fail('property names must be in double quotes', i); }
					fail('a property name in double quotes was expected, found ' + describe(src[i]), i);
				}
				const keyPos = i;
				const key = str();
				ws();
				if (src[i] !== ':') { fail('":" expected after the property name "' + key.slice(0, 60) + '", found ' + describe(src[i]), i); }
				i++;
				path.push(key);
				const v = value(depth + 1);
				path.pop();
				const line = lineOf(keyPos);
				if (keys.has(key)) { duplicates.push({ path: path.slice(), key, firstLine: keys.get(key), line }); }
				keys.set(key, line);
				set(obj, key, v);
				ws();
				if (src[i] === ',') { i++; continue; }
				if (src[i] === '}') { i++; return obj; }
				fail('"," or "}" expected after a property value, found ' + describe(src[i]), i);
			}
		}
		function array(depth) {
			i++;
			const arr = [];
			const items = [];
			meta.set(arr, { items });
			ws();
			if (src[i] === ']') { i++; return arr; }
			while (true) {
				ws();
				if (src[i] === ']') { jsonc = true; i++; return arr; }
				items.push(lineOf(i));
				path.push(arr.length);
				arr.push(value(depth + 1));
				path.pop();
				ws();
				if (src[i] === ',') { i++; continue; }
				if (src[i] === ']') { i++; return arr; }
				fail('"," or "]" expected after an array item, found ' + describe(src[i]), i);
			}
		}
		const docs = [];
		ws();
		if (i >= n) { const e = new Error('The input is empty.'); e.code = 'EMPTY'; throw e; }
		while (i < n) {
			const start = i;
			const v = value(0);
			docs.push({ value: v, line: lineOf(start) });
			ws();
			if (src[i] === ',') { fail('"," after the end of a JSON document (paste several documents one after another without commas)', i); }
		}
		return { docs, meta, duplicates, jsonc };
	}

	function pathStr(segments) {
		let out = '';
		segments.forEach((s, idx) => {
			if (typeof s === 'number') { out += '[' + s + ']'; } else if (/^[A-Za-z_$][\w$-]*$/.test(s)) { out += (idx ? '.' : '') + s; } else { out += '[' + JSON.stringify(String(s).slice(0, 80)) + ']'; }
		});
		return out || '(document)';
	}

	// ------------------------------------------------------------------ small helpers
	const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
	const asStr = v => (typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : '');
	const cap = (s, max) => (s.length > max ? s.slice(0, max) : s);
	function baseName(cmd) {
		const s = String(cmd || '').trim().replace(/^["']|["']$/g, '');
		const b = s.split(/[\\/]/).pop().toLowerCase();
		return b.replace(/\.(exe|cmd|bat|com)$/, '');
	}
	function shellSplit(s) {
		const out = [];
		let cur = '', q = null, has = false;
		const str = cap(String(s), MAX_SCAN);
		for (let k = 0; k < str.length; k++) {
			const c = str[k];
			if (q) { if (c === q) { q = null; } else if (c === '\\' && q === '"' && k + 1 < str.length) { cur += str[++k]; } else { cur += c; } continue; }
			if (c === '"' || c === "'") { q = c; has = true; continue; }
			if (/\s/.test(c)) { if (cur || has) { out.push(cur); cur = ''; has = false; } continue; }
			cur += c;
		}
		if (cur || has) { out.push(cur); }
		return out;
	}
	function levenshtein(a, b, max) {
		if (Math.abs(a.length - b.length) > max) { return max + 1; }
		let prev = new Array(b.length + 1);
		for (let j = 0; j <= b.length; j++) { prev[j] = j; }
		for (let x = 1; x <= a.length; x++) {
			const cur = [x];
			let best = x;
			for (let j = 1; j <= b.length; j++) {
				cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[x - 1] === b[j - 1] ? 0 : 1));
				if (cur[j] < best) { best = cur[j]; }
			}
			if (best > max) { return max + 1; }
			prev = cur;
		}
		return prev[b.length];
	}
	/** Glob with * and ? only, case-insensitive, linear-time two-pointer matcher (no regular expressions). */
	function globMatch(pattern, text) {
		const p = String(pattern).toLowerCase(), t = String(text).toLowerCase();
		let pi = 0, ti = 0, star = -1, mark = 0;
		while (ti < t.length) {
			if (pi < p.length && (p[pi] === '?' || p[pi] === t[ti])) { pi++; ti++; } else if (pi < p.length && p[pi] === '*') { star = pi++; mark = ti; } else if (star >= 0) { pi = star + 1; ti = ++mark; } else { return false; }
		}
		while (pi < p.length && p[pi] === '*') { pi++; }
		return pi === p.length;
	}

	// ------------------------------------------------------------------ secrets
	// Known credential formats. Bounded quantifiers; no look-behind (older Safari).
	const TOKEN_FORMATS = [
		['Private key', /-----BEGIN[ A-Z]{0,40}PRIVATE KEY-----/],
		['GitHub fine-grained token', /github_pat_[A-Za-z0-9_]{40,255}/],
		['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{30,255}/],
		['GitLab token', /\bglpat-[A-Za-z0-9_-]{20,64}/],
		['Slack token', /\bxox[abposr]-[A-Za-z0-9-]{10,200}/],
		['Slack webhook URL', /hooks\.slack\.com\/services\/[A-Za-z0-9+/]{20,200}/],
		['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,200}/],
		['OpenAI API key', /(?:^|[^A-Za-z0-9])(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200})/],
		['AWS access key ID', /(?:^|[^A-Z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])/],
		['Google API key', /AIza[0-9A-Za-z_-]{35}/],
		['Stripe secret key', /\b[rs]k_live_[0-9A-Za-z]{10,200}/],
		['JSON Web Token', /\beyJ[A-Za-z0-9_-]{10,4000}\.eyJ[A-Za-z0-9_-]{5,4000}\.[A-Za-z0-9_-]{0,4000}/],
		['npm token', /\bnpm_[A-Za-z0-9]{36}\b/],
		['Hugging Face token', /\bhf_[A-Za-z0-9]{30,40}\b/]
	];
	function findTokens(s) {
		const text = cap(String(s), MAX_SCAN);
		const out = [];
		for (const [type, re] of TOKEN_FORMATS) {
			const m = text.match(re);
			if (!m) { continue; }
			const v = m[1] || m[0];
			if (type === 'OpenAI API key' && (/^sk-ant-/.test(v) || !/[0-9]/.test(v))) { continue; }
			if (out.some(o => o.value.includes(v) || v.includes(o.value))) { continue; }
			out.push({ type, value: type === 'Private key' ? text.slice(text.indexOf(v), text.indexOf(v) + 400) : v });
		}
		return out;
	}
	const REFERENCE = /^\s*(?:\$\{[^{}]{1,200}\}|\$[A-Za-z_][A-Za-z0-9_]{0,100}|%[A-Za-z_][A-Za-z0-9_]{0,100}%|\{\{[^{}]{1,200}\}\}|\{env:[^{}]{1,100}\}|(?:op|vault|secret|keychain|aws-sm|gcp-sm|azure-kv):\/{0,2}\S{1,300})\s*$/i;
	const HAS_REFERENCE = /\$\{[^{}]{1,200}\}|\$[A-Za-z_][A-Za-z0-9_]{1,100}|%[A-Za-z_][A-Za-z0-9_]{1,100}%|\{\{[^{}]{1,200}\}\}/;
	const PLACEHOLDER = /^(?:<[^<>]{1,100}>|\[[^\[\]]{1,100}\]|your[-_ .].{0,80}|.{0,80}[-_ ]here|x{3,}|\*{3,}|\.{3,}|•{3,}|changeme|change[-_]me|replace[-_ ]?me|todo|tbd|placeholder|example|dummy|none|null|undefined|test|true|false|redacted)$/i;
	const isReference = v => REFERENCE.test(v);
	const isPlaceholder = v => PLACEHOLDER.test(String(v).trim());
	const looksLikePath = v => /^(?:[A-Za-z]:[\\/]|\/|~[\\/]|\.{1,2}[\\/]|\\\\)/.test(v);
	const SECRET_NAME = /(?:^|[_.-])(?:TOKEN|SECRET|PASSWORD|PASSWD|PWD|PASS|API[_-]?KEY|APIKEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|AUTH|CREDENTIALS?|PAT|COOKIE|SESSION|SIGNING[_-]?KEY|ENCRYPTION[_-]?KEY|KEY)(?:[_.-]|$)/i;
	const NOT_SECRET_NAME = /(?:^|[_.-])(?:FILE|PATH|DIR|URL|URI|HOST|HOSTNAME|PORT|ENDPOINT|MODE|TYPE|METHOD|ENABLED|DISABLED|REQUIRED|SCOPES?|HEADER|PROVIDER|NAME|ID|USER|USERNAME|LENGTH|MIN|MAX|TIMEOUT|TTL|EXPIRY|EXPIRES|REGION|VERSION|FORMAT|ISSUER|AUDIENCE|ALG|ALGORITHM|ROTATION|STRATEGY)(?:[_.-]|$)/i;
	function secretLiteral(v) {
		const s = String(v).trim();
		if (s.length < 6 || isReference(s) || isPlaceholder(s) || HAS_REFERENCE.test(s) || looksLikePath(s)) { return false; }
		if (/^\d{1,6}$/.test(s) || /^(?:yes|no|on|off|enabled|disabled)$/i.test(s)) { return false; }
		if (/^https?:\/\//i.test(s)) { return false; }
		return true;
	}
	function mask(v) {
		const s = String(v);
		if (s.length < 8) { return '•••• (' + s.length + ' characters)'; }
		const keep = Math.min(4, Math.floor(s.length / 5));
		return s.slice(0, keep) + '…•••• (' + s.length + ' characters)';
	}

	// ------------------------------------------------------------------ paths
	const SENSITIVE_SEGMENTS = new Set(['.ssh', '.aws', '.gnupg', '.kube', '.docker', '.azure', '.password-store', '.netrc', '.npmrc', '.pypirc', '.git-credentials', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', '.env', 'keychains', '.vault-token', 'shadow', 'gshadow', 'sudoers']);
	function normPath(p) {
		let s = String(p).trim().replace(/^["']|["']$/g, '').replace(/\\/g, '/');
		s = s.replace(/^(?:\$\{env:HOME\}|\$\{HOME\}|\$HOME|%USERPROFILE%|%HOMEPATH%|\$\{userHome\}|~)(?=\/|$)/i, '~');
		const unc = s.startsWith('//');
		s = s.replace(/\/{2,}/g, '/');
		if (unc) { s = '/' + s; }
		const win = /^[A-Za-z]:/.test(s);
		const parts = [];
		const segs = s.split('/');
		segs.forEach((seg, idx) => {
			if (seg === '.' || (seg === '' && idx > 0)) { return; }
			if (seg === '..') { if (parts.length > 1 || (parts.length === 1 && parts[0] !== '' && parts[0] !== '~' && !/^[A-Za-z]:$/.test(parts[0]))) { parts.pop(); } return; }
			parts.push(seg);
		});
		let out = parts.join('/');
		if (s.startsWith('/') && !out.startsWith('/')) { out = '/' + out; }
		if (/^[A-Za-z]:$/.test(out)) { out += '/'; }
		if (out === '') { out = s.startsWith('/') ? '/' : s; }
		return win ? out.toLowerCase() : out;
	}
	/** Home aliases: /home/x, /Users/x, c:/users/x, /root are compared as ~ as well. */
	function homeAlias(n) {
		const m = n.match(/^(?:\/home\/[^/]+|\/Users\/[^/]+|[a-z]:\/users\/[^/]+|\/root)(?=\/|$)(.*)$/i);
		if (!m || /^[a-z]:\/users\/(?:public|default)$/i.test(n.slice(0, n.length - m[1].length))) { return null; }
		return '~' + m[1];
	}
	function classifyPath(raw) {
		const s = String(raw).trim();
		if (!s) { return null; }
		const n = normPath(s);
		const alias = homeAlias(n);
		const segs = n.toLowerCase().split('/');
		if (n.includes('*')) { const prefix = n.slice(0, n.indexOf('*')).replace(/\/+$/, ''); return { kind: 'wildcard', norm: n, rootLike: prefix === '' || /^[a-z]:$/i.test(prefix) || prefix === '~' }; }
		if (n === '/' || /^[a-z]:\/$/i.test(n) || n === '/mnt/c' || /^file:\/*$/.test(n)) { return { kind: 'root', norm: n }; }
		for (const seg of segs) {
			if (SENSITIVE_SEGMENTS.has(seg) || /^\.env\.[\w.-]+$/.test(seg) || /^id_(?:rsa|ed25519|ecdsa)/.test(seg)) { return { kind: 'sensitive', norm: n, detail: seg }; }
		}
		if (/^\/etc(?:\/|$)/.test(n) || /^[a-z]:\/windows\/system32\/config/i.test(n) || /\/library\/keychains(?:\/|$)/i.test(n) || /\/\.config\/gcloud(?:\/|$)/i.test(n) || /(?:^|\/)\.cursor\/mcp\.json$|claude_desktop_config\.json$/i.test(n)) { return { kind: 'sensitive', norm: n, detail: n }; }
		if (n === '~' || alias === '~' || n === '/root') { return { kind: 'home', norm: n }; }
		if (/^(?:\/tmp|\/var\/tmp|\/dev\/shm|\/private\/tmp)(?:\/|$)/.test(n) || /^(?:%temp%|%tmp%|\$tmpdir|\$\{tmpdir\})(?:\/|$)/i.test(n) || /\/appdata\/local\/temp(?:\/|$)/i.test(n) || /^[a-z]:\/windows\/temp(?:\/|$)/i.test(n)) { return { kind: 'temp', norm: n }; }
		if (/^(?:~|\/home\/[^/]+|\/users\/[^/]+|[a-z]:\/users\/[^/]+)\/downloads(?:\/|$)/i.test(n)) { return { kind: 'downloads', norm: n }; }
		return { kind: 'other', norm: n, alias };
	}
	const isPathLike = v => /^(?:[A-Za-z]:[\\/]?$|[A-Za-z]:[\\/]|\/|~(?:[\\/]|$)|\$HOME\b|\$\{HOME\}|\$\{env:HOME\}|\$\{userHome\}|%USERPROFILE%|%HOMEPATH%|\\\\|\.{1,2}[\\/])/i.test(String(v).trim());
	const SECRET_FLAG = /^--?(?:[\w-]*[-_])?(?:api[-_]?key|apikey|token|password|passwd|pass|secret|private[-_]?key|key|pat|bearer|auth|credentials?)$/i;
	const NOT_SECRET_FLAG = /(?:file|path|env|url|uri|name|id|type|header|dir|endpoint|mode)$/i;
	const PATH_FLAG = /^--?(?:root|roots|dir|dirs|directory|directories|allowed[-_]?(?:dirs?|directories|paths?|roots?)|paths?|base[-_]?(?:dir|path)?|workspace|workdir|mount|repo|repository|r|db[-_]?path|data[-_]?dir|home|folder|allow)$/i;
	const PATH_ENV = /(?:^|_)(?:ALLOWED_(?:DIRS?|DIRECTORIES|PATHS?|ROOTS?)|ROOTS?|ROOT_(?:DIR|PATH)|BASE_(?:DIR|PATH)|WORKSPACE(?:_DIR|_PATH)?|DATA_DIR|DIRS|DIRECTORIES|DIR|DIRECTORY|PATHS)$/i;

	// ------------------------------------------------------------------ hosts
	const TUNNEL_SUFFIXES = ['ngrok.io', 'ngrok-free.app', 'ngrok.app', 'ngrok.dev', 'ngrok-free.dev', 'trycloudflare.com', 'loca.lt', 'localtunnel.me', 'serveo.net', 'localhost.run', 'lhr.life', 'pinggy.link', 'pinggy.io', 'bore.pub', 'tunnelmole.net', 'devtunnels.ms', 'telebit.io', 'localxpose.io', 'loclx.io', 'zrok.io'];
	const CAPTURE_HOSTS = ['webhook.site', 'requestbin.com', 'requestbin.net', 'pipedream.net', 'hookbin.com', 'beeceptor.com', 'ptsv2.com', 'ptsv3.com', 'interact.sh', 'oast.fun', 'oast.live', 'oast.me', 'oast.online', 'oast.pro', 'oast.site', 'burpcollaborator.net', 'canarytokens.com', 'pastebin.com', 'paste.ee', 'hastebin.com', 'transfer.sh', 'requestcatcher.com'];
	const DYNDNS_SUFFIXES = ['duckdns.org', 'no-ip.org', 'no-ip.biz', 'ddns.net', 'dynu.net', 'hopto.org', 'zapto.org', 'sytes.net', 'serveftp.com', 'freedns.afraid.org', 'dyndns.org'];
	const hostIs = (host, list) => list.some(s => host === s || host.endsWith('.' + s));
	function ipv4(host) { const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/); return m && m.slice(1).every(x => +x <= 255) ? m.slice(1).map(Number) : null; }
	function hostClass(hostRaw) {
		const host = String(hostRaw).toLowerCase().replace(/^\[|\]$/g, '');
		const v4 = ipv4(host);
		if (host === '169.254.169.254' || host === 'metadata.google.internal' || host === '100.100.100.200' || host === 'fd00:ec2::254' || host === 'metadata.azure.com') { return 'metadata'; }
		if (host === 'localhost' || host.endsWith('.localhost') || host === '::1' || host === '0.0.0.0' || (v4 && v4[0] === 127)) { return 'local'; }
		if (v4) {
			if (v4[0] === 10 || (v4[0] === 172 && v4[1] >= 16 && v4[1] <= 31) || (v4[0] === 192 && v4[1] === 168) || (v4[0] === 100 && v4[1] >= 64 && v4[1] <= 127)) { return 'private'; }
			if (v4[0] === 169 && v4[1] === 254) { return 'metadata'; }
			return 'public-ip';
		}
		if (host.includes(':')) { if (/^f[cd]/.test(host)) { return 'private'; } if (/^fe80/.test(host)) { return 'metadata'; } return 'public-ip'; }
		if (/\.(?:local|internal|lan|home\.arpa|corp|intranet|localdomain)$/.test(host) || !host.includes('.')) { return 'private'; }
		return 'public';
	}

	// ------------------------------------------------------------------ rule catalogue (CyberDat's own wording)
	const GROUPS = {
		secrets: 'Secrets in the configuration', launch: 'Risky launch commands', files: 'Broad file access', remote: 'Remote servers',
		capabilities: 'Dangerous tool capabilities', poisoning: 'Tool description poisoning', names: 'Duplicate and look-alike names', hygiene: 'Hygiene'
	};
	const SECRET_FIX = 'Remove the value from the file and rotate it if the file was shared. Reference it instead: an environment variable (for example ${env:NAME} or $NAME, depending on the client), an input prompt the client supports, or a secrets manager.';
	const R = {
		'MCP-SEC-001': ['secrets', 'Secret written directly in an environment variable', 'The variable name suggests a credential and its value is written in the configuration file. Configuration files are copied, synced and committed to repositories more often than people expect.', SECRET_FIX],
		'MCP-SEC-002': ['secrets', 'Credential with a known format in the configuration', 'The value has the format of a real credential type. Anyone who can read this configuration can use it.', SECRET_FIX],
		'MCP-SEC-003': ['secrets', 'Credentials inside a URL', 'User name and password or a key in a URL end up in logs, process lists and error messages.', 'Move the credential out of the URL into an environment variable or header that references a secret, and rotate it if the file was shared.'],
		'MCP-SEC-004': ['secrets', 'Credential written directly in an HTTP header', 'The header value is a literal credential stored in the configuration file.', 'Reference the value from an environment variable or input prompt instead (for example Bearer ${env:NAME}), and rotate it if the file was shared.'],
		'MCP-SEC-005': ['secrets', 'Secret passed as a command-line argument', 'Command-line arguments are visible to other local processes and are often logged.', 'Pass the secret through an environment variable that references a secret store, and rotate it if the file was shared.'],
		'MCP-CMD-001': ['launch', 'Downloaded script executed directly', 'The launch command downloads code and pipes or passes it straight to an interpreter. Whatever the remote host serves at that moment runs with your permissions, every time the server starts.', 'Install the server from a package or image with a pinned version and a checked hash, then start it directly without a download step.'],
		'MCP-CMD-002': ['launch', 'Server started through a shell', 'A shell interprets the command line before the server starts. Chained commands, redirections and substitutions make it harder to see what actually runs.', 'Start the server executable directly with command and args. On Windows, cmd /c is sometimes needed for npx; keep it to a single command.'],
		'MCP-CMD-003': ['launch', 'Package runner without a pinned version', 'npx, uvx and similar runners download the newest published version when no exact version is given. A compromised or changed release would run automatically on the next start.', 'Pin an exact version (for example package@1.2.3 or package==1.2.3) and update deliberately.'],
		'MCP-CMD-004': ['launch', 'Container with host-level privileges', 'The container is started with options that remove its isolation from the host.', 'Remove privileged options. Grant only the specific capability, device or network the server needs, if any.'],
		'MCP-CMD-005': ['launch', 'Container mounts the host root or home directory', 'The container can read (and unless mounted read-only, change) the whole host file system or your home directory, including keys and credentials.', 'Mount only the project directory the server needs, read-only where possible (:ro).'],
		'MCP-CMD-006': ['launch', 'Server started with elevated privileges', 'The server runs as an administrator. Any tool call, including one triggered by injected instructions, runs with those rights.', 'Run the server as your normal user. If it needs one privileged operation, give it a narrow, separate helper.'],
		'MCP-CMD-007': ['launch', 'Executable started from a temporary or downloads folder', 'Programs in temporary and download folders are easy to replace and rarely reviewed.', 'Install the server to a stable location you control, or use a package manager with a pinned version.'],
		'MCP-CMD-008': ['launch', 'Inline code passed to an interpreter', 'The configuration contains program code that is run directly. It is hard to review and easy to tamper with.', 'Put the code into a reviewed script or package and start that instead.'],
		'MCP-CMD-009': ['launch', 'Package installed from a URL or Git repository', 'The server is installed from a URL or repository instead of a registry release. Without a commit pin the code can change at any time.', 'Use a released version from a registry, or pin the exact commit hash.'],
		'MCP-FS-001': ['files', 'File access to the whole file system', 'The server is given the file system root. Every readable file on the machine becomes reachable through its tools, including keys and other users\u2019 data where permissions allow.', 'Allow only the project directories the server needs.'],
		'MCP-FS-002': ['files', 'File access to the entire home directory', 'Your home directory contains SSH keys, cloud credentials, browser profiles and configuration files of other tools, including other MCP configurations.', 'Allow specific project folders instead of the home directory.'],
		'MCP-FS-003': ['files', 'Access to a location that holds credentials', 'The allowed location contains keys, tokens or secrets (for example .ssh, .aws or .env).', 'Remove this location. Give the server only the credentials it needs through its own configuration.'],
		'MCP-FS-004': ['files', 'Wildcard in an allowed path', 'A wildcard makes the allowed area hard to predict and often much wider than intended.', 'List explicit directories instead of patterns.'],
		'MCP-NET-001': ['remote', 'Remote server over unencrypted HTTP', 'Requests, responses and any credentials travel unencrypted and can be read or changed on the network.', 'Use https:// for every remote server.'],
		'MCP-NET-002': ['remote', 'No credentials configured for a remote server', 'This configuration sends no credentials. That is normal when the server uses the MCP authorization flow (OAuth) or is public; otherwise anyone who knows the URL may reach it.', 'Confirm how the server authenticates clients. No change is needed if your client signs in with OAuth.'],
		'MCP-NET-003': ['remote', 'Cloud metadata or link-local address', 'This address belongs to cloud instance metadata services, which hand out instance credentials.', 'Remove this address. MCP servers should never point at instance metadata endpoints.'],
		'MCP-NET-004': ['remote', 'Server reached through a tunnel service', 'Tunnel addresses are temporary and can be taken over or reused by someone else after they expire.', 'Use a stable domain you control, or run the server locally.'],
		'MCP-NET-005': ['remote', 'Unusual server address', 'The address uses a raw IP, look-alike characters, a dynamic DNS name or a request-capture service. Such addresses are used to hide where data goes.', 'Verify the address with the server provider and prefer a well-known domain over https.'],
		'MCP-NET-006': ['remote', 'Uncommon port on a remote server', 'An uncommon port is not a risk by itself, but it can indicate a temporary or personal deployment.', 'Confirm the port with the server provider.'],
		'MCP-NET-007': ['remote', 'TLS certificate checks disabled', 'Turning off certificate verification lets anyone on the network impersonate the server.', 'Remove the option. If an internal certificate authority is used, add its certificate to the trust store instead.'],
		'MCP-NET-008': ['remote', 'Internal server over unencrypted HTTP', 'The address is in a private network. Unencrypted HTTP is common there, but other devices on the same network can read the traffic.', 'Prefer HTTPS when the network is shared with other devices or users.'],
		'MCP-CAP-001': ['capabilities', 'Tool that runs commands or code', 'The tool executes commands or code chosen by the model. Instructions hidden in documents, web pages or other tool output can make the model call it.', 'Connect such servers only in isolated environments, keep confirmation prompts on, and prefer servers that accept a fixed list of commands.'],
		'MCP-CAP-002': ['capabilities', 'Tool that writes, moves or deletes files', 'The tool can change or remove files in the areas the server can reach.', 'Keep confirmation prompts on for this tool and limit the server to the folders it needs.'],
		'MCP-CAP-003': ['capabilities', 'Tool that requests arbitrary URLs', 'The tool fetches any address the model chooses. It can be used to send data out, and the content it returns may contain instructions aimed at the model.', 'Keep confirmation prompts on, and treat fetched content as untrusted.'],
		'MCP-CAP-004': ['capabilities', 'Browser automation tool', 'The tool controls a browser, possibly with your signed-in sessions.', 'Use a separate browser profile without personal sign-ins and keep confirmation prompts on.'],
		'MCP-CAP-005': ['capabilities', 'Tool that reads or sends email or messages', 'Messages can carry private data, and a sending tool can send it anywhere.', 'Keep confirmation prompts on for sending tools.'],
		'MCP-CAP-006': ['capabilities', 'Unrestricted code or command argument', 'The argument accepts any text and has no list of allowed values or pattern.', 'If the server is yours, restrict the argument with enum or pattern in the input schema.'],
		'MCP-CAP-007': ['capabilities', 'Tool that runs database statements', 'The tool runs SQL chosen by the model. Without a read-only connection it can change or delete data.', 'Connect with a read-only database user, and keep confirmation prompts on for write-capable tools.'],
		'MCP-CAP-008': ['capabilities', 'Private data and outbound channel in the same setup', 'One tool can read private data (files, mail, databases) and another can send data out (web requests, messages). Instructions injected through any content can chain the two.', 'Do not combine such servers in one session, or keep confirmation prompts on for every outbound tool.'],
		'MCP-TP-001': ['poisoning', 'Hidden characters in a tool description', 'The text contains invisible or direction-changing characters. They can hide instructions that the model reads but people do not see.', 'Do not connect the server until the provider explains the characters. Reviewers should look at the decoded text shown here.'],
		'MCP-TP-002': ['poisoning', 'Instruction-override wording in a tool description', 'Tool descriptions are sent to the model as context. Wording that tells the model to ignore or replace its instructions is a common injection pattern.', 'Treat the server as untrusted until the description is explained or fixed.'],
		'MCP-TP-003': ['poisoning', 'Description asks to hide actions from the user', 'A legitimate tool has no reason to ask the model to keep something from the user.', 'Do not connect the server. Report the description to the provider.'],
		'MCP-TP-004': ['poisoning', 'Description asks for credentials or private files', 'The description or an argument description asks the model to read or pass keys, credential files or configuration. This is how tool poisoning exfiltrates data through tool arguments.', 'Do not connect the server. If it was connected, rotate the credentials it could reach.'],
		'MCP-TP-005': ['poisoning', 'Hidden instruction markup in a tool description', 'Tags such as <IMPORTANT> or <system>, HTML comments or prompt delimiters inside a description are aimed at the model, not at people.', 'Treat the server as untrusted until the description is explained or fixed.'],
		'MCP-TP-006': ['poisoning', 'Description changes how other tools behave', 'The description gives the model rules for tools of another server. A malicious server can redirect or copy data handled by trusted tools this way.', 'Remove the server, or review all of its descriptions carefully before use.'],
		'MCP-TP-007': ['poisoning', 'Very long description or embedded encoded data', 'Very long descriptions and long encoded blobs are hard to review and can hide instructions.', 'Read the full description before connecting the server.'],
		'MCP-NAME-001': ['names', 'Same tool name on several servers', 'When two servers offer a tool with the same name, the model may call the wrong one. A malicious server can shadow a trusted tool this way.', 'Keep one of the servers, or use client settings that prefix tool names with the server name.'],
		'MCP-NAME-002': ['names', 'Very similar tool names on different servers', 'Names that differ by one character or only by separators are easy to confuse.', 'Check that both servers are trusted, and remove one if they overlap.'],
		'MCP-NAME-003': ['names', 'Duplicate key in the JSON', 'JSON readers keep only one of two equal keys, usually the last. One definition silently replaces the other.', 'Remove or rename one of the keys.'],
		'MCP-NAME-004': ['names', 'Package name resembles a well-known package', 'The name is close to, but not the same as, a well-known MCP package. Look-alike names are a common way to publish malicious packages.', 'Check the exact package name and publisher in the registry before running it. This tool does not contact any registry.'],
		'MCP-HYG-001': ['hygiene', 'Container image without a pinned version', 'Without a fixed tag or digest the image can change between starts.', 'Use a specific version tag, or better an image digest (@sha256:\u2026).'],
		'MCP-HYG-002': ['hygiene', 'File server without allowed directories', 'No directories are listed. Depending on the client, access is then decided by client roots or fails; the configuration alone does not show the limit.', 'List the directories the server may use.'],
		'MCP-HYG-003': ['hygiene', 'No timeouts configured', 'None of the servers sets a timeout. Supported settings differ by client.', 'If your client supports it, set startup and tool-call timeouts.'],
		'MCP-HYG-004': ['hygiene', 'Tool calls approved automatically', 'Automatic approval removes the confirmation step that lets you stop unexpected tool calls, including calls caused by injected instructions.', 'Approve automatically only read-only tools. Keep confirmation on for tools that write, send, delete or execute.'],
		'MCP-HYG-005': ['hygiene', 'Very large number of tools', 'Many tools make it harder to review what the model can do and increase the chance of confusing similar tools.', 'Enable only the tools you use, if the client or server supports filtering.']
	};

	// ------------------------------------------------------------------ normalization
	const SERVER_MAP_KEYS = [['mcpServers'], ['servers'], ['mcp', 'servers'], ['context_servers'], ['mcp_servers']];
	const looksServer = v => isObj(v) && (typeof v.command === 'string' || isObj(v.command) || typeof v.url === 'string' || typeof v.serverUrl === 'string' || typeof v.httpUrl === 'string' || typeof v.uri === 'string' || Array.isArray(v.tools));
	const looksTool = v => isObj(v) && typeof v.name === 'string' && ('description' in v || 'inputSchema' in v || 'input_schema' in v || 'annotations' in v);

	function normalize(parsed, notes) {
		const servers = [];
		let toolListNo = 0;
		const lineOfKey = (container, key) => { const m = parsed.meta.get(container); return m ? (m.keys ? m.keys.get(key) : m.items ? m.items[key] : 0) || 0 : 0; };
		function addServer(name, obj, segs, line) {
			if (servers.length >= MAX_SERVERS) { return; }
			const s = { id: 's' + servers.length, name: String(name), path: segs, line, obj, kind: 'config', command: '', args: [], argLines: [], env: {}, envObj: null, url: '', urlKey: '', headers: {}, headersObj: null, transport: '', hasTimeout: false, autoApprove: [], autoApproveKey: '', autoWildcard: false, trust: false, tools: [], disabled: obj.disabled === true, packages: [], images: [], stages: [], paths: [], hosts: [], caps: new Set() };
			let cmd = obj.command;
			let args = obj.args;
			let env = obj.env;
			if (isObj(cmd)) { s.cmdObj = cmd; args = cmd.args; env = env || cmd.env; cmd = cmd.path || cmd.command; s.cmdPathKey = true; }
			if (typeof cmd === 'string') {
				s.command = cmd;
				if (!Array.isArray(args) && /\s/.test(cmd.trim())) { const parts = shellSplit(cmd); s.command = parts[0] || ''; s.args = parts.slice(1); s.splitCommand = true; notes.push('Server "' + s.name + '": the command contains spaces and no args list; it was split like a shell would.'); }
			}
			if (Array.isArray(args)) { s.args = args.map(asStr); s.argsArr = args; } else if (args !== undefined && !s.splitCommand) { notes.push('Server "' + s.name + '": args is not a list and was ignored.'); }
			if (isObj(env)) { s.envObj = env; for (const k of Object.keys(env)) { s.env[k] = asStr(env[k]); } }
			for (const k of ['url', 'serverUrl', 'httpUrl', 'uri', 'endpoint']) { if (typeof obj[k] === 'string') { s.url = obj[k]; s.urlKey = k; break; } }
			const headers = isObj(obj.headers) ? obj.headers : isObj(obj.requestInit) && isObj(obj.requestInit.headers) ? obj.requestInit.headers : null;
			if (headers) { s.headersObj = headers; for (const k of Object.keys(headers)) { s.headers[k] = asStr(headers[k]); } }
			const t = typeof obj.type === 'string' ? obj.type : typeof obj.transport === 'string' ? obj.transport : isObj(obj.transport) && typeof obj.transport.type === 'string' ? obj.transport.type : '';
			s.transport = /^(?:stdio)$/i.test(t) ? 'stdio' : /^sse$/i.test(t) ? 'sse' : /^(?:http|streamable-?http|streamablehttp)$/i.test(t) ? 'http' : s.url ? (/\/sse\/?(?:\?|$)/i.test(s.url) ? 'sse' : 'http') : s.command ? 'stdio' : (t || 'unknown');
			s.hasTimeout = Object.keys(obj).some(k => /timeout/i.test(k));
			for (const k of ['autoApprove', 'alwaysAllow', 'auto_approve', 'approvedTools', 'autoApproveTools']) {
				if (Array.isArray(obj[k])) { s.autoApprove = obj[k].map(asStr); s.autoApproveKey = k; s.autoWildcard = s.autoApprove.some(x => x === '*' || x === 'all'); break; }
				if (obj[k] === true) { s.autoApproveKey = k; s.autoWildcard = true; break; }
			}
			s.trust = obj.trust === true;
			if (Array.isArray(obj.tools)) { addTools(s, obj.tools, segs.concat('tools')); }
			servers.push(s);
			return s;
		}
		function addTools(s, list, segs) {
			list.forEach((t, idx) => {
				if (!looksTool(t)) { return; }
				if (s.tools.length >= MAX_TOOLS) { return; }
				s.tools.push({ name: t.name, title: asStr(t.title || (isObj(t.annotations) && t.annotations.title) || ''), description: asStr(t.description), schema: isObj(t.inputSchema) ? t.inputSchema : isObj(t.input_schema) ? t.input_schema : null, annotations: isObj(t.annotations) ? t.annotations : {}, path: segs.concat(idx), line: lineOfKey(list, idx), obj: t });
			});
		}
		function addToolList(list, segs, label) {
			toolListNo++;
			const s = { id: 's' + servers.length, name: label || 'Tool list ' + toolListNo, path: segs, line: 0, obj: null, kind: 'tools', command: '', args: [], argLines: [], env: {}, url: '', headers: {}, transport: '', hasTimeout: false, autoApprove: [], autoWildcard: false, trust: false, tools: [], disabled: false, packages: [], images: [], stages: [], paths: [], hosts: [], caps: new Set() };
			addTools(s, list, segs);
			if (s.tools.length && servers.length < MAX_SERVERS) { servers.push(s); }
		}
		parsed.docs.forEach((d, docIdx) => {
			const v = d.value;
			const base = parsed.docs.length > 1 ? ['document ' + (docIdx + 1)] : [];
			let found = false;
			if (Array.isArray(v)) {
				if (v.some(looksTool)) { addToolList(v, base); found = true; } else if (v.some(looksServer)) { v.forEach((x, idx) => { if (looksServer(x)) { addServer(x.name || 'server ' + (idx + 1), x, base.concat(idx), lineOfKey(v, idx)); } }); found = true; }
			} else if (isObj(v)) {
				for (const keys of SERVER_MAP_KEYS) {
					let parent = v, ok = true;
					for (let k = 0; k < keys.length - 1; k++) { parent = parent[keys[k]]; if (!isObj(parent)) { ok = false; break; } }
					if (!ok) { continue; }
					const map = parent[keys[keys.length - 1]];
					const segs = base.concat(keys);
					if (isObj(map)) { for (const name of Object.keys(map)) { if (isObj(map[name])) { addServer(name, map[name], segs.concat(name), lineOfKey(map, name)); found = true; } } }
					else if (Array.isArray(map)) { map.forEach((x, idx) => { if (isObj(x)) { addServer(x.name || 'server ' + (idx + 1), x, segs.concat(idx), lineOfKey(map, idx)); found = true; } }); }
				}
				const toolsHost = Array.isArray(v.tools) ? v : isObj(v.result) && Array.isArray(v.result.tools) ? v.result : null;
				if (!found && toolsHost) {
					const info = isObj(v.serverInfo) ? v.serverInfo : isObj(v.result) && isObj(v.result.serverInfo) ? v.result.serverInfo : null;
					addToolList(toolsHost.tools, base.concat(toolsHost === v ? ['tools'] : ['result', 'tools']), info && typeof info.name === 'string' ? info.name : (typeof v.name === 'string' ? v.name : ''));
					found = true;
				}
				if (!found && looksServer(v) && !Array.isArray(v.tools)) { addServer(v.name || 'server', v, base, d.line); found = true; }
				if (!found) {
					const names = Object.keys(v).filter(k => looksServer(v[k]));
					if (names.length) { names.forEach(name => addServer(name, v[name], base.concat(name), lineOfKey(v, name))); found = true; }
				}
			}
			if (!found) { notes.push('Document ' + (docIdx + 1) + ' (line ' + d.line + ') contains no MCP servers or tool list that this tool recognizes.'); }
		});
		return { servers, lineOfKey };
	}

	// ------------------------------------------------------------------ analysis
	const KNOWN_PACKAGES = ['@modelcontextprotocol/server-filesystem', '@modelcontextprotocol/server-memory', '@modelcontextprotocol/server-everything', '@modelcontextprotocol/server-brave-search', '@modelcontextprotocol/server-github', '@modelcontextprotocol/server-postgres', '@modelcontextprotocol/server-puppeteer', '@modelcontextprotocol/server-slack', '@modelcontextprotocol/server-sequential-thinking', '@modelcontextprotocol/inspector', '@modelcontextprotocol/sdk', 'mcp-server-git', 'mcp-server-fetch', 'mcp-server-time', 'mcp-server-sqlite', 'mcp-server-everything', '@playwright/mcp'];
	const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash']);
	const ELEVATE = new Set(['sudo', 'doas', 'runas', 'gsudo', 'pkexec']);
	const INTERP_INLINE = { node: ['-e', '--eval', '-p', '--print'], nodejs: ['-e', '--eval', '-p', '--print'], bun: ['-e', '--eval'], python: ['-c'], python3: ['-c'], py: ['-c'], perl: ['-e', '-E'], ruby: ['-e'], php: ['-r'] };
	const NPX_VALUE_FLAGS = new Set(['-p', '--package', '-c', '--call', '--registry', '--cache', '--userconfig']);
	const UVX_VALUE_FLAGS = new Set(['--from', '--with', '--with-editable', '--with-requirements', '--python', '-p', '--index', '--index-url', '--extra-index-url', '--default-index', '-i', '--directory', '--project', '--cache-dir', '--env-file']);
	const DOCKER_VALUE_FLAGS = new Set(['-e', '--env', '-v', '--volume', '--mount', '--name', '-p', '--publish', '--network', '--net', '--pid', '--ipc', '--uts', '--userns', '--cgroupns', '--cap-add', '--cap-drop', '--user', '-u', '-w', '--workdir', '--entrypoint', '--env-file', '--label', '-l', '--memory', '-m', '--cpus', '--platform', '--restart', '--security-opt', '--device', '--add-host', '--dns', '--hostname', '-h', '--tmpfs', '--ulimit', '--pull', '--stop-timeout', '--log-driver', '--log-opt', '--gpus', '--runtime', '--group-add', '--shm-size', '--volumes-from', '--expose', '--link', '--mac-address', '--ip', '--health-cmd', '--memory-swap', '--cpu-shares', '--storage-opt', '--annotation']);

	function npmSpec(spec) {
		const s = String(spec).trim();
		if (/^(?:https?:|git\+|git:|github:|gitlab:|bitbucket:|gist:)/i.test(s) || (/^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(s) && !s.startsWith('@'))) { return { kind: 'source', name: s, pinned: /#[0-9a-f]{40}\b|\/commit\/[0-9a-f]{40}\b/i.test(s), source: s }; }
		if (/^(?:file:|\.{1,2}[\\/]|\/|[A-Za-z]:[\\/]|~)/.test(s) || /\.tgz$/i.test(s)) { return { kind: 'local', name: s }; }
		const m = s.match(/^(@[^/@\s]+\/[^@\s]+|[^@\s]+)(?:@(.*))?$/);
		if (!m) { return null; }
		const version = m[2] || '';
		return { kind: 'registry', ecosystem: 'npm', name: m[1].toLowerCase(), version, pinned: /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version) };
	}
	function pySpec(spec) {
		const s = String(spec).trim();
		if (/^(?:git\+|https?:|file:)/i.test(s) || /@\s*(?:git\+|https?:)/i.test(s)) { return { kind: 'source', name: s, pinned: /@[0-9a-f]{40}\b|#[0-9a-f]{40}\b/i.test(s), source: s }; }
		if (/^(?:\.{1,2}[\\/]|\/|[A-Za-z]:[\\/]|~)/.test(s)) { return { kind: 'local', name: s }; }
		const m = s.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]{0,100}\])?\s*(?:(==|===|@)\s*([^\s,;]+)|([<>~!=]=?.*))?$/);
		if (!m) { return null; }
		return { kind: 'registry', ecosystem: 'pypi', name: m[1].toLowerCase().replace(/[-_.]+/g, '-'), version: m[3] || m[4] || '', pinned: !!m[3] && /^\d+(?:\.\d+)*(?:[a-z0-9.+-]*)$/i.test(m[3]) };
	}
	function imageRef(img) {
		const s = String(img);
		const digest = /@sha256:[0-9a-f]{64}$/i.test(s);
		const noDigest = s.replace(/@sha256:[0-9a-f]{64}$/i, '');
		const lastSlash = noDigest.lastIndexOf('/');
		const colon = noDigest.lastIndexOf(':');
		const tag = colon > lastSlash ? noDigest.slice(colon + 1) : '';
		const name = colon > lastSlash ? noDigest.slice(0, colon) : noDigest;
		return { name: name.toLowerCase(), tag, digest, pinned: digest || (!!tag && tag !== 'latest' && tag !== 'stable' && tag !== 'edge' && tag !== 'main' && tag !== 'master') };
	}
	function splitVolume(v) {
		const s = String(v);
		const m = s.match(/^([A-Za-z]:[\\/][^:]*|[^:]*):([^:]+)(?::(.*))?$/);
		return m ? { src: m[1], dst: m[2], opts: m[3] || '' } : { src: '', dst: s, opts: '' };
	}

	function analyze(text, options, hooks) {
		const opts = options || {};
		const onProgress = hooks && hooks.onProgress;
		const input = String(text == null ? '' : text);
		if (input.length > MAX_INPUT_CHARS) { const e = new Error('The input is larger than the 5 MB limit.'); e.code = 'TOO_LARGE'; throw e; }
		const parsed = parseDocuments(input);
		const notes = [];
		if (parsed.jsonc) { notes.push('Comments or trailing commas were accepted (JSON with comments, as used by some clients).'); }
		const { servers, lineOfKey } = normalize(parsed, notes);
		if (!servers.length) {
			const e = new Error('No MCP servers or tool lists were recognized. Expected an object with "mcpServers", "servers", "mcp.servers" or "context_servers", a single server object with "command" or "url", or a tool list ({"tools": [...]} or a tools/list response).');
			e.code = 'NOT_RECOGNIZED';
			throw e;
		}
		const ctx = { findings: [], secrets: new Map(), seenSecret: new Set(), parsed, lineOfKey, truncated: false };
		const lineAt = (s, sub) => {
			// sub: array of keys under the server object; returns the best known line.
			let container = s.obj, line = s.line;
			if (!container) { return line; }
			for (const key of sub) {
				if (container === null || typeof container !== 'object') { break; }
				const l = lineOfKey(container, key);
				if (l) { line = l; }
				container = container[key];
			}
			return line;
		};
		function emit(rule, severity, s, sub, evidence, extra) {
			if (ctx.findings.length >= MAX_FINDINGS) { ctx.truncated = true; return null; }
			const r = R[rule];
			const segs = s ? s.path.concat(sub || []) : (sub || []);
			const f = { rule, group: r[0], severity, serverId: s ? s.id : '', server: s ? s.name : 'Whole configuration', location: pathStr(segs), line: s && s.obj ? lineAt(s, sub || []) : (extra && extra.line) || (s ? s.line : 0), title: r[1], explanation: r[2], fix: r[3], evidence: evidence || '' };
			if (extra && extra.why) { f.explanation = extra.why + ' ' + f.explanation; }
			ctx.findings.push(f);
			return f;
		}
		function rememberSecret(v, type) { const s = String(v); if (s.length >= 4 && !ctx.secrets.has(s)) { ctx.secrets.set(s, type); } }
		function secretFinding(s, sub, value, context) {
			const tokens = findTokens(value);
			for (const t of tokens) {
				rememberSecret(t.value, t.type);
				if (ctx.seenSecret.has(t.value)) { continue; }
				ctx.seenSecret.add(t.value);
				emit('MCP-SEC-002', 'high', s, sub, t.type + ': ' + mask(t.value), { why: context ? 'Found in ' + context + '.' : '' });
			}
			return tokens.length > 0;
		}

		const total = servers.length;
		servers.forEach((s, idx) => {
			analyzeServer(s, ctx, emit, secretFinding, rememberSecret);
			for (const t of s.tools) { analyzeTool(s, t, ctx, emit, secretFinding); }
			if (s.kind === "config" && (s.autoApproveKey || s.trust)) { autoApproval(s, emit); }
			if (s.tools.length > 50) { emit('MCP-HYG-005', s.autoWildcard || s.trust ? 'medium' : 'low', s, s.kind === 'config' ? ['tools'] : [], s.tools.length + ' tools' + (s.autoWildcard || s.trust ? ', approved automatically' : '')); }
			if (onProgress) { onProgress(idx + 1, total); }
		});
		analyzeCombinations(servers, ctx, emit, parsed);

		// Redact every remembered secret from every string that leaves the engine.
		const secrets = [...ctx.secrets.keys()].sort((a, b) => b.length - a.length);
		const redact = str => { let o = String(str); for (const sv of secrets) { if (o.includes(sv)) { o = o.split(sv).join(mask(sv)); } } return o; };
		const findings = ctx.findings.map(f => Object.fromEntries(Object.entries(f).map(([k, v]) => [k, typeof v === 'string' ? redact(v) : v])));
		findings.sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.line - b.line);
		const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
		const byGroup = {};
		for (const f of findings) { bySeverity[f.severity]++; byGroup[f.group] = (byGroup[f.group] || 0) + 1; }
		const level = SEVERITIES.find(sv => bySeverity[sv] > 0) || 'none';
		const serverSummaries = servers.map(s => ({ id: s.id, name: redact(s.name), kind: s.kind, transport: s.transport, location: redact(pathStr(s.path)), line: s.line, summary: redact(summaryOf(s)), toolCount: s.tools.length, disabled: s.disabled }));
		if (ctx.truncated) { notes.push('More than ' + MAX_FINDINGS + ' findings: the rest were not listed.'); }
		return {
			engine: VERSION, ruleset: RULESET_VERSION, mode: 'security', level,
			counts: { documents: parsed.docs.length, servers: servers.filter(s => s.kind === 'config').length, toolLists: servers.filter(s => s.kind === 'tools').length, tools: servers.reduce((n, s) => n + s.tools.length, 0), findings: findings.length, bySeverity, byGroup },
			servers: serverSummaries, findings, notes: notes.map(redact)
		};
	}

	function summaryOf(s) {
		if (s.kind === 'tools') { return s.tools.length + ' tools'; }
		if (s.url) { return s.transport.toUpperCase() + ' ' + cap(s.url, 300); }
		const line = [s.command].concat(s.args).join(' ');
		return cap(line, 300) + (line.length > 300 ? '…' : '');
	}

	// ---- servers
	function analyzeServer(s, ctx, emit, secretFinding, rememberSecret) {
		if (s.kind !== 'config') { return; }
		const argSub = idx => (s.cmdPathKey ? ['command', 'args', idx] : ['args', idx]);
		const envSub = k => (s.cmdPathKey && !s.obj.env ? ['command', 'env', k] : ['env', k]);
		// Secrets in env.
		for (const [k, v] of Object.entries(s.env)) {
			const sub = envSub(k);
			if (secretFinding(s, sub, v, 'environment variable ' + k)) { continue; }
			if (/^AWS_SECRET_ACCESS_KEY$/i.test(k) && /^[A-Za-z0-9/+]{30,60}$/.test(v.trim())) { rememberSecret(v.trim(), 'AWS secret access key'); emit('MCP-SEC-002', 'high', s, sub, 'AWS secret access key in ' + k + ': ' + mask(v.trim())); continue; }
			urlSecrets(s, sub, v, ctx, emit, rememberSecret);
			if (SECRET_NAME.test(k) && !NOT_SECRET_NAME.test(k) && secretLiteral(v)) { rememberSecret(v.trim(), 'secret'); emit('MCP-SEC-001', 'medium', s, sub, k + ' = ' + mask(v.trim())); }
			tlsOff(s, sub, k, v, emit);
			if (PATH_ENV.test(k) && v) { for (const part of v.split(/[;,]|:(?![\\/])/)) { if (part.trim()) { pathFinding(s, sub, part.trim(), true, emit, 'environment variable ' + k); } } }
		}
		// Headers.
		for (const [k, v] of Object.entries(s.headers)) {
			const sub = ['headers', k];
			if (secretFinding(s, sub, v, 'header ' + k)) { continue; }
			if (/^(?:authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|cookie|x-[\w-]*(?:token|key|secret))$/i.test(k)) {
				const cred = v.replace(/^\s*(?:bearer|basic|token|apikey|api-key|digest)\s+/i, '').trim();
				if (secretLiteral(cred)) { rememberSecret(cred, 'header credential'); emit('MCP-SEC-004', 'medium', s, sub, k + ': ' + mask(cred)); }
			}
		}
		// Remote URL.
		if (s.url) { analyzeUrl(s, ctx, emit, rememberSecret, secretFinding); }
		// Launch chain.
		if (s.command) { analyzeLaunch(s, s.command, s.args, argSub, 0, ctx, emit, secretFinding, rememberSecret); }
		// Arguments: secrets, URLs with credentials, TLS flags.
		s.args.forEach((a, idx) => {
			const sub = argSub(idx);
			secretFinding(s, sub, a, 'argument ' + (idx + 1));
			urlSecrets(s, sub, a, ctx, emit, rememberSecret);
			const flag = a.match(/^(--?[A-Za-z][\w-]*)(?:=(.*))?$/);
			if (flag && SECRET_FLAG.test(flag[1]) && !NOT_SECRET_FLAG.test(flag[1])) {
				const val = flag[2] !== undefined ? flag[2] : s.args[idx + 1];
				if (val !== undefined && secretLiteral(val) && !findTokens(val).length) { rememberSecret(val.trim(), 'argument secret'); emit('MCP-SEC-005', 'medium', s, flag[2] !== undefined ? sub : argSub(idx + 1), flag[1] + ' ' + mask(val.trim())); }
			}
			if (/^--?(?:insecure|no-verify-ssl|no-verify|ignore-certificate-errors|skip-tls-verify|tls-skip-verify|disable-ssl-verification|allow-insecure)$/i.test(a)) { emit('MCP-NET-007', 'medium', s, sub, a); }
		});
	}

	function urlSecrets(s, sub, value, ctx, emit, rememberSecret) {
		const text = cap(String(value), MAX_SCAN);
		const re = /\b([a-z][a-z0-9+.-]{1,20}):\/\/([^\s"'<>/?#@]{1,300})@/gi;
		let m;
		let count = 0;
		while ((m = re.exec(text)) && count++ < 20) {
			const userinfo = m[2];
			const colon = userinfo.indexOf(':');
			if (colon < 0) { continue; }
			const pw = decodeURIComponentSafe(userinfo.slice(colon + 1));
			if (!pw || isReference(pw) || HAS_REFERENCE.test(pw) || isPlaceholder(pw)) { continue; }
			rememberSecret(userinfo.slice(colon + 1), 'password in URL');
			rememberSecret(pw, 'password in URL');
			emit('MCP-SEC-003', findTokens(pw).length ? 'high' : 'medium', s, sub, 'password in a ' + m[1].toLowerCase() + ' URL: ' + mask(pw));
		}
		const q = /[?&](api[_-]?key|apikey|key|token|access[_-]?token|auth|secret|password|pwd|sig|signature|client[_-]?secret)=([^&#\s"']{6,500})/gi;
		count = 0;
		while ((m = q.exec(text)) && count++ < 20) {
			const v = decodeURIComponentSafe(m[2]);
			if (isReference(v) || HAS_REFERENCE.test(v) || isPlaceholder(v)) { continue; }
			rememberSecret(m[2], 'key in URL');
			rememberSecret(v, 'key in URL');
			const known = findTokens(v);
			ctx.seenSecret.add(v);
			emit('MCP-SEC-003', known.length ? 'high' : 'medium', s, sub, (known.length ? known[0].type : 'value') + ' in URL parameter ' + m[1] + ': ' + mask(v));
		}
	}
	function decodeURIComponentSafe(v) { try { return decodeURIComponent(v); } catch (e) { return v; } }
	function tlsOff(s, sub, k, v, emit) {
		const val = String(v).trim().toLowerCase();
		if ((/^NODE_TLS_REJECT_UNAUTHORIZED$/i.test(k) && val === '0') || (/^PYTHONHTTPSVERIFY$/i.test(k) && val === '0') || (/(?:^|_)(?:SSL_VERIFY|TLS_VERIFY|VERIFY_SSL|VERIFY_TLS|SSL_CERT_VERIFY)$/i.test(k) && /^(?:0|false|no|off)$/.test(val)) || (/(?:^|_)(?:INSECURE|SKIP_TLS_VERIFY|TLS_SKIP_VERIFY|INSECURE_SKIP_VERIFY)$/i.test(k) && /^(?:1|true|yes|on)$/.test(val)) || (/^(?:CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE)$/i.test(k) && val === '')) {
			emit('MCP-NET-007', 'medium', s, sub, k + '=' + v);
		}
	}

	function analyzeUrl(s, ctx, emit, rememberSecret, secretFinding) {
		const sub = [s.urlKey];
		secretFinding(s, sub, s.url, 'the server URL');
		urlSecrets(s, sub, s.url, ctx, emit, rememberSecret);
		let u;
		try { u = new URL(s.url.trim()); } catch (e) { emit('MCP-NET-005', 'low', s, sub, 'the URL could not be parsed', { why: 'The address is not a valid absolute URL.' }); return; }
		const host = u.hostname.toLowerCase();
		const cls = hostClass(host);
		s.hosts.push({ host, scheme: u.protocol.replace(':', ''), sub });
		const credSent = Object.keys(s.headers).some(k => /^(?:authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|cookie|x-[\w-]*(?:token|key|secret))$/i.test(k)) || /@/.test(u.href.split('/')[2] || '') || /[?&](?:api[_-]?key|apikey|key|token|access[_-]?token|auth|secret|password)=/i.test(u.search);
		const plain = u.protocol === 'http:' || u.protocol === 'ws:';
		if (cls === 'metadata') { emit('MCP-NET-003', 'high', s, sub, host); }
		else if (plain && cls === 'private') { emit('MCP-NET-008', credSent ? 'low' : 'info', s, sub, u.protocol + '//' + host + (credSent ? ' with credentials' : '')); }
		else if (plain && cls !== 'local') { emit('MCP-NET-001', credSent ? 'high' : 'medium', s, sub, u.protocol + '//' + host + (credSent ? ' — credentials are sent unencrypted' : ''), credSent ? { why: 'Credentials are configured for this server, so they travel unencrypted.' } : null); }
		if (cls === 'public' || cls === 'public-ip') {
			if (hostIs(host, TUNNEL_SUFFIXES)) { emit('MCP-NET-004', 'medium', s, sub, host); }
			if (hostIs(host, CAPTURE_HOSTS)) { emit('MCP-NET-005', 'medium', s, sub, host + ' (request-capture or paste service)'); }
			else if (/(?:^|\.)xn--/.test(host)) { emit('MCP-NET-005', 'medium', s, sub, host + ' (internationalized name; may imitate another domain)'); }
			else if (hostIs(host, DYNDNS_SUFFIXES)) { emit('MCP-NET-005', 'low', s, sub, host + ' (dynamic DNS)'); }
			else if (cls === 'public-ip') { emit('MCP-NET-005', 'low', s, sub, host + ' (raw IP address)'); }
			if (u.port && !['80', '443', '8080', '8443'].includes(u.port)) { emit('MCP-NET-006', 'info', s, sub, 'port ' + u.port); }
			if (!credSent && u.protocol === 'https:' && !hostIs(host, TUNNEL_SUFFIXES) && !hostIs(host, CAPTURE_HOSTS)) { emit('MCP-NET-002', 'info', s, sub, host); }
		}
	}

	function pathFinding(s, sub, raw, strong, emit, where) {
		const c = classifyPath(raw);
		if (!c) { return; }
		s.paths.push({ raw, norm: c.norm, alias: c.alias || homeAlias(c.norm), sub, kind: c.kind });
		const w = where ? ' (' + where + ')' : '';
		if (c.kind === 'root') { s.caps.add('fs-root'); emit('MCP-FS-001', strong ? 'high' : 'medium', s, sub, raw + w); }
		else if (c.kind === 'home') { s.caps.add('fs-home'); emit('MCP-FS-002', 'medium', s, sub, raw + w); }
		else if (c.kind === 'sensitive') { s.caps.add('fs-sensitive'); emit('MCP-FS-003', strong ? 'high' : 'medium', s, sub, raw + w); }
		else if (c.kind === 'wildcard') { if (c.rootLike) { s.caps.add('fs-root'); } emit('MCP-FS-004', c.rootLike && strong ? 'high' : 'medium', s, sub, raw + w); }
		if (c.kind !== 'temp') { s.caps.add('fs'); }
	}

	function analyzeLaunch(s, command, args, argSub, depth, ctx, emit, secretFinding, rememberSecret, offset) {
		const off = offset || 0;
		const base = baseName(command);
		const sub = idx => (idx < 0 ? (s.cmdPathKey ? ['command', 'path'] : ['command']) : argSub(idx + off));
		s.stages.push(base);
		if (depth > 4) { return; }
		// Executable location.
		const loc = classifyPath(command);
		if (loc && (loc.kind === 'temp' || loc.kind === 'downloads') && depth === 0) { emit('MCP-CMD-007', 'medium', s, sub(-1), command); }
		if (ELEVATE.has(base)) {
			emit('MCP-CMD-006', 'medium', s, depth ? sub(-1 - off) : sub(-1), base);
			let k = 0;
			while (k < args.length && /^-/.test(args[k])) { if (/^-(?:u|g|C|h|p)$|^--(?:user|group)$/.test(args[k])) { k++; } k++; }
			if (k < args.length) { analyzeLaunch(s, args[k], args.slice(k + 1), argSub, depth + 1, ctx, emit, secretFinding, rememberSecret, off + k + 1); }
			return;
		}
		if (SHELLS.has(base) || base === 'cmd' || base === 'powershell' || base === 'pwsh') {
			let script = null, scriptIdx = -1, encoded = null;
			for (let k = 0; k < args.length; k++) {
				const a = args[k];
				if (base === 'cmd' && /^\/[ck]$/i.test(a)) { script = args.slice(k + 1).join(' '); scriptIdx = k + 1; break; }
				if (SHELLS.has(base) && /^-[a-z]*c[a-z]*$/.test(a)) { script = args[k + 1] || ''; scriptIdx = k + 1; break; }
				if ((base === 'powershell' || base === 'pwsh') && /^-(?:c|command)$/i.test(a)) { script = args.slice(k + 1).join(' '); scriptIdx = k + 1; break; }
				if ((base === 'powershell' || base === 'pwsh') && /^-(?:e|ec|enc|encodedcommand)$/i.test(a)) { encoded = args[k + 1] || ''; scriptIdx = k + 1; break; }
				if ((base === 'powershell' || base === 'pwsh') && /^-(?:f|file)$/i.test(a)) { const p = classifyPath(args[k + 1] || ''); if (p && (p.kind === 'temp' || p.kind === 'downloads')) { emit('MCP-CMD-007', 'medium', s, sub(k + 1), args[k + 1]); } break; }
			}
			if (encoded !== null) {
				let decoded = '';
				try { const bin = typeof atob === 'function' ? atob(encoded) : Buffer.from(encoded, 'base64').toString('binary'); for (let k = 0; k + 1 < bin.length && k < MAX_SCAN * 2; k += 2) { decoded += String.fromCharCode(bin.charCodeAt(k) | (bin.charCodeAt(k + 1) << 8)); } } catch (e) { decoded = ''; }
				emit('MCP-CMD-002', 'medium', s, sub(scriptIdx), 'encoded PowerShell command' + (decoded ? ': ' + cap(decoded, 200) : ''), { why: 'The command is Base64-encoded, which hides what runs.' });
				if (decoded) { script = decoded; }
			}
			if (script !== null) {
				const sc = cap(script, MAX_SCAN);
				const pipe = /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|fetch)\b[^|\n]{0,500}\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k|fi|a)?sh|iex|invoke-expression|python3?|node|perl|ruby|pwsh|powershell)\b/i;
				const subst = /(?:\$\(|`)\s*(?:curl|wget)\b|\b(?:iex|invoke-expression)\s*\(?\s*\(?\s*(?:iwr|irm|invoke-webrequest|invoke-restmethod|\(?\s*new-object\s+net\.webclient)/i;
				const dl = /\bdownloadstring\s*\(|\bdownloadfile\s*\(/i;
				if (pipe.test(sc) || subst.test(sc) || dl.test(sc)) { emit('MCP-CMD-001', 'high', s, sub(scriptIdx), cap(sc.replace(/\s+/g, ' '), 200)); }
				else if (encoded === null) {
					const chained = /&&|\|\||;|\||`|\$\(|>|</.test(sc);
					emit('MCP-CMD-002', chained ? 'medium' : 'info', s, sub(scriptIdx), base + ': ' + cap(sc.replace(/\s+/g, ' '), 200));
				}
				const segments = sc.split(/&&|\|\||;|\|/).slice(0, 10);
				for (const seg of segments) {
					const toks = shellSplit(seg);
					if (toks.length) { analyzeLaunch(s, toks[0], toks.slice(1), () => sub(scriptIdx), depth + 1, ctx, emit, secretFinding, rememberSecret, 0); }
				}
			}
			return;
		}
		const fsServer = /filesystem|(?:^|[-_/])fs(?:$|[-_])|(?:^|[-_/])files?(?:$|[-_])/i;
		// Package runners.
		let pkgArgs = null, eco = null, k0 = 0;
		if (base === 'npx' || base === 'bunx') { pkgArgs = args; eco = 'npm'; }
		else if ((base === 'pnpm' || base === 'yarn') && /^(?:dlx|exec)$/.test(args[0] || '')) { pkgArgs = args.slice(1); eco = 'npm'; k0 = 1; }
		else if (base === 'npm' && /^(?:exec|x)$/.test(args[0] || '')) { pkgArgs = args.slice(1).filter(a => a !== '--'); eco = 'npm'; k0 = 1; }
		else if (base === 'uvx') { pkgArgs = args; eco = 'pypi'; }
		else if (base === 'uv' && args[0] === 'tool' && args[1] === 'run') { pkgArgs = args.slice(2); eco = 'pypi'; k0 = 2; }
		else if (base === 'pipx' && args[0] === 'run') { pkgArgs = args.slice(1); eco = 'pypi'; k0 = 1; }
		if (pkgArgs) {
			const specs = [];
			let first = -1;
			for (let k = 0; k < pkgArgs.length; k++) {
				const a = pkgArgs[k];
				const eq = a.match(/^(--?[\w-]+)=(.*)$/);
				const flag = eq ? eq[1] : a;
				if (eco === 'npm' && (flag === '-p' || flag === '--package')) { specs.push({ spec: eq ? eq[2] : pkgArgs[k + 1], idx: k0 + k + (eq ? 0 : 1) }); if (!eq) { k++; } continue; }
				if (eco === 'pypi' && (flag === '--from' || flag === '--spec' || flag === '--with')) { specs.push({ spec: eq ? eq[2] : pkgArgs[k + 1], idx: k0 + k + (eq ? 0 : 1), with: flag === '--with' }); if (!eq) { k++; } continue; }
				if (/^-/.test(a)) { if (!eq && ((eco === 'npm' && NPX_VALUE_FLAGS.has(a)) || (eco === 'pypi' && UVX_VALUE_FLAGS.has(a)))) { k++; } continue; }
				first = k;
				break;
			}
			const hasFrom = specs.some(x => !x.with);
			if (first >= 0 && !(eco === 'npm' && specs.length) && !(eco === 'pypi' && hasFrom)) { specs.push({ spec: pkgArgs[first], idx: k0 + first }); }
			for (const sp of specs) {
				if (!sp.spec) { continue; }
				const p = eco === 'npm' ? npmSpec(sp.spec) : pySpec(sp.spec);
				if (!p) { continue; }
				if (p.kind === 'source') { if (!p.pinned) { emit('MCP-CMD-009', 'medium', s, sub(sp.idx), sp.spec); } s.packages.push({ name: p.name, ecosystem: eco, pinned: p.pinned, version: '', sub: sub(sp.idx) }); continue; }
				if (p.kind === 'local') { continue; }
				s.packages.push({ name: p.name, ecosystem: eco, pinned: p.pinned, version: p.version, sub: sub(sp.idx) });
				if (!p.pinned) { emit('MCP-CMD-003', 'info', s, sub(sp.idx), base + ' ' + sp.spec + (p.version ? ' (version "' + p.version + '" is not exact)' : ' (no version)')); }
			}
			// Positional arguments after the package are server arguments.
			const rest = first >= 0 ? pkgArgs.slice(first + 1) : [];
			const pkgName = (s.packages[s.packages.length - 1] || {}).name || '';
			serverArgs(s, rest, k0 + first + 1, sub, fsServer.test(pkgName) || fsServer.test(s.name), emit);
			if ((fsServer.test(pkgName) && /filesystem/.test(pkgName)) && !rest.some(a => !/^-/.test(a))) { emit('MCP-HYG-002', 'low', s, sub(k0 + first), pkgName); }
			if (/fetch|browser|puppeteer|playwright|brave-search|search/.test(pkgName)) { s.caps.add('egress'); }
			if (/filesystem|gmail|mail|postgres|sqlite|mysql|drive|notion|github|gitlab|slack|memory/.test(pkgName)) { s.caps.add('private'); }
			if (/slack|gmail|mail|discord|telegram|github|gitlab/.test(pkgName)) { s.caps.add('egress-maybe'); }
			return;
		}
		if (base === 'docker' || base === 'podman' || base === 'nerdctl') { analyzeDocker(s, args, sub, emit, secretFinding, rememberSecret); return; }
		// Interpreters.
		if (INTERP_INLINE[base] || base === 'deno') {
			const inl = INTERP_INLINE[base] || [];
			for (let k = 0; k < args.length; k++) {
				if (inl.includes(args[k]) || (base === 'deno' && k === 0 && args[k] === 'eval')) { emit('MCP-CMD-008', 'medium', s, sub(k + 1), base + ' ' + args[k] + ' ' + cap(args[k + 1] || '', 120)); break; }
				if (!/^-/.test(args[k])) {
					const p = classifyPath(args[k]);
					if (p && (p.kind === 'temp' || p.kind === 'downloads')) { emit('MCP-CMD-007', 'medium', s, sub(k), args[k]); }
					serverArgs(s, args.slice(k + 1), k + 1, sub, fsServer.test(s.name), emit);
					break;
				}
			}
			return;
		}
		serverArgs(s, args, 0, sub, fsServer.test(s.name) || fsServer.test(base), emit);
	}

	/** Paths given to a server: positional paths and values of path flags. */
	function serverArgs(s, args, offset, sub, fsServer, emit) {
		for (let k = 0; k < args.length; k++) {
			const a = args[k];
			const eq = a.match(/^(--?[\w-]+)=(.*)$/);
			if (eq && PATH_FLAG.test(eq[1])) { for (const part of eq[2].split(',')) { pathFinding(s, sub(offset + k), part, true, emit); } continue; }
			if (PATH_FLAG.test(a) && k + 1 < args.length && !/^-/.test(args[k + 1])) { for (const part of args[k + 1].split(',')) { pathFinding(s, sub(offset + k + 1), part, true, emit); } k++; continue; }
			if (/^-/.test(a)) { continue; }
			if (fsServer || isPathLike(a)) { if (isPathLike(a) || fsServer) { if (fsServer || /^(?:[A-Za-z]:[\\/]?$|\/$|~$|\$HOME$|%USERPROFILE%$)/i.test(a.trim()) || classifyPath(a).kind !== 'other') { pathFinding(s, sub(offset + k), a, fsServer, emit); } else { pathFinding(s, sub(offset + k), a, false, emit); } } }
		}
	}

	function analyzeDocker(s, args, sub, emit, secretFinding, rememberSecret) {
		const runIdx = args.findIndex(a => a === 'run' || a === 'create');
		if (runIdx < 0) { return; }
		let k = runIdx + 1;
		let image = null, imageIdx = -1;
		const flagValue = (a, idx) => { const eq = a.indexOf('='); return a.startsWith('--') && eq > 0 ? [a.slice(0, eq), a.slice(eq + 1), idx] : [a, args[idx + 1], idx + 1]; };
		while (k < args.length) {
			const a = args[k];
			if (!/^-/.test(a)) { image = a; imageIdx = k; break; }
			const [flag, val, vIdx] = flagValue(a, k);
			const takesValue = DOCKER_VALUE_FLAGS.has(flag);
			const consumed = takesValue && !(a.startsWith('--') && a.includes('='));
			if (flag === '--privileged') { emit('MCP-CMD-004', 'high', s, sub(k), '--privileged'); s.caps.add('host'); }
			if (takesValue && val !== undefined) {
				const lv = String(val).toLowerCase();
				if ((flag === '--network' || flag === '--net' || flag === '--pid' || flag === '--ipc' || flag === '--uts' || flag === '--userns' || flag === '--cgroupns') && lv === 'host') { emit('MCP-CMD-004', 'medium', s, sub(vIdx), flag + '=host'); }
				if (flag === '--cap-add') { if (lv === 'all') { emit('MCP-CMD-004', 'high', s, sub(vIdx), '--cap-add=ALL'); } else if (/^(?:cap_)?(?:sys_admin|sys_ptrace|sys_module|dac_read_search|dac_override|net_admin|net_raw|sys_rawio|bpf|perfmon)$/.test(lv)) { emit('MCP-CMD-004', 'medium', s, sub(vIdx), '--cap-add=' + val); } }
				if (flag === '--security-opt' && /(?:seccomp|apparmor)[=:]unconfined|label[=:]disable|no-new-privileges[=:]false/.test(lv)) { emit('MCP-CMD-004', 'medium', s, sub(vIdx), '--security-opt ' + val); }
				if (flag === '--device') { emit('MCP-CMD-004', 'medium', s, sub(vIdx), '--device ' + val); }
				if (flag === '-v' || flag === '--volume' || flag === '--mount') {
					let src = '', ro = false;
					if (flag === '--mount') { const kv = Object.fromEntries(String(val).split(',').map(x => { const e = x.indexOf('='); return e > 0 ? [x.slice(0, e).trim().toLowerCase(), x.slice(e + 1).trim()] : [x.trim().toLowerCase(), 'true']; })); src = kv.source || kv.src || ''; ro = 'readonly' in kv || 'ro' in kv; if ((kv.type || 'volume') !== 'bind') { src = src && /[\\/]/.test(src) ? src : ''; } }
					else { const v = splitVolume(val); src = v.src; ro = /(?:^|,)ro(?:,|$)/.test(v.opts); }
					if (src && /[\\/~$%]/.test(src)) {
						const c = classifyPath(src);
						if (/(?:^|\/)docker\.sock$|^\/\/\.\/pipe\/docker_engine$|^\\\\\.\\pipe\\docker_engine$/i.test(src.replace(/\\/g, '/')) || /docker_engine$/i.test(src)) { emit('MCP-CMD-004', 'high', s, sub(vIdx), 'Docker socket mounted: ' + src); s.caps.add('host'); }
						else if (c && c.kind === 'root') { emit('MCP-CMD-005', 'high', s, sub(vIdx), src + (ro ? ' (read-only)' : '')); s.caps.add('fs-root'); s.paths.push({ raw: src, norm: c.norm, alias: null, sub: sub(vIdx), kind: 'root' }); }
						else if (c && c.kind === 'home') { emit('MCP-CMD-005', 'medium', s, sub(vIdx), src + (ro ? ' (read-only)' : '')); s.caps.add('fs-home'); s.paths.push({ raw: src, norm: c.norm, alias: c.alias || homeAlias(c.norm), sub: sub(vIdx), kind: 'home' }); }
						else { pathFinding(s, sub(vIdx), src, true, emit, 'container mount'); }
					}
				}
				if (flag === '-e' || flag === '--env') {
					const eq = String(val).indexOf('=');
					if (eq > 0) {
						const name = val.slice(0, eq), v = val.slice(eq + 1);
						if (!secretFinding(s, sub(vIdx), v, 'container variable ' + name) && SECRET_NAME.test(name) && !NOT_SECRET_NAME.test(name) && secretLiteral(v)) { rememberSecret(v.trim(), 'secret'); emit('MCP-SEC-001', 'medium', s, sub(vIdx), name + ' = ' + mask(v.trim())); }
						tlsOff(s, sub(vIdx), name, v, emit);
					}
				}
			}
			k += consumed ? 2 : 1;
		}
		if (image) {
			const ref = imageRef(image);
			s.images.push({ name: ref.name, pinned: ref.pinned, sub: sub(imageIdx) });
			if (!ref.pinned) { emit('MCP-HYG-001', 'low', s, sub(imageIdx), image + (ref.tag ? '' : ' (no tag)')); }
		}
	}

	function autoApproval(s, emit) {
		const sub = s.autoApproveKey ? [s.autoApproveKey] : ['trust'];
		const risky = /(?:^|_|-)(?:exec|execute|run|shell|bash|cmd|command|terminal|eval|write|edit|delete|remove|rm|move|rename|create|update|merge|push|send|post|reply|forward|upload|drop|deploy|publish|transfer|pay|commit|close|kill)(?:_|-|$)|^(?:write|delete|send|run|exec|create|update|merge|push|post|deploy)/i;
		const toolRisk = n => risky.test(n) || s.tools.some(t => t.name === n && t.caps && (t.caps.has('exec') || t.caps.has('write') || t.caps.has('egress')));
		const toolsRisky = s.tools.some(t => t.caps && (t.caps.has('exec') || t.caps.has('write') || t.caps.has('egress')));
		if (s.trust) { emit('MCP-HYG-004', toolsRisky ? 'high' : 'medium', s, ['trust'], 'trust: true — every tool call of this server runs without confirmation'); }
		if (!s.autoApproveKey) { return; }
		if (s.autoWildcard) { emit('MCP-HYG-004', toolsRisky ? 'high' : 'medium', s, sub, s.autoApproveKey + ': all tools' + (toolsRisky ? ', including tools that execute, write or send' : '')); return; }
		const riskyNames = s.autoApprove.filter(toolRisk);
		if (riskyNames.length) { emit('MCP-HYG-004', 'high', s, sub, s.autoApproveKey + ': ' + riskyNames.slice(0, 8).join(', ') + (riskyNames.length > 8 ? ' …' : '') + ' (tools with side effects)'); }
		else if (s.autoApprove.length >= 10) { emit('MCP-HYG-004', 'medium', s, sub, s.autoApprove.length + ' tools approved automatically'); }
		else if (s.autoApprove.length && !s.autoApprove.every(n => /^(?:get|list|read|search|find|describe|show|view|convert|query|lookup|fetch_?status|status|count|explain|help)[_-]?/i.test(n))) { emit('MCP-HYG-004', 'low', s, sub, s.autoApprove.join(', ')); }
		else if (s.autoApprove.length) { emit('MCP-HYG-004', 'info', s, sub, s.autoApprove.join(', ') + ' (read-only names)'); }
	}

	// ---- tools
	function toolTexts(t) {
		const out = [];
		if (t.description) { out.push({ text: t.description, sub: ['description'], kind: 'description' }); }
		if (t.title) { out.push({ text: t.title, sub: ['title'], kind: 'title' }); }
		let budget = 2000;
		const walk = (node, sub, depth) => {
			if (!isObj(node) || depth > 12 || budget-- <= 0) { return; }
			for (const key of ['description', 'title']) { if (typeof node[key] === 'string') { out.push({ text: node[key], sub: sub.concat(key), kind: 'argument' }); } }
			if (typeof node.default === 'string') { out.push({ text: node.default, sub: sub.concat('default'), kind: 'argument' }); }
			if (Array.isArray(node.enum)) { node.enum.forEach((e, idx) => { if (typeof e === 'string' && e.length > 20) { out.push({ text: e, sub: sub.concat('enum', idx), kind: 'argument' }); } }); }
			if (isObj(node.properties)) { for (const p of Object.keys(node.properties)) { walk(node.properties[p], sub.concat('properties', p), depth + 1); } }
			if (isObj(node.items)) { walk(node.items, sub.concat('items'), depth + 1); }
			for (const comb of ['anyOf', 'oneOf', 'allOf']) { if (Array.isArray(node[comb])) { node[comb].forEach((x, idx) => walk(x, sub.concat(comb, idx), depth + 1)); } }
		};
		if (t.schema) { walk(t.schema, [t.obj && t.obj.input_schema ? 'input_schema' : 'inputSchema'], 0); }
		return out;
	}
	const stringParams = schema => (isObj(schema) && isObj(schema.properties) ? Object.entries(schema.properties).filter(([, p]) => isObj(p) && (p.type === 'string' || (Array.isArray(p.type) && p.type.includes('string')))) : []);
	const unconstrained = p => !Array.isArray(p.enum) && p.const === undefined && typeof p.pattern !== 'string';

	const TP = {
		zw: /[\u200B-\u200F\u2060-\u2064\uFEFF\u180E\u00AD]/g,
		bidi: /[\u202A-\u202E\u2066-\u2069]/g,
		tags: /[\u{E0000}-\u{E007F}]/gu,
		override: /\b(?:ignore|disregard|forget|override|bypass|skip)\b[^.!?\n]{0,40}?\b(?:all|any|the|your|every)?\s*(?:previous|prior|above|earlier|preceding|other|system|original|safety|existing)\b[^.!?\n]{0,20}?\b(?:instructions?|prompts?|rules|guidelines|directions|messages|policies|guardrails)\b/i,
		newRole: /\b(?:you must now|from now on,? you|new instructions?:|act as (?:an?|the) (?:different|new|unrestricted)|you are now (?:an?|in) |developer mode|jailbreak)\b/i,
		conceal: /\b(?:do not|don't|never|without)\b[^.!?\n]{0,30}?\b(?:tell|inform|mention|reveal|show|notify|alert|let)\b[^.!?\n]{0,20}?\bthe user\b|\bthe user (?:does not|doesn't|need not|needn't|should not|shouldn't|must not) (?:need to )?(?:know|be told|see|notice)\b|\bwithout (?:the )?user(?:'s|s)? (?:knowledge|consent|noticing|approval|awareness)\b|\b(?:silently|secretly|covertly)\b/i,
		sensitive: /~\/\.ssh|\.ssh\/|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws\/credentials|\b\.aws\b|(?:^|[\s'"`(])\.env\b|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\bmcp\.json\b|claude_desktop_config|\.cursor\/|\bcredentials? files?\b|\bprivate keys?\b|\/etc\/(?:passwd|shadow)|\bkeychain\b|\bapi[ _-]?keys?\b|\baccess tokens?\b|\bpasswords?\b|\bsecrets?\b|\benvironment variables\b|\bsession cookies?\b|\bconversation history\b|\bsystem prompt\b/i,
		specific: /~\/\.ssh|\.ssh\/|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws\/credentials|\b\.aws\b|(?:^|[\s'"`(])\.env\b|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\bmcp\.json\b|claude_desktop_config|\.cursor\/|\bcredentials? files?\b|\bprivate keys?\b|\/etc\/(?:passwd|shadow)|\bkeychain\b/i,
		action: /\b(?:read|open|cat|load|include|send|pass|attach|upload|forward|copy|provide|put|insert|append|add|embed|paste|share|transmit|post|leak|exfiltrate|extract|dump|collect)\b/i,
		markup: /<\s*\/?\s*(?:important|system|instructions?|secret|hidden|admin|assistant|im_start|im_end|critical)\b[^>]{0,40}>|\[\s*\/?(?:INST|SYSTEM)\s*\]|<!--|\{\{\s*(?:system|instructions?)\s*\}\}|<\|(?:im_start|im_end|system)\|>/i,
		otherTools: /\b(?:all|any|every|other) (?:other )?tools?\b[^.!?\n]{0,60}?\b(?:always|must|instead|also|first)\b|\b(?:when|whenever|before|after|instead of)\b[^.!?\n]{0,40}?\b(?:any|other|another) (?:tool|function|server)\b/i,
		redirect: /\b(?:always|also|instead|must|redirect|bcc|cc|forward|replace|change|override|add|copy|send)\b/i,
		blob: /[A-Za-z0-9+/]{160,}={0,2}/
	};
	const sentences = s => cap(s, MAX_SCAN).replace(/([.!?])\s+/g, '$1\n').split(/\n+/).slice(0, 400);

	function analyzeTool(s, t, ctx, emit, secretFinding) {
		const base = t.path.slice(s.path.length);
		const tsub = rest => base.concat(rest || []);
		const caps = t.caps = new Set();
		const name = String(t.name);
		const lname = name.toLowerCase();
		const desc = cap(t.description, MAX_SCAN);
		const ro = t.annotations.readOnlyHint === true || /\bread[- ]only\b/i.test(desc);
		const sp = stringParams(t.schema);
		const label = 'tool "' + cap(name, 80) + '"';
		const emitT = (rule, sev, rest, ev, extra) => emit(rule, sev, s, tsub(rest), ev, extra);
		// Capability classification (names and descriptions).
		const execName = /(?:^|[_-])(?:exec|execute|shell|bash|sh|cmd|terminal|powershell|pwsh|subprocess|spawn|system)(?:[_-]|$)|run[_-]?(?:command|cmd|shell|script|code|python|js|javascript|bash|process|program)|python[_-]?(?:exec|run|repl)|(?:code|script)[_-]?(?:exec|run|runner|interpreter)|^eval(?:uate)?[_-]?(?:code|python|js)?$/i;
		const execDesc = /\b(?:execut\w*|runs?|running)\b[^.!?\n]{0,40}?\b(?:shell|commands?|code|scripts?|python|bash|powershell|process(?:es)?|programs?)\b|\barbitrary (?:code|commands?|programs?)\b/i;
		const browserEval = /(?:evaluate|eval|execute|run|inject)[^.!?\n]{0,30}?\b(?:javascript|js|script)\b|browser[_-]?evaluate|run[_-]?javascript|evaluate[_-]?script/i;
		const sqlTool = /(?:^|[_-])(?:sql|query|execute[_-]?(?:sql|query|statement)|run[_-]?(?:sql|query))(?:[_-]|$)|^(?:query|sql)$/i;
		const isBrowserEval = browserEval.test(name) || browserEval.test(desc);
		const isSql = (sqlTool.test(name) && (/\bsql\b|database|statement|query/i.test(desc) || sp.some(([p]) => /^(?:sql|statement|query)$/i.test(p)))) || (/\bsql\b/i.test(desc) && /\bexecut|\brun\b/i.test(desc));
		if (!isBrowserEval && !isSql && (execName.test(name) || execDesc.test(desc))) {
			caps.add('exec');
			const free = sp.filter(([, p]) => unconstrained(p));
			const high = free.length > 0 || /\barbitrary\b/i.test(desc);
			emitT('MCP-CAP-001', high ? 'high' : 'medium', [], label + (free.length ? ' — unrestricted argument ' + free.map(([p]) => p).slice(0, 3).join(', ') : ''));
		}
		if (isBrowserEval) { caps.add('exec'); caps.add('egress'); emitT('MCP-CAP-004', 'medium', [], label + ' — runs JavaScript in a web page'); }
		else if (/^browser[_-]|(?:^|[_-])(?:navigate|click|screenshot|page|puppeteer|playwright)(?:[_-]|$)/i.test(name)) { caps.add('browser'); caps.add('egress'); s.browserTools = (s.browserTools || 0) + 1; }
		if (isSql) {
			caps.add('private');
			const write = /\b(?:insert|update|delete|drop|alter|create|truncate|grant|any sql|arbitrary|all statements|write)\b/i.test(desc) || /^(?:execute|run)[_-]/i.test(name);
			if (!ro) { emitT('MCP-CAP-007', write ? 'medium' : 'low', [], label + (write ? ' — can change data' : ' — read-only status unknown')); }
		}
		if (/(?:^|[_-])(?:write|edit|delete|remove|move|rename|overwrite|append|patch|upload|create)[_-]?(?:file|files|directory|dir|folder|path|paths)(?:[_-]|$)|^(?:rm|mv|cp|mkdir|unlink|rmdir|delete)$/i.test(lname) || (t.annotations.destructiveHint === true && /file|director|folder|path/i.test(lname + ' ' + desc))) {
			caps.add('write');
			const sev = s.caps.has('fs-root') || s.caps.has('fs-sensitive') ? 'high' : s.caps.has('fs-home') ? 'medium' : 'low';
			emitT('MCP-CAP-002', sev, [], label + (sev === 'high' ? ' — on a server with access to the whole file system or credential folders' : sev === 'medium' ? ' — on a server with access to the home directory' : ''));
		}
		if (/(?:^|[_-])(?:read|get|cat|view|open|search|list)[_-]?(?:text[_-]?)?(?:file|files|file[_-]?contents|directory|multiple[_-]?files)(?:[_-]|$)|^read[_-]/i.test(lname)) { caps.add('private'); }
		if (/(?:^|[_-])(?:send|post|reply|forward|share)[_-]?(?:email|emails|mail|message|messages|msg|sms|dm|chat|tweet|notification)s?(?:[_-]|$)/i.test(lname)) { caps.add('egress'); caps.add('send'); emitT('MCP-CAP-005', 'low', [], label + ' — sends messages'); }
		else if (/(?:^|[_-])(?:read|list|get|search)[_-]?(?:inbox|emails?|mails?|messages)(?:[_-]|$)/i.test(lname)) { caps.add('private'); emitT('MCP-CAP-005', 'low', [], label + ' — reads messages'); }
		const urlParam = sp.find(([p, d]) => /^(?:url|uri|endpoint|href|link|address|target)$/i.test(p) && unconstrained(d));
		if (!caps.has('browser') && !isBrowserEval && (/(?:^|[_-])(?:fetch|http|download|curl|wget|scrape|crawl|browse)(?:[_-]|$)|^get[_-]?url$|web[_-]?(?:fetch|request|get)|(?:^|[_-])(?:http|make|send|web|api|url)[_-]?request(?:[_-]|$)|^request$/i.test(lname) || (urlParam && /\b(?:fetch|request|download|retriev|get|open|call)\w*\b/i.test(desc)))) {
			caps.add('egress');
			emitT('MCP-CAP-003', 'low', [], label + (urlParam ? ' — any URL in "' + urlParam[0] + '"' : ''));
		}
		if (!caps.has('exec')) {
			const codeParams = sp.filter(([p, d]) => /^(?:command|cmd|script|code|shell|statement|expression|program)$/i.test(p) && unconstrained(d));
			if (codeParams.length && !isSql) { emitT('MCP-CAP-006', 'low', ['inputSchema', 'properties', codeParams[0][0]], label + ' — ' + codeParams.map(([p]) => p).join(', ')); }
		}
		for (const c of caps) { s.caps.add(c === 'private' ? 'private' : c === 'egress' ? 'egress' : c); }

		// Poisoning.
		const texts = toolTexts(t);
		const tp = new Set();
		let tpFindings = [];
		for (const tx of texts) {
			const text = String(tx.text);
			secretFinding(s, tsub(tx.sub), text, 'the ' + tx.kind + ' of ' + label);
			const zw = (text.match(TP.zw) || []).length;
			const bidi = (text.match(TP.bidi) || []).length;
			const tagChars = text.match(TP.tags) || [];
			if (zw || bidi || tagChars.length) {
				const hidden = tagChars.map(ch => { const cp = ch.codePointAt(0) - 0xE0000; return cp >= 32 && cp < 127 ? String.fromCharCode(cp) : ''; }).join('');
				const parts = [];
				if (zw) { parts.push(zw + ' zero-width character' + (zw === 1 ? '' : 's')); }
				if (bidi) { parts.push(bidi + ' text-direction control' + (bidi === 1 ? '' : 's')); }
				if (tagChars.length) { parts.push(tagChars.length + ' invisible tag character' + (tagChars.length === 1 ? '' : 's') + (hidden ? ' spelling "' + cap(hidden, 200) + '"' : '')); }
				tp.add('TP-001');
				tpFindings.push(emitT('MCP-TP-001', bidi || tagChars.length ? 'high' : 'medium', tx.sub, label + ', ' + tx.kind + ': ' + parts.join(', ')));
			}
			const visible = cap(text.replace(TP.zw, '').replace(TP.bidi, '').replace(TP.tags, ''), MAX_SCAN);
			if (TP.override.test(visible) || TP.newRole.test(visible)) { tp.add('TP-002'); tpFindings.push(emitT('MCP-TP-002', 'medium', tx.sub, label + ': "' + cap(((visible.match(TP.override) || visible.match(TP.newRole))[0]), 120) + '"')); }
			if (TP.conceal.test(visible)) { tp.add('TP-003'); tpFindings.push(emitT('MCP-TP-003', 'medium', tx.sub, label + ': "' + cap(visible.match(TP.conceal)[0], 120) + '"')); }
			for (const sent of sentences(visible)) {
				if (TP.sensitive.test(sent) && TP.action.test(sent)) {
					const specific = TP.specific.test(sent);
					const inArg = tx.kind === 'argument';
					if (specific || inArg || /\b(?:before|first|always|must|note to|ignore)\b/i.test(sent)) {
						tp.add('TP-004');
						tpFindings.push(emitT('MCP-TP-004', specific || inArg ? 'high' : 'medium', tx.sub, label + ': "' + cap(sent.trim(), 160) + '"'));
						break;
					}
				}
			}
			if (TP.markup.test(visible)) { tp.add('TP-005'); tpFindings.push(emitT('MCP-TP-005', 'medium', tx.sub, label + ': ' + cap(visible.match(TP.markup)[0], 60))); }
			if (text.length > 4000 && tx.kind === 'description') { emitT('MCP-TP-007', 'low', tx.sub, label + ': ' + text.length + ' characters'); }
			else if (TP.blob.test(visible)) { emitT('MCP-TP-007', 'low', tx.sub, label + ': long encoded-looking block'); }
			t.visibleTexts = (t.visibleTexts || []).concat({ text: visible, sub: tx.sub, kind: tx.kind });
		}
		// Combinations raise severity: markup or override together with concealment or data requests.
		tpFindings = tpFindings.filter(Boolean);
		const combo = (tp.has('TP-002') || tp.has('TP-005')) && (tp.has('TP-003') || tp.has('TP-004') || tp.has('TP-001')) || (tp.has('TP-002') && tp.has('TP-005'));
		if (combo) { for (const f of tpFindings) { if ((f.rule === 'MCP-TP-002' || f.rule === 'MCP-TP-005' || f.rule === 'MCP-TP-003') && f.severity !== 'high') { f.severity = 'high'; f.explanation = 'Several injection signals appear in the same tool. ' + f.explanation; } } }
		if (tp.size) { s.caps.add('poisoned'); }
	}

	// ---- whole configuration
	function analyzeCombinations(servers, ctx, emit, parsed) {
		const config = servers.filter(s => s.kind === 'config');
		// Duplicate JSON keys.
		for (const d of parsed.duplicates.slice(0, 200)) {
			const p = d.path.map(String);
			const important = p.length && (['mcpServers', 'servers', 'context_servers', 'mcp_servers'].includes(p[p.length - 1]) || ['env', 'headers', 'args', 'command', 'url', 'autoApprove', 'alwaysAllow'].includes(d.key) || p.includes('env') || p.includes('headers'));
			emit('MCP-NAME-003', important ? 'medium' : 'low', null, d.path.concat(d.key), '"' + cap(d.key, 80) + '" appears on lines ' + d.firstLine + ' and ' + d.line + '; only one is used', { line: d.line });
		}
		// Tool names across servers.
		const byName = new Map();
		for (const s of servers) {
			const seen = new Set();
			for (const t of s.tools) {
				const k = String(t.name).toLowerCase();
				if (seen.has(k)) { continue; }
				seen.add(k);
				if (!byName.has(k)) { byName.set(k, []); }
				byName.get(k).push({ s, t });
			}
		}
		for (const [k, list] of byName) {
			const owners = [...new Set(list.map(x => x.s.name))];
			if (owners.length > 1) { emit('MCP-NAME-001', 'medium', list[1].s, list[1].t.path.slice(list[1].s.path.length), '"' + cap(k, 80) + '" is offered by ' + owners.map(o => '"' + cap(o, 60) + '"').join(', ')); }
		}
		const names = [...byName.keys()].slice(0, 2000);
		const norm = n => n.replace(/[-_\s.]/g, '');
		const reported = new Set();
		for (let a = 0; a < names.length; a++) {
			for (let b = a + 1; b < names.length; b++) {
				const x = names[a], y = names[b];
				if (Math.abs(x.length - y.length) > 1 || x === y) { continue; }
				const ownersX = byName.get(x).map(o => o.s.name), ownersY = byName.get(y).map(o => o.s.name);
				if (ownersX.every(o => ownersY.includes(o)) && ownersY.every(o => ownersX.includes(o))) { continue; }
				const similar = norm(x) === norm(y) || (x.length >= 6 && levenshtein(x, y, 1) <= 1);
				if (similar && !reported.has(x + '|' + y)) {
					reported.add(x + '|' + y);
					const o = byName.get(y)[0];
					emit('MCP-NAME-002', 'low', o.s, o.t.path.slice(o.s.path.length), '"' + cap(x, 60) + '" (' + cap(ownersX[0], 40) + ') and "' + cap(y, 60) + '" (' + cap(ownersY[0], 40) + ')');
				}
			}
		}
		// Look-alike package names (short built-in list, no registry access).
		for (const s of config) {
			for (const p of s.packages) {
				if (!p.name || KNOWN_PACKAGES.includes(p.name) || p.name.length < 8) { continue; }
				let match = null;
				for (const known of KNOWN_PACKAGES) {
					const d = levenshtein(p.name, known, 2);
					const sameTail = p.name.includes('/') && known.includes('/') && p.name.split('/')[1] === known.split('/')[1] && levenshtein(p.name.split('/')[0], known.split('/')[0], 3) <= 3;
					if ((d > 0 && d <= 2) || sameTail) { match = known; break; }
				}
				if (match) { emit('MCP-NAME-004', 'medium', s, p.sub.slice(s.path.length ? 0 : 0), p.name + ' resembles ' + match); }
			}
		}
		// Cross-server references in descriptions.
		const toolOwner = new Map();
		for (const s of servers) { for (const t of s.tools) { if (String(t.name).length >= 4) { toolOwner.set(String(t.name).toLowerCase(), s); } } }
		for (const s of servers) {
			for (const t of s.tools) {
				for (const tx of t.visibleTexts || []) {
					let hit = null;
					for (const sent of sentences(tx.text)) {
						const words = sent.toLowerCase().match(/[a-z0-9_.-]{4,80}/g) || [];
						const other = words.find(w => toolOwner.has(w) && toolOwner.get(w) !== s && w !== String(t.name).toLowerCase());
						if ((other && TP.redirect.test(sent)) || (TP.otherTools.test(sent) && TP.redirect.test(sent))) { hit = { sent, other }; break; }
					}
					if (hit) { emit('MCP-TP-006', 'medium', s, t.path.slice(s.path.length).concat(tx.sub), 'tool "' + cap(t.name, 60) + '": "' + cap(hit.sent.trim(), 160) + '"' + (hit.other ? ' (refers to "' + hit.other + '" of server "' + cap(toolOwner.get(hit.other).name, 60) + '")' : '')); break; }
				}
			}
		}
		// Private data + outbound channel.
		const priv = servers.filter(s => s.caps.has('private') || s.caps.has('fs') || s.caps.has('fs-root') || s.caps.has('fs-home') || s.caps.has('fs-sensitive'));
		const out = servers.filter(s => s.caps.has('egress'));
		if (priv.length && out.length && (priv.some(p => out.some(o => o !== p)) || priv.some(p => p.caps.has('private') && p.caps.has('egress') && p.tools.some(t => t.caps && t.caps.has('private')) && p.tools.some(t => t.caps && t.caps.has('egress'))))) {
			const auto = s => s.autoWildcard || s.trust || s.autoApprove.some(n => s.tools.some(t => t.name === n && t.caps && t.caps.has('egress')) || /send|post|fetch|forward|upload|http|request/i.test(n));
			const high = out.some(auto);
			const target = out[0];
			emit('MCP-CAP-008', high ? 'high' : 'medium', target, [], 'private data: ' + priv.map(x => '"' + cap(x.name, 40) + '"').slice(0, 4).join(', ') + '; outbound: ' + out.map(x => '"' + cap(x.name, 40) + '"').slice(0, 4).join(', ') + (high ? '; outbound calls are approved automatically' : ''));
		}
		// Many tools in total.
		const totalTools = servers.reduce((n, s) => n + s.tools.length, 0);
		if (totalTools > 100) { emit('MCP-HYG-005', 'low', null, [], totalTools + ' tools across all servers'); }
		// Timeouts.
		const runnable = config.filter(s => s.command || s.url);
		if (runnable.length && !runnable.some(s => s.hasTimeout)) { emit('MCP-HYG-003', 'info', null, [], runnable.length + ' server' + (runnable.length === 1 ? '' : 's') + ' without a timeout setting'); }
	}

	// ------------------------------------------------------------------ policy
	const POLICY_KEYS = {
		version: 'number', description: 'string',
		allowedCommands: 'list', deniedCommands: 'list', allowedPackages: 'list', deniedPackages: 'list', requirePinnedVersions: 'boolean',
		allowedHosts: 'list', deniedHosts: 'list', requireHttps: 'boolean', allowedPaths: 'list', deniedPaths: 'list',
		allowedTransports: 'list', allowedEnv: 'list', forbidLiteralSecrets: 'boolean', deniedTools: 'list', allowAutoApprove: 'boolean',
		maxServers: 'int', maxToolsPerServer: 'int'
	};
	const EXAMPLE_POLICY = {
		version: 1,
		description: 'Example team policy for MCP servers',
		allowedCommands: ['npx', 'uvx', 'docker', 'node'],
		deniedCommands: ['sudo', 'bash', 'sh', 'curl', 'wget', 'powershell'],
		allowedPackages: ['@modelcontextprotocol/*', 'mcp-server-*', 'registry.example.com/*'],
		requirePinnedVersions: true,
		allowedHosts: ['*.example.com', 'localhost'],
		deniedHosts: ['*.ngrok-free.app', '*.trycloudflare.com'],
		requireHttps: true,
		allowedPaths: ['~/projects', '/srv/shared'],
		deniedPaths: ['~/.ssh', '~/.aws', '~/.config'],
		allowedTransports: ['stdio', 'http'],
		forbidLiteralSecrets: true,
		deniedTools: ['*exec*', 'run_*', '*shell*'],
		allowAutoApprove: false,
		maxServers: 10,
		maxToolsPerServer: 40
	};
	function suggest(key) {
		let best = null, bestD = 4;
		for (const k of Object.keys(POLICY_KEYS)) { const d = levenshtein(key.toLowerCase(), k.toLowerCase(), 3); if (d < bestD) { bestD = d; best = k; } }
		return best;
	}
	function validatePolicy(policyText) {
		const errors = [], warnings = [];
		const t = String(policyText == null ? '' : policyText);
		if (!t.trim()) { return { policy: null, errors: ['The policy is empty. Paste a policy in JSON or load the example policy.'], warnings }; }
		if (t.length > MAX_POLICY_CHARS) { return { policy: null, errors: ['The policy is larger than 256 KB.'], warnings }; }
		let parsed;
		try { parsed = parseDocuments(t); } catch (e) { return { policy: null, errors: ['Policy: ' + e.message], warnings }; }
		if (parsed.docs.length !== 1) { return { policy: null, errors: ['The policy must be a single JSON object; found ' + parsed.docs.length + ' documents.'], warnings }; }
		const p = parsed.docs[0].value;
		if (!isObj(p)) { return { policy: null, errors: ['The policy must be a JSON object such as {"deniedCommands": ["sudo"]}.'], warnings }; }
		const lineOf = k => { const m = parsed.meta.get(p); return m && m.keys.get(k) ? ' (line ' + m.keys.get(k) + ')' : ''; };
		for (const d of parsed.duplicates) { errors.push('The setting "' + d.key + '" appears twice (lines ' + d.firstLine + ' and ' + d.line + ').'); }
		const out = {};
		for (const k of Object.keys(p)) {
			const type = POLICY_KEYS[k];
			if (k.startsWith('$') || k.startsWith('_')) { continue; }
			if (!type) { const s = suggest(k); errors.push('Unknown setting "' + cap(k, 60) + '"' + lineOf(k) + '.' + (s ? ' Did you mean "' + s + '"?' : ' See the example policy for the supported settings.')); continue; }
			const v = p[k];
			if (type === 'list') {
				if (!Array.isArray(v) || v.some(x => typeof x !== 'string')) { errors.push('"' + k + '"' + lineOf(k) + ' must be a list of text values, for example ' + JSON.stringify(EXAMPLE_POLICY[k] || ['value']).slice(0, 80) + '.'); continue; }
				if (v.length > 500) { errors.push('"' + k + '"' + lineOf(k) + ' has more than 500 entries.'); continue; }
				const bad = v.find(x => !x.trim() || x.length > 200);
				if (bad !== undefined) { errors.push('"' + k + '"' + lineOf(k) + ' contains an empty or longer than 200 characters entry.'); continue; }
				if ((k === 'allowedPaths' || k === 'deniedPaths') && v.some(x => x.includes('*'))) { errors.push('"' + k + '"' + lineOf(k) + ': wildcards are not supported in paths. List directories; every path inside them matches.'); continue; }
				if (k === 'allowedTransports') { const badT = v.find(x => !/^(?:stdio|http|sse)$/i.test(x)); if (badT) { errors.push('"allowedTransports"' + lineOf(k) + ' accepts "stdio", "http" and "sse"; "' + cap(badT, 40) + '" is not one of them.'); continue; } }
				out[k] = v.map(x => x.trim());
			} else if (type === 'boolean') {
				if (typeof v !== 'boolean') { errors.push('"' + k + '"' + lineOf(k) + ' must be true or false (without quotes).'); continue; }
				out[k] = v;
			} else if (type === 'int') {
				if (typeof v !== 'number' || !Number.isInteger(v) || v < 1 || v > 100000) { errors.push('"' + k + '"' + lineOf(k) + ' must be a whole number from 1 to 100000.'); continue; }
				out[k] = v;
			} else if (k === 'version') {
				if (v !== 1) { errors.push('"version"' + lineOf(k) + ' must be 1. Only policy version 1 is supported.'); continue; }
			} else if (typeof v !== type) { errors.push('"' + k + '"' + lineOf(k) + ' must be text.'); }
		}
		const ruleKeys = Object.keys(out).filter(k => k !== 'description');
		if (!errors.length && !ruleKeys.length) { warnings.push('The policy contains no rules, so nothing is checked. Add settings such as "deniedCommands" or "allowedHosts".'); }
		for (const [allow, deny] of [['allowedCommands', 'deniedCommands'], ['allowedPackages', 'deniedPackages'], ['allowedHosts', 'deniedHosts']]) {
			if (out[allow] && out[deny]) {
				for (const a of out[allow]) { for (const d of out[deny]) { if (globMatch(d, a) || globMatch(a, d)) { warnings.push('"' + a + '" in "' + allow + '" overlaps "' + d + '" in "' + deny + '". Denied entries take precedence.'); } } }
			}
		}
		if (out.allowedPaths && out.deniedPaths) {
			for (const a of out.allowedPaths) { for (const d of out.deniedPaths) { const na = normPath(a), nd = normPath(d); if (inside(na, nd)) { warnings.push('Allowed path "' + a + '" is inside denied path "' + d + '"; it can never be used. Denied paths take precedence.'); } else if (inside(nd, na)) { warnings.push('Allowed path "' + a + '" contains denied path "' + d + '". Granting "' + a + '" to a server is reported as a violation because it includes "' + d + '".'); } } }
		}
		return { policy: errors.length ? null : out, errors, warnings };
	}
	function inside(p, base) {
		// The home directory (~) lives under the file system root on every platform.
		if (base === '/') { return p.startsWith('/') || p === '~' || p.startsWith('~/'); }
		if (/^[a-z]:\/?$/i.test(base) && (p === '~' || p.startsWith('~/'))) { return true; }
		const b = base.replace(/\/+$/, '');
		return p === b || p.startsWith(b + '/') || (/^[a-z]:$/i.test(b) && p.startsWith(b + '/'));
	}
	function pathVariants(norm) { const a = homeAlias(norm); return a ? [norm, a] : [norm]; }

	function checkPolicy(text, policyText, hooks) {
		const v = validatePolicy(policyText);
		if (v.errors.length) { const e = new Error(v.errors.join('\n')); e.code = 'POLICY_INVALID'; e.errors = v.errors; e.warnings = v.warnings; throw e; }
		const policy = v.policy;
		const sec = analyze(text, {}, hooks);
		// Re-parse to get raw structures (analysis returns only masked data).
		const parsed = parseDocuments(String(text));
		const notes = [];
		const { servers } = normalize(parsed, notes);
		const ctx = { findings: [], secrets: new Map(), seenSecret: new Set(), parsed, lineOfKey: () => 0, truncated: false };
		const collected = [];
		const noop = () => null;
		const emitCollect = (rule, severity, s, sub, evidence) => { collected.push({ rule, s, sub, evidence }); return { rule, severity }; };
		const remember = (val, type) => { if (String(val).length >= 4) { ctx.secrets.set(String(val), type); } };
		const secretFinding = (s, sub, value) => { const tk = findTokens(value); for (const x of tk) { remember(x.value, x.type); collected.push({ rule: 'MCP-SEC-002', s, sub, evidence: x.type + ': ' + mask(x.value) }); } return tk.length > 0; };
		for (const s of servers) { analyzeServer(s, ctx, emitCollect, secretFinding, remember); for (const t of s.tools) { analyzeTool(s, t, ctx, noop, () => false); } }
		const violations = [];
		const lineFor = (s, sub) => { let c = s.obj, line = s.line; if (!c) { return line; } for (const key of sub || []) { if (c === null || typeof c !== 'object') { break; } const m = parsed.meta.get(c); const l = m ? (m.keys ? m.keys.get(key) : m.items ? m.items[key] : 0) : 0; if (l) { line = l; } c = c[key]; } return line; };
		const add = (rule, s, sub, message, fix) => violations.push({ rule, server: s ? s.name : 'Whole configuration', location: pathStr((s ? s.path : []).concat(sub || [])), line: s ? lineFor(s, sub) : 0, message, fix });
		const config = servers.filter(s => s.kind === 'config');
		const matchAny = (list, val) => list.some(p => globMatch(p, val));
		if (policy.maxServers && config.length > policy.maxServers) { add('maxServers', null, [], config.length + ' servers are configured; the policy allows at most ' + policy.maxServers + '.', 'Remove servers you do not need.'); }
		for (const s of servers) {
			if (s.kind === 'config') {
				if (policy.allowedTransports && !policy.allowedTransports.map(x => x.toLowerCase()).includes(s.transport)) { add('allowedTransports', s, s.url ? [s.urlKey] : ['command'], 'Transport "' + s.transport + '" is not in the allowed list (' + policy.allowedTransports.join(', ') + ').', 'Use an allowed transport or ask for a policy exception.'); }
				const stages = [...new Set(s.stages.filter(Boolean))];
				for (const st of stages) {
					if (policy.deniedCommands && matchAny(policy.deniedCommands, st)) { add('deniedCommands', s, ['command'], 'Command "' + st + '" is denied by the policy.', 'Start the server without this command.'); }
					else if (policy.allowedCommands && !matchAny(policy.allowedCommands, st)) { add('allowedCommands', s, ['command'], 'Command "' + st + '" is not in the allowed list (' + policy.allowedCommands.join(', ') + ').', 'Use an allowed launcher or ask for a policy exception.'); }
				}
				const pkgs = s.packages.map(p => ({ name: p.name, pinned: p.pinned, sub: p.sub.slice(0), kind: 'Package' })).concat(s.images.map(i => ({ name: i.name, pinned: i.pinned, sub: i.sub.slice(0), kind: 'Image' })));
				for (const p of pkgs) {
					const sub = p.sub;
					if (policy.deniedPackages && matchAny(policy.deniedPackages, p.name)) { add('deniedPackages', s, sub, p.kind + ' "' + p.name + '" is denied by the policy.', 'Remove this server or use an approved package.'); }
					else if (policy.allowedPackages && !matchAny(policy.allowedPackages, p.name)) { add('allowedPackages', s, sub, p.kind + ' "' + p.name + '" is not in the allowed list.', 'Use an approved package or ask for it to be added to the policy.'); }
					if (policy.requirePinnedVersions && !p.pinned) { add('requirePinnedVersions', s, sub, p.kind + ' "' + p.name + '" has no exact version.', 'Pin an exact version or image digest.'); }
				}
				const hosts = s.hosts.slice();
				s.args.forEach((a, idx) => { const m = a.match(/\b(https?|wss?):\/\/([^\s/:?#"'@]+(?::[^\s/?#"'@]*)?@)?([^\s/:?#"']+)/i); if (m) { hosts.push({ host: m[3].toLowerCase(), scheme: m[1].toLowerCase(), sub: (s.cmdPathKey ? ['command', 'args', idx] : ['args', idx]) }); } });
				for (const h of hosts) {
					const local = hostClass(h.host) === 'local';
					if (policy.deniedHosts && matchAny(policy.deniedHosts, h.host)) { add('deniedHosts', s, h.sub, 'Host "' + h.host + '" is denied by the policy.', 'Remove this server or use an approved host.'); }
					else if (policy.allowedHosts && !matchAny(policy.allowedHosts, h.host)) { add('allowedHosts', s, h.sub, 'Host "' + h.host + '" is not in the allowed list.', 'Use an approved host or ask for it to be added to the policy.'); }
					if (policy.requireHttps && (h.scheme === 'http' || h.scheme === 'ws') && !local) { add('requireHttps', s, h.sub, 'Host "' + h.host + '" is reached over ' + h.scheme + '://.', 'Use https:// (or wss://).'); }
				}
				for (const p of s.paths) {
					const variants = pathVariants(p.norm).concat(p.alias ? [p.alias] : []);
					let denied = null;
					if (policy.deniedPaths) {
						for (const d of policy.deniedPaths) { const nd = normPath(d); if (variants.some(x => inside(x, nd) || inside(nd, x))) { denied = d; break; } }
						if (denied) { add('deniedPaths', s, p.sub, 'Path "' + p.raw + '" ' + (variants.some(x => inside(x, normPath(denied))) ? 'is inside' : 'includes') + ' denied path "' + denied + '".', 'Allow a narrower directory that does not contain denied paths.'); continue; }
					}
					if (policy.allowedPaths) {
						if (!/^(?:\/|~|[a-z]:\/)/i.test(p.norm)) { add('allowedPaths', s, p.sub, 'Relative path "' + p.raw + '" depends on the working directory and cannot be matched against the allowed paths.', 'Use an absolute path inside an allowed directory.'); continue; }
						if (!policy.allowedPaths.some(a => variants.some(x => inside(x, normPath(a))))) { add('allowedPaths', s, p.sub, 'Path "' + p.raw + '" is outside the allowed paths (' + policy.allowedPaths.join(', ') + ').', 'Use a directory inside an allowed path.'); }
					}
				}
				if (policy.allowedEnv) { for (const k of Object.keys(s.env)) { if (!matchAny(policy.allowedEnv, k)) { add('allowedEnv', s, ['env', k], 'Environment variable "' + k + '" is not in the allowed list.', 'Remove the variable or ask for it to be added to the policy.'); } } }
				if (policy.allowAutoApprove === false && (s.autoApproveKey && (s.autoWildcard || s.autoApprove.length) || s.trust)) { add('allowAutoApprove', s, s.autoApproveKey ? [s.autoApproveKey] : ['trust'], 'Tool calls of this server are approved automatically, which the policy does not allow.', 'Remove ' + (s.autoApproveKey || 'trust') + ' from the server.'); }
			}
			if (policy.maxToolsPerServer && s.tools.length > policy.maxToolsPerServer) { add('maxToolsPerServer', s, ['tools'], s.tools.length + ' tools; the policy allows at most ' + policy.maxToolsPerServer + ' per server.', 'Enable only the tools you need.'); }
			if (policy.deniedTools) { for (const t of s.tools) { const hit = policy.deniedTools.find(p => globMatch(p, t.name)); if (hit) { add('deniedTools', s, t.path.slice(s.path.length), 'Tool "' + cap(t.name, 80) + '" matches denied pattern "' + hit + '".', 'Disable this tool or remove the server.'); } } }
		}
		if (policy.forbidLiteralSecrets) {
			for (const c of collected) { if (/^MCP-SEC-/.test(c.rule)) { add('forbidLiteralSecrets', c.s, c.sub.slice(c.s.path.length && c.sub[0] === c.s.path[0] ? c.s.path.length : 0), R[c.rule][1] + ': ' + c.evidence + '.', 'Reference the secret from an environment variable or secret store.'); } }
		}
		const secrets = [...ctx.secrets.keys()].sort((a, b) => b.length - a.length);
		const redact = str => { let o = String(str); for (const sv of secrets) { if (o.includes(sv)) { o = o.split(sv).join(mask(sv)); } } return o; };
		const clean = violations.map(x => Object.fromEntries(Object.entries(x).map(([k, val]) => [k, typeof val === 'string' ? redact(val) : val])));
		const rules = Object.keys(policy).filter(k => k !== 'description');
		return { engine: VERSION, ruleset: RULESET_VERSION, mode: 'policy', rulesChecked: rules, warnings: v.warnings, violations: clean, counts: { servers: sec.counts.servers, toolLists: sec.counts.toolLists, tools: sec.counts.tools, violations: clean.length, securityFindings: sec.counts.findings }, servers: sec.servers, notes: sec.notes };
	}

	return { VERSION, RULESET_VERSION, MAX_INPUT_CHARS, MAX_POLICY_CHARS, RULES: R, GROUPS, EXAMPLE_POLICY, KNOWN_PACKAGES, parseDocuments, analyze, validatePolicy, checkPolicy, globMatch, classifyPath, normPath, mask, findTokens };
}));
