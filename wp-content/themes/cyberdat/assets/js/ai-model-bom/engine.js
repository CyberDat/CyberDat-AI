/*!
 * CyberDat AI Model Bill of Materials — engine (Build and Review), shared by the worker and the Node tests.
 *
 * Contract (enforced by tests):
 *  - pure functions over text and plain objects: no network, storage, DOM or eval;
 *  - no regular-expression look-behind, no word-boundary or ASCII word-class escapes: words and names written by users (Cyrillic,
 *    umlauts, NFC or NFD) are compared after Unicode normalization, never with ASCII word classes. ASCII
 *    classes appear only inside machine formats (token alphabets, hex digests, URL schemes, SPDX ids);
 *  - findings show secrets only as their type and a masked fragment.
 * CycloneDX is referenced by name only (specification 1.7, Apache-2.0, by the CycloneDX project / OWASP); no
 * schema or specification text is bundled. The structure check covers only the subset of fields this tool uses.
 */
(function (root, factory) {
	const api = factory();
	if (typeof module === 'object' && module.exports) { module.exports = api; } else { root.CyberDatAiBom = api; }
}(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const ENGINE = '1.0.2';
	const RULESET = '2026-11-14.1';
	const SPEC_VERSION = '1.7';
	const TOOL_NAME = 'CyberDat AI Model Bill of Materials';
	const MAX_INPUT_CHARS = 5 * 1024 * 1024;
	const MAX_FIELD_CHARS = 64 * 1024;
	const MAX_DEPTH = 128;
	const MAX_FINDINGS = 5000;
	const P = 'cyberdat:aibom:';

	// ------------------------------------------------------------------ rule catalogue
	const RULES = {
		'AIBOM-LIC-001': ['license', 'medium', 'Model license missing or unknown', 'Without a license nobody can tell whether the model may be used, changed or redistributed in this system.', 'Add the license of the model as an SPDX identifier (for example Apache-2.0) or the name of the license terms.'],
		'AIBOM-LIC-002': ['license', 'medium', 'Dataset license missing or unknown', 'The terms of the data used for training or fine-tuning can restrict how the model may be used.', 'Add the license or the terms under which the dataset was obtained.'],
		'AIBOM-VER-001': ['version', 'medium', 'Model version missing', 'Without a version the document cannot say which model was reviewed, and a later model can silently replace it.', 'Add the exact version, release date or revision of the model.'],
		'AIBOM-VER-002': ['version', 'medium', 'Model version is floating', 'A branch name, “latest” or a range can point to a different model tomorrow, so the document no longer describes what runs.', 'Use an exact version, snapshot date or commit revision instead of a branch, tag such as “latest”, or range.'],
		'AIBOM-VER-003': ['version', 'low', 'Base model version missing or floating', 'Fine-tuning results depend on the exact base model; a different base revision can behave differently.', 'Add the exact version or revision of the base model.'],
		'AIBOM-WGT-001': ['weights', 'medium', 'Weights file without a hash', 'Without a digest nobody can check that the deployed file is the one that was reviewed.', 'Add a SHA-256 (or stronger) digest of the weights file.'],
		'AIBOM-WGT-002': ['weights', 'medium', 'Pickle-based weights format', 'Formats based on Python pickle (.pkl, .pt, .pth, .bin, .ckpt, joblib) can run code when the file is loaded.', 'Prefer safetensors. If a pickle-based file is needed, load it only from a verified source with a checked digest, and in an isolated environment.'],
		'AIBOM-WGT-003': ['weights', 'low', 'Weak hash algorithm', 'MD5 and SHA-1 are not collision resistant, so a different file can have the same digest.', 'Record a SHA-256, SHA-384 or SHA-512 digest.'],
		'AIBOM-WGT-004': ['weights', 'low', 'Weights file without a source', 'Without a source it is unclear where the file was obtained and how to fetch the same file again.', 'Add the download location, registry entry or internal storage path.'],
		'AIBOM-WGT-005': ['weights', 'low', 'No weights files listed', 'For a model you run yourself, the weights are the core artefact of the supply chain.', 'List the weights files with format, digest and source.'],
		'AIBOM-PRV-001': ['provenance', 'medium', 'Fine-tuned model without a base model', 'License terms, known weaknesses and behaviour of the base model carry over to the fine-tuned model.', 'Name the base model and its exact version.'],
		'AIBOM-DAT-001': ['data', 'medium', 'Dataset without a source', 'Without a source the origin, consent and license of the data cannot be traced.', 'Add where the dataset comes from: a URL, a catalogue entry or an internal location.'],
		'AIBOM-DAT-002': ['data', 'medium', 'Personal data status unknown', 'If it is not known whether a dataset contains personal data, data-protection duties cannot be assessed.', 'State whether the dataset contains personal data: yes or no.'],
		'AIBOM-DAT-003': ['data', 'low', 'No datasets listed', 'A model you trained or fine-tuned depends on its training data; without it the document is incomplete.', 'List the training and fine-tuning datasets with source, license and personal-data status.'],
		'AIBOM-DEP-001': ['dependencies', 'medium', 'Dependency without a version', 'Without versions the framework and libraries that run the model cannot be checked for known vulnerabilities.', 'Add the exact version of each framework and library.'],
		'AIBOM-DEP-002': ['dependencies', 'low', 'Dependency version is floating', 'A range or “latest” can install a different release at the next build.', 'Pin the exact version that was tested.'],
		'AIBOM-NET-001': ['endpoints', 'medium', 'Address uses http://', 'Unencrypted connections can be read or changed in transit, including model files and API calls.', 'Use https:// for this address.'],
		'AIBOM-SEC-001': ['secrets', 'high', 'Credentials in an address', 'The address contains a password or a key. Anyone who receives the document can use it.', 'Remove the credential from the address, revoke it if it is real, and store it in a secrets manager.'],
		'AIBOM-SEC-002': ['secrets', 'high', 'Secret in a field', 'The value has the format of a known credential. A bill of materials is meant to be shared, so it must not contain secrets.', 'Remove the value, revoke it if it is real, and refer to the secret by name only (for example “stored in the vault as OCR_API_KEY”).'],
		'AIBOM-SEC-003': ['secrets', 'medium', 'Long random-looking value', 'The value is not a known credential format but looks like a key or token.', 'Check the value. If it is a secret, remove it and revoke it.'],
		'AIBOM-DOC-001': ['documentation', 'medium', 'No intended purpose', 'Without a stated purpose, uses outside it cannot be recognized or limited.', 'Describe what the model is used for and by whom.'],
		'AIBOM-DOC-002': ['documentation', 'medium', 'No limitations', 'Readers need to know where the model is unreliable or must not be used.', 'List known limitations: languages, input types, situations where results are unreliable.'],
		'AIBOM-DOC-003': ['documentation', 'medium', 'No quality or safety evaluation', 'Without an evaluation there is no recorded basis for trusting the model in this use.', 'Add the metrics you measured and how the model was checked for safety problems.'],
		'AIBOM-DOC-004': ['documentation', 'medium', 'No responsible person or contact', 'Questions, incidents and updates need an owner who can be reached.', 'Name the responsible person or team and add a contact (e-mail or URL).'],
		'AIBOM-DOC-005': ['documentation', 'low', 'Model type not stated', 'Whether the model is your own, fine-tuned or used through an external API changes which risks apply.', 'Choose the model type: own, fine-tuned or external API.'],
		'AIBOM-DOC-006': ['documentation', 'low', 'No vendor', 'For a fine-tuned or external model, the vendor is part of the supply chain.', 'Name the vendor or provider of the model.'],
		'AIBOM-FMT-001': ['format', 'medium', 'No machine-learning model component', 'The document contains no component of type machine-learning-model, so model-level gaps cannot be checked.', 'Add the model as a component of type machine-learning-model.'],
		'AIBOM-FMT-002': ['format', 'low', 'Structure problems', 'Some fields do not follow the CycloneDX structure that this tool checks. They were read where possible.', 'Correct the fields listed under “Structure”.']
	};
	const GROUPS = { license: 'Licenses', version: 'Versions', weights: 'Weights files', provenance: 'Base model', data: 'Data', dependencies: 'Dependencies', endpoints: 'Addresses', secrets: 'Secrets', documentation: 'Documentation', format: 'Format' };
	const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };

	// ------------------------------------------------------------------ text helpers (Unicode-aware)
	const str = v => (v === undefined || v === null ? '' : typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : '');
	const nfc = s => str(s).normalize('NFC');
	const clean = s => nfc(s).replace(/^[\s ​﻿]+|[\s ​﻿]+$/gu, '');
	const fold = s => clean(s).normalize('NFKC').toLocaleLowerCase('en-US').replace(/[\s.:;,!]+$/u, '');
	const normKey = k => str(k).normalize('NFKC').toLocaleLowerCase('en-US').replace(/[\s_.\-]/gu, '');
	const UNKNOWN = new Set(['', 'unknown', 'unbekannt', 'неизвестно', 'неизвестна', 'неизвестен', 'n/a', 'na', 'none', 'noassertion', 'tbd', 'todo', '?', '-', '—', '–', 'not specified', 'unspecified', 'nicht angegeben', 'не указано', 'не указана', 'нет данных']);
	const isMissing = v => UNKNOWN.has(fold(v));
	const FLOATING = new Set(['latest', 'main', 'master', 'head', 'trunk', 'dev', 'develop', 'development', 'nightly', 'stable', 'current', 'newest', 'neueste', 'aktuell', 'последняя', 'последний', 'текущая', 'текущий', '*', 'x']);
	function isFloating(v) {
		const f = fold(v);
		if (!f) { return false; }
		if (FLOATING.has(f) || FLOATING.has(f.replace(/^v/u, ''))) { return true; }
		if (/[\^~<>|*]/u.test(f) || /(?:^|\.)x$/u.test(f) || f.indexOf('vers:') === 0) { return true; }
		return f.indexOf('refs/heads/') === 0 || f.indexOf('branch:') === 0;
	}
	const HEX = /^[0-9a-fA-F]+$/u;
	const DIGEST_LENGTHS = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256', 96: 'SHA-384', 128: 'SHA-512' };
	const isDigest = v => HEX.test(v) && Object.prototype.hasOwnProperty.call(DIGEST_LENGTHS, v.length);
	const HASH_ALGS = ['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'BLAKE2b-256', 'BLAKE2b-384', 'BLAKE2b-512', 'BLAKE3', 'Streebog-256', 'Streebog-512'];
	function normAlg(a) {
		const k = normKey(a);
		return HASH_ALGS.find(x => normKey(x) === k) || '';
	}
	const PICKLE_EXT = ['pkl', 'pickle', 'pt', 'pth', 'bin', 'ckpt', 'joblib'];
	const PICKLE_FORMAT = new Set(['pickle', 'pkl', 'pytorch', 'torch', 'pt', 'pth', 'checkpoint', 'ckpt', 'joblib', 'bin']);
	function isPickle(file, format) {
		const f = fold(file);
		const dot = f.lastIndexOf('.');
		if (dot >= 0 && PICKLE_EXT.indexOf(f.slice(dot + 1)) >= 0) { return true; }
		return PICKLE_FORMAT.has(normKey(format));
	}
	const MODEL_TYPES = { own: 'own', finetuned: 'fine-tuned', externalapi: 'external-api' };
	const normType = t => MODEL_TYPES[normKey(t)] || '';
	const PD = { yes: 'yes', no: 'no', unknown: 'unknown' };
	const normPd = v => PD[fold(v)] || '';
	const isUrlLike = s => /^[A-Za-z][A-Za-z0-9+.-]{0,30}:[^\s]+$/u.test(s);

	// ------------------------------------------------------------------ secrets
	// Token alphabets are ASCII by definition of each format; boundaries are checked in code, not with look-behind.
	const SECRET_PATTERNS = [
		['AWS access key ID', /(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}/gu],
		['GitHub token', /gh[pousr]_[0-9A-Za-z]{30,}/gu],
		['GitHub fine-grained token', /github_pat_[0-9A-Za-z_]{40,}/gu],
		['GitLab token', /glpat-[0-9A-Za-z_-]{20,}/gu],
		['Slack token', /xox[abposr]-[0-9A-Za-z-]{10,}/gu],
		['Anthropic API key', /sk-ant-[0-9A-Za-z_-]{20,}/gu],
		['OpenAI-style API key', /sk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{20,}/gu],
		['Google API key', /AIza[0-9A-Za-z_-]{35}/gu],
		['Hugging Face token', /hf_[0-9A-Za-z]{30,}/gu],
		['Stripe key', /[rs]k_(?:live|test)_[0-9A-Za-z]{10,}/gu],
		['npm token', /npm_[0-9A-Za-z]{36}/gu],
		['JSON Web Token', /eyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{5,}\.[0-9A-Za-z_-]*/gu],
		['Private key', /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/gu],
		['Azure storage key', /AccountKey=[0-9A-Za-z+/]{40,}={0,2}/gu]
	];
	const SECRET_WORDS = ['password', 'passwd', 'pwd', 'pass', 'secret', 'clientsecret', 'token', 'accesstoken', 'refreshtoken', 'apikey', 'xapikey', 'key', 'auth', 'authorization', 'sig', 'signature', 'credential', 'credentials', 'privatekey', 'sas'];
	const isSecretName = name => { const k = normKey(name).replace(/^.*:/u, ''); return SECRET_WORDS.indexOf(k) >= 0 || /(?:password|secret|token|apikey|privatekey)$/u.test(k); };
	const TOKEN_CHAR = /[\p{L}\p{N}\p{M}_]/u;
	function mask(v) {
		const s = str(v);
		const n = [...s].length;
		return n <= 8 ? '•'.repeat(Math.max(4, n)) : [...s].slice(0, 4).join('') + '… (' + n + ' characters)';
	}
	const URL_RE = /(?:https?|git\+https?|git\+ssh|ssh|ftp|s3|gs|hf):\/\/[^\s"'<>]+/giu;
	function urlParts(u) {
		const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/u.exec(u);
		if (!m) { return null; }
		const at = m[2].lastIndexOf('@');
		const userinfo = at >= 0 ? m[2].slice(0, at) : '';
		const hostport = at >= 0 ? m[2].slice(at + 1) : m[2];
		const host = hostport.replace(/:\d+$/u, '').replace(/^\[|\]$/gu, '').toLowerCase();
		return { scheme: m[1].toLowerCase(), userinfo, host, hostport, path: m[3], query: m[4] || '', fragment: m[5] || '' };
	}
	const maskUrlPath = path => path.replace(/[\p{L}\p{N}\p{M}+=_.\-]{32,}/gu, value => exportTokenLike(value) ? '[' + mask(value) + ']' : value);
	const isLocal = h => h === 'localhost' || h === '::1' || /^127\.\d+\.\d+\.\d+$/u.test(h) || h.endsWith('.localhost');
	// Preserve ordinary long Unicode words; glued credentials still match their format or token digits.
	function exportTokenLike(value) {
		if (/^\p{ASCII}+$/u.test(value) || /\p{N}/u.test(value)) { return true; }
		return SECRET_PATTERNS.some(([, re]) => { re.lastIndex = 0; return re.test(value); });
	}
	function entropy(s) {
		const c = new Map();
		for (const ch of s) { c.set(ch, (c.get(ch) || 0) + 1); }
		let e = 0;
		for (const n of c.values()) { const p = n / s.length; e -= p * Math.log2(p); }
		return e;
	}

	/** All secret-like spans in one text value. opts.noOpaque disables the unrecognized-long-value heuristic. */
	function scanText(text, opts) {
		const s = str(text);
		const out = [];
		if (!s) { return out; }
		const taken = [];
		const overlaps = (a, b) => taken.some(([x, y]) => a < y && b > x);
		URL_RE.lastIndex = 0;
		let m;
		while ((m = URL_RE.exec(s))) {
			const u = m[0].replace(/[).,;\]]+$/u, '');
			const p = urlParts(u);
			if (!p) { continue; }
			const safePath = maskUrlPath(p.path);
			const start = m.index, end = m.index + u.length;
			if (p.userinfo.indexOf(':') > 0 && p.userinfo.length > p.userinfo.indexOf(':') + 1) {
				out.push({ rule: 'AIBOM-SEC-001', kind: 'password in the address', start, end, shown: p.scheme + '://' + mask(p.userinfo.slice(0, p.userinfo.indexOf(':'))) + ':••••@' + p.hostport + safePath });
				taken.push([start, end]);
			} else if (p.query) {
				for (const pair of p.query.slice(1).split('&')) {
					const eq = pair.indexOf('=');
					const name = eq >= 0 ? pair.slice(0, eq) : pair;
					const value = eq >= 0 ? pair.slice(eq + 1) : '';
					let dec = name;
					try { dec = decodeURIComponent(name); } catch (e) { /* keep raw */ }
					if (value.length >= 6 && isSecretName(dec)) {
						out.push({ rule: 'AIBOM-SEC-001', kind: 'key in the address (' + dec + ')', start, end, shown: p.scheme + '://' + p.hostport + safePath + '?' + dec + '=' + mask(value) });
						taken.push([start, end]);
						break;
					}
				}
			}
			if (p.scheme === 'http' && !isLocal(p.host)) { out.push({ rule: 'AIBOM-NET-001', kind: 'http address', start, end, shown: 'http://' + p.hostport + (safePath.length > 40 ? safePath.slice(0, 40) + '…' : safePath) }); }
		}
		for (const [kind, re] of SECRET_PATTERNS) {
			re.lastIndex = 0;
			while ((m = re.exec(s))) {
				const start = m.index, end = m.index + m[0].length;
				if (start > 0 && TOKEN_CHAR.test(s[start - 1]) && kind !== 'Private key' && kind !== 'Azure storage key') { continue; }
				if (end < s.length && TOKEN_CHAR.test(s[end]) && kind !== 'Private key' && kind !== 'JSON Web Token') { continue; }
				if (overlaps(start, end)) { continue; }
				out.push({ rule: 'AIBOM-SEC-002', kind, start, end, shown: kind === 'Private key' ? 'BEGIN … PRIVATE KEY' : mask(m[0]) });
				taken.push([start, end]);
			}
		}
		// Read complete quoted values before JSON/Markdown escaping; unquoted assignments end at delimiters.
		const ASSIGN = /([\p{L}\p{N}\p{M}_.\-]{2,40})["']?[ \t]*[:=][ \t]*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s"',;&<>]+)/gu;
		while ((m = ASSIGN.exec(s))) {
			const quoted = m[2][0] === '"' || m[2][0] === "'";
			const value = quoted ? m[2].slice(1, -1) : m[2];
			const vStart = m.index + m[0].length - m[2].length + (quoted ? 1 : 0);
			if (!value || !isSecretName(m[1]) || overlaps(vStart, vStart + value.length)) { continue; }
			out.push({ rule: 'AIBOM-SEC-002', kind: 'value assigned to “' + m[1] + '”', start: vStart, end: vStart + value.length, shown: mask(value) });
			taken.push([vStart, vStart + value.length]);
		}
		if (!(opts && opts.noOpaque)) {
			const OPAQUE = /[\p{L}\p{N}\p{M}+/=_.\-]{32,}/gu;
			while ((m = OPAQUE.exec(s))) {
				const v = m[0], start = m.index, end = start + v.length;
				if ((start > 0 && TOKEN_CHAR.test(s[start - 1])) || (end < s.length && TOKEN_CHAR.test(s[end]))) { continue; }
				if (overlaps(start, end) || HEX.test(v.replace(/[-_.]/gu, '')) || s.slice(Math.max(0, start - 3), start).indexOf('://') >= 0) { continue; }
				if (taken.some(([x, y]) => start >= x && end <= y)) { continue; }
				const inUrl = [...s.matchAll(URL_RE)].some(u => start >= u.index && end <= u.index + u[0].length);
				if (inUrl || !/\p{N}/u.test(v) || !/\p{L}/u.test(v) || entropy(v) < 3.5 || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(v)) { continue; }
				const digits = (v.match(/\p{N}/gu) || []).length, upper = (v.match(/\p{Lu}/gu) || []).length, lower = (v.match(/\p{Ll}/gu) || []).length;
				if (digits < 3 || (upper === 0 && lower > 0 && digits < 6)) { continue; }
				out.push({ rule: 'AIBOM-SEC-003', kind: 'unrecognized long value', start, end, shown: mask(v) });
				taken.push([start, end]);
			}
		}
		return out;
	}
	/** Replace every recognized secret span with its masked form (for evidence, reports and notes). */
	function maskSecrets(text) {
		const s = str(text);
		const spans = scanText(s).filter(x => x.rule !== 'AIBOM-NET-001').sort((a, b) => b.start - a.start);
		let out = s;
		for (const x of spans) { out = out.slice(0, x.start) + '[' + x.shown + ']' + out.slice(x.end); }
		return out;
	}

	/** Conservative export boundary: mask unknown long token-shaped values too, without an entropy exemption. */
	function maskExportText(text) {
		// Redact long path components before credential spans can absorb the whole address.
		const s = str(text).replace(URL_RE, url => {
			const p = urlParts(url);
			if (!p || !p.path) { return url; }
			const start = url.indexOf(p.path, url.indexOf('://') + 3);
			const path = maskUrlPath(p.path);
			return url.slice(0, start) + path + url.slice(start + p.path.length);
		});
		const spans = scanText(s).filter(x => x.rule !== 'AIBOM-NET-001');
		const urls = [...s.matchAll(URL_RE)].map(m => ({ start: m.index, end: m.index + m[0].length, text: m[0] }));
		for (const u of urls) {
			const q = u.text.indexOf('?');
			if (q < 0) { continue; }
			let offset = q + 1;
			for (const pair of u.text.slice(offset).split('&')) {
				const eq = pair.indexOf('='), value = eq < 0 ? '' : pair.slice(eq + 1).split('#')[0];
				const a = u.start + offset + eq + 1, b = a + value.length;
				if (/^[\p{L}\p{N}\p{M}+/=_.\-]{32,}$/u.test(value) && exportTokenLike(value) && !spans.some(x => a < x.end && b > x.start)) { spans.push({ start: a, end: b, shown: mask(value) }); }
				offset += pair.length + 1;
			}
		}
		const re = /[\p{L}\p{N}\p{M}+/=_.\-]{32,}/gu;
		let m;
		while ((m = re.exec(s))) {
			const a = m.index, b = a + m[0].length;
			if (!exportTokenLike(m[0]) || (a && TOKEN_CHAR.test(s[a - 1])) || (b < s.length && TOKEN_CHAR.test(s[b])) || spans.some(x => a < x.end && b > x.start) || urls.some(u => a >= u.start && b <= u.end)) { continue; }
			spans.push({ start: a, end: b, shown: mask(m[0]) });
		}
		let out = s;
		for (const x of spans.sort((a, b) => b.start - a.start)) { out = out.slice(0, x.start) + '[' + x.shown + ']' + out.slice(x.end); }
		return out;
	}
	function exportInventory(inventory) {
		const inv = normalizeInventory(inventory);
		const walk = v => typeof v === 'string' ? maskExportText(v) : Array.isArray(v) ? v.map(walk) : isObj(v) ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)])) : v;
		const safe = walk(inv);
		// Exact source revisions are public identifiers in the typed version fields, not free-text secrets.
		const revision = v => /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/iu.test(v);
		if (revision(inv.model.version)) { safe.model.version = inv.model.version; }
		if (revision(inv.model.baseModel.version)) { safe.model.baseModel.version = inv.model.baseModel.version; }
		inv.dependencies.forEach((d, i) => { if (revision(d.version)) { safe.dependencies[i].version = d.version; } });
		// A digest is intentionally public only in the typed weights-hash field; a hex token in free text is not exempt.
		inv.weights.forEach((w, i) => {
			if (isDigest(w.hash)) { safe.weights[i].hash = w.hash; }
			// File names are typed identifiers; keep ordinary names, while existing secret/token checks still apply.
			safe.weights[i].file = maskSecrets(w.file);
		});
		return safe;
	}

	// ------------------------------------------------------------------ strict JSON reader with lines and duplicate keys
	function parseJson(text) {
		const s = str(text);
		let i = 0, line = 1, col = 1;
		const lines = new Map();
		const duplicates = [];
		const err = (msg) => { const e = new Error(msg + ' (line ' + line + ', column ' + col + ').'); e.code = 'PARSE'; e.line = line; e.column = col; throw e; };
		const adv = n => { for (let k = 0; k < n; k++) { if (s.charCodeAt(i) === 10) { line++; col = 1; } else { col++; } i++; } };
		const ws = () => { while (i < s.length) { const c = s.charCodeAt(i); if (c === 32 || c === 9 || c === 10 || c === 13) { adv(1); } else { break; } } };
		function string() {
			adv(1);
			let out = '', start = i;
			for (;;) {
				if (i >= s.length) { err('Unterminated string'); }
				const c = s.charCodeAt(i);
				if (c === 34) { out += s.slice(start, i); adv(1); return out; }
				if (c < 32) { err('Control character in string'); }
				if (c === 92) {
					out += s.slice(start, i);
					const e = s[i + 1];
					const map = { '"': '"', '\\': '\\', '/': '/', b: '\u0008', f: '\f', n: '\n', r: '\r', t: '\t' };
					if (e === 'u') {
						const h = s.slice(i + 2, i + 6);
						if (!/^[0-9a-fA-F]{4}$/u.test(h)) { err('Invalid \\u escape'); }
						out += String.fromCharCode(parseInt(h, 16));
						adv(6);
					} else if (Object.prototype.hasOwnProperty.call(map, e)) { out += map[e]; adv(2); } else { err('Invalid escape'); }
					start = i;
					continue;
				}
				i++; col++;
			}
		}
		function value(path, depth) {
			if (depth > MAX_DEPTH) { err('Nesting is deeper than ' + MAX_DEPTH + ' levels'); }
			ws();
			lines.set(path, line);
			const c = s[i];
			if (c === '{') {
				adv(1); ws();
				const obj = {};
				const seen = new Set();
				if (s[i] === '}') { adv(1); return obj; }
				for (;;) {
					ws();
					if (s[i] !== '"') { err(s[i] === '}' ? 'Trailing comma before }' : 'Expected a property name in double quotes'); }
					const keyLine = line;
					const k = string();
					ws();
					if (s[i] !== ':') { err('Expected : after a property name'); }
					adv(1);
					const p = path + '/' + k.replace(/~/gu, '~0').replace(/\//gu, '~1');
					if (seen.has(k)) { duplicates.push({ path: p, key: k, line: keyLine }); }
					seen.add(k);
					const v = value(p, depth + 1);
					Object.defineProperty(obj, k, { value: v, enumerable: true, writable: true, configurable: true });
					ws();
					if (s[i] === ',') { adv(1); continue; }
					if (s[i] === '}') { adv(1); return obj; }
					err('Expected , or } in an object');
				}
			}
			if (c === '[') {
				adv(1); ws();
				const arr = [];
				if (s[i] === ']') { adv(1); return arr; }
				for (;;) {
					arr.push(value(path + '/' + arr.length, depth + 1));
					ws();
					if (s[i] === ',') { adv(1); ws(); if (s[i] === ']') { err('Trailing comma before ]'); } continue; }
					if (s[i] === ']') { adv(1); return arr; }
					err('Expected , or ] in an array');
				}
			}
			if (c === '"') { return string(); }
			const lit = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(s.slice(i, i + 400));
			if (!lit) { err(i >= s.length ? 'Unexpected end of input' : 'Unexpected character “' + s[i] + '”'); }
			adv(lit[0].length);
			return lit[0] === 'true' ? true : lit[0] === 'false' ? false : lit[0] === 'null' ? null : Number(lit[0]);
		}
		if (s.charCodeAt(0) === 0xfeff) { i = 1; }
		const v = value('', 0);
		ws();
		if (i < s.length) { err('Unexpected text after the end of the JSON document'); }
		return { value: v, lines, duplicates };
	}

	// ------------------------------------------------------------------ inventory (the Build form model)
	function emptyInventory() {
		return { model: { name: '', version: '', vendor: '', license: '', type: '', baseModel: { name: '', version: '' } }, weights: [], datasets: [], dependencies: [], deployment: { environment: '', apis: [] }, purpose: '', limitations: '', evaluation: { metrics: [], safety: '' }, owner: { name: '', organization: '', contact: '' } };
	}
	const lim = v => { const s = clean(v); return s.length > MAX_FIELD_CHARS ? s.slice(0, MAX_FIELD_CHARS) : s; };
	/** Canonical form: trimmed NFC strings, known enum values, empty rows dropped (kept with keepEmpty). */
	function normalizeInventory(inv, keepEmpty) {
		const keep = keepEmpty ? () => true : null;
		const i = inv || {};
		const m = i.model || {};
		const b = m.baseModel || {};
		const out = emptyInventory();
		Object.assign(out.model, { name: lim(m.name), version: lim(m.version), vendor: lim(m.vendor), license: lim(m.license), type: normType(m.type), baseModel: { name: lim(b.name), version: lim(b.version) } });
		out.weights = (i.weights || []).map(w => ({ file: lim(w.file), format: lim(w.format), hashAlg: normAlg(w.hashAlg) || (clean(w.hashAlg) ? lim(w.hashAlg) : ''), hash: lim(w.hash), source: lim(w.source) })).filter(keep || (w => w.file || w.format || w.hash || w.source));
		out.datasets = (i.datasets || []).map(d => ({ name: lim(d.name), role: ['training', 'fine-tuning', 'evaluation'].indexOf(normKey(d.role) === 'finetuning' ? 'fine-tuning' : normKey(d.role)) >= 0 ? (normKey(d.role) === 'finetuning' ? 'fine-tuning' : normKey(d.role)) : '', source: lim(d.source), license: lim(d.license), personalData: normPd(d.personalData) })).filter(keep || (d => d.name || d.source || d.license));
		out.dependencies = (i.dependencies || []).map(d => ({ kind: normKey(d.kind) === 'framework' ? 'framework' : 'library', name: lim(d.name), version: lim(d.version) })).filter(keep || (d => d.name || d.version));
		const dep = i.deployment || {};
		out.deployment = { environment: lim(dep.environment), apis: (dep.apis || []).map(a => ({ name: lim(a.name), url: lim(a.url) })).filter(a => a.name || a.url) };
		out.purpose = lim(i.purpose);
		out.limitations = lim(i.limitations);
		const ev = i.evaluation || {};
		out.evaluation = { metrics: (ev.metrics || []).map(x => ({ type: lim(x.type), value: lim(x.value), slice: lim(x.slice) })).filter(x => x.type || x.value || x.slice), safety: lim(ev.safety) };
		const o = i.owner || {};
		out.owner = { name: lim(o.name), organization: lim(o.organization), contact: lim(o.contact) };
		return out;
	}

	/** Labelled text fields of an inventory, for the secret scan. */
	function inventoryFields(inv) {
		const f = [];
		const add = (label, v, noOpaque) => { if (clean(v)) { f.push({ label, text: v, noOpaque: !!noOpaque }); } };
		const m = inv.model;
		add('Model › Name', m.name); add('Model › Version', m.version); add('Model › Vendor', m.vendor); add('Model › License', m.license);
		add('Model › Base model', m.baseModel.name); add('Model › Base model version', m.baseModel.version);
		inv.weights.forEach((w, k) => { const p = 'Weights file ' + (k + 1) + ' › '; add(p + 'File', w.file); add(p + 'Format', w.format); add(p + 'Hash', w.hash, isDigest(w.hash)); add(p + 'Source', w.source); });
		inv.datasets.forEach((d, k) => { const p = 'Dataset ' + (k + 1) + ' › '; add(p + 'Name', d.name); add(p + 'Source', d.source); add(p + 'License', d.license); });
		inv.dependencies.forEach((d, k) => { const p = 'Dependency ' + (k + 1) + ' › '; add(p + 'Name', d.name); add(p + 'Version', d.version); });
		add('Deployment › Where it runs', inv.deployment.environment);
		inv.deployment.apis.forEach((a, k) => { const p = 'External API ' + (k + 1) + ' › '; add(p + 'Name', a.name); add(p + 'Address', a.url); });
		add('Purpose', inv.purpose); add('Limitations', inv.limitations);
		inv.evaluation.metrics.forEach((x, k) => { const p = 'Evaluation metric ' + (k + 1) + ' › '; add(p + 'Metric', x.type); add(p + 'Value', x.value); add(p + 'Data', x.slice); });
		add('Evaluation › Safety', inv.evaluation.safety);
		add('Responsible › Name', inv.owner.name); add('Responsible › Organization', inv.owner.organization); add('Responsible › Contact', inv.owner.contact);
		return f;
	}

	// ------------------------------------------------------------------ rules
	function finding(id, location, evidence, extra) {
		const r = RULES[id];
		return Object.assign({ rule: id, group: r[0], severity: r[1], title: r[2], explanation: r[3], fix: r[4], location: location ? maskSecrets(location) : '', evidence: evidence ? maskSecrets(evidence) : '' }, extra || {});
	}
	/**
	 * Gaps and risks of one canonical inventory. ctx.where(field) maps a logical field to a location label
	 * (Review passes JSON paths and lines); ctx.models lets Review check several model components.
	 */
	function checkInventory(inv, ctx, hooks) {
		const c = ctx || {};
		const where = c.where || (k => ({ location: k }));
		const out = [];
		const push = (id, key, evidence, extra) => { if (out.length < MAX_FINDINGS) { const w = where(key); out.push(finding(id, w.location, evidence, Object.assign(w.line ? { line: w.line } : {}, extra || {}))); } };
		const models = c.models || [{ model: inv.model, purpose: inv.purpose, limitations: inv.limitations, evaluation: inv.evaluation, key: 'model' }];
		for (const md of models) {
			const m = md.model, k = md.key;
			if (isMissing(m.license)) { push('AIBOM-LIC-001', k + '.license', m.license); }
			if (md.versionRange) { push('AIBOM-VER-002', k + '.version', md.versionRange); }
			else if (isMissing(m.version)) { push('AIBOM-VER-001', k + '.version'); }
			else if (isFloating(m.version)) { push('AIBOM-VER-002', k + '.version', m.version); }
			const t = m.type;
			if (!t) { push('AIBOM-DOC-005', k + '.type'); }
			if (t === 'fine-tuned' && isMissing(m.baseModel.name)) { push('AIBOM-PRV-001', k + '.baseModel'); }
			if (!isMissing(m.baseModel.name) && (isMissing(m.baseModel.version) || isFloating(m.baseModel.version))) { push('AIBOM-VER-003', k + '.baseModel.version', m.baseModel.name + (clean(m.baseModel.version) ? ' @ ' + m.baseModel.version : '')); }
			if ((t === 'fine-tuned' || t === 'external-api') && isMissing(m.vendor)) { push('AIBOM-DOC-006', k + '.vendor'); }
			if ((t === 'own' || t === 'fine-tuned') && !inv.weights.length) { push('AIBOM-WGT-005', k + '.weights'); }
			if ((t === 'own' || t === 'fine-tuned') && !inv.datasets.length) { push('AIBOM-DAT-003', k + '.datasets'); }
			if (isMissing(md.purpose)) { push('AIBOM-DOC-001', k + '.purpose'); }
			if (isMissing(md.limitations)) { push('AIBOM-DOC-002', k + '.limitations'); }
			const ev = md.evaluation;
			if (!ev.metrics.some(x => !isMissing(x.type) || !isMissing(x.value)) && isMissing(ev.safety)) { push('AIBOM-DOC-003', k + '.evaluation'); }
		}
		if (models.length) {
			const o = inv.owner;
			if ((isMissing(o.name) && isMissing(o.organization)) || isMissing(o.contact)) { push('AIBOM-DOC-004', 'owner'); }
		}
		inv.weights.forEach((w, n) => {
			const label = w.file || ('weights file ' + (n + 1));
			if (!isDigest(w.hash)) { push('AIBOM-WGT-001', 'weights.' + n + '.hash', clean(w.hash) ? label + ': ' + maskExportText(w.hash).slice(0, 24) : label); }
			else if (['MD5', 'SHA-1'].indexOf(normAlg(w.hashAlg) || DIGEST_LENGTHS[w.hash.length]) >= 0) { push('AIBOM-WGT-003', 'weights.' + n + '.hashAlg', label + ': ' + (normAlg(w.hashAlg) || DIGEST_LENGTHS[w.hash.length])); }
			if (isPickle(w.file, w.format)) { push('AIBOM-WGT-002', 'weights.' + n + '.format', label + (clean(w.format) ? ' (' + w.format + ')' : '')); }
			if (isMissing(w.source)) { push('AIBOM-WGT-004', 'weights.' + n + '.source', label); }
		});
		inv.datasets.forEach((d, n) => {
			const label = d.name || ('dataset ' + (n + 1));
			if (isMissing(d.license)) { push('AIBOM-LIC-002', 'datasets.' + n + '.license', label + (clean(d.license) ? ': ' + d.license : '')); }
			if (isMissing(d.source)) { push('AIBOM-DAT-001', 'datasets.' + n + '.source', label); }
			if (d.personalData !== 'yes' && d.personalData !== 'no') { push('AIBOM-DAT-002', 'datasets.' + n + '.personalData', label + ': ' + (d.personalData || 'not stated')); }
		});
		inv.dependencies.forEach((d, n) => {
			if (isMissing(d.name)) { return; }
			if (isMissing(d.version)) { push('AIBOM-DEP-001', 'dependencies.' + n + '.version', d.name); }
			else if (isFloating(d.version)) { push('AIBOM-DEP-002', 'dependencies.' + n + '.version', d.name + ' ' + d.version); }
		});
		if (hooks && hooks.onProgress) { hooks.onProgress(1, 2); }
		const seen = new Set();
		for (const f of (c.fields || inventoryFields(inv))) {
			for (const x of scanText(f.text, { noOpaque: f.noOpaque })) {
				const id = x.rule + '|' + f.label + '|' + x.shown;
				if (seen.has(id)) { continue; }
				seen.add(id);
				if (out.length >= MAX_FINDINGS) { break; }
				const w = f.line ? { location: f.label, line: f.line } : { location: f.label };
				out.push(Object.assign(finding(x.rule, w.location, '', w.line ? { line: w.line } : {}), { evidence: x.kind + ': ' + x.shown, secretType: x.rule === 'AIBOM-NET-001' ? undefined : x.kind }));
			}
		}
		return out;
	}
	function summarize(findings) {
		const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
		const byGroup = {};
		const byRule = {};
		let level = 'none';
		for (const f of findings) {
			bySeverity[f.severity]++;
			byGroup[f.group] = (byGroup[f.group] || 0) + 1;
			byRule[f.rule] = (byRule[f.rule] || 0) + 1;
			if (RANK[f.severity] > RANK[level]) { level = f.severity; }
		}
		return { level, counts: { findings: findings.length, bySeverity, byGroup, byRule } };
	}
	const sortFindings = list => list.sort((a, b) => RANK[b.severity] - RANK[a.severity] || (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0));

	// ------------------------------------------------------------------ export: CycloneDX 1.7
	const SPDX_COMMON = ['0BSD', 'AFL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later', 'Apache-1.1', 'Apache-2.0', 'Artistic-2.0', 'BSD-1-Clause', 'BSD-2-Clause', 'BSD-3-Clause', 'BSD-3-Clause-Clear', 'BSL-1.0', 'CC-BY-2.0', 'CC-BY-3.0', 'CC-BY-4.0', 'CC-BY-NC-4.0', 'CC-BY-NC-ND-4.0', 'CC-BY-NC-SA-4.0', 'CC-BY-ND-4.0', 'CC-BY-SA-3.0', 'CC-BY-SA-4.0', 'CC0-1.0', 'CDLA-Permissive-1.0', 'CDLA-Permissive-2.0', 'CDLA-Sharing-1.0', 'ECL-2.0', 'EPL-1.0', 'EPL-2.0', 'EUPL-1.2', 'GFDL-1.3-only', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later', 'ISC', 'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later', 'MIT', 'MIT-0', 'MPL-2.0', 'MS-PL', 'NCSA', 'ODbL-1.0', 'ODC-By-1.0', 'OFL-1.1', 'OpenSSL', 'PDDL-1.0', 'PostgreSQL', 'Python-2.0', 'Unicode-3.0', 'Unlicense', 'UPL-1.0', 'WTFPL', 'Zlib'];
	const SPDX_BY_KEY = new Map(SPDX_COMMON.map(x => [x.toLowerCase(), x]));
	function licenseChoice(v) {
		const s = clean(v);
		if (!s) { return undefined; }
		const id = SPDX_BY_KEY.get(s.toLowerCase());
		if (id) { return [{ license: { id } }]; }
		if (/ (?:OR|AND|WITH) /u.test(s) && /^[0-9A-Za-z.+\-() ]+$/u.test(s)) { return [{ expression: s }]; }
		return [{ license: { name: s } }];
	}
	function readLicense(list) {
		if (!Array.isArray(list) || !list.length) { return ''; }
		const x = list[0] || {};
		if (typeof x.expression === 'string') { return x.expression; }
		const l = x.license || {};
		return str(l.id) || str(l.name);
	}
	function uuid() {
		const b = new Uint8Array(16);
		const c = (typeof crypto !== 'undefined' && crypto.getRandomValues) ? crypto : null;
		if (c) { c.getRandomValues(b); } else { for (let k = 0; k < 16; k++) { b[k] = Math.floor(Math.random() * 256); } }
		b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
		const h = [...b].map(x => x.toString(16).padStart(2, '0')).join('');
		return 'urn:uuid:' + h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
	}
	const prop = (name, value) => (clean(value) ? { name: P + name, value: clean(value) } : null);
	const props = list => { const p = list.filter(Boolean); return p.length ? p : undefined; };
	const compact = o => { for (const k of Object.keys(o)) { if (o[k] === undefined) { delete o[k]; } } return o; };

	function toCycloneDX(inventory, opts) {
		const inv = exportInventory(inventory);
		const o = opts || {};
		const m = inv.model;
		const refs = [];
		const comps = [];
		const model = compact({
			type: 'machine-learning-model', 'bom-ref': 'model-1', name: m.name || 'Unnamed model',
			version: m.version || undefined,
			supplier: m.vendor ? { name: m.vendor } : undefined,
			licenses: licenseChoice(m.license),
			pedigree: m.baseModel.name || m.baseModel.version ? { ancestors: [compact({ type: 'machine-learning-model', name: m.baseModel.name || 'Unnamed base model', version: m.baseModel.version || undefined })] } : undefined,
			properties: props([prop('model-type', m.type), m.name ? null : prop('model-name-missing', 'true')])
		});
		comps.push(model);
		inv.weights.forEach((w, k) => {
			const ref = 'weights-' + (k + 1);
			refs.push(ref);
			const digest = isDigest(w.hash);
			const alg = normAlg(w.hashAlg) || (digest ? DIGEST_LENGTHS[w.hash.length] : '');
			comps.push(compact({
				type: 'file', 'bom-ref': ref, name: w.file || 'Unnamed weights file',
				hashes: digest && alg ? [{ alg, content: w.hash.toLowerCase() === w.hash ? w.hash : w.hash }] : undefined,
				externalReferences: w.source && isUrlLike(w.source) ? [{ type: 'distribution', url: w.source }] : undefined,
				properties: props([prop('weights-format', w.format), w.file ? null : prop('file-name-missing', 'true'), digest && alg ? null : prop('weights-hash-unverified', w.hash), digest && alg ? null : prop('weights-hash-algorithm', w.hashAlg), w.source && !isUrlLike(w.source) ? prop('source', w.source) : null])
			}));
		});
		const dataRefs = [];
		inv.datasets.forEach((d, k) => {
			const ref = 'data-' + (k + 1);
			refs.push(ref); dataRefs.push({ ref });
			comps.push(compact({
				type: 'data', 'bom-ref': ref, name: d.name || 'Unnamed dataset',
				licenses: licenseChoice(d.license),
				data: [compact({ type: 'dataset', name: d.name || undefined, contents: d.source && isUrlLike(d.source) ? { url: d.source } : undefined, sensitiveData: d.personalData === 'yes' ? ['personal data'] : undefined })],
				properties: props([prop('dataset-role', d.role), prop('personal-data', d.personalData), d.name ? null : prop('dataset-name-missing', 'true'), d.source && !isUrlLike(d.source) ? prop('source', d.source) : null, d.license ? null : null])
			}));
		});
		inv.dependencies.forEach((d, k) => {
			const ref = 'dep-' + (k + 1);
			refs.push(ref);
			comps.push(compact({ type: d.kind, 'bom-ref': ref, name: d.name || 'Unnamed dependency', version: d.version || undefined, properties: props([d.name ? null : prop('dependency-name-missing', 'true')]) }));
		});
		const mc = {};
		const params = dataRefs.length ? { datasets: dataRefs } : undefined;
		if (params) { mc.modelParameters = params; }
		const metrics = inv.evaluation.metrics.map(x => compact({ type: x.type || undefined, value: x.value || undefined, slice: x.slice || undefined }));
		if (metrics.length) { mc.quantitativeAnalysis = { performanceMetrics: metrics }; }
		const cons = compact({ useCases: inv.purpose ? [inv.purpose] : undefined, technicalLimitations: inv.limitations ? [inv.limitations] : undefined });
		if (Object.keys(cons).length) { mc.considerations = cons; }
		const mcp = props([prop('safety-evaluation', inv.evaluation.safety)]);
		if (mcp) { mc.properties = mcp; }
		if (Object.keys(mc).length) { model.modelCard = mc; }
		const services = inv.deployment.apis.map((a, k) => { const ref = 'api-' + (k + 1); refs.push(ref); return compact({ 'bom-ref': ref, name: a.name || 'Unnamed external API', endpoints: a.url && isUrlLike(a.url) ? [a.url] : undefined, properties: props([a.url && !isUrlLike(a.url) ? prop('endpoint', a.url) : null, a.name ? null : prop('api-name-missing', 'true')]) }); });
		const ow = inv.owner;
		const contact = clean(ow.contact);
		const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(contact);
		const isWeb = /^https?:\/\/[^\s]+$/iu.test(contact);
		let supplier;
		if (ow.name || ow.organization || contact) {
			supplier = compact({ name: ow.organization || undefined, url: isWeb ? [contact] : undefined, contact: ow.name || isEmail ? [compact({ name: ow.name || undefined, email: isEmail ? contact : undefined })] : undefined });
		}
		const metaProps = props([prop('deployment', inv.deployment.environment), contact && !isEmail && !isWeb ? prop('owner-contact', contact) : null, ow.organization ? null : null]);
		const bom = {
			bomFormat: 'CycloneDX', specVersion: SPEC_VERSION, serialNumber: o.serialNumber || uuid(), version: 1,
			metadata: compact({ timestamp: o.timestamp || new Date().toISOString().replace(/\.\d{3}Z$/u, 'Z'), tools: { components: [{ type: 'application', name: TOOL_NAME, version: ENGINE }] }, supplier, properties: metaProps }),
			components: comps
		};
		if (services.length) { bom.services = services; }
		bom.dependencies = [{ ref: 'model-1', dependsOn: refs }].concat(refs.map(ref => ({ ref })));
		if (!refs.length) { delete bom.dependencies[0].dependsOn; }
		return bom;
	}

	// ------------------------------------------------------------------ Markdown export
	const md = s => str(s).replace(/([\\`*_{}\[\]<>()#+!|~])/gu, '\\$1').replace(/\r?\n/gu, '  \n');
	function toMarkdown(inventory, findings, opts) {
		const inv = exportInventory(inventory);
		const o = opts || {};
		const m = inv.model;
		const L = [];
		const field = (k, v) => L.push('- **' + k + ':** ' + (clean(v) ? md(v) : '_not stated_'));
		L.push('# AI Bill of Materials: ' + md(m.name || 'Unnamed model'), '');
		L.push('Generated with ' + TOOL_NAME + ' ' + ENGINE + ' (rules ' + RULESET + ') on ' + md(o.timestamp || new Date().toISOString()) + '. CycloneDX ' + SPEC_VERSION + ' JSON is exported separately.', '');
		L.push('> This document reflects only what was entered. It helps document the model and its supply chain; it does not verify the entries and does not assess the model.', '');
		L.push('## Model', '');
		field('Name', m.name); field('Version', m.version); field('Vendor', m.vendor); field('License', m.license);
		field('Type', { own: 'Own model', 'fine-tuned': 'Fine-tuned model', 'external-api': 'External model used through an API' }[m.type] || '');
		field('Base model', m.baseModel.name ? m.baseModel.name + (m.baseModel.version ? ' ' + m.baseModel.version : '') : '');
		L.push('', '## Weights files', '');
		if (!inv.weights.length) { L.push('_None listed._'); }
		inv.weights.forEach(w => L.push('- ' + md(w.file || 'Unnamed weights file') + ' — format: ' + (w.format ? md(w.format) : '_not stated_') + '; hash: ' + (w.hash ? md((w.hashAlg ? w.hashAlg + ' ' : '') + w.hash) : '_not stated_') + '; source: ' + (w.source ? md(w.source) : '_not stated_')));
		L.push('', '## Data', '');
		if (!inv.datasets.length) { L.push('_None listed._'); }
		inv.datasets.forEach(d => L.push('- ' + md(d.name || 'Unnamed dataset') + (d.role ? ' (' + md(d.role) + ')' : '') + ' — source: ' + (d.source ? md(d.source) : '_not stated_') + '; license: ' + (d.license ? md(d.license) : '_not stated_') + '; personal data: ' + (d.personalData || '_not stated_')));
		L.push('', '## Dependencies', '');
		if (!inv.dependencies.length) { L.push('_None listed._'); }
		inv.dependencies.forEach(d => L.push('- ' + md(d.name || 'Unnamed dependency') + ' ' + (d.version ? md(d.version) : '_version not stated_') + ' (' + d.kind + ')'));
		L.push('', '## Deployment', '');
		field('Where it runs', inv.deployment.environment);
		if (inv.deployment.apis.length) { L.push('- **External APIs:**'); inv.deployment.apis.forEach(a => L.push('  - ' + md(a.name || 'Unnamed API') + (a.url ? ': ' + md(a.url) : ''))); } else { L.push('- **External APIs:** _none listed_'); }
		L.push('', '## Intended purpose', '', clean(inv.purpose) ? md(inv.purpose) : '_Not stated._');
		L.push('', '## Limitations', '', clean(inv.limitations) ? md(inv.limitations) : '_Not stated._');
		L.push('', '## Evaluation', '');
		if (!inv.evaluation.metrics.length) { L.push('- **Metrics:** _none listed_'); }
		inv.evaluation.metrics.forEach(x => L.push('- ' + md(x.type || 'Metric') + ': ' + md(x.value) + (x.slice ? ' (' + md(x.slice) + ')' : '')));
		field('Safety evaluation', inv.evaluation.safety);
		L.push('', '## Responsible', '');
		field('Person or team', inv.owner.name); field('Organization', inv.owner.organization); field('Contact', inv.owner.contact);
		if (findings) {
			L.push('', '## Gaps found by the check', '');
			if (!findings.length) { L.push('No known gaps matched. This does not mean the model or its supply chain is safe.'); }
			for (const f of findings) { L.push('- **' + f.severity.toUpperCase() + '** ' + f.rule + ' — ' + md(f.title) + (f.location ? ' (' + md(f.location) + ')' : '') + (f.evidence ? ': ' + md(f.evidence) : '')); }
		}
		return L.join('\n') + '\n';
	}

	// ------------------------------------------------------------------ structure check (subset of CycloneDX 1.7 used by this tool)
	const KEYS = {
		bom: ['$schema', 'bomFormat', 'specVersion', 'serialNumber', 'version', 'metadata', 'components', 'services', 'externalReferences', 'dependencies', 'compositions', 'vulnerabilities', 'annotations', 'formulation', 'declarations', 'definitions', 'citations', 'properties', 'signature'],
		metadata: ['timestamp', 'lifecycles', 'tools', 'manufacturer', 'authors', 'component', 'manufacture', 'supplier', 'licenses', 'properties', 'distributionConstraints'],
		component: ['type', 'mime-type', 'bom-ref', 'supplier', 'manufacturer', 'authors', 'author', 'publisher', 'group', 'name', 'version', 'versionRange', 'isExternal', 'description', 'scope', 'hashes', 'licenses', 'copyright', 'patentAssertions', 'cpe', 'purl', 'omniborId', 'swhid', 'swid', 'modified', 'pedigree', 'externalReferences', 'components', 'evidence', 'releaseNotes', 'modelCard', 'data', 'cryptoProperties', 'properties', 'tags', 'signature'],
		service: ['bom-ref', 'provider', 'group', 'name', 'version', 'description', 'endpoints', 'authenticated', 'x-trust-boundary', 'trustZone', 'data', 'licenses', 'patentAssertions', 'externalReferences', 'services', 'releaseNotes', 'properties', 'tags', 'signature'],
		hash: ['alg', 'content'],
		license: ['bom-ref', 'id', 'name', 'acknowledgement', 'text', 'url', 'licensing', 'properties'],
		expression: ['expression', 'acknowledgement', 'bom-ref'],
		externalReference: ['url', 'comment', 'type', 'hashes', 'properties'],
		property: ['name', 'value'],
		orgEntity: ['bom-ref', 'name', 'address', 'url', 'contact'],
		orgContact: ['bom-ref', 'name', 'email', 'phone'],
		dependency: ['ref', 'dependsOn', 'provides'],
		pedigree: ['ancestors', 'descendants', 'variants', 'commits', 'patches', 'notes'],
		modelCard: ['bom-ref', 'modelParameters', 'quantitativeAnalysis', 'considerations', 'properties'],
		modelParameters: ['approach', 'task', 'architectureFamily', 'modelArchitecture', 'datasets', 'inputs', 'outputs'],
		considerations: ['users', 'useCases', 'technicalLimitations', 'performanceTradeoffs', 'ethicalConsiderations', 'environmentalConsiderations', 'fairnessAssessments'],
		quantitativeAnalysis: ['performanceMetrics', 'graphics'],
		performanceMetric: ['type', 'value', 'slice', 'confidenceInterval'],
		componentData: ['bom-ref', 'type', 'name', 'contents', 'classification', 'sensitiveData', 'graphics', 'description', 'governance'],
		dataContents: ['attachment', 'url', 'properties']
	};
	const COMPONENT_TYPES = ['application', 'framework', 'library', 'container', 'platform', 'operating-system', 'device', 'device-driver', 'firmware', 'file', 'machine-learning-model', 'data', 'cryptographic-asset'];
	const DATA_TYPES = ['source-code', 'configuration', 'dataset', 'definition', 'other'];
	const EXTREF_TYPES = ['vcs', 'issue-tracker', 'website', 'advisories', 'bom', 'mailing-list', 'social', 'chat', 'documentation', 'support', 'source-distribution', 'distribution', 'distribution-intake', 'license', 'build-meta', 'build-system', 'release-notes', 'security-contact', 'model-card', 'log', 'configuration', 'evidence', 'formulation', 'attestation', 'threat-model', 'adversary-model', 'risk-assessment', 'vulnerability-assertion', 'exploitability-statement', 'pentest-report', 'static-analysis-report', 'dynamic-analysis-report', 'runtime-analysis-report', 'component-analysis-report', 'maturity-report', 'certification-report', 'codified-infrastructure', 'quality-metrics', 'poam', 'electronic-signature', 'digital-signature', 'rfc-9116', 'patent', 'patent-family', 'patent-assertion', 'citation', 'other'];
	const SPEC_VERSIONS = ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7'];
	const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
	const ptr = p => p.replace(/^\//u, '').split('/').map(x => x.replace(/~1/gu, '/').replace(/~0/gu, '~')).reduce((a, x) => (/^\d+$/u.test(x) ? a + '[' + x + ']' : a + (a ? '.' : '') + x), '') || '(document)';

	/** Problems in the checked subset. lines: Map json-pointer -> line (optional). */
	function validateCycloneDX(input, lines) {
		// Work on a copy: a non-standard spelling is reported and then checked under its standard name,
		// the same way Review reads it (so one misspelled key does not hide the problems below it).
		const bom = isObj(input) ? JSON.parse(JSON.stringify(input)) : input;
		const probs = [];
		const add = (p, msg) => { if (probs.length < 2000) { probs.push({ location: ptr(p), line: lines ? lines.get(p) || nearestLine(lines, p) : undefined, message: msg }); } };
		const closed = (o, kind, p) => {
			if (!isObj(o)) { add(p, 'should be an object'); return false; }
			for (const k of Object.keys(o)) {
				if (KEYS[kind].indexOf(k) < 0) {
					const canon = KEYS[kind].find(x => normKey(x) === normKey(k));
					add(p + '/' + k, canon ? 'key “' + k + '” is not the standard spelling “' + canon + '” (read as “' + canon + '”)' : 'unknown key “' + k + '” for ' + kind);
					if (canon && !Object.prototype.hasOwnProperty.call(o, canon)) { o[canon] = o[k]; }
				}
			}
			return true;
		};
		const strField = (o, k, p) => { if (o[k] !== undefined && typeof o[k] !== 'string') { add(p + '/' + k, '“' + k + '” should be a string'); } };
		const arr = (o, k, p) => { if (o[k] === undefined) { return []; } if (!Array.isArray(o[k])) { add(p + '/' + k, '“' + k + '” should be an array'); return []; } return o[k]; };
		const refs = new Map();
		const regRef = (r, p) => { if (r === undefined) { return; } if (typeof r !== 'string' || !r) { add(p, 'bom-ref should be a non-empty string'); return; } if (refs.has(r)) { add(p, 'bom-ref “' + r + '” is used more than once'); } refs.set(r, p); };
		const props2 = (o, p) => arr(o, 'properties', p).forEach((x, k) => { if (closed(x, 'property', p + '/properties/' + k)) { if (typeof x.name !== 'string') { add(p + '/properties/' + k, 'property needs a “name” string'); } strField(x, 'value', p + '/properties/' + k); } });
		const org = (o, p) => { if (o === undefined) { return; } if (closed(o, 'orgEntity', p)) { strField(o, 'name', p); arr(o, 'url', p).forEach((u, k) => { if (typeof u !== 'string') { add(p + '/url/' + k, 'url should be a string'); } }); arr(o, 'contact', p).forEach((c, k) => contact(c, p + '/contact/' + k)); } };
		const contact = (c, p) => { if (closed(c, 'orgContact', p)) { strField(c, 'name', p); strField(c, 'email', p); if (typeof c.email === 'string' && !/^[^\s@]+@[^\s@]+$/u.test(c.email)) { add(p + '/email', 'email is not an e-mail address'); } } };
		const lic = (o, k0, p) => arr(o, k0, p).forEach((x, k) => {
			const q = p + '/' + k0 + '/' + k;
			if (!isObj(x)) { add(q, 'license entry should be an object'); return; }
			if (x.license !== undefined) {
				if (Object.keys(x).length !== 1) { add(q, 'license entry with “license” must not have other keys'); }
				if (closed(x.license, 'license', q + '/license')) {
					const hasId = typeof x.license.id === 'string', hasName = typeof x.license.name === 'string';
					if (hasId === hasName) { add(q + '/license', 'license needs exactly one of “id” or “name”'); }
				}
			} else if (x.expression !== undefined) { if (closed(x, 'expression', q)) { strField(x, 'expression', q); } }
			else { add(q, 'license entry needs “license” or “expression”'); }
		});
		const extRefs = (o, p) => arr(o, 'externalReferences', p).forEach((x, k) => { const q = p + '/externalReferences/' + k; if (closed(x, 'externalReference', q)) { if (typeof x.url !== 'string' || !x.url) { add(q, 'external reference needs a “url”'); } if (EXTREF_TYPES.indexOf(x.type) < 0) { add(q + '/type', 'external reference type “' + str(x.type) + '” is not a CycloneDX type'); } } });
		function comp(c, p, depth) {
			if (!closed(c, 'component', p)) { return; }
			if (COMPONENT_TYPES.indexOf(c.type) < 0) { add(p + '/type', 'component type “' + str(c.type) + '” is not a CycloneDX type'); }
			if (typeof c.name !== 'string' || !c.name) { add(p, 'component needs a “name”'); }
			if (c.version !== undefined && c.versionRange !== undefined) { add(p, '“version” and “versionRange” must not both be set'); }
			strField(c, 'version', p); strField(c, 'versionRange', p); strField(c, 'description', p);
			regRef(c['bom-ref'], p + '/bom-ref');
			org(c.supplier, p + '/supplier'); org(c.manufacturer, p + '/manufacturer');
			arr(c, 'authors', p).forEach((a, k) => contact(a, p + '/authors/' + k));
			arr(c, 'hashes', p).forEach((h, k) => { const q = p + '/hashes/' + k; if (closed(h, 'hash', q)) { if (HASH_ALGS.indexOf(h.alg) < 0) { add(q + '/alg', 'hash algorithm “' + str(h.alg) + '” is not a CycloneDX algorithm'); } if (typeof h.content !== 'string' || !isDigest(h.content)) { add(q + '/content', 'hash content is not a hex digest of 32, 40, 64, 96 or 128 characters'); } } });
			lic(c, 'licenses', p); extRefs(c, p); props2(c, p);
			if (c.pedigree !== undefined && closed(c.pedigree, 'pedigree', p + '/pedigree')) { arr(c.pedigree, 'ancestors', p + '/pedigree').forEach((a, k) => comp(a, p + '/pedigree/ancestors/' + k, depth + 1)); }
			if (c.modelCard !== undefined) {
				if (c.type !== 'machine-learning-model') { add(p + '/modelCard', 'modelCard is meant for components of type machine-learning-model'); }
				const q = p + '/modelCard';
				if (closed(c.modelCard, 'modelCard', q)) {
					const mc = c.modelCard;
					if (mc.modelParameters !== undefined && closed(mc.modelParameters, 'modelParameters', q + '/modelParameters')) {
						arr(mc.modelParameters, 'datasets', q + '/modelParameters').forEach((d, k) => { const r = q + '/modelParameters/datasets/' + k; if (isObj(d) && d.ref !== undefined && Object.keys(d).length === 1) { if (typeof d.ref !== 'string') { add(r, 'dataset ref should be a string'); } else { dataRefs.push([d.ref, r]); } } else { cdata(d, r); } });
					}
					if (mc.considerations !== undefined && closed(mc.considerations, 'considerations', q + '/considerations')) {
						for (const k of ['users', 'useCases', 'technicalLimitations', 'performanceTradeoffs']) { arr(mc.considerations, k, q + '/considerations').forEach((x, n) => { if (typeof x !== 'string') { add(q + '/considerations/' + k + '/' + n, k + ' items should be strings'); } }); }
					}
					if (mc.quantitativeAnalysis !== undefined && closed(mc.quantitativeAnalysis, 'quantitativeAnalysis', q + '/quantitativeAnalysis')) {
						arr(mc.quantitativeAnalysis, 'performanceMetrics', q + '/quantitativeAnalysis').forEach((x, n) => { const r = q + '/quantitativeAnalysis/performanceMetrics/' + n; if (closed(x, 'performanceMetric', r)) { strField(x, 'type', r); strField(x, 'value', r); strField(x, 'slice', r); } });
					}
					props2(mc, q);
				}
			}
			if (c.data !== undefined) {
				if (c.type !== 'data') { add(p + '/data', '“data” should only be used on components of type data'); }
				arr(c, 'data', p).forEach((d, k) => cdata(d, p + '/data/' + k));
			}
			if (depth < 32) { arr(c, 'components', p).forEach((x, k) => comp(x, p + '/components/' + k, depth + 1)); }
		}
		function cdata(d, p) {
			if (!closed(d, 'componentData', p)) { return; }
			if (DATA_TYPES.indexOf(d.type) < 0) { add(p + '/type', 'data type “' + str(d.type) + '” is not a CycloneDX data type'); }
			regRef(d['bom-ref'], p + '/bom-ref');
			strField(d, 'name', p);
			if (d.contents !== undefined && closed(d.contents, 'dataContents', p + '/contents')) { strField(d.contents, 'url', p + '/contents'); props2(d.contents, p + '/contents'); }
			arr(d, 'sensitiveData', p).forEach((x, k) => { if (typeof x !== 'string') { add(p + '/sensitiveData/' + k, 'sensitiveData items should be strings'); } });
		}
		const dataRefs = [];
		if (!closed(bom, 'bom', '')) { return probs; }
		if (bom.bomFormat !== 'CycloneDX') { add('/bomFormat', 'bomFormat should be “CycloneDX”'); }
		if (SPEC_VERSIONS.indexOf(bom.specVersion) < 0) { add('/specVersion', 'specVersion “' + str(bom.specVersion) + '” is not a known CycloneDX version'); }
		if (bom.serialNumber !== undefined && (typeof bom.serialNumber !== 'string' || !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(bom.serialNumber))) { add('/serialNumber', 'serialNumber should be urn:uuid: followed by a lower-case UUID'); }
		if (bom.version !== undefined && !(Number.isInteger(bom.version) && bom.version >= 1)) { add('/version', 'version should be a whole number of at least 1'); }
		if (bom.metadata !== undefined && closed(bom.metadata, 'metadata', '/metadata')) {
			const md2 = bom.metadata;
			if (md2.timestamp !== undefined && (typeof md2.timestamp !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/u.test(md2.timestamp))) { add('/metadata/timestamp', 'timestamp should be an ISO 8601 date-time'); }
			org(md2.supplier, '/metadata/supplier'); org(md2.manufacturer, '/metadata/manufacturer');
			arr(md2, 'authors', '/metadata').forEach((a, k) => contact(a, '/metadata/authors/' + k));
			if (md2.component !== undefined) { comp(md2.component, '/metadata/component', 0); }
			props2(md2, '/metadata');
		}
		arr(bom, 'components', '').forEach((c, k) => comp(c, '/components/' + k, 0));
		arr(bom, 'services', '').forEach((sv, k) => { const p = '/services/' + k; if (closed(sv, 'service', p)) { if (typeof sv.name !== 'string' || !sv.name) { add(p, 'service needs a “name”'); } regRef(sv['bom-ref'], p + '/bom-ref'); org(sv.provider, p + '/provider'); arr(sv, 'endpoints', p).forEach((e, n) => { if (typeof e !== 'string') { add(p + '/endpoints/' + n, 'endpoints should be strings'); } }); extRefs(sv, p); props2(sv, p); lic(sv, 'licenses', p); } });
		props2(bom, '');
		arr(bom, 'dependencies', '').forEach((d, k) => { const p = '/dependencies/' + k; if (closed(d, 'dependency', p)) { if (typeof d.ref !== 'string' || !refs.has(d.ref)) { add(p + '/ref', 'dependency ref “' + str(d.ref) + '” does not match any bom-ref'); } arr(d, 'dependsOn', p).forEach((r, n) => { if (!refs.has(r)) { add(p + '/dependsOn/' + n, 'dependsOn “' + str(r) + '” does not match any bom-ref'); } }); } });
		for (const [r, p] of dataRefs) { if (!refs.has(r)) { add(p, 'dataset ref “' + r + '” does not match any bom-ref'); } }
		return probs;
	}

	// ------------------------------------------------------------------ Review: CycloneDX -> inventory
	/** Lookup by key after normalization (case, _, -, camelCase); records non-standard spellings. */
	function getter(lines) {
		return function get(o, key, p) {
			if (!isObj(o)) { return { v: undefined, p: p + '/' + key }; }
			if (Object.prototype.hasOwnProperty.call(o, key)) { return { v: o[key], p: p + '/' + key }; }
			const k2 = Object.keys(o).find(k => normKey(k) === normKey(key));
			return k2 === undefined ? { v: undefined, p: p + '/' + key } : { v: o[k2], p: p + '/' + k2 };
		};
	}
	function fromCycloneDX(bom, lines) {
		const get = getter(lines);
		const g = (o, ...keys) => { let cur = o; for (const k of keys) { cur = get(cur, k, '').v; } return cur; };
		const listOf = v => (Array.isArray(v) ? v : []);
		const propsOf = o => { const m = new Map(); for (const x of listOf(g(o, 'properties'))) { if (isObj(x) && typeof x.name === 'string' && !m.has(normKey(x.name))) { m.set(normKey(x.name), str(x.value)); } } return m; };
		const pv = (o, name) => propsOf(o).get(normKey(P + name)) || '';
		const flat = [];
		const walk = (list, p, depth) => listOf(list).forEach((c, k) => { if (!isObj(c)) { return; } const q = p + '/' + k; flat.push({ c, p: q }); if (depth < 32) { const sub = get(c, 'components', q); walk(sub.v, sub.p, depth + 1); } });
		const top = get(bom, 'components', '');
		walk(top.v, top.p, 0);
		const typeOf = c => str(g(c, 'type'));
		const inv = emptyInventory();
		const loc = new Map();
		const models = [];
		// Responsible party candidates: an organizational entity (name + contact[] + url[]) or a person (name + email).
		const fromEntity = (ent, extraContact) => {
			if (!isObj(ent)) { return null; }
			const person = listOf(g(ent, 'contact')).filter(isObj)[0] || {};
			const r = { name: str(g(person, 'name')), organization: str(g(ent, 'name')), contact: str(g(person, 'email')) || listOf(g(ent, 'url')).map(str).find(Boolean) || extraContact || '' };
			return r.name || r.organization || r.contact ? r : null;
		};
		const fromPerson = p => (isObj(p) && (str(g(p, 'name')) || str(g(p, 'email'))) ? { name: str(g(p, 'name')), organization: '', contact: str(g(p, 'email')) } : null);
		flat.forEach(({ c, p }) => {
			const t = typeOf(c);
			const lic = get(c, 'licenses', p);
			if (t === 'machine-learning-model') {
				const anc = listOf(g(c, 'pedigree', 'ancestors')).filter(isObj)[0] || {};
				const mc = get(c, 'modelCard', p);
				const cons = get(mc.v, 'considerations', mc.p);
				const qa = get(mc.v, 'quantitativeAnalysis', mc.p);
				const pm = get(qa.v, 'performanceMetrics', qa.p);
				const vr = get(c, 'versionRange', p);
				const model = { name: str(g(c, 'name')), version: str(g(c, 'version')), vendor: str(g(c, 'supplier', 'name')) || str(g(c, 'manufacturer', 'name')), license: readLicense(lic.v), type: normType(pv(c, 'model-type')), baseModel: { name: str(anc.name), version: str(anc.version) } };
				const useCases = listOf(get(cons.v, 'useCases', cons.p).v).map(str).filter(Boolean);
				const limits = listOf(get(cons.v, 'technicalLimitations', cons.p).v).map(str).filter(Boolean);
				const metrics = listOf(pm.v).filter(isObj).map(x => ({ type: str(x.type), value: str(x.value), slice: str(x.slice) }));
				const safety = pv(mc.v, 'safety-evaluation') || pv(c, 'safety-evaluation');
				const key = 'model' + models.length;
				loc.set(key + '.license', lic.p); loc.set(key + '.version', vr.v !== undefined ? vr.p : p + '/version'); loc.set(key + '.type', p + '/properties');
				loc.set(key + '.baseModel', p + '/pedigree'); loc.set(key + '.baseModel.version', p + '/pedigree'); loc.set(key + '.vendor', p + '/supplier');
				loc.set(key + '.weights', p); loc.set(key + '.datasets', p); loc.set(key + '.purpose', cons.p + '/useCases'); loc.set(key + '.limitations', cons.p + '/technicalLimitations'); loc.set(key + '.evaluation', mc.p);
				models.push({ model, purpose: useCases.join('\n'), limitations: limits.join('\n'), evaluation: { metrics, safety }, key, versionRange: vr.v !== undefined ? str(vr.v) || 'versionRange' : '', comp: c, path: p });
			} else if (t === 'file') {
				const h = listOf(g(c, 'hashes')).filter(isObj)[0] || {};
				const n = inv.weights.length;
				const ext = listOf(g(c, 'externalReferences')).filter(isObj);
				const dist = ext.find(x => ['distribution', 'distribution-intake', 'source-distribution', 'vcs', 'website'].indexOf(str(x.type)) >= 0) || ext[0] || {};
				inv.weights.push({ file: g(c, 'properties') && pv(c, 'file-name-missing') ? '' : str(g(c, 'name')), format: pv(c, 'weights-format'), hashAlg: str(h.alg) || pv(c, 'weights-hash-algorithm'), hash: str(h.content) || pv(c, 'weights-hash-unverified'), source: str(dist.url) || pv(c, 'source') });
				loc.set('weights.' + n + '.hash', p + '/hashes'); loc.set('weights.' + n + '.hashAlg', p + '/hashes'); loc.set('weights.' + n + '.format', p); loc.set('weights.' + n + '.source', p + '/externalReferences');
			} else if (t === 'data') {
				const d0 = listOf(g(c, 'data')).filter(isObj);
				const first = d0[0] || {};
				const n = inv.datasets.length;
				const ext = listOf(g(c, 'externalReferences')).filter(isObj)[0] || {};
				const pdProp = pv(c, 'personal-data');
				const sensitive = d0.some(d => listOf(g(d, 'sensitiveData')).some(x => clean(x)));
				inv.datasets.push({ name: pv(c, 'dataset-name-missing') ? '' : str(g(c, 'name')) || str(first.name), role: pv(c, 'dataset-role'), source: str(g(first, 'contents', 'url')) || str(ext.url) || pv(c, 'source'), license: readLicense(lic.v), personalData: normPd(pdProp) || (sensitive ? 'yes' : '') });
				loc.set('datasets.' + n + '.license', lic.p); loc.set('datasets.' + n + '.source', p + '/data'); loc.set('datasets.' + n + '.personalData', p + '/properties');
			} else if (t === 'framework' || t === 'library') {
				const n = inv.dependencies.length;
				inv.dependencies.push({ kind: t, name: pv(c, 'dependency-name-missing') ? '' : str(g(c, 'name')), version: str(g(c, 'version')) || str(g(c, 'versionRange')) });
				loc.set('dependencies.' + n + '.version', p + '/version');
			}
		});
		const svc = get(bom, 'services', '');
		listOf(svc.v).forEach((s, k) => { if (!isObj(s)) { return; } const eps = listOf(g(s, 'endpoints')).map(str).filter(Boolean); const name = pv(s, 'api-name-missing') ? '' : str(g(s, 'name')); if (!eps.length) { inv.deployment.apis.push({ name, url: pv(s, 'endpoint') }); } for (const e of eps) { inv.deployment.apis.push({ name, url: e }); } });
		const meta = get(bom, 'metadata', '');
		inv.deployment.environment = pv(meta.v, 'deployment');
		const mcomp = g(meta.v, 'component');
		const firstModel = models[0] ? models[0].comp : null;
		const extra = pv(meta.v, 'owner-contact');
		const candidates = [fromEntity(g(meta.v, 'supplier'), extra), fromEntity(g(meta.v, 'manufacturer'))]
			.concat(listOf(g(meta.v, 'authors')).map(fromPerson), [fromEntity(g(mcomp, 'supplier')), fromEntity(g(mcomp, 'manufacturer'))], listOf(g(mcomp, 'authors')).map(fromPerson))
			.concat(firstModel ? [fromEntity(g(firstModel, 'manufacturer'))].concat(listOf(g(firstModel, 'authors')).map(fromPerson)) : [])
			.filter(Boolean);
		const owner = candidates.find(o => (o.name || o.organization) && o.contact) || candidates[0];
		if (owner) { inv.owner = owner; } else if (extra) { inv.owner.contact = extra; }
		loc.set('owner', '/metadata');
		if (models[0]) { inv.model = models[0].model; inv.purpose = models[0].purpose; inv.limitations = models[0].limitations; inv.evaluation = models[0].evaluation; }
		return { inventory: inv, models, loc };
	}

	function allStrings(v, p, out, depth) {
		if (out.length > 200000 || depth > MAX_DEPTH) { return; }
		if (typeof v === 'string') { out.push({ p, text: v }); return; }
		if (Array.isArray(v)) { v.forEach((x, k) => allStrings(x, p + '/' + k, out, depth + 1)); return; }
		if (isObj(v)) { for (const k of Object.keys(v)) { const q = p + '/' + k.replace(/~/gu, '~0').replace(/\//gu, '~1'); if (isSecretName(k) && typeof v[k] === 'string' && v[k].length >= 8 && !isUrlLike(v[k])) { out.push({ p: q, text: k + '=' + v[k], named: true }); } else { allStrings(v[k], q, out, depth + 1); } } }
		if (isObj(v) && typeof v.name === 'string' && typeof v.value === 'string' && isSecretName(v.name) && v.value.length >= 8) { out.push({ p: p + '/value', text: v.name.replace(/[:=\s]/gu, '_') + '=' + v.value, named: true }); }
	}

	function review(text, hooks) {
		const s = str(text);
		if (s.length > MAX_INPUT_CHARS) { const e = new Error('The input is larger than the 5 MB limit.'); e.code = 'TOO_LARGE'; throw e; }
		if (!s.trim()) { const e = new Error('The input is empty.'); e.code = 'EMPTY'; throw e; }
		const progress = (d, t) => { if (hooks && hooks.onProgress) { hooks.onProgress(d, t); } };
		const parsed = parseJson(s);
		progress(1, 5);
		const bom = parsed.value;
		const get = getter(parsed.lines);
		const fmt = isObj(bom) ? get(bom, 'bomFormat', '').v : undefined;
		if (!isObj(bom) || typeof fmt !== 'string' || normKey(fmt) !== 'cyclonedx') {
			const e = new Error(Array.isArray(bom) ? 'The JSON is a list, not a CycloneDX BOM object.' : isObj(bom) && (bom.spdxVersion || bom.SPDXID) ? 'This looks like an SPDX document. Only CycloneDX JSON is supported in this version.' : 'This JSON is not a CycloneDX BOM: “bomFormat”: “CycloneDX” is missing.');
			e.code = 'NOT_CYCLONEDX';
			throw e;
		}
		const structure = validateCycloneDX(bom, parsed.lines);
		for (const d of parsed.duplicates) { structure.push({ location: ptr(d.path), line: d.line, message: 'duplicate key “' + d.key + '”; the last value is used' }); }
		if (fmt !== 'CycloneDX' && !structure.some(x => x.location === 'bomFormat')) { structure.push({ location: 'bomFormat', line: parsed.lines.get('/bomFormat'), message: 'bomFormat should be “CycloneDX”' }); }
		progress(2, 5);
		const { inventory, models, loc } = fromCycloneDX(bom, parsed.lines);
		// Rows are kept even when empty so that row indexes match the locations recorded while reading.
		const inv = normalizeInventory(inventory, true);
		const where = key => { const p = loc.get(key); return p ? { location: ptr(p), line: parsed.lines.get(p) || nearestLine(parsed.lines, p) } : { location: key }; };
		progress(3, 5);
		const strings = [];
		allStrings(bom, '', strings, 0);
		const fields = strings.filter(x => x.p !== '/serialNumber' && !/\/bom-ref$|\/ref$|\/dependsOn\/\d+$/u.test(x.p)).map(x => ({ label: ptr(x.p), line: parsed.lines.get(x.p) || nearestLine(parsed.lines, x.p), text: x.text, noOpaque: /\/hashes\/\d+\/content$/u.test(x.p) }));
		const ms = models.map(m => ({ model: normalizeInventory({ model: m.model }).model, purpose: m.purpose, limitations: m.limitations, evaluation: normalizeInventory({ evaluation: m.evaluation }).evaluation, key: m.key, versionRange: m.versionRange }));
		const findings = checkInventory(inv, { where, models: ms, fields }, null);
		if (!models.length) { findings.push(finding('AIBOM-FMT-001', 'components')); }
		if (structure.length) { findings.push(finding('AIBOM-FMT-002', '(document)', '', { evidence: structure.length + ' problem' + (structure.length === 1 ? '' : 's') + ' in the checked fields' })); }
		progress(4, 5);
		sortFindings(findings);
		const notes = [];
		const sv = str(get(bom, 'specVersion', '').v);
		if (['1.0', '1.1', '1.2', '1.3', '1.4'].indexOf(sv) >= 0) { notes.push('specVersion ' + sv + ' predates model cards (CycloneDX 1.5). Model card fields were read if present.'); }
		if (models.length > 1) { notes.push(models.length + ' model components found. Model-level checks ran for each; weights, data and dependencies are checked once for the whole document.'); }
		const sm = summarize(findings);
		progress(5, 5);
		const shownStructure = structure.slice(0, 2000).map(x => Object.assign({}, x, { location: maskSecrets(x.location), message: maskSecrets(x.message) }));
		return { mode: 'review', engine: ENGINE, ruleset: RULESET, level: sm.level, counts: Object.assign(sm.counts, { models: models.length, weights: inv.weights.length, datasets: inv.datasets.length, dependencies: inv.dependencies.length, apis: inv.deployment.apis.length, structure: structure.length }), findings, structure: shownStructure, notes, inventory: inv, inventoryView: maskDeep(normalizeInventory(inv)), modelNames: models.map(m => maskSecrets(m.model.name)), specVersion: sv };
	}
	const maskDeep = v => (typeof v === 'string' ? maskSecrets(v) : Array.isArray(v) ? v.map(maskDeep) : isObj(v) ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, maskDeep(x)])) : v);
	function nearestLine(lines, p) { let q = p; while (q) { q = q.slice(0, q.lastIndexOf('/')); if (lines.has(q)) { return lines.get(q); } } return lines.get('') || 1; }

	// ------------------------------------------------------------------ Build
	function build(inventory, opts, hooks) {
		const inv = normalizeInventory(inventory);
		const findings = sortFindings(checkInventory(inv, { where: k => ({ location: buildLabel(k) }) }, hooks));
		const bom = toCycloneDX(inv, opts);
		const bomText = JSON.stringify(bom, null, 2) + '\n';
		const structure = validateCycloneDX(JSON.parse(bomText));
		const sm = summarize(findings);
		const secrets = findings.filter(f => f.group === 'secrets').length;
		const markdown = toMarkdown(inv, findings, opts);
		return { mode: 'build', engine: ENGINE, ruleset: RULESET, level: sm.level, counts: sm.counts, findings, bom, bomText, markdown, bomTextMasked: bomText, markdownMasked: markdown, structure, secrets, inventory: inv };
	}
	function buildLabel(k) {
		const map = { 'model.license': 'Model › License', 'model.version': 'Model › Version', 'model.type': 'Model › Type', 'model.baseModel': 'Model › Base model', 'model.baseModel.version': 'Model › Base model version', 'model.vendor': 'Model › Vendor', 'model.weights': 'Weights files', 'model.datasets': 'Data', 'model.purpose': 'Purpose', 'model.limitations': 'Limitations', 'model.evaluation': 'Evaluation', owner: 'Responsible' };
		if (map[k]) { return map[k]; }
		const m = /^(weights|datasets|dependencies)\.(\d+)\.(.+)$/u.exec(k);
		if (m) { const names = { weights: 'Weights file', datasets: 'Dataset', dependencies: 'Dependency' }; const f = { hash: 'Hash', hashAlg: 'Hash algorithm', format: 'Format', source: 'Source', license: 'License', personalData: 'Personal data', version: 'Version' }; return names[m[1]] + ' ' + (Number(m[2]) + 1) + ' › ' + (f[m[3]] || m[3]); }
		return k;
	}

	// ------------------------------------------------------------------ example for the page
	const EXAMPLE = {
		model: { name: 'Ticket Router', version: '1.2.0', vendor: 'Example Support Ltd', license: 'Apache-2.0', type: 'fine-tuned', baseModel: { name: 'example-base-encoder', version: 'latest' } },
		weights: [{ file: 'ticket-router.pt', format: 'PyTorch', hashAlg: 'SHA-256', hash: '', source: 'http://models.example.com/ticket-router/1.2.0/' }],
		datasets: [{ name: 'Support tickets 2025 (synthetic)', role: 'fine-tuning', source: 'https://data.example.com/tickets-2025', license: '', personalData: 'unknown' }],
		dependencies: [{ kind: 'framework', name: 'PyTorch', version: '2.5.1' }, { kind: 'library', name: 'transformers', version: '' }],
		deployment: { environment: 'Internal Kubernetes cluster', apis: [{ name: 'Translation API', url: 'https://translate.example.net/v1' }] },
		purpose: 'Route incoming support tickets to the right team.',
		limitations: '',
		evaluation: { metrics: [{ type: 'accuracy', value: '0.91', slice: 'December 2025 tickets' }], safety: '' },
		owner: { name: 'Support ML team', organization: 'Example Support Ltd', contact: 'support-ml@example.com' }
	};

	return { ENGINE, RULESET, SPEC_VERSION, TOOL_NAME, MAX_INPUT_CHARS, MAX_FIELD_CHARS, RULES, GROUPS, EXAMPLE, parseJson, normKey, normalizeInventory, emptyInventory, checkInventory, build, review, toCycloneDX, toMarkdown, validateCycloneDX, fromCycloneDX, scanText, maskSecrets, isFloating, isMissing, isPickle };
}));
