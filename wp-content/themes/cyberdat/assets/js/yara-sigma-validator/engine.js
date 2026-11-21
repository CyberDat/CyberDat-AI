/*!
 * CyberDat YARA/Sigma Rule Validator & Converter — engine, shared by the worker and the Node tests.
 *
 * Contract (enforced by tests):
 *  - static analysis only: rules are never compiled by a real YARA engine, never run against files, and regular
 *    expressions written in rules are never turned into JavaScript RegExp objects or executed;
 *  - own YAML subset reader with size, depth, line and time limits; anchors, aliases, tags and merge keys are refused;
 *  - own converters to Splunk SPL, Microsoft KQL and Elastic Lucene; unsupported constructs give an error that names
 *    them, never a silently wrong query;
 *  - no network, storage, DOM or eval; no regular-expression look-behind; user text matched with Unicode classes and
 *    the u flag; secrets found in rules are shown masked in findings and reports.
 * Sigma specification: public domain (SigmaHQ). YARA syntax: VirusTotal YARA documentation (BSD-3-Clause).
 * Referenced by name only; no specification text and no SigmaHQ rules (DRL 1.1) are bundled.
 */
(function (root, factory) {
	const api = factory();
	if (typeof module === 'object' && module.exports) { module.exports = api; } else { root.CyberDatRuleValidator = api; }
}(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const ENGINE = '1.0.0';
	const RULESET = '2026-11-18.1';
	const MAX_INPUT_CHARS = 1024 * 1024;
	const MAX_LINES = 20000;
	const MAX_DEPTH = 64;
	const TIME_BUDGET_MS = 10000;

	const DEF = {
		'SIG-YAML-001': ['error', 'YAML cannot be read', 'The rule is not valid YAML, so no tool can load it.', 'Fix the indentation or quoting at the reported line. Use spaces, not tabs.'],
		'SIG-YAML-002': ['error', 'YAML anchors, aliases, tags or merge keys', 'Anchors, aliases, tags and merge keys are not needed in Sigma rules and are refused here for safety. An unquoted value that starts with * is read as an alias.', 'Write values out in full and quote values that start with * or &, for example \'*\'.'],
		'SIG-YAML-003': ['error', 'Duplicate key', 'A key appears twice in the same mapping; most YAML readers silently keep only one of them.', 'Merge the values into a list or rename one of the keys.'],
		'SIG-REQ-001': ['error', 'Title missing', 'Every Sigma rule needs a title.', 'Add a short title that says what the rule detects.'],
		'SIG-REQ-002': ['error', 'Log source missing', 'Without category, product or service in logsource, converters cannot know which logs the rule applies to.', 'Add logsource with at least one of category, product or service.'],
		'SIG-REQ-003': ['error', 'Detection missing', 'The detection section holds the search identifiers and the condition.', 'Add a detection mapping with at least one search identifier and a condition.'],
		'SIG-REQ-004': ['error', 'Condition missing', 'The condition says how the search identifiers are combined.', 'Add condition, for example “condition: selection”.'],
		'SIG-ID-001': ['error', 'Invalid id', 'The id should be a UUID so the rule can be tracked across versions.', 'Use a random UUID (version 4).'],
		'SIG-DATE-001': ['error', 'Invalid date format', 'Dates in Sigma rules use the ISO 8601 form YYYY-MM-DD.', 'Write the date as YYYY-MM-DD, for example 2026-11-18.'],
		'SIG-DATE-002': ['warning', 'Modified before created', 'The modified date is earlier than the creation date.', 'Check both dates.'],
		'SIG-LVL-001': ['error', 'Invalid level', 'Level must be informational, low, medium, high or critical.', 'Use one of the five levels.'],
		'SIG-STS-001': ['error', 'Invalid status', 'Status must be stable, test, experimental, deprecated or unsupported.', 'Use one of the five status values.'],
		'SIG-TAG-001': ['warning', 'Tag in an unknown format', 'Tags are expected in lower case in namespaces such as attack.t1059.001, attack.execution, cve.2026-12345 or tlp.clear.', 'Use a known namespace and lower case.'],
		'SIG-TITLE-001': ['warning', 'Title too long', 'Titles should stay under 256 characters.', 'Shorten the title and move details to description.'],
		'SIG-COND-001': ['error', 'Condition syntax error', 'The condition cannot be parsed.', 'Use search identifiers with and, or, not, parentheses, “1 of …” or “all of …”.'],
		'SIG-COND-002': ['error', 'Condition refers to a missing search identifier', 'A name or pattern in the condition matches no search identifier in detection.', 'Fix the name in the condition or add the search identifier.'],
		'SIG-COND-003': ['warning', 'Search identifier not used', 'A search identifier in detection is not used by the condition, so it has no effect.', 'Use it in the condition or remove it.'],
		'SIG-MOD-001': ['error', 'Unknown value modifier', 'The modifier after | is not a Sigma value modifier.', 'Check the spelling (for example endswith, contains, startswith).'],
		'SIG-MOD-002': ['error', 'Conflicting value modifiers', 'These modifiers cannot be combined in one field.', 'Keep one of contains, startswith and endswith; use re, cidr and exists alone.'],
		'SIG-DET-001': ['error', 'Empty or malformed search identifier', 'A search identifier must be a mapping of fields, a list of mappings or a list of keywords.', 'Add field: value pairs or keywords.'],
		'SIG-Q-001': ['info', 'No false positives listed', 'Listing known false positives helps analysts triage alerts.', 'Add falsepositives, or “Unknown” if none are known.'],
		'SIG-Q-002': ['warning', 'Overly broad value', 'A value made only of wildcards, or a contains/startswith/endswith value shorter than 3 characters, matches almost everything.', 'Use a more specific value.'],
		'SIG-Q-003': ['info', 'Duplicate value', 'The same value, tag or search identifier content appears more than once.', 'Remove the duplicate.'],
		'SIG-Q-004': ['info', 'Id missing', 'Without an id the rule is hard to track and deduplicate.', 'Add a random UUID as id.'],
		'SIG-Q-005': ['info', 'Level missing', 'Without a level, alerts cannot be prioritised.', 'Add level.'],
		'SIG-Q-006': ['info', 'Description or author missing', 'Description and author help others maintain the rule.', 'Add description and author.'],
		'YAR-SYN-001': ['error', 'Syntax error', 'The rule text cannot be parsed.', 'Fix the syntax at the reported line.'],
		'YAR-NAME-001': ['error', 'Invalid or reserved name', 'Rule names and tags must start with a letter or underscore, contain only letters, digits and underscores, be at most 128 characters long and must not be YARA keywords.', 'Rename the rule or tag.'],
		'YAR-NAME-002': ['error', 'Duplicate rule name', 'Two rules have the same name; YARA refuses to compile the file.', 'Give each rule a unique name.'],
		'YAR-STR-001': ['error', 'Duplicate string identifier', 'Two strings in the same rule have the same identifier.', 'Rename one of them.'],
		'YAR-STR-002': ['error', 'Undeclared string', 'The condition uses a string that is not declared in strings.', 'Declare the string or fix the identifier.'],
		'YAR-STR-003': ['warning', 'Unused string', 'A declared string is not used by the condition; YARA reports this as an error unless the condition uses “them” or a matching pattern.', 'Use it in the condition or remove it.'],
		'YAR-HEX-001': ['error', 'Invalid hex string', 'Hex strings consist of byte pairs, ?? wildcards, ~XX negations, jumps [n-m] with n ≤ m and alternatives ( … | … ).', 'Fix the hex string.'],
		'YAR-RE-001': ['error', 'Invalid regular expression', 'The regular expression is not well formed (checked statically, never executed).', 'Balance parentheses and brackets and check quantifiers.'],
		'YAR-MOD-001': ['error', 'Invalid string modifier', 'The modifier is unknown or not allowed for this string type.', 'Hex strings accept only private; regular expressions accept nocase, wide, ascii, fullword and private.'],
		'YAR-IMP-001': ['error', 'Module not imported', 'The condition uses a module that is not imported.', 'Add import "module" at the top of the file.'],
		'YAR-IMP-002': ['info', 'Module imported but not used', 'Unused imports load modules for nothing.', 'Remove the import.'],
		'YAR-COND-001': ['error', 'Condition missing', 'Every YARA rule needs a condition section.', 'Add condition:.'],
		'YAR-META-001': ['error', 'Invalid meta value', 'Meta values must be quoted strings, integers or true/false.', 'Quote the value.'],
		'YAR-Q-001': ['warning', 'String shorter than 4 bytes', 'Very short strings make scanning slow and match too often.', 'Use longer strings or combine them with other conditions.'],
		'YAR-Q-002': ['warning', 'Regular expression likely slow', 'Leading or unbounded .* / .+ and nested quantifiers make scanning slow.', 'Anchor the expression with fixed text and use bounded repetition such as .{0,64}.'],
		'YAR-Q-003': ['info', 'No file size limit', 'Without a filesize limit the rule is evaluated on very large files too.', 'Add, for example, filesize < 5MB.'],
		'SEC-001': ['warning', 'Value that looks like a secret', 'The rule contains a value in a known credential format or a long random-looking value. Rules are often shared.', 'Check the value; do not publish rules that contain real secrets.']
	};
	const SEV_RANK = { error: 3, warning: 2, info: 1 };

	// ------------------------------------------------------------------ helpers
	const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
	const nfc = s => String(s).normalize('NFC');
	function budget() { const end = Date.now() + TIME_BUDGET_MS; return () => { if (Date.now() > end) { const e = new Error('Processing took longer than ' + (TIME_BUDGET_MS / 1000) + ' seconds and was stopped.'); e.code = 'TIMEOUT'; throw e; } }; }

	// ------------------------------------------------------------------ secrets (masked)
	const SECRET_PATTERNS = [
		['AWS access key ID', /(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}/gu], ['GitHub token', /gh[pousr]_[0-9A-Za-z]{30,}/gu], ['GitLab token', /glpat-[0-9A-Za-z_-]{20,}/gu],
		['Slack token', /xox[abposr]-[0-9A-Za-z-]{10,}/gu], ['Anthropic API key', /sk-ant-[0-9A-Za-z_-]{20,}/gu], ['OpenAI-style API key', /sk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{20,}/gu],
		['Google API key', /AIza[0-9A-Za-z_-]{35}/gu], ['Hugging Face token', /hf_[0-9A-Za-z]{30,}/gu], ['JSON Web Token', /eyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{5,}\.[0-9A-Za-z_-]*/gu],
		['Private key', /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/gu]
	];
	const TOKEN_CHAR = /[\p{L}\p{N}\p{M}_]/u;
	// No name prefix in the pattern (a prefix made it quadratic on long input): the separator right after the word already
	// ensures the key ends with it, e.g. user_password: or ApiToken= match, TokenElevationType: does not.
	// Every repeated part is bounded so that the scan stays linear on long or hostile input (ReDoS).
	const KEYED = /(?:credentials?|password|secret|token)(?:\|[\p{L}\p{N}]{1,20}){0,4}["']?[ \t]{0,20}(?:==|=~|!=|=|:|[ \t](?:contains|startswith|endswith|has|matches regex)[ \t])[ \t]{0,20}(@?"(?:[^"\\\n]|\\.){0,500}"|'(?:[^'\\\n]|\\.){0,500}'|[^\s"',;)]+)/giu;
	const mask = v => { const c = [...String(v)]; return c.length <= 8 ? '••••' : c.slice(0, 4).join('') + '… (' + c.length + ' characters)'; };
	function entropy(s) { const m = new Map(); for (const ch of s) { m.set(ch, (m.get(ch) || 0) + 1); } let e = 0; for (const n of m.values()) { const p = n / s.length; e -= p * Math.log2(p); } return e; }
	function findSecrets(text) {
		const s = String(text || '');
		const out = [];
		const taken = (a, b) => out.some(x => a < x.end && b > x.start);
		for (const [kind, re] of SECRET_PATTERNS) { re.lastIndex = 0; let m; while ((m = re.exec(s))) { const a = m.index, b = a + m[0].length; if ((a > 0 && TOKEN_CHAR.test(s[a - 1]) && kind !== 'Private key') || taken(a, b)) { continue; } out.push({ kind, start: a, end: b, shown: kind === 'Private key' ? 'BEGIN … PRIVATE KEY' : mask(m[0]) }); } }
		const LONG = /[0-9A-Za-z+/=_\-.]{24,}/gu;
		let m;
		while ((m = LONG.exec(s))) {
			const v = m[0], a = m.index, b = a + v.length;
			if (taken(a, b) || (a > 0 && TOKEN_CHAR.test(s[a - 1])) || (b < s.length && TOKEN_CHAR.test(s[b]))) { continue; }
			if (!/[0-9]/u.test(v) || !/[A-Za-z]/u.test(v) || /^[0-9a-fA-F-]+$/u.test(v) || /^(?:https?|www)/iu.test(v) || /^[0-9a-f]{8}-[0-9a-f]{4}-/iu.test(v) || entropy(v) < 3.8) { continue; }
			out.push({ kind: 'unrecognized long value', start: a, end: b, shown: mask(v) });
		}
		// The value after a key or field named …credential(s), …password, …secret or …token is masked whatever its length
		// (owner decision 2026-11-21): YAML/JSON keys, key=value, and the SPL, KQL and Lucene forms of a converted query.
		KEYED.lastIndex = 0;
		while ((m = KEYED.exec(s))) {
			const v = m[1];
			let a = m.index + m[0].length - v.length, b = a + v.length;
			if (v[0] === '@') { a += 2; b -= 1; } else if (v[0] === '"' || v[0] === '\'') { a += 1; b -= 1; }
			if (b <= a || taken(a, b) || /^\[|…|••••/u.test(s.slice(a, b))) { continue; }
			out.push({ kind: 'value of a secret field', start: a, end: b, shown: mask(s.slice(a, b)) });
		}
		return out.sort((x, y) => x.start - y.start);
	}
	function maskSecrets(text) { let s = String(text || ''); for (const x of findSecrets(s).sort((p, q) => q.start - p.start)) { s = s.slice(0, x.start) + '[' + x.kind + ': ' + x.shown + ']' + s.slice(x.end); } return s; }

	function finding(id, line, evidence, ruleName) {
		const d = DEF[id];
		return { id, severity: d[0], title: d[1], explanation: d[2], fix: d[3], line: line || 0, rule: ruleName ? maskSecrets(nfc(ruleName)).slice(0, 200) : '', evidence: evidence ? maskSecrets(nfc(evidence)).slice(0, 300) : '' };
	}
	const yamlError = (id, line, msg) => { const e = new Error(msg + (line ? ' (line ' + line + ')' : '')); e.code = id; e.line = line; return e; };

	// ------------------------------------------------------------------ YAML subset reader
	/** Returns { docs: [value], lines: Map(path -> line) }. Throws SIG-YAML-001/002/003. */
	function parseYaml(text, tick) {
		const src = String(text || '').replace(/^\ufeff/u, '');
		if (src.length > MAX_INPUT_CHARS) { throw yamlError('SIG-YAML-001', 0, 'The input is larger than 1 MB'); }
		const raw = src.split(/\r\n|\r|\n/u);
		if (raw.length > MAX_LINES) { throw yamlError('SIG-YAML-001', 0, 'The input has more than ' + MAX_LINES + ' lines'); }
		const lines = new Map();
		const docs = [];
		let cur = [];
		const flush = () => { if (cur.some(l => l.text.trim() && !/^\s*#/u.test(l.text))) { docs.push(cur); } cur = []; };
		raw.forEach((t, i) => { if (/^---\s*(?:#.*)?$/u.test(t)) { flush(); } else if (/^\.\.\.\s*$/u.test(t)) { flush(); } else { cur.push({ n: i + 1, text: t }); } });
		flush();
		const out = docs.map((d, di) => parseDoc(d, di));
		return { docs: out, lines };

		function stripComment(t) {
			let q = '', out = '';
			for (let i = 0; i < t.length; i++) {
				const c = t[i];
				if (q) { out += c; if (c === q) { if (q === '\'' && t[i + 1] === '\'') { out += t[++i]; continue; } q = ''; } else if (q === '"' && c === '\\') { out += t[++i] || ''; } continue; }
				if (c === '#' && (i === 0 || /\s/u.test(t[i - 1]))) { break; }
				if ((c === '\'' || c === '"') && (i === 0 || /[\s:\-[{,]/u.test(t[i - 1]))) { q = c; }
				out += c;
			}
			return out.replace(/\s+$/u, '');
		}
		function parseDoc(docLines, di) {
			const L = docLines.map(l => {
				if (/^ *\t/u.test(l.text)) { throw yamlError('SIG-YAML-001', l.n, 'Tab characters are not allowed in indentation'); }
				const body = stripComment(l.text);
				return { n: l.n, raw: l.text, body, indent: body.length - body.replace(/^ +/u, '').length };
			});
			let i = 0;
			const skip = () => { while (i < L.length && !L[i].body.trim()) { i++; } };
			const pfx = di ? '/doc' + di : '';
			skip();
			if (i >= L.length) { return null; }
			const v = block(L[i].indent, pfx, 0);
			skip();
			if (i < L.length) { throw yamlError('SIG-YAML-001', L[i].n, 'Unexpected indentation or content'); }
			return v;

			function block(ind, path, depth) {
				if (depth > MAX_DEPTH) { throw yamlError('SIG-YAML-001', L[i].n, 'Nesting is deeper than ' + MAX_DEPTH + ' levels'); }
				if (tick) { tick(); }
				skip();
				const line = L[i];
				const t = line.body.trim();
				if (t === '-' || t.startsWith('- ')) { return seq(line.indent, path, depth); }
				if (keyOf(t)) { return map(line.indent, path, depth); }
				i++;
				return scalar(t, line.n, path);
			}
			function keyOf(t) {
				let m;
				if (t[0] === '"' || t[0] === '\'') { const q = t[0]; let j = 1; for (; j < t.length; j++) { if (t[j] === '\\' && q === '"') { j++; continue; } if (t[j] === q) { if (q === '\'' && t[j + 1] === '\'') { j++; continue; } break; } } if (t[j + 1] === ':' && (t.length === j + 2 || t[j + 2] === ' ')) { return { key: unquote(t.slice(0, j + 1), 0), rest: t.slice(j + 2).trim() }; } return null; }
				if ((m = /^([^\s:#'"[\]{},&*!|>%@`][^:#]*?|[^\s:#'"[\]{},&*!|>%@`]?)\s*:(?:\s+(.*))?$/u.exec(t)) && !/^- /u.test(t)) { return { key: m[1].trim(), rest: (m[2] || '').trim() }; }
				return null;
			}
			function map(ind, path, depth) {
				const obj = {};
				for (;;) {
					skip();
					if (i >= L.length) { break; }
					const line = L[i];
					if (line.indent < ind) { break; }
					if (line.indent > ind) { throw yamlError('SIG-YAML-001', line.n, 'Unexpected indentation'); }
					const t = line.body.trim();
					const k = keyOf(t);
					if (!k) { throw yamlError('SIG-YAML-001', line.n, 'Expected “key: value”'); }
					if (k.key === '<<') { throw yamlError('SIG-YAML-002', line.n, 'Merge keys are not accepted'); }
					if (Object.prototype.hasOwnProperty.call(obj, k.key)) { throw yamlError('SIG-YAML-003', line.n, 'Duplicate key “' + k.key + '”'); }
					const p = path + '/' + k.key;
					lines.set(p, line.n);
					i++;
					let v;
					if (k.rest === '' ) {
						skip();
						if (i < L.length && (L[i].indent > ind || (L[i].indent === ind && /^- |^-$/u.test(L[i].body.trim())))) { v = block(L[i].indent, p, depth + 1); } else { v = null; }
					} else if (/^[|>][+-]?$/u.test(k.rest)) { v = blockScalar(k.rest, ind); }
					else { v = scalar(k.rest, line.n, p); }
					Object.defineProperty(obj, k.key, { value: v, enumerable: true, writable: true, configurable: true });
				}
				return obj;
			}
			function seq(ind, path, depth) {
				const arr = [];
				for (;;) {
					skip();
					if (i >= L.length) { break; }
					const line = L[i];
					const t = line.body.trim();
					if (line.indent !== ind || !(t === '-' || t.startsWith('- '))) { if (line.indent > ind) { throw yamlError('SIG-YAML-001', line.n, 'Unexpected indentation in a list'); } break; }
					const p = path + '/' + arr.length;
					lines.set(p, line.n);
					const rest = t === '-' ? '' : t.slice(2).trim();
					if (rest === '') { i++; skip(); arr.push(i < L.length && L[i].indent > ind ? block(L[i].indent, p, depth + 1) : null); continue; }
					if (keyOf(rest) && !/^["']/u.test(rest) || (keyOf(rest) && /^["'][^"']*["']\s*:/u.test(rest))) {
						// "- key: value" starts a mapping whose further keys are indented to the key column
						const col = line.indent + (line.body.length - line.body.trimStart().length - line.indent) + 2;
						L[i] = { n: line.n, raw: line.raw, body: ' '.repeat(col) + rest, indent: col };
						arr.push(map(col, p, depth + 1));
						continue;
					}
					i++;
					arr.push(/^[|>][+-]?$/u.test(rest) ? blockScalar(rest, ind) : scalar(rest, line.n, p));
				}
				return arr;
			}
			function blockScalar(ind0, parentIndent) {
				const keep = ind0.includes('+'), strip = ind0.includes('-'), folded = ind0[0] === '>';
				const parts = [];
				let ind = -1;
				while (i < L.length) {
					const r = L[i].raw;
					if (!r.trim()) { parts.push(''); i++; continue; }
					const n = r.length - r.replace(/^ +/u, '').length;
					if (n <= parentIndent) { break; }
					if (ind < 0) { ind = n; }
					if (n < ind) { break; }
					parts.push(r.slice(ind));
					i++;
				}
				while (!keep && parts.length && parts[parts.length - 1] === '') { parts.pop(); }
				let s = folded ? parts.join('\n').replace(/([^\n])\n(?!\n| )/gu, '$1 ') : parts.join('\n');
				if (!strip) { s += '\n'; }
				return s;
			}
		}
		function unquote(t, n) {
			if (t[0] === '\'') { if (!t.endsWith('\'') || t.length < 2) { throw yamlError('SIG-YAML-001', n, 'Unterminated single-quoted string'); } return t.slice(1, -1).replace(/''/gu, '\''); }
			if (!t.endsWith('"') || t.length < 2) { throw yamlError('SIG-YAML-001', n, 'Unterminated double-quoted string'); }
			const body = t.slice(1, -1);
			let out = '';
			for (let k = 0; k < body.length; k++) {
				const c = body[k];
				if (c !== '\\') { out += c; continue; }
				const e = body[++k];
				const map = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', '/': '/', '0': '\u0000', ' ': ' ' };
				if (e === 'x' || e === 'u' || e === 'U') { const len = e === 'x' ? 2 : e === 'u' ? 4 : 8; const h = body.slice(k + 1, k + 1 + len); if (!new RegExp('^[0-9A-Fa-f]{' + len + '}$', 'u').test(h)) { throw yamlError('SIG-YAML-001', n, 'Invalid escape in a double-quoted string'); } out += String.fromCodePoint(parseInt(h, 16)); k += len; }
				else if (Object.prototype.hasOwnProperty.call(map, e)) { out += map[e]; } else { throw yamlError('SIG-YAML-001', n, 'Invalid escape \\' + e + ' in a double-quoted string'); }
			}
			return out;
		}
		function scalar(t, n, path) {
			if (/^[&*!]/u.test(t)) { throw yamlError('SIG-YAML-002', n, t[0] === '&' ? 'Anchors are not accepted' : t[0] === '*' ? 'Aliases are not accepted (quote values that start with *)' : 'Tags are not accepted'); }
			if (t[0] === '\'' || t[0] === '"') { return unquote(t, n); }
			if (t[0] === '[' || t[0] === '{') { return flow(t, n, path); }
			if (/^(?:null|Null|NULL|~)$/u.test(t)) { return null; }
			if (/^(?:true|True|TRUE)$/u.test(t)) { return true; }
			if (/^(?:false|False|FALSE)$/u.test(t)) { return false; }
			if (/^[-+]?(?:0|[1-9][0-9]*)$/u.test(t) && t.length < 16) { return Number(t); }
			if (/^[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+)$/u.test(t)) { return Number(t); }
			if (/:\s/u.test(t) && !/^https?:/u.test(t)) { throw yamlError('SIG-YAML-001', n, 'Unquoted value contains “: ”; quote it'); }
			return t;
		}
		function flow(t, n, path) {
			let k = 0;
			const ws = () => { while (k < t.length && t[k] === ' ') { k++; } };
			function val(depth) {
				if (depth > MAX_DEPTH) { throw yamlError('SIG-YAML-001', n, 'Flow collection nested too deeply'); }
				ws();
				const c = t[k];
				if (c === '[') { k++; const a = []; ws(); if (t[k] === ']') { k++; return a; } for (;;) { a.push(val(depth + 1)); ws(); if (t[k] === ',') { k++; continue; } if (t[k] === ']') { k++; return a; } throw yamlError('SIG-YAML-001', n, 'Expected , or ] in a flow list'); } }
				if (c === '{') { k++; const o = {}; ws(); if (t[k] === '}') { k++; return o; } for (;;) { ws(); const key = String(atom(true)); ws(); if (t[k] !== ':') { throw yamlError('SIG-YAML-001', n, 'Expected : in a flow mapping'); } k++; if (Object.prototype.hasOwnProperty.call(o, key)) { throw yamlError('SIG-YAML-003', n, 'Duplicate key “' + key + '”'); } o[key] = val(depth + 1); ws(); if (t[k] === ',') { k++; continue; } if (t[k] === '}') { k++; return o; } throw yamlError('SIG-YAML-001', n, 'Expected , or } in a flow mapping'); } }
				return atom(false);
			}
			function atom(isKey) {
				ws();
				const c = t[k];
				if (c === '\'' || c === '"') { let j = k + 1; for (; j < t.length; j++) { if (t[j] === '\\' && c === '"') { j++; continue; } if (t[j] === c) { if (c === '\'' && t[j + 1] === '\'') { j++; continue; } break; } } const s = unquote(t.slice(k, j + 1), n); k = j + 1; return s; }
				let j = k;
				while (j < t.length && !/[,\]}]/u.test(t[j]) && !(isKey && t[j] === ':')) { j++; }
				const s = t.slice(k, j).trim();
				k = j;
				return isKey ? s : scalar(s, n, path);
			}
			const v = val(0);
			ws();
			if (k < t.length) { throw yamlError('SIG-YAML-001', n, 'Unexpected text after a flow collection'); }
			return v;
		}
	}

	// ------------------------------------------------------------------ Sigma
	const MODIFIERS = new Set(['contains', 'startswith', 'endswith', 'all', 'exists', 'cased', 'neq', 'windash', 're', 'i', 'm', 's', 'base64', 'base64offset', 'utf16le', 'utf16be', 'utf16', 'wide', 'lt', 'lte', 'gt', 'gte', 'minute', 'hour', 'day', 'week', 'month', 'year', 'cidr', 'expand', 'fieldref']);
	const LEVELS = ['informational', 'low', 'medium', 'high', 'critical'];
	const STATUSES = ['stable', 'test', 'experimental', 'deprecated', 'unsupported'];
	const TACTICS = ['reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'];
	function tagOk(t) {
		if (typeof t !== 'string' || t !== t.toLowerCase()) { return false; }
		return /^attack\.t[0-9]{4}(?:\.[0-9]{3})?$/u.test(t) || /^attack\.(?:g|s|m|ds|a)[0-9]{4}$/u.test(t) || (t.startsWith('attack.') && TACTICS.includes(t.slice(7))) || /^cve\.[0-9]{4}-[0-9]{4,}$/u.test(t) || /^car\.[0-9]{4}-[0-9]{2}-[0-9]{3}$/u.test(t) || /^tlp\.(?:clear|white|green|amber|amber-strict|red)$/u.test(t) || /^detection\.(?:dfir|emerging-threats|threat-hunting)$/u.test(t);
	}
	function validDate(s) { const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/u.exec(String(s)); if (!m) { return false; } const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])); return d.getUTCFullYear() === +m[1] && d.getUTCMonth() === +m[2] - 1 && d.getUTCDate() === +m[3]; }

	/** Condition string -> AST. Identifiers may contain letters (any script), digits, _ and * (patterns). */
	function parseCondition(src) {
		const s = String(src);
		const toks = [];
		const re = /\s*(?:(\()|(\))|([\p{L}\p{N}_*.-]+)|(\S))/guy;
		let m;
		while (re.lastIndex < s.length && (m = re.exec(s))) {
			if (m[4]) { const e = new Error('Unexpected character “' + m[4] + '”' + (m[4] === '|' ? ' (aggregations are not supported)' : '')); e.code = 'SIG-COND-001'; throw e; }
			if (m[1]) { toks.push('('); } else if (m[2]) { toks.push(')'); } else if (m[3]) { toks.push(m[3]); }
			if (!m[0]) { break; }
		}
		let k = 0;
		const fail = msg => { const e = new Error(msg); e.code = 'SIG-COND-001'; throw e; };
		const peek = () => toks[k], next = () => toks[k++];
		const isKw = t => ['and', 'or', 'not', 'of', '(', ')'].includes(String(t).toLowerCase());
		function expr() { let l = andE(); while (peek() && peek().toLowerCase() === 'or') { next(); l = { type: 'or', items: [l, andE()] }; } return l; }
		function andE() { let l = notE(); while (peek() && peek().toLowerCase() === 'and') { next(); l = { type: 'and', items: [l, notE()] }; } return l; }
		function notE() { if (peek() && peek().toLowerCase() === 'not') { next(); return { type: 'not', item: notE() }; } return atom(); }
		function atom() {
			const t = next();
			if (t === undefined) { fail('The condition ends unexpectedly'); }
			if (t === '(') { const e = expr(); if (next() !== ')') { fail('Missing )'); } return e; }
			if (t === ')' || isKw(t)) { fail('Unexpected “' + t + '”'); }
			if ((/^[0-9]+$/u.test(t) || t.toLowerCase() === 'all' || t.toLowerCase() === 'any') && peek() && peek().toLowerCase() === 'of') {
				next();
				const p = next();
				if (p === undefined || isKw(p)) { fail('“of” must be followed by a name pattern or “them”'); }
				const q = t.toLowerCase() === 'any' ? '1' : t.toLowerCase();
				if (q !== 'all' && +q < 1) { fail('“0 of” is not meaningful'); }
				return { type: 'of', quant: q, pattern: p };
			}
			return { type: 'id', name: t };
		}
		if (!toks.length) { fail('The condition is empty'); }
		const ast = expr();
		if (k < toks.length) { fail('Unexpected “' + toks[k] + '”'); }
		return ast;
	}
	const globMatch = (pattern, name) => { if (pattern === 'them') { return true; } if (!pattern.includes('*')) { return pattern === name; } const parts = pattern.split('*'); let pos = 0; if (!name.startsWith(parts[0])) { return false; } pos = parts[0].length; for (let j = 1; j < parts.length - 1; j++) { const f = name.indexOf(parts[j], pos); if (f < 0) { return false; } pos = f + parts[j].length; } return name.length - pos >= parts[parts.length - 1].length && name.endsWith(parts[parts.length - 1]); };
	function condRefs(ast, out) { if (!ast) { return out; } if (ast.type === 'id') { out.push({ kind: 'id', name: ast.name }); } else if (ast.type === 'of') { out.push({ kind: 'of', name: ast.pattern }); } else if (ast.type === 'not') { condRefs(ast.item, out); } else { for (const x of ast.items) { condRefs(x, out); } } return out; }
	const splitField = k => { const p = String(k).split('|'); return { field: p[0], mods: p.slice(1) }; };

	function validateSigmaDoc(doc, lines, pfx) {
		const out = [];
		const L = p => lines.get(pfx + p) || 0;
		const title = isObj(doc) && typeof doc.title === 'string' ? doc.title : '';
		const add = (id, p, ev) => out.push(finding(id, typeof p === 'number' ? p : L(p || ''), ev, title));
		if (!isObj(doc)) { add('SIG-REQ-003', 0, 'The document is not a mapping'); return out; }
		if (typeof doc.title !== 'string' || !doc.title.trim()) { add('SIG-REQ-001', '/title'); } else if ([...doc.title].length > 256) { add('SIG-TITLE-001', '/title', [...doc.title].length + ' characters'); }
		if (doc.id === undefined || doc.id === null) { add('SIG-Q-004', 1); } else if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(String(doc.id))) { add('SIG-ID-001', '/id', String(doc.id)); }
		for (const k of ['date', 'modified']) { if (doc[k] !== undefined && doc[k] !== null && !validDate(doc[k])) { add('SIG-DATE-001', '/' + k, k + ': ' + doc[k]); } }
		if (validDate(doc.date) && validDate(doc.modified) && String(doc.modified) < String(doc.date)) { add('SIG-DATE-002', '/modified', doc.modified + ' < ' + doc.date); }
		if (doc.level === undefined || doc.level === null) { add('SIG-Q-005', 1); } else if (!LEVELS.includes(doc.level)) { add('SIG-LVL-001', '/level', String(doc.level)); }
		if (doc.status !== undefined && doc.status !== null && !STATUSES.includes(doc.status)) { add('SIG-STS-001', '/status', String(doc.status)); }
		if (!doc.description || !doc.author) { add('SIG-Q-006', 1, [!doc.description ? 'description' : '', !doc.author ? 'author' : ''].filter(Boolean).join(', ')); }
		if (!doc.falsepositives || (Array.isArray(doc.falsepositives) && !doc.falsepositives.length)) { add('SIG-Q-001', 1); }
		if (Array.isArray(doc.tags)) {
			const seen = new Set();
			let dup = false;
			doc.tags.forEach((t, k) => { if (!tagOk(t)) { add('SIG-TAG-001', '/tags/' + k, String(t)); } const low = String(t).toLowerCase(); if (seen.has(low)) { dup = true; } seen.add(low); });
			if (dup) { add('SIG-Q-003', '/tags', 'duplicate tag'); }
		}
		const ls = doc.logsource;
		if (!isObj(ls) || !['category', 'product', 'service'].some(k => typeof ls[k] === 'string' && ls[k].trim())) { add('SIG-REQ-002', '/logsource'); }
		const det = doc.detection;
		if (!isObj(det)) { add('SIG-REQ-003', '/detection'); return out; }
		const ids = Object.keys(det).filter(k => k !== 'condition' && k !== 'timeframe');
		const contents = new Map();
		for (const id of ids) {
			const v = det[id];
			const p = '/detection/' + id;
			const ok = isObj(v) ? Object.keys(v).length > 0 : Array.isArray(v) ? v.length > 0 && (v.every(x => isObj(x) && Object.keys(x).length) || v.every(x => !isObj(x) && !Array.isArray(x))) : false;
			if (!ok) { add('SIG-DET-001', p, id); continue; }
			const key = JSON.stringify(v);
			if (contents.has(key)) { add('SIG-Q-003', p, id + ' repeats ' + contents.get(key)); } else { contents.set(key, id); }
			const maps = isObj(v) ? [v] : v.filter(isObj);
			const keywords = Array.isArray(v) && !v.some(isObj) ? v : [];
			for (const mp of maps) {
				for (const [fk, fv] of Object.entries(mp)) {
					const { field, mods } = splitField(fk);
					const unknown = mods.filter(x => !MODIFIERS.has(x));
					if (unknown.length) { add('SIG-MOD-001', p + '/' + fk, fk); }
					const pos = mods.filter(x => ['contains', 'startswith', 'endswith'].includes(x));
					const conflict = pos.length > 1 || (mods.includes('re') && mods.some(x => !['re', 'i', 'm', 's'].includes(x))) || (mods.some(x => ['i', 'm', 's'].includes(x)) && !mods.includes('re')) || (mods.includes('cidr') && mods.length > 1) || (mods.includes('exists') && mods.length > 1) || (mods.includes('base64offset') && !mods.includes('contains'));
					if (conflict) { add('SIG-MOD-002', p + '/' + fk, fk); }
					if (Array.isArray(fv) && (!fv.length || fv.some(x => x === null))) { add('SIG-DET-001', p + '/' + fk, fk + ': ' + (fv.length ? 'null inside a value list' : 'empty value list')); }
					const vals = Array.isArray(fv) ? fv : [fv];
					if (Array.isArray(fv)) { const s2 = new Set(); for (const x of fv) { const k2 = String(x).toLowerCase(); if (s2.has(k2)) { add('SIG-Q-003', p + '/' + fk, String(x)); break; } s2.add(k2); } }
					for (const x of vals) {
						if (typeof x !== 'string') { continue; }
						const core = x.replace(/[*?]/gu, '');
						if (!core.length && !mods.includes('re') || (pos.length && [...core].length < 3)) { add('SIG-Q-002', p + '/' + fk, field + ': ' + x); break; }
					}
					void field;
				}
			}
			if (keywords.length) { const s2 = new Set(); for (const x of keywords) { const k2 = String(x).toLowerCase(); if (s2.has(k2)) { add('SIG-Q-003', p, String(x)); break; } s2.add(k2); } }
		}
		if (det.condition === undefined || det.condition === null || det.condition === '') { add('SIG-REQ-004', '/detection'); return dedupe(out); }
		const conds = Array.isArray(det.condition) ? det.condition : [det.condition];
		const used = new Set();
		conds.forEach((c, k) => {
			const p = Array.isArray(det.condition) ? '/detection/condition/' + k : '/detection/condition';
			let ast;
			try { ast = parseCondition(c); } catch (e) { add('SIG-COND-001', p, String(c) + ' — ' + e.message); return; }
			for (const r of condRefs(ast, [])) {
				const hits = r.kind === 'id' ? ids.filter(x => x === r.name) : ids.filter(x => globMatch(r.name, x));
				if (!hits.length) { add('SIG-COND-002', p, r.name); }
				for (const h of hits) { used.add(h); }
			}
		});
		if (!out.some(f => f.id === 'SIG-COND-001')) { for (const id of ids) { if (!used.has(id) && isObj(det[id]) || (!used.has(id) && Array.isArray(det[id]))) { add('SIG-COND-003', '/detection/' + id, id); } } }
		return dedupe(out);
	}
	function dedupe(list) { const seen = new Set(); return list.filter(f => { const k = f.id + '|' + f.line + '|' + f.evidence; if (seen.has(k)) { return false; } seen.add(k); return true; }); }

	// ------------------------------------------------------------------ Sigma -> SPL / KQL / Lucene
	const TARGETS = { spl: 'Splunk SPL', kql: 'Microsoft KQL', lucene: 'Elastic Lucene' };
	const UNSUPPORTED_MODS = { spl: ['re', 'cidr'], kql: [], lucene: [] };
	const NEVER = ['windash', 'base64', 'base64offset', 'utf16le', 'utf16be', 'utf16', 'wide', 'expand', 'fieldref', 'cased', 'neq', 'lt', 'lte', 'gt', 'gte', 'minute', 'hour', 'day', 'week', 'month', 'year', 'i', 'm', 's'];
	const convError = (msg, diag) => { const e = new Error(diag ? diag + ': ' + msg : msg); e.code = 'UNSUPPORTED'; e.diag = diag || 'CONV-UNSUPPORTED'; return e; };
	/** Sigma value -> [{lit}|{wild:'*'|'?'}] (backslash escapes * ? and \). */
	function pattern(v) {
		const s = nfc(v);
		const parts = [];
		let lit = '';
		for (let k = 0; k < s.length; k++) {
			const c = s[k];
			if (c === '\\' && (s[k + 1] === '*' || s[k + 1] === '?' || s[k + 1] === '\\')) { lit += s[++k]; continue; }
			if (c === '*' || c === '?') { if (lit) { parts.push({ lit }); lit = ''; } parts.push({ wild: c }); continue; }
			lit += c;
		}
		if (lit) { parts.push({ lit }); }
		return parts;
	}
	function buildTree(doc, condSrc) {
		const det = doc.detection;
		const ids = Object.keys(det).filter(k => k !== 'condition' && k !== 'timeframe');
		const sel = id => {
			const v = det[id];
			// Refuse what Sigma forbids or what would turn into an empty or wrong query (Codex acceptance C15, C16, C18, C22).
			if (!Object.prototype.hasOwnProperty.call(det, id) || id === 'condition' || id === 'timeframe') { throw convError('the condition refers to “' + id + '”, which is not a search identifier in detection.', 'SIG-COND-002'); }
			if (Array.isArray(v) && !v.length) { throw convError('the search identifier “' + id + '” is an empty list.', 'SIG-DET-001'); }
			if (Array.isArray(v) && !v.some(isObj)) { if (v.some(x => x === null)) { throw convError('the keyword list “' + id + '” contains null, which Sigma does not allow in lists.', 'SIG-DET-001'); } return { type: 'or', items: v.map(x => ({ type: 'kw', value: x })) }; }
			if (!(isObj(v) && Object.keys(v).length) && !(Array.isArray(v) && v.every(x => isObj(x) && Object.keys(x).length))) { throw convError('the search identifier “' + id + '” is empty or malformed.', 'SIG-DET-001'); }
			const maps = isObj(v) ? [v] : v;
			const one = mp => ({ type: 'and', items: Object.entries(mp).map(([fk, fv]) => {
				const { field, mods } = splitField(fk);
				for (const m of mods) { if (!MODIFIERS.has(m)) { throw convError('the value modifier “' + m + '” is unknown; the field is not converted with a different meaning.', 'SIG-MOD-001'); } }
				if (Array.isArray(fv) && !fv.length) { throw convError('the field “' + (field || '(keywords)') + '” has an empty value list.', 'SIG-DET-001'); }
				if (Array.isArray(fv) && fv.some(x => x === null)) { throw convError('the value list of “' + (field || '(keywords)') + '” contains null, which Sigma does not allow in lists. Use “' + field + ': null” on its own.', 'SIG-DET-001'); }
				if (field === '') { const vals = Array.isArray(fv) ? fv : [fv]; return { type: mods.includes('all') ? 'and' : 'or', items: vals.map(x => ({ type: 'kw', value: x })) }; }
				for (const m of mods) { if (NEVER.includes(m)) { throw convError('The modifier “' + m + '” is not supported by the converter.'); } }
				if (mods.includes('exists')) { return fv === false ? { type: 'notexists', field } : { type: 'exists', field }; }
				if (fv === null) { return { type: 'notexists', field }; }
				const vals = Array.isArray(fv) ? fv : [fv];
				const items = vals.map(x => x === null ? { type: 'notexists', field } : { type: 'cmp', field, value: x, mods });
				return items.length === 1 ? items[0] : { type: mods.includes('all') ? 'and' : 'or', items };
			}) });
			return maps.length === 1 ? one(maps[0]) : { type: 'or', items: maps.map(one) };
		};
		function walk(ast) {
			if (ast.type === 'id') { return sel(ast.name); }
			if (ast.type === 'not') { return { type: 'not', item: walk(ast.item) }; }
			if (ast.type === 'of') {
				const hits = ids.filter(x => globMatch(ast.pattern, x));
				if (!hits.length) { throw convError('“' + ast.pattern + '” matches no search identifier in detection.', 'SIG-COND-002'); }
				if (ast.quant !== 'all' && ast.quant !== '1') { throw convError('“' + ast.quant + ' of” is not supported by the converter; only “1 of” and “all of”.'); }
				return { type: ast.quant === 'all' ? 'and' : 'or', items: hits.map(sel) };
			}
			return { type: ast.type, items: ast.items.map(walk) };
		}
		return flatten(walk(parseCondition(condSrc)));
	}
	function flatten(n) {
		if (n.type === 'and' || n.type === 'or') {
			const items = [];
			for (const c of n.items.map(flatten)) { if (c.type === n.type) { items.push(...c.items); } else { items.push(c); } }
			return items.length === 1 ? items[0] : { type: n.type, items };
		}
		if (n.type === 'not') { return { type: 'not', item: flatten(n.item) }; }
		return n;
	}
	const reEsc = s => s.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
	function kqlStr(s) { return s.includes('\\') ? '@"' + s.replace(/"/gu, '""') + '"' : '"' + s.replace(/"/gu, '\\"') + '"'; }
	function kqlField(f) { return /^[A-Za-z_][A-Za-z0-9_]*$/u.test(f) ? f : '[\'' + f.replace(/'/gu, '\\\'') + '\']'; }
	const LUCENE_SPECIAL = /[+\-=&|><!(){}[\]^"~:\\/ \t]/gu;
	function render(node, target, fmap, parent) {
		const F = f => (fmap && Object.prototype.hasOwnProperty.call(fmap, f) ? String(fmap[f]) : f);
		if (node.type === 'and' || node.type === 'or') {
			const op = target === 'kql' ? ' ' + node.type + ' ' : ' ' + node.type.toUpperCase() + ' ';
			const s = node.items.map(c => render(c, target, fmap, node)).join(op);
			const wrap = parent && (parent.type === 'not' ? target !== 'kql' : parent.type !== node.type);
			return wrap ? '(' + s + ')' : s;
		}
		if (node.type === 'not') { return target === 'kql' ? 'not(' + render(node.item, target, fmap, null) + ')' : 'NOT ' + render(node.item, target, fmap, node); }
		if (node.type === 'exists') { const f = F(node.field); return target === 'spl' ? f + '="*"' : target === 'kql' ? 'isnotempty(' + kqlField(f) + ')' : '_exists_:' + f; }
		if (node.type === 'notexists') { const f = F(node.field); return target === 'spl' ? 'NOT ' + f + '="*"' : target === 'kql' ? 'isempty(' + kqlField(f) + ')' : 'NOT _exists_:' + f; }
		if (node.type === 'kw') {
			const v = nfc(node.value);
			if (/[*?]/u.test(v) && target !== 'lucene') { throw convError('Keywords with wildcards are not supported for ' + TARGETS[target] + '.'); }
			if (target === 'kql') { return '* contains ' + kqlStr(v); }
			return '"' + v.replace(/\\/gu, '\\\\').replace(/"/gu, '\\"') + '"';
		}
		// cmp
		const f = F(node.field);
		const mods = node.mods;
		for (const m of mods) { if ((UNSUPPORTED_MODS[target] || []).includes(m)) { throw convError('The modifier “' + m + '” is not supported for ' + TARGETS[target] + '.'); } }
		if (typeof node.value === 'number' || typeof node.value === 'boolean') {
			if (mods.some(m => ['contains', 'startswith', 'endswith', 're', 'cidr'].includes(m))) { throw convError('Modifiers on number or boolean values are not supported.'); }
			return target === 'spl' ? f + '=' + node.value : target === 'kql' ? kqlField(f) + ' == ' + node.value : f + ':' + node.value;
		}
		if (typeof node.value !== 'string') { throw convError('Only strings, numbers, booleans and null are supported as values.'); }
		const raw = nfc(node.value);
		if (mods.includes('re')) { return target === 'kql' ? kqlField(f) + ' matches regex ' + kqlStr(raw) : f + ':/' + raw.replace(/\//gu, '\\/') + '/'; }
		if (mods.includes('cidr')) { return target === 'kql' ? (raw.includes(':') ? 'ipv6_is_in_range(' : 'ipv4_is_in_range(') + kqlField(f) + ', ' + kqlStr(raw) + ')' : f + ':"' + raw + '"'; }
		let parts = pattern(raw);
		if (mods.includes('contains')) { parts = [{ wild: '*' }].concat(parts, [{ wild: '*' }]); }
		else if (mods.includes('startswith')) { parts = parts.concat([{ wild: '*' }]); }
		else if (mods.includes('endswith')) { parts = [{ wild: '*' }].concat(parts); }
		if (target === 'spl') {
			if (parts.some(p => p.wild === '?')) { throw convError('The ? wildcard is not supported for Splunk SPL.'); }
			if (parts.some(p => p.lit && p.lit.includes('*'))) { throw convError('The value contains a literal * (written \\* in Sigma). Splunk SPL search cannot match a literal asterisk: in a search term * is always a wildcard, so the query would match more than the rule. Not converted for Splunk SPL; KQL and Lucene keep it literal.', 'CONV-SPL-STAR'); }
			return f + '="' + parts.map(p => (p.wild ? '*' : p.lit.replace(/\\/gu, '\\\\').replace(/"/gu, '\\"'))).join('') + '"';
		}
		if (target === 'lucene') {
			if (!parts.length) { return f + ':""'; }
			return f + ':' + parts.map(p => (p.wild ? p.wild : p.lit.replace(LUCENE_SPECIAL, '\\$&').replace(/[*?]/gu, '\\$&'))).join('');
		}
		const lits = parts.filter(p => p.lit).map(p => p.lit);
		const shape = parts.map(p => (p.wild ? p.wild : 'L')).join('');
		const K = kqlField(f);
		if (shape === 'L') { return K + ' =~ ' + kqlStr(lits[0]); }
		if (shape === '*L*') { return K + ' contains ' + kqlStr(lits[0]); }
		if (shape === 'L*') { return K + ' startswith ' + kqlStr(lits[0]); }
		if (shape === '*L') { return K + ' endswith ' + kqlStr(lits[0]); }
		if (shape === '*' || shape === '**') { return 'isnotempty(' + K + ')'; }
		return K + ' matches regex ' + kqlStr('(?i)^' + parts.map(p => (p.wild === '*' ? '.*' : p.wild === '?' ? '.' : reEsc(p.lit))).join('') + '$');
	}
	/** Conversion refused because the check found error-level problems (owner decision 2026-11-21): no query is produced. */
	function refuseConversion(result, target) {
		if (!TARGETS[target]) { throw convError('Unknown target ' + target); }
		const errs = (result.findings || []).filter(f => f.severity === 'error');
		const codes = [...new Set(errs.map(f => f.id))];
		const where = errs.slice(0, 5).map(f => f.id + (f.line ? ' (line ' + f.line + ')' : '')).join(', ');
		const error = 'The check found ' + errs.length + ' error' + (errs.length === 1 ? '' : 's') + ' (' + where + (errs.length > 5 ? ', …' : '') + '). Fix them first; a rule with errors would give a wrong or empty query.';
		const r = { title: '(rule with errors)', queries: [], error, code: codes.join(' ') };
		return { target, targetLabel: TARGETS[target], rules: [r], refused: codes, containsSecrets: false, masked: [{ title: r.title, queries: [], error, code: r.code }] };
	}
	/** Converts one Sigma rule (YAML text) to the target. Returns { queries: [], errors: [] }. */
	function convert(text, target, fieldmap) {
		if (!TARGETS[target]) { throw convError('Unknown target ' + target); }
		const tick = budget();
		const y = parseYaml(text, tick);
		const out = { target, targetLabel: TARGETS[target], rules: [] };
		y.docs.forEach(doc => {
			const r = { title: isObj(doc) && typeof doc.title === 'string' ? nfc(doc.title) : '(untitled)', queries: [], error: '' };
			try {
				if (!isObj(doc) || !isObj(doc.detection) || doc.detection.condition === undefined) { throw convError('The rule has no detection condition.'); }
				const conds = Array.isArray(doc.detection.condition) ? doc.detection.condition : [doc.detection.condition];
				for (const c of conds) { r.queries.push(render(buildTree(doc, String(c)), target, fieldmap || {}, null)); }
			} catch (e) { r.error = e.code === 'UNSUPPORTED' ? e.message : (e.message || 'The rule cannot be converted.'); r.code = e.diag || 'CONV-ERROR'; r.queries = []; }
			out.rules.push(r);
		});
		out.containsSecrets = out.rules.some(r => r.queries.some(q => findSecrets(q).length) || findSecrets(r.title).length);
		// Everything shown or exported by default is masked: titles, queries and messages all come from the user's rule.
		out.masked = out.rules.map(r => ({ title: maskSecrets(r.title), queries: r.queries.map(maskSecrets), error: maskSecrets(r.error), code: r.code || '' }));
		return out;
	}

	// ------------------------------------------------------------------ YARA (static)
	const YARA_KEYWORDS = new Set(['all', 'and', 'any', 'ascii', 'at', 'base64', 'base64wide', 'condition', 'contains', 'endswith', 'entrypoint', 'false', 'filesize', 'for', 'fullword', 'global', 'import', 'icontains', 'iendswith', 'iequals', 'in', 'include', 'int16', 'int16be', 'int32', 'int32be', 'int8', 'int8be', 'istartswith', 'matches', 'meta', 'nocase', 'none', 'not', 'of', 'or', 'private', 'rule', 'startswith', 'strings', 'them', 'true', 'uint16', 'uint16be', 'uint32', 'uint32be', 'uint8', 'uint8be', 'wide', 'xor', 'defined']);
	const MODULES = new Set(['pe', 'elf', 'math', 'hash', 'dotnet', 'cuckoo', 'magic', 'time', 'console', 'string', 'macho', 'dex', 'lnk', 'tests']);
	const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/u;
	function yaraTokens(src) {
		const s = String(src);
		const toks = [];
		let line = 1;
		let k = 0;
		const err = (msg, code) => { const e = new Error(msg + ' (line ' + line + ')'); e.code = code || 'YAR-SYN-001'; e.line = line; throw e; };
		while (k < s.length) {
			const c = s[k];
			if (c === '\n') { line++; k++; continue; }
			if (/\s/u.test(c)) { k++; continue; }
			if (c === '/' && s[k + 1] === '/') { while (k < s.length && s[k] !== '\n') { k++; } continue; }
			if (c === '/' && s[k + 1] === '*') { const end = s.indexOf('*/', k + 2); if (end < 0) { err('Unterminated comment'); } for (let j = k; j < end; j++) { if (s[j] === '\n') { line++; } } k = end + 2; continue; }
			if (c === '"') {
				let j = k + 1, v = '';
				for (; j < s.length; j++) {
					if (s[j] === '\n') { err('Unterminated string'); }
					if (s[j] === '\\') { const e = s[j + 1]; if (e === 'x') { if (!/^[0-9A-Fa-f]{2}$/u.test(s.slice(j + 2, j + 4))) { err('Invalid \\x escape in a string'); } v += String.fromCharCode(parseInt(s.slice(j + 2, j + 4), 16)); j += 3; continue; } if (!'"\\tnr'.includes(e)) { err('Invalid escape \\' + e + ' in a string'); } v += { '"': '"', '\\': '\\', t: '\t', n: '\n', r: '\r' }[e]; j++; continue; }
					if (s[j] === '"') { break; }
					v += s[j];
				}
				if (j >= s.length) { err('Unterminated string'); }
				toks.push({ t: 'str', v, line, raw: s.slice(k, j + 1) });
				k = j + 1;
				continue;
			}
			const prev = toks[toks.length - 1];
			if (c === '/' && prev && (prev.v === '=' || prev.v === 'matches')) {
				let j = k + 1, inClass = false;
				for (; j < s.length; j++) { if (s[j] === '\n') { err('Unterminated regular expression', 'YAR-RE-001'); } if (s[j] === '\\') { j++; continue; } if (s[j] === '[') { inClass = true; } else if (s[j] === ']') { inClass = false; } else if (s[j] === '/' && !inClass) { break; } }
				if (j >= s.length) { err('Unterminated regular expression', 'YAR-RE-001'); }
				const body = s.slice(k + 1, j);
				let fl = '';
				let m = j + 1;
				while (m < s.length && /[is]/u.test(s[m])) { fl += s[m]; m++; }
				toks.push({ t: 're', v: body, flags: fl, line });
				k = m;
				continue;
			}
			if (c === '{' && prev && prev.v === '=') {
				const end = s.indexOf('}', k);
				if (end < 0) { err('Unterminated hex string'); }
				const body = s.slice(k + 1, end);
				toks.push({ t: 'hex', v: body.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//gu, ' '), line });
				for (const ch of body) { if (ch === '\n') { line++; } }
				k = end + 1;
				continue;
			}
			let m;
			const rest = s.slice(k, k + 300);
			if ((m = /^[$#@!][A-Za-z0-9_]*\*?/u.exec(rest))) { toks.push({ t: 'sid', v: m[0], line }); k += m[0].length; continue; }
			if ((m = /^(?:0x[0-9A-Fa-f]+|0o[0-7]+|[0-9]+(?:\.[0-9]+)?(?:KB|MB)?)/u.exec(rest))) { toks.push({ t: 'num', v: m[0], line }); k += m[0].length; continue; }
			if ((m = /^[A-Za-z_][A-Za-z0-9_]*/u.exec(rest))) { toks.push({ t: 'id', v: m[0], line }); k += m[0].length; continue; }
			if ((m = /^(?:==|!=|<=|>=|<<|>>|\.\.|[{}()[\]:=,.<>+\-*\\%&|^~])/u.exec(rest))) { toks.push({ t: 'op', v: m[0], line }); k += m[0].length; continue; }
			if (/[^\x00-\x7f]/u.test(c)) { err('Unexpected character “' + c + '” outside a string'); }
			err('Unexpected character “' + c + '”');
		}
		return toks;
	}
	function checkHex(body) {
		const s = body.replace(/\s+/gu, ' ').trim();
		if (!s) { return { ok: false, msg: 'empty hex string' }; }
		let depth = 0, bytes = 0, minBytes = 0, lastJump = true, items = 0;
		const toks = s.match(/~?[0-9A-Fa-f?]{2}|\[[^\]]*\]|[()|]|\S+/gu) || [];
		for (const t of toks) {
			if (t === '(') { depth++; lastJump = true; continue; }
			if (t === ')') { if (--depth < 0) { return { ok: false, msg: 'unbalanced )' }; } continue; }
			if (t === '|') { if (!depth) { return { ok: false, msg: '| outside parentheses' }; } continue; }
			if (t[0] === '[') {
				const m = /^\[\s*([0-9]*)\s*(?:(-)\s*([0-9]*))?\s*\]$/u.exec(t);
				if (!m || (!m[2] && m[1] === '')) { return { ok: false, msg: 'invalid jump ' + t }; }
				if (m[2] && m[1] !== '' && m[3] !== '' && +m[1] > +m[3]) { return { ok: false, msg: 'jump ' + t + ' has a lower bound above the upper bound' }; }
				if (lastJump && items === 0) { return { ok: false, msg: 'a hex string cannot start with a jump' }; }
				lastJump = true;
				continue;
			}
			if (/^~?[0-9A-Fa-f?]{2}$/u.test(t)) { items++; bytes++; if (!depth) { minBytes++; } lastJump = false; if (t[0] === '~' && t.includes('??')) { return { ok: false, msg: '~?? is not allowed' }; } continue; }
			return { ok: false, msg: 'invalid token “' + t + '”' };
		}
		if (depth) { return { ok: false, msg: 'unbalanced (' }; }
		if (!bytes) { return { ok: false, msg: 'no bytes' }; }
		if (lastJump) { return { ok: false, msg: 'a hex string cannot end with a jump' }; }
		return { ok: true, bytes: minBytes || bytes };
	}
	/** Static checks of a YARA regular expression body; never compiled or executed. */
	function checkRegex(body) {
		if (!body.length) { return { ok: false, msg: 'empty regular expression' }; }
		let depth = 0, inClass = false, prevAtom = false;
		const groupHasQuant = [false];
		let nested = false;
		for (let k = 0; k < body.length; k++) {
			const c = body[k];
			if (c === '\\') { if (k + 1 >= body.length) { return { ok: false, msg: 'trailing backslash' }; } k++; prevAtom = true; continue; }
			if (inClass) { if (c === ']') { inClass = false; prevAtom = true; } continue; }
			if (c === '[') { inClass = true; if (body[k + 1] === ']') { k++; } continue; }
			if (c === '(') { depth++; groupHasQuant.push(false); prevAtom = false; continue; }
			if (c === ')') { if (--depth < 0) { return { ok: false, msg: 'unbalanced )' }; } const inner = groupHasQuant.pop(); const q = body[k + 1]; if (inner && (q === '*' || q === '+' || q === '{')) { nested = true; } prevAtom = true; continue; }
			if (c === '*' || c === '+' || c === '?') { if (!prevAtom && !(c === '?' && /[*+?}]/u.test(body[k - 1] || ''))) { return { ok: false, msg: 'quantifier “' + c + '” without anything to repeat' }; } if (c !== '?') { groupHasQuant[groupHasQuant.length - 1] = true; } prevAtom = c !== '?' ? false : prevAtom; continue; }
			if (c === '{') { const m = /^\{([0-9]*)(?:,([0-9]*))?\}/u.exec(body.slice(k)); if (m) { if (!prevAtom) { return { ok: false, msg: 'quantifier without anything to repeat' }; } if (m[1] !== '' && m[2] && +m[1] > +m[2]) { return { ok: false, msg: 'quantifier {n,m} with n > m' }; } groupHasQuant[groupHasQuant.length - 1] = true; k += m[0].length - 1; prevAtom = false; continue; } }
			if (c === '|') { prevAtom = false; continue; }
			prevAtom = true;
		}
		if (inClass) { return { ok: false, msg: 'unterminated [' }; }
		if (depth) { return { ok: false, msg: 'unbalanced (' }; }
		const slow = /^\.[*+]/u.test(body) || /(?:^|[^\\])\.[*+](?!\?)/u.test(body) || nested;
		return { ok: true, slow, nested };
	}
	const utf8Len = s => { let n = 0; for (const ch of String(s)) { const c = ch.codePointAt(0); n += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4; } return n; };
	function validateYara(text, tick) {
		const out = [];
		let toks;
		try { toks = yaraTokens(text); } catch (e) { return [finding(e.code === 'YAR-RE-001' ? 'YAR-RE-001' : 'YAR-SYN-001', e.line, e.message)]; }
		let k = 0;
		const imports = new Map();
		const names = new Map();
		const peek = () => toks[k], next = () => toks[k++];
		const add = (id, line, ev, rule) => out.push(finding(id, line, ev, rule));
		const syn = (msg, line) => { const e = new Error(msg); e.code = 'YAR-SYN-001'; e.line = line; throw e; };
		try {
			while (k < toks.length) {
				if (tick) { tick(); }
				const t = next();
				if (t.t === 'id' && (t.v === 'import' || t.v === 'include')) { const s = next(); if (!s || s.t !== 'str') { syn('“' + t.v + '” must be followed by a quoted name', t.line); } if (t.v === 'import') { imports.set(s.v, s.line); } continue; }
				if (t.t === 'id' && (t.v === 'private' || t.v === 'global')) { continue; }
				if (!(t.t === 'id' && t.v === 'rule')) { syn('Expected “rule”, “import” or “include”, found “' + (t.v || t.t) + '”', t.line); }
				const nm = next();
				if (!nm || (nm.t !== 'id' && nm.t !== 'num')) { syn('Rule name missing', t.line); }
				let name = nm.v;
				if (nm.t === 'num' && peek() && peek().t === 'id' && peek().line === nm.line) { name = nm.v + next().v; }
				if (!NAME_RE.test(name) || YARA_KEYWORDS.has(name)) { add('YAR-NAME-001', nm.line, name, name); }
				if (names.has(name)) { add('YAR-NAME-002', nm.line, name + ' (first on line ' + names.get(name) + ')', name); } else { names.set(name, nm.line); }
				if (peek() && peek().v === ':') { next(); while (peek() && peek().t === 'id' && peek().v !== '{') { const tg = next(); if (!NAME_RE.test(tg.v) || YARA_KEYWORDS.has(tg.v)) { add('YAR-NAME-001', tg.line, 'tag ' + tg.v, name); } } }
				const open = next();
				if (!open || open.v !== '{') { syn('Expected { after the rule name', nm.line); }
				const strings = new Map();
				let condToks = null, condLine = 0, section = '';
				let depth = 1;
				while (k < toks.length && depth > 0) {
					const x = peek();
					if (x.v === '}' && depth === 1 && section !== 'condition') { next(); depth = 0; break; }
					if (x.t === 'id' && ['meta', 'strings', 'condition'].includes(x.v) && toks[k + 1] && toks[k + 1].v === ':') { section = x.v; next(); next(); if (section === 'condition') { condToks = []; condLine = x.line; } continue; }
					if (section === 'meta') {
						const key = next();
						if (key.t !== 'id' || !peek() || peek().v !== '=') { syn('Expected “name = value” in meta', key.line); }
						next();
						let v = next();
						if (v && v.v === '-' && peek() && peek().t === 'num') { v = next(); }
						if (!v || !(v.t === 'str' || (v.t === 'num' && /^(?:0x[0-9A-Fa-f]+|0o[0-7]+|[0-9]+)$/u.test(v.v)) || (v.t === 'id' && (v.v === 'true' || v.v === 'false')))) { add('YAR-META-001', key.line, key.v + ' = ' + (v ? v.v : ''), name); }
						continue;
					}
					if (section === 'strings') {
						const id = next();
						if (id.t !== 'sid' || id.v[0] !== '$') { syn('Expected a string identifier such as $a', id.line); }
						if (!peek() || peek().v !== '=') { syn('Expected = after ' + id.v, id.line); }
						next();
						const val = next();
						if (!val || !['str', 'hex', 're'].includes(val.t)) { syn('Expected a text string, hex string or regular expression after ' + id.v + ' =', id.line); }
						if (id.v !== '$' && strings.has(id.v)) { add('YAR-STR-001', id.line, id.v, name); }
						strings.set(id.v, { line: id.line, type: val.t });
						const mods = [];
						while (peek() && peek().t === 'id' && peek().line === val.line && !['meta', 'strings', 'condition'].includes(peek().v)) {
							const md = next();
							mods.push(md.v);
							if (peek() && peek().v === '(') { let d = 0; do { const z = next(); if (z.v === '(') { d++; } else if (z.v === ')') { d--; } } while (d > 0 && k < toks.length); }
						}
						const allowed = val.t === 'str' ? ['nocase', 'wide', 'ascii', 'xor', 'base64', 'base64wide', 'fullword', 'private'] : val.t === 're' ? ['nocase', 'wide', 'ascii', 'fullword', 'private'] : ['private'];
						if (mods.some(md => !allowed.includes(md))) { add('YAR-MOD-001', id.line, id.v + ' ' + mods.join(' '), name); }
						if (val.t === 'hex') { const h = checkHex(val.v); if (!h.ok) { add('YAR-HEX-001', val.line, id.v + ': ' + h.msg, name); } else if (h.bytes < 4) { add('YAR-Q-001', val.line, id.v + ' (' + h.bytes + ' bytes)', name); } }
						if (val.t === 're') { const r = checkRegex(val.v); if (!r.ok) { add('YAR-RE-001', val.line, id.v + ': ' + r.msg, name); } else if (r.slow) { add('YAR-Q-002', val.line, id.v + ' /' + val.v.slice(0, 60) + '/', name); } }
						if (val.t === 'str' && utf8Len(val.v) < 4) { add('YAR-Q-001', val.line, id.v + ' (' + utf8Len(val.v) + ' bytes)', name); }
						continue;
					}
					if (section === 'condition') {
						const z = next();
						if (z.v === '{') { depth++; } else if (z.v === '}') { depth--; if (depth === 0) { break; } }
						condToks.push(z);
						continue;
					}
					syn('Unexpected “' + (x.v || x.t) + '” in rule ' + name + '; expected meta:, strings: or condition:', x.line);
				}
				if (depth !== 0) { syn('Missing } at the end of rule ' + name, nm.line); }
				if (condToks === null) { add('YAR-COND-001', nm.line, name, name); continue; }
				if (!condToks.length) { syn('Empty condition in rule ' + name, condLine); }
				let par = 0;
				for (const z of condToks) { if (z.v === '(') { par++; } else if (z.v === ')') { if (--par < 0) { syn('Unbalanced ) in the condition of ' + name, z.line); } } }
				if (par !== 0) { syn('Unbalanced ( in the condition of ' + name, condLine); }
				const last = condToks[condToks.length - 1];
				if (last.t === 'id' && ['and', 'or', 'not', 'of', 'at', 'in'].includes(last.v) || (last.t === 'op' && /^(?:==|!=|<=|>=|<|>|\+|-|\*|\\|%|&|\||\^|~|<<|>>|\.|,)$/u.test(last.v))) { syn('The condition of ' + name + ' ends with “' + last.v + '”', last.line); }
				const declared = [...strings.keys()].filter(x => x !== '$');
				const used = new Set();
				let them = false, filesize = false;
				condToks.forEach((z, zi) => {
					if (z.t === 'sid') {
						const base = '$' + z.v.slice(1).replace(/\*$/u, '');
						if (z.v === '$' || z.v === '#' || z.v === '@' || z.v === '!') { return; }
						if (z.v.endsWith('*')) { const hits = declared.filter(d => d.startsWith(base)); if (!hits.length) { add('YAR-STR-002', z.line, z.v, name); } hits.forEach(h => used.add(h)); return; }
						if (!strings.has(base)) { add('YAR-STR-002', z.line, z.v, name); } else { used.add(base); }
					}
					if (z.t === 'id' && z.v === 'them') { them = true; }
					if (z.t === 'id' && z.v === 'filesize') { filesize = true; }
					if (z.t === 'id' && MODULES.has(z.v) && condToks[zi + 1] && condToks[zi + 1].v === '.') { if (!imports.has(z.v)) { add('YAR-IMP-001', z.line, z.v + '.' + (condToks[zi + 2] ? condToks[zi + 2].v : ''), name); } imports.set(z.v + ':used', 1); }
				});
				if (!them) { for (const d of declared) { if (!used.has(d)) { add('YAR-STR-003', strings.get(d).line, d, name); } } }
				if (!filesize) { add('YAR-Q-003', condLine, name, name); }
			}
		} catch (e) {
			if (e.code !== 'YAR-SYN-001') { throw e; }
			return [finding('YAR-SYN-001', e.line, e.message)];
		}
		for (const [m, line] of imports) { if (!m.includes(':') && !imports.has(m + ':used')) { out.push(finding('YAR-IMP-002', line, m)); } }
		return dedupe(out);
	}

	// ------------------------------------------------------------------ entry points
	function detectKind(text) {
		const s = String(text || '');
		if (/^\s*(?:(?:private|global)\s+)*rule\s+[A-Za-z0-9_]+/mu.test(s) || /^\s*import\s+"/mu.test(s)) { return 'yara'; }
		return 'sigma';
	}
	/** validate(text, { kind: 'auto'|'sigma'|'yara' }) -> { kind, findings, counts, rules } */
	function validate(text, opts) {
		const o = opts || {};
		const s = String(text || '');
		if (s.length > MAX_INPUT_CHARS) { const e = new Error('The input is larger than 1 MB.'); e.code = 'TOO_LARGE'; throw e; }
		if (!s.trim()) { const e = new Error('The input is empty.'); e.code = 'EMPTY'; throw e; }
		const tick = budget();
		const kind = o.kind === 'sigma' || o.kind === 'yara' ? o.kind : detectKind(s);
		let findings = [], rules = 0, notes = [];
		if (kind === 'yara') {
			findings = validateYara(s, tick);
			rules = (s.match(/(?:^|\s)rule\s+[A-Za-z0-9_]+/gu) || []).length;
		} else {
			let y;
			try { y = parseYaml(s, tick); } catch (e) { if (!/^SIG-YAML/u.test(e.code || '')) { throw e; } findings = [finding(e.code, e.line, e.message)]; y = null; }
			if (y) {
				rules = y.docs.length;
				y.docs.forEach((d, di) => { if (isObj(d) && d.action !== undefined) { notes.push('Document ' + (di + 1) + ' uses “action” (rule collections); collections are not supported, each document is checked on its own.'); } findings.push(...validateSigmaDoc(d, y.lines, di ? '/doc' + di : '')); });
			}
		}
		for (const x of findSecrets(s)) { findings.push(finding('SEC-001', s.slice(0, x.start).split('\n').length, x.kind + ': ' + x.shown)); }
		findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.line - b.line || (a.id < b.id ? -1 : 1));
		const counts = { error: 0, warning: 0, info: 0 };
		for (const f of findings) { counts[f.severity]++; }
		return { engine: ENGINE, ruleset: RULESET, kind, rules, findings, counts, notes };
	}
	const mdEsc = s => String(s).replace(/([\\`*_{}\[\]<>()#+!|~])/gu, '\\$1').replace(/\r?\n/gu, ' ');
	function exportReport(result, conversion, opts) {
		const o = opts || {};
		const note = 'Static checks only. Syntax checks do not replace compiling the rule with the official engine and testing it on data; converted queries must be checked in your SIEM. Secrets found in rules are masked.';
		const conv = conversion ? { target: conversion.targetLabel, rules: conversion.rules.map(r => Object.assign({ title: maskSecrets(r.title), queries: r.queries.map(maskSecrets), error: maskSecrets(r.error) }, r.code ? { code: r.code } : {})) } : undefined;
		const json = { tool: 'CyberDat YARA/Sigma Rule Validator & Converter', engine: ENGINE, ruleset: RULESET, generatedAt: o.timestamp || new Date().toISOString(), note, kind: result.kind, counts: result.counts, findings: result.findings, notes: result.notes, conversion: conv };
		const L = ['# Rule check report', '', 'Generated with CyberDat YARA/Sigma Rule Validator & Converter ' + ENGINE + ' (rules ' + RULESET + ') on ' + mdEsc(json.generatedAt) + '. Input: ' + (result.kind === 'yara' ? 'YARA' : 'Sigma') + '.', '', '> ' + note, '', '- Errors: ' + result.counts.error + '; warnings: ' + result.counts.warning + '; info: ' + result.counts.info, ''];
		if (!result.findings.length) { L.push('No problems found by these checks. This does not mean the rule is correct or effective.', ''); }
		for (const f of result.findings) { L.push('- **' + f.severity.toUpperCase() + '** ' + f.id + ' ' + mdEsc(f.title) + (f.line ? ' (line ' + f.line + ')' : '') + (f.rule ? ' — rule ' + mdEsc(f.rule) : '') + (f.evidence ? ': `' + f.evidence.replace(/`/gu, '\'') + '`' : '')); }
		if (conv) { L.push('', '## Conversion to ' + conv.target, ''); for (const r of conv.rules) { L.push('### ' + mdEsc(r.title), ''); if (r.error) { L.push('Not converted: ' + mdEsc(r.error), ''); } for (const q of r.queries) { L.push('```', q, '```', ''); } } }
		return { json: JSON.stringify(json, null, 2) + '\n', markdown: L.join('\n') + '\n' };
	}

	const EXAMPLE_SIGMA = "title: Net.exe started from a command shell\nid: 5b0f3c2e-8a71-4d6e-9f12-3c4b5a6d7e8f\nstatus: test\ndescription: Detects net.exe started by cmd.exe (example rule written by CyberDat).\nauthor: CyberDat\ndate: 2026-11-18\ntags:\n    - attack.discovery\n    - attack.t1033\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\net.exe'\n        ParentImage|endswith: '\\cmd.exe'\n    filter_admin:\n        User|contains: 'svc_'\n    condition: selection and not filter_admin\nfalsepositives:\n    - Administrators checking their own account\nlevel: low\n";
	const EXAMPLE_YARA = 'import "pe"\n\nrule Example_Loader_Marker\n{\n    meta:\n        author = "CyberDat"\n        description = "Example rule written by CyberDat"\n    strings:\n        $marker = "ExampleLoaderMarker" wide ascii\n        $mz = { 4D 5A 90 00 }\n        $cfg = /cfg_[0-9]{2}\\.example/\n    condition:\n        $mz at 0 and filesize < 5MB and pe.number_of_sections > 2 and ($marker or $cfg)\n}\n';
	const EXAMPLE_FIELDMAP = { spl: { Image: 'process_path', ParentImage: 'parent_process_path', User: 'user' }, kql: { Image: 'FolderPath', ParentImage: 'InitiatingProcessFolderPath', User: 'AccountName' }, lucene: { Image: 'process.executable', ParentImage: 'process.parent.executable', User: 'user.name' } };

	return { ENGINE, RULESET, MAX_INPUT_CHARS, DEF, TARGETS, MODIFIERS, parseYaml, parseCondition, validate, convert, refuseConversion, exportReport, detectKind, checkRegex, checkHex, findSecrets, maskSecrets, EXAMPLE_SIGMA, EXAMPLE_YARA, EXAMPLE_FIELDMAP };
}));
