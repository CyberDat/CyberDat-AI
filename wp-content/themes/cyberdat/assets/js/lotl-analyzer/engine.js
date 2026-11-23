/*!
 * CyberDat LotL / LOLBAS Command Analyzer.
 * Copyright (C) 2026 CyberDat contributors.
 * SPDX-License-Identifier: GPL-3.0-only
 * Modified 2026-11-13: explicit GPL notice and corresponding-source delivery.
 * This program is free software: you may redistribute and modify it under
 * GNU GPL version 3. It comes WITHOUT ANY WARRANTY, including MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See LICENSE-LOLBAS.txt and SOURCE.md.
 */
/*!
 * CyberDat LotL / LOLBAS Command Analyzer: static analysis engine.
 *
 * Pure and side-effect free: no DOM, storage or network APIs. Commands are treated as
 * text only; nothing is executed or evaluated. Loaded by the Web Worker after
 * lolbas-data.js (GPL-3.0 LOLBAS snapshot) and by Node.js tests.
 *
 * What it reports for each command line:
 *  - Windows binaries, scripts and libraries listed in LOLBAS, with their documented functions;
 *  - documented LOLBAS usages the command matches (category, description, ATT&CK id exactly
 *    as given in LOLBAS) and the LOLBAS detection hints (IOC text, references);
 *  - CyberDat heuristics (encoded PowerShell, download cradles, obfuscation, unusual paths ...),
 *    clearly separated from LOLBAS data and without ATT&CK mappings.
 * A match does not prove malice: most of these binaries are used legitimately every day.
 */
(function (root, factory) {
	'use strict';
	if (typeof module === 'object' && module.exports) {
		module.exports = factory(require('./lolbas-data.js'));
	} else {
		root.CyberDatLotlAnalyzer = factory(root.CyberDatLolbasData);
	}
}(typeof self !== 'undefined' ? self : this, function (DATA) {
	'use strict';

	const VERSION = '1.0.2';
	const RULESET_VERSION = '2026-11-13.1';
	const MAX_INPUT_CHARS = 5 * 1024 * 1024;
	const MAX_LINE_CHARS = 32768;
	const MAX_COMMANDS = 20000;
	const MAX_DECODE_DEPTH = 2;

	if (!DATA || !Array.isArray(DATA.entries)) { throw new Error('LOLBAS data snapshot is missing.'); }

	// LOLBAS categories that describe an outright abuse capability.
	const RISKY = new Set(['Download', 'Upload', 'AWL Bypass', 'UAC Bypass', 'Dump', 'Credentials', 'Tamper', 'ADS', 'Conceal']);
	const RANK = { info: 0, low: 1, medium: 2, high: 3 };
	const lower = s => s.toLowerCase();
	const maxSev = (a, b) => (RANK[a] >= RANK[b] ? a : b);
	const down = s => ({ high: 'medium', medium: 'low', low: 'low', info: 'info' }[s]);

	// ---------------------------------------------------------------- tokenizer
	const DASHES_RE = /[\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]/g;

	/** Split on whitespace; quotes are removed but keep grouping; command separators become own tokens. */
	function tokenize(s) {
		const out = [];
		let cur = '';
		let quote = '';
		const push = () => { if (cur) { out.push(cur); } cur = ''; };
		for (let i = 0; i < s.length; i++) {
			const ch = s[i];
			if (quote) {
				if (ch === quote) { quote = ''; } else { cur += ch; }
				continue;
			}
			if (ch === '"' || ch === '\'') {
				// A quote that opens inside a word and closes before the word ends is obfuscation (c"er"tutil); drop it.
				quote = ch;
				continue;
			}
			if (ch === ' ' || ch === '\t') { push(); continue; }
			if (ch === '&' || ch === '|') {
				push();
				let op = ch;
				if (s[i + 1] === ch) { op += ch; i++; }
				out.push(op);
				continue;
			}
			cur += ch;
		}
		push();
		return out;
	}
	const SEPARATORS = new Set(['&', '&&', '|', '||']);

	// ---------------------------------------------------------------- LOLBAS index
	const EXT_RE = /\.(exe|dll|vbs|js|wsf|ps1|cmd|bat|cpl|msc|hta|sys|ocx)$/i;
	const byName = new Map();   // "certutil.exe" -> entry
	const byBase = new Map();   // "certutil" -> entry (executables and scripts only)
	const NEED_RE = /\{([A-Z_]+)(?::([^}]*))?\}/g;

	function baseName(token) {
		let t = token.replace(/^[(@]+|[),]+$/g, '');
		const comma = t.indexOf(',');
		if (comma > 0) { t = t.slice(0, comma); }
		const slash = Math.max(t.lastIndexOf('\\'), t.lastIndexOf('/'));
		return lower(slash >= 0 ? t.slice(slash + 1) : t);
	}

	function normalizeFlag(t) {
		return /^[-/]/.test(t) ? '-' + t.slice(1) : t;
	}

	/**
	 * Literal pieces of a (lower-cased) token that identify a documented usage. Concrete example
	 * values (URLs, IPs, paths, file names, flag values) are dropped: "/node:192.0.2.1" keeps "-node:".
	 */
	function keyPieces(tok, own, ownBase) {
		const out = [];
		for (let piece of tok.split(/[,\s]+/)) {
			piece = piece.replace(/^[("']+|[)"';]+$/g, '');
			if (!piece || piece === own || piece === ownBase) { continue; }
			if (/^[-/][a-z][a-z0-9_-]*[:=]/.test(piece)) { out.push(normalizeFlag(piece.replace(/([:=]).*$/, '$1'))); continue; }
			if (/^[-/][a-z?][a-z0-9_.-]*$/.test(piece)) { out.push(normalizeFlag(piece)); continue; }
			const proto = piece.match(/^(javascript|vbscript):/);
			if (proto) { out.push(proto[0]); continue; }
			if (/:\/\/|^\d|\\|^[a-z]:|\d+\.\d+\.\d+/.test(piece)) { continue; }
			if (/\.[a-z0-9]{1,5}$/.test(piece) && !/\.dll$/.test(piece)) { continue; }
			if (/^[a-z][a-z0-9_.]{1,40}$/.test(piece)) { out.push(piece); }
		}
		return out;
	}

	/** Distinctive literal tokens and placeholder requirements of one documented command. */
	function signature(command, entry) {
		const text = command.replace(/\r?\n/g, ' ');
		const tokens = tokenize(text.replace(DASHES_RE, '-'));
		const own = lower(entry.name);
		const ownBase = own.replace(EXT_RE, '');
		let start = tokens.findIndex(t => { const b = baseName(t); return b === own || b === ownBase; });
		const isLib = /\.dll$/i.test(entry.name);
		let args = start >= 0 ? tokens.slice(start + 1) : tokens.slice(1);
		if (start >= 0 && isLib) {
			const rest = tokens[start].split(',').slice(1).join(',');
			if (rest) { args = [rest].concat(args); }
		}
		const keys = [];
		const needs = [];
		for (const raw of args) {
			if (SEPARATORS.has(raw)) { break; }
			let tok = raw;
			let m;
			NEED_RE.lastIndex = 0;
			while ((m = NEED_RE.exec(tok)) !== null) {
				const kind = m[1];
				const ext = (m[2] || '').match(/^\.[a-z0-9]+$/i) ? lower(m[2]) : '';
				if (kind === 'REMOTEURL') { needs.push({ kind: 'url', ext }); }
				else if (kind === 'PATH_SMB') { needs.push({ kind: 'unc', ext }); }
				else if ((kind === 'PATH' || kind === 'PATH_ABSOLUTE') && ext) { needs.push({ kind: 'path', ext }); }
			}
			if (/\}:[A-Za-z0-9_]+/.test(tok)) { needs.push({ kind: 'ads', ext: '' }); }
			tok = lower(tok.replace(NEED_RE, ' ')).replace(/[{}]/g, ' ');
			for (const k of keyPieces(tok, own, ownBase)) { if (keys.indexOf(k) === -1) { keys.push(k); } }
		}
		return { keys, needs };
	}

	for (const entry of DATA.entries) {
		const key = lower(entry.name);
		byName.set(key, entry);
		if (!/\.dll$/i.test(key)) { byBase.set(key.replace(EXT_RE, ''), entry); }
		entry.sigs = entry.commands.map(c => signature(c.command, entry));
		entry.categories = Array.from(new Set(entry.commands.map(c => c.category)));
		entry.pathSet = new Set(entry.paths.map(p => lower(p)));
	}

	// ---------------------------------------------------------------- deobfuscation
	function deobfuscate(line) {
		const notes = [];
		let s = line;
		const nf = typeof s.normalize === 'function' ? s.normalize('NFKC') : s;
		if (nf !== s) { notes.push('Unicode compatibility characters normalized (NFKC)'); s = nf; }
		const dashes = s.match(DASHES_RE);
		if (dashes) { notes.push(dashes.length + ' Unicode dash character' + (dashes.length === 1 ? '' : 's') + ' used in place of "-"'); s = s.replace(DASHES_RE, '-'); }
		const carets = s.match(/\^(?=[^\s^])/g);
		if (carets && /[A-Za-z]\^[A-Za-z]/.test(s)) { notes.push(carets.length + ' cmd.exe escape character' + (carets.length === 1 ? '' : 's') + ' (^) inside words'); }
		if (carets) { s = s.replace(/\^\^/g, '\u0000').replace(/\^(?=[^\s])/g, '').replace(/\u0000/g, '^'); }
		const ticks = s.match(/(?<=[A-Za-z])`(?=[A-Za-z])/g);
		if (ticks) { notes.push(ticks.length + ' PowerShell backtick' + (ticks.length === 1 ? '' : 's') + ' inside words'); s = s.replace(/(?<=[A-Za-z])`(?=[A-Za-z])/g, ''); }
		const inWordQuotes = s.match(/[A-Za-z]["'][A-Za-z]*["'](?=[A-Za-z])|[A-Za-z]""|""(?=[A-Za-z])/g);
		if (inWordQuotes) { notes.push('quotes inserted inside words'); }
		return { text: s, notes };
	}

	function caseObfuscated(token) {
		const letters = token.replace(/[^A-Za-z]/g, '');
		if (letters.length < 6) { return false; }
		let switches = 0;
		for (let i = 1; i < letters.length; i++) { if ((letters[i] === letters[i].toUpperCase()) !== (letters[i - 1] === letters[i - 1].toUpperCase())) { switches++; } }
		return switches >= 4;
	}

	// ---------------------------------------------------------------- log line extraction
	const CMDLINE_FIELD_RE = /(?:^|[\s,{;])"?(?:Parent)?(?:CommandLine|command_line|process\.command_line|ProcessCommandLine|Process Command Line)"?\s*[:=]\s*/i;
	/** If the line looks like a log record with a command-line field, return that field. */
	function extractCommand(line) {
		const m = CMDLINE_FIELD_RE.exec(line);
		if (!m) { return { text: line, field: false }; }
		let rest = line.slice(m.index + m[0].length);
		if (rest[0] === '"') {
			let out = '';
			for (let i = 1; i < rest.length; i++) {
				const ch = rest[i];
				if (ch === '\\' && i + 1 < rest.length) {
					const n = rest[i + 1];
					out += n === 'n' ? ' ' : n === 't' ? ' ' : n === 'u' ? String.fromCharCode(parseInt(rest.substr(i + 2, 4), 16) || 32) : n;
					i += n === 'u' ? 5 : 1;
					continue;
				}
				if (ch === '"') { break; }
				out += ch;
			}
			return { text: out, field: true };
		}
		return { text: rest, field: true };
	}

	// ---------------------------------------------------------------- heuristics (CyberDat, not LOLBAS)
	const HEURISTICS = {
		'LOT-H-001': { severity: 'medium', title: 'Encoded PowerShell command', explain: 'PowerShell -EncodedCommand takes Base64 of UTF-16LE text. Administrators rarely need it interactively; it hides the real command from casual review. The decoded text is shown and analyzed below.' },
		'LOT-H-002': { severity: 'medium', title: 'PowerShell download pattern', explain: 'The command uses a PowerShell or .NET method that fetches content from the network (for example Net.WebClient, DownloadString, Invoke-WebRequest, Start-BitsTransfer).' },
		'LOT-H-003': { severity: 'medium', title: 'Dynamic code execution in PowerShell', explain: 'Invoke-Expression (IEX) runs a string as code. Combined with a download it executes remote content without writing a script file.' },
		'LOT-H-004': { severity: 'high', title: 'Download combined with dynamic execution', explain: 'Content is fetched from the network and passed to Invoke-Expression in the same command, a pattern often called a download cradle.' },
		'LOT-H-005': { severity: 'low', title: 'PowerShell options that reduce visibility', explain: 'Options such as a hidden window, -NoProfile, -NonInteractive or -ExecutionPolicy Bypass are common in automation but also in attacks. Their presence alone is weak evidence.' },
		'LOT-H-006': { severity: 'medium', title: 'Command-line obfuscation', explain: 'Characters that the shell ignores (^ carets, quotes inside words, PowerShell backticks), look-alike dashes or random letter case change how the command looks without changing what it does. Legitimate tools rarely produce this.' },
		'LOT-H-007': { severity: 'medium', title: 'LOLBAS binary run from an unexpected location', explain: 'The binary is started with a full path that is not one of the locations listed for it in LOLBAS. A copied or renamed system binary in a user-writable folder deserves a closer look.' },
		'LOT-H-008': { severity: 'medium', title: 'Script protocol in arguments', explain: 'javascript: or vbscript: in arguments makes hosts such as mshta or rundll32 run script code given directly on the command line.' },
		'LOT-H-009': { severity: 'low', title: 'User-writable location', explain: 'The command reads, writes or runs files in a location any user can write to (Temp, AppData, Users\\Public, ProgramData).' },
		'LOT-H-010': { severity: 'medium', title: 'NTFS alternate data stream syntax', explain: 'A file name followed by :stream addresses an alternate data stream, which hides content inside another file.' },
		'LOT-H-011': { severity: 'low', title: 'Remote URL or network path in arguments', explain: 'An argument points to an http(s)/ftp URL or a \\\\host\\share path. Check whether the binary is expected to reach that location.' },
		'LOT-H-012': { severity: 'medium', title: 'In-memory decoding or assembly loading', explain: 'FromBase64String, [Reflection.Assembly]::Load or similar calls decode or load code in memory.' },
		'LOT-H-014': { severity: 'medium', title: 'Remote location passed to a binary LOLBAS lists for downloads', explain: 'This binary has documented download or upload uses in LOLBAS, and the command gives it a URL or network path, although not in a documented form. Check what was transferred.' },
		'LOT-H-013': { severity: 'low', title: 'Long Base64-like argument', explain: 'A long Base64-looking string is passed on the command line. It may be an encoded script or file content.' }
	};

	const PS_NAMES = new Set(['powershell', 'powershell.exe', 'pwsh', 'pwsh.exe', 'powershell_ise.exe']);
	const ENC_PARAM_RE = /^[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)$/i;
	const URL_RE = /\b(?:https?|ftp):\/\/[^\s"'<>]{3,}/i;
	const UNC_RE = /(?:^|[\s"'=(,])\\\\[A-Za-z0-9._-]{1,253}\\[^\s"']+/;
	/** \\host\share on an internal network: single-label host, internal DNS suffix or private IPv4 (WebDAV @SSL/@port is never internal). */
	function internalShare(t) {
		const m = String(t).match(/^\\\\([^\\]{1,253})\\/);
		if (!m || /@/.test(m[1])) { return false; }
		const h = m[1].toLowerCase();
		return !h.includes('.') || /\.(?:local|lan|internal|corp|intranet|home\.arpa|localdomain)$/.test(h) || /^(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}$/.test(h);
	}
	const WRITABLE_RE = /%(?:temp|tmp|appdata|localappdata|public|programdata)%|\$env:(?:temp|tmp|appdata|localappdata|public|programdata)|\\(?:users\\public|appdata\\(?:local|roaming)|programdata|windows\\temp|temp)\\/i;
	const ADS_RE = /[A-Za-z0-9_\-\\)]\.[A-Za-z0-9]{1,8}:[A-Za-z0-9_.-]{1,64}(?:[\s"']|$)/;
	const DOWNLOAD_RE = /\b(?:Net\.WebClient|DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|Net\.Http\.HttpClient|XMLHTTP|WinHttpRequest)\b|(?:^|[\s;|(])(?:iwr|irm|curl|wget)\s+["']?(?:https?:)?\/\//i;
	const IEX_RE = /\b(?:Invoke-Expression|iex)\b/i;
	const STEALTH_RE = /(?:^|\s)[-/](?:w|wi|win|wind|windo|window|windows|windowst|windowsty|windowstyl|windowstyle)\s+(?:h|hi|hid|hidd|hidde|hidden|1)\b|(?:^|\s)[-/](?:nop|noprofile|noni|noninteractive)\b|(?:^|\s)[-/](?:ep|ex|exec|executionpolicy)\s+(?:bypass|unrestricted)\b/gi;
	const INMEM_RE = /\bFromBase64String\b|\[(?:System\.)?Reflection\.Assembly\]::Load|\bIO\.Compression\.(?:GzipStream|DeflateStream)\b/i;
	const B64_ARG_RE = /(?:^|\s)[A-Za-z0-9+/]{60,}={0,2}(?:\s|$)/;

	function decodeUtf16Base64(b64) {
		if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64) || b64.length % 4 === 1) { return null; }
		let bin;
		try { bin = atob(b64.length % 4 ? b64 + '='.repeat(4 - (b64.length % 4)) : b64); } catch (e) { return null; }
		if (bin.length % 2) { return null; }
		let out = '';
		for (let i = 0; i + 1 < bin.length; i += 2) { out += String.fromCharCode(bin.charCodeAt(i) | (bin.charCodeAt(i + 1) << 8)); }
		const printable = out.replace(/[\x20-\x7E\t\r\n\u00A0-\uFFFF]/g, '').length;
		return printable / Math.max(1, out.length) < 0.05 ? out : null;
	}

	// ---------------------------------------------------------------- matching
	function argMatchesKey(tokens, key) {
		if (key[0] === '-') {
			const prefix = /[:=]$/.test(key);
			for (const t of tokens) {
				if (t === key) { return true; }
				if (prefix ? t.startsWith(key) : (t.startsWith(key + ':') || t.startsWith(key + '='))) { return true; }
			}
			return false;
		}
		for (const t of tokens) {
			if (t === key || t.startsWith(key) && /[:=(]$/.test(key)) { return true; }
			if (t.split(/[,;]/).some(p => p === key || p.replace(/^.*\\/, '') === key)) { return true; }
			if (/[:]$/.test(key) && t.indexOf(key) !== -1) { return true; }
		}
		return false;
	}

	function needSatisfied(need, raw, tokens) {
		const ext = need.ext;
		const endsExt = t => !ext || lower(t).replace(/[",;)}]+$/, '').endsWith(ext);
		// The extension in a LOLBAS URL placeholder is illustrative; any remote location satisfies it.
		if (need.kind === 'url') { return raw.some(t => /(?:https?|ftp):\/\//i.test(t)) || raw.some(t => /^\\\\[^\\]+\\/.test(t)); }
		if (need.kind === 'unc') { return raw.some(t => /^\\\\[^\\]+\\/.test(t.replace(/^[^\\]*(?=\\\\)/, ''))); }
		if (need.kind === 'ads') { return raw.some(t => ADS_RE.test(t + ' ')); }
		if (need.kind === 'path') { return tokens.some(t => endsExt(t)); }
		return true;
	}

	function matchEntry(entry, argsRaw) {
		// Quoted arguments ("ac i ntds") are also compared word by word.
		const tokens = [];
		for (const t of argsRaw) {
			for (const w of lower(t).replace(/[{}]/g, ' ').split(/\s+/)) { if (w) { tokens.push(normalizeFlag(w)); } }
		}
		const matches = [];
		entry.sigs.forEach((sig, idx) => {
			if (!sig.keys.length && !sig.needs.length) { return; }
			const hit = sig.keys.filter(k => argMatchesKey(tokens, k)).length;
			// File extensions in LOLBAS path placeholders are illustrative once flags identify the usage;
			// they only matter for templates without literal keys (e.g. "mshta.exe {PATH:.hta}").
			const needsOk = sig.needs.every(n => (n.kind === 'path' && sig.keys.length) || needSatisfied(n, argsRaw, tokens));
			const words = sig.keys.filter(k => k[0] !== '-');
			const flags = sig.keys.filter(k => k[0] === '-');
			const wordsOk = words.every(k => argMatchesKey(tokens, k));
			const flagHit = flags.filter(k => argMatchesKey(tokens, k)).length;
			const valueFlags = flags.filter(k => /[:=]$/.test(k));
			const remoteNeed = sig.needs.some(n => n.kind === 'url' || n.kind === 'unc');
			let quality = '';
			if (hit === sig.keys.length && needsOk) { quality = 'full'; }
			// Partial: every distinctive word matches and at most one flag is missing; or every value-taking
			// flag matches and the remote location the usage needs is present; or keys match but a local
			// file of the documented type is missing.
			else if (sig.keys.length >= 2 && wordsOk && flagHit >= flags.length - 1 && hit >= 1 && needsOk) { quality = 'partial'; }
			else if (remoteNeed && needsOk && valueFlags.length && valueFlags.every(k => argMatchesKey(tokens, k))) { quality = 'partial'; }
			else if (sig.keys.length >= 1 && hit === sig.keys.length && !needsOk && !remoteNeed) { quality = 'partial'; }
			if (!quality) { return; }
			// Templates without literal keys (e.g. "msedge.exe {REMOTEURL}") only show that a usage is possible;
			// a browser opening a URL is its normal job.
			if (!sig.keys.length) {
				if (remoteNeed && /browser/i.test(entry.description)) { return; }
				quality = 'partial';
			}
			matches.push({ idx, quality, specific: sig.keys.length >= 2, remote: remoteNeed && needsOk, score: (hit + (needsOk ? sig.needs.length : 0)) / Math.max(1, sig.keys.length + sig.needs.length) });
		});
		matches.sort((a, b) => (a.quality === b.quality ? 0 : a.quality === 'full' ? -1 : 1) || b.score - a.score);
		// Keep full matches, or the best partial ones; one per category.
		const seen = new Set();
		const out = [];
		const best = matches.length && matches[0].quality === 'full' ? matches.filter(m => m.quality === 'full') : matches.slice(0, 3);
		for (const m of best) {
			const c = entry.commands[m.idx];
			const k = c.category + '|' + m.quality;
			if (seen.has(k)) { continue; }
			seen.add(k);
			out.push({ quality: m.quality, specific: m.specific, remote: m.remote, command: c.command, description: c.description, usecase: c.usecase, category: c.category, privileges: c.privileges, mitre: c.mitre, os: c.os });
		}
		return out;
	}

	// ---------------------------------------------------------------- secret masking (shared block)
	// The same block is in the Prompt Injection Detector and the LotL Command Analyzer engines (a test checks that both copies
	// are equal). It masks what the page shows and what the reports contain; detection always runs on the original text.
	// The whole text is masked first and cut afterwards, so a secret is never cut into a piece that is no longer recognised.
	// Pattern-based: it hides common forms, it cannot promise to find every secret. Unicode classes use the u flag, there is no
	// look-behind, every repeated part is bounded or runs over a single class, and every character is covered at most once.
	const SECRET_FORMATS = [
		['AWS access key ID', /(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}/gu], ['GitHub token', /gh[pousr]_[0-9A-Za-z]{30,255}/gu],
		['GitHub fine-grained token', /github_pat_[0-9A-Za-z_]{40,255}/gu], ['GitLab token', /glpat-[0-9A-Za-z_-]{20,255}/gu],
		['Slack token', /xox[abposr]-[0-9A-Za-z-]{10,255}/gu], ['Slack webhook', /hooks\.slack\.com\/services\/[0-9A-Za-z_/]{8,255}/gu],
		['Anthropic API key', /sk-ant-[0-9A-Za-z_-]{20,255}/gu], ['OpenAI-style API key', /sk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{20,255}/gu],
		['Google API key', /AIza[0-9A-Za-z_-]{35}/gu], ['Hugging Face token', /hf_[0-9A-Za-z]{30,255}/gu], ['Stripe key', /[rsp]k_(?:live|test)_[0-9A-Za-z]{10,255}/gu],
		['npm token', /npm_[0-9A-Za-z]{36}/gu], ['JSON Web Token', /eyJ[0-9A-Za-z_-]{10,8000}\.eyJ[0-9A-Za-z_-]{2,8000}\.[0-9A-Za-z_-]{0,8000}/gu],
		['Azure storage key', /AccountKey=[0-9A-Za-z+/]{40,200}={0,2}/gu]
	];
	const PEM_BEGIN = /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/gu;
	const PEM_END = /-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/uy;
	const SECRET_TOKEN_CHAR = /[\p{L}\p{N}\p{M}_]/u;
	// key = value, key: value, "key": "value", key => value, "key is value" after a credential, password, secret, token, api key,
	// access/private key, authorization, auth, csrf, session id or cookie key: the value is masked whatever its length.
	// An auth scheme (Bearer, Basic, Token) before the value is skipped so that the value itself is masked.
	const SECRET_KEYED = /(?:credentials?|passwords?|passwort|passwd|passphrase|pwd|пароль|secret|token|api[_.\- ]?key|x[_.\-]?api[_.\-]?key|access[_.\-]?key(?:[_.\-]?id)?|private[_.\-]?key|authorization|auth|csrf|session[_.\-]?(?:id|key)?|cookie)["'”»“]?[ \t]{0,20}(?:=>|=|:|[ \t](?:is|ist|—|-)[ \t])[ \t]{0,20}(?:(?:bearer|basic|token)[ \t]{1,20})?("(?:[^"\\\n]|\\.){0,500}"|'(?:[^'\\\n]|\\.){0,500}'|“[^”\n]{0,500}”|«[^»\n]{0,500}»|„[^“\n]{0,500}“|[^\s"',;)\]}<>]{1,4000})/giu;
	/** An HTTP auth scheme with its credential, also without a key name (Bearer …, Basic …). */
	const SECRET_BEARER = /(?:bearer|basic)[ \t]{1,20}([A-Za-z0-9._~+/=-]{6,4000})/giu;
	/** Command-line options that take a password or token: /pass:…, /rp …, -Password …, --token=…, -ApiKey … */
	const SECRET_OPTION = /(?:^|[\s"'(])(?:--?|\/)(?:password|passwd|passphrase|pwd|pass|rp|secret|token|access[_-]?token|api[_-]?key|client[_-]?secret)(?::|=|[ \t]{1,20})("(?:[^"\\\n]|\\.){0,500}"|'(?:[^'\\\n]|\\.){0,500}'|[^\s"'|&;<>]{1,4000})/giu;
	/** curl -u user:password, --user, --proxy-user: the part after the first colon. */
	const SECRET_USER_OPTION = /(?:^|[\s"'(])(?:-u|-U|--user|--proxy-user)(?:=|[ \t]{1,20})("[^"\n]{1,500}"|'[^'\n]{1,500}'|[^\s"'|&;<>]{1,4000})/gu;
	/** ConvertTo-SecureString "plain text" -AsPlainText: the plain-text password. */
	const SECRET_SECURESTRING = /ConvertTo-SecureString[ \t]{1,20}(?:-String[ \t]{1,20})?("(?:[^"\\\n]|\\.){1,500}"|'(?:[^'\\\n]|\\.){1,500}')/giu;
	const SECRET_URL = /(?:https?|wss?|ftps?|sftp|ssh|smb|git\+https?|git\+ssh|s3|gs|hf):\/\/[^\s"'<>`]{1,4000}/giu;
	const SECRET_LONG = /[0-9A-Za-z+/=_\-.~]{24,4000}/gu;
	// A separate word of 16 to 500 characters from letters, digits, "_" and "-" with lower case, upper case and digits is masked
	// without a key (the rule of the Prompt Injection Test Bench 1.0.3). Words are separated by space, quotes, brackets, commas
	// or semicolons; a part of a path, an address or a dotted name is not a separate word.
	const SECRET_UNKEYED = /[A-Za-z0-9_-]{16,500}/gu;
	const SECRET_WORD_LEFT = /[\s"'`(\[{<,;]/u, SECRET_WORD_RIGHT = /[\s"'`)\]}>,;.!?:]/u;
	const SECRET_PARAM_NAMES = new Set(['password', 'passwd', 'passphrase', 'pwd', 'pass', 'secret', 'clientsecret', 'token', 'accesstoken', 'refreshtoken', 'idtoken', 'authtoken', 'sessiontoken', 'securitytoken', 'apikey', 'xapikey', 'key', 'accesskey', 'accesskeyid', 'privatekey', 'auth', 'authorization', 'sig', 'signature', 'credential', 'credentials', 'session', 'sessionid', 'sid', 'csrf', 'csrftoken', 'xsrftoken', 'cookie', 'xamzsignature', 'xamzcredential', 'xamzsecuritytoken', 'xgoogsignature', 'xgoogcredential']);
	const secretParamName = n => { const k = n.toLowerCase().replace(/[^a-z0-9]/gu, ''); return SECRET_PARAM_NAMES.has(k) || /(?:password|secret|token|apikey|privatekey|signature)$/u.test(k); };
	function secretShown(v) { const t = String(v); if (t.length <= 8) { return '••••'; } const c = [...t]; return c.length <= 8 ? '••••' : c.slice(0, 4).join('') + '… (' + c.length + ' characters)'; }
	function secretEntropy(s) { const m = new Map(); for (const ch of s) { m.set(ch, (m.get(ch) || 0) + 1); } let e = 0; for (const n of m.values()) { const p = n / s.length; e -= p * Math.log2(p); } return e; }
	function percentDecode(s) {
		if (s.indexOf('%') < 0 && s.indexOf('+') < 0) { return s; }
		const t = s.replace(/\+/gu, ' ');
		try { return decodeURIComponent(t); } catch (e) { return t.replace(/%([0-9A-Fa-f]{2})/gu, (m, h) => String.fromCharCode(parseInt(h, 16))); }
	}
	/** Base64 that decodes to readable text with spaces (an encoded command, a payload) is content, not a random key. */
	function readableBase64(v) {
		if (v.length % 4 === 1 || !/^[A-Za-z0-9+/]+={0,2}$/u.test(v) || typeof atob !== 'function') { return false; }
		let b;
		try { b = atob(v.length % 4 ? v + '='.repeat(4 - (v.length % 4)) : v); } catch (e) { return false; }
		let printable = 0, zeroOdd = 0, spaces = 0;
		for (let i = 0; i < b.length; i++) { const c = b.charCodeAt(i); if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) { printable++; } if (c === 32) { spaces++; } if (c === 0 && i % 2 === 1) { zeroOdd++; } }
		const utf16 = zeroOdd >= b.length / 2 - 1;
		return spaces > 0 && (utf16 || printable >= b.length * 0.95);
	}
	/** A random-looking value: letters and digits, not hex, not a path or a name made of words, high character entropy. */
	function tokenLike(v, min) {
		if (v.length < min || !/\p{N}/u.test(v) || !/\p{L}/u.test(v) || /^[0-9A-Fa-f-]+$/u.test(v) || secretEntropy(v) < 3.5) { return false; }
		const parts = v.split(/[-_./~+=]/u).filter(Boolean);
		// a part made of letters then digits (python3, Framework64) or digits then letters is a word, not a token
		return !parts.every(p => p.length <= 4 || /^(?:\p{L}+\p{N}*|\p{N}+\p{L}*)$/u.test(p));
	}
	/** Secret spans in a text: [{ kind, start, end, shown }], sorted and not overlapping. */
	function findSecrets(text) {
		const s = String(text === undefined || text === null ? '' : text);
		const out = [];
		if (!s) { return out; }
		const cov = new Uint8Array(s.length), inUrl = new Uint8Array(s.length);
		const taken = (a, b) => { for (let i = a; i < b; i++) { if (cov[i]) { return true; } } return false; };
		const put = (kind, a, b, value) => { if (b <= a || taken(a, b)) { return; } cov.fill(1, a, b); out.push({ kind, start: a, end: b, shown: secretShown(value === undefined ? s.slice(a, b) : value) }); };
		let m;
		// Private key blocks: from BEGIN to END when END follows within 20,000 characters, otherwise the header line.
		PEM_BEGIN.lastIndex = 0;
		let endAt = -2;
		while ((m = PEM_BEGIN.exec(s))) {
			if (endAt !== -1 && endAt < m.index) { endAt = s.indexOf('-----END', m.index + m[0].length); }
			let b = m.index + m[0].length;
			if (endAt >= 0 && endAt - m.index < 20000) { PEM_END.lastIndex = endAt; const e = PEM_END.exec(s); if (e) { b = endAt + e[0].length; } }
			if (!taken(m.index, b)) { cov.fill(1, m.index, b); out.push({ kind: 'Private key', start: m.index, end: b, shown: 'BEGIN … PRIVATE KEY' }); }
			PEM_BEGIN.lastIndex = b;
		}
		// Addresses: credentials before @, secret or token-like query and fragment values (percent escapes decoded before
		// they are classified; the original span is replaced), token-like path segments.
		SECRET_URL.lastIndex = 0;
		while ((m = SECRET_URL.exec(s))) {
			// trailing punctuation is not part of the address (a loop: a regular expression anchored at the end is quadratic)
			let len = m[0].length;
			while (len > 1 && ').,;:!?]}*'.indexOf(m[0][len - 1]) >= 0) { len--; }
			const u = m[0].slice(0, len);
			const start = m.index, scheme = u.indexOf('://') + 3;
			inUrl.fill(1, start, start + u.length);
			let i = scheme;
			while (i < u.length && u[i] !== '/' && u[i] !== '?' && u[i] !== '#') { i++; }
			const at = u.lastIndexOf('@', i);
			if (at >= scheme && u.slice(scheme, at).indexOf(':') >= 0) { put('credentials in the address', start + scheme, start + at); }
			let q = u.indexOf('?', i), h = u.indexOf('#', i);
			if (q < 0) { q = u.length; }
			if (h < 0) { h = u.length; }
			const pathEnd = Math.min(q, h);
			let k = i;
			for (const seg of u.slice(i, pathEnd).split('/')) {
				const d = percentDecode(seg);
				if (tokenLike(d, 20) && !readableBase64(d)) { put('token in the address', start + k, start + k + seg.length, d); }
				k += seg.length + 1;
			}
			for (const [from, to] of [[q + 1, h], [h + 1, u.length]]) {
				if (from > u.length || to <= from) { continue; }
				let p = from;
				for (const pair of u.slice(from, to).split(/[&;]/u)) {
					const eq = pair.indexOf('=');
					if (eq > 0 && eq < pair.length - 1) {
						const name = percentDecode(pair.slice(0, eq)), raw = pair.slice(eq + 1), value = percentDecode(raw);
						const a = start + p + eq + 1, b = a + raw.length;
						const known = SECRET_FORMATS.some(([, re]) => { re.lastIndex = 0; return re.test(value); });
						if (secretParamName(name)) { put('secret in the address (' + name.slice(0, 40) + ')', a, b, value); }
						else if (known || (tokenLike(value, 20) && !readableBase64(value))) { put('token in the address', a, b, value); }
					}
					p += pair.length + 1;
				}
			}
			SECRET_URL.lastIndex = start + Math.max(u.length, 1);
		}
		for (const [kind, re] of SECRET_FORMATS) {
			re.lastIndex = 0;
			while ((m = re.exec(s))) {
				const a = m.index, b = a + m[0].length;
				if (a > 0 && SECRET_TOKEN_CHAR.test(s[a - 1]) && kind !== 'Azure storage key') { continue; }
				put(kind, a, b);
			}
		}
		for (const RE of [SECRET_KEYED, SECRET_BEARER, SECRET_OPTION, SECRET_USER_OPTION, SECRET_SECURESTRING]) {
			RE.lastIndex = 0;
			while ((m = RE.exec(s))) {
				const v = m[1];
				let a = m.index + m[0].length - v.length, b = a + v.length;
				if (v[0] === '"' || v[0] === '\'' || v[0] === '“' || v[0] === '«' || v[0] === '„') { a += 1; b -= 1; }
				if (RE === SECRET_USER_OPTION) { const c = s.indexOf(':', a); if (c < 0 || c >= b - 1) { continue; } a = c + 1; }
				// a value that is already a masked marker, or a variable or placeholder, stays as it is
				if (b <= a) { continue; }
				const val = s.slice(a, b);
				if (val[0] === '[' || val.indexOf('…') >= 0 || val.indexOf('••••') >= 0) { continue; }
				put('value of a secret field', a, b, val);
			}
		}
		SECRET_LONG.lastIndex = 0;
		while ((m = SECRET_LONG.exec(s))) {
			const v = m[0], a = m.index, b = a + v.length;
			if ((a > 0 && SECRET_TOKEN_CHAR.test(s[a - 1])) || (b < s.length && SECRET_TOKEN_CHAR.test(s[b])) || /^(?:https?|www)/iu.test(v) || inUrl[a] || inUrl[b - 1]) { continue; }
			if (!tokenLike(v, 24) || readableBase64(v.replace(/[.~_-]+$/u, ''))) { continue; }
			put('unrecognized long value', a, b);
		}
		// Values without a key. Not hex (hashes), GUIDs, words without digits, and not base64 that decodes to readable text:
		// an encoded command or payload is material of the analysis, not a secret.
		SECRET_UNKEYED.lastIndex = 0;
		while ((m = SECRET_UNKEYED.exec(s))) {
			const v = m[0], a = m.index, b = a + v.length;
			if ((a > 0 && !SECRET_WORD_LEFT.test(s[a - 1])) || (b < s.length && !SECRET_WORD_RIGHT.test(s[b])) || inUrl[a]) { continue; }
			if ((s[b] === '.' || s[b] === ':') && b + 1 < s.length && !/\s/u.test(s[b + 1])) { continue; }
			if (!/[a-z]/u.test(v) || !/[A-Z]/u.test(v) || !/[0-9]/u.test(v) || /^[0-9A-Fa-f-]+$/u.test(v)) { continue; }
			if (readableBase64(v) || readableBase64(v.replace(/-/gu, '+').replace(/_/gu, '/'))) { continue; }
			put('value that looks like a secret', a, b);
		}
		return out.sort((x, y) => x.start - y.start);
	}
	/** Text with every recognised secret replaced by its kind and a masked fragment (one pass: linear in the text). */
	function maskSecrets(text, spans) {
		const s = String(text === undefined || text === null ? '' : text);
		const parts = [];
		let k = 0;
		// consecutive spans of the same kind and masked form share one marker string (fewer allocations on many short values)
		let kind = null, shown = null, marker = '';
		for (const x of spans || findSecrets(s)) { if (x.kind !== kind || x.shown !== shown) { kind = x.kind; shown = x.shown; marker = '[' + kind + ': ' + shown + ']'; } parts.push(s.slice(k, x.start), marker); k = x.end; }
		parts.push(s.slice(k));
		return parts.join('');
	}
	/** Masked text cut to max characters (masking first, then cutting). */
	const maskedClip = (text, max) => { const t = maskSecrets(text); return t.length > max ? t.slice(0, max) + '…' : t; };
	// ---------------------------------------------------------------- end of secret masking (shared block)

	/**
	 * Mask every piece of the user's text in one analysed command before it is shown or exported: the command line, the
	 * normalized command, deobfuscation notes, binary names as written, heuristic details and decoded commands (also those
	 * analysed inside). Decoded commands and long addresses are masked first and cut afterwards.
	 */
	function maskResult(r, done) {
		if (!r || done.has(r)) { return r; }
		done.add(r);
		r.original = maskSecrets(r.original);
		if (r.normalized) { r.normalized = maskSecrets(r.normalized); }
		r.deobfuscation = r.deobfuscation.map(n => maskSecrets(n));
		for (const b of r.binaries) { if (!done.has(b)) { done.add(b); b.as = maskSecrets(b.as); } }
		for (const h of r.heuristics) { if (!done.has(h)) { done.add(h); h.details = h.details.map(d => maskedClip(d, h.id === 'LOT-H-011' ? 120 : 4000)); } }
		for (const d of r.decoded) {
			if (done.has(d)) { continue; }
			done.add(d);
			d.text = maskedClip(d.text, 4000);
			maskResult(d.analysis, done);
		}
		return r;
	}

	// ---------------------------------------------------------------- analysis of one command
	function analyzeCommand(original, depth) {
		const extracted = extractCommand(original);
		const de = deobfuscate(extracted.text.length > MAX_LINE_CHARS ? extracted.text.slice(0, MAX_LINE_CHARS) : extracted.text);
		const text = de.text;
		const tokens = tokenize(text);
		const result = { original, extractedFromLog: extracted.field, normalized: text !== extracted.text ? text : null, truncated: extracted.text.length > MAX_LINE_CHARS, deobfuscation: de.notes, binaries: [], heuristics: [], decoded: [], severity: 'none' };
		const heur = new Map();
		const addH = (id, detail, severity) => {
			const h = HEURISTICS[id];
			const prev = heur.get(id);
			const sev = severity || h.severity;
			if (prev) { if (detail && prev.details.indexOf(detail) === -1 && prev.details.length < 5) { prev.details.push(detail); } prev.severity = maxSev(prev.severity, sev); return; }
			heur.set(id, { id, severity: sev, title: h.title, explanation: h.explain, details: detail ? [detail] : [] });
		};

		// Find invocations of LOLBAS binaries.
		let segStart = true;
		let prev = '';
		const seen = new Set();
		for (let i = 0; i < tokens.length; i++) {
			const raw = tokens[i];
			if (SEPARATORS.has(raw)) { segStart = true; prev = raw; continue; }
			const atCommand = segStart || /^[/-][ckr]$/i.test(prev) || /^(?:start|call|cmd|cmd\.exe|&)$/i.test(prev);
			// A quoted command passed to cmd /c or powershell -Command is analyzed as its own command line.
			if (/\s/.test(raw) && /^(?:[/-][ckr]|-command|-c)$/i.test(prev) && depth < MAX_DECODE_DEPTH + 1) {
				const nested = analyzeCommand(raw, depth + 1);
				for (const b of nested.binaries) { result.binaries.push(b); }
				for (const h of nested.heuristics) { for (const d of (h.details.length ? h.details : [''])) { addH(h.id, d, h.severity); } }
				for (const d of nested.decoded) { result.decoded.push(d); }
				for (const n of nested.deobfuscation) { if (de.notes.indexOf(n) === -1) { de.notes.push(n); } }
				segStart = false;
				prev = raw;
				continue;
			}
			segStart = false;
			prev = raw;
			if (/^[-/][^\\]/.test(raw) && !/^\/\//.test(raw)) { continue; }
			const name = baseName(raw);
			let entry = byName.get(name);
			if (!entry && atCommand && !/\.[a-z0-9]{2,4}$/i.test(name)) { entry = byBase.get(name); }
			if (!entry || /\.dll$/i.test(entry.name) && !/\.dll/i.test(raw)) { continue; }
			let end = i + 1;
			while (end < tokens.length && !SEPARATORS.has(tokens[end])) { end++; }
			let args = tokens.slice(i + 1, end);
			if (/\.dll$/i.test(entry.name)) {
				const rest = raw.split(',').slice(1).join(',');
				if (rest) { args = [rest].concat(args); }
			}
			const key = entry.name + '|' + i;
			if (seen.has(key)) { continue; }
			seen.add(key);
			const inv = {
				name: entry.name,
				type: entry.type,
				as: raw,
				description: entry.description,
				functions: entry.categories,
				page: entry.page,
				matches: matchEntry(entry, args),
				ioc: entry.ioc.slice(0, 12),
				references: entry.references.slice(0, 12),
				severity: 'info'
			};
			// Unexpected location: only when a concrete full path is given.
			const p = raw.replace(/^[(]+|[,)]+$/g, '').replace(/,.*$/, '');
			if (/^(?:[a-z]:\\|\\\\)/i.test(p) && entry.pathSet.size && !entry.pathSet.has(lower(p)) && !Array.from(entry.pathSet).some(x => /[*<\[]|\\v\d|\{/.test(x) && lower(p).endsWith('\\' + lower(entry.name)) && lower(p).slice(0, 10) === x.slice(0, 10))) {
				if (WRITABLE_RE.test(p) || !/^c:\\(?:windows|program files)/i.test(p)) { addH('LOT-H-007', entry.name + ' started from ' + p); }
			}
			const shownName = raw.replace(/^.*\\/, '').replace(/,.*$/, '');
			if (caseObfuscated(shownName)) { de.notes.push('random letter case in the binary name "' + shownName + '"'); }
			const hasRemote = args.some(t => URL_RE.test(t) || /^\\\\[^\\]+\\/.test(t));
			// Internal file shares (single-label host, internal suffix, private address) are routine for software
			// deployment: they keep the LOLBAS match but do not raise it to high on their own.
			const hasExternal = args.some(t => URL_RE.test(t) || (/^\\\\[^\\]+\\/.test(t) && !internalShare(t)));
			if (hasRemote && !inv.matches.some(m => m.category === 'Download' || m.category === 'Upload') && entry.categories.some(c => c === 'Download' || c === 'Upload') && !/browser/i.test(entry.description)) {
				addH('LOT-H-014', entry.name + ' (LOLBAS documents: ' + entry.categories.join(', ') + ')');
			}
			for (const m of inv.matches) {
				let sev;
				if (m.quality === 'full') { sev = RISKY.has(m.category) ? 'high' : (hasExternal ? 'high' : 'medium'); }
				else { sev = RISKY.has(m.category) ? 'medium' : 'low'; }
				if (m.category === 'Execute' && m.quality === 'full' && !m.specific && !hasExternal &&!args.some(t => WRITABLE_RE.test(t) || /(?:java|vb)script:/i.test(t))) { sev = 'low'; }
				if (m.remote) { sev = maxSev(sev, 'medium'); }
				m.severity = sev;
				inv.severity = maxSev(inv.severity, sev);
			}
			result.binaries.push(inv);
		}

		// PowerShell: encoded command and patterns.
		const isPs = tokens.some(t => PS_NAMES.has(baseName(t))) || /\bSyncAppvPublishingServer\b/i.test(text);
		if (isPs || DOWNLOAD_RE.test(text) || IEX_RE.test(text)) {
			for (let i = 0; i < tokens.length - 1; i++) {
				if (ENC_PARAM_RE.test(tokens[i]) && tokens.slice(0, i).some(t => PS_NAMES.has(baseName(t)))) {
					const decoded = decodeUtf16Base64(tokens[i + 1]);
					if (decoded) {
						addH('LOT-H-001', 'decoded ' + decoded.length + ' characters');
						const inner = depth < MAX_DECODE_DEPTH ? analyzeCommand(decoded, depth + 1) : null;
						result.decoded.push({ kind: 'PowerShell -EncodedCommand (Base64, UTF-16LE)', text: decoded, analysis: inner });
					} else {
						addH('LOT-H-001', 'value is not valid Base64 of UTF-16LE text', 'low');
					}
				}
			}
			const dl = DOWNLOAD_RE.test(text);
			const iex = IEX_RE.test(text);
			if (dl && iex) { addH('LOT-H-004', ''); }
			else if (dl) { addH('LOT-H-002', ''); }
			else if (iex && isPs) { addH('LOT-H-003', ''); }
			if (isPs) {
				const flags = (text.match(STEALTH_RE) || []).map(s => s.trim());
				if (flags.length) { addH('LOT-H-005', Array.from(new Set(flags)).join(', ')); }
			}
		}
		if (INMEM_RE.test(text)) { addH('LOT-H-012', (text.match(INMEM_RE) || [''])[0]); }
		for (const m of text.matchAll(/FromBase64String\(\s*['"]([A-Za-z0-9+/=]{8,20000})['"]\s*\)/g)) {
			let d = decodeUtf16Base64(m[1]);
			if (!d) { try { d = atob(m[1]); if (/[^\x09\x0A\x0D\x20-\x7E]/.test(d)) { d = null; } } catch (e) { d = null; } }
			if (d) { result.decoded.push({ kind: 'FromBase64String literal', text: d, analysis: depth < MAX_DECODE_DEPTH ? analyzeCommand(d, depth + 1) : null }); }
		}
		if (/(?:^|[\s"'(])(?:java|vb)script:/i.test(text)) { addH('LOT-H-008', (text.match(/(?:java|vb)script:/i) || [''])[0]); }
		if (WRITABLE_RE.test(text)) { addH('LOT-H-009', (text.match(WRITABLE_RE) || [''])[0]); }
		const ads = text.match(ADS_RE);
		if (ads && !/^[a-z]:/i.test(ads[0]) && !/(?:https?|ftp):/i.test(text.slice(Math.max(0, ads.index - 8), ads.index + ads[0].length))) { addH('LOT-H-010', ads[0].trim()); }
		const url = text.match(URL_RE) || text.match(UNC_RE);
		if (url) { addH('LOT-H-011', url[0].trim()); }
		if (!heur.has('LOT-H-001') && B64_ARG_RE.test(text)) { addH('LOT-H-013', ''); }
		if (de.notes.length) { addH('LOT-H-006', de.notes.join('; ')); }

		result.heuristics = Array.from(heur.values());
		let sev = 'none';
		if (result.binaries.length) { sev = 'info'; }
		for (const b of result.binaries) { sev = maxSev(sev, b.severity); }
		for (const h of result.heuristics) { sev = maxSev(sev, h.severity); }
		for (const d of result.decoded) { if (d.analysis && d.analysis.severity !== 'none') { sev = maxSev(sev, d.analysis.severity); } }
		// A LOLBAS usage that is executed together with obfuscation or remote content is stronger evidence.
		if (sev === 'medium' && result.heuristics.filter(h => RANK[h.severity] >= RANK.medium).length >= 2) { sev = 'high'; }
		result.severity = sev;
		return result;
	}

	/** Analyze one or more command lines (one per line). */
	function analyze(input, options, hooks) {
		const text = String(input == null ? '' : input);
		if (text.length > MAX_INPUT_CHARS) {
			const err = new Error('The input is larger than 5 MB. Split it into smaller parts.');
			err.code = 'TOO_LARGE';
			throw err;
		}
		const onProgress = hooks && typeof hooks.onProgress === 'function' ? hooks.onProgress : null;
		const lines = text.split(/\r?\n/);
		const commands = [];
		const counts = { commands: 0, bySeverity: { high: 0, medium: 0, low: 0, info: 0, none: 0 }, byCategory: {}, binaries: {}, heuristics: {}, skipped: 0 };
		let level = 'none';
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (!line.trim()) { continue; }
			if (counts.commands >= MAX_COMMANDS) { counts.skipped++; continue; }
			// detection runs on the original line; what is kept for the page and the report is masked
			const r = maskResult(analyzeCommand(line, 0), new WeakSet());
			r.line = i + 1;
			counts.commands++;
			counts.bySeverity[r.severity]++;
			level = RANK[r.severity] !== undefined && (level === 'none' || RANK[r.severity] > RANK[level]) ? r.severity : level;
			const all = [r].concat(r.decoded.map(d => d.analysis).filter(Boolean));
			for (const a of all) {
				for (const b of a.binaries) {
					counts.binaries[b.name] = (counts.binaries[b.name] || 0) + 1;
					for (const m of b.matches) { counts.byCategory[m.category] = (counts.byCategory[m.category] || 0) + 1; }
				}
				for (const h of a.heuristics) { counts.heuristics[h.id] = (counts.heuristics[h.id] || 0) + 1; }
			}
			commands.push(r);
			if (onProgress && (i % 200 === 0)) { onProgress(i, lines.length); }
		}
		if (onProgress) { onProgress(lines.length, lines.length); }
		return { engine: VERSION, ruleset: RULESET_VERSION, data: { commit: DATA.meta.commit, commitDate: DATA.meta.commitDate, entries: DATA.meta.entries, commands: DATA.meta.commands, license: DATA.meta.license }, level, counts, commands };
	}

	return {
		VERSION,
		RULESET_VERSION,
		MAX_INPUT_CHARS,
		DATA_META: DATA.meta,
		HEURISTICS: Object.keys(HEURISTICS).map(id => ({ id, severity: HEURISTICS[id].severity, title: HEURISTICS[id].title, explanation: HEURISTICS[id].explain })),
		analyze,
		_internal: { findSecrets, maskSecrets, tokenize, deobfuscate, signature, extractCommand, decodeUtf16Base64, analyzeCommand, byName }
	};
}));
