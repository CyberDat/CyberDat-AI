/*!
 * CyberDat System Prompt & Agent Leak Inspector — analysis engine.
 *
 * Contract (enforced by tests):
 *  - input is text: it is never executed, evaluated or sent anywhere; no LLM, API or network access;
 *  - no network, storage, DOM or eval APIs (runs in a Web Worker and in Node for tests);
 *  - results never contain the full prompt or response: only short excerpts. Recognized secrets and any long
 *    value without spaces are masked (first characters and length). Masking is best effort;
 *  - every regular expression is linear or bounded; text comparison has token, memory and time limits.
 * Rules and wording are CyberDat's own. The tool cannot prove that a prompt will not leak.
 */
(function (root, factory) {
	if (typeof module === 'object' && module.exports) { module.exports = factory(); } else { root.CyberDatLeakInspector = factory(); }
}(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const VERSION = '1.0.2';
	const RULESET_VERSION = '2026-11-24.1';
	const MAX_PROMPT_CHARS = 1024 * 1024;
	const MAX_RESPONSE_CHARS = 5 * 1024 * 1024;
	const WARN_CHARS = 1024 * 1024;
	const MAX_PROMPT_TOKENS = 150000;
	const MAX_RESPONSE_TOKENS = 600000;
	const TIME_BUDGET_MS = 15000;
	const MAX_SCAN = 200000;
	const MAX_FINDINGS = 1000;
	const MAX_FRAGMENTS = 200;
	const MAX_DECODE_CANDIDATES = 300;
	const DEFAULT_MIN_WORDS = 8;
	const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };
	const SEVERITIES = ['high', 'medium', 'low', 'info'];

	// ------------------------------------------------------------------ helpers
	/**
	 * JavaScript \b and \w only know ASCII letters, so Cyrillic and umlaut words never matched. Rewrite them with
	 * Unicode classes, without look-behind (unsupported in older Safari): a word start consumes one separator,
	 * a word end is a look-ahead.
	 */
	const WORD_END = '(?![\\p{L}\\p{N}_])';
	const WORD_START = '(?:^|[^\\p{L}\\p{N}_])';
	function ub(re) {
		const src = re.source;
		let out = '';
		for (let i = 0; i < src.length; i++) {
			const c = src[i];
			if (c === '\\' && src[i + 1] === 'b') {
				const prev = out[out.length - 1] || '';
				const end = /[A-Za-z0-9)*}\]+.Ѐ-ӿÀ-ɏ]/.test(prev) && !/\(\?:$/.test(out);
				out += end ? WORD_END : WORD_START;
				i++;
			} else if (c === '\\' && src[i + 1] === 'w') {
				out += '[\\p{L}\\p{N}_]';
				i++;
			} else if (c === '\\') {
				out += c + src[i + 1];
				i++;
			} else {
				out += c;
			}
		}
		return new RegExp(out, re.flags.includes('u') ? re.flags : re.flags + 'u');
	}
	const cap = (s, n) => (s.length > n ? s.slice(0, n) : s);
	function lineOf(text, index) { let n = 1; for (let i = 0; i < index && i < text.length; i++) { if (text.charCodeAt(i) === 10) { n++; } } return n; }
	function lineIndex(text) { const starts = [0]; for (let i = 0; i < text.length; i++) { if (text.charCodeAt(i) === 10) { starts.push(i + 1); } } return pos => { let lo = 0, hi = starts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= pos) { lo = mid; } else { hi = mid - 1; } } return lo + 1; }; }
	function mask(v) {
		const s = String(v);
		if (s.length < 8) { return '•••• (' + s.length + ' characters)'; }
		return s.slice(0, Math.min(4, Math.floor(s.length / 5))) + '…•••• (' + s.length + ' characters)';
	}
	// Long values without spaces are masked even when no rule recognizes them (lesson from the MCP Checker review).
	const LONG_VALUE = /[A-Za-z0-9+/=_\-.~:@%!$#*]{20,}/g;
	function maskLongValues(s) {
		return String(s).replace(LONG_VALUE, v => ((v.length >= 32 || (/[A-Za-z]/.test(v) && /[0-9]/.test(v))) ? mask(v) : v));
	}

	// ------------------------------------------------------------------ secrets
	const TOKEN_FORMATS = [
		['Private key', /-----BEGIN[ A-Z]{0,40}PRIVATE KEY-----/],
		['GitHub fine-grained token', /github_pat_[A-Za-z0-9_]{40,255}/],
		['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{30,255}/],
		['GitLab token', /\bglpat-[A-Za-z0-9_-]{20,64}/],
		['Slack token', /\bxox[abposr]-[A-Za-z0-9-]{10,200}/],
		['Slack webhook URL', /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9+/_-]{8,200}/],
		['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,200}/],
		['OpenAI API key', /(?:^|[^A-Za-z0-9])(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200})/],
		['AWS access key ID', /(?:^|[^A-Z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])/],
		['AWS secret access key', /(?:^|[^A-Za-z0-9/+])([A-Za-z0-9/+]{20,40}EXAMPLEKEY)(?![A-Za-z0-9/+])/],
		['Google API key', /AIza[0-9A-Za-z_-]{35}/],
		['Stripe secret key', /\b[rs]k_live_[0-9A-Za-z]{10,200}/],
		['JSON Web Token', /\beyJ[A-Za-z0-9_-]{10,4000}\.eyJ[A-Za-z0-9_-]{5,4000}\.[A-Za-z0-9_-]{0,4000}/],
		['npm token', /\bnpm_[A-Za-z0-9]{36}\b/],
		['Hugging Face token', /\bhf_[A-Za-z0-9]{30,40}\b/]
	];
	function findTokens(text) {
		const out = [];
		const t = cap(String(text), MAX_SCAN);
		for (const [type, re0] of TOKEN_FORMATS) {
			const re = new RegExp(re0.source, 'g');
			let m, n = 0;
			while ((m = re.exec(t)) && n++ < 50) {
				const v = m[1] || m[0];
				if (type === 'OpenAI API key' && (/^sk-ant-/.test(v) || !/[0-9]/.test(v))) { continue; }
				if (!out.some(o => o.value.includes(v) || v.includes(o.value))) { out.push({ type, value: v, index: m.index + (m[0].length - v.length) }); }
				if (m[0].length === 0) { re.lastIndex++; }
			}
		}
		return out;
	}
	const PLACEHOLDER = /^(?:<[^<>]{1,80}>|\[[^\[\]]{1,80}\]|\{\{?[^{}]{1,80}\}?\}|\$\{[^{}]{1,80}\}|your[-_ .].{0,60}|x{3,}|\*{3,}|\.{3,}|changeme|placeholder|example|redacted|none|null)$/i;
	const SECRET_WORD = '(?:password|passwd|passcode|passphrase|secret|api[ _-]?key|access[ _-]?key|token|credentials?|passwort|kennwort|zugangsdaten|пароль|токен|ключ(?: api)?)';
	const ASSIGN = ub(new RegExp('\\b' + SECRET_WORD + '\\b[^\\n.,;:=]{0,24}?(?:\\s(?:is|ist|lautet|равен|это)\\s|\\s?[:=]\\s?|\\s[—–]\\s)\\s*["\'`]?([^\\s"\'`,;<>]{6,120})', 'gi'));
	function literalSecret(v) {
		const s = v.replace(/[.)\]]+$/, '');
		if (s.length < 6 || PLACEHOLDER.test(s) || /^https?:/i.test(s)) { return null; }
		if (!(/[0-9]/.test(s) || /[^A-Za-z\u00C0-\u024F\u0400-\u04FF]/.test(s) || s.length >= 12)) { return null; }
		return s;
	}
	function findSecrets(text) {
		const t = cap(String(text), MAX_SCAN);
		const out = findTokens(t).map(x => ({ kind: 'token', type: x.type, value: x.value, index: x.index }));
		let m, n = 0;
		const re = new RegExp(ASSIGN.source, ASSIGN.flags); // keep the u flag: ASSIGN uses Unicode word starts
		while ((m = re.exec(t)) && n++ < 200) {
			const v = literalSecret(m[1]);
			if (v && !out.some(o => o.value.includes(v) || v.includes(o.value))) { out.push({ kind: 'assignment', type: 'secret value', value: v, index: m.index + m[0].lastIndexOf(m[1]) }); }
		}
		const conn = /\b([a-z][a-z0-9+.-]{1,20}):\/\/([^\s:/@"'<>]{1,100}):([^\s@"'<>]{3,200})@([^\s/"'<>]{1,253})/gi;
		n = 0;
		while ((m = conn.exec(t)) && n++ < 100) {
			if (PLACEHOLDER.test(m[3]) || /^\$\{|^\{\{|^%/.test(m[3])) { continue; }
			if (!out.some(o => o.value === m[3])) { out.push({ kind: 'connection', type: m[1].toLowerCase() + ' connection password', value: m[3], index: m.index + m[0].indexOf(':' + m[3] + '@') + 1, host: m[4] }); }
		}
		return out;
	}

	// ------------------------------------------------------------------ prompt audit rules (CyberDat wording)
	const GROUPS = {
		secrets: 'Secrets in the prompt', internal: 'Internal details', business: 'Confidential business logic', protection: 'Weak protection',
		input: 'Untrusted input', tools: 'Tool permissions', autonomy: 'Autonomous actions', pii: 'Personal data',
		leak: 'Prompt leak in the response'
	};
	const ARCH = 'Anything in a system prompt should be treated as readable by users: models can be talked into repeating it. Keep secrets and sensitive rules outside the prompt and enforce them in code.';
	const R = {
		'LKI-SEC-001': ['secrets', 'Credential with a known format in the prompt', 'The value has the format of a real credential. If the prompt leaks, the credential leaks with it. ' + ARCH, 'Remove the credential from the prompt, rotate it, and let the backend attach it to tool or API calls.'],
		'LKI-SEC-002': ['secrets', 'Password or secret written in the prompt', 'A password, key or token is written directly in the instructions. ' + ARCH, 'Remove the value and rotate it. Give the model a tool that performs the privileged action instead of the credential itself.'],
		'LKI-SEC-003': ['secrets', 'Connection string with a password', 'The prompt contains a connection address with an embedded password, which reveals both the system and its credential.', 'Remove the connection string and rotate the password. Connect from the backend with a least-privilege account.'],
		'LKI-INT-001': ['internal', 'Internal host or address', 'Private IP addresses and internal host names describe your network to anyone who extracts the prompt.', 'Remove internal addresses. If the assistant needs a service, call it through a backend tool.'],
		'LKI-INT-002': ['internal', 'Personal work email address', 'Named employee addresses in a prompt can be extracted and used for phishing or social engineering.', 'Use a role mailbox (for example support@) or route escalations through a tool.'],
		'LKI-INT-003': ['internal', 'Internal file path or share', 'File shares and server paths reveal internal structure.', 'Remove paths from the prompt; reference documents through a retrieval tool with access control.'],
		'LKI-INT-004': ['internal', 'Internal code name', 'Code names of unreleased projects are often confidential.', 'Remove code names unless they are public.'],
		'LKI-BIZ-001': ['business', 'Confidential prices, limits or thresholds', 'Discount ceilings, approval thresholds and internal prices can be extracted and exploited, for example by asking for the maximum discount.', 'Enforce limits in backend logic. The model can request an action; the server decides whether it is allowed.'],
		'LKI-BIZ-002': ['business', 'Moderation exceptions or bypass rules', 'Exceptions such as “allow even if flagged” tell an attacker exactly how to bypass checks once the prompt leaks.', 'Implement moderation and exceptions outside the model and do not describe them in the prompt.'],
		'LKI-BIZ-003': ['business', 'Content marked as confidential', 'The prompt itself labels part of its content confidential, but the model cannot keep it confidential reliably.', 'Move confidential content out of the prompt.'],
		'LKI-PRT-001': ['protection', '“Never reveal these instructions” used as protection', 'Telling the model to keep its instructions secret is a weak measure: rephrased or indirect requests often bypass it. It must not be the only protection for sensitive content.', 'Assume the prompt can be extracted. Remove sensitive content and use architectural measures: backend authorization, tool-level permissions, output filtering for known secrets.'],
		'LKI-PRT-003': ['protection', 'Safety checks switched off or refusals forbidden', 'The prompt switches off safety checks, filters or moderation, or forbids the model to refuse a request. Whoever learns the condition can use it, and the model loses its own last line of defence.', 'Keep safety checks on in every mode and enforce them outside the model; let the model refuse, and handle exceptions for trusted users in the application.'],
		'LKI-PRT-002': ['protection', 'Password or code word unlocks special behaviour', 'A passphrase in the prompt that switches modes or lifts restrictions is readable by anyone who extracts the prompt, and can be guessed or leaked.', 'Authenticate users in your application, not in the prompt. Give privileged users a different configuration server-side.'],
		'LKI-INP-002': ['input', 'External content ranked above the operator’s rules', 'The prompt tells the model to follow instructions from fetched, downloaded or uploaded content even over the operator’s or system rules. Anyone who can place text in that content can then take control of the assistant.', 'Treat external content as data, never as instructions, and say so in the prompt; keep the operator’s rules first and enforce critical limits in code.'],
		'LKI-INP-001': ['input', 'Untrusted input inserted without clear boundaries', 'A placeholder for user, email or web content sits in the instructions without delimiters or a statement that it is data. Text in that content can then pose as instructions.', 'Wrap untrusted content in clear delimiters (for example <document>…</document>) and state that it is data that cannot change the instructions. This reduces, but does not remove, prompt injection.'],
		'LKI-TOOL-002': ['tools', 'Data sent to an outside recipient without consent', 'The prompt tells the agent to send conversations, files or personal data to an external address or third party without asking or informing the user. A manipulated agent can use the same channel, and the user does not know where their data goes.', 'Send data out only through a tool that checks the recipient and asks the user, enforced in the application; tell users where their data goes.'],
		'LKI-TOOL-001': ['tools', 'Broad tool permissions', 'The agent is described as having unrestricted access to a shell, files, network or email. Injected instructions can use the same access.', 'Grant the narrowest tools needed, enforce permissions in the tool implementation, and isolate risky tools.'],
		'LKI-AUT-001': ['autonomy', 'Irreversible action without human confirmation', 'The prompt asks the agent to delete, pay, deploy or block automatically. A manipulated or mistaken model can then cause irreversible damage.', 'Require explicit human confirmation for irreversible actions, enforced by the application, not only by the prompt.'],
		'LKI-PII-001': ['pii', 'Personal data in the prompt', 'Names, phone numbers, email or postal addresses of customers or people in a prompt can be extracted by other users.', 'Retrieve personal data per request through an access-controlled tool and only for the authorized user.'],
		'LKI-PII-002': ['pii', 'Bank or card number in the prompt', 'Valid IBAN or payment card numbers in a prompt can be extracted and misused.', 'Remove financial identifiers from the prompt; look them up server-side when needed.'],
		'LKC-001': ['leak', 'Verbatim prompt text in the response', 'A sequence of words from the reference prompt appears unchanged in the response.', 'Review why the response repeats the prompt. Remove sensitive content from the prompt and consider output filtering for distinctive prompt passages.'],
		'LKC-002': ['leak', 'Near-verbatim prompt text in the response', 'After normalizing case, spacing, punctuation and invisible characters, a sequence of words from the prompt appears in the response.', 'Treat this like a verbatim leak: formatting changes do not hide the content.'],
		'LKC-003': ['leak', 'Prompt text hidden in encoded form', 'Part of the response decodes (Base64, hex or URL encoding) to text from the reference prompt. Encoding is a common way to slip prompt content past simple filters.', 'Decode-and-compare checks on output can catch this; also review how the encoded content was requested.'],
		'LKC-004': ['leak', 'Many prompt phrases reused (overlap measure)', 'This is a similarity measure, not a verdict: it shows how many of the prompt’s three-word phrases also appear in the response. A close paraphrase scores high; an unrelated answer scores low.', 'Read the matched phrases. A high share may indicate a paraphrased leak; a low share does not prove there was none.'],
		'LKC-005': ['leak', 'Secret from the prompt appears in the response', 'A credential or secret value found in the reference prompt also appears in the response.', 'Rotate the secret immediately and remove it from the prompt.']
	};

	// Sentence splitter that keeps positions; bounded. A dot, question or exclamation mark followed by a non-space
	// character (addresses, host names, decimals) does not end a sentence.
	function sentences(text) {
		const out = [];
		const re = /(?:[^.!?\n]|[.!?](?=[^\s.!?]))+[.!?]*|\n+/g;
		let m, n = 0;
		const t = cap(text, MAX_SCAN);
		while ((m = re.exec(t)) && n++ < 20000) { if (m[0].trim()) { out.push({ text: m[0], index: m.index }); } }
		return out;
	}
	const NEGATION = /\b(?:never|cannot|can't|can not|no|not|without network|keine?n?|nicht|niemals|nie|не|нельзя|никогда)\b/i;
	const RX = {
		privateIp: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g,
		internalHost: /\b(?:[a-z0-9-]{1,63}\.){0,6}(?:[a-z0-9-]{1,63}\.(?:internal|corp|local|lan|intranet|localdomain|home\.arpa)\b|intranet\.[a-z0-9.-]{2,100}|[a-z0-9-]{1,63}\.(?:internal|corp|intranet)\.[a-z0-9.-]{2,100})/gi,
		// Local parts and domains may contain any letters and combining marks (jürgen@, иван@, NFD); the address is group 1.
		email: /(?:^|[^\p{L}\p{N}\p{M}._%+-])([\p{L}\p{N}_%+-][\p{L}\p{N}\p{M}._%+-]{0,63}@[\p{L}\p{N}][\p{L}\p{N}\p{M}.-]{0,252}\.\p{L}[\p{L}\p{M}]{1,23})(?![\p{L}\p{N}\p{M}])/gu,
		roleMailbox: /^(?:support|info|help|hilfe|contact|kontakt|sales|noreply|no-reply|privacy|security|hello|team|service|office|press|jobs|billing|admin|webmaster|abuse)$/i,
		uncPath: /\\\\[A-Za-z0-9._$-]{1,63}\\[^\s"'<>]{1,200}/g,
		unixPath: /(?:^|[\s"'(=])(\/(?:srv|home|opt|var|etc|mnt|data|share|internal)\/[^\s"'<>),;]{1,200})/g,
		winPath: /\b[A-Za-z]:\\(?:Users|Shares?|Data|Finance|HR|Internal)\\[^\s"'<>]{1,200}/g,
		codename: ub(/\b(?:code ?name|codename|internal project name|kodename|кодов(?:ое|ым) назван\w*)\b|\bproject\s+[A-Z][A-Z0-9]{3,}\b/i),
		percent: /\b\d{1,3}(?:[.,]\d{1,2})?\s?%/,
		// Percentages written in words (EN, DE, RU): "forty percent", "dreißig Prozent", "сорок процентов".
		percentWords: ub(/\b(?:(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|a hundred|hundred)(?:[- ](?:one|two|three|four|five|six|seven|eight|nine))?\s+(?:percent|per cent)|(?:ein|zwei|drei|vier|fünf|sechs|sechzehn|sieben|siebzehn|acht|neun|zehn|elf|zwölf|fünfzehn|zwanzig|dreißig|dreissig|vierzig|fünfzig|sechzig|siebzig|achtzig|neunzig|hundert)\w{0,20}\s+prozent|(?:один|одн|два|две|три|четыр|пят|шест|сем|восем|девят|десят|одиннадцат|двенадцат|двадцат|тридцат|сорок|девяносто|сто|половин)\w{0,10}\s+(?:\w{1,15}\s+)?процент\w*)\b/i),
		// Concessions and limits that the prompt hides: hidden rebates, undisclosed ceilings or floors (business logic).
		concession: ub(/\b(?:rebate\w*|markdown\w*|concession\w*|price cut\w*|nachlass\w*|preisnachlass\w*|abschl[aä]g\w*|zugeständnis\w*|entgegenkommen|уступк\w*|уступ(?:и|а)\w*)\b/i),
		limitWord: ub(/\b(?:ceiling|cap|maximum|floor|minimum|lowest price|bottom line|walk-?away price|obergrenze|untergrenze|höchst\w*|mindest\w*|maximal\w*|grenze|потол\w*|предел\w*|максимальн\w*|минимальн\w*|границ\w*)\b/i),
		conceal: ub(/\b(?:conceal\w*|hidden|hide\w*|secret\w*|unpublished|undisclosed|keep (?:it|this|that|these|those|the \w+) (?:to yourself|private|secret|quiet)|keep (?:it|this|that) to yourself|(?:never|do not|don't) (?:mention|reveal|disclose|tell|state)|geheim\w*|verborgen\w*|versteckt\w*|verrate\w* (?:\w+ ){0,3}nicht|nicht (?:verraten|nennen|erwähnen|mitteilen)|nenne (?:\w+ ){0,3}(?:niemals|nie|nicht)|bleib\w* (?:\w+ ){0,1}(?:intern|vertraulich)|nicht offen\w*|wird nicht (?:\w+ ){0,1}(?:genannt|mitgeteilt)|keep (?:\w+ ){0,3}(?:internal|confidential|to yourself)|nur intern|не озвучива\w*|скрыт\w*|секретн\w*|тайн\w*|не (?:сообщай|раскрывай|говори|называй|упоминай|разглашай))\b/i),
		money: ub(/(?:[$€£]\s?\d[\d.,]{0,12}|\b\d[\d.,]{0,12}\s?(?:eur|euro|usd|dollars?|gbp|rub|руб\w*|€|\$)\b)/i),
		threshold: ub(/\b(?:below|under|above|over|less than|more than|fewer than|at least|at most|up to|bis zu|unter|über|mindestens|höchstens|до|ниже|выше|не более|не менее)\b[^.\n]{0,20}?\d/i),
		bizWord: ub(/\b(?:discount|rabatt|rebate\w*|markdown\w*|concession\w*|nachlass\w*|preisnachlass\w*|zugeständnis\w*|уступк\w*|скидк\w*|refund\w*|erstattung\w*|возврат\w*|price\w*|preis\w*|цен\w*|cost\w*|kosten|стоимост\w*|approve\w*|genehmig\w*|одобр\w*|limit\w*|grenze|лимит\w*|threshold|schwelle|порог\w*|score|reputation|rating|bonus|commission|provision|наценк\w*|закупочн\w*|purchase price|einkaufspreis|list price|below list|listenpreis\w*|прайс\w*|прейскурант\w*)\b/i),
		bypass: ub(/\b(?:even if (?:the )?(?:spam )?(?:filter|system|check|moderation)?\s*(?:flags?|blocks?|rejects?)|shadow-?ban\w*|bypass\w*|whitelist\w*|allowlist\w*|skip (?:the )?(?:check|review|moderation)|silently (?:remove|delete|ban|block|approve)|ohne prüfung|trotz (?:sperre|markierung)|в обход|без проверки|даже если (?:фильтр|система))\b/i),
		confidential: ub(/\b(?:confidential|internal only|internal use only|do not share with (?:customers|users)|vertraulich|nur intern|конфиденциальн\w*|только для внутреннего)\b/i),
		secrecy: ub(/\b(?:never|do not|don't|under no circumstances|in no case)\b[^.\n]{0,40}?\b(?:reveal|disclose|share|repeat|show|output|tell)\b[^.\n]{0,30}?\b(?:these |this |the |your |my )?(?:instructions|system prompt|prompt|rules|guidelines|configuration)\b|\b(?:niemals|nie|keinesfalls)\b[^.\n]{0,40}?\b(?:anweisungen|systemprompt|system-prompt|regeln)\b[^.\n]{0,30}?\b(?:preis\w*|verrat\w*|offenleg\w*|weiter\w*)|(?:не\s+раскрыва\w*|не\s+показыва\w*|не\s+разглаша\w*|не\s+сообща\w*)[^.\n]{0,40}?(?:инструкци\w*|системн\w+ промпт\w*|промпт\w*|правил\w*)/i),
		gate: ub(/\b(?:passphrase|password|pass ?word|code ?word|secret word|kennwort|passwort|codewort|кодов\w+ слов\w*|пароль)\b[^.\n]{0,80}?\b(?:admin(?:istrator)? mode|developer mode|debug mode|god mode|unlock\w*|ignore (?:all )?(?:content )?restrictions|lift (?:all )?restrictions|entwicklermodus|adminmodus|einschränkungen (?:aufheben|ignorieren)|hebe alle einschränkungen|режим администратора|режим разработчика|сними все ограничения)/i),
		placeholder: /\{\{\s*[A-Za-z_][A-Za-z0-9_.-]{0,60}\s*\}\}|\{[A-Za-z_][A-Za-z0-9_]{0,60}\}|\$\{[A-Za-z_][A-Za-z0-9_.]{0,60}\}|<<\s*[A-Za-z_][A-Za-z0-9_]{0,60}\s*>>|\[\[\s*[A-Za-z_][A-Za-z0-9_]{0,60}\s*\]\]|%\([A-Za-z_][A-Za-z0-9_]{0,60}\)s/g,
		dataStatement: ub(/\b(?:untrusted|treat (?:it |them |the [a-z ]{1,30})?(?:as|strictly as) (?:data|content)|(?:is|are) data,? not instructions|do not follow (?:any )?instructions|ignore (?:any )?instructions (?:that appear |inside|in )|cannot change (?:these|the) instructions|als daten|keine anweisungen|как данные|не являются инструкциями)\b/i),
		toolBroad: ub(/\b(?:unrestricted|unlimited|full|complete|root|administrator|admin|any|all)\b[^.\n]{0,30}?\b(?:shell|command line|terminal|commands?|file ?system|files|network|internet|e-?mails?|mailbox(?:es)?|inbox(?:es)?|database|servers?)\b(?:[^.\n]{0,20}?\b(?:access|permissions?|rights)\b)?|\brun any command\b|\bsend (?:e-?mails? )?to any (?:address|recipient)\b|\bread all (?:mailboxes|files|e-?mails)\b|\b(?:vollen?|uneingeschränkten?)\b[^.\n]{0,40}?\b(?:zugriff|zugang)\b|\bgesamte[n]? dateisystem\b|полн\w+ доступ|любые команды|неограниченн\w+ доступ/i),
		irreversible: ub(/\b(?:delet\w*|remov\w*|drop\w*|wip\w*|purg\w*|transfer\w*|wire|pay\w*|refund\w*|charg\w*|deploy\w*|publish\w*|block\w*|ban\w*|terminat\w*|cancel\w*|lösch\w*|überweis\w*|bereitstell\w*|sperr\w*|удал\w*|списыва\w*|списыв\w*|блокир\w*|перевод\w*|оплач\w*|erase\w*|destroy\w*|settle\w*|format\w* (?:the |all |every )?(?:\w+ )?(?:disks?|drives?|partitions?|volumes?)|bezahl\w*|zahle|zahlt|auszahl\w*|zahl\w* (?:\w+ ){0,3}aus|begleich\w*|abbuch\w*|entfern\w*|vernicht\w*|zerstör\w*|formatier\w*|оплат\w*|плати\w*|возврат\w*|выплат\w*|плат[её]ж\w*|erstatt\w*|rückerstatt\w*|(?:очищ|очист)\w* (?:\w+ ){0,3}(?:резерв|архив|баз|данн|запис|журнал|бэкап|копи)\w*|перечисл\w*|переводи\w*|стира\w*|стир\w*|сотри\w*|сотрё\w*|сотре\w*|уничтож\w*|форматир\w*)/i),
		noConfirm: ub(/\b(?:without (?:asking|any )?(?:for )?(?:confirmation|approval|asking|review|human)|do not (?:wait for|ask for) (?:human )?(?:approval|confirmation)|don't (?:wait for|ask for) (?:human )?(?:approval|confirmation)|no (?:human )?(?:approval|confirmation) (?:is )?(?:needed|required)|automatically|on your own|ohne (?:nachzufragen|bestätigung|rückfrage|freigabe)|automatisch|без подтверждения|не запрашивая подтверждени\w*|автоматически|самостоятельно)\b|ohne nachzufragen|не запрашивая подтверждения/i),
		// Human confirmation explicitly not needed, in more word orders and forms (EN, DE, RU).
		noConfirm2: ub(/\b(?:without (?:any |a |an |the |prior |explicit |first )?(?:\w+(?:'s)? )?(?:confirmation|approval|sign-?off|consent|permission)|without (?:waiting for|checking with)|(?:no|not) (?:\w+(?:'s)? ){0,2}(?:approval|confirmation|sign-?off|consent|permission) (?:is |are )?(?:needed|required|necessary)|(?:approval|confirmation|sign-?off|consent|permission) (?:is |are )?not (?:needed|required|necessary)|(?:you )?(?:do not|don't) need (?:\w+(?:'s)? ){0,2}(?:approval|confirmation|permission|consent|sign-?off)|ohne (?:\w+ ){0,3}(?:bestätigung|freigabe|rückfrage|zustimmung|genehmigung|einwilligung)\w*|ohne (?:\w+ ){0,3}(?:einzuholen|abzuwarten|zu fragen|nachzufragen|zu warten)|(?:bestätigung|freigabe|rückfrage|zustimmung|genehmigung)\w* (?:\w+ ){0,4}(?:ist|sind) nicht (?:nötig|notwendig|erforderlich)|selbstständig|selbständig|eigenständig|без (?:\w+ ){0,2}(?:подтвержд|согласи|одобрен|разрешени|согласован|санкци)\w*|не дожидаясь|не (?:спрашивая|согласовывая)|(?:подтвержд|согласи|одобрен|разрешени|согласован)\w* (?:\w+ ){0,2}не (?:нужн\w*|требуется|обязательн\w*))\b/i),
		// Data sent to an outside recipient without the user's consent (tools).
		sendVerb: ub(/\b(?:send\w*|sent|forward\w*|upload\w*|post\w*|transmit\w*|share\w*|sync\w*|export\w*|push\w*|relay\w*|mirror\w*|leit\w*|weiterleit\w*|schick\w*|übermittel\w*|übertrag\w*|hochlad\w*|lad\w* (?:\w+ ){0,6}hoch|teil\w*|exportier\w*|spiegel\w*|пересыла\w*|перешл\w*|отправл\w*|отправ\w*|переда\w*|выгружа\w*|загружа\w*|дублир\w*|слива\w*)\b/i),
		dataObj: ub(/\b(?:conversations?|chats?|transcripts?|dialog\w*|messages?|history|logs?|files?|attachments?|uploads?|recordings?|(?:personal|customer|user) data|chatverl\w*|gespräch\w*|unterhaltung\w*|nachricht\w*|verlauf\w*|datei\w*|anh[aä]ng\w*|daten|protokoll\w*|переписк\w*|диалог\w*|разговор\w*|сообщени\w*|истори\w*|файл\w*|вложени\w*|данн\w*|журнал\w*)\b/i),
		outside: ub(/https?:\/\/|\b[\p{L}\p{N}._%+-]{1,64}@[\p{L}\p{N}-]{1,63}\.[\p{L}.]{2,30}|\b(?:[a-z0-9-]{1,63}\.){1,4}(?:com|org|net|io|de|ru|eu|info|biz|example|invalid|test)\b|\b(?:external|third[- ]party|outside|partner\w*|vendor\w*|extern\w*|dritt\w*|fremd\w*|anbieter\w*|внешн\w*|сторонн\w*|партн\w*|чуж\w*)\b/i),
		noConsent: ub(/\b(?:without (?:\w+(?:'s)? ){0,3}(?:consent|permission|knowledge|asking|telling|informing|notice|notifying|approval)\w*|silently|secretly|covertly|quietly|behind (?:the )?(?:user|customer)'?s? back|(?:does|do) not need to (?:be )?(?:informed|asked|told|notified)|no need to (?:ask|tell|inform|notify)|(?:never|do not|don't) (?:tell|inform|notify|ask) (?:the )?(?:users?|customers?|clients?)|ohne (?:\w+ ){0,3}(?:zustimmung|einwilligung|wissen|erlaubnis|benachrichtigung)\w*|ohne (?:\w+ ){0,3}(?:zu fragen|zu informieren|nachzufragen)|stillschweigend|heimlich|unbemerkt|без (?:\w+ ){0,2}(?:согласи|ведома|спроса|уведомлен|разрешени|предупрежден)\w*|не (?:спрашивая|сообщая|уведомляя|предупреждая)|молча|тайно|незаметно|скрытно)\b/i),
		// External content ranked above the operator's rules (input): source ... priority ... operator rules, in this order.
		extSource: ub(/\b(?:fetched|retrieved|downloaded|uploaded|scraped|crawled|incoming|attached|web ?pages?|websites?|e-?mails?|documents?|attachments?|files?|search results?|tool (?:outputs?|results?|responses?)|pdfs?|heruntergeladen\w*|abgerufen\w*|hochgeladen\w*|webseite\w*|website\w*|e-mail\w*|dokument\w*|anh[aä]ng\w*|datei\w*|suchergebnis\w*|internet\w*|скачанн\w*|загруженн\w*|извлечённ\w*|извлеченн\w*|найденн\w*|страниц\w*|сайт\w*|письм\w*|документ\w*|вложени\w*|файл\w*|интернет\w*)\b/i),
		priority: ub(/\b(?:более важн\w*|(?:take|takes|have|has|get|gets|be given) (?:\w+ ){0,1}(?:precedence|priority) over|(?:more important|higher priority|more authoritative|weightier) than|override\w*|outrank\w*|supersede\w*|even (?:if|when) (?:they|it|this|these) (?:conflict|contradict|clash)\w*|(?:haben|hat|genießen|bekommen) (?:\w+ ){0,2}vorrang vor|wichtiger als|(?:stehen|steht) über|überschreib\w*|außer kraft|auch wenn (?:sie|es|diese) (?:\w+ ){0,3}widersprech\w*|важнее|приоритетн\w*|приоритет над|(?:ставь|ставить|считай|считать) (?:\w+ ){0,4}выше|главнее|отменя\w*|даже если (?:они|оно|это) противореч\w*)\b/i),
		operatorRules: ub(/\b(?:operator\w*|admin\w*|system\w*|developer\w*|owner\w*|platform\w*|your (?:rules|instructions|guidelines|restrictions|policy)|(?:these|the|my|our) (?:rules|instructions|restrictions|guidelines)|betreiber\w*|administrator\w*|vorgaben|regeln|richtlinien|einschränkung\w*|beschränkung\w*|vorschrift\w*|polic(?:y|ies)|anweisungen|политик\w*|оператор\w*|администратор\w*|админ\w*|систем\w*|правил\w*|ограничени\w*|инструкци\w*)\b/i),
		// Safety checks switched off, refusals forbidden (protection).
		safetyOff: ub(/\b(?:disabl\w*|turn\w* off|switch\w* off|shut\w* off|deactivat\w*|bypass\w*|skip\w*|suspend\w*|lift\w*|ignor\w*|deaktivier\w*|abschalt\w*|ausschalt\w*|schalt\w* (?:[\p{L}-]+ ){1,4}aus|umgeh\w*|übergeh\w*|ignorier\w*|außer kraft|отключ\w*|выключ\w*|обход\w*|обойд\w*|игнорир\w*)\b/i),
		safetyTarget: ub(/\b(?:safety\w*|guardrails?|safeguards?|content (?:filters?|polic\w*)|moderation\w*|filters?|(?:security|safety) (?:checks?|rules|polic\w*|restrictions)|sicherheit\w*|schutz\w*|filter\w*|moderation\w*|inhaltsfilter\w*|moderationsfilter\w*|фильтр\w*|модераци\w*|безопасност\w*|защит\w*)\b/i),
		noRefusal: ub(/\b(?:(?:never|do not|don't|must not|mustn't|should not|shall not) (?:ever )?(?:refuse|decline|reject|turn down|say no)|always (?:comply|obey)|(?:lehne|lehnt) (?:\w+ ){0,1}(?:keine|nie|niemals)\w* (?:\w+ ){0,3}ab|verweigere (?:nie|niemals|keine)\w*|(?:nie|niemals) (?:\w+ ){0,1}ablehnen|(?:никогда )?не отказыва\w*|не откажи\w*|всегда (?:выполняй|подчиняйся))\b/i),
		unconditional: ub(/\b(?:whatever|regardless|no matter|even if|even when|under any circumstances|any requests?|every requests?|all requests|a request|for any reason|egal|unabhängig|selbst wenn|auch wenn|jede\w* anfrage|keine\w* anfrage|unter allen umständen|даже если|ни при каких|что бы ни|любо\w*|всех запрос\w*|никаки\w*)\b/i),
		negBefore: ub(/\b(?:never|not|don't|do not|must not|no|nie|niemals|nicht|kein\w*|не|никогда|нельзя)\s+(?:[\p{L}-]+\s+){0,2}$/i),
		// Prohibition or negation in the clause of an action (round 12): "never send", "do not delete", "Lösche niemals",
		// "запрещено передавать", "… is forbidden". See prohibitedAt().
		negWord: ub(/\b(?:never|not|cannot|can't|don't|doesn't|won't|mustn't|shouldn't|isn't|aren't|no|nobody|forbidden|prohibited|nie|niemals|nicht|kein\w*|keinesfalls|verboten|untersagt|не|ни|никогда|нельзя|запрещ\w*|недопустим\w*)\b/i),
		// Words about asking, waiting, approval or consent: a negation that governs one of them ("не спрашивая", "no need
		// to ask", "do not wait for approval") is the absence of a check, not a prohibition of the action.
		confirmWord: ub(/\b(?:ask\w*|wait\w*|confirm\w*|approv\w*|consent\w*|permission\w*|inform\w*|tell\w*|notif\w*|check\w*|need\w*|requir\w*|sign\w*|matter|longer|later|only|frag\w*|wart\w*|bestätig\w*|zustimm\w*|freigab\w*|freigeb\w*|einwillig\w*|informier\w*|benachrichtig\w*|nötig|notwendig|erforderlich|nur|lediglich|спраш\w*|спрос\w*|дожида\w*|ожида\w*|жд\w*|подтвержд\w*|соглас\w*|уведом\w*|сообща\w*|предупрежд\w*|нужн\w*|требу\w*|запрашива\w*|только)\b/i),
		prohibPred: ub(/\b(?:forbidden|prohibited|not (?:allowed|permitted)|verboten|untersagt|nicht (?:erlaubt|gestattet|zulässig)|unzulässig|запрещ\w*|не допуска\w*|недопустим\w*|не разреша\w*)\b/i),
		negAfterDe: ub(/^(?:\s+[\p{L}-]+){0,2}?\s+(?:nie|niemals|nicht|keine?\w*)\b(?!\s+(?:nur|erst)\b)/i),
		leadNeg: ub(/\b(?:never|do not|don't|must not|niemals|nie|keinesfalls|auf keinen fall|unter keinen umständen|under no circumstances|in no case|никогда|ни в коем случае|ни при каких \p{L}+)\s*,\s*(?:[^,;:]{0,40},\s*)?$/i),
		// Concealment words that are adjectives can be negated: "there are no secret discounts", "keine geheimen Grenzen".
		concealAdj: ub(/^[^\p{L}]?(?:conceal|hidden|hide|secret|unpublished|undisclosed|confidential|geheim|verborgen|versteckt|vertraulich|скрыт|секретн|тайн|конфиденциальн)/i),
		noExistBefore: ub(/\b(?:no|without|keine?\w*|ohne|никаких|нет|без|ни)\s+(?:[\p{L}-]+\s+){0,2}$/i),
		noExist: ub(/\b(?:there (?:are|is) no|we (?:have|use|offer|keep) no|gibt es nicht|es gibt keine\w*|у нас нет|нет|не существу\w*|отсутству\w*|don't exist|do not exist|existier\w* nicht)\b/i),
		// Prices the customer is meant to know: published, listed, agreed, allowed to be told.
		publicMark: ub(/\b(?:public\w*|published|listed|advertised|announced|official\w*|website|pricing page|price list|catalog\w*|catalogue|brochure|agreed|terms (?:and conditions|of service)|tell anyone|share (?:it |them )?(?:freely|with anyone)|öffentlich\w*|veröffentlicht\w*|preisliste\w*|katalog\w*|offiziell\w*|webseite\w*|vereinbart\w*|agb|geschäftsbedingungen|offen (?:kommuniziert|genannt)|публичн\w*|опубликован\w*|официальн\w*|на сайте|каталог\w*|согласованн\w*|можно (?:говорить|сообщать|называть))\b/i),
		// Absence of a human check in more forms (round 12): no approval step, on its own, no human in the loop,
		// "eine Freigabe ist nicht vorgesehen", "без участия человека".
		noConfirm3: ub(/\b(?:(?:there is |there's )?no (?:human |manual |prior |separate )?(?:approval|confirmation|sign-?off|review|checkpoint)(?: step| stage| gate| check)?|(?:does not|doesn't|do not|don't|will not) (?:need to )?(?:require|need) (?:any |a |an |the )?(?:\w+(?:'s)? )?(?:approval|confirmation|sign-?off|consent|review)|on (?:its|their|his|her) own|by (?:itself|yourself|themselves)|autonomously|at (?:its|their) own discretion|(?:with )?no human in the loop|without (?:a |any )?human(?: in the loop| involvement| oversight| participation| review| intervention| input)?|without (?:a |any )?(?:person|anyone|someone|operator|staff|employee|manager|colleague)\w*(?: (?:reviewing|approving|checking|confirming|signing))?|without involving (?:a |any )?(?:human|person|operator|anyone)|(?:nobody|no one|no (?:\w+ )?(?:manager|human|person|employee|operator|admin\w*|colleague|supervisor|staff)) (?:needs|has|is required) to (?:approve|confirm|sign|review|check)|(?:approval|confirmation|sign-?off) (?:is |are )?optional|(?:freigabe|bestätigung|zustimmung|genehmigung|rückfrage|abstimmung|prüfung)\w* (?:[\p{L}-]+ ){0,5}(?:nicht|kein\w*) (?:[\p{L}-]+ )?(?:nötig|notwendig|erforderlich|vorgesehen|verlangt|gefordert)|(?:freigabe|bestätigung|zustimmung|genehmigung|rückfrage|abstimmung|prüfung|kontrolle)\w* (?:[\p{L}-]+ ){0,4}entf[aä]ll\w*|ohne (?:menschliche\w* |manuelle\w* )?(?:beteiligung|mitwirkung|kontrolle|aufsicht|zutun)|ohne dass (?:[\p{L}-]+ ){0,4}(?:zustimmt|prüft|freigibt|bestätigt|eingreift|genehmigt)|eigenmächtig|auf eigene faust|без участия|без (?:\w+ ){0,1}(?:контрол|проверк|вмешательств)\w* (?:человек|оператор|сотрудник|админ)\w*|по своему усмотрению|(?:согласов|подтвержд|одобр|разреш)\w* (?:\w+ ){0,3}не (?:нужн\w*|требуется|обязательн\w*|предусмотрен\w*))\b/i),
		// Sending in indirect wording (round 12): archiving, copying, delivery; "Kopien gehen an …", "уходят на …".
		sendVerb2: ub(/\b(?:archiv\w*|replicat\w*|cop(?:y|ies|ied)|deliver\w*|transfer\w*|weitergab\w*|weitergeb\w*|weiterzugeb\w*|ausleit\w*|ausgeleitet|kopier\w*|zustell\w*|(?:geht|gehen|go|goes) (?:\w+ ){0,3}(?:an|to)|архивир\w*|копир\w*|уход\w*|уйдут|направля\w*|доставля\w*|передач\w*)\b/i),
		dataObjDe: /(?:dialog|gespräch|chatverl|chatprotokoll|unterhaltung|korrespondenz|kundendaten|nutzerdaten|nachrichten|бесед|содержим|расшифровк|correspondence)/i,
		outside2: ub(/\b(?:außerhalb|beyond (?:the |our )?(?:trusted )?(?:perimeter|boundary|network)|contractor\w*|subcontractor\w*|supplier\w*|auftragnehmer\w*|dienstleister\w*|подрядчик\w*|поставщик\w*|за предел\w*|вне (?:\w+ ){0,2}(?:контур|периметр|сет)\w*)\b/i),
		noConsent2: ub(/\b(?:(?:does not|doesn't|do not|don't|will not) (?:need to )?(?:require|need) (?:any |the )?(?:\w+(?:'s)? )?(?:approval|consent|permission|sign-?off|confirmation)|no need to (?:check|confirm|ask|tell|inform|notify|get|obtain)|(?:is|are) not (?:informed|told|notified|asked)|with no (?:\w+(?:'s)? )?(?:consent|approval|permission)|without checking (?:for )?(?:\w+(?:'s)? ){0,2}consent|(?:wird|werden) (?:\w+ ){0,2}nicht (?:informiert|benachrichtigt|gefragt)|(?:prüfung|einholung|abfrage) der (?:einwilligung|zustimmung)\w* entf[aä]ll\w*|(?:einwilligung|zustimmung|freigabe|erlaubnis)\w* (?:\w+ ){0,4}(?:entf[aä]ll\w*|nicht (?:nötig|notwendig|erforderlich|vorgesehen))|ohne (?:\w+ ){0,2}prüfung der (?:einwilligung|zustimmung)|без (?:\w+ ){0,2}согласова\w*|без проверки согласия|(?:согласов|соглас|уведомл|информир)\w* (?:\w+ ){0,3}не (?:нужн\w*|требуется|обязательн\w*)|не (?:уведомля\w*|информиру\w*|сообща\w*|ставим в известность)|(?:do not|don't|never) (?:bother|trouble|ask) (?:\w+ ){0,4}(?:consent|permission|approval)\w*|(?:no|skip\w*|without (?:a |any )?)(?: \w+){0,1} consent (?:prompt|dialog|step|check|request)\w*|ohne dass (?:\w+ ){0,4}(?:erfährt|weiß|zustimmt|einwilligt|bemerkt|merkt|gefragt wird|informiert wird)|without (?:the )?(?:\w+(?:'s)? ){0,2}(?:knowing|noticing|being (?:asked|told|informed))|чтобы (?:\w+ ){0,2}не (?:узнал\w*|знал\w*|заметил\w*))\b/i),
		// The agent is permitted to send (round 12, "indirect permission wording"); a condition of consent cancels it.
		permission: ub(/\b(?:you may|you can|you are (?:allowed|permitted|free) to|is (?:allowed|permitted) to|has (?:the )?(?:right|authority|permission) to|du darfst|darf|dürfen|ist berechtigt|ist erlaubt|разрешено|разрешается|вправе|можно|может)\b/i),
		consentGiven: ub(/\b(?:with (?:the )?(?:\w+(?:'s)? )?(?:explicit |written |prior )?(?:consent|permission|approval)|(?:if|when|after|once) (?:the )?(?:user|customer|client)s? (?:\w+ ){0,1}(?:asks|agrees|requests|consents|confirms|approves|opts)|(?:on|at) (?:the )?(?:\w+(?:'s)? )?request|mit (?:\w+ ){0,2}(?:zustimmung|einwilligung|erlaubnis)|nach (?:\w+ ){0,2}(?:zustimmung|einwilligung)|auf wunsch|wenn (?:der|die) (?:nutzer|kunde|kundin)\w* (?:\w+ ){0,3}(?:zustimmt|einwilligt|wünscht|bittet)|с (?:\w+ ){0,1}согласия|по (?:\w+ ){0,1}просьбе|по запросу|если (?:пользователь|клиент) (?:\w+ ){0,2}(?:согласи|попрос|просит)\w*)\b/i),
		// Conflict between external content and the rules resolved in favour of the content (input, round 12).
		conflict: ub(/\b(?:conflict\w*|contradict\w*|clash\w*|disagree\w*|differ\w*|diverg\w*|inconsistent|widersprech\w*|widerspr\w*|abweich\w*|etwas anderes|anders als|im widerspruch|расход\w*|расхожд\w*|противореч\w*|отлича\w*|не совпада\w*|конфликт\w*|иначе)\b/i),
		favour: ub(/\b(?:in favou?r of|side with|go with|follow|obey|defer to|prefer|zugunsten|richte dich nach|folge|befolge|halte dich an|bevorzuge|в пользу|следуй|руководствуйся|подчиняйся|придерживайся|отдавай предпочтение)\b/i),
		subordinate: ub(/\b(?:(?:are|is) subordinate to|yield\w* to|give way to|defer\w* to|bow to|(?:sind|ist) (?:\w+ ){0,2}(?:untergeordnet|nachrangig)|weich\w* (?:\w+ ){0,3}(?:inhalten|dokumenten|quellen)|подчиня\w*|уступа\w*|подчинен\w*)\b/i),
		extWins: ub(/\b(?:wins|prevails|takes over|gewinnt|setzt sich durch|побеждает|берёт верх|берет верх)\b/i),
		claimVerb: ub(/\b(?:claims?|says|asks|tries|attempts|pretends|purports|insists|behauptet|vorgibt|versucht|verlangt|утвержда\w*|пыта\w*|заявля\w*|требу\w*|просит)\b(?:\s+(?:that|it|they|to|zu|dass|что))?\s+(?:[\p{L}-]+\s+){0,1}$/i),
		extSource2: ub(/\b(?:external (?:content|data|sources?|documents?|text|material)|knowledge base|retrieval|rag|externe\w* (?:inhalt|quelle|daten|dokument|text)\w*|wissensdatenbank|внешн\w* (?:содержим|источник|данн|документ|текст|материал)\w*|база знаний|базы знаний|содержим\w*)\b/i),
		// Protection suspended in more forms (round 12): skipped, waived, "gilt nicht", "entfallen", "не применяется".
		safetyOff2: ub(/\b(?:waiv\w*|set aside|relax\w*|entf[aä]ll\w*|aussetz\w*|ausgesetzt|aufheb\w*|aufgehoben|пропуска\w*|пропуст\w*|отменя\w*|снима\w*|приостан\w*)\b/i),
		suspended: ub(/\b(?:(?:does|do) not apply|(?:is|are) not (?:applied|active|enforced|in force)|no longer appl\w*|(?:gilt|gelten|greift|greifen) (?:[\p{L}-]+ ){0,3}nicht|не (?:применя\w*|действу\w*|работа\w*)|не нужн\w*)\b/i),
		noRefusal2: ub(/\b(?:(?:отказывать|отклонять|отказ\w*) (?:\w+ ){0,2}нельзя|(?:refusing|declining|refusals?) (?:is |are )?not (?:allowed|permitted|an option)|(?:darfst|darf|dürfen) (?:\w+ ){0,3}nicht ablehnen|ablehnen (?:ist|darfst du) nicht)\b/i),
		phone: /(?:\+\d{1,3}[\s.-]?)(?:\(?\d{1,4}\)?[\s.-]?){2,5}\d{2,4}\b/g,
		address: ub(/\b(?:street|str\.|straße|strasse|avenue|ave\.|road|ул\.|улица|проспект|д\.\s?\d)\b/i),
		customer: ub(/\b(?:customer|client|patient|kunde|kundin|клиент\w*|пациент\w*)\b/i),
		personName: ub(/\b(?:[A-Z][a-z]{1,20} [A-Z][a-z]{1,20}|[А-ЯЁ][а-яё]{1,20} [А-ЯЁ][а-яё]{1,20})\b/),
		iban: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b/g,
		card: /\b(?:\d[ -]?){13,19}\b/g
	};
	function ibanValid(raw) {
		const s = raw.replace(/\s/g, '');
		if (s.length < 15 || s.length > 34) { return false; }
		const r = (s.slice(4) + s.slice(0, 4)).replace(/[A-Z]/g, c => String(c.charCodeAt(0) - 55));
		let mod = 0;
		for (const ch of r) { mod = (mod * 10 + Number(ch)) % 97; }
		return mod === 1;
	}
	function luhn(raw) {
		const d = raw.replace(/\D/g, '');
		if (d.length < 13 || d.length > 19 || /^(\d)\1+$/.test(d)) { return false; }
		let sum = 0;
		for (let i = 0; i < d.length; i++) { let x = Number(d[d.length - 1 - i]); if (i % 2) { x *= 2; if (x > 9) { x -= 9; } } sum += x; }
		return sum % 10 === 0;
	}

	// ------------------------------------------------------------------ clause modality (round 12)
	// A clause ends at a comma (not inside a number), semicolon, colon, bracket or a dash between spaces. Windows are
	// bounded (160 characters before, 120 after), so every check is linear in the length of the sentence.
	const CLAUSE_BREAK = /,(?!\d)|[;:()[\]]|\s[—–-]\s/g;
	function lastBreak(s) { CLAUSE_BREAK.lastIndex = 0; let i = -1, m; while ((m = CLAUSE_BREAK.exec(s))) { i = m.index + m[0].length - 1; } return i; }
	function firstBreak(s) { CLAUSE_BREAK.lastIndex = 0; const m = CLAUSE_BREAK.exec(s); return m ? m.index : s.length; }
	/**
	 * Is the action word at [start, end) of the sentence prohibited or negated in its own clause? True for a negation
	 * before it ("never send", "не удаляй", "Führe keine Überweisungen"), a German negation just after it ("Lösche
	 * niemals"), a prohibition anywhere in the clause ("ist … verboten", "запрещено") or a leading "Never, …,". A negation
	 * that governs a word about asking or approval ("не спрашивая", "no need to ask") does not count.
	 */
	function prohibitedAt(x, start, end, cue) {
		const before = x.slice(Math.max(0, start - 160), start);
		const br = lastBreak(before);
		const c = before.slice(br + 1);
		const re = new RegExp(RX.negWord.source, 'giu');
		let last = null, m, n = 0;
		while ((m = re.exec(c)) && n++ < 50) { last = m; if (!m[0].length) { re.lastIndex++; } }
		if (last && !RX.confirmWord.test(c.slice(last.index + last[0].length))) { return true; }
		if (!cue && end - start > 3 && RX.negWord.test(' ' + x.slice(start + 1, end))) { return true; }
		const after = x.slice(end, end + 120);
		const a = after.slice(0, firstBreak(after));
		if (RX.prohibPred.test(c + ' ' + a) || RX.negAfterDe.test(a)) { return true; }
		return br >= 0 && RX.leadNeg.test(before.slice(0, br + 1));
	}
	// First occurrence of re in x that is not prohibited (bounded number of occurrences).
	function affirmed(x, re, cue) {
		const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
		let m, n = 0;
		while ((m = g.exec(x)) && n++ < 200) {
			const lead = /^[^\p{L}\p{N}_]/u.test(m[0]) ? 1 : 0;
			if (!prohibitedAt(x, m.index + lead, m.index + m[0].length, cue)) { return m; }
			if (!m[0].length) { g.lastIndex++; }
		}
		return null;
	}
	// Concealment that is not itself negated ("there are no secret discounts", "keine geheimen Preisgrenzen").
	function concealed(x) {
		const g = new RegExp(RX.conceal.source, 'giu');
		let m, n = 0;
		while ((m = g.exec(x)) && n++ < 100) {
			if (!RX.concealAdj.test(m[0])) { return true; }
			const before = x.slice(Math.max(0, m.index - 80), m.index + 1);
			const c = before.slice(lastBreak(before) + 1);
			const after = x.slice(m.index + m[0].length, m.index + m[0].length + 80);
			const clause = c + after.slice(0, firstBreak(after));
			if (!RX.noExistBefore.test(c) && !RX.noExist.test(clause)) { return true; }
			if (!m[0].length) { g.lastIndex++; }
		}
		return false;
	}
	function cueAffirmed(x, list) { for (const re of list) { if (affirmed(x, re, true)) { return true; } } return false; }
	function confidentialHere(x) {
		const m = RX.confidential.exec(x);
		if (!m) { return false; }
		const before = x.slice(Math.max(0, m.index - 80), m.index + 1);
		const c = before.slice(lastBreak(before) + 1);
		const after = x.slice(m.index + m[0].length, m.index + m[0].length + 80);
		return !RX.noExistBefore.test(c) && !RX.noExist.test(c + after.slice(0, firstBreak(after)));
	}

	function audit(text, hooks) {
		const input = String(text == null ? '' : text);
		if (!input.trim()) { const e = new Error('Paste a system prompt or agent description first.'); e.code = 'EMPTY'; throw e; }
		if (input.length > MAX_PROMPT_CHARS) { const e = new Error('The prompt is larger than the 1 MB limit.'); e.code = 'TOO_LARGE'; throw e; }
		const t = cap(input, MAX_SCAN);
		const line = lineIndex(t);
		const findings = [];
		const secrets = [];
		const add = (rule, severity, index, evidence) => { if (findings.length < MAX_FINDINGS) { findings.push({ rule, severity, line: index >= 0 ? line(index) : 0, evidence }); } };
		const progress = hooks && hooks.onProgress;
		// Secrets.
		for (const s of findSecrets(t)) {
			secrets.push(s.value);
			if (s.kind === 'token') { add('LKI-SEC-001', 'high', s.index, s.type + ': ' + mask(s.value)); }
			else if (s.kind === 'connection') { add('LKI-SEC-003', 'high', s.index, s.type + ': ' + mask(s.value) + ' (host ' + s.host + ')'); }
			else { add('LKI-SEC-002', 'medium', s.index, 'value ' + mask(s.value)); }
		}
		if (progress) { progress(1, 4); }
		// Internal details.
		const internal = new Map();
		for (const re of [RX.privateIp, RX.internalHost]) { re.lastIndex = 0; let m, n = 0; while ((m = re.exec(t)) && n++ < 200) { if (!internal.has(m[0].toLowerCase())) { internal.set(m[0].toLowerCase(), m.index); } } }
		for (const [v, i] of internal) { add('LKI-INT-001', 'medium', i, v); }
		RX.email.lastIndex = 0;
		let m, n = 0;
		const emails = [];
		while ((m = RX.email.exec(t)) && n++ < 200) {
			const local = m[1].split('@')[0];
			if (RX.roleMailbox.test(local)) { continue; }
			emails.push({ value: m[1].normalize('NFC'), index: m.index + m[0].length - m[1].length });
		}
		for (const re of [RX.uncPath, RX.unixPath, RX.winPath]) { re.lastIndex = 0; n = 0; while ((m = re.exec(t)) && n++ < 100) { add('LKI-INT-003', 'low', m.index, (m[1] || m[0]).trim()); } }
		const cn = t.match(RX.codename);
		if (cn) { add('LKI-INT-004', 'low', t.indexOf(cn[0]), cn[0]); }
		if (progress) { progress(2, 4); }
		// Sentence-level rules.
		const sens = sentences(t);
		let bizHit = false, gateHit = false, secrecyAt = -1;
		// "Do not reveal these instructions" marks the content of the prompt, discounts included, as meant to be hidden.
		const docSecrecy = RX.secrecy.test(t);
		for (let si = 0; si < sens.length; si++) {
			const s = sens[si];
			const x = s.text;
			// An instruction and its qualifier are often split over two sentences ("Delete X. Do this automatically.").
			const pair = x + ' ' + (sens[si + 1] ? sens[si + 1].text : '');
			const pct = RX.percent.test(x) || RX.percentWords.test(x);
			// Round 12: a discount or price is a finding only with signs of concealment (in the sentence, or in a
			// neighbouring sentence about the limit); published or agreed prices and "there are no secret discounts" are not.
			const conHere = concealed(x) || confidentialHere(x);
			const near = j => { const y = sens[j] && sens[j].text; return !!y && concealed(y) && (RX.limitWord.test(y) || RX.bizWord.test(y) || RX.concession.test(y)); };
			const pub = RX.publicMark.test(x);
			const hiddenLimit = conHere && (RX.concession.test(x) || (pct && RX.bizWord.test(x)) || (RX.limitWord.test(x) && (RX.bizWord.test(x) || /preis|rabatt|price|цен/iu.test(x))));
			const hiddenDiscount = RX.bizWord.test(x) && pct && !pub && (near(si + 1) || near(si + 2) || near(si - 1) || docSecrecy);
			const internalLogic = RX.bizWord.test(x) && !pub && ((RX.money.test(x) && (RX.threshold.test(x) || ub(/\b(?:internal|purchase|cost|einkauf|enterprise|partner)\w*|закупочн/i).test(x))) || (RX.threshold.test(x) && /\d/.test(x) && ub(/\b(?:approve|genehmig|refund|erstatt|allow|reputation|score)\w*|одобр|возврат/i).test(x)));
			if (hiddenLimit || hiddenDiscount || internalLogic) {
				add('LKI-BIZ-001', 'medium', s.index, cap(x.trim(), 160)); bizHit = true;
			}
			if (affirmed(x, RX.bypass)) { add('LKI-BIZ-002', 'medium', s.index, cap(x.trim(), 160)); bizHit = true; }
			if (RX.confidential.test(x)) { add('LKI-BIZ-003', 'low', s.index, cap(x.trim(), 160)); }
			if (RX.gate.test(x)) { add('LKI-PRT-002', 'high', s.index, cap(x.trim(), 160)); gateHit = true; }
			if (secrecyAt < 0 && RX.secrecy.test(x)) { secrecyAt = s.index; }
			if (RX.toolBroad.test(x) && !ub(/\b(?:cannot|can not|can't|no access|without (?:network|internet)|kein\w*|nicht)\b|не может|нет доступа/i).test(x)) { add('LKI-TOOL-001', 'medium', s.index, cap(x.trim(), 160)); }
			// Round 12: actions are checked for prohibition or negation in their own clause (prohibitedAt).
			const verbAt = re => affirmed(x, re);
			const sendAny = RX.sendVerb.test(x) || RX.sendVerb2.test(x);
			if (sendAny && (RX.dataObj.test(x) || RX.dataObjDe.test(x)) && (RX.outside.test(x) || RX.outside2.test(x))) {
				const noConsent = cueAffirmed(x, [RX.noConsent, RX.noConsent2]);
				const allowed = !noConsent && RX.permission.test(x) && !RX.consentGiven.test(x);
				if ((noConsent || allowed) && (verbAt(RX.sendVerb) || verbAt(RX.sendVerb2))) { add('LKI-TOOL-002', 'medium', s.index, cap(x.trim(), 160)); }
			}
			const pr = RX.priority.exec(x);
			const protective = RX.dataStatement.test(x);
			const rulesAfter = !!pr && (RX.operatorRules.test(x.slice(pr.index + pr[0].length)) || (/außer kraft/iu.test(pr[0]) && RX.operatorRules.test(x.slice(Math.max(0, pr.index - 80), pr.index + 1))));
			let inp = !!pr && !protective && RX.extSource.test(x.slice(0, pr.index + 1)) && rulesAfter && !prohibitedAt(x, pr.index + (/^[^\p{L}\p{N}_]/u.test(pr[0]) ? 1 : 0), pr.index + pr[0].length) && !RX.claimVerb.test(x.slice(Math.max(0, pr.index - 40), pr.index + 1).replace(/[^\s]$/u, ' '));
			if (!inp && !protective && RX.conflict.test(x) && RX.operatorRules.test(x) && (RX.extSource.test(x) || RX.extSource2.test(x))) {
				// "resolve it in favour of the document", "richte dich nach der Webseite", "следуй тексту страницы", "the page wins".
				const fv = affirmed(x, RX.favour);
				const obj = fv ? x.slice(fv.index + fv[0].length, fv.index + fv[0].length + 60) : '';
				const head = obj.split(/[,;:.]/)[0];
				inp = (!!fv && (RX.extSource.test(head) || RX.extSource2.test(head)) && !RX.operatorRules.test(head.split(/\s+/).slice(0, 3).join(' '))) || (() => { const w = affirmed(x, RX.extWins); return !!w && (RX.extSource.test(x.slice(Math.max(0, w.index - 40), w.index + 1)) || RX.extSource2.test(x.slice(Math.max(0, w.index - 40), w.index + 1))); })();
			}
			if (!inp && !protective) {
				// "the rules are subordinate to external content", "правила подчиняются содержимому внешних документов".
				const sb = affirmed(x, RX.subordinate);
				inp = !!sb && RX.operatorRules.test(x.slice(Math.max(0, sb.index - 80), sb.index + 1)) && (RX.extSource.test(x.slice(sb.index + 1, sb.index + 100)) || RX.extSource2.test(x.slice(sb.index + 1, sb.index + 100)));
			}
			if (inp) { add('LKI-INP-002', 'medium', s.index, cap(x.trim(), 160)); }
			const nearSafety = mm => !!mm && RX.safetyTarget.test(x.slice(Math.max(0, mm.index - 60), mm.index + mm[0].length + 60));
			const susp = RX.suspended.exec(x);
			const suspendedHit = !!susp && RX.safetyTarget.test(x.slice(Math.max(0, susp.index - 60), susp.index + susp[0].length)) && !ub(/\b(?:even|auch|selbst|даже)\b/i).test(x.slice(Math.max(0, susp.index - 60), susp.index + 1)) && !RX.negWord.test(x.slice(Math.max(0, susp.index - 30), susp.index + 1));
			if (nearSafety(verbAt(RX.safetyOff)) || nearSafety(verbAt(RX.safetyOff2)) || suspendedHit || (RX.noRefusal.test(x) && RX.unconditional.test(x)) || RX.noRefusal2.test(x)) { add('LKI-PRT-003', 'medium', s.index, cap(x.trim(), 160)); gateHit = true; }
			if (verbAt(RX.irreversible) && cueAffirmed(pair, [RX.noConfirm, RX.noConfirm2, RX.noConfirm3]) && !ub(/\b(?:ask (?:the user )?for (?:explicit )?confirmation|after (?:explicit )?confirmation|only after|nur nach|never (?:send|delete|deploy)|let the (?:human|engineer|user) (?:decide|run))\b|после подтверждения/i).test(pair)) { add('LKI-AUT-001', 'high', s.index, cap(pair.trim(), 160)); }
		}
		// Untrusted input placeholders.
		RX.placeholder.lastIndex = 0;
		n = 0;
		const hasStatement = RX.dataStatement.test(t);
		while ((m = RX.placeholder.exec(t)) && n++ < 50) {
			const before = t.slice(Math.max(0, m.index - 120), m.index);
			const after = t.slice(m.index + m[0].length, m.index + m[0].length + 120);
			const open = /(?:<([A-Za-z_][\w-]{0,40})[^>]{0,40}>|```|"""|''')\s*$/.exec(before);
			const delimited = !!open && (open[1] ? new RegExp('^\\s*</' + open[1] + '\\s*>').test(after) : /^\s*(?:```|"""|''')/.test(after));
			if (delimited && hasStatement) { continue; }
			add('LKI-INP-001', delimited ? 'low' : 'medium', m.index, m[0] + (delimited ? ' (delimited, but the prompt does not say the content is data)' : ' (no delimiters)'));
		}
		// Personal data.
		const pii = [];
		RX.phone.lastIndex = 0;
		n = 0;
		while ((m = RX.phone.exec(t)) && n++ < 100) { if (m[0].replace(/\D/g, '').length >= 8) { pii.push({ kind: 'phone number', index: m.index, value: m[0] }); } }
		// An email address is customer data when its own sentence names a customer or holds a phone number;
		// otherwise a personal (non-role) address is treated as a staff address.
		const sentenceAt = i => sens.find(x => x.index <= i && i < x.index + x.text.length) || { text: '' };
		const staffEmails = [];
		for (const e of emails) {
			const st = sentenceAt(e.index).text;
			RX.phone.lastIndex = 0;
			if (RX.customer.test(st) || RX.phone.test(st)) { pii.push({ kind: 'email address', index: e.index, value: e.value }); } else { staffEmails.push(e); }
		}
		const addr = t.match(RX.address);
		if (addr) { pii.push({ kind: 'postal address', index: t.indexOf(addr[0]), value: addr[0] }); }
		const customerContext = RX.customer.test(t) || RX.personName.test(t);
		if (pii.length) {
			const kinds = [...new Set(pii.map(p => p.kind))];
			add('LKI-PII-001', kinds.length >= 3 ? 'high' : 'medium', pii[0].index, kinds.join(', ') + (customerContext ? ' with a customer or person name' : ''));
		}
		for (const e of staffEmails) { add('LKI-INT-002', 'medium', e.index, e.value); }
		RX.iban.lastIndex = 0;
		n = 0;
		while ((m = RX.iban.exec(t)) && n++ < 50) { if (ibanValid(m[0])) { secrets.push(m[0]); add('LKI-PII-002', 'high', m.index, 'IBAN ' + mask(m[0].replace(/\s/g, ''))); } }
		RX.card.lastIndex = 0;
		n = 0;
		while ((m = RX.card.exec(t)) && n++ < 50) { if (luhn(m[0]) && !/^\+/.test(t.slice(Math.max(0, m.index - 1), m.index + 1))) { secrets.push(m[0]); add('LKI-PII-002', 'high', m.index, 'card number ' + mask(m[0].replace(/\D/g, ''))); } }
		if (progress) { progress(3, 4); }
		// Secrecy instruction: weak protection, stronger when the prompt holds sensitive content.
		if (secrecyAt >= 0) {
			const sensitive = findings.some(f => /^LKI-(?:SEC|INT-001|INT-002|BIZ-001|BIZ-002|PII|PRT-002)/.test(f.rule)) || bizHit || gateHit;
			add('LKI-PRT-001', sensitive ? 'medium' : 'low', secrecyAt, sensitive ? 'the prompt also contains sensitive content (see other findings)' : 'no sensitive content found, but the instruction gives no real protection');
		}
		if (progress) { progress(4, 4); }
		const notes = [];
		if (input.length > MAX_SCAN) { notes.push('Only the first ' + MAX_SCAN.toLocaleString('en-US') + ' characters were checked by the rules.'); }
		return finish('audit', findings, secrets, notes, { chars: input.length });
	}

	// ------------------------------------------------------------------ leak check
	const INVISIBLE = /[\u200B-\u200F\u2060-\u2064\uFEFF\u00AD\u202A-\u202E\u2066-\u2069\u180E]|[\u{E0000}-\u{E007F}]/gu;
	const WORD = /[\p{L}\p{N}]+/gu;
	/** Tokens with normalized form, exact form and character offsets into the original text. */
	function tokenize(text, maxTokens) {
		const map = [];
		let clean = '';
		for (let i = 0; i < text.length; i++) {
			const cp = text.codePointAt(i);
			const ch = String.fromCodePoint(cp);
			const step = cp > 0xFFFF ? 2 : 1;
			if (!/^(?:[\u200B-\u200F\u2060-\u2064\uFEFF\u00AD\u202A-\u202E\u2066-\u2069\u180E]|[\u{E0000}-\u{E007F}])$/u.test(ch)) { for (let k = 0; k < step; k++) { map.push(i + k); } clean += ch; }
			i += step - 1;
		}
		const tokens = [];
		WORD.lastIndex = 0;
		let m;
		while ((m = WORD.exec(clean)) && tokens.length < maxTokens) {
			const exact = m[0];
			tokens.push({ exact, norm: exact.normalize('NFKC').toLowerCase(), start: map[m.index], end: map[m.index + exact.length - 1] + 1 });
		}
		return { tokens, truncated: !!WORD.exec(clean) };
	}
	function excerpt(text, start, end) {
		const s = text.slice(start, Math.min(end, start + 300)).replace(INVISIBLE, '').replace(/\s+/g, ' ').trim();
		return s + (end - start > 300 ? ' …' : '');
	}
	/** Longest-match search of prompt word sequences (length >= k) in the response, bounded by time. */
	function matchRuns(P, Rt, k, deadline) {
		const index = new Map();
		for (let j = 0; j + k <= P.length; j++) {
			const key = P.slice(j, j + k).map(x => x.norm).join('\u0001');
			const list = index.get(key);
			if (!list) { index.set(key, [j]); } else if (list.length < 32) { list.push(j); }
		}
		const runs = [];
		let timedOut = false;
		for (let i = 0; i + k <= Rt.length;) {
			if ((i & 2047) === 0 && Date.now() > deadline) { timedOut = true; break; }
			const list = index.get(Rt.slice(i, i + k).map(x => x.norm).join('\u0001'));
			if (!list) { i++; continue; }
			let best = null;
			for (const j of list) {
				let len = k;
				while (i + len < Rt.length && j + len < P.length && Rt[i + len].norm === P[j + len].norm) { len++; }
				if (!best || len > best.len) { best = { i, j, len }; }
			}
			runs.push(best);
			i += best.len;
		}
		return { runs, timedOut };
	}
	function ngramOverlap(P, Rt, n, deadline) {
		const STOP = new Set(['the', 'a', 'an', 'and', 'or', 'to', 'of', 'in', 'on', 'for', 'is', 'are', 'be', 'it', 'you', 'your', 'i', 'we', 'with', 'that', 'this', 'as', 'at', 'by', 'if', 'do', 'not', 'der', 'die', 'das', 'und', 'oder', 'zu', 'in', 'mit', 'ist', 'du', 'ich', 'nicht', 'ein', 'eine', 'и', 'в', 'на', 'с', 'не', 'что', 'как', 'по', 'к', 'я', 'ты', 'это']);
		const pg = new Map();
		for (let j = 0; j + n <= P.length; j++) {
			const words = P.slice(j, j + n).map(x => x.norm);
			if (words.every(w => STOP.has(w) || /^\d+$/.test(w))) { continue; }
			const key = words.join(' ');
			if (!pg.has(key)) { pg.set(key, j); }
		}
		const hit = new Set();
		let timedOut = false;
		for (let i = 0; i + n <= Rt.length; i++) {
			if ((i & 4095) === 0 && Date.now() > deadline) { timedOut = true; break; }
			const key = Rt.slice(i, i + n).map(x => x.norm).join(' ');
			if (pg.has(key)) { hit.add(key); }
		}
		const covered = new Uint8Array(P.length);
		for (const key of hit) { const j = pg.get(key); for (let x = 0; x < n; x++) { covered[j + x] = 1; } }
		const spans = [];
		for (let j = 0; j < P.length;) { if (!covered[j]) { j++; continue; } let e = j; while (e < P.length && covered[e]) { e++; } spans.push([j, e]); j = e; }
		return { total: pg.size, matched: hit.size, ratio: pg.size ? hit.size / pg.size : 0, spans: spans.sort((a, b) => (b[1] - b[0]) - (a[1] - a[0])).slice(0, 10), timedOut };
	}
	function bytesToText(bytes) {
		try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (e) { return null; }
	}
	function printable(s) {
		if (!s || s.length < 12) { return false; }
		let ok = 0;
		for (const ch of s) { if (/[\p{L}\p{N}\p{P}\p{Zs}\n\r\t]/u.test(ch)) { ok++; } }
		return ok / [...s].length >= 0.9 && /[\p{L}]{3,}/u.test(s);
	}
	function decodeCandidates(text) {
		const out = [];
		const t = cap(text, MAX_SCAN * 5);
		const push = (kind, raw, decoded, index) => { if (out.length < MAX_DECODE_CANDIDATES && printable(decoded)) { out.push({ kind, raw, text: decoded, index }); } };
		let m, n = 0;
		const b64 = /[A-Za-z0-9+/]{20,}={0,2}|[A-Za-z0-9_-]{24,}={0,2}/g;
		while ((m = b64.exec(t)) && n++ < 2000) {
			const s = m[0].replace(/-/g, '+').replace(/_/g, '/');
			if (s.replace(/=+$/, '').length % 4 === 1) { continue; }
			let bin;
			try { bin = typeof atob === 'function' ? atob(s + '='.repeat((4 - s.length % 4) % 4)) : Buffer.from(s, 'base64').toString('binary'); } catch (e) { continue; }
			const bytes = new Uint8Array(bin.length);
			for (let i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }
			push('Base64', m[0], bytesToText(bytes), m.index);
		}
		n = 0;
		const hex = /\b(?:[0-9a-fA-F]{2}){12,}\b/g;
		while ((m = hex.exec(t)) && n++ < 2000) {
			const bytes = new Uint8Array(m[0].length / 2);
			for (let i = 0; i < bytes.length; i++) { bytes[i] = parseInt(m[0].substr(i * 2, 2), 16); }
			push('hex', m[0], bytesToText(bytes), m.index);
		}
		n = 0;
		const url = /(?:[^\s%<>"']{0,40}%[0-9A-Fa-f]{2}){3,}[^\s<>"']{0,40}/g;
		while ((m = url.exec(t)) && n++ < 2000) {
			let d = null;
			try { d = decodeURIComponent(m[0].replace(/\+/g, ' ')); } catch (e) { d = null; }
			push('URL encoding', m[0], d, m.index);
		}
		return out;
	}

	function leakCheck(promptText, responseText, options, hooks) {
		const prompt = String(promptText == null ? '' : promptText);
		const response = String(responseText == null ? '' : responseText);
		if (!prompt.trim() || !response.trim()) { const e = new Error('Paste both the reference prompt and the response or transcript.'); e.code = 'EMPTY'; throw e; }
		if (prompt.length > MAX_PROMPT_CHARS) { const e = new Error('The reference prompt is larger than the 1 MB limit.'); e.code = 'TOO_LARGE'; throw e; }
		if (response.length > MAX_RESPONSE_CHARS) { const e = new Error('The response is larger than the 5 MB limit.'); e.code = 'TOO_LARGE'; throw e; }
		const opts = options || {};
		const k = Math.max(4, Math.min(50, Math.floor(Number(opts.minWords) || DEFAULT_MIN_WORDS)));
		const progress = hooks && hooks.onProgress;
		const deadline = Date.now() + (Number(opts.timeBudgetMs) || TIME_BUDGET_MS);
		const notes = [];
		const findings = [];
		const add = (rule, severity, evidence, extra) => { if (findings.length < MAX_FINDINGS) { findings.push(Object.assign({ rule, severity, line: 0, evidence }, extra || {})); } };
		const pt = tokenize(prompt, MAX_PROMPT_TOKENS);
		const rt = tokenize(response, MAX_RESPONSE_TOKENS);
		if (pt.truncated) { notes.push('The prompt has more than ' + MAX_PROMPT_TOKENS.toLocaleString('en-US') + ' words; only the first part was compared.'); }
		if (rt.truncated) { notes.push('The response has more than ' + MAX_RESPONSE_TOKENS.toLocaleString('en-US') + ' words; only the first part was compared.'); }
		const P = pt.tokens, Rt = rt.tokens;
		const pLine = lineIndex(prompt), rLine = lineIndex(response);
		const secrets = findSecrets(prompt);
		const secretValues = secrets.map(s => s.value);
		if (progress) { progress(1, 4); }
		// 1. Verbatim and near-verbatim runs.
		const { runs, timedOut } = matchRuns(P, Rt, k, deadline);
		if (timedOut) { notes.push('The time limit was reached while comparing word sequences; results are partial.'); }
		const covered = new Uint8Array(P.length);
		runs.sort((a, b) => b.len - a.len);
		for (const r of runs.slice(0, MAX_FRAGMENTS)) {
			for (let x = 0; x < r.len; x++) { covered[r.j + x] = 1; }
			const pStart = P[r.j].start, pEnd = P[r.j + r.len - 1].end, rStart = Rt[r.i].start, rEnd = Rt[r.i + r.len - 1].end;
			// Verbatim: identical text up to whitespace; the first letter may change case (quoted mid-sentence).
			const pa = prompt.slice(pStart, pEnd).replace(/\s+/g, ' '), ra = response.slice(rStart, rEnd).replace(/\s+/g, ' ');
			const exact = pa === ra || (pa.slice(1) === ra.slice(1) && pa.charAt(0).toLowerCase() === ra.charAt(0).toLowerCase());
			const share = P.length ? r.len / P.length : 0;
			const sev = r.len >= 20 || share >= 0.25 ? 'high' : 'medium';
			add(exact ? 'LKC-001' : 'LKC-002', sev, r.len + ' words: “' + excerpt(response, rStart, rEnd) + '”', { line: rLine(rStart), promptLine: pLine(pStart), words: r.len });
		}
		const coveredWords = covered.reduce((a, b) => a + b, 0);
		if (runs.length > MAX_FRAGMENTS) { notes.push(runs.length + ' matching sequences found; the longest ' + MAX_FRAGMENTS + ' are listed.'); }
		if (progress) { progress(2, 4); }
		// 2. Encoded content (depth 2).
		const decoded = [];
		let layer = [{ text: response, depth: 0 }];
		for (let depth = 1; depth <= 2 && layer.length; depth++) {
			const next = [];
			for (const src of layer) {
				for (const c of decodeCandidates(src.text)) {
					if (decoded.length >= MAX_DECODE_CANDIDATES || Date.now() > deadline) { break; }
					const dt = tokenize(c.text, 20000).tokens;
					const sub = matchRuns(P, dt, Math.min(k, 5), deadline);
					const words = sub.runs.reduce((a, r) => a + r.len, 0);
					const leakedSecret = secretValues.find(v => c.text.includes(v));
					decoded.push({ kind: c.kind, depth, line: rLine(src.depth ? 0 : c.index), excerpt: excerpt(c.text, 0, c.text.length), matchedWords: words });
					if (words) { add('LKC-003', 'high', c.kind + (depth > 1 ? ' (inside another encoding)' : '') + ' decodes to ' + words + ' words of the prompt: “' + excerpt(c.text, 0, c.text.length) + '”', { line: src.depth ? 0 : rLine(c.index), words }); }
					if (leakedSecret) { add('LKC-005', 'high', 'inside ' + c.kind + ': ' + mask(leakedSecret)); }
					next.push({ text: c.text, depth });
				}
			}
			layer = next;
		}
		if (progress) { progress(3, 4); }
		// 3. Secrets from the prompt in the response (raw and after removing invisible characters).
		const plain = response.replace(INVISIBLE, '');
		for (const s of secrets) {
			if (s.value.length >= 6 && (response.includes(s.value) || plain.includes(s.value))) { const at = response.indexOf(s.value); add('LKC-005', 'high', s.type + ': ' + mask(s.value), { line: at >= 0 ? rLine(at) : 0 }); }
		}
		// 4. Overlap measure (no verdict).
		const ov = ngramOverlap(P, Rt, 3, deadline);
		if (ov.timedOut) { notes.push('The time limit was reached while measuring phrase overlap; the share is a lower bound.'); }
		const pct = Math.round(ov.ratio * 1000) / 10;
		const overlap = { ngram: 3, promptPhrases: ov.total, matchedPhrases: ov.matched, share: pct, fragments: ov.spans.map(([a, b]) => '“' + excerpt(prompt, P[a].start, P[b - 1].end) + '”') };
		if (ov.matched) { add('LKC-004', ov.ratio >= 0.35 ? 'medium' : ov.ratio >= 0.15 ? 'low' : 'info', pct + '% of the prompt’s ' + ov.total + ' three-word phrases appear in the response (' + ov.matched + ' phrases)'); }
		if (progress) { progress(4, 4); }
		const verbatimShare = P.length ? Math.round(coveredWords / P.length * 1000) / 10 : 0;
		return finish('leak', findings, secretValues.concat(findTokens(response).map(t => t.value)), notes, { promptWords: P.length, responseWords: Rt.length, minWords: k, verbatimShare, overlap, decoded });
	}

	// ------------------------------------------------------------------ output
	function finish(mode, raw, secrets, notes, extra) {
		const known = [...new Set(secrets.filter(v => v && v.length >= 4))].sort((a, b) => b.length - a.length);
		const redact = s => { let o = String(s); for (const v of known) { if (o.includes(v)) { o = o.split(v).join(mask(v)); } } return maskLongValues(o); };
		const findings = raw.map(f => {
			const r = R[f.rule];
			return { rule: f.rule, group: r[0], severity: f.severity, title: r[1], explanation: r[2], fix: r[3], line: f.line || 0, promptLine: f.promptLine || 0, words: f.words || 0, evidence: redact(f.evidence) };
		});
		findings.sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.line - b.line);
		const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
		const byGroup = {};
		for (const f of findings) { bySeverity[f.severity]++; byGroup[f.group] = (byGroup[f.group] || 0) + 1; }
		const level = SEVERITIES.find(s => bySeverity[s] > 0) || 'none';
		const out = { engine: VERSION, ruleset: RULESET_VERSION, mode, level, counts: { findings: findings.length, bySeverity, byGroup }, findings, notes: notes.map(redact).concat('Masking is best effort: secrets in an unusual form can remain in excerpts. Review results before sharing.') };
		if (extra) {
			for (const [k2, v] of Object.entries(extra)) {
				if (k2 === 'overlap') { out.overlap = Object.assign({}, v, { fragments: v.fragments.map(redact) }); }
				else if (k2 === 'decoded') { out.decoded = v.map(d => Object.assign({}, d, { excerpt: redact(d.excerpt) })); }
				else { out[k2] = v; }
			}
		}
		return out;
	}

	return { VERSION, RULESET_VERSION, MAX_PROMPT_CHARS, MAX_RESPONSE_CHARS, WARN_CHARS, DEFAULT_MIN_WORDS, RULES: R, GROUPS, audit, leakCheck, mask, maskLongValues, findSecrets, tokenize, decodeCandidates };
}));
