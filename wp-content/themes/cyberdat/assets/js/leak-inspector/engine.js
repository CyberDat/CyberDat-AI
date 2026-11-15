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

	const VERSION = '1.0.0';
	const RULESET_VERSION = '2026-11-14.1';
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
		const re = new RegExp(ASSIGN.source, 'gi');
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
		'LKI-PRT-002': ['protection', 'Password or code word unlocks special behaviour', 'A passphrase in the prompt that switches modes or lifts restrictions is readable by anyone who extracts the prompt, and can be guessed or leaked.', 'Authenticate users in your application, not in the prompt. Give privileged users a different configuration server-side.'],
		'LKI-INP-001': ['input', 'Untrusted input inserted without clear boundaries', 'A placeholder for user, email or web content sits in the instructions without delimiters or a statement that it is data. Text in that content can then pose as instructions.', 'Wrap untrusted content in clear delimiters (for example <document>…</document>) and state that it is data that cannot change the instructions. This reduces, but does not remove, prompt injection.'],
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

	// Sentence splitter that keeps positions; bounded.
	function sentences(text) {
		const out = [];
		const re = /[^.!?\n]+[.!?]*|\n+/g;
		let m, n = 0;
		const t = cap(text, MAX_SCAN);
		while ((m = re.exec(t)) && n++ < 20000) { if (m[0].trim()) { out.push({ text: m[0], index: m.index }); } }
		return out;
	}
	const NEGATION = /\b(?:never|cannot|can't|can not|no|not|without network|keine?n?|nicht|niemals|nie|не|нельзя|никогда)\b/i;
	const RX = {
		privateIp: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g,
		internalHost: /\b(?:[a-z0-9-]{1,63}\.){0,6}(?:[a-z0-9-]{1,63}\.(?:internal|corp|local|lan|intranet|localdomain|home\.arpa)\b|intranet\.[a-z0-9.-]{2,100}|[a-z0-9-]{1,63}\.(?:internal|corp|intranet)\.[a-z0-9.-]{2,100})/gi,
		email: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g,
		roleMailbox: /^(?:support|info|help|hilfe|contact|kontakt|sales|noreply|no-reply|privacy|security|hello|team|service|office|press|jobs|billing|admin|webmaster|abuse)$/i,
		uncPath: /\\\\[A-Za-z0-9._$-]{1,63}\\[^\s"'<>]{1,200}/g,
		unixPath: /(?:^|[\s"'(=])(\/(?:srv|home|opt|var|etc|mnt|data|share|internal)\/[^\s"'<>),;]{1,200})/g,
		winPath: /\b[A-Za-z]:\\(?:Users|Shares?|Data|Finance|HR|Internal)\\[^\s"'<>]{1,200}/g,
		codename: ub(/\b(?:code ?name|codename|internal project name|kodename|кодов(?:ое|ым) назван\w*)\b|\bproject\s+[A-Z][A-Z0-9]{3,}\b/i),
		percent: /\b\d{1,3}(?:[.,]\d{1,2})?\s?%/,
		money: ub(/(?:[$€£]\s?\d[\d.,]{0,12}|\b\d[\d.,]{0,12}\s?(?:eur|euro|usd|dollars?|gbp|rub|руб\w*|€|\$)\b)/i),
		threshold: ub(/\b(?:below|under|above|over|less than|more than|fewer than|at least|at most|up to|bis zu|unter|über|mindestens|höchstens|до|ниже|выше|не более|не менее)\b[^.\n]{0,20}?\d/i),
		bizWord: ub(/\b(?:discount|rabatt|скидк\w*|refund\w*|erstattung\w*|возврат\w*|price\w*|preis\w*|цен\w*|cost\w*|kosten|стоимост\w*|approve\w*|genehmig\w*|одобр\w*|limit\w*|grenze|лимит\w*|threshold|schwelle|порог\w*|score|reputation|rating|bonus|commission|provision|наценк\w*|закупочн\w*|purchase price|einkaufspreis)\b/i),
		bypass: ub(/\b(?:even if (?:the )?(?:spam )?(?:filter|system|check|moderation)?\s*(?:flags?|blocks?|rejects?)|shadow-?ban\w*|bypass\w*|whitelist\w*|allowlist\w*|skip (?:the )?(?:check|review|moderation)|silently (?:remove|delete|ban|block|approve)|ohne prüfung|trotz (?:sperre|markierung)|в обход|без проверки|даже если (?:фильтр|система))\b/i),
		confidential: ub(/\b(?:confidential|internal only|internal use only|do not share with (?:customers|users)|vertraulich|nur intern|конфиденциальн\w*|только для внутреннего)\b/i),
		secrecy: ub(/\b(?:never|do not|don't|under no circumstances|in no case)\b[^.\n]{0,40}?\b(?:reveal|disclose|share|repeat|show|output|tell)\b[^.\n]{0,30}?\b(?:these |this |the |your |my )?(?:instructions|system prompt|prompt|rules|guidelines|configuration)\b|\b(?:niemals|nie|keinesfalls)\b[^.\n]{0,40}?\b(?:anweisungen|systemprompt|system-prompt|regeln)\b[^.\n]{0,30}?\b(?:preis\w*|verrat\w*|offenleg\w*|weiter\w*)|(?:не\s+раскрыва\w*|не\s+показыва\w*|не\s+разглаша\w*|не\s+сообща\w*)[^.\n]{0,40}?(?:инструкци\w*|системн\w+ промпт\w*|промпт\w*|правил\w*)/i),
		gate: ub(/\b(?:passphrase|password|pass ?word|code ?word|secret word|kennwort|passwort|codewort|кодов\w+ слов\w*|пароль)\b[^.\n]{0,80}?\b(?:admin(?:istrator)? mode|developer mode|debug mode|god mode|unlock\w*|ignore (?:all )?(?:content )?restrictions|lift (?:all )?restrictions|entwicklermodus|adminmodus|einschränkungen (?:aufheben|ignorieren)|hebe alle einschränkungen|режим администратора|режим разработчика|сними все ограничения)/i),
		placeholder: /\{\{\s*[A-Za-z_][A-Za-z0-9_.-]{0,60}\s*\}\}|\{[A-Za-z_][A-Za-z0-9_]{0,60}\}|\$\{[A-Za-z_][A-Za-z0-9_.]{0,60}\}|<<\s*[A-Za-z_][A-Za-z0-9_]{0,60}\s*>>|\[\[\s*[A-Za-z_][A-Za-z0-9_]{0,60}\s*\]\]|%\([A-Za-z_][A-Za-z0-9_]{0,60}\)s/g,
		dataStatement: ub(/\b(?:untrusted|treat (?:it |them |the [a-z ]{1,30})?(?:as|strictly as) (?:data|content)|(?:is|are) data,? not instructions|do not follow (?:any )?instructions|ignore (?:any )?instructions (?:that appear |inside|in )|cannot change (?:these|the) instructions|als daten|keine anweisungen|как данные|не являются инструкциями)\b/i),
		toolBroad: ub(/\b(?:unrestricted|unlimited|full|complete|root|administrator|admin|any|all)\b[^.\n]{0,30}?\b(?:shell|command line|terminal|commands?|file ?system|files|network|internet|e-?mails?|mailbox(?:es)?|inbox(?:es)?|database|servers?)\b(?:[^.\n]{0,20}?\b(?:access|permissions?|rights)\b)?|\brun any command\b|\bsend (?:e-?mails? )?to any (?:address|recipient)\b|\bread all (?:mailboxes|files|e-?mails)\b|\b(?:vollen?|uneingeschränkten?)\b[^.\n]{0,40}?\b(?:zugriff|zugang)\b|\bgesamte[n]? dateisystem\b|полн\w+ доступ|любые команды|неограниченн\w+ доступ/i),
		irreversible: ub(/\b(?:delet\w*|remov\w*|drop\w*|wip\w*|purg\w*|transfer\w*|wire|pay\w*|refund\w*|charg\w*|deploy\w*|publish\w*|block\w*|ban\w*|terminat\w*|cancel\w*|lösch\w*|überweis\w*|bereitstell\w*|sperr\w*|удал\w*|списыва\w*|списыв\w*|блокир\w*|перевод\w*|оплач\w*)/i),
		noConfirm: ub(/\b(?:without (?:asking|any )?(?:for )?(?:confirmation|approval|asking|review|human)|do not (?:wait for|ask for) (?:human )?(?:approval|confirmation)|don't (?:wait for|ask for) (?:human )?(?:approval|confirmation)|no (?:human )?(?:approval|confirmation) (?:is )?(?:needed|required)|automatically|on your own|ohne (?:nachzufragen|bestätigung|rückfrage|freigabe)|automatisch|без подтверждения|не запрашивая подтверждени\w*|автоматически|самостоятельно)\b|ohne nachzufragen|не запрашивая подтверждения/i),
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
			const local = m[0].split('@')[0];
			if (RX.roleMailbox.test(local)) { continue; }
			emails.push({ value: m[0], index: m.index });
		}
		for (const re of [RX.uncPath, RX.unixPath, RX.winPath]) { re.lastIndex = 0; n = 0; while ((m = re.exec(t)) && n++ < 100) { add('LKI-INT-003', 'low', m.index, (m[1] || m[0]).trim()); } }
		const cn = t.match(RX.codename);
		if (cn) { add('LKI-INT-004', 'low', t.indexOf(cn[0]), cn[0]); }
		if (progress) { progress(2, 4); }
		// Sentence-level rules.
		const sens = sentences(t);
		let bizHit = false, gateHit = false, secrecyAt = -1;
		for (let si = 0; si < sens.length; si++) {
			const s = sens[si];
			const x = s.text;
			// An instruction and its qualifier are often split over two sentences ("Delete X. Do this automatically.").
			const pair = x + ' ' + (sens[si + 1] ? sens[si + 1].text : '');
			if (RX.bizWord.test(x) && (RX.percent.test(x) || (RX.money.test(x) && (RX.threshold.test(x) || ub(/\b(?:internal|purchase|cost|einkauf|enterprise|partner)\w*|закупочн/i).test(x))) || (RX.threshold.test(x) && /\d/.test(x) && ub(/\b(?:approve|genehmig|refund|erstatt|allow|reputation|score)\w*|одобр|возврат/i).test(x)))) {
				add('LKI-BIZ-001', 'medium', s.index, cap(x.trim(), 160)); bizHit = true;
			}
			if (RX.bypass.test(x)) { add('LKI-BIZ-002', 'medium', s.index, cap(x.trim(), 160)); bizHit = true; }
			if (RX.confidential.test(x)) { add('LKI-BIZ-003', 'low', s.index, cap(x.trim(), 160)); }
			if (RX.gate.test(x)) { add('LKI-PRT-002', 'high', s.index, cap(x.trim(), 160)); gateHit = true; }
			if (secrecyAt < 0 && RX.secrecy.test(x)) { secrecyAt = s.index; }
			if (RX.toolBroad.test(x) && !ub(/\b(?:cannot|can not|can't|no access|without (?:network|internet)|kein\w*|nicht)\b|не может|нет доступа/i).test(x)) { add('LKI-TOOL-001', 'medium', s.index, cap(x.trim(), 160)); }
			if (RX.irreversible.test(x) && RX.noConfirm.test(pair) && !ub(/\b(?:ask (?:the user )?for (?:explicit )?confirmation|after (?:explicit )?confirmation|only after|nur nach|never (?:send|delete|deploy)|let the (?:human|engineer|user) (?:decide|run))\b|после подтверждения/i).test(pair)) { add('LKI-AUT-001', 'high', s.index, cap(pair.trim(), 160)); }
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
