/*!
 * CyberDat Email Header Analyzer — engine, shared by the worker and the Node tests.
 *
 * Contract (enforced by tests):
 *  - only the header block (text before the first empty line) is analysed; the body and attachments are never parsed,
 *    returned or exported — only their size is counted;
 *  - no DNS, WHOIS, reputation or DKIM signature check: results recorded by the receiving servers are shown and judged
 *    by their position (trust boundary); nothing is sent anywhere;
 *  - linear-time parsing with size, count and time limits; no regular-expression look-behind; user text matched with
 *    Unicode classes and the u flag; values that look like secrets are masked in results and exports;
 *  - own rules and brand list written by CyberDat. Organizational domains use the Public Suffix List (MPL-2.0), shipped
 *    unmodified as public_suffix_list.dat / psl-data.js next to this file.
 */
(function (root, factory) {
	const api = factory();
	if (typeof module === 'object' && module.exports) {
		module.exports = api;
		try { api.loadPSL(require('node:fs').readFileSync(require('node:path').join(__dirname, 'public_suffix_list.dat'), 'utf8').replace(/\r\n/g, '\n')); } catch (e) { /* tests load it explicitly */ }
	} else {
		root.CyberDatEmailHeaders = api;
		if (root.CyberDatPSL && root.CyberDatPSL.text) { api.loadPSL(root.CyberDatPSL.text, root.CyberDatPSL); }
	}
}(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const ENGINE = '1.0.0';
	const RULESET = '2026-11-23.1';
	const MAX_INPUT_CHARS = 5 * 1024 * 1024;
	const MAX_HEADER_CHARS = 1024 * 1024;
	const MAX_HEADERS = 10000;
	const MAX_RECEIVED = 2000;
	const MAX_PARSE_CHARS = 8000;
	const TIME_BUDGET_MS = 10000;
	const SKEW_MS = 5 * 60000;
	const FUTURE_MS = 15 * 60000;

	// id: [severity, title, why it matters, what to check next]
	const DEF = {
		'EHA-PARSE-001': ['info', 'Received line not recognised', 'The tool could not read the from/by parts of this Received line. It is shown as written and not used for the path.', 'Read the line yourself; unusual formats come from old or custom mail servers, but forged lines also look unusual.'],
		'EHA-PATH-001': ['low', 'Times along the path go backwards', 'A server further along the path recorded an earlier time than the one before it, by more than 5 minutes. Clocks can be wrong, but forged Received lines below the trust boundary often have inconsistent times.', 'Compare the times above and below the trust boundary; only the lines above it were written by your servers.'],
		'EHA-PATH-002': ['medium', 'Received date in the future', 'A server recorded a date more than 15 minutes after the time of this analysis.', 'Check whether the line is below the trust boundary (written by the sender) and whether the server clock was wrong.'],
		'EHA-PATH-003': ['info', 'Long delivery time', 'More than an hour passed between the first and the last recorded hop. Queues, greylisting and retries are common causes.', 'Usually harmless. If the message claims urgency, the delay may simply mean it sat in a queue.'],
		'EHA-PATH-005': ['low', 'No Received lines', 'Without Received lines the delivery path is unknown. The headers may be incomplete (for example copied from a mail client view) or the message was not delivered by SMTP.', 'Copy the complete original headers (Show original in Gmail, View message source or Message headers in Outlook).'],
		'EHA-PATH-006': ['info', 'Received line without a date', 'A Received line has no date, so its place in time is unknown.', 'Usually a server quirk. Treat it with more caution if it is below the trust boundary.'],
		'EHA-AUTH-001': ['high', 'DMARC failed', 'A receiving server you can trust recorded dmarc=fail: neither SPF nor DKIM confirmed the domain shown in From. Spoofed messages fail DMARC.', 'Treat the sender as unverified. Do not use links or attachments; confirm through a channel you already know.'],
		'EHA-AUTH-002': ['medium', 'SPF did not pass', 'The sending server is not permitted by the SPF record of the envelope sender domain (fail, softfail or permerror), and DMARC did not pass.', 'Look at the sending IP in the trust-boundary hop and at the envelope sender (smtp.mailfrom or Return-Path).'],
		'EHA-AUTH-003': ['medium', 'DKIM signature failed', 'A DKIM signature could not be verified (fail or permerror) and DMARC did not pass. The message may have been altered or the signature forged.', 'Check which domain (d=) signed and whether a forwarder or a mailing list changed the message.'],
		'EHA-AUTH-004': ['low', 'No trusted authentication results', 'No SPF, DKIM or DMARC result written by a server inside the trust boundary was found. Either your server does not record them or the headers are incomplete.', 'Look for Authentication-Results added by your own mail server; enter your domain or server names to set the trust boundary.'],
		'EHA-AUTH-005': ['medium', 'Untrusted authentication results claim a pass', 'Authentication-Results or Received-SPF that report a pass were written below the trust boundary or by a server that is not yours. Anyone can write such a header; senders add forged ones to look legitimate.', 'Ignore these results. Rely on the results written by your own servers, shown as trusted.'],
		'EHA-AUTH-006': ['low', 'DMARC failed on a forwarded or list message', 'DMARC failed, but the message went through a forwarder or a mailing list (ARC pass recorded by your server, or a List-Id header). Forwarding and lists often break SPF and DKIM. A List-Id header can also be added by a sender.', 'Check the ARC results and the list or forwarding server. If you do not subscribe to such a list, treat it as a DMARC failure.'],
		'EHA-ALIGN-001': ['medium', 'No sender identity matches From', 'Neither the SPF domain (envelope sender) nor a DKIM signing domain belongs to the same organizational domain as From, and no trusted DMARC result is recorded.', 'Ask whether the sending service is expected to send for this domain. Without alignment the From address is not confirmed.'],
		'EHA-RP-001': ['info', 'Return-Path on another domain', 'Bounces go to a different organizational domain than From. Newsletter and ticket services do this routinely.', 'Usually harmless. It matters more together with failed authentication or a lookalike domain.'],
		'EHA-REPLY-001': ['medium', 'Reply-To on another domain', 'Replies would go to a different organizational domain than the From address. Fraud messages use this to receive answers while showing a trusted sender.', 'Before replying, check the Reply-To address. Reply to a known address instead.'],
		'EHA-FROM-001': ['medium', 'Another address or domain in the display name', 'The name shown in From contains an address or domain that is not the real sender address. Mail apps often show only the name.', 'Look at the actual address in angle brackets, not at the name.'],
		'EHA-FROM-002': ['medium', 'Display name names a brand the address does not belong to', 'The name shown in From names a well-known company, but the sending domain is not one of its domains.', 'Do not trust the name. Go to the company website yourself instead of using links in the message.'],
		'EHA-FROM-003': ['low', 'From missing or unusual', 'The From header is missing, empty or lists more than one address.', 'Treat the sender as unknown.'],
		'EHA-LOOK-001': ['low', 'Internationalized domain', 'A sender domain is written in punycode (xn--), which mail apps may show with non-Latin or accented letters. Legitimate for many local names, but also used for lookalikes.', 'Compare the decoded form shown here with the domain you expect.'],
		'EHA-LOOK-002': ['medium', 'Mixed alphabets in a domain', 'A domain label mixes letters from different alphabets, for example Latin and Cyrillic. This is a common way to imitate a domain.', 'Treat the domain as a lookalike unless you know it.'],
		'EHA-LOOK-003': ['high', 'Lookalike domain', 'The From or Reply-To domain looks like a well-known brand or like your own domain (similar letters, digits for letters, rn for m, one changed letter, or the brand name inside another domain).', 'Compare letter by letter with the real domain. Do not use links, attachments or reply.'],
		'EHA-MSGID-001': ['low', 'No Message-ID', 'Almost all mail software adds a Message-ID. Its absence suggests a hand-made or bulk-sending script.', 'Treat as a minor sign, stronger together with other findings.'],
		'EHA-MSGID-002': ['info', 'Message-ID from another domain', 'The Message-ID was created under a different organizational domain than From. Many services (Outlook, newsletter tools) do this.', 'Usually harmless; it can show which system actually created the message.'],
		'EHA-DATE-001': ['low', 'No Date', 'The Date header is required and normally set by the sending software.', 'Treat as a minor sign, stronger together with other findings.'],
		'EHA-DATE-002': ['low', 'Unusual Date', 'The Date is in the future, far from the delivery time, cannot be read, or has a time zone that does not exist.', 'Compare it with the dates in the Received lines above the trust boundary.'],
		'EHA-INFO-001': ['info', 'Mail software named', 'X-Mailer or User-Agent names the program that created the message.', 'Information only. Bulk-sending libraries in personal-looking mail can be a sign of a campaign.'],
		'EHA-INFO-002': ['info', 'Originating IP recorded', 'X-Originating-IP shows the address of the device or webmail session that sent the message.', 'Information only. It can identify the sender\'s network; it is set by the sending service.'],
		'EHA-INFO-003': ['info', 'Bulk or list mail', 'List-Unsubscribe, List-Id or Precedence marks a newsletter, notification or mailing list.', 'Information only. Lists explain some SPF and DMARC failures.'],
		'EHA-BRAND-001': ['high', 'Claims a brand and fails authentication', 'The message presents itself as a well-known company (name or lookalike domain) and authentication failed or does not match From.', 'Treat as likely impersonation. Report it to your security team; do not use links, attachments or reply.']
	};
	const SEV_RANK = { high: 4, medium: 3, low: 2, info: 1 };
	// Own short list of often impersonated brands: words to recognise in display names and the organizational domains they use.
	const BRANDS = [
		['PayPal', ['paypal'], ['paypal.com', 'paypal.de', 'paypal.me']],
		['Microsoft', ['microsoft', 'office 365', 'microsoft 365', 'outlook', 'onedrive', 'sharepoint'], ['microsoft.com', 'office.com', 'office365.com', 'outlook.com', 'live.com', 'hotmail.com', 'microsoftonline.com', 'sharepoint.com', 'onmicrosoft.com']],
		['Apple', ['apple', 'icloud', 'itunes'], ['apple.com', 'icloud.com', 'me.com', 'appleid.com']],
		['Amazon', ['amazon'], ['amazon.com', 'amazon.de', 'amazon.co.uk', 'amazon.fr', 'amazonses.com', 'amazon.es', 'amazon.it']],
		['Google', ['google', 'gmail'], ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com']],
		['DHL', ['dhl'], ['dhl.com', 'dhl.de']],
		['DocuSign', ['docusign'], ['docusign.com', 'docusign.net']],
		['Netflix', ['netflix'], ['netflix.com']],
		['Sparkasse', ['sparkasse'], ['sparkasse.de']],
		['Sberbank', ['sberbank', 'сбербанк', 'сбер'], ['sberbank.ru', 'sber.ru', 'sberbank.com']],
		['Telekom', ['telekom'], ['telekom.de', 'telekom.com', 't-online.de']],
		['LinkedIn', ['linkedin'], ['linkedin.com']],
		['Facebook', ['facebook', 'instagram'], ['facebook.com', 'facebookmail.com', 'instagram.com', 'meta.com']],
		['Dropbox', ['dropbox'], ['dropbox.com', 'dropboxmail.com']],
		['Adobe', ['adobe'], ['adobe.com']],
		['FedEx', ['fedex'], ['fedex.com']],
		['UPS', ['ups'], ['ups.com']],
		['Booking.com', ['booking.com'], ['booking.com']]
	].map(([name, words, domains]) => ({ name, words, domains, label: words[0] }));
	const PROVIDER_GROUPS = [['google.com', 'gmail.com', 'googlemail.com'], ['outlook.com', 'office365.com', 'microsoft.com', 'hotmail.com', 'live.com', 'exchangelabs.com']];
	// Mailbox providers that receive mail for a customer's own domain (Google Workspace, Microsoft 365). Kept short on purpose.
	const MAILBOX_PROVIDERS = [
		{ name: 'Google', host: /^mx\.google\.com$/u },
		{ name: 'Microsoft', host: /^(?:[a-z0-9-]+\.)+outlook\.com$/u }
	];
	const mailboxProvider = host => { const h = String(host || '').toLowerCase().replace(/\.$/u, ''); return MAILBOX_PROVIDERS.find(p => p.host.test(h)) || null; };

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
	const mask = v => { const c = [...String(v)]; return c.length <= 8 ? '••••' : c.slice(0, 4).join('') + '… (' + c.length + ' characters)'; };
	function entropy(s) { const m = new Map(); for (const ch of s) { m.set(ch, (m.get(ch) || 0) + 1); } let e = 0; for (const n of m.values()) { const p = n / s.length; e -= p * Math.log2(p); } return e; }
	function findSecrets(text) {
		const s = String(text || '');
		const out = [];
		const taken = (a, b) => out.some(x => a < x.end && b > x.start);
		for (const [kind, re] of SECRET_PATTERNS) { re.lastIndex = 0; let m; while ((m = re.exec(s))) { const a = m.index, b = a + m[0].length; if ((a > 0 && TOKEN_CHAR.test(s[a - 1]) && kind !== 'Private key') || taken(a, b)) { continue; } out.push({ kind, start: a, end: b, shown: kind === 'Private key' ? 'BEGIN … PRIVATE KEY' : mask(m[0]) }); } }
		const LONG = /[0-9A-Za-z+/=_\-.]{32,}/gu;
		let m;
		while ((m = LONG.exec(s))) {
			const v = m[0], a = m.index, b = a + v.length;
			if (taken(a, b) || (a > 0 && TOKEN_CHAR.test(s[a - 1])) || (b < s.length && TOKEN_CHAR.test(s[b]))) { continue; }
			if (!/[0-9]/u.test(v) || !/[A-Za-z]/u.test(v) || /^[0-9a-fA-F-]+$/u.test(v) || v.split('.').length > 2 || /^(?:https?|www)/iu.test(v) || entropy(v) < 4.2) { continue; }
			out.push({ kind: 'unrecognized long value', start: a, end: b, shown: mask(v) });
		}
		return out.sort((x, y) => x.start - y.start);
	}
	function maskSecrets(text) { let s = String(text === undefined || text === null ? '' : text); for (const x of findSecrets(s).sort((p, q) => q.start - p.start)) { s = s.slice(0, x.start) + '[' + x.kind + ': ' + x.shown + ']' + s.slice(x.end); } return s; }

	// ------------------------------------------------------------------ punycode (RFC 3492) and IDNA-like conversion
	const PB = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, BIAS0 = 72, N0 = 128;
	function adapt(delta, num, first) { let d = first ? Math.floor(delta / DAMP) : delta >> 1; d += Math.floor(d / num); let k = 0; while (d > ((PB - TMIN) * TMAX) >> 1) { d = Math.floor(d / (PB - TMIN)); k += PB; } return k + Math.floor((PB - TMIN + 1) * d / (d + SKEW)); }
	function digitOf(c) { const x = c.charCodeAt(0); if (x >= 48 && x <= 57) { return x - 22; } if (x >= 65 && x <= 90) { return x - 65; } if (x >= 97 && x <= 122) { return x - 97; } return PB; }
	const charOf = d => String.fromCharCode(d + 22 + 75 * (d < 26 ? 1 : 0));
	function punyDecode(input) {
		const out = [];
		const b = input.lastIndexOf('-');
		for (let j = 0; j < (b > 0 ? b : 0); j++) { if (input.charCodeAt(j) >= 128) { throw new Error('bad punycode'); } out.push(input.charCodeAt(j)); }
		let i = 0, n = N0, bias = BIAS0;
		for (let idx = b > 0 ? b + 1 : 0; idx < input.length;) {
			const oldi = i;
			for (let w = 1, k = PB; ; k += PB) {
				if (idx >= input.length) { throw new Error('bad punycode'); }
				const d = digitOf(input[idx++]);
				if (d >= PB) { throw new Error('bad punycode'); }
				i += d * w;
				const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
				if (d < t) { break; }
				w *= PB - t;
				if (w > 1e12) { throw new Error('bad punycode'); }
			}
			bias = adapt(i - oldi, out.length + 1, oldi === 0);
			n += Math.floor(i / (out.length + 1));
			i %= out.length + 1;
			if (n > 0x10ffff || out.length > 63) { throw new Error('bad punycode'); }
			out.splice(i++, 0, n);
		}
		return String.fromCodePoint(...out);
	}
	function punyEncode(str) {
		const cps = [...str].map(c => c.codePointAt(0));
		let out = cps.filter(c => c < 128).map(c => String.fromCharCode(c)).join('');
		const basic = out.length;
		let h = basic;
		if (basic) { out += '-'; }
		let n = N0, delta = 0, bias = BIAS0;
		while (h < cps.length) {
			const m = Math.min(...cps.filter(c => c >= n));
			delta += (m - n) * (h + 1);
			n = m;
			for (const c of cps) {
				if (c < n) { delta++; }
				if (c === n) {
					let q = delta;
					for (let k = PB; ; k += PB) { const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias; if (q < t) { break; } out += charOf(t + (q - t) % (PB - t)); q = Math.floor((q - t) / (PB - t)); }
					out += charOf(q);
					bias = adapt(delta, h + 1, h === basic);
					delta = 0;
					h++;
				}
			}
			delta++; n++;
		}
		return out;
	}
	function toASCII(domain) {
		return String(domain || '').trim().replace(/[.。．｡]+$/u, '').split(/[.。．｡]/u).map(l => { const x = nfc(l).toLowerCase(); if (/^[\x00-\x7f]*$/u.test(x)) { return x; } try { return 'xn--' + punyEncode(x); } catch (e) { return x; } }).join('.');
	}
	// A label that is not valid punycode for a domain name is never turned into Unicode: decoding error, an empty or all-ASCII
	// result, control, format, private-use, surrogate, noncharacter, space or other invisible characters, a leading combining
	// mark, a dot, hyphen rules, not NFC lower case, or a result that does not convert back to the same label. Such a label is
	// shown as it is (ASCII) and reported as invalid. The engine's own strict decoder is used everywhere (no URL or
	// domainToUnicode of the runtime), so Node and every browser give the same result.
	const IDN_BAD = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zs}\p{Zl}\p{Zp}\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufffb\ufdd0-\ufdef\ufffe\uffff\u{1fffe}\u{1ffff}\u{2fffe}\u{2ffff}\u{3fffe}\u{3ffff}\u{e0000}-\u{e0fff}.\u3002\uff0e\uff61]/u;
	function decodeLabel(label) {
		const a = String(label).toLowerCase();
		if (a.length > 63 || !/^xn--[a-z0-9-]+$/u.test(a)) { return null; }
		let u;
		try { u = punyDecode(a.slice(4)); } catch (e) { return null; }
		if (!u || /^[\x00-\x7f]*$/u.test(u) || IDN_BAD.test(u) || /^\p{M}/u.test(u) || /^-|-$/u.test(u) || /^..--/u.test(u) || u !== nfc(u).toLowerCase()) { return null; }
		let back;
		try { back = 'xn--' + punyEncode(u); } catch (e) { return null; }
		return back === a ? u : null;
	}
	/** Returns { unicode, invalid }: the display form of a domain and its xn-- labels that are not valid punycode. */
	function idnInfo(domain) {
		const invalid = [];
		const unicode = String(domain || '').split('.').map(l => {
			if (!/^xn--/iu.test(l)) { return l; }
			const u = decodeLabel(l);
			if (u === null) { invalid.push(l); return l; }
			return u;
		}).join('.');
		return { unicode, invalid };
	}
	function toUnicode(domain) { return idnInfo(domain).unicode; }

	// ------------------------------------------------------------------ Public Suffix List
	const PSL = { exact: new Set(), wild: new Set(), exc: new Set(), loaded: false, meta: null };
	function loadPSL(text, meta) {
		PSL.exact = new Set(); PSL.wild = new Set(); PSL.exc = new Set();
		for (const line of String(text || '').split('\n')) {
			const t = line.trim();
			if (!t || t.startsWith('//')) { continue; }
			const rule = t.split(/\s/u)[0];
			if (rule.startsWith('!')) { PSL.exc.add(toASCII(rule.slice(1))); } else if (rule.startsWith('*.')) { PSL.wild.add(toASCII(rule.slice(2))); } else { PSL.exact.add(toASCII(rule)); }
		}
		PSL.loaded = PSL.exact.size > 1000;
		PSL.meta = meta ? { source: meta.source, license: meta.license, date: meta.date, sha256: meta.sha256 } : PSL.meta;
		return PSL.loaded;
	}
	/** Organizational (registrable) domain in ASCII, or '' when the domain is itself a public suffix or invalid. */
	function orgDomain(domain) {
		const d = toASCII(domain);
		if (!d || !d.includes('.') || d.length > 253) { return ''; }
		const L = d.split('.');
		if (L.some(x => !x)) { return ''; }
		let suffix = 1;
		if (PSL.loaded) {
			for (let i = 0; i < L.length; i++) {
				const cand = L.slice(i).join('.');
				if (PSL.exc.has(cand)) { suffix = L.length - i - 1; break; }
				if (PSL.exact.has(cand) || (i + 1 < L.length && PSL.wild.has(L.slice(i + 1).join('.')))) { suffix = L.length - i; break; }
			}
		} else {
			const last2 = L.slice(-2).join('.');
			if (L.length >= 3 && /^(?:co|com|org|net|gov|ac|edu)\.[a-z]{2}$/u.test(last2)) { suffix = 2; }
		}
		return L.length > suffix ? L.slice(-(suffix + 1)).join('.') : '';
	}
	function expandOrgs(orgs) { const s = new Set(orgs.filter(Boolean)); for (const g of PROVIDER_GROUPS) { if (g.some(x => s.has(x))) { g.forEach(x => s.add(x)); } } return s; }

	// ------------------------------------------------------------------ small parsers
	function isIPv4(s) { const p = String(s).split('.'); return p.length === 4 && p.every(x => /^(?:0|[1-9][0-9]{0,2})$/u.test(x) && Number(x) <= 255); }
	function isIPv6(s) {
		const t = String(s).replace(/%[0-9A-Za-z._-]+$/u, '');
		if (!t.includes(':') || t.length > 45 || !/^[0-9A-Fa-f:.]+$/u.test(t)) { return false; }
		const dbl = t.split('::');
		if (dbl.length > 2) { return false; }
		const parts = t.split(':').filter((x, i, a) => !(x === '' && (i === 0 || i === a.length - 1 || a[i - 1] === '')));
		let groups = 0;
		for (const g of parts) { if (g === '') { continue; } if (g.includes('.')) { if (!isIPv4(g)) { return false; } groups += 2; } else if (/^[0-9A-Fa-f]{1,4}$/u.test(g)) { groups++; } else { return false; } }
		return dbl.length === 2 ? groups < 8 : groups === 8;
	}
	function ipClass(ip) {
		if (!ip) { return ''; }
		if (isIPv4(ip)) {
			const [a, b, c] = ip.split('.').map(Number);
			if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) { return 'private'; }
			if (a === 127) { return 'loopback'; }
			if (a === 169 && b === 254) { return 'link-local'; }
			if (a === 100 && b >= 64 && b <= 127) { return 'shared'; }
			if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) { return 'documentation'; }
			return 'public';
		}
		const t = ip.toLowerCase().replace(/%.*$/u, '');
		if (t === '::1') { return 'loopback'; }
		if (/^fe[89ab]/u.test(t)) { return 'link-local'; }
		if (/^f[cd]/u.test(t)) { return 'private'; }
		if (/^2001:0?db8:/u.test(t)) { return 'documentation'; }
		return 'public';
	}
	const isInternalIp = ip => ['private', 'loopback', 'link-local', 'shared'].includes(ipClass(ip));
	function isHostname(s) {
		const t = String(s || '').replace(/\.$/u, '');
		if (!t.includes('.') || t.length > 253 || isIPv4(t)) { return false; }
		return t.split('.').every(l => l.length > 0 && l.length <= 63 && /^[\p{L}\p{N}](?:[\p{L}\p{N}_-]*[\p{L}\p{N}])?$/u.test(l));
	}
	const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
	const ZONES = { ut: 0, utc: 0, gmt: 0, z: 0, est: -300, edt: -240, cst: -360, cdt: -300, mst: -420, mdt: -360, pst: -480, pdt: -420 };
	/** RFC 5322 date -> { ms, tzValid, offsetMin } or null. */
	function parseDate(raw) {
		const s = String(raw || '').slice(0, 200);
		const m = /([0-9]{1,2})\s+([A-Za-z]{3})[A-Za-z]*\.?\s+([0-9]{2,4})\s+([0-9]{1,2}):([0-9]{2})(?::([0-9]{2}))?(?:\s+([+-][0-9]{4}|[A-Za-z]{1,5}))?/u.exec(s);
		if (!m) { return null; }
		const mon = MONTHS[m[2].toLowerCase()];
		if (mon === undefined) { return null; }
		let y = Number(m[3]);
		if (m[3].length === 2) { y += y < 50 ? 2000 : 1900; } else if (m[3].length === 3) { y += 1900; }
		const d = Number(m[1]), h = Number(m[4]), mi = Number(m[5]), se = Number(m[6] || 0);
		if (d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) { return null; }
		let off = 0, tzValid = true;
		const z = m[7] || '';
		if (/^[+-][0-9]{4}$/u.test(z)) {
			const hh = Number(z.slice(1, 3)), mm = Number(z.slice(3, 5));
			off = (z[0] === '-' ? -1 : 1) * (hh * 60 + mm);
			if (hh > 14 || ![0, 15, 30, 45].includes(mm) || (hh === 14 && mm > 0) || (z[0] === '-' && hh > 12)) { tzValid = false; }
		} else if (z) {
			const k = z.toLowerCase();
			if (Object.prototype.hasOwnProperty.call(ZONES, k)) { off = ZONES[k]; }
		}
		return { ms: Date.UTC(y, mon, d, h, mi, se) - off * 60000, tzValid, offsetMin: off };
	}
	/** Decodes RFC 2047 encoded words with TextDecoder; returns { text, unknownCharset }. */
	function decodeWords(value) {
		let unknown = '';
		const s = String(value || '').replace(/(=\?[^?\s]{1,40}\?[BbQq]\?[^?\s]*\?=)\s+(?==\?[^?\s]{1,40}\?[BbQq]\?)/gu, '$1');
		const text = s.replace(/=\?([^?\s]{1,40})\?([BbQq])\?([^?\s]*)\?=/gu, (all, cs, enc, data) => {
			let bytes;
			try {
				if (enc.toUpperCase() === 'B') { const bin = atobSafe(data); bytes = Uint8Array.from(bin, c => c.charCodeAt(0)); }
				else { const q = data.replace(/_/gu, ' '); const arr = []; for (let i = 0; i < q.length; i++) { if (q[i] === '=' && /^[0-9A-Fa-f]{2}$/u.test(q.slice(i + 1, i + 3))) { arr.push(parseInt(q.slice(i + 1, i + 3), 16)); i += 2; } else { arr.push(q.charCodeAt(i) & 255); } } bytes = Uint8Array.from(arr); }
				const label = cs.split('*')[0].toLowerCase();
				return new TextDecoder(label === 'utf8' ? 'utf-8' : label).decode(bytes);
			} catch (e) { unknown = cs; return all; }
		});
		return { text: nfc(text), unknownCharset: unknown };
	}
	function atobSafe(b64) {
		const t = String(b64).replace(/[^A-Za-z0-9+/]/gu, '');
		if (typeof atob === 'function') { return atob(t + '==='.slice((t.length + 3) % 4)); }
		return Buffer.from(t, 'base64').toString('latin1');
	}
	/** Address list parser: "Name <a@b>", "a@b", quoted names, groups; commas outside quotes and angle brackets. */
	function parseAddresses(value) {
		const s = String(value || '').slice(0, MAX_PARSE_CHARS);
		const items = [];
		let cur = '', q = false, ang = 0, par = 0;
		for (let i = 0; i < s.length; i++) {
			const c = s[i];
			if (q) { cur += c; if (c === '\\' && i + 1 < s.length) { cur += s[++i]; } else if (c === '"') { q = false; } continue; }
			if (c === '"') { q = true; } else if (c === '<') { ang++; } else if (c === '>') { ang = Math.max(0, ang - 1); } else if (c === '(') { par++; } else if (c === ')') { par = Math.max(0, par - 1); }
			if ((c === ',' || c === ';') && !ang && !par) { items.push(cur); cur = ''; continue; }
			cur += c;
		}
		items.push(cur);
		const out = [];
		for (const raw of items) {
			let t = raw.trim().replace(/^[^:<"]*:\s*/u, m => (m.includes('@') ? m : ''));
			if (!t) { continue; }
			let name = '', addr = '';
			const lt = t.lastIndexOf('<'), gt = t.lastIndexOf('>');
			if (lt >= 0 && gt > lt) { addr = t.slice(lt + 1, gt).trim(); name = t.slice(0, lt).trim(); }
			else { const m = /([^\s<>()"]+@[^\s<>()",;]+)/u.exec(t); addr = m ? m[1] : ''; name = m ? t.replace(m[1], '').replace(/[()]/gu, '').trim() : t; }
			name = name.replace(/^"(.*)"$/u, '$1').replace(/\\(.)/gu, '$1').trim();
			name = decodeWords(name).text.trim();
			const at = addr.lastIndexOf('@');
			const domain = at > 0 ? addr.slice(at + 1).replace(/[>.\s]+$/u, '').toLowerCase() : '';
			out.push({ name, address: addr, domain: domain ? toASCII(domain) : '', domainUnicode: domain ? toUnicode(toASCII(domain)) : '' });
		}
		return out.filter(x => x.address || x.name);
	}
	const domainOfAddr = a => { const s = String(a || '').replace(/^<|>$/gu, '').trim(); const at = s.lastIndexOf('@'); return at > 0 ? toASCII(s.slice(at + 1).replace(/[>.\s]+$/u, '')) : (isHostname(s) ? toASCII(s) : ''); };

	// ------------------------------------------------------------------ header block
	/** Splits input into the header block and the ignored rest. Unfolds continuation lines. */
	function readHeaders(text, tick) {
		let s = String(text || '').replace(/^\ufeff/u, '').replace(/\r+\n|\r/gu, '\n').replace(/[\u00a0\u2007\u202f]/gu, ' ');
		const lines = s.split('\n');
		let i = 0;
		while (i < lines.length && !lines[i].trim()) { i++; }
		if (i < lines.length && /^From [^\s:]+ /u.test(lines[i])) { i++; }
		const start = i;
		while (i < lines.length && lines[i].trim()) { i++; }
		const head = lines.slice(start, i);
		const rest = lines.slice(i + 1);
		const bodyChars = rest.join('\n').length;
		const bodyLines = rest.length && !(rest.length === 1 && !rest[0]) ? rest.length : 0;
		const ind = head.filter(l => l.trim()).map(l => l.length - l.replace(/^[ ]+/u, '').length);
		const common = head.length && head.every(l => /^\s/u.test(l)) ? Math.min(...ind) : 0;
		const headers = [];
		const notes = [];
		let orphan = 0;
		for (let raw of head) {
			if (tick && headers.length % 500 === 0) { tick(); }
			raw = raw.slice(common).replace(/\s+$/u, '');
			if (/^[ \t]/u.test(raw)) { if (headers.length) { headers[headers.length - 1].raw += '\n' + raw; headers[headers.length - 1].value += ' ' + raw.trim(); } else { orphan++; } continue; }
			const m = /^([!-9;-~][!-9;-~ ]{0,75}?)\s*:\s?(.*)$/u.exec(raw);
			if (!m || /\s/u.test(m[1].trim())) { if (headers.length) { headers[headers.length - 1].raw += '\n' + raw; headers[headers.length - 1].value += ' ' + raw.trim(); } else { orphan++; } continue; }
			if (headers.length >= MAX_HEADERS) { const e = new Error('More than ' + MAX_HEADERS + ' header lines.'); e.code = 'TOO_LARGE'; throw e; }
			headers.push({ name: m[1].trim(), key: m[1].trim().toLowerCase(), value: m[2].trim(), raw, index: headers.length });
		}
		if (orphan) { notes.push(orphan + ' line(s) before the first header were ignored.'); }
		for (const h of headers) { h.value = h.value.replace(/[ \t]+/gu, ' ').trim(); }
		return { headers, bodyLines, bodyChars, headerChars: head.join('\n').length, notes };
	}

	// ------------------------------------------------------------------ Received
	const KEYWORDS = ['from', 'by', 'via', 'with', 'id', 'for'];
	function splitClauses(main) {
		const out = {};
		let depth = 0, cur = null, buf = '';
		const flush = () => { if (cur && out[cur] === undefined) { out[cur] = buf.trim(); } buf = ''; };
		for (let i = 0; i < main.length; i++) {
			const c = main[i];
			if (c === '(' || c === '[') { depth++; } else if ((c === ')' || c === ']') && depth > 0) { depth--; }
			if (depth === 0 && (i === 0 || /\s/u.test(main[i - 1]))) {
				let kw = '';
				for (const k of KEYWORDS) { if (main.slice(i, i + k.length).toLowerCase() === k && (i + k.length === main.length || /\s/u.test(main[i + k.length]))) { kw = k; break; } }
				if (kw) { flush(); cur = kw; i += kw.length - 1; continue; }
			}
			buf += c;
		}
		flush();
		return out;
	}
	function ipsIn(text) {
		const out = [];
		for (let tok of String(text || '').split(/[\s()[\];,<>]+/u)) {
			tok = tok.replace(/^IPv6:/iu, '').replace(/[.:]$/u, m => (m === ':' ? '' : ''));
			if (isIPv4(tok) || isIPv6(tok)) { out.push(tok); }
		}
		return out;
	}
	function parseReceived(h) {
		const v = h.value.slice(0, MAX_PARSE_CHARS);
		const semi = v.lastIndexOf(';');
		const main = semi >= 0 ? v.slice(0, semi) : v;
		const dateRaw = semi >= 0 ? v.slice(semi + 1).trim() : '';
		const date = dateRaw ? parseDate(dateRaw) : null;
		const c = splitClauses(main);
		const hop = { headerIndex: h.index, raw: maskSecrets(h.value).slice(0, 2000), parsed: false, from: null, by: null, with: '', id: '', for: '', dateRaw: dateRaw.slice(0, 120), time: date ? date.ms : null, dateValid: !!date, ip: '', ipClass: '' };
		if (c.from !== undefined) {
			const f = c.from;
			const first = (f.split(/[\s(]/u)[0] || '').replace(/^\[|\]$/gu, '');
			const helo = (/helo[=\s]+([^\s()[\]]+)/iu.exec(f) || [])[1] || '';
			const paren = (/\(([^()]*)\)/u.exec(f) || [])[1] || '';
			const rdnsTok = (paren.trim().split(/\s+/u)[0] || '').replace(/\.$/u, '');
			const ips = ipsIn(f.replace(/^IPv6:/iu, ''));
			const host = isHostname(first) ? first.replace(/\.$/u, '') : (isIPv4(first.replace(/^IPv6:/iu, '')) || isIPv6(first.replace(/^IPv6:/iu, '')) ? '' : first);
			hop.from = { host, helo: helo.replace(/\.$/u, ''), rdns: isHostname(rdnsTok) ? rdnsTok : '', ip: ips[0] || '' };
			hop.ip = hop.from.ip;
			hop.ipClass = ipClass(hop.ip);
		}
		if (c.by !== undefined) {
			const b = c.by;
			const first = (b.split(/[\s(]/u)[0] || '').replace(/^\[|\]$/gu, '');
			const ips = ipsIn(b);
			hop.by = { host: isHostname(first) ? first.replace(/\.$/u, '') : '', ip: isIPv4(first) || isIPv6(first) ? first : (ips[0] || '') };
		}
		hop.with = (c.with || '').split(/[\s(]/u)[0] || '';
		hop.id = (c.id || '').split(/[\s(;]/u)[0] || '';
		hop.for = ((/<([^<>\s]+)>/u.exec(c.for || '') || [])[1] || (c.for || '').split(/[\s(;]/u)[0] || '').slice(0, 200);
		hop.parsed = !!((hop.from && (hop.from.host || hop.from.ip || hop.from.helo)) || (hop.by && (hop.by.host || hop.by.ip)));
		return hop;
	}
	const hopLabel = f => (f ? (f.rdns && f.rdns !== 'unknown' ? f.rdns : f.host && !/^(?:unknown|localhost)$/iu.test(f.host) ? f.host : f.helo || f.ip || '') : '');

	// ------------------------------------------------------------------ authentication headers
	function splitTop(v, sep) { const out = []; let depth = 0, cur = ''; for (const c of v) { if (c === '(') { depth++; } else if (c === ')' && depth) { depth--; } if (c === sep && !depth) { out.push(cur); cur = ''; } else { cur += c; } } out.push(cur); return out; }
	function parseAuthResults(h) {
		const segs = splitTop(h.value.slice(0, MAX_PARSE_CHARS), ';').map(x => x.trim()).filter(Boolean);
		let authserv = '';
		if (segs.length && !/^[A-Za-z0-9-]+\s*=/u.test(segs[0])) { authserv = segs.shift().split(/\s/u)[0].toLowerCase().replace(/\.$/u, ''); if (/^i=[0-9]+$/u.test(authserv) && segs.length && !/=/u.test(segs[0].split(/\s/u)[0])) { authserv = segs.shift().split(/\s/u)[0].toLowerCase(); } }
		if (/^i=/u.test(authserv)) { authserv = ''; }
		const methods = [];
		for (const s of segs) {
			const noComments = s.replace(/\([^()]*\)/gu, ' ');
			if (/^i=[0-9]+$/u.test(s) && !methods.length) { continue; }
			const m = /^([A-Za-z0-9-]+)\s*=\s*([A-Za-z]+)/u.exec(noComments.trim());
			if (!m) { if (!methods.length && !authserv && isHostname(s.split(/\s/u)[0])) { authserv = s.split(/\s/u)[0].toLowerCase(); } continue; }
			const props = {};
			for (const p of noComments.matchAll(/([A-Za-z]+)\.([A-Za-z0-9-]+)\s*=\s*([^\s;]+)/gu)) { props[(p[1] + '.' + p[2]).toLowerCase()] = p[3].replace(/^"|"$/gu, ''); }
			const dm = /(?:^|\s)d=([^\s;]+)/u.exec(noComments);
			if (dm && !props['header.d']) { props['header.d'] = dm[1]; }
			methods.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), props, comment: ((/\(([^()]*)\)/u.exec(s) || [])[1] || '').slice(0, 200) });
		}
		return { header: h.name, headerIndex: h.index, authservId: authserv, methods };
	}
	function parseReceivedSpf(h) {
		const v = h.value.slice(0, MAX_PARSE_CHARS);
		const result = ((/^([A-Za-z]+)/u.exec(v) || [])[1] || '').toLowerCase();
		const env = (/envelope-from=["<]?([^\s;"<>]+)/iu.exec(v) || [])[1] || (/domain of (?:[^\s@]+@)?([^\s;)]+)/iu.exec(v) || [])[1] || (/smtp\.mailfrom=([^\s;]+)/iu.exec(v) || [])[1] || '';
		const ip = (/client-ip=(?:IPv6:)?([0-9A-Fa-f:.]+)/iu.exec(v) || [])[1] || '';
		return { header: h.name, headerIndex: h.index, result, domain: domainOfAddr(env), ip };
	}
	function parseDkimSignature(h) {
		const tags = {};
		for (const part of h.value.slice(0, MAX_PARSE_CHARS).split(';')) { const k = part.indexOf('='); if (k > 0) { tags[part.slice(0, k).trim().toLowerCase()] = part.slice(k + 1).replace(/\s+/gu, ''); } }
		return { headerIndex: h.index, d: toASCII(tags.d || ''), s: (tags.s || '').slice(0, 100), a: (tags.a || '').slice(0, 40), h: (tags.h || '').split(':').filter(Boolean).slice(0, 60) };
	}

	// ------------------------------------------------------------------ lookalikes
	const CONFUSABLE = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'һ': 'h', 'ӏ': 'l', 'к': 'k', 'м': 'm', 'т': 't', 'в': 'b', 'н': 'h', 'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'τ': 't', 'υ': 'u', 'χ': 'x', 'β': 'b', 'μ': 'm', 'η': 'n', '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g', 'ı': 'i' };
	function skeleton(s) {
		let t = nfc(String(s || '').toLowerCase()).normalize('NFD').replace(/\p{M}/gu, '');
		t = [...t].map(c => CONFUSABLE[c] || c).join('');
		return t.replace(/rn/gu, 'm').replace(/vv/gu, 'w').replace(/i/gu, 'l');
	}
	function lev1(a, b) {
		if (a === b) { return 0; }
		if (Math.abs(a.length - b.length) > 1) { return 2; }
		let i = 0; while (i < a.length && i < b.length && a[i] === b[i]) { i++; }
		const ra = a.slice(i + 1), rb = b.slice(i + 1);
		if (a.length === b.length) { return ra === rb || (a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2)) ? 1 : 2; }
		return a.length > b.length ? (a.slice(i + 1) === b.slice(i) ? 1 : 2) : (b.slice(i + 1) === a.slice(i) ? 1 : 2);
	}
	function scriptsOf(label) {
		const s = new Set();
		for (const ch of label) {
			if (!/\p{L}/u.test(ch)) { continue; }
			s.add(/\p{Script=Latin}/u.test(ch) ? 'Latin' : /\p{Script=Cyrillic}/u.test(ch) ? 'Cyrillic' : /\p{Script=Greek}/u.test(ch) ? 'Greek' : 'other');
		}
		return s;
	}
	/** Returns { kind: 'brand'|'own', target } when the domain imitates a brand or an own domain. */
	function lookalike(domain, ownOrgs) {
		const uni = toUnicode(toASCII(domain));
		const org = orgDomain(domain);
		if (!org) { return null; }
		const orgUni = toUnicode(org);
		const orgLabel = orgUni.split('.')[0];
		const labels = uni.split('.').slice(0, -1).filter(Boolean);
		for (const b of BRANDS) {
			if (b.domains.includes(org)) { return null; }
		}
		const sk = skeleton(orgLabel);
		for (const b of BRANDS) {
			if (/[^a-z]/u.test(b.label)) { continue; }
			const bs = skeleton(b.label);
			for (const l of labels) {
				const ls = skeleton(l);
				if (ls === bs && l !== b.label) { return { kind: 'brand', target: b.name }; }
				if (ls.split('-').includes(bs) || (bs.length >= 5 && ls.includes(bs))) { return { kind: 'brand', target: b.name }; }
			}
			if (b.label.length >= 5 && orgLabel !== b.label && lev1(orgLabel, b.label) === 1) { return { kind: 'brand', target: b.name }; }
		}
		for (const o of ownOrgs) {
			const ol = toUnicode(o).split('.')[0];
			if (!ol || o === org || orgLabel === ol) { continue; }
			if (skeleton(ol) === sk || (ol.length >= 5 && lev1(orgLabel, ol) === 1)) { return { kind: 'own', target: o }; }
		}
		return null;
	}
	function brandInName(name, fromOrg) {
		const n = skeleton(name);
		const raw = nfc(String(name || '').toLowerCase());
		for (const b of BRANDS) {
			if (b.domains.includes(fromOrg)) { continue; }
			for (const w of b.words) {
				const hay = /[^a-z .]/u.test(w) ? raw : n;
				const ww = /[^a-z .]/u.test(w) ? w : skeleton(w);
				let k = hay.indexOf(ww);
				while (k >= 0) {
					const before = k === 0 ? '' : hay[k - 1], after = hay[k + ww.length] || '';
					if (!/[\p{L}\p{N}]/u.test(before) && !/[\p{L}\p{N}]/u.test(after)) { return b; }
					k = hay.indexOf(ww, k + 1);
				}
			}
		}
		return null;
	}

	// ------------------------------------------------------------------ analysis
	function analyze(text, opts) {
		const o = opts || {};
		const s = String(text === undefined || text === null ? '' : text);
		if (s.length > MAX_INPUT_CHARS) { const e = new Error('The input is larger than 5 MB.'); e.code = 'TOO_LARGE'; throw e; }
		if (!s.trim()) { const e = new Error('The input is empty.'); e.code = 'EMPTY'; throw e; }
		const tick = budget();
		const now = o.now ? Date.parse(o.now) : Date.now();
		const rd = readHeaders(s, tick);
		if (rd.headerChars > MAX_HEADER_CHARS) { const e = new Error('The header part is larger than 1 MB.'); e.code = 'TOO_LARGE'; throw e; }
		const H = rd.headers;
		if (!H.length) { const e = new Error('No header lines were found. Paste the headers or the whole message source, starting with lines such as “Received:” or “From:”.'); e.code = 'NO_HEADERS'; throw e; }
		const notes = rd.notes.slice();
		if (rd.bodyLines) { notes.push('The message body (' + rd.bodyLines + ' lines after the first empty line) was ignored: it is not analysed, shown or exported.'); }
		const all = k => H.filter(h => h.key === k);
		const one = k => H.find(h => h.key === k);
		const f = [];
		const add = (id, evidence, extra) => { if (!f.some(x => x.id === id)) { const d = DEF[id]; f.push(Object.assign({ id, severity: d[0], group: d[0] === 'info' ? 'info' : 'warning', title: d[1], explanation: d[2], next: d[3], evidence: evidence ? maskSecrets(nfc(evidence)).slice(0, 300) : '' }, extra || {})); } };

		// summary
		const fromH = all('from');
		const fromList = fromH.length ? parseAddresses(fromH.map(h => h.value).join(', ')) : [];
		const from = fromList[0] || null;
		const fromOrg = from && from.domain ? orgDomain(from.domain) : '';
		const replyTo = one('reply-to') ? parseAddresses(one('reply-to').value)[0] || null : null;
		const rpH = one('return-path');
		const returnPath = rpH ? (/<([^<>]*)>/u.exec(rpH.value) || [null, rpH.value.trim()])[1] : null;
		const subj = one('subject') ? decodeWords(one('subject').value) : null;
		if (subj && subj.unknownCharset) { notes.push('The subject uses the character set “' + subj.unknownCharset + '”, which this browser cannot decode; it is shown encoded.'); }
		const dateH = one('date');
		const date = dateH ? parseDate(dateH.value) : null;
		const msgId = one('message-id') ? one('message-id').value.trim() : '';
		const own = (Array.isArray(o.own) ? o.own : String(o.own || '').split(/[\s,;]+/u)).map(x => String(x).trim().replace(/^.*@/u, '').replace(/^\.+|\.+$/gu, '')).filter(Boolean).slice(0, 20);
		const ownOrgs = own.map(orgDomain).filter(Boolean);

		// path and trust boundary
		const recH = all('received').slice(0, MAX_RECEIVED);
		if (all('received').length > MAX_RECEIVED) { notes.push('Only the first ' + MAX_RECEIVED + ' Received lines were analysed.'); }
		const hops = recH.map(h => { tick(); return parseReceived(h); });
		let T;
		if (ownOrgs.length) { T = expandOrgs(ownOrgs); }
		else {
			const top = hops.find(x => x.parsed && x.by && x.by.host);
			const first = hops.length && hops[0].by && hops[0].by.host ? hops[0].by.host : (top ? top.by.host : '');
			T = expandOrgs([orgDomain(first)]);
		}
		const boundaryOf = TT => {
			const trustedHop = i => {
				const x = hops[i];
				if (i === 0) { return true; }
				if (!x.parsed || !x.by) { return false; }
				if (x.by.host) { return TT.has(orgDomain(x.by.host)); }
				return !!x.by.ip && isInternalIp(x.by.ip);
			};
			let bb = hops.length ? 0 : -1;
			while (bb >= 0 && bb + 1 < hops.length && trustedHop(bb + 1)) { bb++; }
			return bb;
		};
		// Results headers trusted by position: above the boundary Received line, or in the contiguous block right after it.
		const blockAfterOf = bb => { const set = new Set(); const i0 = bb >= 0 ? hops[bb].headerIndex : -1; if (i0 >= 0) { for (let j = i0 + 1; j < H.length && (H[j].key === 'authentication-results' || H[j].key === 'received-spf'); j++) { set.add(j); } } return set; };
		const positionAt = (bb, idx) => { const i0 = bb >= 0 ? hops[bb].headerIndex : -1; return i0 >= 0 && (idx < i0 || blockAfterOf(bb).has(idx)); };
		const idIn = (TT, id) => !id || !isHostname(id) || TT.has(orgDomain(id));
		const arRaw = all('authentication-results').map(parseAuthResults);
		const rspfRaw = all('received-spf').map(parseReceivedSpf);
		let b = boundaryOf(T);
		// Own domain hosted by a mailbox provider (Google Workspace, Microsoft 365): when the topmost external Received line
		// was written by that provider and nothing above it recorded results, the provider is the trust boundary, provided it
		// also wrote Authentication-Results in a trusted position. Results lower down that only name the provider stay untrusted.
		let providerBoundary = null;
		if (ownOrgs.length && b >= 0 && b + 1 < hops.length) {
			const nx = hops[b + 1];
			const pv = nx.parsed && nx.by && nx.by.host ? mailboxProvider(nx.by.host) : null;
			const hasTrusted = (TT, bb) => arRaw.some(x => positionAt(bb, x.headerIndex) && idIn(TT, x.authservId)) || rspfRaw.some(x => positionAt(bb, x.headerIndex));
			if (pv && !hasTrusted(T, b)) {
				const pOrg = orgDomain(nx.by.host);
				const P = expandOrgs([pOrg]);
				const T2 = expandOrgs([...T, pOrg]);
				const b2 = boundaryOf(T2);
				if (b2 > b && arRaw.some(x => positionAt(b2, x.headerIndex) && (!x.authservId || !isHostname(x.authservId) || P.has(orgDomain(x.authservId))))) {
					T = T2; b = b2;
					providerBoundary = { provider: pv.name, host: String(hops[b].by && hops[b].by.host ? hops[b].by.host : nx.by.host).toLowerCase().replace(/\.$/u, '') };
				}
			}
		}
		hops.forEach((x, i) => { x.trusted = b >= 0 && i <= b; x.boundary = i === b; x.step = hops.length - i; });
		const bh = b >= 0 ? hops[b] : null;
		const external = bh && bh.from ? { label: hopLabel(bh.from), host: bh.from.rdns || bh.from.host, helo: bh.from.helo, ip: bh.from.ip, ipClass: bh.from.ip ? ipClass(bh.from.ip) : '' } : null;
		const bottom = hops[hops.length - 1];
		const internal = hops.length > 0 && b === hops.length - 1 && (!bottom.from || !bottom.from.ip || isInternalIp(bottom.from.ip)) && !!fromOrg && T.has(fromOrg);
		// times
		const timed = hops.filter(x => x.parsed && x.time !== null);
		for (let i = 0; i < hops.length; i++) { const x = hops[i]; const below = hops.slice(i + 1).find(y => y.parsed && y.time !== null); x.delaySec = x.time !== null && below ? Math.round((x.time - below.time) / 1000) : null; }
		if (!hops.length) { add('EHA-PATH-005', ''); }
		if (hops.some(x => !x.parsed)) { add('EHA-PARSE-001', hops.filter(x => !x.parsed).length + ' line(s): ' + hops.find(x => !x.parsed).raw.slice(0, 120)); }
		if (hops.some(x => x.parsed && x.dateRaw === '')) { add('EHA-PATH-006', 'step ' + hops.find(x => x.parsed && x.dateRaw === '').step); }
		const back = hops.find(x => x.parsed && x.delaySec !== null && x.delaySec * 1000 < -SKEW_MS);
		if (back) { add('EHA-PATH-001', 'step ' + back.step + ' is ' + Math.round(-back.delaySec / 60) + ' minutes earlier than the step before'); }
		const fut = timed.find(x => x.time > now + FUTURE_MS);
		if (fut) { add('EHA-PATH-002', 'step ' + fut.step + ': ' + fut.dateRaw); }
		const totalSec = timed.length > 1 ? Math.round((timed[0].time - timed[timed.length - 1].time) / 1000) : null;
		if (totalSec !== null && totalSec > 3600) { add('EHA-PATH-003', Math.round(totalSec / 60) + ' minutes'); }

		// authentication results and their trust
		const bIdx = bh ? bh.headerIndex : -1;
		const blockAfter = new Set();
		if (bIdx >= 0) { for (let j = bIdx + 1; j < H.length && (H[j].key === 'authentication-results' || H[j].key === 'received-spf'); j++) { blockAfter.add(j); } }
		const positionTrusted = idx => bIdx >= 0 && (idx < bIdx || blockAfter.has(idx));
		const idTrusted = id => !id || !isHostname(id) || T.has(orgDomain(id));
		const ar = all('authentication-results').map(parseAuthResults).map(x => Object.assign(x, { trusted: positionTrusted(x.headerIndex) && idTrusted(x.authservId), reason: !positionTrusted(x.headerIndex) ? 'below the trust boundary' : !idTrusted(x.authservId) ? 'written by a server that is not yours' : 'written by your server' }));
		// A receiving server writes its results once: a second header with the same id just below the boundary line is not trusted.
		for (const x of ar) { if (x.trusted && blockAfter.has(x.headerIndex) && ar.some(y => y !== x && y.trusted && y.headerIndex < bIdx && y.authservId === x.authservId)) { x.trusted = false; x.reason = 'duplicate of the result written above by the same server'; } }
		const rspf = all('received-spf').map(parseReceivedSpf).map(x => Object.assign(x, { trusted: positionTrusted(x.headerIndex), reason: positionTrusted(x.headerIndex) ? 'written by your server' : 'below the trust boundary' }));
		const aar = all('arc-authentication-results').map(parseAuthResults);
		const dkimSigs = all('dkim-signature').map(parseDkimSignature);
		const tAr = ar.filter(x => x.trusted);
		const pick = m => { for (const x of tAr) { const r = x.methods.find(y => y.method === m); if (r) { return Object.assign({ trusted: true, authservId: x.authservId }, r); } } return null; };
		const eff = { spf: pick('spf'), dkim: null, dmarc: pick('dmarc'), arc: pick('arc') };
		const tDkim = tAr.flatMap(x => x.methods.filter(y => y.method === 'dkim'));
		if (tDkim.length) { const pass = tDkim.find(y => y.result === 'pass'); eff.dkim = Object.assign({ trusted: true }, pass || tDkim[0]); }
		if (!eff.spf) { const rs = rspf.find(x => x.trusted); if (rs) { eff.spf = { method: 'spf', result: rs.result, props: { 'smtp.mailfrom': rs.domain }, trusted: true, fromReceivedSpf: true }; } }
		const anyTrusted = tAr.length > 0 || rspf.some(x => x.trusted);
		const claimsPass = x => (x.methods || []).some(y => y.result === 'pass') || x.result === 'pass';
		const untrustedPass = ar.filter(x => !x.trusted && claimsPass(x)).concat(rspf.filter(x => !x.trusted && claimsPass(x)));
		const dm = eff.dmarc ? eff.dmarc.result : '';
		const dmarcPass = dm === 'pass' || dm === 'bestguesspass';
		const listId = !!one('list-id');
		const forwarded = (eff.arc && eff.arc.result === 'pass') || listId;
		if (dm === 'fail') { add(forwarded ? 'EHA-AUTH-006' : 'EHA-AUTH-001', 'dmarc=fail' + (eff.dmarc.props['header.from'] ? ' header.from=' + eff.dmarc.props['header.from'] : '') + (forwarded ? (eff.arc && eff.arc.result === 'pass' ? '; arc=pass' : '; List-Id present') : '')); }
		if (!dmarcPass && !(dm === 'fail' && forwarded)) {
			if (eff.spf && ['fail', 'softfail', 'permerror'].includes(eff.spf.result)) { add('EHA-AUTH-002', 'spf=' + eff.spf.result + (eff.spf.props['smtp.mailfrom'] ? ' smtp.mailfrom=' + eff.spf.props['smtp.mailfrom'] : '')); }
			if (tDkim.length && !tDkim.some(y => y.result === 'pass') && tDkim.some(y => y.result === 'fail' || y.result === 'permerror')) { add('EHA-AUTH-003', 'dkim=' + tDkim.find(y => y.result === 'fail' || y.result === 'permerror').result); }
		}
		if (!anyTrusted && !internal) { add('EHA-AUTH-004', ar.length || rspf.length ? (ar.length + rspf.length) + ' untrusted result header(s)' : 'none recorded'); }
		if (untrustedPass.length) { const u = untrustedPass[0]; add('EHA-AUTH-005', (u.header || 'Authentication-Results') + (u.authservId ? ' by ' + u.authservId : '') + ' (' + (u.reason || 'untrusted') + ')'); }

		// alignment
		const spfDomain = eff.spf && eff.spf.props['smtp.mailfrom'] ? domainOfAddr(eff.spf.props['smtp.mailfrom']) : (returnPath ? domainOfAddr(returnPath) : '');
		const spfSource = eff.spf && eff.spf.props['smtp.mailfrom'] ? (eff.spf.fromReceivedSpf ? 'Received-SPF (trusted)' : 'Authentication-Results smtp.mailfrom (trusted)') : returnPath ? 'Return-Path (not verified)' : '';
		const dkimDomains = tDkim.length ? tDkim.map(y => ({ domain: domainOfAddr(y.props['header.d'] || y.props['header.i'] || ''), result: y.result, verified: true })) : dkimSigs.map(x => ({ domain: x.d, result: 'not verified', verified: false }));
		const alignment = {
			fromDomain: from ? from.domain : '', fromDomainUnicode: from ? from.domainUnicode : '', fromOrg, approximate: !PSL.loaded,
			spf: { domain: spfDomain, org: spfDomain ? orgDomain(spfDomain) : '', source: spfSource, result: eff.spf ? eff.spf.result : '', aligned: !!spfDomain && !!fromOrg && orgDomain(spfDomain) === fromOrg },
			dkim: dkimDomains.filter(x => x.domain).map(x => Object.assign(x, { org: orgDomain(x.domain), aligned: !!fromOrg && orgDomain(x.domain) === fromOrg }))
		};
		if (!['pass', 'fail', 'bestguesspass'].includes(dm) && !internal && fromOrg) {
			const ids = (alignment.spf.domain ? 1 : 0) + alignment.dkim.length;
			const ok = anyTrusted ? ((alignment.spf.aligned && eff.spf && eff.spf.result === 'pass') || alignment.dkim.some(x => x.aligned && x.result === 'pass')) : (alignment.spf.aligned || alignment.dkim.some(x => x.aligned));
			if (ids && !ok) { add('EHA-ALIGN-001', 'From ' + fromOrg + '; SPF domain ' + (alignment.spf.domain || 'none') + '; DKIM ' + (alignment.dkim.map(x => x.domain).join(', ') || 'none')); }
		}

		// sender identity
		if (!fromH.length || fromList.filter(x => x.address).length !== 1) { add('EHA-FROM-003', fromH.length ? fromList.filter(x => x.address).length + ' addresses' : 'no From header'); }
		if (rpH && returnPath && returnPath.includes('@') && fromOrg && orgDomain(domainOfAddr(returnPath)) && orgDomain(domainOfAddr(returnPath)) !== fromOrg) { add('EHA-RP-001', 'Return-Path ' + domainOfAddr(returnPath)); }
		if (replyTo && replyTo.domain && fromOrg && orgDomain(replyTo.domain) !== fromOrg) { add('EHA-REPLY-001', 'Reply-To ' + replyTo.domainUnicode); }
		let brand = null;
		if (from && from.name && fromOrg) {
			const inName = [];
			const nm = from.name.slice(0, 300);
			for (const m of nm.matchAll(/[^\s<>"'@(),;:]+@([^\s<>"'(),;:]+)/gu)) { inName.push(m[1]); }
			for (const m of nm.matchAll(/(?:^|[^\p{L}\p{N}@.-])((?:[\p{L}\p{N}-]+\.)+[\p{L}]{2,})(?=$|[^\p{L}\p{N}.-])/gu)) { inName.push(m[1]); }
			const other = inName.map(x => x.toLowerCase().replace(/\.$/u, '')).find(x => orgDomain(x) && orgDomain(x) !== fromOrg);
			if (other) { add('EHA-FROM-001', 'name “' + from.name + '” mentions ' + other); }
			const bn = brandInName(nm, fromOrg);
			if (bn) { brand = bn.name; add('EHA-FROM-002', 'name “' + from.name + '”, address domain ' + (from.domainUnicode || from.domain)); }
		}
		const idDomains = [from && from.domain, replyTo && replyTo.domain, returnPath && domainOfAddr(returnPath)].filter(Boolean);
		const puny = idDomains.find(d => d.split('.').some(l => l.startsWith('xn--')));
		if (puny) {
			// every punycode sender domain is listed; an invalid label stays in ASCII and is named, so the alphabet check below
			// cannot pass it silently
			const shown = [...new Set(idDomains.filter(d => d.split('.').some(l => l.startsWith('xn--'))))].map(d => {
				const x = idnInfo(d);
				return d + (x.unicode !== d ? ' = ' + x.unicode : '') + (x.invalid.length ? ' (invalid punycode label' + (x.invalid.length > 1 ? 's ' : ' ') + x.invalid.join(', ') + ': not decoded, shown in ASCII; alphabets not checked)' : '');
			});
			add('EHA-LOOK-001', shown.join('; '));
		}
		const mixed = idDomains.find(d => toUnicode(d).split('.').some(l => scriptsOf(l).size > 1));
		if (mixed) { add('EHA-LOOK-002', toUnicode(mixed) + ' (' + toUnicode(mixed).split('.').map(l => [...scriptsOf(l)].join('+')).filter(x => x.includes('+')).join(', ') + ')'); }
		for (const d of [from && from.domain, replyTo && replyTo.domain].filter(Boolean)) {
			const lk = lookalike(d, ownOrgs);
			if (lk) { if (lk.kind === 'brand') { brand = brand || lk.target; } add('EHA-LOOK-003', toUnicode(d) + ' resembles ' + (lk.kind === 'brand' ? 'the brand ' + lk.target : 'your domain ' + lk.target)); break; }
		}
		const authFailed = f.some(x => x.id === 'EHA-AUTH-001' || x.id === 'EHA-ALIGN-001') || (f.some(x => x.id === 'EHA-AUTH-002') && f.some(x => x.id === 'EHA-AUTH-003'));
		if (brand && authFailed) { add('EHA-BRAND-001', brand + '; ' + f.filter(x => ['EHA-AUTH-001', 'EHA-AUTH-002', 'EHA-AUTH-003', 'EHA-ALIGN-001'].includes(x.id)).map(x => x.id).join(', ')); }
		// Message-ID, Date, information
		if (!msgId) { add('EHA-MSGID-001', ''); }
		else if (fromOrg) { const md = domainOfAddr((/@([^>@\s]+)>?\s*$/u.exec(msgId) || [])[1] || ''); if (md && orgDomain(md) && orgDomain(md) !== fromOrg) { add('EHA-MSGID-002', md); } }
		if (!dateH) { add('EHA-DATE-001', ''); }
		else {
			// reference times come only from lines written by the user's servers (above the trust boundary)
			const tt = timed.filter(x => x.trusted);
			const topTime = tt.length ? tt[0].time : null, botTime = tt.length ? tt[tt.length - 1].time : null;
			const bad = !date ? 'cannot be read' : !date.tzValid ? 'impossible time zone' : date.ms > now + FUTURE_MS ? 'in the future' : topTime !== null && date.ms > topTime + FUTURE_MS ? 'after delivery' : botTime !== null && date.ms < botTime - 7 * 86400000 ? 'more than 7 days before delivery' : '';
			if (bad) { add('EHA-DATE-002', dateH.value.slice(0, 80) + ' (' + bad + ')'); }
		}
		const mailer = one('x-mailer') || one('user-agent');
		if (mailer) { add('EHA-INFO-001', mailer.name + ': ' + mailer.value.slice(0, 120)); }
		const xoip = one('x-originating-ip');
		if (xoip) { add('EHA-INFO-002', xoip.value.slice(0, 60)); }
		const prec = one('precedence');
		if (one('list-unsubscribe') || listId || (prec && /^(?:bulk|list|junk)$/iu.test(prec.value.trim()))) { add('EHA-INFO-003', [one('list-id') && 'List-Id', one('list-unsubscribe') && 'List-Unsubscribe', prec && 'Precedence: ' + prec.value].filter(Boolean).join(', ')); }

		f.sort((x, y) => SEV_RANK[y.severity] - SEV_RANK[x.severity] || (x.id < y.id ? -1 : 1));
		const counts = { high: 0, medium: 0, low: 0, info: 0 };
		for (const x of f) { counts[x.severity]++; }
		const addrOut = list => list.map(a => ({ name: maskSecrets(a.name).slice(0, 200), address: a.address.slice(0, 254), domain: a.domainUnicode || a.domain }));
		return {
			engine: ENGINE, ruleset: RULESET, psl: PSL.meta, pslLoaded: PSL.loaded,
			headerCount: H.length, bodyIgnored: { lines: rd.bodyLines, chars: rd.bodyChars }, notes,
			summary: {
				from: from ? { name: maskSecrets(from.name).slice(0, 200), address: from.address.slice(0, 254), domain: from.domainUnicode || from.domain } : null, fromCount: fromList.filter(x => x.address).length,
				replyTo: replyTo ? addrOut([replyTo])[0] : null, returnPath: returnPath ? returnPath.slice(0, 254) : null,
				to: addrOut(parseAddresses(all('to').map(h => h.value).join(', '))).slice(0, 50), cc: addrOut(parseAddresses(all('cc').map(h => h.value).join(', '))).slice(0, 50),
				deliveredTo: all('delivered-to').concat(all('x-original-to'), all('envelope-to')).map(h => h.value.slice(0, 254)).slice(0, 20),
				subject: subj ? maskSecrets(subj.text).slice(0, 500) : null, date: dateH ? { raw: dateH.value.slice(0, 120), iso: date ? new Date(date.ms).toISOString() : null } : null, messageId: msgId.slice(0, 300),
				mailer: mailer ? mailer.value.slice(0, 200) : '', originatingIp: xoip ? xoip.value.slice(0, 60) : ''
			},
			path: { hops, boundaryIndex: b, trustedOrgs: [...T].filter(Boolean), ownDeclared: ownOrgs.length > 0, providerBoundary, external, internal, totalDelaySec: totalSec },
			auth: { results: ar, receivedSpf: rspf, arc: aar, dkimSignatures: dkimSigs, effective: eff, alignment },
			findings: f, counts
		};
	}

	const NOTE = 'Based only on the headers as recorded by the servers. No DNS, WHOIS, reputation or DKIM signature check was made. No finding does not mean a message is safe or genuine: a hijacked real account passes every check. The message body was not analysed or included.';
	const mdEsc = s => String(s).replace(/([\\`*_{}[\]<>()#+!|~])/gu, '\\$1').replace(/\r?\n/gu, ' ');
	/** Markdown and JSON report. maskRecipients: To, Cc, delivery addresses and Received "for"; maskInternal: private, loopback and link-local IPs. */
	function exportReport(result, opts) {
		const o = opts || {};
		const r = JSON.parse(JSON.stringify(result));
		const ipMap = new Map(), rcMap = new Map();
		const maskIp = ip => { if (!o.maskInternal || !ip || !isInternalIp(ip)) { return ip; } if (!ipMap.has(ip)) { ipMap.set(ip, '[internal IP ' + (ipMap.size + 1) + ']'); } return ipMap.get(ip); };
		const recips = new Set();
		if (o.maskRecipients) {
			for (const a of r.summary.to.concat(r.summary.cc)) { if (a.address) { recips.add(a.address.toLowerCase()); } }
			for (const d of r.summary.deliveredTo) { recips.add(d.replace(/[<>]/gu, '').trim().toLowerCase()); }
			for (const h of r.path.hops) { if (h.for) { recips.add(h.for.toLowerCase()); } }
		}
		const maskRc = a => { const k = String(a || '').toLowerCase(); if (!o.maskRecipients || !recips.has(k)) { return a; } if (!rcMap.has(k)) { rcMap.set(k, '[recipient ' + (rcMap.size + 1) + ']'); } return rcMap.get(k); };
		const scrub = s => {
			let t = maskSecrets(String(s));
			if (o.maskRecipients) { for (const a of recips) { if (a) { t = t.split(a).join(maskRc(a)); const up = a.toUpperCase(); t = t.split(up).join(maskRc(a)); } } }
			if (o.maskInternal) { t = t.replace(/[0-9A-Fa-f:.%]{3,}/gu, m => (isIPv4(m) || isIPv6(m) ? maskIp(m) : m)); }
			return t;
		};
		const walk = v => (typeof v === 'string' ? scrub(v) : Array.isArray(v) ? v.map(walk) : isObj(v) ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)])) : v);
		const clean = walk(r);
		if (o.maskRecipients) { clean.summary.to = clean.summary.to.map(a => ({ name: a.name ? '[name]' : '', address: maskRc(a.address), domain: '' })); clean.summary.cc = clean.summary.cc.map(a => ({ name: a.name ? '[name]' : '', address: maskRc(a.address), domain: '' })); }
		const json = { tool: 'CyberDat Email Header Analyzer', engine: ENGINE, ruleset: RULESET, publicSuffixList: r.psl, generatedAt: o.timestamp || new Date().toISOString(), note: NOTE, masked: { recipients: !!o.maskRecipients, internalIps: !!o.maskInternal, secrets: true }, summary: clean.summary, bodyIgnored: clean.bodyIgnored, notes: clean.notes, path: { boundaryIndex: clean.path.boundaryIndex, trustedOrgs: clean.path.trustedOrgs, providerBoundary: clean.path.providerBoundary, external: clean.path.external, internal: clean.path.internal, totalDelaySec: clean.path.totalDelaySec, hops: clean.path.hops.map(h => ({ step: h.step, parsed: h.parsed, trusted: h.trusted, boundary: h.boundary, from: h.from, by: h.by, with: h.with, id: h.id, for: h.for, date: h.dateRaw, delaySec: h.delaySec, ipClass: h.ipClass, raw: h.parsed ? undefined : h.raw })) }, auth: clean.auth, counts: clean.counts, findings: clean.findings };
		const S = clean.summary;
		const L = ['# Email header analysis', '', 'Generated with CyberDat Email Header Analyzer ' + ENGINE + ' (rules ' + RULESET + ') on ' + mdEsc(json.generatedAt) + '.', '', '> ' + NOTE, ''];
		L.push('- From: ' + (S.from ? mdEsc((S.from.name ? S.from.name + ' ' : '') + '<' + S.from.address + '>') : 'missing'));
		if (S.replyTo) { L.push('- Reply-To: ' + mdEsc(S.replyTo.address)); }
		if (S.returnPath) { L.push('- Return-Path: ' + mdEsc(S.returnPath)); }
		L.push('- To: ' + mdEsc(S.to.map(a => a.address).join(', ') || '—'));
		L.push('- Subject: ' + mdEsc(S.subject === null ? '—' : S.subject));
		L.push('- Date: ' + mdEsc(S.date ? S.date.raw : 'missing'));
		L.push('- High: ' + clean.counts.high + '; medium: ' + clean.counts.medium + '; low: ' + clean.counts.low + '; info: ' + clean.counts.info, '');
		L.push('## Findings', '');
		const warn = clean.findings.filter(x => x.group === 'warning'), info = clean.findings.filter(x => x.group === 'info');
		if (!warn.length && !info.length) { L.push('No known warning signs matched. This does not mean the message is safe.', ''); }
		for (const x of warn) { L.push('- **' + x.severity.toUpperCase() + '** ' + x.id + ' — ' + mdEsc(x.title) + (x.evidence ? ': `' + x.evidence.replace(/`/gu, '\'') + '`' : ''), '  - Why: ' + mdEsc(x.explanation), '  - Check next: ' + mdEsc(x.next)); }
		if (info.length) { L.push('', '### Minor and informational', ''); for (const x of info) { L.push('- ' + x.id + ' — ' + mdEsc(x.title) + (x.evidence ? ': `' + x.evidence.replace(/`/gu, '\'') + '`' : '')); } }
		L.push('', '## Path (from sender to recipient)', '');
		if (json.path.providerBoundary) { L.push('Trust boundary: ' + mdEsc(json.path.providerBoundary.host) + ' (mailbox provider for your domain).', ''); }
		L.push('| Step | From | By | Time | Delay | Trust |', '|---|---|---|---|---|---|');
		for (const h of json.path.hops.slice().reverse()) { L.push('| ' + h.step + ' | ' + mdEsc(h.parsed ? [h.from && (h.from.rdns || h.from.host || h.from.helo), h.from && h.from.ip].filter(Boolean).join(' ') : 'not parsed: ' + String(h.raw || '').slice(0, 80)) + ' | ' + mdEsc(h.by ? h.by.host || h.by.ip : '') + ' | ' + mdEsc(h.date || '—') + ' | ' + (h.delaySec === null ? '—' : h.delaySec + ' s') + ' | ' + (h.boundary ? 'trust boundary' : h.trusted ? 'your servers' : 'not verifiable') + ' |'); }
		L.push('', '## Authentication', '');
		for (const a of clean.auth.results) { L.push('- ' + (a.trusted ? 'Trusted' : 'NOT trusted (' + a.reason + ')') + ' ' + mdEsc(a.header) + (a.authservId ? ' by ' + mdEsc(a.authservId) : '') + ': ' + a.methods.map(m => m.method + '=' + m.result).join(', ')); }
		const al = clean.auth.alignment;
		L.push('- Alignment' + (al.approximate ? ' (approximate: Public Suffix List not loaded)' : '') + ': From ' + mdEsc(al.fromOrg || '—') + '; SPF ' + mdEsc(al.spf.domain || '—') + (al.spf.aligned ? ' aligned' : ' not aligned') + '; DKIM ' + mdEsc(al.dkim.map(x => x.domain + (x.aligned ? ' aligned' : ' not aligned')).join(', ') || '—'), '');
		return { json: JSON.stringify(json, null, 2) + '\n', markdown: L.join('\n') + '\n' };
	}

	const EXAMPLE_NORMAL = 'Return-Path: <alice@example.org>\nDelivered-To: bob@example.com\nReceived: from mx.example.com (mx.example.com [192.0.2.25])\n\tby imap.example.com (Postfix) with ESMTPS id 4Xk9Ex1\n\tfor <bob@example.com>; Wed, 18 Nov 2026 14:02:07 +0100 (CET)\nAuthentication-Results: mx.example.com;\n\tspf=pass smtp.mailfrom=example.org;\n\tdkim=pass header.d=example.org header.s=s2026;\n\tdmarc=pass header.from=example.org\nReceived: from mail.example.org (mail.example.org [198.51.100.10])\n\tby mx.example.com (Postfix) with ESMTPS id 4Xk9Ex0\n\tfor <bob@example.com>; Wed, 18 Nov 2026 14:02:05 +0100 (CET)\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=s2026;\n\th=from:to:subject:date:message-id; bh=ZXhhbXBsZQ==; b=ZXhhbXBsZQ==\nFrom: =?UTF-8?Q?J=C3=BCrgen_Beispiel?= <juergen@example.org>\nTo: Bob <bob@example.com>\nSubject: Meeting notes\nDate: Wed, 18 Nov 2026 14:02:01 +0100\nMessage-ID: <20261118130201.4711@mail.example.org>\n\n(The message body would be here; it is ignored.)\n';
	const EXAMPLE_PHISHING = 'Return-Path: <bounce@bulk.example.net>\nDelivered-To: bob@example.com\nReceived: from mx.example.com (mx.example.com [192.0.2.25])\n\tby imap.example.com (Postfix) with ESMTPS id 4Xm1Ab2\n\tfor <bob@example.com>; Wed, 18 Nov 2026 09:15:44 +0100 (CET)\nAuthentication-Results: mx.example.com;\n\tspf=softfail smtp.mailfrom=bulk.example.net;\n\tdkim=none;\n\tdmarc=fail header.from=paypa1-secure.example\nReceived: from unknown (unknown [203.0.113.44])\n\tby mx.example.com (Postfix) with ESMTP id 4Xm1Ab1\n\tfor <bob@example.com>; Wed, 18 Nov 2026 09:15:42 +0100 (CET)\nAuthentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\nReceived: from mail.paypal.example (mail.paypal.example [198.51.100.7])\n\tby relay.bulk.example.net with ESMTP id 77; Wed, 18 Nov 2026 07:10:00 +0000\nFrom: "PayPal Service" <service@paypa1-secure.example>\nReply-To: support@example.net\nTo: bob@example.com\nSubject: =?UTF-8?B?WW91ciBhY2NvdW50IGlzIGxpbWl0ZWQ=?=\nDate: Wed, 18 Nov 2026 09:15:40 +0100\nX-Mailer: PHPMailer 6.9.1\n\n(The message body would be here; it is ignored.)\n';

	return { ENGINE, RULESET, MAX_INPUT_CHARS, MAX_HEADER_CHARS, DEF, BRANDS, MAILBOX_PROVIDERS, loadPSL, orgDomain, toASCII, toUnicode, idnInfo, punyEncode, punyDecode, decodeWords, parseAddresses, parseDate, parseReceived, readHeaders, isIPv4, isIPv6, ipClass, skeleton, analyze, exportReport, findSecrets, maskSecrets, EXAMPLE_NORMAL, EXAMPLE_PHISHING };
}));
