/*!
 * CyberDat Privacy Shield Log Anonymizer — detection and replacement engine.
 *
 * Pure, dependency-free and side-effect free: no DOM, storage or network APIs
 * are used. Loaded by the Web Worker (importScripts) and by Node.js tests.
 *
 * Invariants:
 *  - Replacement spans never contain line breaks, so the number of lines and
 *    every delimiter outside a replaced value are preserved.
 *  - Every regular expression is line-local (no \s that could cross lines)
 *    and uses bounded quantifiers to keep scanning close to linear time.
 *    The only multi-line detector (private keys) is bounded to 64 KiB.
 */
(function (root, factory) {
	'use strict';
	const api = factory();
	if (typeof module === 'object' && module.exports) {
		module.exports = api;
	} else {
		root.CyberDatLogAnonymizer = api;
	}
}(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const VERSION = '1.0.3';
	const RULESET_VERSION = '2026-11-14.1';
	const CHUNK_CHARS = 1 << 20;
	const MAX_KEY_BLOCK = 65536;
	const MAX_CUSTOM_RULES = 20;
	const MAX_CUSTOM_PATTERN = 1000;

	/** Toggleable categories, in display order. */
	const CATEGORIES = [
		{ id: 'ipv4', name: 'IPv4 addresses', prefix: 'IPV4' },
		{ id: 'ipv6', name: 'IPv6 addresses', prefix: 'IPV6' },
		{ id: 'email', name: 'Email addresses', prefix: 'EMAIL' },
		{ id: 'mac', name: 'MAC addresses', prefix: 'MAC' },
		{ id: 'jwt', name: 'JSON Web Tokens', prefix: 'JWT' },
		{ id: 'auth', name: 'Authorization headers (Bearer, Basic and others)', prefix: 'AUTH_TOKEN' },
		{ id: 'apiKey', name: 'Cloud and service API keys', prefix: 'API_KEY' },
		{ id: 'secret', name: 'Passwords and secrets (key=value, cookies, URL passwords)', prefix: 'SECRET' },
		{ id: 'privateKey', name: 'Private key blocks', prefix: 'PRIVATE_KEY' },
		{ id: 'username', name: 'Usernames', prefix: 'USER' },
		{ id: 'personName', name: 'Names in explicit person/contact fields', prefix: 'PERSON' },
		{ id: 'phone', name: 'Telephone numbers in explicit contact fields', prefix: 'PHONE' },
		{ id: 'host', name: 'Hostnames and domains', prefix: 'HOST' },
		{ id: 'card', name: 'Payment card numbers (Luhn-checked)', prefix: 'CARD' },
		{ id: 'ssn', name: 'US Social Security numbers', prefix: 'SSN' },
		{ id: 'custom', name: 'Custom rules', prefix: 'CUSTOM' }
	];
	const CATEGORY_IDS = CATEGORIES.map(c => c.id);

	function defaultOptions() {
		const categories = {};
		for (const id of CATEGORY_IDS) { categories[id] = true; }
		return { categories, labelMode: 'stable', keepPrivateIPv4: false, customRules: [] };
	}

	// ---------------------------------------------------------------- helpers

	const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
	const IPV4_SOURCE = '(?:' + OCTET + '\\.){3}' + OCTET;
	const IPV4_EXACT = new RegExp('^' + IPV4_SOURCE + '$');
	const EMAIL_EXACT = /^[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,63}$/;
	const LABEL_LIKE = /^(?:REDACTED_[A-Z0-9_]+|[A-Z][A-Z0-9_]{1,40}_\d{1,9})$/;
	const PLACEHOLDER_VALUES = new Set(['', '-', '--', '*', 'null', 'nil', 'none', 'undefined', 'true', 'false', 'redacted', '[redacted]', '<redacted>', '(redacted)', '[filtered]', 'filtered', 'n/a', 'na', '<hidden>', 'hidden', 'masked', '[masked]']);

	function isPlaceholder(value) {
		const v = value.trim().toLowerCase();
		return PLACEHOLDER_VALUES.has(v) || /^\*{2,}$/.test(v) || /^x{4,}$/.test(v) || /^#{3,}$/.test(v) || LABEL_LIKE.test(value.trim()) || /\bREDACTED_[A-Z0-9_]+\b/.test(value);
	}

	function isIPv4(value) { return IPV4_EXACT.test(value); }

	/** 0.0.0.0, 255.255.255.255 and netmasks (255.255.255.0 …) identify nobody. */
	function isNonIdentifyingIPv4(value) {
		const p = value.split('.').map(Number);
		const n = ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
		if (n === 0) { return true; }
		const inverted = (~n) >>> 0;
		return p[0] === 255 && (inverted & (inverted + 1)) === 0;
	}

	function isPrivateIPv4(value) {
		const p = value.split('.').map(Number);
		return p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254);
	}

	function isIPv6(candidate) {
		let value = candidate;
		const zone = value.indexOf('%');
		if (zone !== -1) { value = value.slice(0, zone); }
		if (value.length < 2 || value === '::') { return false; }
		let groups;
		let extra = 0;
		const lastColon = value.lastIndexOf(':');
		const tail = value.slice(lastColon + 1);
		if (tail.indexOf('.') !== -1) {
			if (!isIPv4(tail)) { return false; }
			value = value.slice(0, lastColon + 1) + '0';
			extra = 1;
		}
		const doubles = value.split('::').length - 1;
		if (doubles > 1) { return false; }
		if (doubles === 0 && (value.startsWith(':') || value.endsWith(':'))) { return false; }
		if (doubles === 1) {
			if (/^:[^:]/.test(value) || /[^:]:$/.test(value)) { return false; }
			const [left, right] = value.split('::');
			const l = left ? left.split(':') : [];
			const r = right ? right.split(':') : [];
			groups = l.concat(r);
			if (groups.length + extra > 7) { return false; }
			// Guard against code such as "a::b": real prefixes have 2+ characters.
			if (left && l[0].length < 2) { return false; }
		} else {
			groups = value.split(':');
			if (groups.length + extra !== 8) { return false; }
		}
		return groups.every(g => /^[0-9A-Fa-f]{1,4}$/.test(g));
	}

	function luhnValid(digits) {
		let sum = 0;
		let double = false;
		for (let i = digits.length - 1; i >= 0; i--) {
			let d = digits.charCodeAt(i) - 48;
			if (double) { d *= 2; if (d > 9) { d -= 9; } }
			sum += d;
			double = !double;
		}
		return sum % 10 === 0;
	}

	const CARD_IIN = /^(?:4|5[1-5]|2(?:22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720)|3[47]|3(?:0[0-5]|[689])|6(?:011|5|4[4-9]|22)|35(?:2[89]|[3-8]\d)|62|50(?:18|20|38)|5893|6304|6759|676[1-3])/;

	function cardValid(raw) {
		const separators = raw.replace(/\d/g, '');
		if (separators && !/^(?: +|-+)$/.test(separators)) { return false; }
		if (separators) {
			const groups = raw.split(/[ -]/);
			if (groups.some(g => g.length < 3 || g.length > 6)) { return false; }
		}
		const digits = raw.replace(/\D/g, '');
		if (digits.length < 13 || digits.length > 19) { return false; }
		if (/^(\d)\1+$/.test(digits)) { return false; }
		return CARD_IIN.test(digits) && luhnValid(digits);
	}

	// Country-code TLDs (ISO 3166-1 alpha-2 plus common exceptional ccTLDs).
	const CC_TLDS = 'ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw';
	// Deliberately short generic list: word-like gTLDs (.name, .run, .page …) cause
	// too many false positives against code identifiers such as "user.name".
	const G_TLDS = 'com net org info biz edu gov mil int arpa io ai dev app cloud tech online site xyz security cyber local internal lan corp home localdomain intranet test example invalid';
	const TLDS = new Set((CC_TLDS + ' ' + G_TLDS).split(' '));
	// Two-label names ending in these are usually files or code ("app.py", "user.id").
	const TWO_LABEL_EXCLUDED = new Set('py rs sh md pl pm ps mo ml tf gs ms sc cr tk bz cc so ai app zip mov id to do is it in at by no as am be my on or an if me us cs ts js gz sk dll exe log ini yml'.split(' '));

	/**
	 * Shared AWS service endpoints ("iam.amazonaws.com", "ec2.eu-central-1.amazonaws.com") identify
	 * nobody and are needed to read CloudTrail. Bucket or account-specific names have more labels
	 * ("my-bucket.s3.eu-central-1.amazonaws.com") and are still masked.
	 */
	function isPublicServiceEndpoint(host) {
		return /^[a-z0-9-]{2,40}(?:\.[a-z]{2}(?:-gov)?-[a-z]{4,9}-\d)?\.amazonaws\.com$/.test(host.toLowerCase());
	}

	function hostValid(host) {
		const h = host.replace(/\.$/, '');
		if (h.length < 4 || h.length > 253 || isPublicServiceEndpoint(h)) { return false; }
		const labels = h.split('.');
		if (labels.length < 2) { return false; }
		const tld = labels[labels.length - 1].toLowerCase();
		if (!TLDS.has(tld)) { return false; }
		if (labels.length === 2 && TWO_LABEL_EXCLUDED.has(tld)) { return false; }
		// Mixed-case labels ("System.out", "Thread.run") are code, not hostnames.
		if (labels.some(l => /[a-z]/.test(l) && /[A-Z]/.test(l))) { return false; }
		if (labels.every(l => /^\d+$/.test(l.replace(/-/g, '')))) { return false; }
		return true;
	}

	function looksLikeAddress(value) {
		const v = value.trim();
		return isIPv4(v) || isIPv4(v.replace(/:\d{1,5}$/, '')) || isIPv6(v.replace(/^\[|\](?::\d{1,5})?$/g, '')) || EMAIL_EXACT.test(v);
	}

	// ------------------------------------------------------ key classification

	const KEY_EXCLUDED_SUFFIX = /(?:count|type|types|length|len|size|expiresin|expiresat|expires|expiry|expiration|ttl|limit|timeout|policy|policies|hint|required|enabled|disabled|reset|url|uri|endpoint|file|path|format|algorithm|alg|version|min|max|usage|used|status|valid|validity|age|changed|changedat|updated|updatedat|lastset|strength|prompt|field|header|location|store|provider|issuer|scope|scopes|method|mode|kind|rotation|attempts|failures|retries|duration|created|createdat|lifetime|refreshed)$/;
	const SECRET_KEY = /(?:password|passwd|passphrase|pwd|secret|token|apikey|accesskey|authkey|privatekey|credential|sessionid|sessid|accountkey|sharedaccesskey|connectionstring|signature|xapikey|clientkey|masterkey|encryptionkey|signingkey|webhooksecret)/;
	const SECRET_KEY_EXACT = /^(?:pass|pw|dbpass|userpass|adminpass|rootpass|sig|otp|cvv|cvc)$/;
	const KEY_EXCLUDED_PREFIX = /^(?:max|min|num|total|count)/;
	// "secret_name", "token_id", "api_key_arn" name a secret; they do not contain one.
	const SECRET_KEY_NOT_VALUE = /(?:name|names|id|ids|arn|ref|label|alias|description|desc|owner)$/;
	const USER_KEY = /(?:user|username|usr|uname|login|loginname|logonname|account|accountname|acct|owner|principal|samaccountname|upn|userprincipalname|actor|requester|initiator)$/;
	const HOST_KEY = /(?:host|hostname|servername|computer|computername|machinename|nodename|workstation|workstationname|devicename|dvchost|shost|dhost|fqdn|domainname|vhost|sni)$/;

	function classifyKey(key) {
		const k = key.toLowerCase().replace(/[^a-z0-9]/g, '');
		if (!k || k.length > 64) { return null; }
		if ((KEY_EXCLUDED_SUFFIX.test(k) || KEY_EXCLUDED_PREFIX.test(k) || /tokens$/.test(k)) && !/(?:sessionid|sessid)$/.test(k)) { return null; }
		const namesSecret = SECRET_KEY_NOT_VALUE.test(k) && !/(?:sessionid|sessid)$/.test(k);
		if ((SECRET_KEY.test(k) && !namesSecret) || SECRET_KEY_EXACT.test(k)) { return 'secret'; }
		if (/^(?:personname|fullname|contactname|customername|displayname)$/.test(k)) { return 'personName'; }
		if (/^(?:(?:contact|customer|mobile|home|work)?(?:phone|telephone)(?:number)?|mobilenumber|tel)$/.test(k)) { return 'phone'; }
		if (USER_KEY.test(k)) { return 'username'; }
		if (HOST_KEY.test(k)) { return 'host'; }
		return null;
	}

	// -------------------------------------------------------------- detectors
	// Each detector scans one chunk and calls emit(start, end, category, prefix, value, norm).

	const RE = {
		privateKeyBegin: /-----BEGIN ((?:[A-Z0-9]+ ){0,4})PRIVATE KEY( BLOCK)?-----/g,
		bearerBasic: /(?<![A-Za-z0-9_-])(Bearer|Basic)[ \t]+([A-Za-z0-9._~+\/=-]{8,8192})/gi,
		authHeader: /(?<![A-Za-z0-9_-])(?:Proxy-)?Authorization(["']?)[ \t]{0,8}[:=][ \t]{0,8}(["']?)/gi,
		jwt: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,4096}\.eyJ[A-Za-z0-9_-]{5,8192}\.[A-Za-z0-9_-]{0,4096}(?![A-Za-z0-9_-])/g,
		apiKeys: [
			['AWS access key ID', /(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16,17}(?![A-Z0-9])/g],
			['GitHub token', /(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9_])/g],
			['GitHub fine-grained token', /(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22,255}(?![A-Za-z0-9_])/g],
			['GitLab token', /(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])/g],
			['Slack token', /(?<![A-Za-z0-9_-])xox[abposr]-[A-Za-z0-9-]{10,255}(?![A-Za-z0-9_-])/g],
			['Slack webhook', /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\/-]{10,255}/g],
			['Stripe key', /(?<![A-Za-z0-9_])(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,255}(?![A-Za-z0-9_])/g],
			['Google API key', /(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])/g],
			['Google OAuth token', /(?<![A-Za-z0-9_-])ya29\.[0-9A-Za-z_-]{20,2048}(?![A-Za-z0-9_-])/g],
			['Anthropic API key', /(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])/g],
			['OpenAI API key', /(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,255}(?![A-Za-z0-9_-])/g],
			['SendGrid API key', /(?<![A-Za-z0-9_-])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g],
			['npm token', /(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9_])/g],
			['Hugging Face token', /(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{30,64}(?![A-Za-z0-9_])/g],
			['DigitalOcean token', /(?<![A-Za-z0-9_])do[opr]_v1_[a-f0-9]{64}(?![A-Za-z0-9_])/g],
			['Azure storage key', /(?<=AccountKey=)[A-Za-z0-9+\/]{40,128}={0,2}/g]
		],
		url: /(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]{1,15}):\/\/(?:([^\s:@\/?#"'<>]{1,128})(?::([^\s@\/?#"'<>]{0,256}))?@)?(\[[0-9A-Fa-f:.]{2,45}\]|[^\s\/:?#"'<>\[\](),;]{1,253})/gd,
		cookie: /(?<![A-Za-z0-9_-])(Set-Cookie|Cookie)(["']?)[ \t]{0,8}:[ \t]{0,8}/gi,
		kv: /(?<![A-Za-z0-9_.-])(["']?)([A-Za-z0-9_][A-Za-z0-9_.-]{0,63})\1[ \t]{0,8}(?:=>|:=|[:=])[ \t]{0,8}(?:"((?:[^"\\\r\n]|\\.){0,4096})"|'([^'\r\n]{0,4096})'|([^\s"',;&|<>{}\[\]()]{1,4096}))/gd,
		xml: /<([A-Za-z][A-Za-z0-9_.-]{0,63})(?:[ \t][^<>\r\n]{0,256})?>([^<\r\n]{1,4096})<\/\1>/gd,
		xmlData: /<Data[ \t]+Name=["']([A-Za-z0-9_]{1,64})["'][ \t]*>([^<\r\n]{1,1024})<\/Data>/gd,
		winText: /(?<![A-Za-z])(Account Name|Account Domain|Workstation Name|Source Workstation|Computer Name|User Name|Logon Account|Client Name|Caller User Name|Target User Name|Target Server Name|Client Address)[ \t]{0,8}:[ \t]{1,16}([^\s]{1,256})/gd,
		card: /(?<![\d.-])\d(?:[ -]?\d){12,18}(?![\d])(?!-\d)/g,
		ssn: /(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])/g,
		// URL-encoded form in query strings: bob%40example.com.
		emailEncoded: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._+-]{1,64}%40(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,63}(?![A-Za-z0-9-])/gi,
		email: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,63}(?![A-Za-z0-9-])/g,
		ipv6: /(?<![0-9A-Za-z_:.])(?=[0-9A-Fa-f:]{0,39}:[0-9A-Fa-f]{0,4}:)[0-9A-Fa-f:]{2,39}(?:(?<=:)(?:\d{1,3}\.){3}\d{1,3})?(?:%[0-9A-Za-z._-]{1,32})?(?![0-9A-Za-z_:]|\.\d)/g,
		ipv4: new RegExp('(?<![\\d.])(?<!\\d\\.)' + IPV4_SOURCE + '(?!\\d|\\.\\d)', 'g'),
		// "version 1.2.3.4", "app_version=1.2.3.4", "{"version":"1.2.3.4"", "v1.2.3.4".
		versionContext: /(?<![A-Za-z])(?:v|ver|version|release|build|rev|revision|firmware|fw)(?:[_-][A-Za-z]{1,16})?["']?[ \t]{0,3}[:=#]?[ \t]{0,3}["']?v?$/i,
		// Product tokens such as "Chrome/120.0.0.0" or "Version/17.0.0.1" in user agents.
		productToken: /(?<![A-Za-z0-9])[A-Z][A-Za-z]{1,20}\/$/,
		mac: /(?<![0-9A-Fa-f:.-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-]|\.[0-9A-Fa-f])/g,
		macDotted: /(?<![0-9A-Fa-f.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![0-9A-Fa-f.])/g,
		sshUser: [
			/\b(?:Accepted|Failed) (?:password|publickey|keyboard-interactive(?:\/pam)?|none|gssapi-with-mic|hostbased) for (?:invalid user )?([^\s()\[\];,'"]{1,64}) from\b/gd,
			/\b[Ii]nvalid user ([^\s()\[\];,'"]{1,64}) from\b/gd,
			/\bConnection (?:closed|reset) by (?:authenticating|invalid) user ([^\s()\[\];,'"]{1,64}) /gd,
			/\bfor user ([^\s()\[\];,'"]{1,64})(?=\(|[ \t]+by\b|[ \t]*$|[ \t]*[;,.])/gmd,
			/\bDisconnected from (?:authenticating |invalid )?user ([^\s()\[\];,'"]{1,64}) /gd,
			/\bby ([A-Za-z0-9._-]{1,64})\(uid=\d{1,10}\)/gd,
			/\bof user ([A-Za-z0-9_][A-Za-z0-9._-]{0,63}?)\.?(?=[ \t]|$)/gmd,
			/\bnew (?:user|group): name=([^,\s]{1,64})/gd,
			/\bpassword changed for ([^\s()\[\];,'"]{1,64})/gd,
			// Apache httpd auth modules: "user bob not found", "user bob: authentication failure".
			/\buser ([^\s:()\[\];,'"]{1,64})(?=: authentication failure| not found)/gd,
			// Common/combined access log remote_user field: 'IP ident USER [11/Nov/2026:…'.
			/^\S{1,256} \S{1,64} ([^\s\[\]"]{1,128}) \[\d{1,2}\/[A-Z][a-z]{2}\/\d{4}:/gmd,
			// Nested JSON objects such as "user":{"id":1,"name":"alice"}.
			/"(?:user|username|account|actor|owner|principal|customer)"[ \t]*:[ \t]*\{[^{}\r\n]{0,400}?"(?:name|login|username|display_?name|full_?name)"[ \t]*:[ \t]*"((?:[^"\\\r\n]|\\.){1,128})"/gd,
			// AWS IAM/STS ARNs: arn:aws:iam::123456789012:user/path/Alice, assumed-role/Role/session.
			/\barn:aws[a-z-]{0,12}:(?:iam|sts)::\d{12}:(?:user|federated-user)\/(?:[^\s"',\/]{1,128}\/){0,8}([^\s"',\/]{1,128})/gd,
			/\barn:aws[a-z-]{0,12}:sts::\d{12}:assumed-role\/[^\s"',\/]{1,128}\/([^\s"',]{1,128})/gd
		],
		sudoUser: /\bsudo(?:\[\d{1,10}\])?:[ \t]{1,16}([A-Za-z0-9._-]{1,64})[ \t]{1,4}:/gd,
		homePath: /(?:\/home\/|\/Users\/|(?<![A-Za-z])[A-Za-z]:(?:\\\\|\\|\/)Users(?:\\\\|\\|\/))([^\s\/\\:*?"'<>|,;]{1,64})/gid,
		domainUser: /(?<![A-Za-z0-9_\\\/:.-])([A-Z][A-Z0-9-]{1,14})\\{1,2}([A-Za-z0-9][A-Za-z0-9._-]{0,63})(?![A-Za-z0-9_\\])/gd,
		syslogHost: /^(?:<\d{1,3}>\d{0,2} ?)?(?:[A-Z][a-z]{2} [ 0-3]\d \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?) ([A-Za-z0-9][A-Za-z0-9._-]{0,253}) (?=[A-Za-z0-9_.\/-]{1,64}(?:\[\d{1,10}\])?(?::| - ))/gmd,
		fqdn: /(?<![A-Za-z0-9_@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,126}[A-Za-z]{2,63}\.?(?![A-Za-z0-9_-]|\.[A-Za-z0-9])/g
	};

	// Scan keys first: parsing up to4096 value characters for every unrelated
	// "ab:" in a long line otherwise repeats the same work. The exact original
	// value grammar is retained and is applied only at recognized key positions.
	const KV_HEAD_RE = /(?<![A-Za-z0-9_.-])(["']?)([A-Za-z0-9_][A-Za-z0-9_.-]{0,63})\1[ \t]{0,8}(?:=>|:=|[:=])[ \t]{0,8}/gd;
	const KV_VALUE_RE = new RegExp(RE.kv.source, 'dy');

	const DOMAIN_USER_EXCLUDED = /^(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+|BUILTIN|NT|AUTHORITY|SERVICE|APPPOOL|SYSTEM32|SYSWOW64|WINDOWS)$/;
	const USER_STOPWORDS = new Set(['in', 'of', 'the', 'a', 'an', 'and', 'or', 'to', 'with', 'from', 'by', 'for', 'is', 'not', 'on', 'at', 'input', 'name', 'id']);
	const HOME_EXCLUDED = new Set(['public', 'default', 'default user', 'all users', 'shared', 'defaultuser0', '%username%', '$user', '${user}', '~']);

	function lineEndFrom(text, index) {
		let i = index;
		while (i < text.length && text.charCodeAt(i) !== 10 && text.charCodeAt(i) !== 13) { i++; }
		return i;
	}

	/** Emit one span per physical or JSON-escaped line of a key body, keeping breaks. */
	function emitBody(emit, text, start, end, value) {
		const body = text.slice(start, end);
		const parts = /(\r\n|\n|\r|\\r\\n|\\n|\\r)/g;
		let pos = 0;
		let m;
		const segments = [];
		while ((m = parts.exec(body)) !== null) {
			segments.push([pos, m.index]);
			pos = m.index + m[0].length;
		}
		segments.push([pos, body.length]);
		for (const [a, b] of segments) {
			const seg = body.slice(a, b);
			const lead = seg.length - seg.trimStart().length;
			const core = seg.trim();
			if (core) {
				emit(start + a + lead, start + a + lead + core.length, 'privateKey', 'PRIVATE_KEY', value, value);
			}
		}
	}

	function detectPrivateKeys(text, emit) {
		const re = RE.privateKeyBegin;
		re.lastIndex = 0;
		let m;
		while ((m = re.exec(text)) !== null) {
			const bodyStart = m.index + m[0].length;
			const endMarker = '-----END ' + m[1] + 'PRIVATE KEY' + (m[2] || '') + '-----';
			const window = text.slice(bodyStart, bodyStart + MAX_KEY_BLOCK);
			const endRel = window.indexOf(endMarker);
			let bodyEnd;
			if (endRel !== -1) {
				bodyEnd = bodyStart + endRel;
			} else {
				// Truncated block: mask following base64-looking lines (or the rest of an escaped line).
				const sameLineEnd = lineEndFrom(text, bodyStart);
				if (sameLineEnd > bodyStart + 8) {
					const quote = text.indexOf('"', bodyStart);
					bodyEnd = quote !== -1 && quote < sameLineEnd ? quote : sameLineEnd;
				} else {
					bodyEnd = sameLineEnd;
					let cursor = sameLineEnd;
					const limit = Math.min(text.length, bodyStart + MAX_KEY_BLOCK);
					while (cursor < limit) {
						const lineStart = cursor + (text.startsWith('\r\n', cursor) ? 2 : 1);
						const lineEnd = lineEndFrom(text, lineStart);
						const line = text.slice(lineStart, lineEnd).trim();
						if (!/^(?:[A-Za-z0-9+\/=]{16,}|Proc-Type:.*|DEK-Info:.*|Comment:.*|Version:.*)$/.test(line)) { break; }
						bodyEnd = lineEnd;
						cursor = lineEnd;
					}
				}
			}
			const value = text.slice(m.index, endRel !== -1 ? bodyEnd + endMarker.length : bodyEnd);
			emitBody(emit, text, bodyStart, bodyEnd, value);
			re.lastIndex = Math.max(re.lastIndex, bodyEnd);
		}
	}

	function detectBearerBasic(text, emit) {
		const re = RE.bearerBasic;
		re.lastIndex = 0;
		let m;
		while ((m = re.exec(text)) !== null) {
			const scheme = m[1].toLowerCase();
			let token = m[2];
			const tokenStart = m.index + m[0].length - token.length;
			if (scheme === 'basic') {
				token = token.replace(/[.,;]+$/, '');
				if (!/^[A-Za-z0-9+\/]+={0,2}$/.test(token) || token.length % 4 !== 0) { continue; }
				let decoded = '';
				try { decoded = typeof atob === 'function' ? atob(token) : Buffer.from(token, 'base64').toString('latin1'); } catch (e) { continue; }
				if (decoded.indexOf(':') === -1) { continue; }
				emit(tokenStart, tokenStart + token.length, 'auth', 'BASIC_AUTH', token, token);
			} else {
				token = token.replace(/[.,;]+$/, '');
				// "token_type=bearer expires_in=3600": a key=value pair is not a token.
				if (/=[^=]/.test(token)) { continue; }
				if (token.length < 20 && !/[0-9._~+\/=-]/.test(token)) { continue; }
				emit(tokenStart, tokenStart + token.length, 'auth', 'BEARER_TOKEN', token, token);
			}
		}
	}

	function detectAuthHeaders(text, emit) {
		const re = RE.authHeader;
		re.lastIndex = 0;
		let m;
		while ((m = re.exec(text)) !== null) {
			let start = m.index + m[0].length;
			const lineEnd = lineEndFrom(text, start);
			const before = m.index > 0 ? text[m.index - 1] : '';
			const quote = m[2] || (before === '"' || before === "'" ? before : '');
			let end = lineEnd;
			if (quote) {
				let i = start;
				while (i < lineEnd && !(text[i] === quote && text[i - 1] !== '\\')) { i++; }
				end = i;
			}
			// The header value runs to the end of the line: never rescan it (keeps this linear).
			re.lastIndex = Math.max(re.lastIndex, end);
			let value = text.slice(start, end);
			const scheme = /^([A-Za-z][A-Za-z0-9-]{1,31})[ \t]+(?=\S)/.exec(value);
			if (scheme) {
				start += scheme[0].length;
				value = value.slice(scheme[0].length);
			}
			const trimmed = value.replace(/[ \t,;]+$/, '');
			if (trimmed.length < 4 || isPlaceholder(trimmed)) { continue; }
			emit(start, start + trimmed.length, 'auth', 'AUTH_TOKEN', trimmed, trimmed);
		}
	}

	function detectSimple(re, text, emit, category, prefix, validate, normalize) {
		re.lastIndex = 0;
		let m;
		while ((m = re.exec(text)) !== null) {
			if (m[0].length === 0) { re.lastIndex++; continue; }
			const value = m[0];
			if (validate && !validate(value, m, text)) { continue; }
			emit(m.index, m.index + value.length, category, prefix, value, normalize ? normalize(value) : value);
		}
	}

	function detectApiKeys(text, emit) {
		for (const [provider, re] of RE.apiKeys) {
			detectSimple(re, text, emit, 'apiKey', 'API_KEY', provider === 'OpenAI API key' ? (v => /\d/.test(v) && /[A-Za-z]{2}/.test(v.slice(3))) : null);
		}
	}

	function hostToken(raw) {
		return raw.replace(/\.$/, '');
	}

	function emitHostValue(emit, start, value) {
		const v = value.replace(/\.$/, '');
		if (!v || isPlaceholder(v) || v.toLowerCase() === 'localhost' || looksLikeAddress(v) || isPublicServiceEndpoint(v)) { return; }
		if (!/^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,252})$/.test(v)) { return; }
		emit(start, start + v.length, 'host', 'HOST', v, v.toLowerCase());
	}

	function detectUrls(text, emit) {
		const re = RE.url;
		re.lastIndex = 0;
		let m;
		while ((m = re.exec(text)) !== null) {
			const [, , user, pass, host] = m;
			const idx = m.indices;
			if (user && !isPlaceholder(user)) {
				emit(idx[2][0], idx[2][1], 'username', 'USER', user, user);
			}
			if (pass && !isPlaceholder(pass)) {
				emit(idx[3][0], idx[3][1], 'secret', 'SECRET', pass, pass);
			}
			if (host && host[0] !== '[') {
				const h = hostToken(host);
				if (!isIPv4(h) && h.toLowerCase() !== 'localhost' && !isPublicServiceEndpoint(h) && /[A-Za-z]/.test(h) && /^[A-Za-z0-9._-]+$/.test(h)) {
					emit(idx[4][0], idx[4][0] + h.length, 'host', 'HOST', h, h.toLowerCase());
				}
			}
		}
	}

	function detectCookies(text, emit) {
		const re = RE.cookie;
		re.lastIndex = 0;
		let m;
		while ((m = re.exec(text)) !== null) {
			const isSet = m[1].toLowerCase() === 'set-cookie';
			let start = m.index + m[0].length;
			const lineEnd = lineEndFrom(text, start);
			const before = m.index > 0 ? text[m.index - 1] : '';
			let quote = m[2] || (before === '"' || before === "'" ? before : '');
			// JSON/YAML form: "cookie": "sid=…; theme=…" — the value has its own opening quote.
			if (text[start] === '"' || text[start] === "'") {
				quote = text[start];
				start++;
			}
			let end = lineEnd;
			if (quote) {
				const q = text.indexOf(quote, start);
				if (q !== -1 && q < lineEnd) { end = q; }
			}
			re.lastIndex = Math.max(re.lastIndex, end);
			const header = text.slice(start, end);
			const pair = /(?:^|;[ \t]*)([^=;\s]{1,256})=([^;\r\n]{0,4096})/g;
			let p;
			let first = true;
			while ((p = pair.exec(header)) !== null) {
				if (isSet && !first) { break; }
				first = false;
				const value = p[2].replace(/[ \t]+$/, '');
				if (!value || isPlaceholder(value)) { continue; }
				const valueStart = start + p.index + p[0].length - p[2].length;
				emit(valueStart, valueStart + value.length, 'secret', 'COOKIE', value, value);
			}
		}
	}

	function emitClassified(emit, key, value, start) {
		if (value == null) { return; }
		const category = classifyKey(key);
		if (!category) { return; }
		const trimmed = value.replace(/[ \t]+$/, '');
		if (!trimmed || isPlaceholder(trimmed)) { return; }
		// sudo/env "PWD=/home/alice" is the working directory, not a password.
		if (category === 'secret' && /^pwd$/i.test(key.replace(/[^A-Za-z]/g, '')) && /^(?:\/|~|[A-Za-z]:[\\\/])/.test(trimmed)) { return; }
		if (category === 'personName') {
			// Deliberately contextual: no inference of personal names from arbitrary prose.
			if (trimmed.length <= 128 && /^[\p{L}\p{M}][\p{L}\p{M} .’'\-]{0,127}$/u.test(trimmed)) {
				emit(start, start + trimmed.length, 'personName', 'PERSON', trimmed, trimmed);
			}
			return;
		}
		if (category === 'phone') {
			const digits = trimmed.replace(/\D/g, '');
			if (digits.length >= 7 && digits.length <= 15 && /^\+?[0-9(][0-9 () .\-]{5,48}$/.test(trimmed)) {
				emit(start, start + trimmed.length, 'phone', 'PHONE', trimmed, digits);
			}
			return;
		}
		if (category === 'host') {
			emitHostValue(emit, start, trimmed);
			return;
		}
		// Addresses inside values are left to the dedicated detectors for consistent labels.
		if (looksLikeAddress(trimmed)) { return; }
		if (/^(?:bearer|basic|digest|token|negotiate|ntlm)$/i.test(trimmed)) { return; }
		if (category === 'secret') {
			emit(start, start + trimmed.length, 'secret', 'SECRET', trimmed, trimmed);
		} else if (trimmed.length <= 128) {
			emit(start, start + trimmed.length, 'username', 'USER', trimmed, trimmed);
		}
	}

	/** Explicit contact fields with space-separated values; stop at the next field. */
	function detectContacts(text, emit) {
		const re = /(?<![A-Za-z0-9_.-])(["']?)((?:person|full|contact|customer|display)[_.-]?name|(?:(?:contact|customer|mobile|home|work)[_.-]?)?(?:phone|telephone)(?:[_.-]?number)?|mobile[_.-]?number|tel)\1[ \t]{0,8}[:=][ \t]{0,8}(?:"([^"\r\n]{1,160})"|'([^'\r\n]{1,160})'|([^\r\n,;]{1,160}?)(?=[ \t]+[A-Za-z_][A-Za-z0-9_.-]{0,63}[ \t]{0,8}[:=]|[\r\n,;]|$))/gmdi;
		let m;
		while ((m = re.exec(text)) !== null) {
			const group = m[3] != null ? 3 : m[4] != null ? 4 : 5;
			emitClassified(emit, m[2], m[group], m.indices[group][0]);
		}
	}

	/** CEF custom string labels belong to their event and slot, not the next line. */
	function detectCef(text, emit) {
		const lines = /^.*CEF:\d{1,3}\|[^\r\n]*$/gm;
		let line;
		while ((line = lines.exec(text)) !== null) {
			const cefStart = line[0].indexOf('CEF:');
			let pipes = 0, start = -1;
			for (let i = cefStart; i < line[0].length; i++) {
				if (line[0][i] === '\\') { i++; continue; }
				if (line[0][i] === '|' && ++pipes === 7) { start = i + 1; break; }
			}
			if (start < 0) { continue; }
			const extension = line[0].slice(start), fields = [], keys = /(?:^|[ \t])([A-Za-z][A-Za-z0-9_]{0,63})=/g;
			let m;
			while ((m = keys.exec(extension)) !== null) {
				// A backslash-escaped space is part of the preceding value.
				let slashes = 0, at = m.index - 1;
				while (at >= 0 && extension[at--] === '\\') { slashes++; }
				if (slashes % 2) { continue; }
				fields.push({ key: m[1], head: m.index, start: keys.lastIndex });
			}
			const sensitive = new Set();
			for (let i = 0; i < fields.length; i++) {
				const f = fields[i];
				f.value = extension.slice(f.start, i + 1 < fields.length ? fields[i + 1].head : extension.length).trimEnd();
				if (/^cs[1-6]Label$/i.test(f.key) && f.value.length <= 256) {
					const label = f.value.replace(/\\([\\=|])/g, '$1').replace(/[^A-Za-z0-9]/g, '');
					if (classifyKey(label) === 'secret' || /^(?:authorization|bearer|authentication)$/i.test(label)) { sensitive.add(f.key.slice(0, 3).toLowerCase()); }
				}
			}
			for (const f of fields) {
				if (sensitive.has(f.key.toLowerCase()) && f.value && !isPlaceholder(f.value)) {
					const at = line.index + start + f.start;
					emit(at, at + f.value.length, 'secret', 'SECRET', f.value, f.value);
				}
			}
		}
	}

	function detectKeyValues(text, emit) {
		KV_HEAD_RE.lastIndex = 0;
		let head, m;
		while ((head = KV_HEAD_RE.exec(text)) !== null) {
			if (!classifyKey(head[2])) {
				// The old scanner resumed *inside* a quoted value. Preserve that
				// boundary (including empty/malformed values), so nested quoted
				// pairs receive exactly the same handling as before.
				if (text[KV_HEAD_RE.lastIndex] === '"' || text[KV_HEAD_RE.lastIndex] === "'") {
					KV_VALUE_RE.lastIndex = head.index;
					const quoted = KV_VALUE_RE.exec(text);
					if (quoted) {
						const group = quoted[3] != null ? 3 : (quoted[4] != null ? 4 : 5);
						KV_HEAD_RE.lastIndex = quoted[group] ? quoted.indices[group][0] : KV_VALUE_RE.lastIndex;
					} else { KV_HEAD_RE.lastIndex = head.index + 1; }
				}
				continue;
			}
			KV_VALUE_RE.lastIndex = head.index;
			m = KV_VALUE_RE.exec(text);
			if (!m) { continue; }
			KV_HEAD_RE.lastIndex = KV_VALUE_RE.lastIndex;
			const key = m[2];
			const group = m[3] != null ? 3 : (m[4] != null ? 4 : 5);
			if (m[group] == null || m[group] === '') { continue; }
			const valueStart = m.indices[group][0];
			const separator = text.slice(m.indices[2][1], valueStart);
			// "ruser= rhost=x" / "new user: name=x": an empty value followed by the next key=value pair.
			const nextPair = group === 5 && /[ \t]$/.test(separator) && /^[A-Za-z_][A-Za-z0-9_.-]{0,63}=(?!=|$)/.test(m[group]);
			// PAM "pam_unix(passwd:chauthtok)" is service:module, not key: value.
			const pamPair = /:/.test(separator) && m.index > 0 && text[m.index - 1] === '(';
			if (!nextPair && !pamPair) {
				emitClassified(emit, key, m[group], valueStart);
			}
			// Continue scanning inside the value so nested pairs are still found.
			KV_HEAD_RE.lastIndex = m.indices[group][0];
		}
		let re = RE.xml;
		re.lastIndex = 0;
		while ((m = re.exec(text)) !== null) {
			emitClassified(emit, m[1], m[2], m.indices[2][0]);
			re.lastIndex = m.indices[2][0];
		}
		re = RE.xmlData;
		re.lastIndex = 0;
		while ((m = re.exec(text)) !== null) {
			emitClassified(emit, m[1], m[2], m.indices[2][0]);
		}
		re = RE.winText;
		re.lastIndex = 0;
		while ((m = re.exec(text)) !== null) {
			const label = m[1].toLowerCase();
			const key = /domain|workstation|computer|client name|server name/.test(label) ? 'hostname' : (/address/.test(label) ? '' : 'username');
			if (key) { emitClassified(emit, key, m[2], m.indices[2][0]); }
		}
	}

	function detectIPv4(text, emit, options) {
		const re = RE.ipv4;
		re.lastIndex = 0;
		let m;
		while ((m = re.exec(text)) !== null) {
			const value = m[0];
			if (isNonIdentifyingIPv4(value)) { continue; }
			if (options.keepPrivateIPv4 && isPrivateIPv4(value)) { continue; }
			const before = text.slice(Math.max(0, m.index - 32), m.index);
			if (RE.versionContext.test(before) || RE.productToken.test(before)) { continue; }
			emit(m.index, m.index + value.length, 'ipv4', 'IPV4', value, value);
		}
	}

	function detectUserContext(text, emit) {
		for (const re of RE.sshUser.concat([RE.sudoUser])) {
			re.lastIndex = 0;
			let m;
			while ((m = re.exec(text)) !== null) {
				const v = m[1];
				if (isPlaceholder(v) || looksLikeAddress(v) || USER_STOPWORDS.has(v.toLowerCase())) { continue; }
				emit(m.indices[1][0], m.indices[1][1], 'username', 'USER', v, v);
			}
		}
		let re = RE.homePath;
		re.lastIndex = 0;
		let m;
		while ((m = re.exec(text)) !== null) {
			const v = m[1];
			if (HOME_EXCLUDED.has(v.toLowerCase()) || isPlaceholder(v)) { continue; }
			emit(m.indices[1][0], m.indices[1][1], 'username', 'USER', v, v);
		}
		re = RE.domainUser;
		re.lastIndex = 0;
		while ((m = re.exec(text)) !== null) {
			if (DOMAIN_USER_EXCLUDED.test(m[1])) { continue; }
			const v = m[2];
			if (isPlaceholder(v)) { continue; }
			emit(m.indices[2][0], m.indices[2][1], 'username', 'USER', v, v);
		}
	}

	function detectHostContext(text, emit) {
		const re = RE.syslogHost;
		re.lastIndex = 0;
		let m;
		while ((m = re.exec(text)) !== null) {
			emitHostValue(emit, m.indices[1][0], m[1]);
		}
		const fq = RE.fqdn;
		fq.lastIndex = 0;
		while ((m = fq.exec(text)) !== null) {
			const host = hostToken(m[0]);
			if (!hostValid(host)) { continue; }
			emit(m.index, m.index + host.length, 'host', 'HOST', host, host.toLowerCase());
		}
	}

	// ------------------------------------------------------------ custom rules

	/** Validate user rules. Returns { rules, errors } — errors are user-facing. */
	function compileCustomRules(input) {
		const rules = [];
		const errors = [];
		const list = Array.isArray(input) ? input : [];
		if (list.length > MAX_CUSTOM_RULES) {
			errors.push({ index: MAX_CUSTOM_RULES, field: 'pattern', message: 'A maximum of ' + MAX_CUSTOM_RULES + ' custom rules is supported.' });
		}
		list.slice(0, MAX_CUSTOM_RULES).forEach((rule, index) => {
			const pattern = typeof rule.pattern === 'string' ? rule.pattern : '';
			const label = typeof rule.label === 'string' ? rule.label.trim() : '';
			if (!pattern) { errors.push({ index, field: 'pattern', message: 'Enter a regular expression.' }); return; }
			if (pattern.length > MAX_CUSTOM_PATTERN) { errors.push({ index, field: 'pattern', message: 'The pattern is longer than ' + MAX_CUSTOM_PATTERN + ' characters.' }); return; }
			if (!/^[A-Z][A-Z0-9_]{0,31}$/.test(label) || /^REDACTED_/.test(label)) {
				errors.push({ index, field: 'label', message: 'Use 1–32 uppercase letters, digits or underscores, starting with a letter (not REDACTED_).' });
				return;
			}
			let re;
			try {
				re = new RegExp(pattern, 'g' + (rule.caseInsensitive ? 'i' : ''));
			} catch (e) {
				errors.push({ index, field: 'pattern', message: 'Invalid regular expression: ' + String(e.message).replace(/^Invalid regular expression: /, '') });
				return;
			}
			if (re.test('')) {
				errors.push({ index, field: 'pattern', message: 'The pattern matches an empty string. Make it match at least one character.' });
				return;
			}
			re.lastIndex = 0;
			rules.push({ re, label });
		});
		return { rules, errors };
	}

	function detectCustom(text, emit, rules, warnings) {
		for (const rule of rules) {
			const re = rule.re;
			re.lastIndex = 0;
			let m;
			while ((m = re.exec(text)) !== null) {
				if (m[0].length === 0) { re.lastIndex++; continue; }
				if (/[\r\n]/.test(m[0])) { warnings.multilineCustom++; continue; }
				emit(m.index, m.index + m[0].length, 'custom', rule.label, m[0], m[0]);
			}
		}
	}

	// --------------------------------------------------------------- session

	function normalizeOptions(raw) {
		const base = defaultOptions();
		const o = raw && typeof raw === 'object' ? raw : {};
		const categories = {};
		for (const id of CATEGORY_IDS) {
			categories[id] = o.categories && typeof o.categories[id] === 'boolean' ? o.categories[id] : base.categories[id];
		}
		return {
			categories,
			labelMode: o.labelMode === 'generic' ? 'generic' : 'stable',
			keepPrivateIPv4: o.keepPrivateIPv4 === true,
			customRules: Array.isArray(o.customRules) ? o.customRules : []
		};
	}

	/** Split one CSV/TSV line; returns [{ value, start }] with offsets of the unquoted value, or null if malformed. */
	function splitDelimited(line, delimiter) {
		const fields = [];
		let i = 0;
		while (i <= line.length) {
			if (line[i] === '"') {
				let j = i + 1;
				while (j < line.length) {
					if (line[j] === '"' && line[j + 1] === '"') { j += 2; continue; }
					if (line[j] === '"') { break; }
					j++;
				}
				if (j >= line.length) { return null; }
				fields.push({ value: line.slice(i + 1, j), start: i + 1 });
				i = j + 1;
				if (i < line.length && line[i] !== delimiter) { return null; }
				i++;
			} else {
				let j = line.indexOf(delimiter, i);
				if (j === -1) { j = line.length; }
				fields.push({ value: line.slice(i, j), start: i });
				i = j + 1;
			}
			if (fields.length > 512) { return null; }
		}
		return fields;
	}

	function countChar(text, code) {
		let n = 0;
		for (let i = 0; i < text.length; i++) { if (text.charCodeAt(i) === code) { n++; } }
		return n;
	}

	function createSession(rawOptions) {
		const options = normalizeOptions(rawOptions);
		const compiled = compileCustomRules(options.customRules);
		if (compiled.errors.length) {
			const err = new Error(compiled.errors[0].message);
			err.code = 'CUSTOM_RULE';
			err.details = compiled.errors;
			throw err;
		}
		const enabled = options.categories;
		const entries = new Map();
		const counters = new Map();
		const stats = {};
		for (const id of CATEGORY_IDS) { stats[id] = { replacements: 0, unique: 0 }; }
		const warnings = { multilineCustom: 0 };

		// CSV/TSV with a header row: classify columns by header name exactly like key=value keys.
		// Decided once from the first two lines of the input; header line itself is never masked.
		let csv = null;
		let csvDecided = false;
		let csvHeaderPending = false;
		function decideCsv(text) {
			csvDecided = true;
			const lines = text.split('\n', 3).map(l => l.replace(/\r$/, ''));
			if (lines.length < 2) { return; }
			for (const d of [',', '\t', ';']) {
				const head = splitDelimited(lines[0], d);
				if (!head || head.length < 2 || !head.every(h => /^[A-Za-z_][A-Za-z0-9_ .-]{0,63}$/.test(h.value))) { continue; }
				const second = splitDelimited(lines[1], d);
				if (!second || second.length !== head.length) { continue; }
				const columns = head.map(h => h.value);
				if (columns.some(name => classifyKey(name))) {
					csv = { delimiter: d, columns };
					csvHeaderPending = true;
				}
				return;
			}
		}
		function detectCsv(text, emit) {
			if (!csvDecided) { decideCsv(text); }
			if (!csv) { return; }
			let pos = 0;
			while (pos < text.length) {
				let end = text.indexOf('\n', pos);
				if (end === -1) { end = text.length; }
				const line = text.slice(pos, end).replace(/\r$/, '');
				if (csvHeaderPending) {
					csvHeaderPending = false;
				} else {
					const fields = splitDelimited(line, csv.delimiter);
					if (fields && fields.length === csv.columns.length) {
						fields.forEach((f, i) => emitClassified(emit, csv.columns[i], f.value, pos + f.start));
					}
				}
				pos = end + 1;
			}
		}

		const detectors = [
			['custom', (t, e) => detectCustom(t, e, compiled.rules, warnings)],
			['privateKey', detectPrivateKeys],
			['jwt', (t, e) => detectSimple(RE.jwt, t, e, 'jwt', 'JWT')],
			['auth', detectBearerBasic],
			['auth', detectAuthHeaders],
			['apiKey', detectApiKeys],
			['*', detectUrls],
			['secret', detectCookies],
			['*', detectKeyValues],
			['*', detectContacts],
			['secret', detectCef],
			['*', detectCsv],
			['card', (t, e) => detectSimple(RE.card, t, e, 'card', 'CARD', v => cardValid(v), v => v.replace(/\D/g, ''))],
			['ssn', (t, e) => detectSimple(RE.ssn, t, e, 'ssn', 'SSN')],
			['email', (t, e) => {
				detectSimple(RE.emailEncoded, t, e, 'email', 'EMAIL', null, v => v.replace(/%40/i, '@').toLowerCase());
				detectSimple(RE.email, t, e, 'email', 'EMAIL', null, v => v.toLowerCase());
			}],
			['ipv6', (t, e) => detectSimple(RE.ipv6, t, e, 'ipv6', 'IPV6', v => isIPv6(v), v => v.toLowerCase())],
			['ipv4', (t, e) => detectIPv4(t, e, options)],
			['mac', (t, e) => {
				const norm = v => v.toLowerCase().replace(/[^0-9a-f]/g, '');
				detectSimple(RE.mac, t, e, 'mac', 'MAC', null, norm);
				detectSimple(RE.macDotted, t, e, 'mac', 'MAC', null, norm);
			}],
			['username', detectUserContext],
			['host', detectHostContext]
		];

		function labelFor(prefix, category, norm, value) {
			const key = prefix + '\u0000' + norm;
			let entry = entries.get(key);
			if (!entry) {
				const n = (counters.get(prefix) || 0) + 1;
				counters.set(prefix, n);
				entry = { label: options.labelMode === 'generic' ? 'REDACTED_' + prefix : prefix + '_' + n, category, original: value, occurrences: 0 };
				entries.set(key, entry);
				stats[category].unique++;
			}
			entry.occurrences++;
			stats[category].replacements++;
			return entry.label;
		}

		/**
		 * Process one chunk that starts and ends on a line boundary.
		 * Returns { output, spans } where spans are [outStart, outEnd, category] in the chunk output.
		 */
		function processChunk(text, wantSpans) {
			const covered = new Uint8Array(text.length);
			const accepted = [];
			const emit = (start, end, category, prefix, value, norm) => {
				if (!enabled[category] || end <= start || start < 0 || end > text.length) { return; }
				for (let i = start; i < end; i++) {
					if (covered[i]) { return; }
					const c = text.charCodeAt(i);
					if (c === 10 || c === 13) { return; }
				}
				covered.fill(1, start, end);
				accepted.push({ start, end, category, prefix, value, norm });
			};
			for (const [category, detector] of detectors) {
				if (category !== '*' && !enabled[category]) { continue; }
				detector(text, emit);
			}
			accepted.sort((a, b) => a.start - b.start);
			const parts = [];
			const spans = wantSpans ? [] : null;
			let pos = 0;
			let outLen = 0;
			for (const span of accepted) {
				const before = text.slice(pos, span.start);
				parts.push(before);
				outLen += before.length;
				const label = labelFor(span.prefix, span.category, span.norm, span.value);
				parts.push(label);
				if (spans) { spans.push([outLen, outLen + label.length, span.category]); }
				outLen += label.length;
				pos = span.end;
			}
			parts.push(text.slice(pos));
			return { output: parts.join(''), spans };
		}

		function result() {
			const map = [];
			for (const entry of entries.values()) {
				map.push({ label: entry.label, category: entry.category, original: entry.original, occurrences: entry.occurrences });
			}
			return { stats, map, warnings: Object.assign({}, warnings) };
		}

		return { options, processChunk, result };
	}

	/** Split at line boundaries near CHUNK_CHARS without cutting a private key block. */
	function nextCut(text, from, chunkChars) {
		if (text.length - from <= chunkChars) { return text.length; }
		let cut = text.indexOf('\n', from + chunkChars);
		if (cut === -1) { return text.length; }
		cut += 1;
		const begin = text.lastIndexOf('-----BEGIN ', cut);
		if (begin >= from) {
			const end = text.indexOf('-----END ', begin);
			if (end === -1 || end >= cut) {
				const limit = Math.min(text.length, begin + MAX_KEY_BLOCK + 256);
				const endLine = end !== -1 && end < limit ? text.indexOf('\n', end) : text.indexOf('\n', limit);
				cut = endLine === -1 ? text.length : endLine + 1;
			}
		}
		return cut;
	}

	/**
	 * Anonymize a full text. callbacks.onProgress(done, total) is called per chunk.
	 * Returns { output, stats, map, preview: { text, spans, truncated }, lines, warnings }.
	 */
	function anonymize(text, rawOptions, callbacks) {
		if (typeof text !== 'string') { throw new TypeError('Input must be a string.'); }
		const cb = callbacks || {};
		const previewChars = typeof cb.previewChars === 'number' ? cb.previewChars : 200000;
		const chunkChars = typeof cb.chunkChars === 'number' ? cb.chunkChars : CHUNK_CHARS;
		const session = createSession(rawOptions);
		const outputs = [];
		const previewSpans = [];
		let previewText = '';
		let outOffset = 0;
		let from = 0;
		while (from < text.length) {
			const cut = nextCut(text, from, chunkChars);
			const wantSpans = outOffset < previewChars;
			const { output, spans } = session.processChunk(text.slice(from, cut), wantSpans);
			if (wantSpans) {
				for (const [s, e, c] of spans) {
					if (outOffset + s >= previewChars) { break; }
					previewSpans.push([outOffset + s, Math.min(outOffset + e, previewChars), c]);
				}
				previewText += output.slice(0, Math.max(0, previewChars - outOffset));
			}
			outputs.push(output);
			outOffset += output.length;
			from = cut;
			if (cb.onProgress) { cb.onProgress(from, text.length); }
		}
		const output = outputs.join('');
		const linesIn = countChar(text, 10);
		const linesOut = countChar(output, 10);
		if (linesIn !== linesOut || countChar(text, 13) !== countChar(output, 13)) {
			const err = new Error('Structure check failed: the number of lines changed. No output was produced.');
			err.code = 'STRUCTURE';
			throw err;
		}
		const res = session.result();
		return {
			output,
			stats: res.stats,
			map: res.map,
			warnings: res.warnings,
			lines: linesIn + (text.length && !text.endsWith('\n') ? 1 : 0),
			preview: { text: previewText, spans: previewSpans, truncated: output.length > previewChars }
		};
	}

	return {
		VERSION,
		RULESET_VERSION,
		CATEGORIES,
		defaultOptions,
		compileCustomRules,
		anonymize,
		createSession,
		_internal: { isIPv4, isNonIdentifyingIPv4, isIPv6, isPrivateIPv4, luhnValid, cardValid, hostValid, classifyKey, nextCut, MAX_KEY_BLOCK }
	};
}));
