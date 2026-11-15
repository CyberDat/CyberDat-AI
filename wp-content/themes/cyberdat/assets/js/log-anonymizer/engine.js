/*!
 * CyberDat Privacy Shield Log Anonymizer — detection and replacement engine.
 *
 * Pure, dependency-free and side-effect free: no DOM, storage or network APIs
 * are used. Loaded by the Web Worker (importScripts) and by Node.js tests.
 *
 * Invariants:
 *  - Replacement spans never contain line breaks, so the number of lines and
 *    every delimiter outside a replaced value are preserved.
 *  - Key matching is bounded; scalar/CSV readers scan forward linearly.
 *    CSV replacements retain raw framing and complete logical records.
 *    Private-key block lookahead is bounded to 64 KiB.
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

	const VERSION = '1.1.0';
	const RULESET_VERSION = '2026-11-15.2';
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
		{ id: 'identifier', name: 'Identifiers and personal fields', prefix: 'ID' },
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
	const EMAIL_LOCAL = String.raw`[\p{L}\p{N}\p{M}._%+\-]{1,64}`;
	const EMAIL_DOMAIN = String.raw`(?:[\p{L}\p{N}](?:[\p{L}\p{N}\p{M}-]{0,61}[\p{L}\p{N}\p{M}])?\.){1,8}(?:xn--[A-Za-z0-9-]{2,59}|[\p{L}][\p{L}\p{M}]{1,62})`;
	const EMAIL_EXACT = new RegExp('^'+EMAIL_LOCAL+'@'+EMAIL_DOMAIN+'$', 'u');
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

	// These tables are the single source for classification and its UI description.
	const KEY_RULES = {
		metadata: 'count type types length len size expiresin expiresat expires expiry expiration ttl limit timeout policy policies hint required enabled disabled reset url uri endpoint file path format algorithm alg version min max usage used status valid validity age changed changedat updated updatedat lastset strength prompt field header location store provider issuer scope scopes method mode kind rotation attempts failures retries duration created createdat lifetime refreshed active inactive rotated region service date time'.split(' '),
		secretWords: 'password passwd passphrase pwd secret token credential credentials signature'.split(' '),
		secretCompounds: 'apikey accesskey authkey privatekey sessionid sessid accountkey sharedaccesskey connectionstring xapikey clientkey masterkey encryptionkey signingkey webhooksecret'.split(' '),
		secretExact: 'pass pw dbpass userpass adminpass rootpass sig otp cvv cvc sid csrf xsrf pin'.split(' '),
		secretReferences: 'name names id ids arn ref label alias description desc owner'.split(' '),
		users: 'user username usr uname login loginname logonname account accountname acct owner principal samaccountname upn userprincipalname actor requester initiator benutzer benutzername suser ruser duser'.split(' '),
		names: 'personname fullname contactname customername displayname firstname lastname givenname familyname surname'.split(' '),
		phones: ['phone','phonenumber','telephone','telephonenumber','mobilenumber','tel','mobile','cell','fax', ...['contact','customer','mobile','home','work'].flatMap(p=>['phone','phonenumber','telephone','telephonenumber'].map(n=>p+n))],
		identifiers: 'customerid accountid tenantid orgid organizationid clientid deviceid memberid subscriberid imei awsaccountid'.split(' '),
		personal: 'address street streetaddress postalcode postcode zipcode dob dateofbirth birthdate birthday iban accountnumber bankaccount'.split(' '),
		hosts: 'host hostname servername computer computername machinename nodename workstation workstationname devicename dvchost shost dhost fqdn domainname vhost sni rhost'.split(' '),
		localized: {username:['benutzer','benutzername','anmeldename','пользователь','имяпользователя','логин'],secret:['passwort','kennwort','пароль'],phone:['telefon','телефон'],personName:['vorname','nachname','имя','фамилия','фио']}
	};
	function keyWords(key) {
		return key.normalize('NFC').replace(/([\p{Lu}])([\p{Lu}][\p{Ll}])/gu,'$1 $2')
			.replace(/([\p{Ll}\p{N}])([\p{Lu}])/gu,'$1 $2').toLowerCase().split(/[^\p{L}\p{N}\p{M}]+/u).filter(Boolean);
	}
	function classifyKey(key) {
		const words=keyWords(key), k=words.join(''), last=words[words.length-1];
		if (!k || k.length>64) return null;
		if (KEY_RULES.metadata.includes(last) || KEY_RULES.metadata.includes(words.slice(-2).join('')) || ['max','min','num','total','count'].includes(words[0])) return null;
		for (const [category,names] of Object.entries(KEY_RULES.localized)) if(names.includes(k))return category;
		if(KEY_RULES.identifiers.includes(k)||KEY_RULES.personal.includes(k))return 'identifier';
		if(KEY_RULES.names.includes(k))return 'personName';
		if(KEY_RULES.phones.includes(k))return 'phone';
		const session=/^(?:sessionid|sessid)$/.test(words.slice(-2).join(''))||/^(?:sessionid|sessid)$/.test(last);
		let compound=false;for(let n=1;n<=3;n++)if(KEY_RULES.secretCompounds.includes(words.slice(-n).join('')))compound=true;
		if((KEY_RULES.secretWords.some(w=>words.includes(w))||compound||KEY_RULES.secretExact.includes(k)) && (!KEY_RULES.secretReferences.includes(last)||session))return 'secret';
		if(k==='userid'||k==='uid'||KEY_RULES.users.includes(last)||KEY_RULES.users.includes(words.slice(-2).join(''))||KEY_RULES.users.includes(words.slice(-3).join('')))return 'username';
		if(KEY_RULES.hosts.includes(last)||KEY_RULES.hosts.includes(words.slice(-2).join('')))return 'host';
		return null;
	}
	function fieldType(key) {
		const k=keyWords(key).join(''), c=classifyKey(key);
		if(c==='secret')return /password|passwd|passphrase|pwd|passwort|kennwort|пароль/.test(k)?'password':/apikey|xapikey|accesskey/.test(k)?'api_key':/token|csrf|xsrf|sid/.test(k)?'token':'secret';
		if(c==='username')return undefined;
		if(c==='identifier')return KEY_RULES.personal.includes(k)?'personal':'identifier';
		return undefined;
	}

	// -------------------------------------------------------------- detectors
	// Each detector scans one chunk and calls emit(start, end, category, prefix, value, norm).

	const SPACED_KEY_SOURCE = String.raw`(?:User[ \t]{1,8}(?:name|ID)|API[ \t]{1,8}Key|Access[ \t]{1,8}Token|Auth[ \t]{1,8}Token|Client[ \t]{1,8}Secret|Private[ \t]{1,8}Key|(?:Full|Person|First|Last|Given|Family|Contact|Customer|Display)[ \t]{1,8}name|(?:Street[ \t]{1,8}address|Date[ \t]{1,8}of[ \t]{1,8}birth)|Имя[ \t]{1,8}пользователя)`;
	const CONTEXT_KEY_SOURCE = String.raw`(?:${SPACED_KEY_SOURCE}|[\p{L}\p{N}_][\p{L}\p{N}\p{M}_.-]{0,63})`;

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
		kv: new RegExp(String.raw`(?<![\p{L}\p{N}\p{M}_.-])(["']?)(${CONTEXT_KEY_SOURCE})\1[ \t]{0,8}(?:=>|:=|[:=])[ \t]{0,8}(?:"((?:[^"\\\r\n]|\\.){0,4096})"|'([^'\r\n]{0,4096})'|([^\s"',;&|<>{}\[\]()]{1,4096}))`, 'gdiu'),
		xml: /<([A-Za-z][A-Za-z0-9_.-]{0,63})(?:[ \t][^<>\r\n]{0,256})?>([^<\r\n]{1,4096})<\/\1>/gd,
		xmlData: /<Data[ \t]+Name=["']([A-Za-z0-9_]{1,64})["'][ \t]*>([^<\r\n]{1,1024})<\/Data>/gd,
		winText: /(?<![A-Za-z])(Account Name|Account Domain|Workstation Name|Source Workstation|Computer Name|User Name|Logon Account|Client Name|Caller User Name|Target User Name|Target Server Name|Client Address)[ \t]{0,8}:[ \t]{1,16}([^\s]{1,256})/gd,
		card: /(?<![\d.-])\d(?:[ -]?\d){12,18}(?![\d])(?!-\d)/g,
		ssn: /(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])/g,
		// URL-encoded form in query strings: bob%40example.com.
		emailEncoded: new RegExp(String.raw`(^|[^\p{L}\p{N}\p{M}._%+-])(`+EMAIL_LOCAL+'%40'+EMAIL_DOMAIN+')','giu'),
		email: new RegExp(String.raw`(^|[^\p{L}\p{N}\p{M}._%+-])(`+EMAIL_LOCAL+'@'+EMAIL_DOMAIN+')','gu'),
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
			// User names may contain any letters (Cyrillic, umlauts): Unicode classes with the u flag.
			// \p{M} after the first character: decomposed (NFD) names such as "jo" + U+0308 + "rg".
			/\bby ([\p{L}\p{N}._-][\p{L}\p{M}\p{N}._-]{0,63})\(uid=\d{1,10}\)/gdu,
			/(?:^|[ \t:])(?:Removed|New|Started|Closed|Stopped) session [\p{L}\p{N}._-]{1,32} of user ([\p{L}\p{N}_][\p{L}\p{M}\p{N}._-]{0,63}?)\.?(?=[ \t]|$)/gmidu,
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
		sudoUser: /\bsudo(?:\[\d{1,10}\])?:[ \t]{1,16}([\p{L}\p{N}._-][\p{L}\p{M}\p{N}._-]{0,63})[ \t]{1,4}:/gdu,
		homePath: /(?:\/home\/|\/Users\/|(?<![A-Za-z])[A-Za-z]:(?:\\\\|\\|\/)Users(?:\\\\|\\|\/))([^\s\/\\:*?"'<>|,;]{1,64})/gid,
		domainUser: /(?<![A-Za-z0-9_\\\/:.-])([A-Z][A-Z0-9-]{1,14})\\{1,2}([\p{L}\p{N}][\p{L}\p{M}\p{N}._-]{0,63})(?![\p{L}\p{M}\p{N}_\\])/gdu,
		syslogHost: /^(?:<\d{1,3}>\d{0,2} ?)?(?:[A-Z][a-z]{2} [ 0-3]\d \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?) ([A-Za-z0-9][A-Za-z0-9._-]{0,253}) (?=[A-Za-z0-9_.\/-]{1,64}(?:\[\d{1,10}\])?(?::| - ))/gmd,
		fqdn: /(?<![A-Za-z0-9_@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,126}[A-Za-z]{2,63}\.?(?![A-Za-z0-9_-]|\.[A-Za-z0-9])/g
	};

	// Scan keys first. Recognized scalar fields use a linear reader; the bounded
	// legacy grammar is retained only to enter unknown quoted containers.
	const KV_HEAD_RE = new RegExp(String.raw`(?<![\p{L}\p{N}\p{M}_.-])(["']?)(${CONTEXT_KEY_SOURCE})\1[ \t]{0,8}(?:=>|:=|[:=])[ \t]{0,8}`, 'gdiu');
	const KV_VALUE_RE = new RegExp(RE.kv.source, 'diyu');
	const KV_NEXT_SPACED_RE = new RegExp(String.raw`^${SPACED_KEY_SOURCE}=(?!=|$)`, 'i');

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

	function detectEmails(text,emit) {
		for(const re of [RE.emailEncoded,RE.email]){re.lastIndex=0;let m;while((m=re.exec(text))!==null){
			const start=m.index+m[1].length,value=m[2],end=start+value.length;
			if(/^[\p{L}\p{N}\p{M}-]/u.test(text.slice(end,end+2)))continue;
			const norm=value.replace(/%40/i,'@').normalize('NFC').toLowerCase();emit(start,end,'email','EMAIL',value,norm);
		}}
	}

	function ibanValid(value){
		const n=value.replace(/ /g,'').toUpperCase();if(!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(n))return false;
		let remainder=0;for(const ch of n.slice(4)+n.slice(0,4)){const digits=/[A-Z]/.test(ch)?String(ch.charCodeAt(0)-55):ch;for(const d of digits)remainder=(remainder*10+Number(d))%97;}return remainder===1;
	}
	function detectIdentifiers(text,emit){
		const arn=/arn:aws(?:-[a-z]+){0,3}:[a-z0-9-]{1,63}:[a-z0-9-]{0,63}:(\d{12}):/gd;let m;
		while((m=arn.exec(text))!==null)emit(m.indices[1][0],m.indices[1][1],'identifier','AWS_ACCOUNT',m[1],m[1]);
		for(const re of [/[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}/g,/[A-Za-z]{2}\d{2}(?: [A-Za-z0-9]{4}){2,7}(?: [A-Za-z0-9]{1,4})?/g]){
			re.lastIndex=0;while((m=re.exec(text))!==null){if(/[\p{L}\p{N}\p{M}]$/u.test(text.slice(Math.max(0,m.index-2),m.index))||/^[\p{L}\p{N}\p{M}]/u.test(text.slice(m.index+m[0].length,m.index+m[0].length+2))||!ibanValid(m[0]))continue;emit(m.index,m.index+m[0].length,'identifier','IBAN',m[0],m[0].replace(/ /g,'').toUpperCase());}
		}
	}
	function detectSids(text,emit){const re=/S-1-\d{1,20}(?:-\d{1,10}){3,15}/g;let m;while((m=re.exec(text))!==null){if(/[\p{L}\p{N}-]$/u.test(text.slice(Math.max(0,m.index-2),m.index))||/^[\p{L}\p{N}-]/u.test(text.slice(m.index+m[0].length,m.index+m[0].length+2)))continue;emit(m.index,m.index+m[0].length,'username','SID',m[0],m[0]);}}

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
				emit(valueStart, valueStart + value.length, 'secret', 'SECRET', value, value,undefined,'cookie');
			}
		}
	}

	function emitClassified(emit, key, value, start) {
		if (value == null) { return; }
		const category = classifyKey(key);
		if (!category) { return; }
		const type=fieldType(key), baseEmit=emit;emit=(...args)=>baseEmit(...args,undefined,type);
		const trimmed = value.replace(/[ \t]+$/, '');
		if (!trimmed || isPlaceholder(trimmed)) { return; }
		if(category==='username' && keyWords(key).join('')==='uid' && /^\d+$/.test(trimmed))return;
		if(category==='identifier'){emit(start,start+trimmed.length,'identifier',KEY_RULES.personal.includes(keyWords(key).join(''))?'PII':'ID',trimmed,trimmed);return;}
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
		} else if (trimmed.length <= 128 || key.toLowerCase().replace(/[^a-z0-9]/g, '') === 'userid') {
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

	/** Linear scalar reader: no value-length truncation or regex recursion. */
	function readKeyValue(text, start) {
		const quote = text[start] === '"' || text[start] === "'" ? text[start] : '';
		let at = start + (quote ? 1 : 0);
		const valueStart = at;
		while (at < text.length) {
			const ch = text[at];
			if (ch === '\r' || ch === '\n') { break; }
			if (quote) {
				if (ch === quote) { break; }
				if (ch === '\\' && at + 1 < text.length && text[at + 1] !== '\r' && text[at + 1] !== '\n') { at += 2; continue; }
			} else if (/[\s"',;&|<>{}\[\]()]/.test(ch)) { break; }
			at++;
		}
		return { start: valueStart, end: at, next: at + (quote && text[at] === quote ? 1 : 0), quoted: !!quote };
	}

	function detectKeyValues(text, emit, enabled) {
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
			const key = head[2], category = classifyKey(key);
			if(category==='personName'){
				const from=KV_HEAD_RE.lastIndex, quote=text[from]==='"'||text[from]==="'"?text[from]:'';let start=from+(quote?1:0),end=start;
				while(end<text.length&&end-start<=160){const ch=text[end];if(quote?ch===quote:/[,;&|\t\r\n]/.test(ch))break;end++;}
				let value=text.slice(start,end);
				if(!quote && /[?&]/.test(text[head.index-1]||'')){const stop=value.search(/[ \t]/);if(stop>=0){value=value.slice(0,stop);end=start+value.length;}}
				if(!quote){const next=/[ ]+[\p{L}\p{N}_][\p{L}\p{N}\p{M}_.-]{0,63}[ \t]{0,8}(?:=>|:=|[:=])/u.exec(value);if(next){value=value.slice(0,next.index);end=start+value.length;}}
				if(value.length<=128)emitClassified(emit,key,value,start);
				KV_HEAD_RE.lastIndex=Math.max(head.index+1,start);continue;
			}

			const credential = category === 'secret' || key.toLowerCase().replace(/[^a-z0-9]/g, '') === 'userid';
			KV_VALUE_RE.lastIndex = head.index;
			const legacy = KV_VALUE_RE.exec(text);
			let token;
			if (legacy) {
				const group = legacy[3] != null ? 3 : legacy[4] != null ? 4 : 5;
				token = { start: legacy.indices[group][0], end: legacy.indices[group][1], next: KV_VALUE_RE.lastIndex, quoted: group !== 5 };
				if (credential && ((group === 5 && token.end - token.start === 4096) || (group === 4 && text[token.end - 1] === '\\') || token.start < KV_HEAD_RE.lastIndex)) {
					const complete = readKeyValue(text, KV_HEAD_RE.lastIndex);
					if (complete.end - complete.start > 4096 || (group === 4 && text[token.end - 1] === '\\')) { token = complete; }
				}
			} else if (credential) {
				token = readKeyValue(text, KV_HEAD_RE.lastIndex);
				if (token.end - token.start <= 4096) { continue; }
			} else { continue; }
			if (token.end === token.start) { continue; }
			const value = text.slice(token.start, token.end);
			const separator = text.slice(head.indices[2][1], token.start);
			const nextPair = !token.quoted && /[ \t]$/.test(separator) && (/^[A-Za-z_][A-Za-z0-9_.-]{0,63}=(?!=|$)/.test(value) || KV_NEXT_SPACED_RE.test(text.slice(token.start, token.start + 128)));
			const pamPair = /:/.test(separator) && head.index > 0 && text[head.index - 1] === '(';
			const jsonScalar = !token.quoted && head[1] === '"' && /^"[ \t]*:[ \t]*$/.test(separator) && /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(value);
			if (!nextPair && !pamPair) {
				emitClassified(jsonScalar ? ((a,b,c,d,e,f,g,type) => emit(a,b,c,d,e,f,true,type)) : emit, key, value, token.start);
			}
			// An enabled credential context owns its complete scalar. Rescanning
			// nested "password=" strings inside it would be quadratic on long input.
			KV_HEAD_RE.lastIndex = !nextPair && !pamPair && token.end - token.start > 4096 && enabled[category] && (category === 'secret' || category === 'username')
				? Math.max(head.index + 1, token.end - 128) : token.start;
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
				errors.push({ index, field: 'pattern', message: 'Invalid regular expression. Review the pattern syntax.' });
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

	/** Parse raw CSV offsets, never reserialize the document. Quotes/newlines stay in place. */
	function readDelimitedRecord(text, from, delimiter, limit) {
		const fields = [];
		const stop = limit == null ? text.length : Math.min(limit, text.length);
		let at = from;
		while (at <= stop) {
			let start = at;
			while (start < stop && (text[start] === ' ' || (delimiter !== '\t' && text[start] === '\t'))) { start++; }
			const quoted = text[start] === '"';
			let end, next;
			if (quoted) {
				start++;
				end = start;
				while (end < stop) {
					if (text[end] === '"') {
						if (text[end + 1] === '"') { end += 2; continue; }
						break;
					}
					end++;
				}
				if (end >= stop) { return null; }
				next = end + 1;
				while (next < stop && (text[next] === ' ' || (delimiter !== '\t' && text[next] === '\t'))) { next++; }
			} else {
				next = at;
				while (next < stop && text[next] !== delimiter && text[next] !== '\r' && text[next] !== '\n') {
					if (text[next] === '"') { return null; }
					next++;
				}
				end = next;
				while (end > start && (text[end - 1] === ' ' || (delimiter !== '\t' && text[end - 1] === '\t'))) { end--; }
			}
			if (next === stop && stop < text.length) { return null; }
			if (next < stop && text[next] !== delimiter && text[next] !== '\r' && text[next] !== '\n') { return null; }
			fields.push({ start, end, quoted });
			if (fields.length > 512) { return null; }
			if (text[next] === delimiter) { at = next + 1; continue; }
			let after = next;
			if (text[after] === '\r') { after++; }
			if (text[after] === '\n') { after++; }
			return { fields, end: next, next: after };
		}
		return null;
	}

	function csvFieldValue(text, field) {
		const raw = text.slice(field.start, field.end);
		return field.quoted ? raw.replace(/""/g, '"') : raw;
	}

	// Keep established ordinary-log labels/options. Typed CSV labels are subtypes
	// within the existing username/secret groups, including their totals and map.
	function csvColumn(header) {
		const name=header.trim();let category=/^[\p{L}_][\p{L}\p{N}\p{M}_ .\t-]{0,127}$/u.test(name)?classifyKey(name):null;
		const k=keyWords(name).join('');if(/[ \t]/.test(name)&&!['userid','accesstoken','authtoken','clientsecret',...KEY_RULES.users,...KEY_RULES.names,...KEY_RULES.phones,...KEY_RULES.secretWords,...KEY_RULES.secretCompounds,...KEY_RULES.secretExact,...KEY_RULES.identifiers,...KEY_RULES.personal,...KEY_RULES.hosts,...Object.values(KEY_RULES.localized).flat()].includes(k))category=null;
		return {name,category};
	}

	function csvFormatError() {
		const error = new Error('The recognized CSV table has an invalid record or inconsistent column count. No output was produced. Review the CSV structure.');
		error.code = 'CSV_FORMAT';
		return error;
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
		const fieldStats = {};

		let csvTables=null, chunkOffset=0, csvRanges=[],csvRegions=[];
		function planCsv(text){
			csvTables=[];let pos=text.charCodeAt(0)===0xFEFF?1:0;
			while(pos<text.length){let selected=null;
				const physicalEnd=lineEndFrom(text,pos), heading=text.slice(pos,Math.min(physicalEnd,pos+MAX_KEY_BLOCK));
				if(!/[,;\t]/.test(heading)||/[=\[\]{}:]/.test(heading)){pos=physicalEnd+(text.startsWith('\r\n',physicalEnd)?2:1);continue;}
				for(const delimiter of [',','\t',';']){
					const head=readDelimitedRecord(text,pos,delimiter,pos+MAX_KEY_BLOCK);if(!head||head.fields.length<2)continue;
					const columns=head.fields.map(f=>csvColumn(csvFieldValue(text,f)));
					if(columns.some(c=>c.name.length>128||/[=\[\]{}\r\n\0:]/.test(c.name))||!columns.some(c=>c.category))continue;
					// Each heading must look like a name, not ordinary prose with commas.

					const second=head.next<text.length?readDelimitedRecord(text,head.next,delimiter):null;
					if(second&&second.fields.length!==columns.length)continue;
					if(!second&&head.next<text.length)continue;
					let end=head.next,at=head.next;
					while(at<text.length){if(text[at]==='\r'||text[at]==='\n')break;const row=readDelimitedRecord(text,at,delimiter);if(!row||row.fields.length!==columns.length)break;end=row.next;at=row.next;}
					selected={start:pos,headerEnd:head.next,end,delimiter,columns};break;
				}
				if(selected){csvTables.push(selected);pos=selected.end;}else{const end=lineEndFrom(text,pos);pos=end+(text.startsWith('\r\n',end)?2:1);}
			}
		}
		function csvChunkCut(text,from,chunkChars){
			if(!csvTables)planCsv(text);let cut=nextCut(text,from,chunkChars);
			for(const table of csvTables){if(cut<=table.headerEnd||cut>=table.end)continue;let pos=Math.max(from,table.headerEnd);while(pos<cut){const row=readDelimitedRecord(text,pos,table.delimiter);if(!row)break;pos=row.next;}cut=Math.max(cut,pos);}
			return cut;
		}
		function detectCsv(text,emit){
			if(!csvTables)planCsv(text);csvRanges=[];csvRegions=[];const values=[];
			for(const table of csvTables){if(table.end<=chunkOffset||table.start>=chunkOffset+text.length)continue;
				csvRanges.push({start:Math.max(0,table.start-chunkOffset),end:Math.min(text.length,table.end-chunkOffset)});
				let pos=Math.max(table.headerEnd-chunkOffset,0);
				while(pos<Math.min(text.length,table.end-chunkOffset)){
					const row=readDelimitedRecord(text,pos,table.delimiter);if(!row||row.fields.length!==table.columns.length)break;
					row.fields.forEach((field,i)=>{csvRegions.push(field);values.push({field,column:table.columns[i]});});pos=row.next;
				}
			}
			for(const {field,column}of values){const value=csvFieldValue(text,field);if(!value)continue;
				if(['secret','username','identifier'].includes(column.category)){
					const fullEmit=(a,b,cat,prefix,original,norm,scalar,type)=>{const pieces=/[^\r\n]+/g,raw=text.slice(field.start,field.end);let m;while((m=pieces.exec(raw))!==null)emit(field.start+m.index,field.start+m.index+m[0].length,cat,prefix,value,norm,false,type);};
					emitClassified(fullEmit,column.name,value,field.start);
				}else emitClassified(emit,column.name,text.slice(field.start,field.end),field.start);
			}
		}
		function csvSpanAllowed(text,start,end){
			const region=csvRanges.find(r=>start<r.end&&end>r.start);if(!region)return true;
			let low=0,high=csvRegions.length;while(low<high){const mid=(low+high)>>>1;if(csvRegions[mid].start<=start)low=mid+1;else high=mid;}
			const field=csvRegions[low-1];if(!field||start<field.start||end>field.end)return false;
			if(!field.quoted)return true;
			for(const at of [start,end]){if(at<=field.start||at>=field.end||text[at-1]!=='"'||text[at]!=='"')continue;let first=at-1;while(first>field.start&&text[first-1]==='"')first--;if((at-first)%2)return false;}return true;
		}

		const detectors = [
			// Explicit scalar credentials take precedence over patterns inside them.
			['*', (t, e) => detectKeyValues(t, e, enabled)],
			['custom', (t, e) => detectCustom(t, e, compiled.rules, warnings)],
			['privateKey', detectPrivateKeys],
			['jwt', (t, e) => detectSimple(RE.jwt, t, e, 'jwt', 'JWT')],
			['auth', detectBearerBasic],
			['auth', detectAuthHeaders],
			['apiKey', detectApiKeys],
			['*', detectUrls],
			['secret', detectCookies],
			['*', detectContacts],
			['secret', detectCef],
			['card', (t, e) => detectSimple(RE.card, t, e, 'card', 'CARD', v => cardValid(v), v => v.replace(/\D/g, ''))],
			['ssn', (t, e) => detectSimple(RE.ssn, t, e, 'ssn', 'SSN')],
			['email', detectEmails],
			['identifier', detectIdentifiers],
			['username', detectSids],
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

		function labelFor(prefix, category, norm, value, type) {
			if(category==='secret')prefix='SECRET';
			const key = category + '\u0000' + norm;
			let entry = entries.get(key);
			if (!entry) {
				const n = (counters.get(prefix) || 0) + 1;
				counters.set(prefix, n);
				entry = { label: options.labelMode === 'generic' ? 'REDACTED_' + prefix : prefix + '_' + n, category, original: value, occurrences: 0 };
				entries.set(key, entry);
				stats[category].unique++;
			}
			if(type){const typed=fieldStats[type]||(fieldStats[type]={category,replacements:0,unique:0});if(!entry.types)entry.types=new Set();if(!entry.types.has(type)){typed.unique++;entry.types.add(type);}typed.replacements++;}
			entry.occurrences++;
			stats[category].replacements++;
			return entry.label;
		}

		/**
		 * Process one chunk that starts and ends on a line boundary.
		 * CSV callers use session.nextCut() to retain complete logical records.
		 * Returns { output, spans } where spans are [outStart, outEnd, category] in the chunk output.
		 */
		function processChunk(text, wantSpans) {
			const covered = new Uint8Array(text.length);
			const accepted = [];
			const emit = (start, end, category, prefix, value, norm, jsonScalar, fieldType) => {
				if (!enabled[category] || end <= start || start < 0 || end > text.length || !csvSpanAllowed(text, start, end)) { return; }
				for (let i = start; i < end; i++) {
					if (covered[i]) { return; }
					const c = text.charCodeAt(i);
					if (c === 10 || c === 13) { return; }
				}
				covered.fill(1, start, end);
				accepted.push({ start, end, category, prefix, value, norm, jsonScalar, fieldType });
			};
			detectCsv(text, emit);
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
				const rawLabel = labelFor(span.prefix, span.category, span.norm, span.value, span.fieldType);
				const label = span.jsonScalar ? '"' + rawLabel + '"' : rawLabel;
				parts.push(label);
				if (spans) { spans.push([outLen, outLen + label.length, span.category]); }
				outLen += label.length;
				pos = span.end;
			}
			parts.push(text.slice(pos));
			chunkOffset+=text.length;
			return { output: parts.join(''), spans };
		}

		function result() {
			const map = [];
			for (const entry of entries.values()) {
				map.push(Object.assign({ label: entry.label, category: entry.category, original: entry.original, occurrences: entry.occurrences },entry.types?{fieldTypes:[...entry.types].sort()}:{}));
			}
			return { stats, map, fieldStats: Object.keys(fieldStats).length ? fieldStats : undefined, warnings: Object.assign({}, warnings) };
		}

		return { options, processChunk, result, nextCut: csvChunkCut };
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
	 * Returns { output, stats, fieldStats, map, preview: { text, spans, truncated }, lines, warnings }.
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
			const cut = session.nextCut(text, from, chunkChars);
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
			fieldStats: res.fieldStats,
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
		_internal: { isIPv4, isNonIdentifyingIPv4, isIPv6, isPrivateIPv4, luhnValid, cardValid, hostValid, classifyKey, keyWords, fieldType, KEY_RULES, ibanValid, nextCut, MAX_KEY_BLOCK }
	};
}));
