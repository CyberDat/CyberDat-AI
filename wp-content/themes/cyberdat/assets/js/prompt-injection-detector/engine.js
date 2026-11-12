/*!
 * CyberDat Indirect Prompt Injection Sanitizer & Detector: analysis engine.
 *
 * Pure, dependency-free and side-effect free: no DOM, storage or network APIs
 * are used. Loaded by the Web Worker (importScripts) and by Node.js tests.
 *
 * Model:
 *  - Detection is the primary result. A finding has a rule id, group,
 *    severity, position in the ORIGINAL text and a plain-language explanation.
 *  - Before matching, a normalized copy is built (invisible and bidi
 *    characters removed, Unicode NFKC). Encoded fragments (Base64, hex, URL,
 *    HTML/Unicode escapes) are decoded to a bounded depth and analyzed too.
 *  - The sanitized copy is secondary and always comes with an explicit list of
 *    edits, so the user can see what was changed.
 *  - Rules are heuristics. A rephrased attack is not detected; nothing here can
 *    certify a text as safe.
 *
 * Performance and ReDoS: every pattern is line-local and uses bounded
 * quantifiers; multi-line constructs (HTML comments, hidden elements) are found
 * with indexOf scans and bounded windows. Input size is capped.
 */
(function (root, factory) {
	'use strict';
	const api = factory();
	if (typeof module === 'object' && module.exports) {
		module.exports = api;
	} else {
		root.CyberDatPromptInjectionDetector = api;
	}
}(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const VERSION = '1.0.0';
	const RULESET_VERSION = '2026-11-11.1';
	const MAX_INPUT_CHARS = 20 * 1024 * 1024;
	const MAX_FINDINGS = 2000;
	const MAX_PER_RULE = 300;
	const MAX_DECODE_DEPTH = 3;
	const MAX_DECODE_CANDIDATES = 4000;
	const MAX_DECODED_CHARS = 4 * 1024 * 1024;
	const MAX_DECODED_LISTED = 200;
	const MAX_CANDIDATE_CHARS = 1 << 20;
	const CHUNK_CHARS = 1 << 19;
	const RESCAN_LINE_CHARS = 20000;

	const GROUPS = [
		{ id: 'role', name: 'Role and boundary spoofing' },
		{ id: 'override', name: 'Instruction override' },
		{ id: 'exfiltration', name: 'Tool calls and data exfiltration' },
		{ id: 'hidden', name: 'Hidden text' },
		{ id: 'encoded', name: 'Encoded payloads' },
		{ id: 'obfuscation', name: 'Obfuscation' },
		{ id: 'extraction', name: 'System prompt and secret extraction' }
	];
	const GROUP_IDS = GROUPS.map(g => g.id);
	const SEVERITIES = ['high', 'medium', 'low'];
	const RANK = { low: 1, medium: 2, high: 3 };

	function defaultOptions() {
		return { normalizeNFKC: true, removeInvisible: true, neutralize: 'low', previewChars: 200000 };
	}

	// ---------------------------------------------------------------- helpers

	/** Letter-aware word boundaries (JavaScript \b is ASCII-only). */
	const L = String.raw`(?<![\p{L}\p{N}_])`;
	const R = String.raw`(?![\p{L}\p{N}_])`;
	const rx = source => new RegExp(source, 'giu');
	const rxm = source => new RegExp(source, 'gimu');

	function maxSeverity(a, b) {
		return (RANK[a] || 0) >= (RANK[b] || 0) ? a : b;
	}

	function codePointBefore(text, i) {
		if (i <= 0) { return -1; }
		const c = text.charCodeAt(i - 1);
		if (c >= 0xDC00 && c <= 0xDFFF && i >= 2) {
			const h = text.charCodeAt(i - 2);
			if (h >= 0xD800 && h <= 0xDBFF) { return ((h - 0xD800) << 10) + (c - 0xDC00) + 0x10000; }
		}
		return c;
	}

	function hex(cp) {
		return 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');
	}

	/** Make invisible and control characters visible for display (excerpts, diff). */
	const INVISIBLE_DISPLAY_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁤⁦-⁯ㅤ︀-️﻿ﾠ\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;
	function visible(s) {
		return s.replace(INVISIBLE_DISPLAY_RE, ch => '⟨' + hex(ch.codePointAt(0)) + '⟩');
	}

	function clip(s, max) {
		return s.length > max ? s.slice(0, max) + '…' : s;
	}

	// ---------------------------------------------------------------- invisible characters

	const INVISIBLE_RE = /[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁤⁦-⁯ㅤ︀-️﻿ﾠ\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]+/gu;
	const EMOJI_RE = /\p{Extended_Pictographic}|\p{Regional_Indicator}/u;
	const RTL_RE = /[֐-ࣿיִ-﷿ﹰ-﻿]/;
	const LETTER_RE = /[\p{L}\p{N}]/u;

	function kindOf(cp) {
		if (cp >= 0xE0000 && cp <= 0xE007F) { return 'tag'; }
		if ((cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF) || (cp >= 0x180B && cp <= 0x180D) || cp === 0x180F) { return 'variation'; }
		if (cp === 0x200E || cp === 0x200F || cp === 0x061C || (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)) { return 'bidi'; }
		if (cp === 0x00AD) { return 'softHyphen'; }
		return 'zeroWidth';
	}

	function lineAround(text, i) {
		const s = text.lastIndexOf('\n', i - 1) + 1;
		let e = text.indexOf('\n', i);
		if (e < 0) { e = text.length; }
		return text.slice(s, Math.min(e, s + 4000));
	}

	/**
	 * Find runs of invisible characters in the original text. Each run is split
	 * by kind; "legit" marks uses that are normal in real text (emoji joiners,
	 * emoji presentation selectors, a leading BOM, direction marks in RTL text).
	 */
	function scanInvisible(text) {
		const runs = [];
		INVISIBLE_RE.lastIndex = 0;
		let m;
		while ((m = INVISIBLE_RE.exec(text)) !== null) {
			const start = m.index;
			const end = start + m[0].length;
			const prev = codePointBefore(text, start);
			const next = end < text.length ? text.codePointAt(end) : -1;
			const prevChar = prev >= 0 ? String.fromCodePoint(prev) : '';
			const nextChar = next >= 0 ? String.fromCodePoint(next) : '';
			const cps = Array.from(m[0], ch => ch.codePointAt(0));
			const kinds = {};
			for (const cp of cps) { const k = kindOf(cp); kinds[k] = (kinds[k] || 0) + 1; }
			const only = Object.keys(kinds);
			let legit = false;
			const afterEmoji = EMOJI_RE.test(prevChar) || prev === 0x20E3 || (prev >= 0x30 && prev <= 0x39) || prev === 0x23 || prev === 0x2A || (prev >= 0x2190 && prev <= 0x2BFF) || (prev >= 0x3000 && prev <= 0x9FFF);
			if (only.length === 1 && only[0] === 'zeroWidth' && cps.length <= 2 && cps.every(cp => cp === 0x200D) && EMOJI_RE.test(prevChar) && EMOJI_RE.test(nextChar)) {
				legit = true; // emoji ZWJ sequence
			} else if (only.length === 1 && only[0] === 'variation' && cps.length === 1 && afterEmoji) {
				legit = true; // emoji or text presentation selector
			} else if (cps.length === 2 && cps[0] === 0xFE0F && cps[1] === 0x200D && EMOJI_RE.test(prevChar) && EMOJI_RE.test(nextChar)) {
				legit = true;
			} else if (start === 0 && cps.length === 1 && cps[0] === 0xFEFF) {
				legit = true; // byte order mark
			} else if (only.length === 1 && only[0] === 'softHyphen' && cps.length <= 2) {
				legit = true; // hyphenation hint
			} else if (only.length === 1 && only[0] === 'tag' && prev === 0x1F3F4 && cps[cps.length - 1] === 0xE007F) {
				legit = true; // subdivision flag emoji, e.g. England
			} else if (only.length === 1 && only[0] === 'bidi' && cps.every(cp => cp === 0x200E || cp === 0x200F || cp === 0x061C) && RTL_RE.test(lineAround(text, start))) {
				legit = true; // direction marks in right-to-left text
			} else if (only.length === 1 && only[0] === 'zeroWidth' && cps.length === 1 && cps[0] === 0x200C && /[؀-ۿऀ-෿]/.test(prevChar + nextChar)) {
				legit = true; // ZWNJ in Persian or Indic scripts
			}
			runs.push({ start, end, cps, kinds, legit, prevIsLetter: LETTER_RE.test(prevChar), nextIsLetter: LETTER_RE.test(nextChar) });
		}
		return runs;
	}

	// ---------------------------------------------------------------- normalization

	const NON_ASCII_RUN_RE = /[^\x00-\x7F]+/g;
	const SEGMENT_RE = /\P{M}\p{M}*|\p{M}+/gu;

	/**
	 * Build the normalized text used for matching: invisible characters removed,
	 * then NFKC applied segment by segment so that every normalized position can
	 * be mapped back to the original text. Returns the edits, which double as the
	 * mapping table.
	 */
	function normalize(text, runs) {
		const edits = [];
		const parts = [];
		let pos = 0;
		let n = 0;
		const nfkc = typeof String.prototype.normalize === 'function';
		function pushPlain(s, origStart) {
			if (!s) { return; }
			if (!nfkc || /^[\x00-\x7F]*$/.test(s)) { parts.push(s); n += s.length; return; }
			NON_ASCII_RUN_RE.lastIndex = 0;
			let last = 0;
			let m;
			while ((m = NON_ASCII_RUN_RE.exec(s)) !== null) {
				// Include a preceding ASCII base so combining marks compose with it.
				let runStart = m.index;
				if (runStart > last && /^\p{M}/u.test(m[0])) { runStart--; }
				if (runStart > last) { const plain = s.slice(last, runStart); parts.push(plain); n += plain.length; }
				const run = s.slice(runStart, m.index + m[0].length);
				if (run.normalize('NFKC') === run) {
					parts.push(run); n += run.length;
				} else {
					SEGMENT_RE.lastIndex = 0;
					let sm;
					let local = 0;
					while ((sm = SEGMENT_RE.exec(run)) !== null) {
						const seg = sm[0];
						const norm = seg.normalize('NFKC');
						if (norm !== seg) {
							const o0 = origStart + runStart + sm.index;
							edits.push({ o0, o1: o0 + seg.length, n0: n, n1: n + norm.length, kind: 'nfkc', from: seg, to: norm });
						}
						parts.push(norm); n += norm.length;
						local = sm.index + seg.length;
					}
					if (local < run.length) { const rest = run.slice(local); parts.push(rest); n += rest.length; }
				}
				last = m.index + m[0].length;
			}
			if (last < s.length) { const tail = s.slice(last); parts.push(tail); n += tail.length; }
		}
		for (const run of runs) {
			pushPlain(text.slice(pos, run.start), pos);
			edits.push({ o0: run.start, o1: run.end, n0: n, n1: n, kind: 'invisible', run });
			pos = run.end;
		}
		pushPlain(text.slice(pos), pos);
		edits.sort((a, b) => a.o0 - b.o0);
		const normalized = parts.join('');
		return { text: normalized, edits, toOrig: mapper(edits) };
	}

	/** Map a normalized offset back to the original text. */
	function mapper(edits) {
		const byN = edits.slice().sort((a, b) => a.n0 - b.n0 || a.o0 - b.o0);
		return function (n, isEnd) {
			let lo = 0;
			let hi = byN.length - 1;
			let k = -1;
			while (lo <= hi) {
				const mid = (lo + hi) >> 1;
				if (byN[mid].n0 < n || (byN[mid].n0 === n && (isEnd || byN[mid].n1 === byN[mid].n0))) { k = mid; lo = mid + 1; } else { hi = mid - 1; }
			}
			if (k < 0) { return n; }
			const e = byN[k];
			if (n >= e.n1) { return e.o1 + (n - e.n1); }
			return isEnd ? e.o1 : e.o0;
		};
	}

	/** Light normalization for decoded fragments (offsets are not needed there). */
	function quickNormalize(s) {
		const t = s.replace(INVISIBLE_RE, '');
		return typeof t.normalize === 'function' ? t.normalize('NFKC') : t;
	}

	// ---------------------------------------------------------------- context heuristics

	const QUOTE_PAIRS = { '"': '"', '“': '”', '„': '“”', '«': '»', '‘': '’', '\'': '\'', '`': '`', '»': '«', '”': '”' };
	const EXAMPLE_BEFORE_RE = /(?:e\.g\.|i\.e\.|for example|for instance|such as|like|phrases?|strings?|called|known as|zum Beispiel|z\.\s?B\.|beispielsweise|etwa|например|такие как|вроде|типа|наподобие)\s{0,3}[:,]?\s{0,3}["“„«‘'`]?\s{0,2}$/iu;
	const NEGATION_BEFORE_RE = /(?:never|not|n't|don't|do not|must not|should not|avoid(?:ing)?|nicht|nie(?:mals)?|kein\p{L}*|не|никогда|нельзя)\s{1,3}(?:\p{L}+\s{1,3}){0,3}$/iu;

	function lineBounds(text, start, end) {
		const ls = text.lastIndexOf('\n', start - 1) + 1;
		let le = text.indexOf('\n', end);
		if (le < 0) { le = text.length; }
		return [ls, le];
	}

	/** The phrase is quoted or presented as an example ("phrases like ..."). */
	const OBJECT_AFTER_RE = /^[\s,]{0,3}(?:(?:and|or|,)\s{0,3}\S{1,24}\s{1,3})?(?:markers?|tokens?|tags?|delimiters?|format|template|syntax|strings?)\b/i;
	function isMention(text, start, end) {
		const [ls, le] = lineBounds(text, start, end);
		if (OBJECT_AFTER_RE.test(text.slice(end, Math.min(le, end + 40)))) { return true; }
		const before = text.slice(Math.max(ls, start - 80), start);
		if (EXAMPLE_BEFORE_RE.test(before)) { return true; }
		const near = before.slice(-28);
		for (let i = near.length - 1; i >= 0; i--) {
			const close = QUOTE_PAIRS[near[i]];
			if (!close) { continue; }
			if (near[i] === '\'' && i > 0 && /\p{L}/u.test(near[i - 1])) { continue; } // apostrophe
			const after = text.slice(end, Math.min(le, end + 120));
			for (const c of close) { if (after.indexOf(c) !== -1) { return true; } }
			return false;
		}
		return false;
	}

	function isNegated(text, start) {
		const ls = text.lastIndexOf('\n', start - 1) + 1;
		return NEGATION_BEFORE_RE.test(text.slice(Math.max(ls, start - 30), start));
	}

	// ---------------------------------------------------------------- text rules

	const OVERRIDE_VERB_EN = String.raw`(?:ignore|ignoring|disregard|forget|override|overrule|bypass|discard|abandon|neglect|nullify|cancel)`;
	const OVERRIDE_TARGET_EN = String.raw`(?:previous|prior|above|earlier|preceding|foregoing|all|any|every|your|the|these|those|system|original|initial|existing|old|current|developer|safety)`;
	const OVERRIDE_OBJECT_EN = String.raw`(?:instructions?|prompts?|rules?|directions?|directives?|guidelines?|guidance|context|messages?|constraints?|polic(?:y|ies)|guardrails?|restrictions?|programming|commands?|orders?|safeguards?|filters?)`;
	/** A gap inside one clause: no line break, sentence end or "and/then/but" followed by another verb. */
	const GAP = n => String.raw`(?:(?!\s(?:and|then|but|und|dann|aber|и|затем|но)\s)[^\n.!?;]){0,${n}}?`;
	const ROLE_TOKENS = String.raw`<\|\s?(?:im_start|im_end|im_sep|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id|begin_of_text|end_of_text|eom_id|ipython|tool|developer)\s?\|>`;

	/**
	 * Text rules run on the normalized text and on decoded fragments.
	 * mention: severity drops to low when the phrase is quoted or given as an example.
	 * negation: the match is skipped when directly preceded by a negation ("never print...").
	 * sanitize: 'sentence' removes the enclosing sentence, 'match' only the match, 'none' keeps it.
	 */
	const TEXT_RULES = [
		// 1. Role and boundary spoofing
		{ id: 'PI-ROLE-001', group: 'role', severity: 'high', sanitize: 'match', mention: true,
			title: 'Chat template control token',
			explain: 'Special tokens such as <|im_start|> or <|eot_id|> delimit messages inside a model prompt. In untrusted content they try to fake the start of a new system or assistant message.',
			re: rx(ROLE_TOKENS) },
		{ id: 'PI-ROLE-002', group: 'role', severity: 'high', sanitize: 'match', mention: true,
			title: 'Instruction-format delimiter',
			explain: 'Markers like [INST], [/INST] and <<SYS>> are used by some model families to separate system and user turns. Retrieved text has no reason to contain them.',
			re: rx(String.raw`\[\/?(?:INST|SYS|SYSTEM)\]|<<\/?SYS>>`) },
		{ id: 'PI-ROLE-003', group: 'role', severity: 'medium', sanitize: 'match', mention: true,
			title: 'Pseudo-XML role or instruction tag',
			explain: 'Tags such as <system> or </instructions> imitate the structure many applications use to separate trusted instructions from data.',
			re: rx(String.raw`<\/?(?:system|system[_-]prompt|sys|assistant|developer|admin|instructions?|user[_-]instructions|im[_-]system|prompt|system[_-]message|important[_-]instructions)(?:\s[^<>\n]{0,100})?>`) },
		{ id: 'PI-ROLE-004', group: 'role', severity: 'medium', sanitize: 'sentence', mention: true,
			title: 'Role label followed by a directive',
			explain: 'A line that starts with a role name ("System:", "Assistant:") and then addresses the reader imitates a message from a trusted participant of the conversation.',
			re: rxm(String.raw`^[ \t>*#_\-\[(]{0,8}(?:system|assistant|developer|admin(?:istrator)?|operator|root|sistema|systém|система|ассистент)\s{0,3}(?:prompt|message|note|override|instructions?|update)?\s{0,2}[\])]?\s{0,2}[:：]\s{0,4}[^\n]{0,160}?${L}(?:you|your|ignore|must|always|never|respond|reply|answer|from now|instructions?|du|dein\p{L}*|sie|ты|твой|твои|вы|ваш\p{L}*)${R}`) },
		{ id: 'PI-ROLE-005', group: 'role', severity: 'medium', sanitize: 'match', mention: true,
			title: 'Fake end-of-context boundary',
			explain: 'Decorated lines like "--- END OF DOCUMENT ---" or closing tags like </context> try to convince the model that the untrusted data has ended and that what follows is a new instruction.',
			re: rxm(String.raw`(?:[\-=#*_~\[<(]{2,}[ \t]{0,3}(?:end|begin|start|close|ende|конец)[ \t]{0,3}(?:of[ \t]{1,3})?(?:the[ \t]{1,3})?(?:system[ \t]{1,3}|user[ \t]{1,3}|untrusted[ \t]{1,3}|external[ \t]{1,3}|retrieved[ \t]{1,3})?(?:document|context|input|data|content|prompt|instructions?|message|conversation|text|email|search results?|kontext|dokument|документа|контекста)s?[ \t]{0,3}(?:[\-=#*_~\]>)]{2,})?|<\/(?:document|context|untrusted[_-]?input|user[_-]?input|search[_-]?results?|retrieved[_-]?(?:content|documents?)|email|tool[_-]?output|function[_-]?results|external[_-]?content)>)`) },
		{ id: 'PI-ROLE-006', group: 'role', severity: 'low', sanitize: 'none', mention: false,
			title: 'Chat message structure with a privileged role',
			explain: 'A JSON message with role "system" or "developer" can be legitimate API code, but inside retrieved data it may try to inject a privileged message.',
			re: rx(String.raw`"role"\s{0,3}:\s{0,3}"(?:system|developer)"`) },
		{ id: 'PI-ROLE-007', group: 'role', severity: 'medium', sanitize: 'sentence', mention: true,
			title: 'Fake conversation turn',
			explain: 'Lines starting with "Human:" or "Assistant:" imitate a transcript format used in prompts and can make the model treat injected text as a previous turn.',
			re: rxm(String.raw`^[ \t>]{0,4}(?:Human|Assistant|AI)\s?:\s{1,4}\S`) },

		// 2. Instruction override
		{ id: 'PI-OVR-001', group: 'override', severity: 'high', sanitize: 'sentence', mention: true,
			title: 'Instruction override (English)',
			explain: 'Asks the model to ignore or replace the instructions it was given. This is the core move of most prompt injections.',
			re: rx(String.raw`\b${OVERRIDE_VERB_EN}\b${GAP(40)}\b${OVERRIDE_TARGET_EN}\b${GAP(30)}\b${OVERRIDE_OBJECT_EN}\b`) },
		{ id: 'PI-OVR-002', group: 'override', severity: 'high', sanitize: 'sentence', mention: true,
			title: 'Request to forget prior context (English)',
			explain: 'Asks the model to drop everything it was told before, so that the injected text becomes the only instruction.',
			re: rx(String.raw`\b(?:forget|disregard|ignore)\s{1,3}(?:about\s{1,3})?(?:everything|all(?:\s{1,3}of)?\s{1,3}(?:that|this|the above)|what\s{1,3}(?:you\s{1,3}(?:were|have\s{1,3}been)\s{1,3}told|was\s{1,3}said))(?:\s{1,3}(?:above|before|earlier|previously|so\s{1,3}far|until\s{1,3}now|you\s{1,3}(?:were|have\s{1,3}been)\s{1,3}told))?`) },
		{ id: 'PI-OVR-003', group: 'override', severity: 'high', sanitize: 'sentence', mention: true,
			title: 'Replacement task or goal',
			explain: 'Announces new or "real" instructions for the model, replacing the task the user actually asked for.',
			re: rx(String.raw`\b(?:your|the)\s{1,3}(?:new|real|actual|true|only|updated|primary|main)\s{1,3}(?:task|goal|job|objective|purpose|mission|instructions?|directive|role)\s{1,3}(?:is|are|now|will\s{1,3}be)\b|\b(?:new|updated|revised|real|actual|override)\s{1,3}(?:system\s{1,3})?(?:instructions?|directives?|orders?)\s{0,3}(?::|-{1,2}>|=>)`) },
		{ id: 'PI-OVR-004', group: 'override', severity: 'medium', sanitize: 'sentence', mention: true,
			title: 'Identity or mode reassignment',
			explain: 'Tries to give the model a new persona or an unrestricted "mode" so that it stops following its configuration.',
			re: rx(String.raw`\b(?:from\s{1,3}now\s{1,3}on|starting\s{1,3}now|henceforth|for\s{1,3}the\s{1,3}rest\s{1,3}of\s{1,3}(?:this|the)\s{1,3}conversation)\b[^\n]{0,20}?\byou(?:'ll|\s{1,3}(?:are|will|must|shall|should|have))\b|\byou\s{1,3}are\s{1,3}no\s{1,3}longer\b|\byou\s{1,3}are\s{1,3}now\s{1,3}(?:an?\s{1,3}(?:different|new|unrestricted|unfiltered|uncensored|evil|rogue|jailbroken)\b|(?:acting|operating|called|named|free|unrestricted|unfiltered|uncensored|jailbroken|DAN)\b|in\s{1,3}(?:developer|god|admin|debug|jailbreak|unrestricted|maintenance)\s{1,3}mode\b)|\bpretend\s{1,3}(?:to\s{1,3}be|you\s{1,3}are|that\s{1,3}you)\b|\b(?:enable|activate|enter|switch\s{1,3}to)\s{1,3}(?:developer|god|admin|debug|jailbreak|unrestricted|DAN)\s{1,3}mode\b|\bdo\s{1,3}anything\s{1,3}now\b`) },
		{ id: 'PI-OVR-005', group: 'override', severity: 'high', sanitize: 'sentence', mention: true,
			title: 'Instruction to hide actions from the user',
			explain: 'Tells the model to keep something from the user. Legitimate content never needs to ask an assistant to deceive the person it works for.',
			re: rx(String.raw`\b(?:do\s{1,3}not|don't|never)\s{1,3}(?:tell|inform|mention\s{1,3}(?:this|it)\s{1,3}to|alert|notify|let)\s{1,3}(?:the\s{1,3})?(?:user|human|operator|reader|recipient)s?\b|\bwithout\s{1,3}(?:telling|informing|notifying|alerting)\s{1,3}(?:the\s{1,3})?(?:user|human|operator)\b|\b(?:keep\s{1,3}this|this\s{1,3}(?:instruction|message)\s{1,3}(?:is|must\s{1,3}(?:be|remain)))\s{1,3}(?:secret|hidden|confidential)\s{1,3}from\s{1,3}(?:the\s{1,3})?(?:user|human)\b`) },
		{ id: 'PI-OVR-006', group: 'override', severity: 'medium', sanitize: 'sentence', mention: true,
			title: 'Text addressed to an AI system',
			explain: 'Content that speaks directly to "the AI" or "the assistant" reading it is a typical sign of an indirect injection planted in a web page, document or email.',
			re: rx(String.raw`\b(?:attention|note|message|instructions?|important|notice)\s{0,3}(?:to|for)\s{1,3}(?:the\s{1,3}|any\s{1,3}|all\s{1,3})?(?:AI|LLM|assistant|language\s{1,3}model|chatbot|GPT|AI\s{1,3}(?:assistant|agent|model)s?)s?\b|\bif\s{1,3}you\s{1,3}are\s{1,3}(?:an?\s{1,3})?(?:AI|LLM|large\s{1,3}language\s{1,3}model|language\s{1,3}model|assistant|chatbot|AI\s{1,3}(?:assistant|agent|model))\b|\b(?:AI|LLM)\s{1,3}(?:assistants?|agents?|models?|systems?)\s{1,3}(?:reading|processing|summari[sz]ing|analy[sz]ing)\s{1,3}(?:this|these)\b`) },
		{ id: 'PI-OVR-010', group: 'override', severity: 'high', sanitize: 'sentence', mention: true,
			title: 'Instruction override (German)',
			explain: 'German phrasing of "ignore all previous instructions".',
			re: rx(String.raw`${L}(?:ignorier(?:e|en|t)?|vergiss|vergessen\s{1,3}sie|missacht(?:e|en)|überschreib(?:e|en)|umgeh(?:e|en)|verwirf|verwerfen\s{1,3}sie)${R}${GAP(40)}${L}(?:alle|sämtliche|vorherigen?|vorigen?|bisherigen?|obigen?|früheren?|deine|ihre|ursprünglichen?|vorangegangenen?|vorhergehenden?)${R}${GAP(30)}${L}(?:Anweisungen|Anweisung|Instruktionen|Befehle|Regeln|Vorgaben|Anordnungen|Richtlinien|Systemanweisungen?|Einschränkungen)${R}`) },
		{ id: 'PI-OVR-011', group: 'override', severity: 'medium', sanitize: 'sentence', mention: true,
			title: 'Identity reassignment or new instructions (German)',
			explain: 'German phrasing that announces new instructions or gives the model a new identity.',
			re: rx(String.raw`${L}(?:vergiss|vergessen\s{1,3}sie)\s{1,3}alles(?:\s{0,3},?\s{0,3}(?:was|bisher|davor|oben|zuvor))?${R}|${L}(?:neue|aktualisierte|geänderte|echte)\s{1,3}(?:System)?(?:anweisungen|anweisung|instruktionen|aufgabe)\s{0,3}:|${L}ab\s{1,3}(?:jetzt|sofort)\s{1,3}(?:bist|wirst|sollst|musst)\s{1,3}du${R}|${L}du\s{1,3}bist\s{1,3}(?:jetzt|nun|ab\s{1,3}sofort)\s{1,3}(?:ein|eine|kein|keine|der|die|DAN|im)${R}|${L}(?:sag|sage|erzähl|erzähle)\s{1,3}(?:dem|der)\s{1,3}(?:Nutzer|Benutzer|Anwender)(?:in)?\s{1,3}nichts${R}`) },
		{ id: 'PI-OVR-020', group: 'override', severity: 'high', sanitize: 'sentence', mention: true,
			title: 'Instruction override (Russian)',
			explain: 'Russian phrasing of "ignore all previous instructions".',
			re: rx(String.raw`${L}(?:игнорируй(?:те)?|проигнорируй(?:те)?|забудь(?:те)?|не\s{1,3}обращай(?:те)?\s{1,3}внимани[ея]\s{1,3}на|отмени(?:те)?|пренебреги(?:те)?|не\s{1,3}следуй(?:те)?|не\s{1,3}выполняй(?:те)?|отбрось(?:те)?)${R}${GAP(40)}${L}(?:все|всё|любые|предыдущ\p{L}*|прежн\p{L}*|вышеизложенн\p{L}*|вышеуказанн\p{L}*|вышесказанн\p{L}*|ранее|сво[иёе]\p{L}*|тво[иёе]\p{L}*|системн\p{L}*|исходн\p{L}*|изначальн\p{L}*|старые|данные\s{1,3}тебе)${R}${GAP(30)}${L}(?:инструкци\p{L}*|указани\p{L}*|правил\p{L}*|команд\p{L}*|промпт\p{L}*|ограничени\p{L}*|установк\p{L}*|директив\p{L}*)`) },
		{ id: 'PI-OVR-021', group: 'override', severity: 'medium', sanitize: 'sentence', mention: true,
			title: 'Identity reassignment or new instructions (Russian)',
			explain: 'Russian phrasing that announces new instructions, tells the model to forget everything, or gives it a new identity.',
			re: rx(String.raw`${L}забудь(?:те)?\s{1,3}(?:вс[её]|обо\s{1,3}вс[её]м)(?:\s{0,3},?\s{0,3}(?:что|чему|выше|ранее|до\s{1,3}этого))?${R}|${L}(?:новые|обновл[её]нные|настоящие)\s{1,3}(?:системные\s{1,3})?(?:инструкции|указания|правила)\s{0,3}:|${L}(?:теперь|отныне|с\s{1,3}этого\s{1,3}момента|с\s{1,3}этой\s{1,3}минуты)\s{1,3}ты\s{1,3}(?:—\s{0,2}|-\s{0,2})?(?:не\s{1,3})?(?:будешь|должен|должна|являешься|работаешь|отвечаешь|—|\p{L}+ий|\p{L}+ый|\p{L}+ой)${R}|${L}ты\s{1,3}больше\s{1,3}не${R}|${L}не\s{1,3}(?:говори|сообщай|рассказывай|показывай)(?:те)?\s{1,3}(?:об\s{1,3}этом\s{1,3})?пользовател\p{L}*${R}`) },
		{ id: 'PI-OVR-030', group: 'override', severity: 'high', sanitize: 'sentence', mention: true,
			title: 'Instruction override (French or Spanish)',
			explain: 'French or Spanish phrasing of "ignore all previous instructions".',
			re: rx(String.raw`${L}(?:ignore[zr]?|oublie[zr]?)\s{1,3}(?:toutes\s{1,3})?(?:les|tes|vos)\s{1,3}(?:instructions|consignes|règles)\s{1,3}(?:précédentes|antérieures|ci-dessus|initiales)${R}|${L}(?:ignora(?:r)?|olvida(?:r)?)\s{1,3}(?:todas\s{1,3})?(?:las|tus|sus)\s{1,3}(?:instrucciones|reglas|indicaciones)\s{1,3}(?:anteriores|previas|iniciales)${R}`) },

		// 3. Tool calls and data exfiltration
		{ id: 'PI-EXF-001', group: 'exfiltration', severity: 'high', sanitize: 'match', mention: false,
			title: 'Markdown image that can leak data',
			explain: 'When a chat interface renders a Markdown image, the browser fetches its URL automatically. Query parameters or placeholders in that URL can carry conversation data to a third party without a click.',
			re: rx(String.raw`!\[[^\]\n]{0,200}\]\(\s{0,3}<?(?:https?:)?\/\/[^\s)<>]{1,300}\?[^\s)<>]{0,1000}?(?:(?:(?<=[?&;])(?:q|data|d|c|p|info|content|msg|message|text|secret|token|key|apikey|api_key|password|pass|pwd|prompt|conversation|chat|history|session|cookie|email|payload|exfil|leak|summary|context|memory)=)|\\?\{[^}\s]{1,40}\\?\}|%7B|\$\{?[A-Za-z_]{1,40}|\[[A-Z_]{3,40}\])`) },
		{ id: 'PI-EXF-002', group: 'exfiltration', severity: 'high', sanitize: 'match', mention: false,
			title: 'URL with a data placeholder',
			explain: 'A link or image URL that contains a placeholder such as {conversation} or [SECRET] asks the model to fill in private data and send it to the link target.',
			re: rx(String.raw`(?:\]\(|<img\b[^>\n]{0,200}?\bsrc\s{0,2}=\s{0,2}["']?|\bhref\s{0,2}=\s{0,2}["']?|\bsrc\s{0,2}=\s{0,2}["']?)(?:https?:)?\/\/[^\s"'<>)]{1,300}?(?:\\?\{\s{0,2}(?:data|secret|prompt|conversation|history|summary|info|password|token|key|api_?key|user_?data|email|chat|messages?|context|system_?prompt|creds?|credentials|cookie|session|memory)[^}\s]{0,20}\\?\}|%7B(?:data|secret|prompt|conversation|history|summary|password|token|key|email|chat|context)[^%\s]{0,20}%7D|\$\{[A-Za-z_]{1,40}\}|\[(?:DATA|SECRET|PROMPT|CONVERSATION|HISTORY|SUMMARY|INFO|PASSWORD|TOKEN|KEY|EMAIL|CONTEXT)[A-Z_]{0,20}\])`) },
		{ id: 'PI-EXF-003', group: 'exfiltration', severity: 'high', sanitize: 'sentence', mention: true,
			title: 'Instruction to send private data to an external destination',
			explain: 'Asks the model to transmit conversation content, credentials or user data to a URL, webhook or email address. This is how an injection turns into a data leak.',
			re: rx(String.raw`\b(?:send|post|upload|transmit|forward|exfiltrate|leak|e-?mail|submit|report|append|attach|encode|embed|copy|pass)\b${GAP(60)}\b(?:(?:the|all|this|your|any|my)\s{1,3})?(?:(?:entire|full|whole|previous|prior|current|complete)\s{1,3})?(?:conversation|chat(?:\s{1,3}history|\s{1,3}log)?|message\s{1,3}history|previous\s{1,3}messages|system\s{1,3}prompt|api[ _-]?keys?|passwords?|credentials|secrets?|access\s{1,3}tokens?|session\s{1,3}(?:tokens?|cookies?)|cookies|private\s{1,3}keys?|user(?:'s)?\s{1,3}(?:data|emails?|files|details|information|messages)|personal\s{1,3}(?:data|information)|environment\s{1,3}variables|contents?\s{1,3}of\s{1,3}(?:the\s{1,3})?(?:inbox|mailbox|files?|documents?|this\s{1,3}chat))\b[^\n]{0,80}?(?:https?:\/\/|\b(?:to|at|into)\s{1,3}(?:this|the\s{1,3}following|my|our|the)\s{1,3}(?:url|link|endpoint|server|address|webhook|email|inbox|form)\b|\bwebhook\b|@[a-z0-9-]{1,63}\.[a-z]{2,24}\b)`) },
		{ id: 'PI-EXF-004', group: 'exfiltration', severity: 'medium', sanitize: 'sentence', mention: true, negation: true,
			title: 'Instruction to leak private data',
			explain: 'Asks the model to leak, upload or forward private data. No destination was found on the same line, but the intent is the same.',
			re: rx(String.raw`\b(?:exfiltrate|leak|forward|upload|transmit|smuggle)\b${GAP(40)}\b(?:(?:the|all|this|your|any)\s{1,3})?(?:(?:entire|full|whole|previous|current)\s{1,3})?(?:conversation|chat\s{1,3}history|message\s{1,3}history|system\s{1,3}prompt|api[ _-]?keys?|passwords?|credentials|secrets|access\s{1,3}tokens?|session\s{1,3}cookies?|private\s{1,3}keys?|user(?:'s)?\s{1,3}(?:data|emails?|files|messages)|personal\s{1,3}data)\b`) },
		{ id: 'PI-EXF-005', group: 'exfiltration', severity: 'medium', sanitize: 'match', mention: false,
			title: 'Known request-capture or tunnelling service',
			explain: 'Services such as webhook.site, request bins, ngrok tunnels and out-of-band testing domains collect incoming requests. In untrusted content they often mark the receiving end of a leak.',
			re: rx(String.raw`\b(?:webhook\.site|requestbin\.(?:com|net)|[a-z0-9-]{1,63}\.pipedream\.net|[a-z0-9-]{1,63}\.ngrok(?:-free)?\.(?:io|app|dev)|[a-z0-9-]{1,63}\.burpcollaborator\.net|[a-z0-9-]{1,63}\.oastify\.com|[a-z0-9-]{1,63}\.oast\.(?:pro|live|site|online|fun|me)|[a-z0-9-]{1,63}\.interact\.sh|canarytokens\.com|[a-z0-9-]{1,63}\.beeceptor\.com|hookbin\.com|[a-z0-9-]{1,63}\.requestcatcher\.com)\b`) },
		{ id: 'PI-EXF-006', group: 'exfiltration', severity: 'medium', sanitize: 'match', mention: true,
			title: 'Tool or function call markup',
			explain: 'Markup that imitates how an agent framework represents tool calls can trick an agent into running a tool it was not asked to use.',
			re: rx(String.raw`<\/?(?:tool_call|tool_use|function_call|function_calls|tool_code|tool_request|invoke\s{1,3}name\s{0,2}=|execute_command|run_command)\b`) },
		{ id: 'PI-EXF-007', group: 'exfiltration', severity: 'medium', sanitize: 'sentence', mention: true,
			title: 'Directive to use a tool',
			explain: 'Tells the model to call a specific tool or function. In retrieved content this is an attempt to make an agent act on behalf of the author of the content.',
			re: rx(String.raw`\b(?:you\s{1,3}(?:must|should|need\s{1,3}to|have\s{1,3}to|will)|please|now|immediately|first|then)\s{1,3}(?:call|invoke|use|run|execute|trigger)\s{1,3}(?:the\s{1,3})?[\x60'"]?[A-Za-z][A-Za-z0-9_.-]{1,40}[\x60'"]?\s{1,3}(?:tool|plugin|action)\b|\b(?:AI|assistant|agent|LLM|model)\b[^\n]{0,30}?\b(?:call|invoke|execute|trigger)\s{1,3}(?:the\s{1,3})?[\x60'"]?[A-Za-z][A-Za-z0-9_.-]{1,40}[\x60'"]?\s{1,3}(?:tool|function|plugin|action)\b`) },
		{ id: 'PI-EXF-008', group: 'exfiltration', severity: 'high', sanitize: 'sentence', mention: true,
			title: 'Shell command that reads and sends secrets',
			explain: 'A network command combined with command substitution, secret environment variables or credential files would send local secrets elsewhere if an agent executed it.',
			re: rx(String.raw`\b(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|nc|ncat|netcat)\b[^\n]{0,200}?(?:\$\(|\x60[^\x60\n]{1,80}\x60|\$\{?[A-Z_]{0,30}(?:KEY|TOKEN|SECRET|PASS(?:WORD)?|CRED(?:ENTIAL)?S?)[A-Z_]{0,30}\}?|\/etc\/(?:passwd|shadow)|~\/\.(?:ssh|aws|config|netrc)|\.env\b|\$env:[A-Za-z_]{1,40}|id_rsa|\.git-credentials)`),
			check(m) {
				// An API token passed in an Authorization header is ordinary API documentation.
				if (/Authorization|-u\s|--user\b|-H\s/i.test(m[0]) && !/\$\(|\x60|\/etc\/|~\/\.|id_rsa|\.env\b|\.git-credentials/.test(m[0])) { return null; }
				return this.severity;
			} },
		{ id: 'PI-EXF-009', group: 'exfiltration', severity: 'low', sanitize: 'none', mention: false,
			title: 'Download piped into a shell',
			explain: 'A command that downloads a script and runs it immediately. Common in installation guides, but an agent should never execute it from untrusted content.',
			re: rx(String.raw`\b(?:curl|wget)\b[^\n|]{1,300}\|\s{0,3}(?:sudo\s{1,3})?(?:ba|z|da)?sh\b`) },

		// 7. System prompt and secret extraction
		{ id: 'PI-EXT-001', group: 'extraction', severity: 'high', sanitize: 'sentence', mention: true,
			title: 'Request to reveal the system prompt',
			explain: 'Asks the model to print its hidden instructions. Leaked prompts expose business logic and help attackers tailor further injections.',
			re: rx(String.raw`\b(?:reveal|print|show|output|repeat|display|tell(?:\s{1,3}me)?|give(?:\s{1,3}me)?|leak|dump|disclose|share|write(?:\s{1,3}out)?|list|recite|spell\s{1,3}out|summari[sz]e|translate|paste|what\s{1,3}(?:is|are|was|were))\b${GAP(30)}\b(your|the|its|any)\s{1,3}(?:(?:full|entire|original|initial|hidden|secret|complete|exact|underlying|internal|confidential|first)\s{1,3}){0,2}(?:system\s{0,3}(?:prompt|message|instructions?)|initial\s{1,3}(?:prompt|instructions?)|pre-?prompt|developer\s{1,3}(?:message|instructions?|prompt)|hidden\s{1,3}instructions?|instructions\s{1,3}you\s{1,3}(?:were|have\s{1,3}been)\s{1,3}given)\b`),
			check(m) { return /^(?:your|its)$/i.test(m[1]) ? 'high' : 'low'; } },
		{ id: 'PI-EXT-002', group: 'extraction', severity: 'high', sanitize: 'sentence', mention: true,
			title: 'Request to repeat the text above verbatim',
			explain: 'Asking the model to repeat "everything above" or to start its answer with "You are" is a common way to extract the system prompt that precedes the user input.',
			re: rx(String.raw`\b(?:repeat|print|output|copy|echo|write\s{1,3}out|reproduce)\b[^\n]{0,40}?\b(?:everything|all(?:\s{1,3}(?:of\s{1,3})?(?:the\s{1,3})?(?:text|words|content))?|the\s{1,3}(?:words|text|lines|content|instructions))\s{1,3}(?:above|before\s{1,3}this|preceding|prior\s{1,3}to\s{1,3}this|that\s{1,3}came\s{1,3}before|you\s{1,3}(?:were|have\s{1,3}been)\s{1,3}given)\b|\b(?:verbatim|word\s{1,3}for\s{1,3}word)\b[^\n]{0,40}?\b(?:above|instructions|prompt|system\s{1,3}message)\b|\bstart(?:ing)?\s{1,3}(?:your\s{1,3}(?:answer|response|reply)\s{1,3})?with\s{1,3}["“']You\s{1,3}are\b`) },
		{ id: 'PI-EXT-003', group: 'extraction', severity: 'medium', sanitize: 'sentence', mention: true, negation: true,
			title: 'Request to reveal secrets or credentials',
			explain: 'Asks the model to output keys, passwords, tokens or environment variables it may have access to through tools or its context.',
			re: rx(String.raw`\b(?:reveal|print|show|output|tell(?:\s{1,3}me)?|give(?:\s{1,3}me)?|leak|dump|disclose|share|list|send|display|expose)\b${GAP(30)}\b(your|the|all|any|its)\b${GAP(20)}\b(?:api[ _-]?keys?|passwords?|credentials|secrets?|access[ _-]?tokens?|auth(?:entication)?[ _-]?tokens?|environment[ _-]variables|env[ _-]?vars|\.env(?:\s{1,3}file)?|private[ _-]keys?|ssh[ _-]keys?|session[ _-](?:tokens?|cookies?)|connection[ _-]strings?)\b`),
			check(m, text, end) {
				if (/^(?:your|its)$/i.test(m[1])) { return 'high'; }
				// "... you have access to", "... you know": addressed to the model.
				return /^[^\n.!?]{0,40}?\b\byou\s{1,3}(?:have|can|know|see|store|remember|were\s{1,3}given)\b/i.test(text.slice(end, end + 60)) ? 'medium' : 'low';
			} },
		{ id: 'PI-EXT-010', group: 'extraction', severity: 'high', sanitize: 'sentence', mention: true, negation: true,
			title: 'Request to reveal the system prompt or secrets (German)',
			explain: 'German phrasing of a request to show the system prompt, instructions, passwords or keys.',
			re: rx(String.raw`${L}(?:zeig(?:e|en)?|gib|nenne|verrate|wiederhole|drucke|schreib(?:e)?|teile|offenbare|gib\s{1,3}mir)${R}${GAP(30)}${L}(?:deinen?|deine|deines|ihren?|ihre|den|die|alle)\s{1,3}(?:(?:vollständigen?|ursprünglichen?|geheimen?|versteckten?|internen?|genauen?)\s{1,3})?(?:System-?\s?prompt|Systemanweisungen?|System-?Nachricht|Anweisungen|Passw(?:ö|oe)rter|Passwort|API-?Schlüssel|Zugangsdaten|Geheimnisse|Umgebungsvariablen)${R}`) },
		{ id: 'PI-EXT-020', group: 'extraction', severity: 'high', sanitize: 'sentence', mention: true, negation: true,
			title: 'Request to reveal the system prompt or secrets (Russian)',
			explain: 'Russian phrasing of a request to show the system prompt, instructions, passwords or keys.',
			re: rx(String.raw`${L}(?:покажи|выведи|раскрой|повтори|напиши|сообщи|дай|назови|перечисли|распечатай|скажи|выдай|отправь)(?:те)?${R}${GAP(30)}(?:(сво[йиюеё]\p{L}*|тво[йиюеё]\p{L}*|ваш\p{L}*|все|весь|мне)\s{1,3})?(?:(?:полн\p{L}*|исходн\p{L}*|скрыт\p{L}*|секретн\p{L}*|внутренн\p{L}*|точн\p{L}*)\s{1,3})?(системн\p{L}*\s{1,3}(?:промпт\p{L}*|инструкци\p{L}*|подсказк\p{L}*|сообщени\p{L}*)|инструкци\p{L}*|парол\p{L}*|API[- ]?ключ\p{L}*|ключ\p{L}*\s{1,3}(?:API|доступа)|уч[её]тн\p{L}*\s{1,3}данн\p{L}*|токен\p{L}*|секрет\p{L}*|переменн\p{L}*\s{1,3}окружения)`),
			check(m) { return m[1] || /^системн/i.test(m[2]) ? 'high' : 'low'; } },

		// 5. Encoded payloads (instruction to decode and act)
		{ id: 'PI-ENC-002', group: 'encoded', severity: 'high', sanitize: 'sentence', mention: true,
			title: 'Instruction to decode and follow hidden content',
			explain: 'Asks the model to decode, decrypt or reverse a string and then act on it. Encoding is used to get instructions past filters and human reviewers.',
			re: rx(String.raw`${L}(?:decode|base64[- ]?decode|decipher|decrypt|unscramble|reverse|rot-?13|deobfuscate|dekodiere|entschlüssele|декодируй|расшифруй|переверни)(?:те)?${R}[^\n]{0,60}?${L}(?:and|then|und|dann|и|затем|потом)\s{1,3}(?:follow|execute|run|obey|do|perform|carry\s{1,3}out|act\s{1,3}on|apply|befolge|führe|выполни|следуй|сделай)${R}`) }
	];
	const RULES_BY_ID = {};
	for (const rule of TEXT_RULES) { RULES_BY_ID[rule.id] = rule; }

	/** Rules evaluated by dedicated detectors (metadata for explanations and the rule list). */
	const DETECTOR_RULES = [
		{ id: 'PI-HID-001', group: 'hidden', severity: 'medium', sanitize: 'none', title: 'Zero-width characters', explain: 'Zero-width characters are invisible to readers but visible to a model. They can split keywords so filters miss them or carry hidden data. Isolated ones outside words get low severity.' },
		{ id: 'PI-HID-002', group: 'hidden', severity: 'high', sanitize: 'none', title: 'Long run of invisible characters', explain: 'Eight or more consecutive invisible characters are typical of zero-width steganography: hidden data encoded as invisible characters.' },
		{ id: 'PI-HID-003', group: 'hidden', severity: 'high', sanitize: 'none', title: 'Unicode tag characters (hidden ASCII text)', explain: 'Characters from the Unicode Tags block are not displayed but many models read them as ordinary letters. They can smuggle an entire invisible instruction.' },
		{ id: 'PI-HID-004', group: 'hidden', severity: 'medium', sanitize: 'none', title: 'Bidirectional control characters', explain: 'Bidi overrides and isolates can make text display in a different order than a model reads it. Severity is low in lines that contain right-to-left script.' },
		{ id: 'PI-HID-005', group: 'hidden', severity: 'high', sanitize: 'none', title: 'Variation selectors used to hide data', explain: 'Variation selectors that do not follow an emoji, or long sequences of them, can encode hidden bytes ("emoji smuggling").' },
		{ id: 'PI-HID-006', group: 'hidden', severity: 'medium', sanitize: 'match', title: 'HTML or Markdown comment with instructions', explain: 'Comments are not rendered, so a human reviewer does not see them, but a model reading the page source does. Comments are reported when they address an AI system or contain an injection pattern.' },
		{ id: 'PI-HID-007', group: 'hidden', severity: 'low', sanitize: 'match', title: 'Text hidden with HTML or CSS', explain: 'Elements with display:none, zero font size, zero opacity, white or transparent color, off-screen positioning or the hidden attribute are invisible on the page but present in the text a model receives. Severity rises when the hidden text addresses an AI or contains an injection pattern.' },
		{ id: 'PI-ENC-001', group: 'encoded', severity: 'high', sanitize: 'match', title: 'Injection pattern inside encoded text', explain: 'A Base64, hex, URL-encoded or escaped fragment decodes to text that matches an injection rule. Models can decode such fragments themselves, while people and filters usually do not.' },
		{ id: 'PI-OBF-001', group: 'obfuscation', severity: 'medium', sanitize: 'none', title: 'Mixed-script word (possible homoglyphs)', explain: 'A word mixes Latin letters with look-alike Cyrillic or Greek letters. This defeats keyword filters while looking normal to a reader.' },
		{ id: 'PI-OBF-002', group: 'obfuscation', severity: 'high', sanitize: 'sentence', title: 'Obfuscated injection phrase', explain: 'After replacing look-alike letters, digits used as letters (leetspeak) or spaced-out letters, the text matches an injection rule that the plain text did not match.' },
		{ id: 'PI-OBF-003', group: 'obfuscation', severity: 'medium', sanitize: 'none', title: 'Spaced-out keyword', explain: 'A sensitive keyword is written with spaces or punctuation between the letters, a common trick to bypass keyword filters.' },
		{ id: 'PI-OBF-004', group: 'obfuscation', severity: 'high', sanitize: 'none', title: 'Injection phrase disguised with special characters', explain: 'An injection phrase was only recognized after removing invisible characters or normalizing styled, fullwidth or compatibility letters (Unicode NFKC).' }
	];
	for (const rule of DETECTOR_RULES) { RULES_BY_ID[rule.id] = rule; }
	const ALL_RULES = TEXT_RULES.concat(DETECTOR_RULES);

	/** Apply all text rules to a string. Returns raw hits with offsets relative to text. */
	function scanText(text, base, hits, rules) {
		for (const rule of rules || TEXT_RULES) {
			const re = rule.re;
			re.lastIndex = 0;
			let m;
			let count = 0;
			while ((m = re.exec(text)) !== null) {
				if (m[0].length === 0) { re.lastIndex++; continue; }
				let severity = rule.severity;
				if (rule.check) {
					severity = rule.check(m, text, m.index + m[0].length);
					if (!severity) { continue; }
				}
				const start = m.index;
				const end = start + m[0].length;
				if (rule.negation && isNegated(text, start)) { continue; }
				let mentioned = false;
				if (rule.mention && isMention(text, start, end)) { mentioned = true; severity = 'low'; }
				hits.push({ ruleId: rule.id, start: base + start, end: base + end, severity, mentioned, baseSeverity: rule.check ? severity : rule.severity, text: m[0] });
				if (++count > MAX_PER_RULE * 4) { break; }
			}
		}
		return hits;
	}

	// ---------------------------------------------------------------- decoding

	// A preceding "=" is a key=value separator, not padding, so it may start a candidate.
	const B64_RE = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])/g;
	const HEX_RE = /(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])/g;
	const HEX_ESC_RE = /(?:\\x[0-9A-Fa-f]{2}){4,}/g;
	const HEX_SPACED_RE = /(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}[ :]){5,}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])/g;
	const URL_TOKEN_RE = /[^\s<>"'`]{6,}/g;
	const ESCAPE_RE = /&#(?:\d{2,7}|[xX][0-9A-Fa-f]{1,6});|\\u[0-9A-Fa-f]{4}|\\u\{[0-9A-Fa-f]{1,6}\}|&(?:lt|gt|amp|quot|apos|nbsp);/g;
	const PRINTABLE_RE = /[\p{L}\p{N}\p{P}\p{S}\p{Zs}\t\n\r]/u;

	let utf8 = null;
	function utf8Decode(bytes) {
		if (!utf8) { utf8 = new TextDecoder('utf-8', { fatal: true }); }
		try { return utf8.decode(bytes); } catch (e) { return null; }
	}

	function readable(s) {
		if (!s || s.length < 6) { return false; }
		let printable = 0;
		let letters = 0;
		let spaces = 0;
		const sample = s.length > 4000 ? s.slice(0, 4000) : s;
		for (const ch of sample) {
			if (PRINTABLE_RE.test(ch)) { printable++; }
			if (/\p{L}/u.test(ch)) { letters++; }
			if (ch === ' ' || ch === '\n') { spaces++; }
		}
		const len = Array.from(sample).length;
		return printable / len >= 0.95 && letters / len >= 0.5 && (spaces > 0 || len <= 24);
	}

	/** A decoded layer that is itself Base64 or hex (multi-layer encoding). */
	function isEncodedLayer(d) {
		return !!d && d.length >= 16 && d.length <= MAX_CANDIDATE_CHARS && (/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(d) || /^(?:[0-9A-Fa-f]{2}){8,}$/.test(d));
	}

	function decodeBase64(s) {
		let t = s.replace(/=+$/, '');
		if (/[-_]/.test(t)) {
			if (/[+/]/.test(t)) { return null; }
			t = t.replace(/-/g, '+').replace(/_/g, '/');
		}
		if (t.length % 4 === 1) { return null; }
		while (t.length % 4) { t += '='; }
		let bin;
		try { bin = atob(t); } catch (e) { return null; }
		const bytes = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }
		return utf8Decode(bytes);
	}

	function decodeHex(s) {
		const digits = s.replace(/\\x|[ :]/g, '');
		if (digits.length % 2) { return null; }
		const bytes = new Uint8Array(digits.length / 2);
		for (let i = 0; i < bytes.length; i++) { bytes[i] = parseInt(digits.substr(i * 2, 2), 16); }
		return utf8Decode(bytes);
	}

	function decodeUrl(s) {
		return s.replace(/(?:%[0-9A-Fa-f]{2})+/g, seq => {
			try { return decodeURIComponent(seq); } catch (e) { return seq; }
		});
	}

	const NAMED_ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: '\'', nbsp: ' ' };
	function decodeEscapes(s) {
		return s.replace(ESCAPE_RE, e => {
			let cp;
			if (e[0] === '&' && e[1] !== '#') { return NAMED_ENTITIES[e.slice(1, -1)]; }
			if (e[0] === '&') { cp = e[2] === 'x' || e[2] === 'X' ? parseInt(e.slice(3, -1), 16) : parseInt(e.slice(2, -1), 10); }
			else if (e[2] === '{') { cp = parseInt(e.slice(3, -1), 16); }
			else { cp = parseInt(e.slice(2), 16); }
			return cp > 0 && cp <= 0x10FFFF ? String.fromCodePoint(cp) : e;
		});
	}

	/** Find encoded fragments in a string. Offsets are relative to the string. */
	function findEncoded(text, budget) {
		const found = [];
		const add = (start, end, encoding, decoded) => {
			if (budget.candidates++ > MAX_DECODE_CANDIDATES || budget.chars > MAX_DECODED_CHARS) { return; }
			if (!decoded) { return; }
			budget.chars += decoded.length;
			found.push({ start, end, encoding, decoded });
		};
		let m;
		const seen = new Set();
		HEX_RE.lastIndex = 0;
		while ((m = HEX_RE.exec(text)) !== null) {
			if (m[0].length > MAX_CANDIDATE_CHARS) { continue; }
			const d = decodeHex(m[0]);
			if (readable(d) || isEncodedLayer(d)) { add(m.index, m.index + m[0].length, 'hex', d); seen.add(m.index); }
		}
		for (const re of [HEX_ESC_RE, HEX_SPACED_RE]) {
			re.lastIndex = 0;
			while ((m = re.exec(text)) !== null) {
				const d = decodeHex(m[0]);
				if (readable(d)) { add(m.index, m.index + m[0].length, 'hex', d); }
			}
		}
		B64_RE.lastIndex = 0;
		while ((m = B64_RE.exec(text)) !== null) {
			if (seen.has(m.index) || m[0].length > MAX_CANDIDATE_CHARS) { continue; }
			if (!/[0-9+/=_-]|[a-z][A-Z]|[A-Z][a-z]{0,2}[A-Z]/.test(m[0])) { continue; }
			const d = decodeBase64(m[0]);
			if (readable(d) || isEncodedLayer(d)) { add(m.index, m.index + m[0].length, /[-_]/.test(m[0]) ? 'base64url' : 'base64', d); }
		}
		URL_TOKEN_RE.lastIndex = 0;
		while ((m = URL_TOKEN_RE.exec(text)) !== null) {
			const tok = m[0];
			if (tok.indexOf('%') === -1 || tok.length > MAX_CANDIDATE_CHARS) { continue; }
			const escapes = tok.match(/%[0-9A-Fa-f]{2}/g);
			if (!escapes || escapes.length < 3) { continue; }
			const d = decodeUrl(tok);
			if (d !== tok && /\p{L}/u.test(d)) { add(m.index, m.index + tok.length, 'url', d); }
		}
		// HTML entities and \u escapes: decode per line when a line has three or more.
		ESCAPE_RE.lastIndex = 0;
		let lineStart = -1;
		let lineEnd = -1;
		let first = -1;
		let last = -1;
		let numeric = 0;
		const flush = () => {
			if (numeric >= 3) {
				const seg = text.slice(first, last);
				const d = decodeEscapes(seg);
				if (d !== seg) { add(first, last, 'escapes', d); }
			}
			numeric = 0;
		};
		while ((m = ESCAPE_RE.exec(text)) !== null) {
			if (m.index >= lineEnd) {
				flush();
				lineStart = text.lastIndexOf('\n', m.index - 1) + 1;
				lineEnd = text.indexOf('\n', m.index);
				if (lineEnd < 0) { lineEnd = text.length; }
				first = m.index;
			}
			last = m.index + m[0].length;
			if (m[0][1] === '#' || m[0][0] === '\\') { numeric++; }
		}
		flush();
		return found;
	}

	/**
	 * Decode a fragment recursively and collect rule hits from every layer.
	 * Returns { hits: [{ruleId, severity}], layers: [{encoding, decoded}] }.
	 */
	function analyzeDecoded(decoded, depth, budget) {
		const norm = quickNormalize(decoded);
		const hits = scanText(norm, 0, []);
		const nested = [];
		if (depth < MAX_DECODE_DEPTH) {
			for (const c of findEncoded(norm, budget)) {
				const inner = analyzeDecoded(c.decoded, depth + 1, budget);
				nested.push({ encoding: c.encoding, decoded: c.decoded, inner });
				for (const h of inner.hits) { hits.push(h); }
			}
		}
		return { hits, nested };
	}

	// ---------------------------------------------------------------- hidden content in markup

	const HIDE_STYLE_RE = /display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|!|["']|$)|(?:^|[;\s"'])opacity\s*:\s*0(?:\.0+)?\s*(?:;|!|["']|$)|(?:^|[;\s"'])color\s*:\s*(?:#f{3}(?:f{3})?\b|white\b|transparent\b|rgba\([^)]{0,40},\s*0(?:\.0+)?\s*\))|(?:left|top|right|text-indent|margin-left)\s*:\s*-\d{4,}|clip\s*:\s*rect\(\s*0|clip-path\s*:\s*inset\(\s*(?:50|100)%|max-height\s*:\s*0(?:px)?\s*(?:;|["'])|(?:^|\s)hidden(?=[\s=/]|$)/i;
	const OPEN_TAG_RE = /<([a-zA-Z][a-zA-Z0-9-]{0,20})(\s[^<>]{1,1000})>/g;
	const VOID_TAGS = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
	const AI_ADDRESS_CS_RE = /\b(?:AI|A\.I\.|LLM|GPT|ChatGPT|Claude|Copilot|Gemini|Llama|KI)\b/u;
	const AI_ADDRESS_CI_RE = /\b(?:assistant|language model|chatbot|ai agent|ai model)s?\b|(?<![\p{L}])(?:Sprachmodell|Assistent|ИИ|нейросет\p{L}*|ассистент\p{L}*|языков\p{L}*\s+модел\p{L}*)(?![\p{L}])/iu;
	const addressesAI = s => AI_ADDRESS_CS_RE.test(s) || AI_ADDRESS_CI_RE.test(s);

	function stripTags(s) {
		return s.replace(/<[^<>]{0,1000}>/g, ' ').replace(/\s+/g, ' ').trim();
	}

	/** HTML comments, Markdown comments and CSS-hidden elements (normalized offsets). */
	function findHiddenMarkup(text, emit) {
		let p = 0;
		while (p < text.length) {
			const open = text.indexOf('<!--', p);
			if (open < 0) { break; }
			const close = text.indexOf('-->', open + 4);
			if (close < 0) { break; }
			if (close - open <= 20000) {
				emit({ kind: 'comment', start: open, end: close + 3, inner: text.slice(open + 4, close) });
			}
			p = close + 3;
		}
		const md = /^[ \t]{0,3}\[(?:\/\/|comment|_|#|\s)\]:\s{0,3}(?:#|<>)\s{0,3}(?:\(([^\n]{0,2000})\)|"([^\n]{0,2000})")/gm;
		let m;
		while ((m = md.exec(text)) !== null) {
			emit({ kind: 'comment', start: m.index, end: m.index + m[0].length, inner: m[1] || m[2] || '' });
		}
		if (text.indexOf('<') === -1) { return; }
		OPEN_TAG_RE.lastIndex = 0;
		while ((m = OPEN_TAG_RE.exec(text)) !== null) {
			const tag = m[1].toLowerCase();
			if (VOID_TAGS.has(tag) || !HIDE_STYLE_RE.test(m[2])) { continue; }
			if (/aria-hidden|\bclass\s*=\s*["'][^"']*\b(?:sr-only|visually-hidden|screen-reader)/i.test(m[2]) && !/display\s*:\s*none|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:/i.test(m[2])) { continue; }
			const bodyStart = m.index + m[0].length;
			const windowText = text.slice(bodyStart, bodyStart + 20000);
			const closeRe = new RegExp('</' + tag + '\\s*>', 'i');
			const ci = windowText.search(closeRe);
			if (ci < 0) { continue; }
			const closeLen = windowText.slice(ci).match(closeRe)[0].length;
			emit({ kind: 'element', start: m.index, end: bodyStart + ci + closeLen, inner: stripTags(windowText.slice(0, ci)), style: clip(m[2].trim(), 160) });
		}
	}

	// ---------------------------------------------------------------- obfuscation

	const CONFUSABLES = {
		'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ї': 'i', 'ј': 'j', 'ԁ': 'd', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w', 'ѵ': 'v', 'ɡ': 'g', 'һ': 'h', 'ү': 'y', 'ⅰ': 'i',
		'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'У': 'Y', 'І': 'I', 'Ј': 'J', 'Ѕ': 'S', 'Ԁ': 'D', 'Ԛ': 'Q', 'Ԝ': 'W', 'Һ': 'H',
		'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'τ': 't', 'υ': 'u', 'χ': 'x', 'γ': 'y', 'ω': 'w',
		'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X'
	};
	const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i', '|': 'l' };
	const MIXED_CANDIDATE_RE = /[Ͱ-ϿЀ-ӿԀ-ԯ]/;
	const WORD_RE = /[\p{L}\p{M}]{2,}/gu;
	// Tokens of letters, digits and leet symbols; filtered in code (lookaheads here were slow on long texts).
	const LEET_TOKEN_RE = /[\p{L}\p{N}@$!|]{3,}/gu;
	const LEET_CHAR_RE = /[013457@$!|]/;
	const HAS_LETTER_RE = /\p{L}/u;
	const isLeetToken = t => t.length <= 40 && LEET_CHAR_RE.test(t) && HAS_LETTER_RE.test(t);
	const LEET_EXCLUDE_RE = /^(?:v?\d+(?:[._]\d+)*[a-z]{0,2}|[a-f0-9]+|\d+(?:st|nd|rd|th|px|pt|em|ms|kb|mb|gb|tb|k|m|x|d|h|s|g)|[a-z]{1,4}\d{1,4}|x86_64|ipv[46]|utf-?(?:8|16|32)|h26[45]|mp[34]|web3)$/i;
	const SPACED_RE = /(?<![\p{L}\p{N}])\p{L}(?:[ .\-_*·•|,'+~]{1,3}\p{L}(?![\p{L}\p{N}])){4,}/gu;
	const SPACED_KEYWORDS = new Set(['ignore', 'instructions', 'instruction', 'system', 'prompt', 'password', 'jailbreak', 'override', 'disregard', 'forget', 'reveal', 'secret', 'secrets', 'previous', 'ignoriere', 'anweisungen', 'игнорируй', 'инструкции', 'пароль', 'промпт', 'systemprompt']);
	const LATIN_RE = /\p{Script=Latin}/u;
	const CYRILLIC_RE = /\p{Script=Cyrillic}/u;
	const GREEK_RE = /[\p{Script=Greek}]/u;
	const GREEK_UNITS_RE = /^[^\p{Script=Greek}]*[μΩπλΔσθ][^\p{Script=Greek}]*$/u;

	function mixedScript(word) {
		if (!LATIN_RE.test(word)) { return null; }
		const cyr = CYRILLIC_RE.test(word);
		const greek = GREEK_RE.test(word) && !GREEK_UNITS_RE.test(word);
		if (!cyr && !greek) { return null; }
		const foreign = [];
		for (const ch of word) {
			if ((cyr && CYRILLIC_RE.test(ch)) || (greek && GREEK_RE.test(ch))) { foreign.push(ch); }
		}
		return { script: cyr ? 'Cyrillic' : 'Greek', foreign };
	}

	/**
	 * Transform one line: confusables in mixed words to Latin, leetspeak tokens to
	 * letters, spaced-out letters collapsed. Returns null when nothing changed.
	 * idx[i] is the offset in the line of transformed character i.
	 */
	function deobfuscateLine(line) {
		// Own regex instances: the caller iterates the shared global ones (lastIndex must not be reset).
		const wordRe = new RegExp(WORD_RE.source, WORD_RE.flags);
		const leetRe = new RegExp(LEET_TOKEN_RE.source, LEET_TOKEN_RE.flags);
		const spacedRe = new RegExp(SPACED_RE.source, SPACED_RE.flags);
		const chars = Array.from(line);
		const offsets = [];
		let o = 0;
		for (const ch of chars) { offsets.push(o); o += ch.length; }
		const offsetIndex = new Map(offsets.map((v, i) => [v, i]));
		const out = chars.slice();
		const drop = new Uint8Array(chars.length);
		const space = new Uint8Array(chars.length);
		let changed = false;
		let m;
		wordRe.lastIndex = 0;
		while ((m = wordRe.exec(line)) !== null) {
			if (!mixedScript(m[0])) { continue; }
			let i = offsetIndex.get(m.index);
			for (const ch of m[0]) { if (CONFUSABLES[ch]) { out[i] = CONFUSABLES[ch]; changed = true; } i++; }
		}
		leetRe.lastIndex = 0;
		while ((m = leetRe.exec(line)) !== null) {
			if (!isLeetToken(m[0])) { continue; }
			const letters = (m[0].match(/\p{L}/gu) || []).length;
			if (letters < 2 || /^[a-f0-9]+$/i.test(m[0])) { continue; }
			let i = offsetIndex.get(m.index);
			for (const ch of m[0]) { if (LEET[ch]) { out[i] = LEET[ch]; changed = true; } i++; }
		}
		spacedRe.lastIndex = 0;
		while ((m = spacedRe.exec(line)) !== null) {
			let i = offsetIndex.get(m.index);
			const end = m.index + m[0].length;
			let gap = [];
			for (; i < chars.length && offsets[i] < end; i++) {
				if (/\p{L}/u.test(chars[i])) {
					if (gap.length) {
						const wide = gap.length >= 2 && gap.every(g => chars[g] === ' ');
						for (const g of gap) { drop[g] = 1; }
						if (wide) { drop[gap[0]] = 0; space[gap[0]] = 1; }
						changed = true;
					}
					gap = [];
				} else {
					gap.push(i);
				}
			}
		}
		if (!changed) { return null; }
		let text = '';
		const idx = [];
		for (let i = 0; i < out.length; i++) {
			if (drop[i]) { continue; }
			const piece = space[i] ? ' ' : out[i];
			for (let k = 0; k < piece.length; k++) { idx.push(offsets[i]); }
			text += piece;
		}
		idx.push(line.length);
		return { text, idx };
	}

	// ---------------------------------------------------------------- analysis

	function makeLineIndex(text) {
		const starts = [0];
		let p = -1;
		while ((p = text.indexOf('\n', p + 1)) !== -1) { starts.push(p + 1); }
		return function (offset) {
			let lo = 0;
			let hi = starts.length - 1;
			while (lo < hi) {
				const mid = (lo + hi + 1) >> 1;
				if (starts[mid] <= offset) { lo = mid; } else { hi = mid - 1; }
			}
			return { line: lo + 1, column: offset - starts[lo] + 1, lineCount: starts.length };
		};
	}

	function excerpt(text, start, end) {
		const [ls, le] = lineBounds(text, start, Math.max(start, end - 1));
		const before = text.slice(Math.max(ls, start - 60), start);
		const match = text.slice(start, end);
		const after = text.slice(end, Math.min(le, end + 60));
		return {
			before: (start - 60 > ls ? '…' : '') + visible(before).replace(/\t/g, ' '),
			match: clip(visible(match), 300),
			after: visible(after).replace(/\r$/, '').replace(/\t/g, ' ') + (end + 60 < le ? '…' : '')
		};
	}

	function describeInvisible(run) {
		const names = { zeroWidth: 'zero-width', bidi: 'bidi control', tag: 'tag', variation: 'variation selector', softHyphen: 'soft hyphen' };
		return Object.keys(run.kinds).map(k => run.kinds[k] + ' ' + names[k] + (run.kinds[k] === 1 ? ' character' : ' characters')).join(', ');
	}

	function decodeTags(cps) {
		let s = '';
		for (const cp of cps) {
			if (cp >= 0xE0020 && cp <= 0xE007E) { s += String.fromCharCode(cp - 0xE0000); }
		}
		return s;
	}

	function decodeVariationSelectors(cps) {
		const bytes = [];
		for (const cp of cps) {
			if (cp >= 0xFE00 && cp <= 0xFE0F) { bytes.push(cp - 0xFE00); }
			else if (cp >= 0xE0100 && cp <= 0xE01EF) { bytes.push(cp - 0xE0100 + 16); }
		}
		return bytes.length ? utf8Decode(new Uint8Array(bytes)) : null;
	}

	/**
	 * Analyze text. Options: normalizeNFKC, removeInvisible, neutralize ('high' |
	 * 'medium' | 'low' | 'none'), previewChars. hooks.onProgress(done, total).
	 */
	function analyze(input, options, hooks) {
		const text = String(input == null ? '' : input);
		if (text.length > MAX_INPUT_CHARS) {
			const err = new Error('The text is larger than 20 MB. Split it into smaller parts.');
			err.code = 'TOO_LARGE';
			throw err;
		}
		const opts = Object.assign(defaultOptions(), options || {});
		const onProgress = hooks && typeof hooks.onProgress === 'function' ? hooks.onProgress : null;
		const total = text.length * 2 + 1;
		const progress = done => { if (onProgress) { onProgress(Math.min(done, total), total); } };

		// 1. Normalization
		const runs = scanInvisible(text);
		const norm = normalize(text, runs);
		const ntext = norm.text;
		progress(Math.round(text.length * 0.1));

		// 2. Text rules on the normalized text, chunked at line breaks
		const hits = [];
		for (let pos = 0; pos < ntext.length;) {
			let end = Math.min(ntext.length, pos + CHUNK_CHARS);
			if (end < ntext.length) {
				const nl = ntext.indexOf('\n', end);
				end = nl === -1 ? ntext.length : nl + 1;
			}
			scanText(ntext.slice(pos, end), pos, hits);
			pos = end;
			progress(Math.round(text.length * 0.1 + (pos / Math.max(1, ntext.length)) * text.length * 0.9));
		}

		const raw = []; // { ruleId, severity, nStart, nEnd } or { ruleId, severity, oStart, oEnd }
		for (const h of hits) { raw.push({ ruleId: h.ruleId, severity: h.severity, mentioned: h.mentioned, nStart: h.start, nEnd: h.end, layer: 'text', matched: h.text }); }

		// 3. Encoded fragments
		const budget = { candidates: 0, chars: 0 };
		const decodedList = [];
		const encoded = findEncoded(ntext, budget);
		let decodedCount = 0;
		for (const c of encoded) {
			const result = analyzeDecoded(c.decoded, 1, budget);
			decodedCount++;
			const chain = [c.encoding];
			let deepest = c.decoded;
			for (let layer = result.nested[0]; layer; layer = layer.inner.nested[0]) { chain.push(layer.encoding); deepest = layer.decoded; }
			if (decodedList.length < MAX_DECODED_LISTED) {
				decodedList.push({ nStart: c.start, nEnd: c.end, chain, preview: clip(visible(deepest.replace(/\s+/g, ' ').trim()), 200), flagged: result.hits.length > 0 });
			}
			if (result.hits.length) {
				let sev = 'medium';
				const ids = [];
				for (const h of result.hits) {
					sev = maxSeverity(sev, h.mentioned ? 'medium' : h.severity);
					if (ids.indexOf(h.ruleId) === -1) { ids.push(h.ruleId); }
				}
				raw.push({ ruleId: 'PI-ENC-001', severity: sev, nStart: c.start, nEnd: c.end, layer: 'decoded', inner: ids,
					detail: 'Decoded (' + chain.join(' → ') + '): “' + clip(visible(deepest.replace(/\s+/g, ' ').trim()), 160) + '”. Matches ' + ids.map(id => id + ' (' + RULES_BY_ID[id].title + ')').join(', ') + '.' });
			}
		}
		progress(Math.round(text.length * 1.3));

		// 4. Hidden text: invisible characters (original offsets)
		for (const run of runs) {
			if (run.legit) { continue; }
			const desc = describeInvisible(run);
			if (run.kinds.tag) {
				const hidden = decodeTags(run.cps);
				const inner = hidden ? scanText(quickNormalize(hidden), 0, []) : [];
				const ids = Array.from(new Set(inner.map(h => h.ruleId)));
				raw.push({ ruleId: 'PI-HID-003', severity: 'high', oStart: run.start, oEnd: run.end, layer: 'hidden', inner: ids,
					detail: desc + '. Hidden text reads: “' + clip(hidden, 200) + '”' + (ids.length ? '. Matches ' + ids.join(', ') + '.' : '.') });
			}
			if (run.kinds.variation && run.kinds.variation >= 2) {
				const hidden = decodeVariationSelectors(run.cps);
				const ok = hidden && readable(hidden);
				raw.push({ ruleId: 'PI-HID-005', severity: 'high', oStart: run.start, oEnd: run.end, layer: 'hidden',
					detail: desc + (ok ? '. Decoded as bytes: “' + clip(hidden, 200) + '”.' : '.') });
			} else if (run.kinds.variation && !run.kinds.tag) {
				raw.push({ ruleId: 'PI-HID-005', severity: 'low', oStart: run.start, oEnd: run.end, layer: 'hidden', detail: desc + ' not attached to an emoji.' });
			}
			const zw = (run.kinds.zeroWidth || 0) + (run.kinds.softHyphen || 0);
			if (run.cps.length >= 8 && !run.kinds.tag && !(run.kinds.variation >= 2)) {
				raw.push({ ruleId: 'PI-HID-002', severity: 'high', oStart: run.start, oEnd: run.end, layer: 'hidden', detail: run.cps.length + ' consecutive invisible characters (' + desc + ').' });
			} else if (run.kinds.zeroWidth) {
				const inWord = run.prevIsLetter && run.nextIsLetter;
				raw.push({ ruleId: 'PI-HID-001', severity: inWord ? 'medium' : 'low', oStart: run.start, oEnd: run.end, layer: 'hidden', detail: zw + ' zero-width character' + (zw === 1 ? '' : 's') + (inWord ? ' inside a word.' : '.') });
			}
			if (run.kinds.bidi) {
				const rtl = RTL_RE.test(lineAround(text, run.start));
				raw.push({ ruleId: 'PI-HID-004', severity: rtl ? 'low' : 'medium', oStart: run.start, oEnd: run.end, layer: 'hidden', detail: desc + (rtl ? ' in a line with right-to-left script.' : ' in a line without right-to-left script.') });
			}
		}

		// 5. Hidden markup (normalized offsets) — severity from rules matching inside
		const textHits = raw.filter(h => h.layer === 'text');
		const sortedText = textHits.slice().sort((a, b) => a.nStart - b.nStart);
		const hitsWithin = (s, e) => {
			const out = [];
			let lo = 0;
			let hi = sortedText.length;
			while (lo < hi) { const mid = (lo + hi) >> 1; if (sortedText[mid].nStart < s) { lo = mid + 1; } else { hi = mid; } }
			for (let i = lo; i < sortedText.length && sortedText[i].nStart < e; i++) { if (sortedText[i].nEnd <= e) { out.push(sortedText[i]); } }
			return out;
		};
		findHiddenMarkup(ntext, item => {
			const inside = hitsWithin(item.start, item.end);
			const strong = inside.filter(h => RANK[RULES_BY_ID[h.ruleId].severity] >= RANK.medium);
			const ai = addressesAI(item.inner);
			let severity = null;
			if (strong.length) { severity = 'high'; }
			else if (ai) { severity = 'medium'; }
			else if (item.kind === 'element' && item.inner.replace(/[^\p{L}]/gu, '').length >= 20) { severity = 'low'; }
			if (!severity) { return; }
			const ids = Array.from(new Set(strong.map(h => h.ruleId)));
			raw.push({ ruleId: item.kind === 'comment' ? 'PI-HID-006' : 'PI-HID-007', severity, nStart: item.start, nEnd: item.end, layer: 'hidden', inner: ids,
				detail: (item.kind === 'comment' ? 'Comment text: “' : 'Hidden by “' + item.style + '”. Text: “') + clip(visible(item.inner.replace(/\s+/g, ' ').trim()), 160) + '”' + (ids.length ? '. Contains ' + ids.join(', ') + '.' : ai ? '. Addresses an AI system.' : '.') });
		});

		// 6. Obfuscation
		const lineCache = new Map();
		const plainHitsOnLine = (ls, le) => hitsWithin(ls, le);
		const rescanned = new Set();
		const rescan = (ls, le) => {
			if (rescanned.has(ls) || le - ls > RESCAN_LINE_CHARS) { return; }
			rescanned.add(ls);
			const line = ntext.slice(ls, le);
			const t = deobfuscateLine(line);
			if (!t) { return; }
			const transformed = scanText(t.text, 0, []);
			if (!transformed.length) {
				return;
			}
			const plain = plainHitsOnLine(ls, le);
			for (const h of transformed) {
				const s = ls + t.idx[h.start];
				const e = ls + t.idx[Math.max(h.start, h.end - 1)] + 1;
				if (plain.some(p => p.ruleId === h.ruleId && p.nStart < e && p.nEnd > s)) { continue; }
				raw.push({ ruleId: 'PI-OBF-002', severity: h.mentioned ? 'low' : maxSeverity('medium', h.severity), nStart: s, nEnd: Math.max(e, s + 1), layer: 'normalized', inner: [h.ruleId],
					detail: 'Reads as “' + clip(h.text, 160) + '” and then matches ' + h.ruleId + ' (' + RULES_BY_ID[h.ruleId].title + ').' });
			}
		};
		let cachedLine = [0, -1];
		const lineOf = i => {
			// Cached: many candidates on one long line must not rescan it each time (quadratic).
			if (i >= cachedLine[0] && i <= cachedLine[1]) { return cachedLine; }
			const ls = ntext.lastIndexOf('\n', i - 1) + 1;
			let le = ntext.indexOf('\n', i);
			if (le < 0) { le = ntext.length; }
			cachedLine = [ls, le];
			return cachedLine;
		};
		for (let pos = 0; pos < ntext.length; pos += CHUNK_CHARS) {
			const chunk = ntext.slice(pos, pos + CHUNK_CHARS);
			let m;
			if (MIXED_CANDIDATE_RE.test(chunk) && /[A-Za-z]/.test(chunk)) {
				WORD_RE.lastIndex = 0;
				let group = null;
				const flushGroup = () => {
					if (!group) { return; }
					raw.push({ ruleId: 'PI-OBF-001', severity: 'medium', nStart: group.s, nEnd: group.e, layer: 'normalized',
						detail: group.words + ' word' + (group.words === 1 ? '' : 's') + ' mixing Latin with ' + group.script + ' letters: ' + Array.from(new Set(group.foreign)).slice(0, 12).map(ch => ch + ' (' + hex(ch.codePointAt(0)) + ')').join(', ') + '.' });
					group = null;
				};
				while ((m = WORD_RE.exec(chunk)) !== null) {
					const info = mixedScript(m[0]);
					if (!info) { continue; }
					const s = pos + m.index;
					const e = s + m[0].length;
					if (group && s - group.e < 40 && ntext.slice(group.e, s).indexOf('\n') === -1) {
						group.e = e; group.words++; group.foreign.push(...info.foreign);
					} else {
						flushGroup();
						group = { s, e, words: 1, foreign: info.foreign.slice(), script: info.script };
					}
					const [ls, le] = lineOf(s);
					rescan(ls, le);
				}
				flushGroup();
			}
			SPACED_RE.lastIndex = 0;
			while ((m = SPACED_RE.exec(chunk)) !== null) {
				const s = pos + m.index;
				const collapsed = m[0].replace(/[^\p{L}]+/gu, '').toLowerCase();
				const [ls, le] = lineOf(s);
				rescan(ls, le);
				if (SPACED_KEYWORDS.has(collapsed) || Array.from(SPACED_KEYWORDS).some(k => k.length >= 6 && collapsed.indexOf(k) !== -1)) {
					raw.push({ ruleId: 'PI-OBF-003', severity: 'medium', nStart: s, nEnd: s + m[0].length, layer: 'normalized', detail: 'Reads as “' + clip(collapsed, 80) + '”.' });
				}
			}
			if (/[0-9@$!|]/.test(chunk)) {
				LEET_TOKEN_RE.lastIndex = 0;
				while ((m = LEET_TOKEN_RE.exec(chunk)) !== null) {
					if (!isLeetToken(m[0]) || LEET_EXCLUDE_RE.test(m[0])) { continue; }
					const [ls, le] = lineOf(pos + m.index);
					rescan(ls, le);
				}
			}
		}
		lineCache.clear();

		// Phrases recognized only after removing invisible characters or NFKC.
		const editsByO = norm.edits;
		const editsIn = (o0, o1) => {
			let lo = 0;
			let hi = editsByO.length;
			while (lo < hi) { const mid = (lo + hi) >> 1; if (editsByO[mid].o1 <= o0) { lo = mid + 1; } else { hi = mid; } }
			const out = [];
			for (let i = lo; i < editsByO.length && editsByO[i].o0 < o1; i++) { out.push(editsByO[i]); }
			return out;
		};

		// 7. Map to original offsets, build findings
		const lineIndex = makeLineIndex(text);
		const findings = [];
		const perRule = {};
		const counts = { total: 0, bySeverity: { high: 0, medium: 0, low: 0 }, byGroup: {}, byRule: {} };
		for (const g of GROUP_IDS) { counts.byGroup[g] = { high: 0, medium: 0, low: 0, total: 0 }; }
		const extra = [];
		for (const h of raw) {
			if (h.nStart !== undefined) {
				h.oStart = norm.toOrig(h.nStart, false);
				h.oEnd = Math.max(h.oStart + 1, norm.toOrig(h.nEnd, true));
				if (h.oEnd > text.length) { h.oEnd = text.length; }
			}
			if (h.layer === 'text') {
				const edits = editsIn(h.oStart, h.oEnd).filter(e => (e.kind === 'nfkc' && /[\p{L}\p{N}]/u.test(e.to)) || (e.kind === 'invisible' && !e.run.legit));
				if (edits.length) {
					const inv = edits.filter(e => e.kind === 'invisible').length;
					const nf = edits.length - inv;
					h.layer = 'normalized';
					extra.push({ ruleId: 'PI-OBF-004', severity: h.mentioned ? 'low' : 'high', oStart: h.oStart, oEnd: h.oEnd, layer: 'normalized', inner: [h.ruleId],
						detail: 'Matches ' + h.ruleId + ' only after ' + [inv ? 'removing ' + inv + ' run' + (inv === 1 ? '' : 's') + ' of invisible characters' : '', nf ? 'normalizing ' + nf + ' styled or compatibility character' + (nf === 1 ? '' : 's') : ''].filter(Boolean).join(' and ') + '. Normalized text: “' + clip(h.matched, 160) + '”.' });
				}
			}
		}
		const all = raw.concat(extra);
		all.sort((a, b) => a.oStart - b.oStart || RANK[b.severity] - RANK[a.severity] || a.ruleId.localeCompare(b.ruleId));
		const lastByRule = {};
		for (const h of all) {
			const rule = RULES_BY_ID[h.ruleId];
			const prev = lastByRule[h.ruleId];
			if (prev && h.oStart < prev.oEnd) {
				// Same rule, overlapping span: merge.
				prev.oEnd = Math.max(prev.oEnd, h.oEnd);
				if (RANK[h.severity] > RANK[prev.severity]) {
					counts.bySeverity[prev.severity]--; counts.byGroup[rule.group][prev.severity]--;
					prev.severity = h.severity;
					counts.bySeverity[prev.severity]++; counts.byGroup[rule.group][prev.severity]++;
				}
				if (prev.finding) {
					prev.finding.end = prev.oEnd;
					prev.finding.severity = prev.severity;
					prev.finding.excerpt = excerpt(text, prev.oStart, prev.oEnd);
				}
				continue;
			}
			lastByRule[h.ruleId] = h;
			counts.total++;
			counts.bySeverity[h.severity]++;
			counts.byGroup[rule.group][h.severity]++;
			counts.byGroup[rule.group].total++;
			counts.byRule[h.ruleId] = (counts.byRule[h.ruleId] || 0) + 1;
			perRule[h.ruleId] = (perRule[h.ruleId] || 0) + 1;
			if (findings.length >= MAX_FINDINGS || perRule[h.ruleId] > MAX_PER_RULE) { continue; }
			const pos = lineIndex(h.oStart);
			const finding = {
				n: findings.length,
				ruleId: h.ruleId,
				group: rule.group,
				severity: h.severity,
				title: rule.title,
				explanation: rule.explain,
				start: h.oStart,
				end: h.oEnd,
				line: pos.line,
				column: pos.column,
				layer: h.layer,
				mentioned: !!h.mentioned,
				detail: h.detail || (h.layer === 'normalized' ? 'Detected in the normalized text.' : ''),
				inner: h.inner || [],
				excerpt: excerpt(text, h.oStart, h.oEnd)
			};
			if (h.mentioned) { finding.detail = (finding.detail ? finding.detail + ' ' : '') + 'The phrase appears quoted or given as an example, so its severity was lowered to low. Quoting does not make an instruction harmless to a model.'; }
			h.finding = finding;
			findings.push(finding);
		}
		for (const f of findings) {
			// Recompute counts are already final; keep finding severities in sync after merges.
			f.severity = f.severity || 'low';
		}
		const level = counts.bySeverity.high ? 'high' : counts.bySeverity.medium ? 'medium' : counts.bySeverity.low ? 'low' : 'none';

		// 8. Normalization report
		const invisibleCounts = { zeroWidth: 0, bidi: 0, tag: 0, variation: 0, softHyphen: 0, legit: 0 };
		for (const run of runs) {
			for (const k of Object.keys(run.kinds)) { invisibleCounts[k] += run.kinds[k]; }
			if (run.legit) { invisibleCounts.legit += run.cps.length; }
		}
		const nfkcEdits = norm.edits.filter(e => e.kind === 'nfkc');
		const nfkcExamples = [];
		for (const e of nfkcEdits) {
			if (nfkcExamples.length >= 8) { break; }
			const pair = visible(e.from) + ' → ' + visible(e.to);
			if (nfkcExamples.indexOf(pair) === -1) { nfkcExamples.push(pair); }
		}
		const decoded = decodedList.map(d => {
			const s = norm.toOrig(d.nStart, false);
			const pos = lineIndex(s);
			return { line: pos.line, column: pos.column, chain: d.chain, preview: d.preview, flagged: d.flagged };
		});

		// 9. Sanitized copy
		const sanitized = sanitize(text, runs, norm.edits, findings, opts);
		progress(total);

		return {
			engine: VERSION,
			ruleset: RULESET_VERSION,
			chars: text.length,
			lines: text.length ? lineIndex(text.length).lineCount - (text.endsWith('\n') ? 1 : 0) : 0,
			level,
			counts,
			findings,
			findingsTruncated: counts.total > findings.length,
			normalization: { invisible: invisibleCounts, nfkcChanged: nfkcEdits.length, nfkcExamples, decodedCount, decoded, normalizedLength: ntext.length },
			sanitized,
			preview: highlightPreview(text, findings, opts.previewChars)
		};
	}

	// ---------------------------------------------------------------- sanitized copy

	function sentenceBounds(text, start, end) {
		const ls = text.lastIndexOf('\n', start - 1) + 1;
		let s = start;
		const minS = Math.max(ls, start - 400);
		// Stop at a sentence end or at the end of an HTML tag, so surrounding markup is kept.
		while (s > minS && text[s - 1] !== '>' && !(/[.!?。]/.test(text[s - 1]) && (s >= text.length || /\s/.test(text[s])))) { s--; }
		while (s < start && /[ \t]/.test(text[s])) { s++; }
		let le = text.indexOf('\n', end);
		if (le < 0) { le = text.length; }
		if (le > 0 && text[le - 1] === '\r') { le--; }
		let e = end;
		const maxE = Math.min(le, end + 400);
		while (e < maxE && text[e] !== '<' && !(/[.!?。]/.test(text[e]) && (e + 1 >= text.length || /\s/.test(text[e + 1])))) { e++; }
		if (e < maxE && text[e] !== '<') { e++; }
		return [Math.min(s, start), Math.max(e, end)];
	}

	/**
	 * Build the sanitized copy and the list of edits applied to the original.
	 * Edits: removal of invisible characters (not legitimate uses), NFKC changes,
	 * and replacement of flagged passages with a visible marker.
	 */
	function sanitize(text, runs, normEdits, findings, opts) {
		const edits = [];
		if (opts.removeInvisible) {
			for (const run of runs) {
				if (!run.legit) { edits.push({ start: run.start, end: run.end, replacement: '', kind: 'invisible', ids: [] }); }
			}
		}
		if (opts.normalizeNFKC) {
			for (const e of normEdits) {
				if (e.kind === 'nfkc') { edits.push({ start: e.o0, end: e.o1, replacement: e.to, kind: 'nfkc', ids: [] }); }
			}
		}
		const threshold = RANK[opts.neutralize] || 0;
		if (threshold) {
			for (const f of findings) {
				const rule = RULES_BY_ID[f.ruleId];
				if (RANK[f.severity] < threshold || rule.sanitize === 'none') { continue; }
				const [s, e] = rule.sanitize === 'sentence' ? sentenceBounds(text, f.start, f.end) : [f.start, f.end];
				edits.push({ start: s, end: e, replacement: null, kind: 'flag', ids: [f.ruleId] });
			}
		}
		edits.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
		const merged = [];
		for (const e of edits) {
			const cur = merged[merged.length - 1];
			if (cur && e.start < cur.end) {
				if (e.kind === 'flag' || cur.kind === 'flag') {
					cur.kind = 'flag';
					cur.end = Math.max(cur.end, e.end);
					for (const id of e.ids) { if (cur.ids.indexOf(id) === -1) { cur.ids.push(id); } }
				}
				continue;
			}
			if (cur && e.start === cur.end && e.kind === 'flag' && cur.kind === 'flag') {
				cur.end = e.end;
				for (const id of e.ids) { if (cur.ids.indexOf(id) === -1) { cur.ids.push(id); } }
				continue;
			}
			merged.push({ start: e.start, end: e.end, replacement: e.replacement, kind: e.kind, ids: e.ids.slice() });
		}
		const parts = [];
		let pos = 0;
		const byKind = { invisible: 0, nfkc: 0, flag: 0 };
		for (const e of merged) {
			if (e.kind === 'flag') {
				e.replacement = '[REMOVED: possible prompt injection, ' + e.ids.join(', ') + ']';
				// Keep line structure: removed multi-line passages keep their line breaks.
				const breaks = (text.slice(e.start, e.end).match(/\r?\n/g) || []).join('');
				e.replacement += breaks;
			}
			byKind[e.kind]++;
			parts.push(text.slice(pos, e.start), e.replacement);
			pos = e.end;
		}
		parts.push(text.slice(pos));
		const output = parts.join('');
		// Diff preview: unchanged runs and changes, bounded.
		const limit = opts.previewChars || 200000;
		const diff = [];
		let shown = 0;
		pos = 0;
		for (const e of merged) {
			if (shown >= limit) { break; }
			if (e.start > pos) {
				const same = text.slice(pos, Math.min(e.start, pos + (limit - shown)));
				diff.push({ t: 's', v: same });
				shown += same.length;
				if (shown >= limit) { break; }
			}
			const removed = text.slice(e.start, e.end);
			diff.push({ t: 'c', kind: e.kind, del: clip(visible(removed), 4000), ins: e.replacement, ids: e.ids });
			shown += Math.min(removed.length, 4000) + e.replacement.length;
			pos = e.end;
		}
		if (shown < limit && pos < text.length) {
			diff.push({ t: 's', v: text.slice(pos, pos + (limit - shown)) });
			shown += Math.min(text.length - pos, limit - shown);
		}
		return { text: output, changes: byKind, totalChanges: merged.length, diff, diffTruncated: pos < text.length && shown >= limit };
	}

	/** Original text with non-overlapping finding spans for the highlighted view. */
	function highlightPreview(text, findings, limit) {
		const max = limit || 200000;
		const spans = findings.filter(f => f.start < max).slice().sort((a, b) => a.start - b.start || RANK[b.severity] - RANK[a.severity]);
		const segments = [];
		let pos = 0;
		for (const f of spans) {
			const s = Math.max(f.start, pos);
			const e = Math.min(f.end, max);
			if (e <= s) { continue; }
			if (s > pos) { segments.push({ v: text.slice(pos, s) }); }
			segments.push({ v: visible(text.slice(s, e)), f: f.n, sev: f.severity });
			pos = e;
		}
		if (pos < Math.min(text.length, max)) { segments.push({ v: text.slice(pos, Math.min(text.length, max)) }); }
		return { segments, truncated: text.length > max, shownChars: Math.min(text.length, max) };
	}

	return {
		VERSION,
		RULESET_VERSION,
		MAX_INPUT_CHARS,
		GROUPS,
		SEVERITIES,
		RULES: ALL_RULES.map(r => ({ id: r.id, group: r.group, severity: r.severity, title: r.title, explanation: r.explain })),
		defaultOptions,
		analyze,
		_internal: { normalize, scanInvisible, scanText, findEncoded, deobfuscateLine, isMention, isNegated, visible, sentenceBounds, TEXT_RULES, decodeBase64, readable }
	};
}));
