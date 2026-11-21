/*!
 * CyberDat MITRE ATLAS Attack Vector Mapper — engine (System profile, Finding mapper, Browse), shared by the worker and the
 * Node tests. Data: MITRE ATLAS snapshot in atlas-data.js (Apache-2.0, Copyright MITRE; see the header of that file).
 *
 * Contract (enforced by tests):
 *  - pure functions over text and plain objects: no network, storage, DOM or eval; no model or external service;
 *  - no regular-expression look-behind; user text is matched with Unicode classes (letters, digits, combining marks)
 *    and the u flag, including the patterns built at run time; text is normalized to NFC first;
 *  - every technique id used by the CyberDat mapping exists in the snapshot; names, ids, tactic links and mitigations
 *    always come from the snapshot, never from this file;
 *  - pasted text is never returned whole; secrets in it appear only as their type and a masked fragment.
 */
(function (root, factory) {
	const api = factory(root);
	if (typeof module === 'object' && module.exports) { module.exports = api; } else { root.CyberDatAtlasMapper = api; }
}(typeof self !== 'undefined' ? self : this, function (root) {
	'use strict';

	const ENGINE = '1.0.2';
	const RULESET = '2026-11-15.1';
	const MAX_INPUT_CHARS = 100000;
	const DATA = (typeof module === 'object' && module.exports && typeof require === 'function') ? require('./atlas-data.js') : root.CyberDatAtlasData;

	// ------------------------------------------------------------------ data indexes (MITRE ATLAS)
	const TECH = new Map(DATA.techniques.map(t => [t.id, t]));
	const TACTIC = new Map(DATA.tactics.map(t => [t.id, t]));
	const MIT = new Map(DATA.mitigations.map(m => [m.id, m]));
	const CHILDREN = new Map();
	for (const t of DATA.techniques) { if (t.parent) { if (!CHILDREN.has(t.parent)) { CHILDREN.set(t.parent, []); } CHILDREN.get(t.parent).push(t.id); } }
	const MIT_BY_TECH = new Map();
	const TECH_BY_MIT = new Map();
	for (const [m, t, d] of DATA.mitigates) {
		if (!MIT_BY_TECH.has(t)) { MIT_BY_TECH.set(t, []); }
		MIT_BY_TECH.get(t).push({ id: m, how: d });
		if (!TECH_BY_MIT.has(m)) { TECH_BY_MIT.set(m, []); }
		TECH_BY_MIT.get(m).push(t);
	}

	// ------------------------------------------------------------------ CyberDat mapping: system properties
	const PROPERTIES = {
		'external-api': ['Uses an external model through an API', [
			['AML.T0051.000', 'Users write prompts that reach the model directly.'],
			['AML.T0054', 'Users can try to talk the model out of its restrictions.'],
			['AML.T0069.002', 'The system prompt sent with each request can be coaxed out.'],
			['AML.T0055', 'API keys for the provider must be stored somewhere and can leak.'],
			['AML.T0034', 'Every request is billed, so abuse costs money.'],
			['AML.T0077', 'Model output is rendered to users and can carry links or images.']]],
		'own-model': ['Runs its own or a fine-tuned model', [
			['AML.T0040', 'The model is reachable through an inference API you operate.'],
			['AML.T0005.001', 'Outputs can be collected to replicate the model.'],
			['AML.T0137', 'Outputs can reveal information about the training data.'],
			['AML.T0015', 'Inputs can be crafted so the model misclassifies them.'],
			['AML.T0035', 'Model files and training artifacts are assets that can be stolen.'],
			['AML.T0029', 'Self-hosted inference capacity can be exhausted.']]],
		'rag': ['Retrieval (RAG) over external or user-supplied documents', [
			['AML.T0051.001', 'Retrieved documents can contain instructions the model follows.'],
			['AML.T0070', 'Documents in the index can be planted or changed.'],
			['AML.T0071', 'False entries can be injected into what the retriever returns.'],
			['AML.T0066', 'Content can be written so that the retriever selects it.'],
			['AML.T0085.000', 'The retrieval database can be used to collect data.'],
			['AML.T0082', 'Credentials stored in indexed documents can be retrieved.']]],
		'agent-tools': ['Agent that can call tools or take actions', [
			['AML.T0053', 'The model decides which tools to call.'],
			['AML.T0086', 'Tool calls can send data out.'],
			['AML.T0101', 'Tool calls can delete or overwrite data.'],
			['AML.T0080', 'The agent context can be poisoned to change later actions.'],
			['AML.T0110', 'Tool definitions, code or responses can be poisoned.'],
			['AML.T0083', 'Agent configuration often holds credentials for tools.'],
			['AML.T0010.005', 'Third-party tools are part of the supply chain.']]],
		'file-upload': ['Users can upload files that the AI processes', [
			['AML.T0051.001', 'Uploaded files can contain instructions the model follows.'],
			['AML.T0129', 'Images, audio or documents can hide triggers.'],
			['AML.T0119', 'Automated processing of uploaded artifacts can be exploited.'],
			['AML.T0068', 'Instructions can be hidden or encoded inside files.']]],
		'public': ['Publicly accessible (no login, or open sign-up)', [
			['AML.T0049', 'Anyone can reach the application.'],
			['AML.T0093', 'Prompts can be planted through the public interface.'],
			['AML.T0034.000', 'Automated excessive queries are easy without accounts.'],
			['AML.T0029', 'The service can be flooded.'],
			['AML.T0005.001', 'Public outputs can be harvested to replicate the model.'],
			['AML.T0132', 'Publicly exposed AI services may be misconfigured.']]],
		'training-pipeline': ['Has a training or fine-tuning pipeline', [
			['AML.T0020', 'Training data can be poisoned.'],
			['AML.T0018.000', 'The model itself can be poisoned during training.'],
			['AML.T0043.004', 'A backdoor trigger can be inserted through training data.'],
			['AML.T0010.002', 'External data repositories feed the pipeline.'],
			['AML.T0059', 'Dataset integrity can be eroded over time.'],
			['AML.T0035', 'Training artifacts can be collected.']]],
		'open-registry': ['Uses models or datasets from public registries', [
			['AML.T0010.003', 'Model repositories are part of the supply chain.'],
			['AML.T0010.002', 'Dataset repositories are part of the supply chain.'],
			['AML.T0011.000', 'Downloaded model files can be unsafe to load.'],
			['AML.T0018.002', 'Model files can embed malware.'],
			['AML.T0115', 'Poisoned artifacts can be published to registries.'],
			['AML.T0111', 'Download counts and stars can be inflated.']]]
	};

	// ------------------------------------------------------------------ CyberDat mapping: words in a finding -> technique
	// A rule proposes its technique when any "strong" term matches, or when every group has a match. Terms match at the
	// start of a word (stems: "poison" also matches "poisoned"); a trailing "$" means the whole word; spaces and hyphens
	// between words of a phrase are interchangeable. "unless": a more specific rule that, when proposed, replaces this one.
	const RULES = [
		{ id: 'MAP-01', technique: 'AML.T0051.000', strong: ['direct prompt injection', 'direkte prompt injection', 'прям промпт инъекц', 'прям инъекц промпт'], generic: ['prompt injection', 'promptinjection', 'prompt injektion', 'промпт инъекц'], groups: [['ignor', 'disregard', 'missacht', 'игнорир', 'пренебре', 'persuad', 'überred', 'уговор', 'talked into', 'tricked'], ['instruction', 'anweisung', 'инструкц', 'rules$', 'regeln', 'правил']], unless: ['MAP-02', 'MAP-18', 'MAP-28'] },
		{ id: 'MAP-02', technique: 'AML.T0051.001', strong: ['indirect prompt injection', 'indirekte prompt injection', 'косвенн промпт инъекц', 'косвенн инъекц'], groups: [['hidden instruction', 'embedded instruction', 'instructions for the model', 'instructions to the model', 'versteckte anweisung', 'anweisungen an das modell', 'anweisungen für das modell', 'скрыт инструкц', 'скрыт команд', 'спрятан команд', 'спрятаны команд', 'команды для ии', 'инструкции для модели'], ['web page', 'webpage', 'website', 'document', 'pdf$', 'email', 'e mail', 'mail$', 'upload', 'retriev', 'webseite', 'dokument', 'datei', 'hochgeladen', 'страниц', 'сайт', 'документ', 'письм', 'файл']] },
		{ id: 'MAP-03', technique: 'AML.T0054', strong: ['jailbreak', 'jail break', 'джейлбрейк', 'джейлбрейк'], groups: [['bypass', 'circumvent', 'umgeh', 'обош', 'обход'], ['guardrail', 'restriction', 'safety filter', 'einschränkung', 'schutzmechanism', 'ограничени']] },
		{ id: 'MAP-04', technique: 'AML.T0069.002', groups: [['system prompt', 'systemprompt', 'system instructions', 'системн промпт', 'системн инструкц'], ['reveal', 'disclos', 'leak', 'expos', 'dump', 'preisgeg', 'verrat', 'offengeleg', 'раскры', 'утек', 'утечк', 'выдал']] },
		{ id: 'MAP-05', technique: 'AML.T0077', groups: [['markdown image', 'markdown bild', 'render', 'image url', 'bild url', 'изображен', 'картинк'], ['exfiltrat', 'external server', 'externen server', 'внешн сервер', 'carried', 'übertrag', 'передал', 'утек']] },
		{ id: 'MAP-06', technique: 'AML.T0070', strong: ['rag poisoning', 'отравлен индекс', 'отравление rag'], groups: [['rag$', 'retrieval', 'knowledge base', 'wissensdatenbank', 'wiki$', 'база знаний', 'базу знаний', 'индекс', 'vector store', 'vektordatenbank'], ['poison', 'vergift', 'отравл', 'false', 'falsch', 'ложн', 'manipul', 'planted', 'eingeschleust', 'подброс', 'edited']] },
		{ id: 'MAP-07', technique: 'AML.T0020', strong: ['data poisoning', 'отравлен данных', 'отравление обучающ'], groups: [['training data', 'training set', 'training dataset', 'trainingsdaten', 'trainingsdatensatz', 'обучающ', 'обучен выборк', 'annotat', 'labels'], ['poison', 'vergift', 'отравл', 'manipul', 'mislabel', 'испорч', 'tamper', 'намеренно']] },
		{ id: 'MAP-08', technique: 'AML.T0043.004', strong: ['backdoor', 'back door', 'hintertür', 'бэкдор', 'trigger phrase', 'trigger wort', 'триггер фраз'] },
		{ id: 'MAP-09', technique: 'AML.T0005.001', strong: ['model extraction', 'model stealing', 'model theft', 'modelldiebstahl', 'model extraktion', 'кража модел', 'извлечен модел'], groups: [['quer', 'abfrage', 'запрос'], ['copy of the model', 'clone', 'replicat', 'nachgebaut', 'nachbau', 'клон', 'копию модел']] },
		{ id: 'MAP-10', technique: 'AML.T0137.003', groups: [['training data', 'trainingsdaten', 'обучающ', 'memoriz', 'memoris', 'auswendig'], ['verbatim', 'wörtlich', 'дословн', 'reproduc', 'regurgit']] },
		{ id: 'MAP-11', technique: 'AML.T0137.000', strong: ['membership inference', 'membership attack', 'mitgliedschaftsinferenz', 'вывод о членстве', 'атак на членство'] },
		{ id: 'MAP-12', technique: 'AML.T0015', strong: ['adversarial example', 'adversarial input', 'adversarial perturb', 'adversarial image', 'adversarial sample', 'adversarial beispiel', 'состязательн пример', 'adversarial атак'], groups: [['evad', 'evasion', 'umgangen', 'umgeh', 'обход', 'обош'], ['classifier', 'detection model', 'detector', 'spam filter', 'spamfilter', 'классификатор', 'детектор', 'erkennungsmodell']] },
		{ id: 'MAP-13', technique: 'AML.T0029', strong: ['denial of service', 'dos attack', 'ddos', 'отказ в обслуживан', 'dienstverweigerung'], groups: [['overload', 'überlast', 'перегруз', 'flood', 'exhaust'], ['server', 'service', 'dienst', 'сервис', 'сервер', 'inference', 'endpoint']] },
		{ id: 'MAP-14', technique: 'AML.T0034', strong: ['cost harvesting', 'llmjacking', 'denial of wallet'], groups: [['bill$', 'invoice', 'rechnung', 'kosten', 'costs', 'счёт', 'счет', 'стоимост', 'расход'], ['jump', 'spike', 'rose$', 'stieg', 'explod', 'вырос', 'increase', 'fache', 'десятки', 'zwanzigfach', 'zehnfach']] },
		{ id: 'MAP-15', technique: 'AML.T0011.000', strong: ['pickle', 'torch.load', 'joblib'] },
		{ id: 'MAP-16', technique: 'AML.T0010.003', groups: [['model hub', 'hugging face', 'huggingface', 'model repository', 'model registry', 'modell hub', 'реестр модел', 'хаб модел'], ['malicious', 'bösartig', 'вредонос', 'look alike', 'typosquat', 'fake', 'gefälscht', 'поддельн', 'compromis']] },
		{ id: 'MAP-17', technique: 'AML.T0010.001', groups: [['package', 'paket', 'пакет', 'dependenc', 'abhängigkeit', 'зависимост', 'library', 'библиотек', 'pypi$', 'npm$'], ['malicious', 'compromis', 'bösartig', 'kompromittiert', 'вредонос', 'скомпрометир', 'backdoored', 'typosquat']], unless: ['MAP-25'] },
		{ id: 'MAP-18', technique: 'AML.T0110.000', strong: ['tool poisoning', 'tool vergiftung', 'отравлен инструмент'], groups: [['tool description', 'tool beschreibung', 'описание инструмент', 'tool definition', 'mcp$'], ['hidden', 'versteckt', 'скрыт', 'instruction', 'anweisung', 'указани', 'poison', 'vergift']] },
		{ id: 'MAP-19', technique: 'AML.T0053', groups: [['agent', 'агент'], ['tool', 'werkzeug', 'инструмент', 'calling', 'invok', 'aufgerufen', 'вызва', 'payment', 'zahlung', 'платеж', 'платёж']], unless: ['MAP-18', 'MAP-23'] },
		{ id: 'MAP-20', technique: 'AML.T0101', groups: [['agent', 'агент', 'assistant', 'assistent', 'ассистент'], ['delet', 'gelöscht', 'lösch', 'удал', 'wiped', 'destroy', 'zerstört', 'уничтож']] },
		{ id: 'MAP-21', technique: 'AML.T0086', groups: [['agent', 'агент'], ['send', 'sent$', 'forward', 'gesendet', 'weitergeleitet', 'отправ', 'переслал'], ['outside', 'external', 'extern', 'внешн', 'attacker', 'angreifer', 'злоумышленник']] },
		{ id: 'MAP-22', technique: 'AML.T0055', groups: [['api key', 'api schlüssel', 'ключ api', 'api ключ', 'api token', 'secret key', 'access key', 'zugangsschlüssel'], ['commit', 'github', 'repositor', 'репозитор', 'public', 'öffentlich', 'публичн', 'frontend', 'klartext', 'plain text', 'cleartext', 'открыт', 'expos', 'leak', 'stolen', 'gestohlen', 'украден', 'утек']], secrets: true },
		{ id: 'MAP-23', technique: 'AML.T0083', groups: [['agent configuration', 'agent config', 'agentenkonfiguration', 'конфигурац агент', 'mcp config', 'mcp konfiguration'], ['password', 'passwort', 'пароль', 'credential', 'zugangsdaten', 'учетн', 'учётн', 'token', 'secret', 'key$']] },
		{ id: 'MAP-24', technique: 'AML.T0088', strong: ['deepfake', 'deep fake', 'дипфейк'] },
		{ id: 'MAP-25', technique: 'AML.T0060', strong: ['slopsquatting'], groups: [['hallucinat', 'halluzin', 'галлюцин', 'did not exist', 'nicht existier', 'не существ'], ['package', 'paket', 'пакет', 'library', 'bibliothek', 'библиотек', 'registered', 'registriert', 'зарегистр']] },
		{ id: 'MAP-26', technique: 'AML.T0080.000', strong: ['memory poisoning', 'gedächtnisvergiftung', 'отравлен памят'], groups: [['memory', 'gedächtnis', 'langzeitgedächtnis', 'памят'], ['stored', 'gespeichert', 'speichert', 'сохран', 'poison', 'vergift', 'отравл', 'later sessions', 'dauerhaft', 'persist', 'последующ']] },
		{ id: 'MAP-27', technique: 'AML.T0132', groups: [['without authentication', 'ohne authentifizierung', 'без аутентификац', 'unauthenticated', 'no authentication', 'without a password', 'ohne passwort', 'без пароля', 'open to the internet', 'öffentlich erreichbar', 'доступен из интернет'], ['server', 'endpoint', 'endpunkt', 'сервер', 'ollama', 'api$', 'model', 'modell', 'модел', 'inferenz', 'inference']] },
		{ id: 'MAP-28', technique: 'AML.T0068', groups: [['base64', 'invisible unicode', 'invisible character', 'unsichtbare zeichen', 'невидим', 'zero width', 'homoglyph', 'encoded', 'kodiert', 'закодир', 'obfuscat', 'verschleier', 'обфуск'], ['instruction', 'anweisung', 'инструкц', 'prompt', 'промпт', 'filter', 'фильтр']] },
		{ id: 'MAP-29', technique: 'AML.T0092', groups: [['chat history', 'chatverlauf', 'conversation history', 'истори чата', 'истори переписк'], ['modif', 'manipul', 'altered', 'verändert', 'изменен', 'подмен']] },
		{ id: 'MAP-30', technique: 'AML.T0085.000', groups: [['rag$', 'retrieval', 'knowledge base', 'wissensdatenbank', 'база знаний', 'базы знаний'], ['confidential', 'vertraulich', 'конфиденц', 'should not see', 'nicht sehen', 'не должен', 'unauthori', 'unberechtigt', 'без доступа']], unless: ['MAP-06'] },
		{ id: 'MAP-31', technique: 'AML.T0137.002', strong: ['model inversion', 'modellinversion', 'инверси модел'], groups: [['reconstruct', 'rekonstru', 'восстанов'], ['face', 'gesicht', 'лиц', 'training', 'обучающ']] },
		{ id: 'MAP-32', technique: 'AML.T0052.000', groups: [['phishing', 'фишинг', 'spearphishing', 'spear phishing'], ['llm$', 'language model', 'sprachmodell', 'языков модел', 'chatgpt', 'generated by', 'generiert', 'сгенерир', 'ai generated', 'ki generiert']] }
	];

	// ------------------------------------------------------------------ text helpers (Unicode)
	const norm = s => String(s || '').normalize('NFC').replace(/­/gu, '').toLocaleLowerCase('en-US');
	const esc = s => s.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
	const W = '[\\p{L}\\p{N}\\p{M}]';
	/** Term -> RegExp (u flag): starts at a word start, words may be joined by spaces or hyphens, stems continue. */
	function termRe(term) {
		const whole = term.endsWith('$');
		// Every word of a phrase is a stem ("системн промпт" matches "системный промпт"); "$" fixes only the last word.
		const words = norm(whole ? term.slice(0, -1) : term).split(/[\s-]+/u).filter(Boolean).map(esc);
		const body = words.map((w, i) => w + (i < words.length - 1 || !whole ? W + '*' : '')).join('[\\s\\-]{1,3}');
		return new RegExp('(?:^|[^\\p{L}\\p{N}\\p{M}])(' + body + ')(?!' + W + ')', 'gu');
	}
	const COMPILED = RULES.map(r => ({ rule: r, strong: (r.strong || []).map(termRe), generic: (r.generic || []).map(termRe), groups: (r.groups || []).map(g => g.map(termRe)) }));
	function firstMatch(text, list) {
		for (const re of list) { re.lastIndex = 0; const m = re.exec(text); if (m) { return m[1]; } }
		return '';
	}

	// ------------------------------------------------------------------ secrets in pasted text (masked)
	const SECRET_PATTERNS = [
		['AWS access key ID', /(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}/gu], ['GitHub token', /gh[pousr]_[0-9A-Za-z]{30,}/gu], ['GitHub fine-grained token', /github_pat_[0-9A-Za-z_]{40,}/gu],
		['GitLab token', /glpat-[0-9A-Za-z_-]{20,}/gu], ['Slack token', /xox[abposr]-[0-9A-Za-z-]{10,}/gu], ['Anthropic API key', /sk-ant-[0-9A-Za-z_-]{20,}/gu],
		['OpenAI-style API key', /sk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{20,}/gu], ['Google API key', /AIza[0-9A-Za-z_-]{35}/gu], ['Hugging Face token', /hf_[0-9A-Za-z]{30,}/gu],
		['JSON Web Token', /eyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{5,}\.[0-9A-Za-z_-]*/gu], ['Private key', /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/gu]
	];
	const TOKEN_CHAR = /[\p{L}\p{N}\p{M}_]/u;
	function mask(v) { const c = [...String(v)]; return c.length <= 8 ? '••••' : c.slice(0, 4).join('') + '… (' + c.length + ' characters)'; }
	function entropy(s) { const m = new Map(); for (const ch of s) { m.set(ch, (m.get(ch) || 0) + 1); } let e = 0; for (const n of m.values()) { const p = n / s.length; e -= p * Math.log2(p); } return e; }
	// Preserve ordinary long Unicode words; glued credentials still match their format or token digits.
	function exportTokenLike(value) {
		if (/^\p{ASCII}+$/u.test(value) || /\p{N}/u.test(value)) { return true; }
		return SECRET_PATTERNS.some(([, re]) => { re.lastIndex = 0; return re.test(value); });
	}
	/** Known-format secrets and unrecognized long random-looking values: [{ kind, start, end, shown }]. */
	function findSecrets(text) {
		const s = String(text || '');
		const out = [];
		const taken = (a, b) => out.some(x => a < x.end && b > x.start);
		const urls = [];
		const URL = /(?:https?|git\+https?|git\+ssh|ssh|ftp|s3|gs|hf):\/\/([^\s"'<>/?#]*)([^\s"'<>]*)/giu;
		let url;
		while ((url = URL.exec(s))) {
			urls.push([url.index, url.index + url[0].length]);
			const authority = url[1], start = url.index + url[0].indexOf('://') + 3, at = authority.lastIndexOf('@');
			if (at > 0 && authority.slice(0, at).includes(':')) {
				out.push({ kind: 'URL credentials', start, end: start + at, shown: '••••:••••' });
			}
			// Inspect tail components, not the hostname or URL separators, for unknown long values.
			const tail = /[\p{L}\p{N}\p{M}+_.\-]{24,}/gu;
			let part;
			while ((part = tail.exec(url[2]))) {
				const a = start + authority.length + part.index, b = a + part[0].length;
				if (exportTokenLike(part[0]) && !taken(a, b)) { out.push({ kind: 'unrecognized long value', start: a, end: b, shown: mask(part[0]) }); }
			}
		}
		for (const [kind, re] of SECRET_PATTERNS) {
			re.lastIndex = 0;
			let m;
			while ((m = re.exec(s))) {
				const a = m.index, b = a + m[0].length;
				if ((a > 0 && TOKEN_CHAR.test(s[a - 1]) && kind !== 'Private key') || taken(a, b)) { continue; }
				out.push({ kind, start: a, end: b, shown: kind === 'Private key' ? 'BEGIN … PRIVATE KEY' : mask(m[0]) });
			}
		}
		// Password/token assignments are sensitive even when they have no provider prefix or high entropy.
		// Match recognized keys only: https: must never consume a later ?token= assignment.
		const ASSIGN = /(^|[^\p{L}\p{N}\p{M}_.\-])((?:password|passwd|pwd|secret|client[_.\-]*secret|token|access[_.\-]*token|refresh[_.\-]*token|api[_.\-]*key|x[_.\-]*api[_.\-]*key|authorization|credentials?|private[_.\-]*key))["']?[ \t]*[:=][ \t]*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s"',;&<>#]+)/giu;
		let assigned;
		while ((assigned = ASSIGN.exec(s))) {
			const key = assigned[2].normalize('NFC').toLowerCase().replace(/[_.\-]/gu, '');
			if (!/^(?:password|passwd|pwd|secret|clientsecret|token|accesstoken|refreshtoken|apikey|xapikey|authorization|credential|credentials|privatekey)$/u.test(key)) { continue; }
			const quoted = assigned[3][0] === '"' || assigned[3][0] === "'";
			const value = quoted ? assigned[3].slice(1, -1) : assigned[3];
			const a = assigned.index + assigned[0].length - assigned[3].length + (quoted ? 1 : 0), b = a + value.length;
			if (!value || taken(a, b)) { continue; }
			out.push({ kind: 'assigned secret', start: a, end: b, shown: mask(value) });
		}
		const LONG = /[\p{L}\p{N}\p{M}+/=_\-.]{24,}/gu;
		let m;
		while ((m = LONG.exec(s))) {
			const v = m[0], a = m.index, b = a + v.length;
			if (!exportTokenLike(v) || taken(a, b) || (a > 0 && TOKEN_CHAR.test(s[a - 1])) || (b < s.length && TOKEN_CHAR.test(s[b])) || urls.some(([x, y]) => a >= x && b <= y)) { continue; }
			if (/^(?:https?|www)/iu.test(v)) { continue; }
			out.push({ kind: 'unrecognized long value', start: a, end: b, shown: mask(v) });
		}
		return out.sort((x, y) => x.start - y.start);
	}
	function maskSecrets(text) {
		let s = String(text || '');
		for (const x of findSecrets(s).sort((p, q) => q.start - p.start)) { s = s.slice(0, x.start) + '[' + x.kind + ': ' + x.shown + ']' + s.slice(x.end); }
		return s;
	}

	// ------------------------------------------------------------------ views of the data
	const brief = id => { const t = TECH.get(id); return t ? { id: t.id, name: t.name, parent: t.parent, parentName: t.parent ? TECH.get(t.parent).name : '' } : null; };
	function mitigationsFor(id) {
		const own = (MIT_BY_TECH.get(id) || []).map(x => ({ id: x.id, name: MIT.get(x.id).name, how: x.how, via: '' }));
		const t = TECH.get(id);
		if (t && t.parent) {
			for (const x of MIT_BY_TECH.get(t.parent) || []) { if (!own.some(o => o.id === x.id)) { own.push({ id: x.id, name: MIT.get(x.id).name, how: x.how, via: t.parent }); } }
		}
		return own.sort((a, b) => (a.id < b.id ? -1 : 1));
	}
	function techniqueView(id) {
		const t = TECH.get(id);
		if (!t) { return null; }
		return { id: t.id, name: t.name, description: t.description, maturity: t.maturity, tactics: t.tactics.map(x => ({ id: x, name: TACTIC.get(x).name })), parent: t.parent ? brief(t.parent) : null, subtechniques: (CHILDREN.get(id) || []).map(brief), mitigations: mitigationsFor(id) };
	}
	function mitigationView(id) {
		const m = MIT.get(id);
		return m ? { id: m.id, name: m.name, description: m.description, categories: m.categories, lifecyclePhases: m.lifecyclePhases, techniques: (TECH_BY_MIT.get(id) || []).map(brief).sort((a, b) => (a.id < b.id ? -1 : 1)) } : null;
	}
	function tacticView(id) {
		const t = TACTIC.get(id);
		return t ? { id: t.id, name: t.name, description: t.description, techniques: DATA.techniques.filter(x => !x.parent && x.tactics.includes(id)).map(x => ({ id: x.id, name: x.name, subtechniques: (CHILDREN.get(x.id) || []).length })) } : null;
	}
	function byTactic(items) {
		const groups = DATA.tactics.map(t => ({ tactic: { id: t.id, name: t.name }, techniques: [] }));
		for (const it of items) {
			for (const tac of TECH.get(it.id).tactics) { groups.find(g => g.tactic.id === tac).techniques.push(it); }
		}
		return groups.filter(g => g.techniques.length);
	}

	// ------------------------------------------------------------------ modes
	function profile(selected, hooks) {
		const keys = (selected || []).filter(k => Object.prototype.hasOwnProperty.call(PROPERTIES, k));
		const found = new Map();
		for (const k of keys) {
			for (const [id, reason] of PROPERTIES[k][1]) {
				if (!found.has(id)) { found.set(id, { id, reasons: [] }); }
				found.get(id).reasons.push({ property: k, label: PROPERTIES[k][0], reason });
			}
		}
		if (hooks && hooks.onProgress) { hooks.onProgress(1, 1); }
		const items = [...found.values()].map(x => Object.assign(techniqueView(x.id), { reasons: x.reasons, source: 'CyberDat mapping' })).sort((a, b) => (a.id < b.id ? -1 : 1));
		return { mode: 'profile', engine: ENGINE, ruleset: RULESET, data: dataInfo(), properties: keys.map(k => ({ id: k, label: PROPERTIES[k][0] })), count: items.length, techniques: items, groups: byTactic(items) };
	}
	function mapFinding(text, hooks) {
		const raw = String(text || '');
		if (raw.length > MAX_INPUT_CHARS) { const e = new Error('The text is longer than ' + MAX_INPUT_CHARS.toLocaleString('en-US') + ' characters.'); e.code = 'TOO_LARGE'; throw e; }
		if (!raw.trim()) { const e = new Error('The text is empty.'); e.code = 'EMPTY'; throw e; }
		const secrets = findSecrets(raw);
		// Secrets are removed before matching so that their characters never become evidence.
		let clean = raw;
		for (const x of secrets.slice().sort((p, q) => q.start - p.start)) { clean = clean.slice(0, x.start) + ' ' + clean.slice(x.end); }
		const t = norm(clean);
		const hits = new Map();
		COMPILED.forEach((c, i) => {
			const words = [];
			for (const re of c.strong) { re.lastIndex = 0; const m = re.exec(t); if (m) { words.push(m[1]); break; } }
			let generic = '';
			if (!words.length && c.generic.length) { generic = firstMatch(t, c.generic); }
			if (!words.length && c.groups.length) {
				const g = c.groups.map(list => firstMatch(t, list));
				if (g.every(Boolean)) { words.push(...g); }
			}
			if (!words.length && c.rule.secrets && secrets.some(s => s.kind !== 'unrecognized long value')) { words.push('[' + secrets.find(s => s.kind !== 'unrecognized long value').kind + ']'); }
			if (words.length || generic) { hits.set(c.rule.id, { rule: c.rule, words: words.length ? words : [generic], genericOnly: !words.length }); }
			if (hooks && hooks.onProgress && i % 8 === 7) { hooks.onProgress(i + 1, COMPILED.length); }
		});
		for (const [id, h] of [...hits]) {
			const blockers = (h.rule.unless || []).filter(u => hits.has(u));
			if (blockers.length && (h.genericOnly || h.rule.id !== 'MAP-01')) { hits.delete(id); }
		}
		const items = [...hits.values()].map(h => Object.assign(techniqueView(h.rule.technique), { rule: h.rule.id, matched: [...new Set(h.words)], source: 'CyberDat mapping' })).sort((a, b) => (a.id < b.id ? -1 : 1));
		return { mode: 'finding', engine: ENGINE, ruleset: RULESET, data: dataInfo(), chars: raw.length, secrets: secrets.map(s => ({ kind: s.kind, shown: s.shown })), count: items.length, techniques: items, groups: byTactic(items) };
	}
	function search(query) {
		const q = norm(query).trim();
		if (!q) { return { query: '', tactics: DATA.tactics.map(t => ({ id: t.id, name: t.name })), techniques: [], mitigations: [] }; }
		const words = q.split(/\s+/u);
		const hit = (id, name) => words.every(w => norm(id).includes(w) || norm(name).includes(w));
		return {
			query: q,
			tactics: DATA.tactics.filter(t => hit(t.id, t.name)).map(t => ({ id: t.id, name: t.name })),
			techniques: DATA.techniques.filter(t => hit(t.id, t.name)).map(t => brief(t.id)).slice(0, 200),
			mitigations: DATA.mitigations.filter(m => hit(m.id, m.name)).map(m => ({ id: m.id, name: m.name }))
		};
	}
	function lookup(id) {
		const s = String(id || '').trim().toUpperCase();
		if (TECH.has(s)) { return { kind: 'technique', item: techniqueView(s) }; }
		if (MIT.has(s)) { return { kind: 'mitigation', item: mitigationView(s) }; }
		if (TACTIC.has(s)) { return { kind: 'tactic', item: tacticView(s) }; }
		return null;
	}
	function dataInfo() { const m = DATA.meta; return { name: m.name, release: m.release, releaseDate: m.releaseDate, commit: m.commit, license: m.license, copyright: m.copyright, modification: m.modification, counts: m.counts }; }

	// ------------------------------------------------------------------ export
	const mdEsc = s => String(s).replace(/([\\`*_{}\[\]<>()#+!|~])/gu, '\\$1').replace(/\r?\n/gu, '  \n');
	/** selection: [{ id, note, source }] (source: 'CyberDat mapping (profile)', 'CyberDat mapping (finding)', 'Browse'). */
	function exportSelection(selection, opts) {
		const o = opts || {};
		const items = (selection || []).filter(s => TECH.has(s.id)).map(s => {
			const t = techniqueView(s.id);
			return { id: t.id, name: t.name, tactics: t.tactics.map(x => x.id + ' ' + x.name), parent: t.parent ? t.parent.id : null, mitigations: t.mitigations.map(m => ({ id: m.id, name: m.name, via: m.via || undefined })), selectedFrom: maskSecrets(String(s.source || '')), note: maskSecrets(String(s.note || '')).slice(0, 4000) };
		});
		const d = dataInfo();
		const json = {
			tool: 'CyberDat MITRE ATLAS Attack Vector Mapper', engine: ENGINE, mappingRules: RULESET, generatedAt: maskSecrets(String(o.timestamp || new Date().toISOString())),
			data: { source: 'MITRE ATLAS', release: d.release, releaseDate: d.releaseDate, commit: d.commit, license: d.license, attribution: d.copyright + '. MITRE ATLAS data licensed under the Apache License 2.0. Modified: ' + d.modification },
			note: 'Candidate techniques for review, not a security assessment and not a complete threat model. Technique names, ids, tactics and mitigations are MITRE ATLAS data; the reasons for proposing them are CyberDat mapping, not an assessment by MITRE. Secrets in notes are masked.',
			techniques: items
		};
		const L = ['# MITRE ATLAS techniques selected for review', '', 'Generated with CyberDat MITRE ATLAS Attack Vector Mapper ' + ENGINE + ' on ' + mdEsc(json.generatedAt) + '. Data: MITRE ATLAS ' + d.release + ' (' + d.releaseDate + ').', '', '> Candidates for review, not a security assessment and not a complete threat model. Technique names, ids, tactics and mitigations are MITRE ATLAS data; why they were proposed is CyberDat mapping, not an assessment by MITRE.', ''];
		if (!items.length) { L.push('_No techniques selected._', ''); }
		for (const it of items) {
			L.push('## ' + it.id + ' ' + mdEsc(it.name), '');
			L.push('- **Tactics:** ' + mdEsc(it.tactics.join(', ')));
			if (it.parent) { L.push('- **Sub-technique of:** ' + it.parent); }
			L.push('- **Selected from:** ' + mdEsc(it.selectedFrom || 'Browse'));
			L.push('- **Related mitigations (MITRE ATLAS):** ' + (it.mitigations.length ? it.mitigations.map(m => m.id + ' ' + mdEsc(m.name) + (m.via ? ' (via ' + m.via + ')' : '')).join('; ') : '_none listed_'));
			L.push('- **Note:** ' + (it.note ? mdEsc(it.note) : '_none_'), '');
		}
		L.push('---', '', 'Data source: MITRE ATLAS ' + d.release + ', github.com/mitre-atlas/atlas-data commit ' + d.commit + '. ' + mdEsc(d.copyright) + '. Licensed under the Apache License 2.0. ' + mdEsc(d.modification));
		return { json: JSON.stringify(json, null, 2) + '\n', markdown: L.join('\n') + '\n', count: items.length };
	}

	return { ENGINE, RULESET, MAX_INPUT_CHARS, DATA, PROPERTIES, RULES, profile, mapFinding, search, lookup, techniqueView, mitigationView, tacticView, exportSelection, findSecrets, maskSecrets, termRe, norm };
}));
