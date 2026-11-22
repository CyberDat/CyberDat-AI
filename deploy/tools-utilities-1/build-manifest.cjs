/*
 * Builds deploy/tools-utilities-1/manifest.json in the release-1 manifest shape (base/target maps of every theme file
 * with bytes, mode and sha256 of the exact LF bytes stored in git) and an explicit delta.
 * Base = the theme that runs on closed staging: snapshot/staging-theme-20261122 (cd06239, published by Codex; its 159
 * theme files equal staging by SHA-256). So base_sha256 of every modified file is the staging version.
 * Target = this branch (owner decisions of 2026-11-22 per file group):
 *   A  staging version kept (must NOT be in the delta): intelligence/threat files, Log Anonymizer Stage1;
 *   B  our version (in the delta): engines of tools 2, 3, 5, 6 and their constants, catalogue, tools.php, previews 5-10,
 *      functions.php, page-templates/tools.php;
 *   C  merged (staging + ours): template-parts of tools 2, 3 (in the delta) and of tool 4, inc/assets.php (equal to staging);
 *   added = the 29 files that staging does not have (tools 8-10 of release 1.3, the utility, the Hub previews README).
 *   node deploy/tools-utilities-1/build-manifest.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE_COMMIT = 'cd06239d39e6a81139e7fec843412f86f0de0140';
const BASE_REF = 'snapshot/staging-theme-20261122';
const THEME = 'wp-content/themes/cyberdat/';
const ROOT = path.join(__dirname, '../..');
const sh = c => cp.execSync(c, { cwd: ROOT, maxBuffer: 1 << 28 });
const CHECK = process.argv.includes('--check');
const commit = sh('git rev-parse ' + (process.argv.slice(2).find(x => !x.startsWith('--')) || 'HEAD')).toString().trim();
const blob = (rev, p) => sh('git cat-file blob ' + rev + ':' + p);
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
function tree(rev) {
	const out = {};
	for (const line of sh('git ls-tree -r -z ' + rev + ' -- ' + THEME).toString().split('\0').filter(Boolean)) {
		const [meta, p] = line.split('\t');
		const buf = sh('git cat-file blob ' + meta.split(' ')[2]);
		out[p.slice(THEME.length)] = { bytes: buf.length, mode: '0644', sha256: sha(buf) };
	}
	return Object.fromEntries(Object.entries(out).sort(([a], [b]) => (a < b ? -1 : 1)));
}
const base = tree(BASE_COMMIT);
const target = tree(commit);
if (Object.keys(base).length !== 159) { throw new Error('the staging snapshot has 159 theme files'); }
const added = Object.keys(target).filter(k => !base[k]);
const removed = Object.keys(base).filter(k => !target[k]);
const modified = Object.keys(target).filter(k => base[k] && base[k].sha256 !== target[k].sha256);

// Owner decisions 2026-11-22.
const PREVIEW = 'assets/images/tools-hub/';
const GROUP_A = ['assets/js/intelligence-live.js', 'assets/js/intelligence-charts.js', 'assets/js/threat-analytics.js', 'assets/js/threat-pulse.js', 'inc/threat-pulse.php',
	'template-parts/home/threat-dashboard.php', 'template-parts/home/threat-pulse.php',
	'assets/js/log-anonymizer/app.js', 'assets/js/log-anonymizer/engine.js', 'assets/js/log-anonymizer/worker.js', 'inc/tool-log-anonymizer.php', 'template-parts/tools/log-anonymizer.php'];
const GROUP_B = ['assets/js/ai-model-bom/engine.js', 'assets/js/atlas-mapper/engine.js', 'inc/tool-ai-model-bom.php', 'inc/tool-atlas-mapper.php',
	'assets/js/prompt-injection-detector/app.js', 'assets/js/prompt-injection-detector/engine.js', 'assets/js/prompt-injection-detector/worker.js', 'inc/tool-prompt-injection-detector.php',
	'assets/js/lotl-analyzer/engine.js', 'inc/tool-lotl-analyzer.php', 'inc/tools-catalog.json', 'inc/tools.php',
	...['agent-leak-inspector', 'ai-model-bom', 'mitre-atlas-mapper', 'prompt-injection-test-bench', 'yara-sigma-validator', 'container-hardening-audit'].map(x => PREVIEW + x + '.svg'),
	'functions.php', 'page-templates/tools.php'];
const GROUP_C = { 'template-parts/tools/prompt-injection-detector.php': 'merged', 'template-parts/tools/lotl-command-analyzer.php': 'merged', 'template-parts/tools/mcp-security-checker.php': 'merged, equal to staging (our branch had no own change)', 'inc/assets.php': 'equal to staging (staging is a superset: the intelligence-live enqueue; nothing of ours differs)' };
for (const k of GROUP_A) {
	if (!base[k] || !target[k] || base[k].sha256 !== target[k].sha256) { throw new Error('group A file must equal the staging version: ' + k); }
}
for (const k of GROUP_B.concat(Object.keys(GROUP_C))) { if (!base[k] || !target[k]) { throw new Error('missing on staging or in the target: ' + k); } }
const expectMod = GROUP_B.concat(Object.keys(GROUP_C).filter(k => base[k].sha256 !== target[k].sha256)).sort();
if (modified.join() !== expectMod.join() || removed.length) { throw new Error('unexpected modified/removed files: ' + modified.concat(removed).join(', ') + ' / expected ' + expectMod.join(', ')); }
const T = { slug: 'email-header-analyzer', title: 'Email Header Analyzer', dir: 'email-header-analyzer', inc: 'tool-email-header-analyzer.php', css: 'email-header-analyzer.css' };
const R13 = ['prompt-injection-test-bench', 'yara-sigma-validator', 'container-hardening-audit'];
const R13_DIRS = { 'prompt-injection-test-bench': 'prompt-injection-test-bench', 'yara-sigma-validator': 'yara-sigma-validator', 'container-hardening-audit': 'container-hardening-audit' };
const ownFiles = (slug, dir) => added.filter(k => k === 'inc/tool-' + slug + '.php' || k === 'assets/css/' + slug + '.css' || k === 'template-parts/tools/' + slug + '.php' || k.startsWith('assets/js/' + dir + '/'));
const mine = ownFiles(T.slug, T.dir);
const myPreview = PREVIEW + T.slug + '.svg';
const r13Files = Object.fromEntries(R13.map(s => [s, ownFiles(s, R13_DIRS[s])]));
const accounted = mine.concat([myPreview, PREVIEW + 'README.md'], ...Object.values(r13Files));
const stray = added.filter(k => !accounted.includes(k));
if (stray.length || accounted.length !== added.length || added.length !== 29) { throw new Error('added files must be the 29 files absent on staging: ' + stray.join(', ')); }
const PREVIEW_GROUPS = {
	'tools-hub-previews-5-7': ['agent-leak-inspector', 'ai-model-bom', 'mitre-atlas-mapper'].map(x => PREVIEW + x + '.svg').concat([PREVIEW + 'README.md']),
	'tools-release-1.3': R13.map(x => PREVIEW + x + '.svg')
};
// Secret masking of tools 2 and 3 (owner task 2026-11-21) and the masked sanitized copy of tool 2 (owner decision 2026-11-22).
const MASK = {
	'prompt-injection-detector': { tool: 2, title: 'Indirect Prompt Injection Sanitizer & Detector', engine: 'assets/js/prompt-injection-detector/engine.js', inc: 'inc/tool-prompt-injection-detector.php', template: 'template-parts/tools/prompt-injection-detector.php', constant: 'CYBERDAT_PROMPT_DETECTOR_ENGINE', version: '1.0.4', extra: ['assets/js/prompt-injection-detector/app.js', 'assets/js/prompt-injection-detector/worker.js'] },
	'lotl-command-analyzer': { tool: 3, title: 'LotL / LOLBAS Command Analyzer', engine: 'assets/js/lotl-analyzer/engine.js', inc: 'inc/tool-lotl-analyzer.php', template: 'template-parts/tools/lotl-command-analyzer.php', constant: 'CYBERDAT_LOTL_ENGINE', version: '1.0.1' }
};
const maskFiles = t => [t.engine, t.inc, t.template].concat(t.extra || []);
const PI_EDITORIAL = 'deploy/tools-prompt-injection-detector/editorial.json';
const maskBlock = k => { const s = blob(commit, THEME + k).toString('utf8'); const a = s.indexOf('// ---------------------------------------------------------------- secret masking (shared block)'), b = s.indexOf('// ---------------------------------------------------------------- end of secret masking (shared block)'); return a > 0 && b > a ? s.slice(a, b) : ''; };
const blocks = Object.values(MASK).map(t => maskBlock(t.engine));
if (!blocks[0] || blocks[0] !== blocks[1]) { throw new Error('the secret masking block must be present and equal in both engines'); }
for (const t of Object.values(MASK)) {
	if (!blob(commit, THEME + t.engine).toString('utf8').includes("const VERSION = '" + t.version + "';") || !blob(commit, THEME + t.inc).toString('utf8').includes('const ' + t.constant + " = '" + t.version + "';")) { throw new Error('engine version ' + t.version + ' expected in ' + t.engine + ' and ' + t.inc); }
}
// Group C templates: 3-way merge with base 0a32f12 (parent of Stage1 d0cba38, also in our history). Every line that Stage1
// added on staging (staging line not in the merge base) must still be in the target.
const MERGE_BASE = '0a32f1234e596c425cda58b096ea1e085147386f';
for (const k of ['template-parts/tools/prompt-injection-detector.php', 'template-parts/tools/lotl-command-analyzer.php', 'template-parts/tools/mcp-security-checker.php']) {
	const now = new Set(blob(commit, THEME + k).toString('utf8').split('\n'));
	const mb = new Set(blob(MERGE_BASE, THEME + k).toString('utf8').split('\n'));
	const lost = blob(BASE_COMMIT, THEME + k).toString('utf8').split('\n').filter(l => !mb.has(l) && !now.has(l));
	if (lost.length) { throw new Error('merged template lost Stage1 lines: ' + k + ': ' + lost.length); }
}
const lines = (rev, k) => blob(rev, THEME + k).toString('utf8').split('\n');
const fn = lines(commit, 'functions.php'), fnBase = lines(BASE_COMMIT, 'functions.php');
const fnAdded = fn.filter(l => !fnBase.includes(l)).map(l => l.trim()).filter(Boolean);
const includes = ['tool-prompt-injection-test-bench.php', 'tool-yara-sigma-validator.php', 'tool-container-hardening-audit.php', T.inc].map(f => "require_once __DIR__ . '/inc/" + f + "';");
if (fnAdded.join() !== includes.join() || fnBase.some(l => !fn.includes(l))) { throw new Error('functions.php must gain exactly the four include lines (tools 8-10, the utility)'); }
const li = fn.findIndex(l => l.trim() === includes[0]);
const cat = JSON.parse(blob(commit, THEME + 'inc/tools-catalog.json').toString('utf8'));
const catBase = JSON.parse(blob(BASE_COMMIT, THEME + 'inc/tools-catalog.json').toString('utf8'));
// Staging has the ten tools (1-7 available, 8-10 planned with short planned texts). Target: all available, 8-10 with their
// release descriptions, the utility appended. Entries 1-7 are identical; 8-10 may differ only in status and description.
const only = (e, keys) => Object.assign({}, e, Object.fromEntries(keys.map(k => [k, null])));
if (cat.length !== catBase.length + 1 || cat.slice(0, catBase.length).some((e, i) => JSON.stringify(only(e, ['status', 'description'])) !== JSON.stringify(only(catBase[i], ['status', 'description'])))) { throw new Error('the ten catalogue entries may change only in status and description, and exactly one entry is added'); }
const catChanges = cat.slice(0, catBase.length).map((e, i) => [e, catBase[i]]).filter(([e, b]) => JSON.stringify(e) !== JSON.stringify(b)).map(([e, b]) => ({ slug: e.slug, status: { from: b.status, to: e.status }, description_changed: e.description !== b.description }));
if (catChanges.map(c => c.slug).join() !== R13.join()) { throw new Error('only the entries of tools 8-10 may change: ' + catChanges.map(c => c.slug).join()); }
if (cat.some(e => e.status !== 'available')) { throw new Error('every catalogue entry must be available in this package'); }
const entry = cat[cat.length - 1];
if (entry.slug !== T.slug) { throw new Error('catalogue entry must be the utility'); }
const toolsPhp = blob(commit, THEME + 'inc/tools.php').toString('utf8');
const canonFn = toolsPhp.slice(toolsPhp.indexOf('function cyberdat_tools_staging_canonical()'), toolsPhp.indexOf("add_action( 'rank_math/head', 'cyberdat_tools_staging_canonical'"));
if (!canonFn.includes("'available' === $tool['status']") || /'(?:log-anonymizer|mcp-security-checker|agent-leak-inspector)'/.test(canonFn)) { throw new Error('the staging canonical must take its slugs from the catalogue'); }
const hubNow = lines(commit, 'page-templates/tools.php'), hubBase = lines(BASE_COMMIT, 'page-templates/tools.php');
const hubChanged = hubNow.map((l, i) => [i, l]).filter(([i, l]) => l !== hubBase[i]);
if (hubNow.length !== hubBase.length || hubChanged.length !== 1) { throw new Error('page-templates/tools.php must change in exactly one line'); }
// Applying the delta to the staging base must give exactly the target map.
const applied = Object.assign({}, base);
for (const k of added.concat(modified)) { applied[k] = target[k]; }
for (const k of removed) { delete applied[k]; }
if (JSON.stringify(Object.fromEntries(Object.entries(applied).sort(([a], [b]) => (a < b ? -1 : 1)))) !== JSON.stringify(target)) { throw new Error('base + delta does not give the target'); }
const PSL_FILES = ['assets/js/email-header-analyzer/public_suffix_list.dat', 'assets/js/email-header-analyzer/psl-data.js', 'assets/js/email-header-analyzer/LICENSE-MPL-2.0.txt'];
const fileMap = ks => Object.fromEntries(ks.map(k => [k, Object.assign({ bytes: target[k].bytes, sha256: target[k].sha256 }, base[k] ? { base_sha256: base[k].sha256 } : {})]));
const manifest = {
	schema: 'cyberdat-theme-release/1',
	revision: 'tools-utilities-1/2',
	base_commit: BASE_COMMIT,
	base_ref: BASE_REF,
	base_note: 'Base = the exact staging theme published by Codex on 2026-11-22 (159 files equal to staging by SHA-256). base_sha256 of every modified file is the staging version.',
	theme_commit: commit,
	install_rule: 'The installer copies the delta files as they are and changes no theme file (no prepare step that edits inc/tools.php, inc/tools-catalog.json or any other file). Before installing, every theme file on staging equals the base map; after installing, every theme file equals the target map of this manifest, byte for byte. Catalogue statuses and the staging canonical scope are part of the package.',
	owner_decisions: {
		date: '2026-11-22',
		staging_kept: GROUP_A,
		ours: GROUP_B,
		merged: GROUP_C,
		absent_on_staging_added: 'the 29 added files (tools 8-10 of release 1.3, the utility, the Hub previews README) are a new installation'
	},
	note: 'Theme delta over the staging theme: release 1.3 (tools 8-10: their files, catalogue statuses and descriptions, functions.php includes, Hub previews), quick utility 1 (Email Header Analyzer: its files, its Hub preview, the unmodified Public Suffix List data file, its JS carrier and the MPL-2.0 license text, which must be published together, one functions.php include, one catalogue entry), inc/tools.php: the staging canonical takes its pages from the catalogue (status available), one line of the Hub template ("Quick utility"), the export fixes and secret masking of tools 5 and 6 (b8ff2f3), secret masking of tools 2 and 3 with the masked sanitized copy of tool 2 (secret_masking, sanitized_copy_editorial: FAQ text), the redrawn previews of tools 5-10 (hub_previews). The templates of tools 2 and 3 keep the Stage1 markup of staging (notranslate, privacy note) with the masking texts and the switch added. Log Anonymizer and the intelligence files stay as on staging. Hashes are of the LF bytes in git (git -c core.autocrlf=false archive). No archive is built here: Codex builds and seals the archive with its own release tooling.',
	counts: { base: Object.keys(base).length, target: Object.keys(target).length, added: added.length, modified: modified.length, removed: removed.length },
	delta: { added, modified, removed },
	delta_files: Object.fromEntries(added.concat(modified).sort().map(k => [k, Object.assign({ status: base[k] ? 'modified' : 'added', bytes: target[k].bytes, sha256: target[k].sha256 }, base[k] ? { base_sha256: base[k].sha256 } : {})])),
	release_1_3: Object.fromEntries(R13.map(s => [s, { files: fileMap(r13Files[s]), catalogue: catChanges.find(c => c.slug === s) }])),
	tools: {
		[T.slug]: {
			utility: 1, title: T.title, url: entry.url,
			files: fileMap(mine),
			hub_preview: fileMap([myPreview]),
			mpl_files_publish_together: PSL_FILES,
			shared: {
				'functions.php': { add_lines: includes, after_line: fn[li - 1].trim(), first_line_number: li + 1, utility_line: includes[3] },
				'inc/tools-catalog.json': { append_entry: entry, position: 'after the ten tools (index ' + (cat.length - 1) + ')', changes_of_tools_8_10: catChanges, replace_whole_file: true },
				'inc/tools.php': { change: 'cyberdat_tools_staging_canonical(): pages with catalogue status available instead of a hand-written slug list; other checks unchanged', replace_whole_file: true },
				'page-templates/tools.php': { replace_line_number: hubChanged[0][0] + 1, from: hubBase[hubChanged[0][0]].trim(), to: hubChanged[0][1].trim(), effect: 'cards with kind=utility read "Quick utility"; all other cards unchanged' }
			}
		}
	},
	export_masking_5_6: { change: 'Codex export redaction fix and the second masking fix (b8ff2f3) of tools 5 and 6; staging has the earlier tools-release-1.2/2 versions', files: fileMap(['assets/js/ai-model-bom/engine.js', 'inc/tool-ai-model-bom.php', 'assets/js/atlas-mapper/engine.js', 'inc/tool-atlas-mapper.php']) },
	secret_masking: {
		task: 'Owner task 2026-11-21: tools 2 and 3 on staging showed and exported secrets in finding excerpts and quoted commands (blocker of the public launch).',
		change: 'One shared masking block in both engines (the same block, checked): known formats, JWT, private key blocks, values after credential/password/secret/token/api key/authorization/cookie keys whatever their length, Bearer/Basic, password options (/pass:, /rp, -Password, -u user:password, ConvertTo-SecureString), credentials, secret query values (percent escapes decoded) and token-like path segments in addresses, long opaque values. The whole text is masked before it is cut. Detection runs on the original text and is unchanged (corpus and held-out outputs identical).',
		tools: Object.fromEntries(Object.entries(MASK).map(([slug, t]) => [slug, { tool: t.tool, title: t.title, engine_version: t.version, masked: slug === 'lotl-command-analyzer' ? 'command line, normalized command, deobfuscation notes, binary as written, heuristic details, decoded commands and their nested analysis (page and JSON report)' : 'finding excerpts, quoted text in details (normalized, decoded, hidden, comment text), decoded fragment previews (page and JSON report); the sanitized copy by default (on screen, Copy and Download; masked after sanitization)', not_masked: slug === 'lotl-command-analyzer' ? '' : 'the highlighted text: it is the complete text the user pasted (the page says so); the sanitized copy only while the user switches on "Do not mask secrets in the sanitized copy" (off on every page load, warning shown)', files: fileMap(maskFiles(t)) }]))
	},
	sanitized_copy_editorial: (() => { const b = blob(commit, PI_EDITORIAL); return { path: PI_EDITORIAL, fields: ['how_it_works', 'faq'], change: 'describe the masked sanitized copy and the switch (owner decision 2026-11-22); set by Codex on the existing page meta', bytes: b.length, sha256: sha(b) }; })(),
	hub_previews: Object.fromEntries(Object.entries(PREVIEW_GROUPS).map(([pkg, files]) => [pkg, fileMap(files)])),
	base,
	target
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const keys = ['base', 'target', 'delta', 'delta_files', 'tools', 'release_1_3', 'export_masking_5_6', 'hub_previews', 'secret_masking', 'sanitized_copy_editorial', 'owner_decisions'];
	const same = current.base_commit === BASE_COMMIT && keys.every(k => JSON.stringify(current[k]) === JSON.stringify(manifest[k]));
	console.log(same ? 'PASS: tools-utilities-1 manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: tools-utilities-1 manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12) + '; utility files: ' + mine.length);
