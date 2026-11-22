/*
 * Builds deploy/tools-utilities-1/manifest.json in the release-1 manifest shape (base/target maps of every theme file
 * with bytes, mode and sha256 of the exact LF bytes stored in git), an explicit delta, and for the utility: its own files
 * with hashes and only its lines in the shared files (functions.php include, catalogue entry).
 * Base = what closed staging will run before this package: the theme of integration/tools-release-1.3 at 835bb53 (equal
 * to the tools-release-1.3 manifest target) with the Codex Hub redesign overlaid (feat/tools-hub-cyber-glass 0a32f12, the
 * Hub installed on staging: its theme files that differ from its base 24a333d). The overlay is only valid while 1.2/1.3
 * leave those Hub files untouched; this is checked.
 * Hub previews are grouped by the package that ships them: tools 5-7 -> deploy/tools-hub-previews-5-7 (Codex, tools on
 * staging), tools 8-10 -> deploy/tools-release-1.3/hub-previews.json, the utility's preview -> this package.
 *   node deploy/tools-utilities-1/build-manifest.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE_COMMIT = '835bb53448ea76b207c23f9ac94e8209d1e4f1f0';
const HUB_COMMIT = '0a32f1234e596c425cda58b096ea1e085147386f';
const HUB_FROM = '24a333ddf2f91499b0b693f3810181990f8ec8e4';
const THEME = 'wp-content/themes/cyberdat/';
const ROOT = path.join(__dirname, '../..');
const sh = c => cp.execSync(c, { cwd: ROOT, maxBuffer: 1 << 28 });
const CHECK = process.argv.includes('--check');
const commit = sh('git rev-parse ' + (process.argv.slice(2).find(x => !x.startsWith('--')) || 'HEAD')).toString().trim();
const blob = (rev, p) => sh('git cat-file blob ' + rev + ':' + p);
function tree(rev) {
	const out = {};
	for (const line of sh('git ls-tree -r -z ' + rev + ' -- ' + THEME).toString().split('\0').filter(Boolean)) {
		const [meta, p] = line.split('\t');
		const buf = sh('git cat-file blob ' + meta.split(' ')[2]);
		out[p.slice(THEME.length)] = { bytes: buf.length, mode: '0644', sha256: crypto.createHash('sha256').update(buf).digest('hex') };
	}
	return Object.fromEntries(Object.entries(out).sort(([a], [b]) => (a < b ? -1 : 1)));
}
const base13 = tree(BASE_COMMIT);
const parent = JSON.parse(fs.readFileSync(path.join(ROOT, 'deploy/tools-release-1.3/manifest.json'), 'utf8'));
if (JSON.stringify(base13) !== JSON.stringify(parent.target)) { throw new Error('base theme differs from the tools-release-1.3 manifest target'); }
const hubFull = sh('git rev-parse ' + HUB_COMMIT).toString().trim();
const hubFrom = tree(HUB_FROM), hubTree = tree(hubFull);
const hubDelta = Object.keys(hubTree).filter(k => !hubFrom[k] || hubFrom[k].sha256 !== hubTree[k].sha256);
if (Object.keys(hubFrom).some(k => !hubTree[k])) { throw new Error('the Hub branch removes theme files'); }
for (const k of hubDelta) {
	const a = hubFrom[k] ? hubFrom[k].sha256 : null, b = base13[k] ? base13[k].sha256 : null;
	if (a !== b) { throw new Error('Hub file also changed by releases 1.2/1.3, overlay invalid: ' + k); }
}
const base = Object.fromEntries(Object.entries(Object.assign({}, base13, Object.fromEntries(hubDelta.map(k => [k, hubTree[k]])))).sort(([a], [b]) => (a < b ? -1 : 1)));
const target = tree(commit);
const added = Object.keys(target).filter(k => !base[k]);
const removed = Object.keys(base).filter(k => !target[k]);
const modified = Object.keys(target).filter(k => base[k] && base[k].sha256 !== target[k].sha256);
const T = { slug: 'email-header-analyzer', title: 'Email Header Analyzer', dir: 'email-header-analyzer', inc: 'tool-email-header-analyzer.php', css: 'email-header-analyzer.css' };
const PREVIEW = 'assets/images/tools-hub/';
const mine = added.filter(k => k === 'inc/' + T.inc || k === 'assets/css/' + T.css || k === 'template-parts/tools/' + T.slug + '.php' || k.startsWith('assets/js/' + T.dir + '/'));
const myPreview = PREVIEW + T.slug + '.svg';
const stray = added.filter(k => !mine.includes(k) && k !== myPreview);
if (stray.length || !added.includes(myPreview)) { throw new Error('added files must be the utility and its preview: ' + stray.join(', ')); }
const PREVIEW_GROUPS = {
	'tools-hub-previews-5-7': ['agent-leak-inspector', 'ai-model-bom', 'mitre-atlas-mapper'].map(x => PREVIEW + x + '.svg').concat([PREVIEW + 'README.md']),
	'tools-release-1.3': ['prompt-injection-test-bench', 'yara-sigma-validator', 'container-hardening-audit'].map(x => PREVIEW + x + '.svg')
};
// Owner task 2026-11-21 (blocker of the public launch): secret masking in the exports of tools 2 and 3 on staging.
const MASK = {
	'prompt-injection-detector': { tool: 2, title: 'Indirect Prompt Injection Sanitizer & Detector', engine: 'assets/js/prompt-injection-detector/engine.js', inc: 'inc/tool-prompt-injection-detector.php', template: 'template-parts/tools/prompt-injection-detector.php', constant: 'CYBERDAT_PROMPT_DETECTOR_ENGINE', version: '1.0.4', extra: ['assets/js/prompt-injection-detector/app.js', 'assets/js/prompt-injection-detector/worker.js'] },
	'lotl-command-analyzer': { tool: 3, title: 'LotL / LOLBAS Command Analyzer', engine: 'assets/js/lotl-analyzer/engine.js', inc: 'inc/tool-lotl-analyzer.php', template: 'template-parts/tools/lotl-command-analyzer.php', constant: 'CYBERDAT_LOTL_ENGINE', version: '1.0.1' }
};
const maskFiles = t => [t.engine, t.inc, t.template].concat(t.extra || []);
const MASK_FILES = [].concat(...Object.values(MASK).map(maskFiles));
// Owner decision 2026-11-22: the detector's sanitized copy is masked by default (page switch to show the complete copy); FAQ text updated.
const PI_EDITORIAL = 'deploy/tools-prompt-injection-detector/editorial.json';
const maskBlock = k => { const s = blob(commit, THEME + k).toString('utf8'); const a = s.indexOf('// ---------------------------------------------------------------- secret masking (shared block)'), b = s.indexOf('// ---------------------------------------------------------------- end of secret masking (shared block)'); return a > 0 && b > a ? s.slice(a, b) : ''; };
const blocks = Object.values(MASK).map(t => maskBlock(t.engine));
if (!blocks[0] || blocks[0] !== blocks[1]) { throw new Error('the secret masking block must be present and equal in both engines'); }
for (const t of Object.values(MASK)) {
	if (!blob(commit, THEME + t.engine).toString('utf8').includes("const VERSION = '" + t.version + "';") || !blob(commit, THEME + t.inc).toString('utf8').includes('const ' + t.constant + " = '" + t.version + "';")) { throw new Error('engine version ' + t.version + ' expected in ' + t.engine + ' and ' + t.inc); }
}
const expectMod = ['functions.php', 'inc/tools-catalog.json', 'inc/tools.php', 'page-templates/tools.php'].concat(MASK_FILES, ...Object.values(PREVIEW_GROUPS)).sort();
if (modified.join() !== expectMod.join() || removed.length) { throw new Error('unexpected modified/removed files: ' + modified.concat(removed).join(', ')); }
const fn = blob(commit, THEME + 'functions.php').toString('utf8').split('\n');
const fnBase = blob(BASE_COMMIT, THEME + 'functions.php').toString('utf8').split('\n');
const include = "require_once __DIR__ . '/inc/" + T.inc + "';";
const li = fn.findIndex(l => l.trim() === include);
const fnAdded = fn.filter(l => !fnBase.includes(l)).map(l => l.trim()).filter(Boolean);
if (li < 0 || fnAdded.length !== 1) { throw new Error('functions.php must gain exactly the one include line'); }
const cat = JSON.parse(blob(commit, THEME + 'inc/tools-catalog.json').toString('utf8'));
const catBase = JSON.parse(blob(BASE_COMMIT, THEME + 'inc/tools-catalog.json').toString('utf8'));
// Owner decision 2026-11-21: the installed catalogue gives the final statuses (tools 1-10 and the utility "available"), so the
// installer never edits theme files; the ten entries differ from the base only in status.
const noStatus = e => Object.assign({}, e, { status: null });
if (cat.length !== catBase.length + 1 || cat.slice(0, catBase.length).some((e, i) => JSON.stringify(noStatus(e)) !== JSON.stringify(noStatus(catBase[i])))) { throw new Error('the ten catalogue entries may change only in status, and exactly one entry is added'); }
if (cat.some(e => e.status !== 'available')) { throw new Error('every catalogue entry must be available in this package'); }
const statusChanges = cat.slice(0, catBase.length).filter((e, i) => e.status !== catBase[i].status).map(e => ({ slug: e.slug, from: catBase.find(b => b.slug === e.slug).status, to: e.status }));
const entry = cat[cat.length - 1];
if (entry.slug !== T.slug) { throw new Error('catalogue entry must be the utility'); }
const toolsPhp = blob(commit, THEME + 'inc/tools.php').toString('utf8');
const canonFn = toolsPhp.slice(toolsPhp.indexOf('function cyberdat_tools_staging_canonical()'), toolsPhp.indexOf("add_action( 'rank_math/head', 'cyberdat_tools_staging_canonical'"));
if (!canonFn.includes("'available' === $tool['status']") || /'(?:log-anonymizer|mcp-security-checker|agent-leak-inspector)'/.test(canonFn)) { throw new Error('the staging canonical must take its slugs from the catalogue'); }
const hubNow = blob(commit, THEME + 'page-templates/tools.php').toString('utf8').split(String.fromCharCode(10)), hubBase = blob(hubFull, THEME + 'page-templates/tools.php').toString('utf8').split(String.fromCharCode(10));
const hubChanged = hubNow.map((l, i) => [i, l]).filter(([i, l]) => l !== hubBase[i]);
if (hubNow.length !== hubBase.length || hubChanged.length !== 1) { throw new Error('page-templates/tools.php must change in exactly one line'); }
const PSL_FILES = ['assets/js/email-header-analyzer/public_suffix_list.dat', 'assets/js/email-header-analyzer/psl-data.js', 'assets/js/email-header-analyzer/LICENSE-MPL-2.0.txt'];
const manifest = {
	schema: 'cyberdat-theme-release/1',
	revision: 'tools-utilities-1/1',
	parent_revision: parent.revision,
	parent_theme_commit: parent.theme_commit,
	base_commit: BASE_COMMIT,
	hub_commit: hubFull,
	hub_overlay: hubDelta,
	theme_commit: commit,
	install_rule: 'The installer copies the target files as they are and changes no theme file (no prepare step that edits inc/tools.php, inc/tools-catalog.json or any other file). After installation every theme file on staging equals the target map of this manifest, byte for byte. Catalogue statuses and the staging canonical scope are part of the package.',
	staging_known_differences: { source: 'Codex, 2026-11-21: prepare.py of the 1.2 installer (archive 178eb167…) edited two theme files on staging; staging equals that archive byte for byte. Not verified here (no staging access).', 'inc/tools-catalog.json': 'status planned -> available for agent-leak-inspector, ai-model-bom, mitre-atlas-mapper', 'inc/tools.php': 'cyberdat_tools_staging_canonical(): slug list extended by agent-leak-inspector, ai-model-bom, mitre-atlas-mapper', effect: 'base_sha256 of these two files on staging differs from the base map; both files are replaced as a whole by the target bytes (the target already contains these effects and the statuses of tools 8-10 and the utility).' },
	note: 'Theme delta for quick utility 1 (Email Header Analyzer) over tools-release-1.3/1 plus the Codex Hub on staging (hub_commit; hub_overlay lists its files): the utility\'s files and its Hub preview (including the unmodified Public Suffix List data file, its JS carrier and the MPL-2.0 license text, which must be published together), one functions.php include, one catalogue entry appended (kind utility) and the final statuses: tools 1-10 and the utility "available" (the ten entries otherwise unchanged), inc/tools.php: the staging canonical takes its pages from the catalogue (status available) instead of a slug list, one line of the staging Hub template so that utility cards read "Quick utility" instead of Phase/Release, secret masking in the page and exports of tools 2 and 3 (secret_masking: two engines, their version constants and one help text each; for the detector also app.js and worker.js: the sanitized copy is masked by default, with a switch to show the complete copy; sanitized_copy_editorial: the FAQ text). hub_previews also lists the redrawn previews of tools 5-10 by the package that ships them (base_sha256 = staging Hub version). Hashes are of the LF bytes in git (git -c core.autocrlf=false archive). No archive is built here: Codex builds and seals the archive with its own release tooling.',
	counts: { base: Object.keys(base).length, target: Object.keys(target).length, added: added.length, modified: modified.length, removed: removed.length },
	delta: { added, modified, removed },
	delta_files: Object.fromEntries(added.concat(modified).sort().map(k => [k, Object.assign({ status: base[k] ? 'modified' : 'added', bytes: target[k].bytes, sha256: target[k].sha256 }, base[k] ? { base_sha256: base[k].sha256 } : {})])),
	tools: {
		[T.slug]: {
			utility: 1, title: T.title, url: entry.url,
			files: Object.fromEntries(mine.map(k => [k, { bytes: target[k].bytes, sha256: target[k].sha256 }])),
			hub_preview: { [myPreview]: { bytes: target[myPreview].bytes, sha256: target[myPreview].sha256 } },
			mpl_files_publish_together: PSL_FILES,
			shared: {
				'functions.php': { add_line: include, after_line: fn[li - 1].trim(), line_number: li + 1 },
				'inc/tools-catalog.json': { append_entry: entry, position: 'after the ten tools (index ' + (cat.length - 1) + ')', status_changes: statusChanges, replace_whole_file: true },
				'inc/tools.php': { change: 'cyberdat_tools_staging_canonical(): pages with catalogue status available instead of a hand-written slug list; other checks unchanged', replace_whole_file: true },
				'page-templates/tools.php': { replace_line_number: hubChanged[0][0] + 1, from: hubBase[hubChanged[0][0]].trim(), to: hubChanged[0][1].trim(), effect: 'cards with kind=utility read "Quick utility"; all other cards unchanged' }
			}
		}
	},
	secret_masking: {
		task: 'Owner task 2026-11-21: tools 2 and 3 on staging showed and exported secrets in finding excerpts and quoted commands (blocker of the public launch).',
		change: 'One shared masking block in both engines (the same block, checked): known formats, JWT, private key blocks, values after credential/password/secret/token/api key/authorization/cookie keys whatever their length, Bearer/Basic, password options (/pass:, /rp, -Password, -u user:password, ConvertTo-SecureString), credentials, secret query values (percent escapes decoded) and token-like path segments in addresses, long opaque values. The whole text is masked before it is cut. Detection runs on the original text and is unchanged (corpus and held-out outputs identical).',
		tools: Object.fromEntries(Object.entries(MASK).map(([slug, t]) => [slug, { tool: t.tool, title: t.title, engine_version: t.version, masked: slug === 'lotl-command-analyzer' ? 'command line, normalized command, deobfuscation notes, binary as written, heuristic details, decoded commands and their nested analysis (page and JSON report)' : 'finding excerpts, quoted text in details (normalized, decoded, hidden, comment text), decoded fragment previews (page and JSON report); the sanitized copy by default (on screen, Copy and Download; masked after sanitization)', not_masked: slug === 'lotl-command-analyzer' ? '' : 'the highlighted text: it is the complete text the user pasted (the page says so); the sanitized copy only while the user switches on "Do not mask secrets in the sanitized copy" (off on every page load, warning shown)', files: Object.fromEntries(maskFiles(t).map(k => [k, { bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: base[k].sha256 }])) }]))
	},
	sanitized_copy_editorial: (() => { const b = blob(commit, PI_EDITORIAL); return { path: PI_EDITORIAL, fields: ['how_it_works', 'faq'], change: 'describe the masked sanitized copy and the switch (owner decision 2026-11-22); set by Codex on the existing page meta', bytes: b.length, sha256: crypto.createHash('sha256').update(b).digest('hex') }; })(),
	hub_previews: Object.fromEntries(Object.entries(PREVIEW_GROUPS).map(([pkg, files]) => [pkg, Object.fromEntries(files.map(k => [k, { bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: base[k].sha256 }]))])),
	base,
	target
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const same = JSON.stringify(current.target) === JSON.stringify(target) && JSON.stringify(current.delta) === JSON.stringify(manifest.delta) && JSON.stringify(current.tools) === JSON.stringify(manifest.tools) && JSON.stringify(current.hub_previews) === JSON.stringify(manifest.hub_previews) && JSON.stringify(current.secret_masking) === JSON.stringify(manifest.secret_masking) && JSON.stringify(current.sanitized_copy_editorial) === JSON.stringify(manifest.sanitized_copy_editorial);
	console.log(same ? 'PASS: tools-utilities-1 manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: tools-utilities-1 manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12) + '; utility files: ' + mine.length);
