/*
 * Builds deploy/tools-utilities-1/manifest.json in the release-1 manifest shape (base/target maps of every theme file
 * with bytes, mode and sha256 of the exact LF bytes stored in git), an explicit delta, and for the utility: its own files
 * with hashes and only its lines in the shared files (functions.php include, catalogue entry).
 * Base = what closed staging will run before this package: the theme of integration/tools-release-1.3 at e1bff4e (equal
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

const BASE_COMMIT = 'e1bff4ecdf925745be28e31781c6b4dd2585fd70';
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
const expectMod = ['functions.php', 'inc/tools-catalog.json', 'page-templates/tools.php'].concat(...Object.values(PREVIEW_GROUPS)).sort();
if (modified.join() !== expectMod.join() || removed.length) { throw new Error('unexpected modified/removed files: ' + modified.concat(removed).join(', ')); }
const fn = blob(commit, THEME + 'functions.php').toString('utf8').split('\n');
const fnBase = blob(BASE_COMMIT, THEME + 'functions.php').toString('utf8').split('\n');
const include = "require_once __DIR__ . '/inc/" + T.inc + "';";
const li = fn.findIndex(l => l.trim() === include);
const fnAdded = fn.filter(l => !fnBase.includes(l)).map(l => l.trim()).filter(Boolean);
if (li < 0 || fnAdded.length !== 1) { throw new Error('functions.php must gain exactly the one include line'); }
const cat = JSON.parse(blob(commit, THEME + 'inc/tools-catalog.json').toString('utf8'));
const catBase = JSON.parse(blob(BASE_COMMIT, THEME + 'inc/tools-catalog.json').toString('utf8'));
if (JSON.stringify(cat.slice(0, catBase.length)) !== JSON.stringify(catBase) || cat.length !== catBase.length + 1) { throw new Error('the ten catalogue entries must be unchanged and exactly one entry added'); }
const entry = cat[cat.length - 1];
if (entry.slug !== T.slug || entry.status !== 'planned') { throw new Error('catalogue entry must be the utility, status planned'); }
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
	note: 'Theme delta for quick utility 1 (Email Header Analyzer) over tools-release-1.3/1 plus the Codex Hub on staging (hub_commit; hub_overlay lists its files): the utility\'s files and its Hub preview (including the unmodified Public Suffix List data file, its JS carrier and the MPL-2.0 license text, which must be published together), one functions.php include, one catalogue entry appended (kind utility, status planned; the ten entries unchanged), one line of the staging Hub template so that utility cards read "Quick utility" instead of Phase/Release. hub_previews also lists the redrawn previews of tools 5-10 by the package that ships them (base_sha256 = staging Hub version). Hashes are of the LF bytes in git (git -c core.autocrlf=false archive). No archive is built here: Codex builds and seals the archive with its own release tooling.',
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
				'inc/tools-catalog.json': { append_entry: entry, position: 'after the ten tools (index ' + (cat.length - 1) + ')' },
				'page-templates/tools.php': { replace_line_number: hubChanged[0][0] + 1, from: hubBase[hubChanged[0][0]].trim(), to: hubChanged[0][1].trim(), effect: 'cards with kind=utility read "Quick utility"; all other cards unchanged' }
			}
		}
	},
	hub_previews: Object.fromEntries(Object.entries(PREVIEW_GROUPS).map(([pkg, files]) => [pkg, Object.fromEntries(files.map(k => [k, { bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: base[k].sha256 }]))])),
	base,
	target
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const same = JSON.stringify(current.target) === JSON.stringify(target) && JSON.stringify(current.delta) === JSON.stringify(manifest.delta) && JSON.stringify(current.tools) === JSON.stringify(manifest.tools) && JSON.stringify(current.hub_previews) === JSON.stringify(manifest.hub_previews);
	console.log(same ? 'PASS: tools-utilities-1 manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: tools-utilities-1 manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12) + '; utility files: ' + mine.length);
