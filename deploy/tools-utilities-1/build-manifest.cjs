/*
 * Builds deploy/tools-utilities-1/manifest.json in the release-1 manifest shape (base/target maps of every theme file
 * with bytes, mode and sha256 of the exact LF bytes stored in git), an explicit delta, and for the utility: its own files
 * with hashes and only its lines in the shared files (functions.php include, catalogue entry).
 * Base = integration/tools-release-1.3 tip 58ed710, whose theme equals the tools-release-1.3 manifest target.
 *   node deploy/tools-utilities-1/build-manifest.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE_COMMIT = '58ed71050440ff48204620b38dd465a9c521a21f';
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
const base = tree(BASE_COMMIT);
const parent = JSON.parse(fs.readFileSync(path.join(ROOT, 'deploy/tools-release-1.3/manifest.json'), 'utf8'));
if (JSON.stringify(base) !== JSON.stringify(parent.target)) { throw new Error('base theme differs from the tools-release-1.3 manifest target'); }
const target = tree(commit);
const added = Object.keys(target).filter(k => !base[k]);
const removed = Object.keys(base).filter(k => !target[k]);
const modified = Object.keys(target).filter(k => base[k] && base[k].sha256 !== target[k].sha256);
const T = { slug: 'email-header-analyzer', title: 'Email Header Analyzer', dir: 'email-header-analyzer', inc: 'tool-email-header-analyzer.php', css: 'email-header-analyzer.css' };
const mine = added.filter(k => k === 'inc/' + T.inc || k === 'assets/css/' + T.css || k === 'template-parts/tools/' + T.slug + '.php' || k.startsWith('assets/js/' + T.dir + '/'));
const stray = added.filter(k => !mine.includes(k));
if (stray.length) { throw new Error('added files not owned by the utility: ' + stray.join(', ')); }
if (modified.join() !== 'functions.php,inc/tools-catalog.json,page-templates/tools.php' || removed.length) { throw new Error('unexpected modified/removed files: ' + modified.concat(removed).join(', ')); }
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
const hubNow = blob(commit, THEME + 'page-templates/tools.php').toString('utf8').split(String.fromCharCode(10)), hubBase = blob(BASE_COMMIT, THEME + 'page-templates/tools.php').toString('utf8').split(String.fromCharCode(10));
const hubChanged = hubNow.map((l, i) => [i, l]).filter(([i, l]) => l !== hubBase[i]);
if (hubNow.length !== hubBase.length || hubChanged.length !== 1) { throw new Error('page-templates/tools.php must change in exactly one line'); }
const PSL_FILES = ['assets/js/email-header-analyzer/public_suffix_list.dat', 'assets/js/email-header-analyzer/psl-data.js', 'assets/js/email-header-analyzer/LICENSE-MPL-2.0.txt'];
const manifest = {
	schema: 'cyberdat-theme-release/1',
	revision: 'tools-utilities-1/1',
	parent_revision: parent.revision,
	parent_theme_commit: parent.theme_commit,
	base_commit: BASE_COMMIT,
	theme_commit: commit,
	note: 'Theme delta for quick utility 1 (Email Header Analyzer) over tools-release-1.3/1: the utility\'s files (including the unmodified Public Suffix List data file, its JS carrier and the MPL-2.0 license text, which must be published together), one functions.php include, one catalogue entry appended (kind utility, status planned; the ten entries unchanged), one hub template line so that utility cards read "Quick utility" instead of Phase/Release. Hashes are of the LF bytes in git (git -c core.autocrlf=false archive). No archive is built here: Codex builds and seals the archive with its own release tooling.',
	counts: { base: Object.keys(base).length, target: Object.keys(target).length, added: added.length, modified: modified.length, removed: removed.length },
	delta: { added, modified, removed },
	delta_files: Object.fromEntries(added.concat(modified).sort().map(k => [k, Object.assign({ status: base[k] ? 'modified' : 'added', bytes: target[k].bytes, sha256: target[k].sha256 }, base[k] ? { base_sha256: base[k].sha256 } : {})])),
	tools: {
		[T.slug]: {
			utility: 1, title: T.title, url: entry.url,
			files: Object.fromEntries(mine.map(k => [k, { bytes: target[k].bytes, sha256: target[k].sha256 }])),
			mpl_files_publish_together: PSL_FILES,
			shared: {
				'functions.php': { add_line: include, after_line: fn[li - 1].trim(), line_number: li + 1 },
				'inc/tools-catalog.json': { append_entry: entry, position: 'after the ten tools (index ' + (cat.length - 1) + ')' },
				'page-templates/tools.php': { replace_line_number: hubChanged[0][0] + 1, from: hubBase[hubChanged[0][0]].trim(), to: hubChanged[0][1].trim(), effect: 'cards with kind=utility read "Quick utility"; all other cards unchanged' }
			}
		}
	},
	base,
	target
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const same = JSON.stringify(current.target) === JSON.stringify(target) && JSON.stringify(current.delta) === JSON.stringify(manifest.delta) && JSON.stringify(current.tools) === JSON.stringify(manifest.tools);
	console.log(same ? 'PASS: tools-utilities-1 manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: tools-utilities-1 manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12) + '; utility files: ' + mine.length);
