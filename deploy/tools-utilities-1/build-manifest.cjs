/*
 * Builds deploy/tools-utilities-1/manifest.json, revision tools-utilities-1/3, in the release-1 manifest shape (base/target
 * maps of every theme file with bytes, mode and sha256 of the exact LF bytes stored in git) and an explicit delta.
 * Base = the theme that runs on closed staging since 2026-11-23: integration/tools-utilities-1 at 7b9bee5 (installed by
 * Codex, 188/188 theme files equal to 7b9bee5). So base_sha256 of every modified file is the staging version.
 * Target = this branch. The delta may contain only files of the Email Header Analyzer (owner task 2026-11-23: strict
 * punycode, rules 2026-11-23.1); nothing is added or removed.
 * Revision 2 (base = staging snapshot cd06239, theme 3082f05, 29 added + 22 modified) is installed; it stays in git history.
 *   node deploy/tools-utilities-1/build-manifest.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE_COMMIT = '7b9bee515ab906805eec99af12e0f7683954eec1';
const BASE_REF = 'integration/tools-utilities-1@7b9bee5 (staging theme since 2026-11-23)';
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
if (Object.keys(base).length !== 188) { throw new Error('the staging theme (7b9bee5) has 188 files'); }
const added = Object.keys(target).filter(k => !base[k]);
const removed = Object.keys(base).filter(k => !target[k]);
const modified = Object.keys(target).filter(k => base[k] && base[k].sha256 !== target[k].sha256);

// Only Email Header Analyzer files may change.
const T = { slug: 'email-header-analyzer', title: 'Email Header Analyzer', engine: 'assets/js/email-header-analyzer/engine.js', inc: 'inc/tool-email-header-analyzer.php' };
const isEha = k => k.startsWith('assets/js/' + T.slug + '/') || k === T.inc || k === 'template-parts/tools/' + T.slug + '.php' || k === 'assets/css/' + T.slug + '.css';
if (added.length || removed.length) { throw new Error('nothing may be added or removed: ' + added.concat(removed).join(', ')); }
const foreign = modified.filter(k => !isEha(k));
if (foreign.length) { throw new Error('only Email Header Analyzer files may change: ' + foreign.join(', ')); }
const EXPECT = [T.engine, T.inc];
if (modified.join() !== EXPECT.join()) { throw new Error('expected exactly the engine and its PHP constants to change: ' + modified.join(', ')); }
const engine = blob(commit, THEME + T.engine).toString('utf8');
const incPhp = blob(commit, THEME + T.inc).toString('utf8');
const ver = (s, re) => { const m = s.match(re); return m ? m[1] : null; };
const RULES = { from: ver(blob(BASE_COMMIT, THEME + T.engine).toString('utf8'), /const RULESET = '([^']+)';/), to: ver(engine, /const RULESET = '([^']+)';/) };
const ENGINE = ver(engine, /const ENGINE = '([^']+)';/);
if (RULES.to !== '2026-11-23.1' || ver(incPhp, /const CYBERDAT_EHA_RULESET = '([^']+)';/) !== RULES.to || ver(incPhp, /const CYBERDAT_EHA_ENGINE = '([^']+)';/) !== ENGINE) { throw new Error('rules 2026-11-23.1 and the engine version must be equal in the engine and in ' + T.inc); }
// Applying the delta to the staging base must give exactly the target map.
const applied = Object.assign({}, base);
for (const k of modified) { applied[k] = target[k]; }
if (JSON.stringify(Object.fromEntries(Object.entries(applied).sort(([a], [b]) => (a < b ? -1 : 1)))) !== JSON.stringify(target)) { throw new Error('base + delta does not give the target'); }
const fileMap = ks => Object.fromEntries(ks.map(k => [k, { bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: base[k].sha256 }]));
const manifest = {
	schema: 'cyberdat-theme-release/1',
	revision: 'tools-utilities-1/3',
	base_commit: BASE_COMMIT,
	base_ref: BASE_REF,
	base_note: 'Base = the staging theme after the installation of tools-utilities-1/2 (Codex 2026-11-23: 188/188 theme files equal to 7b9bee5). base_sha256 of every modified file is the staging version.',
	previous_revision: { revision: 'tools-utilities-1/2', base_commit: 'cd06239d39e6a81139e7fec843412f86f0de0140', theme_commit: '3082f05e46ea5558fe6262a5817f64a2d62a918c', manifest_sha256: '7cd76a8f991ee8fbda08ef27c25f19f577119cb6f51c1986533595d2bb7b828e', status: 'installed on staging (Codex, 2026-11-23)' },
	theme_commit: commit,
	install_rule: 'The installer copies the delta files as they are and changes no other theme file. Before installing, every theme file on staging equals the base map; after installing, every theme file equals the target map of this manifest, byte for byte.',
	note: 'Email Header Analyzer only: strict punycode (an xn-- label that is not valid punycode stays in ASCII and is named as invalid in the EHA-LOOK-001 evidence; no control or invisible characters in the output; EHA-LOOK-002 cannot pass such a label silently); rules ' + RULES.from + ' -> ' + RULES.to + ', engine ' + ENGINE + ' unchanged. No new finding ids; the frozen rules.json catalogue is unchanged. Hashes are of the LF bytes in git (git -c core.autocrlf=false archive). No archive is built here: Codex builds and seals the archive with its own release tooling.',
	counts: { base: Object.keys(base).length, target: Object.keys(target).length, added: 0, modified: modified.length, removed: 0 },
	delta: { added, modified, removed },
	delta_files: Object.fromEntries(modified.map(k => [k, { status: 'modified', bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: base[k].sha256 }])),
	tools: { [T.slug]: { utility: 1, title: T.title, engine_version: ENGINE, rules: RULES, files: fileMap(modified) } },
	base,
	target
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const keys = ['revision', 'base', 'target', 'delta', 'delta_files', 'tools', 'previous_revision'];
	const same = current.base_commit === BASE_COMMIT && keys.every(k => JSON.stringify(current[k]) === JSON.stringify(manifest[k]));
	console.log(same ? 'PASS: tools-utilities-1 manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: tools-utilities-1 manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12) + '; delta: ' + modified.join(', '));
