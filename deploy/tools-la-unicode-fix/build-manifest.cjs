/*
 * Builds deploy/tools-la-unicode-fix/manifest.json in the release-1 manifest shape (base/target maps of every theme
 * file with bytes, mode and sha256 of the exact LF bytes stored in git) plus an explicit delta.
 * Base = the installed staging theme (release-1 target, verified byte-equal to the release-1 manifest).
 *   node deploy/tools-la-unicode-fix/build-manifest.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE_COMMIT = '24a333ddf2f91499b0b693f3810181990f8ec8e4';
const THEME = 'wp-content/themes/cyberdat/';
const ROOT = path.join(__dirname, '../..');
const sh = c => cp.execSync(c, { cwd: ROOT, maxBuffer: 1 << 28 });
const CHECK = process.argv.includes('--check');
const commit = sh('git rev-parse ' + (process.argv.slice(2).find(x => !x.startsWith('--')) || 'HEAD')).toString().trim();
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
const target = tree(commit);
const release1 = JSON.parse(fs.readFileSync(path.join(ROOT, 'deploy/tools-release-1/manifest.json'), 'utf8'));
const sameAsRelease1 = JSON.stringify(Object.keys(base).sort()) === JSON.stringify(Object.keys(release1.target).sort()) && Object.keys(base).every(k => base[k].sha256 === release1.target[k].sha256 && base[k].bytes === release1.target[k].bytes);
if (!sameAsRelease1) { throw new Error('base theme differs from the release-1 manifest target'); }
const added = Object.keys(target).filter(k => !base[k]);
const removed = Object.keys(base).filter(k => !target[k]);
const modified = Object.keys(target).filter(k => base[k] && base[k].sha256 !== target[k].sha256);
const manifest = {
	schema: 'cyberdat-theme-release/1',
	revision: 'tools-la-unicode-fix/1',
	parent_revision: release1.revision,
	parent_theme_commit: release1.theme_commit,
	base_commit: BASE_COMMIT,
	theme_commit: commit,
	note: 'Theme-only fix over the installed release-1 theme (Log Anonymizer Unicode names, look-behind notice in three tools, MCP limitation). Hashes are of the LF bytes in git (git -c core.autocrlf=false archive). No archive is built here: Codex builds and seals the archive with its own release tooling.',
	counts: { base: Object.keys(base).length, target: Object.keys(target).length, added: added.length, modified: modified.length, removed: removed.length },
	delta: { added, modified, removed },
	base,
	target
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const same = JSON.stringify(current.target) === JSON.stringify(target) && JSON.stringify(current.delta) === JSON.stringify(manifest.delta);
	console.log(same ? 'PASS: la-unicode-fix manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: la-unicode-fix manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12));
