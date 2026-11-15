/*
 * Builds deploy/tools-release-1.2/manifest.json in the release-1 manifest shape (base/target maps of every theme
 * file with bytes, mode and sha256 of the exact LF bytes stored in git) plus an explicit delta.
 * Base = the tools-la-unicode-marks/1 target (1b0651c, verified byte-equal to deploy/tools-la-unicode-marks/manifest.json target).
 * The delta (added and modified files with hashes) is what Codex applies on top of the current staging theme.
 *   node deploy/tools-release-1.2/build-manifest.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE_COMMIT = '1b0651ccec38022fe4a23ac128a61a106e442469';
const RELEASE1_COMMIT = '24a333ddf2f91499b0b693f3810181990f8ec8e4';
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
const parent = JSON.parse(fs.readFileSync(path.join(ROOT, 'deploy/tools-la-unicode-marks/manifest.json'), 'utf8'));
if (JSON.stringify(base) !== JSON.stringify(parent.target)) { throw new Error('base theme differs from the tools-la-unicode-marks manifest target'); }
const release1 = tree(RELEASE1_COMMIT);
const cumulative = Object.keys(target).filter(k => !release1[k] || release1[k].sha256 !== target[k].sha256);
const added = Object.keys(target).filter(k => !base[k]);
const removed = Object.keys(base).filter(k => !target[k]);
const modified = Object.keys(target).filter(k => base[k] && base[k].sha256 !== target[k].sha256);
const manifest = {
	schema: 'cyberdat-theme-release/1',
	revision: 'tools-release-1.2/1',
	parent_revision: parent.revision,
	parent_theme_commit: parent.theme_commit,
	release1_commit: RELEASE1_COMMIT,
	base_commit: BASE_COMMIT,
	theme_commit: commit,
	note: 'Theme delta for release 1.2 tools 5 (System Prompt & Agent Leak Inspector) and 6 (AI Model Bill of Materials) over tools-la-unicode-marks/1: new tool files, two functions.php includes, two catalogue descriptions (status planned). cumulative = files that differ from the installed release-1 theme. Hashes are of the LF bytes in git (git -c core.autocrlf=false archive). No archive is built here: Codex builds and seals the archive with its own release tooling.',
	counts: { base: Object.keys(base).length, target: Object.keys(target).length, added: added.length, modified: modified.length, removed: removed.length },
	delta: { added, modified, removed },
	delta_files: Object.fromEntries(added.concat(modified).sort().map(k => [k, Object.assign({ status: base[k] ? 'modified' : 'added', bytes: target[k].bytes, sha256: target[k].sha256 }, base[k] ? { base_sha256: base[k].sha256 } : {})])),
	cumulative_vs_release1: cumulative,
	base,
	target
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const same = JSON.stringify(current.target) === JSON.stringify(target) && JSON.stringify(current.delta) === JSON.stringify(manifest.delta);
	console.log(same ? 'PASS: tools-release-1.2 manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: tools-release-1.2 manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12));
