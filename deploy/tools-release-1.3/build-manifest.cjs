/*
 * Builds deploy/tools-release-1.3/manifest.json in the release-1 manifest shape (base/target maps of every theme file
 * with bytes, mode and sha256 of the exact LF bytes stored in git), an explicit delta, and per tool: its own files with
 * hashes and only its lines in the shared files (functions.php include, catalogue entry).
 * Base = integration/tools-release-1.2 tip 2a4cfbe, whose theme is byte-equal to the tools-release-1.2/1 manifest target.
 *   node deploy/tools-release-1.3/build-manifest.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE_COMMIT = '2a4cfbe8a7ff94508944eb4fd67a4755ffa8ae2f';
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
const TOOLS = [
	{ n: 8, slug: 'prompt-injection-test-bench', title: 'LLM Prompt Injection Test Bench', dir: 'prompt-injection-test-bench', inc: 'tool-prompt-injection-test-bench.php', css: 'prompt-injection-test-bench.css' },
	{ n: 9, slug: 'yara-sigma-validator', title: 'YARA/Sigma Rule Validator & Converter', dir: 'yara-sigma-validator', inc: 'tool-yara-sigma-validator.php', css: 'yara-sigma-validator.css' },
	{ n: 10, slug: 'container-hardening-audit', title: 'Docker & Kubernetes Hardening Audit Generator', dir: 'container-hardening-audit', inc: 'tool-container-hardening-audit.php', css: 'container-hardening-audit.css' }
];
const base = tree(BASE_COMMIT);
const parent = JSON.parse(fs.readFileSync(path.join(ROOT, 'deploy/tools-release-1.2/manifest.json'), 'utf8'));
if (JSON.stringify(base) !== JSON.stringify(parent.target)) { throw new Error('base theme differs from the tools-release-1.2 manifest target'); }
const target = tree(commit);
const added = Object.keys(target).filter(k => !base[k]);
const removed = Object.keys(base).filter(k => !target[k]);
const modified = Object.keys(target).filter(k => base[k] && base[k].sha256 !== target[k].sha256);
const fn = blob(commit, THEME + 'functions.php').toString('utf8').split('\n');
const fnBase = blob(BASE_COMMIT, THEME + 'functions.php').toString('utf8').split('\n');
const cat = JSON.parse(blob(commit, THEME + 'inc/tools-catalog.json').toString('utf8'));
const catBase = JSON.parse(blob(BASE_COMMIT, THEME + 'inc/tools-catalog.json').toString('utf8'));
const entries = c => (Array.isArray(c) ? c : c.tools);
const owned = new Set();
const tools = {};
for (const t of TOOLS) {
	const mine = added.filter(k => k === 'inc/' + t.inc || k === 'assets/css/' + t.css || k === 'template-parts/tools/' + t.slug + '.php' || k.startsWith('assets/js/' + t.dir + '/'));
	mine.forEach(k => owned.add(k));
	const include = "require_once __DIR__ . '/inc/" + t.inc + "';";
	const li = fn.findIndex(l => l.trim() === include);
	if (li < 0) { throw new Error('functions.php lacks ' + include); }
	const now = entries(cat).find(e => e.slug === t.slug), was = entries(catBase).find(e => e.slug === t.slug);
	if (!now || now.status !== 'planned') { throw new Error(t.slug + ' catalogue status must stay planned'); }
	const changed = Object.keys(now).filter(k => JSON.stringify(now[k]) !== JSON.stringify(was[k]));
	if (changed.join() !== 'description') { throw new Error(t.slug + ': catalogue fields changed other than description: ' + changed.join()); }
	tools[t.slug] = {
		tool: t.n, title: t.title, url: now.url,
		files: Object.fromEntries(mine.map(k => [k, { bytes: target[k].bytes, sha256: target[k].sha256 }])),
		shared: {
			'functions.php': { add_line: include, after_line: fn[li - 1].trim(), line_number: li + 1 },
			'inc/tools-catalog.json': { slug: t.slug, field: 'description', from: was.description, to: now.description, status: now.status }
		}
	};
}
const stray = added.filter(k => !owned.has(k));
if (stray.length) { throw new Error('added files not owned by a tool: ' + stray.join(', ')); }
if (modified.join() !== 'functions.php,inc/tools-catalog.json' || removed.length) { throw new Error('unexpected modified/removed files: ' + modified.concat(removed).join(', ')); }
const fnAdded = fn.filter(l => !fnBase.includes(l)).map(l => l.trim()).filter(Boolean);
if (fnAdded.length !== 3) { throw new Error('functions.php must gain exactly three include lines, got ' + fnAdded.length); }
const manifest = {
	schema: 'cyberdat-theme-release/1',
	revision: 'tools-release-1.3/1',
	parent_revision: parent.revision,
	parent_theme_commit: parent.theme_commit,
	base_commit: BASE_COMMIT,
	theme_commit: commit,
	note: 'Theme delta for release 1.3 tools 8 (LLM Prompt Injection Test Bench), 9 (YARA/Sigma Rule Validator & Converter) and 10 (Docker & Kubernetes Hardening Audit Generator) over tools-release-1.2/1: new tool files, three functions.php includes, three catalogue descriptions (status planned). "tools" lists each tool\'s own files and only its lines in the shared files, so a tool can be installed alone. Hashes are of the LF bytes in git (git -c core.autocrlf=false archive). No archive is built here: Codex builds and seals the archive with its own release tooling.',
	counts: { base: Object.keys(base).length, target: Object.keys(target).length, added: added.length, modified: modified.length, removed: removed.length },
	delta: { added, modified, removed },
	delta_files: Object.fromEntries(added.concat(modified).sort().map(k => [k, Object.assign({ status: base[k] ? 'modified' : 'added', bytes: target[k].bytes, sha256: target[k].sha256 }, base[k] ? { base_sha256: base[k].sha256 } : {})])),
	tools,
	base,
	target
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const same = JSON.stringify(current.target) === JSON.stringify(target) && JSON.stringify(current.delta) === JSON.stringify(manifest.delta) && JSON.stringify(current.tools) === JSON.stringify(tools);
	console.log(same ? 'PASS: tools-release-1.3 manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: tools-release-1.3 manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12) + '; per tool: ' + TOOLS.map(t => t.slug + ' ' + Object.keys(tools[t.slug].files).length).join(', '));
