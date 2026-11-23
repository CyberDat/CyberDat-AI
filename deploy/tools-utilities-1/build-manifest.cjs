/*
 * Builds deploy/tools-utilities-1/manifest.json, revision tools-utilities-1/4, in the release-1 manifest shape (base/target
 * maps of every theme file with bytes, mode and sha256 of the exact LF bytes stored in git) and an explicit delta.
 * Base = the theme that runs on closed staging since 2026-11-23: integration/tools-utilities-1 at 73d99a4 (revision 3
 * installed). So base_sha256 of every modified file is the staging version.
 * Target = this branch. Owner task 2026-11-23 "all remaining functional items", by item:
 *   leak_atlas    Leak Inspector and ATLAS mapper rules (engines, version constants, page texts)
 *   large_input   warning before large inputs in the nine tools that accept files (their scripts, tools-common.css)
 *   unkeyed_mask  values without a key in the shared masking block of tools 2 and 3 (engines, version constants)
 * Nothing is added or removed; any other changed theme file stops the build.
 *   node deploy/tools-utilities-1/build-manifest.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE_COMMIT = '73d99a4cb1d60acee957ce55bf59d765286695a9';
const BASE_REF = 'integration/tools-utilities-1@73d99a4 (staging theme since 2026-11-23)';
const THEME = 'wp-content/themes/cyberdat/';
const ROOT = path.join(__dirname, '../..');
const sh = c => cp.execSync(c, { cwd: ROOT, maxBuffer: 1 << 28 });
const CHECK = process.argv.includes('--check');
const commit = sh('git rev-parse ' + (process.argv.slice(2).find(x => !x.startsWith('--')) || 'HEAD')).toString().trim();
const blob = (rev, p) => sh('git cat-file blob ' + rev + ':' + p);
const text = (rev, k) => blob(rev, THEME + k).toString('utf8');
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
if (Object.keys(base).length !== 188) { throw new Error('the staging theme (73d99a4) has 188 files'); }
const added = Object.keys(target).filter(k => !base[k]);
const removed = Object.keys(base).filter(k => !target[k]);
const modified = Object.keys(target).filter(k => base[k] && base[k].sha256 !== target[k].sha256);

const FILE_TOOLS = ['log-anonymizer', 'prompt-injection-detector', 'lotl-analyzer', 'mcp-checker', 'leak-inspector', 'ai-model-bom', 'email-header-analyzer', 'container-hardening-audit', 'prompt-injection-test-bench'];
const ITEMS = {
	leak_atlas: ['assets/js/leak-inspector/engine.js', 'inc/tool-leak-inspector.php', 'template-parts/tools/agent-leak-inspector.php', 'assets/js/atlas-mapper/engine.js', 'inc/tool-atlas-mapper.php', 'template-parts/tools/mitre-atlas-mapper.php'],
	large_input: FILE_TOOLS.map(t => 'assets/js/' + t + '/app.js').concat(['assets/css/tools-common.css']),
	unkeyed_mask: ['assets/js/prompt-injection-detector/engine.js', 'inc/tool-prompt-injection-detector.php', 'assets/js/lotl-analyzer/engine.js', 'inc/tool-lotl-analyzer.php']
};
const expected = [].concat(...Object.values(ITEMS)).sort();
if (added.length || removed.length) { throw new Error('nothing may be added or removed: ' + added.concat(removed).join(', ')); }
if (modified.join() !== expected.join()) { throw new Error('modified files differ from the owner items: ' + modified.filter(k => !expected.includes(k)).concat(expected.filter(k => !modified.includes(k)).map(k => 'missing ' + k)).join(', ')); }
// shared blocks: equal in every copy
const between = (s, a, b) => { const i = s.indexOf(a), j = s.indexOf(b); return i > 0 && j > i ? s.slice(i, j) : ''; };
const MASK = ['// ---------------------------------------------------------------- secret masking (shared block)', '// ---------------------------------------------------------------- end of secret masking (shared block)'];
const masks = ['assets/js/prompt-injection-detector/engine.js', 'assets/js/lotl-analyzer/engine.js'].map(k => between(text(commit, k), ...MASK));
if (!masks[0] || masks[0] !== masks[1] || !masks[0].includes('SECRET_UNKEYED')) { throw new Error('the secret masking block with the rule for values without a key must be equal in tools 2 and 3'); }
const LARGE = ['// ---------------------------------------------------------------- warning before large inputs (shared block)', '// ---------------------------------------------------------------- end of warning before large inputs (shared block)'];
const larges = ITEMS.large_input.filter(k => k.endsWith('app.js')).map(k => between(text(commit, k), ...LARGE));
if (!larges[0] || larges.some(b => b !== larges[0])) { throw new Error('the warning block before large inputs must be equal in the nine tools'); }
// versions: engine and PHP constant agree
const ver = (k, re) => { const m = text(commit, k).match(re); return m ? m[1] : null; };
const VERSIONS = {
	'agent-leak-inspector': { engine: ver('assets/js/leak-inspector/engine.js', /const VERSION = '([^']+)';/), rules: ver('assets/js/leak-inspector/engine.js', /const RULESET_VERSION = '([^']+)';/), php: [ver('inc/tool-leak-inspector.php', /CYBERDAT_LKI_ENGINE = '([^']+)'/), ver('inc/tool-leak-inspector.php', /CYBERDAT_LKI_RULESET = '([^']+)'/)], want: ['1.0.1', '2026-11-23.1'] },
	'mitre-atlas-mapper': { engine: ver('assets/js/atlas-mapper/engine.js', /const ENGINE = '([^']+)';/), rules: ver('assets/js/atlas-mapper/engine.js', /const RULESET = '([^']+)';/), php: [ver('inc/tool-atlas-mapper.php', /CYBERDAT_ATL_ENGINE = '([^']+)'/), ver('inc/tool-atlas-mapper.php', /CYBERDAT_ATL_RULESET = '([^']+)'/)], want: ['1.0.4', '2026-11-23.1'] },
	'prompt-injection-detector': { engine: ver('assets/js/prompt-injection-detector/engine.js', /const VERSION = '([^']+)';/), php: [ver('inc/tool-prompt-injection-detector.php', /CYBERDAT_PROMPT_DETECTOR_ENGINE = '([^']+)'/)], want: ['1.0.5'] },
	'lotl-command-analyzer': { engine: ver('assets/js/lotl-analyzer/engine.js', /const VERSION = '([^']+)';/), php: [ver('inc/tool-lotl-analyzer.php', /CYBERDAT_LOTL_ENGINE = '([^']+)'/)], want: ['1.0.2'] }
};
for (const [slug, v] of Object.entries(VERSIONS)) {
	const got = [v.engine].concat(v.rules ? [v.rules] : []);
	if (got.join() !== v.want.join() || v.php.join() !== v.want.join()) { throw new Error('versions of ' + slug + ': engine ' + got.join(' / ') + ', PHP ' + v.php.join(' / ') + ', expected ' + v.want.join(' / ')); }
}
// ATLAS data unchanged
if (target['assets/js/atlas-mapper/atlas-data.js'].sha256 !== base['assets/js/atlas-mapper/atlas-data.js'].sha256) { throw new Error('the ATLAS 2026.10 data must not change'); }
// Applying the delta to the staging base must give exactly the target map.
const applied = Object.assign({}, base);
for (const k of modified) { applied[k] = target[k]; }
if (JSON.stringify(Object.fromEntries(Object.entries(applied).sort(([a], [b]) => (a < b ? -1 : 1)))) !== JSON.stringify(target)) { throw new Error('base + delta does not give the target'); }
const fileMap = ks => Object.fromEntries(ks.slice().sort().map(k => [k, { bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: base[k].sha256 }]));
const EDITORIAL = 'deploy/tools-utilities-1/editorial-r4.json';
const ed = blob(commit, EDITORIAL);
const manifest = {
	schema: 'cyberdat-theme-release/1',
	revision: 'tools-utilities-1/4',
	base_commit: BASE_COMMIT,
	base_ref: BASE_REF,
	base_note: 'Base = the staging theme after the installation of tools-utilities-1/3 (73d99a4). base_sha256 of every modified file is the staging version.',
	previous_revision: { revision: 'tools-utilities-1/3', base_commit: '7b9bee515ab906805eec99af12e0f7683954eec1', theme_commit: 'c9b76a23806edc5adce571f2ffa1450608d7ad32', manifest_sha256: 'd572358a4084c0540b62e3d4aceb0fa4643f3d452201057c6d17c639d0980716', status: 'installed on staging (2026-11-23)' },
	theme_commit: commit,
	install_rule: 'The installer copies the delta files as they are and changes no other theme file (no prepare step). Before installing, every theme file on staging equals the base map; after installing, every theme file equals the target map of this manifest, byte for byte. The page meta in editorial_r4 is set by Codex on the existing Leak Inspector page.',
	note: 'Owner task 2026-11-23: Leak Inspector and ATLAS mapper rules for the classes of the Codex 1.2 acceptance misses (own held-out set frozen before the change), a warning before large inputs in the nine tools that accept files, and the rule for values without a key in the shared masking block of tools 2 and 3. ATLAS 2026.10 data unchanged. Log Anonymizer Strict Mode not included (owner decision). Hashes are of the LF bytes in git (git -c core.autocrlf=false archive). No archive is built here: Codex builds and seals the archive with its own release tooling.',
	counts: { base: Object.keys(base).length, target: Object.keys(target).length, added: 0, modified: modified.length, removed: 0 },
	delta: { added, modified, removed },
	delta_files: Object.fromEntries(modified.map(k => [k, { status: 'modified', bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: base[k].sha256 }])),
	items: Object.fromEntries(Object.entries(ITEMS).map(([k, files]) => [k, fileMap(files)])),
	versions: Object.fromEntries(Object.entries(VERSIONS).map(([slug, v]) => [slug, v.rules ? { engine: v.engine, rules: v.rules } : { engine: v.engine }])),
	editorial_r4: { path: EDITORIAL, page: 'agent-leak-inspector', fields: ['documentation', 'faq'], change: 'Limits and one FAQ question: the leak check compares words, not meaning (L05, owner decision: not fixed, stated plainly)', bytes: ed.length, sha256: sha(ed) },
	base,
	target
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const keys = ['revision', 'base', 'target', 'delta', 'delta_files', 'items', 'versions', 'editorial_r4', 'previous_revision'];
	const same = current.base_commit === BASE_COMMIT && keys.every(k => JSON.stringify(current[k]) === JSON.stringify(manifest[k]));
	console.log(same ? 'PASS: tools-utilities-1 manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: tools-utilities-1 manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12) + '; items: ' + Object.entries(ITEMS).map(([k, v]) => k + ' ' + v.length).join(', '));
