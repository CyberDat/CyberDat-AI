/*
 * Builds deploy/tools-utilities-1/manifest.json, revision tools-utilities-1/5, in the release-1 manifest shape (base/target
 * maps of every theme file with bytes, mode and sha256 of the exact LF bytes stored in git) and an explicit delta.
 * Base = the current staging theme with the Research UI: snapshot/staging-theme-20261124 at e781091 (revision 4 plus the
 * staging Research UI files). So base_sha256 of every modified file is the staging version.
 * Target = this branch. Owner task 2026-11-24 "final round of Leak Inspector and ATLAS", one item:
 *   leak_atlas    Leak Inspector and ATLAS mapper rules (engines, version constants, page texts)
 * Large inputs, masking and the Test Bench are not part of this revision (accepted by Codex on d404fdb). Nothing is added
 * or removed; any other changed theme file stops the build.
 *   node deploy/tools-utilities-1/build-manifest.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE_COMMIT = 'e7810914ee46946cab3a1dc5c636c2b3ea1e0b1f';
const BASE_REF = 'snapshot/staging-theme-20261124@e781091 (staging theme with the Research UI, 2026-11-24)';
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
if (Object.keys(base).length !== 188) { throw new Error('the staging theme (e781091) has 188 files'); }
const added = Object.keys(target).filter(k => !base[k]);
const removed = Object.keys(base).filter(k => !target[k]);
const modified = Object.keys(target).filter(k => base[k] && base[k].sha256 !== target[k].sha256);

const FILE_TOOLS = ['log-anonymizer', 'prompt-injection-detector', 'lotl-analyzer', 'mcp-checker', 'leak-inspector', 'ai-model-bom', 'email-header-analyzer', 'container-hardening-audit', 'prompt-injection-test-bench'];
const ITEMS = {
	leak_atlas: ['assets/js/leak-inspector/engine.js', 'inc/tool-leak-inspector.php', 'template-parts/tools/agent-leak-inspector.php', 'assets/js/atlas-mapper/engine.js', 'inc/tool-atlas-mapper.php', 'template-parts/tools/mitre-atlas-mapper.php']
};
// accepted by Codex on d404fdb, unchanged in this revision (checked below)
const ACCEPTED = FILE_TOOLS.map(t => 'assets/js/' + t + '/app.js').concat(['assets/css/tools-common.css', 'assets/js/prompt-injection-detector/engine.js', 'assets/js/lotl-analyzer/engine.js', 'assets/js/prompt-injection-test-bench/engine.js']);
const expected = [].concat(...Object.values(ITEMS)).sort();
if (added.length || removed.length) { throw new Error('nothing may be added or removed: ' + added.concat(removed).join(', ')); }
if (modified.join() !== expected.join()) { throw new Error('modified files differ from the owner items: ' + modified.filter(k => !expected.includes(k)).concat(expected.filter(k => !modified.includes(k)).map(k => 'missing ' + k)).join(', ')); }
// shared blocks: equal in every copy
const between = (s, a, b) => { const i = s.indexOf(a), j = s.indexOf(b); return i > 0 && j > i ? s.slice(i, j) : ''; };
const MASK = ['// ---------------------------------------------------------------- secret masking (shared block)', '// ---------------------------------------------------------------- end of secret masking (shared block)'];
const masks = ['assets/js/prompt-injection-detector/engine.js', 'assets/js/lotl-analyzer/engine.js'].map(k => between(text(commit, k), ...MASK));
if (!masks[0] || masks[0] !== masks[1] || !masks[0].includes('SECRET_UNKEYED')) { throw new Error('the secret masking block with the rule for values without a key must be equal in tools 2 and 3'); }
const LARGE = ['// ---------------------------------------------------------------- warning before large inputs (shared block)', '// ---------------------------------------------------------------- end of warning before large inputs (shared block)'];
const larges = FILE_TOOLS.map(t => 'assets/js/' + t + '/app.js').map(k => between(text(commit, k), ...LARGE));
for (const k of ACCEPTED) { if (target[k].sha256 !== base[k].sha256) { throw new Error('accepted by Codex on d404fdb, must not change: ' + k); } }
if (!larges[0] || larges.some(b => b !== larges[0])) { throw new Error('the warning block before large inputs must be equal in the nine tools'); }
// versions: engine and PHP constant agree
const ver = (k, re) => { const m = text(commit, k).match(re); return m ? m[1] : null; };
const VERSIONS = {
	'agent-leak-inspector': { engine: ver('assets/js/leak-inspector/engine.js', /const VERSION = '([^']+)';/), rules: ver('assets/js/leak-inspector/engine.js', /const RULESET_VERSION = '([^']+)';/), php: [ver('inc/tool-leak-inspector.php', /CYBERDAT_LKI_ENGINE = '([^']+)'/), ver('inc/tool-leak-inspector.php', /CYBERDAT_LKI_RULESET = '([^']+)'/)], want: ['1.0.2', '2026-11-24.1'] },
	'mitre-atlas-mapper': { engine: ver('assets/js/atlas-mapper/engine.js', /const ENGINE = '([^']+)';/), rules: ver('assets/js/atlas-mapper/engine.js', /const RULESET = '([^']+)';/), php: [ver('inc/tool-atlas-mapper.php', /CYBERDAT_ATL_ENGINE = '([^']+)'/), ver('inc/tool-atlas-mapper.php', /CYBERDAT_ATL_RULESET = '([^']+)'/)], want: ['1.0.5', '2026-11-24.1'] },
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
const EDITORIAL = 'deploy/tools-utilities-1/editorial-r5.json';
const ed = blob(commit, EDITORIAL);
const manifest = {
	schema: 'cyberdat-theme-release/1',
	revision: 'tools-utilities-1/5',
	base_commit: BASE_COMMIT,
	base_ref: BASE_REF,
	base_note: 'Base = the current staging theme with the Research UI (snapshot/staging-theme-20261124 at e781091: revision 4 plus the staging Research UI files). base_sha256 of every modified file is the staging version.',
	previous_revision: { revision: 'tools-utilities-1/4', base_commit: '73d99a4cb1d60acee957ce55bf59d765286695a9', theme_commit: '276ff6baf2385bfca7daf298e358482e9f8ca6ee', manifest_sha256: '57bdd7874be2b8f9900429f8d32f91d4ff9462721f420044dbf0af3131e49da5', status: 'large inputs, masking and the Test Bench accepted by Codex on d404fdb; the staging theme is now e781091' },
	theme_commit: commit,
	install_rule: 'The installer copies the delta files as they are and changes no other theme file (no prepare step). Before installing, every theme file on staging equals the base map; after installing, every theme file equals the target map of this manifest, byte for byte. The page meta in editorial_r5 is set by Codex on the existing Leak Inspector and ATLAS mapper pages.',
	note: 'Owner task 2026-11-24 (final round before launch): Leak Inspector without findings for protective and prohibiting wording and for published prices, more indirect wording of the six risk classes; ATLAS mapper without attack techniques for permitted tool use, vault references and denials, parent techniques for general tool or context poisoning, more wording of the ten classes. Own held-out set frozen before the change (tests/fixtures/*/heldout-r12.json). ATLAS 2026.10 data unchanged. Hashes are of the LF bytes in git (git -c core.autocrlf=false archive). No archive is built here: Codex builds and seals the archive with its own release tooling.',
	counts: { base: Object.keys(base).length, target: Object.keys(target).length, added: 0, modified: modified.length, removed: 0 },
	delta: { added, modified, removed },
	delta_files: Object.fromEntries(modified.map(k => [k, { status: 'modified', bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: base[k].sha256 }])),
	items: Object.fromEntries(Object.entries(ITEMS).map(([k, files]) => [k, fileMap(files)])),
	versions: Object.fromEntries(Object.entries(VERSIONS).map(([slug, v]) => [slug, v.rules ? { engine: v.engine, rules: v.rules } : { engine: v.engine }])),
	editorial_r5: { path: EDITORIAL, pages: ['agent-leak-inspector', 'mitre-atlas-mapper'], fields: ['documentation', 'faq'], change: 'Limits and one FAQ question on each page: the analysis is lexical; protective wording and denials are recognized only in simple forms and can still be misread', bytes: ed.length, sha256: sha(ed) },
	base,
	target
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const keys = ['revision', 'base', 'target', 'delta', 'delta_files', 'items', 'versions', 'editorial_r5', 'previous_revision'];
	const same = current.base_commit === BASE_COMMIT && keys.every(k => JSON.stringify(current[k]) === JSON.stringify(manifest[k]));
	console.log(same ? 'PASS: tools-utilities-1 manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: tools-utilities-1 manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12) + '; items: ' + Object.entries(ITEMS).map(([k, v]) => k + ' ' + v.length).join(', '));
