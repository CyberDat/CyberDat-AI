/*
 * Builds deploy/ai-tools-owasp-2026/manifest.json: the delta package "AI tools: OWASP 2026 references" (page text of the
 * six AI tools: OWASP LLM Top 10 2026 / Agentic Top 10 2026 line, rules update date) over the theme of 6e5ba9c.
 * No JavaScript file may change (engines, rules, masking and exports stay byte-identical). Release-1 manifest
 * shape: base/target maps of every theme file (bytes, mode, sha256 of the exact LF bytes stored in git), an explicit
 * delta with base_sha256 for modified files. Any other change stops the build.
 * Any theme change outside the expected list stops the build.
 *   node deploy/ai-tools-owasp-2026/build-manifest.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE_COMMIT = '6e5ba9c7b04abab22a61c5e410eff225d13dfaa9';
const BASE_REF = 'feature/threat-map-1.2@6e5ba9c (package threat-map-1.2/1 installed)';
const THEME = 'wp-content/themes/cyberdat/';
const ROOT = path.join(__dirname, '../..');
const sh = c => cp.execSync(c, { cwd: ROOT, maxBuffer: 1 << 28 });
const CHECK = process.argv.includes('--check');
const commit = sh('git rev-parse ' + (process.argv.slice(2).find(x => !x.startsWith('--')) || 'HEAD')).toString().trim();
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const blob = (rev, p) => sh('git cat-file blob ' + rev + ':' + p);
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
if (Object.keys(base).length !== 451) throw new Error('the theme at 6e5ba9c has 451 files');
const added = Object.keys(target).filter(k => !base[k]);
const removed = Object.keys(base).filter(k => !target[k]);
const modified = Object.keys(target).filter(k => base[k] && base[k].sha256 !== target[k].sha256);

const PAGES = ['prompt-injection-detector', 'prompt-injection-test-bench', 'agent-leak-inspector', 'mcp-security-checker', 'mitre-atlas-mapper', 'ai-model-bom'].map(p => 'template-parts/tools/' + p + '.php');
const ITEMS = {
	owasp_2026: ['inc/tools-owasp-2026.php'].concat(PAGES),
};
const ADDED = ['inc/tools-owasp-2026.php'];
const MODIFIED = PAGES.slice().sort();
if (removed.length) throw new Error('nothing may be removed: ' + removed.join(', '));
if (added.join() !== ADDED.join()) throw new Error('added files differ: ' + added.join(', '));
if (modified.join() !== MODIFIED.join()) throw new Error('modified files differ: ' + modified.join(', '));
if ([].concat(...Object.values(ITEMS)).sort().join() !== ADDED.concat(MODIFIED).sort().join()) throw new Error('items do not cover the delta');
// Everything else is untouched (checked by the delta list): no JavaScript, engine, rule or export file changes.
if (Object.keys(target).some(k => /\.js$/.test(k) && target[k].sha256 !== (base[k] || {}).sha256)) throw new Error('a JavaScript file changed');
const applied = Object.assign({}, base);
for (const k of added.concat(modified)) applied[k] = target[k];
if (JSON.stringify(Object.fromEntries(Object.entries(applied).sort(([a], [b]) => (a < b ? -1 : 1)))) !== JSON.stringify(target)) throw new Error('base + delta does not give the target');

const manifest = {
	schema: 'cyberdat-theme-release/1',
	revision: 'ai-tools-owasp-2026/1',
	base_commit: BASE_COMMIT,
	base_ref: BASE_REF,
	base_note: 'Base = the theme at 6e5ba9c (feature/threat-map-1.2, package threat-map-1.2/1 installed). base_sha256 of every modified file is that version.',
	theme_commit: commit,
	install_rule: 'The installer copies the delta files as they are and changes no other theme file. Before installing, every theme file equals the base map; after installing, every theme file equals the target map. No database, editorial, timer or wp-config change: no editorial text in the database mentions OWASP. The Research plugin, its tables and its timers, the threat map, the Tools hub and SEO are not touched.',
	note: 'AI tools: OWASP references follow the 2026 editions (OWASP Top 10 for LLM Applications 2026, OWASP Top 10 for Agentic Applications 2026). Six AI tool pages get a "Mapped to OWASP Top 10 for LLM Applications 2026" line (names only, no links, as on all tool pages) and "rules updated YYYY-MM-DD"; Leak Inspector cites LLM08:2026 Hidden Context Exposure instead of the 2025 entry. Sources and mapping: docs/OWASP-2026-MAPPING.md; gaps: docs/OWASP-2026-GAPS.md.',
	counts: { base: Object.keys(base).length, target: Object.keys(target).length, added: added.length, modified: modified.length, removed: 0 },
	delta: { added, modified, removed },
	delta_files: Object.fromEntries(added.map(k => [k, { status: 'added', bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: null }])
		.concat(modified.map(k => [k, { status: 'modified', bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: base[k].sha256 }])).sort(([a], [b]) => (a < b ? -1 : 1))),
	items: Object.fromEntries(Object.entries(ITEMS).map(([k, files]) => [k, files.slice().sort()])),
	owasp: { llm: 'OWASP Top 10 for LLM Applications 2026 (released 2026-08-04, CC BY-SA 4.0)', agentic: 'OWASP Top 10 for Agentic Applications 2026 (2025-12-09)', mapping: 'docs/OWASP-2026-MAPPING.md', gaps: 'docs/OWASP-2026-GAPS.md', editorial: 'none needed' },
	base,
	target,
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const keys = ['revision', 'base_commit', 'base', 'target', 'delta', 'delta_files', 'items', 'owasp'];
	const same = keys.every(k => JSON.stringify(current[k]) === JSON.stringify(manifest[k]));
	console.log(same ? 'PASS: ai-tools-owasp-2026 manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: ai-tools-owasp-2026 manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12));
