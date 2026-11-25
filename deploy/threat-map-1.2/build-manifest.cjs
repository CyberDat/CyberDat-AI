/*
 * Builds deploy/threat-map-1.2/manifest.json: the delta package "Global Cyber Threat Map v1.2" (UN-recognised borders:
 * Crimea in Ukraine, N. Cyprus in Cyprus, Somaliland in Somalia) over the theme of package threat-map-1.1 (9082de0). Release-1 manifest
 * shape: base/target maps of every theme file (bytes, mode, sha256 of the exact LF bytes stored in git), an explicit
 * delta with base_sha256 for modified files, and the server files (systemd samples) with their sha256.
 * Any theme change outside the expected list stops the build.
 *   node deploy/threat-map-1.2/build-manifest.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE_COMMIT = '9082de07dbba9ae9c331563a729113bcbf4b30c0';
const BASE_REF = 'feature/threat-map-1.1@9082de0 (package threat-map-1.1/1 installed over threat-map-1/1)';
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
if (Object.keys(base).length !== 451) throw new Error('the threat-map-1.1 theme (9082de0) has 451 files');
const added = Object.keys(target).filter(k => !base[k]);
const removed = Object.keys(base).filter(k => !target[k]);
const modified = Object.keys(target).filter(k => base[k] && base[k].sha256 !== target[k].sha256);

const ITEMS = {
	borders: ['assets/maps/threat-map-countries.json', 'assets/maps/NOTICE.md', 'inc/threat-map/render.php'],
};
const ADDED = [];
const MODIFIED = ITEMS.borders.slice().sort();
if (removed.length) throw new Error('nothing may be removed: ' + removed.join(', '));
if (added.join() !== ADDED.join()) throw new Error('added files differ: ' + added.join(', '));
if (modified.join() !== MODIFIED.join()) throw new Error('modified files differ: ' + modified.join(', '));
if ([].concat(...Object.values(ITEMS)).sort().join() !== ADDED.concat(MODIFIED).sort().join()) throw new Error('items do not cover the delta');
// Everything else is untouched (checked by the delta list). The new geometry must carry the borders statement.
if (!/^Borders follow UN-recognised boundaries: Crimea is shown as part of Ukraine\. Derived from Natural Earth 1:110m\./.test(JSON.parse(blob(commit, THEME + 'assets/maps/threat-map-countries.json').toString('utf8')).borders || '')) throw new Error('geometry without the UN-borders statement');
const applied = Object.assign({}, base);
for (const k of added.concat(modified)) applied[k] = target[k];
if (JSON.stringify(Object.fromEntries(Object.entries(applied).sort(([a], [b]) => (a < b ? -1 : 1)))) !== JSON.stringify(target)) throw new Error('base + delta does not give the target');

const SERVER_FILES = { 'cyberdat-threatmap.service': 'docs/threat-map/cyberdat-threatmap.service', 'cyberdat-threatmap.timer': 'docs/threat-map/cyberdat-threatmap.timer' };
const server = Object.fromEntries(Object.entries(SERVER_FILES).map(([name, p]) => { const b = blob(commit, p); return [name, { source: p, install_to: '/etc/systemd/system/' + name, bytes: b.length, sha256: sha(b) }]; }));
const geo = JSON.parse(blob(commit, THEME + 'assets/maps/threat-map-countries.json').toString('utf8'));
const manifest = {
	schema: 'cyberdat-theme-release/1',
	revision: 'threat-map-1.2/1',
	base_commit: BASE_COMMIT,
	base_ref: BASE_REF,
	base_note: 'Base = the theme after package threat-map-1.1/1 (feature/threat-map-1.1 at 9082de0). Install this package only after threat-map-1.1; base_sha256 of every modified file is that version.',
	theme_commit: commit,
	install_rule: 'The installer copies the delta files as they are and changes no other theme file. Before installing, every theme file equals the base map (threat-map-1.1 installed); after installing, every theme file equals the target map. No database change, no timer change, no wp-config change. The Research plugin, its tables and its six timers are not touched.',
	note: 'Global Cyber Threat Map v1.2: borders follow UN-recognised boundaries (Crimea shown as part of Ukraine; N. Cyprus joined to Cyprus, Somaliland to Somalia; Kosovo separate), derived from Natural Earth 1:110m; map note "Country attribution is taken from each source as published." Data are not re-attributed.',
	counts: { base: Object.keys(base).length, target: Object.keys(target).length, added: added.length, modified: modified.length, removed: 0 },
	delta: { added, modified, removed },
	delta_files: Object.fromEntries(added.map(k => [k, { status: 'added', bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: null }])
		.concat(modified.map(k => [k, { status: 'modified', bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: base[k].sha256 }])).sort(([a], [b]) => (a < b ? -1 : 1))),
	items: Object.fromEntries(Object.entries(ITEMS).map(([k, files]) => [k, files.slice().sort()])),
	server_files: server,
	database: { tables: ['{prefix}cdtm_counts', '{prefix}cdtm_meta'], migration: 'none', drop: 'wp cyberdat threatmap uninstall --yes' },
	wp_config: [
		{ constant: 'CYBERDAT_RANSOMWARE_LIVE_API_KEY', required_for: 'ransomware layer; without it "not configured"', stored_in_repository: false },
		{ constant: 'CYBERDAT_CLOUDFLARE_RADAR_TOKEN', required_for: 'radar layer (Cloudflare API token, Account > Radar > Read); without it "not configured"', stored_in_repository: false },
	],
	borders: { rule: 'Borders follow UN-recognised boundaries: Crimea is shown as part of Ukraine. Derived from Natural Earth 1:110m.', build: 'node tools/threat-map/build-geometry.cjs world-atlas-2.0.2.tgz', deterministic_sha256: crypto.createHash('sha256').update(blob(commit, THEME + 'assets/maps/threat-map-countries.json')).digest('hex') },
	geometry: { source: geo.source, license: geo.license, input_integrity: geo.input_integrity, input_sha256: geo.input_sha256, areas: geo.countries.length, build: 'node tools/threat-map/build-geometry.cjs world-atlas-2.0.2.tgz' },
	base,
	target,
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const keys = ['revision', 'base_commit', 'base', 'target', 'delta', 'delta_files', 'items', 'server_files', 'geometry', 'borders'];
	const same = keys.every(k => JSON.stringify(current[k]) === JSON.stringify(manifest[k]));
	console.log(same ? 'PASS: threat-map-1.2 manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: threat-map-1.2 manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12));
