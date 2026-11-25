/*
 * Builds deploy/threat-map-1.1/manifest.json: the delta package "Global Cyber Threat Map v1.1" (flags, default layer,
 * Cloudflare Radar) over the theme of package threat-map-1 (feature/threat-map-1 at c964927, being installed by Codex). Release-1 manifest
 * shape: base/target maps of every theme file (bytes, mode, sha256 of the exact LF bytes stored in git), an explicit
 * delta with base_sha256 for modified files, and the server files (systemd samples) with their sha256.
 * Any theme change outside the expected list stops the build.
 *   node deploy/threat-map-1.1/build-manifest.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE_COMMIT = 'c964927ddedddeb73cf602dd9e2fea16ffddb42c';
const BASE_REF = 'feature/threat-map-1@c964927 (package threat-map-1/1 installed over tools-utilities-1/5)';
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
if (Object.keys(base).length !== 198) throw new Error('the threat-map-1 theme (c964927) has 198 files');
const added = Object.keys(target).filter(k => !base[k]);
const removed = Object.keys(base).filter(k => !target[k]);
const modified = Object.keys(target).filter(k => base[k] && base[k].sha256 !== target[k].sha256);

const FLAGS = Object.keys(JSON.parse(blob(commit, THEME + 'assets/flags/flags.json').toString('utf8')).files).map(c => 'assets/flags/4x3/' + c.toLowerCase() + '.svg');
const ITEMS = {
	flags: FLAGS.concat(['assets/flags/flags.json', 'assets/flags/NOTICE.md', 'assets/flags/LICENSE-flag-icons.txt']),
	radar_and_default_layer: ['inc/threat-map/core.php', 'inc/threat-map/view.php', 'inc/threat-map/render.php', 'assets/js/threat-map.js', 'assets/css/threat-map.css'],
};
const ADDED = ITEMS.flags.slice().sort();
const MODIFIED = ITEMS.radar_and_default_layer.slice().sort();
if (removed.length) throw new Error('nothing may be removed: ' + removed.join(', '));
if (added.join() !== ADDED.join()) throw new Error('added files differ: ' + added.join(', '));
if (modified.join() !== MODIFIED.join()) throw new Error('modified files differ: ' + modified.join(', '));
if ([].concat(...Object.values(ITEMS)).sort().join() !== ADDED.concat(MODIFIED).sort().join()) throw new Error('items do not cover the delta');
// Everything outside the map files is untouched (checked by the delta list); 250 flags, one per ISO code.
if (FLAGS.length !== 250) throw new Error('expected 250 flags');
const applied = Object.assign({}, base);
for (const k of added.concat(modified)) applied[k] = target[k];
if (JSON.stringify(Object.fromEntries(Object.entries(applied).sort(([a], [b]) => (a < b ? -1 : 1)))) !== JSON.stringify(target)) throw new Error('base + delta does not give the target');

const SERVER_FILES = { 'cyberdat-threatmap.service': 'docs/threat-map/cyberdat-threatmap.service', 'cyberdat-threatmap.timer': 'docs/threat-map/cyberdat-threatmap.timer' };
const server = Object.fromEntries(Object.entries(SERVER_FILES).map(([name, p]) => { const b = blob(commit, p); return [name, { source: p, install_to: '/etc/systemd/system/' + name, bytes: b.length, sha256: sha(b) }]; }));
const geo = JSON.parse(blob(commit, THEME + 'assets/maps/threat-map-countries.json').toString('utf8'));
const manifest = {
	schema: 'cyberdat-theme-release/1',
	revision: 'threat-map-1.1/1',
	base_commit: BASE_COMMIT,
	base_ref: BASE_REF,
	base_note: 'Base = the theme after package threat-map-1/1 (feature/threat-map-1 at c964927). Install this package only after threat-map-1; base_sha256 of every modified file is that version.',
	theme_commit: commit,
	install_rule: 'The installer copies the delta files as they are and changes no other theme file. Before installing, every theme file equals the base map (threat-map-1 installed); after installing, every theme file equals the target map. No database migration: the tables of threat-map-1 are unchanged (the Radar layer keeps its state in {prefix}cdtm_meta). The Research plugin, its tables and its six timers are not touched.',
	note: 'Global Cyber Threat Map v1.1: country flags (flag-icons 7.6.0, MIT, checked SVG), tab order and default layer from the data with a low-activity note, third layer Cloudflare Radar "DDoS targets" (share of HTTP DDoS requests by target country, percentages from the API, token from the wp-config constant CYBERDAT_CLOUDFLARE_RADAR_TOKEN, slot :47). Sources and terms: docs/THREAT-MAP-SOURCES.md.',
	counts: { base: Object.keys(base).length, target: Object.keys(target).length, added: added.length, modified: modified.length, removed: 0 },
	delta: { added, modified, removed },
	delta_files: Object.fromEntries(added.map(k => [k, { status: 'added', bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: null }])
		.concat(modified.map(k => [k, { status: 'modified', bytes: target[k].bytes, sha256: target[k].sha256, base_sha256: base[k].sha256 }])).sort(([a], [b]) => (a < b ? -1 : 1))),
	items: Object.fromEntries(Object.entries(ITEMS).map(([k, files]) => [k, files.slice().sort()])),
	server_files: server,
	database: { tables: ['{prefix}cdtm_counts', '{prefix}cdtm_meta'], migration: 'none (unchanged since threat-map-1)', drop: 'wp cyberdat threatmap uninstall --yes' },
	wp_config: [
		{ constant: 'CYBERDAT_RANSOMWARE_LIVE_API_KEY', required_for: 'ransomware layer; without it "not configured"', stored_in_repository: false },
		{ constant: 'CYBERDAT_CLOUDFLARE_RADAR_TOKEN', required_for: 'radar layer (Cloudflare API token, Account > Radar > Read); without it "not configured"', stored_in_repository: false },
	],
	flags: { source: 'flag-icons 7.6.0 (npm)', license: 'MIT', files: FLAGS.length, build: 'node tools/threat-map/build-flags.cjs flag-icons-7.6.0.tgz', check: 'tools/threat-map/svg-safety.cjs' },
	geometry: { source: geo.source, license: geo.license, input_integrity: geo.input_integrity, input_sha256: geo.input_sha256, areas: geo.countries.length, build: 'node tools/threat-map/build-geometry.cjs world-atlas-2.0.2.tgz' },
	base,
	target,
};
const file = path.join(__dirname, 'manifest.json');
if (CHECK) {
	const current = JSON.parse(fs.readFileSync(file, 'utf8'));
	const keys = ['revision', 'base_commit', 'base', 'target', 'delta', 'delta_files', 'items', 'server_files', 'geometry', 'flags'];
	const same = keys.every(k => JSON.stringify(current[k]) === JSON.stringify(manifest[k]));
	console.log(same ? 'PASS: threat-map-1.1 manifest matches the theme at ' + commit.slice(0, 12) : 'FAIL: threat-map-1.1 manifest is out of date for ' + commit.slice(0, 12));
	process.exit(same ? 0 : 1);
}
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest.counts) + ' at ' + commit.slice(0, 12));
