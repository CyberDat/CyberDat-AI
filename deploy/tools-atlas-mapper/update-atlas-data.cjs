#!/usr/bin/env node
/*
 * Build-time snapshot of MITRE ATLAS data for the CyberDat MITRE ATLAS Attack Vector Mapper.
 * The page never contacts MITRE or GitHub: this script runs on a maintainer machine and its output is committed.
 *
 * Usage (YAML parser "yaml" 2.6.1, ISC, is a build-time tool only and NOT a repository dependency):
 *   mkdir %TEMP%\atlas-build && cd %TEMP%\atlas-build && npm i --save-exact yaml@2.6.1
 *   NODE_PATH=<that dir>/node_modules node deploy/tools-atlas-mapper/update-atlas-data.cjs --fetch
 *   NODE_PATH=... node deploy/tools-atlas-mapper/update-atlas-data.cjs --source <dir with LICENSE and dist/v6/ATLAS-2026.10.yaml>
 *
 * Pinned source: github.com/mitre-atlas/atlas-data, commit COMMIT (release RELEASE). The script refuses to run when the
 * upstream LICENSE file or the data file does not match the pinned SHA-256: a new release or a changed license needs a
 * reviewed update of the pins (and an owner decision if the license changed).
 *
 * Output (overwritten):
 *   wp-content/themes/cyberdat/assets/js/atlas-mapper/atlas-data.js          tactics, techniques, mitigations and their
 *                                                                              relationships (subset of fields, converted)
 *   wp-content/themes/cyberdat/assets/js/atlas-mapper/LICENSE-ATLAS.txt       upstream LICENSE file, verbatim
 *   wp-content/themes/cyberdat/assets/js/atlas-mapper/LICENSE-APACHE-2.0.txt  full Apache License 2.0 text, verbatim
 *   deploy/tools-atlas-mapper/atlas-snapshot.json                             provenance: commit, release, hashes, counts
 *
 * Nothing is inferred: ids, names, tactic links (achieves), parent techniques (specializes) and mitigation links
 * (mitigates) are copied from the data. Case studies, entities and software are not included.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const COMMIT = 'f56c1468731d6428e5bf875263b4643b46d67437';
const RELEASE = '2026.10';
const RELEASE_DATE = '2026-10-28';
const DATA_PATH = 'dist/v6/ATLAS-2026.10.yaml';
const PINS = {
	LICENSE: 'fa6c92ab3dc75d41413884e8b38cc54cd4e72f4c8f68fc7e77824e48e3047d40',
	[DATA_PATH]: 'ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d',
	'LICENSE-2.0.txt': 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'
};
const RAW = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/' + COMMIT + '/';
const APACHE_URL = 'https://www.apache.org/licenses/LICENSE-2.0.txt';
const ROOT = path.resolve(__dirname, '../..');
const OUT_DIR = path.join(ROOT, 'wp-content/themes/cyberdat/assets/js/atlas-mapper');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');

async function load() {
	const args = process.argv.slice(2);
	const src = args.indexOf('--source');
	const files = {};
	if (src >= 0) {
		const dir = args[src + 1];
		for (const f of ['LICENSE', DATA_PATH]) { files[f] = fs.readFileSync(path.join(dir, f)); }
		const apache = args.indexOf('--apache');
		files['LICENSE-2.0.txt'] = apache >= 0 ? fs.readFileSync(args[apache + 1]) : Buffer.from(await (await fetch(APACHE_URL)).arrayBuffer());
	} else if (args.includes('--fetch')) {
		for (const f of ['LICENSE', DATA_PATH]) { const r = await fetch(RAW + f); if (!r.ok) { throw new Error('download failed: ' + f + ' ' + r.status); } files[f] = Buffer.from(await r.arrayBuffer()); }
		files['LICENSE-2.0.txt'] = Buffer.from(await (await fetch(APACHE_URL)).arrayBuffer());
	} else {
		throw new Error('Use --fetch or --source <dir>.');
	}
	for (const [f, want] of Object.entries(PINS)) {
		const got = sha(files[f]);
		if (got !== want) {
			throw new Error('REFUSED: ' + f + ' does not match the pinned SHA-256 (' + got.slice(0, 16) + '… instead of ' + want.slice(0, 16) + '…). ' + (f === 'LICENSE' ? 'The upstream license file changed: stop and ask the owner before updating.' : 'Review the new release and update the pins deliberately.'));
		}
	}
	if (!/Licensed under the Apache License, Version 2\.0/.test(files.LICENSE.toString('utf8'))) { throw new Error('REFUSED: upstream LICENSE no longer states Apache License 2.0.'); }
	return files;
}

/** Markdown links become plain text: internal ATLAS links keep their id, external links keep only their text. */
function plain(s) {
	return String(s || '')
		.replace(/\[\[[A-Za-z0-9_.-]{1,80}\]\]/g, '')
		.replace(/\[([^\]\n]{1,300})\]\(\s*\/(?:techniques|tactics|mitigations|software|studies|entities)\/(AML\.[A-Z]{1,3}[0-9]{4}(?:\.[0-9]{3})?)\s*\)/g, '$1 ($2)')
		.replace(/(^|[^!])\[([^\]\n]{1,300})\]\(\s*(?:https?:\/\/|\/)[^)\s]{1,500}\s*\)/g, '$1$2')
		.replace(/\r\n?/g, '\n')
		.replace(/[ \t]+\n/g, '\n')
		.trim();
}

function convert(doc) {
	const rels = [];
	for (const group of Object.values(doc.relationships || {})) {
		for (const list of Object.values(group || {})) { for (const r of [].concat(list || [])) { rels.push(r); } }
	}
	const by = t => rels.filter(r => r['relationship-type'] === t);
	const order = new Map(by('sequences').map(r => [r.target, r.position]));
	const tacticsOf = new Map();
	for (const r of by('achieves')) { if (!tacticsOf.has(r.source)) { tacticsOf.set(r.source, []); } tacticsOf.get(r.source).push(r.target); }
	const parentOf = new Map(by('specializes').map(r => [r.source, r.target]));
	const tactics = Object.entries(doc.tactics).map(([id, t]) => ({ id, name: t.name, description: plain(t.description), order: order.has(id) ? order.get(id) : 999 })).sort((a, b) => a.order - b.order || (a.id < b.id ? -1 : 1));
	const techniques = Object.entries(doc.techniques).map(([id, t]) => ({ id, name: t.name, description: plain(t.description), tactics: (tacticsOf.get(id) || []).slice().sort(), parent: parentOf.get(id) || null, maturity: t.maturity || '' })).sort((a, b) => (a.id < b.id ? -1 : 1));
	const mitigations = Object.entries(doc.mitigations).map(([id, m]) => ({ id, name: m.name, description: plain(m.description), categories: m.categories || [], lifecyclePhases: m['lifecycle-phases'] || [] })).sort((a, b) => (a.id < b.id ? -1 : 1));
	const mitigates = by('mitigates').map(r => [r.source, r.target, plain(r.description)]).sort((a, b) => (a[0] + a[1] < b[0] + b[1] ? -1 : 1));
	const ids = new Set(techniques.map(t => t.id).concat(tactics.map(t => t.id), mitigations.map(m => m.id)));
	for (const t of techniques) { for (const x of t.tactics.concat(t.parent ? [t.parent] : [])) { if (!ids.has(x)) { throw new Error('dangling reference ' + t.id + ' -> ' + x); } } }
	for (const [m, t] of mitigates) { if (!ids.has(m) || !ids.has(t)) { throw new Error('dangling mitigation link ' + m + ' -> ' + t); } }
	return { tactics, techniques, mitigations, mitigates };
}

(async () => {
	const files = await load();
	const YAML = require('yaml');
	const ver = require('yaml/package.json').version;
	if (ver !== '2.6.1') { throw new Error('Use yaml 2.6.1 (found ' + ver + ') so the output is reproducible.'); }
	const doc = YAML.parse(files[DATA_PATH].toString('utf8'), { maxAliasCount: -1 });
	if (doc.collection.version !== RELEASE) { throw new Error('release mismatch: ' + doc.collection.version); }
	const data = convert(doc);
	const meta = {
		name: 'MITRE ATLAS',
		release: RELEASE,
		releaseDate: RELEASE_DATE,
		formatVersion: doc['format-version'],
		source: 'https://github.com/mitre-atlas/atlas-data',
		commit: COMMIT,
		file: DATA_PATH,
		license: 'Apache-2.0',
		copyright: 'Copyright 2021-2026 MITRE',
		modification: 'Converted from YAML to JavaScript by CyberDat: subset of fields (tactics, techniques, mitigations, achieves/specializes/mitigates relationships); Markdown links turned into plain text (internal links keep their ATLAS id) and citation markers removed; one HTML example inside a code block is kept as text; case studies, entities and software omitted. No ids or relationships were added.'
	};
	const counts = { tactics: data.tactics.length, techniques: data.techniques.filter(t => !t.parent).length, subtechniques: data.techniques.filter(t => t.parent).length, mitigations: data.mitigations.length, mitigates: data.mitigates.length };
	const header = '/*!\n * MITRE ATLAS data snapshot for the CyberDat MITRE ATLAS Attack Vector Mapper.\n * Source: MITRE ATLAS, ' + meta.source + ', commit ' + COMMIT + ', release ' + RELEASE + ' (' + RELEASE_DATE + '), ' + DATA_PATH + '.\n * ' + meta.copyright + '. Licensed under the Apache License, Version 2.0: LICENSE-ATLAS.txt (upstream notice) and\n * LICENSE-APACHE-2.0.txt (full text) next to this file. This file is MODIFIED: ' + meta.modification + '\n * Generated by deploy/tools-atlas-mapper/update-atlas-data.cjs. Do not edit by hand.\n */\n';
	const body = '(function (root) {\n\t\'use strict\';\n\tconst data = ' + JSON.stringify(Object.assign({ meta: Object.assign({}, meta, { counts }) }, data)) + ';\n\tif (typeof module === \'object\' && module.exports) { module.exports = data; } else { root.CyberDatAtlasData = data; }\n}(typeof self !== \'undefined\' ? self : this));\n';
	fs.mkdirSync(OUT_DIR, { recursive: true });
	const out = {
		'atlas-data.js': Buffer.from(header + body, 'utf8'),
		'LICENSE-ATLAS.txt': files.LICENSE,
		'LICENSE-APACHE-2.0.txt': files['LICENSE-2.0.txt']
	};
	for (const [f, b] of Object.entries(out)) { fs.writeFileSync(path.join(OUT_DIR, f), b); }
	const snapshot = Object.assign({}, meta, { counts, sourceSha256: { LICENSE: PINS.LICENSE, [DATA_PATH]: PINS[DATA_PATH], 'apache.org LICENSE-2.0.txt': PINS['LICENSE-2.0.txt'] }, outputSha256: Object.fromEntries(Object.entries(out).map(([f, b]) => [f, sha(b)])), parser: 'yaml ' + ver + ' (ISC), build time only' });
	fs.writeFileSync(path.join(__dirname, 'atlas-snapshot.json'), JSON.stringify(snapshot, null, 2) + '\n');
	console.log('MITRE ATLAS ' + RELEASE + ': ' + JSON.stringify(counts) + '; atlas-data.js ' + out['atlas-data.js'].length + ' bytes');
})().catch(e => { console.error(e.message); process.exit(1); });
