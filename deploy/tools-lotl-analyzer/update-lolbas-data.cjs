#!/usr/bin/env node
/*
 * Build-time snapshot of the LOLBAS project data for the LotL / LOLBAS Command Analyzer.
 * The page never contacts GitHub: this script runs on a maintainer machine, and its output is
 * committed to the theme.
 *
 * Usage:
 *   node deploy/tools-lotl-analyzer/update-lolbas-data.cjs --source <local LOLBAS checkout>
 *   node deploy/tools-lotl-analyzer/update-lolbas-data.cjs --fetch <commit-sha>   (clones github.com/LOLBAS-Project/LOLBAS into a temp dir)
 *
 * Output (overwritten):
 *   wp-content/themes/cyberdat/assets/js/lotl-analyzer/lolbas-data.js   GPL-3.0 data snapshot (subset of fields, converted from YAML)
 *   wp-content/themes/cyberdat/assets/js/lotl-analyzer/LICENSE-LOLBAS.txt  the upstream LICENSE file, verbatim
 *   deploy/tools-lotl-analyzer/lolbas-snapshot.json                       source commit, date, counts and per-file sha256
 *
 * Only Windows LOLBAS data is used. GTFOBins (Linux) is intentionally not included (owner decision pending).
 * ATT&CK ids are copied from the LOLBAS "MitreID" field only; nothing is inferred.
 */
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const REPO = 'https://github.com/LOLBAS-Project/LOLBAS.git';
const ROOT = path.resolve(__dirname, '../..');
const OUT_DIR = path.join(ROOT, 'wp-content/themes/cyberdat/assets/js/lotl-analyzer');
const SITE_SECTION = { OSBinaries: 'Binaries', OSLibraries: 'Libraries', OSScripts: 'Scripts', OtherMSBinaries: 'OtherMSBinaries', HonorableMentions: 'HonorableMentions' };

// ---------------------------------------------------------------- minimal YAML subset parser
// Supports what LOLBAS uses: block mappings, block sequences (of mappings or scalars),
// '|' block scalars, single/double-quoted and plain scalars, '#' comment lines, a leading '---'.
function parseYaml(text, file) {
	const lines = text.replace(/\r\n?/g, '\n').split('\n');
	let i = 0;
	const fail = msg => { throw new Error(`${file}:${i + 1}: ${msg}`); };
	const indentOf = l => l.match(/^ */)[0].length;
	const skip = () => { while (i < lines.length && (/^\s*$/.test(lines[i]) || /^\s*#/.test(lines[i]) || lines[i].trim() === '---')) { i++; } };
	function scalar(raw) {
		const s = raw.trim();
		if (s === '') { return null; }
		if (s[0] === '\'') { if (!s.endsWith('\'') || s.length < 2) { fail('unterminated single quote'); } return s.slice(1, -1).replace(/''/g, '\''); }
		if (s[0] === '"') { if (!s.endsWith('"') || s.length < 2) { fail('unterminated double quote'); } try { return JSON.parse(s.replace(/\\(u[0-9A-Fa-f]{4}|[\s\S])/g, (m, c) => (/^(?:u[0-9A-Fa-f]{4}|["\\/bfnrt])$/.test(c) ? m : '\\\\' + c)).replace(/\t/g, '\\t')); } catch (e) { fail('bad double-quoted scalar: ' + s.slice(0, 80)); } }
		if (/^[[{]/.test(s) && !/^\[[A-Z0-9]/.test(s)) { fail('flow collections are not supported: ' + s); }
		return s.replace(/\s+#.*$/, '');
	}
	function blockScalar(parentIndent) {
		const out = [];
		let ind = -1;
		while (i < lines.length) {
			const l = lines[i];
			if (/^\s*$/.test(l)) { out.push(''); i++; continue; }
			const n = indentOf(l);
			if (n <= parentIndent) { break; }
			if (ind < 0) { ind = n; }
			out.push(l.slice(ind));
			i++;
		}
		while (out.length && out[out.length - 1] === '') { out.pop(); }
		return out.join('\n') + '\n';
	}
	function keyValue(content, indent) {
		const m = content.match(/^([A-Za-z_][A-Za-z0-9_ ]*):(?:\s+(.*))?$/);
		if (!m) { fail('expected "key: value", got: ' + content); }
		const rest = m[2] === undefined ? '' : m[2];
		if (rest === '|' || rest === '|-' || rest === '>') { i++; return [m[1], blockScalar(indent)]; }
		if (rest.trim() === '') { i++; skip(); return [m[1], i < lines.length && indentOf(lines[i]) > indent ? node(indentOf(lines[i])) : (i < lines.length && indentOf(lines[i]) === indent && /^\s*- /.test(lines[i]) ? node(indent) : null)]; }
		// Plain multi-line continuation (rare): following deeper lines that are not "key:".
		let value = rest;
		i++;
		while (i < lines.length && /^\s+\S/.test(lines[i]) && indentOf(lines[i]) > indent && !/^\s*(?:- |[A-Za-z_][A-Za-z0-9_ ]*:(?:\s|$))/.test(lines[i])) { value += ' ' + lines[i].trim(); i++; }
		return [m[1], scalar(value)];
	}
	function mapping(indent, first) {
		const obj = {};
		if (first) { const [k, v] = keyValue(first, indent); obj[k] = v; }
		for (;;) {
			skip();
			if (i >= lines.length) { break; }
			const n = indentOf(lines[i]);
			if (n < indent || (n === indent && /^\s*- /.test(lines[i]))) { break; }
			if (n > indent) { fail('unexpected indentation'); }
			const [k, v] = keyValue(lines[i].trim(), indent);
			obj[k] = v;
		}
		return obj;
	}
	function sequence(indent) {
		const arr = [];
		for (;;) {
			skip();
			if (i >= lines.length || indentOf(lines[i]) !== indent || !/^\s*- /.test(lines[i])) { break; }
			const content = lines[i].trim().slice(2);
			if (/^[A-Za-z_][A-Za-z0-9_ ]*:(?:\s|$)/.test(content)) { arr.push(mapping(indent + 2, content)); }
			else { arr.push(scalar(content)); i++; }
		}
		return arr;
	}
	function node(indent) { skip(); return /^\s*- /.test(lines[i]) ? sequence(indent) : mapping(indent); }
	skip();
	const doc = mapping(0);
	skip();
	if (i < lines.length) { fail('unparsed content'); }
	return doc;
}

// ---------------------------------------------------------------- build
function args() {
	const a = process.argv.slice(2);
	const get = k => { const j = a.indexOf(k); return j >= 0 ? a[j + 1] : null; };
	return { source: get('--source'), fetch: get('--fetch') };
}

function main() {
	const { source, fetch } = args();
	let dir = source;
	if (fetch) {
		if (!/^[0-9a-f]{40}$/.test(fetch)) { throw new Error('--fetch needs a full 40-character commit sha'); }
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lolbas-'));
		execFileSync('git', ['clone', '--quiet', REPO, dir], { stdio: 'inherit' });
		execFileSync('git', ['-C', dir, 'checkout', '--quiet', fetch], { stdio: 'inherit' });
	}
	if (!dir) { throw new Error('Usage: --source <LOLBAS checkout> | --fetch <commit-sha>'); }
	const git = (...x) => execFileSync('git', ['-C', dir, ...x]).toString().trim();
	const commit = git('rev-parse', 'HEAD');
	const commitDate = git('log', '-1', '--format=%cI');
	if (git('status', '--porcelain')) { throw new Error('Source checkout has local changes; use a clean checkout.'); }
	const license = fs.readFileSync(path.join(dir, 'LICENSE'), 'utf8');
	if (!/GNU GENERAL PUBLIC LICENSE\s+Version 3, 29 June 2007/.test(license)) { throw new Error('Upstream LICENSE is no longer GPL-3.0: review licensing before updating.'); }

	const entries = [];
	const files = {};
	let commands = 0;
	for (const section of Object.keys(SITE_SECTION)) {
		const sdir = path.join(dir, 'yml', section);
		if (!fs.existsSync(sdir)) { continue; }
		for (const f of fs.readdirSync(sdir).filter(x => /\.ya?ml$/i.test(x)).sort()) {
			const rel = `yml/${section}/${f}`;
			const text = fs.readFileSync(path.join(sdir, f), 'utf8');
			files[rel] = crypto.createHash('sha256').update(text).digest('hex');
			const doc = parseYaml(text, rel);
			const expected = (text.match(/^\s*- Command:/gm) || []).length;
			const cmds = Array.isArray(doc.Commands) ? doc.Commands : [];
			if (cmds.length !== expected) { throw new Error(`${rel}: parsed ${cmds.length} commands, file has ${expected}`); }
			if (!doc.Name || !/\.(exe|dll|vbs|js|wsf|ps1|cmd|bat|cpl|msc|hta|sys|ocx)$/i.test(doc.Name)) { throw new Error(`${rel}: unexpected Name ${doc.Name}`); }
			const det = Array.isArray(doc.Detection) ? doc.Detection : [];
			const entry = {
				name: doc.Name,
				type: section,
				description: String(doc.Description || '').trim(),
				paths: (doc.Full_Path || []).map(p => p && p.Path).filter(Boolean),
				commands: cmds.map(c => {
					for (const k of ['Command', 'Description', 'Usecase', 'Category', 'Privileges', 'MitreID']) { if (c[k] === undefined || c[k] === null) { throw new Error(`${rel}: command without ${k}`); } }
					return { command: String(c.Command).trim(), description: String(c.Description).trim(), usecase: String(c.Usecase).trim(), category: String(c.Category).trim(), privileges: String(c.Privileges).trim(), mitre: String(c.MitreID).trim(), os: c.OperatingSystem ? String(c.OperatingSystem).trim() : '' };
				}),
				ioc: det.map(d => d && d.IOC).filter(Boolean).map(String),
				references: det.flatMap(d => d ? ['Sigma', 'Elastic', 'Splunk', 'BlockRule', 'Analysis'].filter(k => d[k]).map(k => [k, String(d[k])]) : []).filter(([, u]) => /^https:\/\/[^\s"'<>]+$/.test(u)),
				page: `https://lolbas-project.github.io/lolbas/${SITE_SECTION[section]}/${doc.Name.replace(/\.[A-Za-z]+$/, '')}/`
			};
			commands += entry.commands.length;
			entries.push(entry);
		}
	}
	if (entries.length < 150) { throw new Error('Too few entries parsed: ' + entries.length); }
	const meta = {
		source: 'LOLBAS Project (https://github.com/LOLBAS-Project/LOLBAS)',
		commit,
		commitDate,
		license: 'GPL-3.0',
		snapshotOf: 'yml/' + Object.keys(SITE_SECTION).join(', yml/'),
		entries: entries.length,
		commands,
		modified: 'Converted from YAML to JSON by deploy/tools-lotl-analyzer/update-lolbas-data.cjs. Only the fields Name, Description, Full_Path, Commands (Command, Description, Usecase, Category, Privileges, MitreID, OperatingSystem), Detection (IOC, Sigma, Elastic, Splunk, BlockRule, Analysis) are kept; Author, Acknowledgement, Resources and Code_Sample are omitted. A link to each entry page is added.'
	};
	const header = [
		'/*!',
		' * LOLBAS data snapshot for the CyberDat LotL / LOLBAS Command Analyzer.',
		` * Source: LOLBAS Project, https://github.com/LOLBAS-Project/LOLBAS, commit ${commit} (${commitDate}).`,
		' * Copyright (C) the LOLBAS Project contributors. Licensed under the GNU General Public License v3.0;',
		' * the full license text is in LICENSE-LOLBAS.txt next to this file. This is a MODIFIED version:',
		' * ' + meta.modified,
		' * Generated file: do not edit by hand. Regenerate with deploy/tools-lotl-analyzer/update-lolbas-data.cjs.',
		' * MITRE ATT&CK(R) technique ids are as given by LOLBAS. ATT&CK(R) is a registered trademark of The MITRE Corporation.',
		' */'
	].join('\n');
	const body = `(function (root) {\n\t'use strict';\n\tconst data = ${JSON.stringify({ meta, entries })};\n\tif (typeof module === 'object' && module.exports) { module.exports = data; } else { root.CyberDatLolbasData = data; }\n}(typeof self !== 'undefined' ? self : this));\n`;
	fs.mkdirSync(OUT_DIR, { recursive: true });
	fs.writeFileSync(path.join(OUT_DIR, 'lolbas-data.js'), header + '\n' + body);
	fs.writeFileSync(path.join(OUT_DIR, 'LICENSE-LOLBAS.txt'), license);
	fs.writeFileSync(path.join(__dirname, 'lolbas-snapshot.json'), JSON.stringify({ ...meta, generatedBy: 'deploy/tools-lotl-analyzer/update-lolbas-data.cjs', files }, null, 2) + '\n');
	console.log(`LOLBAS ${commit.slice(0, 12)} (${commitDate}): ${entries.length} entries, ${commands} documented commands.`);
}

if (require.main === module) {
	try { main(); } catch (e) { console.error('FAIL: ' + e.message); process.exit(1); }
}
module.exports = { parseYaml };
