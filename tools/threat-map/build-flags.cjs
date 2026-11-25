#!/usr/bin/env node
/*
 * Builds the country flags of the Global Cyber Threat Map from flag-icons 7.6.0 (npm, MIT), 4x3 SVG.
 *   node tools/threat-map/build-flags.cjs <flag-icons-7.6.0.tgz>
 * The npm integrity hash is checked; only codes of assets/maps/iso3166-1.json are taken; every SVG must pass
 * tools/threat-map/svg-safety.cjs or it is left out (and listed). Output: assets/flags/4x3/<cc>.svg and
 * assets/flags/flags.json (version, integrity, sha256 per file, left-out codes). No network, no dependencies.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { svgProblems, cleanSvg } = require('./svg-safety.cjs');

const VERSION = '7.6.0';
const INTEGRITY = 'sha512-hir/PsXwr0EESyizKrXJzmkzpLIMf+1vlNKLqAfvdh+bsU94a7LYWTiubkHKqptGoCPzOUGcm6c4PfC9/BaGSQ==';
const THEME = path.join(__dirname, '..', '..', 'wp-content', 'themes', 'cyberdat');
const OUT = path.join(THEME, 'assets', 'flags');
const fail = m => { console.error('build-flags: ' + m); process.exit(1); };

function untarAll(buffer) {
	const files = new Map();
	for (let at = 0; at + 512 <= buffer.length;) {
		const h = buffer.subarray(at, at + 512);
		if (h.every(b => b === 0)) break;
		const field = (a, b) => h.subarray(a, b).toString('utf8').replace(/\0.*$/s, '');
		const name = (field(345, 500) ? field(345, 500) + '/' : '') + field(0, 100);
		const size = parseInt(field(124, 136).trim() || '0', 8);
		files.set(name, buffer.subarray(at + 512, at + 512 + size));
		at += 512 + Math.ceil(size / 512) * 512;
	}
	return files;
}

const tgz = fs.readFileSync(process.argv[2] || fail('usage: node tools/threat-map/build-flags.cjs <flag-icons-7.6.0.tgz>'));
if ('sha512-' + crypto.createHash('sha512').update(tgz).digest('base64') !== INTEGRITY) fail('integrity mismatch: not flag-icons ' + VERSION + ' from npm');
const files = untarAll(zlib.gunzipSync(tgz));
const pkg = JSON.parse(files.get('package/package.json').toString('utf8'));
if (pkg.version !== VERSION || pkg.license !== 'MIT') fail('unexpected package ' + pkg.version + ' ' + pkg.license);
const codes = JSON.parse(fs.readFileSync(path.join(THEME, 'assets', 'maps', 'iso3166-1.json'), 'utf8')).countries.map(c => c[0]);
fs.rmSync(path.join(OUT, '4x3'), { recursive: true, force: true });
fs.mkdirSync(path.join(OUT, '4x3'), { recursive: true });
const out = {}, leftOut = {};
for (const cc of codes) {
	const raw = files.get('package/flags/4x3/' + cc.toLowerCase() + '.svg');
	if (!raw) { leftOut[cc] = 'no file in the package'; continue; }
	const svg = cleanSvg(raw.toString('utf8'));
	const problems = svgProblems(svg);
	if (problems.length) { leftOut[cc] = problems.join('; '); continue; }
	fs.writeFileSync(path.join(OUT, '4x3', cc.toLowerCase() + '.svg'), svg);
	out[cc] = { bytes: Buffer.byteLength(svg), sha256: crypto.createHash('sha256').update(svg).digest('hex') };
}
fs.writeFileSync(path.join(OUT, 'flags.json'), JSON.stringify({
	schema: 1, source: 'flag-icons ' + VERSION + ' (npm), flags/4x3', license: 'MIT', integrity: INTEGRITY,
	format: '4x3 SVG, viewBox 0 0 640 480', files: out, left_out: leftOut,
}, null, 1) + '\n');
fs.writeFileSync(path.join(OUT, 'LICENSE-flag-icons.txt'), files.get('package/LICENSE'));
console.log('flags: ' + Object.keys(out).length + ' written, ' + Object.keys(leftOut).length + ' left out' + (Object.keys(leftOut).length ? ' (' + Object.entries(leftOut).map(([k, v]) => k + ': ' + v).join(', ') + ')' : ''));
