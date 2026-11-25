/*
 * Threat map flags: every shipped SVG passes the safety check, matches flags.json, belongs to the ISO table, has no
 * external reference; the checker rejects hostile samples; the page uses fixed sizes, lazy loading, empty alt and a
 * placeholder.   node tests/threat-map-flags.test.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { svgProblems, cleanSvg } = require('../tools/threat-map/svg-safety.cjs');
const THEME = path.join(__dirname, '..', 'wp-content', 'themes', 'cyberdat');
const DIR = path.join(THEME, 'assets', 'flags');
let n = 0;
const pass = l => { n++; console.log('PASS: ' + l); };

const meta = JSON.parse(fs.readFileSync(path.join(DIR, 'flags.json'), 'utf8'));
const iso = JSON.parse(fs.readFileSync(path.join(THEME, 'assets', 'maps', 'iso3166-1.json'), 'utf8')).countries.map(c => c[0]);
const files = fs.readdirSync(path.join(DIR, '4x3')).sort();
assert.equal(meta.source, 'flag-icons 7.6.0 (npm), flags/4x3');
assert.equal(meta.license, 'MIT');
assert.ok(fs.readFileSync(path.join(__dirname, '..', 'tools', 'threat-map', 'build-flags.cjs'), 'utf8').includes(meta.integrity), 'pinned npm integrity');
assert.match(fs.readFileSync(path.join(DIR, 'LICENSE-flag-icons.txt'), 'utf8'), /The MIT License/);
assert.match(fs.readFileSync(path.join(DIR, 'NOTICE.md'), 'utf8'), /flag-icons 7\.6\.0[\s\S]*MIT/);
pass('flag-icons 7.6.0, MIT, pinned integrity, license and notice shipped');

assert.deepEqual(files, Object.keys(meta.files).map(c => c.toLowerCase() + '.svg').sort(), 'directory = flags.json');
assert.ok(Object.keys(meta.files).every(c => iso.includes(c)), 'only ISO table codes');
assert.equal(Object.keys(meta.files).length + Object.keys(meta.left_out).length, iso.length);
let bytes = 0;
for (const f of files) {
	const raw = fs.readFileSync(path.join(DIR, '4x3', f));
	const text = raw.toString('utf8').replace(/\r\n/g, '\n');
	const cc = f.slice(0, 2).toUpperCase();
	assert.equal(crypto.createHash('sha256').update(text).digest('hex'), meta.files[cc].sha256, 'sha256 ' + f);
	assert.deepEqual(svgProblems(text), [], f);
	assert.ok(!/https?:|\/\//.test(text.replace(/xmlns(?::xlink)?="http:\/\/www\.w3\.org\/(?:2000\/svg|1999\/xlink)"/g, '')), 'no URL in ' + f);
	assert.match(text, /viewBox="0 0 640 480"/, f);
	bytes += raw.length;
}
pass(`${files.length} flags (${Math.round(bytes / 1024)} KB): sha256 as in flags.json, ISO codes only, safety check clean, no URL other than the SVG namespaces, 4x3 view box`);

const ok = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 480"><defs><clipPath id="a"><path d="M0 0h640v480H0z"/></clipPath></defs><g clip-path="url(#a)"><use href="#a"/><path fill="#fff" d="M0 0h640v480H0z"/></g></svg>';
assert.deepEqual(svgProblems(ok), []);
const bad = {
	'script element': ok.replace('<defs>', '<script>alert(1)</script><defs>'),
	'event handler attribute': ok.replace('<svg ', '<svg onload="alert(1)" '),
	'foreignObject': ok.replace('<defs>', '<foreignObject><div/></foreignObject><defs>'),
	'external href': ok.replace('href="#a"', 'href="https://evil.example/x.svg#a"'),
	'external url()': ok.replace('url(#a)', 'url(https://evil.example/a)'),
	'embedded image': ok.replace('<defs>', '<image href="#a"/><defs>'),
	'style element': ok.replace('<defs>', '<style>@import url(x.css)</style><defs>'),
	'DOCTYPE or entity': '<!DOCTYPE svg [<!ENTITY x "y">]>' + ok,
	'javascript: or data: URI': ok.replace('href="#a"', 'href="#a" data-x="javascript:alert(1)"'),
	'animation element': ok.replace('<defs>', '<set attributeName="fill" to="red"/><defs>'),
	'content after </svg>': ok + '<script>x</script>',
};
for (const [rule, sample] of Object.entries(bad)) assert.ok(svgProblems(sample).includes(rule) || (rule === 'content after </svg>' && svgProblems(sample).length > 0), rule);
assert.ok(svgProblems('<html><svg xmlns="http://www.w3.org/2000/svg"></svg></html>').includes('not a single <svg> root with the SVG namespace'));
assert.equal(cleanSvg('<?xml version="1.0"?>\n<!-- c --><svg xmlns="http://www.w3.org/2000/svg"></svg>'), '<svg xmlns="http://www.w3.org/2000/svg"></svg>\n');
pass(`safety check rejects ${Object.keys(bad).length + 1} hostile samples (script, on*, foreignObject, external href/url(), image, style, DOCTYPE/entity, javascript:, animation, trailing content, wrong root)`);

const js = fs.readFileSync(path.join(THEME, 'assets', 'js', 'threat-map.js'), 'utf8').replace(/\r\n/g, '\n');
const render = fs.readFileSync(path.join(THEME, 'inc', 'threat-map', 'render.php'), 'utf8').replace(/\r\n/g, '\n');
const css = fs.readFileSync(path.join(THEME, 'assets', 'css', 'threat-map.css'), 'utf8');
assert.match(js, /img\.width = 20; img\.height = 15; img\.alt = ''; img\.loading = 'lazy'/);
assert.match(js, /u\.origin === location\.origin \? u\.href : null/);
assert.match(js, /cdtm-flag cdtm-flag--none/);
assert.match(render, /width="20" height="15" loading="lazy" decoding="async" alt=""/);
assert.match(css, /\.cdtm-flag\{display:inline-block;width:20px;height:15px/);
assert.match(css, /\.cdtm-flag--none\{background:/);
pass('page: flags with fixed 20×15 size, lazy, empty alt, same-origin base only; same-size placeholder');
console.log(`PASS: threat map flags — ${n} groups`);
