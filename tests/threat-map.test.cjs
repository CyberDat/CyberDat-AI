/*
 * Global Cyber Threat Map: browser script logic, geometry file, ISO table and first-party-only assets (no network).
 *   node tests/threat-map.test.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const THEME = path.join(__dirname, '..', 'wp-content', 'themes', 'cyberdat');
const read = p => fs.readFileSync(path.join(THEME, p), 'utf8').replace(/\r\n/g, '\n');
const m = require(path.join(THEME, 'assets', 'js', 'threat-map.js'));
let n = 0;
const pass = label => { n++; console.log('PASS: ' + label); };

assert.deepEqual(m.edges(0), []);
assert.deepEqual(m.edges(1), [1]);
assert.deepEqual(m.edges(3), [1, 2, 3]);
assert.deepEqual(m.edges(1000), [1, 6, 32, 178, 1000]);
for (const max of [1, 2, 5, 17, 99, 12345]) {
	const e = m.edges(max);
	assert.ok(e.every((v, i) => v <= max && (i === 0 || v > e[i - 1])), 'increasing for ' + max);
	assert.equal(m.step(max, e), e.length);
}
pass('colour steps: geometric, strictly increasing, the maximum gets the top step');
assert.equal(m.step(0, m.edges(10)), 0);
assert.equal(m.step(1, m.edges(10)), 1);
assert.deepEqual(m.legend(m.edges(3), 3).map(x => x.label), ['1', '2', '3']);
assert.deepEqual(m.legend(m.edges(1000), 1000).map(x => x.label), ['1–5', '6–31', '32–177', '178–999', '1,000']);
pass('legend: ranges without gaps or overlaps');
assert.equal(m.delta(5, undefined), null);
assert.deepEqual(m.delta(5, 0), { text: 'new', dir: 'up' });
assert.deepEqual(m.delta(0, 0), { text: '0', dir: '' });
assert.deepEqual(m.delta(15, 10), { text: '+50%', dir: 'up' });
assert.deepEqual(m.delta(5, 10), { text: '-50%', dir: 'down' });
pass('change vs previous period: none without a comparable period, "new" from zero');
assert.equal(m.freshness(1000, 1000 + 10800), 'ok');
assert.equal(m.freshness(1000, 1000 + 10801), 'stale');
assert.equal(m.freshness(1000, 1000 + 172801), 'unavailable');
assert.equal(m.freshness(null, 1), 'unavailable');
assert.equal(m.ago(30), 'less than a minute ago');
assert.equal(m.ago(14 * 60), '14 min ago');
pass('freshness and "Updated N min ago" in the browser match the server thresholds (3 h, 48 h)');
assert.deepEqual(m.edgesShare(0), []);
assert.deepEqual(m.edgesShare(19.81), [0.01, 0.2, 0.79, 2.97, 8.91]);
assert.deepEqual(m.edgesShare(0.005), [0.005]);
for (const max of [0.03, 0.5, 4.3, 37.2, 100]) { const e = m.edgesShare(max); assert.ok(e.every((v, i) => v <= max && (i === 0 || v > e[i - 1])), 'share edges ' + max); assert.equal(m.step(max, e), e.length); }
assert.deepEqual(m.legendShare([0.01, 0.2, 0.79, 2.97, 8.91], 19.81).map(x => x.label), ['0.01–0.20%', '0.20–0.79%', '0.79–2.97%', '2.97–8.91%', '≥ 8.91% (max 19.81%)']);
assert.deepEqual(m.deltaShare(4.3, 3.8), { text: '+0.50 pp', dir: 'up' });
assert.deepEqual(m.deltaShare(1.2, 1.45), { text: '−0.25 pp', dir: 'down' });
assert.deepEqual(m.deltaShare(2, 2), { text: '0.00 pp', dir: '' });
assert.equal(m.deltaShare(2, undefined), null);
pass('shares (Cloudflare Radar): steps and legend in percent; change in percentage points, never a count or a relative change');
assert.equal(m.recordsUrl('https://www.ransomware.live/country/{CC}', 'FR'), 'https://www.ransomware.live/country/FR');
assert.equal(m.recordsUrl('javascript:alert(1)', 'FR'), null);
assert.equal(m.recordsUrl('http://x.example/{CC}', 'FR'), null);
pass('record links: HTTPS only');

const geo = JSON.parse(read('assets/maps/threat-map-countries.json'));
const iso = JSON.parse(read('assets/maps/iso3166-1.json')).countries;
const codes = new Set(iso.map(c => c[0]));
assert.equal(geo.schema, 1);
assert.equal(geo.viewBox, '0 0 1000 400');
assert.match(geo.source, /world-atlas 2\.0\.2, countries-110m\.json/);
assert.match(geo.license, /ISC/);
assert.ok(geo.countries.length >= 170);
assert.ok(geo.countries.every(c => c.iso === null || codes.has(c.iso)));
assert.equal(new Set(geo.countries.filter(c => c.iso).map(c => c.iso)).size, geo.countries.filter(c => c.iso).length);
assert.ok(!geo.countries.some(c => c.iso === 'AQ'), 'Antarctica removed');
assert.ok(geo.countries.every(c => /^(M[-\d. L]+Z)+$/.test(c.d)), 'numeric paths only');
// Coordinates stay in the view box, except the 360° copies of rings that cross the antimeridian (clipped by the SVG).
const outside = geo.countries.filter(c => c.d.match(/-?\d+(\.\d+)?/g).map(Number).some(v => v < 0 || v > 1000)).map(c => c.iso).sort();
assert.deepEqual(outside, ['FJ', 'RU']);
for (const c of geo.countries) for (const v of c.d.match(/-?\d+(\.\d+)?/g).map(Number)) assert.ok(v >= -1000 && v <= 2000);
assert.equal(iso.length, codes.size);
assert.equal(new Set(iso.filter(c => c[1]).map(c => c[1])).size, iso.filter(c => c[1]).length);
const builder = fs.readFileSync(path.join(__dirname, '..', 'tools', 'threat-map', 'build-geometry.cjs'), 'utf8');
assert.ok(builder.includes(geo.input_integrity), 'geometry built from the pinned npm package');
pass('geometry: ' + geo.countries.length + ' areas, valid ISO codes, no Antarctica, numeric paths in the view box, pinned input');

const js = read('assets/js/threat-map.js'), css = read('assets/css/threat-map.css');
assert.ok(!/https?:\/\//.test(js.replace(/'http:\/\/www\.w3\.org\/2000\/svg'/g, '')), 'no absolute URL in the script except the SVG namespace');
assert.ok(!/@import|url\(\s*['"]?https?:/i.test(css));
assert.ok(/fetch\(url\.href, \{ credentials: 'same-origin', redirect: 'error'/.test(js) && /url\.origin !== location\.origin/.test(js));
assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(js), 'no HTML built from strings');
assert.ok(!/localStorage|sessionStorage|document\.cookie/.test(js));
pass('script and styles: same-origin fetch of the theme geometry only; no CDN, storage or HTML from data');

const assets = read('inc/assets.php');
assert.ok(/if\(\$intelligence\) \{[\s\S]*?threat-map\.js[\s\S]*?\n \}/.test(assets), 'map script only on the intelligence page');
assert.ok(!/cyberdat-threat-geo',get_theme_file_uri\('\/assets\/js\/threat-geo\.js/.test(assets));
assert.equal((assets.match(/threat-map\.(js|css)/g) || []).length, 4);
pass('assets: map CSS and JS enqueued on the Threat Intelligence page only');

const units = fs.readdirSync(path.join(__dirname, '..', 'docs', 'threat-map'));
const service = fs.readFileSync(path.join(__dirname, '..', 'docs', 'threat-map', 'cyberdat-threatmap.service'), 'utf8');
const timer = fs.readFileSync(path.join(__dirname, '..', 'docs', 'threat-map', 'cyberdat-threatmap.timer'), 'utf8');
assert.ok(units.includes('cyberdat-threatmap.service') && units.includes('cyberdat-threatmap.timer'));
assert.match(service, /^User=cyberdat-staging$/m);
assert.ok(!/^User=root/m.test(service));
assert.match(service, /wp cyberdat threatmap sync|threatmap sync/);
assert.match(timer, /^OnCalendar=\*-\*-\* \*:07,27,47:00 UTC$/m);
pass('systemd samples: site user (no root), sync at :07, :27, :47');

const digest = crypto.createHash('sha256').update(fs.readFileSync(path.join(THEME, 'assets', 'maps', 'threat-map-countries.json'))).digest('hex');
console.log(`PASS: threat map — ${n} groups; geometry sha256 ${digest.slice(0, 16)}…`);
