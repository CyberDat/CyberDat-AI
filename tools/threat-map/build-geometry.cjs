#!/usr/bin/env node
/*
 * Builds the static country geometry of the Global Cyber Threat Map.
 *
 * Input:  world-atlas 2.0.2 (npm, ISC license; data from Natural Earth, public domain), file countries-110m.json.
 * Output: wp-content/themes/cyberdat/assets/maps/threat-map-countries.json, one SVG path per country,
 *         equirectangular projection, Antarctica removed, ISO 3166-1 alpha-2 codes from assets/maps/iso3166-1.json.
 *
 * Usage:  node tools/threat-map/build-geometry.cjs <world-atlas-2.0.2.tgz>
 *         (download it once from https://registry.npmjs.org/world-atlas/-/world-atlas-2.0.2.tgz; the script checks
 *         the npm integrity hash below and refuses any other file). No network access, no dependencies.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const INTEGRITY = 'sha512-IXfV0qwlKXpckz1FhwXVwKRjiIhOnWttOskm5CtxMsjgE/MXAYRHWJqgXOpM8IkcPBoXnyTU5lFHcYa5ChG0LQ==';
const MEMBER = 'package/countries-110m.json';
const THEME = path.join(__dirname, '..', '..', 'wp-content', 'themes', 'cyberdat');
const OUT = path.join(THEME, 'assets', 'maps', 'threat-map-countries.json');
const ISO = path.join(THEME, 'assets', 'maps', 'iso3166-1.json');
// Equirectangular: 1000 px for 360 degrees of longitude, the same scale for latitude, from 84 N down to 60 S.
const WIDTH = 1000, LAT_TOP = 84, LAT_BOTTOM = -60, K = WIDTH / 360;
const HEIGHT = Math.round((LAT_TOP - LAT_BOTTOM) * K);
const DROP = new Set(['010']); // Antarctica
// Features without a numeric id in world-atlas 2.0.2, keyed by name. Kosovo uses the code the sources use.
const BY_NAME = { Kosovo: 'XK' };

function fail(message) { console.error('build-geometry: ' + message); process.exit(1); }

function untar(buffer, member) {
	for (let at = 0; at + 512 <= buffer.length;) {
		const header = buffer.subarray(at, at + 512);
		if (header.every(b => b === 0)) break;
		const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/s, '');
		const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/s, '');
		const size = parseInt(header.subarray(124, 136).toString('utf8').replace(/\0.*$/s, '').trim() || '0', 8);
		const full = prefix ? prefix + '/' + name : name;
		if (full === member) return buffer.subarray(at + 512, at + 512 + size);
		at += 512 + Math.ceil(size / 512) * 512;
	}
	return null;
}

function decodeArcs(topology) {
	const [sx, sy] = topology.transform.scale, [tx, ty] = topology.transform.translate;
	return topology.arcs.map(arc => {
		let x = 0, y = 0;
		return arc.map(([dx, dy]) => { x += dx; y += dy; return [x * sx + tx, y * sy + ty]; });
	});
}

function ring(arcs, indexes) {
	const points = [];
	for (const index of indexes) {
		const arc = index < 0 ? arcs[~index].slice().reverse() : arcs[index];
		arc.forEach((point, i) => { if (i > 0 || points.length === 0) points.push(point); });
	}
	return points;
}

function project([lon, lat]) {
	return [(lon + 180) * K, (LAT_TOP - Math.max(LAT_BOTTOM, Math.min(LAT_TOP, lat))) * K];
}

// Rings that cross the antimeridian (Russia, Fiji) are unwrapped to continuous longitudes; a ring that then
// extends past ±180° is drawn a second time shifted by 360°, and the SVG view box clips both copies.
function unwrap(points) {
	const out = [];
	let shift = 0;
	points.forEach(([lon, lat], i) => {
		if (i > 0) {
			const prev = points[i - 1][0];
			if (lon - prev > 180) shift -= 360; else if (prev - lon > 180) shift += 360;
		}
		out.push([lon + shift, lat]);
	});
	const lons = out.map(p => p[0]);
	const copies = [out];
	if (Math.max(...lons) > 180) copies.push(out.map(([lon, lat]) => [lon - 360, lat]));
	if (Math.min(...lons) < -180) copies.push(out.map(([lon, lat]) => [lon + 360, lat]));
	return copies;
}

function pathOf(polygons, arcs) {
	let d = '';
	for (const polygon of polygons) {
		for (const points of polygon.flatMap(indexes => unwrap(ring(arcs, indexes)))) {
			let last = '';
			const parts = [];
			for (const point of points) {
				const [x, y] = project(point);
				const pair = x.toFixed(1).replace(/\.0$/, '') + ' ' + y.toFixed(1).replace(/\.0$/, '');
				if (pair !== last) parts.push(pair);
				last = pair;
			}
			if (parts.length >= 3) d += 'M' + parts.join('L') + 'Z';
		}
	}
	return d;
}

function main() {
	const input = process.argv[2];
	if (!input) fail('usage: node tools/threat-map/build-geometry.cjs <world-atlas-2.0.2.tgz>');
	const tgz = fs.readFileSync(input);
	const integrity = 'sha512-' + crypto.createHash('sha512').update(tgz).digest('base64');
	if (integrity !== INTEGRITY) fail('integrity mismatch: not the world-atlas 2.0.2 package from npm');
	const raw = untar(zlib.gunzipSync(tgz), MEMBER);
	if (!raw) fail('countries-110m.json not found in the package');
	const topology = JSON.parse(raw.toString('utf8'));
	if (topology.type !== 'Topology' || !topology.objects || !topology.objects.countries) fail('unexpected TopoJSON');

	const iso = JSON.parse(fs.readFileSync(ISO, 'utf8')).countries;
	const byNumeric = new Map(iso.filter(c => c[1]).map(c => [c[1], c[0]]));
	const arcs = decodeArcs(topology);
	const countries = [];
	const used = new Set();
	for (const geometry of topology.objects.countries.geometries) {
		const id = geometry.id === undefined ? '' : String(geometry.id).padStart(3, '0');
		if (DROP.has(id)) continue;
		const name = geometry.properties && geometry.properties.name;
		const code = id ? byNumeric.get(id) : BY_NAME[name];
		if (id && !code) fail('no ISO alpha-2 code for numeric id ' + id + ' (' + name + ')');
		if (code && used.has(code)) fail('duplicate code ' + code);
		if (code) used.add(code);
		const polygons = geometry.type === 'Polygon' ? [geometry.arcs] : geometry.type === 'MultiPolygon' ? geometry.arcs : [];
		const d = pathOf(polygons, arcs);
		if (!d) continue;
		// A feature without any ISO code (for example a disputed area) is drawn as neutral land, never coloured.
		countries.push({ iso: code || null, name: code ? iso.find(c => c[0] === code)[2] : String(name || 'Unnamed area'), d });
	}
	countries.sort((a, b) => (a.iso || 'ZZZ' + a.name).localeCompare(b.iso || 'ZZZ' + b.name));
	const output = {
		schema: 1,
		source: 'world-atlas 2.0.2, countries-110m.json (npm)',
		license: 'world-atlas: ISC license (Mike Bostock). Data: Natural Earth, public domain.',
		input_integrity: INTEGRITY,
		input_sha256: crypto.createHash('sha256').update(raw).digest('hex'),
		projection: 'equirectangular; longitude -180..180, latitude ' + LAT_TOP + '..' + LAT_BOTTOM + '; Antarctica removed',
		viewBox: '0 0 ' + WIDTH + ' ' + HEIGHT,
		countries
	};
	fs.writeFileSync(OUT, JSON.stringify(output) + '\n');
	console.log('wrote ' + path.relative(process.cwd(), OUT) + ': ' + countries.length + ' areas, ' +
		countries.filter(c => !c.iso).length + ' without ISO code, ' + fs.statSync(OUT).size + ' bytes');
}

main();
