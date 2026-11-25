#!/usr/bin/env node
/*
 * Builds the static country geometry of the Global Cyber Threat Map.
 *
 * Input:  world-atlas 2.0.2 (npm, ISC license; data from Natural Earth, public domain), file countries-110m.json.
 * Output: wp-content/themes/cyberdat/assets/maps/threat-map-countries.json, one SVG path per country,
 *         equirectangular projection, Antarctica removed, ISO 3166-1 alpha-2 codes from assets/maps/iso3166-1.json.
 *
 * Usage:  node tools/threat-map/build-geometry.cjs <world-atlas-2.0.2.tgz> [output.json]  (default: the theme file)
 *         (download it once from https://registry.npmjs.org/world-atlas/-/world-atlas-2.0.2.tgz; the script checks
 *         the npm integrity hash below and refuses any other file). No network access, no dependencies.
 *
 * Borders follow UN-recognised boundaries: Crimea is shown as part of Ukraine. Derived from Natural Earth 1:110m.
 * Natural Earth draws de facto control; this script changes it in one explicit step (unBorders), after reading the
 * topology and before drawing:
 *   1. Crimea: the one polygon of Russia (643) whose bounding box lies in lon 32.0..37.0, lat 44.0..46.7 (Natural
 *      Earth: about 32.4..36.6, 44.3..46.3) is moved to Ukraine (804). It is found by its bounding box, never by
 *      index; if not exactly one polygon matches, the build stops.
 *   2. "N. Cyprus" is joined to Cyprus (CY) and "Somaliland" to Somalia (SO); they are not shown as countries.
 *   3. Kosovo stays a separate area (XK), as the data sources use that code.
 * Joined polygons are merged along their shared arcs (like topojson.merge), so no internal border line is drawn.
 * The build stops if any area is left without an ISO code. The output is deterministic (same input → same bytes).
 */
'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const INTEGRITY = 'sha512-IXfV0qwlKXpckz1FhwXVwKRjiIhOnWttOskm5CtxMsjgE/MXAYRHWJqgXOpM8IkcPBoXnyTU5lFHcYa5ChG0LQ==';
const MEMBER = 'package/countries-110m.json';
const THEME = path.join(__dirname, '..', '..', 'wp-content', 'themes', 'cyberdat');
const OUT = process.argv[3] ? path.resolve(process.argv[3]) : path.join(THEME, 'assets', 'maps', 'threat-map-countries.json');
const ISO = path.join(THEME, 'assets', 'maps', 'iso3166-1.json');
// Equirectangular: 1000 px for 360 degrees of longitude, the same scale for latitude, from 84 N down to 60 S.
const WIDTH = 1000, LAT_TOP = 84, LAT_BOTTOM = -60, K = WIDTH / 360;
const HEIGHT = Math.round((LAT_TOP - LAT_BOTTOM) * K);
const DROP = new Set(['010']); // Antarctica
// Features without a numeric id in world-atlas 2.0.2, keyed by name. Kosovo uses the code the sources use.
const BY_NAME = { Kosovo: 'XK' };
// UN-recognised boundaries (see the header): areas joined to a country, and the Crimea search box.
const JOIN_BY_NAME = { 'N. Cyprus': 'CY', Somaliland: 'SO' };
const CRIMEA_BOX = { lonMin: 32.0, lonMax: 37.0, latMin: 44.0, latMax: 46.7 };

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

function bbox(points) {
	const xs = points.map(p => p[0]), ys = points.map(p => p[1]);
	return { lonMin: Math.min(...xs), lonMax: Math.max(...xs), latMin: Math.min(...ys), latMax: Math.max(...ys) };
}

/**
 * Merges polygons that share arcs into rings of points (like topojson.merge): an arc used twice by the merged rings
 * is an internal border and is dropped; the remaining arcs are stitched end to start in input order.
 */
function mergeRings(polygons, arcs) {
	const count = new Map();
	for (const polygon of polygons) for (const r of polygon) for (const i of r) { const k = i < 0 ? ~i : i; count.set(k, (count.get(k) || 0) + 1); }
	const kept = [];
	for (const polygon of polygons) for (const r of polygon) for (const i of r) if (count.get(i < 0 ? ~i : i) === 1) kept.push(i < 0 ? arcs[~i].slice().reverse() : arcs[i]);
	const key = p => p[0].toFixed(7) + ',' + p[1].toFixed(7);
	const byStart = new Map();
	kept.forEach((a, n) => { const k = key(a[0]); if (!byStart.has(k)) byStart.set(k, []); byStart.get(k).push(n); });
	const done = new Set(), rings = [];
	for (let first = 0; first < kept.length; first++) {
		if (done.has(first)) continue;
		const start = key(kept[first][0]), points = [];
		for (let cur = first; ;) {
			done.add(cur);
			kept[cur].forEach((q, j) => { if (j > 0 || points.length === 0) points.push(q); });
			const end = key(kept[cur][kept[cur].length - 1]);
			if (end === start) break;
			cur = (byStart.get(end) || []).find(n => !done.has(n));
			if (cur === undefined) fail('a merged ring does not close');
		}
		rings.push(points);
	}
	return rings;
}

/** The explicit UN-borders step (see the header). Changes the feature map in place. */
function unBorders(features, arcs) {
	const ru = features.get('RU'), ua = features.get('UA');
	if (!ru || !ua) fail('Russia or Ukraine missing in the topology');
	const inBox = p => { const b = bbox(ring(arcs, p[0])); return b.lonMin >= CRIMEA_BOX.lonMin && b.lonMax <= CRIMEA_BOX.lonMax && b.latMin >= CRIMEA_BOX.latMin && b.latMax <= CRIMEA_BOX.latMax; };
	const crimea = ru.polygons.filter(inBox);
	if (crimea.length !== 1) fail('expected exactly one Crimea polygon in Russia (643), found ' + crimea.length);
	ru.polygons = ru.polygons.filter(p => p !== crimea[0]);
	ua.polygons.push(crimea[0]);
	ua.merge = true;
	for (const [name, code] of Object.entries(JOIN_BY_NAME)) {
		const area = features.get('name:' + name), into = features.get(code);
		if (!area || !into) fail('cannot join ' + name + ' to ' + code);
		into.polygons.push(...area.polygons);
		into.merge = true;
		features.delete('name:' + name);
	}
}

/** SVG path of rings of [lon, lat] points (antimeridian copies included). */
function pathOf(rings) {
	let d = '';
	for (const points of rings.flatMap(r => unwrap(r))) {
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
	const features = new Map();
	for (const geometry of topology.objects.countries.geometries) {
		const id = geometry.id === undefined ? '' : String(geometry.id).padStart(3, '0');
		if (DROP.has(id)) continue;
		const name = geometry.properties && geometry.properties.name;
		const code = id ? byNumeric.get(id) : BY_NAME[name];
		if (id && !code) fail('no ISO alpha-2 code for numeric id ' + id + ' (' + name + ')');
		const k = code || 'name:' + name;
		if (features.has(k)) fail('duplicate area ' + k);
		const polygons = geometry.type === 'Polygon' ? [geometry.arcs] : geometry.type === 'MultiPolygon' ? geometry.arcs.slice() : [];
		features.set(k, { code, polygons, merge: false });
	}
	unBorders(features, arcs);
	const countries = [];
	for (const [k, f] of features) {
		if (!f.code) fail('area without an ISO code after the UN-borders step: ' + k);
		const rings = f.merge ? mergeRings(f.polygons, arcs) : f.polygons.flatMap(p => p.map(r => ring(arcs, r)));
		const d = pathOf(rings);
		if (d) countries.push({ iso: f.code, name: iso.find(c => c[0] === f.code)[2], d });
	}
	countries.sort((a, b) => a.iso.localeCompare(b.iso));
	const output = {
		schema: 1,
		source: 'world-atlas 2.0.2, countries-110m.json (npm)',
		license: 'world-atlas: ISC license (Mike Bostock). Data: Natural Earth, public domain.',
		input_integrity: INTEGRITY,
		input_sha256: crypto.createHash('sha256').update(raw).digest('hex'),
		projection: 'equirectangular; longitude -180..180, latitude ' + LAT_TOP + '..' + LAT_BOTTOM + '; Antarctica removed',
		borders: 'Borders follow UN-recognised boundaries: Crimea is shown as part of Ukraine. Derived from Natural Earth 1:110m. N. Cyprus is joined to Cyprus and Somaliland to Somalia; Kosovo is shown separately (XK).',
		viewBox: '0 0 ' + WIDTH + ' ' + HEIGHT,
		countries
	};
	fs.writeFileSync(OUT, JSON.stringify(output) + '\n');
	console.log('wrote ' + path.relative(process.cwd(), OUT) + ': ' + countries.length + ' areas, ' +
		countries.filter(c => !c.iso).length + ' without ISO code, ' + fs.statSync(OUT).size + ' bytes');
}

main();
