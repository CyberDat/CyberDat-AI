/*
 * Rebuilds the threat map geometry twice from the pinned world-atlas 2.0.2 package and checks that both builds and
 * the committed file are byte-identical (deterministic build, UN-borders step included). Needs the npm tarball:
 *   THREAT_MAP_WORLD_ATLAS_TGZ=<world-atlas-2.0.2.tgz> node tests/threat-map-geometry-build.test.cjs
 * Without it: SKIP (CI has no network and the tarball is not in the repository).
 */
'use strict';
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const tgz = process.env.THREAT_MAP_WORLD_ATLAS_TGZ;
if (!tgz || !fs.existsSync(tgz)) { console.log('SKIP: set THREAT_MAP_WORLD_ATLAS_TGZ to the world-atlas 2.0.2 tarball from npm'); process.exit(0); }
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cdtm-geo-'));
const build = out => { execFileSync(process.execPath, [path.join(__dirname, '..', 'tools', 'threat-map', 'build-geometry.cjs'), tgz, out]); return crypto.createHash('sha256').update(fs.readFileSync(out)).digest('hex'); };
const a = build(path.join(dir, 'a.json')), b = build(path.join(dir, 'b.json'));
const committed = crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname, '..', 'wp-content', 'themes', 'cyberdat', 'assets', 'maps', 'threat-map-countries.json'), 'utf8').replace(/\r\n/g, '\n')).digest('hex');
assert.equal(a, b);
assert.equal(a, committed);
fs.rmSync(dir, { recursive: true, force: true });
console.log('PASS: geometry build is deterministic — two builds and the committed file have sha256 ' + a);
