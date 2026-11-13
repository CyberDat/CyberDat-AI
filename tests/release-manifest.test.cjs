/*
 * The combined release manifest must describe the committed theme files exactly.
 *   node tests/release-manifest.test.cjs
 */
'use strict';
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const out = execFileSync(process.execPath, [path.join(__dirname, '../deploy/tools-release-1/build-manifest.cjs'), 'HEAD', '--check'], { cwd: path.join(__dirname, '..') }).toString();
process.stdout.write(out);
