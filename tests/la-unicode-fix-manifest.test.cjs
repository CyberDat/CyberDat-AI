/*
 * The la-unicode-fix package manifest must describe the committed theme exactly (base = installed release-1 theme).
 *   node tests/la-unicode-fix-manifest.test.cjs
 */
'use strict';
const { execFileSync } = require('node:child_process');
const path = require('node:path');
process.stdout.write(execFileSync(process.execPath, [path.join(__dirname, '../deploy/tools-la-unicode-fix/build-manifest.cjs'), 'HEAD', '--check'], { cwd: path.join(__dirname, '..') }).toString());
