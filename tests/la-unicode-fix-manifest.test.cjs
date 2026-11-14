/*
 * The la-unicode-fix package manifest must describe its theme commit exactly (base = installed release-1 theme).
 * Checked against the manifest's own theme_commit, so later branches built on it (la-unicode-marks) still verify it.
 *   node tests/la-unicode-fix-manifest.test.cjs
 */
'use strict';
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const commit = require('../deploy/tools-la-unicode-fix/manifest.json').theme_commit;
process.stdout.write(execFileSync(process.execPath, [path.join(__dirname, '../deploy/tools-la-unicode-fix/build-manifest.cjs'), commit, '--check'], { cwd: path.join(__dirname, '..') }).toString());
