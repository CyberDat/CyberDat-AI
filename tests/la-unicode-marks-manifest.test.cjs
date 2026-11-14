/*
 * The la-unicode-marks package manifest must describe its theme commit exactly (base = tools-la-unicode-fix/1 target).
 * Checked against the manifest's own theme_commit, so later branches built on it still verify it.
 *   node tests/la-unicode-marks-manifest.test.cjs
 */
'use strict';
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const commit = require('../deploy/tools-la-unicode-marks/manifest.json').theme_commit;
process.stdout.write(execFileSync(process.execPath, [path.join(__dirname, '../deploy/tools-la-unicode-marks/build-manifest.cjs'), commit, '--check'], { cwd: path.join(__dirname, '..') }).toString());
