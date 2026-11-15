/*
 * The tools-release-1.2 package manifest must describe its theme commit exactly (base = tools-la-unicode-marks/1 target).
 * Checked against the manifest's own theme_commit, so later branches built on it still verify it.
 *   node tests/tools-release-1.2-manifest.test.cjs
 */
'use strict';
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const commit = require('../deploy/tools-release-1.2/manifest.json').theme_commit;
process.stdout.write(execFileSync(process.execPath, [path.join(__dirname, '../deploy/tools-release-1.2/build-manifest.cjs'), commit, '--check'], { cwd: path.join(__dirname, '..') }).toString());
