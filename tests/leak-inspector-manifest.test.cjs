/*
 * The Leak Inspector package manifest must describe its theme commit exactly (base = installed release-1 theme).
 * Checked against the manifest's own theme_commit, so branches built on it (integration/tools-release-1.2) still verify it.
 *   node tests/leak-inspector-manifest.test.cjs
 */
'use strict';
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const commit = require('../deploy/tools-leak-inspector/manifest.json').theme_commit;
process.stdout.write(execFileSync(process.execPath, [path.join(__dirname, '../deploy/tools-leak-inspector/build-manifest.cjs'), commit, '--check'], { cwd: path.join(__dirname, '..') }).toString());
