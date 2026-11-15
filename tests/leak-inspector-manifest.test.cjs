/*
 * The Leak Inspector package manifest must describe the committed theme exactly (base = installed release-1 theme).
 *   node tests/leak-inspector-manifest.test.cjs
 */
'use strict';
const { execFileSync } = require('node:child_process');
const path = require('node:path');
process.stdout.write(execFileSync(process.execPath, [path.join(__dirname, '../deploy/tools-leak-inspector/build-manifest.cjs'), 'HEAD', '--check'], { cwd: path.join(__dirname, '..') }).toString());
