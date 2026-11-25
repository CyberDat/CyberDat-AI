/* The threat-map-1 package manifest matches its recorded theme commit (base 5c12bef, delta only). */
'use strict';
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const commit = require('../deploy/threat-map-1/manifest.json').theme_commit;
process.stdout.write(execFileSync(process.execPath, [path.join(__dirname, '../deploy/threat-map-1/build-manifest.cjs'), commit, '--check'], { cwd: path.join(__dirname, '..') }).toString());
