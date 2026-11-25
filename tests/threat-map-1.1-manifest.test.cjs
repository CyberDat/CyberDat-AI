/* The threat-map-1.1 package manifest matches its recorded theme commit (base c964927 = threat-map-1, delta only). */
'use strict';
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const commit = require('../deploy/threat-map-1.1/manifest.json').theme_commit;
process.stdout.write(execFileSync(process.execPath, [path.join(__dirname, '../deploy/threat-map-1.1/build-manifest.cjs'), commit, '--check'], { cwd: path.join(__dirname, '..') }).toString());
