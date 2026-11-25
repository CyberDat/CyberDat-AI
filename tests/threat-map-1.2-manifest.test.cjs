/* The threat-map-1.2 package manifest matches its recorded theme commit (base 9082de0 = threat-map-1.1, delta only). */
'use strict';
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const commit = require('../deploy/threat-map-1.2/manifest.json').theme_commit;
process.stdout.write(execFileSync(process.execPath, [path.join(__dirname, '../deploy/threat-map-1.2/build-manifest.cjs'), commit, '--check'], { cwd: path.join(__dirname, '..') }).toString());
