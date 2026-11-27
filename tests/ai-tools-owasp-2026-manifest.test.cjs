/* The ai-tools-owasp-2026 package manifest matches its recorded theme commit (base 6e5ba9c, delta only, no JavaScript). */
'use strict';
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const commit = require('../deploy/ai-tools-owasp-2026/manifest.json').theme_commit;
process.stdout.write(execFileSync(process.execPath, [path.join(__dirname, '../deploy/ai-tools-owasp-2026/build-manifest.cjs'), commit, '--check'], { cwd: path.join(__dirname, '..') }).toString());
