/*
 * Runs the offline PHP test of the threat map collector (tests/threat-map.test.php) with the PHP on PATH, so the
 * Fast tests workflow (which has PHP for `php -l`) runs it too. Without PHP: SKIP locally, FAIL in CI.
 */
'use strict';
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const probe = spawnSync('php', ['-v'], { encoding: 'utf8' });
if (probe.error || probe.status !== 0) {
	if (process.env.CI) { console.error('FAIL: PHP is required in CI'); process.exit(1); }
	console.log('SKIP: no PHP on PATH (run tests/threat-map.test.php with the pinned WordPress image)');
	process.exit(0);
}
const r = spawnSync('php', [path.join(__dirname, 'threat-map.test.php')], { encoding: 'utf8' });
process.stdout.write(r.stdout);
process.stderr.write(r.stderr);
process.exit(r.status === 0 && /PASS: threat map — \d+ checks/.test(r.stdout) ? 0 : 1);
