/*
 * Runs the offline PHP tests of the threat map (tests/threat-map.test.php, tests/threat-map-layers.test.php) with the
 * PHP on PATH, so the Fast tests workflow (which has PHP for `php -l`) runs them too. Without PHP: SKIP locally, FAIL in CI.
 */
'use strict';
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const probe = spawnSync('php', ['-v'], { encoding: 'utf8' });
if (probe.error || probe.status !== 0) {
	if (process.env.CI) { console.error('FAIL: PHP is required in CI'); process.exit(1); }
	console.log('SKIP: no PHP on PATH (run tests/threat-map*.test.php with the pinned WordPress image)');
	process.exit(0);
}
let failed = 0;
for (const [file, done] of [['threat-map.test.php', /PASS: threat map — \d+ checks/], ['threat-map-layers.test.php', /PASS: threat map layers — \d+ checks/]]) {
	const r = spawnSync('php', [path.join(__dirname, file)], { encoding: 'utf8' });
	process.stdout.write(r.stdout);
	process.stderr.write(r.stderr);
	if (r.status !== 0 || !done.test(r.stdout)) { failed++; console.error('FAIL: ' + file); }
}
process.exit(failed ? 1 : 0);
