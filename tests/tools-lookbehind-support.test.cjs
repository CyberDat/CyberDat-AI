/*
 * Static contract for the "browser not supported" check (Log Anonymizer, Prompt Injection Detector, LotL) and the
 * MCP Checker English-only limitation. Browser behaviour: tests/tools-lookbehind-support-browser.test.cjs.
 *   node tests/tools-lookbehind-support.test.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const T = path.join(__dirname, '../wp-content/themes/cyberdat');
for (const d of ['log-anonymizer', 'prompt-injection-detector', 'lotl-analyzer']) {
	const app = fs.readFileSync(path.join(T, 'assets/js', d, 'app.js'), 'utf8');
	const check = app.indexOf("new RegExp('(?<![a])b')");
	const worker = app.indexOf('new Worker(');
	assert.ok(check > 0 && worker > check, d + ': look-behind check must run before the worker is created');
	assert.ok(app.includes('Browser not supported: this browser lacks a regular-expression feature (look-behind)'), d + ': message');
	assert.ok(!/\(\?<[=!]/.test(app.replace("'(?<![a])b'", '')), d + ': app.js itself must not use look-behind (it would not even parse)');
	assert.ok(!/\(\?<[=!]/.test(fs.readFileSync(path.join(T, 'assets/js', d, 'worker.js'), 'utf8')), d + ': worker.js must not use look-behind');
	console.log('PASS: ' + d + ': look-behind checked before the worker starts; clear message; app/worker parse without it');
}
const mcp = fs.readFileSync(path.join(T, 'template-parts/tools/mcp-security-checker.php'), 'utf8');
assert.ok(mcp.includes('The description-poisoning wording rules are English only.'));
console.log('PASS: MCP Checker Limitations state that poisoning wording rules are English only');
