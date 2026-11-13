/*
 * MCP Security & Policy Checker: DEPENDENT regression examples for changes requested by the owner.
 * Written after the issue was known; they protect the change and are not an independent evaluation.
 *   node tests/mcp-checker-dependent.test.cjs [--report]
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/mcp-checker/engine.js'));
const set = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/mcp-checker/dependent.json'), 'utf8'));
const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };
let ok = 0, fail = 0;
for (const c of set.cases) {
	const r = engine.analyze(JSON.stringify(c.config));
	const problems = [];
	for (const [rule, sev] of c.expect) { if (!r.findings.some(f => f.rule === rule && f.severity === sev)) { problems.push(rule + ' ' + sev + ' missing'); } }
	if (c.notAbove) { const top = r.findings.filter(f => RANK[f.severity] > RANK[c.notAbove]); if (top.length) { problems.push('above ' + c.notAbove + ': ' + top.map(f => f.rule + ':' + f.severity).join(' ')); } }
	for (const [rule, n] of Object.entries(c.count || {})) { const got = r.findings.filter(f => f.rule === rule).length; if (got !== n) { problems.push(rule + ' x' + got + ' (expected ' + n + ')'); } }
	problems.length ? fail++ : ok++;
	console.log((problems.length ? 'FAIL ' : 'ok   ') + c.id + (problems.length ? ': ' + problems.join('; ') : '') + ' [' + r.findings.map(f => f.rule + ':' + f.severity).join(' ') + ']');
}
console.log('dependent examples (' + set.issue + '): ' + ok + '/' + (ok + fail) + ' as expected');
if (!process.argv.includes('--report')) { assert.equal(fail, 0); console.log('PASS: dependent MCP examples'); }
