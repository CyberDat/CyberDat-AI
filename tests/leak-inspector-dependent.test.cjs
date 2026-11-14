/*
 * Leak Inspector: DEPENDENT examples for fixes made after the first corpus run. Not an independent evaluation.
 *   node tests/leak-inspector-dependent.test.cjs [--report]
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/leak-inspector/engine.js'));
const set = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/leak-inspector/dependent.json'), 'utf8'));
const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };
let ok = 0, fail = 0;
function judge(id, fix, r, c) {
	const problems = [];
	for (const [rule, min] of c.expect || []) { if (!r.findings.some(f => f.rule === rule && RANK[f.severity] >= RANK[min])) { problems.push(rule + '>=' + min + ' missing'); } }
	if (c.expectNone) { const top = r.findings.filter(f => RANK[f.severity] >= RANK[c.expectNone]); if (top.length) { problems.push('unexpected ' + top.map(f => f.rule + ':' + f.severity).join(' ')); } }
	problems.length ? fail++ : ok++;
	console.log((problems.length ? 'FAIL ' : 'ok   ') + id + ' [' + fix + ']' + (problems.length ? ': ' + problems.join('; ') : ''));
}
for (const c of set.audit) { judge(c.id, c.fix, engine.audit(c.text), c); }
for (const c of set.leak) { judge(c.id, c.fix, engine.leakCheck(c.prompt, c.response), c); }
console.log('dependent examples: ' + ok + '/' + (ok + fail) + ' as expected (NOT INDEPENDENT)');
if (!process.argv.includes('--report')) { assert.equal(fail, 0); console.log('PASS: dependent leak inspector examples'); }
