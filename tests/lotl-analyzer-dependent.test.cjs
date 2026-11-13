/*
 * LotL / LOLBAS Command Analyzer: DEPENDENT regression examples for issues confirmed by the owner.
 * These examples were written after the issue was known; they protect the fix and are not an independent evaluation.
 *   node tests/lotl-analyzer-dependent.test.cjs [--report]   (--report prints severities without asserting)
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const engine = require(path.join(__dirname, '../wp-content/themes/cyberdat/assets/js/lotl-analyzer/engine.js'));
const set = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/lotl-analyzer/dependent.json'), 'utf8'));
const RANK = { none: -1, info: 0, low: 1, medium: 2, high: 3 };
const sev = cmd => engine.analyze(cmd).commands.reduce((m, c) => (RANK[c.severity] > RANK[m] ? c.severity : m), 'none');
let ok = 0, fail = 0;
for (const c of set.suspicious) { const s = sev(c.cmd); const good = RANK[s] >= RANK[c.min]; good ? ok++ : fail++; console.log((good ? 'ok   ' : 'FAIL ') + c.id + ': ' + s + ' (expected >= ' + c.min + ')'); }
for (const c of set.benign) { const s = sev(c.cmd); const good = RANK[s] <= RANK[c.max]; good ? ok++ : fail++; console.log((good ? 'ok   ' : 'FAIL ') + c.id + ': ' + s + ' (expected <= ' + c.max + ')'); }
console.log('dependent examples (' + set.issue + '): ' + ok + '/' + (ok + fail) + ' as expected');
if (!process.argv.includes('--report')) { assert.equal(fail, 0); console.log('PASS: dependent LotL examples'); }
