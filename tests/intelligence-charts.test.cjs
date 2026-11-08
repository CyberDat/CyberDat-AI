'use strict';
const assert = require('node:assert/strict');
const {lineModel} = require('../wp-content/themes/cyberdat/assets/js/intelligence-charts.js');
const series = Object.fromEntries(Array.from({length:90}, (_, i) => [new Date(Date.UTC(2026,7,11)+i*86400000).toISOString().slice(0,10), i % 11]));
for (const days of [7,30,90]) {
 const model=lineModel(series,days);
 assert.equal(model.rows.length,days);
 assert.equal(model.total,Object.values(series).slice(-days).reduce((a,b)=>a+b,0));
 assert.equal(model.points[0].x,44);assert.equal(model.points.at(-1).x,556);
 assert.ok(model.points.every(p=>Number.isFinite(p.y)&&p.y>=34&&p.y<=174));
 console.log(`PASS: ${days}-day window, totals and bounded SVG geometry`);
}
const empty = Object.fromEntries(Object.keys(series).map(d=>[d,0]));
assert.equal(lineModel(empty,90).maximum,1);assert.ok(lineModel(empty,90).points.every(p=>p.y===174));
console.log('PASS: all-zero dataset has no division by zero or fabricated nonzero values');
assert.throws(()=>lineModel({...series,'bad-date':'<script>'},30));assert.throws(()=>lineModel(series,365));assert.throws(()=>lineModel([],30));
assert.throws(()=>lineModel({...series,[Object.keys(series)[0]]:-1},30));
console.log('PASS: invalid/unbounded series and unsupported periods rejected');
