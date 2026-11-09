const assert = require('node:assert/strict');
const { period, points } = require('../wp-content/themes/cyberdat/assets/js/threat-pulse.js');
const series = {};
for (let i=89;i>=0;i--) series[new Date(Date.UTC(2026,10,9)-i*86400000).toISOString().slice(0,10)] = i%3===0?2:0;
assert.equal(period(series,7).total,6);assert.equal(period(series,30).total,20);assert.equal(period(series,90).total,60);
assert.equal(period(series,8),null);assert.equal(period({},7),null);assert.equal(period(Object.fromEntries(Object.keys(series).map(k=>[k,0])),7).available,false);
const broken={...series};delete broken['2026-11-07'];assert.equal(period(broken,7),null);
for(const days of [7,30,90]){const p=period(series,days);assert.equal(p.values.length,days);assert(points(p.values).every(([x,y])=>x>=4&&x<=276&&y>=6&&y<=46));}
console.log('PASS: 7/30/90 real subsets, absent/zero/gapped history and bounded SVG coordinates');
