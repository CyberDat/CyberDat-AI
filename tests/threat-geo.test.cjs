'use strict';
const assert=require('node:assert/strict');
const {project,clampCamera}=require('../wp-content/themes/cyberdat/assets/js/threat-geo.js');
assert.deepEqual(project(0,0),[500,250]);assert.deepEqual(project(90,-180),[0,0]);assert.deepEqual(project(-90,180),[1000,500]);
assert.deepEqual(clampCamera(1,-50,-50),{scale:1,x:0,y:0});assert.deepEqual(clampCamera(20,-10000,100),{scale:6,x:-5000,y:0});assert.deepEqual(clampCamera(2,-250,-100),{scale:2,x:-250,y:-100});
console.log('PASS: local projection and bounded pan/zoom geometry; no network or invented events');
