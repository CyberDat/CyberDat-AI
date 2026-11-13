/* Verify the full revised manifest against the exact theme bytes; no Git executable required. */
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),theme=path.join(root,'wp-content/themes/cyberdat');
const m=JSON.parse(fs.readFileSync(path.join(root,'deploy/tools-release-1/manifest.json'),'utf8'));
const files=[];function walk(dir){for(const n of fs.readdirSync(dir)){const p=path.join(dir,n),s=fs.lstatSync(p);assert.ok(!s.isSymbolicLink());if(s.isDirectory()){assert.equal(s.mode&0o777,0o755);walk(p);}else{assert.ok(s.isFile());assert.equal(s.mode&0o777,0o644);files.push(path.relative(theme,p));}}}walk(theme);
assert.equal(files.length,125);assert.equal(Object.keys(m.base).length,95);assert.deepEqual(files.sort(),Object.keys(m.target).sort());
for(const f of files){const b=fs.readFileSync(path.join(theme,f));assert.equal(crypto.createHash('sha256').update(b).digest('hex'),m.target[f].sha256,f);assert.equal(b.length,m.target[f].bytes,f);}
assert.match(m.theme_commit,/^[a-f0-9]{40}$/);assert.match(m.archive_sha256,/^[a-f0-9]{64}$/);
console.log('PASS: complete125-file target, modes/no symlinks, SHA256/lengths, base95 and exact source/artifact pins');
