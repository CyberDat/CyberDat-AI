"""Offline GPL delivery/source integrity checks; no installed WordPress access."""
import argparse,hashlib,json,subprocess,tarfile,tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--node',required=True);a=p.parse_args()
r=Path(__file__).resolve().parents[1];d=r/'deploy/tools-lotl-analyzer';theme=r/'wp-content/themes/cyberdat';asset=theme/'assets/js/lotl-analyzer'
m=json.loads((d/'upstream-source-manifest.json').read_text());snap=json.loads((d/'lolbas-snapshot.json').read_text());archive=d/'upstream-source-2056cb7.tar.gz'
checks=[]
def ok(name): checks.append(name);print('PASS: '+name)
assert hashlib.sha256(archive.read_bytes()).hexdigest()==m['source_archive_sha256'];ok('pinned source archive SHA256')
with tempfile.TemporaryDirectory(prefix='cyberdat-lotl-source-') as td:
 root=Path(td)
 with tarfile.open(archive) as tf:
  members=tf.getmembers();assert len(members)==251 and all(x.isfile() and x.mode==0o644 and x.name.startswith('lolbas-source/') and '..' not in Path(x.name).parts for x in members)
  tf.extractall(root,filter='data')
 src=root/'lolbas-source'
 actual={str(x.relative_to(src)):hashlib.sha256(x.read_bytes()).hexdigest() for x in src.rglob('*') if x.is_file()}
 assert actual==m['files'];assert all(actual[k]==v for k,v in snap['files'].items());assert len(snap['files'])==248;ok('all 251 preferred source files and 248 original YAML hashes')
 assert (src/'LICENSE').read_bytes()==(asset/'LICENSE-LOLBAS.txt').read_bytes();assert (src/'NOTICE.md').read_bytes()==(asset/'NOTICE-LOLBAS.md').read_bytes();ok('complete original license and MITRE notices preserved verbatim')
 cmd=[a.node,str(d/'update-lolbas-data.cjs'),'--source',str(src),'--source-metadata',str(d/'lolbas-snapshot.json'),'--output-dir',str(root/'rebuilt'),'--generated-date','2026-11-13']
 result=subprocess.run(cmd,capture_output=True,text=True);assert result.returncode==0,result.stderr
 assert (root/'rebuilt/lolbas-data.js').read_bytes()==(asset/'lolbas-data.js').read_bytes();ok('offline generator byte-exact reproduction of shipped JavaScript data')
 first=src/next(iter(snap['files']));first.write_bytes(first.read_bytes()+b'\n# altered\n')
 cmd[cmd.index('--output-dir')+1]=str(root/'tampered')
 result=subprocess.run(cmd,capture_output=True,text=True);assert result.returncode!=0;ok('tampered preferred source rejected')
for name in ['app.js','engine.js','worker.js','lolbas-data.js']:
 s=(asset/name).read_text()[:2500];assert 'GPL-3.0' in s and '2026-11-13' in s and ('WARRANTY' in s or 'warranty' in s)
ok('dated GPL notices in all four LotL JavaScript files')
assert 'UNVERIFIED' in (asset/'SOURCE.md').read_text();assert 'independent CyberDat tools' in (asset/'SOURCE.md').read_text();ok('scope and legal uncertainty disclosed, no blanket relicensing claim')
print(json.dumps({'checks':len(checks),'status':'PASS','source_archive_sha256':m['source_archive_sha256']}))
