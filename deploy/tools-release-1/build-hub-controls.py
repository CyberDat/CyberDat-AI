#!/usr/bin/env python3
"""Build fresh sealed-layout controls for the explicitly approved Hub revision."""
import argparse,hashlib,importlib.util,json,time,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.dont_write_bytecode=True;sys.path.insert(0,str(HERE))
FILES={'deploy-theme.py','safe_theme.py','legacy_guard.py','route_policy.py','staging-contract.php','wp-state.php','tool-pages.php','protected-files.json','legacy-entrypoints.json'}
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def build(approval,package,authorization,out,registry_output=None):
 need(not out.exists(),'fresh controls output required');pins=json.loads(approval.read_text());need(set(pins['files'])==FILES,'approval set mismatch')
 for n,h in pins['files'].items():
  p=HERE/n;need(p.is_file() and not p.is_symlink(),'unsafe source');b=p.read_bytes();need(hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==h,'unreviewed source: '+n)
  if p.suffix=='.py':compile(b,str(p),'exec')
 s=importlib.util.spec_from_file_location('hub_live',HERE/'deploy-theme.py');live=importlib.util.module_from_spec(s);s.loader.exec_module(live)
 need(sha(package/'parent-package.json')==live.PARENT_PACKAGE,'parent package mismatch')
 parent=json.loads((package/'parent-package.json').read_text());spec=json.loads((package/'package.json').read_text());need(live.approved_release(spec,parent),'unapproved revision delta');need(sha(package/'theme.tar.gz')==spec['archive_sha256'],'archive mismatch')
 a=json.loads(authorization.read_text());need(a['origin']==live.ORIGIN and a['research_commit']==live.RESEARCH and a['artifact_sha256']==sha(package/'theme.tar.gz') and a['package_sha256']==sha(package/'package.json'),'owner artifact mismatch')
 need(a['install_approved'] is True and a['legacy_interlocks_approved'] is True and a['decisions']['D6'] is True and a['decisions']['D7'] is True and a['decisions']['D8'] is True,'required owner decisions missing')
 need(time.time()<a['expires_epoch']<=time.time()+86400 and a['page_approvals']=={'draft':[],'reviewed':[],'publish':[]},'expiry/page approval mismatch')
 out.mkdir(mode=0o700);payload={n:(HERE/n).read_bytes() for n in FILES};payload.update({n:(package/n).read_bytes() for n in ['theme.tar.gz','package.json','parent-package.json']});payload['authorization.json']=authorization.read_bytes()
 for n,b in payload.items():(out/n).write_bytes(b);(out/n).chmod(0o640)
 registry={n:sha(out/n) for n in sorted(payload)};(out/'controls-sha256.json').write_text(json.dumps(registry,indent=2)+'\n');(out/'controls-sha256.json').chmod(0o640)
 if registry_output:
  source_registry={n:sha(HERE/n) for n in sorted(FILES)};source_registry['authorization.json']=sha(HERE/'authorization.example.json');registry_output.write_text(json.dumps(source_registry,indent=2)+'\n')
 return {'files':len(payload),'manifest_sha256':sha(out/'controls-sha256.json'),'source_commit':pins['source_commit']}
if __name__=='__main__':
 p=argparse.ArgumentParser()
 for n in ['approval','package','authorization','output']:p.add_argument('--'+n,required=True,type=Path)
 p.add_argument('--registry-output',type=Path);a=p.parse_args();print(json.dumps(build(a.approval,a.package,a.authorization,a.output,a.registry_output)))
