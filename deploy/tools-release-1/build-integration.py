#!/usr/bin/env python3
"""Build the owner-approved two-file editorial theme derivative and pinned controls."""
import argparse,hashlib,importlib.util,json,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from safe_theme import need,manifest,lint,digest,save

def module(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
live=module('integration_live',HERE/'deploy-theme.py');archive=module('integration_archive',HERE/'build-package.py').archive
FILES={'deploy-theme.py','safe_theme.py','legacy_guard.py','route_policy.py','staging-contract.php','wp-state.php','tool-pages.php','protected-files.json','legacy-entrypoints.json','editorial-integration.json'}
SLUGS=['log-anonymizer','prompt-injection-detector','lotl-command-analyzer','mcp-security-checker']
def build_package(parent_dir,commit,git_file,out):
 need(not out.exists(),'fresh output required')
 need(digest(parent_dir/'theme.tar.gz')==live.INTEGRATION_PARENT_ARCHIVE and digest(parent_dir/'package.json')==live.INTEGRATION_PARENT_PACKAGE,'parent artifact mismatch')
 parent=json.loads((parent_dir/'package.json').read_text());theme=HERE.parent.parent/'wp-content/themes/cyberdat';target=manifest(theme)
 spec={**parent,'revision':live.INTEGRATION_REVISION,'parent_archive_sha256':live.INTEGRATION_PARENT_ARCHIVE,'base':parent['target'],'target':target,'theme_commit':commit}
 need(live.approved_release(spec,parent),'unapproved theme delta')
 git=json.loads(git_file.read_text());expected={x['path'].split('wp-content/themes/cyberdat/',1)[1]:x['sha'] for x in git['tree'] if x['type']=='blob' and x['path'].startswith('wp-content/themes/cyberdat/')}
 need(set(expected)==set(target),'theme Git file-set mismatch')
 for n,h in expected.items():
  b=(theme/n).read_bytes();need(hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==h,'Git theme byte mismatch: '+n)
 count=lint(theme);out.mkdir(mode=0o700);archive(theme,target,out/'theme.tar.gz');spec.update(archive_sha256=digest(out/'theme.tar.gz'),theme_tree_sha1=next(x['sha'] for x in git['tree'] if x['path']=='wp-content/themes/cyberdat'))
 save(out/'package.json',spec);(out/'parent-package.json').write_bytes((parent_dir/'package.json').read_bytes());(out/'parent-package.json').chmod(0o600)
 (out/'SHA256SUMS').write_text(''.join(digest(out/n)+'  '+n+'\n' for n in ['theme.tar.gz','package.json','parent-package.json']));(out/'SHA256SUMS').chmod(0o600)
 return {'files':len(target),'php_linted':count,'archive_sha256':spec['archive_sha256'],'package_sha256':digest(out/'package.json')}
def build_controls(approval,package,authorization,out):
 need(not out.exists(),'fresh controls output required');pins=json.loads(approval.read_text());need(set(pins['files'])==FILES,'approval set mismatch')
 for n,h in pins['files'].items():
  p=HERE/n;need(p.is_file() and not p.is_symlink(),'unsafe source');b=p.read_bytes();need(hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==h,'unreviewed control: '+n)
  if p.suffix=='.py':compile(b,str(p),'exec')
 need(digest(package/'parent-package.json')==live.INTEGRATION_PARENT_PACKAGE,'parent package mismatch')
 spec=json.loads((package/'package.json').read_text());parent=json.loads((package/'parent-package.json').read_text());need(live.approved_release(spec,parent),'unapproved delta');need(digest(package/'theme.tar.gz')==spec['archive_sha256'],'archive changed')
 a=json.loads(authorization.read_text());need(a['origin']==live.ORIGIN and a['research_commit']==live.RESEARCH and a['artifact_sha256']==spec['archive_sha256'] and a['package_sha256']==digest(package/'package.json'),'authorization mismatch')
 need(a['install_approved'] is True and a['legacy_interlocks_approved'] is True and all(a['decisions'].get(x) is True for x in ['D2','D4','D5','D6','D7','D8','D9','D11']),'owner decisions missing')
 need(time.time()<a['expires_epoch']<=time.time()+86400 and a['page_approvals']=={m:SLUGS for m in ['draft','reviewed','publish']},'expiry/page scope mismatch')
 out.mkdir(mode=0o700);payload={n:(HERE/n).read_bytes() for n in FILES};payload.update({n:(package/n).read_bytes() for n in ['theme.tar.gz','package.json','parent-package.json']});payload['authorization.json']=authorization.read_bytes()
 for n,b in payload.items():(out/n).write_bytes(b);(out/n).chmod(0o640)
 registry={n:digest(out/n) for n in sorted(payload)};save(out/'controls-sha256.json',registry);(out/'controls-sha256.json').chmod(0o640)
 return {'files':len(payload),'controls_sha256':digest(out/'controls-sha256.json')}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['package','controls']);p.add_argument('--parent',type=Path);p.add_argument('--commit');p.add_argument('--git-tree',type=Path);p.add_argument('--approval',type=Path);p.add_argument('--authorization',type=Path);p.add_argument('--package',type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
 print(json.dumps(build_package(a.parent,a.commit,a.git_tree,a.output) if a.mode=='package' else build_controls(a.approval,a.package,a.authorization,a.output)))
