#!/usr/bin/env python3
"""Build the exact approved Hub runtime delta; preserve all other theme bytes."""
import argparse,hashlib,importlib.util,json,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
D=Path(__file__).resolve().parent;sys.path.insert(0,str(D))
from safe_theme import need,digest,manifest,lint,save

def mod(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
live=mod('hub_design_live',D/'deploy-theme.py');archive=mod('hub_archive',D/'build-package.py').archive
FILES={'deploy-theme.py','safe_theme.py','legacy_guard.py','route_policy.py','staging-contract.php','wp-state.php','tool-pages.php','protected-files.json','legacy-entrypoints.json','editorial-integration.json'}
def package(parent_dir,git_tree,out):
 need(not out.exists(),'fresh output required');need(digest(parent_dir/'theme.tar.gz')==live.DESIGN_PARENT_ARCHIVE and digest(parent_dir/'package.json')==live.DESIGN_PARENT_PACKAGE,'parent artifact mismatch')
 parent=json.loads((parent_dir/'package.json').read_text());theme=D.parents[1]/'wp-content/themes/cyberdat';full=manifest(theme)
 excluded={'assets/images/tools-hub/README.md'};need(excluded<=set(full),'source illustration README missing');target={n:v for n,v in full.items() if n not in excluded}
 spec={**parent,'revision':live.DESIGN_REVISION,'parent_archive_sha256':live.DESIGN_PARENT_ARCHIVE,'base':parent['target'],'target':target,'theme_commit':live.DESIGN_SOURCE_COMMIT,'excluded_source_files':sorted(excluded)};need(live.approved_release(spec,parent),'unapproved Hub-only delta')
 g=json.loads(git_tree.read_text());expected={x['path'].split('wp-content/themes/cyberdat/',1)[1]:x['sha'] for x in g['tree'] if x['type']=='blob' and x['path'].startswith('wp-content/themes/cyberdat/')};need(set(expected)==set(full),'source Git file-set mismatch')
 for n,h in expected.items():
  b=(theme/n).read_bytes();need(hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==h,'source Git drift: '+n)
 count=lint(theme);out.mkdir(mode=0o700);archive(theme,target,out/'theme.tar.gz');spec.update(archive_sha256=digest(out/'theme.tar.gz'),theme_tree_sha1=next(x['sha'] for x in g['tree'] if x['path']=='wp-content/themes/cyberdat'))
 save(out/'package.json',spec);(out/'parent-package.json').write_bytes((parent_dir/'package.json').read_bytes());(out/'parent-package.json').chmod(0o600);(out/'SHA256SUMS').write_text(''.join(digest(out/n)+'  '+n+'\n' for n in ['theme.tar.gz','package.json','parent-package.json']));(out/'SHA256SUMS').chmod(0o600)
 return {'files':len(target),'modified':sorted(live.DESIGN_MODIFIED),'added':len(live.DESIGN_ADDED),'unchanged_parent_files':123,'php_linted':count,'archive_sha256':spec['archive_sha256'],'package_sha256':digest(out/'package.json')}
def controls(approval,package_dir,authorization,out):
 need(not out.exists(),'fresh controls required');pins=json.loads(approval.read_text());need(set(pins['files'])==FILES,'exact helper set required')
 for n,h in pins['files'].items():
  p=D/n;need(p.is_file() and not p.is_symlink(),'unsafe source');b=p.read_bytes();need(hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==h,'unreviewed helper: '+n)
  if p.suffix=='.py':compile(b,str(p),'exec')
 need(digest(package_dir/'parent-package.json')==live.DESIGN_PARENT_PACKAGE,'wrong package parent');spec=json.loads((package_dir/'package.json').read_text());parent=json.loads((package_dir/'parent-package.json').read_text());need(live.approved_release(spec,parent),'unapproved package scope');need(digest(package_dir/'theme.tar.gz')==spec['archive_sha256'],'archive drift')
 a=json.loads(authorization.read_text());need(a['origin']==live.ORIGIN and a['research_commit']==live.RESEARCH and a['artifact_sha256']==spec['archive_sha256'] and a['package_sha256']==digest(package_dir/'package.json'),'authorization mismatch');need(a['install_approved'] is True and a['legacy_interlocks_approved'] is True and all(a['decisions'].get(n) is True for n in ['D6','D7','D8']),'missing owner decisions');need(time.time()<a['expires_epoch']<=time.time()+86400 and a['page_approvals']=={m:[] for m in ['draft','reviewed','publish']},'page mutation must be unapproved')
 out.mkdir(mode=0o700);payload={n:(D/n).read_bytes() for n in FILES};payload.update({n:(package_dir/n).read_bytes() for n in ['package.json','theme.tar.gz','parent-package.json']});payload['authorization.json']=authorization.read_bytes()
 for n,b in payload.items():(out/n).write_bytes(b);(out/n).chmod(0o640)
 save(out/'controls-sha256.json',{n:digest(out/n) for n in sorted(payload)});(out/'controls-sha256.json').chmod(0o640)
 return {'files':len(payload),'controls_sha256':digest(out/'controls-sha256.json')}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['package','controls']);p.add_argument('--parent',type=Path);p.add_argument('--git-tree',type=Path);p.add_argument('--approval',type=Path);p.add_argument('--authorization',type=Path);p.add_argument('--package',type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();print(json.dumps(package(a.parent,a.git_tree,a.output) if a.mode=='package' else controls(a.approval,a.package,a.authorization,a.output)))
