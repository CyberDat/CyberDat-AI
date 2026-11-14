#!/usr/bin/env python3
"""Single-template derivative of the approved D1 theme; never reads live WP."""
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from safe_theme import need,manifest,lint,digest,save
s=importlib.util.spec_from_file_location('package_builder',HERE/'build-package.py');builder=importlib.util.module_from_spec(s);s.loader.exec_module(builder)
PARENT_ARCHIVE='5ce6c412c8444d36e9ac2f6960c4ee71c3cea7fec3dc0468afd0a4ee9317bc8b'
PARENT_PACKAGE='3ec45c9198efad34c5a107a58144032bf31a0d32832e2c6dfefba7600516a65e'
def build(parent_dir,source_commit,target_tree,original_template,out):
    need(not out.exists(),'fresh output required')
    need(digest(parent_dir/'theme.tar.gz')==PARENT_ARCHIVE and digest(parent_dir/'package.json')==PARENT_PACKAGE,'parent artifact changed')
    parent=json.loads((parent_dir/'package.json').read_text());theme=HERE.parent.parent/'wp-content/themes/cyberdat'
    need(digest(original_template)==parent['base']['page-templates/tools.php']['sha256'],'unverified original backup template')
    need(b'data-tools-filters' in original_template.read_bytes(),'old template has no filters')
    target=manifest(theme);need(len(target)==125 and set(target)==set(parent['target']),'theme file set changed')
    need([n for n in target if target[n]!=parent['target'][n]]==['page-templates/tools.php'],'hotfix must change only catalogue template')
    git=json.loads(target_tree.read_text());expected={x['path'].split('wp-content/themes/cyberdat/',1)[1]:x['sha'] for x in git['tree'] if x['type']=='blob' and x['path'].startswith('wp-content/themes/cyberdat/')}
    need(set(expected)==set(target),'target Git set mismatch')
    for n,h in expected.items():
        b=(theme/n).read_bytes();need(hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==h,'target Git bytes mismatch: '+n)
    count=lint(theme);out.mkdir(mode=0o700);builder.archive(theme,target,out/'theme.tar.gz')
    spec={**parent,'revision':'tools-hub-catalog-10-filter-counter/1','parent_archive_sha256':PARENT_ARCHIVE,'base':parent['target'],'target':target,'theme_commit':source_commit,'theme_tree_sha1':next(x['sha'] for x in git['tree'] if x['path']=='wp-content/themes/cyberdat'),'archive_sha256':digest(out/'theme.tar.gz'),'original_template_sha256':digest(original_template)}
    save(out/'package.json',spec);(out/'parent-package.json').write_bytes((parent_dir/'package.json').read_bytes());(out/'parent-package.json').chmod(0o600)
    (out/'SHA256SUMS').write_text(''.join(digest(out/n)+'  '+n+'\n' for n in ['theme.tar.gz','package.json','parent-package.json']));(out/'SHA256SUMS').chmod(0o600)
    return {'files':125,'delta':['page-templates/tools.php'],'php_linted':count,'archive_sha256':spec['archive_sha256'],'package_sha256':digest(out/'package.json')}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ['parent','git-tree','original-template','output']:p.add_argument('--'+n,required=True,type=Path)
    p.add_argument('--source-commit',required=True);a=p.parse_args();print(json.dumps(build(a.parent,a.source_commit,a.git_tree,a.original_template,a.output)))
