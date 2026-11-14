#!/usr/bin/env python3
"""Rebuild the existing private D1 controls layout from reviewed Git-pinned bytes.

No live WordPress, sudo, SQL, systemd or install operation. Never patch a checksum
entry in place: generate the complete fresh bundle and its manifest, then verify.
"""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import subprocess

HERE = Path(__file__).resolve().parent
FILES = {'deploy-theme.py','safe_theme.py','legacy_guard.py','route_policy.py','staging-contract.php','wp-state.php','tool-pages.php','protected-files.json','legacy-entrypoints.json'}
ARCHIVE = '5ce6c412c8444d36e9ac2f6960c4ee71c3cea7fec3dc0468afd0a4ee9317bc8b'
PACKAGE = '3ec45c9198efad34c5a107a58144032bf31a0d32832e2c6dfefba7600516a65e'

def need(ok, msg):
    if not ok: raise RuntimeError(msg)

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def blob(p):
    b=Path(p).read_bytes()
    return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()

def regular(p):
    need(p.is_file() and not p.is_symlink(), 'not a regular source: '+p.name)

def verify(output):
    output=Path(output);regular(output/'controls-sha256.json')
    expected=json.loads((output/'controls-sha256.json').read_text())
    need(set(expected)==FILES|{'authorization.json','package.json','theme.tar.gz'},'unexpected controls manifest set')
    allowed=set(expected)|{'controls-sha256.json'}
    if (output/'source-controls-sha256.generated.json').exists():allowed.add('source-controls-sha256.generated.json')
    need({p.name for p in output.iterdir()}==allowed,'unexpected controls bundle file')
    for n,h in expected.items():
        p=output/n;regular(p);need(sha(p)==h,'controls SHA256 mismatch: '+n)
    return expected

def build(source, old_controls, approval, package, authorization, output):
    source,old_controls,approval,package,authorization,output=map(Path,[source,old_controls,approval,package,authorization,output])
    need(not output.exists(),'fresh output required')
    regular(approval);pins=json.loads(approval.read_text())
    need(set(pins['files'])==FILES,'approval source set mismatch')
    need(pins['reviewed_source_commit']=='6ec9ff010414e3bcf3992a45bb5104cdc2571670' and pins.get('reviewed_snapshot_fix_commit')=='6ec9ff010414e3bcf3992a45bb5104cdc2571670' and pins['reviewed_installer_change_commit']=='ae48da0e635b45a5e1fefdda54bb95eed2b2cd61','unreviewed source revision')
    baseline=source/'controls-baseline-sha256.json';regular(baseline)
    need(blob(baseline)=='6c1e02caeba6dde7b626675551468180b42db7b1','unreviewed baseline manifest')
    prior=json.loads(baseline.read_text())
    changed=[]
    for n in sorted(FILES):
        f=source/n;regular(f);need(blob(f)==pins['files'][n]['git_blob_sha1'],'unreviewed Git bytes: '+n)
        if sha(f)!=prior[n]: changed.append(n)
        if f.suffix=='.py': compile(f.read_bytes(),str(f),'exec')
        if f.suffix=='.php':
            result=subprocess.run(['/usr/bin/php8.4','-n','-l',str(f)],capture_output=True,timeout=20)
            need(result.returncode==0,'PHP lint failed: '+n)
    need(changed==['deploy-theme.py','wp-state.php'],'unexpected source/old-manifest delta')
    old=old_controls/'deploy-theme.py';regular(old);need(sha(old)==prior['deploy-theme.py'],'old installer is not the pinned original')
    before=old.read_bytes();needle=b"len(spec['target']) == 123"
    need(before.count(needle)==1 and before.replace(needle,b"len(spec['target']) == 125")== (source/'deploy-theme.py').read_bytes(),'installer changes exceed reviewed 123-to-125 adaptation')
    previous=old_controls/'wp-state.php';regular(previous)
    need(sha(previous)==prior['wp-state.php'],'unreviewed previous snapshot helper')
    old_php=previous.read_text()
    declaration="$cd_slugs = array( 'log-anonymizer', 'prompt-injection-detector', 'lotl-command-analyzer', 'mcp-security-checker' );"
    replacement="function cd_tools_slugs() {\n\treturn array( 'log-anonymizer', 'prompt-injection-detector', 'lotl-command-analyzer', 'mcp-security-checker' );\n}\n$cd_slugs = cd_tools_slugs();"
    need(old_php.count(declaration)==1,'snapshot declaration changed')
    reviewed=old_php.replace(declaration,replacement,1).replace('global $wpdb, $cd_slugs;','global $wpdb;\n\t$cd_slugs = cd_tools_slugs();')
    need(reviewed==(source/'wp-state.php').read_text(),'snapshot diff exceeds reviewed local-scope correction')
    for n,h in [('theme.tar.gz',ARCHIVE),('package.json',PACKAGE)]:regular(package/n);need(sha(package/n)==h,'package changed: '+n)
    regular(authorization);auth=json.loads(authorization.read_text())
    need(auth['origin']=='https://staging.cyberdat.eu' and auth['research_commit']=='0ef03e9cb0d8821546983c84fc6998e85cf03f2e' and auth['artifact_sha256']==ARCHIVE and auth['package_sha256']==PACKAGE,'authorization target mismatch')
    need(auth['install_approved'] is True and auth['legacy_interlocks_approved'] is True and auth['decisions']['D6'] is True and auth['decisions']['D7'] is True,'owner decisions missing')
    need(auth['page_approvals']=={'draft':[],'reviewed':[],'publish':[]},'page mutations forbidden')
    output.mkdir(mode=0o700)
    payload={n:(source/n).read_bytes() for n in FILES}
    payload.update({'authorization.json':authorization.read_bytes(),'theme.tar.gz':(package/'theme.tar.gz').read_bytes(),'package.json':(package/'package.json').read_bytes()})
    for n,b in payload.items():(output/n).write_bytes(b);(output/n).chmod(0o640)
    hashes={n:sha(output/n) for n in sorted(payload)}
    (output/'controls-sha256.json').write_text(json.dumps(hashes,indent=2)+'\n');(output/'controls-sha256.json').chmod(0o640)
    verify(output)
    # Generate the complete repository registry as a builder artifact, never patch
    # one expected hash. Runtime owner authorization has its separate sealed hash.
    registry={n:sha(source/n) for n in sorted(FILES)}
    registry['authorization.json']=sha(source/'authorization.example.json')
    (output/'source-controls-sha256.generated.json').write_text(json.dumps(registry,indent=2)+'\n')
    (output/'source-controls-sha256.generated.json').chmod(0o640)
    return {'source_commit':pins['reviewed_source_commit'],'reviewed_installer_change':pins['reviewed_installer_change_commit'],'files':len(payload),'manifest_sha256':sha(output/'controls-sha256.json'),'all_runtime_Git_blobs_verified':True,'package_unchanged':True}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ['source','old-controls','approval','package','authorization','output']:p.add_argument('--'+n,required=True,type=Path)
    a=p.parse_args()
    try:print(json.dumps(build(a.source,a.old_controls,a.approval,a.package,a.authorization,a.output)))
    except Exception as e:print('BLOCKED controls build: '+str(e));raise SystemExit(1)
