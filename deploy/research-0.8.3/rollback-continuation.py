#!/usr/bin/env python3
"""Code-only rollback of Nov13 continuation; never rewind live SQL/checkpoints."""
import sys,pathlib,importlib.util,json,argparse,pwd
sys.dont_write_bytecode=True
P=pathlib.Path;D=P(__file__).parent;sp=importlib.util.spec_from_file_location('manager',D/'manage.py');a=importlib.util.module_from_spec(sp);sp.loader.exec_module(a)
ap=argparse.ArgumentParser();ap.add_argument('--apply',action='store_true');args=ap.parse_args();b=P((D/'continuation-backup.txt').read_text());old=json.loads((a.B/'baseline.json').read_text());base=json.loads((b/'baseline.json').read_text());release=json.loads((b/'release.json').read_text());a.protected(old);a.m.need(a.digest(b/'files.tar.gz')==base['files_sha256'],'Backup archive mismatch');saved=b/'file-restore/var/www/cyberdat-staging/public/wp-content/plugins/cyberdat-research';a.m.need(a.tree(saved)==base['research'],'Restored original code checksum mismatch');a.m.need(a.tree(a.m.PLUGIN)==release['research'],'Current runtime conflict')
if not args.apply:print('PASS: rollback preflight; --apply restores only the Nov13 Research code, retaining newer SQL/CVEs/checkpoints/cursors/backoff. Earlier dense/capacity limitations will return. No live write.');sys.exit(0)
stage=a.m.PLUGIN.parent/'.research083-continuation-rollback';a.m.need(not stage.exists(),'Rollback stage conflict');a.m.owned_copy(saved,stage,pwd.getpwnam('cyberdat-staging'));lock=a.lockdb()
try:a.exchange(stage,a.m.PLUGIN)
finally:lock.stdin.close();lock.wait(timeout=5)
(b/'rollback-applied.json').write_text(json.dumps({'utc':a.utc(),'sql_restored':False,'code':a.tree(a.m.PLUGIN)},indent=2));print('PASS: previous Nov11 Research code restored; SQL/checkpoints/cursors/backoff untouched. No automatic restart, sync or destructive rollback.')
