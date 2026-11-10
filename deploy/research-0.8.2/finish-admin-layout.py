#!/usr/bin/env python3
"""Repair only the newly created public CSS directory, then verify existing UI release."""
import argparse,hashlib,json,os,pathlib,pwd,stat,sys
ORIGINAL=pathlib.Path('/home/cyberdat/cyberdat-deploy/research-0.8.2-admin-ui-prepared/fix-admin-layout.py')
PIN='f12ce239da3c37d9d033b386888dce483d68444755bcd387356969b8327ff801'
def repair_assets(m,backup,patch):
 parent=m.PLUGIN/'assets';css=parent/'discovery-admin.css';php=m.PLUGIN/'includes/discovery-admin.php';account=pwd.getpwnam('cyberdat-staging')
 def need(ok,reason):
  if not ok:raise RuntimeError(reason)
 need(parent.resolve()==parent and parent.is_dir() and not parent.is_symlink(),'Unsafe static asset directory')
 need(parent.stat().st_uid==account.pw_uid and stat.S_IMODE(parent.stat().st_mode) in [0o700,0o755],'Unexpected static directory owner/mode')
 need({p.name for p in parent.iterdir()}=={'discovery-admin.css'} and css.is_file() and not css.is_symlink(),'Static directory contains unexpected files; no chmod performed')
 need(hashlib.sha256(css.read_bytes()).hexdigest()==patch['css'] and hashlib.sha256(php.read_bytes()).hexdigest()==patch['after'],'Installed public asset/admin code conflict')
 snapshot=backup/'asset-directory-mode-before.json'
 if snapshot.exists():
  need(not snapshot.is_symlink() and json.loads(snapshot.read_text())=={'path':str(parent),'mode':'0700','css_sha256':patch['css']},'Permission snapshot conflict')
 else:
  need(stat.S_IMODE(parent.stat().st_mode)==0o700,'Directory already changed without permission snapshot')
  with snapshot.open('x') as stream:json.dump({'path':str(parent),'mode':'0700','css_sha256':patch['css']},stream)
  snapshot.chmod(0o600)
 parent.chmod(0o755)
 print('PASS: dedicated public CSS directory 0700 -> 0755; sole file checksum verified; private paths unchanged',flush=True)
def source_for_resume(text):
 needle=" phase='admin asset and regression verification'"
 if text.count(needle)!=1:raise RuntimeError('Pinned verification contract changed')
 return text.replace(needle," repair_assets(m,backup,patch)\n"+needle)
if __name__=='__main__':
 try:
  parser=argparse.ArgumentParser();parser.add_argument('--verify',required=True,type=pathlib.Path);args=parser.parse_args()
  if os.geteuid()!=0:raise RuntimeError('Use owner interactive sudo')
  sys.dont_write_bytecode=True;data=ORIGINAL.read_bytes()
  if ORIGINAL.is_symlink() or hashlib.sha256(data).hexdigest()!=PIN:raise RuntimeError('Original UI controller checksum mismatch')
  namespace={'__name__':'research_ui_finish','__file__':str(ORIGINAL),'repair_assets':repair_assets}
  exec(compile(source_for_resume(data.decode()),str(ORIGINAL),'exec'),namespace)
  sys.argv=[str(ORIGINAL),'--verify',str(args.verify)];namespace['main']()
 except BaseException as e:
  print('BLOCKED: admin CSS delivery continuation; type='+type(e).__name__)
  if isinstance(e,RuntimeError):print('Reason: '+str(e))
  print('Retain original backup; no raw passwords/logs, reinstall, source/timer change or production operation.');sys.exit(1)
