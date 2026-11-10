#!/usr/bin/env python3
"""Resume the exact saved release with corrected WP-CLI names; no reinstall."""
import argparse,hashlib,os,pathlib,shutil,sys
ORIGINAL=pathlib.Path('/home/cyberdat/cyberdat-deploy/research-0.8.2-prepared/deploy-discovery.py')
PIN='04ee6fcba4f1470166e36fdc33c6f335f36f82436a26fd515259279b941fc518'
REPLACEMENTS={"m.wp('cyberdat-research','discovery-install')":"m.wp('cyberdat-research','discovery_install')","for command in ['test','discovery-test']:":"for command in ['test','discovery_test']:"}
FIXTURE='tests/discovery-database.php'
BEFORE='05043a1c3ed8e1004449643929d7f3c9f89603c36b8a4a3c92d8cbe5f0b82c60'
AFTER='0c880df7ac1a162792964e492fbe967be326ad7a3b589f47979916227c86c0bc'
def installed_match(root,entry):
 target=root/entry['path']
 if target.is_symlink() or not target.is_file():return False
 digest=hashlib.sha256(target.read_bytes()).hexdigest()
 return digest in [BEFORE,AFTER] if entry['path']==FIXTURE and entry['after']==BEFORE else digest==entry['after']
def repair_fixture(m,backup):
 source=pathlib.Path(__file__).resolve().parent/'discovery-database.php'
 if source.is_symlink() or hashlib.sha256(source.read_bytes()).hexdigest()!=AFTER:raise RuntimeError('Corrected fixture checksum mismatch')
 target=m.PLUGIN/FIXTURE;snapshot=backup/'discovery-test-before-hash-fix.php'
 current=hashlib.sha256(target.read_bytes()).hexdigest()
 if current==BEFORE:
  if snapshot.exists():
   if snapshot.is_symlink() or hashlib.sha256(snapshot.read_bytes()).hexdigest()!=BEFORE:raise RuntimeError('Fixture snapshot conflict')
  else:
   with snapshot.open('xb') as stream:stream.write(target.read_bytes())
   snapshot.chmod(0o600)
  m.atomic_copy(source,target)
 elif current!=AFTER:raise RuntimeError('Installed fixture conflict')
 if not snapshot.is_file() or snapshot.is_symlink() or hashlib.sha256(snapshot.read_bytes()).hexdigest()!=BEFORE:raise RuntimeError('Fixture snapshot missing')
 print('PASS: only fixture hash refresh repaired; stale-evidence rejection retained; runtime code unchanged',flush=True)
def corrected_source(text):
 for old,new in REPLACEMENTS.items():
  if text.count(old)!=1:raise RuntimeError('Original deployment contract changed')
  text=text.replace(old,new)
 old="sha(m.PLUGIN/e['path'])==e['after']"
 if text.count(old)!=1:raise RuntimeError('Installed-release validation contract changed')
 text=text.replace(old,'installed_match(m.PLUGIN,e)')
 old=" phase='additive schema and isolated fixed-fixture MariaDB tests'"
 if text.count(old)!=1:raise RuntimeError('Fixture continuation contract changed')
 text=text.replace(old," repair_fixture(m,backup)\n"+old)
 return text
if __name__=='__main__':
 try:
  parser=argparse.ArgumentParser();mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument('--resume',type=pathlib.Path);mode.add_argument('--rollback-code',type=pathlib.Path);args=parser.parse_args()
  if os.geteuid()!=0:raise RuntimeError('Use owner interactive sudo')
  sys.dont_write_bytecode=True
  data=ORIGINAL.read_bytes()
  if ORIGINAL.is_symlink() or hashlib.sha256(data).hexdigest()!=PIN:raise RuntimeError('Original deploy checksum mismatch')
  source=corrected_source(data.decode('utf-8'))
  namespace={'__name__':'cyberdat_discovery_resume','__file__':str(ORIGINAL),'installed_match':installed_match,'repair_fixture':repair_fixture}
  exec(compile(source,str(ORIGINAL),'exec'),namespace)
  sys.argv=[str(ORIGINAL),'--resume' if args.resume else '--rollback-code',str(args.resume or args.rollback_code)]
  namespace['main']()
 except BaseException as e:
  print('BLOCKED: discovery resume; type='+type(e).__name__)
  if isinstance(e,RuntimeError):print('Reason: '+str(e))
  print('No raw credentials/API bodies printed. Keep the original backup; do not rerun --apply.');sys.exit(1)
