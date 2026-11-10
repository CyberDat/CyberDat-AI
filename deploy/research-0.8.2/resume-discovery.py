#!/usr/bin/env python3
"""Resume the exact saved release with corrected WP-CLI names; no reinstall."""
import argparse,hashlib,os,pathlib,sys
ORIGINAL=pathlib.Path('/home/cyberdat/cyberdat-deploy/research-0.8.2-prepared/deploy-discovery.py')
PIN='04ee6fcba4f1470166e36fdc33c6f335f36f82436a26fd515259279b941fc518'
REPLACEMENTS={"m.wp('cyberdat-research','discovery-install')":"m.wp('cyberdat-research','discovery_install')","for command in ['test','discovery-test']:":"for command in ['test','discovery_test']:"}
def corrected_source(text):
 for old,new in REPLACEMENTS.items():
  if text.count(old)!=1:raise RuntimeError('Original deployment contract changed')
  text=text.replace(old,new)
 return text
if __name__=='__main__':
 try:
  parser=argparse.ArgumentParser();parser.add_argument('--resume',required=True,type=pathlib.Path);args=parser.parse_args()
  if os.geteuid()!=0:raise RuntimeError('Use owner interactive sudo')
  sys.dont_write_bytecode=True
  data=ORIGINAL.read_bytes()
  if ORIGINAL.is_symlink() or hashlib.sha256(data).hexdigest()!=PIN:raise RuntimeError('Original deploy checksum mismatch')
  source=corrected_source(data.decode('utf-8'))
  namespace={'__name__':'cyberdat_discovery_resume','__file__':str(ORIGINAL)}
  exec(compile(source,str(ORIGINAL),'exec'),namespace)
  sys.argv=[str(ORIGINAL),'--resume',str(args.resume)]
  namespace['main']()
 except BaseException as e:
  print('BLOCKED: discovery resume; type='+type(e).__name__)
  if isinstance(e,RuntimeError):print('Reason: '+str(e))
  print('No raw credentials/API bodies printed. Keep the original backup; do not rerun --apply.');sys.exit(1)
