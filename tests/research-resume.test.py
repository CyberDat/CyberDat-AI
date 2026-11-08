"""No root, WordPress, DB, network or service calls. Exercise updater failure contracts."""
import importlib.util,pathlib,tempfile,os,stat
root=pathlib.Path(__file__).resolve().parents[1]
for name in ['update-research','resume-research']:
 spec=importlib.util.spec_from_file_location(name,root/'deploy/research'/f'{name}.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 with tempfile.TemporaryDirectory(prefix='cdra-permission-test-') as folder:
  old=os.umask(0o077)
  try:
   module.TOOLS=pathlib.Path(folder)/'code';module.TOOLS.mkdir(mode=0o755)
   assert stat.S_IMODE(module.TOOLS.stat().st_mode)==0o700
   module.code_directory_permissions()
   assert stat.S_IMODE(module.TOOLS.stat().st_mode)==0o755
  finally:os.umask(old)
 for value in [[],{}, {'last_success':123,'last_error':''}]:
  h=module.source_health({'sources':{'kev':value}},'kev');assert isinstance(h,dict);assert h.get('last_success',0)==(123 if value else 0)
 try:module.source_health({'sources':{'kev':['invalid']}},'kev')
 except RuntimeError:pass
 else:raise AssertionError('Invalid health silently accepted')
 print('PASS:',name,'handles restrictive umask and empty PHP health arrays safely')
print('PASS: no backups, service starts, DB queries or deployments performed')
