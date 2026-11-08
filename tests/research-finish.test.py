"""No services/DB/network: prove finish-only scope and secret transport."""
import ast,importlib.util,pathlib,types
root=pathlib.Path(__file__).resolve().parents[1];p=root/'deploy/research/finish-research.py'
spec=importlib.util.spec_from_file_location('finish_research',p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
captured={}
def fake(args,**kwargs):captured['args']=args;captured.update(kwargs);return types.SimpleNamespace(stdout=b'{}',returncode=0)
module.run=fake
payload=b'{"password":"TEST_ONLY_not_a_real_password"}'
module.wp('eval','echo "static-code";',data=payload)
assert captured['data']==payload
assert not any('TEST_ONLY_not_a_real_password' in a for a in captured['args'])
print('PASS: secret is supplied through stdin, never process arguments')
main=next(n for n in ast.parse(p.read_text()).body if isinstance(n,ast.FunctionDef)and n.name=='main')
operations=[]
for n in ast.walk(main):
 if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='wp':
  operations.append([a.value for a in n.args if isinstance(a,ast.Constant)and isinstance(a.value,str)])
assert all(a[0]=='eval' or a[:2] in [['cyberdat-research','status'],['cyberdat-research','verify']]for a in operations)
assert not any(isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id in ['database_backup','owned_copy','rollback']for n in ast.walk(main))
print('PASS: finish has no ingestion, plugin install, migration or backup-copy calls')
assert 'wp_set_password' not in p.read_text() and 'wp_update_user' not in p.read_text()
print('PASS: no credential-reset path; actual HTTP/admin verification remains required')
