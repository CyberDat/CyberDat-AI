"""Offline conditional repair tests; no WP, network, accounts or root operations."""
import ast,importlib.util,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parents[1];path=root/'deploy/research/finish-threat-rankmath.py'
spec=importlib.util.spec_from_file_location('free_finish',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base={'rank_math_active':True,'helper_available':True,'registration_invalid':True,'skip_value':None,'constant_skip':None}
for v in [None,False,0,'','0']:
 s={**base,'skip_value':v};assert m.repair_needed(s);print('PASS: supported absent/false skip state is eligible')
assert m.repair_needed({**base,'registration_invalid':False,'skip_value':'1'}) is False
for patch in [{'rank_math_active':False},{'helper_available':False},{'skip_value':True},{'constant_skip':True}]:
 try:m.repair_needed({**base,**patch})
 except RuntimeError:pass
 else:raise AssertionError(patch)
print('PASS: active frontend is not changed; inconsistent/unavailable states refused')
# Lint embedded PHP strings, without executing them or loading any configuration.
tree=ast.parse(path.read_text());count=0
for node in ast.walk(tree):
 if isinstance(node,ast.Constant) and isinstance(node.value,str) and ('require_once ABSPATH' in node.value):
  result=subprocess.run(['php8.4','-l'],input=('<?php '+node.value).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE);assert result.returncode==0,result.stdout;count+=1
assert count==2
print('PASS: embedded PHP syntax; only supported option update, no plugin patch or account request')
