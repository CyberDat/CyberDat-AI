#!/usr/bin/env python3
"""Selected staging read-adapter/cache/lock diagnostics; no sync or model cache writes."""
import hashlib,importlib.util,json,os,pathlib,sys
P=pathlib.Path;B=P(__file__).resolve().parent
try:
 if os.geteuid()!=0 or sys.argv[1:]!=['--read-only']:raise RuntimeError('Use owner sudo and --read-only')
 os.umask(0o077);sys.dont_write_bytecode=True
 support=P('/home/cyberdat/cyberdat-deploy/analytics-2.1-finish-prepared/support.py')
 if hashlib.sha256(support.read_bytes()).hexdigest()!='40f9a8336296d20fda25da08346d8e2f2892667255d2c1ffc7b223da2043b9c9':raise RuntimeError('Support checksum mismatch')
 spec=importlib.util.spec_from_file_location('model_support',support);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 result=m.wp('eval',(B/'model-probe.php').read_text()[5:],check=False)
 if result.returncode:raise RuntimeError('Selected staging probe failed; raw output suppressed')
 report=json.loads(result.stdout);print('ANALYTICS MODEL DIAGNOSTIC: '+json.dumps(report))
 print('No cache clear/update, SQL writes by probe, synchronization, checkpoint reset, plugin activation, timer action or production operation. WordPress CLI bootstrap only.')
except Exception as e:
 print('BLOCKED: model diagnostic; type='+type(e).__name__)
 if isinstance(e,RuntimeError):print(str(e))
 sys.exit(1)
