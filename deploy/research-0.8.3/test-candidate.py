import sys,os,pathlib,shutil,importlib.util,json,pwd
sys.dont_write_bytecode=True
P=pathlib.Path
spec=importlib.util.spec_from_file_location('support','/home/cyberdat/cyberdat-deploy/content-0.9.0-prepared/support.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
os.chdir(m.RUNTIME);os.umask(0o077)
src=P('/home/cyberdat/cyberdat-deploy/research-0.8.3-work/wp-content/plugins/cyberdat-research');dst=P('/var/lib/cyberdat-staging/research/candidate-0.8.3')
if dst.exists():shutil.rmtree(dst)
shutil.copytree(src,dst)
a=pwd.getpwnam('cyberdat-staging')
for p in [dst,*dst.rglob('*')]:os.chown(p,0,a.pw_gid);p.chmod(0o750 if p.is_dir() else 0o640)
for name,code in [
 ('research',"require '"+str(dst)+"/cyberdat-research.php';require CDRA_DIR.'/tests/database.php';cdra_database_tests();"),
 ('discovery',"require '"+str(dst)+"/cyberdat-research.php';require CDRA_DIR.'/tests/discovery-database.php';cdra_discovery_database_tests();"),
 ('content',"require '"+str(dst)+"/cyberdat-research.php';require CDCA_DIR.'/tests/database.php';cdca_database_tests();"),
 ('evidence',"require '"+str(dst)+"/cyberdat-research.php';require CDCA_DIR.'/tests/evidence-database.php';cdca_evidence_database_tests();")]:
 r=m.wp('--skip-plugins=cyberdat-research','eval',code,check=False)
 print('SUITE',name,'exit',r.returncode,flush=True)
 out=r.stdout.decode(errors='replace');print(out,flush=True)
 if r.returncode:
  # Only exception class/code/location, never arbitrary raw stderr.
  import re
  err=r.stderr.decode(errors='replace');safe=re.findall(r'(?:PHP Fatal error:|Uncaught [A-Za-z_\\]+:)[^\n]*',err)
  print('SAFE ERROR',json.dumps(safe),flush=True);sys.exit(1)
print('PASS: candidate fixtures only; no live sync, selection, migration or publication')
