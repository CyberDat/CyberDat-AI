"""Use the actual installed WP-CLI command factory, without WP/database bootstrap."""
import ast,importlib.util,json,os,pathlib,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
helper=ROOT/'deploy/research-0.8.2/resume-discovery.py'
spec=importlib.util.spec_from_file_location('discovery_resume',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
original=m.ORIGINAL.read_bytes();assert __import__('hashlib').sha256(original).hexdigest()==m.PIN
fixed=m.corrected_source(original.decode());ast.parse(fixed)
assert fixed==(ROOT/'deploy/research-0.8.2/deploy-discovery.py').read_text()
with tempfile.TemporaryDirectory(prefix='cyberdat-cli-registration-') as folder:
 loader=pathlib.Path(folder)/'register.php'
 cli=ROOT/'wp-content/plugins/cyberdat-research/includes/cli.php'
 loader.write_text("<?php if(!defined('ABSPATH')){define('ABSPATH','/offline/');}require "+json.dumps(str(cli))+";\n")
 env=dict(os.environ,WP_CLI_CONFIG_PATH='/dev/null')
 result=subprocess.run(['php8.4','/opt/cyberdat-tools/wp-cli.phar','--skip-packages','--require='+str(loader),'cli','cmd-dump'],cwd=folder,env=env,capture_output=True,text=True)
 assert result.returncode==0,'WP-CLI registration failed; raw output suppressed'
 def lookup(value):
  if isinstance(value,dict):
   if value.get('name')=='cyberdat-research':return {x['name'] for x in value['subcommands']}
   for child in value.values():
    found=lookup(child)
    if found:return found
  elif isinstance(value,list):
   for child in value:
    found=lookup(child)
    if found:return found
 commands=lookup(json.loads(result.stdout))
 assert {'discovery_install','discovery_test','discovery_export'}<=commands
 assert not {'discovery-install','discovery-test'}&commands
 assert "m.wp('cyberdat-research','discovery_install')" in fixed
 assert "['test','discovery_test']" in fixed
print('PASS: actual WP-CLI registers underscore names; resume changes exactly two command names; no WP, DB or network accessed')
