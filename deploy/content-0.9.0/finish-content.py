#!/usr/bin/env python3
"""Pinned one-file menu-order correction and remaining staging acceptance only."""
import argparse,datetime,fcntl,getpass,hashlib,http.cookiejar,importlib.util,json,os,pathlib,shutil,sys,urllib.parse,urllib.request
P=pathlib.Path;B=P(__file__).resolve().parent;phase='preflight';ORIGINAL=P('/home/cyberdat/cyberdat-deploy/content-0.9.0-prepared');TARGET=P('/var/www/cyberdat-staging/public/wp-content/plugins/cyberdat-content/includes/admin.php')
def need(ok,reason):
 if not ok:raise RuntimeError(reason)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def tree(p):return {str(f.relative_to(p)):sha(f) for f in p.rglob('*') if f.is_file()}
def main():
 global phase
 parser=argparse.ArgumentParser();mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument('--finish',type=P);mode.add_argument('--disable-content',type=P);args=parser.parse_args();need(os.geteuid()==0,'Use owner interactive sudo');os.umask(0o077);sys.dont_write_bytecode=True
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  h,name=line.split(maxsplit=1);p=B/name;need(p.resolve().is_relative_to(B) and not p.is_symlink() and sha(p)==h,'Finish bundle conflict')
 for line in (ORIGINAL/'BUNDLE-SHA256SUMS').read_text().splitlines():
  h,name=line.split(maxsplit=1);p=ORIGINAL/name;need(p.resolve().is_relative_to(ORIGINAL) and not p.is_symlink() and sha(p)==h,'Original bundle conflict')
 spec=importlib.util.spec_from_file_location('content_finish_support',B/'support.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 need(m.state()[:5]==['staging','cyberdat_staging',m.HOST,'cyberdat','0'],'Wrong staging identity');backup=args.finish or args.disable_content;need(backup.resolve()==backup and backup.parent==m.BACKUPS and backup.name.startswith('content-0.9-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe original backup')
 state=json.loads((backup/'state.json').read_text());need(state['commit']=='727b56be04f590e65ca7b967838cd753ef38b8f9' and sha(backup/'staging.sql.gz')==state['database_sha256'],'Original backup checksum/release conflict');need(m.guards()==state['guards'] and m.timer_fingerprints()==state['timers'] and m.research_code()==state['research'] and tree(m.THEME)==state['theme'],'Protected baseline changed')
 plugin=TARGET.parent.parent;expected=tree(ORIGINAL/'plugin');installed=tree(plugin);before=sha(ORIGINAL/'plugin/includes/admin.php');after=sha(B/'admin.php');need(installed.keys()==expected.keys() and all(h==expected[name] for name,h in installed.items() if name!='includes/admin.php') and sha(TARGET) in [before,after],'Unexpected installed Content code')
 if args.disable_content:
  config=P('/var/lib/cyberdat-staging/content/worker.json');need(not config.is_symlink() and config.stat().st_uid==0,'Unsafe worker config');cfg=json.loads(config.read_text());cfg['enabled']=False;config.write_text(json.dumps(cfg));config.chmod(0o640);m.wp('plugin','deactivate','cyberdat-content');need(m.guards()==state['guards'] and m.timer_fingerprints()==state['timers'] and m.research_code()==state['research'] and tree(m.THEME)==state['theme'],'Protected baseline changed');print('PASS: Content worker denied and plugin deactivated; Content data/audit retained; no SQL restore or Research/production changes');return
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and m.fetch('/',basic)[0]==200 and m.fetch('/')[0]==401,'Basic Auth preflight failed')
 password=getpass.getpass('EXISTING staging WORDPRESS password (hidden; login check only): ');auth=json.loads(m.wp('eval',"$v=json_decode(stream_get_contents(STDIN),true);$u=get_user_by('login','cyberdat_staging_admin');echo wp_json_encode(['ok'=>$u&&user_can($u,'manage_options')&&wp_check_password($v['password'],$u->user_pass,$u->ID),'cookie'=>LOGGED_IN_COOKIE]);",data=json.dumps({'password':password}).encode()).stdout);need(auth['ok'],'Existing WordPress password mismatch; no reset or patch performed');logs=m.log_indicators()
 phase='one pinned menu callback priority patch'
 saved=backup/'content-menu-before.php'
 if not saved.exists():need(sha(TARGET)==before,'Missing pre-patch snapshot for already changed file');shutil.copyfile(TARGET,saved);saved.chmod(0o600)
 need(sha(saved)==before,'Private prior-file checksum conflict')
 if sha(TARGET)!=after:m.atomic_copy(B/'admin.php',TARGET)
 patched=tree(plugin);need(all(h==expected[name] for name,h in patched.items() if name!='includes/admin.php') and sha(TARGET)==after,'Unexpected Content patch result');print('PASS: original SQL backup verified; one admin hook priority corrected; no reinstall, migration or mock rerun',flush=True)
 phase='read-only existing mock draft and Research proof'
 proof=json.loads(m.wp('eval',"$s=new CDCA_Store();$j=$s->read(1);$versions=$s->db->get_results($s->db->prepare(\"SELECT version,is_mock,document,quality FROM {$s->p}versions WHERE job_id=%d ORDER BY version\",1),ARRAY_A);cdca_need(count($versions)===1,'unexpected_fixture_versions');$doc=json_decode($versions[0]['document'],true);$q=cdca_quality($doc,json_decode($j['brief'],true));$r=new CDRA_Store();$d=cyberdat_research_dashboard();$h=cdra_discovery_handoff(50);echo wp_json_encode(['job'=>1,'status'=>$j['status'],'is_test'=>(bool)$j['is_test'],'versions'=>count($versions),'mock_marked'=>(bool)$doc['is_mock'],'truth_verified'=>$q['truth_verified'],'selected_research_count'=>count($h),'dashboard_sql_match'=>(int)$d['counts']['nvd']===$r->count('nvd'),'queue'=>$s->db->get_results(\"SELECT status,is_test,COUNT(*) AS count FROM {$s->p}jobs GROUP BY status,is_test\",ARRAY_A),'posts'=>(int)$s->db->get_var(\"SELECT COUNT(*) FROM {$s->db->posts}\"),'wp_version'=>get_bloginfo('version'),'php_version'=>PHP_VERSION]);").stdout);need(proof['is_test'] and proof['mock_marked'] and proof['versions']==1 and proof['status']=='draft_ready' and not proof['truth_verified'] and proof['dashboard_sql_match'] and proof['posts']==state['posts'],'Existing draft/Research/post regression')
 phase='remaining consolidated HTTP/admin/protection checks'
 jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),m.Redirect());m.fetch('/wp-login.php',basic,opener);form=urllib.parse.urlencode({'log':'cyberdat_staging_admin','pwd':password,'redirect_to':m.HOST+'/wp-admin/','testcookie':'1'}).encode();m.fetch('/wp-login.php',basic,opener,form);need(any(c.name==auth['cookie'] for c in jar),'Existing administrator login failed')
 for route,marker in [('/wp-admin/admin.php?page=cyberdat-content',b'Content Queue'),('/wp-admin/admin.php?page=cyberdat-research',b'Research Queue')]:
  status,_,body=m.fetch(route,basic,opener);print('ADMIN PAGE: '+json.dumps({'route':route,'http':status,'marker':marker in body}),flush=True);need(status==200 and marker in body,'Admin page unavailable; safe diagnostic above')
 for route in ['/','/threat-intelligence/','/tools/','/wp-json/wp/v2/editorial-formats']:
  status,headers,_=m.fetch(route,basic);need(status==200 and 'noindex' in headers.get('X-Robots-Tag','') and m.fetch(route)[0]==401,'Protected existing route regression: '+route)
 status,_,_=m.fetch('/wp-json/cyberdat-content/v1/worker',basic,data=b'{"action":"claim"}');need(status==403,'Worker accepted missing key');need(m.fetch('/wp-json/cyberdat-content/v1/worker')[0]==401,'Worker Basic Auth protection changed')
 need(m.guards()==state['guards'] and m.timer_fingerprints()==state['timers'] and m.research_code()==state['research'] and tree(m.THEME)==state['theme'],'Protected hashes changed')
 for name,values in m.log_indicators().items():
  for kind,n in values.items():need(n<=logs.get(name,{}).get(kind,0),'New checked PHP/Nginx '+kind+' indicator')
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production read-only HTTPS check failed')
 evidence={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'proof':proof,'menu_fix':'Content submenu priority 20 after Research parent priority 10','original_runtime_commit':state['commit'],'finish_commit':(B/'COMMIT').read_text().strip(),'original_backup':str(backup),'post_publication':False,'llm_or_gpu_run':False,'new_mock_run':False,'research_and_timers_unchanged':True,'protected_configs_and_public_theme_unchanged':True,'home_worker_and_browser_unverified':True};(backup/'finish-evidence.json').write_text(json.dumps(evidence));(backup/'COMPLETE').write_text('COMPLETE\n');print('EVIDENCE: '+json.dumps(evidence));print('COMMIT: '+(B/'COMMIT').read_text().strip());print('BACKUP: '+str(backup));print('QUEUE: '+m.HOST+'/wp-admin/admin.php?page=cyberdat-content');print('PASS: Content Stage 1 mock preparation and remaining staging smoke checks; no reinstall, fixture generation, Research/timer/public theme/config/production change');print('UNVERIFIED: actual home-PC worker/Ollama/GPU and real browser UI; real LLM and publication remain disabled')
if __name__=='__main__':
 try:main()
 except BaseException as e:
  print('BLOCKED: phase='+phase+'; type='+type(e).__name__)
  if isinstance(e,RuntimeError):print('Reason: '+str(e))
  print('Keep original backup/partial state; no credentials or raw response body printed; no destructive rollback or blind reapply.');sys.exit(1)
