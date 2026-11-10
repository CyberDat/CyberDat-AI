#!/usr/bin/env python3
"""Owner-run staging-only Content Stage 1 deployment. No LLM, collectors or timers."""
import argparse,base64,datetime,fcntl,getpass,hashlib,http.cookiejar,importlib.util,json,os,pathlib,pwd,secrets,shutil,subprocess,sys,time,urllib.request,urllib.error,urllib.parse
P=pathlib.Path;B=P(__file__).resolve().parent;phase='preflight';PLUGIN=P('/var/www/cyberdat-staging/public/wp-content/plugins/cyberdat-content');RUNTIME=P('/var/lib/cyberdat-staging/content');PRIVATE=P('/home/cyberdat/cyberdat-deploy/content-0.9-private')
def need(ok,code):
 if not ok:raise RuntimeError(code)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def tree(p):return {str(f.relative_to(p)):sha(f) for f in p.rglob('*') if f.is_file()}
def main():
 global phase
 parser=argparse.ArgumentParser();a=parser.add_mutually_exclusive_group(required=True);a.add_argument('--apply',action='store_true');a.add_argument('--resume',type=P);a.add_argument('--verify',type=P);a.add_argument('--rollback-code',type=P);args=parser.parse_args();need(os.geteuid()==0,'Use owner interactive sudo');os.umask(0o077);sys.dont_write_bytecode=True
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  h,name=line.split(maxsplit=1);p=B/name;need(p.resolve().is_relative_to(B) and not p.is_symlink() and sha(p)==h,'Bundle checksum conflict')
 spec=importlib.util.spec_from_file_location('content_support',B/'support.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);need(m.state()[:5]==['staging','cyberdat_staging',m.HOST,'cyberdat','0'],'Wrong staging identity')
 guards=m.guards();timers=m.timer_fingerprints();research=m.research_code();theme=tree(m.THEME);logs=m.log_indicators();candidates=tree(B/'plugin');backup=args.resume or args.verify or args.rollback_code
 if args.apply:need(not PLUGIN.exists() and not RUNTIME.exists() and not PRIVATE.exists(),'Installed Content release/private config exists; no blind apply')
 else:
  need(backup.resolve()==backup and backup.parent==m.BACKUPS and backup.name.startswith('content-0.9-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe backup')
  state=json.loads((backup/'state.json').read_text());need(state['commit']==(B/'COMMIT').read_text().strip(),'Backup release mismatch');need(state['guards']==guards and state['timers']==timers and state['research']==research and state['theme']==theme,'Protected baseline changed');need(sha(backup/'staging.sql.gz')==state['database_sha256'],'Backup checksum mismatch')
  if PLUGIN.exists():need(all(name in candidates and h==candidates[name] for name,h in tree(PLUGIN).items()),'Installed Content code differs from bundle')
 if args.rollback_code:
  cfg=json.loads((RUNTIME/'worker.json').read_text());cfg['enabled']=False;(RUNTIME/'worker.json').write_text(json.dumps(cfg));os.chown(RUNTIME/'worker.json',0,pwd.getpwnam('cyberdat-staging').pw_gid);(RUNTIME/'worker.json').chmod(0o640);m.wp('plugin','deactivate','cyberdat-content');print('PASS: Content plugin deactivated and worker denied; Content data/history retained; no Research/config/timer/production rollback');return
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and m.fetch('/',basic)[0]==200 and m.fetch('/')[0]==401,'Basic Auth preflight failed')
 wp_password=getpass.getpass('EXISTING staging WORDPRESS password (hidden; not SSH/Basic Auth): ')
 auth=json.loads(m.wp('eval',"$v=json_decode(stream_get_contents(STDIN),true);$u=get_user_by('login','cyberdat_staging_admin');echo wp_json_encode(['ok'=>$u&&user_can($u,'manage_options')&&wp_check_password($v['password'],$u->user_pass,$u->ID),'cookie'=>LOGGED_IN_COOKIE]);",data=json.dumps({'password':wp_password}).encode()).stdout);need(auth['ok'],'Existing WordPress password mismatch; no changes or reset')
 posts=int(m.wp('eval',"global $wpdb;echo (int)$wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->posts}\");").stdout)
 started=time.monotonic();resources_before={'load':os.getloadavg(),'available_kib':next(int(x.split()[1]) for x in P('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))}
 if args.apply:
  phase='private staging backup before plugin/schema changes';need(m.BACKUPS.stat().st_uid==0 and m.BACKUPS.stat().st_mode&0o077==0 and shutil.disk_usage(m.BACKUPS).free>1024**3,'Backup parent/disk preflight');backup=m.BACKUPS/('content-0.9-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));backup.mkdir(mode=0o700);m.database_backup(backup/'staging.sql.gz');state={'commit':(B/'COMMIT').read_text().strip(),'database_sha256':sha(backup/'staging.sql.gz'),'guards':guards,'timers':timers,'research':research,'theme':theme,'posts':posts};(backup/'state.json').write_text(json.dumps(state));print('BACKUP: '+str(backup),flush=True)
 stage=pwd.getpwnam('cyberdat-staging');owner=pwd.getpwnam('cyberdat')
 phase='new standalone Content plugin only'
 if not PLUGIN.exists():PLUGIN.mkdir(mode=0o755)
 PLUGIN.chmod(0o755);os.chown(PLUGIN,stage.pw_uid,stage.pw_gid)
 for src in sorted((B/'plugin').rglob('*')):
  dest=PLUGIN/src.relative_to(B/'plugin')
  if src.is_dir():dest.mkdir(mode=0o755,exist_ok=True);dest.chmod(0o755);os.chown(dest,stage.pw_uid,stage.pw_gid)
  elif not dest.exists():m.atomic_copy(src,dest)
 need(tree(PLUGIN)==candidates,'Installed plugin checksums')
 if not RUNTIME.exists():
  phase='root-controlled mock worker credential outside Git';RUNTIME.mkdir(mode=0o750);RUNTIME.chmod(0o750);os.chown(RUNTIME,0,stage.pw_gid);PRIVATE.mkdir(mode=0o700);os.chown(PRIVATE,owner.pw_uid,owner.pw_gid);token=secrets.token_hex(32)
  cfg={'enabled':True,'mode':'mock_only','workers':{'home-mock':hashlib.sha256(token.encode()).hexdigest()}};(RUNTIME/'worker.json').write_text(json.dumps(cfg));os.chown(RUNTIME/'worker.json',0,stage.pw_gid);(RUNTIME/'worker.json').chmod(0o640)
  (PRIVATE/'bootstrap.json').write_text(json.dumps({'base_url':m.HOST,'worker_id':'home-mock','worker_token':token,'adapter':'mock','generation':{'model':'mock-v1','temperature':0,'max_output_tokens':1024,'timeout_seconds':60}}));os.chown(PRIVATE/'bootstrap.json',owner.pw_uid,owner.pw_gid);(PRIVATE/'bootstrap.json').chmod(0o600)
 need(not RUNTIME.is_symlink() and not (RUNTIME/'worker.json').is_symlink() and (RUNTIME/'worker.json').stat().st_uid==0 and (RUNTIME/'worker.json').stat().st_mode&0o027==0,'Worker server config permissions')
 phase='activation/additive schema and temporary-table tests';m.wp('plugin','activate','cyberdat-content')
 # Freeze only existing ingestion briefly for count-based isolation evidence; never start/stop a timer.
 holder=subprocess.Popen(['/usr/bin/mariadb','--no-defaults','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--skip-password','--batch','--skip-column-names','--unbuffered'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
 try:
  key='cdra_'+hashlib.sha256(b'cyberdat_stagingstg_cdra_').hexdigest()[:32];end=time.monotonic()+150
  while True:
   holder.stdin.write("SELECT GET_LOCK('"+key+"',0);\n");holder.stdin.flush();v=holder.stdout.readline().strip();need(v in ['0','1'],'Research lock status failed')
   if v=='1':break
   need(time.monotonic()<end,'Existing ingestion busy; retain backup and use --resume');print('WAIT: existing ingestion; no concurrent import',flush=True);time.sleep(5)
  for command in [('cyberdat-content','test'),('cyberdat-research','test'),('cyberdat-research','discovery_test')]:
   r=m.wp(*command,check=False);need(r.returncode==0,'Temporary-table test failed: '+command[-1]+'; raw failure output suppressed');print(r.stdout.decode('utf-8','replace'),flush=True)
  handoff=json.loads(m.wp('eval',"$x=cdra_discovery_handoff(50);echo wp_json_encode(['schema'=>'cyberdat-research-handoff/1','selected_count'=>count($x),'read_only'=>true]);").stdout);print('READ-ONLY RESEARCH HANDOFF: '+json.dumps(handoff),flush=True)
 finally:holder.stdin.close();holder.wait(timeout=10)
 phase='one mock HTTPS worker round trip, no LLM';fixture=json.loads(m.wp('cyberdat-content','fixture').stdout);bootstrap=json.loads((PRIVATE/'bootstrap.json').read_text());cfg=json.loads((RUNTIME/'worker.json').read_text());need(cfg['enabled'] and cfg['mode']=='mock_only' and hashlib.sha256(bootstrap['worker_token'].encode()).hexdigest()==cfg['workers']['home-mock'],'Worker credential mismatch')
 # Secrets travel only via stdin memory; never password argv/environment or a saved Basic Auth file.
 worker_config={**bootstrap,'basic_user':'cyberdat_staging_admin','basic_password':basic};result=m.run(['/usr/bin/python3','-I',str(B/'worker.py'),'--stdin-config','--once','--spool',str(PRIVATE/'acceptance-pending.json')],data=json.dumps(worker_config).encode(),timeout=240,check=False);need(result.returncode==0,'Mock HTTPS worker failed; no raw credential-bearing response printed');out=json.loads(result.stdout);print('MOCK WORKER: '+json.dumps(out),flush=True)
 proof=json.loads(m.wp('eval',"$s=new CDCA_Store();$j=$s->read("+str(fixture['id'])+");$versions=(int)$s->db->get_var($s->db->prepare(\"SELECT COUNT(*) FROM {$s->p}versions WHERE job_id=%d\",$j['id']));$d=cyberdat_research_dashboard();$r=new CDRA_Store();echo wp_json_encode(['job'=>(int)$j['id'],'status'=>$j['status'],'is_test'=>(bool)$j['is_test'],'versions'=>$versions,'queue'=>$s->db->get_results(\"SELECT status,is_test,COUNT(*) AS count FROM {$s->p}jobs GROUP BY status,is_test\",ARRAY_A),'dashboard_sql_match'=>(int)$d['counts']['nvd']===$r->count('nvd'),'automatic_publication'=>false,'worker_mode'=>'mock_only','wp_version'=>get_bloginfo('version'),'php_version'=>PHP_VERSION]);").stdout);need(proof['status']=='draft_ready' and proof['is_test'] and proof['versions']==1 and proof['dashboard_sql_match'],'Mock draft/Research regression proof failed')
 phase='one consolidated HTTP/admin/protection smoke test';jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),m.Redirect());m.fetch('/wp-login.php',basic,opener);form=urllib.parse.urlencode({'log':'cyberdat_staging_admin','pwd':wp_password,'redirect_to':m.HOST+'/wp-admin/','testcookie':'1'}).encode();m.fetch('/wp-login.php',basic,opener,form);need(any(c.name==auth['cookie'] for c in jar),'Existing admin login failed')
 for page,marker in [('/wp-admin/admin.php?page=cyberdat-content',b'Content Queue'),('/wp-admin/admin.php?page=cyberdat-research',b'Research Queue')]:
  status,_,body=m.fetch(page,basic,opener);need(status==200 and marker in body,'Existing admin page failed: '+page)
 for path in ['/','/threat-intelligence/','/tools/','/wp-json/wp/v2/editorial-formats']:
  status,headers,body=m.fetch(path,basic);need(status==200 and 'noindex' in headers.get('X-Robots-Tag','') and m.fetch(path)[0]==401,'Staging route protection regression: '+path)
 # Existing Basic Auth alone cannot call the worker. No token in query strings.
 status,_,_=m.fetch('/wp-json/cyberdat-content/v1/worker',basic,data=b'{"action":"claim"}');need(status==403,'Worker accepted missing credential')
 need(m.guards()==guards and m.timer_fingerprints()==timers and m.research_code()==research and tree(m.THEME)==theme,'Protected config/Research/theme/timer changed');need(int(m.wp('eval',"global $wpdb;echo (int)$wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->posts}\");").stdout)==state['posts'],'WordPress post count changed')
 for name,values in m.log_indicators().items():
  for kind,n in values.items():need(n<=logs.get(name,{}).get(kind,0),'New checked PHP/Nginx '+kind+' indicator')
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production read-only HTTPS health failed')
 evidence={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'proof':proof,'handoff':handoff,'mock_worker':out,'research_unchanged':True,'timers_unchanged':True,'theme_unchanged':True,'protection_unchanged':True,'posts_unchanged':True,'home_worker_verified':False,'ollama_verified':False,'llm_run':False,'resources':{'before':resources_before,'after':{'load':os.getloadavg(),'available_kib':next(int(x.split()[1]) for x in P('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))},'seconds':round(time.monotonic()-started,1)}};(backup/'evidence.json').write_text(json.dumps(evidence));(backup/'COMPLETE').write_text('COMPLETE\n');print('EVIDENCE: '+json.dumps(evidence));print('COMMIT: '+(B/'COMMIT').read_text().strip());print('BACKUP: '+str(backup));print('QUEUE: '+m.HOST+'/wp-admin/admin.php?page=cyberdat-content');print('BOOTSTRAP: '+str(PRIVATE/'bootstrap.json')+' (owner-only; contains worker key, never paste in chat)');print('PASS: Stage 1 mock queue/worker preparation; no posts, LLM, collector, timer, production or network-configuration changes');print('UNVERIFIED: home-PC transport/Ollama/GPU and real browser UI; real LLM disabled by design')
if __name__=='__main__':
 try:main()
 except BaseException as e:
  print('BLOCKED: phase='+phase+'; type='+type(e).__name__)
  if isinstance(e,RuntimeError):print('Reason: '+str(e))
  print('Keep backup/partial state; no credential/API body printed or destructive rollback. Use --resume BACKUP after review, never blindly repeat --apply.');sys.exit(1)
