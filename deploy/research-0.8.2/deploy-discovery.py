#!/usr/bin/env python3
"""Owner-run 0.8.2 staging release. Never a production/deployment bootstrap script."""
import argparse,ctypes,datetime,fcntl,getpass,hashlib,importlib.util,json,os,pathlib,pwd,shutil,subprocess,sys,tarfile,time,urllib.request
P=pathlib.Path; B=P(__file__).resolve().parent; phase='preflight'
def need(ok,reason):
 if not ok:raise RuntimeError(reason)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def exchange(a,b):
 libc=ctypes.CDLL(None,use_errno=True);need(hasattr(libc,'renameat2'),'Atomic directory exchange unavailable')
 result=libc.renameat2(-100,os.fsencode(a),-100,os.fsencode(b),2)
 need(result==0,'Atomic release exchange failed; no fallback to partial file copying')
def main():
 global phase
 parser=argparse.ArgumentParser();mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument('--apply',action='store_true');mode.add_argument('--resume',type=P);mode.add_argument('--rollback-code',type=P);args=parser.parse_args()
 need(os.geteuid()==0,'Use owner interactive sudo');os.umask(0o077);sys.dont_write_bytecode=True
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  h,name=line.split(maxsplit=1);p=B/name;need(p.resolve().is_relative_to(B) and not p.is_symlink() and sha(p)==h,'Prepared bundle checksum mismatch')
 spec=importlib.util.spec_from_file_location('discovery_support',B/'support.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 need(m.state()[:5]==['staging','cyberdat_staging',m.HOST,'cyberdat','0'],'Staging identity/guard mismatch')
 patch=json.loads((B/'patch.json').read_text());protected=m.guards();timers=m.timer_fingerprints();logs=m.log_indicators()
 theme={str(p.relative_to(m.THEME)):sha(p) for p in m.THEME.rglob('*') if p.is_file()}
 analytics=m.ROOT/'wp-content/plugins/cyberdat-threat-analytics';analytics_hashes={str(p.relative_to(analytics)):sha(p) for p in analytics.rglob('*') if p.is_file()}
 need(bool(analytics_hashes),'Existing analytics adapter missing')
 if args.apply:
  for e in patch:
   p=m.PLUGIN/e['path'];need((not p.exists()) if e['before'] is None else p.is_file() and sha(p)==e['before'],'Installed Research code conflict; no blind overwrite')
 else:
  for e in patch:need(sha(m.PLUGIN/e['path'])==e['after'],'Installed candidate changed; stop before resume/rollback')
 backup=args.resume or args.rollback_code
 if backup:
  need(backup.resolve()==backup and backup.parent==m.BACKUPS and backup.name.startswith('research-0.8.2-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe backup directory')
  saved=json.loads((backup/'state.json').read_text());need(saved['commit']==(B/'COMMIT').read_text().strip() and saved['protected']==protected and saved['timers']==timers and saved['theme']==theme and saved['analytics']==analytics_hashes,'Backup/protected baseline mismatch')
  for name,h in saved['checksums'].items():need('/' not in name and sha(backup/name)==h,'Backup checksum mismatch')
  previous=P(saved['previous_directory']);need(previous.parent==m.PLUGIN.parent and previous.name.startswith('.cyberdat-research-082-previous-') and previous.is_dir() and not previous.is_symlink(),'Rollback release missing')
 if args.rollback_code:
  # Preserve every discovered row, old backup and schema. Disable discovery before code rollback.
  m.wp('eval',"$s=new CDRA_Store();foreach(cdra_discovery_registry() as $id=>$r){$s->put('discovery_enabled:'.$id,false);}")
  exchange(m.PLUGIN,previous);print('PASS: previous Research code restored atomically; discovery disabled; database/archives retained');return
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and m.fetch('/',basic)[0]==200 and m.fetch('/')[0]==401,'Basic Auth preflight failed')
 need(m.BACKUPS.stat().st_uid==0 and m.BACKUPS.stat().st_mode&0o077==0 and shutil.disk_usage(m.BACKUPS).free>1024**3,'Unsafe backup parent or insufficient free disk')
 resource_before={'load':os.getloadavg(),'mem_available_kib':next((int(line.split()[1]) for line in P('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')),None)};started=time.monotonic()
 before_posts=json.loads(m.wp('eval',"global $wpdb;echo wp_json_encode((int)$wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->posts}\"));").stdout)
 if args.apply:
  phase='private staging backup before code/schema changes'
  stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');backup=m.BACKUPS/('research-0.8.2-'+stamp);backup.mkdir(mode=0o700)
  m.database_backup(backup/'staging.sql.gz')
  with tarfile.open(backup/'research.tar.gz','w:gz') as t:t.add(m.PLUGIN,arcname='cyberdat-research')
  with tarfile.open(backup/'theme.tar.gz','w:gz') as t:t.add(m.THEME,arcname='cyberdat')
  previous=m.PLUGIN.parent/('.cyberdat-research-082-previous-'+stamp);need(not previous.exists(),'Candidate directory conflict');shutil.copytree(m.PLUGIN,previous)
  account=pwd.getpwnam('cyberdat-staging')
  for e in patch:
   source=B/'plugin'/e['path'];target=previous/e['path'];target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
  for p in [previous,*previous.rglob('*')]:need(not p.is_symlink(),'Release symlinks rejected');os.chown(p,account.pw_uid,account.pw_gid);p.chmod(0o755 if p.is_dir() else 0o644)
  for p in previous.rglob('*.php'):m.run(['/usr/bin/php8.4','-l',str(p)])
  saved={'commit':(B/'COMMIT').read_text().strip(),'previous_directory':str(previous),'protected':protected,'timers':timers,'theme':theme,'analytics':analytics_hashes,'checksums':{n:sha(backup/n) for n in ['staging.sql.gz','research.tar.gz','theme.tar.gz']}}
  (backup/'state.json').write_text(json.dumps(saved));print('BACKUP: '+str(backup),flush=True)
  # Existing worker lock: nonblocking, held only across the atomic code exchange.
  holder=subprocess.Popen(['/usr/bin/mariadb','--no-defaults','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--skip-password','--batch','--skip-column-names','--unbuffered'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
  try:
   key='cdra_'+hashlib.sha256(b'cyberdat_stagingstg_cdra_').hexdigest()[:32];holder.stdin.write("SELECT GET_LOCK('"+key+"',0);\n");holder.stdin.flush();need(holder.stdout.readline().strip()=='1','Ingestion currently active; no code swapped; retain backup')
   exchange(m.PLUGIN,previous)
  finally:
   holder.stdin.close();holder.wait(timeout=10)
 phase='additive schema and isolated fixed-fixture MariaDB tests'
 m.wp('cyberdat-research','discovery_install');print('PASS: additive discovery tables; no legacy schema or checkpoint reset',flush=True)
 for command in ['test','discovery_test']:
  result=m.wp('cyberdat-research',command,check=False)
  need(result.returncode==0,'Temporary-table test failed: '+command+'; raw output suppressed; no source enabled by this step')
  print(result.stdout.decode('utf-8','replace'),flush=True)
 # No alternate scheduler: existing dispatch timer will service enabled new sources.
 phase='controlled live discovery; existing KEV/NVD not reimported'
 catalog=json.loads((B/'plugin/includes/discovery-sources.json').read_text());sources=[id for id,r in catalog.items() if r['connection']=='VERIFIED_ENDPOINT'];evidence=[]
 for source in sources:
  script="$id="+json.dumps(source)+";$s=new CDRA_Store();$s->put('discovery_enabled:'.$id,true);$h=$s->get('health:'.$id,[]);if(empty($h['last_success'])||$s->count($id)===0){$r=(new CDRA_Service($s))->sync($id,true);}$h=$s->get('health:'.$id,[]);echo wp_json_encode(['id'=>$id,'count'=>$s->count($id),'health'=>$h]);"
  response=m.wp('eval',script,check=False);need(response.returncode==0,'Controlled source job failed before safe status: '+source)
  row=json.loads(response.stdout);evidence.append(row);print('SOURCE: '+json.dumps({'id':source,'count':row['count'],'last_success':row['health'].get('last_success'),'error':row['health'].get('last_error','')}),flush=True)
  time.sleep(3) # One source at a time, bounded requests; no NVD/KEV request.
 phase='idempotency, queue and regression checks'
 proof=json.loads(m.wp('eval',(B/'verify-discovery.php').read_text()[5:]).stdout);print('EVIDENCE: '+json.dumps(proof),flush=True)
 for path,marker in [('/',b'data-threat-pulse="2.1"'),('/threat-intelligence/',b'data-analytics-dialog'),('/tools/',b'Coming Soon')]:
  code,headers,body=m.fetch(path,basic);need(code==200 and marker in body and 'noindex' in headers.get('X-Robots-Tag',''),'Protected HTTP regression');need(m.fetch(path)[0]==401,'Anonymous Basic Auth regression')
 m.admin_check(basic)
 need(proof['streams'].get('news',0)>0 and proof['streams'].get('research',0)>0 and proof['sources'].get('arxiv',0)>0 and proof['sources'].get('crossref',0)>0,'All three streams and two academic providers are not proven; report PARTIAL')
 need(proof['duplicate_ids']==0 and proof['idempotent'] and proof['legacy_sources_ok'] and proof['dashboard_sql_match'] and proof['admin_registry'] and proof['admin_queue'] and proof['admin_nonce'] and proof['anonymous_rejected'],'Discovery/legacy integrity check failed')
 need(m.guards()==protected and m.timer_fingerprints()==timers and theme=={str(p.relative_to(m.THEME)):sha(p) for p in m.THEME.rglob('*') if p.is_file()} and analytics_hashes=={str(p.relative_to(analytics)):sha(p) for p in analytics.rglob('*') if p.is_file()},'Protected configuration/theme/analytics/timers changed')
 after_posts=json.loads(m.wp('eval',"global $wpdb;echo wp_json_encode((int)$wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->posts}\"));").stdout);need(after_posts==before_posts,'WordPress post count changed during verification')
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production health check failed')
 after=m.log_indicators()
 for path,counts in after.items():
  for kind,n in counts.items():need(n<=logs.get(path,{}).get(kind,0),'New staging PHP/Nginx '+kind+' indicator')
 resources={'before':resource_before,'after':{'load':os.getloadavg(),'mem_available_kib':next((int(line.split()[1]) for line in P('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')),None)},'elapsed_seconds':round(time.monotonic()-started,1),'database_bytes':proof['db_bytes'],'long_term_impact':'UNVERIFIED'};print('RESOURCES: '+json.dumps(resources));(backup/'evidence.json').write_text(json.dumps({'sources':evidence,'proof':proof,'resources':resources}));(backup/'COMPLETE').write_text('COMPLETE\n')
 print('PASS: controlled discovery across all three streams; existing dispatcher reused; no automatic publication')
 print('COMMIT: '+(B/'COMMIT').read_text().strip());print('BACKUP: '+str(backup));print('URL: '+m.HOST+'/wp-admin/admin.php?page=cyberdat-research')
 print('UNVERIFIED: new-source scheduled recurrence, real-browser admin interactions, long-term resource impact; registry blocked sources are not ACTIVE')
if __name__=='__main__':
 try:main()
 except BaseException as e:
  print('BLOCKED: phase='+phase+'; type='+type(e).__name__)
  if isinstance(e,RuntimeError):print('Reason: '+str(e))
  print('Retain backup and partial state. No raw credentials/API bodies, historical import, production writes or destructive cleanup. Do not reapply blindly.');sys.exit(1)
