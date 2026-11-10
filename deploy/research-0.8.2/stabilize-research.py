#!/usr/bin/env python3
"""Owner-run bounded staging stabilization; no collector replacement or timer changes."""
import argparse,datetime,fcntl,getpass,hashlib,importlib.util,json,os,pathlib,shutil,subprocess,sys,tarfile,time,urllib.request
P=pathlib.Path;B=P(__file__).resolve().parent;phase='preflight'
def need(ok,reason):
 if not ok:raise RuntimeError(reason)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 global phase
 parser=argparse.ArgumentParser();mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument('--apply',action='store_true');mode.add_argument('--resume',type=P);mode.add_argument('--observe',type=P);mode.add_argument('--rollback-code',type=P);args=parser.parse_args()
 need(os.geteuid()==0,'Use owner interactive sudo');os.umask(0o077);sys.dont_write_bytecode=True
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  h,name=line.split(maxsplit=1);p=B/name;need(p.resolve().is_relative_to(B) and not p.is_symlink() and sha(p)==h,'Prepared bundle checksum mismatch')
 spec=importlib.util.spec_from_file_location('stabilization_support',B/'support.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,(fcntl.LOCK_SH if args.observe else fcntl.LOCK_EX)|fcntl.LOCK_NB)
 need(m.state()[:5]==['staging','cyberdat_staging',m.HOST,'cyberdat','0'],'Wrong staging identity')
 patch=json.loads((B/'patch.json').read_text());targets=[m.PLUGIN/e['path'] for e in patch]
 def others():return {str(p.relative_to(m.PLUGIN)):sha(p) for p in m.PLUGIN.rglob('*') if p.is_file() and p not in targets}
 def theme():return {str(p.relative_to(m.THEME)):sha(p) for p in m.THEME.rglob('*') if p.is_file()}
 protected=m.guards();timers=m.timer_fingerprints();other_hashes=others();theme_hashes=theme();logs=m.log_indicators()
 for e in patch:
  target=m.PLUGIN/e['path'];need(target.resolve()==target and sha(target) in ([e['before']] if args.apply else [e['before'],e['after']]),'Installed source code conflict')
 backup=args.resume or args.observe or args.rollback_code
 if backup:
  need(backup.resolve()==backup and backup.parent==m.BACKUPS and backup.name.startswith('research-stabilization-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe backup path')
  state=json.loads((backup/'state.json').read_text());need(state['commit']==(B/'COMMIT').read_text().strip() and state['protected']==protected and state['timers']==timers and state['others']==other_hashes and state['theme']==theme_hashes,'Backup/protected baseline changed')
  for name,h in state['checksums'].items():need('/' not in name and sha(backup/name)==h,'Backup checksum mismatch')
 def job(filename):
  code=(B/filename).read_text();need(code.startswith('<?php'),'Invalid PHP payload');end=time.monotonic()+150
  while True:
   wrapped="try{"+code[5:]+"}catch(Throwable $e){echo wp_json_encode(['_error'=>$e instanceof CDRA_Error&&preg_match('/^[a-z0-9_]{1,64}$/D',$e->getMessage())?$e->getMessage():'processing_error','type'=>get_class($e)]);}"
   result=m.wp('eval',wrapped,check=False);need(result.returncode==0,'Staging PHP job failed: '+filename+'; raw output suppressed');value=json.loads(result.stdout)
   if value.get('_error')=='ingestion_locked' and time.monotonic()<end:print('WAIT: existing ingestion lock; no competing fetch',flush=True);time.sleep(5);continue
   need('_error' not in value,'Staging job '+filename+': '+value.get('_error','unknown'));return value
 if args.observe:
  proof=job('stabilize-proof.php');print('OBSERVATION: '+json.dumps(proof));print('TIMERS: '+json.dumps(m.timers()));print('No sync, source state, cache, checkpoint or timer writes; WordPress bootstrap/read-only queries only.');return
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and m.fetch('/',basic)[0]==200 and m.fetch('/')[0]==401,'Basic Auth preflight failed')
 if args.rollback_code:
  # Code-only rollback retains all actual publications, classifications and event audit.
  ids=json.loads((B/'new-sources.json').read_text());m.wp('eval',"$s=new CDRA_Store();foreach(json_decode("+json.dumps(json.dumps(ids))+",true) as $id){$s->put('discovery_enabled:'.$id,false);}")
  for i,e in enumerate(patch):
   if e['path']!='includes/discovery-sources.json':m.atomic_copy(backup/('previous-'+str(i)),m.PLUGIN/e['path'])
  print('PASS: previous classifier/dispatcher restored; new source jobs disabled; registry retained to read historical publications safely; data/audit retained; no SQL restore');return
 before_checkpoint=json.loads(m.wp('eval',"$s=new CDRA_Store();echo wp_json_encode($s->get('nvd_checkpoint'));").stdout)
 posts_before=json.loads(m.wp('eval',"global $wpdb;echo wp_json_encode((int)$wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->posts}\"));").stdout)
 resources_before={'load':os.getloadavg(),'available_kib':next(int(l.split()[1]) for l in P('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:'))};started=time.monotonic()
 if args.apply:
  phase='backup before bounded stabilization'
  need(m.BACKUPS.stat().st_uid==0 and m.BACKUPS.stat().st_mode&0o077==0 and shutil.disk_usage(m.BACKUPS).free>1024**3,'Unsafe backup parent or insufficient disk')
  backup=m.BACKUPS/('research-stabilization-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));backup.mkdir(mode=0o700);m.database_backup(backup/'staging.sql.gz')
  with tarfile.open(backup/'research.tar.gz','w:gz') as archive:archive.add(m.PLUGIN,arcname='cyberdat-research')
  for i,e in enumerate(patch):shutil.copyfile(m.PLUGIN/e['path'],backup/('previous-'+str(i)))
  names=['staging.sql.gz','research.tar.gz']+['previous-'+str(i) for i in range(len(patch))];state={'commit':(B/'COMMIT').read_text().strip(),'protected':protected,'timers':timers,'others':other_hashes,'theme':theme_hashes,'checksums':{n:sha(backup/n) for n in names}};(backup/'state.json').write_text(json.dumps(state));print('BACKUP: '+str(backup),flush=True)
 phase='three pinned files under existing ingestion lock'
 holder=subprocess.Popen(['/usr/bin/mariadb','--no-defaults','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--skip-password','--batch','--skip-column-names','--unbuffered'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
 try:
  key='cdra_'+hashlib.sha256(b'cyberdat_stagingstg_cdra_').hexdigest()[:32];deadline=time.monotonic()+150
  while True:
   holder.stdin.write("SELECT GET_LOCK('"+key+"',0);\n");holder.stdin.flush();value=holder.stdout.readline().strip();need(value in ['0','1'],'Cannot read ingestion lock status')
   if value=='1':break
   need(time.monotonic()<deadline,'Existing ingestion still busy; resume from backup, do not reapply');print('WAIT: existing ingestion; retaining private backup',flush=True);time.sleep(5)
  for e in patch:
   if e['path'].endswith('.php'):m.run(['/usr/bin/php8.4','-l',str(B/e['candidate'])])
   if sha(m.PLUGIN/e['path'])!=e['after']:m.atomic_copy(B/e['candidate'],m.PLUGIN/e['path'])
 finally:holder.stdin.close();holder.wait(timeout=10)
 phase='temporary-table integration and bounded classification correction'
 for command in ['test','discovery_test']:
  result=m.wp('cyberdat-research',command,check=False);need(result.returncode==0,'Temporary-table integration failed: '+command+'; no raw output printed');print(result.stdout.decode('utf-8','replace'),flush=True)
 quality=job('stabilize-quality.php');print('QUALITY: '+json.dumps(quality),flush=True)
 correlation=job('stabilize-correlation.php');print('CORRELATION: '+json.dumps(correlation),flush=True)
 phase='bounded recovery of healthy overdue original feeds'
 # This is controlled due-work recovery, NOT evidence of an automatic timer cycle.
 for recovery in range(3):
  code="$s=new CDRA_Store();$id=cdra_dispatch_due_source($s);if(!$id||!in_array($id,['kev','cisa-advisories','cert-eu','msrc'],true)){echo wp_json_encode(['skipped'=>true]);return;}$h=$s->get('health:'.$id,[]);if(!empty($h['last_error'])){echo wp_json_encode(['skipped'=>true]);return;}try{$r=(new CDRA_Service($s))->sync($id);echo wp_json_encode(['source'=>$id,'requests'=>$r['requests'],'errors'=>$r['errors'],'controlled_not_automatic'=>true]);}catch(CDRA_Error $e){echo wp_json_encode(['source'=>$id,'deferred'=>$e->getMessage()]);}"
  result=m.wp('eval',code,check=False);need(result.returncode==0,'Due feed recovery process failed; raw output suppressed');recovered=json.loads(result.stdout)
  if recovered.get('skipped') or recovered.get('deferred'):break
  print('CONTROLLED DUE RECOVERY: '+json.dumps(recovered),flush=True)
 phase='controlled newly verified source ingestion'
 ids=json.loads((B/'new-sources.json').read_text());source_results=[]
 for id in ids:
  code="$id="+json.dumps(id)+";$s=new CDRA_Store();if(!$s->get('discovery_enabled:'.$id,false)){$u=get_user_by('login','cyberdat_staging_admin');cdra_need($u&&user_can($u,'manage_options'),'owner_admin_missing');$s->put('discovery_enabled:'.$id,true);(new CDRA_Discovery_Store($s))->audit('source_enable',0,[$id=>false],[$id=>true,'basis'=>'owner-approved verified endpoint'],(int)$u->ID);}$h=$s->get('health:'.$id,[]);try{if(!$s->count($id)||empty($h['last_success'])){(new CDRA_Service($s))->sync($id);}}catch(CDRA_Error $e){echo wp_json_encode(['id'=>$id,'deferred'=>$e->getMessage()]);return;}$h=$s->get('health:'.$id,[]);if(!$s->count($id)&&in_array($h['last_error']??'',['http_401','http_403','http_404'],true)){$s->put('discovery_enabled:'.$id,false);}echo wp_json_encode(['id'=>$id,'count'=>$s->count($id),'last_success'=>$h['last_success']??null,'error'=>$h['last_error']??'']);"
  deadline=time.monotonic()+150
  while True:
   result=m.wp('eval',code,check=False);need(result.returncode==0,'New-source process failed: '+id+'; raw output suppressed');row=json.loads(result.stdout)
   if row.get('deferred')=='ingestion_locked' and time.monotonic()<deadline:time.sleep(5);continue
   break
  source_results.append(row);print('SOURCE: '+json.dumps(row),flush=True);time.sleep(3)
 phase='single consolidated protection and SQL smoke test'
 proof=job('stabilize-proof.php');need(proof['duplicate_source_ids']==0 and proof['dashboard_sql_match'],'Duplicate/Dashboard SQL regression');need(all(proof['streams'].get(s,0)>0 for s in ['news','research','papers']),'Required discovery stream empty')
 after_checkpoint=proof['channels']['nvd']['checkpoint'];need(before_checkpoint is None or after_checkpoint is not None and after_checkpoint>=before_checkpoint,'NVD checkpoint moved backwards')
 for path,marker in [('/',b'data-pulse-periods'),('/threat-intelligence/',b'data-analytics-dialog'),('/tools/',b'Coming Soon')]:
  valid=False
  for attempt in range(12):
   status,headers,body=m.fetch(path,basic);valid=status==200 and marker in body and 'noindex' in headers.get('X-Robots-Tag','')
   if valid:break
   time.sleep(5)
  need(valid and m.fetch(path)[0]==401,'Protected route smoke failed: '+path)
 m.admin_check(basic)
 need(protected==m.guards() and timers==m.timer_fingerprints() and other_hashes==others() and theme_hashes==theme(),'Non-target code/config/theme/timer changed')
 posts_after=json.loads(m.wp('eval',"global $wpdb;echo wp_json_encode((int)$wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->posts}\"));").stdout);need(posts_before==posts_after,'WordPress post count changed during controlled verification')
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production HTTPS health failed')
 for path,values in m.log_indicators().items():
  for kind,n in values.items():need(n<=logs.get(path,{}).get(kind,0),'New checked PHP/Nginx '+kind+' indicator')
 resources={'before':resources_before,'after':{'load':os.getloadavg(),'available_kib':next(int(l.split()[1]) for l in P('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:'))},'seconds':round(time.monotonic()-started,1),'db_bytes':proof['db_bytes']}
 evidence={'proof':proof,'quality':quality,'correlation':correlation,'sources':source_results,'resources':resources};(backup/'evidence.json').write_text(json.dumps(evidence));(backup/'COMPLETE').write_text('COMPLETE\n')
 print('EVIDENCE: '+json.dumps(evidence));print('COMMIT: '+(B/'COMMIT').read_text().strip());print('BACKUP: '+str(backup));print('PASS: bounded stabilization; fetch/collector code, theme, Analytics, protected configuration and timer frequencies unchanged; no post publication')
 print('UNVERIFIED: next real cycle of newly added sources and long-duration load; blocked/unsupported channels not counted as connected')
if __name__=='__main__':
 try:main()
 except BaseException as e:
  print('BLOCKED: phase='+phase+'; type='+type(e).__name__)
  if isinstance(e,RuntimeError):print('Reason: '+str(e))
  print('Retain backup and partial state. No raw credentials/API bodies, checkpoint reset, historical mass import or destructive cleanup. Use --resume BACKUP, not blind --apply.');sys.exit(1)
