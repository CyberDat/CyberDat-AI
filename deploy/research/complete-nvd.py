#!/usr/bin/env python3
"""Owner-run staging-only update. No original staging installer, DNS/TLS or production writes."""
import time, re, argparse,base64,datetime,fcntl,getpass,hashlib,http.cookiejar,json,os,pathlib,pwd,shutil,subprocess,sys,tarfile,urllib.error,urllib.parse,urllib.request
P=pathlib.Path;B=P(__file__).resolve().parent
ROOT=P('/var/www/cyberdat-staging/public');THEME=ROOT/'wp-content/themes/cyberdat';PLUGIN=ROOT/'wp-content/plugins/cyberdat-research'
RUNTIME=P('/var/lib/cyberdat-staging/research');CONTROL=P('/etc/cyberdat-staging');TOOLS=P('/opt/cyberdat-research');BACKUPS=P('/var/backups/cyberdat-staging');HOST='https://staging.cyberdat.eu'
phase='preflight'

def need(ok,message):
 if not ok:raise RuntimeError(message)
def sha(p):return hashlib.sha256(P(p).read_bytes()).hexdigest()
def run(args,data=None,timeout=240,env=None,check=True):
 result=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,env=env)
 if check:need(result.returncode==0,'Command failed: '+P(args[0]).name+' exit='+str(result.returncode))
 return result

def wp(*args,check=True,data=None):
 env=dict(os.environ,HOME='/var/lib/cyberdat-staging',WP_CLI_CONFIG_PATH='/var/lib/cyberdat-staging/cli.yml')
 basedir='/var/www/cyberdat-staging:/var/lib/cyberdat-staging:/var/log/cyberdat-staging:/run/mysqld:/etc/ssl/certs:/opt/cyberdat-tools:/etc/cyberdat-staging'
 return run(['/usr/sbin/runuser','-u','cyberdat-staging','--','/usr/bin/php8.4','-d','memory_limit=192M','-d','disable_functions=mail','-d','sendmail_path=/bin/false','-d','opcache.enable_cli=0','-d','sys_temp_dir=/var/lib/cyberdat-staging/tmp','-d','open_basedir='+basedir,'/opt/cyberdat-tools/wp-cli.phar','--path='+str(ROOT),'--no-color','--skip-packages',*args],env=env,check=check,data=data)

def state():return json.loads(wp('eval',"echo wp_json_encode([wp_get_environment_type(),DB_NAME,get_option('home'),get_stylesheet(),get_option('blog_public'),get_option('permalink_structure')]);").stdout)
def guards():
 paths=['/etc/nginx/sites-available/cyberdat','/etc/php/8.4/fpm/pool.d/www.conf','/var/www/cyberdat/public/wp-config.php','/etc/nginx/sites-available/cyberdat-staging','/etc/php/8.4/fpm/pool.d/cyberdat-staging.conf',str(ROOT/'wp-config.php'),str(ROOT/'wp-content/mu-plugins/cyberdat-staging-safety.php'),'/etc/cron.d/cyberdat-staging']
 return {p:sha(p) for p in paths}

def tree(root,files):
 need(root.resolve()==root,'Unsafe release path')
 actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()};need(actual==set(files),'Release file-set conflict')
 for name,info in files.items():
  p=root/name;need(not p.is_symlink() and p.resolve().is_relative_to(root) and sha(p)==info['sha256'],'Release checksum mismatch')
 need(not any(p.is_symlink() for p in root.rglob('*')),'Release symlink rejected')

class Redirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  need(newurl.startswith(HOST+'/') and urllib.parse.urlsplit(newurl).netloc=='staging.cyberdat.eu','External redirect blocked')
  return super().redirect_request(req,fp,code,msg,headers,newurl)

def fetch(path,password=None,opener=None,data=None):
 headers={'User-Agent':'CyberDat-Research-Deployment/0.8.1'}
 if password is not None:headers['Authorization']='Basic '+base64.b64encode(('cyberdat_staging_admin:'+password).encode()).decode()
 request=urllib.request.Request(HOST+path,headers=headers,data=data)
 try:
  with (opener or urllib.request.build_opener(Redirect())).open(request,timeout=40) as result:return result.status,result.headers,result.read(4000000)
 except urllib.error.HTTPError as error:return error.code,error.headers,error.read(4000000)

def owned_copy(source,target,account):
 shutil.copytree(source,target)
 for p in [target,*target.rglob('*')]:os.chown(p,account.pw_uid,account.pw_gid);p.chmod(0o755 if p.is_dir() else 0o644)

def database_backup(path):
 partial=path.with_suffix(path.suffix+'.partial')
 with partial.open('xb') as output:
  dump=subprocess.Popen(['/usr/bin/mariadb-dump','--no-defaults','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--skip-password','--single-transaction','--quick','--routines','--triggers','--events','--hex-blob','--default-character-set=utf8mb4','--databases','cyberdat_staging'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
  compress=subprocess.Popen(['/usr/bin/gzip','-c'],stdin=dump.stdout,stdout=output,stderr=subprocess.DEVNULL);dump.stdout.close();a=compress.wait();b=dump.wait();need(a==0 and b==0,'Staging backup pipeline failed')
 need(partial.stat().st_size>0,'Empty staging backup');partial.chmod(0o600);os.rename(partial,path)

def evidence():
 code=(B/'nvd-proof.php').read_text();need(code.startswith('<?php'),'Invalid evidence code');return json.loads(wp('eval',code[5:]).stdout)

def systemctl(*args,check=True):return run(['/usr/bin/systemctl',*args],check=check)
def timer_states():
 return {n:systemctl('is-active','cyberdat-research-'+n+'.timer',check=False).returncode==0 for n in ['nvd','dispatch']}
def atomic_copy(source,target):
 need(target.resolve()==target and target.is_relative_to(PLUGIN),'Unsafe plugin target');temporary=target.with_name(target.name+'.nvd-partial');need(not temporary.exists(),'Unexpected temporary file');shutil.copyfile(source,temporary);a=pwd.getpwnam('cyberdat-staging');os.chown(temporary,a.pw_uid,a.pw_gid);temporary.chmod(0o644);os.replace(temporary,target)
def main():
 global phase
 parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');parser.add_argument('--resume',type=P);parser.add_argument('--rollback-code',type=P);args=parser.parse_args();need(sum([args.apply,bool(args.resume),bool(args.rollback_code)])==1 and os.geteuid()==0,'Choose one action using owner sudo');os.umask(0o077)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  expected,name=line.split(maxsplit=1);p=B/name;need(p.resolve().is_relative_to(B) and not p.is_symlink() and sha(p)==expected,'Bundle checksum mismatch')
 need(all(timer_states().values()),'NVD and dispatcher timers must already be active');need('OnCalendar=*-*-* *:00/5:00 UTC' in P('/etc/systemd/system/cyberdat-research-dispatch.timer').read_text(),'Unexpected dispatcher interval');identity=state();need(identity[:4]==['staging','cyberdat_staging',HOST,'cyberdat'] and str(identity[4])=='0','Wrong staging identity');protected=guards();targets=json.loads((B/'patch.json').read_text())
 need(all((ROOT/e['target']).resolve()==ROOT/e['target'] and (ROOT/e['target']).is_relative_to(PLUGIN) for e in targets),'Invalid target')
 backup=args.resume or args.rollback_code;old_timers=timer_states()
 if backup:
  backup=backup.resolve();need(backup.parent==BACKUPS and backup.name.startswith('nvd-sync-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe existing backup')
  saved=json.loads((backup/'state.json').read_text());need(sha(backup/'staging.sql.gz')==saved['sql_sha256'] and sha(backup/'plugin.tar.gz')==saved['plugin_sha256'],'Backup integrity failed');need(saved['commit']==(B/'COMMIT').read_text().strip(),'Backup release mismatch')
 for e in targets:need(sha(ROOT/e['target'])==e['after' if backup else 'before'],'Installed code conflict; no blind reapply')
 for e in targets:
  need(sha(B/e['candidate'])==e['after'],'Candidate checksum mismatch');run(['/usr/bin/php8.4','-l',str(B/e['candidate'])])
 basic=None
 if not args.rollback_code:
  basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(bool(basic),'Basic Auth required');need(fetch('/',basic)[0]==200 and fetch('/')[0]==401,'Staging HTTP/auth preflight failed')
 paused=False
 try:
  phase='quiesce staging NVD/dispatch only';systemctl('stop','cyberdat-research-nvd.timer','cyberdat-research-dispatch.timer');paused=True
  for name in ['nvd','dispatch']:systemctl('stop','cyberdat-research@'+name+'.service')
  for name in ['kev','cisa-advisories','cert-eu','msrc']:need(systemctl('is-active','cyberdat-research@'+name+'.service',check=False).returncode!=0,'Another Research source is active; retry later without reinstall')
  if args.rollback_code:
   phase='explicit code-only staging rollback'
   for i,e in enumerate(targets):need(sha(backup/str(i))==e['before'],'Saved file checksum mismatch')
   for i,e in enumerate(targets):atomic_copy(backup/str(i),ROOT/e['target'])
   need(protected==guards(),'Protected state changed');print('PASS: prior three plugin files restored; database and accumulated evidence retained; no DB restore');return
  if not backup:
   phase='private staging database and plugin backup before patch'
   need(BACKUPS.is_dir() and BACKUPS.stat().st_uid==0 and BACKUPS.stat().st_mode&0o077==0,'Unsafe backup parent');need(shutil.disk_usage(BACKUPS).free>1024**3,'Less than 1 GiB free')
   stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');backup=BACKUPS/('nvd-sync-'+stamp);backup.mkdir(mode=0o700)
   database_backup(backup/'staging.sql.gz')
   with tarfile.open(backup/'plugin.tar.gz','w:gz') as archive:archive.add(PLUGIN,arcname='cyberdat-research')
   for i,e in enumerate(targets):shutil.copyfile(ROOT/e['target'],backup/str(i))
   saved={'commit':(B/'COMMIT').read_text().strip(),'sql_sha256':sha(backup/'staging.sql.gz'),'plugin_sha256':sha(backup/'plugin.tar.gz'),'timers':old_timers}
   (backup/'state.json').write_text(json.dumps(saved));print('BACKUP: '+str(backup),flush=True)
   for e in targets:atomic_copy(B/e['candidate'],ROOT/e['target'])
   print('PASS: three pinned plugin files patched; no server configuration or production writes',flush=True)
  phase='offline temporary-table integration tests'
  wp('cyberdat-research','test');print('PASS: fixed-fixture MariaDB tests in temporary tables',flush=True)
  phase='bounded continuation of existing NVD window'
  initial=json.loads(wp('cyberdat-research','status').stdout);window=initial.get('window')
  if not window:
   need(initial.get('last_completed_window') is not None,'No current window or audited completed window; stop without creating historical import')
   target_end=initial['last_completed_window']['end']
  else:target_end=window['end']
  deadline=time.monotonic()+1500
  for batch in range(40):
   status=json.loads(wp('cyberdat-research','status').stdout);done=status.get('last_completed_window')
   if done and done['end']==target_end and not status.get('window'):break
   need(time.monotonic()<deadline,'Bounded session expired; checkpoint retained')
   h=status.get('sources',{}).get('nvd',{});h=h if isinstance(h,dict) else {}
   if h.get('last_error') and h.get('next_due',0)>time.time():
    delay=h['next_due']-time.time();need(time.monotonic()+delay+60<deadline,'API backoff exceeds bounded session; cursor retained for scheduler/resume')
    print('BACKOFF: '+json.dumps({'code':h['last_error'],'until_utc':datetime.datetime.fromtimestamp(h['next_due'],datetime.timezone.utc).isoformat()}),flush=True)
    while h['next_due']>time.time():time.sleep(min(30,h['next_due']-time.time()))
   wait=max(0,31-(time.time()-h.get('last_attempt',0)))
   if wait:time.sleep(min(wait+1,32))
   response=wp('cyberdat-research','sync','--source=nvd','--manual',check=False)
   try:result=json.loads(response.stdout)
   except (ValueError,UnicodeError):raise RuntimeError('NVD worker failed without structured status; cursor retained') from None
   if response.returncode!=0:
    codes=list(result.get('errors',{}).values());recoverable={'nvd_pagination_changed','nvd_pagination_overlap','http_429','http_500','http_502','http_503','http_504','transport','rate_budget'}
    need(codes and all(code in recoverable for code in codes),'Non-transient NVD failure; last-good data and cursor retained')
    print('RETRY PENDING: '+json.dumps(codes),flush=True);continue
   w=result.get('window');print('BATCH: '+json.dumps({'batch':batch+1,'indexed_cves':result['nvd'],'processed':w.get('index') if w else None,'total':w.get('total') if w else None,'checkpoint':result.get('checkpoint'),'requests':result.get('requests')}),flush=True)
  else:raise RuntimeError('Maximum bounded batches reached; cursor retained')
  phase='complete window and Dashboard SQL proof'
  report=evidence();need(report['last_completed'] and report['last_completed']['end']==target_end and report['checkpoint_utc']==target_end and report['window'] is None,'Target window not complete')
  wp('cyberdat-research','verify')
  repeat=json.loads(wp('cyberdat-research','sync','--source=nvd','--scheduled').stdout);need(repeat['requests']==0,'Unexpected immediate repeated fetch')
  after=evidence();need(after==report,'No-op repeated run changed evidence')
  code,headers,body=fetch('/',basic);text=body.decode('utf-8','replace');need(code==200 and 'noindex' in headers.get('X-Robots-Tag',''),'Homepage/noindex failed')
  need('NVD Window: Complete' in text and 'Indexed CVEs: '+str(report['indexed_cves']) in text and 'data-nvd-loaded="'+str(report['kev_matched_chart'])+'"' in text and 'data-nvd-indexed="'+str(report['indexed_cves'])+'"' in text,'HTML and SQL counts/completion mismatch')
  need(fetch('/')[0]==401 and fetch('/tools/',basic)[0]==200,'Auth/Tools regression');need(protected==guards() and identity==state(),'Protected state changed')
  with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production HTTPS failed')
  (backup/'evidence.json').write_text(json.dumps(report));(backup/'COMPLETE').write_text('COMPLETE\n')
  print('PASS: current NVD window completed; ledger unique/contiguous, every ID in DB, CVSS projection equals SQL; immediate repeated scheduled call requests=0')
  print('EVIDENCE: '+json.dumps(report));print('COMMIT: '+(B/'COMMIT').read_text().strip());print('PASS: production HTTPS 200; protected hashes unchanged; staging Basic Auth/noindex preserved')
  print('UNVERIFIED: next real scheduled recurrence not yet observed; complete historical NVD intentionally not imported')
 finally:
  if paused:
   for name,active in old_timers.items():
    if active:systemctl('start','cyberdat-research-'+name+'.timer',check=False)
   restored=timer_states();print('TIMERS: '+json.dumps(restored),flush=True);need(restored==old_timers,'Timer restoration failed; review staging NVD/dispatch timer status')
  if backup:
   print('BACKUP: '+str(backup));print('RESUME ONLY IF BLOCKED: sudo /usr/bin/python3 -I '+str(B/'complete-nvd.py')+' --resume '+str(backup));print('ROLLBACK CODE ONLY: sudo /usr/bin/python3 -I '+str(B/'complete-nvd.py')+' --rollback-code '+str(backup))
if __name__=='__main__':
 try:main()
 except BaseException as error:
  print('BLOCKED: phase='+phase);print('Error type: '+type(error).__name__)
  if isinstance(error,RuntimeError):print('Reason: '+str(error))
  print('No raw credentials/API bodies printed; any backup and committed cursor retained. No reinstall or automatic destructive rollback.');sys.exit(1)
