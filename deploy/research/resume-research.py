#!/usr/bin/env python3
"""Owner-run staging-only update. No original staging installer, DNS/TLS or production writes."""
import argparse,base64,datetime,fcntl,getpass,hashlib,http.cookiejar,json,os,pathlib,pwd,shutil,subprocess,sys,tarfile,urllib.error,urllib.parse,urllib.request
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

def wp(*args,check=True):
 env=dict(os.environ,HOME='/var/lib/cyberdat-staging',WP_CLI_CONFIG_PATH='/var/lib/cyberdat-staging/cli.yml')
 basedir='/var/www/cyberdat-staging:/var/lib/cyberdat-staging:/var/log/cyberdat-staging:/run/mysqld:/etc/ssl/certs:/opt/cyberdat-tools:/etc/cyberdat-staging'
 return run(['/usr/sbin/runuser','-u','cyberdat-staging','--','/usr/bin/php8.4','-d','memory_limit=192M','-d','disable_functions=mail','-d','sendmail_path=/bin/false','-d','opcache.enable_cli=0','-d','sys_temp_dir=/var/lib/cyberdat-staging/tmp','-d','open_basedir='+basedir,'/opt/cyberdat-tools/wp-cli.phar','--path='+str(ROOT),'--no-color','--skip-packages',*args],env=env,check=check)

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

def rollback(backup):
 global phase
 phase='explicit staging-only rollback';backup=backup.resolve();need(backup.parent==BACKUPS and backup.name.startswith('research-0.8.1-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe rollback path')
 metadata=json.loads((backup/'state.json').read_text());need(sha(backup/'theme.tar.gz')==metadata['theme_archive_sha256'],'Rollback theme checksum mismatch')
 for name in ['kev','nvd','cisa-advisories','cert-eu','msrc','dispatch']:
  run(['/usr/bin/systemctl','disable','--now','cyberdat-research-'+name+'.timer'],check=False)
  run(['/usr/bin/systemctl','stop','cyberdat-research@'+name+'.service'],check=False)
 if PLUGIN.exists():wp('plugin','deactivate','cyberdat-research')
 if (CONTROL/'research.json').is_file():(CONTROL/'research.json').write_text(json.dumps({'enabled':False,'host':'staging.cyberdat.eu'})+'\n');(CONTROL/'research.json').chmod(0o640)
 temp=ROOT.parent/('restore-'+backup.name);need(not temp.exists(),'Rollback temporary path exists');temp.mkdir(mode=0o700)
 with tarfile.open(backup/'theme.tar.gz','r:gz') as archive:
  for entry in archive.getmembers():need(not entry.issym() and not entry.islnk() and (entry.isfile() or entry.isdir()) and '..' not in P(entry.name).parts and (entry.name=='cyberdat' or entry.name.startswith('cyberdat/')),'Unsafe rollback archive')
  archive.extractall(temp,filter='data')
 tree(temp/'cyberdat',metadata['previous']['files']);account=pwd.getpwnam('cyberdat-staging')
 for p in [temp/'cyberdat',*(temp/'cyberdat').rglob('*')]:os.chown(p,account.pw_uid,account.pw_gid);p.chmod(0o755 if p.is_dir() else 0o644)
 retained=ROOT.parent/('retained-'+backup.name);need(not retained.exists(),'Rollback retained path exists');retained.mkdir(mode=0o700);os.rename(THEME,retained/'cyberdat')
 try:os.rename(temp/'cyberdat',THEME)
 except BaseException:os.rename(retained/'cyberdat',THEME);raise
 print('PASS: research schedules stopped, plugin deactivated, old theme restored; research tables/evidence and SQL snapshot retained; production untouched')


def source_health(status,name):
 value=status.get('sources',{}).get(name,{})
 if value==[]:value={}
 need(isinstance(value,dict),'Invalid source health structure')
 return value

def code_directory_permissions():
 need(TOOLS.resolve()==TOOLS and TOOLS.is_dir() and not TOOLS.is_symlink(),'Unsafe worker code directory')
 TOOLS.chmod(0o755)

def main():
 global phase
 parser=argparse.ArgumentParser();parser.add_argument('--resume',action='store_true');args=parser.parse_args();need(args.resume and os.geteuid()==0,'Requires owner sudo and --resume');os.umask(0o077)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  expected,name=line.split(maxsplit=1);p=B/name;need(p.resolve().is_relative_to(B) and not p.is_symlink() and sha(p)==expected,'Private bundle checksum mismatch')
 before=state();need(before[:4]==['staging','cyberdat_staging',HOST,'cyberdat'] and str(before[4])=='0' and before[5]=='/%postname%/','Staging identity mismatch')
 need(ROOT.resolve()==ROOT and THEME.resolve()==THEME and PLUGIN.resolve()==PLUGIN and TOOLS.resolve()==TOOLS,'Unsafe staging paths')
 base=json.loads((B/'resume-base.json').read_text());source=json.loads((B/'source.json').read_text());backup=P(base['backup'])
 need(backup.parent==BACKUPS and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe original backup')
 metadata=json.loads((backup/'state.json').read_text());need(metadata['source_commit']==base['commit'],'Backup source mismatch')
 need(sha(backup/'theme.tar.gz')==metadata['theme_archive_sha256'] and sha(backup/'staging.sql.gz')==metadata['database_sha256'],'Original backup checksum mismatch')
 protected=guards();need(protected==metadata['protected_config_hashes'],'Protected configuration changed since interrupted deployment')
 tree(THEME,source['theme']);tree(B/'theme',source['theme']);tree(B/'plugin',source['plugin'])
 current={str(p.relative_to(PLUGIN)) for p in PLUGIN.rglob('*') if p.is_file()};need(current==set(base['plugin']),'Plugin file-set conflict')
 for name,info in base['plugin'].items():
  p=PLUGIN/name;need(not p.is_symlink() and sha(p) in {info['sha256'],source['plugin'][name]['sha256']},'Unexpected installed plugin edit')
 need(TOOLS.stat().st_uid==0 and sha(TOOLS/'run.sh')==sha(B/'run.sh'),'Unexpected worker wrapper')
 for name in ['kev','nvd','cisa-advisories','cert-eu','msrc','dispatch']:
  need(run(['/usr/bin/systemctl','is-active','cyberdat-research@'+name+'.service'],check=False).stdout.strip()!=b'active','Research worker is already running')
  need(run(['/usr/bin/systemctl','is-active','cyberdat-research-'+name+'.timer'],check=False).stdout.strip()!=b'active','Research schedule already active; review before resume')
 need(fetch('/')[0]==401,'Staging authentication missing')
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and fetch('/',basic)[0]==200,'Basic Auth verification failed')
 admin=getpass.getpass('EXISTING staging WordPress password (hidden): ');need(bool(admin),'WordPress verification password required')
 phase='minimal worker and advisory-parser repair'
 code_directory_permissions()
 account=pwd.getpwnam('cyberdat-staging')
 for name,info in source['plugin'].items():
  target=PLUGIN/name
  if sha(target)==info['sha256']:continue
  saved=backup/('resume-before-'+name.replace('/','__'))
  if not saved.exists():shutil.copyfile(target,saved);saved.chmod(0o600)
  temporary=target.with_name(target.name+'.resume-partial');need(not temporary.exists(),'Unexpected temporary plugin patch')
  shutil.copyfile(B/'plugin'/name,temporary);os.chown(temporary,account.pw_uid,account.pw_gid);temporary.chmod(0o644);os.replace(temporary,target)
 tree(PLUGIN,source['plugin'])
 result=run(['/usr/sbin/runuser','-u','cyberdat-staging','--','/bin/sh','-n',str(TOOLS/'run.sh')]);need(TOOLS.stat().st_mode&0o777==0o755,'Worker directory mode repair failed')
 print('PASS: existing backup verified; pinned minimal plugin patches; no reinstall, database reset or credential change')
 phase='resume controlled official-source batch'
 successful=[]
 for name in ['kev','nvd','cisa-advisories','cert-eu','msrc']:
  status=json.loads(wp('cyberdat-research','status').stdout);health=source_health(status,name)
  if health.get('last_success') and not health.get('last_error') and datetime.datetime.now(datetime.timezone.utc).timestamp()-health['last_success']<=(14400 if name=='nvd' else 28800):
   successful.append(name);print('PASS: '+name+' already synchronized; no repeat download');continue
  remaining=max(0,health.get('next_due',0)-datetime.datetime.now(datetime.timezone.utc).timestamp())
  if name in ['cert-eu','cisa-advisories','msrc'] and health.get('last_error') in ['invalid_url','response_size'] and 0<remaining<=300:
   import time
   while remaining>0:
    print('WAIT: preserving '+name+' advisory-error backoff; seconds='+str(int(remaining)),flush=True);time.sleep(min(30,remaining));remaining=max(0,health.get('next_due',0)-datetime.datetime.now(datetime.timezone.utc).timestamp())
  if health.get('last_error') and health.get('next_due',0)>datetime.datetime.now(datetime.timezone.utc).timestamp():
   print('WARNING: '+name+' backoff retained; error='+health['last_error']);need(name not in ['kev','nvd'],'Required source backoff active; no retry performed');continue
  result=run(['/usr/bin/systemctl','start','cyberdat-research@'+name+'.service'],check=False,timeout=200)
  status=json.loads(wp('cyberdat-research','status').stdout);health=source_health(status,name)
  ok=result.returncode==0 and bool(health.get('last_success')) and not health.get('last_error')
  if not ok:
   details=run(['/usr/bin/systemctl','show','cyberdat-research@'+name+'.service','--property=Result,ExecMainStatus,ActiveState','--no-pager'],check=False).stdout.decode()
   for line in details.splitlines():
    if line.startswith(('Result=','ExecMainStatus=','ActiveState=')):print('WORKER '+name+' '+line)
  print(('PASS: ' if ok else 'WARNING: ')+name+' controlled sync; '+('verified' if ok else 'error='+health.get('last_error','worker_failed_before_health')))
  if ok:successful.append(name)
  need(name not in ['kev','nvd'] or ok,'Required source failed; schedules remain disabled')
 need(any(name in successful for name in ['cisa-advisories','cert-eu','msrc']),'No advisory source succeeded; schedules remain disabled')
 wp('cyberdat-research','enable')
 phase='one consolidated functional/security smoke test'
 wp('cyberdat-research','verify')
 for path in ['/','/tools/','/news/','/analysis/','/guides/','/learning/','/topics/','/wp-login.php','/wp-json/wp/v2/editorial-formats']:
  need(fetch(path)[0]==401,'Anonymous staging bypass')
  code,headers,body=fetch(path,basic);need(code==200 and 'noindex' in headers.get('X-Robots-Tag',''),'Staging HTTP/noindex failure')
  if path=='/':need(b'data-research-status' in body and b'Indexed CVEs:' in body,'Dashboard is not using unified provider')
 print('PASS: dashboard, Tools, archives, login, REST 200 with auth; anonymous 401; noindex')
 for item in json.loads((B/'theme/inc/tools-catalog.json').read_text()):
  if item.get('status')!='available':need(fetch(item['url'],basic)[0]==404,'Unfinished tool route changed')
 jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),Redirect());fetch('/wp-login.php',basic,opener)
 form=urllib.parse.urlencode({'log':'cyberdat_staging_admin','pwd':admin,'wp-submit':'Log In','redirect_to':HOST+'/wp-admin/','testcookie':'1'}).encode();fetch('/wp-login.php',basic,opener,form)
 need(any(c.name.startswith('wordpress_logged_in_') for c in jar),'Existing administrator login failed')
 code,headers,body=fetch('/wp-admin/admin.php?page=cyberdat-research',basic,opener);need(code==200 and b'Research Queue' in body and b'Source health' in body,'Editorial queue UI failed')
 invalid=urllib.parse.urlencode({'action':'cdra_save','item_id':'1','status':'approved_for_draft','priority':'','content_hash':'a'*64,'_wpnonce':'invalid'}).encode();need(fetch('/wp-admin/admin-post.php',basic,opener,invalid)[0] in (400,403),'Invalid review nonce accepted')
 print('PASS: administrator Research Queue, source health, filters UI; invalid status-action nonce rejected; no post publication')
 need(protected==guards() and before==state(),'Protected configuration or base WordPress state changed');tree(THEME,source['theme']);tree(PLUGIN,source['plugin'])
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production HTTPS failure')
 phase='enable only successfully verified source schedules'
 for name in successful+['dispatch']:
  timer='cyberdat-research-'+name+'.timer';run(['/usr/bin/systemctl','enable','--now',timer]);need(run(['/usr/bin/systemctl','is-active',timer]).stdout.strip()==b'active','Timer activation failed')
 status=json.loads(wp('cyberdat-research','status').stdout)
 (backup/'COMPLETE').write_text('COMPLETE\n')
 print('PASS: production HTTPS 200 and protected fingerprints unchanged; source schedules active')
 print('COMMIT: '+source['commit']);print('COUNTS: '+json.dumps({k:status[k] for k in ['kev','nvd','queue','coverage_origin','checkpoint','window','backfill','complete_nvd']}))
 for name,h in status['sources'].items():
  h=source_health(status,name)
  at=h.get('last_success',0);fresh=at and datetime.datetime.now(datetime.timezone.utc).timestamp()-at<=(14400 if name=='nvd' else 28800)
  print('SOURCE: '+name+' '+('Sync Error' if h.get('last_error') else 'Fresh' if fresh else 'Stale')+' last_success_utc='+(datetime.datetime.fromtimestamp(at,datetime.timezone.utc).isoformat() if at else 'never')+' error='+h.get('last_error',''))
 print('TIMERS: '+','.join(successful+['dispatch']));print('URL: '+HOST);print('QUEUE: '+HOST+'/wp-admin/admin.php?page=cyberdat-research')
 print('ROLLBACK: sudo /usr/bin/python3 -I '+str(B/'update-research.py')+' --rollback '+str(backup))
 print('UNVERIFIED: long-term scheduled recurrence, complete historical NVD (not imported), browser mobile/Gutenberg; no Content/Social/SEO Agent or LLM calls')
 if len(successful)<5:print('WARNING: unavailable advisory sources remain Sync Error with schedules disabled; do not mark the entire stage PASS')

if __name__=='__main__':
 try:main()
 except BaseException as error:
  print('BLOCKED: phase='+phase);print('Error type: '+type(error).__name__)
  if isinstance(error,RuntimeError):print('Reason: '+str(error))
  print('No raw logs, credentials or API responses printed. Any partial staging state/snapshot retained; do not rerun blindly.');sys.exit(1)
