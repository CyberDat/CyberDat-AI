#!/usr/bin/env python3
# CYBERDAT_TOOLS_RELEASE_1_LEGACY_INTERLOCK
from pathlib import Path as _ToolsLegacyPath
if (_ToolsLegacyPath('/var/www/cyberdat-staging/public/wp-content/themes/cyberdat') / 'inc/tool-security.php').exists():
 raise SystemExit('BLOCKED: Tools Release 1 installed; legacy theme/SQL deploy or rollback requires a compatible package; do not bypass this interlock')
import os as _tools_os, stat as _tools_stat, fcntl as _tools_fcntl
_tools_release_fd = _tools_os.open('/run/lock/cyberdat-staging-tools-release-1.lock', _tools_os.O_RDWR | _tools_os.O_CREAT | _tools_os.O_NOFOLLOW, 0o600)
_tools_lock_stat = _tools_os.fstat(_tools_release_fd)
if not (_tools_stat.S_ISREG(_tools_lock_stat.st_mode) and _tools_lock_stat.st_uid == 0 and _tools_stat.S_IMODE(_tools_lock_stat.st_mode) == 0o600):
 raise SystemExit('BLOCKED: unsafe Tools release lock')
try:
 _tools_fcntl.flock(_tools_release_fd, _tools_fcntl.LOCK_EX | _tools_fcntl.LOCK_NB)
except BlockingIOError:
 raise SystemExit('BLOCKED: Tools deployment or another legacy deployment is running')
if (_ToolsLegacyPath('/var/www/cyberdat-staging/public/wp-content/themes/cyberdat') / 'inc/tool-security.php').exists():
 raise SystemExit('BLOCKED: Tools installed while waiting for release lock')
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
 parser=argparse.ArgumentParser();parser.add_argument('--finish-checks',action='store_true');args=parser.parse_args();need(args.finish_checks and os.geteuid()==0,'Requires owner sudo and --finish-checks');os.umask(0o077)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  expected,name=line.split(maxsplit=1);p=B/name;need(p.resolve().is_relative_to(B) and not p.is_symlink() and sha(p)==expected,'Private bundle checksum mismatch')
 before=state();need(before[:4]==['staging','cyberdat_staging',HOST,'cyberdat'] and str(before[4])=='0' and before[5]=='/%postname%/','Staging identity mismatch')
 source=json.loads((B/'source.json').read_text());base=json.loads((B/'resume-base.json').read_text());backup=P(base['backup']);need(backup.parent==BACKUPS and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe backup directory')
 metadata=json.loads((backup/'state.json').read_text());need(sha(backup/'theme.tar.gz')==metadata['theme_archive_sha256'] and sha(backup/'staging.sql.gz')==metadata['database_sha256'],'Existing backup checksum mismatch')
 protected=guards();need(protected==metadata['protected_config_hashes'],'Protected configuration changed');tree(THEME,source['theme']);tree(PLUGIN,source['plugin'])
 status=json.loads(wp('cyberdat-research','status').stdout);successful=[]
 for name in ['kev','nvd','cisa-advisories','cert-eu','msrc']:
  health=source_health(status,name);need(health.get('last_success') and not health.get('last_error'),'Source requires separate review: '+name);successful.append(name)
 need(status.get('live_enabled') is True,'Dashboard provider is not enabled')
 print('PASS: existing backup, pinned code, five successful sources and enabled data provider; no ingestion or reinstall')
 need(fetch('/')[0]==401,'Staging authentication missing')
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and fetch('/',basic)[0]==200,'Basic Auth verification failed')
 phase='read-only verification of existing WordPress administrator password'
 admin=getpass.getpass('EXISTING staging WORDPRESS password (hidden; not SSH or Basic Auth): ');need(bool(admin),'WordPress password required')
 code="$p=json_decode(stream_get_contents(STDIN),true,8,JSON_THROW_ON_ERROR);$u=get_user_by('login','cyberdat_staging_admin');echo wp_json_encode(['exists'=>(bool)$u,'password_matches'=>$u?wp_check_password($p['password'],$u->user_pass,$u->ID):false,'admin'=>$u?user_can($u,'manage_options'):false,'cookie_name'=>LOGGED_IN_COOKIE]);"
 auth=json.loads(wp('eval',code,data=json.dumps({'password':admin}).encode()).stdout)
 need(auth.get('exists') and auth.get('admin'),'Expected staging administrator missing or lacks capability; no reset performed')
 need(auth.get('password_matches') is True,'Entered WORDPRESS password does not match the existing staging administrator. No HTTP login attempted; no password reset. Enter the existing WordPress password on a later run.')
 print('PASS: entered password matches existing staging administrator; password/hash never printed or changed')
 phase='single normal HTTPS administrator login and cookie diagnostics'
 jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),Redirect())
 fetch('/wp-login.php',basic,opener)
 test_cookie=any(c.name=='wordpress_test_cookie' for c in jar)
 form=urllib.parse.urlencode({'log':'cyberdat_staging_admin','pwd':admin,'wp-submit':'Log In','redirect_to':HOST+'/wp-admin/','testcookie':'1'}).encode()
 login_status,headers,body=fetch('/wp-login.php',basic,opener,form)
 logged=any(c.name==auth['cookie_name'] for c in jar)
 if not logged:
  import re
  text=body.decode('utf-8','replace');error_section=re.search(r'<div[^>]+id=[\x22\x27]login_error[\x22\x27][^>]*>(.*?)</div>',text,re.S)
  error=error_section.group(1) if error_section else ''
  print('LOGIN DIAGNOSTIC: '+json.dumps({'http_status':login_status,'test_cookie_before_post':test_cookie,'logged_in_cookie':logged,'login_error_block':bool(error_section),'cookie_error_indicator':bool(re.search('cookie',error,re.I)),'password_error_indicator':bool(re.search('password|incorrect|invalid',error,re.I))}))
  need(False,'Password matched, but normal HTTP login did not create the expected cookie. Safe diagnostics above; no credentials or raw responses printed.')
 print('PASS: normal staging HTTPS login and expected WordPress cookie')
 wp('cyberdat-research','verify')
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
