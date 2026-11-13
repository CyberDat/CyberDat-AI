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
import re,argparse,base64,datetime,fcntl,getpass,hashlib,http.cookiejar,json,os,pathlib,pwd,shutil,subprocess,sys,tarfile,urllib.error,urllib.parse,urllib.request
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

def log_indicators():
 counts={}
 for name in ['php-error.log','php-fpm.log','nginx-error.log']:
  p=P('/var/log/cyberdat-staging')/name
  if p.is_file() and not p.is_symlink():
   with p.open('rb') as stream:stream.seek(max(0,p.stat().st_size-262144));data=stream.read(262144)
   counts[name]={kind:len(re.findall(pattern,data,re.I)) for kind,pattern in {'fatal':rb'PHP Fatal error|PHP Parse error|Uncaught (?:Error|Exception)','warning':rb'PHP Warning|PHP Notice','database':rb'WordPress database error'}.items()}
 return counts
NAMES=['kev','nvd','cisa-advisories','cert-eu','msrc','dispatch']
def unit(*args,check=True):return run(['/usr/bin/systemctl',*args],check=check)
def timers():return {n:unit('is-active','cyberdat-research-'+n+'.timer',check=False).returncode==0 for n in NAMES}
def proof():
 code=(B/'dashboard-v1-proof.php').read_text();return json.loads(wp('eval',code[5:]).stdout)
def atomic_copy(source,target):
 need(target.resolve()==target and target.is_relative_to(ROOT/'wp-content'),'Unsafe target');part=target.with_name(target.name+'.td-partial');need(not part.exists(),'Conflicting temporary file');shutil.copyfile(source,part);a=pwd.getpwnam('cyberdat-staging');os.chown(part,a.pw_uid,a.pw_gid);part.chmod(0o644);os.replace(part,target)
def refresh():
 wp('eval',"cdra_need(cdra_staging(),'staging_only');$s=new CDRA_Store();$lock='cdra_'.substr(hash('sha256',DB_NAME.$s->prefix),0,32);cdra_need((int)$s->db->get_var($s->db->prepare('SELECT GET_LOCK(%s,0)',$lock))===1,'ingestion_locked');try{(new CDRA_Service($s))->projection();}finally{$s->db->get_var($s->db->prepare('SELECT RELEASE_LOCK(%s)',$lock));}")
def admin_check(basic):
 password=getpass.getpass('EXISTING staging WORDPRESS password (hidden; login test only): ');need(bool(password),'WordPress password required')
 code="$p=json_decode(stream_get_contents(STDIN),true);$u=get_user_by('login','cyberdat_staging_admin');echo wp_json_encode(['ok'=>$u&&user_can($u,'manage_options')&&wp_check_password($p['password'],$u->user_pass,$u->ID),'cookie'=>LOGGED_IN_COOKIE]);"
 auth=json.loads(wp('eval',code,data=json.dumps({'password':password}).encode()).stdout);need(auth['ok'],'Existing staging WordPress password does not match; no reset performed')
 jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),Redirect());fetch('/wp-login.php',basic,opener)
 form=urllib.parse.urlencode({'log':'cyberdat_staging_admin','pwd':password,'redirect_to':HOST+'/wp-admin/','testcookie':'1'}).encode();fetch('/wp-login.php',basic,opener,form);need(any(c.name==auth['cookie'] for c in jar),'Administrator login failed')
 code,_,body=fetch('/wp-admin/admin.php?page=cyberdat-research',basic,opener);need(code==200 and b'Research Queue' in body,'Research Queue HTTP check failed')
 print('PASS: existing administrator login and Research Queue HTTP 200; no credential reset')
def main():
 global phase
 parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');parser.add_argument('--verify',type=P);parser.add_argument('--rollback',type=P);args=parser.parse_args();need(sum([args.apply,bool(args.verify),bool(args.rollback)])==1 and os.geteuid()==0,'Choose --apply, --verify or --rollback with owner sudo');os.umask(0o077)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  expected,name=line.split(maxsplit=1);p=B/name;need(p.resolve().is_relative_to(B) and not p.is_symlink() and sha(p)==expected,'Bundle checksum mismatch')
 logs_before=log_indicators();identity=state();need(identity[:4]==['staging','cyberdat_staging',HOST,'cyberdat'] and str(identity[4])=='0','Wrong staging identity');protected=guards();targets=json.loads((B/'patch.json').read_text());old_timers=timers();backup=args.rollback or args.verify
 for e in targets:
  target=ROOT/e['target'];need(target.resolve()==target and target.is_relative_to(ROOT/'wp-content'),'Unsafe target')
  if args.apply:need((not target.exists()) if e['before'] is None else sha(target)==e['before'],'Installed release conflict; no blind reapply')
  elif args.verify:need(target.is_file() and sha(target)==e['after'],'Installed release differs from expected update')
  else:need((not target.exists() and e['before'] is None) or (target.is_file() and sha(target) in [e['before'],e['after']]),'Rollback conflict; unexpected installed file')
  need(sha(B/e['candidate'])==e['after'],'Candidate checksum mismatch')
  if e['target'].endswith('.php'):run(['/usr/bin/php8.4','-l',str(B/e['candidate'])])
 if backup:
  backup=backup.resolve();need(backup.parent==BACKUPS and backup.name.startswith('dashboard-v1-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe backup');saved=json.loads((backup/'state.json').read_text())
  need(saved['commit']==(B/'COMMIT').read_text().strip() and sha(backup/'staging.sql.gz')==saved['sql_sha256'] and sha(backup/'theme.tar.gz')==saved['theme_sha256'] and sha(backup/'plugin.tar.gz')==saved['plugin_sha256'],'Backup integrity failed')
 basic=None
 if not args.rollback:
  basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and fetch('/',basic)[0]==200 and fetch('/')[0]==401,'HTTP/Basic Auth preflight failed')
 paused=False
 try:
  phase='pause existing Research timers and wait for bounded workers'
  for name in NAMES:unit('stop','cyberdat-research-'+name+'.timer')
  paused=True
  # Wait for a running job to finish; do not kill an ingestion transaction.
  import time
  deadline=time.monotonic()+190
  while any(unit('is-active','cyberdat-research@'+name+'.service',check=False).returncode==0 or unit('show','cyberdat-research@'+name+'.service','--property=ActiveState','--value').stdout.strip()==b'activating' for name in NAMES):
   need(time.monotonic()<deadline,'Research worker still active; no files patched');time.sleep(3)
  if args.rollback:
   phase='explicit code-only rollback'
   for i,e in enumerate(targets):
    if e['before'] is not None:need(sha(backup/str(i))==e['before'],'Rollback file checksum mismatch')
   for i,e in enumerate(targets):
    if e['before'] is not None:atomic_copy(backup/str(i),ROOT/e['target'])
   # New files are retained but unreachable from the old bootstrap/template; no data deletion.
   refresh();need(protected==guards(),'Protected state changed');print('PASS: original code restored; new inert files, backup and accumulated Research data retained');return
  if args.apply:
   phase='private staging database, theme and plugin backup'
   need(BACKUPS.is_dir() and BACKUPS.stat().st_uid==0 and BACKUPS.stat().st_mode&0o077==0,'Unsafe backup parent');need(shutil.disk_usage(BACKUPS).free>1024**3,'Less than 1 GiB free');stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');backup=BACKUPS/('dashboard-v1-'+stamp);backup.mkdir(mode=0o700)
   database_backup(backup/'staging.sql.gz')
   for name,path in [('theme',THEME),('plugin',PLUGIN)]:
    with tarfile.open(backup/(name+'.tar.gz'),'w:gz') as archive:archive.add(path,arcname=path.name)
   for i,e in enumerate(targets):
    if e['before'] is not None:shutil.copyfile(ROOT/e['target'],backup/str(i))
   saved={'commit':(B/'COMMIT').read_text().strip(),'sql_sha256':sha(backup/'staging.sql.gz'),'theme_sha256':sha(backup/'theme.tar.gz'),'plugin_sha256':sha(backup/'plugin.tar.gz'),'timers':old_timers};(backup/'state.json').write_text(json.dumps(saved));print('BACKUP: '+str(backup),flush=True)
   phase='seven pinned code files; install new includes before their callers'
   for e in sorted(targets,key=lambda x:x['before'] is not None):atomic_copy(B/e['candidate'],ROOT/e['target'])
  phase='offline temporary-table contracts and cache rebuild without network'
  wp('cyberdat-research','test');refresh();report=proof();print('PASS: independent SQL/KPI/histogram/feed proofs and temporary-table Research tests',flush=True)
  phase='one consolidated HTTP/filter/SEO/protection smoke test'
  status,headers,body=fetch('/',basic);text=body.decode('utf-8','replace');need(status==200 and 'noindex' in headers.get('X-Robots-Tag','') and 'data-threat-dashboard="1.0"' in text,'New Dashboard HTTP/noindex failed')
  for key,value in report['kpis'].items():need(re.search(r'data-kpi="'+key+r'"\s+data-value="'+str(value)+r'"',text),'Rendered KPI differs from SQL')
  need(report['advisory_feed_records']>0 and text.count('td-advisories')>0,'Advisory block empty')
  for query in ['ti_source=cert-eu','ti_severity=Critical&ti_kind=cve','ti_kind=advisory']:
   code,h,b=fetch('/?'+query,basic);t=b.decode('utf-8','replace');need(code==200 and 'data-threat-dashboard="1.0"' in t and 'noindex' in h.get('X-Robots-Tag',''),'Filter HTTP check failed')
   fragment=t.split('<div class="td-feed"',1)[1].split('<div class="td-section-head"',1)[0]
   if query=='ti_source=cert-eu':need(not re.search(r'data-source="(?!cert-eu")',fragment),'Source filter leaked other sources')
   if query=='ti_severity=Critical&ti_kind=cve':need('data-source="kev"' not in fragment and 'data-source="cert-eu"' not in fragment,'CVE filter mismatch')
  for path in ['/tools/','/news/','/guides/','/learning/','/analysis/','/wp-login.php','/wp-json/wp/v2/editorial-formats','/wp-content/themes/cyberdat/assets/css/threat-dashboard.css']:
   need(fetch(path,basic)[0]==200,'Existing route/asset failed')
  need(fetch('/')[0]==401 and fetch('/wp-config.php',basic)[0]==403,'Access guards changed')
  need(len(re.findall(r'<link\b[^>]*rel=[\"\x27]canonical',text,re.I))<=1 and len(re.findall(r'<meta\b[^>]*name=[\"\x27]description',text,re.I))<=1,'Duplicate SEO metadata')
  need(not re.search(r'(?:PHP (?:Warning|Fatal error|Parse error)|<b>Warning</b>)',text),'PHP error visible in page')
  admin_check(basic);wp('cyberdat-research','verify');need(identity==state() and protected==guards(),'Protected state/configurations changed')
  with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production HTTPS check failed')
  logs_after=log_indicators()
  for name,counts in logs_after.items():
   for kind,value in counts.items():need(value<=logs_before.get(name,{}).get(kind,0),'New staging log error indicator: '+kind)
  print('LOG CHECK: '+json.dumps({'checked_files':len(logs_after),'new_detected_indicators':0,'raw_messages_printed':False}))
  (backup/'evidence.json').write_text(json.dumps(report));(backup/'COMPLETE').write_text('COMPLETE\n')
  print('KPI EVIDENCE: '+json.dumps(report));print('COMMIT: '+(B/'COMMIT').read_text().strip());print('PASS: new staging Dashboard HTML/KPIs/filters, existing routes, Research Queue and Basic Auth/noindex; production HTTPS 200 and protected fingerprints unchanged')
  print('UNVERIFIED: real browser screenshots/responsive interaction and browser JS console; run capture-dashboard.py on Windows. No ingestion, content publication or additional connectors enabled.')
 finally:
  if paused:
   for name,active in old_timers.items():
    if active:unit('start','cyberdat-research-'+name+'.timer',check=False)
   restored=timers();print('TIMERS: '+json.dumps(restored));need(restored==old_timers,'Timer restoration failed')
  if backup:
   print('BACKUP: '+str(backup));print('VERIFY ONLY: sudo /usr/bin/python3 -I '+str(B/'deploy-dashboard.py')+' --verify '+str(backup));print('ROLLBACK CODE: sudo /usr/bin/python3 -I '+str(B/'deploy-dashboard.py')+' --rollback '+str(backup))
if __name__=='__main__':
 try:main()
 except BaseException as error:
  print('BLOCKED: phase='+phase);print('Error type: '+type(error).__name__)
  if isinstance(error,RuntimeError):print('Reason: '+str(error))
  print('No raw credentials/API bodies printed; private snapshot and partial state retained. Do not rerun --apply blindly.');sys.exit(1)
