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
 for name in ['/var/log/cyberdat-staging/php-errors.log','/var/log/nginx/cyberdat-staging.error.log']:
  p=P(name)
  if p.is_file() and not p.is_symlink():
   with p.open('rb') as stream:stream.seek(max(0,p.stat().st_size-262144));data=stream.read(262144)
   counts[name]={kind:len(re.findall(pattern,data,re.I)) for kind,pattern in {'fatal':rb'PHP Fatal error|PHP Parse error|Uncaught (?:Error|Exception)','warning':rb'PHP Warning|PHP Notice','database':rb'WordPress database error'}.items()}
 return counts
NAMES=['kev','nvd','cisa-advisories','cert-eu','msrc','dispatch']
def unit(*args,check=True):return run(['/usr/bin/systemctl',*args],check=check)
def timers():return {n:unit('is-active','cyberdat-research-'+n+'.timer',check=False).returncode==0 for n in NAMES}
def proof():
 code=(B/'dashboard-charts-proof.php').read_text();return json.loads(wp('eval',code[5:]).stdout)
def atomic_copy(source,target):
 need(target.resolve()==target and target.is_relative_to(ROOT/'wp-content'),'Unsafe target');part=target.with_name(target.name+'.td-partial');need(not part.exists(),'Conflicting temporary file');shutil.copyfile(source,part);a=pwd.getpwnam('cyberdat-staging');os.chown(part,a.pw_uid,a.pw_gid);part.chmod(0o644);os.replace(part,target)
def admin_check(basic):
 password=getpass.getpass('EXISTING staging WORDPRESS password (hidden; login test only): ');need(bool(password),'WordPress password required')
 code="$p=json_decode(stream_get_contents(STDIN),true);$u=get_user_by('login','cyberdat_staging_admin');echo wp_json_encode(['ok'=>$u&&user_can($u,'manage_options')&&wp_check_password($p['password'],$u->user_pass,$u->ID),'cookie'=>LOGGED_IN_COOKIE]);"
 auth=json.loads(wp('eval',code,data=json.dumps({'password':password}).encode()).stdout);need(auth['ok'],'Existing staging WordPress password does not match; no reset performed')
 jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),Redirect());fetch('/wp-login.php',basic,opener)
 form=urllib.parse.urlencode({'log':'cyberdat_staging_admin','pwd':password,'redirect_to':HOST+'/wp-admin/','testcookie':'1'}).encode();fetch('/wp-login.php',basic,opener,form);need(any(c.name==auth['cookie'] for c in jar),'Administrator login failed')
 code,_,body=fetch('/wp-admin/admin.php?page=cyberdat-research',basic,opener);need(code==200 and b'Research Queue' in body,'Research Queue HTTP check failed')
 print('PASS: existing administrator login and Research Queue HTTP 200; no credential reset')
GEO=ROOT/'wp-content/plugins/cyberdat-geo-events'
def timer_fingerprints():
 paths=[P('/etc/systemd/system/cyberdat-research@.service'),P('/opt/cyberdat-research/run.sh'),*[P('/etc/systemd/system/cyberdat-research-'+n+'.timer') for n in NAMES]]
 return {str(p):sha(p) for p in paths}
def research_code():return {str(p.relative_to(PLUGIN)):sha(p) for p in PLUGIN.rglob('*') if p.is_file()}
def page_info():
 return json.loads(wp('eval',"$p=get_page_by_path('threat-intelligence',OBJECT,['page','post']);echo wp_json_encode($p?['id'=>$p->ID,'type'=>$p->post_type,'status'=>$p->post_status]:null);").stdout)

class SEOHeadParser(__import__('html.parser',fromlist=['HTMLParser']).HTMLParser):
 def __init__(self):super().__init__(convert_charrefs=True);self.descriptions=[];self.head=True
 def handle_endtag(self,tag):
  if tag.lower()=='head':self.head=False
 def handle_starttag(self,tag,attrs):
  if self.head and tag.lower()=='meta':
   values={k.lower():v for k,v in attrs}
   if str(values.get('name','')).lower()=='description':self.descriptions.append(values.get('content',''))
def verify_description(text):
 import html
 parser=SEOHeadParser();parser.feed(text)
 saved=json.loads(wp('eval',"require_once ABSPATH.'wp-admin/includes/plugin.php';$p=get_page_by_path('threat-intelligence');echo wp_json_encode(['id'=>$p?$p->ID:null,'description'=>$p?get_post_meta($p->ID,'rank_math_description',true):null,'template'=>$p?get_page_template_slug($p):null,'rank_math_active'=>is_plugin_active('seo-by-rank-math/rank-math.php')]);").stdout)
 normal=lambda value:' '.join(html.unescape(value or '').split())
 expected=normal(saved['description']);actual=[normal(value) for value in parser.descriptions]
 print('SEO DESCRIPTION DIAGNOSTIC: '+json.dumps({'page_id':saved['id'],'template':saved['template'],'rank_math_active':saved['rank_math_active'],'description_tag_count':len(actual),'saved_description':expected,'rendered_descriptions':actual,'rank_math_marker':bool(re.search(r'Rank.?Math',text,re.I))},ensure_ascii=False))
 need(bool(expected) and len(actual)==1 and actual[0]==expected,'Description absent, duplicated or differs from saved page metadata; safe diagnostic above, no page settings changed')

def main():
 global phase
 parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');parser.add_argument('--verify',type=P);parser.add_argument('--rollback',type=P);args=parser.parse_args();need(sum([args.apply,bool(args.verify),bool(args.rollback)])==1 and os.geteuid()==0,'Choose one action using owner sudo');os.umask(0o077)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  expected,name=line.split(maxsplit=1);p=B/name;need(p.resolve().is_relative_to(B) and not p.is_symlink() and sha(p)==expected,'Bundle checksum mismatch')
 identity=state();need(identity[:4]==['staging','cyberdat_staging',HOST,'cyberdat'] and str(identity[4])=='0','Wrong staging identity');protected=guards();timer_hashes=timer_fingerprints();agent_hashes=research_code();targets=json.loads((B/'patch.json').read_text());logs_before=log_indicators();backup=args.verify or args.rollback
 if args.apply:
  need(page_info() is None,'Reserved route already exists; stop before changes')
  need(not GEO.exists(),'Geo plugin directory already exists; do not overwrite')
  wp('eval',"require_once ABSPATH.'wp-admin/includes/plugin.php';cdra_need(is_plugin_active('seo-by-rank-math/rank-math.php'),'rank_math_required');$d=cyberdat_research_dashboard();cdra_need(is_array($d)&&isset($d['chart_series']),'installed_1_1_cache_required');global $wpdb;cdra_need(!$wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s',$wpdb->esc_like($wpdb->prefix.'cyberdat_geo_events'))),'geo_table_conflict');")
 for e in targets:
  target=ROOT/e['target'];need(target.resolve()==target and target.is_relative_to(ROOT/'wp-content') and not target.is_relative_to(PLUGIN),'Unsafe target / Research code changes forbidden')
  if args.apply:need((not target.exists()) if e['before'] is None else sha(target)==e['before'],'Installed release conflict')
  elif args.verify:need(target.is_file() and sha(target)==e['after'],'Installed release conflict')
  else:need((not target.exists() and e['before'] is None) or (target.is_file() and sha(target) in [e['before'],e['after']]),'Rollback conflict')
  need(sha(B/e['candidate'])==e['after'],'Candidate checksum mismatch')
  if target.suffix=='.php':run(['/usr/bin/php8.4','-l',str(B/e['candidate'])])
 if backup:
  backup=backup.resolve();need(backup.parent==BACKUPS and backup.name.startswith('threat-2.0-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe backup path');saved=json.loads((backup/'state.json').read_text());need(saved['commit']==(B/'COMMIT').read_text().strip() and sha(backup/'theme.tar.gz')==saved['theme_sha256'] and sha(backup/'staging.sql.gz')==saved['sql_sha256'],'Backup integrity mismatch')
 if args.rollback:
  phase='explicit code rollback; retain new data'
  if page_info():
   need(page_info()['id']==saved['page_id'],'Rollback page identity conflict');wp('post','update',str(saved['page_id']),'--post_status=draft')
  wp('plugin','deactivate','cyberdat-geo-events')
  for i,e in enumerate(targets):
   if e['before'] is not None:need(sha(backup/str(i))==e['before'],'Rollback saved file mismatch')
  for i,e in enumerate(targets):
   if e['before'] is not None:atomic_copy(backup/str(i),ROOT/e['target'])
  need(protected==guards() and agent_hashes==research_code() and timer_hashes==timer_fingerprints(),'Protected code/config changed');print('PASS: prior theme restored; new page kept as draft, Geo plugin inactive; Geo table/backups retained; Research/timers untouched');return
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and fetch('/',basic)[0]==200 and fetch('/')[0]==401,'Basic Auth preflight failed')
 if args.apply:
  phase='private backup before installed changes; no timer operations'
  need(BACKUPS.is_dir() and BACKUPS.stat().st_uid==0 and BACKUPS.stat().st_mode&0o077==0,'Unsafe backup parent');need(shutil.disk_usage(BACKUPS).free>1024**3,'Less than 1 GiB free')
  backup=BACKUPS/('threat-2.0-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));backup.mkdir(mode=0o700);database_backup(backup/'staging.sql.gz')
  with tarfile.open(backup/'theme.tar.gz','w:gz') as archive:archive.add(THEME,arcname='cyberdat')
  for i,e in enumerate(targets):
   if e['before'] is not None:shutil.copyfile(ROOT/e['target'],backup/str(i))
  saved={'commit':(B/'COMMIT').read_text().strip(),'theme_sha256':sha(backup/'theme.tar.gz'),'sql_sha256':sha(backup/'staging.sql.gz'),'page_id':None};(backup/'state.json').write_text(json.dumps(saved));print('BACKUP: '+str(backup),flush=True)
  phase='install local theme and separate empty Geo module'
  for e in sorted(targets,key=lambda x:x['before'] is not None):
   target=ROOT/e['target'];target.parent.mkdir(parents=True,exist_ok=True)
   # Only directories inside the new Geo plugin or new theme map directory are created.
   a=pwd.getpwnam('cyberdat-staging')
   for folder in [GEO,THEME/'assets/maps']:
    if folder.exists():os.chown(folder,a.pw_uid,a.pw_gid);folder.chmod(0o755)
   atomic_copy(B/e['candidate'],target)
  wp('plugin','activate','cyberdat-geo-events')
  phase='create one native staging page and page-specific Rank Math metadata'
  code="$id=wp_insert_post(['post_type'=>'page','post_status'=>'publish','post_name'=>'threat-intelligence','post_title'=>'Threat Intelligence','post_content'=>'Verified vulnerability intelligence, official advisories and transparent geographic observations.'],true);if(is_wp_error($id)){throw new RuntimeException('page_create_failed');}update_post_meta($id,'_wp_page_template','page-templates/threat-intelligence.php');update_post_meta($id,'rank_math_title','Threat Intelligence — CyberDat');update_post_meta($id,'rank_math_description','Explore CyberDat threat intelligence: verified CISA KEV, local NVD/CVSS analytics, official security advisories and transparent geographic observations.');echo wp_json_encode(['id'=>$id]);"
  saved['page_id']=json.loads(wp('eval',code).stdout)['id'];(backup/'state.json').write_text(json.dumps(saved));print('PASS: native staging page created; no sample posts or geolocated fixtures imported',flush=True)
 phase='read-only SQL and application verification'
 # A running source job may briefly precede its projection. Wait for it, without stopping timers/jobs.
 import time
 deadline=time.monotonic()+190
 while any(unit('show','cyberdat-research@'+n+'.service','--property=ActiveState','--value').stdout.strip() in (b'active',b'activating') for n in NAMES):
  need(time.monotonic()<deadline,'Research worker still active; verify later without reinstall');time.sleep(3)
 wp('eval',"$p=get_page_by_path('threat-intelligence');cdra_need($p&&get_permalink($p)==='https://staging.cyberdat.eu/threat-intelligence/','native_permalink_mismatch');")
 report=proof();need(page_info() and page_info()['id']==saved['page_id'],'Page identity mismatch')
 code,headers,body=fetch('/threat-intelligence/',basic);text=body.decode('utf-8','replace');need(code==200 and 'noindex' in headers.get('X-Robots-Tag','') and 'data-threat-dashboard="2.0"' in text and 'data-threat-map' in text,'Dedicated page unavailable')
 need(text.count('data-chart-id=')==6,'Existing charts missing')
 for key,value in report['kpis'].items():need(re.search(r'data-kpi="'+key+r'"\s+data-value="'+str(value)+r'"',text),'KPI differs from SQL')
 need('No verified geolocated threat events available.' in text and 'NO LIVE TELEMETRY' in text,'Honest empty map missing')
 need(text.index('data-threat-map')<text.index('data-kpi=')<text.index('data-charts-version=')<text.index('td-feed'),'Section order mismatch')
 canonical=re.findall(r'<link\b[^>]*rel=[\"\x27]canonical[\"\x27][^>]*>',text,re.I);need(len(canonical)<=1 and (not canonical or '/threat-intelligence/' in canonical[0]),'Canonical duplicate/wrong route');print('SEO: '+('Rank Math canonical present' if canonical else 'Rank Math suppresses canonical on noindex staging; native permalink verified'))
 verify_description(text)
 home_code,h,home=fetch('/',basic);home=home.decode('utf-8','replace');need(home_code==200 and 'data-threat-pulse' in home and 'data-threat-dashboard' not in home and 'td-feed' not in home and 'data-threat-map' not in home,'Homepage not compact')
 nav=home.split('<nav id="site-navigation"',1)[1].split('</nav>',1)[0];need('/threat-intelligence/' in nav and len(re.findall(r'<li\b',nav))>=8,'Primary sections missing')
 for key in ['critical','nvd_7','kev']:
  need(re.search(r'data-pulse-kpi="'+key+r'"\s+data-value="'+str(report['counts'][key])+r'"',home),'Pulse KPI differs from SQL')
 for query in ['ti_source=cert-eu','ti_kind=advisory','ti_severity=Critical&ti_kind=cve']:
  code,_,b=fetch('/threat-intelligence/?'+query,basic);need(code==200 and 'data-threat-dashboard="2.0"' in b.decode('utf-8','replace'),'Dashboard filter route failed')
 for path in ['/tools/','/guides/','/learning/','/news/','/analysis/','/topics/','/wp-login.php','/wp-json/wp/v2/editorial-formats','/wp-content/themes/cyberdat/assets/maps/world-land.svg','/wp-content/themes/cyberdat/assets/js/threat-geo.js']:
  need(fetch(path,basic)[0]==200,'Existing route/static map asset failed')
 endpoint='/wp-json/cyberdat-geo/v1/events';code,_,b=fetch(endpoint,basic);geo=json.loads(b);need(code==200 and geo['items']==[] and geo['mode']=='observed_events' and geo['live_available'] is False and not geo['sources'],'Empty verified Geo endpoint failed')
 need(fetch(endpoint)[0]==401 and fetch('/threat-intelligence/')[0]==401,'Anonymous staging access opened')
 need(fetch(endpoint,basic,data=b'{}')[0] in (404,405),'Geo endpoint accepted a write method')
 need('source_ip' not in json.dumps(geo) and 'target_ip' not in json.dumps(geo),'Geo response includes IP fields')
 need(fetch(endpoint+'?page=11',basic)[0]==400 and fetch(endpoint+'?event_type=malware&days=7&zoom=2',basic)[0]==200,'Geo query bounds failed')
 wp('eval',"require_once ABSPATH.'wp-admin/includes/plugin.php';global $wpdb;cdra_need((int)$wpdb->get_var('SELECT COUNT(*) FROM '.cdgeo_table())===0,'unexpected_geo_events');cdra_need(is_plugin_active('cyberdat-research/cyberdat-research.php'),'research_inactive');")
 admin_check(basic)
 need(identity==state() and protected==guards() and agent_hashes==research_code() and timer_hashes==timer_fingerprints(),'Protected config, Research code or timer files changed')
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production HTTPS check failed')
 after=log_indicators()
 for name,counts in after.items():
  for kind,value in counts.items():need(value<=logs_before.get(name,{}).get(kind,0),'New staging log indicator: '+kind)
 (backup/'evidence.json').write_text(json.dumps({'research':report,'geo':geo,'page_id':saved['page_id'],'research_code_unchanged':True,'timer_files_unchanged':True}));(backup/'COMPLETE').write_text('COMPLETE\n')
 print('PASS: full Dashboard moved, compact home, six charts/KPIs/filters/SEO/routes and Research Queue; Geo empty/no live/IP; no Research code/data or timer operations')
 print('KPI EVIDENCE: '+json.dumps(report));print('LOG CHECK: '+json.dumps({'files_checked':len(after),'status':'PASS' if after else 'UNVERIFIED'}));print('GEO: '+json.dumps(geo));print('COMMIT: '+(B/'COMMIT').read_text().strip());print('URL: '+HOST+'/threat-intelligence/');print('BACKUP: '+str(backup));print('PASS: production HTTPS 200; protected hashes unchanged; Basic Auth/noindex preserved')
 print('UNVERIFIED: real browser screenshots, responsive map/charts and console. Run capture-threat-2.py on Windows. No geo sources or live telemetry connected.')
 print('VERIFY: sudo /usr/bin/python3 -I '+str(B/'deploy-threat-2.py')+' --verify '+str(backup));print('ROLLBACK: sudo /usr/bin/python3 -I '+str(B/'deploy-threat-2.py')+' --rollback '+str(backup))
if __name__=='__main__':
 try:main()
 except BaseException as error:
  print('BLOCKED: phase='+phase);print('Error type: '+type(error).__name__)
  if isinstance(error,RuntimeError):print('Reason: '+str(error))
  print('No credentials/raw responses printed; retain private backup and any partial state. No destructive rollback, timer changes or agent restart. Do not rerun --apply blindly.');sys.exit(1)
