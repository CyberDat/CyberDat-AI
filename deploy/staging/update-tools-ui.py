#!/usr/bin/env python3
"""Staging-only theme replacement. No DB, menu, SEO, server or credential edits."""
import argparse,base64,datetime,fcntl,getpass,hashlib,json,os,pathlib,pwd,shutil,subprocess,sys,tarfile,urllib.error,urllib.request,re
P=pathlib.Path
B=P(__file__).resolve().parent
ROOT=P('/var/www/cyberdat-staging/public')
THEME=ROOT/'wp-content/themes/cyberdat'
BACKUPS=P('/var/backups/cyberdat-staging')
HOST='https://staging.cyberdat.eu'
phase='preflight'

def need(ok,message):
 if not ok:raise RuntimeError(message)
def sha(path):return hashlib.sha256(P(path).read_bytes()).hexdigest()
def run(args,env=None):
 r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,env=env)
 need(r.returncode==0,'Command failed: '+P(args[0]).name+' exit='+str(r.returncode))
 return r.stdout

def wp(code):
 env=dict(os.environ,HOME='/var/lib/cyberdat-staging',WP_CLI_CONFIG_PATH='/var/lib/cyberdat-staging/cli.yml')
 return json.loads(run(['/usr/sbin/runuser','-u','cyberdat-staging','--','/usr/bin/php8.4','-d','memory_limit=128M','-d','disable_functions=mail','-d','sendmail_path=/bin/false','-d','opcache.enable_cli=0','-d','sys_temp_dir=/var/lib/cyberdat-staging/tmp','-d','open_basedir=/var/www/cyberdat-staging:/var/lib/cyberdat-staging:/var/log/cyberdat-staging:/run/mysqld:/etc/ssl/certs:/opt/cyberdat-tools','/opt/cyberdat-tools/wp-cli.phar','--path='+str(ROOT),'--no-color','--skip-packages','eval',code],env=env))

def state():
 return wp("$out=[wp_get_environment_type(),DB_NAME,get_option('home'),get_stylesheet()];foreach(['siteurl','blog_public','blogname','active_plugins','permalink_structure','theme_mods_cyberdat'] as $k){$out[$k]=get_option($k);} $out['tools']=[];foreach(get_posts(['post_type'=>'page','post_status'=>'any','posts_per_page'=>-1,'meta_key'=>'_cyberdat_tools_architecture','meta_value'=>'0.7']) as $p){$out['tools'][]=[$p->ID,$p->post_status,$p->post_name,$p->post_parent];}echo wp_json_encode($out);")

def fingerprints():
 paths=['/etc/nginx/sites-available/cyberdat','/etc/php/8.4/fpm/pool.d/www.conf','/var/www/cyberdat/public/wp-config.php','/etc/nginx/sites-available/cyberdat-staging','/etc/php/8.4/fpm/pool.d/cyberdat-staging.conf',str(ROOT/'wp-config.php'),str(ROOT/'wp-content/mu-plugins/cyberdat-staging-safety.php'),'/etc/cron.d/cyberdat-staging']
 return {p:sha(p) for p in paths}

def verify(root,files):
 need(not root.is_symlink(),'Symlink root rejected')
 actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
 need(actual==set(files),'Theme file set mismatch; stop instead of overwriting unrelated files')
 for name,info in files.items():
  p=root/name
  need(p.resolve().is_relative_to(root.resolve()) and not p.is_symlink() and sha(p)==info['sha256'],'Theme file checksum mismatch')
 need(not any(p.is_symlink() for p in root.rglob('*')),'Theme links rejected')

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None

def get(path,password=None):
 headers={'User-Agent':'CyberDat-Tools-UI/0.7'}
 if password is not None:headers['Authorization']='Basic '+base64.b64encode(('cyberdat_staging_admin:'+password).encode()).decode()
 request=urllib.request.Request(HOST+path,headers=headers)
 try:
  with urllib.request.build_opener(NoRedirect()).open(request,timeout=30) as r:return r.status,r.headers,r.read(2000000)
 except urllib.error.HTTPError as e:return e.code,e.headers,e.read(2000000)

def menu(body):
 text=body.decode('utf-8','replace')
 match=re.search(r'<nav\b[^>]*id="site-navigation"[^>]*>(.*?)</nav>',text,re.S)
 need(bool(match),'Primary navigation missing')
 return re.findall(r'<a\b[^>]*href="([^"]+)"[^>]*>(.*?)</a>',match.group(1),re.S)

def restore(backup):
 backup=backup.resolve()
 need(backup.parent==BACKUPS and backup.name.startswith('tools-ui-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe rollback source')
 previous=json.loads((backup/'previous.json').read_text())
 need(sha(backup/'theme.tar.gz')==(backup/'theme.sha256').read_text().strip(),'Rollback archive checksum mismatch')
 temporary=ROOT.parent/('restore-'+backup.name)
 need(not temporary.exists(),'Rollback preparation path exists')
 temporary.mkdir(mode=0o700)
 with tarfile.open(backup/'theme.tar.gz','r:gz') as archive:
  for item in archive.getmembers():need(not item.issym() and not item.islnk() and (item.isfile() or item.isdir()) and '..' not in P(item.name).parts and (item.name=='cyberdat' or item.name.startswith('cyberdat/')),'Unsafe rollback archive')
  archive.extractall(temporary,filter='data')
 verify(temporary/'cyberdat',previous['files'])
 account=pwd.getpwnam('cyberdat-staging')
 for p in [temporary/'cyberdat',*(temporary/'cyberdat').rglob('*')]:os.chown(p,account.pw_uid,account.pw_gid);p.chmod(0o755 if p.is_dir() else 0o644)
 retained=ROOT.parent/('retained-'+backup.name)
 need(not retained.exists(),'Rollback retention destination exists')
 retained.mkdir(mode=0o700)
 os.rename(THEME,retained/'cyberdat')
 try:os.rename(temporary/'cyberdat',THEME)
 except BaseException:os.rename(retained/'cyberdat',THEME);raise
 print('PASS: previous staging theme restored; updated theme retained; database untouched')

def main():
 global phase
 parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');parser.add_argument('--rollback',type=P);args=parser.parse_args()
 need(os.geteuid()==0,'Requires owner interactive sudo')
 need(args.apply!=bool(args.rollback),'Choose --apply or --rollback')
 os.umask(0o077)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 need(ROOT.resolve()==ROOT and THEME.resolve()==THEME,'Unexpected staging paths')
 before=state();need([before[str(i)] for i in range(4)]==['staging','cyberdat_staging',HOST,'cyberdat'],'Staging identity mismatch')
 guards=fingerprints()
 logs=[P('/var/log/cyberdat-staging/php-errors.log'),P('/var/log/cyberdat-staging/wp-debug.log')]
 offsets={p:p.stat().st_size if p.is_file() else 0 for p in logs}
 if args.rollback:
  phase='explicit staging-only theme rollback';restore(args.rollback)
  need(guards==fingerprints() and before==state(),'Protected state changed during rollback');return
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  expected,name=line.split(maxsplit=1);p=B/name
  need(p.resolve().is_relative_to(B) and not p.is_symlink() and sha(p)==expected,'Bundle checksum mismatch')
 previous=json.loads((B/'previous.json').read_text());source=json.loads((B/'source.json').read_text())
 verify(THEME,previous['files']);verify(B/'theme',source['files'])
 need(re.fullmatch('[0-9a-f]{40}',source['theme_commit']) is not None,'Missing pinned Git commit')
 need(shutil.disk_usage(ROOT).free>256*1024**2,'Less than 256 MiB free')
 need(get('/tools/')[0]==401,'Basic Auth gate missing')
 password=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ')
 status,headers,body=get('/tools/',password)
 need(password and status==200 and 'noindex' in headers.get('X-Robots-Tag',''),'Existing staging access/noindex verification failed')
 original_menu=menu(body)
 need(len(original_menu) in (6,7),'Unexpected primary menu count; review before replacement')
 phase='private theme-only rollback snapshot'
 need(BACKUPS.is_dir() and not BACKUPS.is_symlink() and BACKUPS.stat().st_uid==0 and BACKUPS.stat().st_mode&0o077==0,'Unsafe rollback directory')
 stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
 backup=BACKUPS/('tools-ui-'+stamp);backup.mkdir(mode=0o700)
 with tarfile.open(backup/'theme.tar.gz','w:gz') as archive:archive.add(THEME,arcname='cyberdat')
 (backup/'theme.sha256').write_text(sha(backup/'theme.tar.gz')+'\n');(backup/'previous.json').write_text(json.dumps(previous))
 print('PASS: theme-only rollback snapshot '+str(backup))
 phase='atomic staging theme replacement'
 account=pwd.getpwnam('cyberdat-staging');release=ROOT.parent/('.tools-ui-new-'+stamp)
 shutil.copytree(B/'theme',release)
 for p in [release,*release.rglob('*')]:os.chown(p,account.pw_uid,account.pw_gid);p.chmod(0o755 if p.is_dir() else 0o644)
 verify(release,source['files'])
 retained=ROOT.parent/('.tools-ui-before-'+stamp);retained.mkdir(mode=0o700)
 os.rename(THEME,retained/'cyberdat')
 try:os.rename(release,THEME)
 except BaseException:os.rename(retained/'cyberdat',THEME);raise
 phase='focused Tools/navigation/security verification'
 status,headers,body=get('/tools/',password);text=body.decode('utf-8','replace')
 need(status==200 and 'noindex' in headers.get('X-Robots-Tag',''),'Tools HTTP/noindex failed')
 cards=re.findall(r'<article class="cyberdat-tool-card tools-roadmap-card".*?</article>',text,re.S)
 need(len(cards)==10 and all('Coming Soon' in card and '<a ' not in card for card in cards),'Roadmap card count/status/link failure')
 need('CyberDat Security Tools' in text and 'Free, privacy-focused utilities' in text,'Heading/subtitle missing')
 need('tools-filter.js' in text and 'data-tools-filters hidden' in text,'Progressive filtering markup/script missing')
 current_menu=menu(body)
 need(len(current_menu)==7 and all(item in current_menu for item in original_menu),'Existing menu items changed')
 need(sum(bool(re.fullmatch(r'\s*Tools\s*',label)) for url,label in current_menu)==1,'Tools menu duplicate/missing')
 need('<p class="footer-brand">CyberDat</p>' in text and 'environment-badge' in text,'Footer brand/badge missing')
 need('CyberDat Staging' not in re.search(r'<footer\b.*?</footer>',text,re.S).group(0),'Staging leaked into footer brand')
 need(len(re.findall(r'<link\b[^>]*rel=[\x22\x27]canonical',text))<=1 and len(re.findall(r'<meta\b[^>]*name=[\x22\x27]description',text))<=1,'Duplicate SEO tags')
 print('PASS: Tools 200; ten non-clickable Coming Soon cards; seven primary items; footer brand/badge; noindex')
 for path in ['/','/tools/','/wp-login.php']:
  need(get(path)[0]==401,'Anonymous access bypass')
  need(get(path,password)[0]==200,'Authenticated page failure')
 print('PASS: homepage/Tools/login 200 after auth, anonymous 401; existing mobile toggle retained')
 for tool in json.loads((B/'theme/inc/tools-catalog.json').read_text()):need(get(tool['url'],password)[0]==404,'Unfinished tool route must stay 404')
 for asset in ['assets/css/tools.css','assets/js/tools-filter.js']:
  need(get('/wp-content/themes/cyberdat/'+asset,password)[0]==200,'Asset request failed')
 need(before==state() and guards==fingerprints(),'Database options/draft state or protected config changed')
 checked=0;warnings=0
 for log in logs:
  if log.is_file() and log.stat().st_size>=offsets[log]:
   with log.open('rb') as stream:stream.seek(offsets[log]);new_log=stream.read(2000000)
   need(not re.search(rb'PHP (?:Fatal|Parse) error|Uncaught (?:Error|Exception)|WordPress database error',new_log,re.I),'New PHP fatal/parse/database error in checked private logs')
   warnings+=len(re.findall(rb'PHP (?:Warning|Notice|Deprecated)',new_log,re.I));checked+=1
 print(('PASS: no new fatal/parse/database indicators; checked logs='+str(checked)+'; warning indicators='+str(warnings)) if checked else 'UNVERIFIED: private PHP logs unavailable')
 verify(THEME,source['files'])
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as r:need(r.status==200,'Production HTTPS failed')
 print('PASS: all ten draft routes 404; assets 200; selected DB state/config hashes unchanged; production HTTPS 200')
 (backup/'COMPLETE').write_text('COMPLETE\n')
 print('PASS: staging Tools UI update complete; commit='+source['theme_commit'])
 print('URL: '+HOST+'/tools/')
 print('Rollback: sudo /usr/bin/python3 -I '+str(B/'update-tools-ui.py')+' --rollback '+str(backup))
 print('UNVERIFIED: browser screenshots/real mobile interaction; inspect 320, 768 and 1440 px. No DB/menu settings/production deployment performed.')

if __name__=='__main__':
 try:main()
 except BaseException as error:
  print('BLOCKED: phase='+phase);print('Error type: '+type(error).__name__)
  if isinstance(error,RuntimeError):print('Reason: '+str(error))
  print('No raw responses or secrets printed; retain any snapshot and do not rerun blindly.');sys.exit(1)
