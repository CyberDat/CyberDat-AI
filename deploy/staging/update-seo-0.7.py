#!/usr/bin/env python3
"""Owner-run, staging-only update. Offline bundle; never install/reload services."""
import argparse, base64, datetime, fcntl, getpass, hashlib, json
import os, pathlib, pwd, shutil, subprocess, sys, tarfile, tempfile, urllib.error, urllib.parse, urllib.request, zipfile
P=pathlib.Path
BUNDLE=P(__file__).resolve().parent
ROOT=P('/var/www/cyberdat-staging/public')
RUNTIME=P('/var/lib/cyberdat-staging')
THEME=ROOT/'wp-content/themes/cyberdat'
PLUGIN=ROOT/'wp-content/plugins/seo-by-rank-math'
BACKUPS=P('/var/backups/cyberdat-staging')
HOST='https://staging.cyberdat.eu'
USER='cyberdat-staging'
PHAR='/opt/cyberdat-tools/wp-cli.phar'
phase='preflight'

def need(ok, message):
    if not ok: raise RuntimeError(message)

def digest(p): return hashlib.sha256(P(p).read_bytes()).hexdigest()

def call(argv, data=None, timeout=300, env=None):
    r=subprocess.run(argv,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,env=env)
    need(r.returncode==0,'Command failed: '+P(argv[0]).name+'; exit='+str(r.returncode))
    return r.stdout

def wp(*args):
    env=dict(os.environ,HOME=str(RUNTIME),WP_CLI_CONFIG_PATH=str(RUNTIME/'cli.yml'))
    basedir=':'.join(['/var/www/cyberdat-staging',str(RUNTIME),'/var/log/cyberdat-staging','/run/mysqld','/etc/ssl/certs','/opt/cyberdat-tools'])
    return call(['/usr/sbin/runuser','-u',USER,'--','/usr/bin/php8.4','-d','memory_limit=128M','-d','disable_functions=mail','-d','sendmail_path=/bin/false','-d','opcache.enable_cli=0','-d','sys_temp_dir='+str(RUNTIME/'tmp'),'-d','open_basedir='+basedir,PHAR,'--path='+str(ROOT),'--no-color','--skip-packages',*args],env=env)

def fingerprint():
    paths=['/etc/nginx/sites-available/cyberdat','/etc/php/8.4/fpm/pool.d/www.conf','/var/www/cyberdat/public/wp-config.php','/etc/nginx/sites-available/cyberdat-staging','/etc/php/8.4/fpm/pool.d/cyberdat-staging.conf',str(ROOT/'wp-config.php'),str(ROOT/'wp-content/mu-plugins/cyberdat-staging-safety.php'),'/etc/cron.d/cyberdat-staging']
    return {p:digest(p) for p in paths}

def verify_tree(root, files):
    actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    need(actual==set(files),'Unexpected source/theme file set')
    for name,info in files.items():
        p=root/name
        need(not p.is_symlink() and p.is_file() and digest(p)==info['sha256'],'Source/theme checksum mismatch')
    need(not any(p.is_symlink() for p in root.rglob('*')),'Theme contains symlinks')

class LocalRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        need(urllib.parse.urlsplit(newurl).netloc=='staging.cyberdat.eu' and newurl.startswith(HOST+'/'),'Non-staging redirect blocked')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def http(path, password=None, opener=None, data=None):
    headers={'User-Agent':'CyberDat-Staging-SEO/0.7'}
    if password is not None: headers['Authorization']='Basic '+base64.b64encode(('cyberdat_staging_admin:'+password).encode()).decode()
    req=urllib.request.Request(HOST+path,data=data,headers=headers)
    try:
        with (opener or urllib.request.build_opener(LocalRedirect())).open(req,timeout=45) as response:
            return response.status,response.headers,response.read(3000000)
    except urllib.error.HTTPError as error:
        return error.code,error.headers,error.read(3000000)

def snapshot_database(target):
    with target.open('xb') as dest:
        dump=subprocess.Popen(['/usr/bin/mariadb-dump','--no-defaults','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--skip-password','--single-transaction','--quick','--routines','--triggers','--events','--hex-blob','--default-character-set=utf8mb4','--databases','cyberdat_staging'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        gzip=subprocess.Popen(['/usr/bin/gzip','-c'],stdin=dump.stdout,stdout=dest,stderr=subprocess.DEVNULL)
        dump.stdout.close()
        a=gzip.wait();b=dump.wait()
        need(a==0 and b==0,'Staging rollback database snapshot failed')
    target.chmod(0o600)

def owned_copy(source,dest,uid,gid):
    shutil.copytree(source,dest,symlinks=False)
    for p in [dest,*dest.rglob('*')]:
        os.chown(p,uid,gid);p.chmod(0o755 if p.is_dir() else 0o644)

def main():
    global phase
    parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');parser.add_argument('--rollback',type=P)
    args=parser.parse_args()
    need(os.geteuid()==0,'Run via owner interactive sudo')
    need(args.apply != bool(args.rollback),'Choose --apply or --rollback')
    os.umask(0o077)
    lock=P('/run/lock/cyberdat-staging-seo.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    need(ROOT.is_dir() and ROOT.resolve()==ROOT and THEME.resolve()==THEME and (ROOT/'wp-content/plugins').resolve()==ROOT/'wp-content/plugins' and RUNTIME.resolve()==RUNTIME,'Unexpected staging paths')
    identity=json.loads(wp('eval',"echo wp_json_encode([wp_get_environment_type(),DB_NAME,get_option('home'),get_stylesheet()]);"))
    need(identity==['staging','cyberdat_staging',HOST,'cyberdat'],'Wrong staging identity')
    before=fingerprint()
    if args.rollback:
        rollback(args.rollback,before);return
    for line in (BUNDLE/'BUNDLE-SHA256SUMS').read_text().splitlines():
        expected,name=line.split(maxsplit=1);p=BUNDLE/name
        need(p.resolve().is_relative_to(BUNDLE) and not p.is_symlink() and digest(p)==expected,'Bundle integrity failure')
    source=json.loads((BUNDLE/'source.json').read_text())
    need(len(source['theme_commit'])==40,'Missing pinned source commit')
    verify_tree(BUNDLE/'theme',source['files'])
    verify_tree(THEME,json.loads((BUNDLE/'previous-theme.json').read_text())['files'])
    need(not PLUGIN.exists(),'Rank Math destination already exists: review partial deployment; do not overwrite')
    need(shutil.disk_usage(ROOT).free>1024**3,'Less than 1 GiB free')
    plugin_meta=json.loads((BUNDLE/'rank-math.json').read_text())
    need(digest(BUNDLE/'rank-math.zip')==plugin_meta['sha256'],'Plugin package checksum mismatch')
    need(http('/')[0]==401,'Staging Basic Auth missing')
    basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ')
    need(basic and http('/',basic)[0]==200,'Basic Auth verification failed')
    admin=getpass.getpass('EXISTING staging WordPress password (hidden; final login check): ')
    need(bool(admin),'WordPress verification password required')
    # No installation, DNS/TLS changes, root credentials or production DB connection.
    phase='staging-only rollback snapshot'
    BACKUPS.mkdir(mode=0o700,exist_ok=True)
    need(not BACKUPS.is_symlink() and BACKUPS.stat().st_uid==0 and BACKUPS.stat().st_mode&0o077==0,'Unsafe staging backup directory')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup=BACKUPS/('seo-0.7-'+stamp);backup.mkdir(mode=0o700)
    with tarfile.open(backup/'theme.tar.gz','w:gz') as archive: archive.add(THEME,arcname='cyberdat',recursive=True)
    snapshot_database(backup/'staging.sql.gz')
    (backup/'state.json').write_text(json.dumps({'source':source['theme_commit'],'fingerprints':before,'plugin_preexisting':False,'date_utc':stamp}))
    print('PASS: private staging-only rollback snapshot; path='+str(backup))
    phase='verified staging theme and official plugin installation'
    account=pwd.getpwnam(USER)
    runtime=RUNTIME/('seo-0.7-'+stamp);runtime.mkdir(mode=0o700);os.chown(runtime,account.pw_uid,account.pw_gid)
    for name in ['seo-0.7-seed.php','seo-0.7-check.php','tools-roadmap.json']:
        dest=runtime/name;shutil.copyfile(BUNDLE/name,dest);os.chown(dest,account.pw_uid,account.pw_gid);dest.chmod(0o600)
    new=THEME.parent/('.cyberdat-seo-new-'+stamp)
    owned_copy(BUNDLE/'theme',new,account.pw_uid,account.pw_gid)
    old=ROOT.parent/('.cyberdat-theme-before-'+stamp)
    need(not new.is_symlink() and not old.exists(),'Release path collision')
    os.rename(THEME,old)
    try: os.rename(new,THEME)
    except BaseException:
        os.rename(old,THEME);raise
    # Original theme retained outside the document root; not deleted.
    with zipfile.ZipFile(BUNDLE/'rank-math.zip') as archive:
        for entry in archive.infolist():
            parts=P(entry.filename).parts
            need(parts and parts[0]=='seo-by-rank-math' and '..' not in parts and not entry.filename.startswith('/') and not ((entry.external_attr>>16)&0o170000==0o120000),'Unsafe plugin archive entry')
        archive.extractall(ROOT/'wp-content/plugins')
    for p in [PLUGIN,*PLUGIN.rglob('*')]:
        os.chown(p,account.pw_uid,account.pw_gid);p.chmod(0o755 if p.is_dir() else 0o644)
    wp('plugin','activate','seo-by-rank-math')
    seed=json.loads(wp('eval-file',str(runtime/'seo-0.7-seed.php'),str(runtime/'tools-roadmap.json')))
    need(len(seed['drafts'])==10 and seed['ready_tools']==0,'Draft preparation mismatch')
    phase='single consolidated staging verification'
    checks=wp('eval-file',str(runtime/'seo-0.7-check.php'),str(runtime/'tools-roadmap.json')).decode()
    # Script only prints fixed PASS labels; never raw PHP errors or option values.
    for line in checks.splitlines():
        if line.startswith('PASS: '): print(line)
    from html.parser import HTMLParser
    class Tags(HTMLParser):
        def __init__(self):super().__init__();self.canonical=0;self.descriptions=0;self.ogtitles=0;self.jsonld=0;self.noindex=False
        def handle_starttag(self,tag,attrs):
            a=dict(attrs)
            if tag=='link' and a.get('rel')=='canonical':self.canonical+=1
            if tag=='meta' and a.get('name')=='description':self.descriptions+=1
            if tag=='meta' and a.get('property')=='og:title':self.ogtitles+=1
            if tag=='meta' and a.get('name')=='robots':self.noindex='noindex' in a.get('content','')
            if tag=='script' and a.get('type')=='application/ld+json':self.jsonld+=1
    roadmap=json.loads((BUNDLE/'tools-roadmap.json').read_text())
    for path in ['/','/tools/','/wp-login.php','/news/','/analysis/','/guides/','/learning/','/topics/','/wp-json/wp/v2/editorial-formats']:
        need(http(path)[0]==401,'Anonymous staging access bypass')
        status,headers,body=http(path,basic)
        need(status==200 and 'noindex' in headers.get('X-Robots-Tag',''),'HTTP or noindex failure: '+path)
        if 'text/html' in headers.get('Content-Type',''):
            tags=Tags();tags.feed(body.decode('utf-8','replace'))
            need(tags.canonical<=1 and tags.descriptions<=1 and tags.ogtitles<=1 and tags.jsonld<=1,'Duplicate SEO output: '+path)
            if path in ['/','/tools/']:need(tags.noindex,'Rank Math robots missing')
        print('PASS: authenticated '+path+' HTTP 200; anonymous 401; noindex')
    for tool in roadmap:
        need(http(tool['url'],basic)[0]==404,'Unfinished tool should return 404')
    need(http('/cyberdat-seo-check-nonexistent/',basic)[0]==404,'Missing route should return 404')
    print('PASS: all 10 unfinished tools and nonexistent URL return real 404')
    for path in ['/wp-config.php','/.env','/wp-cron.php','/xmlrpc.php','/wp-content/uploads/forbidden.php']:
        need(http(path,basic)[0]==403,'Protected path unexpectedly accessible')
    # CookieJar module is aliased below because the request helper is named http.
    import http.cookiejar as cookies
    jar=cookies.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),LocalRedirect())
    http('/wp-login.php',basic,opener)
    form=urllib.parse.urlencode({'log':'cyberdat_staging_admin','pwd':admin,'wp-submit':'Log In','redirect_to':HOST+'/wp-admin/','testcookie':'1'}).encode()
    status,headers,body=http('/wp-login.php',basic,opener,form)
    need(status==200 and any(c.name.startswith('wordpress_logged_in_') for c in jar),'Staging administrator login failed')
    need(http('/wp-admin/',basic,opener)[0]==200,'Dashboard failure')
    print('PASS: existing staging administrator login/dashboard')
    for path in ['/sitemap_index.xml','/wp-sitemap.xml','/robots.txt']:
        need(http(path)[0]==401,'Sitemap/robots authentication bypass')
        status,headers,body=http(path,basic)
        need(status in (200,404),'Unexpected authenticated sitemap/robots status')
        if path.endswith('.xml') and status==200:
            import xml.etree.ElementTree as ET
            xml=ET.fromstring(body)
            need(xml.tag.rsplit('}',1)[-1] in ('sitemapindex','urlset'),'Invalid sitemap XML')
            need(not any(t['url'].encode() in body for t in roadmap),'Unfinished tool leaked into sitemap')
        print('PASS: protected '+path+' authenticated HTTP '+str(status))
    need(before==fingerprint(),'Protected production/staging configuration changed')
    with urllib.request.urlopen('https://cyberdat.eu/',timeout=45) as prod:need(prod.status==200,'Production HTTPS failed')
    print('PASS: production HTTPS 200; protected config fingerprints unchanged')
    verify_tree(THEME,source['files'])
    (backup/'COMPLETE').write_text('COMPLETE\n')
    print('PASS: staging SEO update complete; theme commit='+source['theme_commit'])
    print('URL: '+HOST+'/tools/')
    print('Rollback (staging only): sudo python3 '+str(BUNDLE/'update-seo-0.7.py')+' --rollback '+str(backup))
    print('UNVERIFIED: visual responsive/Gutenberg checks; no tool utility released')

def rollback(backup,before):
    global phase
    phase='explicit staging-only rollback'
    backup=backup.resolve()
    need(backup.parent==BACKUPS and backup.name.startswith('seo-0.7-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe rollback source')
    need((backup/'state.json').is_file() and (backup/'staging.sql.gz').stat().st_size>0,'Incomplete rollback snapshot')
    # Never touch production; restore only a verified, locally created staging snapshot.
    with tarfile.open(backup/'theme.tar.gz','r:gz') as archive:
        for member in archive.getmembers():need(not member.issym() and not member.islnk() and '..' not in P(member.name).parts and (member.name=='cyberdat' or member.name.startswith('cyberdat/')),'Unsafe rollback theme archive')
        tmp=ROOT.parent/('rollback-'+backup.name)
        need(not tmp.exists(),'Rollback temporary path exists')
        tmp.mkdir(mode=0o700);archive.extractall(tmp,filter='data')
    retained=ROOT.parent/('retained-after-'+backup.name)
    need(not retained.exists(),'Rollback retention path exists')
    os.rename(THEME,retained);os.rename(tmp/'cyberdat',THEME)
    account=pwd.getpwnam(USER)
    for p in [THEME,*THEME.rglob('*')]:os.chown(p,account.pw_uid,account.pw_gid);p.chmod(0o755 if p.is_dir() else 0o644)
    with (backup/'staging.sql.gz').open('rb') as source:
        unzip=subprocess.Popen(['/usr/bin/gzip','-dc'],stdin=source,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        result=subprocess.run(['/usr/bin/mariadb','--no-defaults','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--skip-password','cyberdat_staging'],stdin=unzip.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        unzip.stdout.close();need(result.returncode==0 and unzip.wait()==0,'Staging database rollback failed')
    # Keep plugin files for review; old active_plugins comes from the snapshot.
    need(before==fingerprint(),'Configuration changed during rollback')
    print('PASS: staging theme/database rollback; updated theme/plugin files retained; no production changes')

if __name__=='__main__':
    try:main()
    except BaseException as error:
        print('BLOCKED: phase='+phase)
        print('Error type: '+type(error).__name__)
        if isinstance(error,RuntimeError): print('Reason: '+str(error))
        print('No raw responses, credentials or logs printed. Do not rerun blindly; staging-only snapshot retained if created.')
        sys.exit(1)
