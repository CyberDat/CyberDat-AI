#!/usr/bin/env python3
"""Static contracts plus isolated nginx/FPM syntax checks. No service is started."""
from pathlib import Path
import subprocess,tempfile,os,pwd,grp,re,shutil
root=Path(__file__).resolve().parents[1];base=root/'deploy/staging';count=0

def check(label,ok):
 global count
 assert ok,label
 count+=1;print('PASS',label)

ng=(base/'nginx/staging.cyberdat.eu.conf.template').read_text();pool=(base/'php-fpm/cyberdat-staging.conf.template').read_text();wp=(base/'wordpress/wp-config.php.template').read_text();mu=(base/'wordpress/cyberdat-staging-safety.php.template').read_text();cron=(base/'cron.template').read_text()
check('Nginx has dedicated staging root/socket', 'root /var/www/cyberdat-staging/public;' in ng and 'unix:/run/php/php8.4-fpm-cyberdat-staging.sock;' in ng)
check('Nginx Basic Auth inherited without bypass',ng.count('auth_basic "')==1 and 'auth_basic off' not in ng and 'satisfy any' not in ng and 'allow ' not in ng)
check('Nginx PHP follows auth and receives server auth identity','fastcgi_param REMOTE_USER $remote_user;' in ng and '$http_remote_user' not in ng and 'fastcgi_param HTTP_AUTHORIZATION "";' in ng)
check('Nginx disallows aliases/symlinks/production paths','alias ' not in ng and 'disable_symlinks on;' in ng and '/var/www/cyberdat/public' not in ng)
check('Uploads PHP block precedes PHP handler',ng.index('^/wp-content/(?:uploads|cache)')<ng.index('location ~* \\.php$'))
check('Nginx hides configs, dotfiles, PHP variants','location ~ /\\.' in ng and 'wp-config' in ng and 'phtml|phar|php[0-9]+' in ng)
check('Nginx noindex applies to errors','X-Robots-Tag "noindex, nofollow" always;' in ng)
check('HTTP Cron and XMLRPC denied','location = /wp-cron.php { deny all; }' in ng and 'location = /xmlrpc.php { deny all; }' in ng)
check('FPM isolated identity, socket, memory and child count',all(x in pool for x in ['user = cyberdat-staging','group = cyberdat-staging','pm.max_children = 1','memory_limit] = 256M','request_terminate_timeout = 60s']))
check('FPM clears environment, disables shared OPcache and mail',all(x in pool for x in ['clear_env = yes','php_admin_flag[opcache.enable] = off','sendmail_path] = /bin/false','disable_functions] = mail']))
check('FPM basedir excludes production and has private temp/logs','open_basedir] = /var/www/cyberdat-staging:' in pool and '/var/www/cyberdat/public' not in pool and 'session.save_path] = /var/lib/cyberdat-staging/sessions' in pool)
check('WP live APIs explicitly off',"define('CYBERDAT_KEV_LIVE', false);" in wp and "define('CYBERDAT_NVD_LIVE', false);" in wp)
check('WP config is staging only, no Playground define',"define('WP_ENVIRONMENT_TYPE', 'staging');" in wp and not re.search(r"define\(['\"]CYBERDAT_PLAYGROUND",wp))
check('Private debug log and disabled HTTP cron',"define('DISABLE_WP_CRON', true);" in wp and "'/var/log/cyberdat-staging/wp-debug.log'" in wp and "define('WP_DEBUG_DISPLAY', false);" in wp)
check('WP CLI memory cannot be raised to web worker ceiling',wp.count("PHP_SAPI === 'cli' ? '128M' : '256M'")==2)
check('Cron restricted path, lock, deadline and no output',all(x in cron for x in ['cyberdat-staging /usr/bin/flock -n','55s','--path=/var/www/cyberdat-staging/public','>/dev/null 2>&1','-d opcache.enable_cli=0']))
check('No unresolved config can bootstrap WordPress',subprocess.run(['php8.4',str(base/'wordpress/wp-config.php.template')],capture_output=True,text=True).stdout=='Unconfigured staging template.')
backup=(base/'backup.md').read_text()
check('Backup fails pipelines, disables tracing, restricts files',all(x in backup for x in ['set +x','set -euo pipefail','umask 077','.gpg.partial','recipient_fpr']))
check('Backup encrypted before disk/offsite, restoration isolated',all(x in backup for x in ['| gzip -c','gpg --batch --encrypt','sha256sum -c SHA256SUMS','independent MariaDB instance','private decryption key stays off-VPS']))
# Scope is intended source/config/docs, not public compressed NVD/KEV data blobs.
scan=list(base.rglob('*'))+[root/'wp-content/themes/cyberdat/inc/preview-guard.php',Path(__file__),root/'tests/preview-guard-case.php',root/'tests/preview-guard.test.py']
private_key=re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')
api_secret=re.compile(r'(?:sk-[A-Za-z0-9]{24,}|AKIA[A-Z0-9]{16})')
for p in scan:
 if p.is_file():
  text=p.read_text();assert not private_key.search(text),str(p);assert not api_secret.search(text),str(p)
check('No private key blocks or known token patterns in new staging sources',True)
# Generated test key and logs exist only in this auto-removed project temporary directory.
os.umask(0o077)
with tempfile.TemporaryDirectory(prefix='.staging-config-test-',dir=root) as directory:
 t=Path(directory);(t/'public').mkdir();(t/'auth').write_text('fixture:*\n')
 openssl=shutil.which('openssl');nginx=shutil.which('nginx') or '/usr/sbin/nginx';fpm=shutil.which('php-fpm8.4') or '/usr/sbin/php-fpm8.4'
 assert openssl and Path(nginx).is_file() and Path(fpm).is_file(),'Required existing test binaries unavailable; do not install automatically'
 subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=staging.cyberdat.eu','-keyout',str(t/'key.pem'),'-out',str(t/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 test=ng.replace('/var/www/cyberdat-staging/public',str(t/'public')).replace('/etc/letsencrypt/live/staging.cyberdat.eu/fullchain.pem',str(t/'cert.pem')).replace('/etc/letsencrypt/live/staging.cyberdat.eu/privkey.pem',str(t/'key.pem')).replace('/etc/nginx/auth/cyberdat-staging.htpasswd',str(t/'auth')).replace('/var/log/nginx/cyberdat-staging.error.log',str(t/'nginx-error.log')).replace('listen 80;','listen 127.0.0.1:18080;').replace('listen [::]:80;','').replace('listen 443 ssl;','listen 127.0.0.1:18443 ssl;').replace('listen [::]:443 ssl;','')
 (t/'fastcgi_params').write_text('fastcgi_param REQUEST_METHOD $request_method;\nfastcgi_param QUERY_STRING $query_string;\n')
 (t/'nginx.conf').write_text('pid '+str(t/'nginx.pid')+';\nerror_log '+str(t/'main-error.log')+';\nevents { worker_connections 16; }\nhttp { access_log off;\n'+test+'\n}\n')
 q=subprocess.run([nginx,'-t','-p',str(t)+'/', '-c',str(t/'nginx.conf')],capture_output=True,text=True)
 check('Isolated Nginx parser accepts template', 'syntax is ok' in q.stderr)
 if q.returncode:
  assert 'socket()' in q.stderr and 'Operation not permitted' in q.stderr,q.stderr
  print('UNVERIFIED full nginx -t: sandbox denies test sockets; no escalation attempted')
 else:
  check('Full isolated nginx -t',True)
 user=pwd.getpwuid(os.getuid()).pw_name;group=grp.getgrgid(os.getgid()).gr_name
 p=pool.replace('user = cyberdat-staging','user = '+user).replace('group = cyberdat-staging','group = '+group).replace('/var/www/cyberdat-staging/public',str(t/'public')).replace('/run/php/php8.4-fpm-cyberdat-staging.sock',str(t/'test-fpm.sock')).replace('/var/log/cyberdat-staging',str(t)).replace('/var/lib/cyberdat-staging',str(t))
 (t/'fpm.conf').write_text('[global]\nerror_log = '+str(t/'fpm-error.log')+'\npid = '+str(t/'fpm.pid')+'\n'+p)
 q=subprocess.run([fpm,'-n','-t','-y',str(t/'fpm.conf')],capture_output=True,text=True)
 assert q.returncode==0,q.stderr
 check('Isolated php-fpm -n -t (one test pool, no master started)',True)
print(count,'staging template checks passed; temporary keys/configs removed')
