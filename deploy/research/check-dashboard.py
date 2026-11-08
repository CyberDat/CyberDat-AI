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

def proof():
 code=(B/'dashboard-proof.php').read_text();need(code.startswith('<?php'),'Invalid proof code');return json.loads(wp('eval',code[5:]).stdout)

def html_proof(report,body):
 import re
 text=body.decode('utf-8','replace')
 need('data-research-status' in text,'No unified provider marker in HTML')
 need('OFFICIAL SNAPSHOT · NOT LIVE' not in text and 'NVD SNAPSHOT · NOT LIVE' not in text,'Snapshot label still rendered')
 for sample in report['samples']:need(sample['cve'] in text,'Database CVE not present in Dashboard HTML')
 need('Indexed CVEs: '+str(report['projection_indexed']) in text,'Indexed NVD count missing from HTML')
 loaded=re.search(r'data-nvd-loaded="(\d+)"',text);need(loaded and int(loaded.group(1))==report['kev_matched_nvd'],'HTML chart/DB subset mismatch')
 for name,health in report['health'].items():
  if health['last_success']:need(datetime.datetime.fromtimestamp(health['last_success'],datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S') in text,'Last Successful Sync missing from HTML')
 return text

def main():
 global phase
 parser=argparse.ArgumentParser();parser.add_argument('--apply-labels',action='store_true');parser.add_argument('--rollback-labels',type=P);args=parser.parse_args();need((args.apply_labels!=bool(args.rollback_labels)) and os.geteuid()==0,'Choose --apply-labels or --rollback-labels with owner sudo');os.umask(0o077)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  expected,name=line.split(maxsplit=1);p=B/name;need(p.resolve().is_relative_to(B) and not p.is_symlink() and sha(p)==expected,'Proof bundle checksum mismatch')
 before=state();need(before[:4]==['staging','cyberdat_staging',HOST,'cyberdat'] and str(before[4])=='0','Wrong staging identity');protected=guards()
 if args.rollback_labels:
  phase='explicit staging two-file rollback';backup=args.rollback_labels.resolve();need(backup.parent==BACKUPS and backup.name.startswith('dashboard-labels-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe rollback path');entries=json.loads((backup/'patch.json').read_text());account=pwd.getpwnam('cyberdat-staging')
  for i,entry in enumerate(entries):
   target=ROOT/entry['target'];need(target.resolve()==target and target.is_relative_to(ROOT) and sha(target) in [entry['before'],entry['after']] and sha(backup/str(i))==entry['saved_sha256'],'Rollback conflict');temporary=target.with_name(target.name+'.dashboard-rollback');need(not temporary.exists(),'Rollback temporary file exists');shutil.copyfile(backup/str(i),temporary);os.chown(temporary,account.pw_uid,account.pw_gid);temporary.chmod(0o644);os.replace(temporary,target)
  need(protected==guards(),'Protected configuration changed');print('PASS: only two staging display files restored; DB, timers and caches untouched');return

 targets=json.loads((B/'patch.json').read_text());
 for entry in targets:
  target=ROOT/entry['target'];need(target.resolve()==target and sha(target)==entry['before'],'Unexpected installed file change')
 phase='read-only database and current rendered-data comparison'
 report=proof();need(report['provider_active'] and report['provider_store']=='research_database_projection' and report['snapshot_selected'] is False,'Provider is not live DB; stop before cosmetic changes')
 need(report['database_kev_active']==report['catalog_kev'] and report['database_nvd']==report['projection_indexed'],'Projection differs from database; possible running sync, stop without cache flush')
 need(all(s['database_kev_match'] and (not s['nvd_loaded'] or s['nvd_database_metric_match'])for s in report['samples']),'Sample CVE values differ between SQL and provider')
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(bool(basic),'Basic Auth required')
 status,headers,body=fetch('/',basic);need(status==200 and 'noindex' in headers.get('X-Robots-Tag',''),'HTTP/noindex check failed');html_proof(report,body)
 print('PASS: SQL/provider/HTML match; actual source is Research Agent database, not legacy snapshot')
 print('EVIDENCE BEFORE: '+json.dumps(report));print('HTTP CACHE HEADERS: '+json.dumps({k:headers.get(k) for k in ['Age','Cache-Control','X-Cache','X-Fastcgi-Cache','Date']}))
 phase='private two-file backup and limited label update'
 need(BACKUPS.is_dir() and BACKUPS.stat().st_uid==0 and BACKUPS.stat().st_mode&0o077==0,'Unsafe backup parent')
 stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');backup=BACKUPS/('dashboard-labels-'+stamp);backup.mkdir(mode=0o700);account=pwd.getpwnam('cyberdat-staging')
 for i,entry in enumerate(targets):
  target=ROOT/entry['target'];shutil.copyfile(target,backup/str(i));entry['saved_sha256']=sha(backup/str(i))
 (backup/'patch.json').write_text(json.dumps(targets));(backup/'proof-before.json').write_text(json.dumps(report))
 for entry in targets:
  target=ROOT/entry['target'];candidate=B/entry['candidate'];need(sha(candidate)==entry['after'],'Candidate checksum mismatch');temporary=target.with_name(target.name+'.dashboard-partial');need(not temporary.exists(),'Unexpected patch temporary file');shutil.copyfile(candidate,temporary);os.chown(temporary,account.pw_uid,account.pw_gid);temporary.chmod(0o644);os.replace(temporary,target)
 phase='verify clarified subset labels and unchanged data'
 fresh=proof();status,headers,body=fetch('/',basic);need(status==200,'Updated homepage failed');text=html_proof(fresh,body)
 need('data-nvd-indexed="'+str(fresh['database_nvd'])+'"' in text and 'KEV MATCHES' in text and 'This chart: '+str(fresh['kev_matched_nvd'])+' KEV-linked CVEs' in text,'Clarified chart labels not rendered')
 need(fetch('/')[0]==401,'Basic Auth protection changed');need(fetch('/tools/',basic)[0]==200,'Tools availability changed');need(protected==guards() and before==state(),'Protected state changed')
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30)as response:need(response.status==200,'Production HTTPS failed')
 (backup/'COMPLETE').write_text('COMPLETE\n');print('PASS: updated chart distinguishes KEV subset, total indexed NVD and full CISA; no imports or cache clears')
 print('EVIDENCE AFTER: '+json.dumps(fresh));print('BACKUP: '+str(backup));print('COMMIT: '+(B/'COMMIT').read_text().strip());print('PASS: production HTTPS 200; protected configurations unchanged; staging anonymous 401/noindex')
 print('URL: '+HOST);print('ROLLBACK: sudo /usr/bin/python3 -I '+str(B/'check-dashboard.py')+' --rollback-labels '+str(backup))

if __name__=='__main__':
 try:main()
 except BaseException as error:
  print('BLOCKED: phase='+phase);print('Error type: '+type(error).__name__)
  if isinstance(error,RuntimeError):print('Reason: '+str(error))
  print('No raw logs, credentials or API responses printed. Any partial staging state/snapshot retained; do not rerun blindly.');sys.exit(1)
