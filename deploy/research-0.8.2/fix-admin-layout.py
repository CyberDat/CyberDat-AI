#!/usr/bin/env python3
"""Staging-only admin rendering/CSS patch. No ingestion, schema or timer changes."""
import argparse,datetime,fcntl,getpass,hashlib,importlib.util,json,os,pathlib,pwd,shutil,sys,tarfile,urllib.request
P=pathlib.Path;B=P(__file__).resolve().parent
phase='preflight'
def need(ok,reason):
 if not ok:raise RuntimeError(reason)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 global phase
 parser=argparse.ArgumentParser();mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument('--apply',action='store_true');mode.add_argument('--verify',type=P);mode.add_argument('--rollback',type=P);args=parser.parse_args()
 need(os.geteuid()==0,'Use owner interactive sudo');os.umask(0o077);sys.dont_write_bytecode=True
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  h,name=line.split(maxsplit=1);p=B/name;need(p.resolve().is_relative_to(B) and not p.is_symlink() and sha(p)==h,'Bundle checksum mismatch')
 spec=importlib.util.spec_from_file_location('admin_ui_support',B/'support.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 need(m.state()[:5]==['staging','cyberdat_staging',m.HOST,'cyberdat','0'],'Wrong staging identity')
 patch=json.loads((B/'patch.json').read_text());php=m.PLUGIN/'includes/discovery-admin.php';css=m.PLUGIN/'assets/discovery-admin.css'
 def other_code():return {str(p.relative_to(m.PLUGIN)):sha(p) for p in m.PLUGIN.rglob('*') if p.is_file() and p not in [php,css]}
 def theme():return {str(p.relative_to(m.THEME)):sha(p) for p in m.THEME.rglob('*') if p.is_file()}
 protected=m.guards();timers=m.timer_fingerprints();others=other_code();theme_hashes=theme();logs=m.log_indicators()
 m.run(['/usr/bin/php8.4','-l',str(B/'discovery-admin.php')])
 backup=args.verify or args.rollback
 if backup:
  need(backup.resolve()==backup and backup.parent==m.BACKUPS and backup.name.startswith('research-admin-ui-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe backup')
  state=json.loads((backup/'state.json').read_text());need(state['commit']==(B/'COMMIT').read_text().strip() and state['protected']==protected and state['timers']==timers and state['other_code']==others and state['theme']==theme_hashes,'Backup/protected baseline changed')
  for name,h in state['checksums'].items():need('/' not in name and sha(backup/name)==h,'Backup checksum mismatch')
 if args.rollback:
  need(sha(php)==patch['after'] and sha(backup/'previous-admin.php')==patch['before'],'Rollback conflict');m.atomic_copy(backup/'previous-admin.php',php);print('PASS: previous admin PHP restored; unused CSS retained; no data restore, source or timer change');return
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and m.fetch('/',basic)[0]==200 and m.fetch('/')[0]==401,'Basic Auth verification failed')
 if args.apply:
  need(php.resolve()==php and sha(php)==patch['before'] and not css.exists(),'Installed admin release conflict; do not reapply')
  need(m.BACKUPS.stat().st_uid==0 and m.BACKUPS.stat().st_mode&0o077==0 and shutil.disk_usage(m.BACKUPS).free>1024**3,'Unsafe backup parent or low disk')
  phase='private backup before two admin UI files'
  backup=m.BACKUPS/('research-admin-ui-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));backup.mkdir(mode=0o700);m.database_backup(backup/'staging.sql.gz')
  with tarfile.open(backup/'research.tar.gz','w:gz') as archive:archive.add(m.PLUGIN,arcname='cyberdat-research')
  shutil.copyfile(php,backup/'previous-admin.php');state={'commit':(B/'COMMIT').read_text().strip(),'protected':protected,'timers':timers,'other_code':others,'theme':theme_hashes,'checksums':{n:sha(backup/n) for n in ['staging.sql.gz','research.tar.gz','previous-admin.php']}};(backup/'state.json').write_text(json.dumps(state));print('BACKUP: '+str(backup),flush=True)
  if not css.parent.exists():css.parent.mkdir(mode=0o755);account=pwd.getpwnam('cyberdat-staging');os.chown(css.parent,account.pw_uid,account.pw_gid)
  need(css.parent.resolve()==css.parent,'Unsafe assets directory');m.atomic_copy(B/'discovery-admin.css',css);m.atomic_copy(B/'discovery-admin.php',php)
 phase='admin asset and regression verification'
 need(sha(php)==patch['after'] and sha(css)==patch['css'],'Installed file hash mismatch')
 code,headers,body=m.fetch('/wp-content/plugins/cyberdat-research/assets/discovery-admin.css',basic);need(code==200 and hashlib.sha256(body).hexdigest()==patch['css'],'CSS HTTP/hash verification failed')
 need(m.fetch('/wp-content/plugins/cyberdat-research/assets/discovery-admin.css')[0]==401,'Anonymous asset access changed')
 for path,marker in [('/',b'data-threat-pulse="2.1"'),('/threat-intelligence/',b'data-analytics-dialog')]:
  code,headers,body=m.fetch(path,basic);need(code==200 and marker in body and 'noindex' in headers.get('X-Robots-Tag',''),'Protected homepage/Dashboard regression')
 m.admin_check(basic)
 need(protected==m.guards() and timers==m.timer_fingerprints() and others==other_code() and theme_hashes==theme(),'Unexpected non-UI code/theme/config/timer change')
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production health failed')
 for path,values in m.log_indicators().items():
  for kind,n in values.items():need(n<=logs.get(path,{}).get(kind,0),'New PHP/Nginx '+kind+' indicator')
 (backup/'COMPLETE').write_text('COMPLETE\n');print('PASS: two admin UI files only; public theme, other Research code, protected configuration and timers unchanged; production HTTPS 200')
 print('COMMIT: '+(B/'COMMIT').read_text().strip());print('BACKUP: '+str(backup));print('UNVERIFIED: actual 768/320 browser layout; rerun capture-research.py on ordinary Windows CMD')
if __name__=='__main__':
 try:main()
 except BaseException as e:
  print('BLOCKED: phase='+phase+'; type='+type(e).__name__)
  if isinstance(e,RuntimeError):print('Reason: '+str(e))
  print('No raw credentials or logs printed. Retain backup and partial state; no blind reapply or destructive rollback.');sys.exit(1)
