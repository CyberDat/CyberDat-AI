#!/usr/bin/env python3
"""One staging JS lifecycle fix; no reinstall, API ingestion, DB reset or timer changes."""
import argparse,datetime,fcntl,getpass,hashlib,importlib.util,json,os,pathlib,shutil,sys,tarfile,time,urllib.request
P=pathlib.Path;B=P(__file__).resolve().parent;phase='preflight'
def need(ok,text):
 if not ok:raise RuntimeError(text)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 global phase
 parser=argparse.ArgumentParser();g=parser.add_mutually_exclusive_group(required=True);g.add_argument('--finish',action='store_true');g.add_argument('--rollback',type=P);args=parser.parse_args();need(os.geteuid()==0,'Use owner sudo');os.umask(0o077);sys.dont_write_bytecode=True
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  h,name=line.split();p=B/name;need(p.resolve().parent==B and not p.is_symlink() and sha(p)==h,'Prepared bundle checksum mismatch')
 spec=importlib.util.spec_from_file_location('dialog_support',B/'support.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 identity=m.state();need(identity[:4]==['staging','cyberdat_staging',m.HOST,'cyberdat'] and str(identity[4])=='0','Wrong staging identity')
 target=m.THEME/'assets/js/threat-analytics.js';patch=json.loads((B/'patch.json').read_text());need(target.resolve()==target and sha(target) in [patch['before'],patch['after']] and sha(B/'threat-analytics.js')==patch['after'],'Installed JS conflict')
 protected=m.guards();research=m.research_code();timers=m.timer_fingerprints();logs=m.log_indicators()
 def other_theme():return {str(p.relative_to(m.THEME)):sha(p) for p in m.THEME.rglob('*') if p.is_file() and p!=target}
 module=m.ROOT/'wp-content/plugins/cyberdat-threat-analytics'
 def adapter():return {str(p.relative_to(module)):sha(p) for p in module.rglob('*') if p.is_file()}
 unchanged=other_theme();module_hashes=adapter();need(bool(module_hashes),'Analytics adapter missing');m.wp('plugin','is-active','cyberdat-threat-analytics')
 def valid(path):
  need(path.resolve()==path and path.parent==m.BACKUPS and path.name.startswith('analytics-2.1-dialog-') and path.stat().st_uid==0 and path.stat().st_mode&0o077==0,'Unsafe backup')
  saved=json.loads((path/'state.json').read_text());need(saved['before']==patch['before'] and saved['after']==patch['after'],'Backup release conflict')
  for name,h in saved['checksums'].items():need('/' not in name and sha(path/name)==h,'Backup checksum mismatch')
  need(saved['protected']==protected and saved['research']==research and saved['timers']==timers and saved['theme']==unchanged and saved['adapter']==module_hashes,'Backup protected baseline differs')
  return saved
 if args.rollback:
  valid(args.rollback);need(sha(args.rollback/'previous.js')==patch['before'],'Rollback source mismatch');m.atomic_copy(args.rollback/'previous.js',target);print('PASS: previous JS restored only; no SQL restore or data deletion');return
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and m.fetch('/',basic)[0]==200 and m.fetch('/')[0]==401,'Basic Auth preflight failed')
 if sha(target)==patch['before']:
  phase='private backup before one JS fix';need(m.BACKUPS.stat().st_uid==0 and m.BACKUPS.stat().st_mode&0o077==0 and shutil.disk_usage(m.BACKUPS).free>1024**3,'Unsafe backup parent/free space')
  backup=m.BACKUPS/('analytics-2.1-dialog-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));backup.mkdir(mode=0o700);m.database_backup(backup/'staging.sql.gz')
  with tarfile.open(backup/'theme.tar.gz','w:gz') as archive:archive.add(m.THEME,arcname='cyberdat')
  shutil.copyfile(target,backup/'previous.js');checksums={n:sha(backup/n) for n in ['staging.sql.gz','theme.tar.gz','previous.js']}
  saved={'commit':(B/'COMMIT').read_text().strip(),'before':patch['before'],'after':patch['after'],'checksums':checksums,'protected':protected,'research':research,'timers':timers,'theme':unchanged,'adapter':module_hashes};(backup/'state.json').write_text(json.dumps(saved));print('BACKUP: '+str(backup),flush=True);m.atomic_copy(B/'threat-analytics.js',target)
 else:
  matches=[p for p in sorted(m.BACKUPS.glob('analytics-2.1-dialog-*'),reverse=True) if (p/'state.json').is_file() and json.loads((p/'state.json').read_text()).get('after')==patch['after']];need(bool(matches),'Patched JS found without matching backup');backup=matches[0];valid(backup);print('PASS: existing fix/backup verified; no rewrite',flush=True)
 phase='bounded SQL and protected HTTP checks';deadline=time.monotonic()+190
 while any(m.unit('show','cyberdat-research@'+n+'.service','--property=ActiveState','--value').stdout.strip() in (b'active',b'activating') for n in m.NAMES):
  need(time.monotonic()<deadline,'Research job active; rerun --finish later without reinstall');time.sleep(3)
 report=m.proof()
 code,_,body=m.fetch('/wp-content/themes/cyberdat/assets/js/threat-analytics.js',basic);need(code==200 and hashlib.sha256(body).hexdigest()==patch['after'],'HTTP JS hash mismatch')
 for path,marker in [('/', 'data-threat-pulse="2.1"'),('/threat-intelligence/','data-analytics-dialog')]:
  code,h,body=m.fetch(path,basic);need(code==200 and marker in body.decode('utf-8','replace') and 'noindex' in h.get('X-Robots-Tag',''),'Protected page regression');need(m.fetch(path)[0]==401,'Basic Auth changed')
 need(identity==m.state() and protected==m.guards() and research==m.research_code() and timers==m.timer_fingerprints() and unchanged==other_theme() and module_hashes==adapter(),'Protected code/config changed')
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production HTTPS health failed')
 after=m.log_indicators();need(len(after)>=2,'Expected staging logs missing')
 for path,values in after.items():
  for kind,n in values.items():need(n<=logs.get(path,{}).get(kind,0),'New PHP/Nginx '+kind+' indicator')
 (backup/'evidence.json').write_text(json.dumps(report));(backup/'COMPLETE').write_text('COMPLETE\n')
 print('PASS: one JS close-event guard deployed; SQL aggregates match; authenticated pages/JS 200; anonymous 401; noindex preserved')
 print('PASS: other theme files, analytics adapter, Research, timers and protected configuration hashes unchanged; production HTTPS 200')
 print('COMMIT: '+(B/'COMMIT').read_text().strip());print('BACKUP: '+str(backup));print('UNVERIFIED: real browser race/interaction acceptance; rerun the existing Windows capture helper, no re-download required')
 print('RESUME: sudo /usr/bin/python3 -I '+str(B/'fix-dialog.py')+' --finish');print('ROLLBACK JS ONLY: sudo /usr/bin/python3 -I '+str(B/'fix-dialog.py')+' --rollback '+str(backup))
if __name__=='__main__':
 try:main()
 except BaseException as e:
  print('BLOCKED: phase='+phase+'; type='+type(e).__name__)
  if isinstance(e,RuntimeError):print('Reason: '+str(e))
  print('Retain backup/partial state; no raw credentials/responses, reinstall, automatic rollback, checkpoint reset or timer action.');sys.exit(1)
