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
"""Owner-run theme-only homepage update. Never call the staging installer or Research sync."""
import argparse,datetime,fcntl,getpass,hashlib,html.parser,importlib.util,json,os,pathlib,shutil,sys,tarfile,time,urllib.request
P=pathlib.Path;B=P(__file__).resolve().parent;phase='preflight'
def need(ok,message):
 if not ok:raise RuntimeError(message)
def sha(p):return hashlib.sha256(P(p).read_bytes()).hexdigest()
def load_support():
 spec=importlib.util.spec_from_file_location('pulse_support',B/'support.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
class PulseHTML(html.parser.HTMLParser):
 def __init__(self):super().__init__(convert_charrefs=True);self.kpis={};self.series={};self.tips=[];self.links=[];self.css=[];self.js=[]
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if 'data-pulse-kpi' in a:self.kpis[a['data-pulse-kpi']]=int(a['data-value'])
  if 'data-pulse-series' in a:self.series[a['data-series-source']]=json.loads(a['data-pulse-series'])
  if 'data-pulse-tip' in a:self.tips.append(a['data-pulse-tip'])
  if tag=='a':self.links.append(a.get('href'))
  if tag=='link':self.css.append(a.get('href',''))
  if tag=='script':self.js.append(a.get('src',''))
def safe_backup(path,m):
 need(path.parent==m.BACKUPS and path.name.startswith('home-pulse-2.0-') and path.resolve()==path and path.stat().st_uid==0 and path.stat().st_mode&0o077==0,'Unsafe backup path')
 saved=json.loads((path/'state.json').read_text());need(saved['commit']==(B/'COMMIT').read_text().strip(),'Backup commit conflict')
 for name,value in saved['checksums'].items():need('/' not in name and sha(path/name)==value,'Backup integrity mismatch')
 return saved

def main():
 global phase
 parser=argparse.ArgumentParser();actions=parser.add_mutually_exclusive_group(required=True);actions.add_argument('--apply',action='store_true');actions.add_argument('--verify',type=P);actions.add_argument('--rollback',type=P);args=parser.parse_args();need(os.geteuid()==0,'Run through owner sudo');os.umask(0o077)
 with (B/'BUNDLE-SHA256SUMS').open() as stream:
  for line in stream:
   checksum,name=line.split();p=B/name;need(p.resolve().parent==B and not p.is_symlink() and sha(p)==checksum,'Bundle checksum mismatch')
 m=load_support();lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 identity=m.state();need(identity[:4]==['staging','cyberdat_staging',m.HOST,'cyberdat'] and str(identity[4])=='0','Wrong staging identity')
 protected=m.guards();research=m.research_code();timers=m.timer_fingerprints();before_logs=m.log_indicators();targets=json.loads((B/'patch.json').read_text());target_names={x['target'] for x in targets}
 # All other theme files, including full Dashboard, charts, map, navigation and SEO, are protected.
 def untouched():return {str(p.relative_to(m.ROOT)):sha(p) for p in m.THEME.rglob('*') if p.is_file() and str(p.relative_to(m.ROOT)) not in target_names}
 untouched_before=untouched()
 for entry in targets:
  target=m.ROOT/entry['target'];need(target.resolve()==target and target.is_relative_to(m.THEME),'Unsafe theme target');need(sha(B/entry['candidate'])==entry['after'],'Candidate mismatch')
  if args.apply:need((not target.exists()) if entry['before'] is None else sha(target)==entry['before'],'Installed file conflict; do not reapply')
  elif args.verify:need(target.is_file() and sha(target)==entry['after'],'Installed file conflict')
  else:need(target.is_file() and sha(target)==entry['after'],'Rollback conflict')
  if entry['target'].endswith('.php'):m.run(['/usr/bin/php8.4','-l',str(B/entry['candidate'])])
 backup=args.verify or args.rollback;saved=safe_backup(backup,m) if backup else None
 if saved:need(saved['protected']==protected and saved['research']==research and saved['timers']==timers and saved['untouched']==untouched_before,'Protected baseline changed since backup')
 if args.rollback:
  phase='explicit theme-only rollback'
  for i,entry in enumerate(targets):
   if entry['before'] is not None:need(sha(backup/str(i))==entry['before'],'Rollback source mismatch')
  for i,entry in enumerate(targets):
   if entry['before'] is not None:m.atomic_copy(backup/str(i),m.ROOT/entry['target'])
  need(protected==m.guards() and research==m.research_code() and timers==m.timer_fingerprints() and untouched_before==untouched(),'Protected files changed')
  print('PASS: prior homepage restored; inert new helper/assets retained; no SQL restore, deletions or timer operations');return
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(bool(basic) and m.fetch('/',basic)[0]==200 and m.fetch('/')[0]==401,'Basic Auth check failed')
 if args.apply:
  phase='backup before theme writes';need(m.BACKUPS.is_dir() and m.BACKUPS.stat().st_uid==0 and m.BACKUPS.stat().st_mode&0o077==0 and shutil.disk_usage(m.BACKUPS).free>1024**3,'Unsafe backup parent or less than 1 GiB free')
  backup=m.BACKUPS/('home-pulse-2.0-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));backup.mkdir(mode=0o700);m.database_backup(backup/'staging.sql.gz')
  with tarfile.open(backup/'theme.tar.gz','w:gz') as archive:archive.add(m.THEME,arcname='cyberdat')
  checksums={name:sha(backup/name) for name in ['staging.sql.gz','theme.tar.gz']}
  for i,entry in enumerate(targets):
   if entry['before'] is not None:shutil.copyfile(m.ROOT/entry['target'],backup/str(i));checksums[str(i)]=sha(backup/str(i))
  saved={'commit':(B/'COMMIT').read_text().strip(),'checksums':checksums,'protected':protected,'research':research,'timers':timers,'untouched':untouched_before};(backup/'state.json').write_text(json.dumps(saved));print('BACKUP: '+str(backup),flush=True)
  phase='theme-only atomic file replacements'
  # Dependencies first, functions/assets bootstrap last. No new directories are required.
  for entry in sorted(targets,key=lambda e:e['target'].endswith(('functions.php','inc/assets.php'))):m.atomic_copy(B/entry['candidate'],m.ROOT/entry['target'])
 phase='one consolidated SQL/HTTP/protection check'
 # Wait only; no stop/restart/disable requests for any Research job or timer.
 deadline=time.monotonic()+190
 while any(m.unit('show','cyberdat-research@'+n+'.service','--property=ActiveState','--value').stdout.strip() in (b'active',b'activating') for n in m.NAMES):
  need(time.monotonic()<deadline,'Research job still active; run --verify later');time.sleep(3)
 report=m.proof();evidence=json.loads(m.wp('eval',(B/'pulse-evidence.php').read_text()[5:]).stdout)
 need(evidence['counts']==report['counts'] and evidence['severity']==report['severity'],'Projection changed during proof; verify later')
 for source in ['kev','nvd']:
  for days in ['7','30','90']:
   p=evidence['periods'][source][days];need(p and p['total']==report['chart_totals'][source][days],'Pulse period differs from independent SQL')
 code,headers,body=m.fetch('/',basic);text=body.decode('utf-8','replace');parsed=PulseHTML();parsed.feed(text)
 need(code==200 and 'noindex' in headers.get('X-Robots-Tag','') and 'data-threat-pulse="2.0"' in text,'Homepage unavailable/noindex missing')
 need(parsed.kpis=={k:report['counts'][k] for k in ['critical','nvd_7','kev','ransomware']},'Pulse KPI mismatch')
 need(parsed.series==evidence['series'],'Rendered daily series differs from SQL-verified projection')
 need('data-threat-dashboard' not in text and 'data-threat-map' not in text and 'partial local coverage' in text,'Homepage scope/coverage failed')
 for label,count in report['severity'].items():
  expected=label+' · '+format(count,',')+' · '+format(100*count/max(1,report['counts']['nvd']),'.1f')+'%';need(expected in parsed.tips,'Severity tooltip count/share mismatch')
 for source in ['kev','nvd']:need(evidence['sync'][source]['at'] in text and evidence['sync'][source]['status'] in text,'Source sync label missing')
 need(m.HOST+'/threat-intelligence/' in parsed.links,'Explore link missing')
 if evidence['signal']:need(evidence['signal']['url'] in parsed.links,'Selected signal source link missing')
 need(any('/assets/js/threat-pulse.js' in s for s in parsed.js) and any('/assets/css/threat-pulse.css' in s for s in parsed.css),'Homepage assets not enqueued')
 for path in ['/wp-content/themes/cyberdat/assets/js/threat-pulse.js','/wp-content/themes/cyberdat/assets/css/threat-pulse.css','/tools/','/wp-login.php']:
  need(m.fetch(path,basic)[0]==200,'Existing route/asset failed')
 code,h,b=m.fetch('/threat-intelligence/',basic);full=b.decode('utf-8','replace');need(code==200 and 'data-threat-dashboard="2.0"' in full and full.count('data-chart-id=')==6 and 'data-threat-map' in full and '/assets/js/threat-pulse.js' not in full,'Full Dashboard regression')
 m.verify_description(full)
 need(m.fetch('/threat-intelligence/')[0]==401 and m.fetch('/')[0]==401,'Anonymous protection changed')
 need(identity==m.state() and protected==m.guards() and research==m.research_code() and timers==m.timer_fingerprints() and untouched_before==untouched(),'Protected files changed')
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production HTTPS check failed')
 after=m.log_indicators();need(len(after)>=2,'Expected staging logs unavailable')
 for path,counts in after.items():
  for kind,count in counts.items():need(count<=before_logs.get(path,{}).get(kind,0),'New PHP/Nginx '+kind+' indicator')
 (backup/'evidence.json').write_text(json.dumps({'pulse':evidence,'independent_sql':report,'protected_files_unchanged':True}));(backup/'COMPLETE').write_text('COMPLETE\n')
 print('PASS: four KPIs, 180 daily series points and 7/30/90 subsets match independent SQL; six severity shares and source signal verified')
 print('PASS: full Dashboard/map/six charts/SEO preserved; Basic Auth/noindex; two logs checked; Research code/timer/protected hashes unchanged; production HTTPS 200')
 print('EVIDENCE: '+json.dumps(evidence));print('COMMIT: '+(B/'COMMIT').read_text().strip());print('BACKUP: '+str(backup));print('URL: '+m.HOST+'/')
 print('UNVERIFIED: real browser 320/768/1440/1920 screenshots, period clicks, touch/keyboard and JS console. Run capture-pulse.py on Windows. No imports, queue writes, timer operations or production changes.')
 print('VERIFY: sudo /usr/bin/python3 -I '+str(B/'deploy-pulse.py')+' --verify '+str(backup));print('ROLLBACK: sudo /usr/bin/python3 -I '+str(B/'deploy-pulse.py')+' --rollback '+str(backup))
if __name__=='__main__':
 try:main()
 except BaseException as error:
  print('BLOCKED: phase='+phase);print('Error type: '+type(error).__name__)
  if isinstance(error,RuntimeError):print('Reason: '+str(error))
  print('No credentials/raw responses printed; retain backup and partial state. Do not rerun --apply blindly. No destructive cleanup or automatic rollback.');sys.exit(1)
