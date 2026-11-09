#!/usr/bin/env python3
"""Staging-only read adapter + UI update, backup before installation, no Research/scheduler writes."""
import argparse,datetime,fcntl,getpass,hashlib,html.parser,importlib.util,json,os,pathlib,pwd,shutil,sys,tarfile,time,urllib.parse,urllib.request
P=pathlib.Path;B=P(__file__).resolve().parent;phase='preflight'
def need(ok,text):
 if not ok:raise RuntimeError(text)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class PulseHTML(html.parser.HTMLParser):
 def __init__(self):super().__init__(convert_charrefs=True);self.model=None;self.values={}
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if 'data-pulse-periods' in a:self.model=json.loads(a['data-pulse-periods'])
  if 'data-pulse-kpi' in a:self.values[a['data-pulse-kpi']]=int(a['data-value'])
def main():
 global phase
 parser=argparse.ArgumentParser();a=parser.add_mutually_exclusive_group(required=True);a.add_argument('--apply',action='store_true');a.add_argument('--verify',type=P);a.add_argument('--rollback',type=P);args=parser.parse_args();need(os.geteuid()==0,'Use owner sudo');os.umask(0o077);sys.dont_write_bytecode=True;os.nice(10)
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  h,name=line.split();p=B/name;need(p.resolve().parent==B and not p.is_symlink() and sha(p)==h,'Bundle mismatch')
 spec=importlib.util.spec_from_file_location('analytics_support',B/'support.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 identity=m.state();need(identity[:4]==['staging','cyberdat_staging',m.HOST,'cyberdat'] and str(identity[4])=='0','Wrong environment')
 targets=json.loads((B/'patch.json').read_text());names={e['target'] for e in targets};module=m.ROOT/'wp-content/plugins/cyberdat-threat-analytics'
 protected=m.guards();research=m.research_code();timers=m.timer_fingerprints();logs=m.log_indicators()
 def untouched():return {str(p.relative_to(m.ROOT)):sha(p) for p in m.THEME.rglob('*') if p.is_file() and str(p.relative_to(m.ROOT)) not in names}
 unchanged=untouched();backup=args.verify or args.rollback
 if args.apply:need(not module.exists(),'Analytics module already exists; do not reinstall')
 for e in targets:
  p=m.ROOT/e['target'];need(p.resolve()==p and (p.is_relative_to(m.THEME) or p.is_relative_to(module)),'Unsafe target')
  need(sha(B/e['candidate'])==e['after'],'Candidate mismatch')
  if args.apply:need((not p.exists()) if e['before'] is None else sha(p)==e['before'],'Installed baseline conflict')
  else:need(p.is_file() and sha(p)==e['after'],'Installed file conflict')
  if e['target'].endswith('.php'):m.run(['/usr/bin/php8.4','-l',str(B/e['candidate'])])
 if backup:
  need(backup.resolve()==backup and backup.parent==m.BACKUPS and backup.name.startswith('analytics-2.1-') and backup.stat().st_uid==0 and backup.stat().st_mode&0o077==0,'Unsafe backup')
  saved=json.loads((backup/'state.json').read_text());need(saved['commit']==(B/'COMMIT').read_text().strip(),'Backup release conflict')
  for name,h in saved['checksums'].items():need('/' not in name and sha(backup/name)==h,'Backup checksum mismatch')
  need(saved['protected']==protected and saved['research']==research and saved['timers']==timers and saved['unchanged']==unchanged,'Protected files changed since backup')
 if args.rollback:
  phase='explicit UI/module rollback; no database restore'
  m.wp('plugin','deactivate','cyberdat-threat-analytics')
  for i,e in enumerate(targets):
   if e['before'] is not None:need(sha(backup/str(i))==e['before'],'Saved file mismatch');m.atomic_copy(backup/str(i),m.ROOT/e['target'])
  print('PASS: previous theme restored; new module inactive; inert files/cache/backups retained; no Research, scheduler or SQL restore');return
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and m.fetch('/',basic)[0]==200 and m.fetch('/')[0]==401,'Basic Auth failed')
 if args.apply:
  phase='private backup before any module/theme installation';need(m.BACKUPS.stat().st_uid==0 and m.BACKUPS.stat().st_mode&0o077==0 and shutil.disk_usage(m.BACKUPS).free>1024**3,'Unsafe backup location or low disk')
  backup=m.BACKUPS/('analytics-2.1-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));backup.mkdir(mode=0o700);m.database_backup(backup/'staging.sql.gz')
  with tarfile.open(backup/'theme.tar.gz','w:gz') as arc:arc.add(m.THEME,arcname='cyberdat')
  checksums={n:sha(backup/n) for n in ['staging.sql.gz','theme.tar.gz']}
  for i,e in enumerate(targets):
   if e['before'] is not None:shutil.copyfile(m.ROOT/e['target'],backup/str(i));checksums[str(i)]=sha(backup/str(i))
  saved={'commit':(B/'COMMIT').read_text().strip(),'checksums':checksums,'protected':protected,'research':research,'timers':timers,'unchanged':unchanged};(backup/'state.json').write_text(json.dumps(saved));print('BACKUP: '+str(backup),flush=True)
  phase='install separate read adapter, then UI assets/templates';account=pwd.getpwnam('cyberdat-staging');module.mkdir(mode=0o755);os.chown(module,account.pw_uid,account.pw_gid)
  for e in targets:
   if '/plugins/' in e['target']:m.atomic_copy(B/e['candidate'],m.ROOT/e['target'])
  m.wp('plugin','activate','cyberdat-threat-analytics')
  for e in sorted(targets,key=lambda x:('/template-parts/' in x['target'] or x['target'].endswith('/inc/assets.php'))):
   if '/themes/' in e['target']:m.atomic_copy(B/e['candidate'],m.ROOT/e['target'])
 phase='single consolidated read-only SQL/endpoint/SEO smoke test';deadline=time.monotonic()+190
 while any(m.unit('show','cyberdat-research@'+n+'.service','--property=ActiveState','--value').stdout.strip() in (b'active',b'activating') for n in m.NAMES):
  need(time.monotonic()<deadline,'Research job busy; verify later, no restart');time.sleep(3)
 base=m.proof();result=m.wp('eval',(B/'proof.php').read_text()[5:],check=False)
 if result.returncode:
  import re
  codes=re.findall(rb'(?:CDRA_Error|RuntimeException|InvalidArgumentException|UnexpectedValueException): ([a-z_0-9]+)',result.stderr)
  raise RuntimeError('Read-only analytics proof failed; code='+(','.join(c.decode() for c in codes[:3]) or 'unavailable'))
 report=json.loads(result.stdout)
 code,h,b=m.fetch('/',basic);text=b.decode('utf-8','replace');home=PulseHTML();home.feed(text)
 need(code==200 and 'data-threat-pulse="2.1"' in text and 'noindex' in h.get('X-Robots-Tag',''),'Homepage/guard missing')
 need(home.values==report['periods']['7']['counts'],'Initial four KPIs differ from SQL')
 for days in ['7','30','90']:need(home.model['periods'][days]==report['periods'][days],'Period data differs from SQL')
 endpoint='/wp-json/cyberdat-analytics/v1/records'
 for key,total in report['chart_counts'].items():
  group,value=key.split(':',1);query=urllib.parse.urlencode({'group':group,'value':value,'per_page':5,'revision':report['revision']});code,h,b=m.fetch(endpoint+'?'+query,basic);data=json.loads(b)
  need(code==200 and data['total']==total and len(data['items'])<=5,'Drill endpoint/SQL mismatch '+key)
  for row in data['items']:need(set(row)=={'id','title','description','source','source_name','url','published','date_added','score','cvss_version','severity'},'Unexpected public fields')
 need(m.fetch(endpoint,basic,data=b'{}')[0] in (404,405),'Write route unexpectedly accepted')
 for q in ['per_page=51','page=601','sort=RAND%28%29','q=%27%20OR%201%3D1','group=day&value=nvd&date=2026-02-30&days=7']:
  need(m.fetch(endpoint+'?'+q,basic)[0]==400,'Invalid query accepted')
 need(m.fetch(endpoint+'?revision='+'0'*64,basic)[0]==409,'Revision mismatch not rejected')
 need(m.fetch(endpoint)[0]==401 and m.fetch('/threat-intelligence/')[0]==401,'Anonymous route opened')
 code,h,b=m.fetch('/threat-intelligence/',basic);full=b.decode('utf-8','replace');need(code==200 and full.count('data-chart-id=')==6 and 'data-analytics-endpoint=' in full and 'data-threat-map' in full and 'data-analytics-dialog' in full and 'noindex' in h.get('X-Robots-Tag',''),'Dashboard components missing');m.verify_description(full)
 for path in ['/tools/','/news/','/analysis/','/guides/','/learning/','/topics/','/wp-content/themes/cyberdat/assets/js/threat-analytics.js','/wp-content/themes/cyberdat/assets/css/threat-analytics.css']:
  need(m.fetch(path,basic)[0]==200,'Existing route/asset failed')
 need(identity==m.state() and protected==m.guards() and research==m.research_code() and timers==m.timer_fingerprints() and unchanged==untouched(),'Protected files changed')
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production HTTPS health failed')
 after=m.log_indicators();need(len(after)>=2,'Expected staging logs missing')
 for path,counts in after.items():
  for key,n in counts.items():need(n<=logs.get(path,{}).get(key,0),'New staging PHP/Nginx '+key+' indicator')
 (backup/'evidence.json').write_text(json.dumps(report));(backup/'COMPLETE').write_text('COMPLETE\n')
 print('PASS: four KPI x three periods; all drill groups, 180 day counts, search/pagination and SQL match; protected REST bounds/GET-only/revisions verified')
 print('PASS: Research/scheduler/config/width/layout files unchanged; Basic Auth/noindex/Rank Math preserved; two logs checked; production HTTPS 200')
 print('EVIDENCE: '+json.dumps(report));print('COMMIT: '+(B/'COMMIT').read_text().strip());print('BACKUP: '+str(backup));print('URL: '+m.HOST+'/')
 print('UNVERIFIED: actual browser/mobile screenshots, clicks/touch/focus/Escape and console; run capture-analytics.py on Windows. No source synchronization or historical import performed.')
 print('VERIFY: sudo /usr/bin/python3 -I '+str(B/'deploy-analytics.py')+' --verify '+str(backup));print('ROLLBACK: sudo /usr/bin/python3 -I '+str(B/'deploy-analytics.py')+' --rollback '+str(backup))
if __name__=='__main__':
 try:main()
 except BaseException as e:
  print('BLOCKED: phase='+phase+'; type='+type(e).__name__)
  if isinstance(e,RuntimeError):print('Reason: '+str(e))
  print('No credentials/raw DB or HTTP bodies printed. Retain backup/partial state; do not rerun --apply blindly. No destructive rollback or Research/timer operations.');sys.exit(1)
