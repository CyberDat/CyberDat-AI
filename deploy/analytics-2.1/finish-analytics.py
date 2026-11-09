#!/usr/bin/env python3
"""Finish an already installed 2.1 release: one JS label fix + SQL/HTTP acceptance. No reinstallation."""
import argparse,datetime,fcntl,getpass,hashlib,html.parser,importlib.util,json,os,pathlib,shutil,sys,tarfile,time,urllib.parse,urllib.request
P=pathlib.Path;B=P(__file__).resolve().parent;phase='preflight';OLD_COMMIT='27e09abda18ff0b9630806ee9797b14c6050050f';TARGET='wp-content/themes/cyberdat/assets/js/threat-analytics.js'
def need(ok,message):
 if not ok:raise RuntimeError(message)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class PulseHTML(html.parser.HTMLParser):
 def __init__(self):super().__init__(convert_charrefs=True);self.model=None;self.values={}
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if 'data-pulse-periods' in a:self.model=json.loads(a['data-pulse-periods'])
  if 'data-pulse-kpi' in a:self.values[a['data-pulse-kpi']]=int(a['data-value'])
def valid_backup(m,path,prefix):
 need(path.resolve()==path and path.parent==m.BACKUPS and path.name.startswith(prefix) and not path.is_symlink() and path.stat().st_uid==0 and path.stat().st_mode&0o077==0,'Unsafe backup path')
 state=json.loads((path/'state.json').read_text())
 for name,value in state['checksums'].items():need('/' not in name and sha(path/name)==value,'Backup checksum mismatch')
 return state

def main():
 global phase
 parser=argparse.ArgumentParser();g=parser.add_mutually_exclusive_group(required=True);g.add_argument('--finish',action='store_true');g.add_argument('--rollback',type=P);args=parser.parse_args();need(os.geteuid()==0,'Use owner sudo');os.umask(0o077);sys.dont_write_bytecode=True;os.nice(10)
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  h,name=line.split();p=B/name;need(p.resolve().parent==B and not p.is_symlink() and sha(p)==h,'Prepared bundle checksum mismatch')
 spec=importlib.util.spec_from_file_location('finish_support',B/'support.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 identity=m.state();need(identity[:4]==['staging','cyberdat_staging',m.HOST,'cyberdat'] and str(identity[4])=='0','Wrong staging identity')
 targets=json.loads((B/'base-patch.json').read_text());old_hash=next(e['after'] for e in targets if e['target']==TARGET);new_hash=sha(B/'threat-analytics.js');target=m.ROOT/TARGET
 protected=m.guards();research=m.research_code();timers=m.timer_fingerprints();logs=m.log_indicators()
 untouched={str(p.relative_to(m.THEME)):sha(p) for p in m.THEME.rglob('*') if p.is_file() and p!=target}
 def unchanged():return {str(p.relative_to(m.THEME)):sha(p) for p in m.THEME.rglob('*') if p.is_file() and p!=target}
 for e in targets:
  path=m.ROOT/e['target'];need(path.resolve()==path and path.is_file(),'Installed file missing/unsafe')
  need(sha(path) in ([old_hash,new_hash] if e['target']==TARGET else [e['after']]),'Installed release differs; stop without overwriting')
 if args.rollback:
  saved=valid_backup(m,args.rollback,'analytics-2.1-finish-');need(saved['before_hash']==old_hash and sha(args.rollback/'previous.js')==old_hash,'Wrong rollback file')
  m.atomic_copy(args.rollback/'previous.js',target)
  need(protected==m.guards() and research==m.research_code() and timers==m.timer_fingerprints() and untouched==unchanged(),'Protected code/config changed')
  print('PASS: only prior JS restored; SQL, backups, plugin, Research and timers retained');return
 # Locate and verify the original backup without modifying it or rerunning deployment.
 originals=[]
 for path in sorted(m.BACKUPS.glob('analytics-2.1-*'),reverse=True):
  if path.name.startswith('analytics-2.1-finish-'):continue
  if not (path/'state.json').is_file():continue
  state=json.loads((path/'state.json').read_text())
  if state.get('commit')==OLD_COMMIT:originals.append(path)
 need(bool(originals),'Original analytics backup not found; no patch applied');original=originals[0];saved=valid_backup(m,original,'analytics-2.1-')
 names={e['target'] for e in targets};original_untouched={str(p.relative_to(m.ROOT)):sha(p) for p in m.THEME.rglob('*') if p.is_file() and str(p.relative_to(m.ROOT)) not in names}
 need(saved['protected']==protected and saved['research']==research and saved['timers']==timers and saved['unchanged']==original_untouched,'Protected baseline changed since original backup')
 m.wp('plugin','is-active','cyberdat-threat-analytics');print('PASS: installed 2.1 module and original backup verified; no reinstall or activation',flush=True)
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and m.fetch('/',basic)[0]==200 and m.fetch('/')[0]==401,'Basic Auth preflight failed')
 if sha(target)==old_hash:
  phase='private backup before one JS replacement';need(shutil.disk_usage(m.BACKUPS).free>1024**3,'Less than 1 GiB free')
  backup=m.BACKUPS/('analytics-2.1-finish-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));backup.mkdir(mode=0o700);m.database_backup(backup/'staging.sql.gz')
  with tarfile.open(backup/'theme.tar.gz','w:gz') as arc:arc.add(m.THEME,arcname='cyberdat')
  shutil.copyfile(target,backup/'previous.js');checksums={name:sha(backup/name) for name in ['staging.sql.gz','theme.tar.gz','previous.js']}
  state={'commit':(B/'COMMIT').read_text().strip(),'checksums':checksums,'before_hash':old_hash,'after_hash':new_hash,'original_backup':str(original),'protected':protected,'research':research,'timers':timers,'untouched':untouched};(backup/'state.json').write_text(json.dumps(state));print('BACKUP: '+str(backup),flush=True)
  m.atomic_copy(B/'threat-analytics.js',target)
 else:
  matches=[]
  for path in sorted(m.BACKUPS.glob('analytics-2.1-finish-*'),reverse=True):
   state=valid_backup(m,path,'analytics-2.1-finish-')
   if state.get('after_hash')==new_hash:matches.append((path,state))
  need(bool(matches),'Patched JS found but matching finish backup missing');backup,state=matches[0]
  need(state['protected']==protected and state['research']==research and state['timers']==timers and state['untouched']==untouched,'Resume baseline conflict')
  print('PASS: label patch already installed; existing backup verified; no rewrite',flush=True)
 phase='single read-only SQL and protected HTTP acceptance';deadline=time.monotonic()+190
 while any(m.unit('show','cyberdat-research@'+n+'.service','--property=ActiveState','--value').stdout.strip() in (b'active',b'activating') for n in m.NAMES):
  need(time.monotonic()<deadline,'Research job busy; finish later without reinstall');time.sleep(3)
 m.proof();result=m.wp('eval',(B/'proof.php').read_text()[5:],check=False)
 if result.returncode:
  import re
  codes=re.findall(rb'(?:CDRA_Error|RuntimeException|InvalidArgumentException|UnexpectedValueException): ([a-z_0-9]+)',result.stderr);raise RuntimeError('SQL proof failed; code='+(','.join(x.decode() for x in codes[:3]) or 'unavailable'))
 report=json.loads(result.stdout)
 code,h,b=m.fetch('/',basic);home=PulseHTML();home.feed(b.decode('utf-8','replace'));need(code==200 and 'noindex' in h.get('X-Robots-Tag','') and home.model,'Homepage/period data missing')
 need(home.values==report['periods']['7']['counts'],'Initial KPI/SQL mismatch')
 for days in ['7','30','90']:need(home.model['periods'][days]==report['periods'][days],'Period model/SQL mismatch')
 endpoint='/wp-json/cyberdat-analytics/v1/records'
 for key,total in report['chart_counts'].items():
  group,value=key.split(':',1);query=urllib.parse.urlencode({'group':group,'value':value,'per_page':5,'revision':report['revision']});code,_,b=m.fetch(endpoint+'?'+query,basic);data=json.loads(b)
  need(code==200 and data['total']==total and len(data['items'])<=5,'REST/SQL count mismatch '+key)
  for row in data['items']:need(set(row)=={'id','title','description','source','source_name','url','published','date_added','score','cvss_version','severity'},'Unexpected record fields')
 for query in ['per_page=51','page=601','sort=RAND%28%29','q=%27%20OR%201%3D1','group=day&value=nvd&date=2026-02-30&days=7']:need(m.fetch(endpoint+'?'+query,basic)[0]==400,'Invalid filter accepted')
 need(m.fetch(endpoint+'?revision='+'0'*64,basic)[0]==409,'Revision guard failed');need(m.fetch(endpoint,basic,data=b'{}')[0] in (404,405),'Write method accepted')
 code,h,b=m.fetch('/threat-intelligence/',basic);full=b.decode('utf-8','replace');need(code==200 and full.count('data-chart-id=')==6 and 'data-threat-map' in full and 'data-analytics-dialog' in full and 'noindex' in h.get('X-Robots-Tag',''),'Full Dashboard regression');m.verify_description(full)
 need(m.fetch(endpoint)[0]==401 and m.fetch('/')[0]==401 and m.fetch('/threat-intelligence/')[0]==401,'Basic Auth guard failed')
 code,_,b=m.fetch('/wp-content/themes/cyberdat/assets/js/threat-analytics.js',basic);need(code==200 and hashlib.sha256(b).hexdigest()==new_hash,'HTTP JS does not match label patch')
 for path in ['/tools/','/news/','/analysis/','/guides/','/learning/','/topics/']:need(m.fetch(path,basic)[0]==200,'Existing route failed')
 need(identity==m.state() and protected==m.guards() and research==m.research_code() and timers==m.timer_fingerprints() and untouched==unchanged(),'Protected code/config changed')
 with urllib.request.urlopen('https://cyberdat.eu/',timeout=30) as response:need(response.status==200,'Production HTTPS check failed')
 after=m.log_indicators();need(len(after)>=2,'Expected logs missing')
 for path,values in after.items():
  for kind,n in values.items():need(n<=logs.get(path,{}).get(kind,0),'New staging PHP/Nginx '+kind+' indicator')
 (backup/'evidence.json').write_text(json.dumps(report));(backup/'COMPLETE').write_text('COMPLETE\n')
 print('PASS: 12 period KPIs, 14 drill groups, 180 days, search, server pagination/sorts, REST bounds/GET/revisions; SQL match')
 print('KPI TABLE: period | start UTC | end UTC | Critical | New NVD | KEV added | Ransomware-linked KEV added')
 for days,p in report['periods'].items():c=p['counts'];print(f"{days}D | {p['start']} | {p['end']} | {c['critical']} | {c['nvd']} | {c['kev']} | {c['ransomware']}")
 print('PASS: no new PHP/Nginx indicators; Basic Auth/noindex/Rank Math preserved; production HTTPS 200; Research/timer/protected fingerprints unchanged')
 print('EVIDENCE: '+json.dumps(report));print('COMMIT: '+(B/'COMMIT').read_text().strip());print('ORIGINAL BACKUP: '+str(original));print('FINISH BACKUP: '+str(backup));print('URL: '+m.HOST+'/')
 print('UNVERIFIED: real browser screenshots, actual interactions and JS console; run capture-analytics.py on Windows. NVD remains partial.')
 print('VERIFY/RESUME: sudo /usr/bin/python3 -I '+str(B/'finish-analytics.py')+' --finish');print('ROLLBACK LABELS ONLY: sudo /usr/bin/python3 -I '+str(B/'finish-analytics.py')+' --rollback '+str(backup))
if __name__=='__main__':
 try:main()
 except BaseException as e:
  print('BLOCKED: phase='+phase+'; type='+type(e).__name__)
  if isinstance(e,RuntimeError):print('Reason: '+str(e))
  print('Retain original/finish backups and partial state; do not rerun installation. No credentials/raw responses, Research restart, checkpoint reset or destructive cleanup.');sys.exit(1)
