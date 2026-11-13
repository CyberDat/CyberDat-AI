#!/usr/bin/env python3
"""Pinned staging-only release, read-only observations and code-only rollback."""
import sys,os,pathlib,importlib.util,json,hashlib,subprocess,shutil,pwd,time,ctypes,datetime,fcntl,argparse
sys.dont_write_bytecode=True
P=pathlib.Path;D=P(__file__).parent;W=P('/home/cyberdat/cyberdat-deploy/research-0.8.3-work');B=P('/var/backups/cyberdat-staging/research-0.8.3-20261111T170009Z')
spec=importlib.util.spec_from_file_location('support',P('/home/cyberdat/cyberdat-deploy/content-0.9.0-prepared/support.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
os.chdir(m.ROOT);os.umask(0o077)

def digest(p):return hashlib.sha256(P(p).read_bytes()).hexdigest()
def tree(p):return {str(f.relative_to(p)):digest(f) for f in p.rglob('*') if f.is_file() and not f.is_symlink()}
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sql(q):
 r=m.run(['/usr/bin/mariadb','--no-defaults','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--skip-password','--batch','--raw','--skip-column-names','cyberdat_staging'],data=('SET SESSION TRANSACTION READ ONLY; START TRANSACTION WITH CONSISTENT SNAPSHOT;'+q+';ROLLBACK;').encode());return r.stdout.decode()
def snapshot():
 q="""SELECT JSON_OBJECT('counts',JSON_OBJECT('queue',(SELECT COUNT(*) FROM stg_cdra_items),'nvd',(SELECT COUNT(*) FROM stg_cdra_items WHERE source='nvd'),'kev',(SELECT COUNT(*) FROM stg_cdra_items WHERE source='kev' AND active=1),'crossref',(SELECT COUNT(*) FROM stg_cdra_items WHERE source='crossref'),'posts',(SELECT COUNT(*) FROM stg_posts),'content_jobs',(SELECT COUNT(*) FROM stg_cdca_jobs)),'duplicates',(SELECT COUNT(*) FROM (SELECT source,source_key FROM stg_cdra_items GROUP BY source,source_key HAVING COUNT(*)>1) x),'db_bytes',(SELECT SUM(DATA_LENGTH+INDEX_LENGTH) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()));
SELECT JSON_OBJECT('key',state_key,'value',JSON_EXTRACT(payload,'$')) FROM stg_cdra_state WHERE state_key IN ('nvd_checkpoint','nvd_window','nvd_last_completed_window','discovery_window:crossref','discovery_checkpoint:crossref','dashboard_v1','health:nvd','health:sophos','health:crossref','health:kev','health:cisa-advisories','health:cert-eu','health:msrc');
SELECT JSON_OBJECT('source',source,'code',code,'created',created) FROM stg_cdra_logs WHERE created >= '2026-11-11 17:00:09' ORDER BY id DESC LIMIT 30"""
 rows=[json.loads(l) for l in sql(q).splitlines()];out={'utc':utc(),'db':rows[0],'state':{},'logs':[]}
 for r in rows[1:]:
  if 'key' not in r:out['logs'].append(r);continue
  k=r['key'];v=r['value']
  if k.startswith('nvd_') and isinstance(v,dict):
   proof=v.pop('time_proof',None);legacy=v.pop('legacy_prefix',None);v.pop('pages',None)
   if proof:v['time_progress']={'covered_until':proof['covered_until'],'target_end':proof['end'],'completed_slices':len(proof['segments']),'pending_slices':len(proof['pending']),'certified_unique':proof['certified_unique'],'probes':proof['probes']}
   if legacy:v['legacy_cursor']=legacy['index']
  if k=='dashboard_v1':
   v={'generated_at':v.get('generated_at'),'counts':v.get('counts'),'feed_count':len(v.get('feed',[]))}
  if k=='discovery_window:crossref' and isinstance(v,dict):v={'start':v['start'],'end':v['end'],'offset':v['offset'],'cursor_present':bool(v.get('cursor')),'seen_count':len(v.get('seen',[]))}
  out['state'][k]=v
 out['timers']=m.timers();out['units']={n:m.unit('show','cyberdat-research@'+n+'.service','--property=Result,ExecMainStatus,ExecMainStartTimestamp,ExecMainExitTimestamp,ActiveState').stdout.decode().splitlines() for n in ['nvd','dispatch']}
 out['load']=os.getloadavg();out['memory']={l.split(':')[0]:l.split(':')[1].strip() for l in P('/proc/meminfo').read_text().splitlines() if l.split(':')[0] in ['MemTotal','MemAvailable','SwapTotal','SwapFree']}
 return out

def protected(base):
 m.need(all(digest(p)==v for p,v in base['protected'].items()),'Protected configuration drift')
 m.need(tree(m.ROOT/'wp-content/plugins/cyberdat-content')==base['content'],'Content code drift')
 now=tree(P('/var/www/cyberdat/public'));m.need(now==base['production'],'Production file drift')
 for p,v in base['timers'].items():
  if p!='/opt/cyberdat-research/run.sh':m.need(digest(p)==v,'Timer/unit drift')
 now=tree(m.THEME);old=base['theme'];allowed='template-parts/home/threat-dashboard.php';m.need({k:v for k,v in now.items() if k!=allowed}=={k:v for k,v in old.items() if k!=allowed},'Unrelated public theme drift')

def lockdb():
 p=subprocess.Popen(['/usr/bin/mariadb','--no-defaults','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--skip-password','--batch','--raw','--skip-column-names','--unbuffered','cyberdat_staging'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
 name='cdra_'+hashlib.sha256(b'cyberdat_stagingstg_cdra_').hexdigest()[:32]
 p.stdin.write(("SELECT GET_LOCK('"+name+"',60);\n").encode());p.stdin.flush();m.need(p.stdout.readline().strip()==b'1','Research ingestion lock unavailable');return p

def exchange(a,b):
 libc=ctypes.CDLL(None,use_errno=True);r=libc.renameat2(-100,os.fsencode(a),-100,os.fsencode(b),2);m.need(r==0,'Atomic Research directory exchange failed')

def rootcopy(src,dst,mode):
 t=dst.with_name(dst.name+'.083-partial');m.need(not t.exists() and not dst.is_symlink(),'Unsafe root file target');shutil.copyfile(src,t);os.chown(t,0,0);t.chmod(mode);os.replace(t,dst)

def main():
 ap=argparse.ArgumentParser();ap.add_argument('mode',choices=['deploy','observe','rollback-ui']);a=ap.parse_args();m.need(os.geteuid()==0,'Owner sudo required');base=json.loads((B/'baseline.json').read_text());m.need(digest(B/'staging.sql.gz')==base['sql_sha256'] and digest(B/'files.tar.gz')==base['files_sha256'],'Backup hash mismatch')
 control=D/'release.json'
 if a.mode=='observe':
  out=snapshot();protected(base);out['protected_and_content_unchanged']=True
  path=B/('observe-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json');path.write_text(json.dumps(out,indent=2));print(json.dumps(out));return
 f=P('/run/lock/cyberdat-staging-research-083.lock').open('a');fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
 yaml=P('/var/lib/cyberdat-staging/research/wp-cli.yml');launcher=P('/opt/cyberdat-research/run.sh');theme=m.THEME/'template-parts/home/threat-dashboard.php'
 if a.mode=='deploy':
  m.need(not control.exists(),'Existing release: observe or rollback, no reapply');protected(base);m.need(tree(m.PLUGIN)==base['research'] and digest(theme)==base['theme']['template-parts/home/threat-dashboard.php'] and digest(launcher)==base['timers'][str(launcher)],'Runtime changed since backup');m.need(not yaml.exists(),'Local WP-CLI config already exists')
  for p in (W/'wp-content/plugins/cyberdat-research').rglob('*.php'):m.run(['/usr/bin/php8.4','-l',str(p)])
  stage=m.PLUGIN.parent/'.cyberdat-research-083-stage';m.need(not stage.exists(),'Stage directory conflict');m.owned_copy(W/'wp-content/plugins/cyberdat-research',stage,pwd.getpwnam('cyberdat-staging'))
  before=snapshot();(B/'pre-deploy.json').write_text(json.dumps(before,indent=2));lock=lockdb()
  try:
   exchange(stage,m.PLUGIN)
   m.atomic_copy(W/'wp-content/themes/cyberdat/template-parts/home/threat-dashboard.php',theme)
   rootcopy(W/'deploy/research-0.8.3/run.sh',launcher,0o755);rootcopy(W/'deploy/research-0.8.3/wp-cli.yml',yaml,0o644)
   release={'utc':utc(),'backup':str(B),'research':tree(m.PLUGIN),'theme_sha256':digest(theme),'launcher_sha256':digest(launcher),'wp_cli_config_sha256':digest(yaml),'old_plugin':str(stage)}
   (B/'release.json').write_text(json.dumps(release,indent=2));control.write_text(json.dumps(release,indent=2));os.chown(control,0,0);control.chmod(0o644)
  finally:lock.stdin.close();lock.wait(timeout=5)
  protected(base);print('PASS: atomic Research 0.8.3 staging install; checkpoints/cursors untouched; only one theme template and scheduled launcher flag changed');print('DEPLOY UTC',release['utc']);print('BACKUP',B);print('NATURAL TIMERS',json.dumps(m.timers()));return
 release=json.loads((B/'release.json').read_text());m.need(digest(theme)==release['theme_sha256'] and digest(launcher)==release['launcher_sha256'] and digest(yaml)==release['wp_cli_config_sha256'],'Rollback conflict');protected(base);lock=lockdb()
 try:
  m.atomic_copy(B/'file-restore/var/www/cyberdat-staging/public/wp-content/themes/cyberdat/template-parts/home/threat-dashboard.php',theme)
  rootcopy(B/'file-restore/opt/cyberdat-research/run.sh',launcher,0o755);yaml.unlink()
 finally:lock.stdin.close();lock.wait(timeout=5)
 print('PASS: informational UI/launcher restored; new Research interpreter retained for persisted time-proof windows. No SQL/checkpoint/data changes. Full collector rollback requires a compatibility review; do not restore old SQL over newer records.')
if __name__=='__main__':
 try:main()
 except Exception as e:print('BLOCKED:',type(e).__name__,str(e));sys.exit(1)
