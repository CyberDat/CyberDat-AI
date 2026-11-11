#!/usr/bin/env python3
"""Staging evidence acceptance. Backup is mandatory; no Research/publication/production write."""
import argparse,base64,ctypes,fcntl,getpass,gzip,hashlib,http.cookiejar,importlib.util,json,os,pathlib,pwd,re,shutil,subprocess,sys,time,urllib.parse,urllib.request
sys.dont_write_bytecode=True
P=pathlib.Path;W=P('/home/cyberdat/cyberdat-deploy/content-1.1-work');SOURCE=P('/home/cyberdat/cyberdat-deploy/seo-0.7-work/wp-content/plugins/cyberdat-content')
SPEC=importlib.util.spec_from_file_location('support','/home/cyberdat/cyberdat-deploy/content-0.9.0-prepared/support.py');m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)
TARGET=m.ROOT/'wp-content/plugins/cyberdat-content'
def hashes(root):return {str(p.relative_to(root)):m.sha(p) for p in root.rglob('*') if p.is_file()}
def exchange(a,b):
 fn=ctypes.CDLL(None,use_errno=True).renameat2;fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
 m.need(fn(-100,os.fsencode(a),-100,os.fsencode(b),2)==0,'Atomic directory exchange failed')
def restore_sql_test(backup):
 raw=gzip.open(backup/'staging.sql.gz','rt').read();sql=['SET SESSION group_concat_max_len=1048576;'];tables=['jobs','versions','events','agents']
 for name in tables:
  old='stg_cdca_'+name;new='cdca_restore_test_'+name
  match=re.search(r'CREATE TABLE `'+old+r'` .*?\n\) ENGINE=.*?;',raw,re.S);m.need(match is not None,'Backup Content schema missing')
  sql.append(match[0].replace('CREATE TABLE `'+old+'`','CREATE TEMPORARY TABLE `'+new+'`',1))
  # MariaDB may wrap INSERT VALUES across lines. Split only at an unquoted semicolon.
  for match_insert in re.finditer(r'^INSERT INTO `'+old+r'` ',raw,re.M):
   start=match_insert.start();quote=None;escaped=False;end=None
   for pos in range(start,len(raw)):
    c=raw[pos]
    if escaped:escaped=False;continue
    if quote:
     if c=='\\':escaped=True
     elif c==quote:quote=None
    elif c in ["'",'"']:quote=c
    elif c==';':end=pos+1;break
   m.need(end is not None,'Incomplete backup INSERT')
   sql.append(raw[start:end].replace('INSERT INTO `'+old+'`','INSERT INTO `'+new+'`',1))
  # Compare all restored columns to current untouched Content rows without printing row bodies.
  columns=re.findall(r'^  `([^`]+)` ',match[0],re.M);order='worker_id' if name=='agents' else 'id';expr="SHA2(GROUP_CONCAT(SHA2(CONCAT_WS(CHAR(31),"+','.join("COALESCE(CAST(`"+c+"` AS CHAR),'[NULL]')" for c in columns)+"),256) ORDER BY `"+order+"` SEPARATOR ''),256)"
  sql.append("SELECT '"+name+"',((SELECT COUNT(*) FROM `"+new+"`)=(SELECT COUNT(*) FROM `"+old+"`)),((SELECT "+expr+" FROM `"+new+"`)<=>(SELECT "+expr+" FROM `"+old+"`));")
 r=m.run(['/usr/bin/mariadb','--no-defaults','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--skip-password','--batch','--skip-column-names','cyberdat_staging'],data='\n'.join(sql).encode(),check=False)
 if r.returncode:
  diagnostics=re.findall(r'ERROR (\d+) \(([A-Z0-9]+)\) at line (\d+)',r.stderr.decode())
  print('TEMPORARY RESTORE ERROR:',json.dumps(diagnostics));(backup/'restore-test-failure.sql').write_text('\n'.join(sql));raise RuntimeError('Temporary restore syntax/compatibility check failed; no runtime exchange')
 lines=r.stdout.decode().splitlines();m.need(len(lines)==4 and all(line.split('\t')[1:]==['1','1'] for line in lines),'Temporary SQL restore differs from unchanged Content state');print('PASS: original four Content tables restored into TEMPORARY tables; every row/column hash matches',flush=True)
def smoke(basic,wordpress):
 m.need(m.fetch('/')[0]==401 and m.fetch('/wp-json/cyberdat-content/v1/worker')[0]==401,'Anonymous protection failed')
 results={}
 for path,marker in [('/',b'data-threat-pulse'),('/threat-intelligence/',b'data-threat-dashboard'),('/tools/',b'<html')]:
  code,h,b=m.fetch(path,basic);m.need(code==200 and marker in b and 'noindex' in h.get('X-Robots-Tag',''),'Public staging regression failed');results[path]=code
 jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),m.Redirect());m.fetch('/wp-login.php',basic,opener)
 data=urllib.parse.urlencode({'log':'cyberdat_staging_admin','pwd':wordpress,'redirect_to':m.HOST+'/wp-admin/','testcookie':'1'}).encode();m.fetch('/wp-login.php',basic,opener,data)
 for path,marker in [('/wp-admin/admin.php?page=cyberdat-content',b'data-evidence-schema="2"'),('/wp-admin/admin.php?page=cyberdat-research',b'Research Queue')]:
  code,h,b=m.fetch(path,basic,opener);m.need(code==200 and marker in b,'Authenticated queue smoke failed');results[path]=code
 code,h,b=m.fetch('/wp-json/cyberdat-content/v1/worker',basic,data=b'{"action":"claim"}');m.need(code==403,'Missing worker key was not rejected')
 return results

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--backup',type=P,required=True);parser.add_argument('--verify',action='store_true');parser.add_argument('--rollback-code',action='store_true');a=parser.parse_args();m.need(os.geteuid()==0,'Owner sudo required');os.umask(0o077);os.chdir(m.ROOT)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 b=a.backup;m.need(b.resolve()==b and b.parent==m.BACKUPS and b.name.startswith('content-evidence-1.1-') and b.stat().st_uid==0 and b.stat().st_mode&0o077==0,'Unsafe backup');base=json.loads((b/'baseline.json').read_text());manifest=json.loads((W/'manifest.json').read_text())
 m.need(base['sql_sha256']==m.sha(b/'staging.sql.gz') and base['tar_sha256']==m.sha(b/'content.tar.gz'),'Backup integrity failed');m.need(m.state()[:5]==['staging','cyberdat_staging',m.HOST,'cyberdat','0'],'Wrong staging identity')
 m.need(base['guards']==m.guards() and base['timers']==m.timer_fingerprints() and base['research']==m.research_code() and base['theme']==hashes(m.THEME) and base['production']==hashes(P('/var/www/cyberdat/public')),'Protected baseline changed')
 if a.rollback_code:
  m.need(hashes(TARGET)==manifest and hashes(b/'runtime-before')==base['content'],'Rollback release mismatch');exchange(TARGET,b/'runtime-before');print('PASS: prior Content code restored; evidence tables/history retained; no SQL or Research rollback');return
 m.need(hashes(SOURCE)==manifest,'Candidate source drift')
 if not a.verify:
  m.need(hashes(TARGET)==base['content'] and not (b/'runtime-before').exists(),'Installed release conflict; use verify after review, no blind reapply')
  restore_sql_test(b)
  candidate=TARGET.parent/'.cyberdat-content-evidence-candidate';m.need(not candidate.exists(),'Candidate path conflict');m.owned_copy(SOURCE,candidate,pwd.getpwnam('cyberdat-staging'))
  # Create only the two additive tables before the atomic code exchange. No activation/migration of old tables.
  code="require '"+str(candidate)+"/includes/enrichment-store.php';CDCA_Evidence_Store::install();"
  m.wp('eval',code);m.need(hashes(candidate)==manifest,'Staged candidate mismatch');exchange(TARGET,candidate);shutil.move(candidate,b/'runtime-before');(b/'DEPLOYED').write_text('atomic Content exchange; two additive tables\n');print('PASS: Content code exchanged atomically; original code retained privately',flush=True)
 m.need(hashes(TARGET)==manifest,'Installed Content hash mismatch')
 # No fixture creation, worker claim, job processing or Research sync here.
 basic=getpass.getpass('EXISTING HTTP Basic password (hidden): ');wordpress=getpass.getpass('EXISTING WORDPRESS password (hidden): ')
 results=smoke(basic,wordpress)
 proof=json.loads(m.wp('eval',"global $wpdb;$wpdb->query('START TRANSACTION READ ONLY');try{$d=cyberdat_research_data();echo wp_json_encode(['nvd_sql'=>(int)$wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->prefix}cdra_items WHERE source='nvd'\"),'nvd_projection'=>(int)$d['indexed_cves'],'kev_sql'=>(int)$wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->prefix}cdra_items WHERE source='kev' AND active=1\"),'kev_projection'=>(int)$d['kev']['catalog']['count'],'posts'=>['count'=>(int)$wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->posts}\"),'hash'=>hash('sha256',wp_json_encode($wpdb->get_results(\"SELECT * FROM {$wpdb->posts} ORDER BY ID\",ARRAY_A)))],'jobs'=>$wpdb->get_results(\"SELECT id,status,is_test FROM {$wpdb->prefix}cdca_jobs ORDER BY id\",ARRAY_A),'versions'=>(int)$wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->prefix}cdca_versions\"),'evidence_rows'=>(int)$wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->prefix}cdca_evidence\"),'enrichment_rows'=>(int)$wpdb->get_var(\"SELECT COUNT(*) FROM {$wpdb->prefix}cdca_enrichments\")]);}finally{$wpdb->query('ROLLBACK');}").stdout)
 m.need(proof['nvd_sql']==proof['nvd_projection'] and proof['kev_sql']==proof['kev_projection'],'Dashboard SQL mismatch');m.need(proof['posts']==base['posts'] and proof['jobs']==[{'id':'1','status':'draft_ready','is_test':'1'}] and proof['versions']==1 and proof['evidence_rows']==0 and proof['enrichment_rows']==0,'Existing posts or live Content queue changed')
 m.need(base['guards']==m.guards() and base['timers']==m.timer_fingerprints() and base['research']==m.research_code() and base['theme']==hashes(m.THEME) and base['production']==hashes(P('/var/www/cyberdat/public')),'Protected regression after smoke')
 after=m.log_indicators();m.need(all(v<=base['logs'].get(name,{}).get(kind,0) for name,counts in after.items() for kind,v in counts.items()),'New log indicator; inspect before acceptance')
 evidence={'utc':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),'http':results,'proof':proof,'sql_restore':'four original Content tables restored only into TEMPORARY tables; full-column hashes match','file_restore':True,'research_unchanged':True,'timers_unchanged':True,'theme_seo_unchanged':True,'production_tree_unchanged':True,'log_files_checked':len(after),'browser_interaction':'UNVERIFIED','backup':str(b)}
 (b/'acceptance.json').write_text(json.dumps(evidence));(W/'acceptance.json').write_text(json.dumps(evidence,indent=2));os.chown(W/'acceptance.json',pwd.getpwnam('cyberdat').pw_uid,pwd.getpwnam('cyberdat').pw_gid)
 print('ACCEPTANCE:',json.dumps(evidence));print('PASS: staging SQL/admin/protection regressions; no real job, post, LLM or production write')
if __name__=='__main__':
 try:main()
 except Exception as e:print('BLOCKED:',type(e).__name__,str(e) if isinstance(e,RuntimeError) else 'safe diagnostic suppressed');sys.exit(1)
