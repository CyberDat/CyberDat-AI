import sys,os,pathlib,importlib.util,json,gzip,re,datetime,zoneinfo
sys.dont_write_bytecode=True
P=pathlib.Path;D=P(__file__).parent;sp=importlib.util.spec_from_file_location('manager',D/'manage.py');a=importlib.util.module_from_spec(sp);sp.loader.exec_module(a);b=P((D/'continuation-backup.txt').read_text());orig=json.loads((a.B/'baseline.json').read_text());a.protected(orig)
raw=gzip.open(a.B/'staging.sql.gz','rt').read();names=list(orig['restore']['temporary_tables']);checks={}
for name in names:
 expected=re.search(r'CREATE TABLE `'+name+r'` .*?\n\) ENGINE=.*?;',raw,re.S)[0].rstrip(';');live=a.sql('SHOW CREATE TABLE `'+name+'`').split('\t',1)[1].strip();clean=lambda x:re.sub(r' AUTO_INCREMENT=\d+','',x).strip();checks[name]=clean(expected)==clean(live)
a.m.need(all(checks.values()),'SQL schema drift')
# Restore only the original items table into TEMPORARY storage to prove no original NVD IDs were lost.
name='stg_cdra_items';schema=re.search(r'CREATE TABLE `'+name+r'` .*?\n\) ENGINE=.*?;',raw,re.S)[0];sql=["SET NAMES utf8mb4;SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';",schema.replace('CREATE TABLE `stg_cdra_items`','CREATE TEMPORARY TABLE `original083_items`',1)]
for hit in re.finditer(r'^INSERT INTO `stg_cdra_items` ',raw,re.M):
 quote=None;escape=False
 for i in range(hit.start(),len(raw)):
  c=raw[i]
  if escape:escape=False;continue
  if quote:
   if c=='\\':escape=True
   elif c==quote:quote=None
  elif c in ["'",'"']:quote=c
  elif c==';':sql.append(raw[hit.start():i+1].replace('INSERT INTO `stg_cdra_items`','INSERT INTO `original083_items`',1));break
sql.append("SELECT JSON_OBJECT('original_nvd',COUNT(*),'missing_nvd',SUM(n.id IS NULL)) FROM original083_items o LEFT JOIN stg_cdra_items n ON n.source='nvd' AND n.source_id=o.source_id WHERE o.source='nvd';DROP TEMPORARY TABLE original083_items;")
r=a.m.run(['/usr/bin/mariadb','--no-defaults','--default-character-set=utf8mb4','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--skip-password','--batch','--raw','--skip-column-names','cyberdat_staging'],data='\n'.join(sql).encode());retention=json.loads(r.stdout);a.m.need(retention['missing_nvd']==0,'NVD record lost')
cut=datetime.datetime.fromisoformat('2026-11-11T17:26:39+00:00');logs={}
for name in orig['logs']:
 p=P(name);data=p.read_bytes()[-4194304:] if p.exists() else b'';counts={'fatal':0,'warning':0,'database':0,'undated_indicators':0}
 for line in data.decode(errors='replace').splitlines():
  kinds=[k for k,pat in {'fatal':'PHP Fatal error|PHP Parse error|Uncaught (?:Error|Exception)','warning':'PHP Warning|PHP Notice','database':'WordPress database error'}.items() if re.search(pat,line,re.I)]
  if not kinds:continue
  ts=None
  match=re.search(r'\[(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2})(?: (UTC|Europe/Berlin))?\]',line)
  if match:
   ts=datetime.datetime.strptime(match[1],'%d-%b-%Y %H:%M:%S').replace(tzinfo=zoneinfo.ZoneInfo(match[2] or 'Europe/Berlin'))
  else:
   match=re.match(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})',line)
   if match:ts=datetime.datetime.strptime(match[1],'%Y/%m/%d %H:%M:%S').replace(tzinfo=zoneinfo.ZoneInfo('Europe/Berlin'))
  if ts is None:counts['undated_indicators']+=1
  elif ts>=cut:
   for k in kinds:counts[k]+=1
 logs[name]=counts
out={'utc':a.utc(),'schema_unchanged':all(checks.values()),'tables_checked':len(checks),'nvd_retention':retention,'logs_since_deploy':logs,'protected_and_production_unchanged':True};(b/'final-proofs.json').write_text(json.dumps(out,indent=2));print(json.dumps(out))
