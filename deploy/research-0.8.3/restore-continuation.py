import sys,os,pathlib,importlib.util,json,gzip,re
sys.dont_write_bytecode=True
P=pathlib.Path;D=P(__file__).parent;sp=importlib.util.spec_from_file_location('manager',D/'manage.py');a=importlib.util.module_from_spec(sp);sp.loader.exec_module(a)
b=P((D/'continuation-backup.txt').read_text());raw=gzip.open(b/'staging.sql.gz','rt').read();names=['stg_cdra_'+n for n in ['items','aliases','cves','state','logs','events','discovery','categories','identifiers','discovery_audit']]+['stg_cdca_'+n for n in ['jobs','versions','events','agents','enrichments','evidence']];sql=['SET NAMES utf8mb4;SET SQL_MODE=\'NO_AUTO_VALUE_ON_ZERO\';']
for name in names:
 new='restore083_'+name;schema=re.search(r'CREATE TABLE `'+name+r'` .*?\n\) ENGINE=.*?;',raw,re.S);a.m.need(schema,'Backup schema missing');sql.append(schema[0].replace('CREATE TABLE `'+name+'`','CREATE TEMPORARY TABLE `'+new+'`',1))
 for match in re.finditer(r'^INSERT INTO `'+name+r'` ',raw,re.M):
  quote=None;escape=False;end=None
  for i in range(match.start(),len(raw)):
   c=raw[i]
   if escape:escape=False;continue
   if quote:
    if c=='\\':escape=True
    elif c==quote:quote=None
   elif c in ["'",'"']:quote=c
   elif c==';':end=i+1;break
  a.m.need(end is not None,'Incomplete backup INSERT');sql.append(raw[match.start():end].replace('INSERT INTO `'+name+'`','INSERT INTO `'+new+'`',1))
 sql.append("SELECT JSON_OBJECT('table','"+name+"','restored_rows',COUNT(*)) FROM `"+new+'`;')
 if name in ['stg_cdra_items','stg_cdra_state']:sql.append("SELECT JSON_OBJECT('json_table','"+name+"','invalid_json',SUM(NOT JSON_VALID(payload))) FROM `"+new+'`;')
 sql.append('DROP TEMPORARY TABLE `'+new+'`;')
r=a.m.run(['/usr/bin/mariadb','--no-defaults','--default-character-set=utf8mb4','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--skip-password','--batch','--raw','--skip-column-names','cyberdat_staging'],data='\n'.join(sql).encode(),timeout=240);out=[json.loads(l) for l in r.stdout.decode().splitlines()];a.m.need(len([x for x in out if 'table' in x])==16 and all((x.get('invalid_json') or 0)==0 for x in out),'Isolated restore failed');(b/'restore-test.json').write_text(json.dumps(out,indent=2));print(json.dumps(out));print('PASS: all 16 tables restored into connection-local TEMPORARY tables; live database untouched')
