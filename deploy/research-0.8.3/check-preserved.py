import sys,os,pathlib,importlib.util,json,gzip,re,hashlib
sys.dont_write_bytecode=True
P=pathlib.Path;D=P(__file__).parent;spec=importlib.util.spec_from_file_location('manager',D/'manage.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base=json.loads((m.B/'baseline.json').read_text());m.protected(base)
names=['stg_cdca_jobs','stg_cdca_versions','stg_cdca_events','stg_cdca_agents','stg_cdca_enrichments','stg_cdca_evidence','stg_options'];queries=[]
for n in names:queries.append('CREATE TEMPORARY TABLE `audit083_'+n+'` LIKE `'+n+'`;')
# SQL dump scanner: quoted semicolons/newlines cannot terminate a statement.
data=gzip.decompress((m.B/'staging.sql.gz').read_bytes()).decode();start=0;quoted=False;escaped=False
for i,ch in enumerate(data):
 if escaped:escaped=False;continue
 if quoted and ch=='\\':escaped=True;continue
 if ch=="'":quoted=not quoted
 if ch==';' and not quoted:
  statement=data[start:i+1];start=i+1
  hit=re.search(r'(?m)^INSERT INTO `(stg_cdca_(?:jobs|versions|events|agents|enrichments|evidence)|stg_options)`(?: \([^;]*?\))?\s+VALUES\s*',statement)
  if hit:queries.append(statement[hit.start():].replace('INSERT INTO `'+hit[1]+'`','INSERT INTO `audit083_'+hit[1]+'`',1))
cols=json.loads(m.sql("SELECT JSON_OBJECT('columns',JSON_OBJECTAGG(TABLE_NAME,c)) FROM (SELECT TABLE_NAME,GROUP_CONCAT(CONCAT('`',COLUMN_NAME,'`') ORDER BY ORDINAL_POSITION SEPARATOR ',') c FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME LIKE 'stg_cdca_%' GROUP BY TABLE_NAME) x").strip())['columns']
# Full-column content hashes, not just row counts. No values are returned.
for n in names[:-1]:
 fields=cols[n];inner='SHA2(CAST(JSON_ARRAY('+fields+') AS CHAR),256)';key=fields.split(',')[0]
 current='(SELECT SHA2(COALESCE(GROUP_CONCAT('+inner+' ORDER BY '+key+" SEPARATOR ''),''),256) FROM `"+n+'`)'
 restored=current.replace('`'+n+'`','`audit083_'+n+'`')
 queries.append("SELECT JSON_OBJECT('table','"+n+"','matches_backup',"+current+'='+restored+');')
queries.append("SELECT JSON_OBJECT('kind','options','matches_backup',COUNT(*)=SUM(a.option_value=b.option_value),'rows',COUNT(*)) FROM stg_options a JOIN audit083_stg_options b USING(option_name) WHERE a.option_name IN ('active_plugins','stg_user_roles','home','siteurl','blog_public','permalink_structure','template','stylesheet') OR a.option_name LIKE '%two_factor%' OR a.option_name LIKE '%totp%' OR a.option_name LIKE '%mfa%';")
queries.append('SELECT JSON_OBJECT(\'posts\',COUNT(*)) FROM stg_posts;')
for n in names:queries.append('DROP TEMPORARY TABLE `audit083_'+n+'`;')
r=m.m.run(['/usr/bin/mariadb','--no-defaults','--protocol=SOCKET','--socket=/run/mysqld/mysqld.sock','--user=root','--skip-password','--batch','--raw','--skip-column-names','cyberdat_staging'],data=('SET SESSION group_concat_max_len=1048576;\n'+''.join(queries)).encode())
rows=[json.loads(l) for l in r.stdout.decode().splitlines()];m.m.need(all(v.get('matches_backup',True) in (True,1) for v in rows) and any(v.get('kind')=='options' and v.get('rows',0)>=8 for v in rows),'Content/options changed from backup');out={'checks':rows,'production_files_unchanged':True,'protected_configs_unchanged':True,'content_code_unchanged':True};(m.B/'preserved.json').write_text(json.dumps(out,indent=2));print(json.dumps(out))
