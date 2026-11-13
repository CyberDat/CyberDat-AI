import sys,pathlib,importlib.util,json
sys.dont_write_bytecode=True
P=pathlib.Path;D=P(__file__).parent;sp=importlib.util.spec_from_file_location('manager',D/'manage.py');a=importlib.util.module_from_spec(sp);sp.loader.exec_module(a)
b=P((D/'continuation-backup.txt').read_text());base=json.loads((b/'baseline.json').read_text());old=json.loads((a.B/'baseline.json').read_text());a.protected(old)
a.m.need(a.digest(b/'staging.sql.gz')==base['sql_sha256'] and a.digest(b/'files.tar.gz')==base['files_sha256'],'Continuation backup checksum mismatch')
names=['registry.php','fetch.php','normalize.php','nvd-progress.php','discovery-ingestion.php']
for n in names:a.m.need(a.digest(a.m.PLUGIN/'includes'/n)==base['research']['includes/'+n],'Installed continuation conflict');a.m.run(['/usr/bin/php8.4','-l',str(a.W/'wp-content/plugins/cyberdat-research/includes'/n)])
tests=a.m.run(['/usr/bin/python3','-I','-B',str(D/'test-candidate.py')],timeout=240);(b/'temporary-table-tests.txt').write_bytes(tests.stdout)
lock=a.lockdb()
try:
 before=a.sql("SELECT JSON_OBJECTAGG(state_key,payload) FROM stg_cdra_state WHERE state_key IN ('nvd_window','nvd_checkpoint','discovery_window:crossref','discovery_checkpoint:crossref','health:nvd','health:crossref','health:sophos')")
 for n in names:a.m.atomic_copy(a.W/'wp-content/plugins/cyberdat-research/includes'/n,a.m.PLUGIN/'includes'/n)
 a.m.atomic_copy(a.W/'wp-content/plugins/cyberdat-research/tests/discovery-database.php',a.m.PLUGIN/'tests/discovery-database.php')
 after=a.sql("SELECT JSON_OBJECTAGG(state_key,payload) FROM stg_cdra_state WHERE state_key IN ('nvd_window','nvd_checkpoint','discovery_window:crossref','discovery_checkpoint:crossref','health:nvd','health:crossref','health:sophos')");a.m.need(before==after,'State changed while applying continuation')
 release=json.loads((a.B/'release.json').read_text());release['research']=a.tree(a.m.PLUGIN);release['dense_cursor_fix_utc']=a.utc();release['continuation_backup']=str(b);(a.B/'release.json').write_text(json.dumps(release,indent=2));(D/'release.json').write_text(json.dumps(release,indent=2));(b/'release.json').write_text(json.dumps(release,indent=2))
finally:lock.stdin.close();lock.wait(timeout=5)
a.protected(old);print('PASS: dense single-response cap and Crossref cursor continuation installed; 4 TEMP suites PASS; exact window/checkpoint/health/backoff state preserved');print('UTC',release['dense_cursor_fix_utc']);print('BACKUP',str(b))
