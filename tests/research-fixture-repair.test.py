"""Exercise the resume repair in an isolated directory; never load WP or use a DB."""
import importlib.util,pathlib,shutil,tempfile,types
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixture_repair',ROOT/'deploy/research-0.8.2/resume-discovery.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
old=pathlib.Path('/home/cyberdat/cyberdat-deploy/research-0.8.2-prepared/plugin/tests/discovery-database.php').read_bytes()
new=(ROOT/'wp-content/plugins/cyberdat-research/tests/discovery-database.php').read_bytes()
with tempfile.TemporaryDirectory(prefix='cyberdat-fixture-repair-') as folder:
 base=pathlib.Path(folder);payload=base/'helper';payload.mkdir();m.__file__=str(payload/'resume.py');(payload/'discovery-database.php').write_bytes(new)
 plugin=base/'plugin';(plugin/'tests').mkdir(parents=True);target=plugin/m.FIXTURE;target.write_bytes(old);(plugin/'runtime.php').write_text('unchanged')
 backup=base/'backup';backup.mkdir()
 support=types.SimpleNamespace(PLUGIN=plugin,atomic_copy=lambda source,dest:shutil.copyfile(source,dest))
 assert m.installed_match(plugin,{'path':m.FIXTURE,'after':m.BEFORE})
 m.repair_fixture(support,backup)
 assert target.read_bytes()==new and (backup/'discovery-test-before-hash-fix.php').read_bytes()==old
 assert (plugin/'runtime.php').read_text()=='unchanged'
 assert m.installed_match(plugin,{'path':m.FIXTURE,'after':m.BEFORE})
 m.repair_fixture(support,backup)
 target.write_text('unexpected edit')
 assert not m.installed_match(plugin,{'path':m.FIXTURE,'after':m.BEFORE})
 try:m.repair_fixture(support,backup);raise AssertionError('Conflict accepted')
 except RuntimeError:pass
assert "'source_changed_reload'&&$hash!==$stale_hash" in new.decode()
assert new.decode().index('$stale_hash=$hash;$hash=')<new.decode().index("$s->editorial($a['id'],'ready_for_content_agent',88,1,$hash)")
print('PASS: fixture-only repair, original snapshot retained, idempotent resume, conflicting edits refused, stale-hash guard retained; no WP/DB')
