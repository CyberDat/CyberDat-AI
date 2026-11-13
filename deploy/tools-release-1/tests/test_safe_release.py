#!/usr/bin/env python3
"""Offline acceptance: real files, real Linux atomic exchanges and real PHP lint.

Pages are an explicit JSON fake; no WordPress, MariaDB, HTTP or systemd is used.
The test subprocess is never the live deploy-theme.py entry point.
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
from safe_theme import Transaction, Refused, digest, manifest, verify, exchange, extract, lint, save, acquire_lock
from route_policy import validate, TOOLS
from legacy_guard import GUARD, require_interlocks

loader = importlib.util.spec_from_file_location('builder', HERE / 'build-package.py')
builder = importlib.util.module_from_spec(loader)
loader.loader.exec_module(builder)


class Crash(BaseException):
    pass


class Pages:
    """Durable fake, including revision/meta duplicates and untouched Research."""
    def __init__(self, path, theme):
        self.path, self.theme = path, theme
        self.events = []
        save(path, {'log-anonymizer': {'status': 'draft', 'meta': [['seo', 'planned'], ['tag', 'a'], ['tag', 'b']]}})

    def snapshot(self): return json.loads(self.path.read_text())

    def restore(self, before, expected):
        self.events.append(('pages_restore', (self.theme / 'new.php').exists()))
        if self.snapshot() not in [before, expected]: raise Refused('stale editorial state')
        save(self.path, before)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cyberdat-tools-offline-')
        self.root = Path(self.tmp.name)
        self.theme = self.root / 'themes/cyberdat'
        self.target = self.root / 'candidate-source'
        self.theme.mkdir(parents=True, mode=0o755)
        self.target.mkdir(mode=0o755)
        (self.theme / 'functions.php').write_text('<?php function fixture_base() {}\n')
        (self.target / 'functions.php').write_text('<?php function fixture_tools() {}\n')
        (self.target / 'new.php').write_text('<?php function fixture_new() {}\n')
        for p in [*self.theme.rglob('*'), *self.target.rglob('*')]: p.chmod(0o644)
        self.archive = self.root / 'theme.tar.gz'
        builder.archive(self.target, manifest(self.target), self.archive)
        self.spec = {'base': manifest(self.theme), 'target': manifest(self.target), 'archive_sha256': digest(self.archive)}
        self.pages = Pages(self.root / 'pages.json', self.theme)
        self.before = self.pages.snapshot()
        self.research = self.root / 'research.json'
        self.research.write_text('{"checkpoint":123,"backoff":456,"cursor":50}')
        self.research_before = self.research.read_bytes()
        self.guard_calls = 0
        self.tx = Transaction(self.theme, self.root / 'backup', self.spec, self.pages, self.guard)

    def guard(self):
        self.guard_calls += 1
        if self.research.read_bytes() != self.research_before: raise Refused('protected drift')

    def tearDown(self): self.tmp.cleanup()

    def test_install_rollback_restores_pages_before_theme(self):
        self.tx.install(self.archive)
        save(self.pages.path, {'log-anonymizer': {'status': 'publish', 'meta': [['seo', 'released']]}, 'new-page': {'status': 'draft'}})
        self.tx.record_pages()
        self.tx.rollback()
        verify(self.theme, self.spec['base'])
        self.assertEqual(self.pages.snapshot(), self.before)
        self.assertEqual(self.pages.events, [('pages_restore', True)])
        self.assertEqual(self.research.read_bytes(), self.research_before)
        self.assertTrue((self.tx.backup / 'theme-before.tar.gz').is_file())

    def test_unknown_editor_edits_block_without_switching_theme(self):
        self.tx.install(self.archive)
        save(self.pages.path, {'unknown_human_edit': 'retain me'})
        with self.assertRaisesRegex(Refused, 'unknown page'): self.tx.rollback()
        verify(self.theme, self.spec['target'])
        self.assertEqual(self.pages.snapshot(), {'unknown_human_edit': 'retain me'})

    def test_archive_checksum_failure_before_backup(self):
        self.archive.write_bytes(b'bad')
        with self.assertRaises(Refused): self.tx.install(self.archive)
        self.assertFalse(self.tx.backup.exists())
        verify(self.theme, self.spec['base'])

    def test_archive_build_is_reproducible(self):
        other = self.root / 'repeat.tar.gz'
        builder.archive(self.target, self.spec['target'], other)
        self.assertEqual(self.archive.read_bytes(), other.read_bytes())

    def test_release_lock_refuses_concurrency_symlinks_and_wrong_mode(self):
        p = self.root / 'release.lock'
        with acquire_lock(p):
            with self.assertRaises(BlockingIOError): acquire_lock(p)
        p.chmod(0o666)
        with self.assertRaises(Refused): acquire_lock(p)
        link = self.root / 'lock-link'; link.symlink_to(p)
        with self.assertRaises(OSError): acquire_lock(link)

    def test_actual_123_file_package_install_and_rollback(self):
        need_env = ['CYBERDAT_TEST_PACKAGE', 'CYBERDAT_TEST_BASE_THEME']
        if not all(os.environ.get(k) for k in need_env):
            self.skipTest('actual package/base export not supplied; run run-tests.py')
        package = Path(os.environ[need_env[0]])
        base = Path(os.environ[need_env[1]])
        spec = json.loads((package / 'package.json').read_text())
        full = self.root / 'full/themes/cyberdat'
        full.parent.mkdir(parents=True)
        shutil.copytree(base, full)
        # A Git export has no directory modes; emulate the verified live 0755/0644 tree.
        for path in [full, *full.rglob('*')]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        pages = Pages(self.root / 'full-pages.json', full)
        tx = Transaction(full, self.root / 'full-backup', spec, pages, self.guard)
        tx.install(package / 'theme.tar.gz')
        verify(full, spec['target'])
        self.assertEqual(len(manifest(full)), 123)
        tx.rollback()
        verify(full, spec['base'])
        self.assertEqual(len(manifest(full)), 95)

    def test_wrong_identity_blocks_before_writes(self):
        self.tx.guard = lambda: (_ for _ in ()).throw(Refused('wrong identity'))
        with self.assertRaises(Refused): self.tx.install(self.archive)
        self.assertFalse(self.tx.backup.exists())

    def test_mandatory_real_php_lint_blocks_syntax_error(self):
        (self.target / 'new.php').write_text('<?php syntax !broken\n')
        self.archive.unlink()
        self.spec['target'] = manifest(self.target)
        builder.archive(self.target, self.spec['target'], self.archive)
        self.spec['archive_sha256'] = digest(self.archive)
        with self.assertRaisesRegex(Refused, 'PHP lint failed'): self.tx.install(self.archive)
        verify(self.theme, self.spec['base'])

    def test_reapply_refused(self):
        self.tx.install(self.archive)
        with self.assertRaises(Refused): self.tx.install(self.archive)

    def test_backup_tampering_blocks_rollback(self):
        self.tx.install(self.archive)
        (self.tx.backup / 'theme-before.tar.gz').write_bytes(b'tampered')
        with self.assertRaisesRegex(Refused, 'backup checksum'): self.tx.rollback()
        verify(self.theme, self.spec['target'])

    def test_journal_permissions_block_rollback(self):
        self.tx.install(self.archive)
        self.tx.journal.chmod(0o644)
        with self.assertRaisesRegex(Refused, 'journal mode'): self.tx.rollback()

    def test_protected_drift_blocks_rollback(self):
        self.tx.install(self.archive)
        self.research.write_text('changed outside release')
        with self.assertRaisesRegex(Refused, 'protected drift'): self.tx.rollback()
        verify(self.theme, self.spec['target'])

    def test_unexpected_file_rejected(self):
        (self.theme / 'unexpected.txt').write_text('x')
        with self.assertRaisesRegex(Refused, 'file set'): self.tx.install(self.archive)

    def test_unexpected_empty_directory_rejected(self):
        (self.theme / 'unexpected').mkdir()
        with self.assertRaisesRegex(Refused, 'directory'): self.tx.install(self.archive)

    def test_symlink_rejected(self):
        (self.theme / 'link').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(Refused, 'symlink'): self.tx.install(self.archive)

    def test_group_writable_file_rejected(self):
        (self.theme / 'functions.php').chmod(0o664)
        with self.assertRaisesRegex(Refused, 'permissions'): self.tx.install(self.archive)

    def test_private_directory_rejected_as_live_theme(self):
        self.theme.chmod(0o700)
        with self.assertRaisesRegex(Refused, 'permissions'): self.tx.install(self.archive)

    def test_atomic_exchange_failure_keeps_base(self):
        with patch('safe_theme.exchange', side_effect=Refused('unsupported filesystem')):
            with self.assertRaises(Refused): self.tx.install(self.archive)
        verify(self.theme, self.spec['base'])

    def test_live_path_never_absent_during_repeated_real_exchanges(self):
        errors, stop = [], threading.Event()
        def observe():
            while not stop.is_set():
                try:
                    if not self.theme.is_dir(): errors.append('missing')
                    os.stat(self.theme)
                except FileNotFoundError: errors.append('ENOENT')
        t = threading.Thread(target=observe)
        t.start()
        try:
            for _ in range(100): exchange(self.theme, self.target)
        finally:
            stop.set(); t.join()
        self.assertEqual(errors, [])

    def test_tar_link_traversal_and_duplicate_rejected(self):
        for name, kind in [('cyberdat/../escape', tarfile.REGTYPE), ('cyberdat/functions.php', tarfile.SYMTYPE), ('/escape', tarfile.REGTYPE)]:
            with self.subTest(name=name):
                archive = self.root / 'evil.tar.gz'
                with tarfile.open(archive, 'w:gz') as tf:
                    m = tarfile.TarInfo(name); m.type = kind; m.linkname = '/etc/passwd';tf.addfile(m)
                with self.assertRaises(Refused): extract(archive, self.root / 'bad-extract', self.spec['target'])
                self.assertFalse((self.root / 'bad-extract').exists())

    def test_tar_valid_count_with_hostile_member_rejected_before_extract(self):
        for change in ['traversal', 'symlink', 'duplicate', 'mode', 'size']:
            with self.subTest(change=change):
                archive = self.root / 'hostile.tar.gz'
                with tarfile.open(self.archive) as source, tarfile.open(archive, 'w:gz') as tf:
                    for m in source.getmembers():
                        b = source.extractfile(m).read() if m.isfile() else None
                        if m.name == 'cyberdat/new.php':
                            if change == 'traversal': m.name = 'cyberdat/../escape.php'
                            elif change == 'symlink': m.type = tarfile.SYMTYPE; m.linkname = '/etc/passwd'; m.size = 0; b = None
                            elif change == 'duplicate': m.name = 'cyberdat/functions.php'
                            elif change == 'mode': m.mode = 0o777
                            elif change == 'size': m.size += 1; b += b'x'
                        tf.addfile(m, io.BytesIO(b) if b is not None else None)
                with self.assertRaises(Refused): extract(archive, self.root / 'hostile-dest', self.spec['target'])
                self.assertFalse((self.root / 'hostile-dest').exists())

    def test_legacy_interlock_aborts_before_old_code(self):
        with patch('pathlib.Path') as fake:
            fake.return_value.__truediv__.return_value.exists.return_value = True
            with self.assertRaisesRegex(SystemExit, 'BLOCKED: Tools Release 1'):
                exec(compile(GUARD + '\nraise AssertionError("old code executed")', 'isolated-legacy', 'exec'), {})

    def test_php_staging_contract_positive_and_each_wrong_field(self):
        code = '''<?php
require $argv[1];
$good = array('cli'=>true,'sapi'=>'cli','root'=>'/var/www/cyberdat-staging/public','db'=>'cyberdat_staging','prefix'=>'stg_','environment'=>'staging','home'=>'https://staging.cyberdat.eu','siteurl'=>'https://staging.cyberdat.eu','stylesheet'=>'cyberdat','template'=>'cyberdat','capability'=>true);
if (!cd_tools_identity_valid($good)) { exit(1); }
foreach ($good as $key=>$value) { $bad=$good; $bad[$key]=false; if (cd_tools_identity_valid($bad)) { exit(2); } }
try { cd_tools_assert_staging(); exit(3); } catch (RuntimeException $e) { echo '12 identity cases and missing-bootstrap rejection'; }
'''
        p = self.root / 'identity.php'; p.write_text(code)
        r = subprocess.run(['/usr/bin/php8.4', '-n', str(p), str(HERE / 'staging-contract.php')], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('12 identity cases', r.stdout)

    def test_route_policy_all_four_published_and_planned(self):
        catalog = [{'slug': k, 'status': 'available'} for k in TOOLS] + [{'slug': 'future', 'status': 'planned'}]
        state = {k: {'published': True, 'ready': True, 'renderer': v[0]} for k, v in TOOLS.items()}
        def fetch(path):
            slug = path.split('/')[2]
            return (200, TOOLS[slug][1].encode()) if slug in TOOLS else (404, b'')
        self.assertEqual(sum(v == 200 for v in validate(catalog, state, fetch).values()), 4)
        state['log-anonymizer']['renderer'] = 'wrong'
        with self.assertRaises(Refused): validate(catalog, state, fetch)

    def test_route_policy_available_but_unpublished_requires_404(self):
        catalog = [{'slug': k, 'status': 'available'} for k in TOOLS]
        self.assertTrue(all(v == 404 for v in validate(catalog, {}, lambda p: (404, b'')).values()))
        with self.assertRaises(Refused): validate(catalog, {}, lambda p: (200, b'placeholder'))

    def test_route_policy_planned_200_is_failure(self):
        catalog = [{'slug': k, 'status': 'available'} for k in TOOLS] + [{'slug': 'future', 'status': 'planned'}]
        with self.assertRaises(Refused): validate(catalog, {}, lambda p: (200 if '/future/' in p else 404, b''))

    def test_legacy_interlock_adoption_is_required(self):
        p = self.root / 'legacy.py'; p.write_text('print("dangerous")\n')
        with self.assertRaises(Refused): require_interlocks([p])
        p.write_text('#!/usr/bin/python3\n' + GUARD + '\nprint("old deployment")\n')
        require_interlocks([p])
        p.write_text('print("too late")\n' + GUARD)
        with self.assertRaises(Refused): require_interlocks([p])

    def test_prepared_cli_context_has_same_sandbox_and_private_helpers(self):
        sp = importlib.util.spec_from_file_location('live_prepared', HERE / 'deploy-theme.py')
        live = importlib.util.module_from_spec(sp); sp.loader.exec_module(live)
        with patch.object(live, 'sql_read_identity'), patch.object(live, 'checked_controls'), patch.object(live.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='{}', stderr='')) as run:
            live.Pages('a' * 64).snapshot()
            cmd = run.call_args.args[0]
            self.assertIn('HOME=/var/lib/cyberdat-staging', cmd)
            self.assertIn('WP_CLI_CONFIG_PATH=/var/lib/cyberdat-staging/cli.yml', cmd)
            self.assertIn('--skip-plugins=cyberdat-research,cyberdat-content', cmd)
            self.assertIn('--user=cyberdat_staging_admin', cmd)
            self.assertEqual(run.call_args.kwargs['cwd'], '/var/lib/cyberdat-staging/research')
            self.assertFalse(any('/root/' in s for s in cmd))
            self.assertIn('opcache.enable_cli=0', cmd)

    def test_install_authorization_requires_exact_package_and_future_approval(self):
        sp = importlib.util.spec_from_file_location('live_authorization', HERE / 'deploy-theme.py')
        live = importlib.util.module_from_spec(sp); sp.loader.exec_module(live)
        package = self.root / 'package.json'; save(package, self.spec)
        a = {'origin': live.ORIGIN, 'research_commit': live.RESEARCH,
             'artifact_sha256': self.spec['archive_sha256'], 'package_sha256': digest(package),
             'install_approved': True, 'legacy_interlocks_approved': True, 'expires_epoch': time.time() + 1000}
        auth = self.root / 'authorization.json'
        with patch.object(live, 'private_root_file'):
            save(auth, a); live.authorize(auth, self.spec, package)
            for field in a:
                bad = dict(a); bad[field] = False; save(auth, bad)
                with self.subTest(field=field), self.assertRaises((Refused, TypeError)):
                    live.authorize(auth, self.spec, package)


def failure_case(point, crash=False):
    def test(self):
        def fail(p):
            if p == point: raise (Crash(point) if crash else RuntimeError(point))
        self.tx.fault = fail
        with self.assertRaises(Crash if crash else RuntimeError): self.tx.install(self.archive)
        self.tx.fault = lambda p: None
        if crash: self.tx.recover()
        verify(self.theme, self.spec['base'])
        self.assertEqual(self.pages.snapshot(), self.before)
        self.assertEqual(self.research.read_bytes(), self.research_before)
    return test


for point in ['after_backup', 'after_extract', 'after_lint', 'before_exchange', 'after_exchange', 'after_verify', 'after_active']:
    for crash in [False, True]:
        setattr(ReleaseTests, 'test_' + ('crash_' if crash else 'failure_') + point, failure_case(point, crash))


def rollback_failure_case(point):
    def test(self):
        self.tx.install(self.archive)
        save(self.pages.path, {'published': 'only deployment-owned change'})
        self.tx.record_pages()
        self.tx.fault = lambda p: (_ for _ in ()).throw(Crash(p)) if p == point else None
        with self.assertRaises(Crash): self.tx.rollback()
        self.tx.fault = lambda p: None
        self.tx.recover()
        verify(self.theme, self.spec['base'])
        self.assertEqual(self.pages.snapshot(), self.before)
    return test


for point in ['before_pages_restore', 'after_pages_restore', 'after_rollback_exchange']:
    setattr(ReleaseTests, 'test_rollback_crash_' + point, rollback_failure_case(point))


if __name__ == '__main__': unittest.main(verbosity=2)
