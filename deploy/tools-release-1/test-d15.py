#!/usr/bin/env python3
"""Execute only the interlock AST in a sandbox; never execute legacy bodies."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from legacy_guard import GUARD, require_interlocks
from safe_theme import acquire_lock, Refused

THEME = '/var/www/cyberdat-staging/public/wp-content/themes/cyberdat'
LOCK = '/run/lock/cyberdat-staging-tools-release-1.lock'
PLAN = json.loads((HERE / 'd15-plan.json').read_text())


class RedirectSandbox(ast.NodeTransformer):
    def __init__(self, theme, lock): self.theme, self.lock = str(theme), str(lock)
    def visit_Constant(self, node):
        if node.value == THEME: return ast.copy_location(ast.Constant(self.theme), node)
        if node.value == LOCK: return ast.copy_location(ast.Constant(self.lock), node)
        return node
    def visit_Compare(self, node):
        # Root-owner policy is unchanged in root runs; non-root sandbox uses its uid.
        node = self.generic_visit(node)
        if isinstance(node.left, ast.Attribute) and node.left.attr == 'st_uid':
            node.comparators = [ast.Constant(os.geteuid())]
        return node


def prefix(path):
    s = Path(path).read_text()
    if GUARD in s:
        require_interlocks([path])
        return GUARD
    expected = next(x['before'] for x in PLAN['targets'] if x['path'] == str(path))
    if hashlib.sha256(s.encode()).hexdigest() != expected: raise AssertionError('unknown pre-adoption file')
    return GUARD


class D15Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cyberdat-d15-test-')
        self.root = Path(self.tmp.name)
        self.theme = self.root / 'theme'; (self.theme / 'inc').mkdir(parents=True)
        self.lock = self.root / 'release.lock'
        self.scopes = []

    def tearDown(self): self.tmp.cleanup()

    def execute(self, guard, body_marker):
        node = ast.parse(guard)
        node = RedirectSandbox(self.theme, self.lock).visit(node)
        node.body.append(ast.Expr(ast.Call(ast.Name('sentinel', ast.Load()), [], [])))
        ast.fix_missing_locations(node)
        scope = {'sentinel': lambda: body_marker.append('legacy-body-would-start')}
        self.scopes.append(scope)
        try: exec(compile(node, '<isolated-interlock-only>', 'exec'), scope)
        finally:
            fd = scope.get('_tools_release_fd')
            if fd is not None: os.close(fd); scope.pop('_tools_release_fd')

    def test_approved_scope_is_exactly_11_plus_11(self):
        self.assertEqual(len(PLAN['targets']), 22)
        self.assertEqual(sum(x['kind'] == 'repository' for x in PLAN['targets']), 11)
        self.assertEqual(sum(x['kind'] == 'prepared' for x in PLAN['targets']), 11)
        self.assertEqual(len({x['path'] for x in PLAN['targets']}), 22)

    def test_all_candidates_compile_and_original_bodies_are_preserved(self):
        for e in PLAN['targets']:
            with self.subTest(path=e['path']):
                raw = Path(e['path']).read_bytes()
                if hashlib.sha256(raw).hexdigest() == e['after']:
                    require_interlocks([e['path']]); raw = raw.replace(GUARD.encode(), b'', 1)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), e['before'])
                a = raw.splitlines(keepends=True); i = int(a[0].startswith(b'#!'))
                candidate = b''.join(a[:i]) + GUARD.encode() + b''.join(a[i:])
                self.assertEqual(hashlib.sha256(candidate).hexdigest(), e['after'])
                compile(candidate, e['path'], 'exec')

    def test_all_22_tools_present_block_before_body_imports_or_lock(self):
        (self.theme / 'inc/tool-security.php').write_text('fixture')
        for e in PLAN['targets']:
            with self.subTest(path=e['path']):
                body = []
                with self.assertRaisesRegex(SystemExit, 'BLOCKED: Tools Release 1 installed'):
                    self.execute(prefix(e['path']), body)
                self.assertEqual(body, [])
                self.assertFalse(self.lock.exists())

    def test_all_22_release_lock_contention_blocks_before_body(self):
        with acquire_lock(self.lock):
            for e in PLAN['targets']:
                with self.subTest(path=e['path']):
                    body = []
                    with self.assertRaisesRegex(SystemExit, 'another legacy deployment'):
                        self.execute(prefix(e['path']), body)
                    self.assertEqual(body, [])

    def test_tools_absent_only_sandbox_sentinel_allowed(self):
        body = []; self.execute(GUARD, body)
        self.assertEqual(body, ['legacy-body-would-start'])

    def test_symlink_lock_refused_before_body(self):
        p = self.root / 'other';p.write_text('unrelated');self.lock.symlink_to(p)
        body = []
        with self.assertRaises(OSError): self.execute(GUARD, body)
        self.assertEqual(body, []); self.assertEqual(p.read_text(), 'unrelated')

    def test_wrong_lock_mode_refused_before_body(self):
        self.lock.write_text(''); self.lock.chmod(0o666);body = []
        with self.assertRaisesRegex(SystemExit, 'unsafe Tools release lock'): self.execute(GUARD, body)
        self.assertEqual(body, [])

    def test_read_only_checker_succeeds_without_running_guard_or_creating_lock(self):
        p = self.root / 'candidate.py';p.write_text('#!/usr/bin/env python3\n' + GUARD + 'raise AssertionError("body must never execute")\n')
        before = p.read_bytes(); require_interlocks([p])
        self.assertEqual(p.read_bytes(), before);self.assertFalse(self.lock.exists())

    def test_read_only_checker_rejects_late_guard(self):
        p = self.root / 'late.py'; p.write_text('print("danger before guard")\n' + GUARD)
        with self.assertRaises(Refused): require_interlocks([p])

    def test_scheduled_launcher_does_not_reference_any_target(self):
        s = Path('/opt/cyberdat-research/run.sh').read_text()
        self.assertIn('wp-cli.phar', s);self.assertIn('--scheduled', s)
        for e in PLAN['targets']:
            self.assertNotIn(e['path'], s)
            self.assertNotIn(Path(e['path']).name, s)


if __name__ == '__main__':
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if output and output.exists(): raise SystemExit('evidence already exists')
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(D15Tests)
    if output:
        output.mkdir(mode=0o700)
        with (output / 'tests.txt').open('w') as f: result = unittest.TextTestRunner(stream=f, verbosity=2).run(suite)
        report = {'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'pass':result.wasSuccessful() and not result.skipped,'scope':'interlock AST only; 22 candidates; no legacy body executed; temporary sandbox lock/theme paths','real_legacy_executed':False,'wp_or_sql_executed':False}
        (output / 'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
        raise SystemExit(0 if report['pass'] else 1)
    unittest.main(verbosity=2)
