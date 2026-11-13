#!/usr/bin/env python3
"""Run offline/sandbox suite and preserve exact results, never staging writes."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--package', required=True, type=Path)
    p.add_argument('--base-theme', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    if a.output.exists(): raise SystemExit('evidence output already exists')
    a.output.mkdir(mode=0o700)
    os.environ['CYBERDAT_TEST_PACKAGE'] = str(a.package.resolve())
    os.environ['CYBERDAT_TEST_BASE_THEME'] = str(a.base_theme.resolve())
    sp = importlib.util.spec_from_file_location('safe_tests', HERE / 'tests/test_safe_release.py')
    module = importlib.util.module_from_spec(sp); sp.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    php = []
    for name in ['staging-contract.php', 'wp-state.php', 'tool-pages.php']:
        r = subprocess.run(['/usr/bin/php8.4', '-n', '-l', str(HERE / name)], capture_output=True, text=True)
        php.append({'file': name, 'exit': r.returncode})
    with (a.output / 'unittest.txt').open('w') as f:
        result = unittest.TextTestRunner(stream=f, verbosity=2).run(suite)
    report = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'scope': 'offline/sandbox only; fake JSON pages, real Linux atomic exchange and PHP lint',
              'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
              'skipped': len(result.skipped), 'php_lint': php,
              'archive_sha256': hashlib.sha256((a.package / 'theme.tar.gz').read_bytes()).hexdigest(),
              'staging_deployment': False, 'wordpress_bootstrap': False, 'sql_execution': False,
              'unverified': ['live FPM/OPcache and renderer HTTP', 'real WordPress selective SQL restore', 'browser acceptance']}
    if json.loads((HERE / 'legacy-entrypoints.json').read_text()).get('status') != 'APPLIED_APPROVED_SCOPE':
        report['unverified'].append('legacy interlocks adoption')
    report['pass'] = result.wasSuccessful() and not result.skipped and all(x['exit'] == 0 for x in php)
    (a.output / 'tests.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    raise SystemExit(0 if report['pass'] else 1)
