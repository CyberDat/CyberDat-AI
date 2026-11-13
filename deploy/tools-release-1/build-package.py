#!/usr/bin/env python3
"""Build theme-only deterministic archive; never reads a deployed WordPress."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from safe_theme import need, manifest, directories, lint, save, digest

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent


def archive(theme, files, output):
    with output.open('xb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w', format=tarfile.USTAR_FORMAT) as tf:
                for name in sorted(directories(files), key=lambda n: (len(Path(n).parts), n)):
                    t = tarfile.TarInfo('cyberdat' + ('' if name == '.' else '/' + name))
                    t.type, t.mode, t.mtime = tarfile.DIRTYPE, 0o755, 0
                    tf.addfile(t)
                for name, entry in sorted(files.items()):
                    b = (theme / name).read_bytes()
                    t = tarfile.TarInfo('cyberdat/' + name)
                    t.size, t.mode, t.mtime = len(b), 0o644, 0
                    tf.addfile(t, io.BytesIO(b))
    output.chmod(0o600)


def build(base, out):
    need(not out.exists(), 'output exists; do not overwrite evidence')
    theme = REPO / 'wp-content/themes/cyberdat'
    trees = json.loads((HERE / 'git-theme-trees.json').read_text())
    for kind, root in [('base', base), ('target', theme)]:
        expected = {x['path'].split('wp-content/themes/cyberdat/', 1)[1]: x['sha'] for x in trees[kind]}
        actual = manifest(root)
        need(set(actual) == set(expected), kind + ' Git file set mismatch')
        for name, sha in expected.items():
            b = (root / name).read_bytes()
            need(hashlib.sha1(b'blob ' + str(len(b)).encode() + b'\0' + b).hexdigest() == sha,
                 kind + ' pinned Git bytes mismatch: ' + name)
    count = lint(theme)
    spec = {'schema': 'cyberdat-theme-release/1',
            'research_commit': '0ef03e9cb0d8821546983c84fc6998e85cf03f2e',
            'tools_commit': 'eb9de8d2c51a515663d48205394cf7300bc0deae',
            'theme_commit': 'cd7df0c2a2fa5b5634977d765884b599a3495340',
            'base': manifest(base), 'target': manifest(theme)}
    need(len(spec['base']) == 95 and len(spec['target']) == 123, 'pinned file counts changed')
    need(not (set(spec['base']) - set(spec['target'])), 'theme deletion refused')
    need(sum(spec['base'].get(k) != v for k, v in spec['target'].items()) == 32, 'unexpected theme delta')
    out.mkdir(mode=0o700)
    archive(theme, spec['target'], out / 'theme.tar.gz')
    spec['archive_sha256'] = digest(out / 'theme.tar.gz')
    save(out / 'package.json', spec)
    (out / 'SHA256SUMS').write_text(''.join(digest(out / n) + '  ' + n + '\n' for n in ['theme.tar.gz', 'package.json']))
    (out / 'SHA256SUMS').chmod(0o600)
    print(json.dumps({'files': 123, 'base_files': 95, 'php_linted': count,
                      'archive_sha256': spec['archive_sha256'], 'package_sha256': digest(out / 'package.json')}))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--base-theme', required=True, type=Path, help='isolated export of Research 0ef03e9 theme')
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    build(a.base_theme, a.output)
