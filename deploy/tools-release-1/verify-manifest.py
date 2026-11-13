#!/usr/bin/env python3
"""Read-only check of a theme directory against deploy/tools-release-1/manifest.json.

  python3 verify-manifest.py <theme_dir> [--manifest manifest.json] [--expect target|base]

--expect target (default): every listed file must exist with the manifest sha256 (after deployment, or on an exported
                           copy before deployment).
--expect base:             state BEFORE deployment: modified files must match base_sha256, added files must be absent.
Prints one line per file (path, status, first 12 hex of sha256) and exits 1 on any mismatch. Never modifies files.
"""
import argparse
import hashlib
import json
import pathlib
import sys


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('theme_dir')
    ap.add_argument('--manifest', default=str(pathlib.Path(__file__).with_name('manifest.json')))
    ap.add_argument('--expect', choices=['target', 'base'], default='target')
    a = ap.parse_args()
    theme = pathlib.Path(a.theme_dir)
    manifest = json.loads(pathlib.Path(a.manifest).read_text(encoding='utf-8'))
    bad = 0
    for rel, e in sorted(manifest['files'].items()):
        p = theme / rel
        if a.expect == 'target':
            want = e.get('sha256')
            if e['status'] == 'deleted':
                ok, got = not p.exists(), ('present' if p.exists() else 'absent')
            else:
                got = sha256(p) if p.is_file() else 'MISSING'
                ok = got == want
        else:
            if e['status'] == 'added':
                got = 'present' if p.exists() else 'absent'
                ok = not p.exists()
            else:
                got = sha256(p) if p.is_file() else 'MISSING'
                ok = got == e.get('base_sha256')
        bad += 0 if ok else 1
        print(('OK       ' if ok else 'MISMATCH ') + rel + '  ' + (got[:12] if len(got) == 64 else got))
    print('%d files, %d mismatches (expect=%s, theme_commit=%s)' % (len(manifest['files']), bad, a.expect, manifest['theme_commit'][:12]))
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
