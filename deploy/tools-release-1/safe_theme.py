#!/usr/bin/env python3
"""Theme-only transaction engine. No WordPress/bootstrap/systemd/network imports.

Live paths and authorization exist only in deploy-theme.py. Tests use this same
engine with private temporary directories and an explicit fake pages adapter.
"""
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import uuid


class Refused(RuntimeError):
    pass


def need(ok, message):
    if not ok:
        raise Refused(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def acquire_lock(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid()
             and stat.S_IMODE(st.st_mode) == 0o600, 'unsafe release lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return os.fdopen(fd, 'r+')
    except BaseException:
        os.close(fd)
        raise


def manifest(root):
    root = Path(root)
    need(not root.is_symlink() and root.is_dir(), 'theme root must be a real directory')
    result = {}
    for p in sorted(root.rglob('*')):
        need(not p.is_symlink(), 'symlink refused: ' + str(p))
        need(p.is_file() or p.is_dir(), 'special file refused')
        if p.is_file():
            result[p.relative_to(root).as_posix()] = {
                'sha256': digest(p), 'bytes': p.stat().st_size, 'mode': '0644'}
    return result


def directories(files):
    out = {'.'}
    for name in files:
        p = PurePosixPath(name)
        need(not p.is_absolute() and '..' not in p.parts and p.as_posix() == name,
             'invalid manifest path')
        out.update(x.as_posix() for x in p.parents)
    return out


def verify(root, expected, owner=None):
    root = Path(root)
    actual = manifest(root)
    need(actual == expected, 'theme file set, length or SHA256 mismatch')
    dirs = directories(expected)
    actual_dirs = {'.'} | {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_dir()}
    need(actual_dirs == dirs, 'unexpected or missing theme directory')
    for p in [root, *root.rglob('*')]:
        st = p.stat()
        want = 0o755 if p.is_dir() else 0o644
        need(stat.S_IMODE(st.st_mode) == want, 'unsafe theme permissions: ' + str(p))
        if owner is not None:
            need((st.st_uid, st.st_gid) == tuple(owner), 'unexpected theme ownership')


def syncdir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value):
    path = Path(path)
    need(not path.is_symlink(), 'journal symlink refused')
    tmp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.partial')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(canonical(value) + '\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    syncdir(path.parent)


def exchange(a, b):
    """Linux RENAME_EXCHANGE. Fail closed; never use a pair of renames."""
    a, b = Path(a), Path(b)
    need(a.is_dir() and b.is_dir() and not a.is_symlink() and not b.is_symlink(),
         'exchange needs two real directories')
    need(a.stat().st_dev == b.stat().st_dev, 'atomic exchange requires same filesystem')
    libc = ctypes.CDLL(None, use_errno=True)
    need(hasattr(libc, 'renameat2'), 'RENAME_EXCHANGE unavailable; no fallback')
    fn = libc.renameat2
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    fn.restype = ctypes.c_int
    need(fn(-100, os.fsencode(a), -100, os.fsencode(b), 2) == 0,
         'atomic exchange failed, errno=' + str(ctypes.get_errno()))
    syncdir(a.parent)
    syncdir(b.parent)


def extract(archive, dest, expected, owner=None):
    """Validate every tar member before extracting any file; no extractall()."""
    dest = Path(dest)
    need(not dest.exists(), 'candidate already exists')
    allowed_dirs = directories(expected)
    with tarfile.open(archive, 'r:gz') as tf:
        members = tf.getmembers()
        need(len(members) == len(expected) + len(allowed_dirs), 'archive member count mismatch')
        seen, content = set(), {}
        for m in members:
            name = m.name.rstrip('/')
            p = PurePosixPath(name)
            need(name not in seen and p.as_posix() == name and not p.is_absolute() and '..' not in p.parts,
                 'duplicate or unsafe archive path')
            seen.add(name)
            need(p.parts and p.parts[0] == 'cyberdat', 'archive outside theme')
            rel = PurePosixPath(*p.parts[1:]).as_posix()
            if m.isdir():
                need(rel in allowed_dirs and m.mode == 0o755, 'unexpected archive directory/mode')
            else:
                need(m.isfile() and not m.issym() and not m.islnk() and rel in expected,
                     'unexpected archive file/link')
                need(m.mode == 0o644 and m.size == expected[rel]['bytes'], 'archive size/mode mismatch')
                b = tf.extractfile(m).read(m.size + 1)
                need(hashlib.sha256(b).hexdigest() == expected[rel]['sha256'], 'archive SHA256 mismatch')
                content[rel] = b
        need(set(content) == set(expected), 'archive missing files')
    dest.mkdir(mode=0o755)
    for name in sorted(allowed_dirs, key=lambda x: (len(PurePosixPath(x).parts), x)):
        if name != '.':
            (dest / name).mkdir(mode=0o755, exist_ok=True)
    for name, b in content.items():
        p = dest / name
        with p.open('xb') as f:
            f.write(b)
            f.flush()
            os.fsync(f.fileno())
        p.chmod(0o644)
    for p in [dest, *dest.rglob('*')]:
        p.chmod(0o755 if p.is_dir() else 0o644)
        if owner is not None:
            os.chown(p, *owner)
    for p in sorted([dest, *(p for p in dest.rglob('*') if p.is_dir())], key=lambda p: len(p.parts), reverse=True):
        syncdir(p)
    verify(dest, expected, owner)


def lint(root, php='/usr/bin/php8.4'):
    files = sorted(Path(root).rglob('*.php'))
    need(bool(files), 'no PHP files to lint')
    for p in files:
        r = subprocess.run([php, '-n', '-l', str(p)], capture_output=True, timeout=20)
        need(r.returncode == 0, 'PHP lint failed: ' + p.name)
    return len(files)


class Transaction:
    def __init__(self, theme, backup, spec, pages, guard, owner=None, fault=None):
        self.theme, self.backup = Path(theme), Path(backup)
        self.spec, self.pages, self.guard, self.owner = spec, pages, guard, owner
        self.fault = fault or (lambda point: None)
        self.journal = self.backup / 'transaction.json'

    def mark(self, state, **values):
        self.data.update(values)
        self.data['state'] = state
        save(self.journal, self.data)

    def install(self, archive):
        self.guard()
        verify(self.theme, self.spec['base'], self.owner)
        need(digest(archive) == self.spec['archive_sha256'], 'package checksum mismatch')
        need(not self.backup.exists(), 'backup already exists; recover, never reapply')
        self.backup.mkdir(mode=0o700)
        with tarfile.open(self.backup / 'theme-before.tar.gz', 'w:gz', dereference=False) as tf:
            tf.add(self.theme, arcname='cyberdat')
        (self.backup / 'theme-before.tar.gz').chmod(0o600)
        with (self.backup / 'theme-before.tar.gz').open('rb') as f:
            os.fsync(f.fileno())
        private = self.theme.parent / ('.tools-release-1-' + uuid.uuid4().hex)
        private.mkdir(mode=0o700)
        slot = private / 'cyberdat'
        self.data = {'schema': 1, 'theme': str(self.theme), 'slot': str(slot),
                     'base': self.spec['base'], 'target': self.spec['target'],
                     'archive_sha256': self.spec['archive_sha256'], 'pages_before': self.pages.snapshot()}
        self.data['base_archive_sha256'] = digest(self.backup / 'theme-before.tar.gz')
        self.data['pages_expected'] = self.data['pages_before']
        self.mark('preparing')
        try:
            self.fault('after_backup')
            extract(archive, slot, self.spec['target'], self.owner)
            self.fault('after_extract')
            lint(slot)
            self.fault('after_lint')
            verify(self.theme, self.spec['base'], self.owner)
            self.guard()
            self.mark('install_exchange_intent')
            self.fault('before_exchange')
            exchange(self.theme, slot)
            self.fault('after_exchange')
            verify(self.theme, self.spec['target'], self.owner)
            verify(slot, self.spec['base'], self.owner)
            self.guard()
            self.fault('after_verify')
            self.mark('active')
            self.fault('after_active')
        except Exception:
            self.recover()
            raise
        return self.data

    def load(self):
        need(self.journal.is_file() and not self.journal.is_symlink(), 'missing/unsafe journal')
        need(stat.S_IMODE(self.journal.stat().st_mode) == 0o600, 'unsafe journal mode')
        self.data = json.loads(self.journal.read_text())
        need(digest(self.backup / 'theme-before.tar.gz') == self.data['base_archive_sha256'],
             'original theme backup checksum mismatch')
        need(self.data['theme'] == str(self.theme), 'journal target conflict')
        need(self.data['base'] == self.spec['base'] and self.data['target'] == self.spec['target']
             and self.data['archive_sha256'] == self.spec['archive_sha256'], 'journal release conflict')
        slot = Path(self.data['slot'])
        need(slot.name == 'cyberdat' and slot.parent.parent == self.theme.parent
             and slot.parent.name.startswith('.tools-release-1-') and not slot.parent.is_symlink(),
             'journal candidate path conflict')
        need(stat.S_IMODE(slot.parent.stat().st_mode) == 0o700, 'candidate parent is not private')
        return slot

    def record_pages(self):
        self.guard()
        self.load()
        need(self.data['state'] == 'active', 'cannot record pages outside active release')
        verify(self.theme, self.spec['target'], self.owner)
        self.mark('active', pages_expected=self.pages.snapshot())

    def rollback(self):
        self.guard()
        slot = self.load()
        verify(self.theme, self.spec['target'], self.owner)
        verify(slot, self.spec['base'], self.owner)
        current = self.pages.snapshot()
        need(current in [self.data['pages_expected'], self.data['pages_before']],
             'unknown page/meta changes; keep active theme, do not overwrite edits')
        self.mark('rollback_pages_intent')
        self.fault('before_pages_restore')
        self.pages.restore(self.data['pages_before'], self.data['pages_expected'])
        need(self.pages.snapshot() == self.data['pages_before'], 'page restore verification failed')
        self.mark('pages_restored')
        self.fault('after_pages_restore')
        self.guard()
        self.mark('rollback_exchange_intent')
        exchange(self.theme, slot)
        self.fault('after_rollback_exchange')
        verify(self.theme, self.spec['base'], self.owner)
        self.mark('rolled_back')

    def recover(self):
        self.guard()
        slot = self.load()
        actual = manifest(self.theme)
        if actual == self.spec['target']:
            self.rollback()
        elif actual == self.spec['base']:
            verify(self.theme, self.spec['base'], self.owner)
            need(self.pages.snapshot() == self.data['pages_before'],
                 'base theme but pages not restored; manual investigation required')
            self.mark('rolled_back' if slot.exists() else 'failed_before_exchange')
        else:
            raise Refused('unknown active theme; no destructive recovery')
