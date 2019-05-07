
from .filecrypt import (
    file_encrypt,
    file_decrypt,
    path_encode,
    path_decode,
    path_hash,
)
from pathlib import Path
import os, stat

from nacl.utils import random as randombytes
from nacl.pwhash import argon2i
from nacl.secret import SecretBox
from nacl.hash import generichash
from nacl.bindings import crypto_secretstream_xchacha20poly1305_KEYBYTES as KEYBYTES

chunk_size = 4096

def make_metadata(path, mode, mtime, ctime):
    mode_bytes = mode.to_bytes(4, byteorder='little', signed=False)
    mtime_bytes = mtime.to_bytes(8, byteorder='little', signed=False)
    ctime_bytes = ctime.to_bytes(8, byteorder='little', signed=False)
    path_bytes = path_encode(path)
    return mode_bytes + mtime_bytes + ctime_bytes + path_bytes

def dest_metadata(metadata):
    mode = int.from_bytes(metadata[0:4], byteorder='little', signed=False)
    mtime = int.from_bytes(metadata[4:12], byteorder='little', signed=False)
    ctime = int.from_bytes(metadata[12:20], byteorder='little', signed=False)
    path = path_decode(metadata[20:])
    return (path, mode, mtime, ctime)

class DirCrypt(object):
    """ API for accessing an encrypted directory """

    def __init__(self, dir_root, version, exclude, config, key):
        self.dir_type = 'crypt'
        self.dir_root = dir_root
        self.version = version
        self.exclude = exclude
        self.config = config
        self.key = key

    def collect_paths(self):
        self.included = dict()
        self.excluded = set()
        for cwd, dirs, files in os.walk(self.dir_root, followlinks=False):
            for d in dirs:
                if any(pat.fullmatch(d) for pat in self.exclude):
                    path = Path(os.path.relpath(os.path.join(cwd, d), self.dir_root))
                    self.excluded.add(path)
                    # This prevents os.walk from walking excluded directories.
                    dirs.remove(d)
            for f in files:
                crypt_file = os.path.join(cwd, f)
                crypt_path = Path(os.path.relpath(crypt_file, self.dir_root))
                crypt_mode = os.stat(crypt_file).st_mode
                if any(pat.fullmatch(f) for pat in self.exclude) or not stat.S_ISREG(crypt_mode):
                    self.excluded.add(crypt_path)
                else:
                    metadata = file_decrypt(self.key, crypt_file, None, metadata_only=True)
                    path, mode, mtime, ctime = dest_metadata(metadata)
                    assert path_hash(self.key, path) == crypt_path
                    self.included[path] = {'mode': mode, 'mtime': mtime, 'ctime': ctime}

    def get_path_type(self, path):
        if path in self.included:
            meta = self.included[path]
            if 'mode' in meta:
                mode = meta['mode']
                if stat.S_ISDIR(mode):
                    return 'DIR'
                if stat.S_ISREG(mode):
                    return 'FILE'
        return None

    def get_path_times(self, path):
        if path in self.included:
            meta = self.included[path]
            return (meta.get('mtime', None), meta.get('ctime', None))
        return (None, None)

    def get_path_mode(self, path):
        if path in self.included:
            meta = self.included[path]
            return meta.get('mode', None)
        return None

    def remove_dir(self, path, res):
        self.remove_file(path, res)

    def remove_file(self, path, res):
        crypt_file = self.dir_root / path_hash(self.key, path)
        try:
            os.remove(crypt_file)
            res.succ_removed_files.append(path)
        except e:
            res.fail_removed_dirs.append((path, str(e)))

    def make_dir(self, path, mode, res):
        metadata = make_metadata(path, stat.S_IFDIR | stat.S_IMODE(mode), 0, 0)
        crypt_file = self.dir_root / path_hash(self.key, path)
        try:
            os.makedirs(crypt_file.parent, exist_ok=True)
            file_encrypt(self.key, None, crypt_file, metadata, chunk_size)
            res.succ_added_dirs.append(path)
        except e:
            res.fail_added_dirs.append((path, str(e)))

    def push_file(self, path, src_file, res):
        st = os.stat(src_file, follow_symlinks=False)
        metadata = make_metadata(path, st.st_mode, st.st_mtime_ns, st.st_ctime_ns)
        crypt_file = self.dir_root / path_hash(self.key, path)
        try:
            os.makedirs(crypt_file.parent, exist_ok=True)
            file_encrypt(self.key, src_file, crypt_file, metadata, chunk_size)
            res.succ_added_dirs.append(path)
        except e:
            res.fail_added_dirs.append((path, str(e)))

    def pull_file(self, path, dst_file, res):
        crypt_file = self.dir_root / path_hash(self.key, path)
        def md_test(md):
            p, m, _, _ = dest_metadata(md)
            return p == path and stat.S_ISREG(m)
        try:
            metadata = file_decrypt(self.key, crypt_file, dst_file, metadata_test=md_test)
            _, mode, mtime, _ = dest_metadata(metadata)
            os.chmod(dst_file, stat.S_IMODE(mode))
            os.utime(dst_file, ns=(mtime, mtime))
            res.succ_copied_files.append(path)
        except e:
            res.fail_copied_files.append((path, str(e)))
