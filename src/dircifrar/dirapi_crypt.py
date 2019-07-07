
from .__init__ import (
    __crypt_metafile__,
    __crypt_dirname__,
)
from .filecrypt import (
    file_encrypt,
    file_decrypt,
    bytes_encrypt,
    bytes_decrypt,
    path_encode,
    path_decode,
    path_hash,
)
from pathlib import Path
import os, stat, json, tempfile

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

def meta_encode_metadata(data):
    return (len(data) + 1).to_bytes(4, byteorder='little', signed=False) + b'\x00' + data

def meta_encode_path(path):
    code = path_encode(path)
    return (len(code) + 1).to_bytes(4, byteorder='little', signed=False) + b'\x01' + code

class DirCrypt(object):
    """ API for accessing an encrypted directory """

    def __init__(self, dir_root, version, exclude, config, crypt_key):
        self.dir_type = 'crypt'
        self.dir_root = dir_root
        self.version = version
        self.exclude = exclude
        self.config = config
        self.crypt_key = crypt_key
        self.crypt_dir = dir_root / __crypt_dirname__
        self.crypt_meta = dir_root / __crypt_metafile__

    def collect_paths(self, force_collect=False):
        self.included = dict()
        self.excluded = set()

        if not self.crypt_meta.is_file() or force_collect:
            for cwd, dirs, files in os.walk(self.crypt_dir, followlinks=False):
                for d in dirs:
                    if any(pat.fullmatch(d) for pat in self.exclude):
                        path = Path(os.path.relpath(os.path.join(cwd, d), self.crypt_dir))
                        self.excluded.add(path)
                        # This prevents os.walk from walking excluded directories.
                        dirs.remove(d)
                for f in files:
                    crypt_file = os.path.join(cwd, f)
                    crypt_path = Path(os.path.relpath(crypt_file, self.crypt_dir))
                    crypt_mode = os.stat(crypt_file).st_mode
                    if any(pat.fullmatch(f) for pat in self.exclude) or not stat.S_ISREG(crypt_mode):
                        self.excluded.add(crypt_path)
                    else:
                        metadata = file_decrypt(self.crypt_key, crypt_file, None, metadata_only=True)
                        path, mode, mtime, ctime = dest_metadata(metadata)
                        assert path_hash(self.crypt_key, path) == crypt_path
                        self.included[path] = {'mode': mode, 'mtime': mtime, 'ctime': ctime}

        else:
            meta_bytes = bytes_decrypt(self.crypt_key, self.crypt_meta)
            i = 0
            while i < len(meta_bytes):
                size = int.from_bytes(meta_bytes[i : i+4], byteorder='little', signed=False)
                i += 4
                type = meta_bytes[i : i+1]
                data = meta_bytes[i+1 : i+size]
                i += size
                if type == b'\x00':
                    path, mode, mtime, ctime = dest_metadata(data)
                    self.included[path] = {'mode': mode, 'mtime': mtime, 'ctime': ctime}
                else:
                    path = path_decode(data)
                    self.excluded.add(path)

    def output_paths(self):
        meta_bytes = b''
        for path in self.included:
            meta = self.included[path]
            metadata = make_metadata(path, meta['mode'], meta['mtime'], meta['ctime'])
            meta_bytes += meta_encode_metadata(metadata)
        for path in self.excluded:
            meta_bytes += meta_encode_path(path)
        bytes_encrypt(self.crypt_key, meta_bytes, self.crypt_meta, chunk_size)

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
        self.remove_file(path, res, is_dir=True)

    def remove_file(self, path, res, is_dir=False):
        crypt_file = self.crypt_dir / path_hash(self.crypt_key, path)
        try:
            os.remove(crypt_file)
            del self.included[path]
            if is_dir:
                res.succ_removed_dirs.append(path)
            else:
                res.succ_removed_files.append(path)
        except e:
            if is_dir:
                res.fail_removed_dirs.append((path, str(e)))
            else:
                res.fail_removed_files.append((path, str(e)))

    def make_dir(self, path, mode, res):
        dir_mode = stat.S_IFDIR | stat.S_IMODE(mode)
        metadata = make_metadata(path, dir_mode, 0, 0)
        crypt_file = self.crypt_dir / path_hash(self.crypt_key, path)
        try:
            os.makedirs(crypt_file.parent, exist_ok=True)
            file_encrypt(self.crypt_key, None, crypt_file, metadata, chunk_size)
            self.included[path] = {'mode': dir_mode, 'mtime': 0, 'ctime': 0}
            res.succ_added_dirs.append(path)
        except e:
            res.fail_added_dirs.append((path, str(e)))

    def push_file(self, path, src_file, res):
        st = os.stat(src_file, follow_symlinks=False)
        metadata = make_metadata(path, st.st_mode, st.st_mtime_ns, st.st_ctime_ns)
        crypt_file = self.crypt_dir / path_hash(self.crypt_key, path)
        try:
            os.makedirs(crypt_file.parent, exist_ok=True)
            file_encrypt(self.crypt_key, src_file, crypt_file, metadata, chunk_size)
            self.included[path] = {'mode': st.st_mode, 'mtime': st.st_mtime_ns, 'ctime': st.st_ctime_ns}
            res.succ_copied_files.append(path)
        except e:
            res.fail_copied_files.append((path, str(e)))

    def pull_file(self, path, dst_file, res):
        crypt_file = self.crypt_dir / path_hash(self.crypt_key, path)
        def md_test(md):
            p, m, _, _ = dest_metadata(md)
            return p == path and stat.S_ISREG(m)
        try:
            metadata = file_decrypt(self.crypt_key, crypt_file, dst_file, metadata_test=md_test)
            _, mode, mtime, _ = dest_metadata(metadata)
            os.chmod(dst_file, stat.S_IMODE(mode))
            os.utime(dst_file, ns=(mtime, mtime))
            res.succ_copied_files.append(path)
        except e:
            res.fail_copied_files.append((path, str(e)))
