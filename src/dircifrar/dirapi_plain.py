
from pathlib import Path
import os, sys, stat, shutil

def exc_info():
    return str(sys.exc_info()[1])

class DirPlain(object):
    """ API for accessing an unencrypted directory """

    def __init__(self, dir_root, version, exclude, config):
        self.dir_type = 'plain'
        self.dir_root = dir_root
        self.version = version
        self.exclude = exclude
        self.config = config

    def collect_paths(self):
        self.included = dict()
        self.excluded = set()
        for cwd, dirs, files in os.walk(self.dir_root, followlinks=False):
            for d in dirs:
                path = Path(os.path.relpath(os.path.join(cwd, d), self.dir_root))
                if any(pat.fullmatch(d) for pat in self.exclude):
                    self.excluded.add(path)
                    # This prevents os.walk from walking excluded directories.
                    dirs.remove(d)
                else:
                    st = os.stat(self.dir_root / path, follow_symlinks=False)
                    self.included[path] = { 'mode': st.st_mode,
                                            # We do not care about the timestamps of directories.
                                            'mtime': 0,
                                            'ctime': 0 }
            for f in files:
                path = Path(os.path.relpath(os.path.join(cwd, f), self.dir_root))
                st = os.stat(self.dir_root / path, follow_symlinks=False)
                # Only regular files are currently covered.
                if any(pat.fullmatch(f) for pat in self.exclude) or not stat.S_ISREG(st.st_mode):
                    self.excluded.add(path)
                else:
                    self.included[path] = { 'mode': st.st_mode,
                                            'mtime': st.st_mtime_ns,
                                            'ctime': st.st_ctime_ns }

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
        plain_dir = self.dir_root / path
        try:
            shutil.rmtree(plain_dir)
            res.log('REMOVE DIR', path)
        except:
            res.log('REMOVE DIR', path, error=exc_info())

    def remove_file(self, path, res):
        plain_file = self.dir_root / path
        try:
            os.remove(plain_file)
            res.log('REMOVE FILE', path)
        except:
            res.log('REMOVE FILE', path, error=exc_info())

    def make_dir(self, path, mode, res):
        plain_dir = self.dir_root / path
        try:
            os.mkdir(plain_dir)
            os.chmod(plain_dir, stat.S_IMODE(mode))
            res.log('ADD DIR', path)
        except:
            res.log('ADD DIR', path, error=exc_info())

    # shutil.copy2 copies both file contents and metadata.

    def push_file(self, path, src_file, res):
        dst_file = self.dir_root / path
        try:
            shutil.copy2(src_file, dst_file, follow_symlinks=False)
            res.log('COPY FILE', path)
        except:
            res.log('COPY FILE', path, error=exc_info())

    def pull_file(self, path, dst_file, res):
        src_file = self.dir_root / path
        try:
            shutil.copy2(src_file, dst_file, follow_symlinks=False)
            res.log('COPY FILE', path)
        except:
            res.log('COPY FILE', path, error=exc_info())
