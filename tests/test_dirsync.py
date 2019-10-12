
from dircifrar.dirsync import (
    DirSync,
    time_resolution_ns,
)
from dircifrar.__init__ import (
    __crypt_metadir__,
)
from nacl.utils import random as randombytes
from nacl.bindings import crypto_secretstream_xchacha20poly1305_KEYBYTES as KEYBYTES
from pathlib import Path
from pprint import pprint
import os, string, tempfile, time, shutil

from hypothesis import given, assume, settings
from hypothesis.strategies import booleans, integers, text, dictionaries, recursive, sampled_from

letters = string.ascii_lowercase + string.digits
names = text(letters, min_size=1, max_size=100)
dtree = recursive(integers(min_value=0, max_value=1024),
                  lambda kids: dictionaries(names, kids))

# pprint(dtree.example())

def make_dtree(dir_path, dtree):
    assume(isinstance(dtree, dict))
    dir_path.mkdir(exist_ok=True)
    for name in dtree.keys():
        path = dir_path / name
        if isinstance(dtree[name], int):
            data = randombytes(dtree[name])
            with open(path, 'wb') as file:
                file.write(data)
        else:
            make_dtree(path, dtree[name])

# make_dtree(Path('zzz'), dtree.example())

def check_files(file1, file2):
    mode1 = file1.stat().st_mode
    mode2 = file2.stat().st_mode
    assert mode1 == mode2
    mtime1 = file1.stat().st_mtime_ns
    mtime2 = file2.stat().st_mtime_ns
    assert abs(mtime1 - mtime2) < time_resolution_ns
    with open(file1, 'rb') as fp1:
        data1 = fp1.read()
    with open(file2, 'rb') as fp2:
        data2 = fp2.read()
    assert data1 == data2
    return True

def check_dirs(dir1, dir2):
    mode1 = dir1.stat().st_mode
    mode2 = dir2.stat().st_mode
    assert mode1 == mode2
    names1 = [ e.name for e in os.scandir(dir1) if (e.is_file or e.is_dir) and not e.is_symlink() ]
    names2 = [ e.name for e in os.scandir(dir2) if (e.is_file or e.is_dir) and not e.is_symlink() ]
    for n in names1:
        if n in names2:
            names2.remove(n)
            p1 = dir1 / n
            p2 = dir2 / n
            if p1.is_file() and p2.is_file():
                assert check_files(p1, p2)
            elif p1.is_dir() and p2.is_dir():
                assert check_dirs(p1, p2)
            else:
                assert False
        else:
            assert False
    assert names2 == []
    return True

@settings(
    max_examples=100,
    deadline=None,
)
@given(
    dtree=dtree,
    test_crypt=booleans(),
    rebuild_meta=booleans(),
)
def test_push_pull(dtree, test_crypt, rebuild_meta):
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir = Path(tmp_dir)
        local_dir_1 = tmp_dir / 'local_dir_1'
        local_dir_2 = tmp_dir / 'local_dir_2'
        remote_dir = tmp_dir / 'remote_dir'
        make_dtree(local_dir_1, dtree)
        make_dtree(local_dir_2, {})
        make_dtree(remote_dir, {})
        time.sleep(0.001)
        remote_key = randombytes(KEYBYTES) if test_crypt else None
        ds = DirSync(local_dir_1, remote_dir, test_key=remote_key)
        ds.do('push')
        if test_crypt and rebuild_meta:
            shutil.rmtree(remote_dir / __crypt_metadir__)
        time.sleep(0.001)
        ds = DirSync(local_dir_2, remote_dir, test_key=remote_key)
        ds.do('pull')
        assert check_dirs(local_dir_1, local_dir_2)
