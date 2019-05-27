
from dircifrar.dirconfig import (
    wrap_master_key,
    unwrap_master_key,
    rewrap_master_key,
)
from nacl.utils import random as randombytes
from nacl.bindings import crypto_secretstream_xchacha20poly1305_KEYBYTES as KEYBYTES
from pathlib import Path
import string, tempfile

from hypothesis import given, assume, settings
from hypothesis.strategies import integers, lists, text

gen_password = text(string.printable, min_size=1)
gen_version_list = lists(integers(0, 10), min_size=1, max_size=5)

@settings(
    max_examples=10,
    deadline=None,
)
@given(
    password_1=gen_password,
    password_2=gen_password,
    version_list_1=gen_version_list,
    version_list_2=gen_version_list,
)
def test_master_key_wrap(password_1, password_2, version_list_1, version_list_2):
    password_1 = password_1.encode('utf-8')
    password_2 = password_2.encode('utf-8')
    version_1 = '.'.join([str(v) for v in version_list_1])
    version_2 = '.'.join([str(v) for v in version_list_2])
    master_key = randombytes(KEYBYTES)
    wrap_1 = wrap_master_key(master_key, version_1, password_1)
    master_key_1a, version_1a = unwrap_master_key(wrap_1, password_1)
    assert master_key_1a == master_key
    assert version_1a == version_1
    wrap_2 = rewrap_master_key(wrap_1, password_1, password_2, new_version=version_2)
    master_key_2a, version_2a = unwrap_master_key(wrap_2, password_2)
    assert master_key_2a == master_key
    assert version_2a == version_2
