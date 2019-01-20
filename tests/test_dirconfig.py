
from dircifrar.dirconfig import (
    make_crypt_config,
    unwrap_crypt_config,
)
from nacl.utils import random as randombytes
from nacl.bindings import crypto_secretstream_xchacha20poly1305_KEYBYTES as KEYBYTES
from pathlib import Path
import string, tempfile

from hypothesis import given, assume, settings
from hypothesis.strategies import integers, lists, text

@settings(
    max_examples=10,
    deadline=None,
)
@given(
    version_list=lists(integers(0, 10), min_size=1, max_size=5),
    password=text(string.printable, min_size=1),
)
def test_crypt_config_wrap(version_list, password):
    password = password.encode('utf-8')
    version_0 = '.'.join([str(v) for v in version_list])
    master_key_0 = randombytes(KEYBYTES)
    config = make_crypt_config(version_0, [], password, test_key=master_key_0)
    master_key_1, version_1 = unwrap_crypt_config(config, password)
    assert master_key_0 == master_key_1
    assert version_0 == version_1
