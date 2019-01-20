
from .__init__ import (
    __pkg_version__,
    __config_filename__,
    __test_password__,
)
from .dirapi_plain import DirPlain
from .dirapi_crypt import DirCrypt

from nacl.utils import random as randombytes
from nacl.pwhash import argon2i
from nacl.secret import SecretBox
from nacl.bindings import crypto_secretstream_xchacha20poly1305_KEYBYTES as KEYBYTES

from pathlib import Path
import json, re

def make_plain_config(version, exclude):
    return {
        'dir_type': 'plain',
        'version': version,
        'exclude': exclude,
    }

# The optional argument 'test_key' in some procedures below is used
# only for testing.

def make_crypt_config(version, exclude, password, test_key=None):
    kdf_salt = randombytes(argon2i.SALTBYTES)
    wrapping_key = argon2i.kdf(KEYBYTES, password, kdf_salt,
                               opslimit=argon2i.OPSLIMIT_MODERATE,
                               memlimit=argon2i.MEMLIMIT_MODERATE)
    box = SecretBox(wrapping_key)
    if test_key:
        master_key = test_key
    else:
        master_key = randombytes(KEYBYTES)
    version_bytes = version.encode('utf-8')
    wrapped_master_key = box.encrypt(master_key + version_bytes)
    return {
        'dir_type': 'crypt',
        'version': __pkg_version__,
        'exclude': exclude,
        'kdf_opslimit': argon2i.OPSLIMIT_MODERATE,
        'kdf_memlimit': argon2i.MEMLIMIT_MODERATE,
        'kdf_salt': kdf_salt.hex(),
        'wrapped_master_key': wrapped_master_key.hex(),
    }

def unwrap_crypt_config(config, password):
    kdf_opslimit = config['kdf_opslimit']
    kdf_memlimit = config['kdf_memlimit']
    kdf_salt = bytes.fromhex(config['kdf_salt'])
    wrapped_master_key = bytes.fromhex(config['wrapped_master_key'])
    wrapping_key = argon2i.kdf(KEYBYTES, password, kdf_salt,
                               opslimit=kdf_opslimit, memlimit=kdf_memlimit)
    box = SecretBox(wrapping_key)
    unwrapped_master_key = box.decrypt(wrapped_master_key)
    master_key = unwrapped_master_key[0:KEYBYTES]
    version = unwrapped_master_key[KEYBYTES:].decode('utf-8')
    return (master_key, version)

def init_config(dir_type, dir_path, exclude, overwrite):
    if dir_type == 'plain':
        config = make_plain_config(__pkg_version__, exclude)
    elif dir_type == 'crypt':
        config = make_crypt_config(__pkg_version__, exclude, __test_password__)
    else:
        raise ValueError(f"Error: {dir_type} is not a supported directory type")
    dir_path = Path(dir_path)
    if not dir_path.is_dir():
        raise ValueError(f"Error: {dir_path} does not exist or is not a directory")
    config_file = dir_path / __config_filename__
    if config_file.is_file():
        if overwrite:
            print(f"Warning: existing {config_file} is overwritten")
        else:
            raise ValueError(f"Error: {config_file} already exists")
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

def open_dirapi(dir_path, test_key=None):
    dir_path = Path(dir_path)
    if not dir_path.is_dir():
        raise ValueError(f"Error: {dir_path} does not exist or is not a directory")

    # When testing DirCrypt API, we want avoid the (intentional) overhead of KDF.
    if test_key:
        return DirCrypt(dir_path, __pkg_version__, [], {}, test_key)

    config_file = dir_path / __config_filename__
    try:
        with open(config_file, 'r') as cf:
            config = json.load(cf)
        assert isinstance(config, dict) and \
               'dir_type' in config and 'version' in config and 'exclude' in config
        dir_type = config['dir_type']
        version = config['version']
        exclude = config['exclude']
        del config['dir_type']
        del config['version']
        del config['exclude']
    except:
        config = {}
        dir_type = 'plain'
        version = '0.0.0'
        exclude = []
    exclude = set(exclude + [__config_filename__])
    exclude = [ re.compile(pat) for pat in exclude ]
    if dir_type == 'plain':
        return DirPlain(dir_path, version, exclude, config)
    elif dir_type == 'crypt':
        master_key, version_1 = unwrapped_master_key(config, __test_password__)
        if version_1 != version:
            raise ValueError(f"Error: {config_file} version check failed")
        return DirCrypt(dir_path, version, exclude, config, master_key)
    else:
        raise ValueError(f"Error: {dir_type} is not a supported directory type")
