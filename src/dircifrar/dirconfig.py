
from .__init__ import (
    __pkg_name__,
    __pkg_version__,
    __config_filename__,
)
from .dirapi_plain import DirPlain
from .dirapi_crypt import DirCrypt

from nacl.utils import random as randombytes
from nacl.pwhash import argon2i
from nacl.secret import SecretBox
from nacl.bindings import crypto_secretstream_xchacha20poly1305_KEYBYTES as KEYBYTES

from getpass import getpass
from pathlib import Path
import json, re

def wrap_master_key(master_key, version, password,
                    kdf_opslimit=argon2i.OPSLIMIT_MODERATE,
                    kdf_memlimit=argon2i.MEMLIMIT_MODERATE):
    kdf_salt = randombytes(argon2i.SALTBYTES)
    wrapping_key = argon2i.kdf(KEYBYTES, password, kdf_salt,
                               opslimit=kdf_opslimit,
                               memlimit=kdf_memlimit)
    version_bytes = version.encode('utf-8')
    box = SecretBox(wrapping_key)
    wrapped_master_key = box.encrypt(master_key + version_bytes)
    return {
        'kdf_opslimit': kdf_opslimit,
        'kdf_memlimit': kdf_memlimit,
        'kdf_salt': kdf_salt.hex(),
        'wrapped_master_key': wrapped_master_key.hex(),
    }

def unwrap_master_key(wrap, password):
    wrapping_key = argon2i.kdf(KEYBYTES, password, bytes.fromhex(wrap['kdf_salt']),
                               opslimit=wrap['kdf_opslimit'],
                               memlimit=wrap['kdf_memlimit'])
    box = SecretBox(wrapping_key)
    unwrapped_master_key = box.decrypt(bytes.fromhex(wrap['wrapped_master_key']))
    master_key = unwrapped_master_key[0:KEYBYTES]
    version = unwrapped_master_key[KEYBYTES:].decode('utf-8')
    return (master_key, version)

def make_plain_config(version, exclude):
    return {
        'dir_type': 'plain',
        'version': version,
        'exclude': exclude,
    }

def make_crypt_config(version, exclude, password):
    master_key = randombytes(KEYBYTES)
    wrap = wrap_master_key(master_key, version, password)
    return {
        'dir_type': 'crypt',
        'version': version,
        'exclude': exclude,
        'master_key_wrap': wrap,
    }

def ask_password(dir_root):
    password = getpass(prompt=f"Type {__pkg_name__} password for {dir_root}: ")
    return password.encode('utf-8')

def choose_password(dir_root):
    password_0 = getpass(prompt=f"Choose  {__pkg_name__} password for {dir_root}: ")
    password_1 = getpass(prompt=f"Confirm {__pkg_name__} password for {dir_root}: ")
    if password_0 == password_1:
        return password_0.encode('utf-8')
    else:
        raise ValueError(f"Error: you typed two different passowords")

def init_config(dir_type, dir_path, exclude, overwrite):
    dir_path = Path(dir_path).resolve()
    if not dir_path.is_dir():
        raise ValueError(f"Error: {dir_path} does not exist or is not a directory")
    config_file = dir_path / __config_filename__
    if config_file.is_file():
        if overwrite:
            print(f"Warning: existing {config_file} is overwritten")
        else:
            raise ValueError(f"Error: {config_file} already exists")
    if dir_type == 'plain':
        config = make_plain_config(__pkg_version__, exclude)
    elif dir_type == 'crypt':
        password = choose_password(dir_path)
        config = make_crypt_config(__pkg_version__, exclude, password)
    else:
        raise ValueError(f"Error: {dir_type} is not a supported directory type")
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

def crypt_change_password(dir_path):
    dir_path = Path(dir_path).resolve()
    if not dir_path.is_dir():
        raise ValueError(f"Error: {dir_path} does not exist or is not a directory")
    config_file = dir_path / __config_filename__
    try:
        with open(config_file, 'r') as cf:
            config = json.load(cf)
        old_version = config['version']
        old_wrap = config['master_key_wrap']
    except:
        raise ValueError(f"Error: {dir_path} is not a well-formed encrypted directory")
    old_password = ask_password(dir_path)
    master_key, old_version_1 = unwrap_master_key(old_wrap, old_password)
    if old_version_1 != old_version:
        raise ValueError(f"Error: {config_file} version check failed")
    new_password = choose_password(dir_path)
    new_wrap = wrap_master_key(master_key, __pkg_version__, new_password)
    config['version'] = __pkg_version__
    config['master_key_wrap'] = new_wrap
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

# The optional argument 'test_key' is only for testing.

def open_dirapi(dir_path, test_key=None):
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
        password = ask_password(dir_path)
        master_key, version_1 = unwrap_master_key(config['master_key_wrap'], password)
        if version_1 != version:
            raise ValueError(f"Error: {config_file} version check failed")
        return DirCrypt(dir_path, version, exclude, config, master_key)
    else:
        raise ValueError(f"Error: {dir_type} is not a supported directory type")
