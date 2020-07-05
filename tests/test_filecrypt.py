
from dircifrar.filecrypt import (
    file_encrypt,
    file_decrypt,
    path_encode,
    path_decode,
    path_hash,
)
from nacl.utils import random as randombytes
from nacl.bindings import crypto_secretstream_xchacha20poly1305_KEYBYTES as KEYBYTES
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, assume
from hypothesis.strategies import integers, booleans, characters, text, lists

@pytest.fixture(scope="module")
def test_oxido(pytestconfig):
    return pytestconfig.getoption('test_oxido')

plain_name = 'plain'
crypt_name = 'crypt'
some_data = b'Tomorrow, and tomorrow, and tomorrow'

metadata_size_min = 0
metadata_size_max = 50

chunk_size = 4096
num_chunks_min = 0
num_chunks_max = 5

odd_chunk_size_min = -50
odd_chunk_size_max =  50

def run_file_enc_dec(metadata_size, num_chunks, odd_chunk_size, crypt_exists, plain_1_exists,
                     oxido_encrypt=None, oxido_decrypt=None):
    plain_size = chunk_size * num_chunks + odd_chunk_size
    assume(plain_size >= 0)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir = Path(tmp_dir)
        key = randombytes(KEYBYTES)
        metadata = randombytes(metadata_size)
        plain_data = randombytes(plain_size)
        plain_file_0 = tmp_dir / (plain_name + '_0')
        plain_file_1 = tmp_dir / (plain_name + '_1')
        crypt_file = tmp_dir / crypt_name
        with open(plain_file_0, 'wb') as plain_0:
            plain_0.write(plain_data)
        if crypt_exists:
            with open(crypt_file, 'wb') as crypt:
                crypt.write(some_data)
        if plain_1_exists:
            with open(plain_file_1, 'wb') as plain_1:
                plain_1.write(some_data)
        file_encrypt(key, plain_file_0, crypt_file, metadata, chunk_size, oxido=oxido_encrypt)
        md = file_decrypt(key, crypt_file, plain_file_1, metadata_only=True, oxido=oxido_decrypt)
        assert md == metadata
        md = file_decrypt(key, crypt_file, plain_file_1, oxido=oxido_decrypt)
        assert md == metadata
        with open(plain_file_1, 'rb') as plain_1:
            plain_data_1 = plain_1.read()
            assert plain_data_1 == plain_data

@given(
    metadata_size=integers(metadata_size_min, metadata_size_max),
    num_chunks=integers(num_chunks_min, num_chunks_max),
    odd_chunk_size=integers(odd_chunk_size_min, odd_chunk_size_max),
    crypt_exists=booleans(),
    plain_1_exists=booleans(),
)
def test_file_enc_dec_pp(metadata_size, num_chunks, odd_chunk_size, crypt_exists, plain_1_exists):
    run_file_enc_dec(metadata_size, num_chunks, odd_chunk_size, crypt_exists, plain_1_exists)

@given(
    metadata_size=integers(metadata_size_min, metadata_size_max),
    num_chunks=integers(num_chunks_min, num_chunks_max),
    odd_chunk_size=integers(odd_chunk_size_min, odd_chunk_size_max),
    crypt_exists=booleans(),
    plain_1_exists=booleans(),
)
def test_file_enc_dec_rp(test_oxido, metadata_size, num_chunks, odd_chunk_size, crypt_exists, plain_1_exists):
    if test_oxido:
        import oxido
        run_file_enc_dec(metadata_size, num_chunks, odd_chunk_size, crypt_exists, plain_1_exists,
                         oxido_encrypt=oxido)
    else:
        assert True

@given(
    metadata_size=integers(metadata_size_min, metadata_size_max),
    num_chunks=integers(num_chunks_min, num_chunks_max),
    odd_chunk_size=integers(odd_chunk_size_min, odd_chunk_size_max),
    crypt_exists=booleans(),
    plain_1_exists=booleans(),
)
def test_file_enc_dec_pr(test_oxido, metadata_size, num_chunks, odd_chunk_size, crypt_exists, plain_1_exists):
    if test_oxido:
        import oxido
        run_file_enc_dec(metadata_size, num_chunks, odd_chunk_size, crypt_exists, plain_1_exists,
                         oxido_decrypt=oxido)
    else:
        assert True

@given(
    metadata_size=integers(metadata_size_min, metadata_size_max),
    num_chunks=integers(num_chunks_min, num_chunks_max),
    odd_chunk_size=integers(odd_chunk_size_min, odd_chunk_size_max),
    crypt_exists=booleans(),
    plain_1_exists=booleans(),
)
def test_file_enc_dec_rr(test_oxido, metadata_size, num_chunks, odd_chunk_size, crypt_exists, plain_1_exists):
    if test_oxido:
        import oxido
        run_file_enc_dec(metadata_size, num_chunks, odd_chunk_size, crypt_exists, plain_1_exists,
                         oxido_encrypt=oxido, oxido_decrypt=oxido)
    else:
        assert True

@given(
    names=lists(text(alphabet=characters(
        whitelist_categories=['L', 'N', 'Pd'],
        blacklist_characters=[b'\x00', b'.']))),
)
def test_path_stuffs(names):
    path = Path()
    for name in names:
        path = path / name
    metadata = path_encode(path)
    path_1 = path_decode(metadata)
    assert path == path_1
    key = randombytes(KEYBYTES)
    hash_1 = path_hash(key, path)
    hash_2 = path_hash(key, path)
    assert hash_1 == hash_2
    part_1, part_2, part_3 = hash_1.parts
    assert len(part_1) == 2 and len(part_2) == 2 and len(part_3) == 60
