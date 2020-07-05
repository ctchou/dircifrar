
from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_ABYTES as crypto_ABYTES,
    crypto_secretstream_xchacha20poly1305_HEADERBYTES as crypto_HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL as crypto_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as crypto_TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_init_pull as crypto_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push as crypto_init_push,
    crypto_secretstream_xchacha20poly1305_pull as crypto_pull,
    crypto_secretstream_xchacha20poly1305_push as crypto_push,
    crypto_secretstream_xchacha20poly1305_state as crypto_state,
)
from nacl.hash import generichash
from pathlib import Path
import os, stat, io, tempfile

exp2_32 = 2 ** 32
exp2_64 = 2 ** 64

def file_encrypt(key, plain_file, crypt_file, metadata, chunk_size, oxido=None):
    if oxido:
        plain_file_str = str(plain_file) if plain_file else ''
        oxido.file_encrypt(key, plain_file_str, str(crypt_file), metadata, chunk_size)
        return

    metadata_size = len(metadata)
    plain_size = os.path.getsize(plain_file) if plain_file else 0
    assert metadata_size >=0 and metadata_size < exp2_32
    assert chunk_size >= 0 and chunk_size < exp2_32
    assert plain_size >= 0 and plain_size < exp2_64
    with tempfile.NamedTemporaryFile(mode='wb', dir=os.path.dirname(crypt_file)) as crypt_fp:
        descriptor = (
            metadata_size.to_bytes(4, byteorder='little', signed=False) +
            chunk_size.to_bytes(4, byteorder='little', signed=False) +
            plain_size.to_bytes(8, byteorder='little', signed=False) )
        crypt_fp.write(descriptor)
        state = crypto_state()
        header = crypto_init_push(state, key)
        crypt_fp.write(header)
        ciphertext = crypto_push(state, descriptor + metadata)
        crypt_fp.write(ciphertext)
        if plain_file:
            with open(plain_file, 'rb') as plain_fp:
                while plain_size > 0:
                    plaintext = plain_fp.read(chunk_size)
                    assert len(plaintext) > 0
                    tag = crypto_TAG_MESSAGE if plain_size >= chunk_size else crypto_TAG_FINAL
                    ciphertext = crypto_push(state, plaintext, tag=tag)
                    crypt_fp.write(ciphertext)
                    plain_size -= chunk_size
        if os.path.exists(crypt_file):
            os.remove(crypt_file)
        os.link(crypt_fp.name, crypt_file)

def file_decrypt(key, crypt_file, plain_file, metadata_only=False, check_path=None, oxido=None):
    if oxido:
        path_bytes = check_path if check_path else b''
        metadata = oxido.file_decrypt(key, str(crypt_file), str(plain_file), metadata_only, path_bytes)
        return bytes(metadata)

    with open(crypt_file, 'rb') as crypt_fp:
        descriptor = crypt_fp.read(16)
        metadata_size = int.from_bytes(descriptor[0:4], byteorder='little', signed=False)
        chunk_size = int.from_bytes(descriptor[4:8], byteorder='little', signed=False)
        plain_size = int.from_bytes(descriptor[8:16], byteorder='little', signed=False)
        header = crypt_fp.read(crypto_HEADERBYTES)
        state = crypto_state()
        crypto_init_pull(state, header, key)
        ciphertext = crypt_fp.read(16 + metadata_size + crypto_ABYTES)
        plaintext, tag = crypto_pull(state, ciphertext)
        assert plaintext[0:16] == descriptor
        metadata = plaintext[16:]
        if metadata_only:
            return metadata
        if check_path:
            mode = int.from_bytes(metadata[0:4], byteorder='little', signed=False)
            path_bytes = metadata[20:]
            assert check_path == path_bytes and stat.S_ISREG(mode)
        with tempfile.NamedTemporaryFile(mode='wb', dir=os.path.dirname(plain_file)) as plain_fp:
            while plain_size > 0:
                ciphertext = crypt_fp.read(chunk_size + crypto_ABYTES)
                plaintext, tag = crypto_pull(state, ciphertext)
                assert len(plaintext) > 0
                plain_fp.write(plaintext)
                if tag == crypto_TAG_FINAL:
                    break
                plain_size -= chunk_size
            if os.path.exists(plain_file):
                os.remove(plain_file)
            os.link(plain_fp.name, plain_file)
        return metadata

def path_encode(path):
    return b'\x00'.join([ part.encode('utf-8') for part in path.parts ])

def path_decode(code):
    path = Path()
    for part in [ part.decode('utf-8') for part in code.split(b'\x00') ]:
        path = path / part
    return path

def path_hash(key, path):
    code = path_encode(path)
    hash = generichash(code, key=key).decode('utf-8')
    return Path(hash[0:2], hash[2:4], hash[4:])
