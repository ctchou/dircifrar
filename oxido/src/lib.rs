
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use sodiumoxide::crypto::secretstream::xchacha20poly1305::Key as Crypto_Key;
use sodiumoxide::crypto::secretstream::xchacha20poly1305::Header as Crypto_Header;
use sodiumoxide::crypto::secretstream::xchacha20poly1305::Tag as Crypto_Tag;
use sodiumoxide::crypto::secretstream::xchacha20poly1305::Stream as Crypto_Stream;
use sodiumoxide::crypto::secretstream::xchacha20poly1305::ABYTES as Crypto_ABYTES;
use sodiumoxide::crypto::secretstream::xchacha20poly1305::HEADERBYTES as Crypto_HEADERBYTES;

#[pymodule]
fn oxido(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(file_encrypt))?;
    m.add_wrapped(wrap_pyfunction!(file_decrypt))?;
    Ok(())
}

const EXP2_32: usize = 1 << 32;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

fn mode_is_reg(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFREG
}

fn read_block(file: &mut fs::File, len: usize) -> Option<Vec<u8>> {
    let mut block = vec![0u8; len];
    let read_len = file.read(&mut block).unwrap();
    if read_len == len {
        Some(block)
    } else {
        None
    }
}

fn dest_metadata(metadata: &[u8]) -> (Vec<u8>, u32, u64, u64) {
    let mut metadata_rdr = Cursor::new(metadata);
    let mode = metadata_rdr.read_u32::<LittleEndian>().unwrap();
    let mtime = metadata_rdr.read_u64::<LittleEndian>().unwrap();
    let ctime = metadata_rdr.read_u64::<LittleEndian>().unwrap();
    let path = metadata[20..].to_vec();
    (path, mode, mtime, ctime)
}

#[pyfunction]
fn file_encrypt(key_bytes: &[u8], plain_file: &str, crypt_file: &str, metadata: &[u8], chunk_size: usize)
                -> PyResult<()> {
    let metadata_size = metadata.len();
    assert!(metadata_size < EXP2_32);
    assert!(chunk_size < EXP2_32);
    let mut plain_size =
        if plain_file.len() == 0 {
            0
        } else {
            fs::metadata(plain_file)?.len()
        };

    let crypt_path = Path::new(crypt_file);
    let crypt_dir = crypt_path.parent().unwrap();
    let mut crypt_temp = NamedTempFile::new_in(crypt_dir)?;

    let mut descriptor = vec![];
    descriptor.write_u32::<LittleEndian>(metadata_size as u32)?;
    descriptor.write_u32::<LittleEndian>(chunk_size as u32)?;
    descriptor.write_u64::<LittleEndian>(plain_size)?;
    crypt_temp.write(&descriptor)?;

    sodiumoxide::init().unwrap();
    let key = Crypto_Key::from_slice(key_bytes).unwrap();
    let (mut enc_stream, header) = Crypto_Stream::init_push(&key).unwrap();
    crypt_temp.write(header.as_ref())?;

    let mut metadata_bytes = descriptor.clone();
    metadata_bytes.extend(metadata.iter().copied());
    let ciphertext = enc_stream.push(&metadata_bytes, None, Crypto_Tag::Message).unwrap();
    crypt_temp.write(&ciphertext)?;

    if plain_size > 0 {
        let mut plain_fp = fs::File::open(plain_file)?;
        let mut plaintext = vec![0u8; chunk_size];
        while plain_size > 0 {
            let read_len = plain_fp.read(&mut plaintext)?;
            assert!(read_len > 0);
            let tag =
                if plain_size >= (chunk_size as u64) {
                    Crypto_Tag::Message
                } else {
                    Crypto_Tag::Final
                };
            let ciphertext = enc_stream.push(&plaintext[0..read_len], None, tag).unwrap();
            crypt_temp.write(&ciphertext)?;
            plain_size -= read_len as u64;
        }
    }
    if crypt_path.exists() {
        fs::remove_file(crypt_path)?;
    }
    fs::hard_link(crypt_temp, crypt_path)?;    

    Ok(())
}

#[pyfunction]
fn file_decrypt(key_bytes: &[u8], crypt_file: &str, plain_file: &str, metadata_only: bool, check_path: &[u8])
                -> PyResult<Vec<u8>> {
    let mut crypt_fp = fs::File::open(crypt_file)?;
    
    let descriptor = read_block(&mut crypt_fp, 16).unwrap();
    let mut descriptor_rdr = Cursor::new(&descriptor);
    let metadata_size = descriptor_rdr.read_u32::<LittleEndian>()? as usize;
    let chunk_size = descriptor_rdr.read_u32::<LittleEndian>()? as usize;
    let mut plain_size = descriptor_rdr.read_u64::<LittleEndian>()? as usize;

    let header_bytes = read_block(&mut crypt_fp, Crypto_HEADERBYTES).unwrap();
    sodiumoxide::init().unwrap();
    let key = Crypto_Key::from_slice(key_bytes).unwrap();
    let header = Crypto_Header::from_slice(&header_bytes).unwrap();
    let mut dec_stream = Crypto_Stream::init_pull(&header, &key).unwrap();

    let ciphertext = read_block(&mut crypt_fp, 16 + metadata_size + Crypto_ABYTES).unwrap();
    let (plaintext, _) = dec_stream.pull(&ciphertext, None).unwrap();
    assert_eq!(descriptor, &plaintext[0..16]);
    let metadata = plaintext[16..].to_vec();
    if metadata_only {
        return Ok(metadata);
    }
    if check_path.len() > 0 {
        let (path, mode, _, _) = dest_metadata(&metadata);
        assert_eq!(path, check_path);
        assert!(mode_is_reg(mode));
    }

    let plain_path = Path::new(plain_file);
    let plain_dir = plain_path.parent().unwrap();
    let mut plain_temp = NamedTempFile::new_in(plain_dir)?;

    if plain_size > 0 {
        let mut ciphertext = vec![0u8; chunk_size + Crypto_ABYTES];
        while plain_size > 0 {
            let read_len = crypt_fp.read(&mut ciphertext).unwrap();
            let (plaintext, tag) = dec_stream.pull(&ciphertext[0..read_len], None).unwrap();
            assert!(plaintext.len() > 0);
            plain_temp.write(&plaintext)?;
            if tag == Crypto_Tag::Final {
                break;
            }
            assert!(plaintext.len() == chunk_size);
            plain_size -= chunk_size;
        }
    }
    if plain_path.exists() {
        fs::remove_file(plain_path)?;
    }
    fs::hard_link(plain_temp, plain_path)?;    

    Ok(metadata)
}

// #[cfg(test)]
// mod tests {
//     #[test]
//     fn it_works() {
//         assert_eq!(2 + 2, 4);
//     }
// }
