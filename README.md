
# dircifrar: A directory synchronization and encryption tool

`dircifrar` is a simple command-line tool for synchronizing and
encrypting directories containing files and subdirectories.  The files
and subdirectories are encrypted individually and the pathnames are
also encrypted.  All encryptions are performed using *authenticated
encryption* with a 256-bit secret key.  Therefore, in addition to the
confidentiality of their names and contents, no files or
subdirectories can be modified, truncated, reordered, or duplicated
without being detected.

The main intended usage of `dircifrar` is to encrypt a directory
before uploading the encrypted version to a cloud storage such as
Dropbox.

Currently `dircifrar` handles only ordinary files and ignores all
symbolic links.

## Usage

Run `dircifrar -h` or `dircifrar <command> -h` for online documentation.

Currently `dircifrar` supports the following commands:

```
    dircifrar init-plain [-o] [-x <exclude>] <dir_path>
```

initializes an unencrypted directory with pathname `<dir_path>`, where
there can be any number of `-x <exclude>` specifying file/directory
names under `<dir_path>` which `dircifrar` will subsequently ignore
when performing synchronization and encryption.  `<exclude>` can be a
Python regular expression.

The result of this initialization is stored in a JSON file named
`.dircifrar_config.json` under `<dir_path>`.  `dircifrar init-plain`
will fail if `.dircifrar_config.json` already exists, unless the `-o`
option is given.  For an unencrypted directory,
`.dircifrar_config.json` is a plaintext file in which everything can
be edited.

```
    dircifrar init-crypt [-o] [-x <exclude>] <dir_path>
```

initializes an encrypted directory with pathname `<dir_path>`, where
the user is prompted for a password from which a *wrapping key* is
derived using the Argon2i function:

https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function

and a randomly generated salt.  The wrapping key is used to encrypt a
randomly generated 256-bit *master key* which in turn is used in the
actual file and subdirectory encryptions.  Both the salt and the
encrypted master key are stored in the `.dircifrar_config.json` file
under `<dir_path>`, so that `dircifrar` can later recover the master
key when given the password.  Note that the version string is
encrypted together with the master key, hence it is not possible to
change the version in `.dircifrar_config.json` without being detected.
The `-o` and `-x` options have the same meanings as before, except
that the `<exclude>` pattern refers to the file/directory names
directly, without decryption .  The `<exclude>` patterns recorded in
`.dircifrar_config.json` is in plaintext and can be edited.

```
    dircifrar push [-v] [-d] <local_dir> <remote_dir>
    dircifrar pull [-v] [-d] <local_dir> <remote_dir>
```

synchronize `<local_dir>` and `<remote_dir>`, where `push` makes
`<remote_dir>` the same as `<local_dir>` and `pull` makes
`<local_dir>` the same as `<remote_dir>`.  Either or both of
`<local_dir>` and `<remote_dir>` can be unencrypted or encrypted,
depending on the information recorded in their respective
`.dircifrar_config.json` file.  If a directory is encrypted, the user
is prompted for the password that is set up by `dircifrar init-crypt`.
The lack of a `.dircifrar_config.json` file makes the directory to be
considered unencrypted.

The directory synchronization algorithm works as follows for `dircifrar push`:

* All files and subdirectories that are in `<remote_dir>` but not in
  `<local_dir>` are removed.

* All files and subdirectories that are in `<local_dir>` but not in
  `<remote_dir>` are copied from the former to the latter.

* All files that are in both `<local_dir>` and `<remote_dir>` but are
  younger in the former than in the latter are copied from the former
  to the latter.  Time stamps of subdirectories are ignored.

`dircifrar pull` works the same way, except that the roles of the two
directories are reversed.

The files/subdirectories specified by the `-x <exclude>` are ignored
by the synchronization algorithm, which also ignores the
`.dircifrar_config.json` files.

## File encryption

Some details about how `dircifrar` encrypts a file or subdirectory:

* Each encrypted file begins with three (plaintext) unsigned integers:

  + A 32-bit integer specifying the size of the metadata section in bytes.

  + A 32-bit integer specifying the size of the chunk size in bytes.

  + A 64-bit integer specifying the size of the unencrypted file in bytes.

* Following that is the encrypted metadata, where the metadata consist of:

  + A 32-bit unsigned integer encoding the mode of the unencrypted file,
    where the mode is the st_mode returned by Python's os.stat function.

  + A 64-bit unsigned integer specifying the mtime of the unencrypted file in nanoseconds.

  + A 64-bit unsigned integer specifying the ctime of the unencrypted file in nanoseconds.
    (Currently ctime is not used in time stamp comparison, but is kept around just in case.)

  + The relative pathname of the file or subdirectory.

* Following that is the encrypted file contents, in as many chunks as needed.
  (Subdirectories do not have this section.)

All encryption above is performed using XChaCha20 + Poly1305:

https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream

## Pathname encryption

The pathname of each file or subdirectory is hashed using BLAKE2b:

https://libsodium.gitbook.io/doc/hashing/generic_hashing

with the master key into 256 bits, which is converted to 64 hex
digits.  The first 2 hex digits are interpreted as a directory name,
the next 2 hex digits another directory name under the first one, and
the remaining 60 hex digits are interpreted as a file name under the
second directory containing the encrypted file or subdirectory.

## Installation

```
pip install dircifrar
```


`dircifrar` is implemented in Python3 and requires Python 3.6 or above.
We recommend the Anaconda distribution:

https://www.anaconda.com/distribution/

which has everything needed by `dircifrar` except **PyNaCl**:

https://pynacl.readthedocs.io/en/stable/

which is a Python binding to **libsodium**:

https://libsodium.gitbook.io/doc/

```
pip install pynacl
```

should automatically install the pre-compiled binary of **libsodium**.

--------------------------------
&copy; 2018-2019  Ching-Tsun Chou (<chingtsun.chou@gmail.com>)
