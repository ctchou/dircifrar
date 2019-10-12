
# dircifrar: A directory synchronization and encryption tool

--------------------------------

`dircifrar` is a simple command-line tool, written for Python 3.6 or
above, for synchronizing two directories and (optionally) encrypting
one of the two directories.  The files and subdirectories in the
encrypted directory are encrypted individually and their pathnames and
metadata are also encrypted.  All encryptions are performed using
[**authenticated
encryption**](https://en.wikipedia.org/wiki/Authenticated_encryption)
with a 256-bit secret key from the
[**libsodium**](https://libsodium.gitbook.io/doc/) library.
Therefore, in addition to the confidentiality of their contents and
metadata, no encrypted files can be modified, truncated, duplicated,
moved, or renamed without being detected.  However, the deletion of
encrypted files are not protected against.

The intended usage of `dircifrar` is to encrypt a plaintext directory
before uploading the encrypted version to a cloud storage such as
Dropbox and Google Drive.  This is achieved by synchronizing the
plaintext directory and an encrypted directory, where the latter is
placed inside the cloud folder on the local machine (for example, the
`Dropbox` folder in the case of Dropbox).  The cloud storage's
automatic synchronization should then take care of the rest.  Needless
to say, `dircifar` cannot protect the plaintext directory, which
should be protected by disk encryption on the local machine.

Currently `dircifrar` handles only ordinary files and ignores all
symbolic links.  So far it has been tested on macOS and Linux only.
It should work on Windows, but this has not been tested and some minor
changes related to pathname manipulations may be necessary.

## Usage

Run `dircifrar -h` or `dircifrar <command> -h` for online documentation.

Currently `dircifrar` supports the following commands:

```
    dircifrar init-plain [-o] [-x <exclude>] <dir_path>
```

initializes an unencrypted directory with pathname `<dir_path>`.
There can be any number of `-x <exclude>` specifying file/directory
names under `<dir_path>` which `dircifrar` will subsequently ignore
when performing synchronization and encryption.  `<exclude>` can be a
Python regular expression.  For example, the `.DS_Store` directories
on macOS should typically be excluded.

The result of this initialization is stored in a JSON file named
`.dircifrar_config.json` under `<dir_path>`.  `dircifrar init-plain`
will fail if `.dircifrar_config.json` already exists, unless the `-o`
(overwrite) option is given.  For an unencrypted directory,
`.dircifrar_config.json` is a plaintext file in which everything can
be edited by hand.

```
    dircifrar init-crypt [-o] [-x <exclude>] <dir_path>
```

initializes an encrypted directory with pathname `<dir_path>`.  The
user is prompted for a password, which needs to be typed in twice.
From the password, a *wrapping key* is derived using the Argon2i
function:

https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function

and a randomly generated *salt*.  The wrapping key is used to encrypt
a randomly generated 256-bit *master key*, which in turn is used in
the actual file and subdirectory encryptions.  The encryption of the
master key uses libsodium's secretbox, which uses XSalsa20 + Poly1305:

https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox

The salt, the key derivation parameters, and the encrypted master key
are stored in the `.dircifrar_config.json` file under `<dir_path>`, so
that `dircifrar` can later recover the master key when given the
password.  Note that the version string is encrypted together with the
master key, hence it is not possible to change the version in
`.dircifrar_config.json` without being detected.  The `-o` and `-x`
options have the same meanings as before, except that the `<exclude>`
pattern refers to the file/directory names directly, without
decryption.  The `<exclude>` patterns recorded in
`.dircifrar_config.json` is in plaintext and can be edited by hand.

```
    dircifrar change-password <dir_path>
```

changes the password of `<dir_path>`, which must be an encrypted
directory set up using `dircifrar init-crypt`.  The user is first
prompted for the old password and then for the new password, which
needs to be typed in twice.

Note that `dircifrar change-password <dir_path>` does not change the
master key.  Hence the already encrypted files and subdirectories in
`<dir_path>` need not be re-encrypted.  In contrast, `dircifrar
init-crypt` always generates a new master key, which renders all
already encrypted files and subdirectories unusable.  Note also that
there is no way to recover a forgotten or lost password.

```
    dircifrar push [-v] [-d] <local_dir> <remote_dir>
    dircifrar pull [-v] [-d] <local_dir> <remote_dir>
```

synchronize `<local_dir>` and `<remote_dir>`, where `push` makes
`<remote_dir>` the same as `<local_dir>` and `pull` makes
`<local_dir>` the same as `<remote_dir>`.  The `<remote_dir>` can be
either encrypted or unencrypted, depending on the information stored
in its `.dircifrar_config.json` file.  The `<local_dir>` should be
unencrypted.  If a directory is encrypted, the user is prompted for
the password that is set up by `dircifrar init-crypt`.  The absence of
a `.dircifrar_config.json` file makes the directory to be considered
unencrypted.

The directory synchronization algorithm works as follows for `dircifrar push`:

* All files and subdirectories that are in `<remote_dir>` but not in
  `<local_dir>` are removed.

* All files and subdirectories that are in `<local_dir>` but not in
  `<remote_dir>` are copied from the former to the latter.

* All files that are in both `<local_dir>` and `<remote_dir>`, but are
  younger in the former than in the latter, are copied from the former
  to the latter.  Time stamps of subdirectories are ignored.

`dircifrar pull` works the same way, except that the roles of the two
directories are reversed.

The files/subdirectories specified by the `-x <exclude>` when the
directories are set up, are ignored by the synchronization algorithm,
which in addition also ignores the `.dircifrar_config.json` file.

If `<remote_dir>` is encrypted, the encrypted contents are not stored
directly under `<remote_dir>`.  Rather, they are stored under the
subdirectory `<remote_dir>/dircifrar_crypt`.  This extra level of
indirection allows the `dircifrar_crypt` subdirectory to take
advantage of Dropbox's [**Smart
Sync**](https://help.dropbox.com/installs-integrations/sync-uploads/smart-sync)
feature by marking its contents as "online-only", thus saving space on
the local machine.  A separate encrypted directory,
`<remote_dir>/dircifrar_meta`, contains the metadata of the files and
directories in `dircifrar_crypt`, so that `dircifrar push` and
`dircifrar pull` do not have to probe the files in `dircifrar_crypt`.
Such probing would cause the contents of `dircifrar_crypt` to be
downloaded even if they have been marked as "online-only" and thus
negate the benefits of Smart Sync.  Under normal circumstances,
`dircifrar` will keep the contents of `dircifrar_crypt` and
`dircifrar_meta` in sync.  If they ever get out of sync,
`dircifrar_meta` can be regenerated using:

```
    dircifrar rebuild-meta <remote_dir>
```

But note that the above operation needs to probe every file in
`dircifrar_crypt` and thus causes them to be downloaded.


## File encryption

Here are some details about how `dircifrar` encrypts a file or
subdirectory:

* Each encrypted file begins with three (plaintext) unsigned integers:

  + A 32-bit integer specifying the size of the metadata section in bytes.

  + A 32-bit integer specifying the size of the chunk size in bytes.

    - Currently the default chunk size is set to 4096.

  + A 64-bit integer specifying the size of the unencrypted file in bytes.

* Following that is the encrypted metadata, where the metadata consist of:

  + A 32-bit unsigned integer encoding the mode of the unencrypted file,
    where the mode is the st_mode returned by Python's os.stat function.

  + A 64-bit unsigned integer specifying the mtime of the unencrypted file in nanoseconds.

  + A 64-bit unsigned integer specifying the ctime of the unencrypted file in nanoseconds.

    - Currently ctime is not used in time stamp comparison, but is kept around just in case.

  + The relative pathname of the file or subdirectory.

* Following that is the encrypted file contents, in as many chunks as needed.

  - Subdirectories do not have this section.

All encryption above is performed using libsodium's secretstream,
which uses XChaCha20 + Poly1305:

https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream

## Pathname encryption

The pathname of each file or subdirectory is hashed using libsodium's
BLAKE2b-based generic hash:

https://libsodium.gitbook.io/doc/hashing/generic_hashing

in the keyed hashing mode using the master key into 256 bits, which is
converted to 64 hex digits.  The first 2 hex digits are interpreted as
a directory name, the next 2 hex digits another directory name under
the first one, and the remaining 60 hex digits are interpreted as a
file name under the second directory containing the encrypted file or
subdirectory.

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

should automatically install the pre-compiled binary of libsodium.

The tests use **pytest**:

https://docs.pytest.org/en/latest/

and **Hypothesis**:

https://hypothesis.readthedocs.io/en/latest/index.html

which need to be installed only if you want to run the tests.

## Acknowledgements

I am grateful to Pascalin Amabegnon and Gaspar Mora Porta for testing
this program and suggesting improvements.

--------------------------------

&copy; 2018-2020  Ching-Tsun Chou (<chingtsun.chou@gmail.com>)
