
from .__init__ import (
    __pkg_name__,
    __pkg_version__,
    __pkg_description__,
)
import sys

if sys.version_info < (3, 6):
    sys.stdout.write(f"Sorry, {__pkg_name__} requires Python 3.6 or above\n")
    sys.exit(1)

from .dirconfig import (
    init_config,
    crypt_change_password,
    crypt_rebuild_meta,
)
from .dirsync import DirSync
import argparse
import logging

def make_default_logger():
    logger = logging.getLogger(__pkg_name__)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        hdl = logging.StreamHandler(sys.stdout)
        hdl.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(hdl)
    return logger

def dirsync(command, prog, argv):
    parser = argparse.ArgumentParser(
        prog=prog,
        description="""
    Synchronize two directories via push or pull
    push: copy local_dir to remote_dir
    pull: copy remote_dir to local_dir
""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('local_dir',
                        help='local directory (unencrypted)')
    parser.add_argument('remote_dir',
                        help='remote directory (encrypted)')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='verbose output')
    parser.add_argument('-d', '--diffonly', action='store_true', default=False,
                        help='only compute diffs between local_dir and remote_dir')
    args = parser.parse_args(argv)
    ds = DirSync(**vars(args))
    res = ds.do(command)
    if args.verbose or args.diffonly:
        logger = make_default_logger()
        res.output(logger)

def dirinit(command, prog, argv):
    parser = argparse.ArgumentParser(
        prog=prog,
        description="""
    init-plain: Initialize an unencrypted directory
    init-crypt: Initialize an encrypted directory
""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('dir_path',
                        help='directory path')
    parser.add_argument('-o', '--overwrite', action='store_true', default=False,
                        help='Overwrite config file if it already exists')
    parser.add_argument('-x', '--exclude', action='append', default=[],
                        help='filename pattern to exclude (there may be multiple such patterns)')
    args = parser.parse_args(argv)
    dir_type = 'crypt' if command == 'init-crypt' else 'plain'
    init_config(dir_type, **vars(args))

def dirmod(command, prog, argv):
    parser = argparse.ArgumentParser(
        prog=prog,
        description="""
     change-password: Change the password of an encrypted directory
     rebuild-meta:    Rebuild the meta info of an encrypted directory
""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('dir_path',
                        help='directory path')
    args = parser.parse_args(argv)
    if command == 'change-password':
        crypt_change_password(**vars(args))
    elif command == 'rebuild-meta':
        crypt_rebuild_meta(**vars(args))

def main():
    parser = argparse.ArgumentParser(
        usage=f"{__pkg_name__} command [<args>]",
        description=f"""
    {__pkg_description__}
    Version: {__pkg_version__}
""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command',
                        choices=[
                            'push', 'pull',
                            'init-plain', 'init-crypt',
                            'change-password', 'rebuild-meta',
                        ],
                        help='command')
    command = parser.parse_args(sys.argv[1:2]).command
    prog = f"{__pkg_name__} {command}"
    argv = sys.argv[2:]
    if command in ['push', 'pull']:
        dirsync(command, prog, argv)
    elif command in ['init-plain', 'init-crypt']:
        dirinit(command, prog, argv)
    elif command in ['change-password', 'rebuild-meta']:
        dirmod(command, prog, argv)
    else:
        sys.stdout.write(f"Invalid command: {command}\n")
        sys.exit(1)
