
from .dirconfig import open_dirapi
from pathlib import Path
import re, sys

time_resolution_ns = 10000  # in nanoseconds

class DirCmp(object):
    """ Object for recording the result of directory comparison """

    def __init__(self, src_dir, dst_dir, src_exc, dst_exc,
                 src_only, dst_only, changed, truly_changed):
        self.src_dir = src_dir
        self.dst_dir = dst_dir
        self.src_exc = src_exc
        self.dst_exc = dst_exc
        self.src_only = src_only
        self.dst_only = dst_only
        self.changed = changed
        self.truly_changed = truly_changed

    def output(self, logger, verbose):
        def src_file(path):
            return self.src_dir / path
        def dst_file(path):
            return self.dst_dir / path
        logger.info(f"SOURCE DIR: {self.src_dir}")
        logger.info(f"TARGET DIR: {self.dst_dir}")
        if verbose:
            for path in sorted(self.src_exc):
                logger.info(f"EXCLUDE: {src_file(path)}")
            for path in sorted(self.dst_exc):
                logger.info(f"EXCLUDE: {dst_file(path)}")
        for path in sorted(self.src_only):
            logger.info(f"ADD: {src_file(path)} -> {dst_file(path)}")
        for path in sorted(self.truly_changed):
            logger.info(f"COPY: {src_file(path)} -> {dst_file(path)}")
        for path in sorted(self.dst_only):
            logger.info(f"REMOVE: {dst_file(path)}")
        
class DirSyncRes(object):
    """ Object for recording the result of directory synchronization """

    def __init__(self, logger):
        self.logger = logger

    def log(self, msg, path, error=None):
        if error:
            self.logger.error(f'{msg}: {path} -> ERROR: {error}')
        else:
            self.logger.info(f'{msg}: {path}')

class AbsDirSync(object):
    """ Object for comparing and synchronizing two directories """

    def __init__(self, logger, src_api, dst_api, copy_file, options):
        self.logger = logger
        self.src_api = src_api
        self.dst_api = dst_api
        self.copy_file = copy_file

        self.diffonly = options.get('diffonly', False)
        self.verbose = options.get('verbose', False)
        self.use_ctime = options.get('use_ctime', False)

    def compare_file_times(self, path):
        """
        Check if src/path is younger than dst/path in terms of mtime.
        If use_ctime is True, also checks src/path's ctime.
        """
        src_mtime_ns, src_ctime_ns = self.src_api.get_path_times(path)
        dst_mtime_ns, _            = self.dst_api.get_path_times(path)
        mtime_cmp = ((src_mtime_ns - dst_mtime_ns) >= time_resolution_ns)
        if self.use_ctime:
            ctime_cmp = ((src_ctime_ns - dst_mtime_ns) >= time_resolution_ns)
            return mtime_cmp or ctime_cmp
        else:
            return mtime_cmp

    def compare_dirs(self):
        """ Compare two directories """
        self.src_api.collect_paths()
        src_inc = set(self.src_api.included.keys())
        src_exc = self.src_api.excluded
        self.dst_api.collect_paths()
        dst_inc = set(self.dst_api.included.keys())
        dst_exc = self.dst_api.excluded
        common_inc = src_inc & dst_inc
        src_only = src_inc - common_inc
        dst_only = dst_inc - common_inc
        changed = set()
        truly_changed = set()
        for path in common_inc:
            src_type = self.src_api.get_path_type(path)
            dst_type = self.dst_api.get_path_type(path)
            if (src_type != dst_type) or (src_type == 'DIR') or self.compare_file_times(path):
                changed.add(path)
                if (src_type != dst_type) or (src_type == 'FILE'):
                    truly_changed.add(path)
        return DirCmp(self.src_api.dir_root, self.dst_api.dir_root, \
                      src_exc, dst_exc, src_only, dst_only, changed, truly_changed)

    def sync_dirs(self):
        """ Synchronize two directories """
        dcmp = self.compare_dirs()
        if self.diffonly:
            dcmp.output(self.logger, self.verbose)
            return
        res = DirSyncRes(self.logger)
        # dcmp.dst_only is sorted in reverse order because the contents of a directory
        # should be removed before the directory itself is removed.
        for path in sorted(dcmp.dst_only, reverse=True):
            dst_type = self.dst_api.get_path_type(path)
            if (dst_type == 'DIR'):
                self.dst_api.remove_dir(path, res)
            elif (dst_type == 'FILE'):
                self.dst_api.remove_file(path, res)
        for path in sorted(dcmp.changed):
            src_type = self.src_api.get_path_type(path)
            dst_type = self.dst_api.get_path_type(path)
            if (src_type == 'FILE') and (dst_type == 'FILE'):
                self.copy_file(path, res)
            elif (src_type == 'FILE') and (dst_type == 'DIR'):
                self.dst_api.remove_dir(path, res)
                self.copy_file(path, res)
            elif (src_type == 'DIR') and (dst_type == 'FILE'):
                src_mode = self.src_api.get_path_mode(path)
                self.dst_api.remove_file(path, res)
                self.dst_api.make_dir(path, src_mode, res)
        for path in sorted(dcmp.src_only):
            src_type = self.src_api.get_path_type(path)
            src_mode = self.src_api.get_path_mode(path)
            if (src_type == 'DIR'):
                self.dst_api.make_dir(path, src_mode, res)
            elif (src_type == 'FILE'):
                self.copy_file(path, res)

class DirSync(object):
    """ Object for directory synchronization and encryption """

    def __init__(self, logger, local_dir, remote_dir, **options):
        self.logger = logger
        self.local_dir = Path(local_dir).resolve()
        self.remote_dir = Path(remote_dir).resolve()
        self.options = options
        self.local_api = open_dirapi(self.local_dir)
        assert self.local_api.dir_type == 'plain'
        test_key = options.get('test_key', None)
        self.remote_api = open_dirapi(self.remote_dir, test_key=test_key)

        def push_file(path, res):
            local_file = self.local_dir / path
            self.remote_api.push_file(path, local_file, res)

        def pull_file(path, res):
            local_file = self.local_dir / path
            self.remote_api.pull_file(path, local_file, res)

        self.push_file = push_file
        self.pull_file = pull_file

    def sync(self, command):
        if command == 'push':
            ds = AbsDirSync(self.logger, self.local_api, self.remote_api, self.push_file, self.options)
            ds.sync_dirs()
        elif command == 'pull':
            ds = AbsDirSync(self.logger, self.remote_api, self.local_api, self.pull_file, self.options)
            ds.sync_dirs()
        else:
            raise ValueError("Error: command must be 'push' or 'pull'")
