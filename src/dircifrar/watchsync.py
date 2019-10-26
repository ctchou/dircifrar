
# The code below is adapted from the code of watchman-make:
# https://facebook.github.io/watchman/docs/watchman-make.html

from .__init__ import (
    __pkg_name__,
)
from .dirsync import DirSync
from pathlib import Path
import pywatchman, os, sys

def patterns_to_terms(pats):
    # convert a list of globs into the equivalent watchman expression term
    if pats is None or len(pats) == 0:
        return ['true']
    terms = ['anyof']
    for p in pats:
        terms.append(['match', p, 'wholename', {'includedotfiles': True}])
    return terms

class Target(object):
    """ Base Class for a Target

    We track the patterns that we consider to be the dependencies for
    this target and establish a subscription for them.

    When we receive notifications for that subscription, we know that
    we should execute the command.
    """
    def __init__(self, syncer, command, logger):
        self.name = __pkg_name__
        self.patterns = '**/*'
        self.syncer = syncer
        self.command = command
        self.logger = logger
        self.triggered = False

    def start(self, client, root):
        query = {
            'expression': patterns_to_terms(self.patterns),
            'fields': ['name']
        }
        watch = client.query('watch-project', root)
        if 'warning' in watch:
            self.logger.warning('WARNING: ' + watch['warning'])
        root_dir = watch['watch']
        if 'relative_path' in watch:
            query['relative_root'] = watch['relative_path']
        # get the initial clock value so that we only get updates
        query['since'] = client.query('clock', root_dir)['clock']
        sub = client.query('subscribe', root_dir, self.name, query)

    def consumeEvents(self, client):
        data = client.getSubscription(self.name)
        if data is None:
            return
        self.triggered = True

    def execute(self, force=False):
        if not (self.triggered or force):
            return
        self.triggered = False
        res = self.syncer.sync(self.command)
        res.output(self.logger)

class WatchSync(object):
    """ Object for watching a directory for changes and copying the changes to another directory """

    def __init__(self, logger, command, local_dir, remote_dir, **options):
        self.logger = logger
        self.watch_command = command
        self.local_dir = Path(local_dir).resolve()
        self.remote_dir = Path(remote_dir).resolve()
        self.settle = options.get('settle', 0.2)
        self.syncer = DirSync(local_dir, remote_dir, **options)

        if self.watch_command == 'watch-push':
            self.sync_command = 'push'
            self.watch_root = self.local_dir
            self.logger.info(f'# WATCH-PUSH: {self.local_dir} -> {self.remote_dir}')
        elif self.watch_command == 'watch-pull':
            self.sync_command = 'pull'
            self.watch_root = self.remote_dir
            self.logger.info(f'# WATCH-PULL: {self.local_dir} <- {self.remote_dir}')
        else:
            raise ValueError("Error: command must be 'watch-push' or 'watch-pull'")

        self.client = pywatchman.client(timeout=600)
        try:
            self.client.capabilityCheck(required=['cmd-watch-project', 'wildmatch'])
            os.chdir(self.watch_root)
            self.target = Target(self.syncer, self.sync_command, self.logger)
            self.target.start(self.client, str(self.watch_root))
        except pywatchman.CommandError as ex:
            raise ValueError(f'Error: watchman exception: {str(ex)}')

        # We sync once at the beginning
        self.target.execute(force=True)

        logger.info('# Waiting for changes')
        while True:
            try:
                # Wait for changes to start to occur.  We're happy to wait quite some time for this
                self.client.setTimeout(600)

                result = self.client.receive()
                self.target.consumeEvents(self.client)

                # Now we wait for events to settle
                self.client.setTimeout(self.settle)
                settled = False
                while not settled:
                    try:
                        result = self.client.receive()
                        self.target.consumeEvents(self.client)
                    except pywatchman.SocketTimeout as ex:
                        # Our short settle timeout hit, so we're now settled
                        settled = True
                        break

                # Now we sync
                self.target.execute()

                # Print this at the bottom of the loop rather than the top
                # because we may timeout every so often and it looks weird
                # to keep printing 'Waiting for changes' each time we do.
                logger.info('# Waiting for changes')

            except pywatchman.SocketTimeout as ex:
                # Let's check to see if we're still functional
                try:
                    vers = self.client.query('version')
                except Exception as ex:
                    raise ValueError(f'Error: watchman exception: {str(ex)}')

            except pywatchman.WatchmanError as ex:
                raise ValueError(f'Error: watchman exception: {str(ex)}')

            except KeyboardInterrupt:
                # suppress ugly stack trace when they Ctrl-C
                break
