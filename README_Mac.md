
## In case you use Homebrew's `python3` and `watchman` on macOS:

After updating Homebrew, you may need to perform the following steps:

* Uninstall and re-install `dircifrar` using pipx.
  Do *not* install `pywatchman` using pipx.

* Kill any running `watchman` process(es).

* Make sure `watchman` is given the proper directory or disk access.

* Test `watchman` at the command line on the directory you want to watch:
```
    watchman watch <dir>
```

* Remember to kill the `watchman` process from the testing.

* If all else fails, try `sudo`.
