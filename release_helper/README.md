# release_helper

This is a simple utility that will help with updating Binary Ninja plugins in the plugin manager

```
$ ls myplugin/plugin.json
myplugin/plugin.json
$ git clone https://github.com/Vector35/release_helper
$ cd myplugin
$ chmod +x ../release_helper/do_release.py
$ pip3 install githubrelease gitpython
$ ../release_helper/do_release.py --help

usage: do_release.py [-h] [-d DESCRIPTION] [-v NEW_VERSION] [--force]

optional arguments:
  -h, --help            show this help message and exit
  -d DESCRIPTION, --description DESCRIPTION
                        Description for the new release
  -v NEW_VERSION, --version NEW_VERSION
                        New version string
  --force               Override the repository dirty check

$ ../release_helper/do_release.py --version 1.5.1

```

## new release

Whenever you have a new release, you can either let the script automatically increment the version number for you, or you can specify it yourself. You can either manually edit the `plugin.json` file with the new version in which case the release script will create the appropriate tag and release for you, or specify it yourself on the command-line.

