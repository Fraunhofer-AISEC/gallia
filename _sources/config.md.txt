<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Configuration

## gallia.toml

All `gallia` settings stem from the commandline interface.
The documentation for all available settings per subcommand is available via `-h/--help`.
Frequently used settings can be put in a configfile which is called `gallia.toml`.
Settings from the config file set the **default** of the respective commandline option.
The config can always be overwritten by manually setting the relevant cli option.

The configuration file `gallia.toml` is written in [TOML](https://toml.io/en/). 
Inheritence is not supported; the first file is loaded.
The `gallia.toml` file is loaded from these locations (in this particular order):

* path specified in the env variable `GALLIA_CONFIG`; see {doc}`../env`.
* current directory
* current Git root (if the current directory is a Git repository)
* `$XDG_CONFIG_HOME/gallia/gallia.toml`
* `~/.config/gallia/gallia.toml`

Only some cli options are exposed to the config file.
The available config settings can be obtained from `gallia --template`.
The output of `--template` is maintained to be up to date and is intended as a starting point.

## Hooks

`gallia` supports hooks for preparation or cleanup/postprocessing tasks.
Alternatively, they can be useful for e.g. sending notifications about the exit_code via e.g. matrix or ntfy.sh.
Hooks are shell scripts which are executed before (= pre-hook) or after (= post-hook) the `main()` method.
These scripts can be specified via `--pre-hook` or `--post-hook` or via `gallia.toml` as well.

The hook scripts have these environment variables set; some are optional and hook scripts are encouraged to check their presence before accessing them:

GALLIA_HOOK
: Either `pre` or `post`.

GALLIA_ARTIFACTS_DIR
: Path to the artifactsdir for the current testrun.

GALLIA_EXIT_CODE (post)
: Is set to the exit_code which `gallia` will use after the hook terminates.
  For instance GALLIA_EXIT_CODE different from zero means that the current testrun failed.

GALLIA_META (post)
: Contains the JSON encoded content of `META.json`.

GALLIA_INVOCATION
: The content os `sys.argv`, in other words the raw invocation of `gallia`.

GALLIA_GROUP (optional)
: Usually the first part of the command on the cli. For instance, for `gallia scan uds identifiers` 
  `GALLIA_GROUP` is `scan`.

GALLIA_SUBGROUP (optional)
: Usually the second part of the command on the cli. For instance, for `gallia scan uds identifiers` 
  `GALLIA_GROUP` is `uds`.

GALLIA_COMMAND (optional)
: Usually the last part of the command on the cli. For instance, for `gallia scan uds identifiers` 
  `GALLIA_COMMAND` is `identifiers`.
