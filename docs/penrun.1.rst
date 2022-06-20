.. SPDX-FileCopyrightText: AISEC Pentesting Team
..
.. SPDX-License-Identifier: CC0-1.0

penrun
======

Synopsis
--------

::

    penrun [ARGS] COMMAND…

Description
-----------

penrun(1) is a runner intended for invoking tests; any shellcommand can be started.
A well defined directory structure is created for the so called "artifacts".
COMMAND is run within this directory which is there for any results (e.g. pcap files, penlog artifacts, …).
For more information about the artifacts directory, see the ARTIFACTS section.

An experimental batched mode is supported.
``penrun`` can read a list of commands or command fragments (see ``-T``) and process them sequentially or in parallel.

Arguments
---------

The following arguments are understood by penrun.

.. cmdoption:: -C CMD

    The output of ``COMMAND`` is piped through the command, specified as ``CMD``.
    The program specified with ``CMD`` must read from stdin and write to stdout.
    Example: ``zstd -T0``. See also: ``-e``.

.. cmdoption:: -S SEC

    Sleep this amount of time (same format as ``sleep(1)`` accepts) between commands.
    Only evaluated in batched mode.

.. cmdoption:: -T TPL

    A template string for command artifacts used by penrun's batched mode.
    The string ``%s`` is expanded to the current line on penrun's stdin.
    Example: If TPL is ``curl -LO %s`` and a list of URLs is piped to penrun, then penrun expands ``%s`` to the current URL and invoces ``curl`` with ``curl -LO URL``.

.. cmdoption:: -c FILE

    Source the config file ``FILE`` instead searching in the known paths.

.. cmdoption:: -d DIR

    Use ``DIR`` for all artifacts instead of creating a new one.

.. cmdoption:: -e EXT

    Use ``EXT`` as a file extension to the OUTPUT file in the artifactsdir.

.. cmdoption:: -j JOBS

    Run ``JOBS`` in parallel when operating in batched mode.

.. cmdoption:: -n

    Ignore the ``PENRUN_DEFAULT_ARGS`` from the config.

.. cmdoption:: -p CMD

    Pipe the output of ``COMMAND`` through the ``CMD`` specified with ``-p``.

.. cmdoption:: -s

    Do not run any hooks this time.

.. cmdoption:: -t TAG

    Adds a suffix to the artifactsdir.
    If the COMMAND is ``ls`` and tag is ``foo`` then the artifactsdir might be ``ls-foo/run-20200806-113712``.

.. cmdoption:: -u

    In batched mode, abort when the first error occurs.

.. cmdoption:: -h

    Show the usage help page and exit


Config Files
------------

Customization is possible with config files, which are plain boring bash files.
The following locations are searched in this order.
The filepath of each config is exported as an environment variable.

* ``PENRUN_PWD_CONF``: ``$PWD/.penrun.sh``
* ``PENRUN_GIT_ROOT_CONF``: ``$GITROOT/.penrun.sh`` (``$GITROOT`` is obtained via ``git rev-parse --show-toplevel``)
* ``PENRUN_USER_CONF``: ``$HOME/.config/penrun/config.sh``
* ``PENRUN_GLOBAL_CONF``: ``/etc/penrun/config.sh``

If **one** of these files is found, automatic sourcing of config files stops.
This choice was made in order to avoid confusing about old and forgotten config files.
Config loading has to be explicit.
If a config hierarchy is required a snippet like the following could be placed in the configuration:

::

    # stuff …

    if [[ -n "${PENRUN_GLOBAL_CONF-}" ]]; then
        source "$PENRUN_GLOBAL_CONF"
    fi

If one of these variables (``PENRUN_PWD_CONF``, …) is not defined, then the config file does not exist.

Config Variables
----------------

The following variables have special meaning in a penrun(1) config script.

PENRUN_DEFAULT_ARGS (array)
    These arguments are prepended to the arguments of COMMAND.
    If COMMAND is ``ls -lah`` and DEFAULT_ARGS is ``(--foo --bar)``, then the following command is invoked: ``ls --foo --bar -lah``.

PENRUN_ARTIFACTS_BASE
    If this variable is set then penrun creates the artifacts folder hierarchy at this location instead of $PWD.

PENRUN_PIPE_COMMAND
    A command (as an bash array) which reads from stdin where the output of ``COMMAND`` is piped into.
    Example: ``PENRUN_PIPE_COMMAND=("hr" "-p" "info")``.

PENRUN_COMPRESSION_COMMAND
    The same as ``-C`` but as a bash array.

PENRUN_OUTPUT_EXTENSION
    The same as ``-e``.

Hooks
-----

Hook functions can be defined as ordinary shell functions.
Hooks must finish with exit code 0.
Any other code is considered an error by penrun causing penrun to exit.
The following hooks are available:

``pre_run``
    This function is run **before** COMMAND.

``post_run``
    This function is run **after** COMMAND.

Functions
---------

cmd_to_artifactsdir
    If this function is defined in the config, then it is called with the following arguments:
    ``artifactsdir``, ``fragment``, ``command``.
    The output of this function will be used by ``penrun`` as the actual artifactsdir.
    The usecase might be, when there is a tool which has a single entrypoint, such as ``git``, then the artifactsdir can be rewritten to use the subcommand as a directory name instead.

Artifacts
---------

On each invocation a new directory is created at the following location ``$PWD/$COMMAND/run-$(date +%Y%m%d-%H%M%S)``, called ``artifactsdir``.
Before COMMAND is invoked, the current directory is changed to ``artifactsdir``.
Artifacts, such as pcap or penlog files, can easily be placed in the current working directory of COMMAND.
The output of stderr and stdout is stored in a file ``OUTPUT`` in the ``artifactsdir``.
Metainformation, such as the exit code, are placed in a file ``META`` in the ``artifactsdir``.
The environment is stored in a file ``ENV`` in the ``artifactsdir``.
In order to locate the last run, the last run's ``artifactsdir`` is always symlinked with ``LATEST``.

META
----

META files contain metainformation about the respective testrun for reproducability reasons.
The file format is a simple linebased key value format.
Keys are separated from values with a colon ``:``; whitespace has no semantic meaning.
META files contain the following key value pairs:

COMMAND (string)::
    The full invocation string; in this manpage referred to as COMMAND.

EXIT (integer)::
    The exit code of the issued COMMAND.

START (string)::
    The exact start date of COMMAND in ISO8601 format.

END (string)::
    The exact end date of COMMAND in ISO8601 format.

ENV
---

All environment variables are stored in this file.
The format is the same as produced by the ``printenv`` tool.

OUTPUT
------

OUTPUT files contain the unfiltered stderr and stdout of COMMAND.
It may be compressed which is then indicated with a ``.gz`` or ``.zst`` file extension.

If hooks are run, their output is stored in PRERUN_OUTPUT and POSTRUN_OUTPUT.

Examples
--------

::

    $ penrun ls -lah > /dev/null
    $ penrun ls -lah > /dev/null
    $ tree ls
    ls
    ├── LATEST -> run-20200710-101415
    ├── run-20200710-101334
    │   ├── ENV
    │   ├── META
    │   └── OUTPUT
    └── run-20200710-101415
        ├── ENV
        ├── META
        └── OUTPUT

Environment Variables
---------------------

The following variables are set by penrun and can be evaluated by programs orchestrated by penrun.

PENRUN_ARTIFACTS
    This variable is set by penrun to the current artifactsdir.
    Spawned programs can use this variable to locate the current artifactsdir to store further artifacts on their own.

PENRUN_BATCHED
    This variable is set, when penrun processes commands in batched mode.

PENRUN_COMMAND
    This variable includes the full command provided to penrun; excluding DEFAULT_ARGS.

PENRUN_PWD_CONF, PENRUN_GIT_ROOT_CONF, PENRUN_USER_CONF, PENRUN_GLOBAL_CONF
    These variables are set if the appropriate config exists (see CUSTOMIZATION).

See Also
--------

:manpage:`hr(1)`, :manpage:`penlog(7)`
