<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Plugins
## Entry Points

`gallia` uses the [`entry_points` mechanism](https://docs.python.org/3/library/importlib.metadata.html#entry-points) for registering plugins.
These `entry_points` are known by `gallia`:

* `gallia_cli_commands`: Subclasses of {meth}`gallia.command.BaseCommand` add new a command to the CLI.
* `gallia_cli_init`: Callables which get called during the initialization phase of the `ArgumentParser`; can be used to add new categories to the CLI.
* `gallia_transports`: Subclasses of {meth}`gallia.transports.BaseTransport` add a new URI scheme for the `--target` flag.
* `gallia_uds_ecus`: Subclasses of {meth}`gallia.uds.ECU` add new choices for the `--oem` flag.

## CLI Categories

TODO

## Commands

TODO
