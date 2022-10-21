<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Plugins
## Entry Points

`gallia` uses the [`entry_points` mechanism](https://docs.python.org/3/library/importlib.metadata.html#entry-points) for registering plugins.
These entry points are known by `gallia`:

`gallia_cli_commands`
: List of subclasses of {class}`gallia.command.BaseCommand` add new a command to the CLI.

`gallia_cli_init`
: List of callables which get called during the initialization phase of the `ArgumentParser`; can be used to add new categories to the CLI.

`gallia_transports`
: List of subclasses of {class}`gallia.transports.BaseTransport` add a new URI scheme for the `--target` flag.

`gallia_uds_ecus`
: List of subclasses of {class}`gallia.services.uds.ECU` which add new choices for the `--oem` flag.

## CLI Categories

TODO

## Commands

TODO
