<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Plugins
## Entry Points

`gallia` uses the [`entry_points` mechanism](https://docs.python.org/3/library/importlib.metadata.html#entry-points) for registering plugins.
These entry points are known by `gallia`:

`gallia_commands`
: List of subclasses of {class}`gallia.command.BaseCommand` add new a command to the CLI.

`gallia_cli_init`
: List of callables which get called during the initialization phase of the `ArgumentParser`; can be used to add new groups to the CLI.

`gallia_transports`
: List of subclasses of {class}`gallia.transports.BaseTransport` add a new URI scheme for the `--target` flag.

`gallia_uds_ecus`
: List of subclasses of {class}`gallia.services.uds.ECU` which add new choices for the `--oem` flag.

## Example

Below is an example that adds a new command to the CLI (using {class}`gallia.command.Script`).
Let's assume the following code snippet lives in the python module `hello.py` within the `hello_gallia` package.

``` python
from argparse import Namespace

from gallia.command import Script


class HelloWorld(Script):
    """A hello world script showing gallia's plugin API."""

    COMMAND = "hello"
    SHORT_HELP = "say hello to the world"


    def main(self, args: Namespace) -> None:
        print("Hello World")


commands = [HelloWorld]
```

In `pyproject.toml` using `poetry` the following entry_point needs to be specified:

``` toml
[tool.poetry.plugins."gallia_commands"]
"hello_world_commands" = "hello_gallia.hello:commands"
```

After issueing `poetry install`, the script can be called with `gallia script hello`.

If a standalone script is desired, the `HelloWorld` class can be called like this:

``` python
parser = argparse.ArgumentParser()
sys.exit(HelloWorld(parser).entry_point(parser.parse_args()))
```
