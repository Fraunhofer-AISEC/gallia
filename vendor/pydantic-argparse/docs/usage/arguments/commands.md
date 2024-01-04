## Overview
`pydantic-argparse` provides functionality for commands. A command is a
positional command-line argument that can be followed by its own specific
subset of command-line arguments. For example: `command --arg abc`.

This section covers the following standard `argparse` argument functionality:

```python
# Subparser Commands
subparsers = parser.add_subparsers()
command = subparsers.add_parser("command")
command.add_argument(...)
```

## Usage
The intended usage of commands is to provide the user with different
application behaviours, each with their own subset of arguments. For example:

```console
$ python3 example.py serve --address 127.0.0.1 --port 8080
```

```python
if args.serve:
    # The serve command was chosen
    # We have typed access to any of the command model arguments we defined
    # For example: `args.serve.address`, `args.serve.port`, etc.
    ...
```

## Pydantic Models
Commands can be created by first defining a `pydantic` model for the command
(e.g., `Command`), containing its own subset of arguments. The command can then
be added to the command-line interface by adding a `pydantic` field with the
type of `Optional[Command]`. Despite each command itself being *optional*,
overall a command is *always* required, as outlined below.

### Required
*Required* commands are defined as follows:

```python
class Command1(BaseModel):
    arg1: str = Field(description="this is sub-argument 1")

class Command2(BaseModel):
    arg2: str = Field(description="this is sub-argument 2")

class Arguments(BaseModel):
    # Commands
    command1: Optional[Command1] = Field(description="this is command 1")
    command2: Optional[Command2] = Field(description="this is command 2")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] {command1,command2} ...

commands:
  {command1,command2}
    command1           this is command 1
    command2           this is command 2

help:
  -h, --help           show this help message and exit
```

This `Arguments` model also generates command-line interfaces for each of its
commands:

```console
$ python3 example.py command1 --help
usage: example.py command1 [-h] --arg1 ARG1

required arguments:
  --arg1 ARG1  this is sub-argument 1

help:
  -h, --help   show this help message and exit
```

```console
$ python3 example.py command2 --help
usage: example.py command2 [-h] --arg2 ARG2

required arguments:
  --arg2 ARG2  this is sub-argument 2

help:
  -h, --help   show this help message and exit
```

Outcomes:

* Providing arguments of `command1 --arg1 abc` will set `args.command1` to
  to `:::python Command1(arg1="abc")`, and `args.command2` to `None`.
* Providing arguments of `command2 --arg2 xyz` will set `args.command2` to
  to `:::python Command2(arg2="xyz")`, and `args.command1` to `None`.
* Commands cannot be omitted.
