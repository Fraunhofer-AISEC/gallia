<!--
SPDX-FileCopyrightText: Hayden Richards

SPDX-License-Identifier: MIT
-->

<div align="center">
    <a href="https://pydantic-argparse.supimdos.com">
        <img src="https://raw.githubusercontent.com/SupImDos/pydantic-argparse/master/docs/assets/images/logo.svg" width="50%">
    </a>
    <h1>
        Pydantic Argparse
    </h1>
    <p>
        <em>Typed Argument Parsing with Pydantic</em>
    </p>
    <a href="https://pypi.python.org/pypi/pydantic-argparse">
        <img src="https://img.shields.io/pypi/v/pydantic-argparse.svg">
    </a>
    <a href="https://pepy.tech/project/pydantic-argparse">
        <img src="https://pepy.tech/badge/pydantic-argparse">
    </a>
    <a href="https://github.com/SupImDos/pydantic-argparse">
        <img src="https://img.shields.io/pypi/pyversions/pydantic-argparse.svg">
    </a>
    <a href="https://github.com/SupImDos/pydantic-argparse/blob/master/LICENSE">
        <img src="https://img.shields.io/github/license/SupImDos/pydantic-argparse.svg">
    </a>
    <br>
    <a href="https://github.com/SupImDos/pydantic-argparse/actions/workflows/tests.yml">
        <img src="https://img.shields.io/github/actions/workflow/status/supimdos/pydantic-argparse/tests.yml?label=tests">
    </a>
    <a href="https://github.com/SupImDos/pydantic-argparse/actions/workflows/tests.yml">
        <img src="https://img.shields.io/coveralls/github/SupImDos/pydantic-argparse">
    </a>
    <a href="https://github.com/SupImDos/pydantic-argparse/actions/workflows/linting.yml">
        <img src="https://img.shields.io/github/actions/workflow/status/supimdos/pydantic-argparse/linting.yml?label=linting">
    </a>
    <a href="https://github.com/SupImDos/pydantic-argparse/actions/workflows/typing.yml">
        <img src="https://img.shields.io/github/actions/workflow/status/supimdos/pydantic-argparse/typing.yml?label=typing">
    </a>
</div>

## Fork major changes
1. Upgrade to only be compatible with `Pydantic` v2+
    - `Pydantic` recently released version 2, which heavily relies on a Rust backend for major speed improvements in data validation.
    - However, there are many breaking changes that were introduced in the process.
2. Nested `Pydantic` models now default to argument **groups** instead of subcommands. This leads to large argument lists being much more composable for large applications since the arguments can be broken into smaller groups.
    - Subcommands are now explicitly *opt-in* features. A convenience base class `pydantic_argparse.BaseCommand` has been provided that sets the queried configuration variable, which can then be used as a typical `pydantic.BaseModel` otherwise.
3. The `metavar` option for `argparser.ArgumentParser.add_argument` now (almost always) defaults to the type of the argument instead of the argument name.


### Argument Groups example
```python
from pydantic import Field, BaseModel
from pydantic_argparse import ArgumentParser, BaseArgument

# BaseArgument is just a pydantic.BaseModel that explicitly opted out from subcommands
# however, pydantic.BaseModel classes have implicitly opted out as well

class Group1(BaseArgument):
    string: str = Field(description="a required string")
    integer: int = Field(description="a required integer")
    decimal: float = Field(description="a required float")
    flag: bool = Field(False, description="a flag")

class Group2(BaseArgument):
    name: str = Field(description="your name")
    age: int = Field(82, description="your age")

class Arguments(BaseModel):
    first: Group1
    second: Group2

if __name__ == "__main__":
    parser = ArgumentParser(model=Arguments)
    parser.parse_typed_args()
```

```console
$ python3 example_groups.py --help
usage: example_groups.py [-h] [-v] --string STR --integer INT [--flag] 
                                   --name STR [--age INT]

FIRST:
  --string  STR      a required string
  --integer INT      a required integer
  --decimal FLOAT    a required float
  --flag             a flag

SECOND:
  --name    STR      your name
  --age     INT      you age (default: 82)

help:
  -h, --help         show this help message and exit
  -v, --version      show program's version number and exit
```

### TODO

- [ ] Look into short arg names at the command line.
  - This may involve the use of the model field `.alias` option

## Help
See [documentation](https://pydantic-argparse.supimdos.com) for help.

## Installation
Installation with `pip` is simple:
```console
$ pip install pydantic-argparse
```

## Example
```py
import pydantic
import pydantic_argparse


class Arguments(pydantic.BaseModel):
    # Required Args
    string: str = pydantic.Field(description="a required string")
    integer: int = pydantic.Field(description="a required integer")
    flag: bool = pydantic.Field(description="a required flag")

    # Optional Args
    second_flag: bool = pydantic.Field(False, description="an optional flag")
    third_flag: bool = pydantic.Field(True, description="an optional flag")


def main() -> None:
    # Create Parser and Parse Args
    parser = pydantic_argparse.ArgumentParser(
        model=Arguments,
        prog="Example Program",
        description="Example Description",
        version="0.0.1",
        epilog="Example Epilog",
    )
    args = parser.parse_typed_args()

    # Print Args
    print(args)


if __name__ == "__main__":
    main()
```

```console
$ python3 example.py --help
usage: Example Program [-h] [-v] --string STRING --integer INTEGER --flag |
                       --no-flag [--second-flag] [--no-third-flag]

Example Description

required arguments:
  --string STRING    a required string
  --integer INTEGER  a required integer
  --flag, --no-flag  a required flag

optional arguments:
  --second-flag      an optional flag (default: False)
  --no-third-flag    an optional flag (default: True)

help:
  -h, --help         show this help message and exit
  -v, --version      show program's version number and exit

Example Epilog
```

```console
$ python3 example.py --string hello --integer 42 --flag
string='hello' integer=42 flag=True second_flag=False third_flag=True
```

## License
This project is licensed under the terms of the MIT license.
