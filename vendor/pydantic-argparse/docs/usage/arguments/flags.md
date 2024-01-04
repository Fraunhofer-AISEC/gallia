## Overview
`pydantic-argparse` provides functionality for flag arguments. A flag is a
command-line argument that has no following value. For example: `--flag` or
`--no-flag`.

This section covers the following standard `argparse` argument functionality:

```python
# Boolean Flags
parser.add_argument("--flag", action=argparse.BooleanOptionalAction)
parser.add_argument("--flag", action="store_true")
parser.add_argument("--no-flag", action="store_false")
# Constant Flags
parser.add_argument("--flag", action="store_const", const="A")
parser.add_argument("--flag", action="store_const", const=Enum.A)
```

## Usage
The intended usage of flags is to enable or disable features. For example:

```console
$ python3 example.py --debug
```

```python
if args.debug:
    # Set logging to DEBUG
    ...
```

## Booleans
Boolean flags can be created by adding a `pydantic` `Field` with the type of
`:::python bool`. There are different kinds of boolean flag arguments, which
are outlined below.

### Required
A *required* boolean flag is defined as follows:

```python
class Arguments(BaseModel):
    # Required Flag
    flag: bool = Field(description="this is a required flag")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] --flag | --no-flag

required arguments:
  --flag, --no-flag  this is a required flag

help:
  -h, --help         show this help message and exit
```

Outcomes:

* Providing an argument of `--flag` will set `args.flag` to `True`.
* Providing an argument of `--no-flag` will set `args.flag` to `False`.
* This argument cannot be omitted.

### Optional (Default `False`)
An *optional* boolean flag with a default of `False` is defined as follows:

```python
class Arguments(BaseModel):
    # Optional Flag (Default False)
    flag: bool = Field(False, description="this is an optional flag")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] [--flag]

optional arguments:
  --flag      this is an optional flag (default: False)

help:
  -h, --help  show this help message and exit
```

Outcomes:

* Providing an argument of `--flag` will set `args.flag` to `True`.
* Omitting this argument will set `args.flag` to `False` (the default).

### Optional (Default `True`)
An *optional* boolean flag with a default of `True` is defined as follows:

```python
class Arguments(BaseModel):
    # Optional Flag (Default True)
    flag: bool = Field(True, description="this is an optional flag")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] [--no-flag]

optional arguments:
  --no-flag   this is an optional flag (default: True)

help:
  -h, --help  show this help message and exit
```

Outcomes:

* Providing an argument of `--no-flag` will set `args.flag` to `False`.
* Omitting this argument will set `args.flag` to `True` (the default).

## Enums
Enum flags can be created by adding a `pydantic` `Field` with the type of an
`:::python enum.Enum` class, which contains only one enumeration. There are
different kinds of enum flag arguments, which are outlined below.

### Optional (Default `None`)
An *optional* enum flag with a default of `None` is defined as follows:

```python
class Constant(enum.Enum):
    VALUE = enum.auto()

class Arguments(BaseModel):
    # Optional Flag (Default None)
    constant: Optional[Constant] = Field(description="this is a constant flag")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] [--constant]

optional arguments:
  --constant  this is a constant flag (default: None)

help:
  -h, --help  show this help message and exit
```

Outcomes:

* Providing an argument of `--constant` will set `args.constant` to `Constant.VALUE`.
* Omitting this argument will set `args.constant` to `None` (the default).

### Optional (Default `Constant`)
An *optional* enum flag with a constant default value is defined as follows:

```python
class Constant(enum.Enum):
    VALUE = enum.auto()

class Arguments(BaseModel):
    # Optional Flag (Default Constant.VALUE)
    constant: Optional[Constant] = Field(Constant.VALUE, description="this is a constant flag")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] [--no-constant]

optional arguments:
  --no-constant  this is a constant flag (default: Constant.VALUE)

help:
  -h, --help     show this help message and exit
```

Outcomes:

* Providing an argument of `--no-constant` will set `args.constant` to `None`.
* Omitting this argument will set `args.constant` to `Constant.VALUE` (the default).

## Literals
Literal flags can be created by adding a `pydantic` `Field` with the type of
`:::python typing.Literal`, which contains only one literal value. There are
different kinds of literal flag arguments, which are outlined below.

### Optional (Default `None`)
An *optional* literal flag with a default of `None` is defined as follows:

```python
class Arguments(BaseModel):
    # Optional Flag (Default None)
    constant: Optional[Literal["VALUE"]] = Field(description="this is a constant flag")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] [--constant]

optional arguments:
  --constant  this is a constant flag (default: None)

help:
  -h, --help  show this help message and exit
```

Outcomes:

* Providing an argument of `--constant` will set `args.constant` to `"VALUE"`.
* Omitting this argument will set `args.constant` to `None` (the default).

### Optional (Default `Constant`)
An *optional* literal flag with a constant default value is defined as follows:

```python
class Arguments(BaseModel):
    # Optional Flag (Default "VALUE")
    constant: Optional[Literal["VALUE"]] = Field("VALUE", description="this is a constant flag")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] [--no-constant]

optional arguments:
  --no-constant  this is a constant flag (default: VALUE)

help:
  -h, --help     show this help message and exit
```

Outcomes:

* Providing an argument of `--no-constant` will set `args.constant` to `None`.
* Omitting this argument will set `args.constant` to `"VALUE"` (the default).
