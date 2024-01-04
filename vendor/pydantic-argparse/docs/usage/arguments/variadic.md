## Overview
`pydantic-argparse` provides functionality for variadic arguments. A variadic
argument is a command-line argument that is followed by one *or more* values.
For example: `--variadic a b c` or `--variadic 1 2 3 4 5 6`.

This section covers the following standard `argparse` argument functionality:

```python
parser.add_argument("--variadic", nargs="+")
```

## Usage
The intended usage of variadic arguments is to capture multiple values for an
argument. For example:

```console
$ python3 example.py --files a.txt b.txt c.txt
```

```python
for file in args.files:
    # We can iterate through all of the values provided by the user
    ...
```

## Container Types
Variadic arguments can be created by adding a `pydantic` `Field` with any
type that is a `:::python collections.abc.Container` type. For example:

* `list[T]`
* `tuple[T]`
* `set[T]`
* `frozenset[T]`
* `deque[T]`

There are different kinds of container variadic arguments, which are outlined
below.

### Required
A *required* container variadic argument is defined as follows:

```python
class Arguments(BaseModel):
    # Required Container Argument
    # Note: `list[int]` is just an example, any container type could be used
    arg: list[int] = Field(description="this is a required variadic argument")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] --arg ARG [ARG ...]

required arguments:
  --arg ARG [ARG ...]  this is a required variadic argument

help:
  -h, --help           show this help message and exit
```

Outcomes:

* Providing an argument of `--arg 1` will set `args.arg` to `[1]`.
* Providing an argument of `--arg 1 2 3` will set `args.arg` to `[1, 2, 3]`.
* This argument cannot be omitted.

### Optional (Default `None`)
An *optional* container variadic argument with a default of `None` is defined
as follows:

```python
class Arguments(BaseModel):
    # Optional Container Argument
    # Note: `list[int]` is just an example, any container type could be used
    arg: Optional[list[int]] = Field(description="this is an optional variadic argument")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] [--arg ARG [ARG ...]]

optional arguments:
  --arg ARG [ARG ...]  this is a required variadic argument (default: None)

help:
  -h, --help           show this help message and exit
```

Outcomes:

* Providing an argument of `--arg 1` will set `args.arg` to `[1]`.
* Providing an argument of `--arg 1 2 3` will set `args.arg` to `[1, 2, 3]`.
* Omitting this argument will set `args.arg` to `None` (the default).

### Optional (Default `Value`)
An *optional* container variadic argument with a constant default value is
defined as follows:

```python
class Arguments(BaseModel):
    # Optional Container Argument
    # Note: `list[int]` is just an example, any container type could be used
    arg: list[int] = Field([4, 5, 6], description="this is an optional variadic argument")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] [--arg ARG [ARG ...]]

optional arguments:
  --arg ARG [ARG ...]  this is an optional variadic argument (default: [4, 5, 6])

help:
  -h, --help           show this help message and exit
```

Outcomes:

* Providing an argument of `--arg 1` will set `args.arg` to `[1]`.
* Providing an argument of `--arg 1 2 3` will set `args.arg` to `[1, 2, 3]`.
* Omitting this argument will set `args.arg` to `[4, 5, 6]` (the default).
