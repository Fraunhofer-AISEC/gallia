## Overview
`pydantic-argparse` provides functionality for regular arguments. A regular
argument is a command-line argument that is followed by *exactly* one value.
For example: `--arg hello`, `--arg 123` or `--arg 42.0`.

This section covers the following standard `argparse` argument functionality:

```python
parser.add_argument("--argument", type=T)
```

## Usage
The intended usage of regular arguments is to capture and validate a value from
the user for the application. For example:

```console
$ python3 example.py --name SupImDos
```

```python
# We can use the validated command-line arguments in the application
print(f"Hello {args.name}!")
```

## Singular Types
Regular arguments can be created by adding a `pydantic` `Field` with any
type that takes "singular" values.

Some examples of simple "singular" inbuilt types:

* `str`
* `int`
* `float`
* `dict`

!!! info
    For more information about simple inbuilt types, see the `pydantic`
    [docs][1]

!!! note
    `pydantic-argparse` handles some types *specially*, such as:

    * `collections.abc.Container` (e.g., `list`, `tuple`, `set`)
    * `bool`
    * `enum.Enum`
    * `typing.Literal`
    * `pydantic.BaseModel`

    The special behaviours of these types are addressed in the following
    sections.

Any type that is able to be validated by `pydantic` can be used. This allows
for advanced argument types, for example:

* `pydantic.FilePath`
* `pydantic.EmailStr`
* `pydantic.AnyUrl`
* `pydantic.IPvAnyAddress`

!!! info
    For more information about advanced `pydantic` types, see the `pydantic`
    [docs][2]

There are different kinds of regular arguments, which are outlined below.

### Required
A *required* regular singular argument is defined as follows:

```python
class Arguments(BaseModel):
    # Required Singular Argument
    # Note: `int` is just an example, any singular type could be used
    arg: int = Field(description="this is a required singular argument")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] --arg ARG

required arguments:
  --arg ARG   this is a required singular argument

help:
  -h, --help  show this help message and exit
```

Outcomes:

* Providing an argument of `--arg 42` will set `args.arg` to `42`.
* This argument cannot be omitted.

### Optional (Default `None`)
An *optional* regular singular argument with a default of `None` is defined as
follows:

```python
class Arguments(BaseModel):
    # Optional Singular Argument
    # Note: `int` is just an example, any singular type could be used
    arg: Optional[int] = Field(description="this is an optional singular argument")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] [--arg ARG]

optional arguments:
  --arg ARG   this is a required singular argument (default: None)

help:
  -h, --help  show this help message and exit
```

Outcomes:

* Providing an argument of `--arg 42` will set `args.arg` to `42`.
* Omitting this argument will set `args.arg` to `None` (the default).

### Optional (Default `Value`)
An *optional* container variadic argument with a constant default value is
defined as follows:

```python
class Arguments(BaseModel):
    # Optional Singular Argument
    # Note: `int` is just an example, any singular type could be used
    arg: int = Field(42, description="this is an optional singular argument")
```

This `Arguments` model generates the following command-line interface:

```console
$ python3 example.py --help
usage: example.py [-h] [--arg ARG]

optional arguments:
  --arg ARG   this is a required singular argument (default: 42)

help:
  -h, --help  show this help message and exit
```

Outcomes:

* Providing an argument of `--arg 7` will set `args.arg` to `7`.
* Omitting this argument will set `args.arg` to `42` (the default).

<!--- Reference -->
[1]: https://docs.pydantic.dev/usage/types/#standard-library-types
[2]: https://docs.pydantic.dev/usage/types/#pydantic-types
