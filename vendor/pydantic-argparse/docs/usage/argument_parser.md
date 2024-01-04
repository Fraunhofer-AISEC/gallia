## Overview
The interface for `pydantic-argparse` is the custom typed
[`ArgumentParser`][pydantic_argparse.argparse.parser.ArgumentParser] class,
which provides declarative, typed argument parsing.

This `ArgumentParser` class presents a very *similar* interface to the `python`
standard library `argparse.ArgumentParser`, in an attempt to provide as close
to a drop-in-replacement as possible.

## Parser Instantiation
To create an instance of the `ArgumentParser`:
```python
parser = pydantic_argparse.ArgumentParser(
    model=Arguments,
    prog="Program Name",
    description="Program Description",
    version="1.2.3",
    epilog="Program Epilog",
    add_help=True,
    exit_on_error=True,
)
```

### Required Parameters
The *required* parameters for the `ArgumentParser` are outlined below:

* `model` (`Type[pydantic.BaseModel]`):
    The model that defines the command-line arguments

### Optional Parameters
The *optional* parameters for the `ArgumentParser` are outlined below:

* `prog` (`Optional[str]`):
    The program name that appears in the help message
* `description` (`Optional[str]`):
    The program description that appears in the help message
* `version` (`Optional[str]`):
    The program version that appears in the help message
* `epilog` (`Optional[str]`):
    The program epilog that appears in the help message
* `add_help` (`bool`):
    Whether to add the `-h / --help` help message action
* `exit_on_error` (`bool`):
    Whether to exit, or raise an `ArgumentError` upon an error

## Argument Parsing
To parse command-line arguments into the `model` using the `ArgumentParser`:
```python
args = parser.parse_typed_args()
```

!!! info
    The `ArgumentParser` is *generic* over its `pydantic` `model`. This means
    that the parsed `args` object is type-hinted as an instance of its `model`.

### Optional Parameters
The *optional* parameters for the `parse_typed_args` method are outlined below:

* `args` (`Optional[List[str]]`):
    Optional list of arguments to parse *instead* of `sys.argv`
