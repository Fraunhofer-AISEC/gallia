"""Tests the `parser` Module.

This module provides full unit test coverage for the `parser` module, testing
all branches of all methods. These unit tests target the typed `ArgumentParser`
class by testing a large number of expected use-cases.
"""


# Standard
import argparse
import collections as coll
import datetime as dt
import re
import sys
import textwrap

# Third-Party
import pydantic
import pytest

# Local
import pydantic_argparse
import tests.conftest as conf

# Typing
from typing import Deque, Dict, FrozenSet, List, Optional, Set, Tuple, Type, TypeVar

# Version-Guarded
if sys.version_info < (3, 8):  # pragma: <3.8 cover
    from typing_extensions import Literal
else:  # pragma: >=3.8 cover
    from typing import Literal


# Constants
ArgumentT = TypeVar("ArgumentT")


@pytest.mark.parametrize("prog",          ["AA", None])
@pytest.mark.parametrize("description",   ["BB", None])
@pytest.mark.parametrize("version",       ["CC", None])
@pytest.mark.parametrize("epilog",        ["DD", None])
@pytest.mark.parametrize("add_help",      [True, False])
@pytest.mark.parametrize("exit_on_error", [True, False])
def test_create_argparser(
    prog: Optional[str],
    description: Optional[str],
    version: Optional[str],
    epilog: Optional[str],
    add_help: bool,
    exit_on_error: bool,
) -> None:
    """Tests Constructing the ArgumentParser.

    Args:
        prog (Optional[str]): Program name for testing.
        description (Optional[str]): Program description for testing.
        version (Optional[str]): Program version for testing.
        epilog (Optional[str]): Program epilog for testing.
        add_help (bool): Whether to add help flag for testing.
        exit_on_error (bool): Whether to exit on error for testing.
    """
    # Create ArgumentParser
    parser = pydantic_argparse.ArgumentParser(
        model=conf.TestModel,
        prog=prog,
        description=description,
        version=version,
        epilog=epilog,
        add_help=add_help,
        exit_on_error=exit_on_error,
    )

    # Asserts
    assert isinstance(parser, pydantic_argparse.ArgumentParser)


@pytest.mark.parametrize(
    (
        "argument_type",
        "argument_default",
        "arguments",
        "result",
    ),
    [
        # Required Arguments
        (int,                    ..., "--test 123",              123),
        (float,                  ..., "--test 4.56",             4.56),
        (str,                    ..., "--test hello",            "hello"),
        (bytes,                  ..., "--test bytes",            b"bytes"),
        (List[str],              ..., "--test a b c",            list(("a", "b", "c"))),
        (Tuple[str, str, str],   ..., "--test a b c",            tuple(("a", "b", "c"))),
        (Set[str],               ..., "--test a b c",            set(("a", "b", "c"))),
        (FrozenSet[str],         ..., "--test a b c",            frozenset(("a", "b", "c"))),
        (Deque[str],             ..., "--test a b c",            coll.deque(("a", "b", "c"))),
        (Dict[str, int],         ..., "--test {'a':2}",          dict(a=2)),
        (dt.date,                ..., "--test 2021-12-25",       dt.date(2021, 12, 25)),
        (dt.datetime,            ..., "--test 2021-12-25T12:34", dt.datetime(2021, 12, 25, 12, 34)),
        (dt.time,                ..., "--test 12:34",            dt.time(12, 34)),
        (dt.timedelta,           ..., "--test PT12H",            dt.timedelta(hours=12)),
        (bool,                   ..., "--test",                  True),
        (bool,                   ..., "--no-test",               False),
        (Literal["A"],           ..., "--test A",                "A"),
        (Literal["A", 1],        ..., "--test 1",                1),
        (conf.TestEnumSingle,    ..., "--test D",                conf.TestEnumSingle.D),
        (conf.TestEnum,          ..., "--test C",                conf.TestEnum.C),

        # Optional Arguments (With Default)
        (int,                  456,                         "--test 123",              123),
        (float,                1.23,                        "--test 4.56",             4.56),
        (str,                  "world",                     "--test hello",            "hello"),
        (bytes,                b"bits",                     "--test bytes",            b"bytes"),
        (List[str],            list(("d", "e", "f")),       "--test a b c",            list(("a", "b", "c"))),
        (Tuple[str, str, str], tuple(("d", "e", "f")),      "--test a b c",            tuple(("a", "b", "c"))),
        (Set[str],             set(("d", "e", "f")),        "--test a b c",            set(("a", "b", "c"))),
        (FrozenSet[str],       frozenset(("d", "e", "f")),  "--test a b c",            frozenset(("a", "b", "c"))),
        (Deque[str],           coll.deque(("d", "e", "f")), "--test a b c",            coll.deque(("a", "b", "c"))),
        (Dict[str, int],       dict(b=3),                   "--test {'a':2}",          dict(a=2)),
        (dt.date,              dt.date(2021, 7, 21),        "--test 2021-12-25",       dt.date(2021, 12, 25)),
        (dt.datetime,          dt.datetime(2021, 7, 21, 3), "--test 2021-04-03T02:00", dt.datetime(2021, 4, 3, 2)),
        (dt.time,              dt.time(3, 21),              "--test 12:34",            dt.time(12, 34)),
        (dt.timedelta,         dt.timedelta(hours=6),       "--test PT12H",            dt.timedelta(hours=12)),
        (bool,                 False,                       "--test",                  True),
        (bool,                 True,                        "--no-test",               False),
        (Literal["A"],         "A",                         "--test",                  "A"),
        (Literal["A", 1],      "A",                         "--test 1",                1),
        (conf.TestEnumSingle,  conf.TestEnumSingle.D,       "--test",                  conf.TestEnumSingle.D),
        (conf.TestEnum,        conf.TestEnum.B,             "--test C",                conf.TestEnum.C),

        # Optional Arguments (With Default) (No Value Given)
        (int,                  456,                            "", 456),
        (float,                1.23,                           "", 1.23),
        (str,                  "world",                        "", "world"),
        (bytes,                b"bits",                        "", b"bits"),
        (List[str],            list(("d", "e", "f")),          "", list(("d", "e", "f"))),
        (Tuple[str, str, str], tuple(("d", "e", "f")),         "", tuple(("d", "e", "f"))),
        (Set[str],             set(("d", "e", "f")),           "", set(("d", "e", "f"))),
        (FrozenSet[str],       frozenset(("d", "e", "f")),     "", frozenset(("d", "e", "f"))),
        (Deque[str],           coll.deque(("d", "e", "f")),    "", coll.deque(("d", "e", "f"))),
        (Dict[str, int],       dict(b=3),                      "", dict(b=3)),
        (dt.date,              dt.date(2021, 7, 21),           "", dt.date(2021, 7, 21)),
        (dt.datetime,          dt.datetime(2021, 7, 21, 3, 7), "", dt.datetime(2021, 7, 21, 3, 7)),
        (dt.time,              dt.time(3, 21),                 "", dt.time(3, 21)),
        (dt.timedelta,         dt.timedelta(hours=6),          "", dt.timedelta(hours=6)),
        (bool,                 False,                          "", False),
        (bool,                 True,                           "", True),
        (Literal["A"],         "A",                            "", "A"),
        (Literal["A", 1],      "A",                            "", "A"),
        (conf.TestEnumSingle,  conf.TestEnumSingle.D,          "", conf.TestEnumSingle.D),
        (conf.TestEnum,        conf.TestEnum.B,                "", conf.TestEnum.B),

        # Optional Arguments (No Default)
        (Optional[int],                  None, "--test 123",              123),
        (Optional[float],                None, "--test 4.56",             4.56),
        (Optional[str],                  None, "--test hello",            "hello"),
        (Optional[bytes],                None, "--test bytes",            b"bytes"),
        (Optional[List[str]],            None, "--test a b c",            list(("a", "b", "c"))),
        (Optional[Tuple[str, str, str]], None, "--test a b c",            tuple(("a", "b", "c"))),
        (Optional[Set[str]],             None, "--test a b c",            set(("a", "b", "c"))),
        (Optional[FrozenSet[str]],       None, "--test a b c",            frozenset(("a", "b", "c"))),
        (Optional[Deque[str]],           None, "--test a b c",            coll.deque(("a", "b", "c"))),
        (Optional[Dict[str, int]],       None, "--test {'a':2}",          dict(a=2)),
        (Optional[dt.date],              None, "--test 2021-12-25",       dt.date(2021, 12, 25)),
        (Optional[dt.datetime],          None, "--test 2021-12-25T12:34", dt.datetime(2021, 12, 25, 12, 34)),
        (Optional[dt.time],              None, "--test 12:34",            dt.time(12, 34)),
        (Optional[dt.timedelta],         None, "--test PT12H",            dt.timedelta(hours=12)),
        (Optional[bool],                 None, "--test",                  True),
        (Optional[Literal["A"]],         None, "--test",                  "A"),
        (Optional[Literal["A", 1]],      None, "--test 1",                1),
        (Optional[conf.TestEnumSingle],  None, "--test",                  conf.TestEnumSingle.D),
        (Optional[conf.TestEnum],        None, "--test C",                conf.TestEnum.C),

        # Optional Arguments (No Default) (No Value Given)
        (Optional[int],                  None, "", None),
        (Optional[float],                None, "", None),
        (Optional[str],                  None, "", None),
        (Optional[bytes],                None, "", None),
        (Optional[List[str]],            None, "", None),
        (Optional[Tuple[str, str, str]], None, "", None),
        (Optional[Set[str]],             None, "", None),
        (Optional[FrozenSet[str]],       None, "", None),
        (Optional[Deque[str]],           None, "", None),
        (Optional[Dict[str, int]],       None, "", None),
        (Optional[dt.date],              None, "", None),
        (Optional[dt.datetime],          None, "", None),
        (Optional[dt.time],              None, "", None),
        (Optional[dt.timedelta],         None, "", None),
        (Optional[bool],                 None, "", None),
        (Optional[Literal["A"]],         None, "", None),
        (Optional[Literal["A", 1]],      None, "", None),
        (Optional[conf.TestEnumSingle],  None, "", None),
        (Optional[conf.TestEnum],        None, "", None),

        # Special Enums and Literals Optional Flag Behaviour
        (Optional[Literal["A"]],        "A",                   "--no-test", None),
        (Optional[Literal["A"]],        "A",                   "",          "A"),
        (Optional[conf.TestEnumSingle], conf.TestEnumSingle.D, "--no-test", None),
        (Optional[conf.TestEnumSingle], conf.TestEnumSingle.D, "",          conf.TestEnumSingle.D),

        # Commands
        (conf.TestCommand,            ..., "test",               conf.TestCommand()),
        (conf.TestCommands,           ..., "test cmd_01",        conf.TestCommands(cmd_01=conf.TestCommand())),
        (conf.TestCommands,           ..., "test cmd_02",        conf.TestCommands(cmd_02=conf.TestCommand())),
        (conf.TestCommands,           ..., "test cmd_03",        conf.TestCommands(cmd_03=conf.TestCommand())),
        (conf.TestCommands,           ..., "test cmd_01 --flag", conf.TestCommands(cmd_01=conf.TestCommand(flag=True))),
        (conf.TestCommands,           ..., "test cmd_02 --flag", conf.TestCommands(cmd_02=conf.TestCommand(flag=True))),
        (conf.TestCommands,           ..., "test cmd_03 --flag", conf.TestCommands(cmd_03=conf.TestCommand(flag=True))),
        (Optional[conf.TestCommand],  ..., "test",               conf.TestCommand()),
        (Optional[conf.TestCommands], ..., "test cmd_01",        conf.TestCommands(cmd_01=conf.TestCommand())),
        (Optional[conf.TestCommands], ..., "test cmd_02",        conf.TestCommands(cmd_02=conf.TestCommand())),
        (Optional[conf.TestCommands], ..., "test cmd_03",        conf.TestCommands(cmd_03=conf.TestCommand())),
        (Optional[conf.TestCommands], ..., "test cmd_01 --flag", conf.TestCommands(cmd_01=conf.TestCommand(flag=True))),
        (Optional[conf.TestCommands], ..., "test cmd_02 --flag", conf.TestCommands(cmd_02=conf.TestCommand(flag=True))),
        (Optional[conf.TestCommands], ..., "test cmd_03 --flag", conf.TestCommands(cmd_03=conf.TestCommand(flag=True))),
    ],
)
def test_valid_arguments(
    argument_type: Type[ArgumentT],
    argument_default: ArgumentT,
    arguments: str,
    result: ArgumentT,
) -> None:
    """Tests ArgumentParser Valid Arguments.

    Args:
        argument_type (Type[ArgumentT]): Type of the argument.
        argument_default (ArgumentT): Default for the argument.
        arguments (str): An example string of arguments for testing.
        result (ArgumentT): Result from parsing the argument.
    """
    # Construct Pydantic Model
    model = conf.create_test_model(test=(argument_type, argument_default))

    # Create ArgumentParser
    parser = pydantic_argparse.ArgumentParser(model)

    # Parse
    args = parser.parse_typed_args(arguments.split())

    # Asserts
    assert isinstance(args.test, type(result))
    assert args.test == result


@pytest.mark.parametrize(
    (
        "argument_type",
        "argument_default",
        "arguments",
    ),
    [
        # Invalid Arguments
        (int,                  ..., "--test invalid"),
        (float,                ..., "--test invalid"),
        (List[int],            ..., "--test invalid"),
        (Tuple[int, int, int], ..., "--test invalid"),
        (Set[int],             ..., "--test invalid"),
        (FrozenSet[int],       ..., "--test invalid"),
        (Deque[int],           ..., "--test invalid"),
        (Dict[str, int],       ..., "--test invalid"),
        (dt.date,              ..., "--test invalid"),
        (dt.datetime,          ..., "--test invalid"),
        (dt.time,              ..., "--test invalid"),
        (dt.timedelta,         ..., "--test invalid"),
        (bool,                 ..., "--test invalid"),
        (Literal["A"],         ..., "--test invalid"),
        (Literal["A", 1],      ..., "--test invalid"),
        (conf.TestEnumSingle,  ..., "--test invalid"),
        (conf.TestEnum,        ..., "--test invalid"),

        # Missing Argument Values
        (int,                  ..., "--test"),
        (float,                ..., "--test"),
        (str,                  ..., "--test"),
        (bytes,                ..., "--test"),
        (List[int],            ..., "--test"),
        (Tuple[int, int, int], ..., "--test"),
        (Set[int],             ..., "--test"),
        (FrozenSet[int],       ..., "--test"),
        (Deque[int],           ..., "--test"),
        (Dict[str, int],       ..., "--test"),
        (dt.date,              ..., "--test"),
        (dt.datetime,          ..., "--test"),
        (dt.time,              ..., "--test"),
        (dt.timedelta,         ..., "--test"),
        (Literal["A"],         ..., "--test"),
        (Literal["A", 1],      ..., "--test"),
        (conf.TestEnumSingle,  ..., "--test"),
        (conf.TestEnum,        ..., "--test"),

        # Missing Arguments
        (int,                  ..., ""),
        (float,                ..., ""),
        (str,                  ..., ""),
        (bytes,                ..., ""),
        (List[int],            ..., ""),
        (Tuple[int, int, int], ..., ""),
        (Set[int],             ..., ""),
        (FrozenSet[int],       ..., ""),
        (Deque[int],           ..., ""),
        (Dict[str, int],       ..., ""),
        (dt.date,              ..., ""),
        (dt.datetime,          ..., ""),
        (dt.time,              ..., ""),
        (dt.timedelta,         ..., ""),
        (bool,                 ..., ""),
        (Literal["A"],         ..., ""),
        (Literal["A", 1],      ..., ""),
        (conf.TestEnumSingle,  ..., ""),
        (conf.TestEnum,        ..., ""),

        # Invalid Optional Arguments
        (Optional[int],                  None, "--test invalid"),
        (Optional[float],                None, "--test invalid"),
        (Optional[List[int]],            None, "--test invalid"),
        (Optional[Tuple[int, int, int]], None, "--test invalid"),
        (Optional[Set[int]],             None, "--test invalid"),
        (Optional[FrozenSet[int]],       None, "--test invalid"),
        (Optional[Deque[int]],           None, "--test invalid"),
        (Optional[Dict[str, int]],       None, "--test invalid"),
        (Optional[dt.date],              None, "--test invalid"),
        (Optional[dt.datetime],          None, "--test invalid"),
        (Optional[dt.time],              None, "--test invalid"),
        (Optional[dt.timedelta],         None, "--test invalid"),
        (Optional[bool],                 None, "--test invalid"),
        (Optional[Literal["A"]],         None, "--test invalid"),
        (Optional[Literal["A", 1]],      None, "--test invalid"),
        (Optional[conf.TestEnumSingle],  None, "--test invalid"),
        (Optional[conf.TestEnum],        None, "--test invalid"),

        # Missing Optional Argument Values
        (Optional[int],                  None, "--test"),
        (Optional[float],                None, "--test"),
        (Optional[str],                  None, "--test"),
        (Optional[bytes],                None, "--test"),
        (Optional[List[int]],            None, "--test"),
        (Optional[Tuple[int, int, int]], None, "--test"),
        (Optional[Set[int]],             None, "--test"),
        (Optional[FrozenSet[int]],       None, "--test"),
        (Optional[Deque[int]],           None, "--test"),
        (Optional[Dict[str, int]],       None, "--test"),
        (Optional[dt.date],              None, "--test"),
        (Optional[dt.datetime],          None, "--test"),
        (Optional[dt.time],              None, "--test"),
        (Optional[dt.timedelta],         None, "--test"),
        (Optional[Literal["A", 1]],      None, "--test"),
        (Optional[conf.TestEnum],        None, "--test"),

        # Commands
        (conf.TestCommand,            ..., ""),
        (conf.TestCommand,            ..., "invalid"),
        (conf.TestCommands,           ..., "test"),
        (conf.TestCommands,           ..., "test invalid"),
        (Optional[conf.TestCommand],  ..., ""),
        (Optional[conf.TestCommand],  ..., "invalid"),
        (Optional[conf.TestCommands], ..., "test"),
        (Optional[conf.TestCommands], ..., "test invalid"),
    ],
)
@pytest.mark.parametrize(
    (
        "exit_on_error",
        "error"
    ),
    [
        (True,  SystemExit),
        (False, argparse.ArgumentError),
    ],
)
def test_invalid_arguments(
    argument_type: Type[ArgumentT],
    argument_default: ArgumentT,
    arguments: str,
    exit_on_error: bool,
    error: Type[Exception],
) -> None:
    """Tests ArgumentParser Invalid Arguments.

    Args:
        argument_type (Type[ArgumentT]): Type of the argument.
        argument_default (ArgumentT): Default for the argument.
        arguments (str): An example string of arguments for testing.
        exit_on_error (bool): Whether to raise or exit on error.
        error (Type[Exception]): Exception that should be raised for testing.
    """
    # Construct Pydantic Model
    model = conf.create_test_model(test=(argument_type, argument_default))

    # Create ArgumentParser
    parser = pydantic_argparse.ArgumentParser(model, exit_on_error=exit_on_error)

    # Assert Parser Raises Error
    with pytest.raises(error):
        # Parse
        parser.parse_typed_args(arguments.split())


def test_help_message(capsys: pytest.CaptureFixture[str]) -> None:
    """Tests ArgumentParser Help Message.

    Args:
        capsys (pytest.CaptureFixture[str]): Fixture to capture STDOUT/STDERR.
    """
    # Construct Pydantic Model
    model = conf.create_test_model()

    # Create ArgumentParser
    parser = pydantic_argparse.ArgumentParser(
        model=model,
        prog="AA",
        description="BB",
        version="CC",
        epilog="DD",
    )

    # Assert Parser Exits
    with pytest.raises(SystemExit):
        # Ask for Help
        parser.parse_typed_args(["--help"])

    # Check STDOUT
    captured = capsys.readouterr()
    assert captured.out == textwrap.dedent(
        """
        usage: AA [-h] [-v]

        BB

        help:
          -h, --help     show this help message and exit
          -v, --version  show program's version number and exit

        DD
        """
    ).lstrip()


def test_version_message(capsys: pytest.CaptureFixture[str]) -> None:
    """Tests ArgumentParser Version Message.

    Args:
        capsys (pytest.CaptureFixture[str]): Fixture to capture STDOUT/STDERR.
    """
    # Construct Pydantic Model
    model = conf.create_test_model()

    # Create ArgumentParser
    parser = pydantic_argparse.ArgumentParser(
        model=model,
        prog="AA",
        description="BB",
        version="CC",
        epilog="DD",
    )

    # Assert Parser Exits
    with pytest.raises(SystemExit):
        # Ask for Version
        parser.parse_typed_args(["--version"])

    # Check STDOUT
    captured = capsys.readouterr()
    assert captured.out == textwrap.dedent(
        """
        CC
        """
    ).lstrip()


@pytest.mark.parametrize(
    (
        "argument_name",
        "argument_field",
    ),
    conf.TestModel.__fields__.items()
)
def test_argument_descriptions(
    argument_name: str,
    argument_field: pydantic.fields.ModelField,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Tests Argument Descriptions.

    Args:
        argument_name (str): Argument name.
        argument_field (pydantic.fields.ModelField): Argument pydantic field.
        capsys (pytest.CaptureFixture[str]): Fixture to capture STDOUT/STDERR.
    """
    # Create ArgumentParser
    parser = pydantic_argparse.ArgumentParser(conf.TestModel)

    # Assert Parser Exits
    with pytest.raises(SystemExit):
        # Ask for Help
        parser.parse_typed_args(["--help"])

    # Capture STDOUT
    captured = capsys.readouterr()

    # Process STDOUT
    # Capture all arguments below 'commands:'
    # Capture all arguments below 'required arguments:'
    # Capture all arguments below 'optional arguments:'
    _, commands, required, optional, _ = re.split(r".+:\n", captured.out)

    # Check if Command, Required or Optional
    if isinstance(argument_field.outer_type_, pydantic.main.ModelMetaclass):
        # Assert Argument Name in Commands Section
        assert argument_name in commands
        assert argument_name not in required
        assert argument_name not in optional

        # Assert Argument Description in Commands Section
        assert argument_field.field_info.description in commands
        assert argument_field.field_info.description not in required
        assert argument_field.field_info.description not in optional

    elif argument_field.required:
        # Format Argument Name
        argument_name = argument_name.replace("_", "-")

        # Assert Argument Name in Required Args Section
        assert argument_name in required
        assert argument_name not in commands
        assert argument_name not in optional

        # Assert Argument Description in Required Args Section
        assert argument_field.field_info.description in required
        assert argument_field.field_info.description not in commands
        assert argument_field.field_info.description not in optional

    else:
        # Format Argument Name and Default
        argument_name = argument_name.replace("_", "-")
        default = f"(default: {argument_field.get_default()})"

        # Assert Argument Name in Optional Args Section
        assert argument_name in optional
        assert argument_name not in commands
        assert argument_name not in required

        # Assert Argument Description in Optional Args Section
        assert argument_field.field_info.description in optional
        assert argument_field.field_info.description not in commands
        assert argument_field.field_info.description not in required

        # Assert Argument Default in Optional Args Section
        assert default in optional
        assert default not in commands
        assert default not in required
