"""Tests the `pydantic-argparse` Environment Variables Functionality.

This module provides functional regression tests for the `pydantic-argparse`
environment variable parsing capabilities.
"""


# Standard
import argparse
import collections as coll
import datetime as dt
import os
import sys

# Third-Party
import pytest
import pytest_mock

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


@pytest.mark.parametrize(
    (
        "argument_type",
        "argument_default",
        "env",
        "result",
    ),
    [
        # Required Arguments
        (int,                  ..., "TEST=123",              123),
        (float,                ..., "TEST=4.56",             4.56),
        (str,                  ..., "TEST=hello",            "hello"),
        (bytes,                ..., "TEST=bytes",            b"bytes"),
        (List[str],            ..., 'TEST=["a","b","c"]',    list(("a", "b", "c"))),
        (Tuple[str, str, str], ..., 'TEST=["a","b","c"]',    tuple(("a", "b", "c"))),
        (Set[str],             ..., 'TEST=["a","b","c"]',    set(("a", "b", "c"))),
        (FrozenSet[str],       ..., 'TEST=["a","b","c"]',    frozenset(("a", "b", "c"))),
        (Deque[str],           ..., 'TEST=["a","b","c"]',    coll.deque(("a", "b", "c"))),
        (Dict[str, int],       ..., 'TEST={"a":2}',          dict(a=2)),
        (dt.date,              ..., "TEST=2021-12-25",       dt.date(2021, 12, 25)),
        (dt.datetime,          ..., "TEST=2021-12-25T12:34", dt.datetime(2021, 12, 25, 12, 34)),
        (dt.time,              ..., "TEST=12:34",            dt.time(12, 34)),
        (dt.timedelta,         ..., "TEST=PT12H",            dt.timedelta(hours=12)),
        (bool,                 ..., "TEST=true",             True),
        (bool,                 ..., "TEST=false",            False),
        (Literal["A"],         ..., "TEST=A",                "A"),
        (Literal["A", 1],      ..., "TEST=1",                1),
        (conf.TestEnumSingle,  ..., "TEST=D",                conf.TestEnumSingle.D),
        (conf.TestEnum,        ..., "TEST=C",                conf.TestEnum.C),

        # Optional Arguments (With Default)
        (int,                  456,                         "TEST=123",              123),
        (float,                1.23,                        "TEST=4.56",             4.56),
        (str,                  "world",                     "TEST=hello",            "hello"),
        (bytes,                b"bits",                     "TEST=bytes",            b"bytes"),
        (List[str],            list(("d", "e", "f")),       'TEST=["a","b","c"]',    list(("a", "b", "c"))),
        (Tuple[str, str, str], tuple(("d", "e", "f")),      'TEST=["a","b","c"]',    tuple(("a", "b", "c"))),
        (Set[str],             set(("d", "e", "f")),        'TEST=["a","b","c"]',    set(("a", "b", "c"))),
        (FrozenSet[str],       frozenset(("d", "e", "f")),  'TEST=["a","b","c"]',    frozenset(("a", "b", "c"))),
        (Deque[str],           coll.deque(("d", "e", "f")), 'TEST=["a","b","c"]',    coll.deque(("a", "b", "c"))),
        (Dict[str, int],       dict(b=3),                   'TEST={"a":2}',          dict(a=2)),
        (dt.date,              dt.date(2021, 7, 21),        "TEST=2021-12-25",       dt.date(2021, 12, 25)),
        (dt.datetime,          dt.datetime(2021, 7, 21, 3), "TEST=2021-04-03T02:00", dt.datetime(2021, 4, 3, 2)),
        (dt.time,              dt.time(3, 21),              "TEST=12:34",            dt.time(12, 34)),
        (dt.timedelta,         dt.timedelta(hours=6),       "TEST=PT12H",            dt.timedelta(hours=12)),
        (bool,                 False,                       "TEST=true",             True),
        (bool,                 True,                        "TEST=false",            False),
        (Literal["A"],         "A",                         "TEST=A",                "A"),
        (Literal["A", 1],      "A",                         "TEST=1",                1),
        (conf.TestEnumSingle,  conf.TestEnumSingle.D,       "TEST=D",                conf.TestEnumSingle.D),
        (conf.TestEnum,        conf.TestEnum.B,             "TEST=C",                conf.TestEnum.C),

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
        (Optional[int],                  None, "TEST=123",              123),
        (Optional[float],                None, "TEST=4.56",             4.56),
        (Optional[str],                  None, "TEST=hello",            "hello"),
        (Optional[bytes],                None, "TEST=bytes",            b"bytes"),
        (Optional[List[str]],            None, 'TEST=["a","b","c"]',    list(("a", "b", "c"))),
        (Optional[Tuple[str, str, str]], None, 'TEST=["a","b","c"]',    tuple(("a", "b", "c"))),
        (Optional[Set[str]],             None, 'TEST=["a","b","c"]',    set(("a", "b", "c"))),
        (Optional[FrozenSet[str]],       None, 'TEST=["a","b","c"]',    frozenset(("a", "b", "c"))),
        (Optional[Deque[str]],           None, 'TEST=["a","b","c"]',    coll.deque(("a", "b", "c"))),
        (Optional[Dict[str, int]],       None, 'TEST={"a":2}',          dict(a=2)),
        (Optional[dt.date],              None, "TEST=2021-12-25",       dt.date(2021, 12, 25)),
        (Optional[dt.datetime],          None, "TEST=2021-12-25T12:34", dt.datetime(2021, 12, 25, 12, 34)),
        (Optional[dt.time],              None, "TEST=12:34",            dt.time(12, 34)),
        (Optional[dt.timedelta],         None, "TEST=PT12H",            dt.timedelta(hours=12)),
        (Optional[bool],                 None, "TEST=true",             True),
        (Optional[Literal["A"]],         None, "TEST=A",                "A"),
        (Optional[Literal["A", 1]],      None, "TEST=1",                1),
        (Optional[conf.TestEnumSingle],  None, "TEST=D",                conf.TestEnumSingle.D),
        (Optional[conf.TestEnum],        None, "TEST=C",                conf.TestEnum.C),

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
        (Optional[Literal["A"]],        "A",                   "TEST=", None),
        (Optional[Literal["A"]],        "A",                   "",      "A"),
        (Optional[conf.TestEnumSingle], conf.TestEnumSingle.D, "TEST=", None),
        (Optional[conf.TestEnumSingle], conf.TestEnumSingle.D, "",      conf.TestEnumSingle.D),

        # Missing Optional Argument Values
        (Optional[int],                  None, "TEST=", None),
        (Optional[float],                None, "TEST=", None),
        (Optional[str],                  None, "TEST=", None),
        (Optional[bytes],                None, "TEST=", None),
        (Optional[List[int]],            None, "TEST=", None),
        (Optional[Tuple[int, int, int]], None, "TEST=", None),
        (Optional[Set[int]],             None, "TEST=", None),
        (Optional[FrozenSet[int]],       None, "TEST=", None),
        (Optional[Deque[int]],           None, "TEST=", None),
        (Optional[Dict[str, int]],       None, "TEST=", None),
        (Optional[dt.date],              None, "TEST=", None),
        (Optional[dt.datetime],          None, "TEST=", None),
        (Optional[dt.time],              None, "TEST=", None),
        (Optional[dt.timedelta],         None, "TEST=", None),
    ],
)
def test_valid_environment_variables(
    argument_type: Type[ArgumentT],
    argument_default: ArgumentT,
    env: str,
    result: ArgumentT,
    mocker: pytest_mock.MockerFixture,
) -> None:
    """Tests ArgumentParser Valid Arguments as Environment Variables.

    Args:
        argument_type (Type[ArgumentT]): Type of the argument.
        argument_default (ArgumentT): Default for the argument.
        env (str): An example string of environment variables for testing.
        result (ArgumentT): Result from parsing the argument.
        mocker (pytest_mock.MockerFixture): PyTest Mocker Fixture.
    """
    # Construct Pydantic Model
    model = conf.create_test_model(test=(argument_type, argument_default))

    # Create ArgumentParser
    parser = pydantic_argparse.ArgumentParser(model)

    # Construct Environment Variables
    environment_variables: Dict[str, str] = dict([env.split("=")]) if env else {}

    # Mock Environment Variables
    mocker.patch.dict(os.environ, environment_variables, clear=True)

    # Parse
    args = parser.parse_typed_args([])  # Empty Arguments

    # Asserts
    assert isinstance(args.test, type(result))
    assert args.test == result


@pytest.mark.parametrize(
    (
        "argument_type",
        "argument_default",
        "env",
    ),
    [
        # Invalid Arguments
        (int,                  ..., "TEST=invalid"),
        (float,                ..., "TEST=invalid"),
        (List[int],            ..., "TEST=invalid"),
        (Tuple[int, int, int], ..., "TEST=invalid"),
        (Set[int],             ..., "TEST=invalid"),
        (FrozenSet[int],       ..., "TEST=invalid"),
        (Deque[int],           ..., "TEST=invalid"),
        (Dict[str, int],       ..., "TEST=invalid"),
        (dt.date,              ..., "TEST=invalid"),
        (dt.datetime,          ..., "TEST=invalid"),
        (dt.time,              ..., "TEST=invalid"),
        (dt.timedelta,         ..., "TEST=invalid"),
        (bool,                 ..., "TEST=invalid"),
        (Literal["A"],         ..., "TEST=invalid"),
        (Literal["A", 1],      ..., "TEST=invalid"),
        (conf.TestEnumSingle,  ..., "TEST=invalid"),
        (conf.TestEnum,        ..., "TEST=invalid"),

        # Missing Argument Values
        (int,                  ..., "TEST="),
        (float,                ..., "TEST="),
        (List[int],            ..., "TEST="),
        (Tuple[int, int, int], ..., "TEST="),
        (Set[int],             ..., "TEST="),
        (FrozenSet[int],       ..., "TEST="),
        (Deque[int],           ..., "TEST="),
        (Dict[str, int],       ..., "TEST="),
        (dt.date,              ..., "TEST="),
        (dt.datetime,          ..., "TEST="),
        (dt.time,              ..., "TEST="),
        (dt.timedelta,         ..., "TEST="),
        (Literal["A"],         ..., "TEST="),
        (Literal["A", 1],      ..., "TEST="),
        (conf.TestEnumSingle,  ..., "TEST="),
        (conf.TestEnum,        ..., "TEST="),

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
        (Optional[int],                  None, "TEST=invalid"),
        (Optional[float],                None, "TEST=invalid"),
        (Optional[List[int]],            None, "TEST=invalid"),
        (Optional[Tuple[int, int, int]], None, "TEST=invalid"),
        (Optional[Set[int]],             None, "TEST=invalid"),
        (Optional[FrozenSet[int]],       None, "TEST=invalid"),
        (Optional[Deque[int]],           None, "TEST=invalid"),
        (Optional[Dict[str, int]],       None, "TEST=invalid"),
        (Optional[dt.date],              None, "TEST=invalid"),
        (Optional[dt.datetime],          None, "TEST=invalid"),
        (Optional[dt.time],              None, "TEST=invalid"),
        (Optional[dt.timedelta],         None, "TEST=invalid"),
        (Optional[bool],                 None, "TEST=invalid"),
        (Optional[Literal["A"]],         None, "TEST=invalid"),
        (Optional[Literal["A", 1]],      None, "TEST=invalid"),
        (Optional[conf.TestEnumSingle],  None, "TEST=invalid"),
        (Optional[conf.TestEnum],        None, "TEST=invalid"),
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
def test_invalid_environment_variables(
    argument_type: Type[ArgumentT],
    argument_default: ArgumentT,
    env: str,
    exit_on_error: bool,
    error: Type[Exception],
    mocker: pytest_mock.MockerFixture,
) -> None:
    """Tests ArgumentParser Invalid Arguments as Environment Variables.

    Args:
        argument_type (Type[ArgumentT]): Type of the argument.
        argument_default (ArgumentT): Default for the argument.
        env (str): An example string of environment variables for testing.
        exit_on_error (bool): Whether to raise or exit on error.
        error (Type[Exception]): Exception that should be raised for testing.
        mocker (pytest_mock.MockerFixture): PyTest Mocker Fixture.
    """
    # Construct Pydantic Model
    model = conf.create_test_model(test=(argument_type, argument_default))

    # Create ArgumentParser
    parser = pydantic_argparse.ArgumentParser(model, exit_on_error=exit_on_error)

    # Construct Environment Variables
    environment_variables: Dict[str, str] = dict([env.split("=")]) if env else {}

    # Mock Environment Variables
    mocker.patch.dict(os.environ, environment_variables, clear=True)

    # Assert Parser Raises Error
    with pytest.raises(error):
        # Parse
        parser.parse_typed_args([])  # Empty Arguments
