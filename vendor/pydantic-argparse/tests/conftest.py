"""Configures Testing and Defines Pytest Fixtures.

The `conftest.py` file serves as a means of providing fixtures for an entire
directory. Fixtures defined in a `conftest.py` can be used by any test in the
package without needing to import them.
"""


# Standard
import argparse
import collections
import datetime
import enum
import sys

# Third-Party
import pydantic

# Local
from pydantic_argparse.argparse import actions

# Typing
from typing import Any, Deque, Dict, FrozenSet, List, Optional, Set, Tuple, Type

# Version-Guarded
if sys.version_info < (3, 8):  # pragma: <3.8 cover
    from typing_extensions import Literal
else:  # pragma: >=3.8 cover
    from typing import Literal


def create_test_model(
    name: str = "test",
    base: Type[pydantic.BaseModel] = pydantic.BaseSettings,
    **fields: Tuple[Type[Any], Any],
) -> Any:
    """Constructs a `pydantic` model with sensible defaults for testing.

    This function returns `Any` instead of `Type[pydantic.BaseModel]` because
    we cannot accurately type the dynamically constructed fields on the
    resultant model. As such, it is more convenient to work with the `Any` type
    in the unit tests.

    Args:
        name (str): Name of the model.
        base (Type[pydantic.BaseModel]): Base class for the model.
        fields (Tuple[Type[Any], Any]): Model fields as `name=(type, default)`.

    Returns:
        Any: Dynamically constructed `pydantic` model.
    """
    # Construct Pydantic Model
    return pydantic.create_model(
        name,
        __base__=base,
        **fields,  # type: ignore[call-overload]
    )


def create_test_field(
    name: str = "test",
    type: Type[Any] = str,  # noqa: A002
    default: Any = ...,
    description: Optional[str] = None,
) -> pydantic.fields.ModelField:
    """Constructs a `pydantic` field with sensible defaults for testing.

    Args:
        name (str): Name of the field.
        type (Type[Any]): Type of the field.
        default (Any): Default value for the field.
        description (Optional[str]): Description for the field.

    Returns:
        pydantic.fields.ModelField: Dynamically constructed `pydantic` model.
    """
    # Construct Pydantic Field
    return pydantic.fields.ModelField.infer(
        name=name,
        value=pydantic.Field(default, description=description),  # type: ignore[arg-type]
        annotation=type,
        class_validators=None,
        config=pydantic.BaseConfig,
    )


def create_test_subparser(
    name: str = "test",
    parser_class: Type[argparse.ArgumentParser] = argparse.ArgumentParser,
) -> actions.SubParsersAction:
    """Constructs a `SubParsersAction` with sensible defaults for testing.

    Args:
        name (str): Name of the action.
        parser_class (Type[argparse.ArgumentParser]): Parser for the action.

    Returns:
        actions.SubParsersAction: Dynamically constructed `SubParsersAction`.
    """
    # Construct SubParsersAction
    return actions.SubParsersAction(
        option_strings=[],  # Always empty for the `SubParsersAction`
        prog=name,
        parser_class=parser_class,
    )


class TestEnum(enum.Enum):
    """Test Enum for Testing."""
    A = enum.auto()
    B = enum.auto()
    C = enum.auto()


class TestEnumSingle(enum.Enum):
    """Test Enum with Single Member for Testing."""
    D = enum.auto()


class TestCommand(pydantic.BaseModel):
    """Test Command Model for Testing."""
    flag: bool = pydantic.Field(False, description="flag")


class TestCommands(pydantic.BaseModel):
    """Test Commands Model for Testing."""
    cmd_01: Optional[TestCommand] = pydantic.Field(None, description="cmd_01")
    cmd_02: Optional[TestCommand] = pydantic.Field(None, description="cmd_02")
    cmd_03: Optional[TestCommand] = pydantic.Field(None, description="cmd_03")


class TestModel(pydantic.BaseModel):
    """Test Model for Testing."""
    # Required Arguments
    arg_01: int = pydantic.Field(description="arg_01")
    arg_02: float = pydantic.Field(description="arg_02")
    arg_03: str = pydantic.Field(description="arg_03")
    arg_04: bytes = pydantic.Field(description="arg_04")
    arg_05: List[str] = pydantic.Field(description="arg_05")
    arg_06: Tuple[str, str, str] = pydantic.Field(description="arg_06")
    arg_07: Set[str] = pydantic.Field(description="arg_07")
    arg_08: FrozenSet[str] = pydantic.Field(description="arg_08")
    arg_09: Deque[str] = pydantic.Field(description="arg_09")
    arg_10: Dict[str, int] = pydantic.Field(description="arg_10")
    arg_11: datetime.date = pydantic.Field(description="arg_11")
    arg_12: datetime.datetime = pydantic.Field(description="arg_12")
    arg_13: datetime.time = pydantic.Field(description="arg_13")
    arg_14: datetime.timedelta = pydantic.Field(description="arg_14")
    arg_15: bool = pydantic.Field(description="arg_15")
    arg_16: Literal["A"] = pydantic.Field(description="arg_16")
    arg_17: Literal["A", 1] = pydantic.Field(description="arg_17")
    arg_18: TestEnumSingle = pydantic.Field(description="arg_18")
    arg_19: TestEnum = pydantic.Field(description="arg_19")

    # Optional Arguments (With Default)
    arg_20: int = pydantic.Field(12345, description="arg_20")
    arg_21: float = pydantic.Field(6.789, description="arg_21")
    arg_22: str = pydantic.Field("ABC", description="arg_22")
    arg_23: bytes = pydantic.Field(b"ABC", description="arg_23")
    arg_24: List[str] = pydantic.Field(list(("A", "B", "C")), description="arg_24")
    arg_25: Tuple[str, str, str] = pydantic.Field(("A", "B", "C"), description="arg_25")
    arg_26: Set[str] = pydantic.Field(set(("A", "B", "C")), description="arg_26")
    arg_27: FrozenSet[str] = pydantic.Field(frozenset(("A", "B", "C")), description="arg_27")
    arg_28: Deque[str] = pydantic.Field(collections.deque(("A", "B", "C")), description="arg_28")
    arg_29: Dict[str, int] = pydantic.Field(dict(A=123), description="arg_29")
    arg_30: datetime.date = pydantic.Field(datetime.date(2021, 12, 25), description="arg_30")
    arg_31: datetime.datetime = pydantic.Field(datetime.datetime(2021, 12, 25, 7), description="arg_31")
    arg_32: datetime.time = pydantic.Field(datetime.time(7, 30), description="arg_32")
    arg_33: datetime.timedelta = pydantic.Field(datetime.timedelta(hours=5), description="arg_33")
    arg_34: bool = pydantic.Field(False, description="arg_34")
    arg_35: bool = pydantic.Field(True, description="arg_35")
    arg_36: Literal["A"] = pydantic.Field("A", description="arg_36")
    arg_37: Literal["A", 1] = pydantic.Field("A", description="arg_37")
    arg_38: TestEnumSingle = pydantic.Field(TestEnumSingle.D, description="arg_38")
    arg_39: TestEnum = pydantic.Field(TestEnum.A, description="arg_39")

    # Optional Arguments (No Default)
    arg_40: Optional[int] = pydantic.Field(description="arg_40")
    arg_41: Optional[float] = pydantic.Field(description="arg_41")
    arg_42: Optional[str] = pydantic.Field(description="arg_42")
    arg_43: Optional[bytes] = pydantic.Field(description="arg_43")
    arg_44: Optional[List[str]] = pydantic.Field(description="arg_44")
    arg_45: Optional[Tuple[str, str, str]] = pydantic.Field(description="arg_45")
    arg_46: Optional[Set[str]] = pydantic.Field(description="arg_46")
    arg_47: Optional[FrozenSet[str]] = pydantic.Field(description="arg_47")
    arg_48: Optional[Deque[str]] = pydantic.Field(description="arg_48")
    arg_49: Optional[Dict[str, int]] = pydantic.Field(description="arg_49")
    arg_50: Optional[datetime.date] = pydantic.Field(description="arg_50")
    arg_51: Optional[datetime.datetime] = pydantic.Field(description="arg_51")
    arg_52: Optional[datetime.time] = pydantic.Field(description="arg_52")
    arg_53: Optional[datetime.timedelta] = pydantic.Field(description="arg_53")
    arg_54: Optional[bool] = pydantic.Field(description="arg_54")
    arg_55: Optional[Literal["A"]] = pydantic.Field(description="arg_55")
    arg_56: Optional[Literal["A", 1]] = pydantic.Field(description="arg_56")
    arg_57: Optional[TestEnumSingle] = pydantic.Field(description="arg_57")
    arg_58: Optional[TestEnum] = pydantic.Field(description="arg_58")

    # Special Enums and Literals Optional Flag Behaviour
    arg_59: Optional[Literal["A"]] = pydantic.Field(description="arg_59")
    arg_60: Optional[Literal["A"]] = pydantic.Field("A", description="arg_60")
    arg_61: Optional[TestEnumSingle] = pydantic.Field(description="arg_61")
    arg_62: Optional[TestEnumSingle] = pydantic.Field(TestEnumSingle.D, description="arg_62")

    # Commands
    arg_63: Optional[TestCommand] = pydantic.Field(description="arg_63")
    arg_64: TestCommand = pydantic.Field(description="arg_64")
    arg_65: Optional[TestCommands] = pydantic.Field(description="arg_65")
    arg_66: TestCommands = pydantic.Field(description="arg_66")
