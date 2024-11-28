# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Pydantic Utility Functions for Declarative Typed Argument Parsing.

The `pydantic` module contains utility functions used for interacting with the
internals of `pydantic`, such as constructing field validators, updating
field validator dictionaries and constructing new model classes with
dynamically generated validators and environment variable parsers.
"""

from collections.abc import Container, Iterator
from dataclasses import dataclass
from enum import Enum
from types import UnionType
from typing import (
    Annotated,
    Any,
    Literal,
    TypeVar,
    Union,
    cast,
    get_args,
    get_origin,
)

from pydantic import BaseModel
from pydantic.fields import FieldInfo
from pydantic_core import PydanticUndefined

from gallia.pydantic_argparse.utils.field import ArgFieldInfo

from .types import all_types

# Constants
T = TypeVar("T")
PydanticModelT = TypeVar("PydanticModelT", bound=BaseModel)
PydanticValidator = classmethod
NoneType = type(None)


@dataclass
class PydanticField:
    """Simple Pydantic v2.0 field wrapper.

    Pydantic fields no longer store their name, so this named tuple
    keeps the field name and field info together.

    The recommended entry point for an arbitrary `pydantic.BaseModel` is the classmethod `PydanticField.parse_model`.
    """

    name: str
    info: FieldInfo
    extra_default: tuple[str, Any] | None = None

    @classmethod
    def parse_model(cls, model: BaseModel | type[BaseModel]) -> Iterator["PydanticField"]:
        """Iterator over the pydantic model fields, yielding this wrapper class.

        Yields:
            Instances of self (`PydanticField`)
        """
        for name, info in model.model_fields.items():
            yield cls(name, info)

    def _get_type(self, annotation: type | None) -> type | tuple[type | None, ...] | None:
        origin = get_origin(annotation)

        if origin is Literal or isinstance(origin, type) and issubclass(origin, Container):
            return origin
        elif origin is Union or origin is UnionType:
            args = get_args(annotation)
            types = [arg for arg in args if arg is not NoneType]
        elif origin is None:
            types = [annotation]
        else:
            raise AssertionError(
                f"Unsupported origin {origin} for field {self.name} with annotation {annotation}"
            )

        base_types: list[type | None] = []

        for t in types:
            origin = get_origin(t)

            if origin is Annotated:
                sub_types = self._get_type(get_args(t)[0])

                if isinstance(sub_types, tuple):
                    base_types += sub_types
                else:
                    base_types.append(sub_types)
            elif origin is not None:
                base_types.append(origin)
            else:
                base_types.append(t)

        return tuple(base_types)

    def get_type(self) -> type | tuple[type | None, ...] | None:
        """Return the mainly interesting types according to the type annotation (in the context of argument parsing).

        Returns: One or more types (potentially None).
        """
        annotation = self.info.annotation
        return self._get_type(annotation)

    def is_a(self, types: Any | tuple[Any, ...]) -> bool:
        """Checks whether the subject *is* any of the supplied types.

        The checks are performed as follows:

        1. `field` *is* one of the `types`
        2. `field` *is an instance* of one of the `types`
        3. `field` *is a subclass* of one of the `types`

        If any of these conditions are `True`, then the function returns `True`,
        else `False`.

        Args:
            types (Union[Any, Tuple[Any, ...]]): Type(s) to compare field against.

        Returns:
            bool: Whether the field *is* considered one of the types.
        """
        # Create tuple if only one type was provided
        if not isinstance(types, tuple):
            types = (types,)

        # Get field type, or origin if applicable
        field_type = self.get_type()
        if not isinstance(field_type, tuple):
            field_type = (field_type,)

        # Check `isinstance` and `issubclass` validity
        # In order for `isinstance` and `issubclass` to be valid, all arguments
        # should be instances of `type`, otherwise `TypeError` *may* be raised.

        is_valid = all_types((*types, *field_type))

        # Perform checks and return
        is_type = False
        for t in field_type:
            is_type = (
                is_type
                or t in types
                or (is_valid and isinstance(t, types))
                or (is_valid and issubclass(t, types))  # type: ignore
            )

        return is_type

    @property
    def model_type(self) -> type[BaseModel]:
        """Try to return the `pydantic.BaseModel` type.

        Raises:
            TypeError: if this field is not a `pydantic.BaseModel` or if the model type cannot be found.
        """
        if not self.is_a(BaseModel):
            raise TypeError("This `pydantic` field is not a `pydantic.BaseModel`")

        types = self.get_type()
        if not isinstance(types, tuple):
            return cast(type[BaseModel], types)

        for t in types:
            if isinstance(t, type) and issubclass(t, BaseModel):
                return t
        raise TypeError("No `pydantic.BaseModel`s were found associated with this field.")

    def is_subcommand(self) -> bool:
        """Check whether the input pydantic Model is a subcommand.

        The default is that all pydantic Models are not subcommands, so this
        has this featured has to be opted in by adding `subcommand=True`
        to the `json_schema_extra` model config. A convenience class has been created
        to provide this default for models that are meant to be command switches at
        the command line: `pydantic_argparse.BaseCommand`.

        Returns:
            bool: if the pydantic model is a subcommand. In all other cases, including when this field is not a
                pydantic model, returns False.
        """
        default = False
        try:
            model = self.model_type
            value = model.model_config["json_schema_extra"].get("subcommand", default)  # type: ignore
            return cast(bool, value)
        except (KeyError, AttributeError, TypeError):
            # KeyError if:
            #   - subcommand key not in json_schema_extra

            # AttributeError if:
            #   - json_schema_extra not in the model_config, ie if using BaseModel
            # just default to not being a subcommand

            # TypeError if
            #   - field is not a pydantic BaseModel or it can't be found
            return default

    def arg_names(self, invert: bool = False) -> tuple[str, str] | tuple[str]:
        """Standardises argument name when printing to command line.

        This also includes potential short names if specified.

        Args:
            invert (bool): Whether to invert the name by prepending `--no-`.

        Returns:
            str: Standardised name of the argument.
        """
        name = self.info.title or self.name

        if isinstance(self.info, ArgFieldInfo) and self.info.positional:
            return (name,)

        prefix = "--no-" if invert else "--"
        long_name = f"{prefix}{name.replace('_', '-')}"

        if isinstance(self.info, ArgFieldInfo) and self.info.short is not None:
            return f"-{self.info.short}", long_name

        return (long_name,)

    def description(self) -> str:
        """Standardises argument description.

        Returns:
            str: Standardised description of the argument.
        """
        # Construct Default String
        default = ""

        if not self.info.is_required():
            _default = self.info.get_default()
            if isinstance(_default, Enum):
                _default = _default.name
            default = f"default: {_default}"

        if self.extra_default is not None:
            if len(default) > 0:
                default += "; "
            default += f"{self.extra_default[0]}: {self.extra_default[1]}"

        if len(default) > 0:
            default = f" ({default})"

        # Return Standardised Description String
        description = self.info.description if self.info.description is not None else ""
        return f"{description}{default}"

    def metavar(self) -> str | None:
        """Generate the metavar name for the field.

        Returns:
            Optional[str]: Field metavar if of type ArgField and has metavar set.
                Otherwise, return constituent type names.
        """
        # check metavar first
        if isinstance(self.info, ArgFieldInfo):
            if self.info.metavar is not None:
                return self.info.metavar

            if self.info.positional:
                return self.arg_names()[0].upper()

        # otherwise default to the type
        field_type = self.get_type()
        if field_type is not None:
            if isinstance(field_type, tuple):
                return "|".join(t.__name__.upper() for t in field_type if t is not None)
            return field_type.__name__.upper()
        else:
            return None

    def arg_required(self) -> dict[str, bool]:
        return (
            {}
            if isinstance(self.info, ArgFieldInfo) and self.info.positional
            else {"required": self.info.is_required() and self.extra_default is None}
        )

    def arg_default(self) -> dict[str, Any]:
        return (
            {}
            if self.extra_default is None
            or isinstance(self.info, ArgFieldInfo)
            and self.info.positional
            else {"default": self.extra_default[1]}
        )

    def arg_const(self) -> dict[str, Any]:
        return (
            {"const": self.info.const, "nargs": "?"}
            if isinstance(self.info, ArgFieldInfo) and self.info.const is not PydanticUndefined
            else {}
        )

    def arg_dest(self) -> dict[str, str]:
        return (
            {}
            if isinstance(self.info, ArgFieldInfo) and self.info.positional
            else {"dest": self.name}
        )


def is_subcommand(model: BaseModel | type[BaseModel]) -> bool:
    """Check whether the input pydantic Model is a subcommand.

    The default is that all pydantic Models are not subcommands, so this
    has this featured has to be opted in by adding `subcommand=True`
    to the `json_schema_extra` model config. A convenience class has been created
    to provide this default for models that are meant to be command switches at
    the command line: `pydantic_argparse.BaseCommand`.


    Args:
        model (BaseModel | Type[BaseModel]): a pydantic BaseModel subclass

    Returns:
        bool: if the pydantic model is a subcommand
    """
    default = False
    try:
        value = model.model_config["json_schema_extra"].get("subcommand", default)  # type: ignore
        return cast(bool, value)
    except (KeyError, AttributeError):
        # KeyError if:
        #   - subcommand key not in json_schema_extra
        # AttributeError if:
        #   - json_schema_extra not in the model_config, ie if using BaseModel
        # just default to not being a subcommand
        return default
