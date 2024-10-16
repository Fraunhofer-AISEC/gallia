# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Pydantic Utility Functions for Declarative Typed Argument Parsing.

The `pydantic` module contains utility functions used for interacting with the
internals of `pydantic`, such as constructing field validators, updating
field validator dictionaries and constructing new model classes with
dynamically generated validators and environment variable parsers.
"""

from collections.abc import Container
from dataclasses import dataclass
from enum import Enum
from types import UnionType
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    Literal,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
    get_args,
    get_origin,
)

import pydantic
from pydantic import BaseModel
from pydantic.fields import FieldInfo
from pydantic_core import PydanticUndefined

from pydantic_argparse.utils.field import ArgFieldInfo

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
    def parse_model(cls, model: BaseModel | Type[BaseModel]) -> Iterator["PydanticField"]:
        """Iterator over the pydantic model fields, yielding this wrapper class.

        Yields:
            Instances of self (`PydanticField`)
        """
        for name, info in model.model_fields.items():
            yield cls(name, info)

    def get_type(self) -> Union[Type, Tuple[Type, ...], None]:
        """Return the type annotation for the `pydantic` field.

        Returns:
            Union[Type, Tuple[Type, ...], None]
        """
        annotation = self.info.annotation
        origin = get_origin(annotation)

        if origin is Literal or isinstance(origin, type) and issubclass(origin, Container):
            return origin
        elif origin is Union or origin is UnionType:
            args = get_args(self.info.annotation)
            types = list(arg for arg in args if arg is not NoneType)
        elif origin is None:
            types = [annotation]
        else:
            assert False, f"Unsupported origin {origin} for field {self.name} with annotation {annotation}"

        base_types = []

        for t in types:
            origin = get_origin(t)

            if origin is not None:
                base_types.append(origin)
            else:
                base_types.append(t)

        return tuple(base_types)

    def is_a(self, types: Union[Any, Tuple[Any, ...]]) -> bool:
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
                is_type or t in types or (is_valid and isinstance(t, types)) or (is_valid and issubclass(t, types))  # type: ignore
            )

        return is_type

    @property
    def model_type(self) -> Type[BaseModel]:
        """Try to return the `pydantic.BaseModel` type.

        Raises:
            TypeError: if this field is not a `pydantic.BaseModel` or if the model type cannot be found.
        """
        if not self.is_a(BaseModel):
            raise TypeError("This `pydantic` field is not a `pydantic.BaseModel`")

        types = self.get_type()
        if not isinstance(types, tuple):
            return cast(Type[BaseModel], types)

        for t in types:
            if isinstance(t, type) and issubclass(t, BaseModel):
                return t
        else:
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

        Args:
            invert (bool): Whether to invert the name by prepending `--no-`.

        Returns:
            str: Standardised name of the argument. Checks `pydantic.Field` title first,
                but defaults to the field name.
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

    def metavar(self) -> Optional[str]:
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
        if field_type:
            if isinstance(field_type, tuple):
                return "|".join(t.__name__.upper() for t in field_type)
            return field_type.__name__.upper()

    def arg_required(self) -> dict[str, bool]:
        return (
            {}
            if isinstance(self.info, ArgFieldInfo) and self.info.positional
            else {"required": self.info.is_required() and self.extra_default is None}
        )

    def arg_default(self) -> dict[str, Any]:
        return (
            {}
            if self.extra_default is None or isinstance(self.info, ArgFieldInfo) and self.info.positional
            else {"default": self.extra_default[1]}
        )

    def arg_const(self) -> dict[str, Any]:
        return (
            {"const": self.info.const, "nargs": "?"}
            if isinstance(self.info, ArgFieldInfo) and self.info.const is not PydanticUndefined
            else {}
        )

    def arg_dest(self) -> dict[str, str]:
        return {} if isinstance(self.info, ArgFieldInfo) and self.info.positional else {"dest": self.name}


def as_validator(
    field: PydanticField,
    caster: Callable[[str], Any],
) -> PydanticValidator:
    """Shortcut to wrap a caster and construct a validator for a given field.

    The provided caster function must cast from a string to the type required
    by the field. Once wrapped, the constructed validator will pass through any
    non-string values, or any values that cause the caster function to raise an
    exception to let the built-in `pydantic` field validation handle them. The
    validator will also cast empty strings to `None`.

    Args:
        name (str): field name
        field (pydantic.fields.FieldInfo): Field to construct validator for.
        caster (Callable[[str], Any]): String to field type caster function.

    Returns:
        PydanticValidator: Constructed field validator function.
    """

    # Dynamically construct a `pydantic` validator function for the supplied
    # field. The constructed validator must be `pre=True` so that the validator
    # is called before the built-in `pydantic` field validation occurs and is
    # provided with the raw input data. The constructed validator must also be
    # `allow_reuse=True` so the `__validator` function name can be reused
    # multiple times when being decorated as a `pydantic` validator. Note that
    # despite the `__validator` function *name* being reused, each instance of
    # the validator function is uniquely constructed for the supplied field.
    @pydantic.validator(field.name, pre=True, allow_reuse=True)
    def __validator(cls: Type[Any], value: T) -> Optional[Union[T, Any]]:
        if not isinstance(value, str):
            return value
        if not value:
            return None
        try:
            return caster(value)
        except Exception:
            return value

    # Rename the validator uniquely for this field to avoid any collisions. The
    # leading `__` and prefix of `pydantic_argparse` should guard against any
    # potential collisions with user defined validators.
    __validator.__name__ = f"__pydantic_argparse_{field.name}"  # type: ignore

    # Return the constructed validator
    return __validator  # type: ignore


def update_validators(
    validators: Dict[str, PydanticValidator],
    validator: Optional[PydanticValidator],
) -> None:
    """Updates a validators dictionary with a possible new field validator.

    Note that this function mutates the validators dictionary *in-place*, and
    does not return the dictionary.

    Args:
        validators (Dict[str, PydanticValidator]): Validators to update.
        validator (Optional[PydanticValidator]): Possible field validator.
    """
    # Check for Validator
    if validator:
        # Add Validator
        validators[validator.__name__] = validator


def model_with_validators(
    model: Type[BaseModel],
    validators: Dict[str, PydanticValidator],
) -> Type[BaseModel]:
    """Generates a new `pydantic` model class with the supplied validators.

    If the supplied base model is a subclass of `pydantic.BaseSettings`, then
    the newly generated model will also have a new `parse_env_var` classmethod
    monkeypatched onto it that suppresses any exceptions raised when initially
    parsing the environment variables. This allows the raw values to still be
    passed through to the `pydantic` field validators if initial parsing fails.

    Args:
        model (Type[BaseModel]): Model type to use as base class.
        validators (Dict[str, PydanticValidator]): Field validators to add.

    Returns:
        Type[BaseModel]: New `pydantic` model type with field validators.
    """
    # Construct New Model with Validators
    model = pydantic.create_model(
        model.__name__,
        __base__=model,
        __validators__=validators,
    )

    # Check if the model is a `BaseSettings`
    # if issubclass(model, pydantic.BaseSettings):
    #     # Hold a reference to the current `parse_env_var` classmethod
    #     parse_env_var = model.__config__.parse_env_var

    #     # Construct a new `parse_env_var` function which suppresses exceptions
    #     # raised by the current `parse_env_var` classmethod. This allows the
    #     # raw values to be passed through to the `pydantic` field validator
    #     # methods if they cannot be parsed initially.
    #     def __parse_env_var(field_name: str, raw_val: str) -> Any:
    #         with contextlib.suppress(Exception):
    #             return parse_env_var(field_name, raw_val)
    #         return raw_val

    #     # Monkeypatch `parse_env_var`
    #     model.__config__.parse_env_var = __parse_env_var  # type: ignore[assignment]

    # Return Constructed Model
    return model


def is_subcommand(model: BaseModel | Type[BaseModel]) -> bool:
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
