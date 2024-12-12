# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import binascii
import os
import tomllib
from abc import ABC
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    TypeAlias,
    TypeVar,
    Unpack,
    get_args,
)

from pydantic import BeforeValidator
from pydantic.fields import _FromFieldInfoInputs
from pydantic_core import PydanticUndefined

from gallia.config import Config
from gallia.pydantic_argparse import BaseCommand
from gallia.pydantic_argparse.utils.field import ArgFieldInfo
from gallia.utils import unravel, unravel_2d


def err_int(x: str, base: int) -> int:
    try:
        return int(x, base)
    except ValueError:
        base_suffix = ""

        if base != 0:
            base_suffix = f" with base {base}"

        raise ValueError(
            f"{repr(x)} is not a valid representation for an integer{base_suffix}"
        ) from None


AutoInt = Annotated[int, BeforeValidator(lambda x: x if isinstance(x, int) else err_int(x, 0))]
"""
Special type for a field, which automatically parses int from a string.

See int() with base=0 for more information on the syntax.

Usage: x: HexInt = ....
"""


HexInt = Annotated[int, BeforeValidator(lambda x: x if isinstance(x, int) else err_int(x, 16))]
"""
Special type for a field, which parses int from a hex string.

See int() with base=16 for more information on the syntax.

Usage: x: HexInt = ....
"""

HexBytes = Annotated[
    bytes,
    BeforeValidator(lambda x: x if isinstance(x, bytes) else binascii.unhexlify(x)),
]
"""
Special type for a field, which parses bytes from hex strings.

See binascii.unhexlify() for more information on the syntax.

Usage: x: HexBytes = ....
"""


def _process_ranges(value: Any) -> Any:
    if isinstance(value, str):
        return unravel(",".join(value.split()))
    elif isinstance(value, list) and all(isinstance(x, str) for x in value):
        return unravel(",".join(value))
    return value


Ranges = Annotated[list[int], BeforeValidator(_process_ranges)]
"""
Special type for a field, which parses one-dimensional ranges.

See unravel() for more information on the syntax.

Usage: x: Ranges = ....
"""

Ranges2D = Annotated[
    dict[int, list[int] | None],
    BeforeValidator(
        lambda x: x
        if isinstance(x, dict)
        else unravel_2d(" ".join(x))
        if isinstance(x, list)
        else unravel_2d(x)
    ),
]
"""
Special type for a field, which parses two-dimensional ranges.

See unravel_2d() for more information on the syntax.

Usage: x: Ranges2D = ....
"""


T = TypeVar("T")
EnumType = TypeVar("EnumType", bound=Enum)
LiteralType = TypeVar("LiteralType")


def auto_enum(x: str, enum_type: type[EnumType]) -> EnumType:
    try:
        return enum_type[x]
    except KeyError:
        try:
            return enum_type(x)
        except ValueError:
            try:
                return enum_type(int(x, 0))
            except ValueError:
                pass

    raise ValueError(f"{x} is not a valid key or value for {enum_type}")


if TYPE_CHECKING:
    Idempotent: TypeAlias = Annotated[T, ""]
    EnumArg: TypeAlias = Annotated[EnumType, ""]
    AutoLiteral: TypeAlias = Annotated[LiteralType, ""]
else:

    class _TrickType:
        def __init__(self, function: Callable[[type[T]], type[T]]):
            self.function = function

        def __getitem__(self, cls: type[T]) -> type[T]:
            return self.function(cls)

    Idempotent = _TrickType(
        lambda cls: Annotated[cls, BeforeValidator(lambda x: x if isinstance(x, cls) else cls(x))]
    )
    """
    Wrapper for fields of types which can be instantiated by a certain value, but not by an instance of its own type.

    This way, it is possible to fill the corresponding parameter of the model with both the value as well as an already instantiated object of that class.

    Usage: x: Idempotent[SomeClass] = ...
    """

    EnumArg = _TrickType(
        lambda cls: Annotated[
            cls, BeforeValidator(lambda x: x if isinstance(x, cls) else auto_enum(x, cls))
        ]
    )
    """
    Wrapper for enum fields to provide automatic parsing of enum values by either name or value similar to AutoInt.

    Usage: x: EnumArg[SomeEnum] = ...
    """

    def auto_literal(cls: type[T]):
        args = get_args(cls)

        mapping = {}

        for arg in args:
            if isinstance(arg, Enum):
                mapping[arg.value] = arg
                mapping[arg.name] = arg
            elif isinstance(arg, bytes):
                mapping[binascii.hexlify(arg)] = arg

        def try_auto_literal(value: Any):
            if value in args:
                return value

            try:
                return mapping[value]
            except KeyError:
                pass

            try:
                return mapping[err_int(value, 0)]
            except (KeyError, ValueError):
                pass

            return value

        return Annotated[cls, BeforeValidator(try_auto_literal)]

    AutoLiteral = _TrickType(auto_literal)
    """
    Wrapper for Literal fields to provide automatic handling of enum, int and bytes parsing for values defined in Literals similar to EnumArg, AutoInt and HexBytes.

    Usage: x: AutoLiteral[Literal[1, 2, 3]] = ...
    """


class ConfigArgFieldInfo(ArgFieldInfo):
    def __init__(
        self,
        default: Any,
        positional: bool,
        short: str | None,
        metavar: str | None,
        cli_group: str | None,
        const: Any,
        hidden: bool,
        config_section: str | None,
        **kwargs: Unpack[_FromFieldInfoInputs],
    ):
        """
        Creates a new ConfigArgFieldInfo.

        This is a special variant of pydantic's FieldInfo, which adds several arguments,
        mainly related to CLI arguments and config sections.
        For general usage and details on the generic parameters see https://docs.pydantic.dev/latest/concepts/fields.
        Just as with pydantic's FieldInfo, this should usually not be called directly.
        Instead use the Field() function of this module.

        :param default: The default value, if non is given explicitly.
        :param positional: Specifies, if the argument is shown as positional, as opposed to optional (default), on the CLI.
        :param short: An optional alternative name for the CLI, which is auto-prefixed with "-".
        :param metavar: The type hint which is shown on the CLI for an argument. If none is specified, it is automatically inferred from its type.
        :param cli_group: The group in the CLI under which the argument is listed. If none is specified, it is automatically set to the CLI group of the config class to which this argument belongs.
        :param const: Specifies, a default value, if the argument is set with no explicit value.
        :param hidden: Specifies, that the argument is part of neither the CLI nor the config file.
        :param config_section: Specifies the config section under which the argument is listed. If none is specified, it is automatically set to the config section of the config class to which this argument belongs.
        :param kwargs: Generic pydantic Field() arguments (see https://docs.pydantic.dev/latest/api/fields/#pydantic.fields.FieldInfo).
        """
        super().__init__(
            default=default,
            positional=positional,
            short=short,
            metavar=metavar,
            cli_group=cli_group,
            const=const,
            hidden=hidden,
            **kwargs,
        )

        self.config_section = config_section


def Field(
    default: Any = PydanticUndefined,
    positional: bool = False,
    short: str | None = None,
    metavar: str | None = None,
    cli_group: str | None = None,
    const: Any = PydanticUndefined,
    hidden: bool = False,
    config_section: str | None = None,
    **kwargs: Unpack[_FromFieldInfoInputs],
) -> Any:
    """
    Creates a new ConfigArgFieldInfo.

    This is a special variant of pydantic's Field() function, which adds several arguments,
    mainly related to CLI arguments and config sections.
    For general usage and details on the generic parameters see https://docs.pydantic.dev/latest/concepts/fields.

    :param default: The default value, if non is given explicitly.
    :param positional: Specifies, if the argument is shown as positional, as opposed to optional (default), on the CLI.
    :param short: An optional alternative name for the CLI, which is auto-prefixed with "-".
    :param metavar: The type hint which is shown on the CLI for an argument. If none is specified, it is automatically inferred from its type.
    :param cli_group: The group in the CLI under which the argument is listed. If none is specified, it is automatically set to the CLI group of the config class to which this argument belongs.
    :param const: Specifies, a default value, if the argument is set with no explicit value.
    :param hidden: Specifies, that the argument is part of neither the CLI nor the config file.
    :param config_section: Specifies the config section under which the argument is listed. If none is specified, it is automatically set to the config section of the config class to which this argument belongs.
    :param kwargs: Generic pydantic Field() arguments (see https://docs.pydantic.dev/latest/api/fields/#pydantic.fields.Field).
    :return: A ConfigArgFieldInfo.
    """
    return ConfigArgFieldInfo(
        default, positional, short, metavar, cli_group, const, hidden, config_section, **kwargs
    )


class GalliaBaseModel(BaseCommand, ABC):
    """
    Base class for config classes for commands.


    """

    init_kwargs: dict[str, Any] | None = Field(
        None,
        hidden=True,
        description="This allows to initialize parts or all of the fields safely. Required args may be specified explicitly to please the linter",
    )
    _cli_group: str | None = None
    _config_section: str | None = None
    __config_registry: dict[str, tuple[str, Any]] = {}

    def __init__(self, **data: Any):
        init_kwargs = data.pop("init_kwargs", {})

        if init_kwargs is None:
            init_kwargs = {}
        else:
            # Copy to avoid side effects when reusing init_kwargs
            init_kwargs = dict(init_kwargs)

        init_kwargs.update(data)

        super().__init__(**init_kwargs)

    def __init_subclass__(
        cls,
        /,
        cli_group: str | None = None,
        config_section: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)

        cls._config_section = config_section
        cls._cli_group = cli_group

        for attribute, info in vars(cls).items():
            # Attribute specific annotation takes precedence
            if isinstance(info, ArgFieldInfo) and info.group is None:
                info.group = cli_group

            if isinstance(info, ConfigArgFieldInfo):
                # Attribute specific annotation takes precedence
                if info.config_section is None:
                    info.config_section = config_section

                # Add config to registry
                if info.config_section is not None:
                    config_attribute = (
                        f"{info.config_section}.{attribute}"
                        if info.config_section != ""
                        else attribute
                    )
                    description = "" if info.description is None else info.description

                    # TODO: Private attributes are write protected and throw a TypeError
                    # This is a quick hack to make it work nonetheless
                    try:
                        GalliaBaseModel.__config_registry[config_attribute] = (
                            description,
                            info.default,
                        )
                    except TypeError:
                        GalliaBaseModel.__config_registry = {}

                    GalliaBaseModel.__config_registry[config_attribute] = (
                        description,
                        info.default,
                    )

    @staticmethod
    def registry() -> dict[str, tuple[str, Any]]:
        return GalliaBaseModel.__config_registry

    @classmethod
    def attributes_from_toml(cls, path: Path) -> dict[str, Any]:
        toml_config = tomllib.loads(path.read_text())
        return cls.attributes_from_config(Config(toml_config))

    @classmethod
    def attributes_from_config(cls, config: Config, source: str = "config file") -> dict[str, Any]:
        result = {}

        for name, info in cls.model_fields.items():
            if isinstance(info, ConfigArgFieldInfo):
                config_attribute = (
                    f"{info.config_section}.{name}" if info.config_section != "" else name
                )

                if (value := config.get_value(config_attribute)) is not None:
                    result[name] = (f"{source} ({info.config_section}:{name})", value)

        return result

    @classmethod
    def attributes_from_env(cls) -> dict[str, Any]:
        result = {}

        for name, info in cls.model_fields.items():
            if isinstance(info, ConfigArgFieldInfo):
                config_attribute = f"GALLIA_{name.upper()}"

                if (value := os.getenv(config_attribute)) is not None:
                    result[name] = (f"environment variable ({config_attribute})", value)

        return result
