import binascii
import os
import tomllib
from abc import ABC
from enum import Enum
from pathlib import Path
from types import UnionType
from typing import Annotated, Any, TypeVar, Union, Unpack, get_args, get_origin

from pydantic import BeforeValidator
from pydantic.fields import _FromFieldInfoInputs
from pydantic_argparse import BaseCommand
from pydantic_argparse.utils.field import ArgFieldInfo
from pydantic_core import PydanticUndefined

from gallia.config import Config

registry = {}


AutoInt = Annotated[int, BeforeValidator(lambda x: x if isinstance(x, int) else int(x, 0))]


HexInt = Annotated[int, BeforeValidator(lambda x: x if isinstance(x, int) else int(x, 16))]


HexBytes = Annotated[
    bytes,
    BeforeValidator(lambda x: x if isinstance(x, bytes) else binascii.unhexlify(x)),
]


EnumType = TypeVar("EnumType", bound=Enum)


def enum(cls: type[EnumType]) -> type[EnumType]:
    return Annotated[cls, BeforeValidator(lambda x: x if isinstance(x, cls) else cls[x])]


T = TypeVar("T")


def idempotent(cls: type[T]) -> type[T]:
    return Annotated[cls, BeforeValidator(lambda x: x if isinstance(x, cls) else cls(x))]


class ConfigArgFieldInfo(ArgFieldInfo):
    def __init__(
        self,
        default: Any,
        positional: bool,
        short: str | None,
        metavar: str | None,
        group: str | None,
        const: Any,
        config_section: str | None,
        **kwargs: Unpack[_FromFieldInfoInputs],
    ):
        super().__init__(
            default=default,
            positional=positional,
            short=short,
            metavar=metavar,
            group=group,
            const=const,
            **kwargs,
        )

        self.config_section = config_section


def Field(
    default: Any = PydanticUndefined,
    positional: bool = False,
    short: str | None = None,
    metavar: str | None = None,
    group: str | None = None,
    const: Any = PydanticUndefined,
    config_section: str | None = None,
    **kwargs: Unpack[_FromFieldInfoInputs],
) -> Any:
    return ConfigArgFieldInfo(
        default, positional, short, metavar, group, const, config_section, **kwargs
    )


class GalliaBaseModel(BaseCommand, ABC):
    init_kwargs: dict | None = None
    _argument_group: str | None
    _config_section: str | None

    def __init__(self, **data: Any):
        init_kwargs = data.pop("init_kwargs", {})
        init_kwargs.update(data)

        super().__init__(**init_kwargs)

    def __init_subclass__(
        cls,
        /,
        argument_group: str | None = None,
        config_section: str | None = None,
        **kwargs,
    ):
        super().__init_subclass__(**kwargs)

        cls._config_section = config_section
        cls._argument_group = argument_group

        for attribute, info in vars(cls).items():
            # Attribute specific annotation takes precedence
            if isinstance(info, ArgFieldInfo) and info.group is None:
                info.group = argument_group

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
                    default = "" if info.default is None else f" ({info.default})"
                    description = "" if info.description is None else info.description
                    type_annotation = cls.__annotations__[attribute]
                    type_hint = (
                        type_annotation.__origin__
                        if get_origin(type_annotation) is Annotated
                        else type_annotation
                    )  # (...).__origin__ is not equivalent to using get_origin(...)

                    if (origin := get_origin(type_hint)) is Union or origin is UnionType:
                        type_ = " | ".join(x.__name__ for x in get_args(type_hint) if x is not None)
                    else:
                        type_ = type_hint.__name__

                    registry[config_attribute] = f"{description} [{type_}]{default}"

    @classmethod
    def attributes_from_toml(cls, path: Path) -> dict[str, Any]:
        toml_config = tomllib.loads(path.read_text())
        return cls.attributes_from_config(Config(toml_config))

    @classmethod
    def attributes_from_config(cls, config: Config) -> dict[str, Any]:
        result = {}

        for name, info in cls.model_fields.items():
            if isinstance(info, ConfigArgFieldInfo):
                config_attribute = (
                    f"{info.config_section}.{name}" if info.config_section != "" else name
                )

                if (value := config.get_value(config_attribute)) is not None:
                    result[name] = value

        return result

    @classmethod
    def attributes_from_env(cls) -> dict[str, Any]:
        result = {}

        for name, info in cls.model_fields.items():
            if isinstance(info, ConfigArgFieldInfo):
                config_attribute = f"GALLIA_{name.upper()}"

                if (value := os.getenv(config_attribute)) is not None:
                    result[name] = value

        return result
