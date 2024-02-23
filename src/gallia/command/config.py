import binascii
import os
import tomllib
from abc import ABC
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import UnionType
from typing import Annotated, Any, TypeVar, Union, get_args, get_origin

from pydantic import BeforeValidator, Field
from pydantic.fields import FieldInfo
from pydantic_argparse import BaseCommand
from pydantic_argparse.argparse.parser import ArgumentGroup
from pydantic_argparse.utils.pydantic import PydanticField

from gallia.config import Config

registry = {}


@dataclass
class ConfigSection:
    name: str | None


def no_config(cls: type) -> type:
    return Annotated[cls, ConfigSection(None)]


AutoInt = Annotated[int, BeforeValidator(lambda x: x if isinstance(x, int) else int(x, 0))]


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


class GalliaBaseModel(BaseCommand, ABC):
    init_kwargs: dict | None = None

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

        for attribute, type_annotation in cls.__annotations__.items():
            # Attribute specific annotation takes precedence, which can also be used to exclude an attribute from any group
            if not (
                get_origin(type_annotation) is Annotated
                and any(isinstance(x, ArgumentGroup) for x in type_annotation.__metadata__)
            ):
                type_annotation = Annotated[type_annotation, ArgumentGroup(argument_group)]
                cls.__annotations__[attribute] = type_annotation

            # Attribute specific annotation takes precedence, which can also be used to exclude an attribute from any section
            if not (
                get_origin(type_annotation) is Annotated
                and any(isinstance(x, ConfigSection) for x in type_annotation.__metadata__)
            ):
                type_annotation = Annotated[type_annotation, ConfigSection(config_section)]
                cls.__annotations__[attribute] = type_annotation

            attribute_config_sections = list(
                x for x in type_annotation.__metadata__ if isinstance(x, ConfigSection)
            )

            if len(attribute_config_sections) > 1:
                raise ValueError("An attribute can only have one config entry!")

            attribute_config_section = attribute_config_sections[0].name

            # Add config to registry
            if attribute_config_section is not None:
                if not hasattr(cls, attribute):
                    info = Field()
                else:
                    info: FieldInfo = getattr(cls, attribute)

                config_attribute = (
                    f"{attribute_config_section}.{attribute}"
                    if attribute_config_section != ""
                    else attribute
                )
                default = "" if info.default is None else f" ({info.default})"
                description = "" if info.description is None else info.description
                type_hint = (
                    type_annotation.__origin__
                )  # This is not equivalent to using get_origin(...)

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

        for field in PydanticField.parse_model(cls):
            for annotation in field.info.metadata:
                if isinstance(annotation, ConfigSection):
                    config_attribute = (
                        f"{annotation.name}.{field.name}" if annotation.name != "" else field.name
                    )

                    if (value := config.get_value(config_attribute)) is not None:
                        result[field.name] = value

        return result

    @classmethod
    def attributes_from_env(cls) -> dict[str, Any]:
        result = {}

        for field in PydanticField.parse_model(cls):
            for annotation in field.info.metadata:
                if isinstance(annotation, ConfigSection):
                    config_attribute = f"GALLIA_{field.name.upper()}"

                    if (value := os.getenv(config_attribute)) is not None:
                        result[field.name] = value

        return result
