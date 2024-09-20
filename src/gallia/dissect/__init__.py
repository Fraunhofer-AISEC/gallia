# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Literal, NotRequired, TypeAlias, TypedDict

from gallia.services.uds.core.service import UDSRequest, UDSResponse


@dataclass
class Field:
    name: str
    raw_data: bytes
    dissected_data: str


class BaseDissector(ABC):
    PROTO: str = ""

    def __init_subclass__(
        cls,
        /,
        proto: str,
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)
        cls.PROTO = proto

    @abstractmethod
    def dissect(self, data: bytes, iotype: str | None = None) -> list[Field]: ...


class UDSDissector(BaseDissector, proto="uds"):
    def dissect(self, data: bytes, iotype: str | None = None) -> list[Field]:
        if data[0] & 0b01000000:
            dissected_data = repr(UDSResponse.parse_dynamic(data))
            name = "uds response"
        else:
            dissected_data = repr(UDSRequest.parse_dynamic(data))
            name = "uds request"

        return [Field(name=name, raw_data=data, dissected_data=dissected_data)]


# TODO: Can the PROTO attribute be used?
registry: dict[str, BaseDissector] = {"uds": UDSDissector()}
