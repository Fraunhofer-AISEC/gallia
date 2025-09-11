# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from typing import Self

from gallia.transports import TargetURI
from gallia.transports.base import BaseTransport


class DummyTransport(BaseTransport, scheme="dummy"):
    @classmethod
    async def connect(cls, target: str | TargetURI, timeout: float | None = None) -> Self:
        t = target if isinstance(target, TargetURI) else TargetURI(target)
        return cls(t)

    async def close(self) -> None:
        pass

    async def read(self, timeout: float | None = None, tags: list[str] | None = None) -> bytes:
        return b""

    async def write(
        self, data: bytes, timeout: float | None = None, tags: list[str] | None = None
    ) -> int:
        return len(data)
