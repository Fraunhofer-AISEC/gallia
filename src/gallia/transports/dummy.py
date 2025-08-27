# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from gallia.transports.base import BaseTransport


class DummyTransport(BaseTransport, scheme="dummy"):
    async def connect(self, timeout: float | None = None) -> None:
        pass

    async def close(self) -> None:
        pass

    async def read(self, timeout: float | None = None, tags: list[str] | None = None) -> bytes:
        return b""

    async def write(
        self, data: bytes, timeout: float | None = None, tags: list[str] | None = None
    ) -> int:
        return len(data)

    async def dumpcap_argument_list(self) -> list[str] | None:
        return None
