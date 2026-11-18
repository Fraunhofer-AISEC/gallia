# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from gallia.command.base import AsyncScript

if TYPE_CHECKING:
    from gallia.command.uds import UDSScanner

__all__ = [
    "AsyncScript",
    "UDSScanner",
]


def __getattr__(name: str) -> Any:
    # UDSScanner is imported lazily: it pulls in gallia.services.uds and
    # the transports, which AsyncScript-only commands do not need.
    if name == "UDSScanner":
        from gallia.command.uds import UDSScanner

        return UDSScanner

    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
