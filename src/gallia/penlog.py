# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from enum import Enum
from typing import Any, Optional

import penlog


class MessageType(str, Enum):
    READ = "read"
    WRITE = "write"
    PREAMBLE = "preamble"
    MESSAGE = "message"
    SUMMARY = "summary"


class Logger(penlog.Logger):
    stack_depth = 4

    def log_preamble(self, data: Any) -> None:
        self.log_msg(
            data,
            MessageType.PREAMBLE,
            penlog.MessagePrio.INFO,
            _depth=self.stack_depth,
        )

    def log_read(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(
            data,
            MessageType.READ,
            penlog.MessagePrio.DEBUG,
            tags,
            _depth=self.stack_depth,
        )

    def log_write(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(
            data,
            MessageType.WRITE,
            penlog.MessagePrio.DEBUG,
            tags,
            _depth=self.stack_depth,
        )

    def log_summary(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(
            data,
            MessageType.SUMMARY,
            penlog.MessagePrio.NOTICE,
            tags,
            _depth=self.stack_depth,
        )


class DiscardLogger(Logger):
    def _log(self, msg: penlog.RecordType, depth: int) -> None:
        pass
