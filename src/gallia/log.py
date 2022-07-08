# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import inspect
import json
import logging
import os
import socket
import sys
import traceback
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum, IntEnum, unique
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, TextIO, Union, cast

import zstandard
from rich.console import Console, RenderableType
from rich.logging import RichHandler
from rich.text import Text
from rich.columns import Columns
from rich.traceback import Traceback

if TYPE_CHECKING:
    from logging import _ExcInfoType


# https://stackoverflow.com/a/35804945
def add_logging_level(level_name: str, level_num: int) -> None:
    method_name = level_name.lower()

    if hasattr(logging, level_name):
        raise AttributeError(f'{level_name} already defined in logging module')
    if hasattr(logging, method_name):
        raise AttributeError(f'{method_name} already defined in logging module')
    if hasattr(logging.getLoggerClass(), method_name):
        raise AttributeError(f'{method_name} already defined in logger class')

    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def for_level(self, message, *args, **kwargs):  # type: ignore
        if self.isEnabledFor(level_num):
            self._log(level_num, message, args, **kwargs)

    def to_root(message, *args, **kwargs):  # type: ignore
        logging.log(level_num, message, *args, **kwargs)

    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    setattr(logging.getLoggerClass(), method_name, for_level)
    setattr(logging, method_name, to_root)


add_logging_level("TRACE", 5)
add_logging_level("NOTICE", 25)

console_stderr = Console(stderr=True)
tz = datetime.utcnow().astimezone().tzinfo
fac = logging.getLogRecordFactory()


def _get_line_number(depth: int) -> tuple[str, int]:
    stack = inspect.stack()
    frame = stack[depth]
    return frame.filename, frame.lineno


def str2bool(s: str) -> bool:
    return s.lower() in ["true", "1", "t", "y"]


def _record_factory(
    name,
    level,
    fn,
    lno,
    msg,
    args,
    exc_info,
    func=None,
    sinfo=None,
    **kwargs,
):
    custom_depth = 7 if name == "root" else 5
    if level == logging.TRACE or level == logging.NOTICE:  # type: ignore
        fn, lno = _get_line_number(custom_depth)
    return fac(
        name,
        level,
        fn,
        lno,
        msg,
        args,
        exc_info,
        func=func,
        sinfo=sinfo,
        **kwargs,
    )


logging.setLogRecordFactory(_record_factory)


@unique
class MessagePrio(IntEnum):
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7
    TRACE = 8


level_to_priority = {
    logging.TRACE: MessagePrio.TRACE,  # type: ignore
    logging.DEBUG: MessagePrio.DEBUG,
    logging.INFO: MessagePrio.INFO,
    logging.NOTICE: MessagePrio.NOTICE,  # type: ignore
    logging.WARNING: MessagePrio.WARNING,
    logging.ERROR: MessagePrio.ERROR,
    logging.CRITICAL: MessagePrio.CRITICAL,
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        dt = datetime.fromtimestamp(record.created, tz=tz)
        d = {
            "version": 2,
            "component": record.name,
            "host": socket.gethostname(),
            "data": record.getMessage(),
            "timestamp": dt.isoformat(),
            "_python_level_no": record.levelno,
            "_python_level_name": record.levelname,
            "_python_func_name": record.funcName,
            "priority": level_to_priority[record.levelno].value,
        }

        if "tags" in record.__dict__:
            d["tags"] = record.__dict__["tags"]

        if record.exc_info:
            d["stacktrace"] = self.formatException(record.exc_info)

        d["line"] = f"{record.pathname}:{record.lineno}"

        return json.dumps(d)


class ConsoleHandler(logging.Handler):
    def __init__(self, level: Union[int, str] = logging.NOTSET) -> None:
        super().__init__(level)
        self.show_date = True
        self.show_component = True

    def render(self, record: logging.LogRecord) -> tuple[RenderableType, Optional[RenderableType]]:
        msg = Text()
        if self.show_date:
            dt = datetime.fromtimestamp(record.created)
            msg.append(dt.strftime("%b %d %H:%m:%S.%f")[:-3])

        if self.show_component:
            if self.show_date:
                msg.append(" ")
            msg.append(f"{record.name.ljust(10)}")

        if self.show_date or self.show_component:
            msg.append(": ")

        s = record.getMessage()

        if record.levelno == logging.TRACE:  # type: ignore
            style = "grey35"
        elif record.levelno == logging.DEBUG:
            style = "grey54"
        elif record.levelno == logging.INFO:
            style = ""
        elif record.levelno == logging.NOTICE:  # type: ignore
            style = "bold"
        elif record.levelno == logging.WARNING:
            style = "bold yellow"
        elif record.levelno == logging.ERROR:
            style = "red"
        elif record.levelno == logging.CRITICAL:
            style = "bold red"
        else:
            style = ""

        msg.append(s, style=style)

        tb = None
        if record.exc_info:
            exc_type, exc_value, exc_traceback = record.exc_info
            assert exc_type
            assert exc_value
            assert exc_traceback
            tb = Traceback.from_exception(exc_type, exc_value, exc_traceback)

        return (msg, tb)

    def emit(self, record: logging.LogRecord) -> None:
        r = self.render(record)
        console_stderr.print(r[0], overflow="ellipsis")
        if r[1] is not None:
            console_stderr.print(r[1])


class ZstdFileHandler(logging.Handler):
    def __init__(self, path: Path, level: Union[int, str] = logging.NOTSET) -> None:
        super().__init__(level)
        self.file = path.open("wb")
        self.compressor = zstandard.ZstdCompressor()
        self.zstd_writer = self.compressor.stream_writer(self.file)

    def close(self) -> None:
        self.zstd_writer.flush()
        self.zstd_writer.close()  # type: ignore
        self.file.close()

    def emit(self, record: logging.LogRecord) -> None:
        data = self.format(record)
        if not data.endswith("\n"):
            data += "\n"
        self.zstd_writer.write(data.encode())


class Logger(logging.Logger):
    def trace(
        self,
        msg: Any,
        *args: Any,
        exc_info: "_ExcInfoType" = None,
        stack_info: bool = False,
        extra: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        if self.isEnabledFor(logging.TRACE):  # type: ignore
            self._log(
                logging.TRACE,  # type: ignore
                msg,
                args,
                exc_info=exc_info,
                extra=extra,
                stack_info=stack_info,
                **kwargs,
            )

    def notice(
        self,
        msg: Any,
        *args: Any,
        exc_info: "_ExcInfoType" = None,
        stack_info: bool = False,
        extra: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        if self.isEnabledFor(logging.NOTICE):  # type: ignore
            self._log(
                logging.NOTICE,  # type: ignore
                msg,
                args,
                exc_info=exc_info,
                extra=extra,
                stack_info=stack_info,
                **kwargs,
            )

    def preamble(
        self,
        msg: Any,
        *args: Any,
        exc_info: "_ExcInfoType" = None,
        stack_info: bool = False,
        extra: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        extra = extra if extra is not None else {}
        extra["tags"] = ["preamble"]
        if self.isEnabledFor(logging.INFO):
            self._log(
                logging.INFO,
                msg,
                args,
                exc_info=exc_info,
                extra=extra,
                stack_info=stack_info,
                **kwargs,
            )

    def result(
        self,
        msg: Any,
        *args: Any,
        exc_info: "_ExcInfoType" = None,
        stack_info: bool = False,
        extra: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        extra = extra if extra is not None else {}
        extra["tags"] = ["result"]
        if self.isEnabledFor(logging.NOTICE):  # type: ignore
            self._log(
                logging.NOTICE,  # type: ignore
                msg,
                args,
                exc_info=exc_info,
                extra=extra,
                stack_info=stack_info,
                **kwargs,
            )

    def write(
        self,
        msg: Any,
        *args: Any,
        exc_info: "_ExcInfoType" = None,
        stack_info: bool = False,
        extra: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        extra = extra if extra is not None else {}
        extra["tags"] = ["write"]
        if self.isEnabledFor(logging.DEBUG):
            self._log(
                logging.DEBUG,
                msg,
                args,
                exc_info=exc_info,
                extra=extra,
                stack_info=stack_info,
                **kwargs,
            )

    def read(
        self,
        msg: Any,
        *args: Any,
        exc_info: "_ExcInfoType" = None,
        stack_info: bool = False,
        extra: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        extra = extra if extra is not None else {}
        extra["tags"] = ["read"]
        if self.isEnabledFor(logging.DEBUG):
            self._log(
                logging.DEBUG,
                msg,
                args,
                exc_info=exc_info,
                extra=extra,
                stack_info=stack_info,
                **kwargs,
            )


logging.setLoggerClass(Logger)


def get_logger(name: str) -> Logger:
    return cast(Logger, logging.getLogger(name))
