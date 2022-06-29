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
from enum import Enum, IntEnum
from typing import Any, Optional, TextIO

from rich.logging import RichHandler

from penlog import haggis_logs

haggis_logs.add_logging_level("TRACE", 5)
haggis_logs.add_logging_level("NOTICE", 25)

fac = logging.getLogRecordFactory()


def _get_line_number(depth: int) -> tuple[str, int]:
    stack = inspect.stack()
    frame = stack[depth]
    return frame.filename, frame.lineno


def str2bool(s: str) -> bool:
    return s.lower() in ["true", "1", "t", "y"]


def _log_record_factory(
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
    if level == 5 or level == 25:
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


logging.setLogRecordFactory(_log_record_factory)

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET",
    format=FORMAT,
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        RichHandler(
            rich_tracebacks=True,
            tracebacks_show_locals=True,
            show_level=False,
            omit_repeated_times=False,
        )
    ],
)


class Penlogger(logging.Logger):
    def trace(self, msg, *args, **kwargs):
        if self.isEnabledFor(5):
            self._log(5, msg, args, **kwargs)

    def notice(self, msg, *args, **kwargs):
        if self.isEnabledFor(25):
            self._log(25, msg, args, **kwargs)


logging.setLoggerClass(Penlogger)
logger: Penlogger = logging.getLogger("foobar")

logger.trace("foo")

logging.trace("foobar")
logging.debug("foobar")
logging.info("foobar")
logging.notice("foobar")
logging.warning("foobar")
logging.error("foobar")
logging.exception(RuntimeError("Deine Mama"))


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


class MessageType(str, Enum):
    MESSAGE = "message"


@dataclass
class RecordType:
    component: str
    data: str
    host: str
    priority: MessagePrio
    timestamp: str
    type: str
    line: Optional[str] = None
    stacktrace: Optional[str] = None
    tags: Optional[list[str]] = None


class Logger:
    def __init__(self, component: str, loglevel: Optional[int] = None):
        self._logger = logging.getLogger(component)
        self.host = socket.gethostname()
        self.component = component
        self.lines = str2bool(os.environ.get("PENLOG_CAPTURE_LINES", ""))
        self.stacktraces = str2bool(os.environ.get("PENLOG_CAPTURE_STACKTRACES", ""))

        # Default the loglevel to the function argument
        # if it is set. Otherwise try to read the environ
        # variable. If it is set, validate it. If it is not
        # set, default to INFO.
        if loglevel is not None:
            self.loglevel = loglevel
        else:
            if (level := os.getenv("PENLOG_LOGLEVEL")) is None:
                self.loglevel = MessagePrio.INFO
            else:
                try:
                    level_int = int(level, 0)
                    self.loglevel = MessagePrio(level_int)
                except ValueError as e:
                    for level_enum in MessagePrio:
                        if level == level_enum.name.lower():
                            self.loglevel = level_enum
                            break
                    else:
                        raise ValueError("invalid loglevel") from e

    def _log(self, msg: RecordType, depth: int) -> None:
        try:
            prio = MessagePrio(msg.priority)
            if prio > self.loglevel:
                return
        except ValueError:
            pass
        msg.component = self.component
        msg.host = self.host
        if msg.priority == MessagePrio.TRACE:
            self._logger.trace(msg)
        elif msg.priority == MessagePrio.DEBUG:
            self._logger.debug(msg)
        elif msg.priority == MessagePrio.INFO:
            self._logger.info(msg)
        elif msg.priority == MessagePrio.NOTICE:
            self._logger.notice(msg)
        elif msg.priority == MessagePrio.WARNING:
            self._logger.warning(msg)
        elif msg.priority == MessagePrio.ERROR:
            self._logger.error(msg)
        elif msg.priority == MessagePrio.CRITICAL:
            self._logger.critical(msg)

    def log_msg(
        self,
        data: Any,
        type_: str = MessageType.MESSAGE,
        prio: MessagePrio = MessagePrio.INFO,
        tags: Optional[list[str]] = None,
        _depth: int = 3,
    ) -> None:
        msg = RecordType(
            component="",
            data=str(data),
            host="",
            id=None,
            line=None,
            priority=prio,
            stacktrace=None,
            tags=tags,
            timestamp="",
            type=type_,
        )
        self._log(msg, _depth)

    def log_trace(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.TRACE, tags, 4)

    def log_debug(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.DEBUG, tags, 4)

    def log_info(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.INFO, tags, 4)

    def log_notice(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.NOTICE, tags, 4)

    def log_warning(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.WARNING, tags, 4)

    def log_error(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.ERROR, tags, 4)

    def log_critical(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.CRITICAL, tags, 4)


logger = Logger("foobert")
logger.log_info("dere")

exit()


class MessageType(str, Enum):
    MESSAGE = "message"


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


class OutputType(Enum):
    JSON = "json"
    JSON_PRETTY = "json-pretty"
    HR = "hr"
    HR_TINY = "hr-tiny"
    HR_NANO = "hr-nano"


class Color(Enum):
    NOP = ""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    PURPLE = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[0;38;5;245m"


@dataclass
class RecordType:
    component: str
    data: str
    host: str
    priority: MessagePrio
    timestamp: str
    type: str
    id: Optional[str] = None
    line: Optional[str] = None
    stacktrace: Optional[str] = None
    tags: Optional[list[str]] = None


def colorize(color: Color, s: str) -> str:
    if color == Color.NOP:
        return s
    return f"{color.value}{s}{Color.RESET.value}"


def _get_line_number(depth: int) -> str:
    stack = inspect.stack()
    frame = stack[depth]
    return f"{frame.filename}:{frame.lineno}"


def str2bool(s: str) -> bool:
    return s.lower() in ["true", "1", "t", "y"]


class HRFormatter:
    def __init__(
        self,
        show_colors: bool,
        show_ids: bool,
        show_lines: bool,
        show_stacktraces: bool,
        show_tags: bool,
        output_type: OutputType,
    ):
        self.show_colors = show_colors
        self.show_ids = show_ids
        self.show_lines = show_lines
        self.show_stacktraces = show_stacktraces
        self.show_tags = show_tags
        self.output_type = output_type

    @staticmethod
    def _colorize_data(data: str, prio: MessagePrio) -> str:
        if prio in (
            MessagePrio.EMERGENCY,
            MessagePrio.ALERT,
            MessagePrio.CRITICAL,
            MessagePrio.ERROR,
        ):
            data = colorize(Color.BOLD, colorize(Color.RED, data))
        elif prio == MessagePrio.WARNING:
            data = colorize(Color.BOLD, colorize(Color.YELLOW, data))
        elif prio == MessagePrio.NOTICE:
            data = colorize(Color.BOLD, data)
        elif prio == MessagePrio.INFO:
            pass
        elif prio in (MessagePrio.DEBUG, MessagePrio.TRACE):
            data = colorize(Color.GRAY, data)
        return data

    def format(self, msg: RecordType) -> str:
        assert self.output_type in (
            OutputType.HR,
            OutputType.HR_TINY,
            OutputType.HR_NANO,
        )

        out = ""
        ts = datetime.fromisoformat(msg.timestamp)
        ts_formatted = ts.strftime("%b %d %H:%M:%S.%f")[:-3]
        component = msg.component
        msgtype = msg.type
        data = msg.data
        if self.show_colors:
            prio = MessagePrio(msg.priority)
            data = self._colorize_data(data, prio)

        if self.output_type == OutputType.HR_TINY:
            out = f"{ts_formatted}: {data}"
        elif self.output_type == OutputType.HR_NANO:
            out = f"{data}"
        elif self.output_type == OutputType.HR:
            out = f"{ts_formatted} {{{component: <8}}} [{msgtype: <8}]: {data}"
        else:
            raise ValueError("BUG: this code should not be reachable")

        if self.show_ids and msg.id is not None:
            out += "\n"
            if self.show_colors:
                out += f" => id  : {colorize(Color.YELLOW, msg.id)}"
            else:
                out += f" => id  : {msg.id}"
        if self.show_lines and msg.line is not None:
            out += "\n"
            if self.show_colors:
                out += f" => line: {colorize(Color.BLUE, msg.line)}"
            else:
                out += f" => line: {msg.line}"
        if self.show_tags and msg.tags is not None:
            out += "\n"
            out += f" => tags: {' '.join(msg.tags)}"
        if self.show_stacktraces and msg.stacktrace is not None:
            out += "\n"
            out += " => stacktrace:\n"
            for line in msg.stacktrace.splitlines():
                if self.show_colors:
                    out += colorize(Color.GRAY, f" | {line}\n")
                else:
                    out += f" | {line}\n"
        return out


class Logger:
    def __init__(
        self,
        component: str = "root",
        flush: bool = False,
        file_: TextIO = sys.stderr,
        loglevel: Optional[MessagePrio] = None,
        output_type: Optional[OutputType] = None,
        show_colors: bool = True,
        include_uuid: bool = False,
    ):
        self.host = socket.gethostname()
        self.component = component
        self.flush = flush
        self.file = file_
        self.include_uuid = include_uuid
        self.lines = str2bool(os.environ.get("PENLOG_CAPTURE_LINES", ""))
        self.stacktraces = str2bool(os.environ.get("PENLOG_CAPTURE_STACKTRACES", ""))

        # Default the loglevel to the function argument
        # if it is set. Otherwise try to read the environ
        # variable. If it is set, validate it. If it is not
        # set, default to INFO.
        if loglevel is not None:
            self.loglevel = loglevel
        else:
            if (level := os.getenv("PENLOG_LOGLEVEL")) is None:
                self.loglevel = MessagePrio.INFO
            else:
                try:
                    level_int = int(level, 0)
                    self.loglevel = MessagePrio(level_int)
                except ValueError as e:
                    for level_enum in MessagePrio:
                        if level == level_enum.name.lower():
                            self.loglevel = level_enum
                            break
                    else:
                        raise ValueError("invalid loglevel") from e

        if output_type:
            self.output_type = output_type
        else:
            if (type_raw := os.environ.get("PENLOG_OUTPUT")) is None:
                self.output_type = OutputType.HR_NANO
            else:
                self.output_type = OutputType(type_raw)

        show_colors = True if show_colors and self.file.isatty() else False
        self.hr_formatter = HRFormatter(
            show_colors=show_colors,
            show_ids=False,
            show_lines=self.lines,
            show_stacktraces=self.stacktraces,
            show_tags=False,
            output_type=self.output_type,
        )

    def _log(self, msg: RecordType, depth: int) -> None:
        try:
            prio = MessagePrio(msg.priority)
            if prio > self.loglevel:
                return
        except ValueError:
            pass
        if self.include_uuid:
            msg.id = str(uuid.uuid4())
        msg.component = self.component
        msg.host = self.host
        now = datetime.now().astimezone()
        msg.timestamp = now.isoformat()
        if self.lines:
            msg.line = _get_line_number(depth)
        if self.stacktraces:
            msg.stacktrace = "".join(traceback.format_stack())
        if self.output_type == OutputType.JSON:
            print(json.dumps(asdict(msg)), file=self.file, flush=self.flush)
        elif self.output_type == OutputType.JSON_PRETTY:
            print(json.dumps(asdict(msg), indent=2), file=self.file, flush=self.flush)
        elif self.output_type in (
            OutputType.HR,
            OutputType.HR_TINY,
            OutputType.HR_NANO,
        ):
            out = self.hr_formatter.format(msg)
            print(out, file=self.file, flush=self.flush)
        else:
            raise RuntimeError("BUG: invalid penlog output")

    def log_msg(
        self,
        data: Any,
        type_: str = MessageType.MESSAGE,
        prio: MessagePrio = MessagePrio.INFO,
        tags: Optional[list[str]] = None,
        _depth: int = 3,
    ) -> None:
        msg = RecordType(
            component="",
            data=str(data),
            host="",
            id=None,
            line=None,
            priority=prio,
            stacktrace=None,
            tags=tags,
            timestamp="",
            type=type_,
        )
        self._log(msg, _depth)

    def log_trace(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.TRACE, tags, 4)

    def log_debug(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.DEBUG, tags, 4)

    def log_info(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.INFO, tags, 4)

    def log_notice(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.NOTICE, tags, 4)

    def log_warning(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.WARNING, tags, 4)

    def log_error(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.ERROR, tags, 4)

    def log_critical(self, data: Any, tags: Optional[list[str]] = None) -> None:
        self.log_msg(data, MessageType.MESSAGE, MessagePrio.CRITICAL, tags, 4)


class DiscardLogger(Logger):
    def _log(self, msg: RecordType, depth: int) -> None:
        pass
