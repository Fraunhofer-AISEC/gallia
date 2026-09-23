# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""Formatting of records, shared by ``hr`` and ``hr --cursed``."""

import datetime
from binascii import unhexlify
from dataclasses import dataclass
from enum import Enum, auto

from gallia.log import ConsoleColor, PenlogRecord, format_prefix, format_timestamp


class InterpretationKind(Enum):
    UDS_REQUEST = auto()
    UDS_POSITIVE_RESPONSE = auto()
    UDS_NEGATIVE_RESPONSE = auto()


@dataclass(frozen=True)
class Interpretation:
    text: str
    kind: InterpretationKind


def interpret_uds(data: str) -> Interpretation | None:
    """Interprets ``data`` as UDS message, if it is one in hex."""
    try:
        pdu = unhexlify(data)
    except ValueError:
        return None
    if len(pdu) == 0 or pdu[0] == 0:
        return None

    # Imported lazily; this takes a while and is rarely needed.
    from gallia.services.uds.core.service import NegativeResponse, UDSRequest, UDSResponse

    try:
        if pdu[0] & 0x40:
            response = UDSResponse.parse_dynamic(pdu)
            if isinstance(response, NegativeResponse):
                return Interpretation(repr(response), InterpretationKind.UDS_NEGATIVE_RESPONSE)
            return Interpretation(repr(response), InterpretationKind.UDS_POSITIVE_RESPONSE)
        return Interpretation(repr(UDSRequest.parse_dynamic(pdu)), InterpretationKind.UDS_REQUEST)
    except Exception:
        return None


INTERPRETATION_COLORS = {
    InterpretationKind.UDS_REQUEST: ConsoleColor.CYAN,
    InterpretationKind.UDS_POSITIVE_RESPONSE: ConsoleColor.GREEN,
    InterpretationKind.UDS_NEGATIVE_RESPONSE: ConsoleColor.ORANGE,
}


@dataclass
class RecordFormatter:
    """Formats records according to the output options of ``hr``."""

    prefix: bool = True
    relative_timings: bool = False
    # Relative timestamps refer to this time; defaults to the first
    # formatted record, i.e. the first displayed one.
    reference_time: datetime.datetime | None = None
    interpret: bool = False

    def format_timestamp(self, dt: datetime.datetime) -> str:
        if not self.relative_timings:
            return format_timestamp(dt)
        if self.reference_time is None:
            self.reference_time = dt

        ms = int((dt - self.reference_time).total_seconds() * 1000)
        sign = "-" if ms < 0 else "+"
        ms = abs(ms)
        return (
            f"{sign}{ms // 86_400_000}d {ms // 3_600_000 % 24:02}:"
            f"{ms // 60_000 % 60:02}:{ms // 1000 % 60:02}.{ms % 1000:03}"
        ).rjust(18)

    def format_prefix(self, record: PenlogRecord) -> str:
        if not self.prefix:
            return ""
        return format_prefix(self.format_timestamp(record.datetime), record.module, record.tags)

    def interpretation(self, record: PenlogRecord) -> Interpretation | None:
        return interpret_uds(record.data) if self.interpret else None

    def format(self, record: PenlogRecord) -> str:
        """Formats a record as a console log line, see :meth:`PenlogRecord.format`.
        Like in the viewer, continuation lines are aligned with the first line."""
        suffix = ""
        if (interpretation := self.interpretation(record)) is not None:
            suffix = f"  # {interpretation.text}"
            if record.colors:
                color = INTERPRETATION_COLORS[interpretation.kind]
                suffix = f"{color.value}{suffix}{ConsoleColor.RESET.value}"
        return record.format(prefix=self.format_prefix(record), suffix=suffix, align=True)
