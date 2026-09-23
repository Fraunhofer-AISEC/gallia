# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""Formatting of records, shared by ``hr`` and ``hr --cursed``."""

import datetime
from dataclasses import dataclass

from gallia.dissect import Dissection, DissectionKind, dissect
from gallia.log import ConsoleColor, PenlogRecord, format_prefix, format_timestamp

DISSECTION_COLORS = {
    DissectionKind.REQUEST: ConsoleColor.CYAN,
    DissectionKind.RESPONSE: ConsoleColor.GREEN,
    DissectionKind.ERROR: ConsoleColor.ORANGE,
    DissectionKind.INFO: ConsoleColor.BLUE,
}


def dissect_record(record: PenlogRecord) -> Dissection | None:
    """Dissects the data of a record according to its protocol. Records
    without protocol, e.g. of older logfiles, are dissected as UDS, if
    possible."""
    return dissect(record.proto or "uds", record.data)


@dataclass
class RecordFormatter:
    """Formats records according to the output options of ``hr``."""

    prefix: bool = True
    relative_timings: bool = False
    # Relative timestamps refer to this time; defaults to the first
    # formatted record, i.e. the first displayed one.
    reference_time: datetime.datetime | None = None
    dissect: bool = False

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

    def dissection(self, record: PenlogRecord) -> Dissection | None:
        return dissect_record(record) if self.dissect else None

    def format(self, record: PenlogRecord) -> str:
        """Formats a record as a console log line, see :meth:`PenlogRecord.format`.
        Like in the viewer, continuation lines are aligned with the first line."""
        suffix = ""
        if (dissection := self.dissection(record)) is not None:
            suffix = f"  # {dissection.text}"
            if record.colors:
                color = DISSECTION_COLORS[dissection.kind]
                suffix = f"{color.value}{suffix}{ConsoleColor.RESET.value}"
        return record.format(prefix=self.format_prefix(record), suffix=suffix, align=True)
