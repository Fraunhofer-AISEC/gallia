# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-lines,eval-used

from __future__ import annotations

import curses
import curses.ascii
import gzip
import json
import mmap
import shutil
import tempfile
import warnings
from argparse import ArgumentParser
from array import array
from binascii import unhexlify
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum, unique
from math import ceil
from pathlib import Path
from typing import Any, BinaryIO, cast

import zstandard as zstd

from gallia.log import PenlogPriority, PenlogRecord
from gallia.services.uds.core.service import NegativeResponse, UDSRequest, UDSResponse


@unique
class InterpretationColor(IntEnum):
    DEFAULT = 42
    UDS_REQUEST = 43
    UDS_POSITIVE_RESPONSE = 44
    UDS_NEGATIVE_RESPONSE = 45


@dataclass
class PenlogEntry(PenlogRecord):
    interpretation: str | None = None
    interpretation_color: InterpretationColor = InterpretationColor.DEFAULT


@dataclass
class FormattedText:
    text: str
    format: int

    @property
    def sanitized_text(self) -> str:
        # Strip 0 bytes…
        return self.text.encode().replace(b"\x00", b"").decode()


@dataclass
class DisplayEntry:
    """
    Represents one single line of a single formatted penlog entry as displayed in the console.

    :param texts: The (differently) formatted text fragments of the displayed line.
    :param penlog_entry_number: The line number of the corresponding penlog entry.
    :param entry_line_number: The index in the list of formatted lines as created for the corresponding penlog entry.
    :param last_line: True if and only if this entry refers to the last of the formatted lines as created for the
                      corresponding penlog entry.
    """

    texts: list[FormattedText]
    penlog_entry_number: int
    entry_line_number: int
    last_line = False


@dataclass
class PriorityZone:
    """
    Represents a continuous range (including start and end) of entries for which a certain priority filter applies.

    :param start: The first penlog entry of the zone.
    :param end: The last penlog entry of the zone.
    :param priority: The filtering priority to be applied on all entries in in the zone.
    """

    start: int
    end: int | None
    priority: PenlogPriority


class EntryCache:
    """
    A simple two level cache that stores the latest accessed penlog entries.

    This is used to speed up the processing of penlog entries by reducing the number of necessary fetches from the
    input file. It may be ineffective if the whole file is kept in memory.
    """

    def __init__(
        self,
        file: BinaryIO | mmap.mmap,
        entry_positions: array[int],
        cache_size: int = 20_000,
    ):
        self.file = file
        self.old_entries: dict[int, PenlogEntry] = {}
        self.entries: dict[int, PenlogEntry] = {}
        self.entry_positions = entry_positions
        self.cache_size = cache_size

    def __len__(self) -> int:
        return len(self.entry_positions)

    def __getitem__(self, entry_number: int) -> PenlogEntry:
        try:
            return self.entries[entry_number]
        except KeyError:
            self._load_entry(entry_number)
            return self.entries[entry_number]

    def _load_entry(self, entry_number: int) -> None:
        self.file.seek(self.entry_positions[entry_number])
        line = self.file.readline()

        if len(self.entries) + len(self.old_entries) >= self.cache_size:
            self.old_entries = self.entries
            self.entries = {}

        try:
            self.entries[entry_number] = self.old_entries.pop(entry_number)
        except KeyError:
            try:
                # TODO: Python 3.11: the cast can be dropped due to typing.Self.
                self.entries[entry_number] = cast(
                    PenlogEntry, PenlogEntry.parse_json(line)
                )
            except (json.decoder.JSONDecodeError, TypeError):
                self.entries[entry_number] = PenlogEntry(
                    data=line.decode("utf-8"),
                    host="",
                    module="JSON",
                    datetime=datetime.fromtimestamp(0),
                    tags=["ERROR"],
                    priority=PenlogPriority.ERROR,
                )


@dataclass
class Configuration:
    priority_zones: list[PriorityZone]
    filter: list[str]
    interpret: bool


class CursedHR:
    """
    A curses based interactive reader for log files complying to penlog.

    It supports the following features:
        - interactive display of penlog files (similar to less)
        - coloring and formatting of entries based on the priority level
        - optimized sectional filtering based on priority
        - unoptimized sectional filtering based on any penlog entry attribute
        - in-line interpretation of UDS messages using the Gallia UDS implementation

    See https://github.com/Fraunhofer-AISEC/penlog for the penlog specification.
    """

    def __init__(
        self,
        in_file: Path,
        priority: PenlogPriority = PenlogPriority.DEBUG,
        filters: list[str] | None = None,
    ):
        self.in_file = in_file
        self.level_pointers: list[array[int]] = list(array("L") for _ in range(9))
        self.entry_positions = array("L")
        self.configuration_history = [
            Configuration(
                priority_zones=[PriorityZone(0, None, priority)],
                filter=filters if filters is not None else [],
                interpret=False,
            )
        ]
        self.configuration_index = 0

        try:
            self.window = self.init_curses()
            self.color_ids = self.define_colors()
            self.file = self.uncompressed_file()

            try:
                with mmap.mmap(
                    self.file.fileno(), 0, access=mmap.ACCESS_READ
                ) as mm_file:
                    self.parse_structure(mm_file)
                    self.entries = EntryCache(mm_file, self.entry_positions)
                    self.handle_io()
            finally:
                self.file.close()
        finally:
            self.terminate_curses()

    def init_curses(self) -> Any:
        window = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.noecho()
        curses.cbreak()
        window.keypad(True)

        return window

    def terminate_curses(self) -> None:
        curses.nocbreak()
        self.window.keypad(False)
        curses.echo()
        curses.endwin()

    def define_colors(self) -> dict[int, int]:
        prio_colors = {
            PenlogPriority.EMERGENCY: (100, curses.COLOR_RED),
            PenlogPriority.ALERT: (101, curses.COLOR_RED),
            PenlogPriority.CRITICAL: (102, curses.COLOR_RED),
            PenlogPriority.ERROR: (103, curses.COLOR_RED),
            PenlogPriority.WARNING: (104, curses.COLOR_YELLOW),
            PenlogPriority.NOTICE: (105, -1),
            PenlogPriority.INFO: (106, -1),
            PenlogPriority.DEBUG: (107, 8),
            PenlogPriority.TRACE: (108, curses.COLOR_BLUE),
        }

        for (identifier, value) in prio_colors.values():
            curses.init_pair(identifier, value, -1)

        curses.init_pair(InterpretationColor.DEFAULT, 8, -1)
        curses.init_pair(InterpretationColor.UDS_REQUEST, curses.COLOR_CYAN, -1)
        curses.init_pair(
            InterpretationColor.UDS_POSITIVE_RESPONSE, curses.COLOR_GREEN, -1
        )
        curses.init_pair(InterpretationColor.UDS_NEGATIVE_RESPONSE, 166, -1)

        return {prio: color[0] for prio, color in prio_colors.items()}

    def uncompressed_file(self) -> BinaryIO:
        """
        Returns an uncompressed version of the input file as referenced by self.in_file.

        In case the input file is already uncompressed, the original file is returned.
        In any other case, the input file is decompressed to a temporary file (potentially on disk).
        """
        self.window.clear()
        self.window.addstr(f"Loading contents from {self.in_file}")
        self.window.refresh()

        try:
            if self.in_file.suffix in [".zst", ".gz"]:
                self.window.erase()
                self.window.addstr(
                    f"Loading contents from {self.in_file}: Decompressing file ..."
                )
                self.window.refresh()

                file = tempfile.TemporaryFile()  # pylint: disable=consider-using-with

                match self.in_file.suffix:
                    case ".zst":
                        with self.in_file.open("rb") as in_file:
                            decomp = zstd.ZstdDecompressor()
                            decomp.copy_stream(in_file, file)
                    case ".gz":
                        with gzip.open(self.in_file, "rb") as in_file:
                            shutil.copyfileobj(in_file, file)
            else:
                file = self.in_file.open("rb")

            file.flush()

            return file  # type: ignore
        except Exception as e:
            raise ValueError("Unsupported file format") from e

    def parse_structure(self, file: BinaryIO | mmap.mmap) -> None:
        """
        Parses an (already uncompressed) penlog file to a skeleton containing structural information but no data.

        This process enables handling relatively large penlog entries efficiently by extracting information on the
        priority from each entry, which can later be used to quickly jump to adjacent entries of at least same priority.
        This is accomplished by the following two data structures:

            - self.entry_positions: Stores the absolute offsets of each penlog entry inside the input file.
                                    This offset can later be used to efficiently retrieve the data for a penlog entry
                                    from the input file without the need to store it in memory.
            - self.level_pointers: Stores the entries which have at least a certain priority (i.e. less or equal).
                                   More precisely, the indices of the corresponding entries in self.entry_positions.
                                   There exists on such list for each priority level.
                                   This allows to quickly find entries which are to be displayed inside a priority zone
                                   even if there are many entries with filtered out priority in between.
        """
        prio_prefix = b'"priority":'
        prio_prefix_len = len(prio_prefix)

        file.seek(0, 2)
        file_length = file.tell()
        file.seek(0)

        self.window.erase()
        self.window.addstr(
            f"Loading contents from {self.in_file}: Parsing structure ({0}%)"
        )
        self.window.refresh()

        prev_progress = 0
        num_entries = 0

        while True:
            n = file.tell()
            line = file.readline()

            if not line:
                break

            prio = PenlogPriority.INFO.value

            if line[0] == 60:  # <P> priority prefix
                prio = line[1] - 48
            elif line[0] != 123:  # no json
                prio = PenlogPriority.ERROR
            elif (pos := line.find(prio_prefix)) > 0:  # json with priority
                pos += prio_prefix_len

                while not 48 <= line[pos] <= 57:  # find first digit after key
                    pos += 1

                prio = line[pos] - 48

            for i in reversed(range(prio, PenlogPriority.TRACE + 1)):
                self.level_pointers[i].append(num_entries)

            self.entry_positions.append(n)
            num_entries += 1

            progress = n * 100 // file_length

            if progress >= prev_progress + 10:
                prev_progress = progress
                self.window.erase()
                self.window.addstr(
                    f"Loading contents from {self.in_file}: Parsing structure ({progress}%)"
                )
                self.window.refresh()

    @property
    def configuration(self) -> Configuration:
        return self.configuration_history[self.configuration_index]

    def new_configuration(self) -> None:
        self.configuration_index += 1
        self.configuration_history = self.configuration_history[
            : self.configuration_index
        ]
        self.configuration_history.append(deepcopy(self.configuration_history[-1]))

    def entry_zone(self, entry_id: int) -> PriorityZone:
        """
        Returns the zone into which the entry with the given id falls.

        :params entry_id: The index of the entry.
        :return: The zone into which the entry with the given id falls.
        """
        for zone in self.configuration.priority_zones:
            if entry_id >= zone.start and (zone.end is None or entry_id <= zone.end):
                return zone

        assert False

    def update_zones(self, new_zone: PriorityZone) -> None:
        """
        Inserts the given zone into the current set of zones.

        Adds a new list of zones into the zone history, which contains the previous zones and the new zone.
        In the process of integrating the new zone, itself as well as old zones may be altered or completely removed.
        It is guaranteed, that the zones are always ordered and do not overlap.

        :param new_zone: The zone to be added.
        """
        assert new_zone.end is not None

        self.new_configuration()

        i = 0

        while i < len(self.configuration.priority_zones) - 1:
            cur_zone = self.configuration.priority_zones[i]
            assert cur_zone.end is not None

            # If no intersection
            if new_zone.end < cur_zone.start or new_zone.start > cur_zone.end:
                i += 1
                continue

            # if current is contained in new
            if new_zone.start <= cur_zone.start and new_zone.end >= cur_zone.end:
                self.configuration.priority_zones.remove(cur_zone)
                continue

            # if new is contained in current
            if new_zone.start > cur_zone.start and new_zone.end < cur_zone.end:
                self.configuration.priority_zones.insert(
                    i + 1,
                    PriorityZone(new_zone.end + 1, cur_zone.end, cur_zone.priority),
                )
                cur_zone.end = new_zone.start - 1
                break

            # if new is intersecting from the left side
            if new_zone.end < cur_zone.end:
                cur_zone.start = new_zone.end + 1

            # if new is intersecting from the right side
            if new_zone.start > cur_zone.start:
                cur_zone.end = new_zone.start - 1

            i += 1

        # if new is contained in or intersecting from the left side into the last zone
        last_zone = self.configuration.priority_zones[-1]

        if new_zone.end >= last_zone.start:
            if new_zone.start >= last_zone.start:
                self.configuration.priority_zones.insert(
                    -1,
                    PriorityZone(
                        last_zone.start, new_zone.start - 1, last_zone.priority
                    ),
                )
            last_zone.start = new_zone.end + 1

        i = 0

        while new_zone.start > self.configuration.priority_zones[i].start:
            i += 1

        self.configuration.priority_zones.insert(i, new_zone)

    def format_text(self, text: str, entry: PenlogEntry) -> FormattedText:
        """
        Returns a formatted text according to the properties of the corresponding penlog entry.

        :param text: The text to be formatted.
        :param entry: The penlog entry to which the text corresponds.
        :return: The formatted text.
        """
        if entry.tags is not None and "JSON" in entry.tags:
            return FormattedText(
                text, curses.color_pair(self.color_ids[PenlogPriority.ERROR])
            )

        text_format = curses.color_pair(self.color_ids[entry.priority])

        if entry.priority < PenlogPriority.INFO:
            text_format = text_format | curses.A_BOLD

        return FormattedText(text, text_format)

    def default_text(self, text: str) -> FormattedText:
        """
        Returns a formatted text with the content of the given text and the default formatting.

        :param text: The text.
        :return: The formatted text.
        """
        return FormattedText(text, curses.color_pair(0))

    def formatted_entry(self, entry_id: int) -> list[DisplayEntry]:
        """
        Returns a list of formatted entries, each corresponding to a single line of the entry referred to by the
        given entry id, as displayed in the console.

        :param entry_id: The index of the entry.
        :return: The formatted display entries for the given entry.
        """
        entry = self.entries[entry_id]
        _, max_width = self.window.getmaxyx()

        prefix = ""
        prefix += entry.datetime.strftime("%b %d %H:%M:%S.%f")[:-3]
        prefix += " "
        prefix += entry.module
        if entry.tags is not None:
            prefix += f" [{', '.join(entry.tags)}]"
        prefix += ": "

        residual_width = max_width - len(prefix) - 1

        user_defined_lines = entry.data.splitlines()

        if len(user_defined_lines) == 0:
            user_defined_lines = [""]

        terminal_width_defined_lines = []

        for line in user_defined_lines:
            if len(line) == 0:
                terminal_width_defined_lines.append("")

            for i in range(ceil(len(line) / residual_width)):
                terminal_width_defined_lines.append(
                    line[i * residual_width : (i + 1) * residual_width]
                )

        result = [
            DisplayEntry(
                [
                    self.default_text(prefix),
                    self.format_text(terminal_width_defined_lines[0], entry),
                ],
                entry_id,
                0,
            )
        ]

        for i, line in enumerate(terminal_width_defined_lines[1:]):
            result.append(
                DisplayEntry(
                    [
                        self.default_text(" " * len(prefix)),
                        self.format_text(line, entry),
                    ],
                    entry_id,
                    i + 1,
                )
            )

        if self.configuration.interpret:
            if entry.interpretation is None:
                self.interpret_entry(entry)

            if entry.interpretation is not None:
                interpretation_text = f"  # {entry.interpretation}"

                while len(interpretation_text) > 0:
                    len_texts = 0

                    for text in result[-1].texts:
                        len_texts += len(text.text)

                    residual_width = max_width - len_texts - 1

                    result[-1].texts.append(
                        FormattedText(
                            interpretation_text[:residual_width],
                            curses.color_pair(entry.interpretation_color),
                        )
                    )

                    interpretation_text = interpretation_text[residual_width:]

                    if len(interpretation_text) > 0:
                        result.append(
                            DisplayEntry(
                                [self.default_text(" " * len(prefix))],
                                entry_id,
                                result[-1].entry_line_number,
                            )
                        )

        result[-1].last_line = True

        return result

    def interpret_entry(self, entry: PenlogEntry) -> None:
        """
        Adds an interpretation to the entry, if the entry can be identified as referring to a UDS request or response.

        :param entry: The entry to be interpreted.
        """
        try:
            if not entry.data.startswith("00"):
                data = unhexlify(entry.data)

                if data[0] & 0b01000000:
                    response = UDSResponse.parse_dynamic(data)
                    entry.interpretation = repr(response)

                    if isinstance(response, NegativeResponse):
                        entry.interpretation_color = (
                            InterpretationColor.UDS_NEGATIVE_RESPONSE
                        )
                    else:
                        entry.interpretation_color = (
                            InterpretationColor.UDS_POSITIVE_RESPONSE
                        )
                else:
                    entry.interpretation = repr(UDSRequest.parse_dynamic(data))
                    entry.interpretation_color = InterpretationColor.UDS_REQUEST
        except Exception as e:
            self.debug_log(repr(e))

    def check_filter(self, entry_id: int) -> bool:
        """
        Check if the entry which is referred to by the given entry id, is still to be displayed after applying filters.

        :param entry_id: The index of the entry.
        :return: The formatted display entries for the given entry.
        """
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)

            for command in self.configuration.filter:
                if not eval(command, self.entries[entry_id].__dict__):
                    return False

        return True

    def calculate_display_entries(
        self, start_entry: int, entry_line: int
    ) -> list[DisplayEntry]:
        """
        Returns a list of display entries starting from the given start entry, which qualify to be displayed by having
        a sufficient priority as well as passing any other filter.

        The display entries may start from a different entry than the one pointed to by the given parameter,
        in case that entry itself does not qualify itself.
        In that case previous entries are taken into account if the entry_line is set to -1
        and if there is at least oneprevious entry which qualifies.
        Otherwise only entries following the given one are taken into account.

        The number of entries which is returned is limited by the number of lines in the console.

        The list is guaranteed to be not empty.
        If there would be no entries to be displayed there will be an info message,
        which informs the user, that no entries are available with the current filtering settings.

        :param start_entry: The starting point for the search for the actual first entry (which qualifies) in the list.
        :param entry_line: The index in the list of formatted lines as created for the corresponding penlog entry.
                           Most importantly, a value of 0 indicates to start from the first line,
                           a value of -1 to start from the last line. Other negative values are not supported.
        :return: The list of display entries.
        """
        max_lines, _ = self.window.getmaxyx()
        max_lines -= 1
        display_entries: list[DisplayEntry] = []

        prio = self.entries[start_entry].priority
        zone = self.entry_zone(start_entry)

        fallback_entry = [
            DisplayEntry(
                [
                    self.default_text(
                        "No entries found! You can select a new priority on this line"
                    )
                ],
                0,
                0,
            )
        ]

        if prio > zone.priority or not self.check_filter(start_entry):
            if entry_line == -1:
                start_entry_ = self.previous_sufficient_entry(start_entry)

                if start_entry_ is None:
                    start_entry_ = self.next_sufficient_entry(0)

                    if start_entry_ is None:
                        return fallback_entry

                    entry_line = 0

                start_entry = start_entry_
            elif entry_line == 0:
                start_entry_ = self.next_sufficient_entry(start_entry)

                if start_entry_ is None:
                    return fallback_entry

                start_entry = start_entry_

            zone = self.entry_zone(start_entry)

        pointer = self.priority_pointer(start_entry, zone.priority)
        assert pointer is not None, f"{start_entry} {zone.priority}"

        i = 0

        while True:
            entry_id = self.level_pointers[zone.priority][pointer]
            new_lines = self.formatted_entry(entry_id)

            if i == 0:
                if entry_line == -1:
                    display_entries.append(new_lines[-1])
                else:
                    display_entries += new_lines[entry_line:]
            else:
                display_entries += new_lines

            if len(display_entries) > max_lines:
                break
            i += 1

            zone, pointer = self.next_sufficient_pointer(zone, pointer, entry_id)

            if pointer is None:
                break

        return display_entries[:max_lines]

    def next_sufficient_entry(self, entry_id: int) -> int | None:
        """
        Returns the index of the next entry after the given one,
        which has a sufficiently high priority to be displayed and also passes any filters.

        If no such entry exists None is returned.

        :param entry_id: The index of the entry in self.entries.
        :return: The index of the next sufficient entry after the given one or None, if no such entry exists.
        """
        prio = self.entries[entry_id].priority
        pointer = self.priority_pointer(entry_id, prio)
        assert pointer is not None
        zone, pointer = self.next_sufficient_pointer(None, pointer, entry_id)
        return (
            self.level_pointers[zone.priority][pointer] if pointer is not None else None
        )

    def previous_sufficient_entry(self, entry_id: int) -> int | None:
        """
        Returns the index of the previous entry after the given one,
        which has a sufficiently high priority to be displayed and also passes any filters.

        If no such entry exists None is returned.

        :param entry_id: The index of the entry in self.entries.
        :return: The index of the previous sufficient entry before the given one or None, if no such entry exists.
        """
        prio = self.entries[entry_id].priority
        pointer = self.priority_pointer(entry_id, prio)
        assert pointer is not None
        zone, pointer = self.previous_sufficient_pointer(None, pointer, entry_id)
        return (
            self.level_pointers[zone.priority][pointer] if pointer is not None else None
        )

    def next_sufficient_pointer(
        self, prio_zone: PriorityZone | None, pointer: int, entry_id: int
    ) -> tuple[PriorityZone, int | None]:
        """
        Returns the index of the next priority pointer after the given one,
        which has a sufficiently high priority to be displayed and also passes any filters,
        along with the priority zone to which it belongs.

        If no such pointer exists None is returned for the pointer.

        :param prio_zone: The zone into which the entry, to which the given pointer points, lies.
        :param pointer: The given pointer's index.
        :param entry_id: The index of the entry, to which the given pointer points, in self.entries.
        :return: The next priority pointer's index along the corresponding priority zone.
        """
        zone, ptr = self.next_sufficient_pointer_without_filters(
            prio_zone, pointer, entry_id
        )

        while ptr is not None and not self.check_filter(
            self.level_pointers[zone.priority][ptr]
        ):
            entry_id = self.level_pointers[zone.priority][ptr]
            zone, ptr = self.next_sufficient_pointer_without_filters(
                prio_zone, ptr, entry_id
            )

        return zone, ptr

    def previous_sufficient_pointer(
        self, prio_zone: PriorityZone | None, pointer: int, entry_id: int
    ) -> tuple[PriorityZone, int | None]:
        """
        Returns the index of the previous priority pointer before the given one,
        which has a sufficiently high priority to be displayed and also passes any filters,
        along with the priority zone to which it belongs.

        If no such pointer exists None is returned for the pointer.

        :param prio_zone: The zone into which the entry, to which the given pointer points, lies.
        :param pointer: The given pointer's index.
        :param entry_id: The index of the entry, to which the given pointer points, in self.entries.
        :return: The previous priority pointer's index along the corresponding priority zone.
        """
        zone, ptr = self.previous_sufficient_pointer_without_filters(
            prio_zone, pointer, entry_id
        )

        while ptr is not None and not self.check_filter(
            self.level_pointers[zone.priority][ptr]
        ):
            entry_id = self.level_pointers[zone.priority][ptr]
            zone, ptr = self.previous_sufficient_pointer_without_filters(
                prio_zone, ptr, entry_id
            )

        return zone, ptr

    def next_sufficient_pointer_without_filters(
        self, prio_zone: PriorityZone | None, pointer: int, entry_id: int
    ) -> tuple[PriorityZone, int | None]:
        """
        Returns the index of the next priority pointer after the given one,
        which has a sufficiently high priority to be displayed, along with the priority zone to which it belongs.

        If no such pointer exists None is returned for the pointer.

        :param prio_zone: The zone into which the entry, to which the given pointer points, lies.
        :param pointer: The given pointer's index.
        :param entry_id: The index of the entry, to which the given pointer points, in self.entries.
        :return: The next priority pointer's index along the corresponding priority zone.
        """
        for zone in self.configuration.priority_zones:
            if zone.end is not None and entry_id >= zone.end:
                continue

            prio_entries = self.level_pointers[zone.priority]

            if len(prio_entries) == 0:
                continue

            next_pointer: int | None

            if zone == prio_zone and pointer + 1 < len(prio_entries):
                next_pointer = pointer + 1
            else:
                next_pointer = self.priority_pointer(
                    max(entry_id, zone.start - 1), zone.priority, 1
                )

            if next_pointer is not None and (
                zone.end is None or prio_entries[next_pointer] <= zone.end
            ):
                return zone, next_pointer

        return self.configuration.priority_zones[-1], None

    def previous_sufficient_pointer_without_filters(
        self, prio_zone: PriorityZone | None, pointer: int, entry_id: int
    ) -> tuple[PriorityZone, int | None]:
        """
        Returns the index of the previous priority pointer before the given one,
        which has a sufficiently high priority to be displayed, along with the priority zone to which it belongs.

        If no such pointer exists None is returned for the pointer.

        :param prio_zone: The zone into which the entry, to which the given pointer points, lies.
        :param pointer: The given pointer's index.
        :param entry_id: The index of the entry, to which the given pointer points, in self.entries.
        :return: The previous priority pointer's index along the corresponding priority zone.
        """
        for zone in reversed(self.configuration.priority_zones):
            if entry_id <= zone.start:
                continue

            prio_entries = self.level_pointers[zone.priority]

            if len(prio_entries) == 0:
                continue

            prev_pointer: int | None

            if zone == prio_zone and pointer > 0:
                prev_pointer = pointer - 1
            else:
                prev_pointer = self.priority_pointer(
                    min(entry_id, zone.end + 1) if zone.end is not None else entry_id,
                    zone.priority,
                    -1,
                )

            if prev_pointer is not None and prio_entries[prev_pointer] >= zone.start:
                return zone, prev_pointer

        return self.configuration.priority_zones[0], None

    def priority_pointer(
        self, entry_id: int, prio: PenlogPriority, mode: int = 0
    ) -> int | None:
        """
        Returns the index of the level pointer of the entry with the given id,
        or depending on the mode the previous or next entry, in the level pointers with the given priority.

        Depending on the mode parameter different pointer indices can be retrieved:
         - case 0: The pointer which points to the exact same entry which is given as the entry id
         - case 1: - 1: The pointer with the next bigger entry_id in the level pointers compared to the given entry id
         - case -1: The pointer with the next smaller entry_id in the level pointers compared to the given entry id

         In none of these cases it can be guaranteed that such a pointer exists in the level pointers for the given
         priority. If no pointer exists, None is returned.

        :param entry_id: The index of the entry in self.entries.
        :param prio: The priority level for which the index in the corresponding level pointers should be calculated.
        :param mode: Determines which pointer index should be returned (must be any of 0, 1 or -1).
        :return: The index of the level pointer or None if no such pointer could be identified.
        """
        prio_entries = self.level_pointers[prio]

        upper = len(prio_entries) - 1
        lower = 0

        while True:
            pointer = (upper + lower) // 2

            if upper == lower + 1 and mode == -1:
                pointer = upper

            prio_entry = prio_entries[pointer]

            if upper == lower:
                break

            # Find the exact match
            if mode == 0:
                if prio_entry > entry_id:
                    upper = max(lower, pointer - 1)
                elif prio_entry < entry_id:
                    lower = min(pointer + 1, upper)
                else:
                    break

            # Find the next bigger entry
            if mode == 1:
                if prio_entry > entry_id:
                    upper = max(lower, pointer)
                else:
                    lower = min(pointer + 1, upper)

            # Find the next smaller entry
            if mode == -1:
                if prio_entry >= entry_id:
                    upper = max(lower, pointer - 1)
                else:
                    lower = min(pointer, upper)

        if mode == 0 and prio_entry != entry_id:
            return None

        if mode == 1 and prio_entry <= entry_id:
            return None

        if mode == -1 and prio_entry >= entry_id:
            return None

        return pointer

    def handle_io(self) -> None:
        start_entry: int | None = None
        max_lines, max_columns = self.window.getmaxyx()
        max_lines -= 1
        filter_history = [self.configuration.filter]

        display_entries = self.calculate_display_entries(0, 0)
        self.display(
            display_entries, self.status(display_entries, (len(display_entries) - 1, 0))
        )
        prefix_length = 0
        cursor = (0, prefix_length)
        self.window.move(*cursor)

        def update_selected_zones(prio: PenlogPriority) -> None:
            nonlocal start_entry
            nonlocal display_entries
            nonlocal cursor
            nonlocal max_lines

            if start_entry is None:
                return

            stop_display_entry = display_entries[
                min(cursor[0], len(display_entries) - 1)
            ]
            stop_entry = stop_display_entry.penlog_entry_number

            if start_entry == stop_entry:
                start_entry = self.previous_sufficient_entry(start_entry)
                stop_entry_ = self.next_sufficient_entry(stop_entry)

                if start_entry is None:
                    start_entry = 0

                if stop_entry_ is None:
                    stop_entry = len(self.entries) - 1
                else:
                    stop_entry = stop_entry_

            self.update_zones(
                PriorityZone(
                    min(start_entry, stop_entry), max(start_entry, stop_entry), prio
                )
            )
            start_entry = None

        while (key := self.window.getkey()) != "q":
            entry_start = display_entries[0].penlog_entry_number
            line_start = display_entries[0].entry_line_number
            cursor = curses.getsyx()
            max_lines, max_columns = self.window.getmaxyx()
            max_lines -= 1

            def page_up() -> None:
                nonlocal entry_start
                nonlocal line_start
                nonlocal display_entries

                for _ in range(max_lines - 1):
                    old_entry_start = entry_start
                    old_line_start = line_start

                    if display_entries[0].entry_line_number == 0:
                        if entry_start > 0:
                            entry_start = max(
                                0, display_entries[0].penlog_entry_number - 1
                            )
                            line_start = -1
                    else:
                        line_start = display_entries[0].entry_line_number - 1

                    if old_entry_start == entry_start and old_line_start == line_start:
                        break

                    display_entries = self.calculate_display_entries(
                        entry_start, line_start
                    )

            def line_up() -> None:
                nonlocal entry_start
                nonlocal line_start

                if display_entries[0].entry_line_number == 0:
                    if entry_start > 0:
                        entry_start = max(0, entry_start - 1)
                        line_start = -1
                else:
                    line_start -= 1

            match key:
                case "KEY_UP":
                    if cursor[0] > 0:
                        cursor = (cursor[0] - 1, cursor[1])
                    else:
                        line_up()
                case "KEY_DOWN":
                    if cursor[0] < max_lines - 1:
                        cursor = cursor[0] + 1, cursor[1]
                    else:
                        if display_entries[0].last_line:
                            entry_start = min(len(self.entries) - 1, entry_start + 1)
                            line_start = 0
                        else:
                            line_start += 1
                case "KEY_PPAGE":
                    if cursor[0] > 0:
                        cursor = (0, cursor[1])
                    else:
                        page_up()
                case "KEY_NPAGE":
                    if cursor[0] < len(display_entries) - 1:
                        cursor = (len(display_entries) - 1, cursor[1])
                    else:
                        entry_start = display_entries[-1].penlog_entry_number
                        line_start = display_entries[-1].entry_line_number
                case "g":
                    entry_start = 0
                    line_start = 0
                    cursor = (0, cursor[1])
                case "G":
                    entry_start = len(self.entries) - 1
                    line_start = -1

                    display_entries = self.calculate_display_entries(
                        entry_start, line_start
                    )
                    page_up()
                    cursor = (len(display_entries) - 1, cursor[1])
                case "KEY_LEFT":
                    if cursor[1] > 0:
                        self.window.move(cursor[0], cursor[1] - 1)
                        continue
                case "KEY_RIGHT":
                    if cursor[1] < max_columns - 1:
                        self.window.move(cursor[0], cursor[1] + 1)
                        continue
                case "v" | "V":
                    if cursor[0] < len(display_entries):
                        start_entry = display_entries[cursor[0]].penlog_entry_number
                # TODO: this is chr(curses.ascii.ESC); but that's no pattern.
                case "\x1b":
                    start_entry = None
                case "p" | "P":
                    function_key = key

                    while (key := self.window.getkey()) != "q":
                        if key == chr(curses.ascii.ESC):
                            start_entry = None
                            break

                        match key:
                            case "m":
                                prio = PenlogPriority.EMERGENCY
                            case "a":
                                prio = PenlogPriority.ALERT
                            case "c":
                                prio = PenlogPriority.CRITICAL
                            case "e":
                                prio = PenlogPriority.ERROR
                            case "w":
                                prio = PenlogPriority.WARNING
                            case "n":
                                prio = PenlogPriority.NOTICE
                            case "i":
                                prio = PenlogPriority.INFO
                            case "d":
                                prio = PenlogPriority.DEBUG
                            case "t":
                                prio = PenlogPriority.TRACE
                            case _:
                                continue

                        if function_key == "p":
                            update_selected_zones(prio)
                        else:
                            self.new_configuration()
                            self.configuration.priority_zones = [
                                PriorityZone(0, None, prio)
                            ]

                        break
                case "u":
                    self.configuration_index = max(0, self.configuration_index - 1)
                case "r":
                    self.configuration_index = min(
                        len(self.configuration_history) - 1,
                        self.configuration_index + 1,
                    )
                case "i":
                    self.new_configuration()
                    self.configuration.interpret = not self.configuration.interpret
                case "f":
                    # fh is short for filter_history to reduce long unreadable lines
                    fh_tmp = list(
                        "; ".join(filter_commands) for filter_commands in filter_history
                    )
                    fh_tmp.append("")
                    fh_index = len(fh_tmp) - 1

                    filter_cursor = len(fh_tmp[fh_index])
                    input_format = curses.color_pair(0)

                    self.display(
                        display_entries, [FormattedText(fh_tmp[fh_index], input_format)]
                    )
                    self.window.move(max_lines, filter_cursor)

                    while (key := self.window.getkey()) != chr(curses.ascii.ESC):
                        match key:
                            case "\n":
                                try:
                                    filter_tmp = parse_filter(fh_tmp[fh_index])
                                    self.debug_log(filter_tmp)
                                    filter_history.append(filter_tmp)
                                    self.new_configuration()
                                    self.configuration.filter = filter_tmp
                                    break
                                except Exception:
                                    pass

                            case "KEY_BACKSPACE":
                                if filter_cursor > 0:
                                    fh_tmp[fh_index] = (
                                        fh_tmp[fh_index][: filter_cursor - 1]
                                        + fh_tmp[fh_index][filter_cursor:]
                                    )
                                    filter_cursor -= 1
                            case "KEY_DC":
                                if filter_cursor < len(fh_tmp[fh_index]):
                                    fh_tmp[fh_index] = (
                                        fh_tmp[fh_index][:filter_cursor]
                                        + fh_tmp[fh_index][filter_cursor + 1 :]
                                    )
                            case "KEY_LEFT":
                                if filter_cursor > 0:
                                    filter_cursor -= 1
                            case "KEY_RIGHT":
                                if filter_cursor < len(fh_tmp[fh_index]):
                                    filter_cursor += 1
                            case "KEY_UP":
                                fh_index = max(0, fh_index - 1)
                            case "KEY_DOWN":
                                fh_index = min(len(fh_tmp) - 1, fh_index + 1)
                            case _:
                                fh_tmp[fh_index] = (
                                    fh_tmp[fh_index][:filter_cursor]
                                    + key
                                    + fh_tmp[fh_index][filter_cursor:]
                                )
                                filter_cursor += 1

                        try:
                            parse_filter(fh_tmp[fh_index])
                            input_format = curses.color_pair(0)
                        except Exception:
                            input_format = curses.color_pair(
                                self.color_ids[PenlogPriority.WARNING]
                            )

                        self.display(
                            display_entries,
                            [FormattedText(fh_tmp[fh_index], input_format)],
                        )
                        self.window.move(
                            max_lines, min(filter_cursor, len(fh_tmp[fh_index]))
                        )

            display_entries = self.calculate_display_entries(entry_start, line_start)

            previous_entry_start = 0
            previous_line_start = 0

            while len(display_entries) < max_lines and (
                previous_entry_start != entry_start or previous_line_start != line_start
            ):
                previous_entry_start = entry_start
                previous_line_start = line_start
                entry_start = display_entries[0].penlog_entry_number
                line_start = display_entries[0].entry_line_number
                line_up()
                display_entries = self.calculate_display_entries(
                    entry_start, line_start
                )

            if start_entry is not None:
                stop_entry = display_entries[
                    min(cursor[0], len(display_entries) - 1)
                ].penlog_entry_number

                for entry in display_entries:
                    if (
                        min(start_entry, stop_entry)
                        <= entry.penlog_entry_number
                        <= max(start_entry, stop_entry)
                    ):
                        for text in entry.texts:
                            text.format = text.format | curses.A_REVERSE

            self.display(display_entries, self.status(display_entries, cursor))
            self.window.move(min(cursor[0], len(display_entries) - 1), cursor[1])

    def status(
        self, display_entries: list[DisplayEntry], cursor: tuple[int, int]
    ) -> list[FormattedText]:
        selected_entry = display_entries[min(cursor[0], len(display_entries) - 1)]
        entry_number = selected_entry.penlog_entry_number + 1
        n = len(self.entries)
        zone = self.entry_zone(selected_entry.penlog_entry_number)
        zone_info = self.default_text(
            f"Zone {self.configuration.priority_zones.index(zone): >2} ({zone.priority.name})"
        )
        progress = self.default_text(
            f"{entry_number: >{len(str(n))}}/{n} ({(entry_number / n) * 100:6.2f}%)"
        )
        _, max_columns = self.window.getmaxyx()
        spacing = self.default_text(
            " " * (max_columns - 1 - len(zone_info.text) - len(progress.text))
        )
        return [zone_info, spacing, progress]

    def display(
        self, display_entries: list[DisplayEntry], status_line: list[FormattedText]
    ) -> None:
        self.window.erase()

        for i, display_entry in enumerate(display_entries):
            for text in display_entry.texts:
                try:
                    self.window.addstr(text.text, text.format)
                except ValueError:
                    self.window.addstr(text.sanitized_text, text.format)

            if i < len(display_entries) - 1:
                self.window.addstr("\n")

        self.window.move(self.window.getmaxyx()[0] - 1, 0)

        for text in status_line:
            try:
                self.window.addstr(text.text, text.format)
            except ValueError:
                self.window.addstr(text.sanitized_text, text.format)

    def debug_log(self, msg: Any) -> None:
        debug_path = Path("/tmp/cursed_log")

        try:
            with debug_path.open("a", encoding="utf-8") as f:
                f.write(str(msg) + "\n")
        except Exception:
            pass


def parse_filter(text: str) -> list[str]:
    test_entry = PenlogEntry(
        module="component",
        data="data",
        host="host",
        priority=PenlogPriority.INFO,
        datetime=datetime.fromtimestamp(0),
        tags=[],
    )

    commands = list(
        command.strip() for command in text.split(";") if len(command.strip()) > 0
    )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)

        for command in commands:
            eval(command, test_entry.__dict__)

    return commands


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("file", type=Path)
    parser.add_argument(
        "--priority", "-p", type=PenlogPriority.from_str, default=PenlogPriority.DEBUG
    )
    parser.add_argument("--filter", "-f", type=parse_filter, default=None)
    args = parser.parse_args()
    CursedHR(args.file, args.priority, args.filter)


if __name__ == "__main__":
    main()
