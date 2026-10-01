# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""Interactive curses based viewer for penlog files (``hr --cursed``).

Only a compact index of the file lives in memory (see
:class:`gallia.log.PenlogReader`); records are parsed when they are
displayed and kept in a bounded LRU cache.
"""

import asyncio
import curses
import datetime
import functools
import json
import os
import re
import signal
import sys
import textwrap
import time
from bisect import bisect_right
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import wcwidth

from gallia.cli.hr import wireshark
from gallia.cli.hr.filters import FILTER_SYNTAX, FilterError, RecordFilter
from gallia.cli.hr.formatting import DISSECTION_COLORS, RecordFormatter, dissect_record
from gallia.cli.hr.terminal import detect_background
from gallia.dissect import Dissection
from gallia.log import (
    ConsoleColor,
    Loglevel,
    PenlogPriority,
    PenlogReader,
    PenlogRecord,
    format_timestamp,
    level_style,
)

PRIORITY_KEYS = {
    "m": PenlogPriority.EMERGENCY,
    "a": PenlogPriority.ALERT,
    "c": PenlogPriority.CRITICAL,
    "e": PenlogPriority.ERROR,
    "w": PenlogPriority.WARNING,
    "n": PenlogPriority.NOTICE,
    "i": PenlogPriority.INFO,
    "d": PenlogPriority.DEBUG,
    "t": PenlogPriority.TRACE,
}

HELP = """\
Navigation
  Up/Down, k/j        move the cursor
  PgUp/PgDn           move the cursor by one page
  Home/End, g/G       jump to the start/end of the file

Actions
  p <prio>            set the priority of the marked range; without a
                      marked range, showing more affects the hidden records
                      around the cursor, showing less the cursor's zone
  P <prio>            set the priority of the entire file
  v                   start/stop marking a range; ESC cancels
  Enter               inspect the record under the cursor (decoded JSON,
                      raw record; n/N for the next/previous record)
  f                   edit the filter (see below); Up/Down browse the history
  d                   toggle dissection of protocol messages, e.g. UDS
  x                   toggle the prefix (timestamp, module, tags)
  t                   toggle absolute/relative timestamps
  z                   set the reference time for relative timestamps
  u / r               undo/redo priority, filter and dissection changes
  ?                   show this help
  q                   quit

Mouse
  click               move the cursor; a double click inspects the record
  wheel               scroll
  Shift + drag        select text (handled by the terminal)

Priority keys
{priorities}

Filter
{filter}"""

Segment = tuple[str, int]  # text and curses attributes
Row = list[Segment]

# Not available in all builds of curses.
BUTTON5_PRESSED: int = getattr(curses, "BUTTON5_PRESSED", 0)


@dataclass(frozen=True)
class MouseEvent:
    x: int
    y: int
    state: int

    @property
    def wheel(self) -> int:
        """-1 for scrolling up, 1 for scrolling down, 0 otherwise."""
        if self.state & curses.BUTTON4_PRESSED:
            return -1
        if self.state & BUTTON5_PRESSED:
            return 1
        return 0

    @property
    def clicked(self) -> bool:
        return bool(self.state & (curses.BUTTON1_PRESSED | curses.BUTTON1_CLICKED))

    @property
    def double_clicked(self) -> bool:
        return bool(self.state & curses.BUTTON1_DOUBLE_CLICKED)


_PRIORITY_WIDTH = max(len(p.name) for p in PenlogPriority)

# Keys (characters or curses key codes) and mouse events.
Event = str | int | MouseEvent

_KEY_NAMES: dict[str | int, str] = {
    curses.KEY_UP: "↑",
    curses.KEY_DOWN: "↓",
    curses.KEY_LEFT: "←",
    curses.KEY_RIGHT: "→",
    curses.KEY_PPAGE: "PgUp",
    curses.KEY_NPAGE: "PgDn",
    curses.KEY_HOME: "Home",
    curses.KEY_END: "End",
    curses.KEY_ENTER: "Enter",
    curses.KEY_BACKSPACE: "Backspace",
    curses.KEY_DC: "Del",
    curses.KEY_RESIZE: "resize",
    "\n": "Enter",
    "\r": "Enter",
    "\x1b": "Esc",
    " ": "Space",
    "\x7f": "Backspace",
}


def key_name(event: Event) -> str:
    """Returns a short, readable name of a key or mouse event."""
    if isinstance(event, MouseEvent):
        if event.double_clicked:
            return "double click"
        return {-1: "wheel ↑", 1: "wheel ↓"}.get(event.wheel, "click" if event.clicked else "mouse")
    if (name := _KEY_NAMES.get(event)) is not None:
        return name
    if isinstance(event, str):
        # Control characters in caret notation, e.g. "\x01" is ^A.
        return f"^{chr(ord(event) + ord('@'))}" if event < " " else event
    try:
        return curses.keyname(event).decode()
    except (curses.error, ValueError):
        return str(event)


_CONTROL_CHARS = {i: "�" for i in [*range(0x20), 0x7F] if i != ord("\t")}


@dataclass(frozen=True)
class View:
    """The settings which select the displayed entries.
    It is immutable; every change is a new item in the undo history."""

    # Sorted (start, priority) pairs; a zone lasts until the next one starts.
    zones: tuple[tuple[int, PenlogPriority], ...]
    filter: RecordFilter
    dissect: bool = False

    def zone_index(self, entry: int) -> int:
        return bisect_right(self.zones, entry, key=lambda z: z[0]) - 1

    def zone_bounds(self, index: int, n_entries: int) -> tuple[int, int, PenlogPriority]:
        """Returns ``(start, end, priority)`` of a zone; ``end`` is exclusive."""
        start, priority = self.zones[index]
        end = self.zones[index + 1][0] if index + 1 < len(self.zones) else n_entries
        return start, end, priority

    def with_priority(
        self, start: int, end: int, priority: PenlogPriority, n_entries: int
    ) -> "View":
        """Returns a copy where the entries ``[start, end)`` use ``priority``."""
        zones = [z for z in self.zones if z[0] < start]
        zones.append((start, priority))
        if end < n_entries:
            zones.append((end, self.zones[self.zone_index(end)][1]))
        zones += [z for z in self.zones if z[0] > end]

        merged: list[tuple[int, PenlogPriority]] = []
        for zone in zones:
            if not merged or merged[-1][1] != zone[1]:
                merged.append(zone)
        return replace(self, zones=tuple(merged))


def wrap(text: str, width: int) -> list[str]:
    rows: list[str] = []
    for raw_line in text.splitlines() or [""]:
        line = raw_line.translate(_CONTROL_CHARS)
        # textwrap is much faster; wcwidth is only needed for wide characters.
        wrapped = textwrap.wrap(line, width) if line.isascii() else wcwidth.wrap(line, width)
        rows += wrapped or [""]
    return rows


_JSON_TOKEN = re.compile(
    r'(?P<key>"(?:[^"\\]|\\.)*")(?=\s*:)'
    r'|(?P<string>"(?:[^"\\]|\\.)*")'
    r"|(?P<number>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)"
    r"|(?P<literal>\b(?:true|false|null)\b)"
)


def chunks(text: str, width: int) -> list[str]:
    """Splits text into rows of ``width`` characters; unlike wrap(), the
    text is preserved exactly (apart from control characters)."""
    text = text.translate(_CONTROL_CHARS)
    return [text[i : i + width] for i in range(0, len(text), width)] or [""]


def wrap_row(row: Row, width: int, indent: int = 0) -> list[Row]:
    """Wraps a row of formatted text at ``width`` characters; continuation
    rows are indented by ``indent`` characters."""
    rows: list[Row] = [[]]
    used = 0
    for text, attr in row:
        pos = 0
        while pos < len(text):
            if used >= width:
                rows.append([(" " * indent, 0)])
                used = indent
            part = text[pos : pos + width - used]
            rows[-1].append((part, attr))
            used += len(part)
            pos += len(part)
    return rows


def cells(text: str) -> int:
    """Returns the number of terminal cells needed for ``text``."""
    return n if (n := wcwidth.wcswidth(text)) >= 0 else len(text)


class Colors:
    """The curses attributes; the colors of the records and dissections
    are the same as for hr without --cursed, see level_style()."""

    def __init__(self, theme: str = "dark") -> None:
        self._pairs: dict[tuple[int, int], int] = {}
        self._foregrounds: dict[int, int] = {}
        self._has_colors = curses.has_colors()
        if self._has_colors:
            curses.use_default_colors()
        many = self._has_colors and curses.COLORS >= 256
        # The background of the cursor line: a subtle gray, which depends
        # on the background of the terminal (see terminal.py).
        self._highlight = (236 if theme == "dark" else 254) if many else None
        self._console_colors = {
            ConsoleColor.RED: curses.COLOR_RED,
            ConsoleColor.GREEN: curses.COLOR_GREEN,
            ConsoleColor.YELLOW: curses.COLOR_YELLOW,
            ConsoleColor.BLUE: curses.COLOR_BLUE,
            ConsoleColor.PURPLE: curses.COLOR_MAGENTA,
            ConsoleColor.CYAN: curses.COLOR_CYAN,
            ConsoleColor.WHITE: curses.COLOR_WHITE,
            ConsoleColor.GRAY: 245 if many else curses.COLOR_WHITE,
            ConsoleColor.ORANGE: 208 if many else curses.COLOR_RED,
        }

        self.levels: dict[int, int] = {
            level: self.console(*level_style(level)) for level in Loglevel
        }
        self.dissections = {kind: self.console(color) for kind, color in DISSECTION_COLORS.items()}
        self.invalid = self.console(ConsoleColor.YELLOW)
        self.heading = curses.A_BOLD
        self.json_key = self.console(ConsoleColor.CYAN)
        self.json_string = self.console(ConsoleColor.GREEN)
        self.json_number = self.console(ConsoleColor.PURPLE)
        self.json_literal = self.console(ConsoleColor.YELLOW)
        self.status = curses.A_REVERSE

    def _pair(self, fg: int, bg: int = -1) -> int:
        if (pair := self._pairs.get((fg, bg))) is None:
            number = len(self._pairs) + 1
            curses.init_pair(number, fg, bg)
            pair = self._pairs[(fg, bg)] = int(curses.color_pair(number))
            self._foregrounds[pair] = fg
        return pair

    def highlight(self, attr: int) -> int:
        """Returns ``attr`` with the background of the cursor line."""
        if self._highlight is None:
            return attr | curses.A_UNDERLINE
        fg = self._foregrounds.get(attr & curses.A_COLOR, -1)
        return (attr & ~curses.A_COLOR) | self._pair(fg, self._highlight)

    def console(self, color: ConsoleColor, bold: bool = False) -> int:
        """Returns the curses attribute for a console color."""
        attr = curses.A_BOLD if bold else curses.A_NORMAL
        if self._has_colors and (fg := self._console_colors.get(color)) is not None:
            attr |= self._pair(fg)
        return attr

    def level(self, levelno: int) -> int:
        if (attr := self.levels.get(levelno)) is None:
            attr = self.console(*level_style(levelno))
        return attr


class TerminalProgress:
    """Shows a progress bar natively in the terminal, e.g. in the tab or the
    taskbar, via OSC 9;4. It is supported by Windows Terminal, ConEmu,
    Ghostty, WezTerm, iTerm2 >= 3.6, and others; most terminals ignore it."""

    REMOVE = 0
    NORMAL = 1
    ERROR = 2
    INDETERMINATE = 3

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._last: tuple[int, int] | None = None

    @staticmethod
    def supported() -> bool:
        # Older versions of iTerm2 show OSC 9 as a notification.
        if os.environ.get("TERM_PROGRAM") == "iTerm.app":
            version = [
                int(v) for v in re.findall(r"\d+", os.environ.get("TERM_PROGRAM_VERSION", ""))
            ]
            return version[:2] >= [3, 6]
        return True

    def set(self, state: int, percent: int = 0) -> None:
        if not self.enabled or (state, percent) == self._last:
            return
        self._last = (state, percent)
        try:
            os.write(sys.stdout.fileno(), f"\x1b]9;4;{state};{percent}\x1b\\".encode())
        except OSError:
            pass

    def update(self, reader: PenlogReader) -> None:
        if reader.index_complete:
            if reader.error is not None:
                self.set(self.ERROR, 100)
            else:
                self.set(self.REMOVE)
        elif (progress := reader.index_progress) is None:
            self.set(self.INDETERMINATE)
        else:
            self.set(self.NORMAL, int(progress * 100))


class Viewer:
    def __init__(
        self,
        screen: Any,
        reader: PenlogReader,
        view: View,
        formatter: RecordFormatter,
        terminal_progress: bool,
        theme: str = "dark",
    ) -> None:
        self.screen = screen
        self.terminal_progress = TerminalProgress(terminal_progress)
        self.reader = reader
        self.colors = Colors(theme)
        # Keys, or None if only a redraw is needed, e.g. on indexing progress.
        self.events: asyncio.Queue[Event | None] = asyncio.Queue()
        self._redraw_pending = False
        # The last key is shown in the status line; busy while handling it.
        self.last_key = ""
        self.busy = False

        self.history = [view]
        self.history_index = 0
        self.filter_history = [view.filter.text] if view.filter else []

        # The dissection setting is part of the view (for undo/redo).
        self.formatter = formatter

        # Only the entries around the visible part of the file are cached.
        self.record = functools.lru_cache(maxsize=2048)(self._load_record)
        self.dissection = functools.lru_cache(maxsize=2048)(self._dissect)
        # Running tshark takes a while; only for the record view.
        self.wireshark = functools.lru_cache(maxsize=64)(self._wireshark)
        self.has_wireshark = wireshark.available()
        self._render = functools.lru_cache(maxsize=2048)(self._render_uncached)
        # Searching visible entries might be slow with sparse filters; the
        # same searches are repeated a lot while drawing and scrolling.
        self._next_visible = functools.lru_cache(maxsize=4096)(self._next_visible_uncached)
        self._prev_visible = functools.lru_cache(maxsize=4096)(self._prev_visible_uncached)
        # (entry, view) -> n: There is no visible entry in [entry, n). While
        # indexing, only the new entries need to be searched then.
        self._exhausted: dict[tuple[int, View], int] = {}

        # Read the first page; the rest is indexed in the background.
        while reader.indexed < self.height and not reader.update_index(self.height):
            pass

        # Screen position: first entry, and its first shown row.
        self.top: tuple[int, int] | None = None
        self.cursor = 0
        self.mark: int | None = None
        self.message = ""

    # ------------------------------------------------------------------
    # Model
    # ------------------------------------------------------------------

    @property
    def view(self) -> View:
        return self.history[self.history_index]

    @property
    def n_entries(self) -> int:
        """The number of entries indexed so far; grows while indexing."""
        return self.reader.indexed

    def _load_record(self, entry: int) -> PenlogRecord:
        try:
            return self.reader[entry]
        except (ValueError, KeyError, TypeError):
            return PenlogRecord(
                module="JSON",
                host="",
                data=self.reader.raw(entry).decode(errors="replace"),
                datetime=datetime.datetime.fromtimestamp(0, tz=datetime.UTC),
                priority=PenlogPriority.ERROR,
                tags=["invalid"],
            )

    def _dissect(self, entry: int) -> Dissection | None:
        return dissect_record(self.record(entry))

    def protocol(self, entry: int) -> str | None:
        """The protocol of an entry; UDS for entries without protocol, e.g.
        of older logfiles, if they can be dissected as UDS."""
        if (proto := self.record(entry).proto) is not None:
            return proto
        return "uds" if self.dissection(entry) is not None else None

    def _wireshark(self, entry: int) -> list[str] | None:
        if not self.has_wireshark or (proto := self.protocol(entry)) is None:
            return None
        return wireshark.dissect(proto, self.record(entry).data)

    def matches_filter(self, entry: int) -> bool:
        record_filter = self.view.filter
        if not record_filter:
            return True
        return record_filter.may_match(self.reader.raw(entry)) and record_filter(self.record(entry))

    def _next_candidate(self, entry: int, end: int, priority: int) -> int | None:
        """Returns the first entry in ``[entry, end)`` with the priority whose raw
        bytes match the filter's raw patterns. This does not parse any entries."""
        patterns = self.view.filter.raw_patterns
        while True:
            # Leapfrog over all conditions until they agree on an entry; the
            # rarest condition determines the jumps. All searches are fast.
            candidate = self.reader.find(priority, entry, end)
            if candidate is None:
                return None
            for pattern in patterns:
                match = self.reader.search(pattern, candidate, end)
                if match is None:
                    return None
                if match != candidate:
                    entry = match
                    break
            else:
                return candidate

    def _prev_candidate(self, start: int, entry: int, priority: int) -> int | None:
        """Like ``_next_candidate``, but returns the last entry in ``[start, entry)``."""
        patterns = self.view.filter.raw_patterns
        while True:
            candidate = self.reader.rfind(priority, start, entry)
            if candidate is None:
                return None
            for pattern in patterns:
                match = self.reader.rsearch(pattern, start, candidate + 1)
                if match is None:
                    return None
                if match != candidate:
                    entry = match + 1
                    break
            else:
                return candidate

    def next_visible(self, entry: int) -> int | None:
        """Returns the first visible entry which is ``>= entry``."""
        key = (entry, self.view)
        start = max(entry, self._exhausted.get(key, entry))
        found = self._next_visible(start, self.view, self.n_entries)
        if found is None and not self.reader.index_complete:
            if len(self._exhausted) > 10_000:
                self._exhausted.clear()
            self._exhausted[key] = self.n_entries
        return found

    def prev_visible(self, entry: int) -> int | None:
        """Returns the last visible entry which is ``<= entry``."""
        # Entries before the end of the index do not change while indexing.
        return self._prev_visible(min(entry, self.n_entries - 1), self.view)

    def _next_visible_uncached(self, entry: int, view: View, n_entries: int) -> int | None:
        del n_entries  # Only part of the cache key.
        if entry >= self.n_entries:
            return None
        entry = max(entry, 0)
        for zone in range(view.zone_index(entry), len(view.zones)):
            start, end, priority = view.zone_bounds(zone, self.n_entries)
            i = max(entry, start)
            while (found := self._next_candidate(i, end, priority)) is not None:
                if self.matches_filter(found):
                    return found
                i = found + 1
        return None

    def _prev_visible_uncached(self, entry: int, view: View) -> int | None:
        if entry < 0:
            return None
        for zone in range(view.zone_index(entry), -1, -1):
            start, end, priority = view.zone_bounds(zone, self.n_entries)
            i = min(entry + 1, end)
            while (found := self._prev_candidate(start, i, priority)) is not None:
                if self.matches_filter(found):
                    return found
                i = found
        return None

    def nearest_visible(self, entry: int) -> int | None:
        if (i := self.next_visible(entry)) is not None:
            return i
        return self.prev_visible(entry)

    def push_view(self, view: View) -> None:
        anchor = self.cursor_entry()
        self.history = self.history[: self.history_index + 1] + [view]
        self.history_index += 1
        self.focus(anchor)

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    @property
    def height(self) -> int:
        lines: int = self.screen.getmaxyx()[0]
        return max(lines - 1, 1)

    @property
    def width(self) -> int:
        columns: int = self.screen.getmaxyx()[1]
        return columns

    def render(self, entry: int) -> list[Row]:
        """Returns the screen rows of an entry."""
        settings = (
            self.width,
            self.formatter.prefix,
            self.formatter.relative_timings,
            self.formatter.reference_time,
            self.view.dissect,
        )
        return self._render(entry, settings)

    def _render_uncached(self, entry: int, settings: tuple[Any, ...]) -> list[Row]:
        del settings  # Only part of the cache key.
        record = self.record(entry)
        prefix = self.formatter.format_prefix(record)
        text_width = max(self.width - 1 - cells(prefix), 20)
        attr = self.colors.level(record.level)

        texts = wrap(record.data, text_width)
        indent = " " * len(prefix)
        rows: list[Row] = [
            [(prefix if i == 0 else indent, curses.A_NORMAL), (text, attr)]
            for i, text in enumerate(texts)
        ]

        if self.view.dissect and (dissection := self.dissection(entry)) is not None:
            comment = f"  # {dissection.text}"
            comment_attr = self.colors.dissections[dissection.kind]
            if cells(texts[-1]) + cells(comment) <= text_width:
                rows[-1].append((comment, comment_attr))
            else:
                for line in wrap(comment.strip(), text_width):
                    rows.append([(indent, curses.A_NORMAL), (line, comment_attr)])

        if record.stacktrace is not None:
            # Like hr without --cursed: after an empty line, not colored.
            rows.append([(indent, curses.A_NORMAL)])
            for line in wrap(record.stacktrace, text_width):
                rows.append([(indent, curses.A_NORMAL), (line, curses.A_NORMAL)])

        return rows

    def frame(self) -> list[tuple[int, Row]]:
        """Returns the rows which fit on the screen, starting at ``self.top``."""
        rows: list[tuple[int, Row]] = []
        if self.top is None:
            return rows

        entry: int | None
        entry, skip = self.top
        while entry is not None:
            for row in self.render(entry)[skip:]:
                rows.append((entry, row))
                if len(rows) == self.height:
                    return rows
            skip = 0
            entry = self.next_visible(entry + 1)
        return rows

    def cursor_entry(self, frame: list[tuple[int, Row]] | None = None) -> int:
        """Returns the entry under the cursor; ``frame`` avoids recomputing it."""
        if frame is None:
            frame = self.frame()
        if len(frame) == 0:
            return self.top[0] if self.top is not None else 0
        return frame[min(self.cursor, len(frame) - 1)][0]

    def selection(self, priority: PenlogPriority) -> tuple[int, int]:
        """Returns the entries ``[start, end)`` for changing the priority
        to ``priority``: the marked range, if any. Otherwise, for showing
        more, the hidden entries around the cursor; for showing less, the
        zone of the cursor. This is where the change has an effect."""
        entry = self.cursor_entry()
        if self.mark is not None and self.mark != entry:
            return min(self.mark, entry), max(self.mark, entry) + 1
        start, end, current = self.view.zone_bounds(self.view.zone_index(entry), self.n_entries)
        if priority <= current:
            return start, end
        prev = self.prev_visible(entry - 1)
        next_ = self.next_visible(entry + 1)
        return (
            prev + 1 if prev is not None else 0,
            next_ if next_ is not None else self.n_entries,
        )

    def record_info(self, entry: int) -> str:
        """Returns information on a record for the status line."""
        record = self.record(entry)
        # Fixed widths first, so that the status line does not jump around.
        parts = [
            f"{record.priority.name:<{_PRIORITY_WIDTH}}",
            format_timestamp(record.datetime),
            record.module,
        ]
        if record.line:
            parts.append(Path(record.line).name)
        if record.tags:
            parts.append(f"[{', '.join(record.tags)}]")
        return "  ".join(parts)

    def addstr(self, y: int, x: int, text: str, attr: int) -> int:
        """Draws text clipped to the screen width and returns the new x."""
        if x < self.width - 1:
            try:
                self.screen.addnstr(y, x, text, self.width - 1 - x, attr)
            except curses.error:
                pass
        return x + cells(text)

    def draw_status(self, left: str, right: str = "", attr: int | None = None) -> None:
        attr = self.colors.status if attr is None else attr
        width = self.width - 1
        if len(left) + len(right) > width:
            left = left[: max(width - len(right) - 1, 0)] + "…"
        line = left + right.rjust(width - len(left))
        self.addstr(self.height, 0, line, attr)

    def draw(self, refresh: bool = True) -> None:
        self.screen.erase()
        frame = self.frame()
        entry = self.cursor_entry(frame)

        marked = (-1, -1)
        if self.mark is not None:
            marked = (min(self.mark, entry), max(self.mark, entry))

        for y, (row_entry, row) in enumerate(frame):
            is_marked = marked[0] <= row_entry <= marked[1]
            # All rows of the record under the cursor are highlighted.
            is_current = row_entry == entry and not is_marked
            x = 0
            for text, attr in row:
                if is_marked:
                    shown = attr | curses.A_REVERSE
                elif is_current:
                    shown = self.colors.highlight(attr)
                else:
                    shown = attr
                x = self.addstr(y, x, text, shown)
            if is_current and x < self.width - 1:
                self.addstr(y, x, " " * (self.width - 1 - x), self.colors.highlight(0))

        if len(frame) == 0:
            hint = "change the priority with P, the filter with f, or undo with u."
            if not self.reader.index_complete:
                hint = "indexing…"
            self.addstr(0, 0, f"No entries match; {hint}", 0)

        view = self.view
        # The message is the most recent information; it goes first, since
        # the status line is cut off at the end on narrow terminals.
        flags = [self.message] if self.message else []
        if len(frame) > 0:
            flags.append(self.record_info(entry))
        if view.filter:
            flags.append(f"filter: {view.filter.text}")
        if view.dissect:
            flags.append("dissect")
        if self.mark is not None:
            flags.append("MARK")
        if self.reader.error is not None:
            flags.append(str(self.reader.error))

        current = entry + 1 if self.n_entries > 0 else 0
        if self.reader.index_complete:
            # Fixed widths, so that the status line does not jump around.
            digits = len(str(self.n_entries))
            percent = current / max(self.n_entries, 1)
            position = f"{current:>{digits}}/{self.n_entries} {percent:>4.0%}"
        else:
            progress = self.reader.index_progress
            state = f"indexing {progress:.0%}" if progress is not None else "loading"
            position = f"{current}/{self.n_entries}+ ({state})"
        key = f"{self.last_key}{' …' if self.busy else ''}"
        self.draw_status(" " + " | ".join(flags), f"{key}  {position}  ? help ")

        self.screen.move(min(self.cursor, max(len(frame) - 1, 0)), 0)
        if refresh:
            self.screen.refresh()

    # ------------------------------------------------------------------
    # Movement
    # ------------------------------------------------------------------

    def scroll_up(self) -> bool:
        if self.top is None:
            return False
        entry, skip = self.top
        if skip > 0:
            self.top = (entry, skip - 1)
            return True
        if (prev := self.prev_visible(entry - 1)) is None:
            return False
        self.top = (prev, len(self.render(prev)) - 1)
        return True

    def scroll_down(self) -> bool:
        """Scrolls down, unless the end of the file is already visible."""
        frame = self.frame()
        if self.top is None or len(frame) < self.height:
            return False
        last_entry, _ = frame[-1]
        last_rows = sum(1 for e, _ in frame if e == last_entry)
        is_complete = last_rows == len(self.render(last_entry)) - (
            self.top[1] if last_entry == self.top[0] else 0
        )
        if is_complete and self.next_visible(last_entry + 1) is None:
            return False

        entry, skip = self.top
        if skip + 1 < len(self.render(entry)):
            self.top = (entry, skip + 1)
        elif (next_ := self.next_visible(entry + 1)) is not None:
            self.top = (next_, 0)
        return True

    def fill(self) -> None:
        """Scrolls up if the screen is not filled, e.g. at the end of the file."""
        while len(self.frame()) < self.height and self.scroll_up():
            pass

    def focus(self, entry: int, row: int | None = None) -> None:
        """Shows ``entry`` (or its nearest visible neighbour) with the
        cursor at screen row ``row``, the current cursor row by default."""
        target = self.nearest_visible(entry)
        if target is None:
            self.top = None
            self.cursor = 0
            return

        self.top = (target, 0)
        for _ in range(self.cursor if row is None else row):
            if not self.scroll_up():
                break
        self.fill()
        self.cursor = next((i for i, (e, _) in enumerate(self.frame()) if e == target), 0)

    def move_cursor(self, delta: int) -> None:
        last_row = len(self.frame()) - 1
        target = self.cursor + delta
        if 0 <= target <= last_row:
            self.cursor = target
            return
        # Scroll the screen as far as possible, then move the cursor.
        scroll = self.scroll_down if delta > 0 else self.scroll_up
        for _ in range(abs(target - min(max(target, 0), last_row))):
            if not scroll():
                break
        self.cursor = max(min(target, len(self.frame()) - 1), 0)

    # ------------------------------------------------------------------
    # Input
    # ------------------------------------------------------------------

    async def event(self) -> Event | None:
        """Waits for the next key; None means that only a redraw is needed."""
        event = await self.events.get()
        if event is None:
            self._redraw_pending = False
        else:
            self.last_key = key_name(event)
        return event

    def request_redraw(self) -> None:
        if not self._redraw_pending:
            self._redraw_pending = True
            self.events.put_nowait(None)

    def _on_input(self) -> None:
        # The screen is in nodelay mode; read everything that is available.
        while True:
            try:
                key = self.screen.get_wch()
            except curses.error:
                return
            if key == curses.KEY_MOUSE:
                try:
                    _, x, y, _, state = curses.getmouse()
                except curses.error:
                    continue
                self.events.put_nowait(MouseEvent(x, y, state))
            else:
                self.events.put_nowait(key)

    def _on_resize(self) -> None:
        size = os.get_terminal_size(sys.stdout.fileno())
        curses.resizeterm(size.lines, size.columns)
        self.events.put_nowait(curses.KEY_RESIZE)

    async def build_index(self) -> None:
        """Builds the index in small steps to keep the interface responsive."""
        last_redraw = 0.0
        while not self.reader.update_index(0x2000):
            self.terminal_progress.update(self.reader)
            if (now := time.monotonic()) - last_redraw > 0.1:
                last_redraw = now
                self.request_redraw()
            await asyncio.sleep(0)
        self.terminal_progress.update(self.reader)
        self.request_redraw()

    async def prompt(
        self, label: str, text: str, history: list[str], validate: Callable[[str], str | None]
    ) -> str | None:
        """A single line editor in the status bar; returns None on ESC.
        ``validate`` returns an error message for invalid input."""
        entries = [*history, text]
        show_cursor(True)
        try:
            return await self._prompt(label, entries, len(entries) - 1, validate)
        finally:
            show_cursor(False)

    async def _prompt(
        self,
        label: str,
        entries: list[str],
        index: int,
        validate: Callable[[str], str | None],
    ) -> str | None:
        text = entries[index]
        pos = len(text)

        while True:
            error = validate(text)
            self.draw(refresh=False)
            attr = self.colors.status | (self.colors.invalid if error else 0)
            offset = max(0, len(label) + pos - self.width + 2)
            self.draw_status((label + text)[offset:], f"{error} " if error else "", attr=attr)
            self.screen.move(self.height, min(len(label) + pos - offset, self.width - 1))
            self.screen.refresh()

            match await self.event():
                case "\x1b":
                    return None
                case "\n" | "\r" | curses.KEY_ENTER:
                    if error is None:
                        return text
                case curses.KEY_BACKSPACE | "\x7f" | "\b":
                    if pos > 0:
                        text = text[: pos - 1] + text[pos:]
                        pos -= 1
                case curses.KEY_DC:
                    text = text[:pos] + text[pos + 1 :]
                case curses.KEY_LEFT:
                    pos = max(0, pos - 1)
                case curses.KEY_RIGHT:
                    pos = min(len(text), pos + 1)
                case curses.KEY_HOME | "\x01":
                    pos = 0
                case curses.KEY_END | "\x05":
                    pos = len(text)
                case curses.KEY_UP | curses.KEY_DOWN as key:
                    entries[index] = text
                    index = max(
                        0, min(len(entries) - 1, index + (-1 if key == curses.KEY_UP else 1))
                    )
                    text = entries[index]
                    pos = len(text)
                case str(char) if char.isprintable():
                    text = text[:pos] + char + text[pos:]
                    pos += 1

    async def edit_filter(self) -> None:
        def validate(text: str) -> str | None:
            try:
                RecordFilter(text)
                return None
            except FilterError as e:
                return str(e)

        text = await self.prompt("filter: ", self.view.filter.text, self.filter_history, validate)
        if text is None or text.strip() == self.view.filter.text:
            return
        if text and text not in self.filter_history:
            self.filter_history.append(text)
        self.push_view(replace(self.view, filter=RecordFilter(text)))

    async def select_priority(self) -> PenlogPriority | None:
        while True:
            self.message = "priority: " + " ".join(
                f"{k}={p.name}" for k, p in PRIORITY_KEYS.items()
            )
            self.draw()
            self.message = ""
            if (key := await self.event()) is not None:
                return PRIORITY_KEYS.get(key) if isinstance(key, str) else None

    def draw_box(self, title: str, rows: list[Row], offset: int, footer: str, width: int) -> int:
        """Draws a scrollable box on top of the log; returns the number of
        rows which fit into it."""
        self.draw(refresh=False)
        screen_height, screen_width = self.height + 1, self.width
        width = min(width, screen_width)
        height = min(len(rows) + 2, screen_height - 1)
        inner = max(height - 2, 1)

        try:
            box = curses.newwin(
                height, width, (screen_height - 1 - height) // 2, (screen_width - width) // 2
            )
            box.erase()
            box.box()
            box.addnstr(0, 2, f" {title} ", width - 4, curses.A_BOLD)
            box.addnstr(height - 1, max(width - len(footer) - 3, 1), f" {footer} ", width - 2)
            for y, row in enumerate(rows[offset : offset + inner]):
                x = 2
                for text, attr in row:
                    if x < width - 2:
                        box.addnstr(y + 1, x, text, width - 2 - x, attr)
                    x += cells(text)
            self.screen.noutrefresh()
            box.noutrefresh()
            curses.doupdate()
        except curses.error:
            # The terminal is too small; show whatever fits.
            self.screen.refresh()
        return inner

    @staticmethod
    def scroll(key: Event, offset: int, page: int, n_rows: int) -> int:
        """Returns the new offset of a scrollable box after a key press."""
        if isinstance(key, MouseEvent):
            offset += 3 * key.wheel
        match key:
            case curses.KEY_UP | "k":
                offset -= 1
            case curses.KEY_DOWN | "j":
                offset += 1
            case curses.KEY_PPAGE:
                offset -= page
            case curses.KEY_NPAGE | " ":
                offset += page
            case curses.KEY_HOME | "g":
                offset = 0
            case curses.KEY_END | "G":
                offset = n_rows
        return max(0, min(offset, n_rows - page))

    def _highlight_json(self, line: str) -> Row:
        attrs = {
            "key": self.colors.json_key,
            "string": self.colors.json_string,
            "number": self.colors.json_number,
            "literal": self.colors.json_literal,
        }
        row: Row = []
        pos = 0
        for m in _JSON_TOKEN.finditer(line):
            if m.start() > pos:
                row.append((line[pos : m.start()], curses.A_NORMAL))
            assert m.lastgroup is not None
            row.append((m.group(), attrs[m.lastgroup]))
            pos = m.end()
        if pos < len(line):
            row.append((line[pos:], curses.A_NORMAL))
        return row

    def record_details(self, entry: int, raw_mode: bool, width: int) -> list[Row]:
        """Returns the rows of the record view of an entry."""
        colors = self.colors
        raw = self.reader.raw(entry).decode(errors="replace")
        rows: list[Row] = []

        def field(name: str, value: str) -> None:
            rows.append([(f"{name:<10}", colors.heading), (value, curses.A_NORMAL)])

        def section(title: str, text_rows: list[Row]) -> None:
            rows.append([])
            rows.append([(f"── {title} ", colors.heading)])
            rows.extend(text_rows)

        more = "" if self.reader.index_complete else "+"
        field("record", f"{entry + 1} of {self.n_entries}{more}")
        field("offset", f"{self.reader.offset(entry)} (in the decompressed data)")
        field("size", f"{len(raw)} bytes")
        field("priority", self.reader.priority(entry).name)

        if raw_mode:
            section("raw", [[(line, curses.A_NORMAL)] for line in chunks(raw, width)])
            return rows

        body = raw
        if (m := re.match(r"<\d>", raw)) is not None:
            field("prefix", m.group())
            body = raw[m.end() :]
        try:
            record = json.loads(body)
        except ValueError as e:
            section("invalid JSON", [[(str(e), colors.invalid)]])
            section("raw", [[(line, curses.A_NORMAL)] for line in chunks(raw, width)])
            return rows

        json_rows: list[Row] = []
        for line in json.dumps(record, indent=2, ensure_ascii=False).splitlines():
            indent = len(line) - len(line.lstrip()) + 2
            json_rows += wrap_row(self._highlight_json(line), width, min(indent, width // 2))
        section("JSON", json_rows)

        if isinstance(record, dict):
            # Long or multiline texts are hard to read in JSON.
            for key in ("data", "stacktrace"):
                value = record.get(key)
                if isinstance(value, str) and ("\n" in value or len(value) > width // 2):
                    section(key, [[(line, curses.A_NORMAL)] for line in wrap(value, width)])
        proto = self.protocol(entry)
        if (dissection := self.dissection(entry)) is not None:
            attr = colors.dissections[dissection.kind]
            section(proto or "", [[(line, attr)] for line in wrap(dissection.text, width)])
        if (tree := self.wireshark(entry)) is not None:
            tree_rows: list[Row] = []
            for line in tree:
                indent = len(line) - len(line.lstrip()) + 2
                tree_rows += wrap_row([(line, curses.A_NORMAL)], width, min(indent, width // 2))
            section(f"Wireshark ({proto})", tree_rows)
        return rows

    async def show_record(self) -> None:
        """Shows the record under the cursor in detail, e.g. for debugging."""
        if self.top is None:
            return
        entry = self.cursor_entry()
        raw_mode = False
        offset = 0

        while True:
            width = max(self.width - 4, 24)
            rows = self.record_details(entry, raw_mode, width - 4)
            mode = "raw" if raw_mode else "decoded"
            footer = "q close · n/N next/prev · r raw/decoded · ↑↓ scroll"
            page = self.draw_box(f"Record {entry + 1} ({mode})", rows, offset, footer, width)

            match key := await self.event():
                case "q" | "\x1b" | "\n" | "\r" | curses.KEY_ENTER:
                    return
                case "n" | "N" | curses.KEY_RIGHT | curses.KEY_LEFT:
                    forward = key in ("n", curses.KEY_RIGHT)
                    other = (
                        self.next_visible(entry + 1) if forward else self.prev_visible(entry - 1)
                    )
                    if other is not None:
                        entry = other
                        offset = 0
                        # The log behind the box follows.
                        self.focus(entry)
                case "r":
                    raw_mode = not raw_mode
                    offset = 0
                case MouseEvent() | str() | int():
                    offset = self.scroll(key, offset, page, len(rows))

    async def show_help(self) -> None:
        """Shows the help in a box on top of the log."""
        text = HELP.format(
            priorities="\n".join(
                f"  {k}                   {p.name}" for k, p in PRIORITY_KEYS.items()
            ),
            filter="\n".join(f"  {line}" for line in FILTER_SYNTAX.splitlines()),
        )
        rows: list[Row] = [[(line, curses.A_NORMAL)] for line in text.splitlines()]
        width = max(cells(line) for line in text.splitlines()) + 4
        offset = 0

        while True:
            page = self.draw_box("Help", rows, offset, "q/ESC close · ↑↓ PgUp/PgDn scroll", width)
            match key := await self.event():
                case "q" | "?" | "\x1b":
                    return
                case MouseEvent() | str() | int():
                    offset = self.scroll(key, offset, page, len(rows))

    async def handle_mouse(self, mouse: MouseEvent) -> None:
        if mouse.wheel != 0:
            # Scroll the log; the cursor stays on its row.
            scroll = self.scroll_down if mouse.wheel > 0 else self.scroll_up
            for _ in range(3):
                if not scroll():
                    break
            self.cursor = min(self.cursor, max(len(self.frame()) - 1, 0))
            return
        if not (mouse.clicked or mouse.double_clicked):
            return
        if 0 <= mouse.y < len(self.frame()):
            self.cursor = mouse.y
            if mouse.double_clicked:
                await self.show_record()

    async def handle(self, key: Event) -> bool:
        """Handles a key press; returns False to quit."""
        match key:
            case "q":
                return False
            case "\x1b":
                self.mark = None
            case curses.KEY_UP | "k":
                self.move_cursor(-1)
            case curses.KEY_DOWN | "j":
                self.move_cursor(1)
            case curses.KEY_PPAGE:
                self.move_cursor(-self.height + 1 if self.cursor == 0 else -self.cursor)
            case curses.KEY_NPAGE | " ":
                last_row = len(self.frame()) - 1
                self.move_cursor(
                    self.height - 1 if self.cursor == last_row else last_row - self.cursor
                )
            case curses.KEY_HOME | "g":
                self.focus(0, 0)
            case curses.KEY_END | "G":
                self.focus(self.n_entries - 1, self.height - 1)
            case curses.KEY_RESIZE:
                self.focus(self.cursor_entry(), min(self.cursor, self.height - 1))
            case "v":
                self.mark = None if self.mark is not None else self.cursor_entry()
            case "p" | "P":
                if (priority := await self.select_priority()) is not None:
                    start, end = self.selection(priority) if key == "p" else (0, self.n_entries)
                    self.mark = None
                    view = self.view.with_priority(start, end, priority, self.n_entries)
                    if view.zones == self.view.zones:
                        self.message = f"records {start + 1}-{end} are already {priority.name}"
                    else:
                        self.push_view(view)
                        self.message = f"records {start + 1}-{end}: {priority.name}"
            case "f":
                await self.edit_filter()
            case "d":
                self.push_view(replace(self.view, dissect=not self.view.dissect))
            case "u" | "r":
                index = self.history_index + (-1 if key == "u" else 1)
                if 0 <= index < len(self.history):
                    anchor = self.cursor_entry()
                    self.history_index = index
                    self.focus(anchor)
                else:
                    self.message = "nothing to undo" if key == "u" else "nothing to redo"
            case "x" | "t":
                anchor = self.cursor_entry()
                if key == "x":
                    self.formatter.prefix = not self.formatter.prefix
                else:
                    self.formatter.relative_timings = not self.formatter.relative_timings
                self.focus(anchor)
            case "z":
                if self.n_entries > 0:
                    self.formatter.reference_time = self.record(self.cursor_entry()).datetime
                    self.formatter.relative_timings = True
                    self.focus(self.cursor_entry())
            case "?":
                await self.show_help()
            case "\n" | "\r" | curses.KEY_ENTER:
                await self.show_record()
            case MouseEvent() as mouse:
                await self.handle_mouse(mouse)
        return True

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        self.screen.nodelay(True)
        loop.add_reader(sys.stdin.fileno(), self._on_input)
        loop.add_signal_handler(signal.SIGWINCH, self._on_resize)
        indexer = asyncio.create_task(self.build_index())

        try:
            self.focus(0, 0)
            while True:
                self.draw()
                key = await self.event()
                if key is None:
                    # New entries were indexed; they might fill the screen.
                    if self.top is None:
                        self.focus(0, 0)
                    else:
                        self.fill()
                    continue
                self.message = ""
                # Show the key while it is handled; slow actions are visible.
                self.busy = True
                self.draw()
                try:
                    if not await self.handle(key):
                        return
                finally:
                    self.busy = False
        finally:
            indexer.cancel()
            self.terminal_progress.set(TerminalProgress.REMOVE)
            loop.remove_reader(sys.stdin.fileno())
            loop.remove_signal_handler(signal.SIGWINCH)


def _curses_main(
    screen: Any,
    reader: PenlogReader,
    view: View,
    formatter: RecordFormatter,
    terminal_progress: bool,
    theme: str,
    mouse: bool,
) -> None:
    curses.set_escdelay(25)
    show_cursor(False)
    if mouse:
        # Note: curses.mouseinterval(0) would report presses immediately, but
        # then, ncurses delivers the last mouse event only with the next input.
        curses.mousemask(curses.ALL_MOUSE_EVENTS)
    viewer = Viewer(screen, reader, view, formatter, terminal_progress, theme)
    asyncio.run(viewer.run())


def show_cursor(visible: bool) -> None:
    try:
        curses.curs_set(1 if visible else 0)
    except curses.error:
        pass


def run(
    path: Path,
    priority: PenlogPriority = PenlogPriority.INFO,
    record_filter: RecordFilter | None = None,
    formatter: RecordFormatter | None = None,
    terminal_progress: bool | None = None,
    theme: str = "auto",
    mouse: bool = True,
) -> None:
    """Runs the viewer; ``terminal_progress`` defaults to auto detection,
    ``theme`` ("dark", "light", or "auto") to the terminal's background."""
    formatter = formatter or RecordFormatter()
    if terminal_progress is None:
        terminal_progress = TerminalProgress.supported()
    with PenlogReader(path) as reader:
        # The log might have been piped via stdin; curses needs the terminal.
        if not sys.stdin.isatty():
            tty = os.open("/dev/tty", os.O_RDONLY)
            os.dup2(tty, sys.stdin.fileno())
            os.close(tty)
        if theme == "auto":
            theme = detect_background()

        view = View(
            zones=((0, priority),),
            filter=record_filter or RecordFilter(),
            dissect=formatter.dissect,
        )
        curses.wrapper(_curses_main, reader, view, formatter, terminal_progress, theme, mouse)
