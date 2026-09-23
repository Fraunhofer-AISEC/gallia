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
import os
import re
import signal
import sys
import textwrap
import time
from binascii import unhexlify
from bisect import bisect_right
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import wcwidth

from gallia.cli.hr.filters import FILTER_SYNTAX, FilterError, RecordFilter
from gallia.log import PenlogPriority, PenlogReader, PenlogRecord

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
  p <prio>            set the priority of the marked range (or of the gap
                      around the entry under the cursor)
  P <prio>            set the priority of the entire file
  v                   start/stop marking a range; ESC cancels
  f                   edit the filter (see below); Up/Down browse the history
  i                   toggle interpretation of UDS messages
  x                   toggle the prefix (timestamp, module, tags)
  t                   toggle absolute/relative timestamps
  z                   set the reference time for relative timestamps
  u / r               undo/redo priority, filter and interpretation changes
  ?                   show this help
  q                   quit

Priority keys
{priorities}

Filter
{filter}"""

Segment = tuple[str, int]  # text and curses attributes
Row = list[Segment]

_CONTROL_CHARS = {i: "�" for i in [*range(0x20), 0x7F] if i != ord("\t")}


@dataclass(frozen=True)
class View:
    """The settings which select the displayed entries.
    It is immutable; every change is a new item in the undo history."""

    # Sorted (start, priority) pairs; a zone lasts until the next one starts.
    zones: tuple[tuple[int, PenlogPriority], ...]
    filter: RecordFilter
    interpret: bool = False

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


def cells(text: str) -> int:
    """Returns the number of terminal cells needed for ``text``."""
    return n if (n := wcwidth.wcswidth(text)) >= 0 else len(text)


class Colors:
    def __init__(self) -> None:
        self._next_pair = 1
        has_colors = curses.has_colors()
        if has_colors:
            curses.use_default_colors()
        many = has_colors and curses.COLORS >= 256
        gray = 245 if many else curses.COLOR_WHITE
        orange = 208 if many else curses.COLOR_RED

        def pair(fg: int, attr: int = 0) -> int:
            if not has_colors:
                return attr
            curses.init_pair(self._next_pair, fg, -1)
            self._next_pair += 1
            return curses.color_pair(self._next_pair - 1) | attr

        red = pair(curses.COLOR_RED, curses.A_BOLD)
        self.priorities = {
            PenlogPriority.EMERGENCY: red,
            PenlogPriority.ALERT: red,
            PenlogPriority.CRITICAL: red,
            PenlogPriority.ERROR: red,
            PenlogPriority.WARNING: pair(curses.COLOR_YELLOW, curses.A_BOLD),
            PenlogPriority.NOTICE: curses.A_BOLD,
            PenlogPriority.INFO: curses.A_NORMAL,
            PenlogPriority.DEBUG: pair(gray),
            PenlogPriority.TRACE: pair(curses.COLOR_BLUE),
        }
        self.prefix = pair(gray)
        self.uds_request = pair(curses.COLOR_CYAN)
        self.uds_positive_response = pair(curses.COLOR_GREEN)
        self.uds_negative_response = pair(orange)
        self.invalid = pair(curses.COLOR_YELLOW)
        self.status = curses.A_REVERSE


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
        prefix: bool,
        relative_timings: bool,
        terminal_progress: bool,
    ) -> None:
        self.screen = screen
        self.terminal_progress = TerminalProgress(terminal_progress)
        self.reader = reader
        self.colors = Colors()
        # Keys, or None if only a redraw is needed, e.g. on indexing progress.
        self.events: asyncio.Queue[str | int | None] = asyncio.Queue()
        self._redraw_pending = False

        self.history = [view]
        self.history_index = 0
        self.filter_history = [view.filter.text] if view.filter else []

        self.prefix = prefix
        self.relative_timings = relative_timings

        # Only the entries around the visible part of the file are cached.
        self.record = functools.lru_cache(maxsize=2048)(self._load_record)
        self.interpretation = functools.lru_cache(maxsize=2048)(self._interpret)
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
        self.reference_time = (
            self.record(0).datetime if self.n_entries > 0 else datetime.datetime.now()
        )

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

    def _interpret(self, entry: int) -> tuple[str, int] | None:
        # Imported lazily; this takes a while and is not needed for startup.
        from gallia.services.uds.core.service import NegativeResponse, UDSRequest, UDSResponse

        try:
            data = unhexlify(self.record(entry).data)
        except ValueError:
            return None
        if len(data) == 0 or data[0] == 0:
            return None

        try:
            if data[0] & 0x40:
                response = UDSResponse.parse_dynamic(data)
                if isinstance(response, NegativeResponse):
                    return repr(response), self.colors.uds_negative_response
                return repr(response), self.colors.uds_positive_response
            return repr(UDSRequest.parse_dynamic(data)), self.colors.uds_request
        except Exception:
            return None

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

    def format_prefix(self, record: PenlogRecord) -> str:
        if self.relative_timings:
            ms = int((record.datetime - self.reference_time).total_seconds() * 1000)
            sign = "-" if ms < 0 else "+"
            ms = abs(ms)
            timestamp = (
                f"{sign}{ms // 86_400_000}d {ms // 3_600_000 % 24:02}:"
                f"{ms // 60_000 % 60:02}:{ms // 1000 % 60:02}.{ms % 1000:03}"
            ).rjust(18)
        else:
            timestamp = record.datetime.strftime("%b %d %H:%M:%S.%f")[:-3]
        tags = f" [{', '.join(record.tags)}]" if record.tags else ""
        return f"{timestamp} {record.module}{tags}: "

    def render(self, entry: int) -> list[Row]:
        """Returns the screen rows of an entry."""
        settings = (
            self.width,
            self.prefix,
            self.relative_timings,
            self.reference_time,
            self.view.interpret,
        )
        return self._render(entry, settings)

    def _render_uncached(self, entry: int, settings: tuple[Any, ...]) -> list[Row]:
        del settings  # Only part of the cache key.
        record = self.record(entry)
        prefix = self.format_prefix(record) if self.prefix else ""
        text_width = max(self.width - 1 - cells(prefix), 20)
        attr = self.colors.priorities[record.priority]

        texts = wrap(record.data, text_width)
        if record.stacktrace is not None:
            texts += wrap(record.stacktrace, text_width)

        indent = " " * len(prefix)
        rows: list[Row] = [
            [(prefix if i == 0 else indent, self.colors.prefix), (text, attr)]
            for i, text in enumerate(texts)
        ]

        if self.view.interpret and (interpretation := self.interpretation(entry)) is not None:
            comment, comment_attr = f"  # {interpretation[0]}", interpretation[1]
            if cells(texts[-1]) + cells(comment) <= text_width:
                rows[-1].append((comment, comment_attr))
            else:
                for line in wrap(comment.strip(), text_width):
                    rows.append([(indent, 0), (line, comment_attr)])

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

    def cursor_entry(self) -> int:
        frame = self.frame()
        if len(frame) == 0:
            return self.top[0] if self.top is not None else 0
        return frame[min(self.cursor, len(frame) - 1)][0]

    def selection(self) -> tuple[int, int]:
        """Returns the marked range of entries ``[start, end)``.
        Without a marked range, the hidden entries around the cursor are
        selected, since this is where changing the priority has an effect."""
        entry = self.cursor_entry()
        if self.mark is not None and self.mark != entry:
            return min(self.mark, entry), max(self.mark, entry) + 1
        prev = self.prev_visible(entry - 1)
        next_ = self.next_visible(entry + 1)
        return (
            prev + 1 if prev is not None else 0,
            next_ if next_ is not None else self.n_entries,
        )

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

        marked = (-1, -1)
        if self.mark is not None:
            entry = self.cursor_entry()
            marked = (min(self.mark, entry), max(self.mark, entry))

        for y, (entry, row) in enumerate(frame):
            extra = curses.A_REVERSE if marked[0] <= entry <= marked[1] else 0
            x = 0
            for text, attr in row:
                x = self.addstr(y, x, text, attr | extra)

        if len(frame) == 0:
            hint = "change the priority with P, the filter with f, or undo with u."
            if not self.reader.index_complete:
                hint = "indexing…"
            self.addstr(0, 0, f"No entries match; {hint}", 0)

        view = self.view
        entry = self.cursor_entry()
        flags = []
        if self.n_entries > 0:
            zone = view.zone_index(entry)
            flags.append(f"{view.zones[zone][1].name} (zone {zone + 1}/{len(view.zones)})")
        if view.filter:
            flags.append(f"filter: {view.filter.text}")
        if view.interpret:
            flags.append("UDS")
        if self.mark is not None:
            flags.append("MARK")
        if self.message:
            flags.append(self.message)
        if self.reader.error is not None:
            flags.append(str(self.reader.error))

        current = entry + 1 if self.n_entries > 0 else 0
        if self.reader.index_complete:
            position = f"{current}/{self.n_entries} ({current / max(self.n_entries, 1):.0%})"
        else:
            progress = self.reader.index_progress
            state = f"indexing {progress:.0%}" if progress is not None else "loading"
            position = f"{current}/{self.n_entries}+ ({state})"
        self.draw_status(" " + " | ".join(flags), f"{position}  ? help ")

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

    async def event(self) -> str | int | None:
        """Waits for the next key; None means that only a redraw is needed."""
        event = await self.events.get()
        if event is None:
            self._redraw_pending = False
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
        index = len(entries) - 1
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

    async def show_help(self) -> None:
        """Shows the help in a box on top of the log."""
        text = HELP.format(
            priorities="\n".join(
                f"  {k}                   {p.name}" for k, p in PRIORITY_KEYS.items()
            ),
            filter="\n".join(f"  {line}" for line in FILTER_SYNTAX.splitlines()),
        )
        lines = text.splitlines()
        offset = 0

        while True:
            self.draw(refresh=False)
            screen_height, screen_width = self.screen.getmaxyx()
            width = min(max(cells(line) for line in lines) + 4, screen_width)
            height = min(len(lines) + 2, screen_height - 1)
            inner = max(height - 2, 1)
            offset = max(0, min(offset, len(lines) - inner))

            try:
                box = curses.newwin(
                    height, width, (screen_height - 1 - height) // 2, (screen_width - width) // 2
                )
                box.erase()
                box.box()
                box.addnstr(0, 2, " Help ", width - 4, curses.A_BOLD)
                footer = " q/ESC close · ↑↓ PgUp/PgDn scroll "
                box.addnstr(height - 1, max(width - len(footer) - 2, 1), footer, width - 2)
                for y, line in enumerate(lines[offset : offset + inner]):
                    box.addnstr(y + 1, 2, line, width - 4)
                self.screen.noutrefresh()
                box.noutrefresh()
                curses.doupdate()
            except curses.error:
                # The terminal is too small; show whatever fits.
                self.screen.refresh()

            match await self.event():
                case "q" | "?" | "\x1b":
                    return
                case curses.KEY_UP | "k":
                    offset -= 1
                case curses.KEY_DOWN | "j":
                    offset += 1
                case curses.KEY_PPAGE:
                    offset -= inner
                case curses.KEY_NPAGE | " ":
                    offset += inner

    async def handle(self, key: str | int) -> bool:
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
                    start, end = self.selection() if key == "p" else (0, self.n_entries)
                    self.mark = None
                    self.push_view(self.view.with_priority(start, end, priority, self.n_entries))
            case "f":
                await self.edit_filter()
            case "i":
                self.push_view(replace(self.view, interpret=not self.view.interpret))
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
                    self.prefix = not self.prefix
                else:
                    self.relative_timings = not self.relative_timings
                self.focus(anchor)
            case "z":
                if self.n_entries > 0:
                    self.reference_time = self.record(self.cursor_entry()).datetime
                    self.relative_timings = True
                    self.focus(self.cursor_entry())
            case "?":
                await self.show_help()
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
                if not await self.handle(key):
                    return
        finally:
            indexer.cancel()
            self.terminal_progress.set(TerminalProgress.REMOVE)
            loop.remove_reader(sys.stdin.fileno())
            loop.remove_signal_handler(signal.SIGWINCH)


def _curses_main(
    screen: Any,
    reader: PenlogReader,
    view: View,
    prefix: bool,
    relative_timings: bool,
    terminal_progress: bool,
) -> None:
    curses.set_escdelay(25)
    viewer = Viewer(screen, reader, view, prefix, relative_timings, terminal_progress)
    asyncio.run(viewer.run())


def run(
    path: Path,
    priority: PenlogPriority = PenlogPriority.INFO,
    record_filter: RecordFilter | None = None,
    prefix: bool = True,
    relative_timings: bool = False,
    terminal_progress: bool | None = None,
) -> None:
    """Runs the viewer; ``terminal_progress`` defaults to auto detection."""
    if terminal_progress is None:
        terminal_progress = TerminalProgress.supported()
    with PenlogReader(path) as reader:
        # The log might have been piped via stdin; curses needs the terminal.
        if not sys.stdin.isatty():
            tty = os.open("/dev/tty", os.O_RDONLY)
            os.dup2(tty, sys.stdin.fileno())
            os.close(tty)

        view = View(zones=((0, priority),), filter=record_filter or RecordFilter())
        curses.wrapper(_curses_main, reader, view, prefix, relative_timings, terminal_progress)
