# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for hr --cursed, which run the viewer on a virtual screen."""

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

curses = pytest.importorskip("curses")

from gallia.cli.hr.filters import RecordFilter
from gallia.cli.hr.formatting import RecordFormatter
from gallia.cli.hr.tui import View, Viewer
from gallia.log import Loglevel, PenlogPriority, PenlogReader, level_style

PRIORITY_NAMES = [p.name for p in PenlogPriority]


class Screen:
    """A minimal stand-in for a curses window, which records the text."""

    def __init__(self, lines: int = 20, columns: int = 80, y: int = 0, x: int = 0) -> None:
        self.lines = lines
        self.columns = columns
        self.y = y
        self.x = x
        self.rows = [" " * columns for _ in range(lines)]

    def getmaxyx(self) -> tuple[int, int]:
        return self.lines, self.columns

    def erase(self) -> None:
        self.rows = [" " * self.columns for _ in range(self.lines)]

    def addnstr(self, y: int, x: int, text: str, n: int, attr: int = 0) -> None:
        text = text[: max(n, 0)][: self.columns - x]
        self.rows[y] = self.rows[y][:x] + text + self.rows[y][x + len(text) :]

    def box(self) -> None:
        pass

    def text(self) -> str:
        return "\n".join(row.rstrip() for row in self.rows)

    def move(self, y: int, x: int) -> None:
        pass

    def refresh(self) -> None:
        pass

    noutrefresh = refresh


@pytest.fixture
def screen(monkeypatch: pytest.MonkeyPatch) -> Iterator[Screen]:
    screen = Screen()
    windows: list[Screen] = []

    def newwin(lines: int, columns: int, y: int, x: int) -> Screen:
        window = Screen(lines, columns, y, x)
        windows.append(window)
        return window

    def doupdate() -> None:
        # Copy the boxes onto the screen, like curses does.
        for window in windows:
            for i, row in enumerate(window.rows):
                screen.addnstr(window.y + i, window.x, row, window.columns)
        windows.clear()

    monkeypatch.setattr(curses, "has_colors", lambda: False)
    monkeypatch.setattr(curses, "newwin", newwin)
    monkeypatch.setattr(curses, "doupdate", doupdate)
    yield screen


@pytest.fixture
def logfile(tmp_path: Path) -> Path:
    """60 records; record n has priority n % 9 and the data "n=NN PRIO"."""
    path = tmp_path / "log.json"
    with path.open("w") as f:
        for n in range(60):
            record = {
                "module": "m",
                "host": "h",
                "data": f"n={n:02} {PRIORITY_NAMES[n % 9]}",
                "datetime": f"2020-01-01T00:00:{n:02}",
                "priority": n % 9,
                "version": 2,
            }
            f.write(json.dumps(record) + "\n")
        f.write("this is { not json\n")
    return path


class Driver:
    """Runs the viewer's key handling like Viewer.run(), without a terminal."""

    def __init__(self, viewer: Viewer, screen: Screen) -> None:
        self.viewer = viewer
        self.screen = screen
        self.loop = asyncio.new_event_loop()
        self.task = self.loop.create_task(self._handle_keys())
        self.keys()

    async def _handle_keys(self) -> None:
        while True:
            self.viewer.draw()
            if (key := await self.viewer.event()) is None:
                continue
            self.viewer.message = ""
            if not await self.viewer.handle(key):
                return

    def keys(self, *keys: str | int) -> None:
        """Presses keys; dialogs (e.g. the record view) stay open until
        they are closed by later keys."""

        async def settle() -> None:
            # Handling keys never waits for anything else than keys; a few
            # iterations of the event loop are enough.
            for _ in range(1000):
                await asyncio.sleep(0)
                if self.viewer.events.empty():
                    break
            for _ in range(5):
                await asyncio.sleep(0)
            assert self.viewer.events.empty()

        for key in keys:
            self.viewer.events.put_nowait(key)
        self.loop.run_until_complete(settle())

    def close(self) -> None:
        self.task.cancel()
        self.loop.run_until_complete(asyncio.gather(self.task, return_exceptions=True))
        self.loop.close()

    def visible(self) -> list[int]:
        """Returns the numbers of the records on the screen."""
        numbers = []
        for entry, _ in self.viewer.frame():
            if entry not in numbers:
                numbers.append(entry)
        return numbers

    @property
    def cursor(self) -> int:
        return self.viewer.cursor_entry()

    def move_to(self, entry: int) -> None:
        self.viewer.focus(entry, 0)
        assert self.cursor == entry


@pytest.fixture
def driver(screen: Screen, logfile: Path) -> Iterator[Driver]:
    with PenlogReader(logfile) as reader:
        reader.build_index()
        view = View(zones=((0, PenlogPriority.ERROR),), filter=RecordFilter())
        viewer = Viewer(screen, reader, view, RecordFormatter(prefix=False), False)
        viewer.focus(0, 0)
        driver = Driver(viewer, screen)
        yield driver
        driver.close()


def with_priority(priority: int, entries: range) -> list[int]:
    return [n for n in entries if n % 9 <= priority]


def test_initial_priority(driver: Driver) -> None:
    assert driver.visible() == with_priority(PenlogPriority.ERROR, range(60))[:19]
    assert "n=00 EMERGENCY" in driver.screen.text()
    assert "ERROR (zone 1/1)" in driver.screen.text()


def test_priority_of_the_whole_file(driver: Driver) -> None:
    driver.keys("P", "t")
    assert driver.visible() == list(range(19))
    assert "records 1-61: TRACE" in driver.screen.text()

    driver.keys("P", "m")
    # The broken last record is an ERROR.
    assert driver.visible() == with_priority(PenlogPriority.EMERGENCY, range(60))

    driver.keys("u")
    assert driver.visible() == list(range(19))
    driver.keys("u")
    assert driver.visible() == with_priority(PenlogPriority.ERROR, range(60))[:19]
    driver.keys("r", "r")
    assert driver.visible()[:2] == [0, 9]
    driver.keys("r")
    assert "nothing to redo" in driver.screen.text()


def test_show_more_around_the_cursor(driver: Driver) -> None:
    driver.move_to(12)
    driver.keys("p", "t")
    # The hidden records between the neighbours of the cursor are shown.
    assert driver.visible()[:9] == [12, 13, 14, 15, 16, 17, 18, 19, 20]
    assert driver.cursor == 12
    driver.move_to(9)
    assert driver.visible()[:5] == [9, 10, 11, 12, 13]
    assert "records 13-18: TRACE" in driver.screen.text()


def test_show_less_in_the_zone(driver: Driver) -> None:
    driver.keys("P", "t")
    driver.move_to(20)
    driver.keys("v")
    driver.move_to(40)
    driver.keys("p", "i")
    # Records 20..40 are INFO now, the rest is still TRACE.
    driver.move_to(19)
    assert driver.visible()[:10] == [19, 20, 21, 22, 23, 24, 27, 28, 29, 30]

    # Without a marked range, showing less affects the zone of the cursor.
    driver.move_to(21)
    driver.keys("p", "e")
    assert "records 21-41: ERROR" in driver.screen.text()
    driver.move_to(17)
    assert driver.visible()[:8] == [17, 18, 19, 20, 21, 27, 28, 29]


def test_marked_range(driver: Driver) -> None:
    driver.move_to(21)
    driver.keys("v")
    driver.move_to(30)
    assert "MARK" in driver.screen.text() or driver.viewer.mark == 21
    driver.keys("p", "t")
    assert driver.viewer.mark is None
    driver.move_to(21)
    assert driver.visible()[:11] == [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 36]


def test_no_change(driver: Driver) -> None:
    driver.keys("p", "e")
    assert "already ERROR" in driver.screen.text()
    driver.keys("u")
    assert "nothing to undo" in driver.screen.text()


def test_cancel_priority_selection(driver: Driver) -> None:
    before = driver.visible()
    driver.keys("p", "\x1b")
    assert driver.visible() == before
    assert len(driver.viewer.history) == 1


def test_filter(driver: Driver) -> None:
    driver.keys("P", "t", "f", *"=1", "\n")
    assert driver.visible() == list(range(10, 20))
    assert "filter: =1" in driver.screen.text()
    driver.keys("u")
    assert driver.viewer.view.filter.text == ""
    assert 20 in driver.visible()


def test_colors_like_hr(screen: Screen, tmp_path: Path) -> None:
    path = tmp_path / "log.json"
    record = {
        "module": "m",
        "host": "h",
        "data": "failed",
        "datetime": "2020-01-01T00:00:00",
        "priority": PenlogPriority.ERROR,
        "version": 2,
        "stacktrace": "Traceback:\n  line 1",
    }
    path.write_text(json.dumps(record) + "\n")

    with PenlogReader(path) as reader:
        view = View(zones=((0, PenlogPriority.TRACE),), filter=RecordFilter())
        viewer = Viewer(screen, reader, view, RecordFormatter(), False)
        error = viewer.colors.level(Loglevel.ERROR)
        assert error == viewer.colors.console(*level_style(Loglevel.ERROR))

        rows = viewer.render(0)
        # The prefix is not colored, the data has the color of the level;
        # the stacktrace follows after an empty line and is not colored.
        prefix = "Jan 01 00:00:00.000 m: "
        assert rows[0] == [(prefix, curses.A_NORMAL), ("failed", error)]
        indent = (" " * len(prefix), curses.A_NORMAL)
        assert rows[1:] == [
            [indent],
            [indent, ("Traceback:", curses.A_NORMAL)],
            [indent, ("  line 1", curses.A_NORMAL)],
        ]
