# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import curses
import curses.ascii
from collections.abc import Callable
from enum import IntEnum, unique
from typing import Any

from gallia.power_supply.base import BasePowerSupplyDriver, ChannelStatus, PowerSupplyStatus
from gallia.power_supply.exceptions import OperationNotSupportedError


@unique
class Color(IntEnum):
    ON = 1
    OFF = 2
    ERROR = 3


# How often pending key presses are checked between two status polls.
KEY_POLL_INTERVAL = 0.05

# Default is one second, which makes quitting with ESC sluggish.
ESC_DELAY_MS = 25

LABEL_WIDTH = 14
COLUMN_WIDTH = 14


@unique
class Key(IntEnum):
    QUIT = ord("q")
    TOGGLE_OUTPUT = ord("o")
    TOGGLE_MASTER = ord("m")
    TOGGLE_OCP = ord("f")
    TOGGLE_OVP = ord("p")
    SET_VOLTAGE = ord("v")
    SET_CURRENT = ord("c")
    LEFT = ord("h")
    RIGHT = ord("l")


HELP = "1-9/←→ select  o output  m master  v voltage  c current  f ocp  p ovp  q quit"

# Exceptions which are shown in the status line instead of terminating the view.
DEVICE_ERRORS = (ValueError, OperationNotSupportedError, OSError, TimeoutError)


def format_value(value: float, unit: str) -> str:
    if 0 < abs(value) < 1:
        return f"{value * 1000:.1f} m{unit}"
    return f"{value:.3f} {unit}"


def format_error(e: Exception) -> str:
    return f"{type(e).__name__}: {e}" if str(e) else type(e).__name__


ROWS: list[tuple[str, Callable[[ChannelStatus], str]]] = [
    ("Set voltage", lambda c: format_value(c.voltage, "V")),
    ("Set current", lambda c: format_value(c.current, "A")),
    ("Voltage", lambda c: format_value(c.measured_voltage, "V")),
    ("Current", lambda c: format_value(c.measured_current, "A")),
    ("Power", lambda c: format_value(c.measured_power, "W")),
]

SWITCH_ROWS: list[tuple[str, Callable[[ChannelStatus], bool]]] = [
    ("Output", lambda c: c.output),
    ("OCP", lambda c: c.ocp),
    ("OVP", lambda c: c.ovp),
]


class CursedNetzteil:
    """A curses based live view for power supplies.

    It periodically polls the status of all channels and allows
    switching outputs and protections as well as setting voltage and
    current of the selected channel.
    """

    def __init__(self, driver: BasePowerSupplyDriver, interval: float) -> None:
        self.driver = driver
        self.interval = interval
        self.status: PowerSupplyStatus | None = None
        self.selected = 1
        self.message = ""
        self.message_is_error = False
        self.window: Any = None

    async def run(self) -> None:
        try:
            self.window = self.init_curses()
            self.define_colors()
            await self.handle_io()
        finally:
            if self.window is not None:
                self.terminate_curses()

    def init_curses(self) -> Any:
        window = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)
        curses.set_escdelay(ESC_DELAY_MS)
        window.keypad(True)
        window.nodelay(True)

        return window

    def terminate_curses(self) -> None:
        curses.nocbreak()
        self.window.keypad(False)
        curses.echo()
        curses.endwin()

    def define_colors(self) -> None:
        curses.init_pair(Color.ON, curses.COLOR_GREEN, -1)
        curses.init_pair(Color.OFF, curses.COLOR_RED, -1)
        curses.init_pair(Color.ERROR, curses.COLOR_RED, -1)

    def set_message(self, message: str, error: bool = False) -> None:
        self.message = message
        self.message_is_error = error

    async def poll(self) -> None:
        try:
            self.status = await self.driver.status()
        except DEVICE_ERRORS as e:
            self.set_message(f"status failed: {format_error(e)}", error=True)

    async def handle_io(self) -> None:
        loop = asyncio.get_running_loop()
        next_poll = 0.0

        while True:
            if loop.time() >= next_poll:
                await self.poll()
                next_poll = loop.time() + self.interval
                self.draw()

            key = self.window.getch()
            if key == curses.ERR:
                await asyncio.sleep(KEY_POLL_INTERVAL)
                continue
            if key in (Key.QUIT, curses.ascii.ESC):
                return

            await self.handle_key(key)
            # Show the effect of the action right away.
            next_poll = 0.0

    async def handle_key(self, key: int) -> None:
        if self.status is None:
            return

        channels = sorted(self.status.channels)
        channel = self.status.channels[self.selected]
        self.set_message("")

        try:
            match key:
                case curses.KEY_LEFT | Key.LEFT:
                    self.selected = max(self.selected - 1, channels[0])
                case curses.KEY_RIGHT | Key.RIGHT:
                    self.selected = min(self.selected + 1, channels[-1])
                case _ if curses.ascii.isdigit(key) and int(chr(key)) in channels:
                    self.selected = int(chr(key))
                case Key.TOGGLE_OUTPUT:
                    await self.driver.set_output(self.selected, not channel.output)
                case Key.TOGGLE_MASTER:
                    await self.driver.set_master(not self.status.master)
                case Key.TOGGLE_OCP:
                    await self.driver.set_ocp(self.selected, not channel.ocp)
                case Key.TOGGLE_OVP:
                    await self.driver.set_ovp(self.selected, not channel.ovp)
                case Key.SET_VOLTAGE:
                    if (value := self.prompt(f"CH {self.selected} voltage [V]: ")) is not None:
                        await self.driver.set_voltage(self.selected, value)
                case Key.SET_CURRENT:
                    if (value := self.prompt(f"CH {self.selected} current [A]: ")) is not None:
                        await self.driver.set_current(self.selected, value)
                case _:
                    pass
        except DEVICE_ERRORS as e:
            self.set_message(format_error(e), error=True)

    def prompt(self, text: str) -> float | None:
        """Reads a number in the last line; blocks until enter is pressed.

        Returns None if the input is empty or invalid.
        """
        max_lines, _ = self.window.getmaxyx()
        self.window.move(max_lines - 1, 0)
        self.window.clrtoeol()
        self.window.addstr(text)

        curses.echo()
        curses.curs_set(1)
        self.window.nodelay(False)
        try:
            raw = self.window.getstr().decode().strip()
        finally:
            self.window.nodelay(True)
            curses.curs_set(0)
            curses.noecho()

        if raw == "":
            return None
        try:
            return float(raw)
        except ValueError:
            self.set_message(f"invalid number: {raw}", error=True)
            return None

    def addstr(self, y: int, x: int, text: str, attr: int = 0) -> None:
        max_lines, max_columns = self.window.getmaxyx()
        if y >= max_lines or x >= max_columns:
            return
        try:
            self.window.addstr(y, x, text[: max_columns - x - 1], attr)
        except curses.error:
            # Too small terminals are not worth crashing for.
            pass

    def switch_attr(self, enabled: bool) -> int:
        return curses.color_pair(Color.ON if enabled else Color.OFF) | curses.A_BOLD

    def draw(self) -> None:
        self.window.erase()
        max_lines, _ = self.window.getmaxyx()

        if self.status is None:
            self.addstr(0, 0, "waiting for status …")
        else:
            self.draw_status(self.status)

        message_attr = curses.color_pair(Color.ERROR) if self.message_is_error else 0
        self.addstr(max_lines - 2, 0, self.message, message_attr)
        self.addstr(max_lines - 1, 0, HELP, curses.A_DIM)
        self.window.refresh()

    def draw_status(self, status: PowerSupplyStatus) -> None:
        self.addstr(0, 0, status.ident, curses.A_BOLD)

        y = 2
        for i, channel in enumerate(sorted(status.channels)):
            attr = curses.A_BOLD | (curses.A_REVERSE if channel == self.selected else 0)
            self.addstr(y, LABEL_WIDTH + i * COLUMN_WIDTH, f"CH {channel}", attr)

        for label, fmt in ROWS:
            y += 1
            self.addstr(y, 0, label)
            for i, channel in enumerate(sorted(status.channels)):
                self.addstr(y, LABEL_WIDTH + i * COLUMN_WIDTH, fmt(status.channels[channel]))

        for label, get in SWITCH_ROWS:
            y += 1
            self.addstr(y, 0, label)
            for i, channel in enumerate(sorted(status.channels)):
                enabled = get(status.channels[channel])
                self.addstr(
                    y,
                    LABEL_WIDTH + i * COLUMN_WIDTH,
                    "ON" if enabled else "OFF",
                    self.switch_attr(enabled),
                )

        y += 2
        self.addstr(y, 0, "Master")
        self.addstr(
            y, LABEL_WIDTH, "ON" if status.master else "OFF", self.switch_attr(status.master)
        )
