# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# Adopted from: https://mdk.fr/blog/how-apt-does-its-fancy-progress-bar.html

import functools
import shutil
from collections.abc import Callable, Iterator
from contextlib import contextmanager

eprint = functools.partial(print, end="", flush=True)


def save_cursor_position() -> None:
    eprint("\0337")


def restore_cursor_position() -> None:
    eprint("\0338")


def lock_footer() -> None:
    _, lines = shutil.get_terminal_size()
    eprint(f"\033[0;{lines-1}r")


def unlock_footer() -> None:
    _, lines = shutil.get_terminal_size()
    eprint(f"\033[0;{lines}r")


def move_to_footer() -> None:
    _, lines = shutil.get_terminal_size()
    eprint(f"\033[{lines};0f")


def move_cursor_up() -> None:
    eprint("\033[1A")


def erase_line() -> None:
    eprint("\033[2K")


def footer_init() -> None:
    # Ensure the last line is available.
    eprint("\n")
    save_cursor_position()
    lock_footer()
    restore_cursor_position()
    move_cursor_up()


def footer_deinit() -> None:
    save_cursor_position()
    unlock_footer()
    move_to_footer()
    erase_line()
    restore_cursor_position()


type ProgressSetter = Callable[[int, int, str], None]


@contextmanager
def progress_bar(bar_len: int = 30) -> Iterator[ProgressSetter]:
    def set_progress(count: int, total: int, suffix: str = "") -> None:
        cols, _ = shutil.get_terminal_size()
        filled_len = int(round(bar_len * count / float(total)))

        percents = round(100.0 * count / float(total), 1)
        bar = "█" * filled_len + "░" * (bar_len - filled_len)

        content = f"{bar}  {percents}%  {suffix}"
        if len(content) > cols:
            content = content[: cols - 1] + "…"

        save_cursor_position()
        move_to_footer()
        erase_line()
        eprint(content)
        restore_cursor_position()

    footer_init()
    try:
        yield set_progress
    finally:
        footer_deinit()
