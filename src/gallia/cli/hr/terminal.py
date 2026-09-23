# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""Detection of the terminal's background color (dark or light)."""

import os
import re
import select
import sys
import time

_OSC11_RESPONSE = re.compile(
    rb"\x1b\]11;rgb:([0-9a-f]{1,4})/([0-9a-f]{1,4})/([0-9a-f]{1,4})", re.IGNORECASE
)
# Every terminal answers the "primary device attributes" query (DA1).
_DA1_RESPONSE = re.compile(rb"\x1b\[\?[0-9;]*c")


def parse_background(response: bytes) -> str | None:
    """Returns "dark" or "light" for the response to an OSC 11 query."""
    if (m := _OSC11_RESPONSE.search(response)) is None:
        return None
    # The components have one to four hex digits.
    red, green, blue = (int(c, 16) / (16 ** len(c) - 1) for c in m.groups())
    luminance = 0.2126 * red + 0.7152 * green + 0.0722 * blue
    return "dark" if luminance < 0.5 else "light"


def parse_colorfgbg(value: str) -> str | None:
    """Returns "dark" or "light" for $COLORFGBG ("fg;bg" or "fg;default;bg"),
    which some terminals set."""
    try:
        background = int(value.rsplit(";", maxsplit=1)[-1])
    except ValueError:
        return None
    return "light" if background in (7, 15) else "dark"


def query_background(timeout: float = 0.5) -> str | None:
    """Asks the terminal for its background color via OSC 11.

    The query is followed by a DA1 query, which every terminal answers;
    thus, there is no need to wait for the timeout if the terminal does
    not support OSC 11."""
    import termios
    import tty

    fd = sys.stdin.fileno()
    if not (os.isatty(fd) and sys.stdout.isatty()):
        return None

    old = termios.tcgetattr(fd)
    response = b""
    try:
        tty.setraw(fd)
        os.write(sys.stdout.fileno(), b"\x1b]11;?\x1b\\\x1b[c")
        deadline = time.monotonic() + timeout
        while _DA1_RESPONSE.search(response) is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                break
            response += os.read(fd, 1024)
    except OSError:
        return None
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, old)
    return parse_background(response)


def detect_background() -> str:
    """Returns "dark" or "light"; dark if it cannot be detected."""
    if sys.platform != "win32" and (background := query_background()) is not None:
        return background
    if (background := parse_colorfgbg(os.environ.get("COLORFGBG", ""))) is not None:
        return background
    return "dark"
