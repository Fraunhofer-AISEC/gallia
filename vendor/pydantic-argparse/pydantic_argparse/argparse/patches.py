# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Monkey patches for ArgumentParser.

In order to support Python 3.7 and 3.8 while retaining the unit tests, we need
to backport the bugfix for [`BPO-29298`](https://bugs.python.org/issue29298).
"""
import argparse
import sys
from typing import Optional


# In Python versions before 3.9, using argparse with required subparsers will
# cause an unhelpful `TypeError` if the 'dest' parameter is not explicitly
# specified, and no arguments are provided. This bug was fixed in 3.11 and
# backported to 3.10 and 3.9. Here, we backport it to 3.7 and 3.8 as well, via
# monkey-patching.
# See: https://github.com/python/cpython/blob/v3.11.1/Lib/argparse.py#L739-L751
if sys.version_info < (3, 9):  # pragma: <3.9 cover
    def _get_action_name(argument: Optional[argparse.Action]) -> Optional[str]:  # pragma: no cover
        """Generates the name for an argument action.

        The behaviour differs depending on what the action contains:
          * `option_strings` are concatenated with a slash.
          * `metavar` and `dest` are returned verbatim.
          * `choices` are joined and represented as a comma-separated set.

        Args:
            argument (Optional[argparse.Action]): Argument action.

        Returns:
            Optional[str]: Generated action name.
        """
        if argument is None:
            return None
        elif argument.option_strings:
            return "/".join(argument.option_strings)
        elif argument.metavar not in (None, argparse.SUPPRESS):
            return argument.metavar
        elif argument.dest not in (None, argparse.SUPPRESS):
            return argument.dest
        elif argument.choices:
            return "{" + ",".join(argument.choices) + "}"
        else:
            return None

    # Monkey-Patch
    argparse._get_action_name = _get_action_name
