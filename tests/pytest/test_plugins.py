# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import subprocess
import sys

import pytest

from gallia.plugins.plugin import load_plugins, validate_plugins


def test_validate_plugins() -> None:
    """All registered plugins must be free of broken entries.

    Command factories can use lazy imports. This test calls every factory
    to surface import errors that may only occur when a command is selected.
    """
    failures = validate_plugins()

    assert not failures, "\n".join(failures)


def test_builtin_plugins_registered() -> None:
    """The builtin plugins must be registered via entry_points.

    Without this check, the resolution test above would pass vacuously if
    the entry_points were broken, since no plugins would be loaded at all.
    """
    names = {plugin.name() for plugin in load_plugins()}

    assert "Gallia UDS" in names
    assert "Gallia XCP" in names


@pytest.mark.skipif(sys.version_info < (3, 15), reason="requires native lazy imports")
def test_builtin_commands_load_on_demand() -> None:
    subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys

from gallia.plugins.plugin import CommandTree, resolve_command
from gallia.plugins.uds import UDSPlugin

commands = UDSPlugin.commands()
assert 'gallia.commands' not in sys.modules

discover = commands['discover']
assert isinstance(discover, CommandTree)
command = resolve_command(discover.subtree['doip'])
assert command.__module__ == 'gallia.commands.discover.doip'
assert 'gallia.commands.discover.hsfz' not in sys.modules
assert 'gallia.commands._registry' not in sys.modules
""",
        ],
        check=True,
    )
