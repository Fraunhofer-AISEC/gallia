# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from gallia.plugins.plugin import load_plugins, validate_plugins


def test_validate_plugins() -> None:
    """All registered plugins must be free of broken entries.

    Command specification strings ("module:QualName") are resolved lazily,
    so a typo in the module path or in the class name does not raise at
    registration time. This test forces the resolution of all specifications
    of all registered plugins.
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
