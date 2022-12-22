# SPDX-FileCopyrightText: 2016-2021 Scott Stevenson <scott@stevenson.io>
#
# SPDX-License-Identifier: ISC

"""XDG Base Directory Specification variables.
xdg_cache_home(), xdg_config_home(), xdg_data_home(), and xdg_state_home()
return pathlib.Path objects containing the value of the environment variable
named XDG_CACHE_HOME, XDG_CONFIG_HOME, XDG_DATA_HOME, and XDG_STATE_HOME
respectively, or the default defined in the specification if the environment
variable is unset, empty, or contains a relative path rather than absolute
path.
xdg_config_dirs() and xdg_data_dirs() return a list of pathlib.Path
objects containing the value, split on colons, of the environment
variable named XDG_CONFIG_DIRS and XDG_DATA_DIRS respectively, or the
default defined in the specification if the environment variable is
unset or empty. Relative paths are ignored, as per the specification.
xdg_runtime_dir() returns a pathlib.Path object containing the value of
the XDG_RUNTIME_DIR environment variable, or None if the environment
variable is not set, or contains a relative path rather than absolute path.
"""

import os
from pathlib import Path
from typing import TypeVar

T = TypeVar("T", Path, None)


def _path_from_env(variable: str, default: T) -> Path | T:
    """Read an environment variable as a path.
    The environment variable with the specified name is read, and its
    value returned as a path. If the environment variable is not set, is
    set to the empty string, or is set to a relative rather than
    absolute path, the default value is returned.
    Parameters
    ----------
    variable : str
        Name of the environment variable.
    default : Path
        Default value.
    Returns
    -------
    Path
        Value from environment or default.
    """
    value = os.environ.get(variable)
    if value and os.path.isabs(value):
        return Path(value)
    return default


def _paths_from_env(variable: str, default: list[Path]) -> list[Path]:
    """Read an environment variable as a list of paths.
    The environment variable with the specified name is read, and its
    value split on colons and returned as a list of paths. If the
    environment variable is not set, or set to the empty string, the
    default value is returned. Relative paths are ignored, as per the
    specification.
    Parameters
    ----------
    variable : str
        Name of the environment variable.
    default : List[Path]
        Default value.
    Returns
    -------
    List[Path]
        Value from environment or default.
    """
    value = os.environ.get(variable)
    if value:
        paths = [Path(path) for path in value.split(":") if os.path.isabs(path)]
        if paths:
            return paths
    return default


def xdg_cache_home() -> Path:
    """Return a Path corresponding to XDG_CACHE_HOME."""
    return _path_from_env("XDG_CACHE_HOME", Path.home() / ".cache")


def xdg_config_dirs() -> list[Path]:
    """Return a list of Paths corresponding to XDG_CONFIG_DIRS."""
    return _paths_from_env("XDG_CONFIG_DIRS", [Path("/etc/xdg")])


def xdg_config_home() -> Path:
    """Return a Path corresponding to XDG_CONFIG_HOME."""
    return _path_from_env("XDG_CONFIG_HOME", Path.home() / ".config")


def xdg_data_dirs() -> list[Path]:
    """Return a list of Paths corresponding to XDG_DATA_DIRS."""
    return _paths_from_env(
        "XDG_DATA_DIRS",
        [Path(path) for path in "/usr/local/share/:/usr/share/".split(":")],
    )


def xdg_data_home() -> Path:
    """Return a Path corresponding to XDG_DATA_HOME."""
    return _path_from_env("XDG_DATA_HOME", Path.home() / ".local" / "share")


def xdg_runtime_dir() -> Path | None:
    """Return a Path corresponding to XDG_RUNTIME_DIR.
    If the XDG_RUNTIME_DIR environment variable is not set, None will be
    returned as per the specification.
    """
    return _path_from_env("XDG_RUNTIME_DIR", None)


def xdg_state_home() -> Path:
    """Return a Path corresponding to XDG_STATE_HOME."""
    return _path_from_env("XDG_STATE_HOME", Path.home() / ".local" / "state")
