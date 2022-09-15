# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
from pathlib import Path
from typing import Any

import tomlkit
from xdg import xdg_config_dirs

ConfigType = dict[str, Any]


def get_git_root() -> Path | None:
    try:
        p = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            check=True,
        )
    except subprocess.SubprocessError:
        return None

    return Path(p.stdout.decode().strip())


def get_config_dirs() -> list[Path]:
    dirs = xdg_config_dirs()
    git_root = get_git_root()
    cwd = Path.cwd()
    if git_root is not None:
        return [cwd, git_root] + dirs
    return [cwd] + dirs


def search_config(
    filename: Path | None = None, extra_paths: list[Path] | None = None
) -> Path | None:
    name = filename if filename is not None else Path("gallia.toml")
    if (s := os.getenv("GALLIA_CONFIG")) is not None:
        if (path := Path(s)).exists():
            return path
        raise FileNotFoundError(s)

    for dir_ in (
        get_config_dirs() if extra_paths is None else extra_paths + get_config_dirs()
    ):
        if (path := dir_.joinpath(name)).exists():
            return path

    return None


def load_config_file(
    filename: Path | None = None,
    extra_paths: list[Path] | None = None,
) -> tuple[ConfigType, Path | None]:
    if (path := search_config(filename, extra_paths)) is not None:
        raw_toml = path.read_text()
        return tomlkit.loads(raw_toml), path
    return {}, None
