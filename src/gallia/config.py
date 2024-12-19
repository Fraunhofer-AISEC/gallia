# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
import tomllib
from pathlib import Path
from typing import Any

from platformdirs import user_config_path


class Config(dict[str, Any]):
    def get_value(self, key: str, default: Any | None = None) -> Any | None:
        parts = key.split(".")
        subdict: dict[str, Any] | None = self
        val: Any | None = None

        for part in parts:
            if subdict is None:
                return default

            val = subdict.get(part)
            subdict = val if isinstance(val, dict) else None

        return val if val is not None else default


def get_git_root() -> Path | None:
    try:
        p = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            check=True,
        )
    except FileNotFoundError:
        return None
    except subprocess.CalledProcessError:
        return None
    return Path(p.stdout.decode().strip())


def get_config_dirs() -> list[Path]:
    user_conf = user_config_path("gallia")
    git_root = get_git_root()
    cwd = Path.cwd()
    if git_root is not None:
        return [cwd, git_root, user_conf]
    return [cwd, user_conf]


def search_config(
    filename: Path | None = None,
    extra_paths: list[Path] | None = None,
) -> Path | None:
    name = filename if filename is not None else Path("gallia.toml")
    if (s := os.getenv("GALLIA_CONFIG")) is not None:
        if (path := Path(s)).exists():
            return path
        raise FileNotFoundError(s)

    extra = []
    if extra_paths is not None:
        extra = extra_paths

    search_paths = get_config_dirs() + extra

    for dir_ in search_paths:
        if (path := dir_.joinpath(name)).exists():
            return path

    return None


def load_config_file(
    filename: Path | None = None,
    extra_paths: list[Path] | None = None,
) -> tuple[Config, Path | None]:
    if (path := search_config(filename, extra_paths)) is not None:
        return Config(tomllib.loads(path.read_text())), path
    return Config(), None
