# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import os
import shutil
import subprocess
from pathlib import Path

import platformdirs
import pytest

from gallia.config import get_config_dirs, load_config_file


def init_repository(path: Path) -> None:
    subprocess.run(["git", "init", path], check=True)


@pytest.mark.skipif(shutil.which("git") is None, reason="git binary is not available")
def test_config_discovery_git(tmp_path: Path) -> None:
    testrepo = tmp_path.joinpath("testrepo")
    testrepo.mkdir()
    init_repository(testrepo)
    os.chdir(testrepo)

    config_file = testrepo.joinpath("gallia.toml")
    config_file.touch()

    _, path = load_config_file()
    assert path is not None
    assert path.name == "gallia.toml"

    foodir = testrepo.joinpath("foo")
    foodir.mkdir()
    os.chdir(foodir)

    _, path = load_config_file()
    assert path is not None
    assert config_file == path


def test_config_discovery_cwd(tmp_path: Path) -> None:
    config_file = tmp_path.joinpath("gallia.toml")
    config_file.touch()
    os.chdir(tmp_path)

    _, path = load_config_file()
    assert path is not None
    assert config_file == path


def test_config_discovery_none(tmp_path: Path) -> None:
    os.chdir(tmp_path)

    _, path = load_config_file()
    assert path is None


def test_config_discovery_env(tmp_path: Path) -> None:
    config_file = tmp_path.joinpath("gallia.toml")
    config_file.touch()
    os.environ["GALLIA_CONFIG"] = str(config_file)
    _, path = load_config_file()
    assert path == config_file

    config_file.unlink()
    with pytest.raises(FileNotFoundError):
        load_config_file()

    del os.environ["GALLIA_CONFIG"]


def test_get_config_dirs() -> None:
    dirs = get_config_dirs()
    assert len(dirs) == 2
    assert dirs[0] == Path.cwd()
    assert dirs[1] == platformdirs.user_config_path("gallia")


def test_get_value(tmp_path: Path) -> None:
    config_file = tmp_path.joinpath("gallia.toml")
    config_file.write_text(
        """[gallia.foobar]
baz = "fiz"
"""
    )
    os.chdir(tmp_path)

    config, _ = load_config_file()

    assert config.get_value("gallia.foobar.baz") == "fiz"


def test_invalid_config(tmp_path: Path) -> None:
    config_file = tmp_path.joinpath("gallia.toml")
    config_file.write_text(
        """[gallia.foobar]
baz = fiz
"""
    )

    with pytest.raises(ValueError):
        load_config_file(config_file)
