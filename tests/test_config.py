import os
from pathlib import Path

import pytest
from pygit2 import init_repository

from gallia.config import load_config_file


def test_config_discovery_git(tmp_path: Path) -> None:
    testrepo = tmp_path.joinpath("testrepo")
    testrepo.mkdir()
    init_repository(str(testrepo))
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


def test_get_value(tmp_path: Path) -> None:
    config_file = tmp_path.joinpath("gallia.toml")
    config_file.write_text("""[gallia.foobar]
baz = "fiz"
""")
    os.chdir(tmp_path)

    config, _ = load_config_file()

    assert config.get_value("gallia.foobar.baz") == "fiz"
