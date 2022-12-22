# SPDX-FileCopyrightText: 2016-2021 Scott Stevenson <scott@stevenson.io>
#
# SPDX-License-Identifier: ISC

import os
from pathlib import Path

from _pytest.monkeypatch import MonkeyPatch

from gallia import xdg

HOME_DIR = Path("/homedir")


def test_xdg_cache_home_unset(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_cache_home when XDG_CACHE_HOME is unset."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("HOME", os.fspath(HOME_DIR))
    assert xdg.xdg_cache_home() == HOME_DIR / ".cache"


def test_xdg_cache_home_empty(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_cache_home when XDG_CACHE_HOME is empty."""
    monkeypatch.setenv("HOME", os.fspath(HOME_DIR))
    monkeypatch.setenv("XDG_CACHE_HOME", "")
    assert xdg.xdg_cache_home() == HOME_DIR / ".cache"


def test_xdg_cache_home_relative(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_cache_home when XDG_CACHE_HOME is relative path."""
    monkeypatch.setenv("HOME", os.fspath(HOME_DIR))
    monkeypatch.setenv("XDG_CACHE_HOME", "rela/tive")
    assert xdg.xdg_cache_home() == HOME_DIR / ".cache"


def test_xdg_cache_home_absolute(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_cache_home when XDG_CACHE_HOME is absolute path."""
    monkeypatch.setenv("XDG_CACHE_HOME", "/xdg_cache_home")
    assert xdg.xdg_cache_home() == Path("/xdg_cache_home")


def test_xdg_config_dirs_unset(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_config_dirs when XDG_CONFIG_DIRS is unset."""
    monkeypatch.delenv("XDG_CONFIG_DIRS", raising=False)
    assert xdg.xdg_config_dirs() == [Path("/etc/xdg")]


def test_xdg_config_dirs_empty(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_config_dirs when XDG_CONFIG_DIRS is empty."""
    monkeypatch.setenv("XDG_CONFIG_DIRS", "")
    assert xdg.xdg_config_dirs() == [Path("/etc/xdg")]


def test_xdg_config_dirs_relative(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_config_dirs when XDG_CONFIG_DIRS is relative paths."""
    monkeypatch.setenv("XDG_CONFIG_DIRS", "rela/tive:ano/ther")
    assert xdg.xdg_config_dirs() == [Path("/etc/xdg")]


def test_xdg_config_dirs_set(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_config_dirs when XDG_CONFIG_DIRS is set."""
    monkeypatch.setenv("XDG_CONFIG_DIRS", "/first:rela/tive:/sec/ond")
    assert xdg.xdg_config_dirs() == [Path("/first"), Path("/sec/ond")]


def test_xdg_config_home_unset(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_config_home when XDG_CONFIG_HOME is unset."""
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", os.fspath(HOME_DIR))
    assert xdg.xdg_config_home() == HOME_DIR / ".config"


def test_xdg_config_home_empty(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_config_home when XDG_CONFIG_HOME is empty."""
    monkeypatch.setenv("HOME", os.fspath(HOME_DIR))
    monkeypatch.setenv("XDG_CONFIG_HOME", "")
    assert xdg.xdg_config_home() == HOME_DIR / ".config"


def test_xdg_config_home_relative(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_config_home when XDG_CONFIG_HOME is relative path."""
    monkeypatch.setenv("HOME", os.fspath(HOME_DIR))
    monkeypatch.setenv("XDG_CONFIG_HOME", "rela/tive")
    assert xdg.xdg_config_home() == HOME_DIR / ".config"


def test_xdg_config_home_absolute(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_config_home when XDG_CONFIG_HOME is absolute path."""
    monkeypatch.setenv("XDG_CONFIG_HOME", "/xdg_config_home")
    assert xdg.xdg_config_home() == Path("/xdg_config_home")


def test_xdg_data_dirs_unset(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_data_dirs when XDG_DATA_DIRS is unset."""
    monkeypatch.delenv("XDG_DATA_DIRS", raising=False)
    assert xdg.xdg_data_dirs() == [
        Path("/usr/local/share/"),
        Path("/usr/share/"),
    ]


def test_xdg_data_dirs_empty(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_data_dirs when XDG_DATA_DIRS is empty."""
    monkeypatch.setenv("XDG_DATA_DIRS", "")
    assert xdg.xdg_data_dirs() == [
        Path("/usr/local/share/"),
        Path("/usr/share/"),
    ]


def test_xdg_data_dirs_relative(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_data_dirs when XDG_DATA_DIRS is relative paths."""
    monkeypatch.setenv("XDG_DATA_DIRS", "rela/tive:ano/ther")
    assert xdg.xdg_data_dirs() == [
        Path("/usr/local/share/"),
        Path("/usr/share/"),
    ]


def test_xdg_data_dirs_set(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_data_dirs when XDG_DATA_DIRS is set."""
    monkeypatch.setenv("XDG_DATA_DIRS", "/first/:rela/tive:/sec/ond/")
    assert xdg.xdg_data_dirs() == [Path("/first/"), Path("/sec/ond/")]


def test_xdg_data_home_unset(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_data_home when XDG_DATA_HOME is unset."""
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", os.fspath(HOME_DIR))
    assert xdg.xdg_data_home() == HOME_DIR / ".local" / "share"


def test_xdg_data_home_empty(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_data_home when XDG_DATA_HOME is empty."""
    monkeypatch.setenv("HOME", os.fspath(HOME_DIR))
    monkeypatch.setenv("XDG_DATA_HOME", "")
    assert xdg.xdg_data_home() == HOME_DIR / ".local" / "share"


def test_xdg_data_home_relative(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_data_home when XDG_DATA_HOME is relative path."""
    monkeypatch.setenv("HOME", os.fspath(HOME_DIR))
    monkeypatch.setenv("XDG_DATA_HOME", "rela/tive")
    assert xdg.xdg_data_home() == HOME_DIR / ".local" / "share"


def test_xdg_data_home_absolute(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_data_home when XDG_DATA_HOME is absolute path."""
    monkeypatch.setenv("XDG_DATA_HOME", "/xdg_data_home")
    assert xdg.xdg_data_home() == Path("/xdg_data_home")


def test_xdg_runtime_dir_unset(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_runtime_dir when XDG_RUNTIME_DIR is unset."""
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert xdg.xdg_runtime_dir() is None


def test_xdg_runtime_dir_empty(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_runtime_dir when XDG_RUNTIME_DIR is empty."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", "")
    assert xdg.xdg_runtime_dir() is None


def test_xdg_runtime_dir_relative(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_runtime_dir when XDG_RUNTIME_DIR is relative path."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", "rela/tive")
    assert xdg.xdg_runtime_dir() is None


def test_xdg_runtime_dir_absolute(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_runtime_dir when XDG_RUNTIME_DIR is absolute path."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/xdg_runtime_dir")
    assert xdg.xdg_runtime_dir() == Path("/xdg_runtime_dir")


def test_xdg_state_home_unset(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_state_home when XDG_STATE_HOME is unset."""
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setenv("HOME", os.fspath(HOME_DIR))
    assert xdg.xdg_state_home() == HOME_DIR / ".local" / "state"


def test_xdg_state_home_empty(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_state_home when XDG_STATE_HOME is empty."""
    monkeypatch.setenv("HOME", os.fspath(HOME_DIR))
    monkeypatch.setenv("XDG_STATE_HOME", "")
    assert xdg.xdg_state_home() == HOME_DIR / ".local" / "state"


def test_xdg_state_home_relative(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_state_home when XDG_STATE_HOME is relative path."""
    monkeypatch.setenv("HOME", os.fspath(HOME_DIR))
    monkeypatch.setenv("XDG_STATE_HOME", "rela/tive")
    assert xdg.xdg_state_home() == HOME_DIR / ".local" / "state"


def test_xdg_state_home_absolute(monkeypatch: MonkeyPatch) -> None:
    """Test xdg_state_home when XDG_STATE_HOME is absolute path."""
    monkeypatch.setenv("XDG_STATE_HOME", "/xdg_state_home")
    assert xdg.xdg_state_home() == Path("/xdg_state_home")
