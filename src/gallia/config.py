# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import sys
from collections.abc import MutableMapping
from datetime import datetime
from pathlib import Path
from typing import Any

import tomlkit
from platformdirs import user_config_path
from pydantic import ValidationError
from pygit2 import discover_repository

from gallia.registry import (
    RegistryItemUnionT,
    RegistryT,
    RegistryValUnionT,
)

# TODO: Remove this check when dropping Python 3.10.
if sys.version_info[1] < 11:
    import tomli as tomllib
else:
    import tomllib


from gallia.log import get_logger

_logger = get_logger("config")


def get_git_root() -> Path | None:
    res = discover_repository(Path.cwd())
    match res:
        case str() as p:
            return Path(p).parent
        case None:
            return None

    raise ValueError(f"unexpected return from pygit2 {res}")


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


DEFAULT_CONFIG_PATH = search_config()


class Config:
    def __init__(self, registry: RegistryT, namespace: str | None = None) -> None:
        self.namespace = namespace
        self.inner: RegistryT = {}
        self.registry = registry
        self._parsed = False

    def _parse_raw(
        self, d: MutableMapping[str, Any], parent_key: str = "", sep: str = "."
    ) -> MutableMapping[str, Any]:
        items: list[tuple[str, Any]] = []
        for k, v in d.items():
            new_key = parent_key + sep + k if parent_key else k
            match v:
                case MutableMapping():
                    items.extend(self._parse_raw(v, new_key, sep=sep).items())
                case str() | int() | float() | bool():
                    items.append((new_key, v))
                case _:
                    raise ValueError(f"invalid config type: {type(v)}")

        return dict(items)

    def _merge_raw(self, d: MutableMapping[str, Any]) -> None:
        print(self.registry)
        print()
        for k, v in d.items():
            if self.namespace is not None and not k.startswith(self.namespace):
                continue

            if k not in self.registry:
                _logger.warn(f"unknown config key: {k}")
                continue

            registered_val = self.registry[k]
            val = registered_val

            # Type validation happens here via pydantic.
            try:
                val.value = v
            except ValidationError as e:
                raise ValueError(f"config '{k}' invalid: {e}") from e

            self.inner[k] = val

    def register_key_item(self, key: str, item: RegistryItemUnionT) -> None:
        if key in self.registry:
            raise ValueError(f"key {key} already registered")
        self.registry[key] = item

    def _get_item(
        self, d: MutableMapping[str, RegistryItemUnionT], key: str
    ) -> RegistryItemUnionT:
        if self.namespace is not None and not key.startswith(self.namespace):
            raise KeyError("invalid namespace")

        if key not in d:
            raise KeyError(f"{key} is not registered")

        return d[key]

    def get_config_item(self, key: str) -> RegistryItemUnionT:
        if not self._parsed:
            raise RuntimeError("config is not parsed")
        return self._get_item(self.inner, key)

    def get_registry_item(self, key: str) -> RegistryItemUnionT:
        return self._get_item(self.registry, key)

    def get_default(self, key: str) -> RegistryValUnionT | None:
        return self.get_registry_item(key).default

    def get_value(self, key: str) -> RegistryValUnionT | None:
        return self.get_config_item(key).value

    def get_help(self, key: str) -> str | None:
        return self.get_registry_item(key).help

    def get_short_help(self, key: str) -> str:
        return self.get_registry_item(key).short_help

    def get(self, key: str) -> int | float | str | bool | None:
        if key not in self.inner:
            return None

        item = self.inner[key]

        if item.value is None:
            return item.default

        return self.inner[key].value

    def parse_toml(self, data: str) -> None:
        raw_config = tomllib.loads(data)
        self._merge_raw(self._parse_raw(raw_config))
        self._parsed = True

    def load_file(
        self,
        filename: Path | None = None,
        extra_paths: list[Path] | None = None,
    ) -> Path | None:
        if (path := search_config(filename, extra_paths)) is not None:
            self.parse_toml(path.read_text())
            return path
        return None

    @property
    def template(self) -> str:
        doc = tomlkit.document()
        doc.add(tomlkit.comment("gallia configuration template"))
        doc.add(tomlkit.comment(f"generated on {datetime.now()}"))
        doc.add(tomlkit.nl())

        subdict = doc
        for k, v in self.registry.items():
            parts = k.split(".")
            subdict = doc
            for part in parts[:-1]:
                if part not in subdict:
                    subdict.add(part, tomlkit.table())

                subdict = subdict[part]  # type: ignore

            item = tomlkit.item(v.default)
            item.comment(v.short_help)

            if (help := v.help) is not None:
                subdict.add(tomlkit.comment(f"# {help}"))

            subdict.add(parts[-1], item)

        out = []
        for line in tomlkit.dumps(doc).strip().splitlines():
            out_line = line
            if not line.startswith("#"):
                out_line = "# " + out_line
            out.append(out_line)
        return "\n".join(out).strip()
