# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Utilities to help with parsing arbitrarily nested `pydantic` models."""

from argparse import Namespace
from typing import Any, Dict, Generic, Optional, Tuple, Type

from boltons.iterutils import get_path, remap
from pydantic import BaseModel

from .namespaces import to_dict
from .pydantic import PydanticField, PydanticModelT

ModelT = PydanticModelT | Type[PydanticModelT] | BaseModel | Type[BaseModel]


class _NestedArgumentParser(Generic[PydanticModelT]):
    """Parses arbitrarily nested `pydantic` models and inserts values passed at the command line."""

    def __init__(
        self, model: PydanticModelT | Type[PydanticModelT],
        namespace: Namespace,
    ) -> None:
        self.model = model
        self.args = to_dict(namespace)
        self.subcommand_path: tuple[str] = tuple()
        self.schema: Dict[str, Any] = self._get_nested_model_fields(self.model, namespace)
        self.schema = self._remove_null_leaves(self.schema)

    def _get_nested_model_fields(self, model: ModelT, namespace: Namespace):
        def contains_subcommand(ns: Namespace, subcommand_path: Tuple[str]):
            for step in subcommand_path:
                ns = getattr(ns, step, None)

                if not isinstance(ns, Namespace):
                    return False

            return True

        model_fields: Dict[str, Any] = dict()

        for field in PydanticField.parse_model(model):
            key = field.name

            if field.is_a(BaseModel):
                if field.is_subcommand():
                    sub_command_path = (*self.subcommand_path, key)

                    if not contains_subcommand(namespace, sub_command_path):
                        continue

                    self.subcommand_path = sub_command_path

                # recursively build nestes pydantic models in dict,
                # which matches the actual schema the nested
                # schema pydantic will be expecting
                model_fields[key] = self._get_nested_model_fields(
                    field.model_type, namespace
                )
            else:
                # start with all leaves as None unless key is in top level
                value = self.args.get(key, None)

                if len(self.subcommand_path) > 0:
                    path = (*self.subcommand_path, key)
                    value = get_path(self.args, path, value)

                model_fields[key] = value

        return model_fields

    def _remove_null_leaves(self, schema: Dict[str, Any]):
        # only remove None leaves
        # actually CANNOT remove empty containers
        # this causes problems with nested submodels that don't
        # get any new args at command line, and therefore, are
        # relying on the submodel defaults
        # -> thus, the submodel name/key needs to be kept in
        # the schema
        return remap(schema, visit=lambda p, k, v: v is not None)

    def validate(self) -> Tuple[PydanticModelT, BaseModel]:
        """Return the root of the model, as well as the sub-model for the bottom subcommand"""
        model = self.model.model_validate(self.schema)
        subcommand = model

        for step in self.subcommand_path:
            subcommand = getattr(subcommand, step)

        return model, subcommand
