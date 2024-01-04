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
        self, model: PydanticModelT | Type[PydanticModelT], namespace: Namespace
    ) -> None:
        self.model = model
        self.args = to_dict(namespace)
        self.schema: Dict[str, Any] = self._get_nested_model_fields(self.model, namespace)
        self.schema = self._remove_null_leaves(self.schema)

    def _get_nested_model_fields(self, model: ModelT, namespace: Namespace, parent: Optional[Tuple] = None):
        def contains_subcommand(namespace: Namespace, subcommand: str):
            for name, obj in vars(namespace).items():
                if isinstance(obj, Namespace):
                    if name == subcommand:
                        return True
                    elif contains_subcommand(obj, subcommand):
                        return True

            return False

        model_fields: Dict[str, Any] = dict()

        for field in PydanticField.parse_model(model):
            key = field.name

            if field.is_a(BaseModel):
                if field.is_subcommand():
                    if not contains_subcommand(namespace, key):
                        continue

                    parent = (*parent, key) if parent is not None else (key,)

                # recursively build nestes pydantic models in dict,
                # which matches the actual schema the nested
                # schema pydantic will be expecting
                model_fields[key] = self._get_nested_model_fields(
                    field.model_type, namespace, parent
                )
            else:
                # start with all leaves as None unless key is in top level
                value = self.args.get(key, None)
                if parent is not None:
                    # however, if travesing nested models, then the parent should
                    # not be None and then there is potentially a real value to get

                    # check full path first
                    # TODO: this may not be needed depending on how nested namespaces work
                    # since the arg groups are not nested -- just flattened
                    path = (*parent, key)
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

    def validate(self):
        """Return an instance of the `pydantic` modeled validated with data passed from the command line."""
        return self.model.model_validate(self.schema)
