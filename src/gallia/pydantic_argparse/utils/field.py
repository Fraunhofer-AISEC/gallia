# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Unpack

from pydantic.fields import FieldInfo, _FromFieldInfoInputs
from pydantic_core import PydanticUndefined


class ArgFieldInfo(FieldInfo):
    def __init__(
        self,
        default: Any,
        positional: bool,
        short: str | None,
        metavar: str | None,
        cli_group: str | None,
        const: Any,
        hidden: bool,
        **kwargs: Unpack[_FromFieldInfoInputs],
    ):
        """Creates a new ArgFieldInfo.

        This is a special variant of pydantic's FieldInfo, which adds several arguments,
        mainly related to CLI arguments.
        For general usage and details on the generic parameters see https://docs.pydantic.dev/latest/concepts/fields.
        Just as with pydantic's FieldInfo, this should usually not be called directly.
        Instead use the Field() function of this module.

        :param default: The default value, if non is given explicitly.
        :param positional: Specifies, if the argument is shown as positional, as opposed to optional (default), on the CLI.
        :param short: An optional alternative name for the CLI, which is auto-prefixed with "-".
        :param metavar: The type hint which is shown on the CLI for an argument. If none is specified, it is automatically inferred from its type.
        :param cli_group: The group in the CLI under which the argument is listed.
        :param const: Specifies, a default value, if the argument is set with no explicit value.
        :param hidden: Specifies, that the argument is part of neither the CLI nor the config file.
        :param kwargs: Generic pydantic Field() arguments (see https://docs.pydantic.dev/latest/api/fields/#pydantic.fields.FieldInfo).
        """
        super().__init__(default=default, **kwargs)

        self.positional = positional
        self.short = short
        self.metavar = metavar
        self.group = cli_group
        self.const = const
        self.hidden = hidden


def Field(
    default: Any = PydanticUndefined,
    positional: bool = False,
    short: str | None = None,
    metavar: str | None = None,
    group: str | None = None,
    const: Any = PydanticUndefined,
    hidden: bool = False,
    **kwargs: Unpack[_FromFieldInfoInputs],
) -> Any:
    """Creates a new ArgFieldInfo.

    This is a special variant of pydantic's Field() function, which adds several arguments,
    mainly related to CLI arguments.
    For general usage and details on the generic parameters see https://docs.pydantic.dev/latest/concepts/fields.

    :param default: The default value, if non is given explicitly.
    :param positional: Specifies, if the argument is shown as positional, as opposed to optional (default), on the CLI.
    :param short: An optional alternative name for the CLI, which is auto-prefixed with "-".
    :param metavar: The type hint which is shown on the CLI for an argument. If none is specified, it is automatically inferred from its type.
    :param cli_group: The group in the CLI under which the argument is listed.
    :param const: Specifies, a default value, if the argument is set with no explicit value.
    :param hidden: Specifies, that the argument is part of neither the CLI nor the config file.
    :param kwargs: Generic pydantic Field() arguments (see https://docs.pydantic.dev/latest/api/fields/#pydantic.fields.Field).
    :return: A ConfigArgFieldInfo.
    """
    return ArgFieldInfo(default, positional, short, metavar, group, const, hidden, **kwargs)
