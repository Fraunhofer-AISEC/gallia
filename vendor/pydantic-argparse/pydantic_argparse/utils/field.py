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
        group: str | None,
        const: Any,
        hidden: bool,
        **kwargs: Unpack[_FromFieldInfoInputs],
    ):
        super().__init__(default=default, **kwargs)

        self.positional = positional
        self.short = short
        self.metavar = metavar
        self.group = group
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
    return ArgFieldInfo(default, positional, short, metavar, group, const, hidden, **kwargs)
