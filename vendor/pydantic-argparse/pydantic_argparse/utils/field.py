from typing import Any, Unpack

from pydantic.fields import FieldInfo, _FromFieldInfoInputs
from pydantic_core import PydanticUndefined


class ArgField(FieldInfo):
    def __init__(self,
                 default: Any = PydanticUndefined,
                 positional: bool = False,
                 short: str | None = None,
                 metavar: str | None = None,
                 group: str | None = None,
                 **kwargs: Unpack[_FromFieldInfoInputs]
                 ):
        super().__init__(default=default, **kwargs)

        self.positional = positional
        self.short = short
        self.metavar = metavar
        self.group = group