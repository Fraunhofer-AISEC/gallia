# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from functools import partial

from gallia.log import get_logger
from gallia.transports import TargetURI

logger = get_logger(__name__)


class PowerSupplyURI(TargetURI):
    @property
    def id(self) -> int:
        if "id" in self.qs:
            return int(self.qs["id"][0], 0)
        return 0

    @property
    def channel(self) -> int | list[int]:
        if "channel" in self.qs:
            if len(ch := self.qs["channel"]) == 1:
                return int(ch[0], 0)
            return list(map(partial(int, base=0), ch))
        return 0

    @property
    def product_id(self) -> str:
        if "product_id" in self.qs:
            return self.qs["product_id"][0]
        return ""
