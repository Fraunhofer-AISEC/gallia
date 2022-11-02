# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from enum import Enum, unique


@unique
class LogMode(Enum):
    implicit = "implicit"
    explicit = "explicit"
    emphasized = "emphasized"
