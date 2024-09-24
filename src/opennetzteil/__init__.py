# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from opennetzteil.devices.rs.hmc804 import HMC804
from opennetzteil.netzteil import BaseNetzteil

netzteile: list[type[BaseNetzteil]] = [HMC804]
