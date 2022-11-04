# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import subprocess


def test_help() -> None:
    subprocess.run(["gallia", "-h"], stdout=subprocess.DEVNULL, check=True)
    subprocess.run(["netzteil", "-h"], stdout=subprocess.DEVNULL, check=True)
    subprocess.run(["hr", "-h"], stdout=subprocess.DEVNULL, check=True)
