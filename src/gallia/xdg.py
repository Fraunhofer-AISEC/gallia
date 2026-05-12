# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import os
import sys
from pathlib import Path

# https://specifications.freedesktop.org/basedir/latest/
if sys.platform.startswith("linux"):

    def user_config_path(appname: str) -> Path:
        if (h := os.getenv("XDG_CONFIG_HOME")) is not None:
            return Path(h).joinpath(appname)
        return Path.home().joinpath(".config").joinpath(appname)

    def user_cache_dir(appname: str) -> Path:
        if (h := os.getenv("XDG_CACHE_HOME")) is not None:
            return Path(h).joinpath(appname)
        return Path.home().joinpath(".cache").joinpath(appname)

# https://gist.github.com/roalcantara/107ba66dfa3b9d023ac9329e639bc58c#correlations
elif sys.platform.startswith("darwin"):

    def user_config_path(appname: str) -> Path:
        return Path.home().joinpath("Library/Application Support").joinpath(appname)

    def user_cache_dir(appname: str) -> Path:
        return Path.home().joinpath("Library/Caches").joinpath(appname)

# https://evgeniipendragon.com/posts/cleaning-up-my-home-with-xdg-base-directory-specification/
elif sys.platform.startswith("win32"):

    def user_config_path(appname: str) -> Path:
        return Path(os.path.expandvars("%LOCALAPPDATA%")).joinpath(appname)

    def user_cache_dir(appname: str) -> Path:
        return user_config_path(appname).joinpath("cache")

else:

    def user_config_path(appname: str) -> Path:
        raise NotImplementedError

    def user_cache_dir(appname: str) -> Path:
        raise NotImplementedError
