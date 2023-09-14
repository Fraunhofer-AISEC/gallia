# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import re
from pathlib import Path
from datetime import datetime
from enum import Enum, unique
from typing import cast
import signal
import subprocess
import zstandard

import exitcode
import msgspec


@unique
class FileNames(Enum):
    PROPERTIES_PRE = "PROPERTIES_PRE.json"
    PROPERTIES_POST = "PROPERTIES_POST.json"
    META = "META.json"
    ENV = "ENV"
    LOGFILE = "log.zst"

tz = datetime.utcnow().astimezone().tzinfo

class RunMeta(msgspec.Struct):
    command: list[str]
    start_time: str
    end_time: str
    exit_code: int

    def json(self) -> str:
        return msgspec.json.encode(self).decode()


class PenRunCommands:
    """
    Class to create artifacts directory structure for the command to be run
    and to execute the command.
    """
    #: The command to be run.
    COMMAND: str | None = None
    #: A list of exception types for which tracebacks are
    #: suppressed at the top level. For these exceptions
    #: a log message with level critical is logged.
    CATCHED_EXCEPTIONS: list[type[Exception]] = []

    def __init__(self, command):
        self.id = self.camel_to_snake(self.__class__.__name__)
        self.COMMAND = command
        self.run_meta = RunMeta(
            command=command,
            start_time=datetime.now(tz).isoformat(),
            exit_code=0,
            end_time="",
        )

    def _dump_environment(self, path: Path) -> None:
        environ = cast(dict[str, str], os.environ)
        data = [f"{k}={v}" for k, v in environ.items()]
        path.write_text("\n".join(data) + "\n")

    def _add_latest_link(self, path: Path) -> None:
        dirs = list(path.glob("run-*"))
        dirs.sort(key=lambda x: x.name)

        latest_dir = dirs[-1].relative_to(path)

        symlink = path.joinpath("LATEST")
        symlink.unlink(missing_ok=True)
        symlink.symlink_to(latest_dir)

    def prepare_artifactsdir(
            self,
            base_dir: Path | None = None,
            force_path: Path | None = None,
    ) -> Path:
        if force_path is not None:
            if force_path.is_dir():
                return force_path

            force_path.mkdir(parents=True)
            return force_path

        if base_dir is not None:
            _command_dir = ""
            if self.COMMAND is not None:
                _command_dir += f"{self.COMMAND[0]}"

            # If self.COMMAND is None, then fallback to self.id.
            if _command_dir == "":
                _command_dir = self.id

            command_dir = base_dir.joinpath(_command_dir)

            _run_dir = f"run-{datetime.now().strftime('%Y%m%d-%H%M%S.%f')}"
            artifacts_dir = command_dir.joinpath(_run_dir).absolute()
            artifacts_dir.mkdir(parents=True)

            self._dump_environment(artifacts_dir.joinpath(FileNames.ENV.value))
            self._add_latest_link(command_dir)

            return artifacts_dir.absolute()

        raise ValueError("base_dir or force_path must be different from None")

    def run(self, base_dir):
        self.artifacts_dir = self.prepare_artifactsdir(base_dir = base_dir)
        exit_code = 0
        try:
            p = subprocess.Popen(self.COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            output, errors = p.communicate()
            exit_code = p.returncode
            print(output, exit_code)
        except KeyboardInterrupt:
            exit_code = 128 + signal.SIGINT
        # Ensure that META.json gets written in the case a
        # command calls sys.exit().
        except SystemExit as e:
            match e.code:
                case int():
                    exit_code = e.code
                case _:
                    exit_code = exitcode.SOFTWARE
        except Exception as e:
            for t in self.CATCHED_EXCEPTIONS:
                if isinstance(e, t):
                    # TODO: Map the exitcode to superclass of builtin exceptions.
                    exit_code = exitcode.IOERR
                    # TODO: uncomment this after setting up logger
                    # self.logger.critical(f"catched by default handler: {e!r}")
                    # self.logger.debug(e, exc_info=True)
                    break
            else:
                exit_code = exitcode.SOFTWARE
                # self.logger.critical(e, exc_info=True)
        finally:
            self.run_meta.exit_code = exit_code
            self.run_meta.end_time = datetime.now(tz).isoformat()
            self.artifacts_dir.joinpath(FileNames.META.value).write_text(
                self.run_meta.json() + "\n"
            )
            self.write_log_file(self.artifacts_dir.joinpath(FileNames.LOGFILE.value), output)

    def write_log_file(self, path, data):
        self.file = zstandard.open(
            filename=path,
            mode="wb",
            cctx=zstandard.ZstdCompressor(
                write_checksum=True,
                write_content_size=True,
                threads=-1,
            ),
        )

        self.file.write(data.encode())

        self.file.flush()
        self.file.close()

    def camel_to_snake(self, s: str) -> str:
        """Convert a CamelCase string to a snake_case string."""
        # https://stackoverflow.com/a/1176023
        s = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", s)
        return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s).lower()


def load_parser():
    """
    Function to load command line arguments and further information about the commands.
    """
    parser = argparse.ArgumentParser(
        description="""This service can be used to run commands.
        Use -h to see help.
        """,
    )
    parser.add_argument(
        'command',
        nargs='+',
        help='command to run'
    )
    parser.add_argument(
        "-d",
        "--dir",
        help="artifacts DIR",
    )
    parser.add_argument(
        "-c",
        "--createdir",
        help="create dir structure",
        action='store_true',
    )

    return parser


def main() -> None:
    parser = load_parser()
    args = parser.parse_args()

    pen_run_commands = PenRunCommands(args.command)

    if args.createdir:
        dir = str(args.dir) if args.dir is not None else os.environ.get('GALLIA_ARTIFACTS_DIR')
        path = Path(dir)
        pen_run_commands.run(path)


if __name__ == "__main__":
    main()