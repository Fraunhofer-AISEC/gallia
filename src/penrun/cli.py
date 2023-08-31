# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# from gallia.commands import BaseClass
import argparse
import os
import sys
from pathlib import Path
from datetime import datetime
from enum import Enum, unique
from typing import cast
import signal

import exitcode
import msgspec


@unique
class FileNames(Enum):
    PROPERTIES_PRE = "PROPERTIES_PRE.json"
    PROPERTIES_POST = "PROPERTIES_POST.json"
    META = "META.json"
    ENV = "ENV"
    LOGFILE = "log.json.zst"


class CommandMeta(msgspec.Struct):
    command: str | None
    group: str | None
    subgroup: str | None

    def json(self) -> str:
        return msgspec.json.encode(self).decode()


class RunMeta(msgspec.Struct):
    command: list[str]
    command_meta: CommandMeta
    start_time: str
    end_time: str
    exit_code: int

    def json(self) -> str:
        return msgspec.json.encode(self).decode()

def load_parser():
    parser = argparse.ArgumentParser(
        description="""This service can be used to run pentest functions.
        Use -h to see help.
        """,
    )
    parser.add_argument(
        'command',
        help='Subcommand to run'
    )
    parser.add_argument(
        "-d",
        "--dir",
        help="artifacts DIR",
    )

    return parser


class PenRunCommands:
    def __init__(self):
        # TODO take command from args
        self.GROUP = 'echo'
        self.SUBGROUP = 'abc'
        self.COMMAND = 'to'
        self.run_meta = RunMeta(
            command=sys.argv,
            command_meta=CommandMeta(
                command=self.COMMAND,
                group=self.GROUP,
                subgroup=self.SUBGROUP,
            ),
            # TODO reformat date, too long, this from gallia.log, check if same as date in prepare_artifactsdir()
            start_time=datetime.now(datetime.utcnow().astimezone().tzinfo).isoformat(),
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
        # TODO check functionality of force_path
        if force_path is not None:
            if force_path.is_dir():
                return force_path

            force_path.mkdir(parents=True)
            return force_path

        if base_dir is not None:
            _command_dir = ""
            if self.GROUP is not None:
                _command_dir += self.GROUP
            if self.SUBGROUP is not None:
                _command_dir += f"_{self.SUBGROUP}"
            if self.COMMAND is not None:
                _command_dir += f"_{self.COMMAND}"

            # When self.GROUP is None, then
            # _command_dir starts with "_"; remove it.
            if _command_dir.startswith("_"):
                _command_dir = _command_dir.removeprefix("_")

            # If self.GROUP, self.SUBGROUP, and
            # self.COMMAND are None, then fallback to self.id.
            if _command_dir == "":
                _command_dir = self.id

            command_dir = base_dir.joinpath(_command_dir)

            _run_dir = f"run-{datetime.now().strftime('%Y%m%d-%H%M%S.%f')}"
            artifacts_dir = command_dir.joinpath(_run_dir).absolute()
            artifacts_dir.mkdir(parents=True)

            self._dump_environment(artifacts_dir.joinpath(FileNames.ENV.value))
            self._add_latest_link(command_dir)

            return artifacts_dir.absolute()

        # TODO uncomment this and check
        # raise ValueError("base_dir or force_path must be different from None")

    # TODO rename this function?
    def run(self, base_dir):
        self.artifacts_dir = self.prepare_artifactsdir(base_dir = base_dir)
        try:
            # TODO check commands actually being run
            os.system('{} {} {}'.format(self.GROUP, self.SUBGROUP, self.COMMAND))
        except KeyboardInterrupt:
            # TODO set up more exit codes
            exit_code = 128 + signal.SIGINT
        finally:
            self.run_meta.end_time = datetime.now(datetime.utcnow().astimezone().tzinfo).isoformat()
            self.artifacts_dir.joinpath(FileNames.META.value).write_text(
                self.run_meta.json() + "\n"
            )


def main() -> None:
    parser = load_parser()
    args = parser.parse_args()

    pen_run_commands = PenRunCommands()

    # TODO rethink arg structure for create dir
    # TODO take folder path from env variables
    if args.command == 'createdir':
        path = Path(str(args.dir))
        pen_run_commands.run(path)


if __name__ == "__main__":
    main()