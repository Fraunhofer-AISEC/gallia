from pathlib import Path
from tempfile import gettempdir
from typing import Generic, TypeAlias, TypeVar

from pydantic.generics import GenericModel

RegistryValT = TypeVar("RegistryValT", str, bool, float, int)
RegistryValUnionT = str | bool | float | int


class RegistryItem(GenericModel, Generic[RegistryValT]):
    class Config:
        validate_assignment = True

    short_help: str
    help: str | None
    default: RegistryValT
    value: RegistryValT | None = None


RegistryItemUnionT: TypeAlias = (
    RegistryItem[str] | RegistryItem[int] | RegistryItem[bool] | RegistryItem[float]
)
RegistryT: TypeAlias = dict[str, RegistryItemUnionT]


REGISTRY: RegistryT = {
    "gallia.lock_file": RegistryItem[str](
        default="",
        short_help="path to file used for a posix lock",
        help=None,
    ),
    "gallia.trace_log": RegistryItem[bool](
        default=False,
        short_help="set loglevel to trace in logfile",
        help=None,
    ),
    "gallia.verbosity": RegistryItem[int](
        default=0,
        short_help="increase verbosity on the console",
        help=None,
    ),
    "gallia.hooks.enable": RegistryItem[bool](
        default=False,
        short_help="run pre and post hooks if defined",
        help="hooks are shellscripts which are run before or after a scanrun",
    ),
    "gallia.hooks.pre": RegistryItem[str](
        default="",
        short_help="shell script to run before the main entry_point",
        help=None,
    ),
    "gallia.hooks.post": RegistryItem[str](
        default="",
        short_help="shell script to run after the main entry_point",
        help=None,
    ),
    "gallia.scanner.artifacts_dir": RegistryItem[str](
        default="",
        short_help="directory for artifacts",
        help=None,
    ),
    "gallia.scanner.artifacts_base": RegistryItem[str](
        default=str(Path(gettempdir()).joinpath("gallia")),
        short_help="base directory for artifacts",
        help=None,
    ),
    "gallia.scanner.db": RegistryItem[str](
        default="",
        short_help="path to a sqlite3 database",
        help=None,
    ),
    "gallia.scanner.dumpcap": RegistryItem[bool](
        default=True,
        short_help="enable/disable creation of a dumpcap file",
        help=None,
    ),
    "gallia.scanner.target": RegistryItem[str](
        default="",
        short_help="URI that describes the target",
        help=None,
    ),
    "gallia.scanner.power_supply": RegistryItem[str](
        default="",
        short_help="URI describing a power supply",
        help=None,
    ),
    "gallia.scanner.power_cycle": RegistryItem[bool](
        default=False,
        short_help="trigger a powercycle before starting the scan",
        help=None,
    ),
    "gallia.scanner.power_cycle_sleep": RegistryItem[float](
        default=5.0,
        short_help="time to sleep after the power-cycle",
        help=None,
    ),
    # TODO
    "gallia.scanner.timeout": RegistryItem[float](
        default=0.5,
        short_help="TODO",
        help=None,
    ),
    "gallia.protocols.uds.ecu_reset": RegistryItem[int](
        default=0x01,
        short_help="TODO",
        help=None,
    ),
    "gallia.protocols.uds.oem": RegistryItem[str](
        default="",
        short_help="TODO",
        help=None,
    ),
    "gallia.protocols.uds.timeout": RegistryItem[float](
        default=0.5,
        short_help="TODO",
        help=None,
    ),
    "gallia.protocols.uds.max_retries": RegistryItem[int](
        default=3,
        short_help="TODO",
        help=None,
    ),
    "gallia.protocols.uds.ping": RegistryItem[bool](
        default=True,
        short_help="TODO",
        help=None,
    ),
    "gallia.protocols.uds.tester_present_interval": RegistryItem[float](
        default=1,
        short_help="TODO",
        help=None,
    ),
    "gallia.protocols.uds.tester_present": RegistryItem[bool](
        default=True,
        short_help="TODO",
        help=None,
    ),
    "gallia.protocols.uds.properties": RegistryItem[bool](
        default=True,
        short_help="TODO",
        help=None,
    ),
    "gallia.protocols.uds.compare_properties": RegistryItem[bool](
        default=True,
        short_help="TODO",
        help=None,
    ),
}
