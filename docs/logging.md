<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Logging

## Concept

`gallia` uses structured structured logging implemented as line separated JSON records.
Each scanner creates a `artifacts_dir` under `artifacts_base`, which contains a zstd compressed logfile `log.json.zst`.
The logfile is created with loglevel `DEBUG`; for debugging purposes loglevel `TRACE` can be enabled with the setting `trace_log`.
Logfiles can be displayed with the `hr` tool which is included in `gallia`.
`hr --cursed` opens an interactive viewer, which supports changing the priority for sections of the logfile, filtering, and interpreting UDS messages; press `?` for help.
Only a compact index of the logfile is kept in memory, so large logfiles can be viewed as well; the index is built in the background.

Both modes support filtering with `-f/--filter`, e.g. `hr -f 'module=scanner tag=result !timeout' log.json.zst`.
Terms are separated by spaces and must all match:
`word` (data contains word, case insensitive), `!word`, `field=a,b`, `field!=a,b`, `field~regex`, and `field!~regex`.
The fields are `module`, `host`, `data`, `tag`, and `line`.

The generic interface which represents a logrecord is {class}`gallia.log.PenlogRecord`.
The generic interface which is used to read a logfile {class}`gallia.log.PenlogReader`.

## API

`gallia` uses the [`logging`](https://docs.python.org/3/library/logging.html) module.
The loglevels `TRACE` and `NOTICE` have been added to the module.

In own scripts {meth}`gallia.log.setup_logging` needs to be called as early as possible.
For creating a {class}`gallia.log.Logger`, there is {meth}`gallia.log.get_logger`.

``` python
from gallia.log import get_logger, setup_logging, Loglevel

# The logfile's loglevel is Loglevel.DEBUG.
# It can be set with the keyword argument file_level.
setup_logging(level=Loglevel.INFO)
logger = get_logger(__name__)
logger.info("hello world")
logger.debug("hello debug")
```

If processing of a logfile is needed, here is a minimal example; {func}`gallia.log.stream_records` reads the logfile once from start to end with constant memory usage.

``` python
from gallia.log import stream_records

for record in stream_records("/path/to/logfile.json.zst"):
    print(record)
```

For random access, e.g. reading the logfile backwards or searching it, see {class}`gallia.log.PenlogReader`.
Compressed logfiles are decompressed to a temporary file in the background for this.
