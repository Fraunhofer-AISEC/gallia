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

If processing of a logfile is needed, here is a minimal example; for custom functionality see {class}`gallia.log.PenlogReader` and {meth}`gallia.log.PenlogReader.records`.

``` python
from gallia.log import PenlogReader

reader = PenlogReader("/path/to/logfile")
for record in reader.records()
    print(record)
```
