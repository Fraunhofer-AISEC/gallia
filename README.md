# Gallia

[![docs](https://img.shields.io/badge/-docs-green)](https://fraunhofer-aisec.github.io/gallia)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/gallia)](https://pypi.python.org/pypi/gallia/)
[![PyPI - License](https://img.shields.io/pypi/l/gallia)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![PyPI](https://img.shields.io/pypi/v/gallia)](https://pypi.python.org/pypi/gallia/)

Gallia is an extendable pentesting framework with the focus on the automotive domain.
The scope of gallia is conducting penetration tests from a single ECU up to whole cars, with the main focus on the UDS interface.
Taking advantage of this modular design, the [logging and archiving](https://fraunhofer-aisec.github.io/gallia/penlog.7.html) functionality was developed separately.
Acting as a generic interface, the logging functionality implements reproducible tests and enables post-processing analyzer tasks.
The [rendered documentation](https://fraunhofer-aisec.github.io/gallia) is available via Github Pages.

Keep in mind that this project is intended for research and development usage only!
Inappropriate usage might cause irreversible damage to the device under test.
We do not take any responsibility for damage caused by the usage of this tool.

## Quickstart

See the [setup instructions](https://fraunhofer-aisec.github.io/gallia/setup.html).

```
$ gallia simple-dtc --target "isotp://can0?src_addr=0x123&dst_addr=0x312&tx_padding=0xaa&rx_padding=0xaa" read
```

For specifying the `--target` argument see the [transports documentation](https://fraunhofer-aisec.github.io/gallia/transports.html).

## Acknowledgments

This work was partly funded by the German Federal Ministry of Education and Research (BMBF) as part of the [SecForCARs](https://www.secforcars.de/) project (grant no. 16KIS0790).
A short presentation and demo video is available at this [page](https://www.secforcars.de/demos/10-automotive-scanning-framework.html).
