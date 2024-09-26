<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Gallia

[![docs](https://img.shields.io/badge/-docs-green)](https://fraunhofer-aisec.github.io/gallia)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/gallia)](https://pypi.python.org/pypi/gallia/)
[![PyPI - License](https://img.shields.io/pypi/l/gallia)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![PyPI](https://img.shields.io/pypi/v/gallia)](https://pypi.python.org/pypi/gallia/)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.10696368.svg)](https://zenodo.org/doi/10.5281/zenodo.10696368)

[![Packaging status](https://repology.org/badge/vertical-allrepos/gallia.svg)](https://repology.org/project/gallia/versions)

Gallia is an extendable pentesting framework with the focus on the automotive domain.
The scope of the toolchain is conducting penetration tests from a single ECU up to whole cars.
Currently, the main focus lies on the [UDS](https://www.iso.org/standard/72439.html) interface.
Acting as a generic interface, the logging functionality implements reproducible tests and enables post-processing tasks.
The [rendered documentation](https://fraunhofer-aisec.github.io/gallia) is available via Github Pages.

Keep in mind that this project is intended for research and development usage only!
Inappropriate usage might cause irreversible damage to the device under test.
We do not take any responsibility for damage caused by the usage of this tool.

## Testimonials

Levent Çelik et al. in [Comparing Open-Source UDS Implementations Through Fuzz Testing](https://saemobilus.sae.org/papers/comparing-open-source-uds-implementations-fuzz-testing-2024-01-2799):

> Among the implementations we've identified, Gallia stands out as the most robust and dependable by a significant margin.

## Quickstart

See the [setup instructions](https://fraunhofer-aisec.github.io/gallia/setup.html).

First create a config template with `--template`, store it to a file called [`gallia.toml`](https://fraunhofer-aisec.github.io/gallia/config.html), and adjust it to your needs.
`gallia` reads this file to set the defaults of the command line flags.
All options correspond to a command line flag; the only required option for scans is `gallia.scanner.target`, for instance `isotp://can0?src_addr=0x123&dst_addr=0x312&tx_padding=0xaa&rx_padding=0xaa`.

```
$ gallia --template > gallia.toml
```

You are all set to start your first scan, for instance read the diagnostic trouble codes:

```
$ gallia primitive uds dtc read
```

The target can also be specified by the `--target` option on the command line.
For the format of the `--target` argument see the [transports documentation](https://fraunhofer-aisec.github.io/gallia/transports.html).

## Acknowledgments

This work was partly funded by the German Federal Ministry of Education and Research (BMBF) as part of the [SecForCARs](https://www.secforcars.de/) project (grant no. 16KIS0790).
A short presentation and demo video is available at this [page](https://www.secforcars.de/demos/10-automotive-scanning-framework.html).

