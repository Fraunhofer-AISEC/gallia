<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 1.1.0 (2022-11-04)

### Added

* New utility `hr` for displaying logfiles (#215)
* Builtin support for controlling power supplies (#255).
* New utility `opennetzteil` for controlling power supplies from the command line (#255)
* Config file support: `gallia.toml` (#209)
* Hooks for starting pre-/postprocessing scripts (#271)
* Documented public API: https://fraunhofer-aisec.github.io/gallia/api.html
* Add a payload fuzzer scanner (#154)
* More documentation… :) For instance, how UDS scanning works: https://fraunhofer-aisec.github.io/gallia/uds/scan_modes.html

### Changed

* Overhauled logging system. Logfiles are now produced by `gallia` itself (#215).
* The CLI interface is now based on subcommands and much cleaner.
* Plugin Interface: https://fraunhofer-aisec.github.io/gallia/plugins.html

### Removed

* Drop support for Python 3.9. Python 3.10 and 3.11 are now supported.
* `penrun` script: Functionality is now completely available within `gallia`.

## 1.0.3 (2022-06-30)

### Fixed

* Fix a crash when the DoIP gateway denies the UDS request (#196)
* Fix the DoIP discovery scanner creating invalid URLs (source and targed where confused) (#196)
* Readd the removed return value to `wait_for_ecu()` (#198)
* vECU: Fix state change comparison and reset security access on session change (#190)

## 1.0.2 (2022-06-30)

### Added

* Add a `--ecu-reset` flag enabling triggering a best effort ECUReset on scanner startup (#189)

### Fixed

* Fix wrong constants in enums, found by applying `@unique` treewide (#193)
* Let `wait_for_ecu()`, and thus `--ping`, recognize `--timeout` (#174)

## 1.0.1 (2022-06-27)

### Changed

* Make gallia [REUSE](https://reuse.software/) compliant (#175)

### Fixed

* Fixed failing CI by removing the pyxcp dependency and vendor the only relevant module (#187)
* Fixed bug causing leaking TCP connections in DoIP discover scanner (#165)
* Fixed missing recognition of `--oem default` in the cli (#171)

## 1.0.0 (2022-06-14)

Initial Release. 🎊
