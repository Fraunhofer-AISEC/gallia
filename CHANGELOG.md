<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
