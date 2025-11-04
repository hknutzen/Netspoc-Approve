# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [2025-11-04-1439]

### Changed

- PAN-OS: Use POST not GET for sending commands to device.
- ASA: Use command 'sh run' instead of 'write term' to request configuration.
- Linux: Leave static routes unchanged, if no routes are given by Netspoc.

### Added

- Log SUDO_USER in history file if approve or compare was initiated by
  non systemuser.

## [2025-05-05-1235]

### Changed

- Option '--brief' of commands 'diamonds approve', 'diamonds compare'
  now only ignores login failure on timeout.
  SSH negotiation error is no longer silently ignored.

## [2025-04-16-1813]

### Added

- 'CHANGELOG.md'
  Newest entries are used to maintain github releases page.
- 'nfpm.yaml'
  configures program 'nfpm' to build 'rpm' + 'deb' packages.

### Changed

- Current date and time is used as version number.
- Timout message is logged to history file of device.
- Status of device is marked as DIFF if compare has errors.
  Previously the error was silently ignored.
