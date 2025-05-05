# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
