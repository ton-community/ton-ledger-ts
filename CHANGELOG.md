# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [7.2.0] - 2025-02-07

- Added support for TON Ledger App 2.2.0 features, including:
- Hardcoded jettons
- Wallet specifiers support in more methods

## [7.1.0] - Not released

### Added

- Added `parseMessage` helper to parse messages into TON Ledger App format
- Added support for TON Ledger App 2.1.0 features, including:
- New message types
- Wallet specifiers (subwallet ID and wallet op inclusion for v4 support)
- `getSettings` method

## [7.0.1] - 2024-01-17

### Fixed

- Fixed incorrect VarUInt encoding of 0 (0 nanoTON, 0 jetton units, etc)

## [7.0.0] - 2023-09-15

### Changed

- Switched `ton-core` and `ton-crypto` to `@ton/core` and `@ton/crypto`

## [6.0.0] - 2023-07-11

### Removed

- Removed `unsafe` payload format

## [5.0.0] - 2023-06-29

### Removed

- Removed `decimals` and `ticker` from `jetton-transfer` request

## [4.1.0] - 2023-06-16

### Added

- Added `signData` method along with `SignDataRequest` type

## [4.0.1] - 2023-06-16

### Fixed

- Fixed the address flags communication

## [4.0.0] - 2023-06-09

### Added

- Added payload types for NFT and Jetton transfers
- Added TON Connect 2.0 address proof request

### Removed

- Removed old payload types except for comment and unsafe

### Changed

- Updated dependencies
- Changed APDU format to be the same as the latest embedded app version (breaking change)

## [3.0.0] - 2023-01-08

### Changed

- Migration to `ton-core`

## [2.3.2]

- Update documentation
