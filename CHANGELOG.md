# changelog

changelog for RedPearl

## [v1.1.0] - 2026-10-11

### Added

- Adaptive Token-Bucket & Jitter Rate Shaping(`stealth_engine`)

- Subnet Partitioning & OUI Pruning(`pruner`)

- The Deception Circuit Breaker in (`RedPearl`)

- Thread-Safe SQLite Backend with WAL (Write-Ahead Logging) Mode for State Management(`state_db`)

### Fixed

- None(for now)

### Changed

- `_process_packet` in `RedPearl` has been refactored for Subnet Partitioning and OUI Pruning update

- `_load_or_fetch_oui` method refactored, now sourcing the `oui.txt` and `mac_vendors.json` on the fly with https requests instead of the old harcoding practice

## [v1.0.0] - 2026-06-02

### Added

- Project files

### Fixed

- None

### Changed

- None
