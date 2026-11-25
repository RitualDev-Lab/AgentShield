# Changelog

All notable changes to **AgentShield** (`@ritualdev-lab/agentshield`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Copy-paste `mcpServers` JSON configuration snippet for Claude Desktop, Cursor, and Windsurf in `README.md`.

## [0.2.2] - 2026-11-24

### Added
- Kernel OS isolation (`Seatbelt`, `Bubblewrap`, `Landlock`, Windows `AppContainer`), `--require-isolation` strict enforcement, ReDoS-safe secret detector, zero-trust in-memory surrogate injection, and SARIF/CI security gate.
- Cross-language runtime defense SDKs for Python (`agentshield-defense`), Go, Rust, and stdio sidecar daemon.
