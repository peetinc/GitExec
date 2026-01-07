# Changelog

All notable changes to GitExec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-01-07

### Changed
- **BREAKING:** Renamed RMM variables for consistency:
  - `GITHUB_ORG` → `github_Org`
  - `GITHUB_REPO` → `github_Repo`
  - `GITHUB_VERSION` → `github_Branch`
- Bootstrap scripts now 100% generic - all configuration via RMM variables (no direct script editing required)
- Authorization header updated from `token` to `Bearer` prefix
- Renamed scripts for platform consistency:
  - `GitExec-gen_sigs.sh` → `macOS-GitExec-gen_sigs.sh`
  - `GitExec-gen_rsa_keys.sh` → `macOS-GitExec-gen_rsa_keys.sh`
  - `test-gitexec.sh` → `macOS-gitexec_test.sh`
  - `test-gitexec.ps1` → `WIN-gitexec_test.ps1`
- Consolidated version references to runtime variables and CHANGELOG

### Fixed
- Added `-f` flag to curl commands for proper HTTP error handling
- Improved macOS PAT retrieval error handling pattern

## [1.0.0] - 2026-01-07

### Added
- Cross-platform support (Windows PowerShell + macOS Bash)
- RSA signature verification for script integrity
- Secure credential storage (Windows DPAPI + macOS Keychain)
- Multi-user execution with per-user isolation
- GitHub API integration with cache-bypass mode
- Comprehensive logging infrastructure
- Bootstrap scripts for initial deployment
- Core libraries for Windows (.psm1) and macOS (.sh)
- Signature generation and verification utilities
- Setup scripts for credential provisioning

### Security
- Scripts verified against RSA signatures before execution
- PAT tokens encrypted with machine-specific entropy
- Per-user script isolation in AppData/Library directories
- No plaintext credentials stored on disk
