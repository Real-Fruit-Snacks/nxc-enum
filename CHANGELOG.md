# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.5.1] - 2024-12-01

### Security
- Debug output now redacts credentials (-p, -H values shown as `****REDACTED****`)
- Output files created with restricted permissions (0o600)
- Credential file permission warnings for overly permissive files
- Added comprehensive security documentation

### Fixed
- Fixed variable shadowing issue in credential validation
- Added authentication validation to prevent missing password/hash errors
- Fixed race condition in parallel output buffer
- Improved exception handling in cache priming and parallel execution

### Changed
- Added constants for magic numbers (thread workers, RID ranges, thresholds)
- Improved type hints throughout the codebase
- Added shared parsing utilities for nxc output
- Enhanced error tracking in parallel module execution

### Documentation
- Added Security Considerations section to README
- Improved code documentation and docstrings

## [1.5.0] - 2024-11-15

### Changed
- Enhanced verbose output parsing
- Improved caching system
- Better error messages

## [1.4.0] - 2024-11-01

### Added
- **Multi-Credential Support** - Test multiple credentials at once
  - `-C credfile`: Credentials file with user:password per line
  - `-U userfile -P passfile`: Separate files paired line-by-line
  - Auto-detects NTLM hashes vs passwords
  - Parallel credential validation
- **Local Admin Detection** - Detects "Pwn3d!" and highlights admin accounts
- **Admin-Aware Command Skipping** - Commands requiring local admin skip non-admin users
- **Share Access Matrix** - Visual matrix comparing user access levels
- **Credential Grouping** - Credentials displayed grouped by admin status
- **Smart Command Execution**
  - Universal commands run once with first valid credential
  - Per-user commands run for each credential

## [1.3.0] - 2024-10-15

### Added
- Consolidated Domain Intelligence section
- Tabular user/group display with categorization
- High-value group highlighting (Domain Admins, etc.)
- Kerberoasting enumeration via LDAP SPNs
- Executive Summary with attack vectors
- Debug mode (`--debug` flag)

## [1.2.0] - 2024-10-01

### Changed
- Major performance overhaul (~50% faster)
- Parallel port scanning, cache priming, and module execution
- Pre-compiled regex patterns
- Credential validation with cache reuse

## [1.1.0] - 2024-09-15

### Added
- Result caching for ~40% performance improvement
- Credential pre-validation
- JSON and file output support

## [1.0.0] - 2024-09-01

### Added
- Initial release
- enum4linux-ng style output formatting
- NetExec command wrapping
- SMB and LDAP enumeration support
- User, group, share, and policy enumeration
- Colored terminal output
- Pass-the-hash support

[Unreleased]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.5.1...HEAD
[1.5.1]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/releases/tag/v1.0.0
