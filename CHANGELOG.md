# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **LAPS Deployment Check** (`--laps`) - Enumerate computers with LAPS configured
  - Identifies computers with ms-Mcs-AdmPwd attribute (LAPS deployed)
  - Detects if current user has permissions to read LAPS passwords
  - Pure enumeration: does NOT retrieve passwords (command in Next Steps)
- **LDAP Signing Check** (`--ldap-signing`) - Check LDAP signing requirements
  - Identifies if LDAP signing is enforced on the domain controller
  - Detects channel binding status
  - Flags security issue if signing not required (LDAP relay possible)
- **Local Groups Enumeration** (`--local-groups`) - List local groups and members
  - Enumerates local groups on target system
  - Highlights Administrators group members
  - Useful for identifying lateral movement paths
- **AD Subnets Enumeration** (`--subnets`) - List AD sites and subnets
  - Queries AD configuration for network topology
  - Shows all subnets and their associated sites
  - Helps identify additional network segments
- **Pre-Windows 2000 Computers** (`--pre2k`) - Find vulnerable computer accounts
  - Identifies computers with pre-Windows 2000 compatibility enabled
  - These accounts have password = lowercase computer name
  - High-value finding for credential attacks
- **BitLocker Status Check** (`--bitlocker`) - Check drive encryption status
  - Queries BitLocker encryption status per drive
  - Identifies encrypted vs unencrypted drives
  - Requires local admin privileges
- **MSSQL Enumeration** (`--mssql`) - Enumerate MSSQL databases
  - Lists databases via Windows integrated authentication
  - Enumerates linked servers (lateral movement)
  - Detects sysadmin privileges
  - Pure enumeration: no command execution
- **RDP Status Check** (`--rdp`) - Check RDP and NLA configuration
  - Verifies if RDP is enabled on target
  - Checks Network Level Authentication (NLA) status
  - Flags security issue if NLA not required
- **FTP Anonymous Access** (`--ftp`) - Check for anonymous FTP
  - Probes anonymous FTP login
  - Lists accessible files if anonymous access allowed
  - High-priority security finding
- **NFS Share Enumeration** (`--nfs`) - List NFS exports
  - Queries exported NFS shares
  - Identifies world-accessible exports
  - Shows mount permissions

- **Multi-Target Scanning** - Scan multiple targets with CIDR notation, IP ranges, or target files
  - CIDR notation support: `nxc-enum 10.0.0.0/24 -u admin -p pass`
  - IP range support: `nxc-enum 10.0.0.1-50 -u admin -p pass`
  - Full IP range: `nxc-enum 10.0.0.1-10.0.0.50 -u admin -p pass`
  - Target file support: `nxc-enum targets.txt -u admin -p pass` (auto-detected!)
  - Clean per-target output with separators and headers
  - Aggregate summary showing status for all targets
  - Combined security findings across targets (signing, anonymous access, etc.)
  - JSON output includes per-target results and aggregate statistics
  - Graceful handling of failed targets (continues to next)
  - Ctrl+C shows summary of completed targets
- **AS-REP Roasting Detection** (`--asreproast`) - Find accounts without Kerberos pre-authentication
  - Pure enumeration: queries LDAP for DONT_REQUIRE_PREAUTH flag (no tickets requested)
  - Identifies accounts vulnerable to AS-REP roasting attacks
  - Copy-paste lists for vulnerable usernames
  - Next Steps recommendation with actual attack command for hash export
- **Domain Computer Enumeration** (`--computers`) - List all domain computers with OS info
  - Operating system summary with version counts
  - Flags outdated/unsupported systems (Windows 7, Server 2008, etc.)
  - Flags end-of-life systems (Windows 8.1, Server 2012 R2, etc.)
  - Separates servers from workstations in output
  - Copy-paste lists for computer names
  - Next Steps recommendation for relay targeting outdated systems
- **Anonymous Session Probing** - Automatic null/guest session detection when no credentials provided
  - Probes SMB null session (`-u '' -p ''`)
  - Probes SMB guest session (`-u 'Guest' -p ''`)
  - Probes LDAP anonymous bind
  - Continues enumeration with working anonymous session if found
  - Always checks for anonymous access even with credentials (security finding)
- **Hosts Resolution Check** - Pre-flight check ensuring DC hostname resolves to target IP
  - **Runs at the very beginning** before any enumeration or credential validation
  - **Hard stop** if resolution fails (exit with error unless bypassed)
  - Extracts hostname from SMB banner (unauthenticated probe)
  - Verifies DNS resolution matches target IP
  - Provides `/etc/hosts` line for quick fix if resolution fails
  - Use `--skip-hosts-check` to bypass (not recommended)
- **Spider Recommendation** - Next Steps suggests `spider_plus` module for readable shares
  - Enumerate: `nxc smb <target> -u <user> -p <pass> -M spider_plus -o OUTPUT_FOLDER=. MAX_FILE_SIZE=10485760`
  - Download: `nxc smb <target> -u <user> -p <pass> -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=. MAX_FILE_SIZE=10485760`
  - MAX_FILE_SIZE set to 10MB (default 50KB skips useful files)
  - Filters out IPC$ and PRINT$ shares
- **Copy-Paste Output Mode** (`--copy-paste`) - Aggregated simple, line-by-line lists at the end of output for easy copying into other tools
  - All copy-paste sections consolidated into a single section at the end
  - Usernames, share names, group names, DC hostnames/IPs
  - Kerberoastable usernames and SPNs
  - Logged-on users, delegation accounts, target services
  - AdminCount accounts, PASSWD_NOTREQD accounts
  - Lists displayed in magenta to stand out from other output

### Changed
- **Target File Auto-Detection** - Removed `-T` flag, target files are now auto-detected
  - If target argument is an existing file, it's treated as a targets file
  - CIDR and IP ranges take precedence (never mistaken for files)
  - Single positional argument for all target types: IP, hostname, CIDR, range, or file
  - Edge case: if a file exists with hostname name, use IP or FQDN instead
- **Aggregated Copy-Paste Sections** - Copy-paste lists now appear in one consolidated section
  - Moved from inline (after each module) to end of output
  - Cleaner main output without interruptions
  - Multi-target mode: aggregates data from all successful targets
- **Smart Next Steps Commands** - Commands now auto-fill with actual credentials
  - Placeholders like `<user>`, `<pass>` replaced with provided credentials
  - Works with single credential (`-u`/`-p`) and multi-credential (`-C`) modes
  - Supports password and hash authentication (auto-converts `-p` to `-H` for hashes)
  - Handles domain-qualified formats (`DOMAIN\user`, `user@domain`)
  - Makes copy-paste from terminal immediately usable
- **Professional Help Output** - Completely revamped `--help` with organized argument groups
  - Authentication, Multi-Credential Mode, Enumeration Modules, Security Checks, Output, Behavior
  - Unicode box header with feature highlights
  - Concise descriptions with `[admin]` markers for privileged modules
  - Comprehensive examples and credential file format documentation
- **AS-REP Roasting is Now Pure Enumeration** - No longer performs the actual attack
  - Previously used `--asreproast` which requests AS-REP tickets (an attack action)
  - Now uses LDAP query for DONT_REQUIRE_PREAUTH UAC flag (read-only enumeration)
  - Actual attack command provided in Next Steps for manual execution
  - Tool remains purely an enumeration/reconnaissance tool

### Fixed
- Fixed SMB signing output showing raw nxc protocol lines in "Signing Negotiation Info" section
- Fixed Shares fallback showing raw INFO verbose lines instead of clean error messages
- Fixed Users fallback showing raw nxc connection lines instead of clean error messages
- Fixed share names with spaces (e.g., "Human Resources") being truncated to first word
- Fixed inconsistent null session detection between anonymous probe and RPC session check

#### Output Quality Improvements (18 fixes from comprehensive DEBUG vs user output analysis)

**CRITICAL Fixes:**
- **Local Groups parsing** - Rewrote to parse actual nxc format (`RID - GroupName`) instead of incorrectly expecting indented member lines; now correctly displays all local groups with RIDs and highlights high-value groups (Administrators, Server Operators, etc.)
- **RDP NLA extraction** - Added regex to parse `(nla:True/False)` from banner; NLA status now correctly displayed instead of "Unknown"
- **Guest session error codes** - Now parses actual NTSTATUS codes (STATUS_ACCOUNT_DISABLED, STATUS_ACCESS_DENIED, etc.) instead of generic "not available" message
- **AD Subnets exception detection** - Added exception indicator checks; Python errors no longer hidden as "0 subnets found" with success icon

**HIGH Priority Fixes:**
- **Users "Last PW Set" column** - Password last set date now displayed in user table when available
- **LDAP Anonymous bind clarity** - Now clarifies when bind works but search requires authentication
- **Print Spooler CVE context** - Status now mentions "PrintNightmare (CVE-2021-34527)" for security awareness
- **Policy flags decoding** - Password properties hex flags now decoded and displayed (DOMAIN_PASSWORD_STORE_CLEARTEXT, DOMAIN_LOCKOUT_ADMINS, etc.)

**MEDIUM Priority Fixes:**
- **Groups Empty vs Access-Denied** - Now distinguishes between truly empty groups and access-denied groups in output
- **Kerberoastable filtered summary** - Shows filtered account count (machine accounts, DCs, krbtgt) when no roastable accounts found
- **Computers OS correlation** - Uses cached SMB banner OS if LDAP returns no OS info
- **WebDAV uncertainty** - Distinguishes "not running" vs "could not determine" status

**LOW Priority Fixes:**
- **Group member counts** - Membercount from LDAP now displayed in OTHER GROUPS section
- **DC in Workstations list** - DCs now filtered from workstation names in copy-paste output
- **Delegation wording** - Changed "No delegation misconfigurations found" to "No delegation configurations found" (semantic accuracy)
- **Subnets operator precedence** - Fixed operator precedence in error detection logic

### Documentation
- **Revamped README** - Complete rewrite with improved structure and clarity
  - Added "Why nxc-enum?" problem/solution table
  - Updated all examples to reflect auto-detection (no `-T` flag)
  - Reorganized into cleaner, more scannable sections
  - Added multi-target summary and copy-paste list output examples
  - Updated comparison table with checkmarks
  - Reduced redundancy (~33% shorter while covering more features)

## [1.5.1] - 2024-12-01

### Security
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
