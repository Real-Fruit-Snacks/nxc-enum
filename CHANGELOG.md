# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.8.0] - 2025-01-19

### Added
- **Kerberos Authentication** - Full Kerberos authentication support
  - `-k, --kerberos` - Use Kerberos authentication
  - `--use-kcache` - Use credentials from ccache file (KRB5CCNAME env var)
  - `--aesKey` - AES key for Kerberos authentication (128 or 256 bit)
  - `--kdcHost` - FQDN of the Key Distribution Center for Kerberos
  - Example: `nxc-enum dc01.corp.local -u admin --use-kcache`
  - Example: `nxc-enum dc01.corp.local -u admin --aesKey <key> --kdcHost dc01.corp.local`
- **Certificate Authentication** - PKINIT certificate-based authentication
  - `--pfx-cert` - Path to PFX certificate file
  - `--pfx-pass` - Password for PFX certificate file
  - `--pem-cert` - Path to PEM certificate file
  - `--pem-key` - Path to PEM private key file
  - Example: `nxc-enum dc01.corp.local -u admin --pfx-cert admin.pfx --pfx-pass certpass`
- **Local Authentication** (`--local-auth`) - Authenticate against local SAM instead of domain
  - Useful for targeting local admin accounts on member servers
  - Example: `nxc-enum 192.168.1.100 -u Administrator -p pass --local-auth`
- **Kerberos Delegation** - S4U2proxy and S4U2self delegation support
  - `--delegate` - Impersonate user via S4U2proxy delegation
  - `--self` - Use S4U2self extension with --delegate
  - Example: `nxc-enum dc01.corp.local -u svc_sql -p pass --delegate admin --self`
- **Spray Control Options** - Fine-grained control over credential testing
  - `--continue-on-success` - Continue testing credentials after finding valid ones
  - `--jitter` - Random delay (0 to SEC) between credential attempts (forces sequential)
  - `--fail-limit` - Stop after N total failed login attempts
  - `--ufail-limit` - Stop testing a user after N failed attempts for that user
  - `--gfail-limit` - Stop after N consecutive failed attempts globally
  - Example: `nxc-enum 10.0.0.1 -U users.txt -p 'Summer2024!' --jitter 2 --fail-limit 10`
- **Active Users Filter** (`--active-users`) - Only show active/enabled user accounts
  - Filters out disabled accounts from user enumeration
  - Useful for targeting only active accounts
- **Shares Access Filter** (`--shares-filter`) - Filter shares by access level
  - `--shares-filter READ` - Only show shares with read access
  - `--shares-filter WRITE` - Only show shares with write access
- **Local Groups Filter** (`--local-groups-filter`) - Filter to specific local group
  - Example: `nxc-enum 10.0.0.1 -u admin -p pass --local-groups --local-groups-filter Administrators`
- **Custom LDAP Query** (`--query`, `--query-attrs`) - Execute custom LDAP queries
  - `--query` - LDAP filter (e.g., '(objectClass=user)')
  - `--query-attrs` - Attributes to retrieve (comma-separated)
  - Example: `nxc-enum 10.0.0.1 -u admin -p pass --query '(objectClass=computer)' --query-attrs cn,operatingSystem`
- **Network Options** - Protocol and network configuration
  - `--port` - Custom SMB port (default: 445)
  - `--smb-timeout` - Timeout for SMB operations specifically
  - `--no-smb` - Skip SMB connection validation (for pure LDAP operations)
  - `-6, --ipv6` - Use IPv6 for connections
  - `--dns-server` - Custom DNS server for hostname resolution
  - `--dns-tcp` - Use TCP for DNS queries instead of UDP

### Changed
- **Credential Validation** - Now supports sequential mode with spray controls
  - Parallel mode (default) for fast validation when no spray options set
  - Sequential mode auto-enabled when jitter or fail limits are specified
  - Per-user failure tracking with `--ufail-limit`
  - Consecutive failure tracking with `--gfail-limit`
- **Credential Model** - Extended to support all authentication methods
  - `auth_type()` now returns: 'certificate', 'kerberos', 'password', 'hash', or 'none'
  - `has_auth()` accepts kcache, AES key, or certificate as valid authentication
  - Sensitive fields (password, hash, AES key, pfx_pass) redacted in repr output

### Documentation
- Added Kerberos Authentication section to README
- Added Certificate Authentication section to README
- Added Spray Control Options to Multi-Credential Mode section
- Added Network Options section to README
- Updated Command Reference with all new arguments

## [1.7.0] - 2025-01-07

### Added
- **Proxy Mode** (`--proxy-mode`) - Optimize for proxychains/SOCKS operation
  - Reduces parallel workers (15 → 2, 100 → 5) to prevent proxy overload
  - Increases timeouts (30s → 120s) for proxy latency
  - Skips incompatible modules (iOXID, VNC) that use raw sockets
  - Skips hostname validation (DNS bypasses proxy)
  - Auto-detects proxychains via LD_PRELOAD environment variable
  - Example: `proxychains nxc-enum 10.0.0.1 -u user -p pass`
- **Validate-Only Mode** (`--validate-only`) - Fast credential testing without enumeration
  - Validates credentials and shows results immediately
  - Detects local admin status (Pwn3d!)
  - Supports single and multi-credential modes
  - Much faster than full enumeration for credential spraying workflows
  - Example: `nxc-enum 10.0.0.1 -C creds.txt --validate-only`
- **Spider Module Options** - New CLI options for share spidering control
  - `--spider` - Spider shares for files (metadata only by default)
  - `--spider-download` - Enable file download during spidering (use with caution)
  - `--spider-max-size` - Max file size to download in bytes (default: 10MB)
  - `--spider-output` - Output directory for downloaded files
- **LAPS Computer Filter** (`--laps-computer`) - Filter LAPS check to specific computers
  - Supports wildcard patterns (e.g., `--laps-computer 'SRV*'`)
  - Useful for large domains to target specific server groups
- **ADCS Server Options** - Enhanced ADCS enumeration control
  - `--adcs-server` - Target specific ADCS server (e.g., 'ca01.corp.local')
  - `--adcs-base-dn` - Custom base DN for ADCS search
- **FTP Credential Testing** - FTP module now tests with provided credentials
  - First tries anonymous access (as before)
  - If anonymous fails AND credentials provided, tests with SMB credentials
  - Reports success/failure for both anonymous and authenticated access
  - Lists files on successful authenticated login
  - No longer just suggests testing credentials as a "next step"
- **9 New Enumeration Modules** - Expanded coverage for penetration testing
  - **gMSA Enumeration** (`gmsa.py`) - Enumerates Group Managed Service Accounts and checks
    if passwords are readable (high-value credential target)
  - **GPP Password Extraction** (`gpp_password.py`) - Reads SYSVOL for Group Policy Preferences
    cpassword values (MS14-025), decrypts locally with known AES key
  - **Network Interfaces** (`interfaces.py`) - Enumerates interfaces via SMB IOCTL, identifies
    multi-homed hosts for pivoting opportunities
  - **Disk Enumeration** (`disks.py`) - Lists disk drives via SRVSVC RPC for storage mapping
  - **Share File Spider** (`spider.py`) - Recursively lists files on shares using spider_plus,
    highlights interesting files (configs, scripts, backups, keys)
  - **SCCM/MECM Discovery** (`sccm.py`) - Discovers SCCM infrastructure from AD, identifies
    site servers, management points, distribution points
  - **VNC Detection** (`vnc.py`) - Scans for VNC services on ports 5900-5903/5800-5801,
    detects unauthenticated access configurations
  - **Fine-Grained Password Policies** (`pso.py`) - Enumerates PSO objects that override
    default password policy, identifies weak policies affecting specific groups
  - **iOXIDResolver** (`ioxid.py`) - Discovers network interfaces via DCOM port 135,
    works without authentication, finds multi-homed hosts for pivoting
- **Discover-Only Mode** (`--discover-only`) - Quick reconnaissance without enumeration
  - Only discovers live SMB hosts, skips all enumeration modules
  - No credentials required - purely network reconnaissance
  - Shows IP, hostname, domain, signing status, and SMBv1 for each host
  - Supports JSON output (`-j -o hosts.json`) for integration with other tools
  - Ideal for initial network mapping before targeted enumeration
  - Example: `nxc-enum 10.0.0.0/24 --discover-only`
- **Parallel Host Pre-scanning** - Dramatically faster multi-target scanning
  - Phase 1: Parallel TCP port 445 scan (100 workers, 0.5s timeout) filters unreachable hosts
  - Phase 2: Parallel SMB validation (20 workers) extracts hostname/domain for live hosts
  - Auto-enabled when targets > 5, use `--no-prescan` to disable
  - /24 network scan (256 hosts): ~42 minutes → ~15 seconds for host discovery
  - Pre-computed SMB info cached and reused during enumeration (no double validation)
- **Discovered Hosts Display** - Shows discovered hosts with hostnames before enumeration
  - Displays `[+] Discovered SMB hosts:` with IP and hostname for each live target
  - Helpful for visibility into which hosts will be enumerated
  - Shows hostname/FQDN extracted during SMB validation phase

### Changed
- **TARGET STATUS Display** - Multi-target summary now shows hostname next to each IP
  - Example: `[+] 10.10.205.146 (DC01) - Completed (121.4s)`
  - Hostname extracted from cache.domain_info when available
- **GPP Password Module Messaging** - Improved output clarity
  - Now lists which GPP XML files were searched (Groups.xml, Services.xml, etc.)
  - Clearer distinction between "not found" and "patched/never used"
  - Suggests Domain User rights when SYSVOL access denied

### Fixed
- **DEBUG Output Noise Filtering** - Fixed upstream nxc tracebacks leaking into DEBUG output
  - Added `_is_debug_noise_line()` filter function to `output.py`
  - Enhanced `is_nxc_noise_line()` in `nxc_output.py` to detect Rich-formatted tracebacks
  - Filters Python tracebacks, Rich box-drawing characters, ERROR lines, exception messages
  - Preserves useful INFO lines while removing upstream nxc bug noise
- **AD Subnets Alternative Command** - Added ldapsearch fallback when get-network module fails
  - Detects module exceptions (PyAsn1UnicodeDecodeError, etc.) and shows helpful message
  - Provides ready-to-run ldapsearch command with correct base DN for subnet enumeration
  - Dynamically constructs DN from domain info: `CN=Subnets,CN=Sites,CN=Configuration,DC=...`
- **RID Brute Parsing** - Fixed regex to handle output without DOMAIN\ prefix
  - Pattern `(\d+):\s*(?:\S+\\)?(\S+)\s+\(SidTypeUser\)` now makes DOMAIN\ optional
  - Fixes silent parsing failure when nxc outputs RID users without domain prefix
- **MSSQL Detection False Negative** - Fixed noise filter incorrectly discarding status lines
  - `is_nxc_noise_line()` now preserves lines with `[+]`, `[-]`, `[*]`, `[!]` indicators
  - Fixes bug where successful MSSQL auth was reported as "service not detected"
- **Computers Module List Attribute Crash** - Fixed `.lower()` called on list attributes
  - `categorize_os()` now handles LDAP multi-valued attributes safely
  - Added defensive `get_os_category()` helper for server/workstation classification
  - Fixes `'list' object has no attribute 'lower'` error in Computers module
- **LDAP Anonymous Probe "(good)" Message** - Fixed misleading success message
  - Added `ldap_unavailable` flag to distinguish connection failure from access denied
  - Added "failed to create connection object" to failure indicator list
  - Now shows "No anonymous access available (LDAP service unavailable)" for non-DCs
  - Only shows "(good)" when LDAP service was accessible but explicitly rejected
- **Early LDAP Module Filtering** - Skip LDAP modules before thread pool submission
  - 16 LDAP-dependent modules now filtered upfront when `cache.ldap_available=False`
  - Single summary message "LDAP unavailable - skipping N LDAP-dependent modules"
  - Reduces thread pool overhead and eliminates redundant individual skip messages

### Performance
- **LDAP Availability Early-Return** - Skip LDAP modules instantly on member servers
  - 15 LDAP-dependent modules now check `cache.ldap_available` before execution
  - Member servers (LDAP ports closed) skip all LDAP modules in <1ms each
  - Previously: Each module attempted LDAP connection, timed out after 15-30s
  - Affected modules: admin_count, delegation, adcs, dc_list, maq, subnets, pso, pre2k,
    pwd_not_required, descriptions, kerberoastable, asreproast, computers, laps, gmsa
  - Impact: ~45-60s saved on member server scans (15 modules × 3s avg timeout)
- **Parallel Multi-Target Enumeration** - Targets now enumerated in parallel (~5x faster)
  - Multi-target mode (>1 target) uses ThreadPoolExecutor with 5 concurrent workers
  - Atomic output buffering prevents output interleaving between targets
  - Single-target mode unchanged (no parallel overhead)
  - 10 targets × 30s each: 5 minutes → ~1 minute
- **Expanded Parallel Module Execution** - 29 modules run in parallel (up from 7)
  - Added 22 independent modules to parallel execution: delegation, pwd_not_required,
    maq, pre2k, dns, webdav, laps, ldap_signing, local_groups, mssql, rdp, ftp, nfs,
    gmsa, pso, sccm, gpp_password, interfaces, disks, vnc, ioxid
  - Worker pool increased from 7 to 15 workers
  - ~50-70% faster single-target enumeration
- **Expanded Cache Priming** - 5 queries primed in parallel (up from 3)
  - Added password policy and LDAP users queries to cache priming
  - Worker pool increased from 3 to 5 workers
  - Reduces redundant network calls during enumeration
- **Tiered Timeout Constants** - Operation-specific timeout configuration
  - Port scan: 0.5s (fast TCP connect)
  - SMB validation: 5s
  - LDAP query: 15s
  - Module default: 30s
  - Heavy modules: 120s
- **LDAP Availability Detection** - Fixed `cache.ldap_available` not detecting LDAP failures
  - Bug: Check only examined stderr, but LDAP failure messages appear in stdout
  - Symptom: LDAP modules ran on member servers despite ports being closed
  - Fix: Now checks both stdout and stderr for failure indicators
  - Indicators: "failed to create connection", "failed to connect", "connection refused",
    "ldap ping failed", "error"
- **Password Placeholder in smbclient Commands** - Fixed `<password>` not being substituted
  - Added regex pattern to handle smbclient credential format (`-U 'user%<password>'`)
  - Previously: `smbclient //host/share -U 'user%<password>'` (placeholder not replaced)
  - Now: `smbclient //host/share -U 'user%ActualPassword'` (correctly substituted)
- **Special Characters in Passwords** - Fixed shell escaping for passwords with special chars
  - Passwords containing backslashes and single quotes now properly escaped
  - Prevents command injection and shell parsing errors in Next Steps commands
- **Missing Multi-Target Copy-Paste Categories** - Added 11 missing categories to aggregated output
  - Added: targets, gmsa_accounts, gpp_passwords, interface_ips, disk_drives,
    interesting_files, sccm_servers, vnc_ports, weak_pso_groups, ioxid_addresses, pivot_ips
  - Multi-target aggregated copy-paste now matches single-target output categories
- **Impacket Credential Placeholders** - Fixed `:<pass>` not being substituted in quoted strings
  - Commands like `getST.py 'domain/user:<pass>'` now properly substitute the password
  - Previously: `'domain/user:<pass>'` (placeholder not replaced inside quotes)
  - Now: `'domain/user:ActualPassword'` (correctly substituted)
- **User@Domain Placeholder Format** - Fixed `-u <user>@<domain>` not being substituted
  - Commands with both `<user>` and `<domain>` placeholders now correctly substitute both
  - Previously: `-u <user>@<domain>` remained as placeholders
  - Now: `-u 'actualuser@actualdomain.local'` (both replaced and properly quoted)
- **CRITICAL: Multi-target CIDR bug** - Fixed all 34 enumeration modules passing CIDR notation to nxc
  - Previously: `nxc smb 10.0.0.0/24 --shares` (scanned entire /24 for every command!)
  - Now: `nxc smb 10.0.0.1 --shares` (correctly uses individual resolved target)
  - Root cause: modules used `args.target` (user input) instead of `cache.target` (resolved IP)
  - Impact: Prevented massive performance degradation and hundreds of connection errors
- **DNS enumeration attribute error** - Fixed `'EnumCache' object has no attribute 'listener_results'`
  - Added `cache.listener_results` storage after listener scan
  - Made dns.py gracefully handle missing attribute when running specific modules

### Changed
- **MSSQL Module - Detection Only** - Rewritten for passive enumeration philosophy
  - Now only tests MSSQL connectivity and authentication
  - NO SQL queries executed on the target (removed `-q` queries)
  - Detects hostname, authentication status, and sysadmin privileges
  - Provides ready-to-run commands as recommendations:
    - Database enumeration (`SELECT name FROM master.dbo.sysdatabases`)
    - Linked servers (`SELECT name FROM sys.servers WHERE is_linked=1`)
    - Privilege check (`-M mssql_priv`)
    - Login enumeration (`-M enum_logins`)
  - User decides when to run queries manually
- **DNS Module - Recommendation Only** - Rewritten for passive enumeration philosophy
  - NO WMI queries executed on the target (nxc `enum_dns` uses WMI)
  - Checks if LDAP/DNS ports are available for enumeration
  - Recommends LDAP-based tools instead:
    - `adidnsdump` for AD-integrated DNS zone dumps
    - `dnstool.py` for specific record queries
    - `dig`/`dnsrecon` for standard DNS enumeration
  - Provides nxc `enum_dns` as alternative (notes it uses WMI)
- **Admin Privilege Checks** - Modules now properly skip when admin not detected
  - `disks.py` - Added `is_admin` parameter, skips gracefully if not admin
  - `local_groups.py` - Added `is_admin` parameter, skips gracefully if not admin
  - `parallel.py` - Updated to pass `needs_admin=True` for disks and local_groups
- **Module Exports Completed** - Added 9 missing exports to `__init__.py`
  - Added: `enum_gmsa`, `enum_gpp_password`, `enum_pso`, `enum_sccm`
  - Added: `enum_disks`, `enum_interfaces`, `enum_ioxid`, `enum_spider`, `enum_vnc`
  - All new modules now properly importable from `nxc_enum.enums`
- **SMB-based Host Validation** - Replaced ICMP ping with SMB-based reachability check
  - More reliable: ICMP ping is commonly blocked by firewalls, SMB ports rarely are
  - Confirms target is a Windows machine with SMB services running
  - Extracts hostname/domain during validation (eliminates redundant SMB call)
  - Single SMB connection now performs both reachability check and hosts resolution data extraction

### Documentation
- **Passive Enumeration Philosophy** - Added new section to README explaining design principles
  - Documents allowed operations (LDAP reads, SMB enumeration, RPC queries)
  - Documents prohibited operations (SQL queries, WMI, Kerberos tickets, command execution)
  - Explains recommendation pattern for MSSQL, DNS, Kerberoast, shares
- **Updated Command Reference** - Added new CLI options to documentation
  - Spider options (`--spider`, `--spider-download`, `--spider-max-size`, `--spider-output`)
  - LAPS filter (`--laps-computer`)
  - ADCS options (`--adcs-server`, `--adcs-base-dn`)
- **Updated Module Descriptions** - Clarified passive nature of MSSQL and DNS modules
  - MSSQL: "MSSQL detection and auth test (recommends queries)"
  - DNS: "DNS enumeration recommendations (passive)"

### Removed
- **ICMP Ping Check** - Removed `ping_host()` function in favor of SMB validation
  - Ping-based checks caused false negatives on hosts with ICMP blocked
  - SMB validation is more appropriate for AD enumeration tool

## [1.6.0] - 2025-01-04

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

[Unreleased]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.8.0...HEAD
[1.8.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Real-Fruit-Snacks/nxc-enum/releases/tag/v1.0.0
