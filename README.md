# nxc-enum

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**NetExec wrapper for comprehensive Active Directory enumeration with enum4linux-ng style output.**

> Combines 30+ enumeration modules across SMB, LDAP, MSSQL, RDP, FTP, and NFS into a single tool with colored output, intelligent credential handling, multi-target scanning, and actionable recommendations.

## Why nxc-enum?

| Problem | Solution |
|---------|----------|
| Running nxc commands manually is tedious | Single command runs all modules |
| Raw nxc output is hard to read | Familiar `[*] [+] [-]` status indicators |
| Manual credential testing across shares | Automated share access matrix |
| Figuring out next steps after enumeration | Actionable commands auto-filled with your creds |
| Scanning multiple targets | CIDR, ranges, and target files supported |
| Checking multiple protocols separately | SMB, LDAP, MSSQL, RDP, FTP, NFS in one scan |

## Quick Start

```bash
# No credentials - auto-probes null/guest sessions
nxc-enum 10.0.0.1

# Single credential - full enumeration
nxc-enum 10.0.0.1 -u admin -p 'Password123' -d CORP

# Multiple credentials - compare access levels
nxc-enum 10.0.0.1 -C creds.txt -d CORP

# Multi-target scanning
nxc-enum 10.0.0.0/24 -u admin -p 'Password123'    # CIDR notation
nxc-enum 10.0.0.1-50 -u admin -p 'Password123'    # IP range
nxc-enum targets.txt -u admin -p 'Password123'    # Target file (auto-detected)

# Specific modules only
nxc-enum 10.0.0.1 -u admin -p pass --shares --users --laps --mssql
```

## Installation

### Requirements

- Python 3.10+
- [NetExec](https://github.com/Pennyw0rth/NetExec) installed and in PATH

**Note:** Zero external Python dependencies - uses only the standard library.

### Setup

```bash
git clone https://github.com/Real-Fruit-Snacks/nxc-enum.git
cd nxc-enum

# Option 1: Run directly
python3 nxc_enum.py --help

# Option 2: Install as package
pip install -e .
nxc-enum --help

# Option 3: Create symlink
sudo ln -s $(pwd)/nxc_enum.py /usr/local/bin/nxc-enum
```

---

## Features

### Core Capabilities

- **enum4linux-ng style output** - Colored `[*]`, `[+]`, `[-]` indicators with organized sections
- **30+ enumeration modules** - Users, groups, shares, LAPS, Kerberoastable, delegation, ADCS, MSSQL, and more
- **Multi-protocol support** - SMB, LDAP, MSSQL, RDP, FTP, NFS enumeration
- **Smart credential handling** - Auto-detects NTLM hashes, supports pass-the-hash
- **Local admin detection** - Automatically identifies Pwn3d! accounts
- **Result caching** - ~50% faster via parallel execution and deduplication

### Multi-Target Scanning

Scan entire networks with a single command:

```bash
nxc-enum 10.0.0.0/24 -u admin -p pass        # CIDR notation
nxc-enum 10.0.0.1-50 -u admin -p pass        # Short range (last octet)
nxc-enum 10.0.0.1-10.0.0.50 -u admin -p pass # Full range
nxc-enum targets.txt -u admin -p pass        # Target file (auto-detected!)
```

**Target type is auto-detected:**
1. Contains `/` → CIDR notation
2. Contains `-` with digits → IP range
3. File exists on disk → Target file
4. Otherwise → Hostname/IP

**Multi-target output includes:**
- Per-target results with clear separation
- Aggregate summary across all targets
- Combined security findings (signing disabled, anonymous access, etc.)
- Graceful failure handling - continues on failed targets

### Multi-Credential Mode

Test multiple credentials and compare access levels:

```bash
nxc-enum 10.0.0.1 -C creds.txt -d CORP              # Credentials file
nxc-enum 10.0.0.1 -U users.txt -P passwords.txt     # Separate files
```

**Features:**
- Visual share access matrix showing permissions per user
- Credentials grouped by admin status
- Admin-only commands skip non-admin users automatically
- Universal commands run once, per-user commands run for each credential

### Copy-Paste Output (`--copy-paste`)

Get clean, line-by-line lists for piping to other tools:

```bash
nxc-enum 10.0.0.1 -u admin -p pass --copy-paste
```

**Output includes:**
- Usernames, group names, share names
- Kerberoastable usernames and SPNs
- AS-REP roastable usernames
- Delegation accounts, DC hostnames/IPs
- Computer names (servers/workstations)
- LAPS-enabled computers, local admin members
- Pre-2K computers, AD subnets
- MSSQL databases, NFS exports

All copy-paste lists appear in a single consolidated section at the end.

### Actionable Next Steps

The tool analyzes findings and provides ready-to-run commands:

```
HIGH PRIORITY (3)
------------------------------------------------------------
  → LAPS readable on 15 computers
    Retrieve LAPS passwords for local admin access
    $ nxc ldap 10.0.0.1 -u 'admin' -p 'Password123' -M laps

  → Kerberoastable accounts: svc_sql, svc_backup
    Request TGS tickets for offline cracking with hashcat
    $ nxc ldap 10.0.0.1 -u 'admin' -p 'Password123' --kerberoasting hashes.txt

  → LDAP signing not required
    LDAP relay to create machine account for RBCD attack
    $ ntlmrelayx.py -t ldap://10.0.0.1 --delegate-access
```

**Credentials are auto-filled** from your input - commands are ready to copy-paste.

---

## Usage Guide

### Hosts Resolution Check (Pre-Flight)

**Before any enumeration begins**, nxc-enum verifies that the DC hostname resolves correctly:

```
[*] Verifying DC hostname resolution...
[+] DC hostname 'DC01.corp.local' resolves correctly
```

If resolution fails:
```
[*] Verifying DC hostname resolution...
[-] DC hostname does not resolve to target IP
    Add to /etc/hosts: 10.0.24.230  DC01.corp.local  CORP  DC01

[*] Use --skip-hosts-check to bypass this check (not recommended)
```

**Why this matters:** Kerberos authentication requires the DC hostname to resolve correctly. Without proper resolution, authentication may fail or use NTLM fallback.

**To fix:** Add the suggested line to `/etc/hosts`, or use `--skip-hosts-check` to bypass (not recommended).

### Anonymous Enumeration

When no credentials are provided, nxc-enum automatically probes for anonymous access:

```bash
nxc-enum 10.0.0.1
```

The tool attempts:
1. **SMB null session** (`-u '' -p ''`)
2. **SMB guest session** (`-u 'Guest' -p ''`)
3. **LDAP anonymous bind**

If any succeed, enumeration continues with that session.

### Single Credential Mode

```bash
# Basic authentication
nxc-enum 10.0.0.1 -u admin -p 'Password123'

# With domain
nxc-enum 10.0.0.1 -u admin -p 'Password123' -d CORP

# Pass-the-hash
nxc-enum 10.0.0.1 -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Specific modules
nxc-enum 10.0.0.1 -u admin -p pass --shares --users --laps --mssql

# Security-focused scan
nxc-enum 10.0.0.1 -u admin -p pass --laps --ldap-signing --pre2k --delegation

# Output to file
nxc-enum 10.0.0.1 -u admin -p pass -o results.txt

# JSON output
nxc-enum 10.0.0.1 -u admin -p pass -j -o results.json

# Debug mode (show raw nxc output)
nxc-enum 10.0.0.1 -u admin -p pass --debug
```

### Credential File Formats

**creds.txt** (user:password or user:hash per line):
```
admin:Password123
faraday:hacksmarter123
svc_backup:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
# Lines starting with # are ignored
```

NTLM hashes are auto-detected (32:32 hex format).

**users.txt / passwords.txt** (paired line-by-line):
```
# users.txt     # passwords.txt
admin           Password123
faraday         hacksmarter123
svc_backup      Summer2024!
```

### Target File Format

**targets.txt**:
```
# Comments start with #
10.0.0.1
10.0.0.2
192.168.1.0/24
172.16.0.1-50
dc01.corp.local
```

Targets can be IPs, hostnames, CIDR ranges, or IP ranges - all in the same file.

---

## Command Reference

### Target

| Argument | Description |
|----------|-------------|
| `TARGET` | IP, hostname, CIDR, range, or target file (auto-detected) |

### Authentication

| Flag | Description |
|------|-------------|
| `-u, --user` | Username |
| `-p, --password` | Password |
| `-H, --hash` | NTLM hash (LM:NT or NT only) |
| `-d, --domain` | Domain name |

### Multi-Credential Mode

| Flag | Description |
|------|-------------|
| `-C, --credfile` | Credentials file (user:password per line) |
| `-U, --userfile` | Usernames file (one per line) |
| `-P, --passfile` | Passwords file (paired with -U) |

### Enumeration Modules

| Flag | Description |
|------|-------------|
| `-A, --all` | Run all enumeration modules |
| `--users` | Domain users via RPC |
| `--groups` | Domain groups with members |
| `--shares` | SMB shares and permissions |
| `--policies` | Password and lockout policies |
| `--sessions` | Active sessions `[admin]` |
| `--loggedon` | Logged on users `[admin]` |
| `--printers` | Printers and spooler status |
| `--av` | AV/EDR products `[admin]` |
| `--computers` | Domain computers with OS info |
| `--local-groups` | Local groups and members |
| `--subnets` | AD sites and subnets |

### Security Checks

| Flag | Description |
|------|-------------|
| `--laps` | LAPS deployment check |
| `--ldap-signing` | LDAP signing requirements |
| `--pre2k` | Pre-Windows 2000 computers |
| `--bitlocker` | BitLocker status `[admin]` |
| `--delegation` | Delegation misconfigurations |
| `--asreproast` | AS-REP roastable accounts |
| `--adcs` | ADCS certificate templates |
| `--dc-list` | Domain controllers and trusts |
| `--pwd-not-reqd` | Accounts with PASSWD_NOTREQD |
| `--admin-count` | Accounts with adminCount=1 |
| `--maq` | Machine account quota |
| `--descriptions` | User description fields |
| `--signing` | SMB signing requirements |
| `--webdav` | WebClient service status |
| `--dns` | DNS records |

### Other Protocols

| Flag | Description |
|------|-------------|
| `--mssql` | MSSQL databases and linked servers |
| `--rdp` | RDP status and NLA check |
| `--ftp` | FTP anonymous access |
| `--nfs` | NFS share exports |

### Output

| Flag | Description |
|------|-------------|
| `-o, --output` | Write output to file |
| `-j, --json` | JSON format (requires -o) |
| `--copy-paste` | Include copy-pastable lists |
| `-q, --quiet` | Suppress banner |

### Behavior

| Flag | Description |
|------|-------------|
| `-t, --timeout` | Command timeout in seconds (default: 30) |
| `--no-validate` | Skip credential validation |
| `--skip-hosts-check` | Skip /etc/hosts resolution check (see below) |
| `--debug` | Show raw nxc command output |

**Note on Hosts Resolution Check:** Before any enumeration begins, nxc-enum verifies that the DC hostname resolves to the target IP. If resolution fails, the tool exits with an error and provides the required `/etc/hosts` entry. Use `--skip-hosts-check` to bypass (not recommended - may cause authentication issues).

---

## Example Output

### Security Findings

```
LDAP SECURITY CONFIGURATION
--------------------------------------------------
  [!] LDAP Signing: NOT REQUIRED
      Vulnerable to LDAP relay attacks

  [!] Channel Binding: NOT ENFORCED
      May be vulnerable to certain relay attacks

LAPS DEPLOYMENT CHECK
--------------------------------------------------
[+] Found 15 computer(s) with LAPS configured
[!] Current user CAN read LAPS passwords!
    This indicates high privileges (Domain Admin, LAPS readers, etc.)

PRE-WINDOWS 2000 COMPUTERS
--------------------------------------------------
[!] Found 3 computer(s) with pre-Windows 2000 compatibility!
[!] Password = lowercase computer name (without $)
  [!] OLDPC01$
      Password likely: oldpc01
```

### Share Access Matrix (Multi-Credential)

```
Share         faraday     admin       svc_backup
------------- ----------  ----------  ----------
ADMIN$        -           READ,WRITE  -
C$            -           READ,WRITE  -
IPC$          READ        READ        READ
NETLOGON      READ        READ        READ
SYSVOL        READ        READ        READ
Backups$      READ        READ,WRITE  READ,WRITE

Legend: WRITE (green) | READ (yellow) | - = No Access

[!] Non-default share 'Backups$' accessible by: admin (RW), svc_backup (RW), faraday (R)
```

### Multi-Target Summary

```
================================================================================
                      MULTI-TARGET SUMMARY (3 targets)
================================================================================

TARGET STATUS
--------------------------------------------------
  [+] 10.0.0.1 - Completed (15.2s)
  [+] 10.0.0.2 - Completed (12.8s)
  [-] 10.0.0.3 - Failed: Connection refused

AGGREGATE FINDINGS
--------------------------------------------------
  [!] SMB Signing Disabled: 2 target(s)
      - 10.0.0.1
      - 10.0.0.2
  [!] LDAP Signing Not Required: 2 target(s)
  [*] Kerberoastable Accounts: 5 total
  [*] AS-REP Roastable Accounts: 2 total
  [*] LAPS Computers: 15 total

STATISTICS
--------------------------------------------------
  Successful: 2/3
  Total Users Enumerated: 47
  Total Shares Found: 12
  Total Scan Time: 28.00s
```

### MSSQL Enumeration

```
MSSQL SERVER INFO
--------------------------------------------------
  Version: SQL Server 2019
  [!] Current user has SYSADMIN privileges!

DATABASES (5)
--------------------------------------------------
  [*] master (system)
  [*] tempdb (system)
  [*] msdb (system)
  [+] HRDatabase (user)
  [+] AppData (user)

LINKED SERVERS (2)
--------------------------------------------------
  [!] SQL02.corp.local
  [!] REPORTING
  [*] Linked servers may allow lateral movement
```

---

## Enumeration Modules

When run without specific flags, all modules are executed:

| Module | Description |
|--------|-------------|
| **Pre-Flight** | |
| Hosts Resolution | Verifies DC hostname resolves to target IP (hard stop if fails) |
| **Core** | |
| Anonymous Probe | Null/guest/LDAP anonymous access |
| Target Info | Target details, credentials (grouped by admin) |
| Listener Scan | LDAP (389/636), SMB (445), NetBIOS (139) |
| Domain Intelligence | SID, DC, FQDN, NetBIOS, DNS domain |
| SMB Dialect | SMB versions, signing requirements |
| RPC Session | Null session, guest access status |
| OS Information | Windows version, build number |
| **User/Group** | |
| Users | User list with categories (built-in, service, domain) |
| Groups | Groups with high-value highlighting and members |
| Local Groups | Local groups and Administrators members |
| Computers | Computer list with OS summary, outdated detection |
| **Resources** | |
| Shares | Permissions (matrix in multi-cred mode) |
| Printers | Print spooler status (PrintNightmare warning) |
| AD Subnets | AD sites and network topology |
| **Security** | |
| Policies | Password and lockout policies |
| Sessions | Active Windows sessions `[admin]` |
| Logged On | Currently logged on users `[admin]` |
| AV/EDR | Installed security products `[admin]` |
| LAPS | LAPS deployment and read permissions |
| LDAP Signing | Signing and channel binding requirements |
| Pre-2K Computers | Computers with weak passwords |
| BitLocker | Drive encryption status `[admin]` |
| Kerberoastable | Accounts with SPNs via LDAP |
| AS-REP Roastable | Accounts without pre-authentication |
| Delegation | Unconstrained/constrained delegation |
| ADCS | Certificate templates and CAs |
| DC List | Domain controllers and trusts |
| AdminCount | Accounts with adminCount=1 |
| PASSWD_NOTREQD | Accounts without password requirement |
| **Other Protocols** | |
| MSSQL | Databases, linked servers, sysadmin check |
| RDP | RDP status and NLA requirements |
| FTP | Anonymous FTP access |
| NFS | NFS exports and permissions |
| **Reporting** | |
| Executive Summary | Security posture and attack vectors |
| Next Steps | Actionable follow-up commands |
| Copy-Paste Lists | Clean output for other tools |

---

## Security Considerations

### Credential Protection

1. **Output File Permissions** - Files created with `0o600` (owner read/write only)
2. **Credential File Warnings** - Alerts if credential files have overly permissive permissions

### Known Limitations

- **Process Visibility** - Credentials are passed as CLI arguments to nxc (visible via `ps aux`)

### Best Practices

```bash
# Set proper permissions on credential files
chmod 600 creds.txt

# Use hash-based auth when possible
nxc-enum 10.0.0.1 -u admin -H <hash>

# Clear history after sensitive operations
history -c
```

---

## Performance

nxc-enum uses a multi-phase parallel execution architecture:

- **Parallel Port Scanning** - All ports checked simultaneously
- **Parallel Cache Priming** - SMB, RID brute, LDAP run in parallel
- **Parallel Credential Validation** - Up to 10 concurrent workers
- **Parallel Module Execution** - Independent modules run simultaneously
- **Result Caching** - No redundant network calls

Result: **~50% faster** than sequential execution.

---

## Comparison with enum4linux-ng

| Feature | enum4linux-ng | nxc-enum |
|---------|:-------------:|:--------:|
| SMB/LDAP Enumeration | ✓ | ✓ |
| User/Group/Share Enumeration | ✓ | ✓ |
| RID Cycling | ✓ | ✓ |
| Domain SID | ✓ | ✓ |
| Pass-the-Hash | ✗ | ✓ |
| Multi-Credential Mode | ✗ | ✓ |
| Multi-Target Scanning | ✗ | ✓ |
| Share Access Matrix | ✗ | ✓ |
| Local Admin Detection | ✗ | ✓ |
| AV/EDR Detection | ✗ | ✓ |
| LAPS Enumeration | ✗ | ✓ |
| LDAP Signing Check | ✗ | ✓ |
| Pre-2K Computer Detection | ✗ | ✓ |
| Kerberoastable Detection | ✗ | ✓ |
| AS-REP Roastable Detection | ✗ | ✓ |
| Delegation Analysis | ✗ | ✓ |
| ADCS Enumeration | ✗ | ✓ |
| MSSQL Enumeration | ✗ | ✓ |
| RDP/NLA Check | ✗ | ✓ |
| FTP Anonymous Check | ✗ | ✓ |
| NFS Export Enumeration | ✗ | ✓ |
| Outdated OS Detection | ✗ | ✓ |
| Next Steps Recommendations | ✗ | ✓ |
| Result Caching | ✗ | ✓ |
| Copy-Paste Lists | ✗ | ✓ |

---

## Development

### Setup

```bash
git clone https://github.com/Real-Fruit-Snacks/nxc-enum.git
cd nxc-enum
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
```

### Testing

```bash
pytest tests/ -v                           # Run all tests
pytest tests/ --cov=nxc_enum               # With coverage
```

### Code Style

```bash
black nxc_enum/ tests/                     # Format code
isort nxc_enum/ tests/                     # Sort imports
flake8 nxc_enum/ tests/ --max-line-length=100
```

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Security Note:** Please follow responsible disclosure for any vulnerabilities discovered.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

MIT License - see [LICENSE](LICENSE).

## Credits

- [NetExec](https://github.com/Pennyw0rth/NetExec) - The underlying enumeration engine
- [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) - Inspiration for output format

## Author

**Real-Fruit-Snacks** - [GitHub](https://github.com/Real-Fruit-Snacks)

[Open an issue](https://github.com/Real-Fruit-Snacks/nxc-enum/issues) for bugs or feature requests.
