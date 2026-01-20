# nxc-enum

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**NetExec wrapper for comprehensive Active Directory enumeration with enum4linux-ng style output.**

> Combines 35+ enumeration modules across SMB, LDAP, MSSQL, RDP, FTP, and NFS into a single tool with colored output, intelligent credential handling, multi-target scanning, and actionable recommendations.

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

# Kerberos authentication (ccache or AES key)
nxc-enum dc01.corp.local -u admin --use-kcache
nxc-enum dc01.corp.local -u admin -p pass -k

# Certificate authentication (PKINIT)
nxc-enum dc01.corp.local -u admin --pfx-cert admin.pfx

# Multi-target scanning
nxc-enum 10.0.0.0/24 -u admin -p 'Password123'    # CIDR notation
nxc-enum 10.0.0.1-50 -u admin -p 'Password123'    # IP range
nxc-enum targets.txt -u admin -p 'Password123'    # Target file (auto-detected)

# Discover live SMB hosts only (no creds required)
nxc-enum 10.0.0.0/24 --discover-only

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
- **35+ enumeration modules** - Users, groups, shares, LAPS, Kerberoastable, delegation, ADCS, MSSQL, gMSA, PSO, SCCM, and more
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
- Discovered hosts display with hostnames before enumeration starts
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

### SMB Reachability & Hosts Resolution Check (Pre-Flight)

**Before any enumeration begins**, nxc-enum performs two pre-flight checks:

1. **SMB Reachability** - Validates the target responds to SMB (port 445)
2. **Hosts Resolution** - Verifies the DC hostname resolves to the target IP

```
[*] Checking SMB reachability...
[+] Target hostname 'DC01.corp.local' resolves correctly
```

If the target doesn't respond to SMB:
```
[*] Checking SMB reachability...
[!] Host not responding to SMB - skipping
```

If hostname resolution fails:
```
[*] Checking SMB reachability...
[-] Target hostname does not resolve to target IP
    Add to /etc/hosts: 10.0.24.230  DC01.corp.local  CORP  DC01

[*] Use --skip-hosts-check to bypass this check (not recommended)
```

**Why SMB instead of ping?** ICMP ping is commonly blocked by firewalls, causing false negatives. SMB-based validation confirms the target is actually running Windows SMB services, which is more appropriate for an AD enumeration tool.

**Why hosts resolution matters:** Kerberos authentication requires the DC hostname to resolve correctly. Without proper resolution, authentication may fail or use NTLM fallback.

**To fix resolution issues:** Add the suggested line to `/etc/hosts`, or use `--skip-hosts-check` to bypass (not recommended).

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
| `--local-auth` | Authenticate against local SAM instead of domain |

### Kerberos Authentication

| Flag | Description |
|------|-------------|
| `-k, --kerberos` | Use Kerberos authentication |
| `--use-kcache` | Use credentials from ccache file (KRB5CCNAME) |
| `--aesKey` | AES key for Kerberos (128 or 256 bit) |
| `--kdcHost` | FQDN of the Key Distribution Center |
| `--delegate` | Impersonate user via S4U2proxy delegation |
| `--self` | Use S4U2self extension with --delegate |

### Certificate Authentication

| Flag | Description |
|------|-------------|
| `--pfx-cert` | Path to PFX certificate file (PKINIT) |
| `--pfx-pass` | Password for PFX certificate |
| `--pem-cert` | Path to PEM certificate file |
| `--pem-key` | Path to PEM private key file |

### Multi-Credential Mode

| Flag | Description |
|------|-------------|
| `-C, --credfile` | Credentials file (user:password per line) |
| `-U, --userfile` | Usernames file (one per line) |
| `-P, --passfile` | Passwords file (paired with -U) |
| `--continue-on-success` | Continue testing after finding valid credentials |
| `--jitter` | Random delay (0 to SEC) between attempts (forces sequential) |
| `--fail-limit` | Stop after N total failed login attempts |
| `--ufail-limit` | Stop testing user after N failures for that user |
| `--gfail-limit` | Stop after N consecutive failures globally |

### Enumeration Modules

| Flag | Description |
|------|-------------|
| `-A, --all` | Run all enumeration modules |
| `--users` | Domain users via RPC |
| `--active-users` | Only show active/enabled users |
| `--groups` | Domain groups with members |
| `--shares` | SMB shares and permissions |
| `--shares-filter` | Filter shares by access (READ or WRITE) |
| `--spider` | Spider shares for files (metadata only) |
| `--spider-download` | Enable file download during spidering |
| `--spider-max-size` | Max file size to download (default: 10MB) |
| `--spider-output` | Output directory for downloaded files |
| `--policies` | Password and lockout policies |
| `--sessions` | Active sessions `[admin]` |
| `--loggedon` | Logged on users `[admin]` |
| `--printers` | Printers and spooler status |
| `--av` | AV/EDR products `[admin]` |
| `--computers` | Domain computers with OS info |
| `--local-groups` | Local groups and members |
| `--local-groups-filter` | Filter to specific local group name |
| `--subnets` | AD sites and subnets |
| `--query` | Custom LDAP query filter |
| `--query-attrs` | Attributes for --query (comma-separated) |

### Security Checks

| Flag | Description |
|------|-------------|
| `--laps` | LAPS deployment check |
| `--laps-computer` | Filter LAPS to computer names matching pattern |
| `--ldap-signing` | LDAP signing requirements |
| `--pre2k` | Pre-Windows 2000 computers |
| `--bitlocker` | BitLocker status `[admin]` |
| `--delegation` | Delegation misconfigurations |
| `--asreproast` | AS-REP roastable accounts |
| `--adcs` | ADCS certificate templates |
| `--adcs-server` | Target specific ADCS server |
| `--adcs-base-dn` | Custom base DN for ADCS search |
| `--dc-list` | Domain controllers and trusts |
| `--pwd-not-reqd` | Accounts with PASSWD_NOTREQD |
| `--admin-count` | Accounts with adminCount=1 |
| `--maq` | Machine account quota |
| `--descriptions` | User description fields |
| `--signing` | SMB signing requirements |
| `--webdav` | WebClient service status |
| `--dns` | DNS enumeration recommendations (passive) |

### Other Protocols

| Flag | Description |
|------|-------------|
| `--mssql` | MSSQL detection and auth test (recommends queries) |
| `--rdp` | RDP status and NLA check |
| `--ftp` | FTP access (anonymous + credential testing) |
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
| `--no-prescan` | Disable parallel host pre-scanning (slower for large target sets) |
| `--discover-only` | Only discover live SMB hosts, skip enumeration (no creds required) |
| `--validate-only` | Only validate credentials, skip enumeration (fast cred check) |
| `--proxy-mode` | Enable proxy mode for proxychains/SOCKS (see below) |
| `--debug` | Show raw nxc command output |

### Network

| Flag | Description |
|------|-------------|
| `--port` | Custom SMB port (default: 445) |
| `--smb-timeout` | Timeout for SMB operations specifically |
| `--no-smb` | Skip SMB validation (for pure LDAP operations) |
| `-6, --ipv6` | Use IPv6 for connections |
| `--dns-server` | Custom DNS server for hostname resolution |
| `--dns-tcp` | Use TCP for DNS queries instead of UDP |

**Note on Hosts Resolution Check:** Before any enumeration begins, nxc-enum verifies that the DC hostname resolves to the target IP. If resolution fails, the tool exits with an error and provides the required `/etc/hosts` entry. Use `--skip-hosts-check` to bypass (not recommended - may cause authentication issues).

**Note on Proxy Mode:** When running through proxychains or a SOCKS proxy, use `--proxy-mode` to reduce concurrency and increase timeouts. This prevents overwhelming the proxy and avoids false negatives from timeout failures. See "Proxy Mode" section below for details.

**Note on Validate-Only Mode:** Use `--validate-only` for fast credential testing without running enumeration. This is ideal when you discover new credentials and want to quickly test them. Shows admin status (Pwn3d!) for each valid credential.

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

### Discovery-Only Mode

```bash
nxc-enum 10.0.0.0/24 --discover-only
```

```
[*] Pre-scanning 256 targets for SMB (port 445)...
[*] Port scan: 256/256 hosts checked
[*] Filtered 246 hosts (port 445 closed/filtered)
[*] Validating SMB on 10 live hosts...
[*] SMB validation: 10/10 complete

======================================================================
  DISCOVERY RESULTS
======================================================================

[*] Hosts scanned: 256
[*] Port 445 open: 10
[+] SMB validated: 10
[*] Elapsed time: 8.52s

----------------------------------------------------------------------
IP               Hostname        Domain               Sign  v1
----------------------------------------------------------------------
10.0.0.1         DC01            corp.local           Yes   No
10.0.0.5         FS01            corp.local           No    No
10.0.0.10        WS001           corp.local           No    Yes
10.0.0.15        WS002           corp.local           No    No
----------------------------------------------------------------------

Legend: Sign=SMB Signing Required, v1=SMBv1 Enabled
```

### Multi-Target Summary

```
================================================================================
                      MULTI-TARGET SUMMARY (3 targets)
================================================================================

TARGET STATUS
--------------------------------------------------
  [+] 10.0.0.1 (DC01) - Completed (15.2s)
  [+] 10.0.0.2 (FS01) - Completed (12.8s)
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

### MSSQL Detection

```
MSSQL SERVICE DETECTED
--------------------------------------------------
  Hostname: SQL01
  Authenticated: Yes
  Privileges: SYSADMIN

[!] Current user has SYSADMIN privileges!

RECOMMENDED ENUMERATION COMMANDS:
--------------------------------------------------

[*] List databases:
    nxc mssql 10.0.0.1 -u 'admin' -p '<password>' -q 'SELECT name FROM master.dbo.sysdatabases'

[*] List linked servers (lateral movement):
    nxc mssql 10.0.0.1 -u 'admin' -p '<password>' -q 'SELECT name FROM sys.servers WHERE is_linked=1'

[*] Check impersonation privileges:
    nxc mssql 10.0.0.1 -u 'admin' -p '<password>' -M mssql_priv
```

*Note: nxc-enum only tests authentication - SQL queries are recommendations for manual execution.*

---

## Enumeration Modules

When run without specific flags, all modules are executed:

| Module | Description |
|--------|-------------|
| **Pre-Flight** | |
| SMB Reachability | Validates target responds to SMB (skips unreachable hosts) |
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
| Spider | Recursive file listing on shares (metadata or download) |
| Printers | Print spooler status (PrintNightmare warning) |
| AD Subnets | AD sites and network topology |
| Network Interfaces | Multi-homed host detection via SMB IOCTL |
| Disks | Disk drive enumeration via RPC `[admin]` |
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
| gMSA | Group Managed Service Account enumeration |
| GPP Password | Group Policy Preferences cpassword extraction (MS14-025) |
| PSO | Fine-Grained Password Policies (Password Settings Objects) |
| SCCM | SCCM/MECM infrastructure discovery |
| MAQ | Machine Account Quota check |
| WebDAV | WebClient service status check |
| DNS | DNS enumeration recommendations |
| **Other Protocols** | |
| MSSQL | Service detection, auth test, recommends queries |
| RDP | RDP status and NLA requirements |
| FTP | Anonymous access + credential testing |
| NFS | NFS exports and permissions |
| VNC | VNC service detection (ports 5900-5903, 5800-5801) |
| iOXID | Multi-homed host discovery via DCOM (port 135) |
| **Reporting** | |
| Executive Summary | Security posture and attack vectors |
| Next Steps | Actionable follow-up commands |
| Copy-Paste Lists | Clean output for other tools |

---

## Proxy Mode (Proxychains/SOCKS)

When running through proxychains or a SOCKS proxy:

```bash
# Explicit proxy mode
proxychains nxc-enum 10.0.0.1 -u admin -p pass --proxy-mode

# Auto-detected (proxychains sets LD_PRELOAD)
proxychains nxc-enum 10.0.0.1 -u admin -p pass
```

**What changes in proxy mode:**

| Setting | Normal | Proxy Mode |
|---------|--------|------------|
| Parallel module workers | 15 | 2 |
| Port prescan workers | 100 | 5 |
| SMB validation workers | 20 | 2 |
| Port prescan timeout | 0.5s | 5.0s |
| Default command timeout | 30s | 120s |
| iOXID module | Enabled | Skipped |
| VNC module | Enabled | Skipped |
| Hostname validation | Enabled | Skipped |

**Why these changes?**
- **Reduced workers**: SOCKS proxies typically support 10-20 concurrent connections max
- **Increased timeouts**: Proxy routing adds latency; fast timeouts cause false negatives
- **Skipped modules**: iOXID and VNC use raw sockets incompatible with proxychains
- **Skipped hostname validation**: DNS queries bypass the proxy

**Important:** Use IP addresses instead of hostnames. DNS resolution happens locally and bypasses the proxy.

---

## Passive Enumeration Philosophy

**nxc-enum is designed for pure reconnaissance - it never executes commands on targets.**

| Allowed Operations | Prohibited Operations |
|-------------------|----------------------|
| LDAP queries (read attributes) | SQL queries on databases |
| SMB share enumeration | WMI queries (execute on target) |
| RPC user/group enumeration | Kerberos ticket requests |
| Port/service detection | xp_cmdshell or command execution |
| Authentication testing | File modification |

**Examples of passive vs. active:**

- **MSSQL**: Tests authentication only, recommends `SELECT` queries for you to run manually
- **DNS**: Checks LDAP/DNS availability, recommends `adidnsdump` commands to run manually
- **Kerberoast/AS-REP**: LDAP queries for SPNs/UAC flags only, recommends ticket extraction commands
- **Shares**: Lists permissions, recommends `spider_plus` commands to run manually

This design ensures nxc-enum is safe for authorized assessments where you need read-only reconnaissance before deciding on further actions.

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

### Multi-Target Host Discovery (New!)

For large target sets (CIDR ranges, IP ranges), nxc-enum performs parallel host discovery:

| Phase | Description | Workers | Timeout |
|-------|-------------|---------|---------|
| 1. TCP Port Scan | Fast filter for port 445 | 100 | 0.5s |
| 2. SMB Validation | Extract hostname/domain | 20 | 10s |

**Performance comparison for /24 network (256 hosts):**

| Scenario | Before | After |
|----------|--------|-------|
| 10 live hosts | ~41 min | ~15 sec |
| 50 live hosts | ~41 min | ~30 sec |
| All offline | ~42 min | ~5 sec |

Auto-enabled when targets > 5. Use `--no-prescan` to disable.

**Quick network mapping:** Use `--discover-only` to find live SMB hosts without running enumeration. Outputs IP, hostname, domain, SMB signing status, and SMBv1 for each host. Supports JSON output for integration with other tools.

### Per-Target Parallelism

- **Parallel Port Scanning** - All ports checked simultaneously
- **Parallel Cache Priming** - SMB, RID brute, LDAP run in parallel
- **Parallel Credential Validation** - Up to 10 concurrent workers
- **Parallel Module Execution** - Independent modules run simultaneously
- **Result Caching** - No redundant network calls

Result: **~50% faster** than sequential execution per target.

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
| FTP Enumeration | ✗ | ✓ |
| NFS Export Enumeration | ✗ | ✓ |
| VNC Detection | ✗ | ✓ |
| iOXID Network Discovery | ✗ | ✓ |
| gMSA Enumeration | ✗ | ✓ |
| GPP Password Extraction | ✗ | ✓ |
| PSO (Fine-Grained Policies) | ✗ | ✓ |
| SCCM Discovery | ✗ | ✓ |
| Share Spidering | ✗ | ✓ |
| Outdated OS Detection | ✗ | ✓ |
| Proxy Mode (Proxychains) | ✗ | ✓ |
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
