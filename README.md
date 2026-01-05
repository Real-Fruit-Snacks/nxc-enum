# nxc-enum

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A NetExec (nxc) wrapper that provides enum4linux-ng style output for Active Directory enumeration.

## Overview

`nxc-enum` wraps NetExec commands and formats the output to match the familiar enum4linux-ng style, with colored status indicators and organized sections. It combines multiple nxc modules into a single comprehensive enumeration tool with intelligent multi-credential support.

## Quick Start

```bash
# No credentials - automatic null/guest session probing
python3 nxc_enum.py 10.0.24.230 -A

# Single credential - full enumeration
python3 nxc_enum.py 10.0.24.230 -u admin -p 'Password123' -d CORP -A

# Multiple credentials - compare access levels
python3 nxc_enum.py 10.0.24.230 -C creds.txt -d CORP -A

# Specific modules only
python3 nxc_enum.py 10.0.24.230 -u admin -p 'Password123' --shares --users
```

## Features

- **enum4linux-ng style output** - Familiar `[*]`, `[+]`, `[-]` status indicators with colored sections
- **Comprehensive AD enumeration** - Users, groups, shares, policies, sessions, Kerberoastable accounts, and more
- **Anonymous session probing** - Automatically tests null/guest sessions when no credentials provided
- **Multi-credential support** - Test multiple credentials with share access matrix output
- **Local admin detection** - Automatically detects and highlights accounts with local admin rights (Pwn3d!)
- **Smart command execution** - Universal commands run once, per-user commands run for each credential
- **Admin-aware skipping** - Commands requiring local admin are skipped for non-admin users
- **Hosts resolution check** - Verifies DC hostname resolves to target IP before enumeration
- **LDAP & SMB support** - Enumerates via both protocols for complete coverage
- **Pass-the-hash support** - Authenticate with NTLM hashes
- **Result caching** - Parallel execution with caching for ~50% faster runtime
- **Credential validation** - Pre-validates credentials before full enumeration
- **Next Steps recommendations** - Actionable follow-up commands based on findings
- **JSON output** - Export results in JSON format for automation
- **Debug mode** - Show raw nxc output for troubleshooting

## Requirements

- Python 3.10+
- [NetExec](https://github.com/Pennyw0rth/NetExec) (nxc) installed and in PATH

**Note:** nxc-enum has zero external Python dependencies beyond the standard library.

## Security Considerations

nxc-enum implements several security measures to protect sensitive credentials:

### Credential Protection

1. **Debug Output Sanitization**: When using `--debug`, passwords and NTLM hashes are automatically redacted from command output. You'll see `****REDACTED****` instead of actual credentials.

2. **Output File Permissions**: Output files created with `-o` are created with `0o600` permissions (owner read/write only) to prevent other users from reading potentially sensitive enumeration results.

3. **Credential File Warnings**: If credential files (`-C`, `-U`, `-P`) have overly permissive permissions (readable by group or others), a warning is displayed recommending `chmod 600`.

### Known Limitations

- **Process Visibility**: Credentials are passed as command-line arguments to nxc. This is inherent to nxc's design and means credentials may be briefly visible via `ps aux`. For maximum security:
  - Use dedicated assessment systems
  - Clear shell history after use (`history -c`)
  - Prefer hash-based authentication (`-H`) when possible

### Best Practices

```bash
# Set proper permissions on credential files
chmod 600 creds.txt

# Use hash-based auth when possible
python3 nxc_enum.py 10.0.24.230 -u admin -H <hash> -A

# Clear history after sensitive operations
history -c
```

## Installation

### From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/Real-Fruit-Snacks/nxc-enum.git
cd nxc-enum

# Option 1: Run directly
chmod +x nxc_enum.py
python3 nxc_enum.py --help

# Option 2: Install as package
pip install -e .

# Option 3: Create symlink for system-wide access
sudo ln -s $(pwd)/nxc_enum.py /usr/local/bin/nxc-enum
```

### Verify Installation

```bash
# Check NetExec is available
nxc --version

# Test nxc-enum
python3 nxc_enum.py --help
# or if installed as package:
nxc-enum --help
```

## Usage

### Anonymous Mode (No Credentials)

When no credentials are provided, nxc-enum automatically probes for anonymous access:

```bash
# Automatic null/guest session probing
python3 nxc_enum.py 10.0.24.230 -A
```

The tool will attempt:
1. **SMB null session** (`-u '' -p ''`)
2. **SMB guest session** (`-u 'Guest' -p ''`)
3. **LDAP anonymous bind**

If any succeed, enumeration continues with that session. Even when credentials are provided, anonymous access is checked and reported as a security finding.

### Single Credential Mode

```bash
# Full enumeration with all modules
python3 nxc_enum.py 10.0.24.230 -u admin -p 'Password123' -A

# With domain
python3 nxc_enum.py 10.0.24.230 -u admin -p 'Password123' -d CORP -A

# Pass-the-hash
python3 nxc_enum.py 10.0.24.230 -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -A

# Specific modules only
python3 nxc_enum.py 10.0.24.230 -u admin -p pass --users --shares --groups

# Save output to file
python3 nxc_enum.py 10.0.24.230 -u admin -p pass -A -o results.txt

# JSON output for automation
python3 nxc_enum.py 10.0.24.230 -u admin -p pass -A -j -o results.json

# Debug mode (show raw nxc output)
python3 nxc_enum.py 10.0.24.230 -u admin -p pass -A --debug
```

### Multi-Credential Mode

Test multiple credentials at once to compare access levels across users:

```bash
# Credentials file (user:password per line)
python3 nxc_enum.py 10.0.24.230 -C creds.txt -d CORP -A

# Separate user and password files (paired line-by-line)
python3 nxc_enum.py 10.0.24.230 -U users.txt -P passwords.txt -d CORP -A

# With JSON output
python3 nxc_enum.py 10.0.24.230 -C creds.txt -A -j -o results.json
```

#### Credential File Formats

**creds.txt** (user:password or user:hash per line):
```
admin:Password123
faraday:hacksmarter123
svc_backup:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
# Lines starting with # are ignored
```

NTLM hashes are auto-detected (32:32 hex format).

**users.txt** / **passwords.txt** (paired line-by-line):
```
# users.txt     # passwords.txt
admin           Password123
faraday         hacksmarter123
svc_backup      Summer2024!
```

## Command Line Options

### Authentication

| Flag | Description |
|------|-------------|
| `TARGET` | Target IP address or hostname (required) |
| `-u, --user` | Username |
| `-p, --password` | Password |
| `-H, --hash` | NTLM hash (LM:NT or NT only) |
| `-d, --domain` | Domain name |

### Multi-Credential Mode

| Flag | Description |
|------|-------------|
| `-C, --credfile` | Credentials file (user:password per line) |
| `-U, --userfile` | Usernames file (one per line) |
| `-P, --passfile` | Passwords file (one per line, paired with -U) |

### Enumeration Modules

| Flag | Description |
|------|-------------|
| `-A, --all` | Run all enumeration modules |
| `--users` | Domain users via RPC |
| `--groups` | Domain groups with members |
| `--shares` | SMB shares and permissions |
| `--policies` | Password and lockout policies |
| `--sessions` | Active sessions [admin] |
| `--loggedon` | Logged on users [admin] |
| `--printers` | Printers and spooler status |
| `--av` | AV/EDR products [admin] |

### Security Checks

| Flag | Description |
|------|-------------|
| `--delegation` | Delegation misconfigurations |
| `--adcs` | ADCS certificate templates |
| `--dc-list` | Domain controllers and trusts |
| `--pwd-not-reqd` | Accounts with PASSWD_NOTREQD |
| `--admin-count` | Accounts with adminCount=1 |
| `--maq` | Machine account quota |
| `--descriptions` | User description fields |
| `--signing` | SMB signing requirements |
| `--webdav` | WebClient service status |
| `--dns` | DNS records |

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
| `--skip-hosts-check` | Skip /etc/hosts resolution check |
| `--debug` | Show raw nxc command output |

## Multi-Credential Execution Flow

In multi-credential mode, commands are categorized for efficient execution:

### Universal Commands (Run Once)

These return the same domain-wide info regardless of which valid user runs them:

| Command | Description |
|---------|-------------|
| Domain Intelligence | Domain SID, hostname, FQDN, DC detection |
| Users | Domain user enumeration |
| Groups | Domain group enumeration |
| Policies | Password and lockout policies |
| Kerberoastable | Accounts with SPNs |
| SMB/OS Info | Server configuration |

### Per-User Commands (Run Per Credential)

These return different results based on user privileges:

| Command | Description | Admin Required |
|---------|-------------|----------------|
| Shares | Share access enumeration | No |
| Sessions | Active RDP/console sessions | Yes |
| Logged On | Currently logged on users | Yes |
| Printers | Print spooler status | No |
| AV/EDR | Installed security products | Yes |

### Admin-Aware Skipping

Commands requiring local admin are automatically skipped for non-admin users:

```
 ============================
|    Active Sessions    |
 ============================
[*] Skipping: requires local admin (current user is not admin)
```

In multi-credential mode, admin-only commands run only for admin credentials:

```
[*] Running for 1 admin user(s), skipping 2 non-admin user(s)
```

## Local Admin Detection

nxc-enum automatically detects local admin privileges via NetExec's "Pwn3d!" indicator:

### Credential Validation Output
```
 ===============================================
|    Credential Validation for 10.0.24.230    |
 ===============================================
[*] Testing 3 credential(s)...
[+] admin: valid (ADMIN)
[+] faraday: valid
[+] alt.svc: valid

[+] 3/3 credentials validated successfully (1 with local admin)
```

### Target Information (Grouped by Admin Status)
```
 ============================
|    Target Information    |
 ============================
[*] Target ........... 10.0.24.230
[*] Credentials ...... 3 validated user(s)
  Local Admins:
    - admin (password)
  Standard Users:
    - faraday (password)
    - alt.svc (password)
[*] Timeout .......... 30 second(s)
```

### Executive Summary
```
CREDENTIALS (3 valid)
--------------------------------------------------
  Local Admins (1):
    - admin
  Standard Users (2):
    - faraday
    - alt.svc
```

## Share Access Matrix

In multi-credential mode, share permissions are displayed as a matrix:

```
 ==========================================
|    Shares Matrix for 10.0.24.230    |
 ==========================================

Share         faraday     admin       svc_backup
------------- ----------  ----------  ----------
ADMIN$        -           READ,WRITE  -
C$            -           READ,WRITE  -
IPC$          READ        READ        READ
NETLOGON      READ        READ        READ
SYSVOL        READ        READ        READ
Finance$      -           READ,WRITE  READ

Legend: WRITE (green) | READ (yellow) | - = No Access

[!] Non-default share 'Finance$' accessible by: admin (RW), svc_backup (R)
```

## Enumeration Modules

When run with `-A` or no specific modules, the following checks are performed:

| # | Section | Description |
|---|---------|-------------|
| 1 | Anonymous Session Probe | Check for null/guest/LDAP anonymous access |
| 2 | Target Information | Display target, credentials (grouped by admin status) |
| 3 | Listener Scan | Check LDAP (389), LDAPS (636), SMB (445), NetBIOS (139) |
| 4 | Domain Intelligence | Consolidated domain info (SID, DC, FQDN, NetBIOS) |
| 5 | SMB Dialect Check | SMB versions, signing requirements |
| 6 | RPC Session Check | Null session, guest access, authentication |
| 7 | OS Information | Windows version, build number |
| 8 | Users via RPC | User list with categories (built-in, service, domain) |
| 9 | Groups via RPC | Groups with high-value highlighting and members |
| 10 | Shares | Share permissions (matrix in multi-cred mode) |
| 11 | Policies | Password and lockout policies |
| 12 | Active Sessions | Windows sessions (admin only) |
| 13 | Logged On Users | Currently logged on users (admin only) |
| 14 | Printers | Print spooler status (PrintNightmare warning) |
| 15 | AV/EDR Detection | Installed security products (admin only) |
| 16 | Kerberoastable | Accounts with SPNs via LDAP |
| 17 | Executive Summary | Target profile, security posture, attack vectors |
| 18 | Next Steps | Actionable follow-up commands based on findings |

## Example Output

### Anonymous Session Probe

```
 ================================================
|    Anonymous Session Probe for 10.0.24.230    |
 ================================================
[*] Probing SMB null session...
[+] SMB null session available!
[*] Probing SMB guest session...
[+] SMB guest session available!
[*] Probing LDAP anonymous bind...
[-] LDAP anonymous bind not available

[!] Anonymous access: SMB null, SMB guest
```

### Single Credential Mode

```
NXC-ENUM - NetExec Enumeration Wrapper (v1.5.1)

[*] Validating credentials...
[+] Credentials validated successfully (LOCAL ADMIN)

 ============================
|    Target Information    |
 ============================
[*] Target ........... 10.0.24.230
[*] Username ......... 'admin' [LOCAL ADMIN]
[*] Password ......... 'Password123'
[*] Domain ........... 'CORP'
[*] Timeout .......... 30 second(s)

 ============================================
|    Domain Intelligence for 10.0.24.230    |
 ============================================
[+] Target is a Domain Controller
  Hostname:        DC01
  FQDN:            DC01.corp.local
  NetBIOS Domain:  CORP
  DNS Domain:      corp.local
  Domain SID:      S-1-5-21-3154413470-3340737026-2748725799

 =======================================
|    Users via RPC for 10.0.24.230    |
 =======================================
[+] Found 16 user(s) total

Built-in Accounts (3)
RID     Username                Description
------  ----------------------  ----------------------------------------
500     Administrator           Built-in admin account
501     Guest                   Built-in guest account
502     krbtgt

Service Accounts (4)
RID     Username                Description
------  ----------------------  ----------------------------------------
1113    alt.svc
1129    Soulkiller.svc
1134    kei.svc
1144    Silverhand.svc

...

 =============================================
|    Executive Summary for 10.0.24.230    |
 =============================================

TARGET PROFILE
--------------------------------------------------
  Target:      10.0.24.230 (DC01.corp.local)
  Role:        Domain Controller
  Domain:      corp.local
  Domain SID:  S-1-5-21-3154413470-3340737026-2748725799

SECURITY POSTURE
--------------------------------------------------
[+] SMB Signing: REQUIRED
[!] Min Password Length: 5 chars (weak)
[!] Lockout Threshold: NONE - Password spraying safe!
[!] Print Spooler: RUNNING - Check for PrintNightmare!
[!] AV/EDR: Windows Defender INSTALLED

ENUMERATION SUMMARY
--------------------------------------------------
  Users:       16
  Groups:      20
  Shares:      3

KERBEROASTABLE ACCOUNTS
--------------------------------------------------
[!] alt.svc, Soulkiller.svc, kei.svc, Silverhand.svc
  → Accounts with SPNs - request TGS tickets for offline cracking

POTENTIAL ATTACK VECTORS
--------------------------------------------------
[!] Password spraying (no lockout)
[!] Kerberoasting (4 accounts with SPNs)
[!] PrintNightmare (spooler running)

 ==========================================
|    Next Steps for 10.0.24.230    |
 ==========================================

HIGH PRIORITY:
  [!] Kerberoastable accounts found
      nxc ldap 10.0.24.230 -u <user> -p <pass> --kerberoasting
      Request TGS tickets for offline password cracking

MEDIUM PRIORITY:
  [!] Print Spooler running
      nxc smb 10.0.24.230 -u <user> -p <pass> -M printnightmare
      Check for PrintNightmare vulnerability

LOW PRIORITY:
  [*] Readable shares: SYSVOL, NETLOGON, Data
      nxc smb 10.0.24.230 -u <user> -p <pass> -M spider_plus -o OUTPUT_FOLDER=.
      Enumerate share contents (creates JSON metadata in current dir)

  [*] Readable shares: SYSVOL, NETLOGON, Data
      nxc smb 10.0.24.230 -u <user> -p <pass> -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=.
      Download files from shares to current directory

Completed after 12.34 seconds
```

### Multi-Credential Mode

```
NXC-ENUM - NetExec Enumeration Wrapper (v1.5.1)

 ===============================================
|    Credential Validation for 10.0.24.230    |
 ===============================================
[*] Testing 3 credential(s)...
[+] admin: valid (ADMIN)
[+] faraday: valid
[+] alt.svc: valid

[+] 3/3 credentials validated successfully (1 with local admin)

 ============================
|    Target Information    |
 ============================
[*] Target ........... 10.0.24.230
[*] Credentials ...... 3 validated user(s)
  Local Admins:
    - admin (password)
  Standard Users:
    - faraday (password)
    - alt.svc (password)
[*] Domain ........... 'CORP'
[*] Timeout .......... 30 second(s)

...

 ==========================================
|    Shares Matrix for 10.0.24.230    |
 ==========================================

Share         faraday     admin       alt.svc
------------- ----------  ----------  ----------
ADMIN$        -           READ,WRITE  -
C$            -           READ,WRITE  -
IPC$          READ        READ        READ
NETLOGON      READ        READ        READ
SYSVOL        READ        READ        READ
Backups$      READ        READ,WRITE  READ,WRITE

[!] Non-default share 'Backups$' accessible by: admin (RW), alt.svc (RW), faraday (R)

 ============================
|    Active Sessions    |
 ============================
[*] Running for 1 admin user(s), skipping 2 non-admin user(s)

admin: SUCCESS - 2 session(s)
faraday: Skipped (not admin)
alt.svc: Skipped (not admin)

Combined Sessions:
  console      CORP\jsmith    Active
  rdp-tcp#1    CORP\admin     Active

 =============================================
|    Executive Summary for 10.0.24.230    |
 =============================================

TARGET PROFILE
--------------------------------------------------
  Target:      10.0.24.230 (DC01.corp.local)
  Role:        Domain Controller
  Domain:      corp.local
  Domain SID:  S-1-5-21-3154413470-3340737026-2748725799

CREDENTIALS (3 valid)
--------------------------------------------------
  Local Admins (1):
    - admin
  Standard Users (2):
    - faraday
    - alt.svc

SHARE ACCESS SUMMARY
--------------------------------------------------
  admin:    6 accessible, 3 writable
  faraday:  4 accessible, 0 writable
  alt.svc:  5 accessible, 1 writable

...

Completed after 18.45 seconds
```

## JSON Output

When using `-j -o results.json`:

```json
{
  "target": {
    "ip": "10.0.24.230",
    "credentials": ["admin", "faraday", "alt.svc"],
    "domain": "CORP",
    "timeout": 30
  },
  "credentials": {
    "tested": 3,
    "valid": ["admin", "faraday", "alt.svc"],
    "admins": ["admin"]
  },
  "domain": {
    "domain_sid": "S-1-5-21-3154413470-3340737026-2748725799",
    "dns_domain": "corp.local",
    "hostname": "DC01",
    "is_dc": true
  },
  "shares_matrix": {
    "ADMIN$": {"admin": "READ,WRITE", "faraday": "NO ACCESS", "alt.svc": "NO ACCESS"},
    "Backups$": {"admin": "READ,WRITE", "faraday": "READ", "alt.svc": "READ,WRITE"}
  },
  "sessions": {
    "admin": {"success": true, "data": ["console CORP\\jsmith Active"]},
    "faraday": {"success": false, "error": "Skipped (not admin)"}
  },
  "kerberoastable": [
    {"user": "alt.svc", "spn": "HTTP/server.corp.local"}
  ],
  "elapsed_time": 18.45
}
```

## Comparison with enum4linux-ng

| Feature | enum4linux-ng | nxc-enum |
|---------|---------------|----------|
| SMB Enumeration | Yes | Yes |
| LDAP Enumeration | Yes | Yes |
| User Enumeration | Yes | Yes |
| Group Enumeration | Yes | Yes |
| Share Enumeration | Yes | Yes |
| Policy Enumeration | Yes | Yes |
| RID Cycling | Yes | Yes |
| Domain SID | Yes | Yes |
| Pass-the-Hash | No | Yes |
| Multi-Credential | No | Yes |
| Share Access Matrix | No | Yes |
| Local Admin Detection | No | Yes |
| Admin-Aware Skipping | No | Yes |
| AV/EDR Detection | No | Yes |
| Kerberoastable Detection | No | Yes |
| Colored Output | Yes | Yes |
| JSON Export | Yes | Yes |
| Result Caching | No | Yes |

## Performance

nxc-enum uses a multi-phase parallel execution architecture:

- **Parallel Port Scanning** - All ports checked simultaneously
- **Parallel Cache Priming** - SMB, RID brute, LDAP connections run in parallel
- **Parallel Credential Validation** - All credentials tested concurrently (up to 10 workers)
- **Parallel Module Execution** - Independent modules run simultaneously
- **Result Caching** - No redundant network calls

This results in **~50% faster execution** compared to sequential approaches.

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/Real-Fruit-Snacks/nxc-enum.git
cd nxc-enum

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt
pip install -e .

# Verify setup
pytest tests/ -v
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=nxc_enum --cov-report=html

# Run specific test file
pytest tests/test_parsing.py -v
```

### Code Formatting

```bash
# Format code
black nxc_enum/ tests/
isort nxc_enum/ tests/

# Check linting
flake8 nxc_enum/ tests/ --max-line-length=100
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Reporting bugs and security issues
- Suggesting features
- Submitting pull requests
- Code style and testing requirements

**Security Note:** As this is a security/penetration testing tool, please follow responsible disclosure practices for any security vulnerabilities you discover.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Credits

- [NetExec](https://github.com/Pennyw0rth/NetExec) - The underlying enumeration engine
- [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) - Inspiration for output format

## Author

**Real-Fruit-Snacks** - [GitHub](https://github.com/Real-Fruit-Snacks)

For questions, bug reports, or feature requests, please [open an issue](https://github.com/Real-Fruit-Snacks/nxc-enum/issues).
