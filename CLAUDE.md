# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

nxc-enum is a NetExec wrapper for Active Directory enumeration with enum4linux-ng style output. It wraps the `nxc` CLI tool to provide comprehensive AD enumeration across SMB, LDAP, MSSQL, RDP, FTP, and NFS protocols. **Zero external Python dependencies** - only requires NetExec installed on the system PATH.

## Build and Test Commands

```bash
# Development setup
pip install -e .
pip install -r requirements-dev.txt

# Run without installing
python3 nxc_enum.py --help

# Testing
pytest tests/ -v                              # All tests
pytest tests/test_parsing.py -v               # Single file
pytest tests/test_parsing.py::TestClassification::test_safe_int_valid -v  # Single test
pytest tests/ --cov=nxc_enum                  # With coverage
pytest tests/ -m "not slow"                   # Skip slow tests

# Formatting (run before commits)
black nxc_enum/ tests/
isort nxc_enum/ tests/
flake8 nxc_enum/ tests/ --max-line-length=100
```

## Architecture

### Entry Points

- `nxc_enum.py` - CLI wrapper (backwards compatibility)
- `nxc_enum/__main__.py` - Module entry (`python -m nxc_enum`)
- `nxc_enum/cli/main.py:main()` - Actual entry point, orchestrates everything

### Execution Flow

```
1. Parse args → expand targets (CIDR/ranges/files) → parse credentials
2. Multi-target prescan (if >5 targets): port 445 scan → SMB validation
3. Per-target execution:
   a. SMB reachability check
   b. Hostname resolution validation (for Kerberos)
   c. Anonymous session probe (null/guest)
   d. Credential validation (detects admin via "Pwn3d!" marker)
   e. Cache priming (7 parallel queries: smb_basic, rid_brute, ldap_basic, etc.)
   f. Sequential modules (domain_intel, smb_info, users, groups)
   g. Parallel modules (36 independent modules via ThreadPoolExecutor)
   h. Reports (summary, next_steps, share_matrix)
4. Multi-target summary (if applicable)
5. Output file / JSON export
```

### Core Module Responsibilities

| Module | Purpose |
|--------|---------|
| `cli/main.py` | Orchestration, target/credential handling, module dispatch |
| `cli/args.py` | Argument parsing with custom formatter |
| `core/runner.py` | `run_nxc()` - subprocess execution, DNS caching, port scanning |
| `core/output.py` | `output()`, `status()`, buffered output, `JSON_DATA` global |
| `core/parallel.py` | `run_parallel_modules()` - ThreadPoolExecutor for 36 modules |
| `core/constants.py` | Regex patterns, thread pool sizes, timeout values |
| `models/cache.py` | `EnumCache` - stores nxc results, batch query parsing |
| `models/credential.py` | `Credential` dataclass with `auth_args()` method |

### The EnumCache System

`EnumCache` is central to avoiding redundant network calls. Key attributes:

```python
# Cached raw nxc output (populated by prime_caches())
cache.smb_basic      # SMB connection result
cache.rid_brute      # RID brute enumeration
cache.ldap_basic     # LDAP connection
cache.pass_pol       # Password policy
cache.ldap_user_batch     # Batch LDAP query for users
cache.ldap_computer_batch # Batch LDAP query for computers

# Parsed batch data (used by multiple modules)
cache.user_batch_parsed     # List[dict] with user attributes
cache.computer_batch_parsed # List[dict] with computer/gMSA attributes

# State flags
cache.ldap_available  # False if LDAP connection failed
cache.anonymous_mode  # True if using null/guest session

# Service availability (from port prescan)
cache.rdp_available, cache.mssql_available, cache.ftp_available, etc.

# Results storage (populated by enum modules)
cache.kerberoastable, cache.delegation_accounts, cache.laps_computers, etc.

# Copy-paste data (aggregated for final output)
cache.copy_paste_data["usernames"], cache.copy_paste_data["spns"], etc.
```

Modules should check `cache.ldap_available` before LDAP operations and use `cache.get_*_from_batch()` methods when possible.

### Threading Model

Two levels of parallelism:

1. **Module-level** (`core/parallel.py`): 36 independent enum modules run via `ThreadPoolExecutor(max_workers=15)`. Each module's output is buffered per-thread, then printed in order.

2. **Target-level** (`cli/main.py`): Multi-target scans run with `ThreadPoolExecutor(max_workers=5)`. Each target's output is buffered entirely, then printed atomically.

**Proxy mode** reduces all worker counts (15→2, 100→5, etc.) to prevent proxy overload.

### Output System

```python
from nxc_enum.core.output import output, status, print_section, JSON_DATA

output("Plain text")                    # Prints and buffers for file output
status("Message", "success")            # [+] Message (green)
status("Message", "info")               # [*] Message (blue)
status("Message", "error")              # [-] Message (red)
status("Message", "warning")            # [!] Message (yellow)
print_section("Title", target)          # Boxed section header

# For JSON export
if args.json_output:
    JSON_DATA["my_key"] = my_data
```

**Thread safety**: `output()` uses `_buffer_lock` when appending to `OUTPUT_BUFFER`. In parallel mode, output goes to thread-local buffers first.

## Enumeration Module Pattern

All modules in `nxc_enum/enums/` follow this pattern:

```python
"""Module docstring."""
from ..core.colors import Colors, c
from ..core.output import JSON_DATA, debug_nxc, output, print_section, status
from ..core.runner import run_nxc

def enum_mymodule(args, cache, is_admin: bool = False):  # is_admin only if needed
    """Enumerate something."""
    target = cache.target if cache else args.target
    print_section("My Module", target)

    # Check prerequisites
    if not cache.ldap_available:
        status("LDAP unavailable - skipping", "error")
        return

    # Try batch data first (faster)
    batch_data = cache.get_something_from_batch()
    if batch_data is not None:
        results = batch_data
    else:
        # Fall back to individual query
        cmd_args = ["ldap", target] + cache.auth_args + ["--query", "..."]
        rc, stdout, stderr = run_nxc(cmd_args, args.timeout)
        debug_nxc(cmd_args, stdout, stderr, "My Query")
        results = parse_output(stdout)

    # Store in cache for other modules
    cache.my_results = results

    # Display results
    if results:
        status(f"Found {len(results)} item(s)", "success")
        for item in results:
            output(f"  {c(item, Colors.YELLOW)}")

        # Add next step recommendation
        cache.add_next_step(
            finding="Something interesting found",
            command=f"nxc ... {target} ...",
            description="What this command does",
            priority="high",  # high/medium/low
        )

        # Store for copy-paste section
        cache.copy_paste_data["my_items"].update(results)
    else:
        status("Nothing found", "info")

    # JSON export
    if args.json_output:
        JSON_DATA["my_module"] = results
```

### Admin-Only Modules

Some modules require local admin (sessions, loggedon, av, disks, bitlocker, local_groups). These receive `is_admin` parameter:

```python
def enum_sessions(args, cache, is_admin: bool = False):
    if not is_admin:
        status("Sessions enumeration requires local admin privileges", "warning")
        return
    # ... proceed with enumeration
```

### Multi-Credential Modules

`*_multi.py` modules compare access across credentials:

```python
def enum_shares_multi(args, creds: list, multi_results: MultiUserResults, cache):
    for cred in creds:
        # Run share enum for each credential
        # Store in multi_results for matrix display
```

## Adding a New Module

1. **Create the module file** (`nxc_enum/enums/newmodule.py`):
   - Follow the pattern above
   - Use `cache.target` not `args.target`
   - Check `cache.ldap_available` for LDAP modules
   - Use batch data when available
   - Call `cache.add_next_step()` for actionable findings
   - Update `cache.copy_paste_data` for aggregated output

2. **Export from `__init__.py`** (`nxc_enum/enums/__init__.py`):
   ```python
   from .newmodule import enum_newmodule
   ```

3. **Add CLI flag** (`nxc_enum/cli/args.py`):
   ```python
   parser.add_argument("--newmodule", action="store_true", help="Description")
   ```

4. **Wire into execution** (`nxc_enum/cli/main.py`):
   - Add to imports
   - Add to `run_all` check list
   - For parallel modules: add tuple to `modules` list in `run_parallel_modules()` in `core/parallel.py`
   - For sequential/blocking modules: call directly in main()

5. **Add copy-paste category** if needed (`models/cache.py`):
   ```python
   self.copy_paste_data["new_items"] = set()
   ```

## Testing Conventions

Tests use `unittest` framework:

```python
class TestMyFeature(unittest.TestCase):
    def test_something_specific(self):
        """Test that X does Y."""
        result = function_under_test(input)
        self.assertEqual(result, expected)
```

Test files mirror source structure: `nxc_enum/parsing/foo.py` → `tests/test_parsing.py`

## Critical Gotchas

1. **Always use `cache.target`** not `args.target` in enum modules - the cache has the resolved target.

2. **Check `cache.ldap_available`** before any LDAP operations - it's set False during cache priming if LDAP fails.

3. **Service availability flags** (`cache.rdp_available`, etc.) are `None` until port prescan runs. Check before skipping:
   ```python
   if cache.mssql_available is False:  # Explicitly False, not None
       status("MSSQL port closed - skipping", "info")
       return
   ```

4. **Thread-local output**: In parallel mode, `output()` writes to thread-local buffer. Don't mix `print()` with `output()`.

5. **Credential handling**: Use `cache.auth_args` for nxc commands. Never build auth args manually.

6. **Timeout inheritance**: Use `args.timeout` for nxc calls. It's adjusted for proxy mode.

7. **Batch data priority**: Always try `cache.get_*_from_batch()` before individual LDAP queries - it's 5-10x faster.

8. **JSON output guard**: Always check `if args.json_output:` before writing to `JSON_DATA`.

## Code Style

- Line length: 100 chars (Black configured)
- Python 3.10+ (match statements, union types with `|`)
- Use `c(text, Colors.*)` for colored output
- Status indicators: `[*]` info, `[+]` success, `[-]` error, `[!]` warning
- Docstrings for public functions, not for obvious internal helpers
