"""NXC command execution and network utilities.

Security Considerations:
    Credentials (passwords, NTLM hashes) are passed to nxc via command-line
    arguments. This is a limitation of the nxc tool design. Be aware that:

    1. Credentials may be briefly visible in process listings (ps aux)
    2. Shell history may capture commands with credentials
    3. Process monitoring tools may log credential arguments

    Mitigations applied:
    - Debug output redacts credential values (see output.py)
    - Output files are created with restricted permissions (0o600)
    - Credential files are checked for overly permissive access

    For maximum security in sensitive environments:
    - Use dedicated assessment systems
    - Clear shell history after use
    - Use hash-based authentication (-H) when possible
"""

import socket
import subprocess


def run_nxc(args: list, timeout: int = 60) -> tuple[int, str, str]:
    """Run netexec command and return exit code, stdout, stderr.

    All commands include --verbose for detailed output that enables
    better parsing and data extraction.

    Security Note:
        Credential arguments (-p, -H) are passed directly to nxc subprocess
        and may be visible in process listings. This is inherent to nxc's
        design. See module docstring for security considerations.

    Args:
        args: Command arguments to pass to nxc
        timeout: Maximum execution time in seconds (default: 60)

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    cmd = ["nxc"] + args

    # Always add --verbose for more detailed output to parse
    if "--verbose" not in args:
        cmd.append("--verbose")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", "netexec (nxc) not found in PATH"
    except PermissionError:
        return -1, "", "Permission denied executing netexec"
    except OSError as e:
        return -1, "", f"OS error executing command: {e}"
    except Exception as e:
        return -1, "", f"Command execution failed: {e}"


def check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        return result == 0
    except (socket.error, socket.timeout, OSError):
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
