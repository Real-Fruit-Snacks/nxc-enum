#!/usr/bin/env python3
"""
nxc-enum - NetExec wrapper with enum4linux-ng style output

This is a thin wrapper for backwards compatibility.
The actual implementation is in the nxc_enum package.
"""

import sys

from nxc_enum.cli.main import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)
