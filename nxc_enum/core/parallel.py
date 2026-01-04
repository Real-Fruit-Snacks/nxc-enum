"""Parallel execution utilities for running enumeration modules concurrently."""

from concurrent.futures import ThreadPoolExecutor, as_completed

from .constants import PARALLEL_MODULE_WORKERS
from .output import (
    OUTPUT_BUFFER,
    _buffer_lock,
    get_output_file_requested,
    get_thread_local,
    set_parallel_mode,
    status,
)


def run_parallel_modules(args, cache, is_admin: bool = False) -> None:
    """Run independent enumeration modules in parallel with buffered output.

    Modules are executed concurrently using a thread pool. Each module's output
    is buffered separately and then printed in the original order after all
    modules complete.

    Args:
        args: Parsed command-line arguments
        cache: EnumCache instance for storing results
        is_admin: Whether the current credential has admin privileges
    """
    _thread_local = get_thread_local()

    # Import here to avoid circular imports
    from ..enums.av import enum_av
    from ..enums.kerberoastable import enum_kerberoastable
    from ..enums.loggedon import enum_loggedon
    from ..enums.policies import enum_policies
    from ..enums.printers import enum_printers
    from ..enums.sessions import enum_sessions
    from ..enums.shares import enum_shares

    # Modules: (function, name, requires_admin)
    modules = [
        (enum_shares, "Shares", False),
        (enum_policies, "Policies", False),
        (enum_sessions, "Sessions", True),  # Requires local admin
        (enum_loggedon, "Logged On", True),  # Requires local admin
        (enum_printers, "Printers", False),
        (enum_av, "AV/EDR", True),  # Requires local admin
        (enum_kerberoastable, "Kerberoastable", False),
    ]

    results = {}  # Store buffered output by module name
    failed_modules = []  # Track modules that failed

    def run_with_buffer(func, name, needs_admin):
        """Execute a module with output buffering."""
        _thread_local.buffer = []
        if needs_admin:
            func(args, cache, is_admin)
        else:
            func(args, cache)
        return name, list(_thread_local.buffer)

    set_parallel_mode(True)
    with ThreadPoolExecutor(max_workers=PARALLEL_MODULE_WORKERS) as executor:
        # Submit all modules and create a mapping from future to module name
        future_to_name = {}
        for func, name, needs_admin in modules:
            future = executor.submit(run_with_buffer, func, name, needs_admin)
            future_to_name[future] = name

        for future in as_completed(future_to_name):
            module_name = future_to_name[future]
            try:
                name, buffer = future.result()
                results[name] = buffer
            except Exception as e:
                failed_modules.append(module_name)
                status(f"Error in parallel module '{module_name}': {e}", "error")
                results[module_name] = []  # Store empty result for failed module
    set_parallel_mode(False)

    # Report failed modules summary if any
    if failed_modules:
        status(
            f"Warning: {len(failed_modules)} module(s) failed: {', '.join(failed_modules)}",
            "warning",
        )

    # Print buffered output in original order
    # Use lock when appending to OUTPUT_BUFFER for thread safety
    for func, name, _ in modules:
        for line in results.get(name, []):
            print(line)
            if get_output_file_requested():
                with _buffer_lock:
                    OUTPUT_BUFFER.append(line)
