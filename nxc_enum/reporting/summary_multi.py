"""Executive summary for multi-credential mode."""

from ..core.colors import Colors, c
from ..core.output import output, print_section


def print_executive_summary_multi(args, cache, creds, results):
    """Print executive summary for multi-credential mode."""
    target = cache.target if cache else args.target
    print_section("Executive Summary", target)

    domain_info = cache.domain_info or {}
    smb_info = cache.smb_info or {}
    policy_info = cache.policy_info or {}

    # Target Profile
    output(c("TARGET PROFILE", Colors.CYAN + Colors.BOLD))
    output("-" * 50)
    _hostname = domain_info.get("hostname", "Unknown")  # noqa: F841 - available for future use
    fqdn = domain_info.get("fqdn", "")
    target_str = f"{target}"
    if fqdn:
        target_str += f" ({fqdn})"
    output(f"  Target:      {target_str}")
    if domain_info.get("is_dc"):
        output(f"  Role:        {c('Domain Controller', Colors.RED)}")
    else:
        output("  Role:        Member Server")
    output(f"  Domain:      {domain_info.get('dns_domain', 'Unknown')}")
    output(f"  Domain SID:  {domain_info.get('domain_sid', 'Unknown')}")
    output("")

    # Credentials Summary - grouped by admin status
    admin_creds = [cred for cred in creds if cred.is_admin]
    std_creds = [cred for cred in creds if not cred.is_admin]

    output(c(f"CREDENTIALS ({len(creds)} valid)", Colors.CYAN + Colors.BOLD))
    output("-" * 50)

    if admin_creds:
        output(c(f"  Local Admins ({len(admin_creds)}):", Colors.RED))
        for cred in admin_creds:
            output(f"    - {cred.display_name()}")

    if std_creds:
        output(f"  Standard Users ({len(std_creds)}):")
        for cred in std_creds:
            output(f"    - {cred.display_name()}")
    output("")

    # Security Posture
    output(c("SECURITY POSTURE", Colors.CYAN + Colors.BOLD))
    output("-" * 50)
    if smb_info.get("signing_required"):
        output(f"[+] SMB Signing: {c('REQUIRED', Colors.GREEN)}")
    else:
        msg = f"[!] SMB Signing: {c('NOT REQUIRED', Colors.RED)}"
        msg += f" - {c('Relay attacks possible!', Colors.RED)}"
        output(msg)

    min_pw_len = policy_info.get("Minimum password length", "Unknown")
    try:
        min_pw_int = int(min_pw_len) if min_pw_len != "Unknown" else None
        if min_pw_int is not None and min_pw_int < 8:
            msg = f"[!] Min Password Length: {c(f'{min_pw_len} chars', Colors.RED)}"
            msg += f" {c('(weak)', Colors.RED)}"
            output(msg)
        else:
            output(f"[+] Min Password Length: {c(f'{min_pw_len} chars', Colors.GREEN)}")
    except (ValueError, TypeError):
        output(f"[*] Min Password Length: {min_pw_len} chars")

    lockout = policy_info.get("Lockout threshold", "Unknown")
    if lockout in ("None", "0", 0, None):
        msg = f"[!] Lockout Threshold: {c('NONE', Colors.RED)}"
        msg += f" - {c('Password spraying safe!', Colors.RED)}"
        output(msg)
    elif lockout == "Unknown":
        output("[*] Lockout Threshold: Unknown")
    else:
        output(f"[+] Lockout Threshold: {c(str(lockout), Colors.GREEN)}")

    # Check for spooler
    for user, (success, spooler_running, verbose_info) in results.printers.items():
        if spooler_running:
            msg = f"[!] Print Spooler: {c('RUNNING', Colors.RED)}"
            msg += f" - {c('Check for PrintNightmare!', Colors.RED)}"
            output(msg)
            break

    # AV/EDR
    if results.av_products:
        products = ", ".join(results.av_products.keys())
        output(f"[!] AV/EDR: {c(products, Colors.YELLOW)}")
    output("")

    # Share Access Summary
    output(c("SHARE ACCESS SUMMARY", Colors.CYAN + Colors.BOLD))
    output("-" * 50)
    if results.shares:
        for user in [cred.display_name() for cred in creds]:
            accessible = sum(
                1
                for s, perms in results.shares.items()
                if perms.get(user, "-") not in ("-", "NO ACCESS")
            )
            writable = sum(
                1 for s, perms in results.shares.items() if "WRITE" in perms.get(user, "")
            )
            writable_color = Colors.RED if writable > 0 else Colors.WHITE
            output(
                f"  {user}: {accessible} accessible, {c(str(writable), writable_color)} writable"
            )
    output("")

    # Key Findings section
    has_key_findings = cache.kerberoastable or cache.privileged_users
    if has_key_findings:
        output(c("KEY FINDINGS", Colors.CYAN + Colors.BOLD))
        output("-" * 50)

    # Kerberoastable
    if cache.kerberoastable:
        # Truncate list if more than 5 accounts
        kerb_usernames = [k["username"] for k in cache.kerberoastable]
        users_list = ", ".join(kerb_usernames[:5])
        if len(cache.kerberoastable) > 5:
            users_list += f" (+{len(cache.kerberoastable) - 5} more)"
        cnt = c(str(len(cache.kerberoastable)), Colors.YELLOW)
        lbl = c("Kerberoastable", Colors.YELLOW)
        lst = c(users_list, Colors.YELLOW)
        output(f"[!] {lbl} ({cnt}): {lst}")
        desc = c("→ Accounts with SPNs - request TGS tickets for offline cracking", Colors.YELLOW)
        output(f"  {desc}")
        output("")

    # Privileged Users
    if cache.privileged_users:
        # Truncate list if more than 5 users
        priv_users = cache.privileged_users[:5]
        priv_list = ", ".join(priv_users)
        if len(cache.privileged_users) > 5:
            priv_list += f" (+{len(cache.privileged_users) - 5} more)"
        cnt = c(str(len(cache.privileged_users)), Colors.RED)
        lbl = c("Privileged Users", Colors.RED)
        lst = c(priv_list, Colors.RED)
        output(f"[!] {lbl} ({cnt}): {lst}")
        output(f"  {c('→ Members of high-value groups (Domain Admins, etc.)', Colors.RED)}")
        output("")

    # Attack Vectors
    output(c("POTENTIAL ATTACK VECTORS", Colors.RED + Colors.BOLD))
    output("-" * 50)
    lockout_val = policy_info.get("Lockout threshold", "Unknown")
    if lockout_val in (None, "None", "0", 0):
        output(f"[!] {c('Password spraying (no lockout)', Colors.RED)}")
    if cache.kerberoastable:
        msg = c(f"Kerberoasting ({len(cache.kerberoastable)} accounts with SPNs)", Colors.RED)
        output(f"[!] {msg}")
    for user, (success, spooler_running, verbose_info) in results.printers.items():
        if spooler_running:
            output(f"[!] {c('PrintNightmare (spooler running)', Colors.RED)}")
            break
    if not smb_info.get("signing_required"):
        output(f"[!] {c('SMB Relay (signing not required)', Colors.RED)}")
