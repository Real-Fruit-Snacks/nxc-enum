"""Executive summary for single-credential mode."""

from ..core.colors import Colors, c
from ..core.output import output, print_section


def print_executive_summary(args, cache):
    """Print executive summary with key findings and warnings."""
    print_section("Executive Summary", args.target)

    domain_info = cache.domain_info or {}
    smb_info = cache.smb_info or {}
    policy_info = cache.policy_info or {}

    # --- Target Profile ---
    output("")
    output(c("TARGET PROFILE", Colors.CYAN + Colors.BOLD))
    output("-" * 50)

    hostname = domain_info.get("hostname", "Unknown")
    fqdn = domain_info.get("fqdn", "")
    dns_domain = domain_info.get("dns_domain", "")
    domain_sid = domain_info.get("domain_sid", "")
    is_dc = domain_info.get("is_dc", False)

    target_desc = f"{hostname}"
    if fqdn:
        target_desc = fqdn
    output(f"  Target:      {args.target} ({target_desc})")
    if is_dc:
        output(f"  Role:        {c('Domain Controller', Colors.BOLD)}")
    if dns_domain:
        output(f"  Domain:      {dns_domain}")
    if domain_sid:
        output(f"  Domain SID:  {domain_sid}")

    # --- Security Posture ---
    output("")
    output(c("SECURITY POSTURE", Colors.CYAN + Colors.BOLD))
    output("-" * 50)

    # SMB Signing
    signing = smb_info.get("signing_required", True)
    if signing:
        output(f"[+] SMB Signing: {c('REQUIRED', Colors.GREEN)}")
    else:
        output(
            f"[!] SMB Signing: {c('NOT REQUIRED', Colors.RED)} - {c('Relay attacks possible!', Colors.RED)}"
        )

    # Password Policy
    min_len = policy_info.get("Minimum password length", "Unknown")
    lockout = policy_info.get("Lockout threshold", "None")

    if min_len and min_len != "Unknown":
        try:
            min_len_int = int(min_len)
            if min_len_int < 8:
                output(
                    f"[!] Min Password Length: {c(f'{min_len} chars', Colors.RED)} {c('(weak)', Colors.RED)}"
                )
            else:
                output(f"[+] Min Password Length: {c(f'{min_len} chars', Colors.GREEN)}")
        except ValueError:
            output(f"[*] Min Password Length: {min_len}")
    else:
        output(f"[*] Min Password Length: {min_len}")

    if lockout == "None" or lockout == "0" or not lockout:
        output(
            f"[!] Lockout Threshold: {c('NONE', Colors.RED)} - {c('Password spraying safe!', Colors.RED)}"
        )
    else:
        output(f"[+] Lockout Threshold: {c(str(lockout), Colors.GREEN)}")

    # Print Spooler
    if cache.spooler_running:
        output(
            f"[!] Print Spooler: {c('RUNNING', Colors.RED)} - {c('Check for PrintNightmare!', Colors.RED)}"
        )
    else:
        output(f"[+] Print Spooler: {c('Not detected', Colors.GREEN)}")

    # AV/EDR
    if cache.av_products:
        av_list = ", ".join(cache.av_products[:3])
        if len(cache.av_products) > 3:
            av_list += f" (+{len(cache.av_products) - 3} more)"
        output(f"[!] AV/EDR: {c(av_list, Colors.YELLOW)}")
    else:
        output(f"[+] AV/EDR: {c('None detected', Colors.GREEN)}")

    # --- Enumeration Summary ---
    output("")
    output(c("ENUMERATION SUMMARY", Colors.CYAN + Colors.BOLD))
    output("-" * 50)

    output(f"  Users:       {cache.user_count}")
    output(f"  Groups:      {cache.group_count}")
    output(f"  Shares:      {cache.share_count}")

    # Key Findings section
    has_key_findings = cache.kerberoastable or cache.privileged_users
    if has_key_findings:
        output("")
        output(c("KEY FINDINGS", Colors.CYAN + Colors.BOLD))
        output("-" * 50)

    # Kerberoastable accounts (confirmed via SPN enumeration)
    if cache.kerberoastable:
        # kerberoastable is a list of dicts with 'username' and 'spns' keys
        kerb_usernames = [k["username"] for k in cache.kerberoastable]
        kerb_list = ", ".join(kerb_usernames[:5])
        if len(cache.kerberoastable) > 5:
            kerb_list += f" (+{len(cache.kerberoastable) - 5} more)"
        output("")
        output(
            f"[!] {c('Kerberoastable', Colors.YELLOW)} ({c(str(len(cache.kerberoastable)), Colors.YELLOW)}): {c(kerb_list, Colors.YELLOW)}"
        )
        output(
            f"  {c('→ Accounts with SPNs - request TGS tickets for offline cracking', Colors.YELLOW)}"
        )

    # Privileged users (members of high-value groups)
    if cache.privileged_users:
        priv_list = ", ".join(sorted(cache.privileged_users)[:8])
        if len(cache.privileged_users) > 8:
            priv_list += f" (+{len(cache.privileged_users) - 8} more)"
        output("")
        output(
            f"[!] {c('Privileged Users', Colors.RED)} ({c(str(len(cache.privileged_users)), Colors.RED)}): {c(priv_list, Colors.RED)}"
        )
        output(f"  {c('→ Members of high-value groups (Domain Admins, etc.)', Colors.RED)}")

    # --- Quick Wins ---
    quick_wins = []
    if not signing:
        quick_wins.append("SMB relay attacks (signing disabled)")
    if lockout == "None" or lockout == "0" or not lockout:
        quick_wins.append("Password spraying (no lockout)")
    if cache.kerberoastable:
        quick_wins.append(f"Kerberoasting ({len(cache.kerberoastable)} accounts with SPNs)")
    if cache.spooler_running:
        quick_wins.append("PrintNightmare (spooler running)")

    if quick_wins:
        output("")
        output(c("POTENTIAL ATTACK VECTORS", Colors.RED + Colors.BOLD))
        output("-" * 50)
        for win in quick_wins:
            output(f"[!] {c(win, Colors.RED)}")
