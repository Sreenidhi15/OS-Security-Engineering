#!/usr/bin/env python3
"""
uid_spoof_demo.py

Simulates a UID spoofing attack against NFSv4 when the server permits
fallback from Kerberos (sec=krb5) to AUTH_SYS (sec=sys).

This is NOT a live exploit — it simulates the attack logic to demonstrate
the vulnerability without requiring an actual NFS server. The simulation
models the exact sequence an attacker would follow on a real network.

Vulnerability:
  NFSv4 servers configured with sec=krb5:sys allow clients to negotiate
  down to AUTH_SYS during the mount handshake. Under AUTH_SYS, the client
  asserts a UID and GID in each RPC call with no cryptographic verification.
  An attacker who creates a local user with the target UID gains full access
  to that user's files on the NFS export — without any valid Kerberos ticket.

CWE:
  CWE-287 — Improper Authentication
  CWE-290 — Authentication Bypass by Spoofing

NIST SP 800-53:
  AC-3  — Access Enforcement (violated: access granted without identity proof)
  IA-2  — Identification and Authentication (violated: UID asserted, not proven)
  IA-5  — Authenticator Management (violated: no credential required)
  SC-8  — Transmission Confidentiality and Integrity (sec=sys transmits in plaintext)

Usage:
  python3 uid_spoof_demo.py
"""

import time
import sys

# ------------------------------------------------------------------ #
# Simulation state — models an NFS server and its export configuration
# ------------------------------------------------------------------ #

class NFSServer:
    """Simulates an NFS server with configurable export security settings."""

    def __init__(self, name: str, export_path: str, sec_options: list[str]):
        self.name = name
        self.export_path = export_path
        self.sec_options = sec_options   # e.g. ["krb5", "sys"] or ["krb5p"]

        # Simulated filesystem: uid -> list of files
        self.filesystem = {
            0:    ["/etc/shadow", "/etc/sudoers", "/root/.ssh/id_rsa"],
            1001: ["financial_report_Q3.xlsx", "personal_notes.txt", "ssh_keys/"],
            1002: ["source_code/", "api_keys.env", "database_backup.sql"],
        }

    def allows_sys_fallback(self) -> bool:
        return "sys" in self.sec_options

    def list_files(self, uid: int) -> list[str]:
        return self.filesystem.get(uid, [f"(no files owned by UID {uid})"])


class NFSClient:
    """Simulates an NFS client attempting to mount and access a share."""

    def __init__(self, hostname: str, local_uid: int):
        self.hostname = hostname
        self.local_uid = local_uid

    def attempt_mount(self, server: NFSServer, requested_sec: str) -> bool:
        """Returns True if mount succeeds with the requested security flavor."""
        if requested_sec == "sys":
            return server.allows_sys_fallback()
        elif requested_sec in ("krb5", "krb5i", "krb5p"):
            # Simulating: attacker does NOT have a valid Kerberos ticket
            return False
        return False


# ------------------------------------------------------------------ #
# Helper output functions
# ------------------------------------------------------------------ #

def step(n: int, text: str) -> None:
    print(f"\n  Step {n}: {text}")
    time.sleep(0.4)

def result(label: str, value: str, highlight: bool = False) -> None:
    marker = "  [!]" if highlight else "  [ ]"
    print(f"{marker} {label}: {value}")

def separator() -> None:
    print("\n" + "-" * 60)


# ------------------------------------------------------------------ #
# Attack simulation
# ------------------------------------------------------------------ #

def simulate_attack(server: NFSServer, target_uid: int) -> None:
    print(f"""
  Target server  : {server.name}
  Export path    : {server.export_path}
  Security config: sec={':'.join(server.sec_options)}
  Target UID     : {target_uid}
  Attacker UID   : 9999 (no privileges on server)
""")

    attacker = NFSClient(hostname="attacker-host", local_uid=9999)

    # Step 1: Try Kerberos — fails (no ticket)
    step(1, "Attempting mount with sec=krb5 (requires valid Kerberos ticket)")
    krb5_success = attacker.attempt_mount(server, "krb5")
    result("Kerberos mount", "FAILED — no valid ticket, as expected")

    # Step 2: Try AUTH_SYS fallback
    step(2, "Negotiating down to sec=sys (AUTH_SYS — no crypto verification)")
    sys_success = attacker.attempt_mount(server, "sys")

    if not sys_success:
        result("AUTH_SYS fallback", "BLOCKED — server does not permit sec=sys", highlight=False)
        print("\n  [SECURE] Server is correctly configured. Attack failed.")
        return

    result("AUTH_SYS fallback", "ALLOWED — server permits sec=sys fallback", highlight=True)

    # Step 3: Spoof the target UID
    step(3, f"Creating local user with UID={target_uid} to match target on server")
    print(f"  $ useradd -u {target_uid} spoofed_user")
    print(f"  $ su - spoofed_user")
    result("Local UID", f"{target_uid} (matches target user on NFS server)", highlight=True)

    # Step 4: Access files
    step(4, "Sending NFS RPC requests with spoofed UID — server accepts without verification")
    spoofed_client = NFSClient(hostname="attacker-host", local_uid=target_uid)
    files = server.list_files(target_uid)

    print(f"\n  RPC call: LOOKUP uid={target_uid} gid={target_uid} path={server.export_path}")
    print(f"  Server response: ACCESS GRANTED (no Kerberos ticket checked)\n")

    print(f"  Files accessible on {server.export_path} as UID {target_uid}:")
    for f in files:
        print(f"    - {f}")

    # Step 5: Root escalation if no_root_squash
    step(5, "Attempting UID=0 spoof (root escalation via no_root_squash)")
    root_files = server.list_files(0)
    print(f"\n  $ useradd -u 0 root_spoof  (or: sudo su)")
    print(f"  RPC call: LOOKUP uid=0 gid=0 path={server.export_path}")
    print(f"  Server response: ACCESS GRANTED (root_squash not enforced)\n")
    print(f"  Files accessible as UID 0 (root):")
    for f in root_files:
        print(f"    - {f}")

    result("Attack outcome", "FULL FILESYSTEM ACCESS without any Kerberos credentials", highlight=True)


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #

def main() -> None:
    print("=" * 60)
    print("  NFSv4 UID Spoofing Demo")
    print("  CWE-287 / CWE-290 — Authentication Bypass")
    print("  NIST SP 800-53: AC-3, IA-2, IA-5, SC-8")
    print("=" * 60)

    # --- Scenario 1: Vulnerable server ---
    separator()
    print("\n[SCENARIO 1] VULNERABLE SERVER")
    print("  Export config: /data *(sec=krb5:sys,rw,subtree_check)")
    print("  Allows AUTH_SYS fallback: YES")

    vulnerable_server = NFSServer(
        name="nfs-server-prod",
        export_path="/data",
        sec_options=["krb5", "sys"],   # vulnerable: sys fallback permitted
    )
    simulate_attack(vulnerable_server, target_uid=1001)

    # --- Scenario 2: Hardened server ---
    separator()
    print("\n[SCENARIO 2] HARDENED SERVER")
    print("  Export config: /data *(sec=krb5p,rw,subtree_check,root_squash)")
    print("  Allows AUTH_SYS fallback: NO")

    hardened_server = NFSServer(
        name="nfs-server-hardened",
        export_path="/data",
        sec_options=["krb5p"],   # hardened: only krb5p, no sys fallback
    )
    simulate_attack(hardened_server, target_uid=1001)

    # --- Summary ---
    separator()
    print("""
[SUMMARY]

  Vulnerable config : sec=krb5:sys   — sys fallback allows UID spoofing
  Hardened config   : sec=krb5p      — only encrypted+authenticated Kerberos

  Root cause  : AUTH_SYS trusts client-asserted UIDs with no verification.
                Kerberos fallback lets an attacker opt out of authentication.

  Fix         : Remove 'sys' from allowed security flavors in /etc/exports.
                Use sec=krb5p (encryption + integrity + authentication).
                Enable root_squash to prevent UID=0 escalation.

  CWE-287     : System accepts UID assertion without cryptographic proof.
  CWE-290     : Authentication is bypassed entirely by negotiating down
                to a weaker security mechanism.

  NIST AC-3   : Access enforcement fails — access granted without
                verified identity.
  NIST IA-2   : Users are not uniquely identified and authenticated
                before accessing resources.
""")


if __name__ == "__main__":
    main()
