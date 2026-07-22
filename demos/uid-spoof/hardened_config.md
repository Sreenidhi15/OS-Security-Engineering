# NFSv4 Hardened Configuration Reference

This document shows the vulnerable vs hardened `/etc/exports` configuration for the UID spoofing vulnerability demonstrated in `uid_spoof_demo.py`.

---

## Vulnerable Configuration

```
# /etc/exports — VULNERABLE
# sec=krb5:sys allows client to negotiate down to AUTH_SYS
# AUTH_SYS accepts client-asserted UIDs with no cryptographic verification

/data  *(sec=krb5:sys,rw,subtree_check)
```

**What makes this vulnerable:**
- `sec=krb5:sys` lists `sys` as an allowed fallback security flavor
- A client that cannot or chooses not to present a Kerberos ticket can mount with `sec=sys`
- Under `sec=sys`, the client asserts UID and GID in each RPC call — the server accepts without verification
- Any client on the network can assume any UID by creating a local user with that UID

---

## Hardened Configuration

```
# /etc/exports — HARDENED
# sec=krb5p enforces: authentication + integrity + encryption
# No sys fallback — AUTH_SYS is not permitted under any circumstance
# root_squash maps UID=0 requests to nobody — prevents root escalation

/data  <trusted-subnet>(sec=krb5p,rw,subtree_check,root_squash)
```

**What each option does:**

| Option | Purpose |
|--------|---------|
| `sec=krb5p` | Requires Kerberos authentication + message integrity + encryption. No sys fallback. |
| `root_squash` | Maps UID=0 from clients to the `nobody` user on the server. Prevents root escalation even if Kerberos is compromised. |
| `subtree_check` | Verifies file requests fall within the exported subtree. Prevents path traversal. |
| `<trusted-subnet>` | Restrict to known client IP range (e.g. `192.168.1.0/24`) instead of wildcard `*`. |

---

## Security Flavor Comparison

| Flavor | Authentication | Integrity | Encryption | UID Spoof Risk |
|--------|---------------|-----------|------------|----------------|
| `sec=sys` | None — UID asserted by client | No | No | HIGH |
| `sec=krb5` | Kerberos ticket | No | No | LOW (if no sys fallback) |
| `sec=krb5i` | Kerberos ticket | Yes (checksums) | No | LOW |
| `sec=krb5p` | Kerberos ticket | Yes | Yes | NONE |

Always use `sec=krb5p` for sensitive exports. `sec=krb5` alone provides authentication but transmits data in plaintext — vulnerable to interception.

---

## Firewall Rule

Restrict NFS port access at the network level as a defense-in-depth measure:

```bash
# Allow NFS only from trusted subnet
iptables -A INPUT -p tcp --dport 2049 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 2049 -j DROP
iptables -A INPUT -p udp --dport 2049 -j DROP
```

---

## NIST SP 800-53 Control Mapping

| Control | Name | How Hardened Config Satisfies It |
|---------|------|----------------------------------|
| AC-3 | Access Enforcement | Kerberos ticket required before any file access is granted |
| IA-2 | Identification and Authentication | Users are cryptographically identified via Kerberos before access |
| IA-5 | Authenticator Management | Kerberos tickets are time-limited (default 8hr) and issued by a trusted KDC |
| SC-8 | Transmission Confidentiality and Integrity | `sec=krb5p` encrypts all NFS traffic; `krb5i` adds integrity checks |
| SC-28 | Protection of Information at Rest | Combined with filesystem permissions, prevents unauthorized data access |
