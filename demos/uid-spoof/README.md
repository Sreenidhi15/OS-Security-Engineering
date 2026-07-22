# UID Spoofing Demo — NFSv4 Kerberos Fallback

A simulation of a UID spoofing attack against NFSv4 when a server permits fallback from Kerberos authentication to AUTH_SYS, allowing an attacker to gain unauthorized access to any user's files without valid credentials.

---

## The Vulnerability

NFSv4 supports multiple security flavors. When a server export is configured with `sec=krb5:sys`, it allows clients to negotiate down to `sec=sys` (AUTH_SYS) during the mount handshake.

Under AUTH_SYS, the NFS client simply asserts a UID and GID in each RPC request. The server accepts these claims with no cryptographic verification — there is no ticket, no signature, no challenge. An attacker who:

1. Has network access to TCP port 2049
2. Mounts the share with `sec=sys`
3. Creates a local user matching the target UID

...gains full read/write access to the target user's files on the server.

---

## Attack Flow

```
Attacker                          NFS Server
   |                                  |
   |-- Mount request (sec=sys) ------>|
   |                                  |-- sec=sys in allowed list? YES
   |<-- Mount granted ----------------|
   |                                  |
   |-- RPC: uid=1001, gid=1001 ------>|
   |                                  |-- No ticket checked. UID trusted.
   |<-- File access granted ----------|
   |                                  |
   |-- RPC: uid=0, gid=0 ------------>|
   |                                  |-- root_squash disabled? Access granted.
   |<-- Root access granted ----------|
```

---

## Files

| File | Description |
|------|-------------|
| `uid_spoof_demo.py` | Simulates the full attack against a vulnerable and hardened server side by side |
| `hardened_config.md` | `/etc/exports` vulnerable vs hardened configuration with line-by-line explanation |

---

## How to Run

```bash
python3 uid_spoof_demo.py
```

No dependencies required — pure Python standard library. No NFS server needed.

**Expected output structure:**

```
SCENARIO 1: VULNERABLE SERVER (sec=krb5:sys)
  Step 1: Kerberos mount — FAILED (no ticket)
  Step 2: AUTH_SYS fallback — ALLOWED
  Step 3: UID spoof to 1001
  Step 4: Files accessed: financial_report_Q3.xlsx, api_keys.env ...
  Step 5: Root escalation — /etc/shadow, /root/.ssh/id_rsa accessed

SCENARIO 2: HARDENED SERVER (sec=krb5p)
  Step 1: Kerberos mount — FAILED (no ticket)
  Step 2: AUTH_SYS fallback — BLOCKED
  Attack failed.
```

---

## CWE and NIST Mapping

| Reference | ID | Description |
|-----------|-----|-------------|
| CWE | CWE-287 | Improper Authentication — server grants access without verifying identity |
| CWE | CWE-290 | Authentication Bypass by Spoofing — attacker asserts a trusted UID |
| NIST | AC-3 | Access Enforcement — access granted without cryptographic identity proof |
| NIST | IA-2 | Identification and Authentication — UID assertion is not authentication |
| NIST | SC-8 | Transmission Confidentiality — AUTH_SYS transmits UID in plaintext |

---

## Remediation

Remove `sys` from the security flavor list in `/etc/exports`:

```
# Vulnerable
/data  *(sec=krb5:sys,rw,subtree_check)

# Hardened
/data  192.168.1.0/24(sec=krb5p,rw,subtree_check,root_squash)
```

See `hardened_config.md` for the full remediation reference.

---

## Interview Answer

**"Walk me through a vulnerability you found and how you would remediate it."**

NFSv4 servers configured with `sec=krb5:sys` allow clients to bypass Kerberos authentication by negotiating down to AUTH_SYS during the mount handshake. Under AUTH_SYS, the client asserts a UID in each RPC call with no cryptographic verification — the server trusts it unconditionally. An attacker with network access to port 2049 can create a local user matching the target UID and gain full file access without any credentials. This maps to CWE-287 and NIST AC-3. The fix is to remove `sys` from the allowed security flavors and enforce `sec=krb5p`, which requires a valid Kerberos ticket and encrypts all traffic.
