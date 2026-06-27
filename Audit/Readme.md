# Audit Logging Module

A security extension to the POSIX shell implementing structured command audit logging, mapped to NIST SP 800-53 controls.

---

## What It Does

Every command executed through the shell is recorded to `shell_audit.log` with:

- ISO 8601 timestamp with timezone offset
- Real UID of the invoking user (`getuid()` — not the effective UID, so setuid wrappers cannot obscure identity)
- PID of the shell process
- Full command string exactly as entered, including pipes and redirection operators
- Exit status of the last command in the pipeline (`-1` for background processes)

Session boundaries are marked with `SESSION START` and `SESSION END` entries so log analysts can distinguish individual shell invocations.

---

## Log Format

```
--- SESSION START | TIME=2026-06-26T09:14:02-0400 | UID=1001 | PID=5821 ---
[2026-06-26T09:14:05-0400] UID=1001 PID=5821 CMD="ls -la" EXIT=0
[2026-06-26T09:14:09-0400] UID=1001 PID=5821 CMD="cat /etc/passwd | grep root" EXIT=0
[2026-06-26T09:14:35-0400] UID=1001 PID=5821 CMD="sleep 10 &" EXIT=-1
[2026-06-26T09:14:44-0400] UID=1001 PID=5821 CMD="fakecommand --flag" EXIT=127
--- SESSION END   | TIME=2026-06-26T09:14:47-0400 | UID=1001 | PID=5821 ---
```

`EXIT=-1` indicates a background process whose exit status was not collected at dispatch time.  
`EXIT=127` is the conventional shell exit code for command not found.

---

## NIST SP 800-53 Control Mapping

| Control | Name | How This Module Satisfies It |
|---------|------|------------------------------|
| AU-2 | Audit Events | Every command execution, including `exit`, is a logged audit event |
| AU-3 | Content of Audit Records | Each record contains: timestamp, user identity (UID), process ID, event (command string), and outcome (exit status) |
| AU-9 | Protection of Audit Information | `O_APPEND` flag ensures atomic writes; log file should be `chmod 600` owned by root in production to prevent tampering |
| AU-12 | Audit Record Generation | The shell generates records at the point of execution; session markers bound each invocation |

This mapping is directly applicable to security audits under frameworks including SOC 2 (CC7.2 — system monitoring), ISO 27001 (A.12.4 — logging and monitoring), and FedRAMP (inherits NIST AU controls).

---

## Files

| File | Description |
|------|-------------|
| `audit_logger.h` | Public API — `audit_init()`, `audit_log()`, `audit_close()` |
| `audit_logger.c` | Implementation with design rationale in comments |
| `myshell.c` | Updated shell with audit hooks at command execution and session boundaries |
| `shell_audit.log.sample` | Example log output showing normal use and anomalous entries (UID=0 session, EXIT=1 on shadow access) |

---

## Build

```bash
gcc -o myshell myshell.c audit_logger.c
./myshell
```

The log file `shell_audit.log` is created in the current working directory.

---

## Security Design Decisions

**Why `O_APPEND`?**  
Each `fwrite` to an `O_APPEND` file is atomic at the OS level up to `PIPE_BUF` bytes (4KB on Linux). This prevents log entry interleaving if multiple shell instances run concurrently under the same user.

**Why `getuid()` instead of `geteuid()`?**  
`getuid()` returns the real user ID — the identity of the user who launched the process. `geteuid()` returns the effective UID, which may be elevated by a setuid bit. Logging the real UID correctly attributes commands to the human operator rather than the privilege level.

**Why flush after every record?**  
Buffered writes would lose the last few log entries if the shell crashes or is killed. Flushing after each `audit_log()` call ensures the log reflects reality up to the moment of failure — which is exactly when audit records matter most.

**What a GRC auditor looks for in this log:**  
- Unexpected UID=0 sessions from non-admin users (privilege escalation indicator)
- Commands with EXIT=1 on sensitive files like `/etc/shadow` (access control enforcement working)
- Long gaps between SESSION START and first command (potential session hijacking)
- High-frequency identical commands (scripted attack pattern)
