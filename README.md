# OS Security Engineering — POSIX Shell & Security Research

**Language:** C | **Platform:** Linux (POSIX-compliant)

---

## Overview

This project has two components. Part A is a fully functional Unix shell built from scratch in C using only standard POSIX system calls — no external libraries. Part B extends the shell with a security audit logging module mapped to NIST SP 800-53 controls, demonstrating how OS-level primitives translate directly into enterprise security requirements.

---

## Part A — POSIX-Compliant Shell in C

### Features

- **Multi-stage pipelines** — connect arbitrary numbers of commands with `|`
- **I/O redirection** — input (`<`) and output (`>`) redirection with full error handling
- **Background execution** — run processes with `&`; shell prints PID and returns immediately
- **Zombie cleanup** — background processes reaped via `waitpid(WNOHANG)` at each loop iteration
- **Custom pipe parser** — `split_by_pipe` manually walks the input string instead of using `strtok` to avoid internal state conflicts during argument parsing
- **Graceful error handling** — distinct messages for command not found, missing input file, and unwritable output path

### System Calls Used

| System Call | Purpose |
|-------------|---------|
| `fork()` | Spawns a child process for each command in the pipeline |
| `execvp()` | Replaces the child process image with the target program |
| `pipe()` | Creates unidirectional data channels between adjacent commands |
| `dup2()` | Redirects stdin/stdout to pipe ends or files |
| `waitpid()` | Reaps foreground and background children; prevents zombie accumulation |
| `open()` / `close()` | Opens files for redirection; closes unused file descriptors in children |

### How to Build & Run

```bash
# Without audit logging
gcc -o myshell myshell.c

# With audit logging (recommended)
gcc -o myshell myshell.c audit/audit_logger.c

./myshell
```

### Test Cases Covered

| # | Scenario |
|---|----------|
| 1 | Simple command |
| 2 | Command with flags |
| 3 | Command not found |
| 4 | Pipeline (two commands) |
| 5 | Three-stage pipeline |
| 6 | Background execution |
| 7 | Output redirection |
| 8 | Invalid output path |
| 9 | Input redirection |
| 10 | Invalid input file |
| 11 | Input redirection + pipeline |
| 12 | Pipeline + output redirection |
| 13 | Input + pipeline + output (all three) |
| 14 | Exit the shell |

### Libraries Used

Only standard POSIX — `stdio.h`, `stdlib.h`, `string.h`, `unistd.h`, `sys/wait.h`, `fcntl.h`. No third-party dependencies.

---

## Part B — Security Extension: Audit Logging (NIST SP 800-53)

The shell is extended with a structured audit logging module that records every command execution to `shell_audit.log`. This demonstrates how OS-level primitives directly implement enterprise security controls.

### What Gets Logged

Every command produces one record containing:

- ISO 8601 timestamp with timezone offset
- Real UID of the invoking user (`getuid()` — not effective UID, so setuid wrappers cannot obscure identity)
- PID of the shell process
- Full command string as entered, including pipes and redirection operators
- Exit status of the last command in the pipeline (`-1` for background processes)

### Sample Log Output

```
--- SESSION START | TIME=2026-06-26T09:14:02-0400 | UID=1001 | PID=5821 ---
[2026-06-26T09:14:05-0400] UID=1001 PID=5821 CMD="ls -la" EXIT=0
[2026-06-26T09:14:09-0400] UID=1001 PID=5821 CMD="cat /etc/passwd | grep root" EXIT=0
[2026-06-26T09:14:35-0400] UID=1001 PID=5821 CMD="sleep 10 &" EXIT=-1
[2026-06-26T09:14:44-0400] UID=1001 PID=5821 CMD="fakecommand --flag" EXIT=127
--- SESSION END   | TIME=2026-06-26T09:14:47-0400 | UID=1001 | PID=5821 ---
```

### NIST SP 800-53 Control Mapping

| Control | Name | How This Module Satisfies It |
|---------|------|------------------------------|
| AU-2 | Audit Events | Every command execution including `exit` is a logged audit event |
| AU-3 | Content of Audit Records | Each record contains timestamp, UID, PID, command string, and exit status |
| AU-9 | Protection of Audit Information | `O_APPEND` ensures atomic writes; log should be `chmod 600` in production |
| AU-12 | Audit Record Generation | Shell generates records at point of execution with session boundary markers |

This mapping applies directly to SOC 2 (CC7.2), ISO 27001 (A.12.4), and FedRAMP audit requirements.

### Audit Module Files

```
audit/
├── audit_logger.h          ← public API
├── audit_logger.c          ← implementation with design rationale
└── shell_audit.log.sample  ← example output including anomalous entries
```

See [`audit/README.md`](audit/README.md) for full design rationale and GRC analysis.

---

## Part C — Coming Next

The next phase adds a working **attack and defense demo** covering:

- Command injection vulnerability (CWE-78) — vulnerable vs hardened shell implementation side by side
- AES mode weakness demo — ECB pattern leakage vs GCM authenticated encryption
- UID spoofing simulation — NFSv4 Kerberos fallback exploitation and remediation

Each demo is mapped to a NIST SP 800-53 control and a CVE or CWE entry.

---

## Repository Structure

```
OS-Security-Engineering/
├── myshell.c               ← POSIX shell implementation
├── audit/
│   ├── README.md           ← NIST control mapping and design rationale
│   ├── audit_logger.h
│   ├── audit_logger.c
│   └── shell_audit.log.sample
└── README.md
```

---

## Skills Demonstrated

`C` · `POSIX` · `fork/exec` · `pipe/dup2` · `IPC` · `Signal Handling` · `NIST SP 800-53` · `Audit Logging` · `AES-256` · `Kerberos` · `DAC/MAC/RBAC` · `SELinux` · `NFS Security` · `CWE-78` · `Distributed Systems Security`
