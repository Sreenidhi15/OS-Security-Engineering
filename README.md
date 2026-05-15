# OS Security Engineering — POSIX Shell & Security Research

**Authors:** Sreenidhi Ramani & Akash Kotagi

---

## Part A — POSIX-Compliant Shell in C

A fully functional Unix shell built from scratch in C using only standard POSIX libraries. No external dependencies.

### Features

- **Multi-stage pipelines** — connect arbitrary numbers of commands with `|`
- **I/O redirection** — input (`<`) and output (`>`) redirection with full error handling
- **Background execution** — run processes with `&`; shell prints PID and returns immediately
- **Zombie cleanup** — background processes reaped via `waitpid(WNOHANG)` at each loop iteration
- **Custom pipe parser** — `split_by_pipe` manually walks the input string instead of using `strtok` to avoid internal state conflicts during argument parsing
- **Graceful error handling** — distinct messages for command not found, missing input file, and unwritable output path

### How to Build & Run

```bash
gcc -o shell shell.c
./shell
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

## Part B — Security Research: Access Control, Cryptography & Distributed Systems

A research presentation covering three pillars of OS security:

- **Access Control** — ACLs vs capabilities, DAC/MAC/RBAC models, Bell-LaPadula, SELinux, AppArmor, AWS IAM
- **Cryptography** — AES-256 modes (ECB/CBC/GCM), RSA vs ECC, hybrid TLS/SSH, password hashing evolution (bcrypt, Argon2)
- **Distributed Systems Security** — NFS architecture, RPC/VFS, Kerberos (krb5/krb5i/krb5p), UID spoofing vulnerabilities, NFSv4 mitigations

---

## What's Coming

This project is actively being extended. The next phase will add a working **attack + defense demo** — demonstrating real vulnerabilities covered in the research (hash cracking, weak encryption modes) alongside their defenses, all running through the shell built in Part A.

---

## Skills Demonstrated

`C` · `POSIX` · `fork/exec` · `pipe/dup2` · `IPC` · `Concurrency` · `AES-256` · `ECC` · `TLS` · `Kerberos` · `DAC/MAC/RBAC` · `SELinux` · `NFS` · `bcrypt` · `Argon2` · `Distributed Systems Security`
